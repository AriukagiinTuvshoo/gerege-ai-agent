import os
import json
import gzip
import time
import shutil
import sqlite3
import hashlib
import subprocess
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

import database
from core.db_engine import is_postgres, get_database_url, dispose_shared_engine

logger = logging.getLogger("core.backup_service")

BACKUP_DIR = os.getenv("BACKUP_DIR", "backups")
SCHEMA_VERSION = "0001_initial_enterprise_schema"


class MaintenanceCredentialRequired(RuntimeError):
    """Backup/restore was attempted with a credential that cannot do it correctly.

    ``pg_dump`` needs ``LOCK TABLE ... ACCESS SHARE`` on every table and restore needs
    ``DROP``/``CREATE`` on the schema, which is ownership. The runtime role
    (``gerege_app``) has neither by design (finding E-05).

    Without this guard the failure is *silent and destructive*: ``pg_dump`` exits
    non-zero with ``permission denied for table registrations``, and the code path
    that writes its stdout to gzip produces a **0-byte backup that is then recorded as
    a success** in the manifest. A restore point that does not exist is worse than no
    restore point, because it is trusted. So the credential is checked before any
    process is spawned.
    """


def _assert_maintenance_credential() -> None:
    """Refuse to dump/restore as a role that cannot complete the operation.

    Only meaningful on PostgreSQL; SQLite has no roles and its backup path copies a
    file, so it is unaffected. Deliberately raises rather than returning a dict, and
    deliberately does not echo the DSN.
    """
    from core.db_engine import get_db_connection, is_postgres

    if not is_postgres():
        return
    try:
        conn = get_db_connection()
    except Exception as exc:  # pragma: no cover - connection failure is reported elsewhere
        raise MaintenanceCredentialRequired(
            f"cannot reach the database to check the backup credential: {type(exc).__name__}"
        ) from None
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT current_user,
                   (SELECT rolcreatedb FROM pg_roles WHERE rolname = current_user),
                   pg_has_role(current_user, 'gerege_owner', 'MEMBER')
            """
        )
        row = cur.fetchone()
        cur.close()
    finally:
        try:
            conn.close()
        except Exception:
            pass

    if not row:
        raise MaintenanceCredentialRequired("could not determine the current database role")
    user, _, is_owner = (row[0], row[1], row[2])
    if not is_owner:
        raise MaintenanceCredentialRequired(
            f"role '{user}' cannot create a trustworthy backup or restore: it does not own "
            "the schema, so pg_dump fails with 'permission denied' and produces an empty "
            "archive, and restore cannot drop/recreate tables.\n"
            "Run backup/restore as the maintenance role instead:\n"
            "  docker compose -f docker-compose.prod.yml run --rm maintenance "
            "python scripts/maintenance.py backup\n"
            "  python scripts/maintenance.py backup     (host, DATABASE_OWNER_URL set)\n"
            "See docs/operations/BACKUP_RESTORE.md."
        )


def _compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _collect_db_table_counts() -> Dict[str, int]:
    counts: Dict[str, int] = {}
    conn = None
    cur = None
    try:
        conn = database.get_connection()
        cur = conn.cursor()
        for tbl in (
            "pages", "registrations", "messages", "session_states", "sessions",
            "user_memories", "invoices", "cargo_packages", "automated_rules",
            "marketing_campaigns", "sent_followups", "appointments",
            "notification_locks", "task_jobs", "audit_logs",
            "comment_automations", "tracked_links",
        ):
            try:
                cur.execute(f"SELECT COUNT(*) FROM {tbl}")
                row = cur.fetchone()
                counts[tbl] = int(row[0] or 0) if row else 0
            except Exception:
                counts[tbl] = 0
        try:
            conn.commit()
        except Exception:
            pass
    finally:
        if cur is not None:
            try:
                cur.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
    return counts


def create_backup(label: str = "manual") -> Dict[str, Any]:
    """
    Өгөгөгдлийн сангийн бүрэн нөөцлөлт (Backup) үүсгэж, gzip шахалт, SHA-256 checksum (.sha256),
    болон метадата манифест (.meta.json) хадгалах.
    SQLite үед online backup API (`sqlite3.Connection.backup`), PostgreSQL үед `pg_dump` ашиглана.
    """
    _assert_maintenance_credential()
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:18]
    safe_label = "".join(c for c in label if c.isalnum() or c in ("_", "-")) or "backup"
    engine_name = "postgresql" if is_postgres() else "sqlite"
    table_counts = _collect_db_table_counts()

    if is_postgres():
        filename = f"pg_backup_{safe_label}_{ts}.sql.gz"
        dest_path = os.path.join(BACKUP_DIR, filename)
        pg_url = get_database_url().replace("postgresql+psycopg2://", "postgresql://")
        try:
            proc = subprocess.run(
                ["pg_dump", "--clean", "--if-exists", "--no-owner", "--no-privileges", pg_url],
                capture_output=True,
                check=True,
                timeout=120,
            )
            with gzip.open(dest_path, "wb") as gz:
                gz.write(proc.stdout)
        except Exception as e:
            logger.error(f"PostgreSQL pg_dump failed: {e}")
            return {"success": False, "error": str(e)}
    else:
        filename = f"sqlite_backup_{safe_label}_{ts}.db.gz"
        raw_temp = os.path.join(BACKUP_DIR, f".tmp_{ts}.db")
        dest_path = os.path.join(BACKUP_DIR, filename)
        try:
            src_conn = sqlite3.connect(database.DB_PATH)
            dst_conn = sqlite3.connect(raw_temp)
            with dst_conn:
                src_conn.backup(dst_conn)
            dst_conn.close()
            src_conn.close()

            with open(raw_temp, "rb") as f_in, gzip.open(dest_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        except Exception as e:
            logger.error(f"SQLite backup failed: {e}")
            return {"success": False, "error": str(e)}
        finally:
            if os.path.exists(raw_temp):
                try:
                    os.remove(raw_temp)
                except Exception:
                    pass

    sha256_hex = _compute_sha256(dest_path)
    with open(dest_path + ".sha256", "w", encoding="utf-8") as sf:
        sf.write(f"{sha256_hex}  {filename}\n")

    size_bytes = os.path.getsize(dest_path)
    created_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    metadata = {
        "filename": filename,
        "engine": engine_name,
        "schema_version": SCHEMA_VERSION,
        "size_bytes": size_bytes,
        "sha256": sha256_hex,
        "created_at": created_str,
        "label": safe_label,
        "table_counts": table_counts,
    }
    with open(dest_path + ".meta.json", "w", encoding="utf-8") as mf:
        json.dump(metadata, mf, ensure_ascii=False, indent=2)

    return {
        "success": True,
        "filename": filename,
        "path": dest_path,
        "size_bytes": size_bytes,
        "sha256": sha256_hex,
        "engine": engine_name,
        "schema_version": SCHEMA_VERSION,
        "table_counts": table_counts,
        "created_at": created_str,
    }


def list_backups() -> List[Dict[str, Any]]:
    """Хадгалагдсан backup файлуудын жагсаалтыг буцаах"""
    if not os.path.exists(BACKUP_DIR):
        return []
    items: List[Dict[str, Any]] = []
    for fname in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if not (fname.endswith(".db.gz") or fname.endswith(".sql.gz")):
            continue
        fpath = os.path.join(BACKUP_DIR, fname)
        sha_path = fpath + ".sha256"
        meta_path = fpath + ".meta.json"
        sha_val = ""
        meta_obj: Dict[str, Any] = {}
        if os.path.exists(sha_path):
            try:
                sha_val = open(sha_path, "r", encoding="utf-8").read().split()[0]
            except Exception:
                sha_val = ""
        if os.path.exists(meta_path):
            try:
                meta_obj = json.loads(open(meta_path, "r", encoding="utf-8").read())
            except Exception:
                meta_obj = {}
        items.append({
            "filename": fname,
            "size_bytes": os.path.getsize(fpath),
            "sha256": sha_val,
            "engine": meta_obj.get("engine") or ("postgresql" if fname.endswith(".sql.gz") else "sqlite"),
            "schema_version": meta_obj.get("schema_version", SCHEMA_VERSION),
            "table_counts": meta_obj.get("table_counts", {}),
            "modified_at": datetime.fromtimestamp(os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M:%S"),
        })
    return items


def verify_backup(filename: str) -> Dict[str, Any]:
    """
    Backup файлын SHA-256 бүрэн бүтэн байдал, SQLite integrity_check + isolated table read test,
    эсвэл PostgreSQL gzip stream & SQL dump structure шалгах.
    """
    clean_name = os.path.basename(filename)
    fpath = os.path.join(BACKUP_DIR, clean_name)
    if not os.path.exists(fpath):
        return {"valid": False, "error": "Backup file not found"}

    if os.path.getsize(fpath) == 0:
        return {"valid": False, "error": "Backup file is empty (0 bytes)"}

    actual_sha = _compute_sha256(fpath)
    sha_path = fpath + ".sha256"
    if os.path.exists(sha_path):
        try:
            expected_sha = open(sha_path, "r", encoding="utf-8").read().split()[0]
        except Exception:
            expected_sha = ""
        if not expected_sha or actual_sha != expected_sha:
            return {"valid": False, "error": "SHA-256 checksum mismatch"}

    if clean_name.endswith(".db.gz"):
        tmp_check = os.path.join(BACKUP_DIR, f".verify_{clean_name}.db")
        try:
            with gzip.open(fpath, "rb") as f_in, open(tmp_check, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
            conn = sqlite3.connect(tmp_check)
            cur = conn.cursor()
            cur.execute("PRAGMA integrity_check")
            res = cur.fetchone()
            if not res or res[0] != "ok":
                conn.close()
                return {"valid": False, "error": f"SQLite integrity check failed: {res}"}
            tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            conn.close()
            if "pages" not in tables:
                return {"valid": False, "error": "Backup SQLite schema missing core 'pages' table"}
        except Exception as e:
            return {"valid": False, "error": f"SQLite backup verification error: {e}"}
        finally:
            if os.path.exists(tmp_check):
                try:
                    os.remove(tmp_check)
                except Exception:
                    pass

    elif clean_name.endswith(".sql.gz"):
        try:
            with gzip.open(fpath, "rt", encoding="utf-8", errors="replace") as gz:
                head_chunk = gz.read(32768)
                while gz.read(65536):
                    pass
            if not head_chunk.strip():
                return {"valid": False, "error": "PostgreSQL SQL dump is empty"}
            valid_markers = ("PostgreSQL database dump", "CREATE TABLE", "SET ", "COPY ", "INSERT INTO")
            if not any(m in head_chunk for m in valid_markers):
                return {"valid": False, "error": "File does not appear to be a valid PostgreSQL SQL dump"}
        except Exception as e:
            return {"valid": False, "error": f"PostgreSQL .sql.gz decompression/verification failed: {e}"}
    else:
        return {"valid": False, "error": "Unsupported backup file extension"}

    return {"valid": True, "filename": clean_name, "sha256": actual_sha}


_REQUIRED_RESTORE_TABLES = (
    "pages",
    "registrations",
    "messages",
    "session_states",
    "sessions",
    "user_memories",
    "invoices",
    "cargo_packages",
    "automated_rules",
    "marketing_campaigns",
    "sent_followups",
    "appointments",
    "notification_locks",
    "task_jobs",
    "audit_logs",
    "comment_automations",
    "tracked_links",
)


def _load_expected_counts(backup_fpath: str) -> Dict[str, int]:
    meta_path = backup_fpath + ".meta.json"
    if not os.path.exists(meta_path):
        return {}
    try:
        with open(meta_path, "r", encoding="utf-8") as mf:
            meta = json.load(mf)
        raw = meta.get("table_counts") or {}
        return {str(k): int(v) for k, v in raw.items() if isinstance(v, (int, float)) and v >= 0}
    except Exception:
        return {}


def _verify_restored_sqlite(db_path: str, expected_counts: Dict[str, int]) -> Dict[str, Any]:
    conn = sqlite3.connect(db_path)
    try:
        ic = conn.execute("PRAGMA integrity_check").fetchone()
        if not ic or ic[0] != "ok":
            return {"verified": False, "error": f"SQLite integrity_check failed: {ic}", "table_counts": {}}

        existing = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        missing = [t for t in _REQUIRED_RESTORE_TABLES if t not in existing]
        if missing:
            return {"verified": False, "error": f"Missing required tables after restore: {missing}", "table_counts": {}}

        actual_counts: Dict[str, int] = {}
        mismatches: Dict[str, Any] = {}
        for t in _REQUIRED_RESTORE_TABLES:
            cnt = int(conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] or 0)
            actual_counts[t] = cnt
            if t in expected_counts:
                exp = expected_counts[t]
                if exp > 0 and cnt == 0:
                    mismatches[t] = {"expected": exp, "actual": cnt, "reason": "empty_table_after_restore"}
                elif cnt != exp:
                    mismatches[t] = {"expected": exp, "actual": cnt, "reason": "row_count_mismatch"}

        if mismatches:
            return {
                "verified": False,
                "error": f"Restored SQLite row count mismatch: {mismatches}",
                "table_counts": actual_counts,
            }
        return {"verified": True, "table_counts": actual_counts}
    finally:
        conn.close()


def _verify_restored_postgres(pg_url: str, expected_counts: Dict[str, int]) -> Dict[str, Any]:
    from sqlalchemy import create_engine, text

    sa_url = pg_url
    if sa_url.startswith("postgres://"):
        sa_url = "postgresql+psycopg2://" + sa_url[len("postgres://"):]
    elif sa_url.startswith("postgresql://"):
        sa_url = "postgresql+psycopg2://" + sa_url[len("postgresql://"):]

    engine = create_engine(sa_url, pool_pre_ping=True, future=True)
    try:
        with engine.connect() as conn:
            existing = {
                r[0]
                for r in conn.execute(
                    text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
                ).fetchall()
            }
            missing = [t for t in _REQUIRED_RESTORE_TABLES if t not in existing]
            if missing:
                return {"verified": False, "error": f"Missing required PostgreSQL tables: {missing}", "table_counts": {}}

            actual_counts: Dict[str, int] = {}
            mismatches: Dict[str, Any] = {}
            for t in _REQUIRED_RESTORE_TABLES:
                cnt = int(conn.execute(text(f"SELECT COUNT(*) FROM {t}")).scalar() or 0)
                actual_counts[t] = cnt
                if t in expected_counts:
                    exp = expected_counts[t]
                    if exp > 0 and cnt == 0:
                        mismatches[t] = {"expected": exp, "actual": cnt, "reason": "empty_table_after_restore"}
                    elif cnt != exp:
                        mismatches[t] = {"expected": exp, "actual": cnt, "reason": "row_count_mismatch"}

            if mismatches:
                return {
                    "verified": False,
                    "error": f"Restored PostgreSQL row count mismatch: {mismatches}",
                    "table_counts": actual_counts,
                }
            return {"verified": True, "table_counts": actual_counts}
    finally:
        engine.dispose()


def _reset_public_schema(pg_url: str) -> Tuple[bool, str]:
    """
    Drop and recreate the `public` schema so a snapshot can be replayed onto a clean slate.

    Replaying a `pg_dump` snapshot is NOT by itself a rollback: the dump only contains
    `DROP TABLE IF EXISTS` for the tables it knows about, so any table created after the
    dump was taken survives. That produced a database that no longer matched
    `core/models.py` while the API still reported `atomic_rollback: True`
    (caught by the CI schema-drift gate on 2026-11-16). Dropping the schema first makes
    the replay authoritative.
    """
    try:
        proc = subprocess.run(
            [
                "psql",
                "--single-transaction",
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                "DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;",
                pg_url,
            ],
            capture_output=True,
            timeout=60,
        )
        if proc.returncode != 0:
            return False, (proc.stderr or b"").decode("utf-8", errors="replace")
        return True, ""
    except Exception as exc:  # pragma: no cover - depends on the server
        return False, str(exc)


def _apply_postgres_sql_file(sql_gz_path: str, pg_url: str, server_ver: int = 0) -> Tuple[bool, str]:
    """Apply a .sql.gz dump to PostgreSQL under --single-transaction."""
    tmp_path = os.path.join(BACKUP_DIR, f".apply_{os.path.basename(sql_gz_path)}.sql")
    try:
        dispose_shared_engine()
        with gzip.open(sql_gz_path, "rt", encoding="utf-8", errors="replace") as gz, open(
            tmp_path, "w", encoding="utf-8", newline="\n"
        ) as sql_out:
            for line in gz:
                if server_ver and server_ver < 170000 and line.lstrip().startswith("SET transaction_timeout"):
                    continue
                sql_out.write(line)
        proc = subprocess.run(
            ["psql", "--single-transaction", "-v", "ON_ERROR_STOP=1", "-f", tmp_path, pg_url],
            capture_output=True,
            check=True,
            timeout=180,
        )
        return True, proc.stdout.decode("utf-8", errors="replace")
    except subprocess.CalledProcessError as cpe:
        err = (cpe.stderr or b"").decode("utf-8", errors="replace")
        return False, err
    except Exception as exc:
        return False, str(exc)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


def _reconverge_runtime_grants(pg_url: str) -> Tuple[bool, str]:
    """Re-apply the least-privilege grant plan after a restore.

    Runs as whoever is doing the restore — which must be the owner (the guard at the top
    of ``restore_backup`` already established that). The grant plan needs only table
    ownership, not ``CREATEROLE``, so it works from this process.

    Returns ``(ok, note)``. A failure here does **not** fail the restore: the data is
    already correct and verified, and refusing at this point would tempt an operator to
    re-run a destructive operation. It is reported in the result and is caught by the
    startup assertion on the next boot, which is the authoritative check.
    """
    try:
        import psycopg2

        from scripts.provision_roles import build_grant_plan

        conn = psycopg2.connect(pg_url)
        conn.autocommit = True
        try:
            plan = build_grant_plan(conn)
            applied = 0
            for statement in plan:
                if statement.startswith("--"):
                    continue
                cur = conn.cursor()
                try:
                    cur.execute(statement)
                    applied += 1
                finally:
                    cur.close()
            return True, f"re-applied {applied} grant statement(s) to the runtime role"
        finally:
            conn.close()
    except Exception as exc:
        logger.error(
            "Could not re-converge runtime grants after restore (%s). The database is "
            "restored but gerege_app's privileges may be broader than the model allows; "
            "run `python scripts/provision_roles.py --apply` before starting the app.",
            type(exc).__name__,
        )
        return False, (
            f"grant re-convergence failed ({type(exc).__name__}); run "
            "scripts/provision_roles.py --apply"
        )


def restore_backup(filename: str, target_db_url: Optional[str] = None) -> Dict[str, Any]:
    """
    Backup файлаас өгөгдлийн санг атомик байдлаар аюулгүй сэргээх (Recovery):
    1. Эхлээд файлын бүрэн бүтэн байдлыг (`verify_backup`) шалгана.
    2. Одоогийн баазыг `pre_restore` нэрээр автоматаар нөөцөлнө.
    3. SQLite (`.db.gz`) үед тусдаа түр бааз дээр бүрэн бүтэн байдал, схем болон мөрийн тоог шалгаад
       `sqlite3.Connection.backup`-аар атомик хуулж, live бааз дээр дахин баталгаажуулна;
       PostgreSQL (`.sql.gz`) үед `psql --single-transaction -v ON_ERROR_STOP=1` ашиглан атомик сэргээж,
       зорилтот PostgreSQL баазаас схем, хүснэгт болон мөрийн тоог бодитоор шалгана.
    4. Баталгаажуулалт унавал `pre_restore` snapshot-оос буцаан бодитоор сэргээнэ (P0 Rollback Fix).
    """
    _assert_maintenance_credential()
    check = verify_backup(filename)
    if not check.get("valid"):
        return {"success": False, "error": check.get("error", "Invalid backup"), "post_restore_verified": False}

    clean_name = os.path.basename(filename)
    fpath = os.path.join(BACKUP_DIR, clean_name)
    expected_counts = _load_expected_counts(fpath)

    # Pre-restore safety snapshot
    pre_snap = create_backup(label="pre_restore")
    if not pre_snap.get("success"):
        return {
            "success": False,
            "error": f"Failed to create pre-restore snapshot: {pre_snap.get('error')}",
            "post_restore_verified": False,
            "rolled_back": False,
            "atomic_rollback": False,
        }

    if clean_name.endswith(".db.gz"):
        tmp_restore = os.path.join(BACKUP_DIR, f".restore_{clean_name}.db")
        try:
            with gzip.open(fpath, "rb") as f_in, open(tmp_restore, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)

            # Verify staging DB (integrity_check + required tables + row counts) BEFORE touching live DB
            staging_check = _verify_restored_sqlite(tmp_restore, expected_counts)
            if not staging_check.get("verified"):
                raise RuntimeError(staging_check.get("error", "Staging DB failed post-restore verification"))

            src_conn = sqlite3.connect(tmp_restore)
            dst_conn = sqlite3.connect(database.DB_PATH)
            with dst_conn:
                src_conn.backup(dst_conn)
            dst_conn.close()
            src_conn.close()

            live_check = _verify_restored_sqlite(database.DB_PATH, expected_counts)
            if not live_check.get("verified"):
                raise RuntimeError(live_check.get("error", "Live SQLite DB failed post-restore verification"))
        except Exception as e:
            logger.error(f"SQLite restore failed ({e}), rolling back from pre_restore snapshot.")
            rollback_ok = False
            pre_name = pre_snap.get("filename")
            if pre_name:
                pre_gz = os.path.join(BACKUP_DIR, pre_name)
                tmp_rb = os.path.join(BACKUP_DIR, f".rb_{pre_name}.db")
                try:
                    with gzip.open(pre_gz, "rb") as f_in, open(tmp_rb, "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)
                    rb_src = sqlite3.connect(tmp_rb)
                    rb_dst = sqlite3.connect(database.DB_PATH)
                    with rb_dst:
                        rb_src.backup(rb_dst)
                    rb_dst.close()
                    rb_src.close()
                    rollback_ok = True
                except Exception as rb_err:
                    logger.error(f"Rollback from pre_restore snapshot failed: {rb_err}")
                finally:
                    if os.path.exists(tmp_rb):
                        try:
                            os.remove(tmp_rb)
                        except Exception:
                            pass
            return {
                "success": False,
                "error": str(e),
                "post_restore_verified": False,
                "rollback_status": "ROLLED_BACK_TO_PRE_SNAPSHOT" if rollback_ok else "ROLLBACK_FAILED",
                "rolled_back": rollback_ok,
                "atomic_rollback": rollback_ok,
                "pre_restore_snapshot": pre_name,
            }
        finally:
            if os.path.exists(tmp_restore):
                try:
                    os.remove(tmp_restore)
                except Exception:
                    pass

        return {
            "success": True,
            "engine": "sqlite",
            "restored_from": clean_name,
            "pre_restore_snapshot": pre_snap.get("filename"),
            "post_restore_verified": True,
            "rolled_back": False,
            "atomic_rollback": False,
            "restored_table_counts": live_check.get("table_counts", {}),
        }

    if clean_name.endswith(".sql.gz"):
        pg_url = (target_db_url or get_database_url()).replace("postgresql+psycopg2://", "postgresql://")
        if not pg_url.startswith(("postgresql://", "postgres://")):
            return {
                "success": False,
                "error": "PostgreSQL target DATABASE_URL is required to restore a .sql.gz backup",
                "post_restore_verified": False,
                "rolled_back": False,
                "atomic_rollback": False,
            }

        server_ver = 0
        try:
            ver_proc = subprocess.run(
                ["psql", "-t", "-A", "-c", "SHOW server_version_num;", pg_url],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if ver_proc.returncode == 0 and ver_proc.stdout.strip().isdigit():
                server_ver = int(ver_proc.stdout.strip())
        except Exception:
            server_ver = 0

        pre_name = pre_snap.get("filename")
        pre_gz = os.path.join(BACKUP_DIR, pre_name) if pre_name else None
        pre_counts = pre_snap.get("table_counts", {})

        # Step 1: Apply SQL dump to PostgreSQL under --single-transaction
        apply_ok, apply_output = _apply_postgres_sql_file(fpath, pg_url, server_ver=server_ver)

        if not apply_ok:
            # SQL execution failed; since --single-transaction was used, check if pre-existing state is intact
            intact_check = _verify_restored_postgres(pg_url, pre_counts)
            if intact_check.get("verified"):
                return {
                    "success": False,
                    "error": f"psql restore execution failed: {apply_output[:400]}",
                    "post_restore_verified": False,
                    "rollback_status": "TRANSACTION_ABORTED_PRE_STATE_PRESERVED",
                    "rolled_back": True,
                    "atomic_rollback": True,
                    "pre_restore_snapshot": pre_name,
                }
            # If not intact, actively recover from pre-restore snapshot
            recovered = False
            if pre_gz and os.path.exists(pre_gz):
                rec_ok, _ = _apply_postgres_sql_file(pre_gz, pg_url, server_ver=server_ver)
                if rec_ok and _verify_restored_postgres(pg_url, pre_counts).get("verified"):
                    recovered = True

            return {
                "success": False,
                "error": f"psql restore execution failed: {apply_output[:400]}",
                "post_restore_verified": False,
                "rollback_status": "ROLLED_BACK_TO_PRE_SNAPSHOT" if recovered else "ROLLBACK_FAILED",
                "rolled_back": recovered,
                "atomic_rollback": recovered,
                "recovery_instruction": None if recovered else f"CRITICAL: Recovery required from {pre_name}",
                "pre_restore_snapshot": pre_name,
            }

        # Step 2: the dump committed. Re-converge the runtime grants BEFORE verifying.
        #
        # A replayed `pg_dump` recreates every table, and the schema's default privileges
        # then hand `gerege_app` full CRUD — including UPDATE and DELETE on `audit_logs`.
        # Measured: after one restore the runtime role could mutate audit history again,
        # and the startup assertion (correctly) refused to boot. Leaving that to the
        # operator's memory would mean "restore then remember to provision", and the
        # failure mode of forgetting is a role that looks provisioned and is not.
        grants_ok, grants_note = _reconverge_runtime_grants(pg_url)

        # Step 2b: verify restored schema, tables, and row counts.
        pg_check = _verify_restored_postgres(pg_url, expected_counts)
        if grants_note:
            pg_check.setdefault("grant_note", grants_note)
        if not pg_check.get("verified"):
            # Post-restore verification failed! Must execute REAL ROLLBACK to pre-restore snapshot.
            ver_err = pg_check.get("error", "PostgreSQL post-restore verification failed")
            logger.warning(
                f"PostgreSQL post-restore verification failed ({ver_err}); executing real rollback to pre_restore snapshot: {pre_name}"
            )
            rollback_ok = False
            if pre_gz and os.path.exists(pre_gz):
                # Replay the snapshot onto a clean schema: the dump cannot drop tables that
                # were created after it was taken, so dropping first is what makes the
                # rollback actually atomic.
                reset_ok, reset_err = _reset_public_schema(pg_url)
                if not reset_ok:
                    logger.error(f"Could not reset schema before rollback: {reset_err}")
                rb_applied, rb_err = _apply_postgres_sql_file(pre_gz, pg_url, server_ver=server_ver)
                if rb_applied:
                    rb_verify = _verify_restored_postgres(pg_url, pre_counts)
                    if rb_verify.get("verified"):
                        rollback_ok = True

            if rollback_ok:
                logger.info(f"PostgreSQL rollback to pre_restore snapshot {pre_name} succeeded.")
                return {
                    "success": False,
                    "error": ver_err,
                    "post_restore_verified": False,
                    "rollback_status": "ROLLED_BACK_TO_PRE_SNAPSHOT",
                    "rolled_back": True,
                    "atomic_rollback": True,
                    "pre_restore_snapshot": pre_name,
                }
            else:
                logger.error(f"PostgreSQL rollback to pre_restore snapshot {pre_name} FAILED!")
                return {
                    "success": False,
                    "error": ver_err,
                    "post_restore_verified": False,
                    "rollback_status": "ROLLBACK_FAILED",
                    "rolled_back": False,
                    "atomic_rollback": False,
                    "recovery_instruction": f"CRITICAL: Automatic rollback failed. Manual recovery required: psql {pg_url} < {pre_name}",
                    "pre_restore_snapshot": pre_name,
                }

        # Restore and verification both succeeded!
        return {
            "success": True,
            "engine": "postgresql",
            "restored_from": clean_name,
            "pre_restore_snapshot": pre_name,
            "post_restore_verified": True,
            "rolled_back": False,
            "atomic_rollback": False,
            "restored_table_counts": pg_check.get("table_counts", {}),
            "details": apply_output[:500],
        }


def prune_old_backups(keep_days: int = 14) -> Dict[str, Any]:
    """Retention Policy: keep_days-ээс хуучин backup файлуудыг автоматаар цэвэрлэх"""
    if not os.path.exists(BACKUP_DIR):
        return {"pruned_count": 0, "pruned_files": []}
    cutoff_ts = time.time() - (max(1, int(keep_days)) * 86400)
    pruned: List[str] = []
    for fname in os.listdir(BACKUP_DIR):
        if not (fname.endswith(".db.gz") or fname.endswith(".sql.gz")):
            continue
        fpath = os.path.join(BACKUP_DIR, fname)
        try:
            if os.path.getmtime(fpath) < cutoff_ts:
                os.remove(fpath)
                for ext in (".sha256", ".meta.json"):
                    if os.path.exists(fpath + ext):
                        os.remove(fpath + ext)
                pruned.append(fname)
        except Exception as e:
            logger.warning(f"Could not prune old backup {fname}: {e}")
    return {"pruned_count": len(pruned), "pruned_files": pruned}
