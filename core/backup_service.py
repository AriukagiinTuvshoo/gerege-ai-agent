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
from typing import Dict, Any, List, Optional

import database
from core.db_engine import is_postgres, get_database_url, dispose_shared_engine

logger = logging.getLogger("core.backup_service")

BACKUP_DIR = os.getenv("BACKUP_DIR", "backups")
SCHEMA_VERSION = "0001_initial_enterprise_schema"


def _compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _collect_db_table_counts() -> Dict[str, int]:
    counts: Dict[str, int] = {}
    conn = database.get_connection()
    cur = conn.cursor()
    for tbl in (
        "pages", "registrations", "messages", "session_states", "sessions",
        "user_memories", "invoices", "cargo_packages", "automated_rules",
        "marketing_campaigns", "sent_followups", "appointments",
        "notification_locks", "task_jobs", "audit_logs",
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
    conn.close()
    return counts


def create_backup(label: str = "manual") -> Dict[str, Any]:
    """
    Өгөгөгдлийн сангийн бүрэн нөөцлөлт (Backup) үүсгэж, gzip шахалт, SHA-256 checksum (.sha256),
    болон метадата манифест (.meta.json) хадгалах.
    SQLite үед online backup API (`sqlite3.Connection.backup`), PostgreSQL үед `pg_dump` ашиглана.
    """
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


def restore_backup(filename: str, target_db_url: Optional[str] = None) -> Dict[str, Any]:
    """
    Backup файлаас өгөгдлийн санг атомик байдлаар аюулгүй сэргээх (Recovery):
    1. Эхлээд файлын бүрэн бүтэн байдлыг (`verify_backup`) шалгана.
    2. Одоогийн баазыг `pre_restore` нэрээр автоматаар нөөцөлнө.
    3. SQLite (`.db.gz`) үед тусдаа түр бааз дээр бүрэн бүтэн байдал, схем болон мөрийн тоог шалгаад
       `sqlite3.Connection.backup`-аар атомик хуулж, live бааз дээр дахин баталгаажуулна;
       PostgreSQL (`.sql.gz`) үед `psql --single-transaction -v ON_ERROR_STOP=1` ашиглан атомик сэргээж,
       зорилтот PostgreSQL баазаас схем, хүснэгт болон мөрийн тоог бодитоор шалгана.
    4. Баталгаажуулалт унавал `pre_restore` snapshot-оос буцаан сэргээнэ.
    """
    check = verify_backup(filename)
    if not check.get("valid"):
        return {"success": False, "error": check.get("error", "Invalid backup"), "post_restore_verified": False}

    clean_name = os.path.basename(filename)
    fpath = os.path.join(BACKUP_DIR, clean_name)
    expected_counts = _load_expected_counts(fpath)

    # Pre-restore safety snapshot
    pre_snap = create_backup(label="pre_restore")

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
                "rolled_back": rollback_ok,
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
            "restored_table_counts": live_check.get("table_counts", {}),
        }

    if clean_name.endswith(".sql.gz"):
        pg_url = (target_db_url or get_database_url()).replace("postgresql+psycopg2://", "postgresql://")
        if not pg_url.startswith(("postgresql://", "postgres://")):
            return {
                "success": False,
                "error": "PostgreSQL target DATABASE_URL is required to restore a .sql.gz backup",
                "post_restore_verified": False,
            }
        try:
            dispose_shared_engine()
            with gzip.open(fpath, "rb") as gz:
                sql_bytes = gz.read()
            proc = subprocess.run(
                ["psql", "--single-transaction", "-v", "ON_ERROR_STOP=1", pg_url],
                input=sql_bytes,
                capture_output=True,
                check=True,
                timeout=180,
            )
            pg_check = _verify_restored_postgres(pg_url, expected_counts)
            if not pg_check.get("verified"):
                raise RuntimeError(pg_check.get("error", "PostgreSQL post-restore verification failed"))

            return {
                "success": True,
                "engine": "postgresql",
                "restored_from": clean_name,
                "pre_restore_snapshot": pre_snap.get("filename"),
                "post_restore_verified": True,
                "restored_table_counts": pg_check.get("table_counts", {}),
                "details": proc.stdout.decode("utf-8", errors="replace")[:500],
            }
        except subprocess.CalledProcessError as e:
            err_detail = (e.stderr or b"").decode("utf-8", errors="replace")[:500]
            logger.error(f"PostgreSQL psql restore failed ({e}): {err_detail}")
            return {
                "success": False,
                "error": f"{e} | stderr: {err_detail}",
                "post_restore_verified": False,
                "atomic_rollback": True,
                "pre_restore_snapshot": pre_snap.get("filename"),
            }
        except Exception as e:
            logger.error(f"PostgreSQL restore failed ({e}); atomic rollback / pre_restore check.")
            return {
                "success": False,
                "error": str(e),
                "post_restore_verified": False,
                "atomic_rollback": True,
                "pre_restore_snapshot": pre_snap.get("filename"),
            }

    return {"success": False, "error": "Unsupported backup format for automatic restore"}


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
