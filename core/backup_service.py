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
from core import backup_archive
from core import backup_crypto
from core import backup_staging
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


def _assert_maintenance_credential(operation: str = "backup") -> None:
    """Refuse to dump/restore as a role that cannot complete the operation.

    Only meaningful on PostgreSQL; SQLite has no roles and its backup path copies a
    file, so it is unaffected. Deliberately raises rather than returning a dict, and
    deliberately does not echo the DSN.

    Phase 18: ``operation`` splits one check into two, because the requirements differ
    and conflating them broke disaster recovery. ``pg_dump`` needs ``LOCK TABLE`` on
    every *existing* table, which means owning all of them — but a **restore into a
    destroyed database has no tables to own**, and the single-condition version of this
    guard therefore refused to restore in precisely the scenario backups exist for.
    A restore instead needs to be able to ``DROP``/``CREATE`` inside the schema, which
    is ownership of the schema (or superuser).
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
        # Phase 22 (P21-10): even a catalog read is bounded. pg_class is normally
        # uncontended, but "normally" is not a bound, and this check runs before every
        # backup, so an unbounded hang here has the same symptom as the reported defect.
        from core import db_bounds

        db_bounds.bound_dbapi_connection(conn)
        cur = conn.cursor()
        # Ask what the role can DO, not what it is called.
        #
        # An earlier version tested `pg_has_role(current_user, 'gerege_owner', 'MEMBER')`.
        # That is wrong twice over: it RAISES when the role does not exist (crashing a
        # cluster where provisioning has not run), and it would refuse a perfectly valid
        # single-credential deployment whose role simply has a different name.
        # ``current_schema()`` is NULL when the search path has no existing schema
        # (for example immediately after ``DROP SCHEMA public; CREATE SCHEMA public;``
        # with a stale search_path). COALESCE keeps the guard from raising instead of
        # reporting: a destroyed database must be reportable, not a crash.
        cur.execute(
            """
            SELECT current_user, r.rolsuper,
                   (SELECT COUNT(*) FROM pg_class c
                      JOIN pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname = COALESCE(current_schema(), 'public') AND c.relkind IN ('r','p')
                       AND pg_get_userbyid(c.relowner) = current_user),
                   (SELECT COUNT(*) FROM pg_class c
                      JOIN pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname = COALESCE(current_schema(), 'public') AND c.relkind IN ('r','p')),
                   (SELECT COUNT(*) FROM pg_namespace n
                     WHERE n.nspname = COALESCE(current_schema(), 'public')
                       AND pg_get_userbyid(n.nspowner) = current_user),
                   COALESCE(has_schema_privilege(COALESCE(current_schema(), 'public')::text, 'CREATE'), false)
              FROM pg_roles r WHERE r.rolname = current_user
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
    user, is_superuser, owned, total, owns_schema, can_create = row

    if operation == "restore":
        # Restoring replays DROP/CREATE. Owning the schema (or being able to CREATE in
        # it) is the requirement; existing tables must also be ours, because the dump
        # drops them. With zero tables the owned==total test is vacuously satisfied,
        # which is what makes a destroyed-database restore possible.
        if is_superuser or ((owns_schema or can_create) and owned == total):
            return
        raise MaintenanceCredentialRequired(
            f"role '{user}' cannot restore into this database: it owns {owned} of {total} "
            "table(s) and does not own the schema or hold CREATE on it. Restore replays "
            "DROP/CREATE, so it would fail part-way.\n"
            "Run restore as the maintenance role instead:\n"
            "  docker compose -f docker-compose.prod.yml run --rm maintenance "
            "python scripts/maintenance.py restore <archive> --yes\n"
            "See docs/operations/BACKUP_ENCRYPTION.md."
        )

    # Backup: a superuser can always dump. Otherwise every table must be owned by this
    # role; owning *some* is not enough, because pg_dump locks all of them.
    if is_superuser or (total > 0 and owned == total):
        return
    if total == 0:
        # An empty schema produces an empty archive. That is not a backup, and silently
        # writing one is the "0-byte backup recorded as success" failure E-05 removed.
        raise MaintenanceCredentialRequired(
            f"role '{user}' cannot create a backup: this schema contains no tables, so the "
            "dump would be empty. If you are recovering, run `restore` instead of `backup`."
        )
    raise MaintenanceCredentialRequired(
        f"role '{user}' cannot create a trustworthy backup: it owns {owned} of "
        f"{total} table(s) in this schema, and pg_dump needs LOCK TABLE on all of them. "
        "It fails with 'permission denied' and leaves an empty archive.\n"
        "Run backup/restore as the maintenance role instead:\n"
        "  docker compose -f docker-compose.prod.yml run --rm maintenance "
        "python scripts/maintenance.py backup\n"
        "  python scripts/maintenance.py backup     (host, DATABASE_OWNER_URL set)\n"
        "See docs/operations/BACKUP_ENCRYPTION.md."
    )


def _compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


#: Tables whose row counts are reported in the backup manifest.
_COUNTED_TABLES = (
    "pages", "registrations", "messages", "session_states", "sessions",
    "user_memories", "invoices", "cargo_packages", "automated_rules",
    "marketing_campaigns", "sent_followups", "appointments",
    "notification_locks", "task_jobs", "audit_logs",
    "comment_automations", "tracked_links",
)


def _collect_db_table_counts(
    deadline: Optional["db_bounds.Deadline"] = None,
    cancel_event: Any = None,
) -> Dict[str, int]:
    """Row counts for the manifest, bounded by a deadline and never faked.

    Phase 22 (P21-10). Three defects are fixed here.

    * **Unbounded.** Every ``SELECT COUNT(*)`` ran on a connection with
      ``statement_timeout = 0``. Under an ``ACCESS EXCLUSIVE`` lock on ``pages`` the first
      count blocked forever and the backup never reached its 120 s dump timeout: Phase 21
      measured 398 s of silence and a harness kill. The session now carries
      ``statement_timeout``/``lock_timeout`` and the whole loop shares one
      :class:`core.db_bounds.Deadline`.
    * **Silent.** ``except Exception: counts[tbl] = 0`` turned a blocked or failed query
      into a plausible zero. A manifest that says ``pages=0`` for a locked table is worse
      than no manifest: it is a false statement about tenant data. A failure now raises.
    * **Unclean.** ``try/finally`` closed the cursor and connection, but a failed statement
      left the transaction open; the context manager rolls back before closing.

    The counts are advisory (they describe what was dumped), so the caller treats a
    timeout as a *failed backup* rather than publishing an archive with a misleading
    manifest. ``deadline=None`` keeps unit callers simple and still applies the session
    bounds.
    """
    from core import db_bounds

    counts: Dict[str, int] = {}
    # SQLite has no server-side timeouts; bounded_session applies none there and the
    # deadline check still runs, so the call is safe on both engines.
    with db_bounds.bounded_session(
        label="table row counts", deadline=deadline, cancel_event=cancel_event
    ) as (conn, dl):
        cur = conn.cursor()
        try:
            for tbl in _COUNTED_TABLES:
                dl.check()
                cur.execute(f"SELECT COUNT(*) FROM {tbl}")
                row = cur.fetchone()
                counts[tbl] = int(row[0] or 0) if row else 0
        finally:
            try:
                cur.close()
            except Exception:
                pass
    return counts


def create_backup(label: str = "manual", staging_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Өгөгдлийн сангийн бүрэн нөөцлөлт (Backup) үүсгэж, gzip шахалт, SHA-256 checksum (.sha256),
    болон метадата манифест (.meta.json) хадгалах.
    SQLite үед online backup API (`sqlite3.Connection.backup`), PostgreSQL үед `pg_dump` ашиглана.

    Phase 18: the dump is written into a private 0700 staging directory first, and only
    moved into ``BACKUP_DIR`` once it is complete. When the caller supplies
    ``staging_dir`` (as the scheduled path does) the plaintext never enters the backup
    directory at all, so an encryption failure downstream cannot leave it behind.

    Phase 20 — the plaintext publication hole is closed *here*, not in the callers.
    Phase 19 found that ``maintenance.py backup``, ``migrate.py``'s pre-migrate snapshot
    and therefore ``deploy.sh``'s pre-deploy rollback point all called this function
    without ``staging_dir``, which fell through to ``dest_path = BACKUP_DIR/...`` and
    published a **plaintext** dump even with ``BACKUP_ENCRYPTION=on``. The policy was
    enforced only in the scheduled caller, so the three commands an operator actually
    types in an incident bypassed it.

    Making callers responsible was rejected: it leaves the insecure default in place and
    every future caller one forgotten argument away from re-opening the leak. Instead
    this function now owns the boundary. When no ``staging_dir`` is supplied it creates
    its own private staging directory, applies the same encryption policy the scheduled
    path uses, and publishes only ciphertext. There is no code path that can publish a
    plaintext archive into ``BACKUP_DIR`` while encryption is required.
    """
    if staging_dir is None:
        return _create_backup_secured(label)
    return _create_backup_dump(label, staging_dir)


def _create_backup_secured(label: str) -> Dict[str, Any]:
    """Run the full secure pipeline for a caller that did not provide staging.

    Dump into private staging → verify → encrypt (policy-enforced) → prove the ciphertext
    authenticates → atomically publish. Plaintext exists only inside a 0700 directory
    that is destroyed on every exit path, so a crash or an encryption failure cannot
    leave tenant data in ``BACKUP_DIR``.

    When encryption is explicitly disabled (``BACKUP_ENCRYPTION=off``, a documented
    non-production mode) the plaintext archive is published as before — but the result is
    flagged ``encryption_format="none"`` and carries a warning, so it is never mistaken
    for an encrypted restore point.
    """
    from core import backup_automation, backup_policy

    # Phase 22 (P21-01): one policy, evaluated before anything touches the database.
    # Phase 20 checked only the key file here and left "may this host write plaintext at
    # all?" to `encryption_required()`, which reads a single variable and does not know
    # what environment it is in - so `ENV=production BACKUP_ENCRYPTION=off` published a
    # full plaintext dump and exited 0. `backup_policy.evaluate()` owns both questions now,
    # and it is a pure function of the environment, so the refusal happens before any
    # tenant row is read.
    policy = backup_policy.evaluate()
    if not policy.allowed:
        return {
            "success": False,
            "error": policy.error,
            "exit_code": policy.exit_code,
            "encryption_policy": policy.code,
            "policy_refused": True,
        }
    encrypting = policy.encrypting
    key_file = backup_policy.key_path()

    staging = backup_staging.StagingDir(BACKUP_DIR)
    try:
        staging.__enter__()
        created = _create_backup_dump(label, staging.path_dir)
        if not created.get("success"):
            created["exit_code"] = 10
            return created

        filename = created["filename"]
        staged_path = os.path.join(staging.path_dir, filename)

        if not encrypting:
            target = os.path.join(BACKUP_DIR, filename)
            staging.publish(staged_path, target)
            # The dump writer creates its sidecars next to the dump, which here is the
            # staging directory; publish them too or the archive arrives without a
            # checksum or manifest.
            for suffix in (".sha256", ".meta.json"):
                staged_sidecar = os.path.join(staging.path_dir, filename + suffix)
                if os.path.exists(staged_sidecar):
                    staging.publish(staged_sidecar, os.path.join(BACKUP_DIR, filename + suffix))
            for published in (target, target + ".sha256", target + ".meta.json"):
                try:
                    os.chmod(published, 0o600)
                except OSError:
                    pass
            created.update(
                path=target,
                encrypted=False,
                encryption_format="none",
                warning="BACKUP_ENCRYPTION is off: the archive is plaintext tenant data",
            )
            return created

        ciphertext_name = filename + backup_archive.ENCRYPTED_SUFFIX
        staged_cipher = staging.path(ciphertext_name)
        ok, error = backup_automation.encrypt_file(staged_path, staged_cipher, key_file)
        if not ok:
            return {"success": False, "error": error, "exit_code": 12, "encryption_failed": True}

        # Prove it authenticates before publishing; an unreadable archive is not a backup.
        roundtrip = staging.path(filename + ".roundtrip")
        ok, error = backup_automation.decrypt_file(staged_cipher, roundtrip, key_file)
        if not ok:
            return {
                "success": False,
                "exit_code": 12,
                "encryption_failed": True,
                "error": f"ciphertext failed its own authentication check: {error}",
            }

        target = os.path.join(BACKUP_DIR, ciphertext_name)
        staging.publish(staged_cipher, target)
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass

        # The manifest names the archive it describes and records the row counts that
        # post-restore verification compares against. Phase 22 found it was written into
        # staging and never published on the encrypted path - only `.sha256` was - so
        # `_load_expected_counts()` returned {} for every encrypted backup and post-restore
        # verification silently had nothing to check beyond "the tables exist". A restore
        # that drops every row then passes. Publish it, rewritten to name the ciphertext.
        staged_meta = staging.path(filename + ".meta.json")
        if os.path.exists(staged_meta):
            try:
                with open(staged_meta, "r", encoding="utf-8") as handle:
                    manifest = json.load(handle)
                manifest["encrypted"] = True
                manifest["archive"] = ciphertext_name
                manifest["ciphertext_sha256"] = _compute_sha256(target)
                published_meta = os.path.join(BACKUP_DIR, ciphertext_name + ".meta.json")
                with open(published_meta, "w", encoding="utf-8") as handle:
                    json.dump(manifest, handle, ensure_ascii=False, indent=2)
                os.chmod(published_meta, 0o600)
                # Keep the plaintext-name manifest too: `verify`/`list` resolve sidecars by
                # the archive name, and both spellings are used across the code base.
                companion = os.path.join(BACKUP_DIR, filename + ".meta.json")
                if companion != published_meta:
                    with open(companion, "w", encoding="utf-8") as handle:
                        json.dump(manifest, handle, ensure_ascii=False, indent=2)
                    os.chmod(companion, 0o600)
            except (OSError, ValueError) as exc:
                logger.warning("could not publish the backup manifest: %s", type(exc).__name__)

        # Rewrite the sidecars so the checksum describes the ciphertext that now exists,
        # not the plaintext that staging is about to destroy (Phase 17's orphaned-checksum
        # bug). The plaintext-name sidecar is kept for compatibility with list/verify.
        digest = _compute_sha256(target)
        for sidecar in {target + ".sha256", os.path.join(BACKUP_DIR, filename + ".sha256")}:
            try:
                with open(sidecar, "w", encoding="utf-8") as handle:
                    handle.write(f"{digest}  {ciphertext_name}\n")
                os.chmod(sidecar, 0o600)
            except OSError:
                pass

        created.update(
            filename=ciphertext_name,
            path=target,
            inner_filename=filename,
            size_bytes=os.path.getsize(target),
            sha256=digest,
            plaintext_sha256=created.get("sha256"),
            encrypted=True,
            encryption_format="authenticated",
        )
        return created
    finally:
        staging.cleanup()


def _create_backup_dump(
    label: str,
    staging_dir: str,
    deadline: Optional["db_bounds.Deadline"] = None,
    cancel_event: Any = None,
) -> Dict[str, Any]:
    """Write the dump itself into ``staging_dir`` and return its manifest.

    Callers reach this only through :func:`create_backup`, which guarantees
    ``staging_dir`` is a private directory. Keeping this split means the dump logic has
    exactly one implementation and cannot be reached with ``staging_dir=None``.
    """
    _assert_maintenance_credential()
    os.makedirs(BACKUP_DIR, exist_ok=True)
    if not staging_dir:
        # Defence in depth: _create_backup_dump is private and only ever called with a
        # real staging directory, but a missing one must never degrade to BACKUP_DIR.
        return {"success": False, "error": "internal error: staged backup requires a staging directory"}
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:18]
    safe_label = "".join(c for c in label if c.isalnum() or c in ("_", "-")) or "backup"
    engine_name = "postgresql" if is_postgres() else "sqlite"
    # Phase 22 (P21-10): the counts are bounded and their failure is fatal. A manifest
    # that says pages=0 for a table it could not read is a false statement about tenant
    # data, and it is exactly what a lock-blocked preflight used to produce.
    from core import db_bounds

    deadline = deadline or db_bounds.Deadline(
        db_bounds.OPERATION_DEADLINE_S, label=f"backup {label}"
    )
    try:
        table_counts = _collect_db_table_counts(deadline=deadline, cancel_event=cancel_event)
    except (db_bounds.BoundedOperationTimeout, db_bounds.BoundedOperationCancelled) as exc:
        logger.error("backup preflight bounds exceeded: %s", exc)
        return {
            "success": False,
            # `exc` already names the step and the bound that fired, so this only adds the
            # consequence: nothing was published and no dump was taken.
            "error": f"database preflight exceeded its deadline - {exc} No archive was published.",

            "exit_code": 17,
            "timeout": True,
        }

    inner_name = (
        f"pg_backup_{safe_label}_{ts}.sql.gz"
        if is_postgres()
        else f"sqlite_backup_{safe_label}_{ts}.db.gz"
    )
    filename = inner_name
    dest_path = os.path.join(staging_dir, inner_name)

    if is_postgres():
        pg_url = get_database_url().replace("postgresql+psycopg2://", "postgresql://")
        # The dump gets what is left of the operation deadline, not a fresh 120 s. Without
        # this the preflight and the dump could each wait out their own bound and the
        # operator would see a hang roughly twice the configured limit.
        try:
            dump_budget = deadline.budget(120.0)
        except Exception as exc:
            return {"success": False, "error": f"deadline exceeded before dump: {exc}",
                    "exit_code": 17, "timeout": True}
        try:
            proc = subprocess.run(
                ["pg_dump", "--clean", "--if-exists", "--no-owner", "--no-privileges", pg_url],
                capture_output=True,
                check=True,
                timeout=dump_budget,
            )
            with gzip.open(dest_path, "wb") as gz:
                gz.write(proc.stdout)
        except subprocess.TimeoutExpired:
            logger.error("pg_dump exceeded its %.1fs budget", dump_budget)
            return {
                "success": False,
                "error": (
                    f"pg_dump did not finish within {dump_budget:.0f}s. The deadline is "
                    f"BACKUP_DB_OPERATION_DEADLINE ({db_bounds.OPERATION_DEADLINE_S:.0f}s). "
                    f"Nothing was published."
                ),
                "exit_code": 17,
                "timeout": True,
            }
        except Exception as e:
            logger.error(f"PostgreSQL pg_dump failed: {e}")
            return {"success": False, "error": str(e)}
    else:
        raw_temp = dest_path + ".raw.tmp"
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

    # Phase 18: a dump is tenant data; never let it be born world-readable.
    for _p in (dest_path,):
        try:
            os.chmod(_p, 0o600)
        except OSError:
            pass

    sha256_hex = _compute_sha256(dest_path)
    with open(dest_path + ".sha256", "w", encoding="utf-8") as sf:
        sf.write(f"{sha256_hex}  {filename}\n")
    try:
        os.chmod(dest_path + ".sha256", 0o600)
    except OSError:
        pass

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
    # Phase 20: Phase 19 found the manifest written 0644 while the dump itself was 0600.
    # It carries the schema version and an exact table/row-count inventory — useful to an
    # attacker sizing the target — so it is tenant-adjacent data and gets the same mode.
    try:
        os.chmod(dest_path + ".meta.json", 0o600)
    except OSError:
        pass

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
    """Хадгалагдсан backup файлуудын жагсаалтыг буцаах.

    Phase 18: encrypted archives (``.enc``) are listed too, with their encryption format
    and whether the ciphertext is authenticated. Phase 17 found this function filtering
    them out, which made ``maintenance.py list`` report "no backups" while a full set of
    encrypted archives sat in the directory — and made ``rollback.sh`` resolve its
    pre-deploy snapshot to the empty string.
    """
    if not os.path.exists(BACKUP_DIR):
        return []
    items: List[Dict[str, Any]] = []
    # Newest first by mtime. Phase 18: the previous lexical sort ordered by *label*
    # before date, so "newest" was not actually newest once more than one label existed.
    candidates = [f for f in os.listdir(BACKUP_DIR) if not f.startswith(".")]
    try:
        candidates.sort(key=lambda f: os.path.getmtime(os.path.join(BACKUP_DIR, f)), reverse=True)
    except OSError:
        candidates.sort(reverse=True)
    for fname in candidates:
        if fname.startswith("."):
            continue
        if not backup_archive.is_archive_name(fname):
            continue
        fpath = os.path.join(BACKUP_DIR, fname)
        if not os.path.isfile(fpath):
            continue
        # Sidecars are named after the inner (plaintext) archive even when the ciphertext
        # is what survives on disk; look both up.
        inner = fname[: -len(backup_archive.ENCRYPTED_SUFFIX)] if backup_archive.is_encrypted_name(fname) else fname
        sha_path = os.path.join(BACKUP_DIR, inner + ".sha256")
        meta_path = os.path.join(BACKUP_DIR, inner + ".meta.json")
        sha_val = ""
        meta_obj: Dict[str, Any] = {}
        if os.path.exists(sha_path):
            try:
                fields = open(sha_path, "r", encoding="utf-8").read().split()
                sha_val = fields[0] if fields else ""
            except Exception:
                sha_val = ""
        if os.path.exists(meta_path):
            try:
                meta_obj = json.loads(open(meta_path, "r", encoding="utf-8").read())
            except Exception:
                meta_obj = {}
        encrypted = backup_archive.is_encrypted_name(fname)
        info = {
            "filename": fname,
            "size_bytes": os.path.getsize(fpath),
            "sha256": sha_val,
            "engine": meta_obj.get("engine") or ("postgresql" if inner.endswith(".sql.gz") else "sqlite"),
            "schema_version": meta_obj.get("schema_version", SCHEMA_VERSION),
            "table_counts": meta_obj.get("table_counts", {}),
            "modified_at": datetime.fromtimestamp(os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M:%S"),
            "encrypted": encrypted,
            "label": meta_obj.get("label", ""),
        }
        if encrypted:
            fmt = backup_archive.encryption_format(fpath)
            info["encryption_format"] = fmt
            # Only the authenticated format carries a cryptographic integrity guarantee.
            info["authenticated"] = fmt == "authenticated"
        else:
            info["encryption_format"] = "none"
            info["authenticated"] = False
        items.append(info)
    return items


def _key_file() -> Optional[str]:
    path = os.getenv("BACKUP_ENCRYPTION_KEY_FILE", "").strip()
    return path or None


def verify_backup(filename: str, key_file: Optional[str] = None) -> Dict[str, Any]:
    """Verify one archive, decrypting it when it is encrypted.

    Phase 18: an ``.enc`` archive is verified by *authenticating the ciphertext*, not by
    checking a gzip CRC after a blind decryption. For the authenticated format a wrong
    key, a flipped bit, a truncated file and a forged stream all fail here with a nonzero
    result. ``valid`` is only ever True when the bytes decrypted were proven to be the
    bytes that were encrypted.
    """
    clean_name = os.path.basename(filename)
    fpath = os.path.join(BACKUP_DIR, clean_name)
    if not os.path.exists(fpath):
        return {"valid": False, "error": "Backup file not found"}
    if not backup_archive.is_archive_name(clean_name):
        return {"valid": False, "error": "Unsupported backup file extension"}
    if os.path.getsize(fpath) == 0:
        return {"valid": False, "error": "Backup file is empty (0 bytes)"}

    encrypted = backup_archive.is_encrypted_name(clean_name)

    # Phase 18: checksum the file that is actually on disk. For a plaintext archive that
    # is the dump itself; for an encrypted one it is the ciphertext, and the sidecar is
    # rewritten to match after encryption so it can still be checked months later.
    inner_name = clean_name[: -len(backup_archive.ENCRYPTED_SUFFIX)] if encrypted else clean_name
    actual_sha = _compute_sha256(fpath)
    sha_candidates = [os.path.join(BACKUP_DIR, clean_name + ".sha256")]
    if encrypted:
        sha_candidates.append(os.path.join(BACKUP_DIR, inner_name + ".sha256"))
    for sha_path in sha_candidates:
        if not os.path.exists(sha_path):
            continue
        try:
            expected_sha = open(sha_path, "r", encoding="utf-8").read().split()[0]
        except Exception:
            expected_sha = ""
        # A sidecar that hashes the *deleted plaintext* cannot validate ciphertext; the
        # scheduled path rewrites it, so a stale one is a real integrity signal.
        if expected_sha and expected_sha != actual_sha:
            return {
                "valid": False,
                "error": "SHA-256 checksum mismatch (the archive on disk is not the one that was recorded)",
            }

    if encrypted:
        key = key_file or _key_file()
        try:
            with backup_archive.resolve(BACKUP_DIR, clean_name, key) as resolved:
                inner_check = _verify_plaintext_dump(resolved.plaintext_path, inner_name)
                if not inner_check.get("valid"):
                    return inner_check
                result = {
                    "valid": True,
                    "filename": clean_name,
                    "sha256": actual_sha,
                    "encrypted": True,
                    "encryption_format": resolved.format,
                    "authenticated": resolved.authenticated,
                }
                if not resolved.authenticated:
                    result["warning"] = (
                        "legacy openssl format: the ciphertext carries no authentication tag; "
                        "integrity rests on the SHA-256 sidecar and the gzip CRC only"
                    )
                return result
        except backup_archive.ArchiveError as exc:
            return {"valid": False, "error": str(exc)}

    result = _verify_plaintext_dump(fpath, clean_name)
    if result.get("valid"):
        result.update(sha256=actual_sha, encrypted=False, encryption_format="none", authenticated=False)
    return result


def _verify_plaintext_dump(fpath: str, clean_name: str) -> Dict[str, Any]:
    """Structure check for a plaintext dump (the part verify_backup always did)."""
    if clean_name.endswith(".db.gz"):
        tmp_check = os.path.join(BACKUP_DIR, f".verify_{os.path.basename(clean_name)}.db")
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

    return {"valid": True, "filename": clean_name}


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


def _as_sqlalchemy_postgres_url(url: str) -> str:
    """Normalize a libpq-style URL to the SQLAlchemy + psycopg2 form.

    `_apply_postgres_sql_file` and friends take `postgres://`/`postgresql://` URLs, while
    `create_engine` in this codebase needs the explicit driver. Raises on anything that is
    not PostgreSQL rather than silently handing SQLite to a PostgreSQL check.
    """
    if url.startswith("postgres://"):
        return "postgresql+psycopg2://" + url[len("postgres://"):]
    if url.startswith("postgresql://") and "+" not in url.split("://", 1)[0]:
        return "postgresql+psycopg2://" + url[len("postgresql://"):]
    if url.startswith("postgresql+psycopg2://"):
        return url
    raise ValueError("expected a PostgreSQL URL for a rollback invariant check")


def _rollback_invariants(pg_url: str) -> Dict[str, Any]:
    """Post-rollback checks that a row-count comparison cannot make.

    Phase 21 (P21-07) observed a failed rollback that left the database reportable as
    drifted: `verify_schema_drift()` returned ``has_drift=True`` after the operator had
    replayed the pre-restore snapshot by hand. Reporting ``ROLLED_BACK_TO_PRE_SNAPSHOT``
    on row counts alone would have been a false success claim about a database whose schema
    no longer matched the models.

    Checks, each independently meaningful:

    ``schema``      live schema vs `core/models.py` (types, indexes, constraints)
    ``ownership``   every public table owned by the owner role (a reset recreates them)
    ``grants``      the runtime role still holds privileges (a reset drops every GRANT)

    Returns a dict with ``all_ok`` and a list of human-readable ``failures``. A failure is
    not fatal to the process; it downgrades the rollback status to RECOVERY_REQUIRED so an
    operator knows the database is not provably in its pre-restore shape.
    """
    from core import db_bounds

    failures: List[str] = []
    detail: Dict[str, Any] = {}

    # 1. Schema drift. Alembic autogenerate with compare_type, against the live database.
    #
    # The engine is passed EXPLICITLY. `verify_schema_drift()` with no argument inspects
    # whatever `DATABASE_URL` happens to be in the process environment, which during a
    # restore is not necessarily the database being restored - the negative control for
    # this check returned "no drift" while a column had just been added to the target,
    # because it was comparing SQLite against the models. A check that can pass without
    # looking at the thing it is checking is worse than no check.
    try:
        from core.schema_manager import drift_report
        from core.db_bounds import CONNECT_TIMEOUT_S
        from sqlalchemy import create_engine as _create_engine

        _drift_engine = _create_engine(
            _as_sqlalchemy_postgres_url(pg_url), future=True,
            connect_args={"connect_timeout": int(CONNECT_TIMEOUT_S)},
        )
        try:
            _raw = drift_report(_drift_engine)
        finally:
            _drift_engine.dispose()
        # Normalize: drift_report() reports the total under "count"; the older
        # verify_schema_drift() wrapper called it "diff_count". Accept either.
        drift = {
            "has_drift": _raw.get("has_drift", True),
            "diff_count": _raw.get("count", _raw.get("diff_count")),
        }
        detail["schema"] = {"has_drift": drift.get("has_drift"),
                            "diff_count": drift.get("diff_count")}
        if drift.get("has_drift"):
            failures.append(
                f"schema drift after rollback: {drift.get('diff_count')} difference(s) "
                f"from core/models.py"
            )
    except Exception as exc:  # pragma: no cover - diagnostic path
        detail["schema"] = {"error": type(exc).__name__}
        failures.append(f"could not check schema drift: {type(exc).__name__}")

    # 2 & 3. Ownership and privileges, in one bounded query.
    try:
        from sqlalchemy import create_engine, text

        engine = create_engine(
            _as_sqlalchemy_postgres_url(pg_url), pool_pre_ping=True, future=True,
            connect_args={"connect_timeout": int(db_bounds.CONNECT_TIMEOUT_S)},
        )
        try:
            with engine.connect() as conn:
                db_bounds.bound_sqlalchemy_connection(conn)
                unowned = conn.execute(text(
                    "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                    "WHERE n.nspname='public' AND c.relkind IN ('r','p') "
                    "AND pg_get_userbyid(c.relowner) <> current_user"
                )).scalar()
                detail["ownership"] = {"tables_not_owned_by_current_role": int(unowned or 0)}
                if unowned:
                    failures.append(
                        f"{unowned} public table(s) are not owned by the current role; a "
                        f"rollback recreated them under a different owner"
                    )

                # The runtime role must still be able to read a representative table.
                runtime_role = os.getenv("GEREGE_RUNTIME_ROLE", "gerege_app")
                exists = conn.execute(
                    text("SELECT count(*) FROM pg_roles WHERE rolname = :r"), {"r": runtime_role}
                ).scalar()
                if exists:
                    can_select = conn.execute(text(
                        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                        "WHERE n.nspname='public' AND c.relkind='r' "
                        f"AND has_table_privilege(:r, c.oid, 'SELECT')"
                    ), {"r": runtime_role}).scalar()
                    total = conn.execute(text(
                        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                        "WHERE n.nspname='public' AND c.relkind='r'"
                    )).scalar()
                    detail["grants"] = {"runtime_role": runtime_role,
                                        "tables_selectable": int(can_select or 0),
                                        "tables": int(total or 0)}
                    if total and can_select != total:
                        failures.append(
                            f"runtime role {runtime_role} can SELECT only "
                            f"{can_select}/{total} tables; grants did not survive the rollback"
                        )
                else:
                    detail["grants"] = {"runtime_role": runtime_role, "present": False}
        finally:
            engine.dispose()
    except Exception as exc:  # pragma: no cover - diagnostic path
        detail["ownership"] = {"error": type(exc).__name__}
        failures.append(f"could not check ownership/grants: {type(exc).__name__}")

    return {
        "all_ok": not failures,
        "checked": True,
        "failures": failures,
        "detail": detail,
    }


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

    from core import db_bounds

    engine = create_engine(
        sa_url,
        pool_pre_ping=True,
        future=True,
        # A restore verification is a bounded operation: it must not wait out a lock held
        # by a stray session, and the connect itself must not hang silently.
        connect_args={"connect_timeout": int(db_bounds.CONNECT_TIMEOUT_S)},
    )
    try:
        with engine.connect() as conn:
            # Phase 22 (P21-10): every statement below counts user tables. Under an
            # ACCESS EXCLUSIVE lock the old code blocked here with no bound at all.
            db_bounds.bound_sqlalchemy_connection(conn)
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
        # Phase 20 rewrote this. The previous implementation ran
        #     DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;
        # as the *restoring* role. On any normal cluster `public` is owned by the bootstrap
        # superuser (it is created by initdb), so that statement failed with "must be owner
        # of schema public" **every time**. The caller logged the failure and replayed
        # anyway, which is why the rollback looked like it worked while the schema was
        # never actually reset — and why, after the schema *was* eventually recreated in
        # one test run, `gerege_owner` lost the ability to GRANT on it and the app could no
        # longer read its own tables.
        #
        # The owner does not need to own `public`; it needs the schema to contain exactly
        # the objects the snapshot has. Dropping every table/view/sequence/function the
        # owner owns achieves that with privileges the least-privilege model actually
        # grants, and it never touches the schema itself, so grants and ownership of
        # `public` survive.
        #
        # `DROP ... CASCADE` takes ACCESS EXCLUSIVE, so it queues behind any open session
        # (a pooling app, a test harness, a psql left open). A bounded lock_timeout makes
        # it fail fast and report honestly instead of hanging during an incident.
        # All statements go in ONE psql invocation: `SET lock_timeout` is session-local, so
        # issuing the SET in a separate call would leave the drops unbounded and the reset
        # would hang exactly as it did before (241 s in CI).
        # Every object in `public` must go, not just the ones the connecting role happens
        # to own. `pg_dump` refuses to run unless the maintenance role owns every table it
        # will lock, so in a correctly-provisioned database those are the same set — but a
        # cluster where migrations were applied by the bootstrap role (which is exactly how
        # CI and a fresh install converge) leaves tables owned by *someone else*. Filtering
        # on `current_user` silently dropped nothing there, and because the script exited 0
        # the caller believed the schema had been reset and replayed the snapshot over live
        # tables. Prefer an honest failure over a silent no-op: if an object cannot be
        # dropped, the DROP raises, psql exits non-zero, and the caller reports that it could
        # not reset the schema instead of pretending it did.
        #
        # `DROP ... CASCADE` takes ACCESS EXCLUSIVE, so it queues behind any open session
        # (a pooling app, a test harness, a psql left open). A bounded lock_timeout makes
        # it fail fast and report honestly instead of hanging during an incident - that hang
        # was real: 180 s in CI, and it turned a recoverable rollback into ROLLBACK_FAILED.
        #
        # All statements go in ONE psql invocation because `SET lock_timeout` is
        # session-local; issuing it separately leaves the drops unbounded.
        script = "; ".join(
            [
                "SET lock_timeout = '10s'",
                "SET statement_timeout = '50s'",
                # Views and materialised views first: they may depend on the tables below.
                "DO $$ DECLARE r record; BEGIN "
                "FOR r IN SELECT c.relname FROM pg_class c "
                "  JOIN pg_namespace n ON n.oid = c.relnamespace "
                " WHERE n.nspname = 'public' AND c.relkind IN ('v','m') LOOP "
                "  EXECUTE format('DROP VIEW IF EXISTS public.%I CASCADE', r.relname); "
                "END LOOP; END $$",
                "DO $$ DECLARE r record; BEGIN "
                "FOR r IN SELECT c.relname FROM pg_class c "
                "  JOIN pg_namespace n ON n.oid = c.relnamespace "
                " WHERE n.nspname = 'public' AND c.relkind IN ('r','p','f') LOOP "
                "  EXECUTE format('DROP TABLE IF EXISTS public.%I CASCADE', r.relname); "
                "END LOOP; END $$",
                "DO $$ DECLARE r record; BEGIN "
                "FOR r IN SELECT c.relname FROM pg_class c "
                "  JOIN pg_namespace n ON n.oid = c.relnamespace "
                " WHERE n.nspname = 'public' AND c.relkind = 'S' LOOP "
                "  EXECUTE format('DROP SEQUENCE IF EXISTS public.%I CASCADE', r.relname); "
                "END LOOP; END $$",
                "DO $$ DECLARE r record; BEGIN "
                "FOR r IN SELECT p.oid::regprocedure AS sig FROM pg_proc p "
                "  JOIN pg_namespace n ON n.oid = p.pronamespace "
                " WHERE n.nspname = 'public' LOOP "
                "  EXECUTE format('DROP FUNCTION IF EXISTS %s CASCADE', r.sig); "
                "END LOOP; END $$",
            ]
        )
        from core import db_bounds

        # Phase 22 (P21-10): bound the server side as well as the subprocess. DROP TABLE
        # waits for its lock; without a lock_timeout the destructive step can burn the
        # whole 120 s subprocess budget queued behind another session and then fail with
        # no useful diagnostic.
        guarded_script = (
            f"SET lock_timeout = {db_bounds._ms(db_bounds.LOCK_TIMEOUT_S)};\n"
            f"SET statement_timeout = {db_bounds._ms(max(db_bounds.STATEMENT_TIMEOUT_S, 55.0))};\n"
            + script
        )
        proc = subprocess.run(
            ["psql", "-v", "ON_ERROR_STOP=1", "-c", guarded_script, pg_url],
            capture_output=True,
            timeout=120,
        )
        if proc.returncode != 0:
            return False, (proc.stderr or b"").decode("utf-8", errors="replace")

        # Post-condition: prove the schema is actually empty. Exit status alone is not
        # evidence - the previous implementation returned 0 while dropping nothing, and the
        # caller replayed a snapshot over live tables on the strength of that 0.
        check = subprocess.run(
            [
                "psql",
                "-tA",
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'public' AND c.relkind IN ('r','p','v','m','S','f')",
                pg_url,
            ],
            capture_output=True,
            timeout=60,
        )
        if check.returncode != 0:
            return False, (check.stderr or b"").decode("utf-8", errors="replace")
        remaining = (check.stdout or b"").decode("utf-8", errors="replace").strip()
        if remaining not in ("0", ""):
            return False, (
                f"{remaining} relation(s) still present in schema 'public' after DROP; "
                "the schema was NOT clean and the snapshot must not be replayed over it"
            )
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
                # `COMMENT ON SCHEMA public` is an ownership assertion, not data. Dropping
                # it is what makes a restore-as-owner work on a normal cluster; the
                # schema's own comment is cosmetic and is restored by nothing that matters.
                if line.lstrip().upper().startswith("COMMENT ON SCHEMA PUBLIC"):
                    continue
                sql_out.write(line)
        # Phase 18: `pg_dump` emits `COMMENT ON SCHEMA public IS ''`, and only the
        # schema's owner may execute that. On a cluster where `public` belongs to the
        # bootstrap account (the normal case — it is created by initdb/the first
        # superuser), restoring as `gerege_owner` therefore failed with
        # "must be owner of schema public" *on every restore into an existing database*,
        # not just during rollback. The comment carries no data, so it is dropped along
        # with the transaction_timeout line for older servers.
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


def _database_is_empty() -> bool:
    """True when the target schema holds no user tables (a destroyed or fresh database)."""
    try:
        from core.db_engine import is_postgres

        if not is_postgres():
            return not os.path.exists(database.DB_PATH) or os.path.getsize(database.DB_PATH) == 0
        from core.db_engine import get_db_connection

        from core import db_bounds

        conn = get_db_connection()
        try:
            # Bounded: this check decides whether a snapshot is needed before a
            # destructive reset, so a hang here blocks the recovery path itself.
            db_bounds.bound_dbapi_connection(conn)
            cur = conn.cursor()
            cur.execute(
                """
                SELECT COUNT(*) FROM pg_class c
                  JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = COALESCE(current_schema(), 'public')
                   AND c.relkind IN ('r','p')
                """
            )
            total = cur.fetchone()[0]
            cur.close()
            return int(total) == 0
        finally:
            conn.close()
    except Exception:
        # If we cannot tell, assume non-empty so the snapshot is still attempted.
        return False


def _create_pre_restore_snapshot() -> Dict[str, Any]:
    """Snapshot the current database before a restore, encrypted like any other backup.

    Phase 18: this used to call ``create_backup`` directly, which writes a **plaintext**
    dump into ``BACKUP_DIR``. The pre-restore snapshot is a full copy of every tenant's
    data, so leaving it unencrypted re-introduced the exact leak the scheduled path was
    fixed for -- and it did so at the worst moment, during an incident. The snapshot now
    goes through the same staging + authenticated-encryption path as a scheduled run.
    """
    from core import backup_automation

    staging = backup_staging.StagingDir(BACKUP_DIR, prefix=".staging-")
    staging.__enter__()
    try:
        created = create_backup(label="pre_restore", staging_dir=staging.path_dir)
        if not created.get("success"):
            return created
        filename = created["filename"]
        staged = os.path.join(staging.path_dir, filename)

        key = backup_automation._key_path()
        if backup_automation.encryption_required() and key:
            ciphertext_name = filename + backup_archive.ENCRYPTED_SUFFIX
            staged_cipher = staging.path(ciphertext_name)
            ok, error = backup_automation.encrypt_file(staged, staged_cipher, key)
            if not ok:
                return {"success": False, "error": f"pre-restore snapshot encryption failed: {error}"}
            target = os.path.join(BACKUP_DIR, ciphertext_name)
            staging.publish(staged_cipher, target)
            os.chmod(target, 0o600)
            digest = backup_automation._publish_ciphertext_checksum(BACKUP_DIR, target)
            created["filename"] = ciphertext_name
            created["sha256"] = digest
            created["encrypted"] = True
            return created

        # Encryption explicitly disabled: publish the plaintext, 0600.
        target = os.path.join(BACKUP_DIR, filename)
        staging.publish(staged, target)
        os.chmod(target, 0o600)
        return created
    finally:
        staging.cleanup()


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
    _assert_maintenance_credential("restore")
    # Phase 20: restore now takes the same directory lock as backup and prune.
    #
    # Phase 19 showed the lock message promised "backup, prune or restore is already
    # running" while only the scheduled backup path ever acquired it. A restore therefore
    # ran happily through a held lock, and a concurrent prune could unlink the archive it
    # was reading (prune selects by mtime and knows nothing about in-flight readers).
    #
    # Lock ordering is deliberately trivial — one lock, at most one holder:
    #     BACKUP_DIR/.backup.lock  ->  everything else
    # No code path takes a second lock while holding this one, so there is no cycle and
    # therefore no deadlock. flock() is released by the kernel on process death, so a
    # SIGKILL cannot wedge the system.
    try:
        with backup_staging.backup_lock(BACKUP_DIR):
            return _restore_backup_locked(filename, target_db_url)
    except backup_staging.LockUnavailable as exc:
        return {
            "success": False,
            "locked": True,
            "error": f"{exc}. A restore, backup or prune is using this backup directory; retry when it finishes.",
            "post_restore_verified": False,
        }


def _restore_backup_locked(filename: str, target_db_url: Optional[str]) -> Dict[str, Any]:
    check = verify_backup(filename)
    if not check.get("valid"):
        return {"success": False, "error": check.get("error", "Invalid backup"), "post_restore_verified": False}

    clean_name = os.path.basename(filename)
    encrypted = backup_archive.is_encrypted_name(clean_name)
    # Phase 18: encrypted archives are decrypted to a private temp file here and the
    # existing (verified) restore machinery operates on that. The plaintext exists only
    # inside a 0700 staging directory for the duration of the restore.
    try:
        resolved = backup_archive.resolve(BACKUP_DIR, clean_name, _key_file())
        resolved.__enter__()
    except backup_archive.ArchiveError as exc:
        return {
            "success": False,
            "error": str(exc),
            "post_restore_verified": False,
            "rolled_back": False,
            "atomic_rollback": False,
        }
    try:
        return _restore_resolved(resolved, clean_name, encrypted, target_db_url, check)
    finally:
        resolved.__exit__(None, None, None)


def _restore_resolved(resolved, clean_name: str, encrypted: bool, target_db_url, check) -> Dict[str, Any]:
    """Restore from a resolved (already decrypted when needed) archive."""
    fpath = resolved.plaintext_path
    restore_name = os.path.basename(fpath)
    expected_counts = _load_expected_counts(os.path.join(BACKUP_DIR, clean_name))
    if not expected_counts and encrypted:
        expected_counts = _load_expected_counts(fpath)

    # Pre-restore safety snapshot.
    #
    # Phase 18: this is skipped when the target database is empty. A restore into a
    # destroyed database is the primary disaster scenario -- there is nothing to snapshot,
    # and treating "cannot snapshot" as fatal turned the recovery operation into a no-op
    # in exactly the case it exists for. The snapshot still protects every restore onto a
    # populated database, where pre-restore state is the thing worth preserving.
    pre_snap: Dict[str, Any]
    if _database_is_empty():
        pre_snap = {"success": True, "skipped": True, "filename": None, "table_counts": {}}
    else:
        pre_snap = _create_pre_restore_snapshot()
        if not pre_snap.get("success"):
            return {
                "success": False,
                "error": f"Failed to create pre-restore snapshot: {pre_snap.get('error')}",
                "post_restore_verified": False,
                "rolled_back": False,
                "atomic_rollback": False,
            }

    if restore_name.endswith(".db.gz"):
        tmp_restore = os.path.join(BACKUP_DIR, f".restore_{restore_name}.db")
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
            "restored_from_encrypted": encrypted,
            "archive_integrity": check.get("encryption_format", "none"),
            "archive_authenticated": check.get("authenticated", False),
        }

    if restore_name.endswith(".sql.gz"):
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

        # Phase 20: the pre-restore snapshot is an *encrypted* archive (`.sql.gz.enc`),
        # but every rollback path below hands ``pre_gz`` straight to
        # ``_apply_postgres_sql_file``, which gzip-reads it. gzip on ciphertext fails, so
        # the automatic rollback could never work once Phase 18 started encrypting the
        # snapshot: it logged "rollback ... FAILED", returned ROLLBACK_FAILED, and left the
        # damaged restore in place. The CI suite did not catch it because the shared test
        # database had already been emptied by an earlier case, so the snapshot step was
        # skipped entirely and the failure never ran.
        #
        # Plaintext is materialised for the duration of the rollback only, inside a 0700
        # directory, and destroyed afterwards.
        # StagingDir registers an atexit hook and a SIGTERM guard in __enter__, so the
        # decrypted copy is removed even if this function returns early or the process is
        # signalled; the explicit cleanup at each exit makes it prompt for the normal case.
        pre_stage = backup_staging.StagingDir(BACKUP_DIR)
        pre_replay = pre_gz
        if pre_gz and os.path.exists(pre_gz) and backup_archive.is_encrypted_name(pre_gz):
            pre_stage.__enter__()
            plaintext = pre_stage.path(os.path.basename(pre_gz)[: -len(backup_archive.ENCRYPTED_SUFFIX)])
            try:
                backup_crypto.decrypt_file(pre_gz, plaintext, _key_file())
                pre_replay = plaintext
            except Exception as exc:
                pre_stage.cleanup()
                pre_replay = None
                logger.error(
                    "cannot decrypt the pre-restore snapshot for replay (%s); the snapshot "
                    "exists but this build cannot use it", type(exc).__name__,
                )

        # Step 1: Apply SQL dump to PostgreSQL under --single-transaction
        apply_ok, apply_output = _apply_postgres_sql_file(fpath, pg_url, server_ver=server_ver)

        if not apply_ok:
            # SQL execution failed; since --single-transaction was used, check if pre-existing state is intact
            intact_check = _verify_restored_postgres(pg_url, pre_counts)
            if intact_check.get("verified"):
                pre_stage.cleanup()
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
            if pre_replay and os.path.exists(pre_replay):
                rec_ok, _ = _apply_postgres_sql_file(pre_replay, pg_url, server_ver=server_ver)
                if rec_ok and _verify_restored_postgres(pg_url, pre_counts).get("verified"):
                    # Same grant problem as the rollback path below: the replay restores
                    # objects, not the least-privilege grants they had.
                    _reconverge_runtime_grants(pg_url)
                    recovered = True

            pre_stage.cleanup()
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
            if pre_replay and os.path.exists(pre_replay):
                # Replay the snapshot onto a clean schema: the dump cannot drop tables that
                # were created after it was taken, so dropping first is what makes the
                # rollback actually atomic.
                reset_ok, reset_err = _reset_public_schema(pg_url)
                if not reset_ok:
                    # Phase 20: this used to be logged and then IGNORED. The replay would
                    # run against a schema that still held the failed restore's tables, so
                    # `pg_dump --clean` could not drop them, the replay blocked on their
                    # locks until psql's own 180 s timeout, and restore_backup reported
                    # ROLLBACK_FAILED — while the operator was told only "rollback failed",
                    # with no hint that a stale client connection was the cause. Not replaying
                    # is the honest, safe outcome: the pre-restore snapshot is untouched and
                    # still on disk, and the caller gets a precise recovery instruction.
                    logger.error(
                        "Could not reset schema before rollback (%s). Pre-restore snapshot "
                        "preserved for manual recovery: %s",
                        reset_err.strip(), pre_name,
                    )
                    pre_stage.cleanup()
                    return {
                        "success": False,
                        "error": ver_err,
                        "post_restore_verified": False,
                        "rollback_status": "RECOVERY_REQUIRED",
                        "rolled_back": False,
                        "atomic_rollback": False,
                        "recovery_required": True,
                        "state_unknown": True,
                        # Phase 18: never interpolate the DSN. Diagnostics only.
                        "rollback_error": (
                            "Could not reset the schema before replaying the pre-restore "
                            f"snapshot: {reset_err.strip().splitlines()[-1] if reset_err.strip() else 'unknown error'}. "
                            "A session holding locks on the schema blocks a clean rollback — "
                            "usually an application or psql client left 'idle in transaction'. "
                            "Disconnect clients, then replay the snapshot with maintenance.py restore."
                        ),
                        "recovery_instruction": (
                            "CRITICAL: Automatic rollback could not run and manual recovery is "
                            f"required. Snapshot: {pre_name}. Replay it with maintenance.py restore "
                            "(the connection string is intentionally omitted from this message)."
                        ),
                        "pre_restore_snapshot": pre_name,
                    }
                rb_applied, rb_err = _apply_postgres_sql_file(pre_replay, pg_url, server_ver=server_ver)
                if rb_applied:
                    # Phase 20: `_reset_public_schema` recreates `public` from scratch, so
                    # every GRANT the runtime role held was destroyed with it. Replaying
                    # pg_dump output as the owner restores objects but not the
                    # least-privilege grants — `--no-privileges` is passed deliberately.
                    # Without this the database is data-correct and permission-broken: the
                    # rollback "succeeds", then the application gets "permission denied"
                    # on every table. Phase 20 caught it because the suite's own
                    # post-rollback requests began returning 500s.
                    grants_ok, grants_note = _reconverge_runtime_grants(pg_url)
                    if not grants_ok:
                        logger.error(
                            "rollback restored the data but could not re-converge runtime "
                            "grants (%s); the application will fail until "
                            "`scripts/provision_roles.py --apply` is run",
                            grants_note,
                        )
                    rb_verify = _verify_restored_postgres(pg_url, pre_counts)
                    if rb_verify.get("verified"):
                        # Phase 6 (P21-07): row counts prove the data came back. They do not
                        # prove the schema did: Phase 21 found a failed rollback left a
                        # database that `verify_schema_drift()` reported as drifted, and
                        # nothing in the rollback path had looked. Ownership and grants are
                        # checked for the same reason - a rollback that restores rows but
                        # loses `gerege_app`'s privileges is data-correct and
                        # permission-broken, which is not a successful recovery.
                        invariants = _rollback_invariants(pg_url)
                        rb_verify["invariants"] = invariants
                        rollback_ok = bool(invariants.get("all_ok"))
                        if not rollback_ok:
                            logger.error(
                                "rollback restored the rows but an invariant failed: %s",
                                invariants.get("failures"),
                            )
                    else:
                        rb_verify["invariants"] = {"all_ok": False, "checked": False,
                                                   "failures": ["row counts did not match"]}

            if rollback_ok:
                logger.info(f"PostgreSQL rollback to pre_restore snapshot {pre_name} succeeded.")
                pre_stage.cleanup()
                return {
                    "success": False,
                    "error": ver_err,
                    "post_restore_verified": False,
                    "rollback_status": "ROLLED_BACK_TO_PRE_SNAPSHOT",
                    "rolled_back": True,
                    "atomic_rollback": True,
                    # The proof, not just the claim: this is what makes the status honest.
                    "rollback_invariants": rb_verify.get("invariants", {}),
                    "pre_restore_snapshot": pre_name,
                }
            else:
                logger.error(f"PostgreSQL rollback to pre_restore snapshot {pre_name} FAILED!")
                pre_stage.cleanup()
                return {
                    "success": False,
                    "error": ver_err,
                    "post_restore_verified": False,
                    "rollback_status": "RECOVERY_REQUIRED",
                    "rolled_back": False,
                    "atomic_rollback": False,
                    # Phase 6 (P21-07): the database is in an unknown state - the restore
                    # half-applied and the rollback did not prove it undid that. Say so with
                    # a status an operator or monitor can act on, rather than "FAILED",
                    # which reads as "the operation did not happen" when the truth is
                    # "the operation happened and was not undone".
                    "recovery_required": True,
                    "state_unknown": True,
                    # Phase 18: never interpolate the DSN here. It carries the owner password,
                    # and this string is printed, logged and returned to the CLI.
                    "recovery_instruction": (
                        "CRITICAL: RECOVERY_REQUIRED - the restore was interrupted and the "
                        "automatic rollback could not prove it restored the pre-restore state. "
                        f"Snapshot: {pre_name}. Do not serve traffic from this database until "
                        "you have replayed that snapshot with maintenance.py restore and then "
                        "run `python scripts/provision_roles.py --verify` and "
                        "`python scripts/maintenance.py status`. "
                        "(The connection string is intentionally omitted from this message.)"
                    ),
                    "pre_restore_snapshot": pre_name,
                }

        # Restore and verification both succeeded!
        # Phase 20: destroy the decrypted snapshot copy if one was staged for replay.
        pre_stage.cleanup()
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


def prune_old_backups(keep_days: int = 14, keep_min: Optional[int] = None) -> Dict[str, Any]:
    """Retention Policy: keep_days-ээс хуучин backup файлуудыг автоматаар цэвэрлэх

    Phase 20 rewrote this against the shared retention rules. As written before, it had
    three defects that only surface during an incident:

    * it matched only ``.sql.gz``/``.db.gz``, so **encrypted archives were never pruned**
      by the operator command (unbounded growth) while their plaintext-named sidecars
      were;
    * it had no count floor at all, so ``--days 0`` deleted every archive including the
      last recoverable one — the exact outcome Phase 18 added a floor to ``prune()`` to
      prevent, in the other retention path;
    * it ran with no lock, so it could race a restore or a backup.
    """
    from core import backup_automation

    if not os.path.exists(BACKUP_DIR):
        return {"pruned_count": 0, "pruned_files": [], "locked": False}
    floor = backup_automation.min_keep() if keep_min is None else max(1, int(keep_min))
    try:
        with backup_staging.backup_lock(BACKUP_DIR):
            # `prune` already implements age + floor + sidecar cleanup + encrypted-aware
            # inventory. Reusing it means there is one retention implementation, not two
            # that disagree about which files count.
            removed = backup_automation.prune(BACKUP_DIR, days=max(1, int(keep_days)), keep_min=floor)
            return {"pruned_count": len(removed), "pruned_files": removed, "locked": False}
    except backup_staging.LockUnavailable as exc:
        return {
            "pruned_count": 0,
            "pruned_files": [],
            "locked": True,
            "error": str(exc),
        }
