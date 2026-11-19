"""Encrypted, verified, scheduled-runnable backups (Phase 16).

E-05 moved backup out of the web process and onto an owner-credentialed maintenance
path. Phase 15 found the second half of that gap: the repository contained **no
scheduler at all**, while two documents claimed an automated daily backup with a
24-hour RPO. This module is the repository-level half of the fix — it makes one
scheduled run possible, measurable, encrypted, retained and alerting. The external
timer that invokes it is infrastructure, and is documented as NOT CONFIGURED rather
than assumed.

Design constraints, all inherited from E-05:

* The owner credential is read from ``DATABASE_OWNER_URL`` only. Nothing here is
  importable in a way that gives ``web``/``worker`` an owner connection, and the
  existing capability guard still decides whether the credential is good enough.
* No password, DSN, or encryption key is ever printed, logged, or written beside the
  archive.
* A failure is loud. ``run_scheduled_backup`` returns a distinct exit code per failure
  class so a timer unit and an alerting rule can tell them apart, and emits a
  machine-readable status file so monitoring does not have to parse text.

Encryption
----------
``openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt``. `openssl` is present in the
runtime image (``python:3.12-slim`` ships it; the Dockerfile already relies on the
image's OpenSSL for TLS) and on any host this project targets. A key file is used
rather than a passphrase argument so the secret never appears in ``ps`` output.

The archive is written to a temporary file, encrypted, verified, and only then renamed
into place. A crash therefore cannot leave a truncated file that looks like a backup —
the same "0-byte archive recorded as success" failure E-05 set out to eliminate, one
layer further out.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# Exit codes: distinct per failure class so a systemd unit, a cron wrapper or an
# alerting rule can distinguish "no credential" from "disk full" without parsing text.
EXIT_OK = 0
EXIT_BACKUP_FAILED = 10
EXIT_ENCRYPTION_FAILED = 11
EXIT_INTEGRITY_FAILED = 12
EXIT_CREDENTIAL_INVALID = 13
EXIT_OFFSITE_FAILED = 14
EXIT_NOT_CONFIGURED = 15
EXIT_LOCKED = 16

ENCRYPTED_SUFFIX = ".enc"
DEFAULT_RETENTION_DAYS = 14
DEFAULT_MIN_KEEP = 7


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "").strip() or default)
    except ValueError:
        return default


def backup_dir() -> str:
    return os.getenv("BACKUP_DIR", "backups")


def retention_days() -> int:
    return _env_int("BACKUP_RETENTION_DAYS", DEFAULT_RETENTION_DAYS)


def min_keep() -> int:
    """Never prune below this many archives, whatever the age rule says.

    A retention bug that deletes every backup is worse than a full disk, so the age
    rule is always bounded by a count floor.
    """
    value = _env_int("BACKUP_MIN_KEEP", DEFAULT_MIN_KEEP)
    # Phase 18: Phase 17 found that a negative floor deleted every archive. A retention
    # floor exists to prevent exactly that, so an out-of-range value is corrected rather
    # than honoured.
    return max(1, value)


def encryption_required() -> bool:
    """Encryption is on by default in production mode.

    Backups are a full copy of every tenant's data. Writing them unencrypted next to
    the database — the Phase 15 finding — is the failure mode this default removes.
    ``BACKUP_ENCRYPTION=off`` is available for local development, and the run fails
    closed in production instead of silently downgrading.
    """
    mode = os.getenv("BACKUP_ENCRYPTION", "on").strip().lower()
    if mode in ("off", "0", "false", "no"):
        return False
    return True


def _key_path() -> Optional[str]:
    path = os.getenv("BACKUP_ENCRYPTION_KEY_FILE", "").strip()
    return path or None


def offsite_target() -> Optional[str]:
    return os.getenv("BACKUP_OFFSITE_PATH", "").strip() or None


def notification_url() -> Optional[str]:
    return os.getenv("BACKUP_ALERT_WEBHOOK", "").strip() or None


def _status_path() -> str:
    return os.path.join(backup_dir(), ".last_backup_status.json")


# ---------------------------------------------------------------------------
# encryption
# ---------------------------------------------------------------------------


def encrypt_file(src: str, dest: str, key_file: str) -> Tuple[bool, str]:
    """Encrypt ``src`` to ``dest`` with authenticated AES-256-GCM.

    Phase 18 replaced the Phase 16 ``openssl enc -aes-256-cbc`` call. CBC carries no MAC,
    so a modified archive decrypted cleanly and the product could not tell a genuine
    archive from a forged one; ``openssl enc`` in OpenSSL 3.0 cannot do AEAD at all.
    See :mod:`core.backup_crypto` for the container format.
    """
    from core import backup_crypto

    try:
        backup_crypto.encrypt_file(src, dest, key_file, original_name=os.path.basename(src))
    except backup_crypto.EncryptionError as exc:
        return False, str(exc)
    except Exception as exc:  # pragma: no cover - unexpected I/O
        return False, f"encryption failed: {type(exc).__name__}"
    return True, ""


def decrypt_file(src: str, dest: str, key_file: str) -> Tuple[bool, str]:
    """Authenticated decryption. Kept for the restore drill and for operator tooling."""
    from core import backup_crypto

    try:
        if backup_crypto.is_authenticated_archive(src):
            backup_crypto.decrypt_file(src, dest, key_file)
        else:
            backup_crypto.decrypt_legacy_openssl(src, dest, key_file)
    except backup_crypto.EncryptionError as exc:
        return False, str(exc)
    except Exception as exc:  # pragma: no cover
        return False, f"decryption failed: {type(exc).__name__}"
    return True, ""


# ---------------------------------------------------------------------------
# retention / offsite / notification
# ---------------------------------------------------------------------------


def _archives(directory: str) -> List[Tuple[str, os.stat_result]]:
    if not os.path.isdir(directory):
        return []
    out = []
    for name in os.listdir(directory):
        if name.startswith("."):
            continue
        if not (name.endswith(".gz") or name.endswith(".gz" + ENCRYPTED_SUFFIX)
                or name.endswith(".db.gz")):
            continue
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            out.append((name, os.stat(path)))
    return sorted(out, key=lambda item: item[1].st_mtime, reverse=True)


def prune(directory: str, days: int, keep_min: int, dry_run: bool = False) -> List[str]:
    """Delete archives older than ``days``, never dropping below ``keep_min`` total.

    Both the age rule and the count floor apply; whichever is more conservative wins.
    The floor is clamped to at least one archive, and a negative or zero configuration is
    corrected rather than obeyed — Phase 17 found ``BACKUP_MIN_KEEP=-5`` silently deleted
    every backup, which is the one outcome a retention floor exists to prevent.

    Phase 18 also fixed sidecar orphaning: Phase 16 built ``<archive>.enc.json`` while the
    real metadata file is ``<archive>.meta.json``, so every pruned archive left its
    checksum and manifest behind forever.
    """
    from core import backup_archive

    keep_min = max(1, int(keep_min))
    cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
    items = _archives(directory)
    removed: List[str] = []
    # Keep the newest `keep_min` regardless of age.
    for index, (name, st) in enumerate(items):
        if index < keep_min:
            continue
        if st.st_mtime > cutoff:
            continue
        path = os.path.join(directory, name)
        if dry_run:
            removed.append(name)
            continue
        try:
            os.remove(path)
            removed.append(name)
            # One helper decides which files belong to this archive, so an encrypted
            # archive also takes the sidecars named after its inner plaintext name.
            for sidecar in backup_archive.sidecar_paths(directory, name).values():
                try:
                    os.remove(sidecar)
                except OSError:
                    pass
        except OSError:
            continue
    return removed


def copy_offsite(src: str, target: str) -> Tuple[bool, str]:
    """Copy ``src`` into ``target`` and prove the copy by size.

    Deliberately not an rm-then-assume: a silent partial copy is the same class of
    bug as a 0-byte backup. A remote/object-store target is out of scope for this
    repository and is documented as NOT CONFIGURED.
    """
    try:
        os.makedirs(target, exist_ok=True)
        dest = os.path.join(target, os.path.basename(src))
        shutil.copy2(src, dest)
        for sidecar in (src + ".sha256", src + ".json"):
            if os.path.exists(sidecar):
                shutil.copy2(sidecar, os.path.join(target, os.path.basename(sidecar)))
        if os.path.getsize(dest) != os.path.getsize(src):
            return False, "offsite copy size mismatch"
        return True, ""
    except Exception as exc:
        return False, f"offsite copy failed: {type(exc).__name__}"


def notify(webhook: str, payload: Dict[str, Any]) -> Tuple[bool, str]:
    """POST a JSON status. Best-effort, bounded, and never raises.

    An alerting failure must not turn a successful backup into a failed one, and must
    not mask a failed backup — it is reported in the status file instead.
    """
    import urllib.request

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return (200 <= resp.status < 300), f"http {resp.status}"
    except Exception as exc:
        return False, f"notification failed: {type(exc).__name__}"


# ---------------------------------------------------------------------------
# the scheduled run
# ---------------------------------------------------------------------------


def _write_status(payload: Dict[str, Any], directory: str) -> None:
    try:
        os.makedirs(directory, exist_ok=True)
        tmp = _status_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, default=str)
        os.replace(tmp, _status_path())
    except Exception:
        pass


def _publish_ciphertext_checksum(directory: str, ciphertext_path: str) -> str:
    """Hash the **ciphertext** and write a ``sha256sum``-compatible sidecar.

    Phase 17: the sidecar hashed the plaintext, which encryption then deleted, so months
    later the only checksum on disk referred to a file that no longer existed and could
    not detect bit-rot in the archive that did. The plaintext-name sidecar is rewritten
    to describe the ciphertext, and a second sidecar named after the ciphertext makes the
    association obvious to anyone reading the directory.
    """
    from core.backup_service import _compute_sha256

    digest = _compute_sha256(ciphertext_path)
    name = os.path.basename(ciphertext_path)
    inner = name[: -len(ENCRYPTED_SUFFIX)] if name.endswith(ENCRYPTED_SUFFIX) else name
    targets = {
        os.path.join(directory, name + ".sha256"),
        os.path.join(directory, inner + ".sha256"),
    }
    for path in targets:
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(f"{digest}  {name}\n")
            os.chmod(path, 0o600)
        except OSError:
            pass
    return digest


def run_scheduled_backup(label: str = "scheduled") -> Dict[str, Any]:
    """One complete scheduled run: backup, encrypt, verify, retain, copy off, alert.

    Returns a result dict that is also written to ``<BACKUP_DIR>/.last_backup_status.json``
    so monitoring can read success/failure without parsing logs. ``exit_code`` is the
    value the process should exit with.

    Phase 18 changed the *shape* of the run, not just its steps. Phase 16 wrote the
    plaintext dump into ``BACKUP_DIR`` and encrypted it afterwards, so every failure
    between those two points left a world-readable copy of every tenant's data behind.
    The dump is now created inside a private 0700 staging directory and the only thing
    that is ever published into ``BACKUP_DIR`` is the ciphertext (or, when encryption is
    explicitly disabled, the dump — announced as a warning). The whole run is serialised
    by an advisory lock so two timers cannot overlap or prune each other's work.
    """
    from core import backup_service, backup_staging

    started = datetime.now(timezone.utc).isoformat()
    directory = backup_dir()
    result: Dict[str, Any] = {
        "label": label,
        "started_at": started,
        "encrypted": False,
        "offsite": False,
        "pruned": [],
        "warnings": [],
        "exit_code": EXIT_OK,
        "success": False,
    }

    os.makedirs(directory, exist_ok=True)
    swept = backup_staging.sweep_stale_staging(directory)
    if swept:
        result["warnings"].append(f"removed {len(swept)} stale staging director(ies) from a previous crash")

    try:
        lock = backup_staging.backup_lock(directory)
        lock.__enter__()
    except backup_staging.LockUnavailable as exc:
        result.update(success=False, exit_code=EXIT_LOCKED, error=str(exc))
        _finish(result, directory)
        return result
    except OSError as exc:
        # An unwritable or missing backup directory. Phase 17 only exercised this through
        # an uncaught traceback, which tells an operator nothing they can act on.
        result.update(
            success=False,
            exit_code=EXIT_BACKUP_FAILED,
            error=(
                f"backup directory is not writable: {type(exc).__name__} "
                f"({os.path.basename(directory) or directory}); check ownership and mode"
            ),
        )
        _finish(result, directory)
        return result

    try:
        return _run_scheduled_backup_locked(label, directory, result)
    finally:
        lock.__exit__(None, None, None)


def _run_scheduled_backup_locked(label: str, directory: str, result: Dict[str, Any]) -> Dict[str, Any]:
    from core import backup_service, backup_staging

    # Record that a run is under way, so monitoring can distinguish "in progress" from
    # "failed" or "never ran" instead of inferring it from a stale timestamp.
    _write_status({**result, "in_progress": True}, directory)

    encrypting = encryption_required()
    key_file = _key_path()
    staging = backup_staging.StagingDir(directory, prefix=".staging-")
    staging.__enter__()

    ciphertext_name: Optional[str] = None
    try:
        # 1. The dump, written into the private staging directory.
        try:
            created = backup_service.create_backup(label=label, staging_dir=staging.path_dir)
        except Exception as exc:
            result.update(success=False, exit_code=EXIT_BACKUP_FAILED,
                          error=f"{type(exc).__name__}: {exc}")
            _finish(result, directory)
            return result

        if not created.get("success"):
            result.update(success=False, exit_code=EXIT_BACKUP_FAILED,
                          error=str(created.get("error") or "backup failed"))
            _finish(result, directory)
            return result

        filename = created["filename"]
        staged_path = os.path.join(staging.path_dir, filename)
        result.update(filename=filename, size_bytes=created.get("size_bytes"))

        # 2. A dump that cannot be verified is not a backup.
        check = backup_service._verify_plaintext_dump(staged_path, filename)
        if not check.get("valid"):
            result.update(success=False, exit_code=EXIT_INTEGRITY_FAILED,
                          error=f"verification failed: {check.get('error')}")
            _finish(result, directory)
            return result

        # 3. Encryption. Fatal when required and impossible -- never downgrade silently.
        if encrypting:
            if not key_file:
                result.update(
                    success=False,
                    exit_code=EXIT_NOT_CONFIGURED,
                    error=(
                        "BACKUP_ENCRYPTION_KEY_FILE is not set but encryption is required. "
                        "No plaintext was written to the backup directory; set the key file "
                        "(see docs/operations/BACKUP_ENCRYPTION.md), or set "
                        "BACKUP_ENCRYPTION=off for a non-production environment."
                    ),
                )
                _finish(result, directory)
                return result

            ciphertext_name = filename + ENCRYPTED_SUFFIX
            staged_cipher = staging.path(ciphertext_name)
            ok, error = encrypt_file(staged_path, staged_cipher, key_file)
            if not ok:
                # The staging directory is destroyed by the context manager; nothing
                # reaches BACKUP_DIR, so there is no plaintext to leak.
                result.update(success=False, exit_code=EXIT_ENCRYPTION_FAILED, error=error)
                _finish(result, directory)
                return result

            # 3b. Prove the ciphertext authenticates before publishing it. A backup that
            # cannot be decrypted by the key that made it is not a backup.
            roundtrip = staging.path(filename + ".roundtrip")
            ok, error = decrypt_file(staged_cipher, roundtrip, key_file)
            if not ok:
                result.update(success=False, exit_code=EXIT_ENCRYPTION_FAILED,
                              error=f"ciphertext failed its own authentication check: {error}")
                _finish(result, directory)
                return result

            publish_target = os.path.join(directory, ciphertext_name)
            staging.publish(staged_cipher, publish_target)
            os.chmod(publish_target, 0o600)
            result["sha256"] = _publish_ciphertext_checksum(directory, publish_target)
            result["encrypted"] = True
            result["encryption_format"] = "authenticated"
            result["filename"] = ciphertext_name
            result["size_bytes"] = os.path.getsize(publish_target)
            archive = publish_target
        else:
            publish_target = os.path.join(directory, filename)
            staging.publish(staged_path, publish_target)
            os.chmod(publish_target, 0o600)
            result["encryption_format"] = "none"
            result["warnings"].append(
                "BACKUP_ENCRYPTION is off: the archive is plaintext tenant data"
            )
            archive = publish_target
    finally:
        # Destroying staging removes any plaintext that is still there, on every path.
        staging.cleanup()

    # 4. Offsite. Phase 17 found this was `shutil.copy2` to a local path, reported as
    # "offsite" success -- no independent failure domain and no transport security.
    # Phase 18 resolves a real provider from the environment, records which one it used
    # and whether it is genuinely independent, and says NOT CONFIGURED when it is not.
    from core import backup_offsite

    try:
        provider = backup_offsite.provider_from_env()
        offsite_error: Optional[str] = None
    except backup_offsite.OffsiteError as exc:
        provider, offsite_error = None, str(exc)

    if offsite_error:
        result["offsite_state"] = "MISCONFIGURED"
        result["warnings"].append(f"offsite storage misconfigured: {offsite_error}")
        result["exit_code"] = EXIT_OFFSITE_FAILED
    elif provider is None:
        result["offsite_state"] = backup_offsite.OFFSITE_NOT_CONFIGURED
        result["warnings"].append(
            "BACKUP_OFFSITE_PATH/BACKUP_OFFSITE_URL is not configured: the only copy is on "
            "this host, so losing the host loses every backup"
        )
    else:
        remote_name = os.path.basename(archive)
        ok, error = provider.upload(archive, remote_name, sha256=result.get("sha256", ""))
        result["offsite"] = bool(ok)
        result["offsite_state"] = "UPLOADED" if ok else "UPLOAD_FAILED"
        result["offsite_provider"] = provider.name
        result["offsite_independent"] = provider.independent_failure_domain
        if not ok:
            result["warnings"].append(f"offsite upload failed: {error}")
            result["exit_code"] = EXIT_OFFSITE_FAILED
        else:
            result["pruned_offsite"] = provider.apply_remote_retention(min_keep())
            if not provider.independent_failure_domain:
                result["warnings"].append(
                    f"offsite provider '{provider.name}' is a local directory: it does not "
                    "provide an independent failure domain"
                )

    # 5. Retention, bounded by a count floor.
    result["pruned"] = prune(directory, retention_days(), min_keep())
    result["retention_days"] = retention_days()

    result["success"] = True
    _finish(result, directory)
    return result


def _finish(result: Dict[str, Any], directory: str) -> None:
    result["finished_at"] = datetime.now(timezone.utc).isoformat()
    _write_status(result, directory)
    webhook = notification_url()
    if webhook:
        payload = {
            "event": "backup.success" if result.get("success") else "backup.failure",
            "label": result.get("label"),
            "filename": result.get("filename"),
            "encrypted": result.get("encrypted"),
            "offsite": result.get("offsite"),
            "exit_code": result.get("exit_code"),
            "error": result.get("error"),
            "warnings": result.get("warnings"),
            "finished_at": result.get("finished_at"),
        }
        ok, detail = notify(webhook, payload)
        if not ok:
            result.setdefault("warnings", []).append(detail)
    else:
        result.setdefault("warnings", []).append(
            "BACKUP_ALERT_WEBHOOK is not configured: nobody is notified of a failure"
        )


def read_status() -> Optional[Dict[str, Any]]:
    """Last run's status, for a monitoring probe. ``None`` when nothing has run."""
    path = _status_path()
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Operational state (Phase 18)
# ---------------------------------------------------------------------------

STATE_NEVER_EXECUTED = "NEVER_EXECUTED"
STATE_IN_PROGRESS = "IN_PROGRESS"
STATE_SUCCESS = "SUCCESS"
STATE_FAILED = "FAILED"
STATE_STALE = "STALE"


def scheduler_installed(paths: Optional[List[str]] = None) -> bool:
    """True when a timer/cron entry that invokes ``backup-run`` is present on this host.

    The repository ships *templates*, not an installed timer. Phase 17 confirmed nothing
    installs them, so "backups are scheduled" was an assumption rather than a fact. This
    probe lets monitoring distinguish "the scheduler is running and the last backup
    failed" from "no scheduler exists, so nothing will ever run".
    """
    candidates = paths or [
        "/etc/systemd/system/gerege-backup.timer",
        "/usr/lib/systemd/system/gerege-backup.timer",
        "/etc/cron.d/gerege-backup",
    ]
    for candidate in candidates:
        try:
            if os.path.exists(candidate):
                return True
        except OSError:
            continue
    return False


def operational_state(max_age_hours: Optional[int] = None) -> Dict[str, Any]:
    """One of NEVER_EXECUTED / IN_PROGRESS / SUCCESS / FAILED / STALE, with detail.

    Monitoring needs these five distinguished. A single "unhealthy" signal cannot tell an
    operator whether to look at the last error, wait, or go and install a timer.
    """
    max_age = max_age_hours if max_age_hours is not None else _env_int("BACKUP_MAX_AGE_HOURS", 36)
    status = read_status()
    if not status:
        return {
            "state": STATE_NEVER_EXECUTED,
            "scheduler_installed": scheduler_installed(),
            "detail": "no scheduled run has ever been recorded on this host",
        }

    if status.get("in_progress"):
        return {"state": STATE_IN_PROGRESS, "scheduler_installed": scheduler_installed(),
                "detail": f"a run started at {status.get('started_at')} has not finished"}

    if not status.get("success"):
        return {
            "state": STATE_FAILED,
            "scheduler_installed": scheduler_installed(),
            "exit_code": status.get("exit_code"),
            "error": status.get("error"),
            "detail": "the last recorded run failed",
        }

    from datetime import datetime, timezone

    stamp = status.get("finished_at") or status.get("started_at")
    age_hours: Optional[float] = None
    if stamp:
        try:
            then = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
            if then.tzinfo is None:
                then = then.replace(tzinfo=timezone.utc)
            age_hours = (datetime.now(timezone.utc) - then).total_seconds() / 3600.0
        except ValueError:
            age_hours = None

    if age_hours is not None and age_hours > max_age:
        return {
            "state": STATE_STALE,
            "scheduler_installed": scheduler_installed(),
            "age_hours": round(age_hours, 1),
            "max_age_hours": max_age,
            "detail": "the last successful run is older than the maximum age",
        }

    return {
        "state": STATE_SUCCESS,
        "scheduler_installed": scheduler_installed(),
        "age_hours": round(age_hours, 1) if age_hours is not None else None,
        "max_age_hours": max_age,
    }
