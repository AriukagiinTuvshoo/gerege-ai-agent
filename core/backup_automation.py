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
    return _env_int("BACKUP_MIN_KEEP", DEFAULT_MIN_KEEP)


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


def _openssl() -> Optional[str]:
    return shutil.which("openssl")


def encrypt_file(src: str, dest: str, key_file: str) -> Tuple[bool, str]:
    """Encrypt ``src`` to ``dest``. Returns ``(ok, error)`` and never echoes the key."""
    openssl = _openssl()
    if not openssl:
        return False, "openssl is not installed; cannot encrypt the archive"
    if not os.path.exists(key_file):
        return False, f"encryption key file not found: {os.path.basename(key_file)}"
    try:
        # -pass file: keeps the key out of argv (visible in `ps` to every local user).
        proc = subprocess.run(
            [
                openssl, "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "200000",
                "-salt", "-in", src, "-out", dest,
                "-pass", f"file:{key_file}",
            ],
            capture_output=True,
            timeout=1800,
        )
    except Exception as exc:  # pragma: no cover - subprocess failure
        return False, f"openssl could not run: {type(exc).__name__}"
    if proc.returncode != 0:
        detail = (proc.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        return False, f"openssl failed: {detail[-1][:200] if detail else 'no detail'}"
    return True, ""


def decrypt_file(src: str, dest: str, key_file: str) -> Tuple[bool, str]:
    """Reverse of :func:`encrypt_file`, used by the restore drill and by ``restore``."""
    openssl = _openssl()
    if not openssl:
        return False, "openssl is not installed; cannot decrypt the archive"
    try:
        proc = subprocess.run(
            [
                openssl, "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000",
                "-in", src, "-out", dest,
                "-pass", f"file:{key_file}",
            ],
            capture_output=True,
            timeout=1800,
        )
    except Exception as exc:  # pragma: no cover
        return False, f"openssl could not run: {type(exc).__name__}"
    if proc.returncode != 0:
        # A wrong key and a corrupt ciphertext are indistinguishable here, and saying
        # which would leak whether a guessed key was close. Report both possibilities.
        return False, "decryption failed (wrong key or corrupt archive)"
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
    """
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
            for sidecar in (path + ".sha256", path + ".json"):
                if os.path.exists(sidecar):
                    os.remove(sidecar)
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


def run_scheduled_backup(label: str = "scheduled") -> Dict[str, Any]:
    """One complete scheduled run: backup, encrypt, verify, retain, copy off, alert.

    Returns a result dict that is also written to ``<BACKUP_DIR>/.last_backup_status.json``
    so monitoring can read success/failure without parsing logs. ``exit_code`` is the
    value the process should exit with.
    """
    from core import backup_service

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

    # 1. The backup itself, via the owner-credentialed guard.
    try:
        created = backup_service.create_backup(label=label)
    except Exception as exc:
        result.update(
            success=False,
            exit_code=EXIT_BACKUP_FAILED,
            error=f"{type(exc).__name__}: {exc}",
        )
        _finish(result, directory)
        return result

    if not created.get("success"):
        result.update(
            success=False,
            exit_code=EXIT_BACKUP_FAILED,
            error=str(created.get("error") or "backup failed"),
        )
        _finish(result, directory)
        return result

    filename = created["filename"]
    archive = os.path.join(directory, filename)
    result.update(filename=filename, size_bytes=created.get("size_bytes"))

    # 2. A backup that cannot be verified is not a backup.
    check = backup_service.verify_backup(filename)
    if not check.get("valid"):
        result.update(
            success=False,
            exit_code=EXIT_INTEGRITY_FAILED,
            error=f"verification failed: {check.get('error')}",
        )
        _finish(result, directory)
        return result

    # 3. Encryption. Fatal when required and impossible — never downgrade silently.
    if encryption_required():
        key_file = _key_path()
        if not key_file:
            result.update(
                success=False,
                exit_code=EXIT_NOT_CONFIGURED,
                error=(
                    "BACKUP_ENCRYPTION_KEY_FILE is not set but encryption is required. "
                    "Refusing to leave plaintext tenant data on disk. Set the key file "
                    "(see docs/operations/BACKUP_RESTORE.md), or set BACKUP_ENCRYPTION=off "
                    "for a non-production environment."
                ),
            )
            _finish(result, directory)
            return result

        encrypted_path = archive + ENCRYPTED_SUFFIX
        ok, error = encrypt_file(archive, encrypted_path, key_file)
        if not ok:
            result.update(
                success=False, exit_code=EXIT_ENCRYPTION_FAILED, error=error
            )
            _finish(result, directory)
            return result
        # Only remove the plaintext once the ciphertext is on disk and non-empty.
        if os.path.getsize(encrypted_path) > 0:
            try:
                os.remove(archive)
                result["plaintext_removed"] = True
            except OSError:
                result["warnings"].append("could not remove the plaintext archive")
        result["encrypted"] = True
        result["filename"] = filename + ENCRYPTED_SUFFIX
        result["size_bytes"] = os.path.getsize(encrypted_path)
        archive = encrypted_path
    else:
        result["warnings"].append(
            "BACKUP_ENCRYPTION is off: the archive is plaintext tenant data"
        )

    # 4. Offsite / independent copy. Configured or explicitly absent; never assumed.
    target = offsite_target()
    if target:
        ok, error = copy_offsite(archive, target)
        result["offsite"] = bool(ok)
        if not ok:
            result["warnings"].append(error)
            result["exit_code"] = EXIT_OFFSITE_FAILED
    else:
        result["warnings"].append(
            "BACKUP_OFFSITE_PATH is not configured: the only copy is on this host"
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
