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
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from core import outbound_http

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
#: Phase 23 (D-7): a configured bound was exceeded (database or pg_dump timeout). 17 is
#: reserved for `maintenance.py legacy` reporting plaintext on disk, so a timeout needs its
#: own code - and it needs to be *named* here, because alerting and `status` read these
#: constants, and a bare 18 in `backup_service.py` was invisible to them.
EXIT_TIMEOUT = 18

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
    """Whether this process must encrypt. Delegates to the centralized policy.

    Phase 22 (P21-01): the body used to be an inline ``BACKUP_ENCRYPTION`` read that
    had no notion of environment, so ``ENV=production BACKUP_ENCRYPTION=off`` returned
    False and the caller happily wrote plaintext. The decision now lives in
    :mod:`core.backup_policy` so that every entry point cannot disagree.

    Contract for legacy callers: True means "encrypt"; a *refused* configuration also
    returns True, so a caller that never looks at ``allowed`` still fails closed
    (missing key + encrypting ⇒ the existing error path) instead of downgrading to
    plaintext. Use :func:`core.backup_policy.evaluate` for the full answer.
    """
    from core.backup_policy import evaluate

    policy = evaluate()
    return policy.encrypting or not policy.allowed


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


def classify_archive(path: str) -> str:
    """Classify a file in the backup directory without reading its contents.

    Phase 20. Phase 19 found that a plaintext dump produced by the old manual path was
    indistinguishable, to the retention code and to ``list``, from a real encrypted
    restore point — so it counted toward the retention floor and could push a genuine
    encrypted archive out of retention.

    Returns one of:

    ``authenticated``
        ``.enc`` carrying this repository's AEAD magic. A cryptographically verifiable
        restore point.
    ``legacy-openssl``
        ``.enc`` with the Phase 16 ``Salted__`` header. Restorable, but **unauthenticated**.
    ``plaintext``
        ``.sql.gz``/``.db.gz``. Restorable, and tenant data in the clear.
    ``unknown``
        An ``.enc`` with neither magic. Never restorable and never counted as a backup.

    Only the file header is inspected — never the body — so classification cannot leak
    tenant data into a log or terminal.
    """
    from core import backup_archive

    name = os.path.basename(path)
    if backup_archive.is_encrypted_name(name):
        return backup_archive.encryption_format(path)
    if backup_archive.is_plaintext_name(name):
        return "plaintext"
    return "unknown"


def is_verified_encrypted(path: str) -> bool:
    """True only for an authenticated AEAD archive — the only thing that counts as secure."""
    return classify_archive(path) == "authenticated"


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


def encrypted_archives(directory: str) -> List[Tuple[str, os.stat_result]]:
    """Only authenticated AEAD archives, newest first.

    This is the inventory the *encrypted* retention floor is measured against. A plaintext
    file sitting in the directory must not be able to satisfy that floor.
    """
    return [(name, st) for name, st in _archives(directory)
            if is_verified_encrypted(os.path.join(directory, name))]


def legacy_plaintext_archives(directory: str) -> List[Tuple[str, os.stat_result]]:
    """Plaintext archives found in a backup directory (Phase 19 leak leftovers).

    Named, not deleted. Phase 20's rule is that these are detected and reported but never
    removed automatically: they may be the only copy of something, and deleting a
    customer's data because a scanner decided it was insecure is worse than the exposure.
    """
    return [(name, st) for name, st in _archives(directory)
            if classify_archive(os.path.join(directory, name)) == "plaintext"]


def prune(directory: str, days: int, keep_min: int, dry_run: bool = False) -> List[str]:
    """Delete archives older than ``days``, never dropping below ``keep_min`` total.

    Both the age rule and the count floor apply; whichever is more conservative wins.
    The floor is clamped to at least one archive, and a negative or zero configuration is
    corrected rather than obeyed — Phase 17 found ``BACKUP_MIN_KEEP=-5`` silently deleted
    every backup, which is the one outcome a retention floor exists to prevent.

    Phase 18 also fixed sidecar orphaning: Phase 16 built ``<archive>.enc.json`` while the
    real metadata file is ``<archive>.meta.json``, so every pruned archive left its
    checksum and manifest behind forever.

    Phase 22 (P21-03). Plaintext archives are **never deleted here**, whatever their age.
    The documented rule - stated in `legacy_plaintext_archives()` and in the operations
    guide - is that a plaintext leftover is detected and reported but not removed
    automatically, because it may be the only copy of something and silently deleting
    customer data is worse than the exposure. The code did not do that: `prune()` iterated
    every archive, so an aged plaintext dump was deleted while an encrypted one was kept by
    the floor. Detection and removal were on opposite sides of the promise.
    Removing plaintext is now exclusively `maintenance.py legacy --quarantine <dir> --yes`,
    which moves rather than deletes and has to be asked for.
    """
    from core import backup_archive

    keep_min = max(1, int(keep_min))
    cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
    # P21-03: exclude plaintext before anything else looks at the list, so no age rule and
    # no floor calculation can act on it. `legacy_plaintext_archives()` was defined for
    # exactly this and had no callers; it is what makes the exclusion auditable.
    #
    # Unknown files are excluded for the same reason and were the more dangerous half: an
    # `.enc` whose header this build does not recognise was iterated, aged, and deleted. It
    # may be a backup from a newer schema, a differently-keyed archive, or something an
    # operator put there deliberately. Retention deletes things it can prove are superseded
    # restore points; it has no business deleting something it cannot classify at all.
    legacy = {name for name, _st in legacy_plaintext_archives(directory)}
    unknown = {
        name for name, _st in _archives(directory)
        if classify_archive(os.path.join(directory, name)) == "unknown"
    }
    items = [
        (name, st) for name, st in _archives(directory)
        if name not in legacy and name not in unknown
    ]
    # Phase 20: the floor protects *verified encrypted* restore points. Counting every
    # file meant a plaintext leftover satisfied the floor, so retention would keep the
    # unencrypted file and delete the encrypted one behind it.
    #
    # Safety net: when the directory holds no authenticated archive at all (a legacy
    # plaintext-only host, or an archive store whose headers are damaged), there is
    # nothing encrypted to protect, and an empty protected set would let the floor be
    # bypassed entirely and delete every file. In that case fall back to protecting the
    # newest `keep_min` of whatever is there. This rule can only ever protect *more*
    # than the plain inventory-based floor did, never less.
    protected_encrypted = {name for name, _st in encrypted_archives(directory)[:keep_min]}
    protected = protected_encrypted or {name for name, _st in items[:keep_min]}
    # Note: `items` no longer contains plaintext, so the fallback can only protect an
    # encrypted archive or a legacy-openssl one. It can never keep a plaintext dump alive
    # for the next run to trip over again.
    removed: List[str] = []
    for name, st in items:
        if name in protected:
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


#: Hosts and ports a webhook may reach, and the one environment variable that relaxes it.
#:
#: Phase 28. The scheme allowlist added in Phase 27 decides how the payload travels; this
#: decides where it lands. The distinction matters because the value is operator
#: configuration, not attacker input - a hostile webhook needs a compromised or careless
#: operator - so the policy is proportionate rather than absolute:
#:
#:   * https is required outside development;
#:   * plain http is allowed only when BACKUP_ALERT_ALLOW_INSECURE=1 AND ENV is not
#:     production, which is what lets the local test sinks work without weakening a
#:     deployed host (the same shape used for the offsite loopback opt-in in Phase 22);
#:   * the destination must resolve only to public addresses, which refuses loopback,
#:     RFC1918, link-local and - the specific case worth naming - 169.254.169.254.
#:
#: Refusing is not a security boundary against an operator who can edit the environment
#: file. It stops the realistic failures: a copied staging URL, a typo resolving to a
#: typo-squatted internal name, and a value that quietly points at cloud metadata.
BACKUP_ALERT_ALLOW_INSECURE_ENV = "BACKUP_ALERT_ALLOW_INSECURE"


def _webhook_destination_refusal(webhook: str) -> str:
    """Why this webhook destination must be refused, or "" when it is acceptable."""
    return _webhook_destination_check(webhook)[0]


def _webhook_destination_check(webhook: str) -> "tuple[str, list]":
    """`(refusal, addresses)` - the verdict AND the addresses it was reached from.

    Phase 30: the addresses are returned so the caller can pin the connection to the exact
    set this function validated. Returning only the verdict forced the caller to resolve
    again, and the second resolution is the one an attacker controls - the race would have
    been moved rather than closed. One resolution, one verdict, one pin.
    """
    parsed = urllib.parse.urlsplit(webhook)
    scheme = parsed.scheme.lower()
    host = parsed.hostname
    if not host:
        return f"webhook {webhook!r} has no host", []
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError:
        return f"webhook {host!r} has an invalid port", []

    production = os.getenv("ENV", "").strip().lower() in ("production", "prod")
    allow_insecure = os.getenv(BACKUP_ALERT_ALLOW_INSECURE_ENV, "").strip() == "1"

    if scheme == "http":
        if production:
            return (
                "plain http webhook refused in production: an alert body carries backup "
                "names, failure text and an exit code. Use https.",
                [],
            )
        if not allow_insecure:
            return (
                "plain http webhook refused: set BACKUP_ALERT_ALLOW_INSECURE=1 outside "
                "production to permit a local test sink.",
                [],
            )

    # Resolve exactly once. Everything below judges this one answer, and the caller pins
    # to it, so no second lookup exists for a resolver to steer.
    addresses = outbound_http.resolve_host(host, port)

    if port not in outbound_http.DEFAULT_ALLOWED_PORTS:
        # A loopback test sink may legitimately use an ephemeral port; a real destination
        # has no reason to use anything but 80/443. Judged from the same resolution.
        all_loopback = bool(addresses) and all(
            (outbound_http.parse_ip(a) is not None and outbound_http.parse_ip(a).is_loopback)
            for _f, a in addresses
        )
        if not (allow_insecure and not production and all_loopback):
            return (
                f"webhook port {port} is not allowed; use 443 (or 80 with the insecure "
                "opt-in outside production)",
                [],
            )

    if not addresses:
        return f"webhook host {host!r} did not resolve", []
    for _family, address in addresses:
        if outbound_http.is_public_address(address):
            continue
        if allow_insecure and not production and outbound_http.parse_ip(address).is_loopback:
            # The documented test path: a local sink on this machine.
            continue
        return (
            f"webhook host {host!r} resolves to {address}, which is not a public address. "
            "Alert destinations must be reachable on the public internet; a private or "
            "metadata address is never a webhook.",
            [],
        )
    return "", addresses


def _open_pinned(opener, request, *, timeout):
    """The single point where an alert request is actually sent.

    Named so a test can assert *that a permitted destination is attempted* without a
    network, which is what the Phase 28 test did by stubbing `urlopen`. That stub stopped
    working when the webhook moved to a pinned opener - the request no longer goes through
    `urlopen`, so the test failed with `URLError` instead of recording a delivery. A test
    that has to know the transport is testing the transport; this keeps the seam explicit.

    The timeout is a required argument rather than a default here so that every attempt's
    bound is stated where the attempt is made, which is what the Phase 22 test checks for.
    """
    return opener.open(request, timeout=timeout)


def _loopback_sink_allowed() -> bool:
    """Whether the documented non-production loopback sink exception is in force.

    Single source of truth for that decision: the destination check and the pinned
    connection both read it, so they cannot disagree about whether 127.0.0.1 is permitted.
    """
    production = os.getenv("ENV", "").strip().lower() in ("production", "prod")
    allow_insecure = os.getenv(BACKUP_ALERT_ALLOW_INSECURE_ENV, "").strip() == "1"
    return allow_insecure and not production


def notify(webhook: str, payload: Dict[str, Any]) -> Tuple[bool, str]:
    """POST a JSON status. Best-effort, bounded, retried, and never raises.

    An alerting failure must not turn a successful backup into a failed one, and must
    not mask a failed backup — it is reported in the status file instead.

    Phase 22: the call is retried a bounded number of times with a fixed short backoff.
    A single attempt meant one dropped TCP packet or one transient 503 from a webhook
    receiver silently lost the alert for a failed backup — the failure it was reporting
    stayed invisible. The retry count and delay are deliberately small and constant: an
    alert that has to wait for a long exponential backoff is nearly as lost as one that
    was never sent, and every attempt is bounded by its own timeout so the total wait is
    bounded too (attempts × timeout + backoff).

    Only transient failures are retried. A 4xx means the request itself is wrong and
    repeating it cannot help, so it is reported immediately.
    """
    import time as _time
    import urllib.error
    import urllib.parse
    import urllib.request

    body = json.dumps(payload).encode("utf-8")
    attempts = max(1, min(int(os.getenv("BACKUP_ALERT_RETRIES", "3")), 10))
    backoff = max(0.0, min(float(os.getenv("BACKUP_ALERT_BACKOFF_S", "1")), 10.0))
    last = "notification failed"
    for attempt in range(1, attempts + 1):
        # Phase 24: build the Request inside the try. A malformed webhook ("not-a-url",
        # "http://") raised ValueError from here, outside every handler, so a typo in
        # BACKUP_ALERT_WEBHOOK crashed the scheduled run instead of being reported. The
        # whole point of this function is that alerting cannot break a backup.
        try:
            # Phase 27 (B310): the webhook URL was passed to urlopen with no scheme check.
            # BACKUP_ALERT_WEBHOOK is operator configuration rather than an attacker-supplied
            # value, so this is not remote code execution - but `file://` is accepted by
            # urlopen and a GET response body read back, and a typo or a copied value is
            # a realistic way to reach it. Alerting should contact an HTTP endpoint or fail.
            scheme = urllib.parse.urlsplit(webhook).scheme.lower()
            if scheme not in ("http", "https"):
                # A wrong scheme cannot be fixed by retrying, so return rather than loop.
                # Reporting "after 2 attempts" for a failure that was never attempted would
                # be a small lie in exactly the place an operator looks to diagnose a typo.
                return (
                    False,
                    f"notification failed: webhook scheme {scheme or '(none)'!r} is not "
                    "http/https; refusing to open it",
                )
            # Phase 28: destination policy. The scheme check above decides how the bytes
            # travel; this decides *where* they go. Both are permanent failures, so both
            # return rather than retry.
            # Phase 30: ONE resolution decides both the verdict and the pinned address.
            # Resolving twice was the bug the pin was supposed to fix: the second answer is
            # the one an attacker controls.
            refusal, addresses = _webhook_destination_check(webhook)
            if refusal:
                return False, f"notification failed: {refusal}"

            from core import pinned_http

            parsed = urllib.parse.urlsplit(webhook)
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
            loopback_ok = _loopback_sink_allowed()
            try:
                opener = pinned_http.build_pinned_opener_from(
                    addresses,
                    scheme=parsed.scheme.lower(),
                    extra_handlers=(pinned_http.SamePolicyRedirectHandler,),
                    require_public=not loopback_ok,
                    allow_loopback=loopback_ok,
                )
            except Exception as exc:
                # Permanent: a destination that will not resolve or pin cannot be fixed by
                # retrying. Reported in the same shape as the other permanent refusals.
                return False, f"notification failed: {type(exc).__name__}"
            req = urllib.request.Request(
                webhook, data=body, headers={"Content-Type": "application/json"}, method="POST"
            )
            with _open_pinned(opener, req, timeout=10) as resp:
                return (200 <= resp.status < 300), f"http {resp.status}"
        except urllib.error.HTTPError as exc:
            last = f"notification failed: HTTP {exc.code}"
            # 429 is a throttle, not a malformed request: the same payload sent a moment
            # later is exactly what the receiver asked for. Every other 4xx means the
            # request itself is wrong, and retrying cannot fix it.
            if 400 <= exc.code < 500 and exc.code != 429:
                return False, last
        except Exception as exc:
            last = f"notification failed: {type(exc).__name__}"
        if attempt < attempts and backoff:
            _time.sleep(backoff)
    return False, f"{last} (after {attempts} attempts)"


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

    # Phase 38 (F-38-D): creating the directory was outside the try below, so an
    # unusable BACKUP_DIR (a path under a full disk, a read-only mount, a typo'd parent)
    # raised an uncaught traceback from os.makedirs and the process died with a stack
    # trace instead of the actionable message the except block was written to produce.
    # The Phase 17 comment in that block claimed this case was handled; it was not, because
    # the exception escaped one statement earlier. Reproduced with
    # BACKUP_DIR=/proc/cannot/create -> FileNotFoundError, no alert, no status file.
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError as exc:
        # `_finish` needs the directory to exist to write status. If it does not, the
        # alert is still attempted and the status write is skipped, rather than losing the
        # notification because the disk is the thing that broke.
        result.update(
            success=False,
            exit_code=EXIT_BACKUP_FAILED,
            error=(
                f"backup directory cannot be created: {type(exc).__name__} "
                f"({os.path.basename(directory) or directory}); check the path, mount "
                "and free space"
            ),
        )
        try:
            _finish(result, directory)
        except OSError:
            pass
        return result

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
        # Phase 20: sweep now runs *while the lock is held*.
        #
        # Phase 19 found that a SIGKILL leaves a plaintext dump in `.staging-*` and that
        # the sweep's 6-hour age guard is the exposure window. The guard exists to avoid
        # deleting a live sibling's staging directory, but once we hold the exclusive
        # directory lock there is provably no other backup running, so the age guard is
        # no longer needed for that purpose. Holding the lock is the sound proof; the age
        # value is only a secondary backstop for a shared filesystem where PIDs collide.
        #
        # This shortens plaintext exposure after a crash from up to 6 hours to "the next
        # backup run", without ever risking an active run's staging directory.
        swept = backup_staging.sweep_stale_staging(
            directory, max_age=backup_staging.STALE_SWEEP_MAX_AGE_LOCKED
        )
        if swept:
            result["warnings"].append(
                f"removed {len(swept)} stale staging director(ies) from a previous crash"
            )
        return _run_scheduled_backup_locked(label, directory, result)
    finally:
        lock.__exit__(None, None, None)


def _run_scheduled_backup_locked(label: str, directory: str, result: Dict[str, Any]) -> Dict[str, Any]:
    from core import backup_service, backup_staging

    # Record that a run is under way, so monitoring can distinguish "in progress" from
    # "failed" or "never ran" instead of inferring it from a stale timestamp.
    _write_status({**result, "in_progress": True}, directory)

    # Phase 22 (P21-01): the same centralized policy the direct path uses. A scheduled
    # run that cannot satisfy the policy must fail loudly rather than publish plaintext.
    from core import backup_policy

    policy = backup_policy.evaluate()
    if not policy.allowed:
        result.update(
            success=False,
            # The policy owns the code: 11 for an unusable key (the historical contract
            # that alerting and the runbook reference), 15 for a configuration refusal.
            exit_code=policy.exit_code,
            error=policy.error,
            encryption_policy=policy.code,
            policy_refused=True,
        )
        _finish(result, directory)
        return result

    encrypting = policy.encrypting
    key_file = backup_policy.key_path()
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
            # Phase 23 (D-7): preserve the code the service chose. This overwrote every
            # failure with EXIT_BACKUP_FAILED (10), so the *scheduled* path - the one a
            # timer actually runs - reported a lock timeout as a generic backup failure
            # while `maintenance.py backup` correctly exited 18. The documented code table
            # promised an operator could tell "exceeded a bound" from "the backup failed";
            # for the scheduled path that promise was false. A default is correct here, an
            # override is not - the same shape as the `create_backup` bug Phase 22 fixed.
            result.update(
                success=False,
                exit_code=created.get("exit_code") or EXIT_BACKUP_FAILED,
                error=str(created.get("error") or "backup failed"),
            )
            if created.get("timeout"):
                result["timeout"] = True
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
            # Phase 22 (P21-05): an upload that returned 200 is not a verified copy.
            # Read the object back and compare its bytes with the digest recorded locally
            # when the archive was written. "OFFSITE_VERIFIED" must mean someone checked,
            # not that a request completed.
            expected_sha = result.get("sha256", "")
            verify_method = getattr(provider, "verify_against_record", None)
            if verify_method is not None and expected_sha:
                verified, verify_error = verify_method(
                    remote_name, expected_sha256=expected_sha,
                    expected_size=result.get("size_bytes"),
                )
            else:
                # Providers without a download implementation fall back to the metadata
                # check, and the result is recorded as weaker so the report can say so.
                verified, verify_error = provider.verify(
                    remote_name, result.get("size_bytes", -1), expected_sha
                )
            result["offsite_readback_verified"] = bool(verified)
            if verified:
                result["offsite_state"] = backup_offsite.OFFSITE_VERIFIED
            else:
                result["offsite_state"] = backup_offsite.OFFSITE_FAILED
                result["warnings"].append(
                    f"offsite read-back verification failed: {verify_error}. The object is "
                    f"present but its bytes are not proven to match this host's copy."
                )
                result["exit_code"] = EXIT_OFFSITE_FAILED

            # Remote retention only removes objects that were verified as readable. Deleting
            # an unverified object risks destroying the only good copy of something the
            # local inventory has already aged out.
            if result.get("offsite_readback_verified"):
                result["pruned_offsite"] = provider.apply_remote_retention(min_keep())
            else:
                result["pruned_offsite"] = []
                result["warnings"].append(
                    "remote retention skipped: no object was deleted while the uploaded "
                    "copy could not be verified"
                )
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
        # Phase 24: redact before the payload leaves the process. The error and warning
        # strings are assembled from several layers, one of which interpolates a raw
        # exception; nothing in them is scrubbed by construction, and the destination is
        # outside the trust boundary. See core/redaction.py - this is defence in depth, not
        # a response to an observed leak.
        try:
            from core import redaction

            payload = redaction.sanitize_payload(
                payload, secret_values=redaction.collect_secret_values()
            )
        except Exception:  # noqa: BLE001 - alerting must never break a backup run
            payload = {
                "event": payload.get("event", "unknown"),
                "error": "<payload suppressed: redaction failed>",
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
