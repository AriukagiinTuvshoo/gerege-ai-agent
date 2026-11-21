"""Centralized backup security policy.

Phase 22 (P21-01). Before this module the only encryption policy was a single
environment variable read inline:

    mode = os.getenv("BACKUP_ENCRYPTION", "on").strip().lower()
    if mode in ("off", "0", "false", "no"):
        return False
    return True

That is one typo away from publishing a full copy of every tenant's data in
plaintext, and it does not care what environment it runs in: `ENV=production
BACKUP_ENCRYPTION=off` produced a plaintext archive with exit code 0. Two
comments in the tree claimed the opposite ("fails closed in production"), so the
documented guarantee and the implemented behaviour disagreed.

This module is now the single place that decides whether a backup may be written
in plaintext. Every entry point - the maintenance CLI, the migration CLI,
deploy.sh, the scheduled runner and any direct ``create_backup()`` caller - goes
through :func:`evaluate`, so a new caller cannot accidentally re-open the hole by
forgetting to ask.

Design rules:

* **Production never publishes plaintext.** Not with ``off``, not with an empty
  value, not with an unrecognised value. There is no override, because an
  override is the thing that gets typo'd at 3am.
* **Unrecognised values fail closed.** ``BACKUP_ENCRYPTION=maybe`` refuses rather
  than guessing; a typo must not silently select a weaker mode.
* **Non-production is explicit about being weaker.** ``BACKUP_ENCRYPTION=off``
  outside production is honoured (local development needs it) but the resulting
  archive is labelled ``encryption_format="none"`` and carries a warning, so it
  can never be mistaken for an encrypted restore point.
* **Errors never echo key material.** Messages name variables and reasons only.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

#: Values that select authenticated encryption.
_ENCRYPTED_VALUES = frozenset({"on", "1", "true", "yes", "required", "require", "enabled"})

#: Values that explicitly ask for plaintext. Only legal outside production.
_PLAINTEXT_VALUES = frozenset({"off", "0", "false", "no", "disabled", "none", "plaintext"})

#: A backup may be produced encrypted, or refused. Never plaintext in production.
MODE_ENCRYPTED = "encrypted"

#: Byte lengths `core.backup_crypto.load_key` can accept: 32 raw bytes, or the common
#: text encodings of a 32-byte key (base64 = 44 with padding, hex = 64). Kept deliberately
#: narrow - anything else is a mistake worth failing closed on.
_ACCEPTABLE_KEY_SIZES = frozenset({32, 43, 44, 64})
MODE_PLAINTEXT = "plaintext"


@dataclass(frozen=True)
class BackupSecurityPolicy:
    """The resolved decision for this process.

    ``allowed`` is the only thing a caller must honour: when it is False the
    backup must not be attempted at all, and the caller must return ``error``.
    """

    allowed: bool
    mode: str
    production: bool
    reason: str
    error: str = ""
    warning: str = ""
    #: Machine-readable tag for the CLI and the status file.
    code: str = ""
    #: Exit status the caller must return. The policy states it so that every entry point
    #: agrees: the documented codes are 11 (encryption failed) and 15 (not configured), and
    #: a missing key has always been 11. Splitting this out here keeps the pre-existing
    #: contract instead of silently reclassifying a failure class that alerting may key on.
    exit_code: int = 15

    @property
    def encrypting(self) -> bool:
        """True when the archive must be encrypted (only meaningful if allowed)."""
        return self.allowed and self.mode == MODE_ENCRYPTED


def is_production() -> bool:
    """Production detection, delegated to the application's single convention.

    ``core.security.is_production_mode()`` already defines production as
    ``ENV=production|prod`` or ``STRICT_SECURITY=1``. Re-deriving it here would be
    the same class of bug this module exists to remove - two places that can
    disagree - so this defers to it. An import cycle would mean the caller is
    being imported before the app is ready; treat that as production, because
    guessing "not production" is how plaintext escapes.
    """
    try:
        from core.security import is_production_mode

        return is_production_mode()
    except Exception:  # pragma: no cover - import cycle / partially initialised
        env = os.getenv("ENV", "").strip().lower()
        strict = os.getenv("STRICT_SECURITY", "").strip().lower()
        return env in ("production", "prod") or strict in ("1", "true", "yes")


def encryption_required() -> bool:
    """Kept for callers that only need the boolean.

    Equivalent to ``evaluate().encrypting`` for every configuration that is
    *allowed*; for a refused configuration it returns True so that a caller which
    ignores :func:`evaluate` fails closed instead of silently writing plaintext.
    """
    return evaluate().encrypting or not evaluate().allowed


def key_path() -> Optional[str]:
    """The configured key file, or None. Never returns key *material*."""
    path = os.getenv("BACKUP_ENCRYPTION_KEY_FILE", "").strip()
    return path or None


def evaluate() -> BackupSecurityPolicy:
    """Decide whether a backup may run, and in which mode.

    Pure function of the environment; no I/O, so it can be called before any
    database connection is opened. That ordering matters: P21-01 requires the
    refusal to happen *before* tenant data is read.
    """
    production = is_production()
    raw = os.getenv("BACKUP_ENCRYPTION", "on").strip()
    mode = raw.lower()

    # An unrecognised value is a configuration error, not a request for plaintext.
    # Guessing here would make `BACKUP_ENCRYPTION=of` (a typo) silently produce a
    # plaintext archive on the one host where someone was trying to encrypt.
    if mode not in _ENCRYPTED_VALUES and mode not in _PLAINTEXT_VALUES:
        return BackupSecurityPolicy(
            allowed=False,
            mode=MODE_ENCRYPTED,
            production=production,
            reason=f"unrecognised BACKUP_ENCRYPTION value {raw!r}",
            error=(
                f"BACKUP_ENCRYPTION={raw!r} is not a recognised value. Use one of "
                f"'on' (default) or 'off' (non-production only). Refusing to guess: an "
                f"unrecognised value must not silently select a weaker mode."
            ),
            code="ENCRYPTION_CONFIG_INVALID",
            exit_code=15,
        )

    wants_encryption = mode in _ENCRYPTED_VALUES

    if not wants_encryption and production:
        # The Phase 21 finding. In production there is no plaintext path, and no
        # acknowledgement variable to re-enable one.
        return BackupSecurityPolicy(
            allowed=False,
            mode=MODE_ENCRYPTED,
            production=True,
            reason="plaintext requested in production",
            error=(
                "BACKUP_ENCRYPTION=off is not permitted in production "
                "(ENV=production|prod or STRICT_SECURITY=1). A backup is a complete copy "
                "of every tenant's data; publishing it in plaintext is not a supported "
                "production mode. Set BACKUP_ENCRYPTION=on and configure "
                "BACKUP_ENCRYPTION_KEY_FILE. No backup was written and no tenant data "
                "was read."
            ),
            code="ENCRYPTION_DISABLED_IN_PRODUCTION",
            exit_code=15,
        )

    if not wants_encryption:
        return BackupSecurityPolicy(
            allowed=True,
            mode=MODE_PLAINTEXT,
            production=False,
            reason="plaintext explicitly permitted outside production",
            warning=(
                "BACKUP_ENCRYPTION is off: the archive is plaintext tenant data. "
                "This is a non-production mode and must never be used for real data."
            ),
            code="PLAINTEXT_NON_PRODUCTION",
        )

    # Encryption wanted: the key must exist and be usable. Checked here so the
    # refusal happens before the dump, and so an empty/unreadable key is a policy
    # failure rather than a formatting error three layers deeper.
    path = key_path()
    if not path:
        return BackupSecurityPolicy(
            allowed=False,
            mode=MODE_ENCRYPTED,
            production=production,
            reason="encryption required but no key file configured",
            error=(
                "encryption is required but BACKUP_ENCRYPTION_KEY_FILE is not set. "
                "No backup was written and no tenant data was read. Configure the key "
                "file (see docs/operations/BACKUP_ENCRYPTION.md)"
                + (
                    "."
                    if production
                    else ", or set BACKUP_ENCRYPTION=off for a non-production environment."
                )
            ),
            code="ENCRYPTION_KEY_MISSING",
            # No key configured at all is the documented "not configured" class (15); the
            # encryption step never begins. A key that is configured but unusable is a
            # different failure (11, below) and alerting may treat them differently.
            exit_code=15,
        )

    if not os.path.exists(path):
        return BackupSecurityPolicy(
            allowed=False,
            mode=MODE_ENCRYPTED,
            production=production,
            reason="key file does not exist",
            # Deliberately only the basename: the full path can disclose host layout.
            error=(
                f"encryption key file not found: {os.path.basename(path)}. "
                "No backup was written."
            ),
            code="ENCRYPTION_KEY_MISSING",
            exit_code=11,
        )
    if not os.path.isfile(path):
        return BackupSecurityPolicy(
            allowed=False,
            mode=MODE_ENCRYPTED,
            production=production,
            reason="key path is not a regular file",
            error=(
                f"BACKUP_ENCRYPTION_KEY_FILE is not a regular file "
                f"({os.path.basename(path)}). No backup was written."
            ),
            code="ENCRYPTION_KEY_INVALID",
            exit_code=11,
        )
    try:
        size = os.path.getsize(path)
    except OSError:
        return BackupSecurityPolicy(
            allowed=False,
            mode=MODE_ENCRYPTED,
            production=production,
            reason="key file unreadable",
            error="encryption key file is unreadable. No backup was written.",
            code="ENCRYPTION_KEY_INVALID",
            exit_code=11,
        )
    if size == 0:
        return BackupSecurityPolicy(
            allowed=False,
            mode=MODE_ENCRYPTED,
            production=production,
            reason="key file is empty",
            error=(
                "encryption key file is empty (0 bytes). No backup was written. "
                "A zero-length key is never a valid AES-256 key."
            ),
            code="ENCRYPTION_KEY_INVALID",
            exit_code=11,
        )

    # Phase 22: a key of the wrong length is *unusable*, not merely unusual. The checks
    # above catch "not a file" and "empty", which let a 5-byte key through as ENCRYPTED -
    # the run then failed deep in the crypto layer with 12 (integrity), reporting an
    # encryption failure for what is a configuration error. The code table exists so an
    # operator can tell "my key is wrong" (11) from "the archive did not authenticate"
    # (12); a key that cannot possibly be AES-256 belongs in the first category. The
    # length is reported, never the content.
    if size not in _ACCEPTABLE_KEY_SIZES:
        return BackupSecurityPolicy(
            allowed=False,
            mode=MODE_ENCRYPTED,
            production=production,
            reason="key file is not a valid AES-256 key length",
            error=(
                f"encryption key file is {size} bytes; an AES-256 key must be 32 raw "
                "bytes (or one of the encoded forms the loader accepts). No backup was "
                "written. Check how the key was generated - see "
                "docs/operations/BACKUP_ENCRYPTION.md."
            ),
            code="ENCRYPTION_KEY_INVALID",
            exit_code=11,
        )

    return BackupSecurityPolicy(
        allowed=True,
        mode=MODE_ENCRYPTED,
        production=production,
        reason="authenticated encryption enabled",
        code="ENCRYPTED",
    )


def describe() -> dict:
    """Operator-facing summary for `maintenance.py status` / `preflight`.

    Reports configuration only - never key content, never a DSN.
    """
    policy = evaluate()
    return {
        "production": policy.production,
        "mode": policy.mode,
        "allowed": policy.allowed,
        "code": policy.code,
        "reason": policy.reason,
        "key_configured": bool(key_path()),
        "error": policy.error,
        "warning": policy.warning,
    }
