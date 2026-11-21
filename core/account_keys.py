"""
Stage E — E-02 Phase 4.1: privacy-preserving account keys for failed-login throttling.

Why a separate module
---------------------
Key derivation and the counting policy have different threat models. Derivation exists so
that no account identifier reaches a shared store in a readable form; the counting policy
lives in `core.rate_limit`. Keeping them apart means this file can be reasoned about — and
tested — without a server, a Redis, or a database.

Why the key is keyed
--------------------
Account identifiers are low entropy: usernames are short and follow patterns
(`<brand>-mn`), and an attacker who can read keys already knows the customer population. A
plain `sha256(identifier)` is therefore not a privacy mechanism — it is a dictionary lookup
away from plaintext. `blake2b(key=secret, ...)` is a keyed MAC: without the secret the digest
cannot be attacked offline at all.

Phase 4.1: normalization follows the DATABASE, not Python
---------------------------------------------------------
Phase 4 normalized with `str.strip().casefold()`. That was wrong, and measurably so:

    SQLite     LOWER('Straße') = 'straße'        casefold('Straße') = 'strasse'
    PostgreSQL LOWER('Straße') = 'straße'        casefold('Straße') = 'strasse'

`casefold()` folds `ß` to `ss`, which neither engine does. Two accounts the database keeps
distinct therefore collapsed onto one counter — one tenant's failed logins could throttle
another tenant. In the other direction PostgreSQL folds `Σ→σ` and `Ø→ø` while SQLite's
`LOWER` is ASCII-only, so `casefold()` *also* splits identifiers the database considers the
same on SQLite.

The only normalization that is guaranteed to match the login lookup is the one the lookup
itself uses. `normalize_identifier()` therefore asks the database to evaluate the same
`LOWER(TRIM(?))` expression the query uses, on the same connection type and engine. Python
never re-implements it. This keeps the throttle honest per engine and needs no assumption
about which Unicode rules apply.

What happens without a secret
-----------------------------
In production, startup fails (see `validate_secret_for_startup`). In development and tests
`account_key()` returns None and the caller skips account-level counting; it deliberately does
**not** fall back to an unkeyed digest, which would look like protection while leaking the
customer list to anyone who can read Redis.

Secret rotation
---------------
Rotating orphans outstanding counters: their keys no longer match, so throttles reset. That is
bounded (they expire within the window) and fails in the safe direction — a rotation can never
lock anyone out.
"""
from __future__ import annotations

import hashlib
import logging
import os
from typing import Optional

logger = logging.getLogger("core.account_keys")

#: Environment variable holding the keyed-HMAC secret.
#:
#: A dedicated secret, not an existing one. The vendor secrets (`META_APP_SECRET`,
#: `TELEGRAM_WEBHOOK_SECRET`, `MANYCHAT_WEBHOOK_SECRET`) rotate on the *vendor's* schedule and
#: are shared with a third party, so reusing one would couple our login throttle to a vendor
#: rotation. `GEMINI_API_KEY` is a billable credential and must never be used as a MAC key.
SECRET_ENV_VAR = "E02_ACCOUNT_KEY_SECRET"

#: Minimum accepted secret length. Below this it is a password, not a key.
MIN_SECRET_LENGTH = 32

#: Digest length in bytes. 128 bits is far beyond collision needs and keeps keys readable.
_DIGEST_SIZE = 16

#: Personalisation string. blake2b caps this at 16 bytes.
_PERSON = b"gerege-e02-acct1"

#: Cached secret. `None` means "not yet read"; `""` means "read and absent".
_secret: Optional[str] = None


def _read_secret() -> str:
    return (os.getenv(SECRET_ENV_VAR, "") or "").strip()


def refresh_secret() -> Optional[str]:
    """
    Re-read the secret from the environment.

    Called at startup, and by tests and operators after a change. Returns the secret, or None
    when unset. Never logs the value.
    """
    global _secret
    value = _read_secret()
    _secret = value or None
    if _secret is None:
        logger.warning(
            "E-02: %s is not set, so account-level failed-login throttling is DISABLED. "
            "Password guessing against one account can proceed by rotating source IPs. "
            "Production refuses to start without it; see .env.example.",
            SECRET_ENV_VAR,
        )
    return _secret


def get_secret() -> Optional[str]:
    """The configured secret, read from the environment on first use."""
    global _secret
    if _secret is None:
        _secret = _read_secret() or None
    return _secret


def validate_secret_for_startup() -> None:
    """
    Fail closed in production when the account-key secret is unusable.

    Phase 4 logged a warning and carried on, which silently disabled account-level throttling
    in the deployment that needed it most. A security control that can be off without anyone
    noticing is worse than one that is absent, because it is believed to be present.

    Development and tests are unaffected: an explicit unset secret there is a supported
    configuration (`test_134`), and account counting degrades to off rather than to an unkeyed
    hash.

    Raises:
        RuntimeError: in production mode, when the secret is unset, blank, or too short.
    """
    from core.security import is_production_mode

    raw = os.getenv(SECRET_ENV_VAR, "")
    value = raw.strip()

    if not is_production_mode():
        return

    if not value:
        raise RuntimeError(
            f"{SECRET_ENV_VAR} is required when running in production: without it the "
            "account-level failed-login throttle would be silently disabled and one account "
            "could be guessed against by rotating source IPs. Generate one with "
            "'python -c \"import secrets; print(secrets.token_urlsafe(48))\"' and set it in the "
            "environment. See docs/deployment/PRODUCTION_DEPLOYMENT.md section 1.2."
        )
    if len(value) < MIN_SECRET_LENGTH:
        raise RuntimeError(
            f"{SECRET_ENV_VAR} is too short (minimum length {MIN_SECRET_LENGTH} characters). "
            "A short value is a password, not a key. Generate one with "
            "'python -c \"import secrets; print(secrets.token_urlsafe(48))\"'. "
            "The value itself is deliberately not printed."
        )


def normalize_identifier(identifier: Optional[str]) -> str:
    """
    Normalize an account identifier exactly the way the login query compares it.

    The query is `LOWER(TRIM(client_username)) = LOWER(?) OR LOWER(TRIM(page_id)) = LOWER(?)`,
    so the throttle asks the database to evaluate that same expression. Whatever the engine
    does — SQLite's ASCII-only `LOWER`, PostgreSQL's Unicode-aware one and its locale rules —
    the key agrees with it by construction rather than by a reimplementation that happens to
    match for ASCII and quietly diverges elsewhere.

    A previous version used `str.strip().casefold()`. That folded `ß→ss`, merging accounts the
    database keeps distinct, and did not fold `Σ`/`Ø` on SQLite where the database's own
    comparison is ASCII-only. Both directions are wrong; see `tests/test_e02_phase41_hardening.py`.

    Returns the empty string for empty/None input; callers treat that as "no account key".
    """
    if not identifier:
        return ""
    raw = str(identifier).strip()
    if not raw:
        return ""
    import database

    try:
        return database.sql_lower_trim(raw)
    except Exception as exc:  # pragma: no cover - depends on a live database
        # E-02 Phase 4.2, audit A. `resolve_account_identity` has a documented fallback for a
        # database outage, but the fallback was unreachable: deriving the key re-entered the
        # database here, so the original exception escaped and the account throttle failed
        # open instead of degrading. Degrade to trimming only. That collapses strictly fewer
        # identifiers than the engine's own comparison, so the worst case during an outage is
        # one account temporarily getting more than one budget — never two unrelated accounts
        # sharing a counter, which is the failure Phase 4.1 ruled out.
        import logging

        logging.getLogger("core.account_keys").error(
            f"Identifier normalization failed ({exc}); using the trimmed identifier"
        )
        return raw


def account_key(identifier: Optional[str]) -> Optional[str]:
    """
    Derive the opaque, keyed digest used as the account identity in the rate-limit store.

    Returns None when the identifier is empty *or* no secret is configured. A None result means
    "do not do account-level counting", never "use a default key" — collapsing every
    unidentified login into one shared bucket would let a stranger throttle everybody.
    """
    secret = get_secret()
    if not secret:
        return None
    normalized = normalize_identifier(identifier)
    if not normalized:
        return None
    return keyed_digest(normalized)


def keyed_digest(value: str) -> str:
    """
    Keyed digest of an already-canonical value.

    Shared with the canonical-account path so an account id and a raw identifier can never
    collide: both go through the same MAC.
    """
    secret = get_secret()
    if not secret:
        raise RuntimeError(
            f"{SECRET_ENV_VAR} is not configured, so no account key can be derived"
        )
    digest = hashlib.blake2b(
        value.encode("utf-8"),
        digest_size=_DIGEST_SIZE,
        key=secret.encode("utf-8"),
        person=_PERSON,
    )
    return digest.hexdigest()
