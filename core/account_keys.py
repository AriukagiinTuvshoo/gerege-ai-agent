"""
Stage E — E-02 Phase 4: privacy-preserving account keys for failed-login throttling.

Why a separate module
---------------------
Key derivation and the counting policy have different threat models. Derivation exists so
that a username never reaches a shared store in a readable form; the counting policy lives
in `core.rate_limit`. Keeping them apart means this file can be reasoned about — and tested
— without a server, a Redis, or a database.

Why the key is keyed
--------------------
The identifier is a *username*, and usernames are low entropy: they are short, they follow
patterns (`<brand>-mn`), and an attacker who can read keys already knows the customer
population. A plain `sha256(username)` is therefore not a privacy mechanism at all — it is a
dictionary lookup away from plaintext, and rainbow tables for common names already exist.
`blake2b(key=secret, ...)` is a keyed MAC: without the secret, the digest cannot be
attacked offline at all. That is the entire point.

What happens without a secret
-----------------------------
Nothing. `account_key()` returns None and the caller skips account-level counting entirely
(see the policy note in `core/rate_limit`). It deliberately does **not** fall back to an
unkeyed digest: a silent fallback would be worse than the gap it papers over, because it
would look like protection while leaking the customer list to anyone who can read Redis.
This is fail-closed on *privacy* and fail-open on *availability* — the honest trade for an
optional secret, and it is logged loudly at startup.

Secret rotation
---------------
Rotating the secret orphans outstanding counters: their keys no longer match, so the
throttle resets. That is bounded and self-healing (the counters expire within the window),
and it is the correct direction to fail — a rotation should never *lock* anyone out.
"""
from __future__ import annotations

import hashlib
import logging
import os
from typing import Optional

logger = logging.getLogger("core.account_keys")

#: Environment variable holding the keyed-HMAC secret.
#:
#: A dedicated secret, not an existing one. `META_APP_SECRET` /
#: `TELEGRAM_WEBHOOK_SECRET` / `MANYCHAT_WEBHOOK_SECRET` are per-vendor verification
#: secrets that rotate on the *vendor's* schedule and are shared with a third party;
#: reusing one would couple our login throttle to a vendor rotation (a webhook secret
#: change would silently reset every account counter) and would widen that secret's blast
#: radius to login identifiers. `GEMINI_API_KEY` is a billable credential and must never be
#: used for hashing.
SECRET_ENV_VAR = "E02_ACCOUNT_KEY_SECRET"

#: Digest length in bytes. 128 bits is far beyond collision needs here and keeps the key
#: short enough to be readable in a Redis key listing.
_DIGEST_SIZE = 16

#: Personalisation string, so a digest produced here can never collide with a digest of the
#: same input produced for another purpose with the same secret. blake2b caps this at 16
#: bytes, so it is a compact domain tag rather than a readable sentence.
_PERSON = b"gerege-e02-acct1"

#: Cached secret. `None` means "not yet read"; `""` means "read and absent".
_secret: Optional[str] = None


def _read_secret() -> str:
    return (os.getenv(SECRET_ENV_VAR, "") or "").strip()


def refresh_secret() -> Optional[str]:
    """
    Re-read the secret from the environment.

    Called at startup, and by tests and operators after a change. Returns the secret, or
    None when unset.
    """
    global _secret
    value = _read_secret()
    _secret = value or None
    if _secret is None:
        logger.warning(
            "E-02: %s is not set, so account-level failed-login throttling is DISABLED. "
            "Password guessing against one account can proceed by rotating source IPs. "
            "Set this variable to a long random value (see .env.example).",
            SECRET_ENV_VAR,
        )
    return _secret


def get_secret() -> Optional[str]:
    """The configured secret, read from the environment on first use."""
    global _secret
    if _secret is None:
        _secret = _read_secret() or None
    return _secret


def normalize_identifier(identifier: Optional[str]) -> str:
    """
    Normalize an account identifier the same way the real lookup does.

    The login query is `LOWER(TRIM(client_username)) = LOWER(?)`, so lookup is already
    case-insensitive and whitespace-insensitive. If the throttle key were *not* normalized
    identically, each spelling of one account would get its own budget and the limit would
    multiply by the number of spellings an attacker cares to try — `Acme-Mn`, `acme-mn`,
    `  ACME-MN  ` and so on.

    `casefold()` is used rather than `lower()`: it is the Unicode-correct case mapping, and
    for the identifiers this accepts it agrees with SQLite's `LOWER` on ASCII while also
    folding non-ASCII forms that `lower()` leaves distinct. Where `casefold()` is *more*
    aggressive than the database lookup, the effect is that two identifiers the database
    treats as distinct would share one counter — so the direction of any disagreement is
    toward sharing a budget, never toward splitting one. Sharing is the safe direction: it
    can only ever over-throttle, and only for identifiers that differ by Unicode case
    presentation of the same name. `test_37` pins the other half of this: identifiers that
    differ by a character casefolding does not touch stay separate.

    Returns the empty string for empty/None input; callers must treat that as "no account
    key" rather than counting all empty identifiers together.
    """
    if not identifier:
        return ""
    return str(identifier).strip().casefold()


def account_key(identifier: Optional[str]) -> Optional[str]:
    """
    Derive the opaque, keyed digest used as the account identity in the rate-limit store.

    Returns None when the identifier is empty *or* no secret is configured. A None result
    means "do not do account-level counting", never "use a default key" — collapsing every
    unidentified login into one shared bucket would let a stranger throttle everybody.
    """
    secret = get_secret()
    if not secret:
        return None
    normalized = normalize_identifier(identifier)
    if not normalized:
        return None
    digest = hashlib.blake2b(
        normalized.encode("utf-8"),
        digest_size=_DIGEST_SIZE,
        key=secret.encode("utf-8"),
        person=_PERSON,
    )
    return digest.hexdigest()
