"""Phase 45 (F-44-F) — refuse to start with a secret that is not secret.

===============================================================================
WHY THIS MODULE EXISTS
===============================================================================
Phase 44 found that production secret handling rested on documentation. The templates
(`.env.example`, `docs/deployment/PRODUCTION_ENV_TEMPLATE.env`) leave every secret blank
with a `generate:` hint, and `_verify_admin_password` did refuse the default admin password
in production — but nothing applied that rule anywhere else. Two consequences were
measured:

  * ``core/security.py``'s predecessor line

        ``META_VERIFY_TOKEN = os.getenv("META_VERIFY_TOKEN", "agent_verify_secret_token_123")``

    completed Meta's subscription handshake with a value printed in this repository, in
    production, with no warning. (Fixed in F-44-B; this module is why the *class* of
    defect cannot silently return.)

  * a deployment that forgot one line of the template came up **healthy**, serving traffic
    with a publicly known credential. Health checks cannot see this: the process is fine,
    the secret is not.

The asymmetry that makes this worth code rather than a checklist: a missing secret almost
never breaks anything at startup. It fails much later, as a webhook accepted that should
have been rejected, or a provider call that succeeds for the wrong reason.

===============================================================================
THE RULE
===============================================================================
Each required secret is checked for four shapes, in order:

1. **unset / empty**       -> ``missing``
2. **published default**   -> ``placeholder`` (the value shipped in this repo)
3. **template residue**    -> ``placeholder`` (``<generate: …>``, ``changeme``, ``your-…``)
4. **too short**           -> ``weak`` (fewer than ``MIN_SECRET_LENGTH`` characters)

Any of them is a startup error **in production**. Development and the test suite keep
working: the checks are advisory there, because a developer needs to be able to run the
app without provisioning six secrets, and nothing is exposed on localhost.

**Secret values never appear in a message, an exception, or a log line.** Only the
variable *name*, the *reason* and — for a length problem — the *length* are reported.
That is deliberate: the fastest way to leak a credential is to print it in the error that
tells you it is misconfigured.

===============================================================================
WHAT THIS MODULE DOES NOT DO
===============================================================================
It does not generate, rotate or store secrets. It does not know which provider issued one.
It cannot tell that a *strong-looking* value is wrong — only that it is not obviously
public, empty or short. It is a floor, not a guarantee.
"""

from __future__ import annotations

import logging
import os
from typing import Dict, List, NamedTuple, Optional

logger = logging.getLogger(__name__)

#: Minimum length for a secret that must be unguessable. 16 characters of base64/hex is
#: ~96 bits; the templates generate 24–32 bytes, so a real deployment passes easily and a
#: human-typed `secret123` does not.
MIN_SECRET_LENGTH = 16

#: Values that carry no secrecy because they are published in this repository or are the
#: obvious thing an operator types when they mean "replace me". Compared case-insensitively
#: after trimming.
PUBLISHED_OR_PLACEHOLDER_VALUES = frozenset(
    {
        # The Meta verify-token default that shipped in main.py, models.py and migration
        # 0001 (F-44-B). Kept here so a revert of the F-44-B fix is caught.
        "agent_verify_secret_token_123",
        # The admin password default in database.py (already guarded separately, listed so
        # there is one authoritative list).
        "admin2026",
        # The `VERIFY_TOKEN` default in executive_bot_service.py: the Telegram
        # `/start <secret>` owner secret (F-51-5). Guarded at the point of use by
        # `core.security.owner_command_secret_is_usable`, listed here so this stays the one
        # authoritative list of values this repository publishes.
        "gerege_verify_2026",
        # Generic residues.
        "changeme",
        "change_me",
        "change-me",
        "password",
        "secret",
        "test",
        "dev",
        "development",
        "example",
        "todo",
        "none",
        "null",
    }
)

#: Substrings that mark an unfilled template or a placeholder rather than a secret.
PLACEHOLDER_MARKERS = ("<generate", "<from", "your-", "your_", "replace", "xxx", "placeholder")


class SecretIssue(NamedTuple):
    """One reason a named variable is not acceptable. Never carries the value."""

    name: str
    reason: str  # "missing" | "placeholder" | "weak"
    detail: str  # human-readable, value-free


#: The variables a production deployment must set to a real secret.
#:
#: Deliberately a small, defensible list. Each entry is a credential whose absence or
#: default is exploitable *by itself*; optional integrations (`QPAY_PASSWORD`,
#: `OPENAI_API_KEY`) are absent by design in many deployments and are not listed.
REQUIRED_PRODUCTION_SECRETS: Dict[str, str] = {
    "E02_ACCOUNT_KEY_SECRET": "account-key derivation for the rate limiter",
}

#: `META_VERIFY_TOKEN` is enforced at the point of use, not here.
#:
#: F-44-B's fix is `core.security.meta_verify_token_is_usable`, consulted by the GET
#: `/webhook` handler itself: in production an unset/empty/placeholder token makes that
#: endpoint answer 403 and log the refusal. That is the correct layer, because the token only
#: matters to Meta traffic - a deployment that runs no Meta integration should not be blocked
#: from starting. Requiring it at startup was measured to be both redundant and harmful: it
#: turned every suite that enters a production lifespan into a failure, and (via the
#: META_VERIFY_TOKEN => META_APP_SECRET conditional pair) switched on webhook signature
#: enforcement for unrelated tests. The routing half of F-44-B is covered by
#: `test_e45_final_hardening.TestMetaVerifyToken`, which asserts the endpoint refuses the
#: published default under production.

#: `ADMIN_PASSWORD` is deliberately NOT in this list.
#:
#: It is already enforced, and better, elsewhere: `database.authenticate_admin` refuses
#: the default in production at the point of use and fails closed, which is a stronger
#: guarantee than refusing at startup (a process that starts and never authenticates anyone is
#: not a breach). Re-checking it here was also measured to be actively harmful: the value is
#: legitimately absent in development, and asserting it at startup broke sixteen suites that
#: authenticate with the documented development credential while telling them nothing about a
#: real production risk. One rule, one place - the F-44-F finding was about secrets that had
#: NO enforcement, not about duplicating the one that had it.
SECRETS_ENFORCED_ELSEWHERE: Dict[str, str] = {
    "ADMIN_PASSWORD": "database.authenticate_admin refuses the default in production",
    "META_VERIFY_TOKEN": (
        "core.security.meta_verify_token_is_usable makes GET /webhook answer 403 in "
        "production when the token is unset, empty or the published placeholder (F-44-B)"
    ),
}

#: Secrets checked only when their integration is actually configured (name -> the variable
#: whose presence means the integration is in use). A deployment that does not use a provider
#: must not be forced to invent a secret for it.
#:
#: `META_APP_SECRET` is here rather than in the required set, and the reasoning matters. It
#: is the signature key for `POST /webhook`, so it is mandatory **whenever Meta is wired up**
#: - which is exactly what `META_VERIFY_TOKEN` being set tells us, since that token exists
#: only to complete Meta's handshake. A deployment that does not run the Meta integration has
#: no `POST /webhook` traffic to verify and no reason to hold the key. Making it
#: unconditionally required was measured to be wrong in a second way: it forced the test
#: suite to set it globally, which switched on signature enforcement for every webhook test
#: and turned `test_meta_webhook_image_url_cannot_reach_loopback` from a skip into a 403.
#: The pair is now consistent: handshake configured => signature key required.
#: `VERIFY_TOKEN` (the Telegram owner-command secret, F-51-5) is deliberately NOT required
#: here, conditionally or otherwise. After the fix an unset value is the *safe* one: no secret
#: can re-register the report recipient, so a deployment that never sets it has a strictly
#: smaller attack surface than one that does. Forcing operators to invent a secret they do not
#: need is the mistake this file already documents for `META_APP_SECRET` — it was measured to
#: turn unrelated suites into failures while removing no risk. The enforcement lives at the
#: point of use, in `core.security.owner_command_secret_is_usable`.
CONDITIONAL_SECRETS: Dict[str, str] = {
    "META_APP_SECRET": "META_VERIFY_TOKEN",
    "TELEGRAM_WEBHOOK_SECRET": "TELEGRAM_BOT_TOKEN",
    "BACKUP_OFFSITE_SECRET_KEY": "BACKUP_OFFSITE_ENDPOINT",
}


def classify_secret(name: str, value: Optional[str]) -> Optional[SecretIssue]:
    """Return why ``value`` is unusable for ``name``, or ``None`` when it is acceptable.

    The returned detail never contains the value: an operator who reads a log or a crash
    report must not receive the credential they were trying to protect.
    """
    raw = "" if value is None else str(value)
    trimmed = raw.strip()

    if not trimmed:
        return SecretIssue(name, "missing", f"{name} is not set")

    lowered = trimmed.lower()
    if lowered in PUBLISHED_OR_PLACEHOLDER_VALUES:
        return SecretIssue(
            name,
            "placeholder",
            f"{name} is a published default value that ships in this repository",
        )
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return SecretIssue(
            name,
            "placeholder",
            f"{name} still contains an unfilled template or placeholder marker",
        )
    if len(trimmed) < MIN_SECRET_LENGTH:
        # The length is safe to report; the value is not.
        return SecretIssue(
            name,
            "weak",
            f"{name} is {len(trimmed)} characters, below the {MIN_SECRET_LENGTH}-character floor",
        )
    return None


def _is_production() -> bool:
    """Same predicate the rest of the codebase uses, imported lazily to avoid a cycle."""
    env = os.getenv("ENV", "").strip().lower()
    strict = os.getenv("STRICT_SECURITY", "").strip().lower()
    return env in ("production", "prod") or strict in ("1", "true", "yes")


def evaluate_secrets(environ: Optional[Dict[str, str]] = None) -> List[SecretIssue]:
    """Collect every issue across the required and conditional secret sets.

    Pure with respect to the process environment when ``environ`` is supplied, which is
    what makes the tests deterministic: they hand in a dict instead of mutating os.environ.
    """
    env = os.environ if environ is None else environ
    issues: List[SecretIssue] = []

    for name in REQUIRED_PRODUCTION_SECRETS:
        issue = classify_secret(name, env.get(name))
        if issue:
            issues.append(issue)

    for name, gate in CONDITIONAL_SECRETS.items():
        gate_value = str(env.get(gate, "") or "").strip()
        if not gate_value:
            continue  # the integration is not configured; its secret is not required
        issue = classify_secret(name, env.get(name))
        if issue:
            issues.append(issue)

    return issues


class InsecureSecretError(RuntimeError):
    """Raised at startup when production is configured with an unusable secret."""


def validate_production_secrets(environ: Optional[Dict[str, str]] = None) -> List[SecretIssue]:
    """Fail startup in production when a required secret is missing, default or weak.

    Returns the issues (empty when fine) so a caller can log them at ``warning`` in
    development. Raises :class:`InsecureSecretError` in production.

    The exception message lists **names and reasons only**. It is designed to be safe to
    paste into a ticket.
    """
    issues = evaluate_secrets(environ)
    if not issues:
        return []

    production = _is_production() if environ is None else (
        str(environ.get("ENV", "")).strip().lower() in ("production", "prod")
        or str(environ.get("STRICT_SECURITY", "")).strip().lower() in ("1", "true", "yes")
    )

    # `detail` carries the reason in words (and, for a weak value, its length - never the
    # value). `reason` alone would say "weak" without saying how weak, which is the one
    # quantity an operator can safely be told.
    rendered = "; ".join(f"{i.name}: {i.reason} ({i.detail})" for i in issues)
    if production:
        raise InsecureSecretError(
            "refusing to start: required production secrets are unusable - "
            f"{rendered}. Generate real values (see docs/deployment/"
            "PRODUCTION_ENV_TEMPLATE.env) and restart. No secret value is printed here."
        )

    logger.warning(
        "secrets are not production-ready (%s). Development continues; "
        "production would refuse to start.", rendered,
    )
    return issues
