"""Centralized secret redaction for operator-facing messages (Phase 24).

Why this exists
---------------

The alert payload forwards `result["error"]` and `result["warnings"]` verbatim to a webhook.
Those strings are assembled from several places, including one that interpolates a raw
exception (`f"{type(exc).__name__}: {exc}"`). Today every exception reaching that site comes
from a layer that does not echo credentials - libpq, `pg_dump` and SQLAlchemy all report host
and port but not the password, and the offsite module reports exception *types* rather than
messages. That was verified, not assumed.

It is still a single change away from being a leak: the guarantee lives in third-party
libraries and in one module's careful `type(exc).__name__` discipline, not in this codebase.
A driver upgrade, a new error path, or a `verbose` flag can put a DSN in a message, and the
message goes to an endpoint outside the trust boundary - possibly a third-party chat service.

So this is deliberately defence in depth rather than a fix for a live exploit. It is written
to be honest about that: `audit()` reports what it found, and the tests assert both that
secrets are removed *and* that ordinary diagnostics survive, because a redactor that eats the
useful half of the message makes outages longer.

Design
------

* **Patterns first, known values second.** DSN/userinfo patterns catch credentials in strings
  this code did not author. Registered secret *values* catch the ones that appear bare.
* **Never widen to "anything that looks random".** That destroys the message.
* **Bound length and strip control characters.** An oversize or multi-line payload can forge
  log lines at the receiving end or be silently truncated by the receiver.
* **Fail safe.** Any internal error returns a conservative message, never the raw input.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set, Tuple

#: Marker substituted for anything redacted. Chosen to be obvious in a chat window.
PLACEHOLDER = "[REDACTED]"

#: Default maximum length of any message that leaves the process. Long enough for a useful
#: diagnostic, short enough that a receiver will not truncate it mid-sentence.
DEFAULT_MAX_LENGTH = 1000

#: Environment variables whose values must never appear in a message.
SECRET_ENV_VARS: Tuple[str, ...] = (
    "DATABASE_URL",
    "DATABASE_OWNER_URL",
    "ADMIN_DATABASE_URL",
    "PGPASSWORD",
    "BACKUP_ENCRYPTION_KEY",
    "BACKUP_OFFSITE_SECRET_KEY",
    "BACKUP_OFFSITE_ACCESS_KEY",
    "BACKUP_ALERT_WEBHOOK",
    "META_APP_SECRET",
    "TELEGRAM_WEBHOOK_SECRET",
    "GEMINI_API_KEY",
    "E02_ACCOUNT_KEY_SECRET",
    "REDIS_URL",
    "QPAY_PASSWORD",
    "POSTGRES_OWNER_PASSWORD",
    "POSTGRES_APP_PASSWORD",
    "ADMIN_PASSWORD",
)


# --- Patterns -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: "re.Pattern[str]"
    replacement: str


def _rule(name: str, pattern: str, replacement: str) -> Rule:
    return Rule(name, re.compile(pattern), replacement)


#: Ordered: the first matching rule wins for a given span.
RULES: Tuple[Rule, ...] = (
    # scheme://user:password@host  ->  scheme://user:[REDACTED]@host
    # Also covers postgres://, postgresql+psycopg2://, redis://, amqp://, https://.
    _rule(
        "url-userinfo",
        r"\b(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)(?P<user>[^/\s:@]+):(?P<secret>[^/\s@]*)@",
        r"\g<scheme>\g<user>:" + PLACEHOLDER + "@",
    ),
    # A bare password= or key= value, in a query string, kwarg or prose.
    _rule(
        "key-value",
        r"(?i)\b(?P<key>password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
        r"private[_-]?key|client[_-]?secret)(?P<sep>\s*[=:]\s*)(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;&}\])]+)",
        r"\g<key>\g<sep>" + PLACEHOLDER,
    ),
    # AWS-style access key ids, which are high-entropy and never legitimate in a message.
    _rule("aws-key-id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", PLACEHOLDER),
    # Bearer tokens.
    _rule("bearer", r"(?i)\b(bearer)\s+[A-Za-z0-9._\-+/=]{8,}", r"\1 " + PLACEHOLDER),
    # JWTs: three base64url segments separated by dots. A very common webhook/API credential,
    # and invisible to the base64 rule because of the separators.
    _rule(
        "jwt",
        r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
        PLACEHOLDER,
    ),
    # Long base64 blobs that look like keys.
    #
    # Deliberately narrow. A first version matched any 40+ char run of [A-Za-z0-9+/_-], which
    # destroyed the two diagnostics an operator most needs: the sha256 digests that prove an
    # archive is intact, and the archive filenames themselves. A redactor that eats those makes
    # every restore argument longer.
    #
    # So: base64 only (must contain + or /, which hex and these filenames never do), and must
    # look random rather than being a single repeated character.
    _rule(
        "base64-blob",
        r"\b(?=[A-Za-z0-9+/]{40,}={0,2}\b)(?=[^\s]*[+/])(?=[^\s]*[0-9])(?=[^\s]*[A-Za-z])"
        r"(?!(.)\1{20,})[A-Za-z0-9+/]{40,}={0,2}\b",
        PLACEHOLDER,
    ),
)

#: Control characters that could forge a line at the receiving end, plus ANSI escapes.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


# --- Core ---------------------------------------------------------------------------------


def redact_text(text: str, *, secret_values: Optional[Iterable[str]] = None) -> str:
    """Remove credential-shaped content from ``text``.

    ``secret_values`` are literal values to scrub wherever they appear. They are applied
    longest-first so a value that contains another is not partially redacted.
    """
    if not text:
        return text
    try:
        cleaned = text

        # 1. Literal known secrets first: they are unambiguous, and a documented DSN would
        #    otherwise be caught by a pattern anyway - this makes it catch the bare value too.
        values = [v for v in (secret_values or ()) if v and len(str(v)) >= 4]
        for value in sorted(set(map(str, values)), key=len, reverse=True):
            if value in cleaned:
                cleaned = cleaned.replace(value, PLACEHOLDER)

        # 2. Pattern rules.
        for rule in RULES:
            cleaned = rule.pattern.sub(rule.replacement, cleaned)

        return cleaned
    except Exception:  # noqa: BLE001 - a redactor must never raise on the alert path
        return f"<unredactable message suppressed: {type(Exception).__name__}>"


def sanitize_message(
    text: Optional[str],
    *,
    secret_values: Optional[Iterable[str]] = None,
    max_length: int = DEFAULT_MAX_LENGTH,
) -> str:
    """Redact, collapse to a single line, bound the length, and never return a secret.

    Collapsing control characters is a security property, not cosmetics: a newline in an
    ``error`` string lets a caller forge what looks like a second log record or a second
    field at the receiving end.
    """
    if text is None:
        return ""
    try:
        cleaned = redact_text(str(text), secret_values=secret_values)
        cleaned = _ANSI_ESCAPE.sub("", cleaned)
        cleaned = _CONTROL_CHARS.sub("", cleaned)
        # Collapse every kind of line break to a single space, then squeeze runs of spaces.
        cleaned = cleaned.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
        cleaned = cleaned.replace("\t", " ")
        cleaned = re.sub(r" {2,}", " ", cleaned).strip()

        if len(cleaned) > max_length:
            head = cleaned[: max(0, max_length - 24)]
            cleaned = f"{head}... [truncated {len(cleaned) - len(head)} chars]"
        return cleaned
    except Exception:  # noqa: BLE001
        return "<message suppressed: redaction failed>"


def collect_secret_values(environ: Optional[dict] = None, extra: Optional[Iterable[str]] = None) -> List[str]:
    """Gather literal secret values worth scrubbing, from the environment plus ``extra``.

    Returns values, never names, and never logs either. An unset variable is skipped; a short
    value is skipped because scrubbing it would redact ordinary text (see the tests).
    """
    import os as _os

    env = environ if environ is not None else _os.environ
    found: Set[str] = set()
    for name in SECRET_ENV_VARS:
        value = env.get(name)
        if value and len(value) >= 8:
            found.add(value)
    # A DSN is a secret as a whole, but its password component is the part that matters and is
    # also what might appear alone. Add it if we can isolate it.
    for name in ("DATABASE_URL", "DATABASE_OWNER_URL", "ADMIN_DATABASE_URL", "REDIS_URL"):
        value = env.get(name) or ""
        match = re.search(r"://[^/\s:@]+:([^/\s@]+)@", value)
        if match and len(match.group(1)) >= 4:
            found.add(match.group(1))
    for value in extra or ():
        if value and len(str(value)) >= 8:
            found.add(str(value))
    return sorted(found, key=len, reverse=True)


# --- Payload ------------------------------------------------------------------------------


def sanitize_payload(
    payload: dict,
    *,
    secret_values: Optional[Iterable[str]] = None,
    max_length: int = DEFAULT_MAX_LENGTH,
) -> dict:
    """Return a copy of ``payload`` with every string value redacted and bounded.

    Key names are preserved so the receiving side keeps its contract. Lists of strings
    (``warnings``) are sanitized item by item and the list is bounded in count, since an
    unbounded list is its own denial-of-service surface at the receiver.
    """
    values = list(secret_values or [])
    result: dict = {}
    try:
        for key, value in payload.items():
            if isinstance(value, str):
                result[key] = sanitize_message(value, secret_values=values, max_length=max_length)
            elif isinstance(value, (list, tuple)):
                items = [
                    sanitize_message(str(item), secret_values=values, max_length=max_length)
                    for item in list(value)[:20]
                ]
                if len(value) > 20:
                    items.append(f"... [{len(value) - 20} more warnings truncated]")
                result[key] = items
            elif isinstance(value, dict):
                result[key] = sanitize_payload(value, secret_values=values, max_length=max_length)
            else:
                result[key] = value
        return result
    except Exception:  # noqa: BLE001
        return {"event": payload.get("event", "unknown"), "error": "<payload suppressed: redaction failed>"}


@dataclass
class AuditFinding:
    where: str
    rule: str
    preview: str


@dataclass
class AuditReport:
    findings: List[AuditFinding] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.findings


def audit(payload: dict, *, secret_values: Optional[Iterable[str]] = None) -> AuditReport:
    """Report which rules fire for a payload, with the offending text previewed.

    Used by tests and by `maintenance.py status --audit-alerting` style checks to prove a
    payload is clean without sending it anywhere. The preview is itself redacted.
    """
    report = AuditReport()
    for key, value in payload.items():
        texts: List[str] = []
        if isinstance(value, str):
            texts = [value]
        elif isinstance(value, (list, tuple)):
            texts = [str(item) for item in value]
        for text in texts:
            for rule in RULES:
                if rule.pattern.search(text):
                    report.findings.append(
                        AuditFinding(where=key, rule=rule.name, preview=sanitize_message(text, max_length=120))
                    )
        for secret in secret_values or ():
            if secret and str(secret) in text:
                report.findings.append(
                    AuditFinding(
                        where=key,
                        rule="known-secret-value",
                        preview=sanitize_message(text, secret_values=[secret], max_length=120),
                    )
                )
    return report
