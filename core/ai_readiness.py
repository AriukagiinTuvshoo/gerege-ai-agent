"""
Truthful AI-readiness state — what a generation call actually did (Phase 50, F-50-1).

Why this module exists
----------------------
``agent.is_gemini_ready()`` is ``bool(agent.default_client)``, and building that client
(``genai.Client(api_key=...)``) performs **no network I/O**. So it reports "ready" for a key
that is wrong, revoked, over quota, or simply unreachable from the current network.
``/api/health`` published that as ``gemini_ready``, sitting next to two honestly named
neighbours — ``meta_token_configured`` and ``telegram_configured`` — which say *configured*
and nothing more.

Measured on 2026-11-26 with a real key in ``.env`` and no route to Google from the sandbox:

    /api/health -> {"gemini_ready": true, ...}
    /api/chat   -> 200, {"model": "fallback"}        # every generation attempt failed
    log         -> ERROR:agent:Gemini API алдаа: TLS/SSL connection has been closed (EOF)

An operator reading ``gemini_ready: true`` would conclude the AI works. This is the same
class of defect as F-48A-3 (the worker-health endpoint asserting a scheduler topology it
never observed), fixed the same way: report what was observed, and name the difference.

Design rules
------------
1. ``/api/health`` is **unauthenticated** and deliberately carries no exception text — see
   the comment on ``/api/ready`` in ``main.py``. ``health_fields()`` therefore publishes a
   closed enum plus counters, never a message. The redacted excerpt stays in ``snapshot()``
   for logs and tests.
2. Nothing here stores a credential. The excerpt passes through ``core.redaction`` (which
   already knows ``GEMINI_API_KEY``), and the classification is a closed set, so a new SDK
   error string cannot become a new disclosure path.
3. State is per-process, in-memory and best-effort: it is a diagnostic, not a record. A
   restart resets it to "never exercised", which is the truth. Recording must never be able
   to break a request, so every public entry point swallows its own errors.
4. Outcomes are tracked per *key scope*. A tenant's own ``gemini_api_key`` proving itself
   says nothing about the administrator's key, so ``scope="page"`` observations never move
   the default verdict — otherwise a working tenant would mask a broken platform key.
"""

from __future__ import annotations

import logging
import re
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------------------------
# Closed vocabularies. Both are published, so neither may grow without thought.
# ----------------------------------------------------------------------------------------

#: Key scopes. ``default`` is the administrator's ``GEMINI_API_KEY``; ``page`` is a tenant's
#: own key stored in ``pages.gemini_api_key``.
SCOPES = ("default", "page")

#: Failure classes reported to an operator. Deliberately coarse: enough to act on
#: ("rotate the key" vs "the network is down" vs "the model id is wrong"), coarse enough
#: that it cannot carry a credential or an internal detail.
ERROR_CLASSES = (
    "auth",         # key invalid, revoked, not permitted -> rotate / re-issue the key
    "quota",        # rate limit or quota exhausted -> billing / backoff
    "model",        # model id not found or not enabled -> check GEMINI_MODEL
    "network",      # DNS, TLS, timeout, connection reset -> egress / proxy / firewall
    "bad_request",  # the request itself was rejected -> payload or SDK/version problem
    "server",       # the provider failed -> retry later
    "other",        # unclassified
)

#: Longest excerpt kept for the log/``snapshot()``. Short: it is a hint, not a transcript.
MAX_EXCERPT_LENGTH = 200

# Ordered: the first matching class wins, so the specific operator-actionable causes are
# tested before the generic ones. A 400 carrying "API_KEY_INVALID" must classify as auth,
# not bad_request, because "rotate the key" is the action that fixes it.
_CLASSIFIERS = (
    ("auth", (
        "api_key_invalid", "api key not valid", "api key invalid", "invalid api key",
        "unauthenticated", "unauthorized", "permission_denied", "forbidden",
        "api key", "api_key", "apikey", "credential",
    )),
    ("quota", (
        "resource_exhausted", "resource exhausted", "quota", "rate limit", "ratelimit",
        "too many requests",
    )),
    ("model", (
        "model not found", "models/ is not found", "is not found for project",
        "unsupported model", "not_found",
    )),
    ("network", (
        "tls", "ssl", "eof", "connection", "connect", "timed out", "timeout",
        "deadline exceeded", "dns", "getaddrinfo", "name or service not known",
        "name resolution", "no address associated", "nodename nor servname",
        "connection refused", "no route to host", "socket", "reset by peer",
        "broken pipe", "connection aborted",
        "remotedisconnected", "unreachable", "network", "temporarily unavailable",
        "proxy", "tunnel connection failed",
    )),
    ("server", (
        "internal error", "internal_server_error", "service unavailable", "unavailable",
        "bad gateway", "gateway timeout",
    )),
    ("bad_request", (
        "invalid_argument", "invalid argument", "bad request", "malformed",
    )),
)

#: Status codes are read only where a provider actually puts one: on the exception, or in the
#: wrappers its SDK formats ("<HttpError 403 when requesting ...>", "Error code: 429 - {...}",
#: "status_code=503"). A bare three-digit number in prose is NOT treated as a status — it made
#: "the report was 429 pages long" a quota failure and "_ssl.c:992" a source of false matches.
_STATUS_TEXT = (
    re.compile(r"\b(?:httperror|error code|status_code|code|status)\D{0,3}(\d{3})\b"),
    re.compile(r"\b(\d{3})\s+when requesting\b"),
)

#: HTTP status attributes some SDK exceptions carry. Used as a strong signal before the text
#: scan, because ``str(exc)`` can contain unrelated numbers (``_ssl.c:992``).
_STATUS_ATTRS = ("status_code", "code", "status")

_LOCK = threading.RLock()


def _empty_scope() -> Dict[str, Any]:
    return {
        # None until a real call has been attempted. Never inferred from configuration.
        "verified": None,
        "attempts": 0,
        "successes": 0,
        "failures": 0,
        "last_error_class": None,
        "last_error_excerpt": "",
        "last_model": None,
        "last_attempt_at": None,
    }


_STATE: Dict[str, Dict[str, Any]] = {scope: _empty_scope() for scope in SCOPES}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _normalize_scope(scope: Optional[str]) -> str:
    return scope if scope in _STATE else "default"


# ----------------------------------------------------------------------------------------
# Redaction
# ----------------------------------------------------------------------------------------

def redacted(exc: Any) -> str:
    """One-line, length-bounded, credential-free text for an exception.

    Falls back to the exception's class name if redaction itself fails: an operator still
    learns something true, and nothing secret escapes.
    """
    try:
        from core import redaction

        # Inside the try on purpose: formatting the exception is itself a call into user
        # code, and `str(exc)` can raise.
        raw = exc if isinstance(exc, str) else f"{type(exc).__name__}: {exc}"
        return redaction.sanitize_message(
            raw,
            secret_values=redaction.collect_secret_values(),
            max_length=MAX_EXCERPT_LENGTH,
        )
    except Exception:  # noqa: BLE001 - a redactor must never become the failure
        try:
            return type(exc).__name__
        except Exception:  # noqa: BLE001
            return "<unreportable error>"


# ----------------------------------------------------------------------------------------
# Classification
# ----------------------------------------------------------------------------------------

def classify_error(exc: Any) -> str:
    """Map an exception to one of :data:`ERROR_CLASSES`. Never raises."""
    try:
        # O-51-2 (Phase 52). An exception that already knows its class says so, and that is
        # better evidence than any needle. `core.ai_router` classifies each failure as it
        # happens and attaches the result to the error it raises when the circuit breaker
        # refuses a later call, which otherwise carries no cause of its own and classified as
        # `other` - measured on this instance, where egress to Google is closed, so
        # `gemini_error_class` reported "unclassified" for a condition that had a known,
        # operator-actionable cause. Validated against ERROR_CLASSES, so a stray or invented
        # attribute cannot add to the vocabulary: the pinned tuple stays the only source of
        # class names, and `tests/test_e50_ai_readiness_truth.py` pins it by exact equality.
        declared = getattr(exc, "gerege_error_class", None)
        if isinstance(declared, str) and declared in ERROR_CLASSES:
            return declared

        status = _status_code(exc)
        if status is not None:
            by_status = _class_for_status(status)
            if by_status:
                return by_status

        text = f"{type(exc).__name__} {exc}".lower()
        for name, needles in _CLASSIFIERS:
            for needle in needles:
                if needle in text:
                    return name
        # Reason phrases are more reliable than digits, so they are tried first; a status
        # code is only honoured where a provider demonstrably put one.
        for pattern in _STATUS_TEXT:
            match = pattern.search(text)
            if match:
                klass = _class_for_status(int(match.group(1)))
                if klass:
                    return klass
        return "other"
    except Exception:  # noqa: BLE001
        return "other"


def _status_code(exc: Any) -> Optional[int]:
    for attr in _STATUS_ATTRS:
        value = getattr(exc, attr, None)
        if isinstance(value, int) and 100 <= value <= 599:
            return value
        if isinstance(value, str) and value.isdigit() and 100 <= int(value) <= 599:
            return int(value)
    return None


def _class_for_status(status: int) -> Optional[str]:
    if status in (401, 403):
        return "auth"
    if status == 429:
        return "quota"
    if status == 404:
        return "model"
    if status == 400:
        return "bad_request"
    if 500 <= status <= 599:
        return "server"
    return None


# ----------------------------------------------------------------------------------------
# Recording
# ----------------------------------------------------------------------------------------

def record_success(scope: str = "default", model: Optional[str] = None) -> None:
    """A real generation call completed. This is the only thing that proves a key works."""
    _record(scope, ok=True, exc=None, model=model)


def record_failure(exc: Any, scope: str = "default", model: Optional[str] = None) -> str:
    """A real generation call failed. Returns the class it was filed under.

    The class is logged here, once, redacted, so an operator chasing "why is every reply the
    fallback?" finds the reason without anyone having to add a log line at each call site.
    """
    klass = _record(scope, ok=False, exc=exc, model=model)
    try:
        logger.warning(
            "AI generation failed (scope=%s class=%s): %s", scope, klass, redacted(exc)
        )
    except Exception:  # noqa: BLE001
        pass
    return klass


def _record(scope: str, ok: bool, exc: Any, model: Optional[str]) -> Optional[str]:
    key = _normalize_scope(scope)
    klass = None if ok else classify_error(exc)
    try:
        with _LOCK:
            entry = _STATE[key]
            entry["attempts"] += 1
            entry["verified"] = ok
            entry["last_attempt_at"] = _now()
            entry["last_model"] = model or entry["last_model"]
            if ok:
                entry["successes"] += 1
                entry["last_error_class"] = None
                entry["last_error_excerpt"] = ""
            else:
                entry["failures"] += 1
                entry["last_error_class"] = klass
                entry["last_error_excerpt"] = redacted(exc)
    except Exception:  # noqa: BLE001 - diagnostics must never break a request
        pass
    return klass


def reset(scope: Optional[str] = None) -> None:
    """Forget observations.

    Called with no argument by tests; called with ``scope="default"`` by the agent when the
    configured key changes, because a verdict about the previous key says nothing about the
    new one.
    """
    try:
        with _LOCK:
            targets = SCOPES if scope is None else (_normalize_scope(scope),)
            for key in targets:
                _STATE[key] = _empty_scope()
    except Exception:  # noqa: BLE001
        pass


# ----------------------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------------------

def snapshot(scope: str = "default") -> Dict[str, Any]:
    """Full observed state for one scope, including the redacted excerpt.

    For logs, tests and admin-only surfaces. **Not** for ``/api/health``: use
    :func:`health_fields`, which excludes free text because that endpoint is unauthenticated.
    """
    with _LOCK:
        return dict(_STATE[_normalize_scope(scope)])


def note(configured: bool, scope: str = "default") -> str:
    """One operator-facing sentence stating what is and is not known.

    Static text built from the closed vocabularies, so it can never carry a secret.
    """
    with _LOCK:
        entry = _STATE[_normalize_scope(scope)]
        verified = entry["verified"]
        klass = entry["last_error_class"]
        attempts = entry["attempts"]

    if not configured:
        return (
            "no API key is configured, so every request is answered by the deterministic "
            "fallback; set GEMINI_API_KEY to change that"
        )
    if verified is None:
        return (
            "GEMINI_API_KEY is set and a client was built, but no generation call has been "
            "attempted since startup, so the key is NOT proven to work: building the client "
            "makes no network call. Send one message to find out."
        )
    if verified:
        return (
            f"the most recent generation call succeeded ({attempts} attempt(s) observed "
            f"since startup)"
        )
    return (
        f"the most recent generation call FAILED (class: {klass}); replies are falling back "
        f"to the deterministic answer. A configured key is not a working key."
    )


def health_fields(configured: bool, scope: str = "default") -> Dict[str, Any]:
    """Exactly what an unauthenticated health endpoint may publish.

    ``gemini_ready`` is kept with its historical meaning (== configured) so existing
    consumers and dashboards do not change behaviour; the new fields are what make the
    distinction visible. No exception text, no key, no URL.
    """
    with _LOCK:
        entry = _STATE[_normalize_scope(scope)]
        verified = entry["verified"]
        klass = entry["last_error_class"]
        attempts = entry["attempts"]

    return {
        # Historical name, historical meaning. Kept so nothing that reads it breaks.
        "gemini_ready": bool(configured),
        # What it always actually meant, now said plainly and consistent with
        # meta_token_configured / telegram_configured.
        "gemini_configured": bool(configured),
        # None = never exercised since startup. True/False = the last real call's outcome.
        "gemini_verified": verified,
        "gemini_error_class": klass,
        "gemini_attempts": attempts,
        "gemini_note": note(configured, scope=scope),
    }
