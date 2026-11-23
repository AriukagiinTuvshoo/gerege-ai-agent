"""Worker liveness without a schema change (Phase 36).

Phase 35's gap: nothing could answer "is the worker process alive?". Queue depth and
failed-job counts were visible, but a worker that had died while the queue was empty was
completely invisible -- no HTTP surface, and the only symptom would be silent
non-delivery until somebody noticed the daily report had stopped.

**Design constraint: no new database table.** ``database.py`` is held byte-identical as an
audited artifact, and adding a table would also mean a migration. Redis is already a hard
production dependency (the API refuses to start without ``REDIS_URL``), so the heartbeat
lives there as a short-TTL key. That gives expiry for free: if the worker dies, the key
disappears on its own and the endpoint reports ``stale`` instead of a stale-but-present
"healthy" flag. A row in a table would have required a separate last-seen comparison and
would slowly accumulate junk rows.

What is stored is deliberately minimal and contains **no task payloads and no tenant
data**: a timestamp, the worker id, and the loop counter. Anything richer belongs in the
task tables, which are already queryable.

Tenancy: this is system-level metadata, not tenant data. It is exposed only through an
admin-gated endpoint.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("core.worker_heartbeat")

#: How long a heartbeat stays "fresh". The worker ticks every ~45 s, so three missed
#: ticks is a strong signal the process is wedged or gone while tolerating a slow tick.
DEFAULT_TTL_SECONDS = 180

#: A heartbeat older than this (but still present) is reported as stale.
#: Kept below the TTL so there is a warning band before the key disappears entirely.
FRESH_WINDOW_SECONDS = 150

#: Exactly the extra keys a caller may publish. An open ``extra`` dict looked convenient
#: but meant any caller could push an arbitrary value -- including a token -- into a
#: payload that is returned over HTTP. Measured during development: passing
#: ``extra={"secret_token": "..."}`` appeared verbatim in ``read()``. An allowlist is the
#: only way to keep that guarantee enforceable rather than a matter of caller discipline.
ALLOWED_EXTRA_KEYS = frozenset({
    "queue_processed",
    "stale_recovered",
    "reports_sent",
    "reminders_sent",
})


def _key() -> str:
    """One key per deployment, not per worker.

    The production topology is a single worker process; if that ever becomes a pool, the
    endpoint below already reports per-worker ids from the stored payload and this can be
    extended to a hash without changing the response shape.
    """
    return os.getenv("WORKER_HEARTBEAT_KEY", "gerege:worker:heartbeat")


def _redis():
    """The same Redis the task queue uses, or None.

    Reusing ``task_queue``'s client avoids a second connection pool: the worker's pool is
    budgeted at 2+2 connections and this must not quietly add more.
    """
    try:
        from core.task_queue import task_queue

        return task_queue._get_redis()
    except Exception as exc:
        logger.warning(f"heartbeat: redis unavailable: {exc}")
        return None


def beat(loop_count: int, worker_id: Optional[str] = None, extra: Optional[Dict[str, Any]] = None) -> bool:
    """Record that the worker completed a tick.

    Returns False when Redis is unavailable, which is not an error: the SQLite/dev path
    has no heartbeat and the worker must keep working regardless. Never raises, because a
    monitoring nicety must never kill the process it is monitoring.
    """
    client = _redis()
    if client is None:
        return False
    payload = {
        "worker_id": worker_id or os.getenv("WORKER_ID", "worker-1"),
        "loop_count": int(loop_count),
        "at": time.time(),
        "pid": os.getpid(),
    }
    if extra:
        # Allowlisted counters only. Scalar types are not a safety property: a string
        # secret is a scalar too. See ALLOWED_EXTRA_KEYS.
        payload.update({
            k: v
            for k, v in extra.items()
            if k in ALLOWED_EXTRA_KEYS and isinstance(v, (int, float, bool))
        })
    try:
        client.set(_key(), json.dumps(payload), ex=DEFAULT_TTL_SECONDS)
        return True
    except Exception as exc:
        logger.warning(f"heartbeat write failed: {exc}")
        return False


def read() -> Dict[str, Any]:
    """Report worker liveness plus queue state.

    The status vocabulary is deliberately explicit, because "unknown" and "dead" call for
    different operator responses:

    ``alive``    a fresh heartbeat exists
    ``stale``    a heartbeat exists but is older than FRESH_WINDOW_SECONDS
    ``missing``  no heartbeat key at all -- the worker has not started, or its TTL lapsed
    ``unknown``  Redis could not be read, so no claim can be made either way

    Never reports ``alive`` on the strength of a stale key: a dead worker's last heartbeat
    would otherwise keep the deployment looking healthy.
    """
    result: Dict[str, Any] = {
        "status": "unknown",
        "heartbeat": None,
        "fresh_window_seconds": FRESH_WINDOW_SECONDS,
        "ttl_seconds": DEFAULT_TTL_SECONDS,
    }
    client = _redis()
    if client is None:
        result["reason"] = "redis unavailable; worker liveness cannot be determined"
        return result
    try:
        raw = client.get(_key())
    except Exception as exc:
        result["reason"] = f"redis read failed: {type(exc).__name__}"
        return result

    if not raw:
        result["status"] = "missing"
        result["reason"] = "no heartbeat key; the worker may not be running"
        return result

    try:
        payload = json.loads(raw)
    except Exception:
        result["status"] = "unknown"
        result["reason"] = "heartbeat payload is not valid JSON"
        return result

    age = time.time() - float(payload.get("at", 0))
    result["heartbeat"] = {
        "worker_id": payload.get("worker_id"),
        "loop_count": payload.get("loop_count"),
        "pid": payload.get("pid"),
        "age_seconds": round(age, 1),
    }
    for key, value in payload.items():
        if key not in ("worker_id", "loop_count", "at", "pid"):
            result["heartbeat"][key] = value
    result["status"] = "alive" if age <= FRESH_WINDOW_SECONDS else "stale"
    if result["status"] == "stale":
        result["reason"] = f"last heartbeat was {age:.0f}s ago"
    return result


def clear() -> None:
    """Remove the heartbeat. Used on graceful shutdown so a restart is visible at once."""
    client = _redis()
    if client is None:
        return
    try:
        client.delete(_key())
    except Exception:
        pass
