"""Worker liveness, per worker (Phase 36, isolated per worker in Phase 41).

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

Phase 41 -- why the key is per worker and not per deployment.

The first version kept one key (``gerege:worker:heartbeat``) and put the worker id in the
payload. Measured: two workers beat, one key exists, and ``read()`` names only whichever
beat last. The other worker is not reported stale, not reported missing, not reported at
all -- and ``worker_id`` defaulted to the literal string ``"worker-1"``, so two processes
with ``WORKER_ID`` unset were indistinguishable even in principle. Scaling the worker out
therefore *reduced* the deployment's observability, silently.

Three concepts were being answered by one key, and they are now separate:

  * **worker health**  -- one distinct state per worker, from that worker's own key;
  * **pool health**    -- derived: how many workers are alive, stale or gone;
  * **deployment health** -- the API's own readiness (``/api/ready``), which is a
    different question and deliberately not part of this module.

Identity: ``task_queue.worker_id`` already exists and is already unique per process
(``<hostname>-<pid>-<uuid6>``) and is already what ``task_jobs.locked_by`` records. It was
being ignored here in favour of an environment variable with a constant default, which
meant the heartbeat named a worker by something that could not identify it.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("core.worker_heartbeat")

#: How long a heartbeat stays "fresh".
#:
#: Phase 41 lowered this from 150 s to 30 s, and moved the beat from the end of the worker
#: tick onto its own timer, because the two numbers were coupled: a tick beats once, the
#: loop then sleeps up to 15 s, and a slow batch was measured at 23.3 s. Worst-case gap
#: between beats was therefore ~38 s, so a 30 s window would have false-staled a healthy
#: worker mid-batch. With the beat on a 10 s timer the gap is 10 s plus Redis latency, and
#: 30 s tolerates two missed beats.
FRESH_WINDOW_SECONDS = int(os.getenv("WORKER_HEARTBEAT_FRESH_SECONDS", "30"))

#: How long a key survives after its last beat. Must exceed the fresh window so there is a
#: "stale" band before the key vanishes: "stale" means wedged, "missing" means gone, and an
#: operator treats those differently.
DEFAULT_TTL_SECONDS = int(os.getenv("WORKER_HEARTBEAT_TTL_SECONDS", "90"))

#: How often the worker's liveness timer beats. Well under the fresh window, so two
#: consecutive Redis failures do not make a healthy worker look stale.
BEAT_INTERVAL_SECONDS = float(os.getenv("WORKER_HEARTBEAT_BEAT_SECONDS", "10"))

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
    # Phase 39 (F-39-D): a scheduler step raised during the tick. The worker can be
    # perfectly alive with a broken scheduler; without this counter that state was
    # invisible over HTTP.
    "scheduler_errors",
    # Phase 41: the liveness timer and the progress record are written separately, so the
    # payload says which one it is.
    "tick_completed_at",
})

_PREFIX_ENV = "WORKER_HEARTBEAT_KEY"

#: A worker id ends up inside a Redis key, so it is validated rather than trusted. The
#: generated form is `<hostname>-<pid>-<uuid6>`; a hostname may contain dots and hyphens
#: but never a colon, a space or a newline. Anything else is rejected at the boundary,
#: because `client.set("gerege:worker:heartbeat:x\r\nFLUSHALL")` is a value a caller could
#: otherwise choose.
_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _prefix() -> str:
    """The key prefix. One deployment may run many workers; each gets its own key."""
    return os.getenv(_PREFIX_ENV, "gerege:worker:heartbeat")


def _key(worker_id: Optional[str] = None) -> str:
    """The heartbeat key for one worker.

    Called with no argument it returns the *prefix*, which is what the pre-Phase-41 tests
    and any operator tooling that wants `KEYS <prefix>:*` should use. Called with an id it
    returns that worker's key. The single-argument call is kept because every existing
    reader of this module addressed "the" heartbeat; the meaning of a bare prefix is
    documented here rather than silently different.
    """
    prefix = _prefix()
    if not worker_id:
        return prefix
    return f"{prefix}:{worker_id}"


def validate_worker_id(worker_id: str) -> str:
    """Reject an id that could escape the key namespace. Returns it unchanged if safe."""
    if not isinstance(worker_id, str) or not _SAFE_ID.match(worker_id):
        raise ValueError(
            f"worker id {worker_id!r} is not a safe key component; expected "
            f"[A-Za-z0-9._-]{{1,128}}"
        )
    return worker_id


def current_worker_id() -> str:
    """This process's identity, taken from the queue's, which is the authoritative one.

    ``task_queue.worker_id`` is what ``task_jobs.locked_by`` records, so using it here
    means the heartbeat and the job table name a worker the same way. ``WORKER_ID`` is
    honoured when set, because an operator may want a stable name across restarts; the
    fallback is the generated per-process id, never a constant.
    """
    explicit = os.getenv("WORKER_ID", "").strip()
    if explicit:
        return validate_worker_id(explicit)
    try:
        from core.task_queue import task_queue

        return validate_worker_id(task_queue.worker_id)
    except Exception:  # pragma: no cover - import cycle or Redis unavailable at import
        return validate_worker_id(f"{os.uname().nodename}-{os.getpid()}")


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


def _payload(worker_id: str, extra: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "worker_id": validate_worker_id(worker_id),
        "at": time.time(),
        "pid": os.getpid(),
    }
    if extra:
        # Allowlisted counters only. Scalar types are not a safety property: a string
        # secret is a scalar too. See ALLOWED_EXTRA_KEYS.
        body.update({
            k: v
            for k, v in extra.items()
            if k in ALLOWED_EXTRA_KEYS and isinstance(v, (int, float, bool))
        })
    return body


def beat(
    loop_count: Optional[int] = None,
    worker_id: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> bool:
    """Record that this worker is alive.

    Writes ONLY this worker's key, so no worker can overwrite another's. Returns False when
    Redis is unavailable, which is not an error: the SQLite/dev path has no heartbeat and
    the worker must keep working regardless. Never raises, because a monitoring nicety must
    never kill the process it is monitoring -- except for an unsafe worker id, which is a
    programming error and is raised so it cannot reach Redis.
    """
    worker_id = validate_worker_id(worker_id or current_worker_id())
    client = _redis()
    if client is None:
        return False
    body = _payload(worker_id, extra)
    if loop_count is not None:
        body["loop_count"] = int(loop_count)
    try:
        client.set(_key(worker_id), json.dumps(body), ex=DEFAULT_TTL_SECONDS)
        return True
    except Exception as exc:
        logger.warning(f"heartbeat write failed: {exc}")
        return False


def _state_from_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    age = time.time() - float(payload.get("at", 0))
    body = {
        "worker_id": payload.get("worker_id"),
        "loop_count": payload.get("loop_count"),
        "pid": payload.get("pid"),
        "age_seconds": round(age, 1),
    }
    for key, value in payload.items():
        if key not in ("worker_id", "loop_count", "at", "pid"):
            body[key] = value
    return {
        "status": "alive" if age <= FRESH_WINDOW_SECONDS else "stale",
        "age_seconds": round(age, 1),
        "heartbeat": body,
    }


def read(worker_id: Optional[str] = None) -> Dict[str, Any]:
    """Report liveness, of one worker (with an id) or of the pool (without).

    The status vocabulary is deliberately explicit, because "unknown" and "dead" call for
    different operator responses:

    ``alive``    a fresh heartbeat exists
    ``stale``    a heartbeat exists but is older than FRESH_WINDOW_SECONDS
    ``missing``  no heartbeat key at all -- the worker has not started, or its TTL lapsed
    ``unknown``  Redis could not be read, so no claim can be made either way

    Never reports ``alive`` on the strength of a stale key: a dead worker's last heartbeat
    would otherwise keep the deployment looking healthy.

    Called without an id this returns the pool view: ``workers`` is one entry per worker
    with its own status, and the top-level ``status`` is the aggregate. ``alive`` means at
    least one worker is alive, ``missing`` means none is even known, and every worker's
    state is reported rather than collapsed.
    """
    client = _redis()
    if client is None:
        return {
            "status": "unknown",
            "heartbeat": None,
            "fresh_window_seconds": FRESH_WINDOW_SECONDS,
            "ttl_seconds": DEFAULT_TTL_SECONDS,
            "reason": "redis unavailable; worker liveness cannot be determined",
        }
    if worker_id:
        return _read_one(client, validate_worker_id(worker_id))
    return _read_pool(client)


def _read_one(client, worker_id: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "status": "unknown",
        "heartbeat": None,
        "worker_id": worker_id,
        "fresh_window_seconds": FRESH_WINDOW_SECONDS,
        "ttl_seconds": DEFAULT_TTL_SECONDS,
    }
    try:
        raw = client.get(_key(worker_id))
    except Exception as exc:
        result["reason"] = f"redis read failed: {type(exc).__name__}"
        return result
    if not raw:
        result["status"] = "missing"
        result["reason"] = "no heartbeat key; this worker may not be running"
        return result
    try:
        payload = json.loads(raw)
    except Exception:
        result["status"] = "unknown"
        result["reason"] = "heartbeat payload is not valid JSON"
        return result
    state = _state_from_payload(payload)
    result.update(state)
    if state["status"] == "stale":
        result["reason"] = f"last heartbeat was {state['age_seconds']:.0f}s ago"
    return result


def _read_pool(client) -> Dict[str, Any]:
    """Every known worker's state, plus the aggregate.

    A key disappears when its TTL lapses, so a worker that has been gone longer than
    DEFAULT_TTL_SECONDS is not in this list at all -- that is the "gone" case, and it is
    reported by its absence rather than by a row saying "missing". ``stale`` is the band
    where the key still exists and the operator should look.
    """
    result: Dict[str, Any] = {
        "status": "unknown",
        "workers": [],
        "worker_count": 0,
        "alive_count": 0,
        "stale_count": 0,
        "fresh_window_seconds": FRESH_WINDOW_SECONDS,
        "ttl_seconds": DEFAULT_TTL_SECONDS,
    }
    prefix = _prefix() + ":"
    legacy_key = _prefix()
    try:
        keys = client.keys(f"{prefix}*")
        # Phase 41 finding, found by this phase's own pool view: a worker still running
        # the PREVIOUS release writes the bare prefix key (there was only ever one key
        # before), which does not match "<prefix>:*". During a rolling deploy that worker
        # is alive and doing work while the pool view reports it as absent - the read used
        # to say "missing" with genuine work in flight. Both layouts are read.
        if client.get(legacy_key):
            keys = list(keys) + [legacy_key]
    except Exception as exc:
        result["reason"] = f"redis read failed: {type(exc).__name__}"
        return result

    workers: List[Dict[str, Any]] = []
    for raw_key in keys:
        key = raw_key.decode() if isinstance(raw_key, bytes) else str(raw_key)
        if key == legacy_key:
            # The legacy record is attributed to the id it carries (below). If it carries
            # none, the name says what it is rather than inventing an identity.
            worker_id = "legacy-shared-key"
        else:
            worker_id = key[len(prefix):]
        try:
            raw = client.get(key)
        except Exception as exc:
            result["reason"] = f"redis read failed: {type(exc).__name__}"
            continue
        if not raw:
            continue  # expired between KEYS and GET; not a worker we can claim anything about
        try:
            payload = json.loads(raw)
        except Exception:
            workers.append({"worker_id": worker_id, "status": "unknown",
                            "reason": "payload is not valid JSON"})
            continue
        if key == legacy_key:
            # A pre-Phase-41 payload does carry `worker_id`; use it so the record is named
            # the same way the old release named it.
            worker_id = str(payload.get("worker_id") or worker_id)
        state = _state_from_payload(payload)
        # A payload with no usable timestamp is not evidence of anything, so it is
        # reported as unknown rather than scored as infinitely old ("stale"). Phase 41
        # found this: a corrupt key was aggregated into the stale count, which reads as
        # "wedged worker" when the truth is "unreadable record".
        if not isinstance(payload.get("at"), (int, float)):
            workers.append({"worker_id": worker_id, "status": "unknown",
                            "reason": "payload has no usable timestamp"})
            continue
        workers.append({
            "worker_id": payload.get("worker_id") or worker_id,
            "status": state["status"],
            "age_seconds": state["age_seconds"],
            "loop_count": state["heartbeat"].get("loop_count"),
            "pid": state["heartbeat"].get("pid"),
            **{k: v for k, v in state["heartbeat"].items()
               if k in ALLOWED_EXTRA_KEYS},
        })

    workers.sort(key=lambda item: str(item.get("worker_id")))
    result["workers"] = workers
    result["worker_count"] = len(workers)
    result["alive_count"] = sum(1 for w in workers if w["status"] == "alive")
    result["stale_count"] = sum(1 for w in workers if w["status"] == "stale")
    result["unknown_count"] = sum(1 for w in workers if w["status"] == "unknown")

    # Backwards compatibility, deliberately narrow.
    #
    # Before Phase 41 this function returned the single worker's payload under
    # `heartbeat`, and consumers read `read()["heartbeat"]["loop_count"]`. With exactly one
    # worker that key still resolves to that worker. With several there is no single
    # worker to name, and `heartbeat` is None rather than one of them chosen arbitrarily -
    # picking one is precisely the bug this phase fixed, and repeating it in the
    # compatibility layer would hide it from anyone who has not migrated.
    result["heartbeat"] = (
        {k: v for k, v in workers[0].items() if k != "status"} if len(workers) == 1 else None
    )
    result["heartbeat_summary"] = workers[0] if len(workers) == 1 else None

    if "reason" in result:
        return result  # a Redis error mid-scan: do not claim a pool state
    if not workers:
        result["status"] = "missing"
        result["reason"] = "no worker heartbeats; no worker has started, or all have expired"
        result["heartbeat"] = None
    elif result["alive_count"]:
        result["status"] = "alive"
        if result["stale_count"]:
            result["reason"] = (
                f"{result['alive_count']} of {result['worker_count']} workers alive, "
                f"{result['stale_count']} stale"
            )
    elif result["stale_count"]:
        result["status"] = "stale"
        result["reason"] = f"no worker is fresh; {result['stale_count']} stale"
    else:
        # Every record present is unreadable. "stale" would claim we know they are old;
        # we do not know anything about them, and the caller needs to be told that.
        result["status"] = "unknown"
        result["reason"] = (
            f"{result['unknown_count']} worker record(s) exist but none is readable"
        )
    return result


def clear(worker_id: Optional[str] = None) -> None:
    """Remove one worker's heartbeat. Called on graceful shutdown so a restart is visible.

    Without an argument it clears only THIS process's key: clearing the whole prefix would
    delete the other workers' heartbeats and make a healthy pool look dead, which is the
    opposite of what a shutdown handler is for.
    """
    client = _redis()
    if client is None:
        return
    try:
        client.delete(_key(worker_id or current_worker_id()))
    except Exception:
        pass


def deregister(worker_id: str) -> bool:
    """Remove a named worker's key. For an operator or a test, not for the worker itself."""
    client = _redis()
    if client is None:
        return False
    try:
        client.delete(_key(validate_worker_id(worker_id)))
        return True
    except Exception:
        return False
