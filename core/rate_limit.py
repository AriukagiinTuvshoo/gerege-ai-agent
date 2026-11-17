"""
Shared-store rate limiting (finding SEC-07).

===============================================================================
WHY THIS EXISTS
===============================================================================
The only limit in the product was `_LOGIN_ATTEMPTS: Dict[str, List[float]]` in `main.py` —
a Python dict. Two problems, both verified by reading the deployment:

1. **It is per process.** `Dockerfile` runs `uvicorn --workers 2` and
   `docker-compose.prod.yml` runs a separate `worker` process. Each gets its own dict, so
   the effective login limit was 10 × (number of processes) per minute, and it reset on
   every deploy.
2. **Three public endpoints had no limit at all** — `POST /api/chat` (the embeddable
   widget, callable by anyone on the internet), `POST /api/upload-receipt` (drives Pillow,
   i.e. CPU an attacker can spend) and `GET /r/{code}` (a redirect endpoint, useful as a
   free traffic amplifier).

===============================================================================
DESIGN
===============================================================================
`RateLimiter` counts per `(scope, identity)` inside a fixed window.

* **Redis backend** (`REDIS_URL` set and reachable): `INCR` + `EXPIRE` in one pipeline.
  `INCR` is atomic, so every worker and every replica shares one counter. This is the
  whole point of the fix.
* **In-memory fallback**: a bounded dict, used when Redis is absent or unreachable.

The fallback is a deliberate availability choice, and it is *not* silently equivalent:
a process-local counter is strictly weaker than a shared one. The limiter therefore
reports which backend it is using (`backend()`), the app logs it once at startup, and
`/api/health` exposes it, so a deployment that thinks it is protected can be checked.
Failing closed instead would turn a Redis outage into a total login outage — a worse
outcome than a temporarily weaker limit for an endpoint that also has password checks.

===============================================================================
TESTABILITY
===============================================================================
`RateLimiter(clock=..., store=...)` accepts an injectable clock and store, so the window
and the counter logic are tested without sleeping and without a live Redis. The
"shared across workers" guarantee is tested with two separate `RateLimiter` *instances*
against one Redis, which is exactly what two worker processes are.
"""
import logging
import os
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("core.rate_limit")

#: Bounded so a hostile client cannot grow the fallback dict without limit.
_MAX_TRACKED_IDENTITIES = 10_000


class _MemoryStore:
    """Process-local counter store. The fallback when Redis is unavailable."""

    backend_name = "memory"

    def __init__(self, clock: Callable[[], float]):
        self._clock = clock
        self._lock = threading.Lock()
        #: key -> (window_started_at, count)
        self._counters: Dict[str, Tuple[float, int]] = {}

    def incr_in_window(self, key: str, window_seconds: int) -> int:
        now = self._clock()
        with self._lock:
            started, count = self._counters.get(key, (now, 0))
            if now - started >= window_seconds:
                # New window.
                started, count = now, 0
            count += 1
            self._counters[key] = (started, count)
            if len(self._counters) > _MAX_TRACKED_IDENTITIES:
                # Evict entries whose window has certainly expired, then, if still too
                # large, the oldest insertion order (dicts preserve it).
                stale = [
                    k for k, (s, _c) in self._counters.items()
                    if now - s >= window_seconds
                ]
                for k in stale:
                    self._counters.pop(k, None)
                while len(self._counters) > _MAX_TRACKED_IDENTITIES:
                    self._counters.pop(next(iter(self._counters)))
            return count


class _RedisStore:
    """Counter store shared by every process pointed at the same Redis."""

    backend_name = "redis"

    def __init__(self, url: str, clock: Callable[[], float]):
        import redis  # imported lazily: optional at runtime

        self._clock = clock
        self._client = redis.from_url(url, decode_responses=True, socket_timeout=3.0)
        self._client.ping()

    def incr_in_window(self, key: str, window_seconds: int) -> int:
        # INCR is atomic. `EXPIRE ... NX` would set the TTL only on creation, but that
        # flag only exists in Redis >= 7.0; deployments run 6.x, where it raises
        # "wrong number of arguments". Instead the TTL is (re)asserted only when the
        # counter is created (`count == 1`), which is equivalent for a fixed window and
        # works on every supported version.
        count = int(self._client.incr(key))
        if count == 1:
            self._client.expire(key, window_seconds)
        return count


class RateLimiter:
    """
    Fixed-window rate limiter over a shared store when one is available.

    ``limit`` requests are allowed per ``window_seconds`` for a given identity.
    """

    def __init__(
        self,
        redis_url: Optional[str] = None,
        clock: Optional[Callable[[], float]] = None,
        store=None,
    ):
        self._clock = clock or time.time
        self._redis_url = (redis_url if redis_url is not None else os.getenv("REDIS_URL", "")).strip()
        if store is not None:
            self._store = store
        else:
            self._store = self._build_store()
        self._lock = threading.Lock()

    def _build_store(self):
        if self._redis_url:
            try:
                return _RedisStore(self._redis_url, self._clock)
            except Exception as exc:  # pragma: no cover - depends on a live server
                logger.warning(
                    f"Rate limiter could not reach Redis ({exc}); falling back to a "
                    "per-process counter. Limits will be weaker than configured."
                )
        return _MemoryStore(self._clock)

    def backend(self) -> str:
        return getattr(self._store, "backend_name", "unknown")

    def is_shared(self) -> bool:
        """True when limits are enforced across processes."""
        return self.backend() == "redis"

    def check(self, scope: str, identity: str, limit: int, window_seconds: int) -> Dict[str, object]:
        """
        Count one request and report whether it is allowed.

        Returns ``{"allowed", "count", "limit", "retry_after"}``. ``retry_after`` is the
        whole window for a fixed window; it is an upper bound on the wait, which is what
        `Retry-After` may legally carry.
        """
        if limit <= 0:
            return {"allowed": True, "count": 0, "limit": limit, "retry_after": 0}
        key = f"ratelimit:{scope}:{identity}"
        try:
            count = self._store.incr_in_window(key, window_seconds)
        except Exception as exc:
            # An outage in the limiter must not take the endpoint down with it. Log loudly
            # and allow: the alternative is that a Redis blip logs everyone out.
            logger.error(f"Rate limiter store failed for {scope} ({exc}); allowing request")
            return {"allowed": True, "count": 0, "limit": limit, "retry_after": 0}
        return {
            "allowed": count <= limit,
            "count": count,
            "limit": limit,
            "retry_after": window_seconds if count > limit else 0,
        }

    def reset(self, scope: Optional[str] = None) -> None:
        """Clear counters. For tests and for an operator unlocking a locked-out client."""
        store = self._store
        if isinstance(store, _MemoryStore):
            with store._lock:
                if scope is None:
                    store._counters.clear()
                else:
                    prefix = f"ratelimit:{scope}:"
                    for k in [k for k in store._counters if k.startswith(prefix)]:
                        store._counters.pop(k, None)
            return
        client = getattr(store, "_client", None)
        if client is not None:
            pattern = f"ratelimit:{scope}:*" if scope else "ratelimit:*"
            for key in client.scan_iter(match=pattern, count=500):
                client.delete(key)


#: Limits applied by the app. Kept here so they are reviewable in one place.
#: (scope, limit, window_seconds) — identity is the client IP.
DEFAULT_LIMITS: Dict[str, Tuple[int, int]] = {
    # Brute force: was 10/60s per process. 10/60s now means 10/60s *total*.
    "auth_login": (10, 60),
    # Public widget. Generous enough for a real conversation, bounded against abuse.
    "api_chat": (30, 60),
    # Receipt uploads drive Pillow decoding, which is CPU an attacker pays nothing for.
    "api_upload_receipt": (10, 60),
    # Redirect endpoint; expensive only in that it fans out to the client's phone.
    "tracked_redirect": (60, 60),
}

#: A lazily-constructed process-wide limiter so imports stay cheap and tests can inject.
_shared_limiter: Optional[RateLimiter] = None
_shared_limiter_lock = threading.Lock()


def get_limiter() -> RateLimiter:
    """Return the process-wide limiter, creating it on first use."""
    global _shared_limiter
    if _shared_limiter is None:
        with _shared_limiter_lock:
            if _shared_limiter is None:
                _shared_limiter = RateLimiter()
                logger.info(
                    f"Rate limiter backend: {_shared_limiter.backend()} "
                    f"(shared across workers: {_shared_limiter.is_shared()})"
                )
    return _shared_limiter


def set_limiter(limiter: Optional[RateLimiter]) -> None:
    """Replace the process-wide limiter. For tests."""
    global _shared_limiter
    _shared_limiter = limiter


def client_identity(request) -> str:
    """
    Best-effort client identity for rate limiting.

    Uses the left-most `X-Forwarded-For` entry when present, because the app runs behind
    Vercel's proxy and would otherwise see every request as one address. That header is
    client-controlled, so it is a rate-limiting key only — it must never be used for
    authentication or authorisation decisions.
    """
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip
    return request.client.host if request.client else "unknown"


def check_request_limit(request, scope: str) -> Optional[Dict[str, object]]:
    """
    Apply the configured limit for `scope`.

    Returns ``None`` when the request is allowed, or a dict describing the rejection —
    the caller turns that into a 429 so this module stays framework-agnostic.
    """
    limit, window = DEFAULT_LIMITS.get(scope, (0, 0))
    if limit <= 0:
        return None
    result = get_limiter().check(scope, client_identity(request), limit, window)
    return None if result["allowed"] else result
