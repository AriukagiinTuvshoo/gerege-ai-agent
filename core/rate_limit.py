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
import ipaddress
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("core.rate_limit")

#: Bounded so a hostile client cannot grow the fallback dict without limit.
_MAX_TRACKED_IDENTITIES = 10_000


@dataclass(frozen=True)
class AdmissionToken:
    """
    Proof of one admitted login attempt, and of the counter generation it consumed.

    E-02 Phase 4.2. A refund is only valid for *this* admission: `generation` names the exact
    counter incarnation the admission incremented, and `identity` names the counter it belongs
    to. Without both, a success that finished late would decrement whatever counter happened to
    exist at refund time — which is how one request's success erased another request's failure
    after the window rolled over.

    `generation` is opaque and unguessable; it carries no account identifier, so it can be
    logged or returned without widening the enumeration surface.

    `admission_id` is unique *per admitted request*, which `generation` alone cannot be: every
    admission inside one window shares a generation. Without a per-request id, replaying one
    successful login would cancel N failures instead of one. It is what makes a refund
    single-use. Tokens are minted and consumed inside one process; they are never returned to
    the client.
    """

    identity: str
    generation: str
    admission_id: str
    #: The window this admission was taken with. The refund must judge expiry against the
    #: admission's own window, not the current policy value: a token taken while the policy was
    #: 5s must be dead after 5s even if the policy has since become 900s, or the memory store
    #: would honour an admission that Redis has already expired.
    window_seconds: Optional[int] = None


class StoreAtCapacityError(RuntimeError):
    """
    The memory store is full of *live* counters and refused to make room.

    E-02 Phase 4.4. Raised only by the process-local fallback, never by Redis. It is distinct
    from a generic store failure because the account path must fail **closed** on it: admitting
    an account whose failures cannot be recorded would grant that account an unlimited budget.
    The IP scope deliberately treats it exactly like any other store error (fail open), because
    there the alternative is a limiter outage logging everybody out.
    """


class RateLimitStoreUnavailable(RuntimeError):
    """
    A shared store is mandatory in this environment and could not be built.

    E-02 Phase 6, R11. Raised at limiter-construction time in production when `REDIS_URL` is
    missing, blank, or unreachable. It is deliberately *not* caught anywhere: it must abort
    startup, because a process that serves traffic with a private in-memory counter enforces
    `limit x workers` while reporting `limit`.

    It carries no connection string or credential — only the exception *class* of the backend
    error — so it is safe to log and to surface as a startup failure.
    """


def shared_store_required() -> bool:
    """
    Whether a shared (non-memory) store is mandatory in this environment.

    Public name for `_redis_is_required()`, used by readiness to decide whether a store outage
    should make the deployment "not ready". True in production and under `STRICT_SECURITY=1`.
    """
    return _redis_is_required()


def _redis_is_required() -> bool:
    """
    Whether a shared Redis store is mandatory in this environment.

    Production (and `STRICT_SECURITY=1`) must never run the per-process fallback: the whole
    point of SEC-07 was that N processes must not mean N times the limit. Development and
    tests are explicitly allowed to run without Redis, which is the documented fallback.
    """
    from core.security import is_production_mode

    return is_production_mode()


def _new_generation() -> str:
    """A fresh, unguessable generation marker for one counter incarnation."""
    return secrets.token_hex(8)


def _generation_key(counter_key: str) -> str:
    """
    Companion key holding the generation marker for a counter.

    Kept beside the counter rather than inside its value so the counter stays a plain integer:
    existing tooling, `peek()`, and `TTL` reporting are unchanged, and no script has to parse a
    composite value. The marker is written with the counter's own TTL, so it expires with the
    window it identifies.
    """
    return f"{counter_key}:gen"


class _MemoryCounter:
    """
    One counter incarnation: its window, its count, its generation, and its refunded claims.

    E-02 Phase 4.3. Bundling the claims with the generation they belong to is the whole design.
    A separate claim structure — global or per-account — needs its own expiry, its own bound,
    and its own eviction policy, and every one of those is a way to forget a live claim. Here
    there is nothing to expire and nothing to evict: the claims stop existing at exactly the
    moment the generation does, which is the only moment they stop being relevant.

    `claims` is bounded by construction. A claim is recorded only for a token, a token is only
    issued to an admitted attempt, and an admitted attempt increments `count`. So
    `len(claims) <= peak(count) <= threshold` for this window, with no separate limit to tune.
    """

    __slots__ = ("started", "count", "generation", "window_seconds", "claims")

    def __init__(self, started: float, window_seconds: int, generation: str, count: int = 0):
        self.started = started
        self.count = count
        self.generation = generation
        self.window_seconds = window_seconds
        self.claims: set = set()

    def expired_at(self, now: float, window_seconds: Optional[int] = None) -> bool:
        """True once this incarnation's window has passed, on its own window or the given one."""
        window = self.window_seconds if window_seconds is None else window_seconds
        return now - self.started >= window

    def __repr__(self) -> str:  # keeps test/debug output readable and identifier-free
        return (
            f"_MemoryCounter(count={self.count}, generation={self.generation!r}, "
            f"claims={len(self.claims)}, window={self.window_seconds}s)"
        )


class _MemoryStore:
    """Process-local counter store. The fallback when Redis is unavailable."""

    backend_name = "memory"

    def __init__(self, clock: Callable[[], float]):
        self._clock = clock
        self._lock = threading.Lock()
        self._counters: Dict[str, _MemoryCounter] = {}

    def _reclaim_expired(self, now: float) -> None:
        """
        Drop every counter whose window has passed. Called with the lock held.

        E-02 Phase 4.4. This *only* removes expired entries. The previous version reclaimed
        expired entries and then, if still over the cap, dropped the oldest **live** counter —
        which let an attacker erase any account's failure budget by filling the store, and which
        contradicted its own docstring. A live counter is now never removed; capacity pressure
        is refused instead (see `_make_room`).
        """
        stale = [k for k, c in self._counters.items() if c.expired_at(now)]
        for k in stale:
            self._counters.pop(k, None)

    def _make_room(self, now: float) -> bool:
        """
        Try to free a slot for a brand-new identity. Called with the lock held.

        Returns True if a slot is available. Reclaims expired entries first — the safe way to
        regain capacity — and refuses rather than displacing a live counter.

        Refusing is the security-preserving direction: an account admitted while its counter
        cannot be stored would never be throttled, which is a worse outcome than that identity
        waiting for another account's window to lapse. The cost is availability for *new*
        identities only; identities that already have a live counter are always served, so no
        active limit is ever weakened by this path.
        """
        if len(self._counters) < _MAX_TRACKED_IDENTITIES:
            return True
        self._reclaim_expired(now)
        return len(self._counters) < _MAX_TRACKED_IDENTITIES

    def _live_entry(self, key: str, now: float, window_seconds: Optional[int] = None):
        """
        The counter if it is still live, else None. Reclaims an expired entry on sight.

        E-02 Phase 4.3. This is the parity fix. Redis deletes an expired key by itself, so a
        refund after the TTL sees no counter; the memory store used to keep the entry until
        something replaced it, and a refund therefore had to check expiry explicitly. Doing
        that check *here*, under the lock, means every caller — refund, read, increment — sees
        the same "expired means absent" state that Redis presents.
        """
        entry = self._counters.get(key)
        if entry is None:
            return None
        if entry.expired_at(now, window_seconds):
            self._counters.pop(key, None)
            return None
        return entry

    def incr_in_window(self, key: str, window_seconds: int) -> int:
        return self.incr_in_window_detailed(key, window_seconds)["count"]

    def incr_in_window_detailed(self, key: str, window_seconds: int) -> Dict[str, Any]:
        """
        Admit one attempt and return its count, remaining window, and generation.

        The generation is minted here, under the same lock acquisition that creates or advances
        the counter, so "which incarnation did this admission increment?" is answered
        atomically. A new window gets a new generation; an increment inside an existing window
        inherits it. Minting outside the lock would let two threads disagree about which window
        they joined.
        """
        now = self._clock()
        with self._lock:
            entry = self._counters.get(key)
            if entry is not None and entry.expired_at(now):
                # Reclaim on sight, exactly as Redis has already done. Note the entry's own
                # window decides this, not the caller's: see the policy note below.
                self._counters.pop(key, None)
                entry = None

            if entry is None or not entry.generation:
                # E-02 Phase 4.4 policy: a counter's window is fixed when its generation is
                # created, and later admissions inherit it. This is what Redis does — its TTL
                # is written once inside the script that creates the counter and never
                # revisited — and it is what the fixed-window model requires: a window that any
                # caller can widen is not a window.
                #
                # This path creates a generation, so it is the only one that can grow the dict.
                # Capacity pressure is refused here rather than by displacing a live counter.
                if not self._make_room(now):
                    raise StoreAtCapacityError(
                        f"memory store is at capacity ({_MAX_TRACKED_IDENTITIES} live "
                        "identities); refusing to admit a new identity"
                    )
                entry = _MemoryCounter(now, int(window_seconds), _new_generation())
                self._counters[key] = entry
            # An existing generation keeps its own window; the caller's is deliberately ignored,
            # so a later longer admission cannot extend this counter and a later shorter one
            # cannot cut it short.
            entry.count += 1
            remaining = max(1, int(entry.window_seconds - (now - entry.started)))
            return {"count": entry.count, "ttl": remaining, "generation": entry.generation}

    def read_counter(self, key: str, window_seconds: Optional[int] = None) -> int:
        """
        Current count, treating an expired entry as absent *and reclaiming it*.

        The reclaim matters beyond tidiness: an expired entry's claims would otherwise linger,
        and a later caller would be looking at a generation whose window is over.
        """
        now = self._clock()
        with self._lock:
            entry = self._live_entry(key, now, window_seconds)
            return 0 if entry is None else entry.count

    def delete_counter(self, key: str) -> None:
        with self._lock:
            self._counters.pop(key, None)

    def ping(self) -> bool:
        """A process-local store is always reachable; readiness uses this for parity."""
        return True

    def refund_admission(self, key: str, token: AdmissionToken) -> bool:
        """
        Reverse exactly one admission, iff it belongs to the live generation.

        E-02 Phase 4.3. Every condition is evaluated inside one critical section, and the first
        of them is now **expiry**:

          1. the counter exists and has not expired — the same state Redis presents after its
             TTL fires, which is what makes the two backends return the same decision;
          2. the live generation equals the token's generation;
          3. the token's admission is not already in this generation's claim set;
          4. the counter is above zero (clamped, so a refund never mints budget).

        Condition 1 is why the Phase 4.2 store refunded an admission whose window was long gone
        whenever nothing had replaced the entry. It is deliberately checked here rather than by
        the caller: a timestamp comparison outside the lock is check-then-act, and another
        thread could roll the window between the comparison and the decrement.

        Returns True only when a slot was actually given back.
        """
        if not token.generation or not token.admission_id:
            return False
        now = self._clock()
        with self._lock:
            # E-02 Phase 4.4. Expiry is judged by the *counter's* window, never the token's.
            # A token carries the window its caller asked for, which is not necessarily the
            # window its generation actually has; letting the token decide made the same token
            # live on Redis and dead on memory (scenario B in the audit evidence).
            entry = self._counters.get(key)
            if entry is None:
                return False
            if entry.expired_at(now):
                # Reclaim on sight: the generation is gone, exactly as Redis's TTL has already
                # removed it.
                self._counters.pop(key, None)
                return False
            if entry.generation != token.generation:
                # A different incarnation of this counter; the admission is not ours to undo.
                return False
            if entry.count <= 0:
                return False
            if token.admission_id in entry.claims:
                return False
            entry.claims.add(token.admission_id)
            entry.count -= 1
            if entry.count == 0:
                # Matches Redis, which deletes the counter at zero. The generation goes with it,
                # so tokens from this window stop matching — the same on both backends.
                self._counters.pop(key, None)
            return True

    def decrement_floor_zero(self, key: str, window_seconds: Optional[int] = None) -> int:
        """
        Unconditional clamped decrement. Retained for the IP/scope limiter's bookkeeping.

        Not used for account refunds: it has no notion of which admission it is reversing,
        which is precisely the E-02 Phase 4.2 defect. Account refunds go through
        `refund_admission()`.
        """
        now = self._clock()
        with self._lock:
            entry = self._live_entry(key, now, window_seconds)
            if entry is None:
                return 0
            entry.count = max(0, entry.count - 1)
            if entry.count == 0:
                self._counters.pop(key, None)
            return entry.count


class _RedisStore:
    """Counter store shared by every process pointed at the same Redis."""

    backend_name = "redis"

    def __init__(self, url: str, clock: Callable[[], float]):
        import redis  # imported lazily: optional at runtime

        self._clock = clock
        self._client = redis.from_url(url, decode_responses=True, socket_timeout=3.0)
        self._client.ping()

    #: Increment and set the expiry in ONE round-trip.
    #:
    #: Phase 4.1, finding B. The Phase 4 version issued `INCR` and then, only when the result
    #: was 1, a separate `EXPIRE`. A crash, a dropped connection, or a killed worker between
    #: those two commands left a counter with no TTL — a permanently throttled account that
    #: never recovers, which is exactly the permanent lockout this phase must not create.
    #:
    #: The window policy is unchanged and deliberately *not* sliding: the TTL is set when the
    #: counter is created and never refreshed, so N failures inside one window expire together
    #: `window_seconds` after the first. Refreshing on every attempt would let an attacker hold
    #: the window open indefinitely and would also let a counter outlive the documented bound.
    #:
    #: `TIME` inside the script gives the TTL that remains, so `retry_after` can be honest
    #: rather than always reporting the full window. It works on Redis 6.x, unlike
    #: `EXPIRE ... NX`, which needs 7.0.
    _INCR_SCRIPT_SOURCE = """
    local current = redis.call('INCR', KEYS[1])
    if current == 1 then
        redis.call('EXPIRE', KEYS[1], ARGV[1])
        -- E-02 Phase 4.2: mint the generation for this counter incarnation, inside the same
        -- script that created the counter, and hand it to the admitted request. The marker
        -- lives in its own key so the counter stays a plain integer: no script parsing, no
        -- change to what `peek`/`ttl`/operator tooling sees. Same TTL as the counter, so it
        -- cannot outlive the window it names.
        local gen = ARGV[2]
        redis.call('SET', KEYS[2], gen, 'EX', ARGV[1])
        return {current, tonumber(ARGV[1]), gen}
    end
    local ttl = redis.call('TTL', KEYS[1])
    if ttl < 0 then
        -- Self-healing: a key that somehow has no expiry (created by an older build, or
        -- restored from a snapshot) gets one now rather than living forever.
        redis.call('EXPIRE', KEYS[1], ARGV[1])
        ttl = tonumber(ARGV[1])
    end
    -- A counter that predates this build has no marker. Mint one for the window it is
    -- already in, so admissions from here on are refundable and the stale-window case is
    -- closed on upgrade rather than only for windows created afterwards.
    local gen = redis.call('GET', KEYS[2])
    if not gen then
        gen = ARGV[2]
        redis.call('SET', KEYS[2], gen, 'EX', ttl)
    end
    return {current, ttl, gen}
    """

    def __init__(self, url: str, clock: Callable[[], float]):
        import redis  # imported lazily: optional at runtime

        self._clock = clock
        self._client = redis.from_url(url, decode_responses=True, socket_timeout=3.0)
        self._client.ping()
        self._incr_script = self._client.register_script(self._INCR_SCRIPT_SOURCE)
        self._refund_script = self._client.register_script(self._REFUND_SCRIPT_SOURCE)
        self._decr_script = self._client.register_script(self._DECR_SCRIPT_SOURCE)

    def increment_is_atomic(self) -> bool:
        """True when increment and expiry happen in one round-trip. Asserted by the tests."""
        return getattr(self, "_incr_script", None) is not None

    def incr_in_window_detailed(self, key: str, window_seconds: int) -> Dict[str, Any]:
        """
        Atomically increment and return ``{"count", "ttl", "generation"}``.

        The count, the remaining window, and the generation all come from the same script
        execution, so they can never disagree about which counter incarnation was incremented.
        """
        generation = _new_generation()
        count, ttl, gen = self._incr_script(
            keys=[key, _generation_key(key)], args=[int(window_seconds), generation]
        )
        return {
            "count": int(count),
            "ttl": int(ttl),
            # The script echoes back the generation actually in force, which for a brand-new
            # counter is the one we proposed and for an existing window is the stored one.
            "generation": gen.decode() if isinstance(gen, bytes) else str(gen),
        }

    def incr_in_window(self, key: str, window_seconds: int) -> int:
        return self.incr_in_window_detailed(key, window_seconds)["count"]

    def read_counter(self, key: str, window_seconds: Optional[int] = None) -> int:
        # A plain GET; expiry is Redis's own job, so `window_seconds` needs no applying.
        return int(self._client.get(key) or 0)

    def delete_counter(self, key: str) -> None:
        self._client.delete(key)

    def ping(self) -> bool:
        """
        Live liveness probe for readiness (E-02 Phase 6, R11).

        The client is built once at startup and never rebuilt, so this is the only way to
        notice a Redis that died *after* startup. It raises nothing itself: the caller maps a
        failure to "store not ok" and logs the exception class only.
        """
        self._client.ping()
        return True

    #: Generation-checked, single-use refund, in one round-trip.
    #:
    #: E-02 Phase 4.2. The old script was a bare clamped `DECR`: it reversed whatever counter
    #: happened to exist at refund time. This one refuses unless the admission's generation is
    #: still the live generation, which is what binds a refund to the window it was admitted
    #: in. Redis executes the whole body atomically, so the check and the decrement cannot be
    #: separated by another request — the same guarantee the memory store gets from its lock.
    #:
    #: Single use is enforced by the `:refunded` key, claimed with `SET NX`: the first refund
    #: of a token wins, a replay loses. It carries the counter's TTL so it cannot accumulate,
    #: and it is scoped to the generation so a new window cannot collide with a stale marker.
    #:
    #: Deleting at zero keeps "no counter" and "zero failures" the same state, so a fresh
    #: window cannot inherit a stale value.
    #:
    #: KEYS: 1 counter, 2 generation marker, 3 refund-claimed marker
    #: ARGV: 1 token generation
    #: Returns 1 when a slot was refunded, 0 when the refund is not valid.
    _REFUND_SCRIPT_SOURCE = """
    local current = tonumber(redis.call('GET', KEYS[1]) or '0')
    if current <= 0 then
        return 0
    end
    local gen = redis.call('GET', KEYS[2])
    if not gen or gen ~= ARGV[1] then
        -- The admission belongs to a window that has already rolled over.
        return 0
    end
    local ttl = redis.call('TTL', KEYS[1])
    if ttl <= 0 then
        return 0
    end
    local claimed = redis.call('SET', KEYS[3], '1', 'EX', ttl, 'NX')
    if not claimed then
        -- This admission was already refunded.
        return 0
    end
    local updated = redis.call('DECR', KEYS[1])
    if updated <= 0 then
        redis.call('DEL', KEYS[1])
        return 1
    end
    return 1
    """

    def refund_admission(self, key: str, token: AdmissionToken) -> bool:
        """Atomically reverse one admission iff it belongs to the live generation."""
        if not token.generation:
            return False
        refunded = self._refund_script(
            keys=[
                key,
                _generation_key(key),
                f"{_generation_key(key)}:refunded:{token.generation}:{token.admission_id}",
            ],
            args=[token.generation],
        )
        return bool(int(refunded))

    #: Retained for API compatibility only. This is the Phase 4.1 primitive that had no notion
    #: of which admission it reversed; nothing in the account path calls it any more. See
    #: `_REFUND_SCRIPT_SOURCE` for the refund that replaced it.
    _DECR_SCRIPT_SOURCE = """
    local current = tonumber(redis.call('GET', KEYS[1]) or '0')
    if current <= 0 then
        redis.call('DEL', KEYS[1])
        return 0
    end
    local updated = redis.call('DECR', KEYS[1])
    if updated <= 0 then
        redis.call('DEL', KEYS[1])
        return 0
    end
    return updated
    """

    def decrement_floor_zero(self, key: str, window_seconds: Optional[int] = None) -> int:
        return int(self._decr_script(keys=[key]))


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
            except Exception as exc:
                # E-02 Phase 6, R11. The silent memory fallback is what made a per-process
                # counter able to stand in for a shared one without anyone noticing: N workers
                # meant N × the limit. In production there is no acceptable fallback, so the
                # error is re-raised and the process fails to start. Development and tests keep
                # the fallback — an absent Redis there is a supported configuration.
                if _redis_is_required():
                    raise RateLimitStoreUnavailable(
                        "Redis could not be initialised in production. A per-process counter "
                        "would multiply the effective limit by the worker count, so the "
                        "limiter refuses to start instead of silently weakening itself. "
                        f"Backend error: {type(exc).__name__}."
                    ) from exc
                logger.warning(
                    f"Rate limiter could not reach Redis ({exc}); falling back to a "
                    "per-process counter. Limits will be weaker than configured. "
                    "This fallback is development-only and is refused in production."
                )
        elif _redis_is_required():
            raise RateLimitStoreUnavailable(
                "REDIS_URL is required when running in production: account and IP counters "
                "must be shared across workers. Without it each worker keeps a private "
                "counter and the effective limit becomes N x the configured limit."
            )
        return _MemoryStore(self._clock)

    def backend(self) -> str:
        return getattr(self._store, "backend_name", "unknown")

    def ping(self) -> bool:
        """
        Whether the configured store answers right now.

        E-02 Phase 6, R11. Used by readiness only. A memory store is process-local and always
        "answers"; a Redis store answers only if the server does. Never raises, and never
        returns or logs the URL or any exception text beyond its class — the caller is an
        unauthenticated endpoint.
        """
        probe = getattr(self._store, "ping", None)
        if probe is None:
            return True
        try:
            return bool(probe())
        except Exception as exc:
            logger.error(f"Rate limiter store ping failed ({type(exc).__name__})")
            return False

    def peek(self, key: str, window_seconds: Optional[int] = None) -> int:
        """
        Read a counter without incrementing it. Diagnostics and tests only.

        Takes the store's own lock (memory) or a plain `GET` (Redis), so a concurrent
        increment can never be observed half-applied. `window_seconds` makes the memory
        store treat an expired entry as absent, matching Redis TTL semantics.
        """
        try:
            return self._store.read_counter(key, window_seconds)
        except Exception as exc:  # pragma: no cover - depends on a live server
            logger.error(f"Rate limiter store failed to read {key} ({exc}); reporting 0")
            return 0

    def reset_key(self, key: str) -> None:
        """
        Delete exactly one counter.

        Used to clear an account's failure count on successful authentication. Deliberately
        narrower than `reset(scope)`, which takes a prefix and would also clear unrelated
        accounts.
        """
        try:
            self._store.delete_counter(key)
        except Exception as exc:  # pragma: no cover - depends on a live server
            logger.error(f"Rate limiter store failed to delete {key} ({exc})")

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


# =============================================================================
# E-02 Phase 3 — trusted-proxy client-IP policy
# =============================================================================
# Why this is not three lines of header parsing
# ---------------------------------------------
# `request.client.host` is NOT the TCP peer on this stack. uvicorn defaults to
# `proxy_headers=True` with `forwarded_allow_ips="127.0.0.1,::1"`, and when the peer is
# trusted it overwrites `scope["client"]` from `X-Forwarded-For` (measured on 0.54.0:
# `1.1.1.1, 2.2.2.2` becomes `2.2.2.2`, the port is forced to 0, and `not-an-ip` is
# accepted verbatim with no validation). The production command therefore passes
# `--no-proxy-headers`, which makes `scope["client"]` the real socket peer, and the rules
# below become the single authority on forwarding.
#
# Policy
# ------
# 1. Start from the socket peer.
# 2. If the peer is not a trusted proxy, ignore every forwarding header.
# 3. Otherwise walk `X-Forwarded-For` right-to-left, skipping addresses that are
#    themselves trusted proxies, and return the first untrusted address.
# 4. Every entry must parse as an IP address; anything else aborts the walk and the peer
#    is returned. A value that cannot be parsed must never become an identity.
# 5. Bounded: at most `_MAX_FORWARDED_HOPS` entries and `_MAX_FORWARDED_HEADER_BYTES` bytes.
# 6. `X-Real-IP` and RFC 7239 `Forwarded` are deliberately NOT supported. Supporting them
#    needs its own trust validation and tests; silently falling back to them is how a
#    "hardened" resolver ends up bypassable again.
#
# Configuration is environment-only: `TRUSTED_PROXIES`, comma separated, IPv4/IPv6/CIDR.
# Empty or unset means trust nothing. `*`, `0.0.0.0/0` and `::/0` are rejected: they would
# disable the policy, so a misconfiguration fails closed rather than open.

#: Requests deeper than this are treated as hostile and fall back to the peer.
_MAX_FORWARDED_HOPS = 15

#: A header longer than this is not inspected at all (it is ~57 KB of addresses).
_MAX_FORWARDED_HEADER_BYTES = 1024

#: Trust entries that would grant universal trust and are therefore refused.
_UNIVERSAL_TRUST_LITERALS = {"*", "all", "any", "0.0.0.0/0", "::/0"}

_trusted_proxy_lock = threading.Lock()
#: Parsed trust list: IPv4Address/IPv6Address/IPv4Network/IPv6Network instances.
_trusted_proxies: List[Any] = []
_trusted_proxies_loaded = False


def _parse_trusted_proxy(entry: str):
    """
    One `TRUSTED_PROXIES` entry -> an address or network object, or None to reject it.

    Both `ip_address` and `ip_network` are used so matching is structural: `2001:db8::1`
    and `2001:0db8:0:0::1` are the same host, and a textual comparison would miss that.
    """
    raw = (entry or "").strip()
    if not raw or raw.lower() in _UNIVERSAL_TRUST_LITERALS:
        return None
    try:
        if "/" in raw:
            network = ipaddress.ip_network(raw, strict=False)
            # /0 is every address; refused above by literal, but catch other spellings.
            if network.prefixlen == 0:
                logger.error(
                    f"TRUSTED_PROXIES entry {raw!r} covers the whole address space and is "
                    "ignored; universal trust would disable the policy"
                )
                return None
            return network
        return ipaddress.ip_address(raw)
    except ValueError:
        logger.warning(
            f"TRUSTED_PROXIES entry {raw!r} is not an IP address or CIDR network and is "
            "ignored. Trust is never widened to compensate."
        )
        return None


def _load_trusted_proxies() -> List[Any]:
    """Parse `TRUSTED_PROXIES` into address/network objects."""
    raw = os.getenv("TRUSTED_PROXIES", "")
    parsed = []
    for entry in raw.split(","):
        parsed_entry = _parse_trusted_proxy(entry)
        if parsed_entry is not None:
            parsed.append(parsed_entry)
    return parsed


def get_trusted_proxies() -> List[Any]:
    """The active trust list. Loaded once per process on first use."""
    global _trusted_proxies, _trusted_proxies_loaded
    if not _trusted_proxies_loaded:
        with _trusted_proxy_lock:
            if not _trusted_proxies_loaded:
                _trusted_proxies = _load_trusted_proxies()
                _trusted_proxies_loaded = True
                if _trusted_proxies:
                    logger.info(
                        "Trusted proxies configured: "
                        + ", ".join(str(p) for p in _trusted_proxies)
                    )
                else:
                    logger.info(
                        "No trusted proxies configured; forwarding headers are ignored. "
                        "Set TRUSTED_PROXIES only if this app runs behind a proxy you control."
                    )
    return list(_trusted_proxies)


def refresh_trusted_proxies() -> List[Any]:
    """Re-read `TRUSTED_PROXIES`. For tests and for a deliberate config reload."""
    global _trusted_proxies, _trusted_proxies_loaded
    with _trusted_proxy_lock:
        _trusted_proxies = _load_trusted_proxies()
        _trusted_proxies_loaded = True
    return list(_trusted_proxies)


def _is_trusted_proxy(address, trusted_list: List[Any]) -> bool:
    """Membership test for an already-parsed address."""
    if address is None:
        return False
    for entry in trusted_list:
        if isinstance(entry, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            if address.version == entry.version and address in entry:
                return True
        elif address == entry:
            return True
    return False


def _peer_address(request):
    """The socket peer as an address object, or None if unusable."""
    client = getattr(request, "client", None)
    host = getattr(client, "host", None) if client else None
    if not host:
        return None
    try:
        return ipaddress.ip_address(host.split("%", 1)[0])  # strip an IPv6 zone id
    except ValueError:
        return None


def resolve_client_ip(request) -> str:
    """
    The one place that decides "who is this client".

    Returns a string suitable for use as a rate-limit key. Never returns a value taken
    from a header unless the socket peer is a configured trusted proxy AND **every** entry
    of the chain parsed as an IP address.

    Strictness (Phase 3.1): an empty or whitespace-only entry is malformed, exactly like
    `not-an-ip` is. One bad entry anywhere in the chain — including one that the walk would
    never have reached — collapses the identity to the socket peer.
    """
    peer = _peer_address(request)
    peer_text = str(peer) if peer is not None else None

    trusted_list = get_trusted_proxies()
    if not trusted_list or peer is None or not _is_trusted_proxy(peer, trusted_list):
        # No policy, or the peer is not a proxy we trust. Forwarding headers are ignored.
        return peer_text or "unknown"

    raw = request.headers.get("x-forwarded-for")
    if not raw:
        return peer_text

    if len(raw) > _MAX_FORWARDED_HEADER_BYTES:
        logger.warning(
            f"Ignoring X-Forwarded-For of {len(raw)} bytes (limit "
            f"{_MAX_FORWARDED_HEADER_BYTES}); using the socket peer"
        )
        return peer_text

    hops = [h.strip() for h in raw.split(",")]
    if len(hops) > _MAX_FORWARDED_HOPS:
        logger.warning(
            f"Ignoring X-Forwarded-For with {len(hops)} hops (limit "
            f"{_MAX_FORWARDED_HOPS}); using the socket peer"
        )
        return peer_text

    # E-02 Phase 3.1: strict validation. EVERY entry must parse as an IP address.
    #
    # Phase 3 had `if not hop: continue`, which silently skipped empty entries and then
    # trusted the rest of the chain, so `", 198.51.100.9"` resolved to `198.51.100.9`
    # instead of the socket peer. An empty or whitespace-only slot is not a valid IP
    # address and must abort the walk, exactly like `not-an-ip` does.
    #
    # Validating the whole chain up front, rather than aborting mid-walk, also removes the
    # second lenient loop that Phase 3 needed for the all-trusted case: if every entry is
    # known to be an address before the walk starts, no path can skip a malformed one.
    addresses = []
    for hop in hops:
        if not hop:
            logger.warning(
                "Empty X-Forwarded-For entry (leading, trailing or doubled comma); "
                "aborting the walk and using the socket peer"
            )
            return peer_text
        try:
            addresses.append(ipaddress.ip_address(hop))
        except ValueError:
            logger.warning(
                f"Unparseable X-Forwarded-For entry {hop[:64]!r}; aborting the walk and "
                "using the socket peer"
            )
            return peer_text

    # Right-to-left: the last entry was appended by the proxy we already trust, so it is
    # the closest hop. Return the first address that is not itself a trusted proxy.
    for address in reversed(addresses):
        if not _is_trusted_proxy(address, trusted_list):
            return str(address)

    # Every hop is a trusted proxy (e.g. a proxy calling itself). The left-most address is
    # the best available answer, and it is still a trusted-proxy address — never a value
    # that failed validation.
    return str(addresses[0]) if addresses else peer_text


def client_identity(request) -> str:
    """
    The rate-limiting identity for a request.

    Phase 3: this delegates entirely to `resolve_client_ip()`. It deliberately does not
    parse headers itself — a second code path is a second policy, and that is how the
    original bypass existed.
    """
    return resolve_client_ip(request)


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


# =============================================================================
# E-02 Phase 4 — account-level failed-login protection
# =============================================================================
# The gap Phase 3 left open
# -------------------------
# Phase 3 made the client IP trustworthy, so an attacker can no longer *claim* somebody
# else's address. It does nothing about an attacker who simply uses addresses it really
# has: a botnet, a residential proxy pool, or one cloud VM per attempt. With `auth_login`
# at 10/60s per IP, 400 attempts against one account cost 40 addresses and 60 seconds —
# and the Phase 2 suite demonstrated exactly that (40 attempts from 40 IPs, all accepted).
#
# The two limits are therefore independent and neither replaces the other:
#   * IP limit   — caps how fast one source can guess against *any* account.
#   * Acct limit — caps how many times one account can be guessed against from *anywhere*.
#
# A note on what is deliberately NOT here: there is no lockout. This is a temporary
# throttle that expires on its own, and a successful authentication clears it outright.
# A permanent or long lockout converts a brute-force defence into a trivial denial of
# service — anyone who can reach the login form could lock the owner out of their own
# tenant indefinitely by guessing wrong. That trade is not worth it, so the throttle is
# bounded below an hour and always self-heals.
#
# Threshold rationale (not invented — tied to what it must stop)
# --------------------------------------------------------------
# 20 failures / 15 minutes per account. Against a real password space the arithmetic that
# matters is guesses-per-hour-per-account, not per-IP:
#   * 20/15min ≈ 80/hour ≈ 1,900/day. Against even a modest password lifted from a
#     top-1,000 list (which 1 attempt in 1,000 would hit), a day of continuous attack is
#     still well inside the margin a normal user's password should have — but it is 20x
#     slower than the per-IP limit alone allows when addresses are free.
#   * It is far above human mistyping: 20 failures in a 15-minute window is not a person
#     fumbling a password, so support load stays nil.
#   * Because success clears the counter, the "I finally remembered it" path is untouched.
# These are configurable through the environment so a deployment can raise them without a
# code change; the defaults are the reviewable policy.
ACCOUNT_FAILURE_THRESHOLD = 20

#: Sliding-window length in seconds for the account counter (15 minutes).
#:
#: Bounded at one hour by `test_43`: past that it stops behaving like a throttle and starts
#: behaving like a lockout, which is the thing this phase must not introduce.
ACCOUNT_FAILURE_WINDOW = 15 * 60

#: Scope name, matching `ratelimit:auth_account:<keyed digest>` in Redis.
ACCOUNT_SCOPE = "auth_account"

#: Throttle message. Fixed text, identical for known and unknown accounts, so the response
#: cannot become the enumeration oracle that the error message no longer is.
ACCOUNT_THROTTLE_MESSAGE = (
    "Хэт олон удаа буруу оролдлого хийлээ. Хэсэг хугацааны дараа дахин оролдоно уу."
)


def account_rate_limit_key(identifier: Optional[str]) -> Optional[str]:
    """
    The account identity used in the store: a keyed digest, or None when unavailable.

    Kept for callers that already hold a canonical id or a normalized identifier. Prefer
    `account_canonical_key()` on the request path, which resolves aliases first. See
    `core/account_keys` for why the digest is keyed and why a missing secret means None rather
    than an unkeyed fallback.
    """
    from core import account_keys

    return account_keys.account_key(identifier)


def refresh_account_key_secret() -> Optional[str]:
    """Re-read the account-key secret from the environment (startup, tests, rotation)."""
    from core import account_keys

    return account_keys.refresh_secret()


def validate_account_key_secret() -> None:
    """Fail closed in production when the account-key secret is unusable."""
    from core import account_keys

    account_keys.validate_secret_for_startup()


def validate_store_for_startup(probe: bool = True) -> None:
    """
    Fail closed in production when no shared rate-limit store can be established.

    E-02 Phase 6, R11. Phase 4 and earlier logged a warning and silently used a per-process
    dict, which multiplied the effective limit by the worker count. This makes the deployment
    contract explicit and checks it *before* the app serves a single request:

      1. `REDIS_URL` must be set and non-blank;
      2. Redis must actually answer a `PING` (so an unreachable host fails startup, not the
         first login);
      3. the limiter must have selected the shared backend.

    Development and tests: returns immediately, keeping the documented memory fallback.

    Args:
        probe: perform the live `PING`. Tests disable it only to prove the URL/shape checks
            in isolation; startup always probes.

    Raises:
        RateLimitStoreUnavailable: in production, with no credentials in the message.
    """
    if not _redis_is_required():
        return

    if not str(os.getenv("REDIS_URL", "")).strip():
        raise RateLimitStoreUnavailable(
            "REDIS_URL is required when running in production: account and IP rate-limit "
            "counters must be shared across workers. Without it each uvicorn worker keeps a "
            "private counter and the effective login limit becomes workers x the configured "
            "limit. Set REDIS_URL (see docker-compose.prod.yml) and restart."
        )

    if probe:
        try:
            _RedisStore(str(os.getenv("REDIS_URL", "")).strip(), time.time)
        except RateLimitStoreUnavailable:
            raise
        except Exception as exc:
            # Class name only: a redis exception can embed the host and, for a malformed URL,
            # the credentials. Neither belongs in a startup log.
            raise RateLimitStoreUnavailable(
                "REDIS_URL is set but Redis did not answer a PING at startup. Refusing to "
                "serve: a per-process counter would multiply the effective limit by the worker "
                f"count. Backend error: {type(exc).__name__}."
            ) from exc

    limiter = get_limiter()
    if not limiter.is_shared():
        raise RateLimitStoreUnavailable(
            "The rate limiter selected a non-shared backend in production, which multiplies "
            "the effective limit by the worker count. Refusing to serve."
        )


def resolve_account_identity(identifier: str) -> Tuple[str, bool]:
    """
    Resolve a submitted login identifier to the value the account counter is keyed on.

    Returns ``(identity_value, is_canonical)``.

    E-02 Phase 4.1, finding A. The login lookup accepts `client_username` OR `page_id`, so the
    Phase 4 implementation — which keyed on the raw submitted string — gave one account one
    budget per alias. Measured: after exhausting the budget through the username, the page_id
    alias still answered 401 and could start again.

    * Known identifier -> the canonical `page_id`. Every supported alias of one account then
      maps to the same counter by construction.
    * Unknown identifier -> the DB-normalized submitted value. Privacy is preserved (it is only
      ever fed to a keyed digest) and unknown accounts stay throttled, so the throttle cannot
      become an existence oracle.

    Resolution is a database read, never trust in a client-supplied value: a page_id that does
    not exist resolves to None and takes the normalized-identifier path.

    A database failure here must not take login down. If resolution raises, the caller's
    identifier is normalized on a best-effort basis; the throttle then keys on the submitted
    value, which is weaker (aliases get separate budgets) but never weaker than Phase 4.
    """
    import database

    raw = str(identifier or "")
    try:
        canonical = database.resolve_canonical_account(raw)
        if canonical:
            return canonical, True
    except Exception as exc:  # the lookup itself failed — fall through to normalization
        logger.error(f"Account identity lookup failed ({exc}); normalizing without it")
    try:
        # Normalize with the engine's own comparison wherever possible, even when the lookup
        # above failed: `LOWER(TRIM(?))` needs no account to exist.
        return database.sql_lower_trim(raw), False
    except Exception as exc:  # pragma: no cover - depends on a live database
        # E-02 Phase 4.2, audit A. The previous fallback was `str.casefold()`, which is NOT the
        # database's comparison: it folds `ß` to `ss`, which neither SQLite nor PostgreSQL
        # does, so during an outage two identifiers the database keeps distinct would share a
        # counter — silently merging unrelated accounts, which Phase 4.1 specifically ruled
        # out. `str.strip()` is the only safe degradation: it can collapse fewer identifiers,
        # never more, so the worst case is an account temporarily getting more than one budget
        # (never less, and never another tenant's counter).
        logger.error(
            f"Account identity normalization failed ({exc}); keying on the trimmed identifier"
        )
        return raw.strip(), False


def account_canonical_key(identifier: str, canonical: Optional[str] = None) -> Optional[str]:
    """
    Derive the store identity for a login attempt.

    `canonical` should be the value returned by `resolve_account_identity`. When it is None the
    identifier is resolved here, so a caller cannot accidentally key on a raw alias.
    """
    if canonical is None:
        canonical, _ = resolve_account_identity(identifier)
    if not canonical:
        return None
    return account_rate_limit_key(canonical)


def _account_store_key_for_identity(identity: Optional[str]) -> Optional[str]:
    digest = account_rate_limit_key(identity)
    if not digest:
        return None
    return f"ratelimit:{ACCOUNT_SCOPE}:{digest}"


def account_store_key(identifier: str, canonical: Optional[str] = None) -> Optional[str]:
    """
    Full store key for an identifier, resolving aliases. Returns None when unconfigured.

    This is the function the request path uses; it is what makes `get_account_failure_count`
    and the login route agree about which counter an account owns.
    """
    if canonical is None:
        canonical, _ = resolve_account_identity(identifier)
    return _account_store_key_for_identity(canonical)


def get_account_failure_count(identifier: str) -> int:
    """
    Current recorded failures for an account, without recording a new one.

    Accepts any alias of the account; resolution happens first, so the username and page_id
    aliases report the same value. Returns 0 when account throttling is not configured.

    E-02 Phase 6, R15. This used to pass `ACCOUNT_FAILURE_WINDOW` (the *policy* window) to
    `peek`, which overrode the generation's own window in the memory store. A generation
    created with a shorter window was therefore reported as live by this function long after
    admission and refund had both started treating it as expired — and because Redis's `GET`
    ignores the argument, the two backends disagreed. Passing `None` means "use the entry's own
    window", which is exactly the rule admission and refund already apply.
    """
    key = account_store_key(identifier)
    if key is None:
        return 0
    return get_limiter().peek(key)


def get_account_failure_count_by_identity(identity: str) -> int:
    """
    Count for an already-resolved canonical identity. No database access.

    Uses the generation's own window, for the same reason as
    `get_account_failure_count` (E-02 Phase 6, R15).
    """
    key = _account_store_key_for_identity(identity)
    if key is None:
        return 0
    return get_limiter().peek(key)


def check_account_login_allowed(
    identifier: str,
    limit: Optional[int] = None,
    window_seconds: Optional[int] = None,
) -> Dict[str, object]:
    """
    Admit or refuse one login attempt against `identifier`.

    Returns ``{"allowed", "count", "limit", "retry_after", "identity", "canonical"}``.

    The increment happens at admission, atomically with its expiry (finding B). That ordering
    is what lets the failure be recorded *after* authentication without a second increment:
    the attempt already holds a slot, and `record_account_failure()` decides whether to keep it.

    When account throttling is not configured the call is a no-op that always allows — the
    documented degradation, refused outright in production by
    `core.account_keys.validate_secret_for_startup`.
    """
    effective_limit = ACCOUNT_FAILURE_THRESHOLD if limit is None else limit
    effective_window = ACCOUNT_FAILURE_WINDOW if window_seconds is None else window_seconds

    identity, canonical = resolve_account_identity(identifier)
    key = _account_store_key_for_identity(identity)
    if key is None:
        return {
            "allowed": True, "count": 0, "limit": 0, "retry_after": 0,
            "identity": identity, "canonical": canonical, "token": None,
        }

    limiter = get_limiter()
    try:
        # Both stores now report the generation they incremented, so the token below names the
        # exact counter incarnation this admission consumed. The memory store implements the
        # same `incr_in_window_detailed` contract under its lock.
        result = limiter._store.incr_in_window_detailed(key, effective_window)
        count, remaining, generation = result["count"], result["ttl"], result["generation"]
    except StoreAtCapacityError as exc:
        # E-02 Phase 4.4. The memory store is full of live counters and would have had to evict
        # one to admit this identity. Fail CLOSED: admitting an account whose failures cannot be
        # recorded would hand it an unlimited budget. No token, no counter, no other identity
        # touched. (Redis never raises this.)
        logger.error(f"Account throttle at capacity for {ACCOUNT_SCOPE} ({exc}); refusing")
        return {
            "allowed": False, "count": 0, "limit": effective_limit,
            "retry_after": effective_window, "identity": identity, "canonical": canonical,
            "token": None, "at_capacity": True,
        }
    except Exception as exc:
        # E-02 Phase 6, R14. Phase 4 copied the IP limiter's fail-open posture here. That is
        # wrong for this scope, and the reason is a difference in what the two limits protect:
        #
        #   * The IP limit is a volume control. Failing it open costs a weaker limit on a
        #     shared address, and the account limit still bounds an attack per account.
        #   * The account limit is the *last* line for a single account. Failing it open does
        #     not weaken it, it removes it: with no counter to increment, nothing bounds how
        #     many passwords can be tried against one account. An attacker who can make the
        #     store fail (or who waits for it to) gets an unlimited budget.
        #
        # The IP limit deliberately keeps its fail-open posture; this branch is not a policy
        # change for it, and it is not reachable from this code path.
        #
        # Fail CLOSED: refuse the attempt, record a security event, and hand the client the
        # same 429 + Retry-After it would receive if the account were genuinely throttled.
        # The exception text is logged server-side only — it can carry a host or a URL, so it
        # must never reach the response body.
        logger.error(
            f"Account throttle store failed for {ACCOUNT_SCOPE} ({exc}); refusing login "
            "(fail-closed policy: an unrecorded attempt would be an unbounded attempt)"
        )
        return {
            "allowed": False, "count": 0, "limit": effective_limit,
            "retry_after": effective_window, "identity": identity, "canonical": canonical,
            "token": None, "store_failed": True,
        }

    allowed = count <= effective_limit
    return {
        "allowed": allowed,
        "count": count,
        "limit": effective_limit,
        # The real remaining window, not the nominal one, so Retry-After is honest.
        "retry_after": max(1, int(remaining)) if not allowed else 0,
        "identity": identity,
        "canonical": canonical,
        # Present only for an admitted attempt: there is no slot to give back when the
        # attempt was refused, and returning a token for it would let a refused attempt
        # cancel a real failure.
        "token": (
            AdmissionToken(
                identity=identity,
                generation=generation,
                admission_id=_new_generation(),
                # The generation's own window, not the one this caller asked for. `remaining`
                # is what the store reports for this generation, so the token can never claim
                # a longer (or shorter) life than the counter it belongs to. The refund takes
                # the authoritative path in the store either way; this keeps the token honest
                # for anyone inspecting it.
                window_seconds=int(remaining),
            )
            if allowed
            else None
        ),
    }


def record_account_failure(identity: str) -> None:
    """
    Record that an admitted attempt was a genuine authentication failure.

    The admission in `check_account_login_allowed` already incremented the counter, so a failed
    password needs no further action: the slot it consumed becomes a recorded failure. This
    function exists as the explicit name for that decision, and as the single place to change
    if the counting model ever separates "attempts" from "failures".
    """
    return None


def clear_account_failures_on_success(
    identity: str,
    canonical: bool = True,
    token: Optional[AdmissionToken] = None,
) -> bool:
    """
    Reverse the slot consumed by a *successful* login.

    E-02 Phase 4.1, finding C. Phase 4 called `reset_account_failures()`, which deleted the
    whole key. With admission-then-verify ordering that loses failures recorded concurrently:

        t0  attacker failure admitted   INCR -> 5
        t1  victim   success admitted   INCR -> 6
        t2  attacker failure admitted   INCR -> 7   (after the success event)
        t3  victim   reset              DEL         -> erases the t2 failure

    The guarantee adopted instead: **a successful login removes exactly the one slot it
    consumed, and nothing else.** Decrementing is linearizable and idempotent per request, so
    no failure recorded after the success was admitted can be lost, and a success can never
    erase a counter it did not own.

    Consequences of the model, stated plainly:
      * Successes do not clear the residual failures of earlier mistyping; they expire with the
        window instead. `test_12` in the Phase 2 suite pins the exact number of attempts a
        given history admits, so this is asserted rather than assumed.
      * The counter is clamped at zero: a success with no failures behind it must not drive the
        counter negative and hand out budget.
    """
    digest = account_rate_limit_key(identity)
    if not digest:
        return False
    key = f"ratelimit:{ACCOUNT_SCOPE}:{digest}"
    if token is None:
        # E-02 Phase 4.2. Without the admission, there is nothing to identify what to refund.
        # Refusing is the safe direction: the cost is a residual failure that expires with its
        # window, whereas guessing would risk erasing someone else's failure.
        logger.error(
            f"Account refund called without an admission token for {ACCOUNT_SCOPE}; refusing"
        )
        return False
    # The token must have been minted for this counter. Without this, a token issued for
    # account A could be replayed against account B whenever the two generations coincided.
    # Compare on the canonical identity, resolved here the same way admission resolved it. The
    # caller legitimately passes aliases: `clear_account_failures_on_success("Acme")` must work
    # for a token minted for canonical `page-acme`, exactly as it always has. Comparing against
    # the raw argument would reject every alias and silently under-refund.
    resolved, _canonical = resolve_account_identity(identity)
    if not token.identity or token.identity != resolved:
        logger.error(f"Account refund token identity mismatch for {ACCOUNT_SCOPE}; refusing")
        return False
    try:
        return bool(get_limiter()._store.refund_admission(key, token))
    except Exception as exc:  # pragma: no cover - depends on a live server
        logger.error(f"Account counter refund failed for {ACCOUNT_SCOPE} ({exc})")
        return False


def reset_account_failures(identifier: str) -> None:
    """
    Clear an account's recorded failures outright.

    **Not used by the login path** — see `clear_account_failures_on_success`, which refunds a
    single slot instead of deleting the counter. This remains for operator use ("clear this
    account now") and for tests.

    Clears only the account counter. The IP counter is intentionally left alone: a successful
    login proves the account, not the source address.
    """
    key = account_store_key(identifier)
    if key is None:
        return
    get_limiter().reset_key(key)
