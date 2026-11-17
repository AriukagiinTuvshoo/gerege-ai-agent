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
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

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

    def read_counter(self, key: str, window_seconds: Optional[int] = None) -> int:
        """
        Current count, treating an entry older than `window_seconds` as expired.

        The window has to be applied here as well as in `incr_in_window`: a caller asking
        "how many failures has this account had?" must get 0 once the window has passed,
        otherwise a throttle would appear to persist after it has actually lapsed.
        """
        now = self._clock()
        with self._lock:
            entry = self._counters.get(key)
            if entry is None:
                return 0
            started, count = entry
            if window_seconds is not None and now - started >= window_seconds:
                return 0
            return count

    def delete_counter(self, key: str) -> None:
        with self._lock:
            self._counters.pop(key, None)

    def decrement_floor_zero(self, key: str, window_seconds: Optional[int] = None) -> int:
        """
        Subtract one from the counter, never below zero, under the store lock.

        Used to refund the slot a successful login consumed. Clamping at zero matters: without
        it, repeated successes would drive the counter negative and hand out free budget.
        """
        now = self._clock()
        with self._lock:
            entry = self._counters.get(key)
            if entry is None:
                return 0
            started, count = entry
            if window_seconds is not None and now - started >= window_seconds:
                self._counters.pop(key, None)
                return 0
            new_count = max(0, count - 1)
            if new_count == 0:
                self._counters.pop(key, None)
            else:
                self._counters[key] = (started, new_count)
            return new_count


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
        return {current, tonumber(ARGV[1])}
    end
    local ttl = redis.call('TTL', KEYS[1])
    if ttl < 0 then
        -- Self-healing: a key that somehow has no expiry (created by an older build, or
        -- restored from a snapshot) gets one now rather than living forever.
        redis.call('EXPIRE', KEYS[1], ARGV[1])
        ttl = tonumber(ARGV[1])
    end
    return {current, ttl}
    """

    def __init__(self, url: str, clock: Callable[[], float]):
        import redis  # imported lazily: optional at runtime

        self._clock = clock
        self._client = redis.from_url(url, decode_responses=True, socket_timeout=3.0)
        self._client.ping()
        self._incr_script = self._client.register_script(self._INCR_SCRIPT_SOURCE)
        self._decr_script = self._client.register_script(self._DECR_SCRIPT_SOURCE)

    def increment_is_atomic(self) -> bool:
        """True when increment and expiry happen in one round-trip. Asserted by the tests."""
        return getattr(self, "_incr_script", None) is not None

    def incr_in_window_detailed(self, key: str, window_seconds: int) -> Dict[str, int]:
        """
        Atomically increment and return ``{"count", "ttl"}``.

        The count and the remaining window come from the same script execution, so the two can
        never disagree.
        """
        count, ttl = self._incr_script(keys=[key], args=[int(window_seconds)])
        return {"count": int(count), "ttl": int(ttl)}

    def incr_in_window(self, key: str, window_seconds: int) -> int:
        return self.incr_in_window_detailed(key, window_seconds)["count"]

    def read_counter(self, key: str, window_seconds: Optional[int] = None) -> int:
        # A plain GET; expiry is Redis's own job, so `window_seconds` needs no applying.
        return int(self._client.get(key) or 0)

    def delete_counter(self, key: str) -> None:
        self._client.delete(key)

    #: Clamped decrement in one round-trip. Deleting at zero keeps "no counter" and "zero
    #: failures" the same state, so a fresh window cannot inherit a stale value.
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
            except Exception as exc:  # pragma: no cover - depends on a live server
                logger.warning(
                    f"Rate limiter could not reach Redis ({exc}); falling back to a "
                    "per-process counter. Limits will be weaker than configured."
                )
        return _MemoryStore(self._clock)

    def backend(self) -> str:
        return getattr(self._store, "backend_name", "unknown")

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
    try:
        import database

        canonical = database.resolve_canonical_account(identifier)
        if canonical:
            return canonical, True
        return database.sql_lower_trim(str(identifier or "")), False
    except Exception as exc:  # pragma: no cover - depends on a live database
        logger.error(f"Account identity resolution failed ({exc}); keying on the raw identifier")
        return str(identifier or "").strip().casefold(), False


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
    """
    key = account_store_key(identifier)
    if key is None:
        return 0
    return get_limiter().peek(key, ACCOUNT_FAILURE_WINDOW)


def get_account_failure_count_by_identity(identity: str) -> int:
    """Count for an already-resolved canonical identity. No database access."""
    key = _account_store_key_for_identity(identity)
    if key is None:
        return 0
    return get_limiter().peek(key, ACCOUNT_FAILURE_WINDOW)


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
            "identity": identity, "canonical": canonical,
        }

    limiter = get_limiter()
    try:
        if hasattr(limiter._store, "incr_in_window_detailed"):
            result = limiter._store.incr_in_window_detailed(key, effective_window)
            count, remaining = result["count"], result["ttl"]
        else:  # memory store: expiry is evaluated against its injected clock
            count = limiter._store.incr_in_window(key, effective_window)
            remaining = effective_window
    except Exception as exc:  # pragma: no cover - depends on a live server
        # Same posture as the IP limiter: a store outage must not take login down. It is also
        # not silent — E-03 owns the general fail-open/fail-closed policy.
        logger.error(f"Account throttle store failed for {ACCOUNT_SCOPE} ({exc}); allowing request")
        return {
            "allowed": True, "count": 0, "limit": effective_limit, "retry_after": 0,
            "identity": identity, "canonical": canonical,
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


def clear_account_failures_on_success(identity: str, canonical: bool = True) -> bool:
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
    try:
        return get_limiter()._store.decrement_floor_zero(key, ACCOUNT_FAILURE_WINDOW) > 0
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
