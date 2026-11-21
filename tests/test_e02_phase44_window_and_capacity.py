"""
Stage E — E-02 Phase 4.4: mixed-window parity and memory capacity eviction security.

Two defects found in the Phase 4.3 store, both reproduced before any change
(`docs/audit/evidence/e02_phase44_before.txt`).

Defect 1 — one generation, two lifetimes
----------------------------------------
A counter's window was not fixed when its generation was created. `_MemoryCounter` widened it
with `max(...)` on every admission, so a later 900s admission turned a 5s counter into a 900s
counter, while Redis sets the TTL once at creation and never touches it again. Measured:

    Scenario A  admit 5s, then 900s, advance 6s
        memory  peek=2, refund of B -> True   (the window had silently become 900s)
        redis   key gone, refund of B -> False
    Scenario B  admit 900s, then 5s, advance 6s
        memory  refund of A(900s) -> True, of B(5s) -> False
        redis   refund of A -> True,        of B -> True

Scenario B is the sharper failure: the *same token* was refused on one backend and accepted on
the other, because each token carried the window its caller asked for rather than the window the
counter actually has.

Chosen policy
-------------
**A counter's window is fixed when its generation is created; later admissions inherit it and
cannot change it.** This is what Redis has always done (the TTL is written once, inside the same
script that creates the counter) and what the fixed-window model requires: a window that any
caller can widen is not a window. Each store therefore judges expiry from its own authoritative
record of the generation, and a token never redefines it.

Defect 2 — capacity pressure erased live budgets
------------------------------------------------
`_evict_if_needed()` reclaimed expired entries and then, if still over the cap, dropped the
oldest *live* counter — despite its docstring claiming an eviction "can never remove a live
generation". Measured with the real 10,000 cap:

    victim at 19 of 20 failures, window live
    10,200 distinct live filler identities
    victim counter evicted -> next attempt allowed=True, count=1

An attacker could therefore reset any account's failure budget by filling the store.

Chosen policy
-------------
**Expired entries are reclaimed; a live counter is never evicted. When the store is full of live
counters, a *new* identity is refused rather than displacing a live one.** Account admission then
fails closed — no token, no counter touched — because admitting an account whose failures cannot
be recorded would silently grant it an unlimited budget. The IP scope keeps its existing
fail-open-on-store-error posture: the alternative there is a Redis blip logging everyone out.

The availability cost of this choice is real and is recorded as a risk: a client able to mint
10,000 distinct live identities can deny admission to *new* identities in that process until the
windows expire. That is bounded, self-healing, and strictly better than issuing unlimited logins.
"""
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import account_keys, rate_limit  # noqa: E402

TEST_SECRET = "e02-p44-test-secret-0123456789abcdef"

ACCOUNT = "phase44-account-a"
OTHER_ACCOUNT = "phase44-account-b"

SHORT = 5
LONG = 900


class Clock:
    def __init__(self, now: float = 6_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture()
def memory(monkeypatch):
    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()
    clock = Clock()
    limiter = rate_limit.RateLimiter(redis_url="", clock=clock)
    previous = rate_limit.get_limiter()
    rate_limit.set_limiter(limiter)
    try:
        yield limiter, clock
    finally:
        rate_limit.set_limiter(previous)


def _redis_or_skip():
    url = os.getenv("REDIS_URL", "").strip()
    if not url:
        pytest.skip("needs REDIS_URL: cross-backend parity cannot be shown without it")
    import redis

    return url, redis.from_url(url, decode_responses=True)


@pytest.fixture()
def redis_limiter(monkeypatch):
    url, client = _redis_or_skip()
    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()
    limiter = rate_limit.RateLimiter(redis_url=url)
    previous = rate_limit.get_limiter()
    rate_limit.set_limiter(limiter)
    for k in client.scan_iter("ratelimit:auth_account:*"):
        client.delete(k)
    try:
        yield limiter, client
    finally:
        for k in client.scan_iter("ratelimit:auth_account:*"):
            client.delete(k)
        rate_limit.set_limiter(previous)


# ===========================================================================
# ISSUE 1 — mixed windows (tests 401-408)
# ===========================================================================
def test_401_a_later_longer_window_does_not_extend_the_generation(memory):
    """
    Scenario A. The first admission fixes the window; a later 900s admission for the same
    account must not turn the live 5s counter into a 900s one.
    """
    limiter, clock = memory
    rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=SHORT)
    key = rate_limit.account_store_key(ACCOUNT)
    entry = limiter._store._counters[key]
    assert entry.window_seconds == SHORT

    rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=LONG)
    entry = limiter._store._counters[key]
    assert entry.window_seconds == SHORT, (
        f"a later {LONG}s admission widened the generation's window to {entry.window_seconds}s; "
        "the window is fixed when the generation is created"
    )


def test_402_scenario_a_refunds_agree_across_backends(memory, redis_limiter):
    """
    Scenario A parity: admit 5s, admit 900s, let the 5s window pass, refund the long token.
    Both backends must refuse, because the generation the token belongs to has expired.
    """
    decisions = {}
    wait = 2

    memory_limiter, clock = memory
    rate_limit.set_limiter(memory_limiter)
    rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=wait)
    long_mem = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=LONG)
    clock.advance(wait + 0.5)
    assert memory_limiter.backend() == "memory"
    decisions["memory"] = rate_limit.clear_account_failures_on_success(
        ACCOUNT, token=long_mem["token"]
    )
    decisions["memory_count"] = rate_limit.get_account_failure_count(ACCOUNT)

    redis_store, client = redis_limiter
    rate_limit.set_limiter(redis_store)
    rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=wait)
    long_red = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=LONG)
    time.sleep(wait + 0.6)
    assert redis_store.backend() == "redis"
    decisions["redis"] = rate_limit.clear_account_failures_on_success(
        ACCOUNT, token=long_red["token"]
    )
    decisions["redis_count"] = rate_limit.get_account_failure_count(ACCOUNT)

    assert decisions["memory"] == decisions["redis"], (
        f"backends disagree on scenario A: {decisions}"
    )
    assert decisions["memory"] is False
    assert decisions["memory_count"] == 0 and decisions["redis_count"] == 0


def test_403_a_later_shorter_window_does_not_shorten_the_generation(memory):
    """
    Scenario B. A 900s generation must not be cut short by a later 5s admission — and the 5s
    token must not be treated as expired while its generation is live.
    """
    limiter, clock = memory
    rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=LONG)
    short = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=SHORT)
    key = rate_limit.account_store_key(ACCOUNT)
    entry = limiter._store._counters[key]
    assert entry.window_seconds == LONG, (
        f"a later {SHORT}s admission shortened the generation's window to "
        f"{entry.window_seconds}s"
    )

    clock.advance(SHORT + 1)
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=short["token"]) is True, (
        "the 5s token was refused while the generation it belongs to is still live; a token "
        "must not judge expiry by the window its own caller asked for"
    )


def test_404_scenario_b_refunds_agree_across_backends(memory, redis_limiter):
    """Scenario B parity: both admissions in a live generation must be refundable on both."""
    outcomes = {}

    memory_limiter, clock = memory
    rate_limit.set_limiter(memory_limiter)
    rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=LONG)
    short_mem = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=1)
    clock.advance(2)
    outcomes["memory"] = rate_limit.clear_account_failures_on_success(
        ACCOUNT, token=short_mem["token"]
    )

    redis_store, client = redis_limiter
    rate_limit.set_limiter(redis_store)
    rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=LONG)
    short_red = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=1)
    time.sleep(1.2)
    outcomes["redis"] = rate_limit.clear_account_failures_on_success(
        ACCOUNT, token=short_red["token"]
    )

    assert outcomes["memory"] == outcomes["redis"] is True, (
        f"backends disagree on scenario B: {outcomes}"
    )


def test_405_the_token_reports_the_generations_effective_expiry(memory):
    """
    The token must describe the counter it belongs to, not the window its caller asked for.
    Otherwise a token can claim 900s of life for a generation that dies in 5s.
    """
    limiter, clock = memory
    rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=SHORT)
    wide = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=LONG)
    assert wide["token"].window_seconds <= SHORT, (
        f"the token claims a {wide['token'].window_seconds}s lifetime for a generation whose "
        f"window is {SHORT}s"
    )


def test_406_redis_does_not_extend_the_ttl_on_a_later_admission(redis_limiter):
    """Redis already fixes the TTL at creation; pinned so the memory fix cannot regress it."""
    limiter, client = redis_limiter
    rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=2)
    key = rate_limit.account_store_key(ACCOUNT)
    ttl_after_first = client.ttl(key)
    assert 0 < ttl_after_first <= 2

    rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=LONG)
    ttl_after_long = client.ttl(key)
    assert ttl_after_long <= ttl_after_first, (
        f"a later long admission pushed the TTL from {ttl_after_first} to {ttl_after_long}"
    )


def test_407_redis_does_not_shorten_the_ttl_on_a_later_admission(redis_limiter):
    """The mirror case: a later short admission must not cut a long generation short."""
    limiter, client = redis_limiter
    rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=LONG)
    key = rate_limit.account_store_key(ACCOUNT)
    ttl_after_long = client.ttl(key)
    assert ttl_after_long > 800

    rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=2)
    ttl_after_short = client.ttl(key)
    assert ttl_after_short > 800, (
        f"a later short admission cut the TTL from {ttl_after_long} to {ttl_after_short}"
    )


def test_408_expired_generation_is_refused_on_both_backends(memory, redis_limiter):
    """Re-pin the Phase 4.3 guarantee after the window-ownership change."""
    decisions = {}

    memory_limiter, clock = memory
    rate_limit.set_limiter(memory_limiter)
    token = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=2)["token"]
    clock.advance(3)
    decisions["memory"] = rate_limit.clear_account_failures_on_success(ACCOUNT, token=token)

    redis_store, client = redis_limiter
    rate_limit.set_limiter(redis_store)
    token_r = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=2)["token"]
    time.sleep(2.6)
    decisions["redis"] = rate_limit.clear_account_failures_on_success(ACCOUNT, token=token_r)

    assert decisions["memory"] == decisions["redis"] is False, decisions


# ===========================================================================
# ISSUE 2 — capacity eviction (tests 409-417)
# ===========================================================================
def _fill_to_capacity(prefix, cap):
    """Create distinct live counters until the store stops accepting new identities."""
    admitted = 0
    refused = 0
    for i in range(cap * 2 + 50):
        hit = rate_limit.check_account_login_allowed(f"{prefix}-{i}", limit=1000)
        if hit["allowed"] and hit["token"] is not None:
            admitted += 1
        else:
            refused += 1
        if refused >= 5:
            break
    return admitted, refused


def test_409_a_live_victim_counter_survives_capacity_pressure(memory, monkeypatch):
    """
    The reported defect. A victim one short of the threshold must still be one short of it
    after the store is driven to capacity by other identities.
    """
    limiter, _clock = memory
    monkeypatch.setattr(rate_limit, "_MAX_TRACKED_IDENTITIES", 12)

    for _ in range(rate_limit.ACCOUNT_FAILURE_THRESHOLD - 1):
        rate_limit.check_account_login_allowed(ACCOUNT, limit=1000)
    assert rate_limit.get_account_failure_count(ACCOUNT) == rate_limit.ACCOUNT_FAILURE_THRESHOLD - 1

    _fill_to_capacity("phase44-filler", 12)

    survived = rate_limit.get_account_failure_count(ACCOUNT)
    assert survived == rate_limit.ACCOUNT_FAILURE_THRESHOLD - 1, (
        f"the victim's live budget was erased by capacity pressure: expected "
        f"{rate_limit.ACCOUNT_FAILURE_THRESHOLD - 1} failures, found {survived}"
    )

    # And it must still bite. NOTE: the fill above raises `limit` so that admissions keep
    # succeeding regardless of count; the threshold assertions here must use the *production*
    # limit, not the raised one, or the limit being tested is 1000 and the assertion is vacuous.
    at_limit = rate_limit.check_account_login_allowed(ACCOUNT)
    assert at_limit["allowed"] is True, "the 20th attempt should still be admitted"
    assert at_limit["count"] == rate_limit.ACCOUNT_FAILURE_THRESHOLD
    over = rate_limit.check_account_login_allowed(ACCOUNT)
    assert over["allowed"] is False, "the victim got a fresh budget after capacity pressure"


def test_410_no_token_is_issued_when_capacity_blocks_a_safe_admission(memory, monkeypatch):
    """
    Admitting an account whose failures cannot be recorded would grant it an unlimited budget,
    so the admission must fail closed: no token, no counter.
    """
    limiter, _clock = memory
    monkeypatch.setattr(rate_limit, "_MAX_TRACKED_IDENTITIES", 8)
    _fill_to_capacity("phase44-full", 8)
    assert len(limiter._store._counters) >= 8

    blocked = rate_limit.check_account_login_allowed("phase44-brand-new-identity", limit=1000)
    assert blocked["allowed"] is False, (
        "a brand-new identity was admitted while the store was at capacity; its failures could "
        "not be recorded, so it was handed an unlimited budget"
    )
    assert blocked["token"] is None, "a capacity-blocked admission was issued a refund token"
    assert rate_limit.get_account_failure_count("phase44-brand-new-identity") == 0


def test_411_expired_entries_are_reclaimed_so_capacity_becomes_usable(memory, monkeypatch):
    """Capacity refusal must be temporary: once the filler windows pass, new identities fit."""
    limiter, clock = memory
    monkeypatch.setattr(rate_limit, "_MAX_TRACKED_IDENTITIES", 6)
    window = 10
    for i in range(6):
        rate_limit.check_account_login_allowed(f"phase44-exp-{i}", limit=1000, window_seconds=window)

    blocked = rate_limit.check_account_login_allowed("phase44-late", limit=1000, window_seconds=window)
    assert blocked["allowed"] is False

    clock.advance(window + 1)
    after = rate_limit.check_account_login_allowed("phase44-late", limit=1000, window_seconds=window)
    assert after["allowed"] is True, "capacity was not recovered after the filler windows expired"
    assert after["token"] is not None
    assert len(limiter._store._counters) <= 6, "expired entries were not reclaimed"


def test_412_concurrent_capacity_pressure_cannot_erase_active_counters(memory, monkeypatch):
    """The threaded version: active budgets must survive a race to fill the store."""
    limiter, _clock = memory
    monkeypatch.setattr(rate_limit, "_MAX_TRACKED_IDENTITIES", 16)

    for _ in range(rate_limit.ACCOUNT_FAILURE_THRESHOLD - 1):
        rate_limit.check_account_login_allowed(ACCOUNT, limit=1000)
    expected = rate_limit.get_account_failure_count(ACCOUNT)

    barrier = threading.Barrier(8)
    errors = []

    def hammer(offset):
        try:
            barrier.wait()
            for i in range(40):
                rate_limit.check_account_login_allowed(f"phase44-c-{offset}-{i}", limit=1000)
        except Exception as exc:  # pragma: no cover - surfaced through the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=hammer, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"capacity pressure raised: {errors[:3]}"
    assert rate_limit.get_account_failure_count(ACCOUNT) == expected, (
        "concurrent capacity pressure erased the active counter"
    )


def test_413_existing_account_limits_remain_enforced_after_pressure(memory, monkeypatch):
    """A throttled account must stay throttled once capacity pressure has been applied."""
    limiter, _clock = memory
    monkeypatch.setattr(rate_limit, "_MAX_TRACKED_IDENTITIES", 12)

    # Exhaust at the PRODUCTION limit so "blocked" means blocked at 20, not at 1000.
    for _ in range(rate_limit.ACCOUNT_FAILURE_THRESHOLD):
        rate_limit.check_account_login_allowed(OTHER_ACCOUNT)
    assert rate_limit.check_account_login_allowed(OTHER_ACCOUNT)["allowed"] is False

    _fill_to_capacity("phase44-pres", 12)

    # Production limit here, not the raised fill limit (see test_409).
    still_blocked = rate_limit.check_account_login_allowed(OTHER_ACCOUNT)
    assert still_blocked["allowed"] is False, (
        "a throttled account was un-throttled by capacity pressure"
    )


def test_414_a_capacity_refusal_touches_no_other_counter(memory, monkeypatch):
    """A refusal must not mint a token, decrement, or reset anyone's budget."""
    limiter, _clock = memory
    monkeypatch.setattr(rate_limit, "_MAX_TRACKED_IDENTITIES", 6)

    for _ in range(3):
        rate_limit.check_account_login_allowed(ACCOUNT, limit=1000)
    before = rate_limit.get_account_failure_count(ACCOUNT)
    _fill_to_capacity("phase44-noop", 6)

    keys_before = set(limiter._store._counters.keys())
    blocked = rate_limit.check_account_login_allowed("phase44-newcomer", limit=1000)
    keys_after = set(limiter._store._counters.keys())

    assert blocked["allowed"] is False
    assert rate_limit.get_account_failure_count(ACCOUNT) == before, (
        "the refused admission changed another account's counter"
    )
    assert keys_after == keys_before, (
        f"a refused admission mutated the store: added={keys_after - keys_before}"
    )


def test_415_the_victim_survives_at_any_insertion_order(memory, monkeypatch):
    """
    Eviction by insertion order was the mechanism, so a live budget must be safe whatever order
    the victim was inserted in.

    The two situations are genuinely different and are asserted separately:

      * victim inserted BEFORE the store fills: it holds a live counter, so nothing may remove
        it and its budget must be intact;
      * victim inserted AFTER the store is full: there is no room, so admitting it would mean
        granting an untracked budget. It must be *refused* (fail closed), not given a fresh
        counter — and certainly not allowed to displace a live one.

    An earlier version of this test asserted "budget intact" for all three orders, which is
    wrong for the third: an identity that never had a counter has no budget to preserve, and the
    correct behaviour there is refusal.
    """
    # --- inserted first, then the store fills ---
    fresh = rate_limit.RateLimiter(redis_url="", clock=Clock())
    rate_limit.set_limiter(fresh)
    monkeypatch.setattr(rate_limit, "_MAX_TRACKED_IDENTITIES", 10)
    for _ in range(2):
        rate_limit.check_account_login_allowed(ACCOUNT, limit=1000)
    _fill_to_capacity("phase44-first", 10)
    assert rate_limit.get_account_failure_count(ACCOUNT) == 2, (
        "the victim's budget was erased when it was inserted first"
    )

    # --- inserted in the middle ---
    fresh = rate_limit.RateLimiter(redis_url="", clock=Clock())
    rate_limit.set_limiter(fresh)
    monkeypatch.setattr(rate_limit, "_MAX_TRACKED_IDENTITIES", 10)
    for i in range(4):
        rate_limit.check_account_login_allowed(f"phase44-mid-pre-{i}", limit=1000)
    for _ in range(2):
        rate_limit.check_account_login_allowed(ACCOUNT, limit=1000)
    _fill_to_capacity("phase44-mid", 10)
    assert rate_limit.get_account_failure_count(ACCOUNT) == 2, (
        "the victim's budget was erased when it was inserted in the middle"
    )

    # --- inserted last, into a store that is already full: must be REFUSED ---
    fresh = rate_limit.RateLimiter(redis_url="", clock=Clock())
    rate_limit.set_limiter(fresh)
    monkeypatch.setattr(rate_limit, "_MAX_TRACKED_IDENTITIES", 10)
    admitted, _refused = _fill_to_capacity("phase44-last", 8)
    assert admitted == 10, f"harness: expected the store to fill to 10, filled to {admitted}"
    victim_key = rate_limit.account_store_key(ACCOUNT)
    assert victim_key not in fresh._store._counters

    late = rate_limit.check_account_login_allowed(ACCOUNT, limit=1000)
    assert late["allowed"] is False, (
        "an identity was admitted into a full store; its failures could not be recorded, so it "
        "received an unlimited budget"
    )
    assert late["token"] is None
    assert victim_key not in fresh._store._counters, (
        "the refused admission created a counter anyway"
    )
    assert rate_limit.get_account_failure_count(ACCOUNT) == 0
    assert len(fresh._store._counters) == 10, "the refused admission displaced a live counter"


def test_416_expired_entries_only_are_reclaimed_never_live_ones(memory, monkeypatch):
    """Structural check: reclamation removes expired entries and leaves live ones alone."""
    limiter, clock = memory
    monkeypatch.setattr(rate_limit, "_MAX_TRACKED_IDENTITIES", 4)
    for i in range(4):
        rate_limit.check_account_login_allowed(f"phase44-live-{i}", limit=1000, window_seconds=100)
    live_keys = set(limiter._store._counters.keys())
    assert len(live_keys) == 4

    # Reclamation with nothing expired must not drop anything.
    limiter._store._reclaim_expired(clock.now)
    assert set(limiter._store._counters.keys()) == live_keys, (
        "reclamation removed a live counter"
    )
    # And the capacity gate must refuse rather than make room by dropping a live one.
    assert limiter._store._make_room(clock.now) is False, (
        "the store reported room while full of live counters"
    )
    assert set(limiter._store._counters.keys()) == live_keys, (
        "the capacity gate evicted a live counter"
    )

    clock.advance(101)
    assert limiter._store._make_room(clock.now) is True, (
        "capacity was not recovered once the windows had expired"
    )
    assert not limiter._store._counters, "expired entries were not reclaimed"


def test_417_redis_is_unaffected_by_memory_capacity(memory, redis_limiter):
    """
    The capacity policy is a memory-store fallback concern only; Redis must keep admitting new
    identities regardless of how full the process-local dict is.
    """
    memory_limiter, _clock = memory
    rate_limit.set_limiter(memory_limiter)
    redis_store, client = redis_limiter
    rate_limit.set_limiter(redis_store)

    for i in range(20):
        hit = rate_limit.check_account_login_allowed(f"phase44-redis-{i}", limit=1000)
        assert hit["allowed"] is True and hit["token"] is not None
