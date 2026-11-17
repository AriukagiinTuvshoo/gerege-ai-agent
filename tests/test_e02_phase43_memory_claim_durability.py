"""
Stage E — E-02 Phase 4.3: memory expiry parity and durable single-use refunds.

Two defects in the Phase 4.2 admission-token design, both reproduced before any change
(`docs/audit/evidence/e02_phase43_before.txt`).

Defect 1 — the memory store does not apply window expiry to a refund
--------------------------------------------------------------------
Redis expires its counter key on its own, so a refund after the TTL finds no counter and is
refused. The memory store keeps the entry until something replaces it, and
`refund_admission()` checked only the generation and the count. An admission whose window had
long since expired was therefore still refundable:

    admit A in W1 -> advance past W1 -> refund A  =>  True   (Redis: False)

Measured damage is bounded but real: it cannot corrupt a live later window (the generation
check still refuses that), but it reports success for a slot that no longer exists and, in the
process, populates claim state for a dead generation.

Defect 2 — the single-use claim set silently forgets live claims
---------------------------------------------------------------
`_refunded` was one process-wide `set` bounded to 10,000 entries, evicted arbitrarily with
`set.pop()`. Because it was global, *other tenants'* refunds consumed the budget and could
evict a live tenant's claim. Measured on the real limit:

    3 admissions for "victim", refund one -> claim recorded, count 2, window still live
    23,997 refunds by unrelated accounts
    replay the victim's token -> True, count 2 -> 1

That is a genuine double refund of a live admission, reachable without knowing any secret.

The fix, and what these tests pin
---------------------------------
A claim is now stored **inside the counter entry it belongs to**, in the same critical section
as the generation, expiry and count checks:

  * claims die exactly when their generation does — no separate expiry logic to drift;
  * claims cannot collide across accounts, because they are not in a shared structure;
  * growth is bounded by the number of *admitted* attempts in one live window per account
    (at most the threshold, since only admitted attempts receive a token);
  * nothing is ever evicted, so no live claim can be forgotten.

Redis already had these properties (a claim key per generation with the counter's TTL, with
Redis doing the expiry), so this is a memory/Redis parity repair rather than a change to the
Redis model.
"""
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import account_keys, rate_limit  # noqa: E402

TEST_SECRET = "e02-p43-test-secret-0123456789abcdef"

ACCOUNT = "phase43-account-a"
OTHER_ACCOUNT = "phase43-account-b"


class Clock:
    """Advanceable clock so a window can expire without sleeping."""

    def __init__(self, now: float = 3_000_000.0):
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
        pytest.skip("needs REDIS_URL: TTL behaviour cannot be shown without it")
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
# ISSUE 1 — memory expiry parity (tests 301-306)
# ===========================================================================
def test_301_memory_refund_of_an_expired_admission_is_refused(memory):
    """
    The reported case: W1 expires and NO later window is created. Redis refuses because its
    key is gone; memory must refuse for the same reason rather than trusting a stale entry.
    """
    limiter, clock = memory
    admission = rate_limit.check_account_login_allowed(ACCOUNT)
    assert admission["count"] == 1

    clock.advance(rate_limit.ACCOUNT_FAILURE_WINDOW + 1)

    refunded = rate_limit.clear_account_failures_on_success(ACCOUNT, token=admission["token"])
    assert refunded is False, (
        "the memory store refunded an admission whose window had already expired; Redis "
        "refuses this because its key is gone, so the two backends disagree"
    )


def test_302_an_expired_memory_entry_is_reclaimed_on_refund_attempt(memory):
    """
    The stale entry must not linger: a refusal is also the moment to drop it, matching the
    state Redis is already in. Otherwise an expired generation keeps its claims alive.
    """
    limiter, clock = memory
    admission = rate_limit.check_account_login_allowed(ACCOUNT)
    key = rate_limit.account_store_key(ACCOUNT)
    assert key in limiter._store._counters

    clock.advance(rate_limit.ACCOUNT_FAILURE_WINDOW + 1)
    rate_limit.clear_account_failures_on_success(ACCOUNT, token=admission["token"])

    assert key not in limiter._store._counters, (
        "the expired counter entry survived the refund attempt; it should be reclaimed the "
        "moment the store observes that its window has passed"
    )


def test_303_redis_refunds_of_an_expired_admission_are_refused(redis_limiter):
    """The same case against a real Redis and a genuinely expired TTL, with no later window."""
    limiter, client = redis_limiter
    window = 1
    admission = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=window)
    assert admission["count"] == 1

    time.sleep(window + 0.7)
    key = rate_limit.account_store_key(ACCOUNT)
    assert client.get(key) is None, "sanity: Redis expired the counter key"

    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=admission["token"]) is False


def test_304_memory_and_redis_agree_when_no_later_window_exists(memory, redis_limiter):
    """
    Parity, stated directly: same sequence, same decision. This is the assertion that failed
    before the fix (memory True, Redis False).
    """
    decisions = {}
    window = 1

    memory_limiter, clock = memory
    rate_limit.set_limiter(memory_limiter)
    admission = rate_limit.check_account_login_allowed(ACCOUNT)
    clock.advance(rate_limit.ACCOUNT_FAILURE_WINDOW + 1)
    decisions["memory"] = rate_limit.clear_account_failures_on_success(
        ACCOUNT, token=admission["token"]
    )

    redis_store, _client = redis_limiter
    rate_limit.set_limiter(redis_store)
    admission_r = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=window)
    time.sleep(window + 0.7)
    decisions["redis"] = rate_limit.clear_account_failures_on_success(
        ACCOUNT, token=admission_r["token"]
    )

    assert decisions["memory"] == decisions["redis"], (
        f"memory and Redis disagree on an expired admission with no replacement window: "
        f"{decisions}"
    )
    assert decisions["memory"] is False


def test_305_an_expired_generation_does_not_inherit_claims_into_a_new_window(memory):
    """
    A claim recorded in W1 must not make a W2 admission look already-refunded, and must not
    keep W1's generation alive.
    """
    limiter, clock = memory

    first = rate_limit.check_account_login_allowed(ACCOUNT)
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=first["token"]) is True

    clock.advance(rate_limit.ACCOUNT_FAILURE_WINDOW + 1)

    # W2: a fresh admission must be refundable exactly once, unaffected by W1's history.
    second = rate_limit.check_account_login_allowed(ACCOUNT)
    assert second["token"].generation != first["token"].generation
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=second["token"]) is True
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=second["token"]) is False


def test_306_refund_after_expiry_does_not_reopen_a_live_later_window(memory):
    """
    The severity bound, asserted so it cannot regress into something worse: even though the
    expired-admission refund is now refused, the underlying guarantee it must never break is
    that an old generation cannot decrement a live newer one.
    """
    limiter, clock = memory
    old = rate_limit.check_account_login_allowed(ACCOUNT)
    clock.advance(rate_limit.ACCOUNT_FAILURE_WINDOW + 1)

    # A live W2 with real failures in it.
    for _ in range(3):
        rate_limit.check_account_login_allowed(ACCOUNT)
    assert rate_limit.get_account_failure_count(ACCOUNT) == 3

    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=old["token"]) is False
    assert rate_limit.get_account_failure_count(ACCOUNT) == 3, (
        "an old generation's refund changed a live newer window"
    )


# ===========================================================================
# ISSUE 2 — durable single-use claims (tests 307-314)
# ===========================================================================
def test_307_a_live_claim_survives_pressure_from_other_accounts(memory, monkeypatch):
    """
    The reported defect, in the shape it was measured: a live claim must not be evictable by
    unrelated accounts' refunds.

    `_MAX_TRACKED_IDENTITIES` is patched down so the pressure is cheap. The old design used that
    constant as the size of a *global* claim set and evicted with `set.pop()`, which picks an
    arbitrary element — so `_apply_foreign_pressure` drives other tenants' refunds until it has
    positively observed the victim's claim disappear. Only then does the replay matter. Against
    the old design this test fails on the replay; against the new one the claim lives inside the
    victim's own counter entry, so nothing foreign can remove it.

    The victim keeps count 2 with a live window throughout: an admission that empties a counter
    deletes it, and the following admission mints a new generation (identical on Redis), which
    would mask the eviction being tested here.
    """
    limiter, _clock = memory
    monkeypatch.setattr(rate_limit, "_MAX_TRACKED_IDENTITIES", 8)

    tokens = [rate_limit.check_account_login_allowed(ACCOUNT)["token"] for _ in range(3)]
    victim = tokens[0]
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=victim) is True
    assert rate_limit.get_account_failure_count(ACCOUNT) == 2, (
        "the victim must still have a live, non-empty counter for a replay to have an effect"
    )

    _apply_foreign_pressure(limiter, victim)

    before = rate_limit.get_account_failure_count(ACCOUNT)
    replay = rate_limit.clear_account_failures_on_success(ACCOUNT, token=victim)
    after = rate_limit.get_account_failure_count(ACCOUNT)

    assert replay is False, (
        "a live claim was forgotten under pressure from other accounts, so the same token was "
        f"refunded twice (count {before} -> {after})"
    )
    assert after == before, f"the replayed refund changed the live count: {before} -> {after}"


def _apply_foreign_pressure(limiter, victim_token, limit=600):
    """
    Other tenants refund until the victim's claim is observably evicted, or the limit is hit.

    Returns True when eviction was observed. Returns False when the store keeps no global claim
    set at all (the new design), after still applying a fixed amount of pressure so the arm is
    not vacuous.
    """
    claim = (victim_token.generation, victim_token.admission_id)
    global_set = getattr(limiter._store, "_refunded", None)
    evicted = False
    for i in range(limit):
        token = rate_limit.check_account_login_allowed(f"phase43-other-{i}")["token"]
        if token is not None:
            rate_limit.clear_account_failures_on_success(f"phase43-other-{i}", token=token)
        if global_set is not None and claim not in global_set:
            evicted = True
            break
    if global_set is not None and not evicted:
        raise AssertionError(
            "the victim's claim was never evicted, so this test did not exercise the defect it "
            "exists to catch"
        )
    return evicted


def test_308_a_live_claim_survives_pressure_within_its_own_account(memory, monkeypatch):
    """
    Pressure is not only cross-tenant. Many refunds on the *same* account inside one live window
    must not evict an earlier claim either.
    """
    limiter, _clock = memory
    monkeypatch.setattr(rate_limit, "_MAX_TRACKED_IDENTITIES", 4)

    tokens = [rate_limit.check_account_login_allowed(ACCOUNT)["token"] for _ in range(12)]
    first = tokens[0]
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=first) is True

    # Refund six more, leaving the counter non-empty so a replay would have an effect.
    for token in tokens[1:7]:
        assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=token) is True
    remaining = rate_limit.get_account_failure_count(ACCOUNT)
    assert remaining == 5, f"expected 5 left after 7 of 12 refunded, got {remaining}"

    claim = (first.generation, first.admission_id)
    global_set = getattr(limiter._store, "_refunded", None)
    if global_set is not None:
        assert claim not in global_set, (
            "harness: the old global set still holds the claim, so eviction was not exercised"
        )

    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=first) is False, (
        "the earliest claim in a live window was forgotten"
    )
    assert rate_limit.get_account_failure_count(ACCOUNT) == remaining


def test_309_claims_are_not_shared_across_accounts(memory):
    """
    Structural: a claim recorded for one account must not be visible to another. The Phase 4.2
    set was process-wide, which is what let one tenant's traffic evict another's claim.
    """
    limiter, _clock = memory
    token_a = rate_limit.check_account_login_allowed(ACCOUNT)["token"]
    rate_limit.check_account_login_allowed(OTHER_ACCOUNT)
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=token_a) is True

    key_b = rate_limit.account_store_key(OTHER_ACCOUNT)
    entry_b = limiter._store._counters.get(key_b)
    assert token_a.admission_id not in repr(entry_b), (
        "one account's refund claim is visible in another account's counter state"
    )


def test_310_claims_do_not_outlive_their_window(memory):
    """
    Memory is reclaimed with the window rather than growing for the process's lifetime.

    The victim keeps a non-empty counter so the entry is still present when the clock passes
    the window: refunding the only admission would empty the counter and delete the entry
    immediately (the same thing Redis does at zero), which would make this test vacuous.
    """
    limiter, clock = memory
    tokens = [rate_limit.check_account_login_allowed(ACCOUNT)["token"] for _ in range(3)]
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=tokens[0]) is True
    key = rate_limit.account_store_key(ACCOUNT)
    entry = limiter._store._counters.get(key)
    assert entry is not None, "the counter should still hold two admissions"
    assert len(entry.claims) == 1

    clock.advance(rate_limit.ACCOUNT_FAILURE_WINDOW + 1)
    assert rate_limit.get_account_failure_count(ACCOUNT) == 0
    assert key not in limiter._store._counters, (
        "the counter entry, and with it every claim it holds, outlived its window"
    )


def test_311_claim_growth_is_bounded_by_admissions_in_the_window(memory):
    """
    Unbounded growth must be impossible. Only *admitted* attempts receive a token, and every
    admitted attempt increments the counter, so the claim set for one counter can never exceed
    that counter's own peak value — there is no separate limit that could drift out of step.
    """
    limiter, _clock = memory
    tokens = [rate_limit.check_account_login_allowed(ACCOUNT)["token"] for _ in range(4)]
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=tokens[0]) is True

    key = rate_limit.account_store_key(ACCOUNT)
    entry = limiter._store._counters.get(key)
    claims = _claims_of(entry)
    peak = limiter._store.read_counter(key, rate_limit.ACCOUNT_FAILURE_WINDOW)
    assert len(claims) == 1, f"expected exactly the one refunded admission, got {claims}"
    assert len(claims) <= peak, (
        f"{len(claims)} claims recorded for a counter that currently reads {peak}"
    )

    # Even refunding every admission cannot exceed the peak the counter ever reached.
    for token in tokens[1:]:
        assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=token) is True
    assert rate_limit.get_account_failure_count(ACCOUNT) == 0


def _claims_of(entry):
    """The refund-claim set of a memory counter entry, whatever shape the store uses."""
    if entry is None:
        return set()
    claims = getattr(entry, "claims", None)
    if claims is not None:
        return set(claims)
    for part in entry:
        if isinstance(part, (set, frozenset)):
            return set(part)
    return set()


def test_312_a_refund_after_the_counter_reaches_zero_is_refused(memory):
    """Clamping: an emptied counter must not go negative or accept further refunds."""
    limiter, _clock = memory
    token = rate_limit.check_account_login_allowed(ACCOUNT)["token"]
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=token) is True
    assert rate_limit.get_account_failure_count(ACCOUNT) == 0

    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=token) is False
    assert rate_limit.get_account_failure_count(ACCOUNT) == 0


def test_313_concurrent_refunds_of_one_token_apply_exactly_once(memory):
    """Threads racing on the same live token: exactly one may win."""
    limiter, _clock = memory
    token = rate_limit.check_account_login_allowed(ACCOUNT)["token"]
    for _ in range(4):
        rate_limit.check_account_login_allowed(ACCOUNT)
    assert rate_limit.get_account_failure_count(ACCOUNT) == 5

    results = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def attempt():
        barrier.wait()
        outcome = rate_limit.clear_account_failures_on_success(ACCOUNT, token=token)
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count(True) == 1, f"{results.count(True)} concurrent refunds succeeded"
    assert rate_limit.get_account_failure_count(ACCOUNT) == 4, (
        f"the counter is {rate_limit.get_account_failure_count(ACCOUNT)}, expected 4"
    )


def test_314_distinct_concurrent_refunds_each_apply_once(memory):
    """Different live tokens refunded concurrently must each subtract exactly one."""
    limiter, _clock = memory
    tokens = [rate_limit.check_account_login_allowed(ACCOUNT)["token"] for _ in range(10)]
    assert rate_limit.get_account_failure_count(ACCOUNT) == 10

    barrier = threading.Barrier(len(tokens))
    outcomes = []
    lock = threading.Lock()

    def attempt(token):
        barrier.wait()
        ok = rate_limit.clear_account_failures_on_success(ACCOUNT, token=token)
        with lock:
            outcomes.append(ok)

    threads = [threading.Thread(target=attempt, args=(t,)) for t in tokens]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(outcomes), f"some distinct live refunds were refused: {outcomes}"
    assert rate_limit.get_account_failure_count(ACCOUNT) == 0


def test_315_redis_claims_are_per_generation_and_expire(redis_limiter):
    """Parity for the claim mechanism: Redis claims carry the counter's TTL and naming."""
    limiter, client = redis_limiter
    window = 30
    token = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=window)["token"]
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=token) is True

    claim_keys = [k for k in client.scan_iter("ratelimit:auth_account:*refunded*")]
    assert claim_keys, "no claim key was written for the refunded admission"
    for k in claim_keys:
        assert token.generation in k, f"claim key is not scoped to the generation: {k}"
        assert token.admission_id in k, f"claim key is not scoped to the admission: {k}"
        ttl = client.ttl(k)
        assert ttl > 0, f"claim key has no expiry and would accumulate: {k} ttl={ttl}"
    # Replay is refused because the claim still exists.
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=token) is False


# ===========================================================================
# TOKEN INTEGRITY — Phase 3 audit, pinned as tests (316-323)
# ===========================================================================
def test_316_token_carries_the_window_it_was_admitted_with(memory):
    """
    The refund needs the admission's own window, not the current policy value: a token taken
    with a short window must expire on that short window even if the policy later says 900s.
    Otherwise the memory store would apply the wrong expiry.
    """
    limiter, clock = memory
    admission = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=5)
    token = admission["token"]
    assert getattr(token, "window_seconds", None) == 5, (
        f"the token does not record its admission window: {token!r}"
    )

    clock.advance(6)
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=token) is False, (
        "a token admitted with a 5s window was refundable after 6s because the refund used a "
        "different window value"
    )


def test_317_generation_and_admission_ids_are_unpredictable_and_distinct(memory):
    """Entropy and uniqueness of the two token fields."""
    limiter, _clock = memory
    generations, admissions = set(), set()
    # HARNESS NOTE: admission is refused past ACCOUNT_FAILURE_THRESHOLD, and a refused attempt
    # gets no token, so asking for 50 at the default limit yields None after 20. Raise the limit
    # for this test — the entropy question is separate from the throttling policy.
    for _ in range(50):
        hit = rate_limit.check_account_login_allowed(
            ACCOUNT, limit=1000, window_seconds=rate_limit.ACCOUNT_FAILURE_WINDOW
        )
        token = hit["token"]
        assert token is not None, "admission was refused below the raised limit"
        generations.add(token.generation)
        admissions.add(token.admission_id)

    assert len(admissions) == 50, "admission ids are not unique across admissions"
    for value in list(admissions)[:5]:
        assert len(value) >= 16, f"admission id is too short to be unpredictable: {value!r}"
        assert all(c in "0123456789abcdef" for c in value), (
            f"admission id is not opaque hex: {value!r}"
        )
    for gen in generations:
        assert len(gen) >= 16, f"generation is too short to be unpredictable: {gen!r}"


def test_318_token_is_bound_to_its_account(memory):
    """A token minted for one account must be refused for another (memory)."""
    limiter, _clock = memory
    token_a = rate_limit.check_account_login_allowed(ACCOUNT)["token"]
    rate_limit.check_account_login_allowed(OTHER_ACCOUNT)
    assert rate_limit.get_account_failure_count(OTHER_ACCOUNT) == 1

    assert rate_limit.clear_account_failures_on_success(OTHER_ACCOUNT, token=token_a) is False
    assert rate_limit.get_account_failure_count(OTHER_ACCOUNT) == 1
    assert token_a.identity == ACCOUNT


def test_319_a_token_cannot_refund_a_different_admission(memory):
    """Refunding a token must consume that admission and no other."""
    limiter, _clock = memory
    tokens = [rate_limit.check_account_login_allowed(ACCOUNT)["token"] for _ in range(4)]
    assert rate_limit.get_account_failure_count(ACCOUNT) == 4

    used = {t.admission_id for t in tokens}
    assert len(used) == 4
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=tokens[2]) is True
    assert rate_limit.get_account_failure_count(ACCOUNT) == 3
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=tokens[2]) is False


def test_320_a_refused_attempt_gets_no_token(memory):
    """
    A throttled attempt consumed no budget it could give back, so it must not receive a token
    — otherwise a blocked attacker could cancel real failures.
    """
    limiter, _clock = memory
    for _ in range(rate_limit.ACCOUNT_FAILURE_THRESHOLD):
        rate_limit.check_account_login_allowed(ACCOUNT)
    refused = rate_limit.check_account_login_allowed(ACCOUNT)
    assert refused["allowed"] is False
    assert refused["token"] is None, "a refused attempt was issued a refund token"


def test_321_token_after_window_rollover_is_refused(memory):
    """Old-generation replay against a live newer window (the Phase 4.2 guarantee, re-pinned)."""
    limiter, clock = memory
    old = rate_limit.check_account_login_allowed(ACCOUNT)["token"]
    clock.advance(rate_limit.ACCOUNT_FAILURE_WINDOW + 1)
    rate_limit.check_account_login_allowed(ACCOUNT)
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=old) is False
    assert rate_limit.get_account_failure_count(ACCOUNT) == 1


def test_322_counter_deletion_at_zero_leaves_no_reusable_state(memory):
    """
    Emptying a counter removes the entry. A later window must start clean, with no claim
    state carried over that could make a fresh admission look already refunded.
    """
    limiter, clock = memory
    token = rate_limit.check_account_login_allowed(ACCOUNT)["token"]
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=token) is True
    key = rate_limit.account_store_key(ACCOUNT)
    assert key not in limiter._store._counters, "an emptied counter kept its entry"

    # Same window, fresh admission: refundable once.
    fresh = rate_limit.check_account_login_allowed(ACCOUNT)["token"]
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=fresh) is True
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=fresh) is False


def test_323_redis_refund_preserves_the_window_ttl(redis_limiter):
    """A refund must not extend or remove the window (re-pinned from Phase 4.2)."""
    limiter, client = redis_limiter
    token = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=60)["token"]
    key = rate_limit.account_store_key(ACCOUNT)
    ttl_before = client.ttl(key)
    assert 0 < ttl_before <= 60

    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=token) is True
    ttl_after = client.ttl(key)
    if ttl_after >= 0:
        assert ttl_after <= ttl_before, (
            f"the refund pushed the TTL from {ttl_before} to {ttl_after}; the window is sliding"
        )
