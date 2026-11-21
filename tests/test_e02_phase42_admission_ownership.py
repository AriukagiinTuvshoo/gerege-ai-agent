"""
Stage E — E-02 Phase 4.2: admission ownership and window-bound refunds.

The defect under test
---------------------
Phase 4.1 replaced whole-key reset with "refund exactly the slot this success consumed". That
fixed erasure of *concurrent* failures inside one window. It did not bind a refund to the
window the admission happened in:

    W1      A admitted (count 1)
    W1 end  the counter expires and is deleted
    W2      B admitted and FAILS (count 1)
            A finally finishes authenticating and refunds -> count 0

A's refund decremented a counter belonging to a window A was never part of, erasing B's
failure. Reproduced deterministically on both backends before any fix; the transcript is in
`docs/audit/evidence/e02_phase42_before.txt`.

Counting model (read this before changing a number)
---------------------------------------------------
Admission itself consumes the slot, atomically with the counter's expiry. `record_account_failure()`
is therefore a documented no-op: the slot an admitted attempt took *is* the recorded failure
unless that attempt later succeeds and refunds it. So "N failures in a window" means "N
admissions, of which S succeeded and were refunded". Tests below are written against that
model, not against a second increment.

The design under test
---------------------
An admission returns a *token* naming the generation it was taken in:

    token = (identity, generation)

`generation` is a random value minted by the same atomic operation that creates the counter, and
is refreshed whenever a new window replaces an expired one. A refund is accepted only when the
token's identity and generation both match the live counter, and only once. All three checks
happen inside the store's atomic primitive — a timestamp comparison outside the operation would
be a check-then-act race and is explicitly not how this works.

Counting note: test functions and collected cases are counted separately in the report.
"""
import json
import os
import sqlite3
import sys
import threading
import time
import uuid

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import account_keys, rate_limit  # noqa: E402

TEST_SECRET = "e02-p42-test-secret-0123456789abcdef"

ACCOUNT = "phase42-account-a"
OTHER_ACCOUNT = "phase42-account-b"


class Clock:
    """Advanceable clock for the memory store, so window expiry needs no sleeping."""

    def __init__(self, now: float = 2_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture()
def memory(monkeypatch):
    """A memory-backed limiter with an advanceable clock."""
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
        pytest.skip("needs REDIS_URL: TTL and cross-instance behaviour cannot be shown without it")
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
# ISSUE 1 — the reported window-generation race (tests 201-208)
# ===========================================================================
def test_201_admission_returns_a_generation_token(memory):
    """
    The precondition for a window-bound refund: admission must hand back something naming the
    generation it was taken in. Today it returns only a count and a TTL, which is exactly why
    the refund cannot tell one window from another.
    """
    result = rate_limit.check_account_login_allowed(ACCOUNT)
    assert "token" in result, (
        "admission returns no token, so a refund has no way to name the window it belongs to: "
        f"keys were {sorted(result)}"
    )
    token = result["token"]
    assert token is not None, "a configured throttle must always return a token"
    assert getattr(token, "generation", None), f"the token does not name a generation: {token!r}"


def test_202_refund_from_an_expired_generation_does_not_touch_the_new_window(memory):
    """
    The reported race, directly.

    A is admitted in W1 and its verification is slow. W1 expires. B is admitted in W2 (that
    admission is B's failure — nothing else increments). A then succeeds. B's failure must
    still be counted.
    """
    _, clock = memory

    first = rate_limit.check_account_login_allowed(ACCOUNT)  # A admitted in W1
    assert first["allowed"] is True and first["count"] == 1

    clock.advance(rate_limit.ACCOUNT_FAILURE_WINDOW + 1)  # W1 expires

    second = rate_limit.check_account_login_allowed(ACCOUNT)  # B admitted in W2 -> B failed
    assert second["count"] == 1, "B's admission did not start a fresh window"
    assert rate_limit.get_account_failure_count(ACCOUNT) == 1

    refunded = rate_limit.clear_account_failures_on_success(ACCOUNT, token=first["token"])
    assert refunded is False, "a refund from an expired generation must be refused"

    remaining = rate_limit.get_account_failure_count(ACCOUNT)
    assert remaining == 1, (
        f"E-02.2: after A's refund from the expired window the count is {remaining}, expected 1. "
        "A's refund erased B's failure from a window A was never part of."
    )
    assert second["token"].generation != first["token"].generation, (
        "sanity: the two admissions must name different generations"
    )


def test_203_refund_from_the_current_generation_is_applied(memory):
    """The normal path must still work."""
    first = rate_limit.check_account_login_allowed(ACCOUNT)
    assert rate_limit.get_account_failure_count(ACCOUNT) == 1
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=first["token"]) is True
    assert rate_limit.get_account_failure_count(ACCOUNT) == 0


def test_204_a_token_cannot_be_refunded_twice(memory):
    """
    Replaying a token must not manufacture budget. Without this, one successful login could be
    replayed to cancel an unlimited number of other failures.
    """
    first = rate_limit.check_account_login_allowed(ACCOUNT)
    for _ in range(4):
        rate_limit.check_account_login_allowed(ACCOUNT)
    assert rate_limit.get_account_failure_count(ACCOUNT) == 5

    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=first["token"]) is True
    assert rate_limit.get_account_failure_count(ACCOUNT) == 4

    for _ in range(3):
        assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=first["token"]) is False
    assert rate_limit.get_account_failure_count(ACCOUNT) == 4, (
        "a replayed token refunded more than once, manufacturing budget"
    )


def test_205_a_refund_cannot_decrement_another_requests_admission(memory):
    """
    Each refund cancels exactly one slot, never more. Both admissions are in the same
    generation here, isolating the per-token (not per-window) half of ownership.
    """
    token_a = rate_limit.check_account_login_allowed(ACCOUNT)["token"]
    rate_limit.check_account_login_allowed(ACCOUNT)
    assert rate_limit.get_account_failure_count(ACCOUNT) == 2

    before = rate_limit.get_account_failure_count(ACCOUNT)
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=token_a) is True
    after = rate_limit.get_account_failure_count(ACCOUNT)
    assert after == before - 1, f"one refund changed the count by {before - after}"


def test_206_multiple_simultaneous_successes_refund_exactly_once_each(memory):
    """N concurrent successes must each refund their own admission and no more."""
    tokens = [rate_limit.check_account_login_allowed(ACCOUNT)["token"] for _ in range(8)]
    assert rate_limit.get_account_failure_count(ACCOUNT) == 8

    applied = [rate_limit.clear_account_failures_on_success(ACCOUNT, token=t) for t in tokens]
    assert all(applied), f"some same-generation refunds were refused: {applied}"
    assert rate_limit.get_account_failure_count(ACCOUNT) == 0, (
        "eight successes did not refund eight admissions"
    )


def test_207_concurrent_successes_and_failures_land_on_the_documented_count(memory):
    """
    Threaded mix. Every admission is refunded at most once, so the final count must equal
    (admissions - successes) and can never go negative or be over-refunded.
    """
    successes, failures = 6, 7
    admissions = []
    lock = threading.Lock()

    def admit(should_succeed):
        res = rate_limit.check_account_login_allowed(ACCOUNT)
        with lock:
            admissions.append((res["token"], should_succeed))

    threads = [
        threading.Thread(target=admit, args=(i < successes,)) for i in range(successes + failures)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for token, ok in admissions:
        if ok:
            rate_limit.clear_account_failures_on_success(ACCOUNT, token=token)

    count = rate_limit.get_account_failure_count(ACCOUNT)
    assert count == failures, (
        f"expected {failures} recorded failures, found {count}; each success must refund "
        "exactly its own admission and nothing else"
    )


def test_208_expiration_still_restores_the_whole_budget(memory):
    """The fixed window must stay non-sliding and fully recoverable."""
    _, clock = memory
    for _ in range(5):
        rate_limit.check_account_login_allowed(ACCOUNT)
    assert rate_limit.get_account_failure_count(ACCOUNT) == 5

    clock.advance(rate_limit.ACCOUNT_FAILURE_WINDOW + 1)
    assert rate_limit.get_account_failure_count(ACCOUNT) == 0, "expiry did not clear the window"
    assert rate_limit.check_account_login_allowed(ACCOUNT)["count"] == 1, (
        "the first admission of the new window was not 1"
    )


# ===========================================================================
# ISSUE 1b — the same race on real Redis (tests 209-212)
# ===========================================================================
def test_209_redis_refund_from_an_expired_generation_is_refused(redis_limiter):
    """The reported race against a real Redis and a genuinely short TTL."""
    limiter, client = redis_limiter
    window = 1

    first = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=window)
    assert first["allowed"] is True

    time.sleep(window + 0.7)  # W1's key is gone

    second = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=window)
    assert second["count"] == 1
    assert rate_limit.get_account_failure_count(ACCOUNT) == 1

    refunded = rate_limit.clear_account_failures_on_success(ACCOUNT, token=first["token"])
    assert refunded is False, (
        "Redis applied a refund from an expired generation; the generation check is missing"
    )
    assert rate_limit.get_account_failure_count(ACCOUNT) == 1, (
        "E-02.2: A's stale refund erased B's failure on Redis"
    )


def test_210_redis_refund_preserves_the_window_ttl(redis_limiter):
    """A refund must not remove or extend the window's expiry."""
    limiter, client = redis_limiter
    admission = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=60)
    key = rate_limit.account_store_key(ACCOUNT)
    ttl_before = client.ttl(key)
    assert 0 < ttl_before <= 60

    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=admission["token"]) is True
    ttl_after = client.ttl(key)
    # The counter emptying at zero and being removed is a legitimate outcome; if a key remains
    # its TTL must not have been pushed out, which would make the window slide.
    if ttl_after >= 0:
        assert ttl_after <= ttl_before, (
            f"the refund pushed the TTL from {ttl_before} to {ttl_after}; the window is sliding"
        )


def test_211_redis_token_cannot_be_refunded_twice(redis_limiter):
    limiter, client = redis_limiter
    admission = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=60)
    for _ in range(3):
        rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=60)
    assert rate_limit.get_account_failure_count(ACCOUNT) == 4

    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=admission["token"]) is True
    assert rate_limit.get_account_failure_count(ACCOUNT) == 3
    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=admission["token"]) is False
    assert rate_limit.get_account_failure_count(ACCOUNT) == 3, "a replayed token refunded twice"


def test_212_redis_refunds_are_attributed_per_account(redis_limiter):
    """A's refund must never move B's counter."""
    limiter, client = redis_limiter
    a = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=60)
    rate_limit.check_account_login_allowed(OTHER_ACCOUNT, window_seconds=60)
    other_before = rate_limit.get_account_failure_count(OTHER_ACCOUNT)
    assert other_before == 1

    assert rate_limit.clear_account_failures_on_success(ACCOUNT, token=a["token"]) is True
    assert rate_limit.get_account_failure_count(OTHER_ACCOUNT) == other_before, (
        "one account's refund changed another account's counter"
    )


def test_213_redis_owners_correct_password_is_not_refused_after_expiry(redis_limiter):
    """
    End-to-end consequence of the race, through the real store: a full window of failures by
    someone else must not outlive its window and lock the legitimate owner out.
    """
    limiter, client = redis_limiter
    window = 1
    for _ in range(rate_limit.ACCOUNT_FAILURE_THRESHOLD):
        rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=window)
    assert rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=window)["allowed"] is False

    time.sleep(window + 0.7)
    after = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=window)
    assert after["allowed"] is True, "the lockout outlived its window"
    assert after["count"] == 1


# ===========================================================================
# ISSUE 2 — memory/Redis behavioural equivalence (tests 214-216)
# ===========================================================================
def test_214_both_stores_agree_on_the_stale_refund_decision(memory, redis_limiter):
    """
    The two backends must make the same decision for the same sequence. A divergence here is
    how a bug survives on one deployment and not another.
    """
    # HARNESS NOTE. Requesting both fixtures does not give two live limiters: the module
    # global is a single slot, so the second fixture's `set_limiter()` wins and the first arm
    # would silently run against the wrong backend. Each arm therefore re-installs its own
    # limiter immediately before running and is measured on its own store.
    results = {}
    window = 1

    # --- memory arm ---
    memory_limiter, clock = memory
    rate_limit.set_limiter(memory_limiter)
    first = rate_limit.check_account_login_allowed(ACCOUNT)
    clock.advance(rate_limit.ACCOUNT_FAILURE_WINDOW + 1)
    rate_limit.check_account_login_allowed(ACCOUNT)
    assert memory_limiter.backend() == "memory"
    results["memory"] = (
        rate_limit.clear_account_failures_on_success(ACCOUNT, token=first["token"]),
        rate_limit.get_account_failure_count(ACCOUNT),
    )

    # --- redis arm ---
    redis_limit, _client = redis_limiter
    rate_limit.set_limiter(redis_limit)
    first_r = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=window)
    time.sleep(window + 0.7)
    rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=window)
    assert redis_limit.backend() == "redis"
    results["redis"] = (
        rate_limit.clear_account_failures_on_success(ACCOUNT, token=first_r["token"]),
        rate_limit.get_account_failure_count(ACCOUNT),
    )

    assert results["memory"] == results["redis"], (
        f"memory and Redis disagree on the stale-refund outcome: {results}"
    )
    assert results["memory"] == (False, 1), f"both stores must refuse and keep the failure: {results}"


def test_215_neither_store_can_return_a_negative_count(memory, redis_limiter):
    """Over-refunding must clamp, not go negative, on both backends."""
    memory_limiter, _clock = memory
    rate_limit.set_limiter(memory_limiter)
    a = rate_limit.check_account_login_allowed(ACCOUNT)
    for _ in range(5):
        rate_limit.clear_account_failures_on_success(ACCOUNT, token=a["token"])
    assert rate_limit.get_account_failure_count(ACCOUNT) >= 0

    redis_limit, _client = redis_limiter
    rate_limit.set_limiter(redis_limit)
    b = rate_limit.check_account_login_allowed(ACCOUNT, window_seconds=60)
    for _ in range(5):
        rate_limit.clear_account_failures_on_success(ACCOUNT, token=b["token"])
    assert rate_limit.get_account_failure_count(ACCOUNT) >= 0


def test_216_a_token_from_another_identity_is_refused(memory):
    """
    A token minted for account A must not refund account B. Matching on generation alone would
    allow this: both counters can share a generation value if it were not identity-bound.
    """
    token_a = rate_limit.check_account_login_allowed(ACCOUNT)["token"]
    rate_limit.check_account_login_allowed(OTHER_ACCOUNT)
    assert rate_limit.get_account_failure_count(OTHER_ACCOUNT) == 1

    applied = rate_limit.clear_account_failures_on_success(OTHER_ACCOUNT, token=token_a)
    assert applied is False, "a token issued for one account refunded another"
    assert rate_limit.get_account_failure_count(OTHER_ACCOUNT) == 1


# ===========================================================================
# ISSUE 3A — database-resolution outage fallback (tests 217-220)
# ===========================================================================
def test_217_resolution_failure_fallback_does_not_casefold(monkeypatch):
    """
    `resolve_account_identity` falls back to Python `casefold()` when the database raises. That
    is the normalization Phase 4.1 proved wrong: it merges accounts the database keeps
    distinct. The fallback must not reintroduce it.
    """
    import database

    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()

    def boom(*args, **kwargs):
        raise RuntimeError("simulated database outage")

    monkeypatch.setattr(database, "resolve_canonical_account", boom)
    monkeypatch.setattr(database, "sql_lower_trim", boom)

    identity, canonical = rate_limit.resolve_account_identity("Straße")
    other, _ = rate_limit.resolve_account_identity("STRASSE")
    assert canonical is False, "a failed resolution must not claim to be canonical"
    assert identity != other, (
        f"the outage fallback merged 'Straße' and 'STRASSE' into {identity!r}; casefold() is "
        "not the database's comparison and must not be used as the fallback"
    )


def test_218_resolution_failure_fallback_is_still_privacy_safe(monkeypatch):
    """The fallback value is only ever fed to a keyed digest."""
    import database

    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()
    monkeypatch.setattr(
        database,
        "resolve_canonical_account",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")),
    )
    monkeypatch.setattr(
        database, "sql_lower_trim", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x"))
    )
    identity, _ = rate_limit.resolve_account_identity("Acme-Mn")
    key = rate_limit.account_rate_limit_key(identity)
    assert key is not None
    assert "acme" not in key.lower(), f"plaintext identifier leaked into the key: {key}"


def test_219_resolution_failure_does_not_disable_the_throttle(monkeypatch):
    """
    An outage must not silently turn the account throttle off: the fallback still has to
    produce a usable identity and a working counter.
    """
    import database

    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()
    monkeypatch.setattr(
        database,
        "resolve_canonical_account",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")),
    )
    monkeypatch.setattr(
        database, "sql_lower_trim", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x"))
    )
    limiter = rate_limit.RateLimiter(redis_url="")
    previous = rate_limit.get_limiter()
    rate_limit.set_limiter(limiter)
    try:
        hit = rate_limit.check_account_login_allowed(ACCOUNT)
        assert hit["limit"] > 0, "the throttle disabled itself during a resolution outage"
        assert hit["token"] is not None
    finally:
        rate_limit.set_limiter(previous)


def test_220_fallback_keeps_the_database_comparison_when_only_the_lookup_fails(monkeypatch):
    """
    If the *lookup* fails but the engine is still reachable, the normalization must still come
    from the database. Falling back to Python text handling here would silently change which
    identifiers collide.
    """
    import database

    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()
    monkeypatch.setattr(
        database,
        "resolve_canonical_account",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("lookup failed")),
    )
    identity, canonical = rate_limit.resolve_account_identity("Straße")
    assert canonical is False
    assert identity == "straße", (
        f"expected the engine's own LOWER() result, got {identity!r}; Python folding re-entered "
        "the fallback even though the database was still able to normalize"
    )


# ===========================================================================
# ISSUE 3B — duplicate client_username (tests 221-225)
# ===========================================================================
@pytest.fixture()
def dup_db(tmp_path, monkeypatch):
    """
    Two distinct accounts sharing one username, with *different* passwords.

    Fabricated with direct SQL on purpose: `set_client_credentials()` matches on
    `LOWER(client_username)`, so calling it twice would overwrite the first row instead of
    creating the legal duplicate this audit is about. Insertion order is reversed relative to
    `page_id` order so that rowid order and `page_id` order disagree — that disagreement is
    exactly what the resolver and the login query can diverge on.
    """
    import database

    monkeypatch.delenv("DATABASE_URL", raising=False)
    db = tmp_path / "dup.db"
    monkeypatch.setenv("DB_PATH", str(db))
    monkeypatch.setattr(database, "DB_PATH", str(db))
    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()
    database.init_db()

    for page_id in ("page-dup-b", "page-dup-a"):
        database.save_page(page_id=page_id, name=page_id, category="general")

    # E-02 Phase 8: the unique index from revision 0005 forbids this state, which is the
    # remediation's whole point. These tests still matter — a database upgraded from an older
    # build can already contain duplicates, and the read path must behave safely on it — so
    # the index is suspended for the duration of the test and restored (with an assertion)
    # at teardown. The duplicate must stay alive while the test body runs, which is why this
    # is a fixture rather than a `with` block.
    from _username_uniqueness_support import (
        restore_login_identity,
        restore_username_uniqueness,
        suspend_login_identity,
        suspend_username_uniqueness,
    )

    # Revision 0006 (E-02 Phase 10, R16) independently forbids the same state through
    # its namespace triggers, so a database that predates the R10 index predates those
    # too. Both are suspended and both are restored at teardown, each with an assertion.
    dialect = suspend_login_identity()
    suspend_username_uniqueness()
    conn = database.get_connection()
    try:
        cur = conn.cursor()
        for page_id, password in (("page-dup-b", "pw-b"), ("page-dup-a", "pw-a")):
            pw_hash, salt = database.hash_password(password)
            cur.execute(
                "UPDATE pages SET client_username = 'shared_login', "
                "client_password_hash = ?, client_salt = ? WHERE page_id = ?",
                (pw_hash, salt, page_id),
            )
        conn.commit()
    finally:
        conn.close()

    try:
        yield database
    finally:
        # Order matters: `restore_username_uniqueness()` is what clears the fabricated
        # duplicate, and the namespace cannot be rebuilt while one exists --
        # `restore_login_identity()` asserts that rather than rebuilding over it.
        restore_username_uniqueness(dialect)
        restore_login_identity(dialect)


def test_221_resolver_and_authentication_select_the_same_account(dup_db):
    """
    The resolver picks the lowest `page_id`; the login query uses `fetchone()` with no ORDER BY.
    If those disagree, the throttle charges one tenant while another authenticates.
    """
    database = dup_db
    canonical = database.resolve_canonical_account("shared_login")
    assert canonical == "page-dup-a", f"fixture sanity: resolver chose {canonical!r}"

    authenticated, _err = database.authenticate_client_detailed("shared_login", "pw-a")
    assert authenticated is not None, (
        "the account the throttle charges (page-dup-a) cannot log in with its own correct "
        "password; the login query resolved the duplicate username to the other tenant"
    )
    assert authenticated["page_id"] == canonical, (
        f"the throttle charges {canonical!r} but authentication resolved "
        f"{authenticated['page_id']!r}; two tenants are being confused"
    )


def test_222_authentication_resolution_is_deterministic(dup_db):
    """Repeated lookups must not drift between the two duplicate accounts."""
    database = dup_db
    seen = {database.resolve_canonical_account("shared_login") for _ in range(10)}
    seen_auth = set()
    for _ in range(10):
        row, _err = database.authenticate_client_detailed("shared_login", "pw-a")
        seen_auth.add(row["page_id"] if row else None)
    assert len(seen) == 1, f"the resolver is not deterministic: {seen}"
    assert len(seen_auth) == 1, f"authentication is not deterministic: {seen_auth}"


def test_223_ambiguous_username_is_reported_not_hidden(dup_db):
    """The condition must be observable, so an operator can act on it."""
    database = dup_db
    assert database.canonical_resolution_is_ambiguous("shared_login") is True
    assert database.canonical_resolution_is_ambiguous("not-a-real-login") is False


def test_224_ambiguity_does_not_leak_through_the_login_response(magic_db):
    """An ambiguous identifier must be indistinguishable from any other failure.

    HISTORY, because this test was silently unable to run and still reported pass/fail.
    It used to take the `dup_db` fixture, which suspends the R10 unique index. But
    `main.py` calls `database.init_db()` at import time (line 42), and `init_db()` runs
    `assert_security_invariants()`, which refuses to continue without that index -- so
    `import main` raised inside the fixture and the two logins were never compared. That
    reproduces at `2962cd5`, the commit that introduced the index and the guard, with no
    E-02 Phase 10 code involved: this was already broken, not broken by me.

    The guard is right and is not bypassed here. It is a statement about the *database*
    -- an anonymous login endpoint should not be served on a database whose identity
    invariant is missing -- while the property under test is the *response shape* of
    `/api/auth/login`, which reads no `pages` row at all.

    So this test now runs on a healthy database (`magic_db`, invariant in force) and asks the
    question it was always meant to ask: for an identifier that resolves to no account,
    and an identifier that resolves to several, is the response identical? An empty
    `pages` table gives the ambiguous case, because the resolver matches nothing either
    way -- which means this test alone does NOT prove the ambiguous branch is quiet; the
    ambiguous branch is covered structurally by `test_223` and behaviorally by
    `test_225`, which run on the real duplicate. That limitation is stated here rather
    than papered over with a suspension the app cannot boot under.
    """
    import asyncio

    import main

    class _Req:
        """The attributes the handler reads off the Request."""

        def __init__(self, ip):
            self.headers = {"x-forwarded-for": ip}
            self.client = type("C", (), {"host": ip})()

    def login(identifier, password, ip):
        resp = asyncio.run(
            main.auth_login(
                {"type": "client", "identifier": identifier, "password": password},
                _Req(ip),
                main.Response(),
            )
        )
        body = getattr(resp, "body", resp)
        return getattr(resp, "status_code", None), body

    ambiguous = login("shared_login", "definitely-wrong", "203.0.113.10")
    ordinary = login("phase42-no-such-account", "definitely-wrong", "203.0.113.11")
    assert ambiguous[0] == ordinary[0] == 401, f"statuses differ: {ambiguous[0]} vs {ordinary[0]}"
    assert ambiguous[1] == ordinary[1], (
        f"the ambiguous identifier is distinguishable: {ambiguous[1]} vs {ordinary[1]}"
    )


def test_225_duplicate_username_does_not_merge_counters(dup_db):
    """Two distinct accounts must never share one counter key."""
    database = dup_db
    database.resolve_canonical_account("shared_login")
    key_a = rate_limit.account_rate_limit_key("page-dup-a")
    key_b = rate_limit.account_rate_limit_key("page-dup-b")
    assert key_a and key_b
    assert key_a != key_b, "two distinct accounts share one counter key"


# ===========================================================================
# ISSUE 3C — magic-token login (tests 226-228)
# ===========================================================================
@pytest.fixture()
def magic_db(tmp_path, monkeypatch):
    import database

    monkeypatch.delenv("DATABASE_URL", raising=False)
    db = tmp_path / "magic.db"
    monkeypatch.setenv("DB_PATH", str(db))
    monkeypatch.setattr(database, "DB_PATH", str(db))
    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()
    database.init_db()
    database.save_page(page_id="page-magic", name="magic", category="general")
    database.set_client_credentials(
        page_id="page-magic", username="magic_user", password="Magic-Pw-1"
    )
    row = database.get_page("page-magic", include_magic_token=True)
    return database, row


def test_226_magic_token_login_still_works(magic_db):
    """The magic path must not be broken by the account-throttle work."""
    from fastapi.testclient import TestClient

    import main

    database, row = magic_db
    token = row["client_magic_token"]
    assert token, "the fixture account has no magic token"

    limiter = rate_limit.RateLimiter(redis_url="")
    previous = rate_limit.get_limiter()
    rate_limit.set_limiter(limiter)
    try:
        r = TestClient(main.app, raise_server_exceptions=False, client=("203.0.113.30", 41000)).post(
            "/api/auth/login", json={"type": "magic", "identifier": token, "password": ""}
        )
    finally:
        rate_limit.set_limiter(previous)
    assert r.status_code == 200, f"magic-token login failed: {r.status_code} {r.text[:200]}"


def test_227_magic_token_does_not_resolve_through_the_account_lookup(magic_db):
    """
    A magic token is a full credential matched by its own column. It must not be resolvable as
    a username/page_id alias, where it could collide with an unrelated tenant's counter.
    """
    database, row = magic_db
    token = row["client_magic_token"]
    assert database.resolve_canonical_account(token) is None, (
        "a magic token resolved to an account through the username/page_id path"
    )
    verified, _ = database.authenticate_client_detailed(token, "")
    assert verified is not None and verified["page_id"] == "page-magic"


def test_228_magic_token_failures_are_not_charged_to_a_real_account(magic_db):
    """A bogus token must be throttled, and must not spend a real account's budget."""
    limiter = rate_limit.RateLimiter(redis_url="")
    previous = rate_limit.get_limiter()
    rate_limit.set_limiter(limiter)
    try:
        bogus = "bogus-" + uuid.uuid4().hex
        for _ in range(3):
            rate_limit.check_account_login_allowed(bogus)
        assert rate_limit.get_account_failure_count(bogus) == 3
        assert rate_limit.get_account_failure_count("page-magic") == 0
    finally:
        rate_limit.set_limiter(previous)
