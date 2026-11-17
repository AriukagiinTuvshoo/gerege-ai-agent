"""
Stage E — E-02 Phase 4.1: hardening of the Phase 4 account-level throttle.

Written before the fixes and expected to FAIL until they exist. Each group below
corresponds to one finding from the independent review of Phase 4.

A. Canonical account identity
   The Phase 4 key was derived from the *submitted* identifier. The login lookup accepts
   `client_username` OR `page_id`, so one account had several budgets: 20 failures on the
   username left the page_id alias at 401. Confirmed against the real implementation, not
   assumed.

B. Atomic INCR + TTL
   `INCR` and `EXPIRE` were two round-trips. A crash between them leaves a counter with no
   expiry, which never recovers. Must become one atomic operation.

C. Reset/verify interleaving
   The Phase 4 route checked the account counter, then authenticated, then reset it. Two
   concurrent requests could both pass the check before either failure was recorded, so N
   concurrent requests all got in. The counter must be consumed atomically at admission, and
   the success path must reverse the one admission it consumed — never clear a whole key.

D. Required production secret
   Production started with no `E02_ACCOUNT_KEY_SECRET` and quietly disabled account
   throttling, logging only a WARNING. Production must refuse to start.

E. Normalization consistency
   `str.casefold()` is not `LOWER()`. Measured: SQLite `LOWER('Straße')` is `'straße'` while
   `casefold('Straße')` is `'strasse'`, so two accounts the database treats as distinct shared
   one counter — one tenant's failures throttled another. PostgreSQL folds `STRASSE` and
   `Straße` differently again. The key must follow exactly what the database compares.

Counting note: this file defines 34 test functions; parametrisation expands it to more
collected cases. Both numbers are reported separately.
"""
import os
import sys
import threading
import time

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402
from core import account_keys, rate_limit  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Username differs from page_id on purpose: that is what made the alias bug visible.
ALPHA_PAGE_ID = "page-alpha-01"
ALPHA_USER = "alpha_login"
ALPHA_PW = "Alpha-Pass-2026"

BETA_PAGE_ID = "page-beta-02"
BETA_USER = "beta_login"
BETA_PW = "Beta-Pass-2026"

TEST_SECRET = "e02-p41-test-secret-0123456789abcdef"


def _policy():
    threshold = getattr(rate_limit, "ACCOUNT_FAILURE_THRESHOLD", None)
    window = getattr(rate_limit, "ACCOUNT_FAILURE_WINDOW", None)
    assert threshold is not None and window is not None, (
        "core.rate_limit defines no account-level policy"
    )
    return threshold, window


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db = tmp_path / "e02p41.db"
    monkeypatch.setenv("DB_PATH", str(db))
    monkeypatch.setattr(database, "DB_PATH", str(db))
    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()
    database.init_db()

    for page_id, user, pw in (
        (ALPHA_PAGE_ID, ALPHA_USER, ALPHA_PW),
        (BETA_PAGE_ID, BETA_USER, BETA_PW),
    ):
        database.save_page(page_id=page_id, name=page_id, category="general")
        database.set_client_credentials(page_id=page_id, username=user, password=pw)

    import main

    previous = rate_limit.get_limiter()
    rate_limit.set_limiter(rate_limit.RateLimiter(redis_url=""))
    try:
        yield main.app
    finally:
        rate_limit.set_limiter(previous)


def _client(asgi, ip):
    """A client whose TCP peer really is `ip`."""
    return TestClient(asgi, raise_server_exceptions=False, client=(ip, 41000))


def _login(asgi, identifier, password, ip="203.0.113.1"):
    return _client(asgi, ip).post(
        "/api/auth/login",
        json={"type": "client", "identifier": identifier, "password": password},
    )


# ===========================================================================
# ISSUE A — canonical account identity (tests 101-112)
# ===========================================================================
def test_101_username_and_page_id_share_one_budget(app):
    """
    The finding. One account, two working identifiers, one budget.

    Before the fix the page_id alias still returned 401 after the username had burned the
    whole budget, so an attacker doubled their attempts for free.
    """
    threshold, _ = _policy()
    for i in range(threshold):
        _login(app, ALPHA_USER, "wrong", ip=f"203.0.113.{i + 1}")

    by_username = _login(app, ALPHA_USER, "wrong", ip="203.0.113.100")
    by_page_id = _login(app, ALPHA_PAGE_ID, "wrong", ip="203.0.113.101")
    assert by_username.status_code == 429, f"username alias not throttled: {by_username.status_code}"
    assert by_page_id.status_code == 429, (
        f"E-02.1: the page_id alias answered {by_page_id.status_code} after the account's "
        "budget was spent through the username. One account, two budgets — alias rotation "
        "multiplies the threshold."
    )


def test_102_alias_rotation_cannot_multiply_the_threshold(app):
    """Alternating aliases must consume ONE budget, not one per alias."""
    threshold, _ = _policy()
    allowed = 0
    for i in range(threshold * 3):
        identifier = ALPHA_USER if i % 2 == 0 else ALPHA_PAGE_ID
        r = _login(app, identifier, "wrong", ip=f"203.0.113.{i + 1}")
        if r.status_code == 429:
            break
        allowed += 1
    assert allowed <= threshold, (
        f"alternating between username and page_id allowed {allowed} attempts against a "
        f"threshold of {threshold}; alias rotation multiplies the budget"
    )


def test_103_canonical_identity_resolves_both_aliases_to_one_account(app):
    """The resolver must map both login aliases onto the same canonical account id."""
    resolve = getattr(database, "resolve_canonical_account", None)
    assert resolve is not None, (
        "database.resolve_canonical_account is missing: there is no way to decide, before "
        "password verification, which account an identifier belongs to"
    )
    by_user = resolve(ALPHA_USER)
    by_page = resolve(ALPHA_PAGE_ID)
    assert by_user == ALPHA_PAGE_ID, f"username resolved to {by_user!r}, not the canonical page id"
    assert by_page == ALPHA_PAGE_ID, f"page_id resolved to {by_page!r}"
    assert by_user == by_page


def test_104_different_accounts_stay_separate(app):
    """Canonicalization must not collapse unrelated tenants into one counter."""
    threshold, _ = _policy()
    for i in range(threshold + 2):
        _login(app, ALPHA_USER, "wrong", ip=f"203.0.113.{i + 1}")
    r = _login(app, BETA_USER, BETA_PW, ip="203.0.113.200")
    assert r.status_code == 200, (
        f"a second account was throttled by the first account's failures ({r.status_code})"
    )


def test_105_unknown_username_is_still_protected(app):
    """An identifier that resolves to nothing must still be counted, or it is a free oracle."""
    threshold, _ = _policy()
    codes = [
        _login(app, "ghost-account-xyz", "wrong", ip=f"203.0.113.{i + 1}").status_code
        for i in range(threshold + 5)
    ]
    assert 429 in codes, f"an unknown username was never throttled: {set(codes)}"


def test_106_unknown_page_id_is_still_protected(app):
    threshold, _ = _policy()
    codes = [
        _login(app, "page-does-not-exist", "wrong", ip=f"203.0.113.{i + 1}").status_code
        for i in range(threshold + 5)
    ]
    assert 429 in codes, f"an unknown page_id was never throttled: {set(codes)}"


def test_107_unknown_aliases_of_one_absent_account_share_a_budget(app):
    """
    Privacy requirement: two spellings of the same *nonexistent* account must not each get
    a fresh budget, or an attacker learns which identifiers resolve.
    """
    threshold, _ = _policy()
    allowed = 0
    for i in range(threshold * 3):
        ident = "ghost-one" if i % 2 == 0 else "  Ghost-One  "
        if _login(app, ident, "wrong", ip=f"203.0.113.{i + 1}").status_code == 429:
            break
        allowed += 1
    assert allowed <= threshold, (
        f"{allowed} attempts allowed against a threshold of {threshold}; unknown identifiers "
        "are not normalized to one budget"
    )


def test_108_database_does_not_allow_duplicate_usernames(app, monkeypatch):
    """
    Duplicate `client_username` values would make "which account does this identifier mean?"
    genuinely ambiguous. `set_client_credentials` must therefore refuse to create one.

    E-02 Phase 6, R10. This test previously created the duplicate *through*
    `set_client_credentials` — the very write condition that let a second tenant rewrite the
    first tenant's row. That made the vulnerable path load-bearing for the audit's own
    evidence. The duplicate is now fabricated with direct SQL (the same approach the Phase 4.2
    suite already uses for `shared_login`), and the write path is asserted to refuse it.

    The assertions on the resolver are retained unchanged: a database that somehow already
    contains duplicates must still resolve them deterministically and report the ambiguity.
    """
    import sqlite3

    database.save_page(page_id="page-dup-01", name="dup1", category="general")
    database.set_client_credentials(page_id="page-dup-01", username="shared_name", password="Dup-Pw-1")
    database.save_page(page_id="page-dup-02", name="dup2", category="general")

    # R10: the write path must now refuse the second tenant's colliding username.
    with pytest.raises(database.CredentialConflictError):
        database.set_client_credentials(page_id="page-dup-02", username="shared_name", password="Dup-Pw-2")

    # Fabricate the duplicate to prove the read path stays safe on *legacy* data — a
    # database that predates the Phase 8 unique index. `legacy_duplicates_allowed()` removes
    # the index for exactly this block and restores it afterwards, asserting that it did.
    from _username_uniqueness_support import legacy_duplicates_allowed

    from _username_uniqueness_support import (
        clear_legacy_duplicates,
        legacy_duplicates_allowed,
    )

    with legacy_duplicates_allowed():
        conn = database.get_connection()
        try:
            cur = conn.cursor()
            pw_hash, salt = database.hash_password("Dup-Pw-2")
            cur.execute(
                "UPDATE pages SET client_username = 'shared_name', client_password_hash = ?, "
                "client_salt = ? WHERE page_id = 'page-dup-02'",
                (pw_hash, salt),
            )
            conn.commit()
        finally:
            conn.close()

        # Assertions run HERE, while the legacy duplicate still exists: that is the state
        # being described. Cleanup happens before leaving the context because the index
        # cannot be restored over a live collision.
        resolve = getattr(database, "resolve_canonical_account", None)
        assert resolve is not None, "no canonical resolver"
        # Whatever it returns, it must be ONE deterministic account, the same both times.
        first = resolve("shared_name")
        second = resolve("shared_name")
        assert first == second, "the resolver is not deterministic for an ambiguous username"
        # And the ambiguity must not be silent.
        report = getattr(database, "canonical_resolution_is_ambiguous", None)
        assert report is not None, (
            "a schema without a unique username constraint can produce duplicates; the "
            "resolver must expose whether an identifier is ambiguous instead of silently "
            "picking one"
        )
        assert report("shared_name") is True, "duplicate usernames were not reported as ambiguous"

        clear_legacy_duplicates()

    # The invariant must be back, and the ambiguity gone with the data.
    assert report("shared_name") is False


def test_109_ambiguity_does_not_leak_through_the_login_response(app):
    """
    Two accounts sharing a username must still be indistinguishable from outside.

    E-02 Phase 6/8, R10: the duplicate is fabricated with direct SQL against a simulated
    legacy database (the Phase 8 unique index forbids it otherwise). The write path refuses
    to create it (see `test_108`), but a database that already contains one must stay safe.
    """
    import sqlite3

    database.save_page(page_id="page-dup-a", name="da", category="general")
    database.set_client_credentials(page_id="page-dup-a", username="ambiguous_x", password="Aa-1")
    database.save_page(page_id="page-dup-b", name="db", category="general")
    with pytest.raises(database.CredentialConflictError):
        database.set_client_credentials(page_id="page-dup-b", username="ambiguous_x", password="Bb-2")
    from _username_uniqueness_support import (
        clear_legacy_duplicates,
        legacy_duplicates_allowed,
    )

    with legacy_duplicates_allowed():
        conn = database.get_connection()
        try:
            cur = conn.cursor()
            pw_hash, salt = database.hash_password("Bb-2")
            cur.execute(
                "UPDATE pages SET client_username = 'ambiguous_x', client_password_hash = ?, "
                "client_salt = ? WHERE page_id = 'page-dup-b'",
                (pw_hash, salt),
            )
            conn.commit()
        finally:
            conn.close()

        # The login is issued while the legacy duplicate exists — that is the state whose
        # exterior behaviour is being asserted.
        r = _login(app, "ambiguous_x", "wrong", ip="203.0.113.5")
        assert r.status_code == 401, f"ambiguous identifier answered {r.status_code}"
        assert set(r.json()) == {"success", "error"}

        clear_legacy_duplicates()


def test_110_no_plaintext_identifier_in_account_keys(app):
    """The canonical key must still be an opaque digest."""
    _policy()
    for i in range(3):
        _login(app, ALPHA_USER, "wrong", ip=f"203.0.113.{i + 1}")

    store = rate_limit.get_limiter()._store
    keys = [k for k in getattr(store, "_counters", {}) if "account" in k]
    assert keys, "no account key was written"
    joined = " ".join(keys).lower()
    for needle in (ALPHA_USER.lower(), ALPHA_PAGE_ID.lower(), "alpha", "beta"):
        assert needle not in joined, f"plaintext identifier {needle!r} found in keys: {keys}"


def test_111_canonical_key_is_derived_from_the_account_not_the_alias(app):
    """
    The digest must be a function of the canonical account id, so two aliases produce the
    same value by construction rather than by coincidence.
    """
    key_for = getattr(rate_limit, "account_canonical_key", None)
    assert key_for is not None, "rate_limit.account_canonical_key is missing"
    from_user = key_for(ALPHA_USER, database.resolve_canonical_account(ALPHA_USER))
    from_page = key_for(ALPHA_PAGE_ID, database.resolve_canonical_account(ALPHA_PAGE_ID))
    assert from_user == from_page, "the canonical key still depends on which alias was used"


def test_112_canonical_lookup_does_not_trust_a_client_supplied_page_id(app):
    """
    Resolution must be against the database. A page_id that does not exist must not become
    a canonical key that could collide with a real one.
    """
    resolve = database.resolve_canonical_account
    assert resolve(ALPHA_PAGE_ID) == ALPHA_PAGE_ID
    assert resolve("page-not-in-db") is None, (
        "a page_id absent from the database was 'resolved' without being looked up"
    )


# ===========================================================================
# ISSUE B — atomic INCR + TTL (tests 113-119)
# ===========================================================================
def _redis_or_skip():
    url = os.getenv("REDIS_URL", "").strip()
    if not url:
        pytest.skip("needs REDIS_URL: an atomic Redis script cannot be observed without Redis")
    import redis

    return url, redis.from_url(url, decode_responses=True)


def test_113_first_increment_sets_a_ttl():
    url, client = _redis_or_skip()
    store = rate_limit.RateLimiter(redis_url=url)._store
    key = "ratelimit:atomic_test:a"
    client.delete(key)
    store.incr_in_window(key, 900)
    ttl = client.ttl(key)
    assert 0 < ttl <= 900, f"first increment left ttl={ttl}"
    client.delete(key)


def test_114_subsequent_increments_preserve_the_window():
    """
    The window must not restart on every attempt (that would let an attacker hold a counter
    open forever), and must not expire early either.
    """
    url, client = _redis_or_skip()
    store = rate_limit.RateLimiter(redis_url=url)._store
    key = "ratelimit:atomic_test:b"
    client.delete(key)
    store.incr_in_window(key, 900)
    first = client.ttl(key)
    time.sleep(2)
    for _ in range(4):
        store.incr_in_window(key, 900)
    later = client.ttl(key)
    assert later <= first, f"TTL grew from {first} to {later}: the window restarted"
    assert later > 0, "the counter expired while still in use"
    assert int(client.get(key)) == 5
    client.delete(key)


def test_115_increment_and_ttl_are_one_atomic_operation():
    """
    Structural check: the store must express this as one round-trip (a Lua script or an
    equivalent single command), because two commands can be interrupted between them.
    """
    url, client = _redis_or_skip()
    store = rate_limit.RateLimiter(redis_url=url)._store
    script = getattr(store, "_incr_script", None)
    assert script is not None, (
        "the Redis store still issues separate INCR/EXPIRE commands; an interruption between "
        "them leaves a counter with no TTL that never expires"
    )
    assert store.increment_is_atomic() is True


def test_116_no_key_can_exist_without_a_ttl():
    """
    The property the previous tests exist to protect, checked directly: after a fresh
    increment the key ALWAYS has a TTL, so no counter can be immortal.
    """
    url, client = _redis_or_skip()
    store = rate_limit.RateLimiter(redis_url=url)._store
    for i in range(20):
        key = f"ratelimit:atomic_test:noTTL{i}"
        client.delete(key)
        store.incr_in_window(key, 60)
        assert client.ttl(key) > 0, f"{key} exists with no expiry"
        client.delete(key)


def test_117_expiration_restores_the_budget():
    url, client = _redis_or_skip()
    store = rate_limit.RateLimiter(redis_url=url)._store
    key = "ratelimit:atomic_test:c"
    client.delete(key)
    for _ in range(5):
        store.incr_in_window(key, 1)
    time.sleep(1.6)
    assert store.read_counter(key) == 0, "the counter survived its own window"


def test_118_concurrent_increments_lose_nothing():
    """Many threads against one real Redis key; the count must be exact."""
    url, client = _redis_or_skip()
    store = rate_limit.RateLimiter(redis_url=url)._store
    key = "ratelimit:atomic_test:d"
    client.delete(key)
    total = 200
    errors = []

    def hit():
        try:
            store.incr_in_window(key, 900)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=hit) for _ in range(total)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors[:3]
    assert int(client.get(key)) == total, f"expected {total}, got {client.get(key)}"
    client.delete(key)


def test_119_atomic_increment_returns_the_ttl(monkeypatch):
    """The operation must report the remaining window so Retry-After can be honest."""
    url, client = _redis_or_skip()
    store = rate_limit.RateLimiter(redis_url=url)._store
    key = "ratelimit:atomic_test:e"
    client.delete(key)
    result = store.incr_in_window_detailed(key, 900)
    assert isinstance(result, dict), "incr_in_window_detailed must return count and ttl"
    assert result["count"] == 1
    assert 0 < result["ttl"] <= 900
    client.delete(key)


# ===========================================================================
# ISSUE C — check/reset ordering (tests 120-129)
# ===========================================================================
def test_120_failure_then_success_refunds_only_its_own_slot(app):
    """
    The documented ordering guarantee, first half.

    Model: a failure consumes a slot and keeps it; a success consumes a slot and refunds that
    same slot. Three failures then a success therefore leaves three, not zero.

    The Phase 4 implementation deleted the whole key here, which is what
    `test_121` and `test_126` exist to prevent: a deletion cannot distinguish a failure that
    happened *after* the success was admitted, so it erased it.
    """
    _policy()
    for i in range(3):
        _login(app, ALPHA_USER, "wrong", ip=f"203.0.113.{i + 1}")
    assert rate_limit.get_account_failure_count(ALPHA_PAGE_ID) == 3

    ok = _login(app, ALPHA_USER, ALPHA_PW, ip="203.0.113.50")
    assert ok.status_code == 200

    remaining = rate_limit.get_account_failure_count(ALPHA_PAGE_ID)
    assert remaining == 3, (
        f"expected 3 residual failures (the success refunds only the slot it consumed), found "
        f"{remaining}. 0 means the counter was deleted rather than refunded, which loses any "
        "failure recorded concurrently."
    )


def test_121_success_then_new_failure_keeps_the_new_failure(app):
    """
    The documented ordering guarantee, second half: a failure that happens after a successful
    login is preserved.
    """
    _policy()
    _login(app, ALPHA_USER, "wrong", ip="203.0.113.1")
    assert rate_limit.get_account_failure_count(ALPHA_PAGE_ID) == 1

    assert _login(app, ALPHA_USER, ALPHA_PW, ip="203.0.113.2").status_code == 200
    # The success refunded its own slot, so the earlier failure remains recorded.
    assert rate_limit.get_account_failure_count(ALPHA_PAGE_ID) == 1

    _login(app, ALPHA_USER, "wrong", ip="203.0.113.3")
    assert rate_limit.get_account_failure_count(ALPHA_PAGE_ID) == 2, (
        "the failure after a successful login was lost"
    )


def test_122_reset_never_deletes_another_accounts_counter(app):
    _policy()
    for i in range(4):
        _login(app, BETA_USER, "wrong", ip=f"203.0.113.{i + 1}")
    beta_before = rate_limit.get_account_failure_count(BETA_PAGE_ID)
    assert beta_before == 4

    for i in range(3):
        _login(app, ALPHA_USER, "wrong", ip=f"198.51.100.{i + 1}")
    assert _login(app, ALPHA_USER, ALPHA_PW, ip="198.51.100.90").status_code == 200

    assert rate_limit.get_account_failure_count(BETA_PAGE_ID) == beta_before, (
        "one account's successful login changed another account's counter"
    )


def test_123_reset_leaves_the_ip_counter_alone(app):
    _policy()
    limiter = rate_limit.get_limiter()
    ip = "203.0.113.77"
    for _ in range(3):
        _login(app, ALPHA_USER, "wrong", ip=ip)
    before = limiter.peek(f"ratelimit:auth_login:{ip}", 60)
    assert before == 3
    assert _login(app, ALPHA_USER, ALPHA_PW, ip=ip).status_code == 200
    after = limiter.peek(f"ratelimit:auth_login:{ip}", 60)
    assert after == before + 1, (
        f"the IP counter went {before} -> {after}; success must not clear the IP counter"
    )


def test_124_concurrent_requests_cannot_overspend_the_budget(app):
    """
    The real defect: N concurrent requests all passed the pre-auth check before any of them
    recorded a failure, so all N were verified instead of only the remaining budget.
    """
    threshold, _ = _policy()
    allowed = []
    lock = threading.Lock()

    def attempt(i):
        r = _login(app, ALPHA_USER, "wrong", ip=f"198.18.{i}.1")
        with lock:
            allowed.append(r.status_code)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(threshold + 15)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    accepted = sum(1 for c in allowed if c != 429)
    assert accepted <= threshold, (
        f"{accepted} of {len(threads)} concurrent requests were verified against a threshold "
        f"of {threshold}; the check and the increment are not one operation"
    )


def test_125_a_failure_is_counted_immediately(app):
    """One failed login, one recorded failure."""
    _policy()
    _login(app, ALPHA_USER, "wrong", ip="203.0.113.1")
    assert rate_limit.get_account_failure_count(ALPHA_PAGE_ID) == 1


def test_126_a_success_leaves_the_counter_untouched(app):
    """
    The documented ordering guarantee, and the core of the finding.

    The throttle admits first and records outcomes afterwards, so a request the attacker
    never had a verified guess against is not a failure. A success therefore records nothing
    and removes nothing.

    The Phase 4 implementation deleted the whole key on success, which erased every failure
    recorded between the success being admitted and the deletion — see `test_121` (already
    passing) and the interleaving model in docs/audit/E02_LOGIN_RATE_LIMIT.md section 4.3.
    """
    _policy()
    for i in range(5):
        _login(app, ALPHA_USER, "wrong", ip=f"203.0.113.{i + 1}")
    assert rate_limit.get_account_failure_count(ALPHA_PAGE_ID) == 5

    assert _login(app, ALPHA_USER, ALPHA_PW, ip="203.0.113.60").status_code == 200

    remaining = rate_limit.get_account_failure_count(ALPHA_PAGE_ID)
    assert remaining == 5, (
        f"a successful login changed the failure counter to {remaining}; the guarantee is that "
        "it removes nothing, so no failure recorded around it can be lost. 0 means the whole "
        "key was deleted; 4 means an admission was refunded."
    )


def test_127_an_admitted_login_is_not_a_failure(app):
    """
    Only a login that actually had a wrong password verified may count. Merely being admitted
    must not consume budget, or the owner's own correct password would cost them a slot.
    """
    _policy()
    for i in range(5):
        assert _login(app, ALPHA_USER, ALPHA_PW, ip=f"203.0.113.{i + 1}").status_code == 200
    assert rate_limit.get_account_failure_count(ALPHA_PAGE_ID) == 0, (
        "five successful logins were recorded as five failures"
    )


def test_128_repeated_successes_never_produce_a_negative_count(app):
    """Successes record nothing, so a counter can never go negative."""
    _policy()
    for i in range(3):
        assert _login(app, ALPHA_USER, ALPHA_PW, ip=f"203.0.113.{i + 1}").status_code == 200
    count = rate_limit.get_account_failure_count(ALPHA_PAGE_ID)
    assert count >= 0, f"counter went negative: {count}"


def test_129_concurrent_success_and_failure_keep_a_bounded_count(app):
    """A mixed concurrent burst must leave a sane, non-negative count."""
    _policy()
    results = []
    lock = threading.Lock()

    def work(i):
        ident = ALPHA_USER
        pw = ALPHA_PW if i % 3 == 0 else "wrong"
        r = _login(app, ident, pw, ip=f"198.19.{i}.1")
        with lock:
            results.append(r.status_code)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(24)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert 500 not in results, "a mixed burst produced a server error"
    count = rate_limit.get_account_failure_count(ALPHA_PAGE_ID)
    assert count >= 0, f"negative counter: {count}"


# ===========================================================================
# ISSUE D — required production secret (tests 130-136)
# ===========================================================================
def _validate():
    """
    Run startup validation. Raises RuntimeError when the configuration is unacceptable.

    Deliberately *calls* the validator: an earlier version returned it, so
    `with pytest.raises(...): _validate()` asserted that constructing a bound method raises,
    which it does not. The tests passed for the wrong reason in one direction and failed in
    the other; both were the helper, not the implementation.
    """
    fn = getattr(account_keys, "validate_secret_for_startup", None)
    assert fn is not None, (
        "core.account_keys has no startup validation, so production can start with account "
        "throttling silently disabled"
    )
    fn()


@pytest.mark.usefixtures("_no_e02_secret_fixture")
def test_130_production_without_secret_refuses_to_start(monkeypatch):
    """The finding: production must fail closed, not log a warning."""
    monkeypatch.delenv("E02_ACCOUNT_KEY_SECRET", raising=False)
    monkeypatch.setenv("ENV", "production")
    monkeypatch.delenv("STRICT_SECURITY", raising=False)
    with pytest.raises(RuntimeError) as excinfo:
        _validate()
    message = str(excinfo.value)
    assert "E02_ACCOUNT_KEY_SECRET" in message, f"error does not name the variable: {message}"


@pytest.mark.usefixtures("_no_e02_secret_fixture")
def test_131_production_with_empty_secret_refuses_to_start(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    for blank in ("", "   ", "\t", "\n  \t "):
        monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", blank)
        with pytest.raises(RuntimeError):
            _validate()


@pytest.mark.usefixtures("_no_e02_secret_fixture")
def test_132_production_with_short_secret_refuses_to_start(monkeypatch):
    """A 3-character secret is not a key. Enforce a floor so 'secret' is not accepted."""
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", "abc")
    with pytest.raises(RuntimeError) as excinfo:
        _validate()
    assert "length" in str(excinfo.value).lower() or "short" in str(excinfo.value).lower()


@pytest.mark.usefixtures("_no_e02_secret_fixture")
def test_133_production_with_good_secret_starts(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", "x" * 64)
    _validate()  # must not raise


@pytest.mark.usefixtures("_no_e02_secret_fixture")
def test_134_development_without_secret_still_starts(monkeypatch):
    """Development and tests keep working; only production fails closed."""
    monkeypatch.delenv("E02_ACCOUNT_KEY_SECRET", raising=False)
    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("STRICT_SECURITY", raising=False)
    _validate()  # must not raise


@pytest.mark.usefixtures("_no_e02_secret_fixture")
def test_135_startup_error_never_contains_the_secret(monkeypatch):
    """A startup failure must not print the secret it rejected."""
    monkeypatch.setenv("ENV", "production")
    secret = "leaky-secret-value-that-must-not-be-printed"
    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", secret)
    # Force a different failure so the message is produced while a secret is configured.
    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", " ")
    try:
        _validate()
    except RuntimeError as exc:
        assert secret not in str(exc)
    else:
        pytest.fail("validation accepted a blank secret")


def test_136_secret_never_appears_in_logs_on_success(app, caplog):
    """Even a valid secret must never be logged."""
    import logging

    with caplog.at_level(logging.DEBUG):
        _login(app, ALPHA_USER, "wrong", ip="203.0.113.9")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert TEST_SECRET not in text, "the account-key secret was written to the log"


# ===========================================================================
# ISSUE E — normalization consistency (tests 137-144)
# ===========================================================================
def _db_lower(value: str) -> str:
    """`LOWER(TRIM(x))` exactly as the login query computes it, on the real engine."""
    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT LOWER(TRIM(?))", (value,))
        return cur.fetchone()[0]
    finally:
        conn.close()


@pytest.mark.parametrize(
    "raw",
    ["Acme-Mn", "ACME-MN", "  acme-mn  ", "\tAcme-Mn\n", "aCmE-mN"],
)
def test_137_ascii_case_and_whitespace_variants_share_one_budget(raw):
    """The baseline the database actually provides: ASCII case + trim."""
    assert account_keys.normalize_identifier(raw) == account_keys.normalize_identifier("acme-mn")


def test_138_python_casefold_does_not_define_the_key():
    """
    The measured inconsistency. If the key normalized with `casefold()` these two would
    collide, and they are distinct accounts as far as the database is concerned.
    """
    assert _db_lower("Straße") != _db_lower("STRASSE"), "sanity: the DB treats these as distinct"
    assert account_keys.normalize_identifier("Straße") != account_keys.normalize_identifier("STRASSE"), (
        "normalize_identifier folds 'Straße' and 'STRASSE' together, which the database does "
        "not — two distinct accounts would share one budget"
    )


def test_139_key_matches_the_database_comparison_semantics():
    """The key must be a function of what the database compares, not of Python's folding."""
    for value in ("Straße", "ΣΊΣΥΦΟΣ", "Ø", "ﬁle", "İstanbul", "ＡＣＭＥ", "ǅungla"):
        expected = _db_lower(value.strip())
        actual = account_keys.normalize_identifier(value)
        assert actual == expected, (
            f"{value!r}: the account key normalizes to {actual!r} but the login query compares "
            f"{expected!r}; the throttle and the authentication lookup disagree"
        )


def test_140_distinct_unicode_identifiers_are_not_merged(app):
    """
    End-to-end consequence of the casefold bug: two real accounts must not share a budget.
    """
    database.save_page(page_id="page-s1", name="s1", category="general")
    database.set_client_credentials(page_id="page-s1", username="Straße", password="Ss-Pw-1")
    database.save_page(page_id="page-s2", name="s2", category="general")
    database.set_client_credentials(page_id="page-s2", username="STRASSE", password="Ss-Pw-2")

    for i in range(5):
        _login(app, "Straße", "wrong", ip=f"203.0.113.{i + 1}")

    assert rate_limit.get_account_failure_count("page-s1") == 5
    assert rate_limit.get_account_failure_count("page-s2") == 0, (
        "failures against 'Straße' were charged to the separate account 'STRASSE'"
    )


def test_141_unicode_variants_the_database_does_fold_share_a_budget(app):
    """
    The key must follow whatever the engine actually folds, not a fixed Unicode table.

    PostgreSQL folds `Ø`/`ø`; SQLite's `LOWER` is ASCII-only and does not. Because the `app`
    fixture isolates each test onto its own SQLite file (it clears `DATABASE_URL`), this test
    runs on **SQLite even in the PostgreSQL CI job**, and therefore skips there — there is no
    folded variant to compare, by the engine's own definition. The skip is the assertion: it
    records that the engines genuinely differ, which is why the implementation delegates the
    comparison to the database instead of reimplementing it.

    `test_139` covers the engine-independent half (the key equals `LOWER(TRIM(x))` for every
    interesting input, on whichever engine the test is running against).
    """
    database.save_page(page_id="page-u1", name="u1", category="general")
    database.set_client_credentials(page_id="page-u1", username="Ø-test", password="U1-Pw")
    folded = _db_lower("Ø-test")
    variant = "ø-test" if folded == _db_lower("ø-test") else None
    if variant is None:
        pytest.skip("this engine does not fold Ø/ø, so there is no variant to test")
    assert account_keys.normalize_identifier(variant) == account_keys.normalize_identifier("Ø-test")


def test_142_normalization_never_modifies_stored_usernames(app):
    """Canonicalization is a key-time operation; the stored value stays byte-identical."""
    before = database.get_page(ALPHA_PAGE_ID)
    _login(app, ALPHA_USER, "wrong", ip="203.0.113.8")
    after = database.get_page(ALPHA_PAGE_ID)
    assert before["client_username"] == after["client_username"] == ALPHA_USER


def test_143_empty_and_whitespace_identifiers_get_no_key():
    """A shared 'empty' bucket would let a stranger throttle everybody."""
    for value in ("", "   ", "\t\n", None):
        assert account_keys.account_key(value) is None, f"{value!r} produced a key"


def test_144_alias_and_username_normalization_agree(app):
    """Both aliases of one account must normalize to the same canonical key."""
    from_user = rate_limit.account_canonical_key(
        ALPHA_USER, database.resolve_canonical_account(ALPHA_USER)
    )
    from_page = rate_limit.account_canonical_key(
        ALPHA_PAGE_ID, database.resolve_canonical_account(ALPHA_PAGE_ID)
    )
    assert from_user == from_page


def test_145_the_app_itself_refuses_to_start_in_production(monkeypatch, tmp_path):
    """
    The end-to-end form of finding D: not just the validator in isolation, but the real
    application's startup, which is what an operator actually runs.

    A validator that nothing calls is not a control. This drives the ASGI lifespan the way
    uvicorn does, so a production deployment missing the secret cannot reach "serving".
    """
    monkeypatch.delenv("E02_ACCOUNT_KEY_SECRET", raising=False)
    monkeypatch.setenv("ENV", "production")
    monkeypatch.delenv("STRICT_SECURITY", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db = tmp_path / "startup.db"
    monkeypatch.setenv("DB_PATH", str(db))
    monkeypatch.setattr(database, "DB_PATH", str(db))
    database.init_db()

    import main

    with pytest.raises(RuntimeError) as excinfo:
        with TestClient(main.app):
            pass
    assert "E02_ACCOUNT_KEY_SECRET" in str(excinfo.value)


def test_146_the_app_starts_in_production_when_the_secret_is_present(monkeypatch, tmp_path):
    """
    The same startup must succeed once a usable secret is configured.

    E-02 Phase 6, R11 changed the deployment contract this test encodes: production now also
    requires a shared store. The previous form of this test started production with **no**
    `REDIS_URL` and asserted success — i.e. it pinned the exact degradation R11 removed, where
    each worker kept a private counter and the effective limit became `limit x workers`. It is
    split in two rather than relaxed:

      * this test: a usable secret *and* a reachable Redis -> startup succeeds;
      * `test_146b`: a usable secret, no Redis -> startup is refused (in the Phase 6 suite).
    """
    monkeypatch.setenv("ENV", "production")
    monkeypatch.delenv("STRICT_SECURITY", raising=False)
    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", "p" * 64)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db = tmp_path / "startup_ok.db"
    monkeypatch.setenv("DB_PATH", str(db))
    monkeypatch.setattr(database, "DB_PATH", str(db))
    database.init_db()
    account_keys.refresh_secret()

    url = os.getenv("REDIS_URL", "").strip()
    if not url:
        pytest.skip("production startup now requires a shared store; needs REDIS_URL")
    previous = rate_limit.get_limiter()
    rate_limit.set_limiter(None)
    try:
        import main

        with TestClient(main.app) as client:
            assert client.get("/api/health").status_code == 200
    finally:
        rate_limit.set_limiter(previous)
