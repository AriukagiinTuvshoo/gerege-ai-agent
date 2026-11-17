"""
Stage E — E-02 Phase 4: account-level failed-login protection.

Written before the implementation, and expected to FAIL until it exists.

The gap this closes
-------------------
Phase 3 made the *client IP* trustworthy. It did not stop an attacker who ignores IPs
entirely: rotating the source address gives a fresh per-IP budget every time, so attempts
against ONE account are bounded only by request rate. The Phase 2 suite proves this — 40
attempts on one account from 40 source IPs were all accepted.

Design decisions asserted by these tests (see docs/audit/E02_LOGIN_RATE_LIMIT.md §12)
----------------------------------------------------------------------------------------
* Identity normalization mirrors the real lookup, which is
  `LOWER(TRIM(client_username))`. Login is ALREADY case-insensitive, so casefolding the
  account key does not merge accounts that the database treats as distinct.
* Keys are a keyed HMAC-SHA256 (blake2b) digest under a server secret. A plain SHA-256 of a
  username is not acceptable — usernames are low-entropy, so an unkeyed hash is reversible
  by dictionary. No secret configured means NO account keying at all (fail closed on
  privacy, never an unkeyed fallback).
* The account counter is separate from the IP counter: successful authentication clears the
  account failures and must NOT clear the IP counter.
* Throttling is temporary, never a hard lockout, so an attacker cannot permanently deny the
  owner access by burning the budget.

Counting note: this file has 30 test functions; parametrisation expands them to more
collected cases. Both numbers are reported separately.
"""
import hmac as hmac_mod
import os
import subprocess
import sys
import textwrap
import threading
import time

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402
from core import rate_limit  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ACME = "Acme-Mn"
ACME_PW = "Acme-Pass-2026"
GLOBEX = "Globex-Mn"
GLOBEX_PW = "Globex-Pass-2026"

#: Names mirroring the real module constants, with a clear failure if they are absent.
def _account_policy():
    threshold = getattr(rate_limit, "ACCOUNT_FAILURE_THRESHOLD", None)
    window = getattr(rate_limit, "ACCOUNT_FAILURE_WINDOW", None)
    assert threshold is not None and window is not None, (
        "E-02: core.rate_limit defines no account-level policy (ACCOUNT_FAILURE_THRESHOLD / "
        "ACCOUNT_FAILURE_WINDOW). There is no account-level failed-login protection."
    )
    return threshold, window


TEST_SECRET = "e02-test-account-key-secret-0123456789"


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    """Fresh DB and a fresh limiter store, with a real peer IP per request."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db = tmp_path / "e02p4.db"
    monkeypatch.setenv("DB_PATH", str(db))
    monkeypatch.setattr(database, "DB_PATH", str(db))
    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    database.init_db()

    for page_id, user, pw in ((ACME, ACME, ACME_PW), (GLOBEX, GLOBEX, GLOBEX_PW)):
        database.save_page(page_id=page_id, name=page_id, category="general")
        database.set_client_credentials(page_id=page_id, username=user, password=pw)

    import main

    previous = rate_limit.get_limiter()
    rate_limit.set_limiter(rate_limit.RateLimiter(redis_url=""))
    try:
        # `main.app` — not the module. TestClient(module) answers 500 to every request.
        yield main.app
    finally:
        rate_limit.set_limiter(previous)


def _client(app, ip):
    """
    A client whose TCP peer really is `ip`.

    This matters: TestClient defaults to `("testclient", 50000)`, which `resolve_client_ip`
    cannot parse, so the IP identity becomes the literal string "unknown". Every request
    would then share one IP bucket and the tests would be measuring the wrong thing.
    """
    return TestClient(app, raise_server_exceptions=False, client=(ip, 41000))


def _login(client, identifier, password):
    return client.post(
        "/api/auth/login",
        json={"type": "client", "identifier": identifier, "password": password},
    )


# ---------------------------------------------------------------------------
# Account identity and normalization (tests 1-8)
# ---------------------------------------------------------------------------
def test_31_same_account_same_ip_is_throttled(app_client):
    """The baseline: repeated failures from one IP on one account must eventually stop."""
    threshold, _ = _account_policy()
    c = _client(app_client, "203.0.113.1")
    codes = [_login(c, ACME, "wrong").status_code for _ in range(threshold + 5)]
    assert 429 in codes, f"no throttling after {len(codes)} failures: {set(codes)}"
    assert codes.index(429) >= 1, "the very first attempt must not be throttled"


def test_32_same_account_different_ips_is_throttled(app_client):
    """
    The core requirement. One account, a different real source IP per attempt, so no
    per-IP budget can ever be exhausted.
    """
    threshold, _ = _account_policy()
    codes = []
    for i in range(threshold + 8):
        codes.append(_login(_client(app_client, f"198.51.100.{i + 1}"), ACME, "wrong").status_code)
    assert 429 in codes, (
        f"E-02: {len(codes)} failures against one account from {len(codes)} distinct source "
        "IPs were all accepted; there is no account-level protection"
    )


def test_33_rotating_x_forwarded_for_still_hits_the_account_limit(app_client):
    """Rotating XFF with no trusted proxy must not help either."""
    threshold, _ = _account_policy()
    codes = []
    for i in range(threshold + 8):
        c = _client(app_client, "203.0.113.200")
        codes.append(
            c.post(
                "/api/auth/login",
                json={"type": "client", "identifier": ACME, "password": "wrong"},
                headers={"X-Forwarded-For": f"10.{i}.0.1"},
            ).status_code
        )
    assert 429 in codes, f"rotating X-Forwarded-For bypassed the account limit: {set(codes)}"


@pytest.mark.parametrize("header", ["X-Real-IP", "Forwarded"])
def test_34_rotating_other_forwarding_headers_still_hits_the_account_limit(app_client, header):
    threshold, _ = _account_policy()
    codes = []
    for i in range(threshold + 8):
        value = f"10.{i}.0.9" if header == "X-Real-IP" else f"for=10.{i}.0.9"
        codes.append(
            _client(app_client, "203.0.113.201")
            .post(
                "/api/auth/login",
                json={"type": "client", "identifier": ACME, "password": "wrong"},
                headers={header: value},
            )
            .status_code
        )
    assert 429 in codes, f"rotating {header} bypassed the account limit: {set(codes)}"


def test_35_different_accounts_do_not_share_a_counter(app_client):
    """
    Burning one account's budget must not throttle another account from the same IP.

    Without this, an attacker could deny service to every tenant at once.
    """
    threshold, _ = _account_policy()
    # Rotate the source IP: burning the budget from ONE address would also exhaust the
    # per-IP limit (10/60s), which is a different layer doing its job. The point here is
    # that the *account* counter for ACME must not block GLOBEX.
    for i in range(threshold + 3):
        _login(_client(app_client, f"203.0.113.{i + 1}"), ACME, "wrong")
    assert rate_limit.get_account_failure_count(ACME) > threshold

    victim = _client(app_client, "203.0.113.50")
    r = _login(victim, GLOBEX, GLOBEX_PW)
    assert r.status_code == 200, (
        f"another account was blocked (status {r.status_code}); the account counters are not "
        "isolated"
    )


@pytest.mark.parametrize(
    "variant",
    [ACME, ACME.lower(), ACME.upper(), f"  {ACME}  ", ACME.title(), ACME.swapcase()],
)
def test_36_username_spelling_variants_share_one_budget(app_client, variant):
    """
    Normalization must match the real lookup (`LOWER(TRIM(client_username))`), otherwise
    each spelling is a separate account and the budget multiplies.
    """
    threshold, _ = _account_policy()
    codes = []
    for i in range(threshold + 8):
        codes.append(_login(_client(app_client, f"192.0.2.{i + 1}"), variant, "wrong").status_code)
    assert 429 in codes, f"spelling {variant!r} opened a separate budget: {set(codes)}"


def test_37_normalization_does_not_merge_distinct_accounts(app_client, monkeypatch):
    """
    The other side of normalization: two genuinely different accounts must stay separate.

    `Acme-Mn` and `Acme.Mn` differ by a character that casefolding and stripping do not
    touch, so draining one must not throttle the other.
    """
    threshold, _ = _account_policy()
    database.save_page(page_id="Acme.Mn", name="Other", category="general")
    database.set_client_credentials(page_id="Acme.Mn", username="Acme.Mn", password="Other-Pass-1")

    for i in range(threshold + 3):
        _login(_client(app_client, f"192.0.2.{i + 1}"), ACME, "wrong")

    r = _login(_client(app_client, "203.0.113.77"), "Acme.Mn", "Other-Pass-1")
    assert r.status_code == 200, (
        "a distinct account was throttled because normalization merged it with another; "
        f"status {r.status_code}"
    )


def test_38_empty_and_malformed_identifiers_do_not_crash_the_limiter(app_client):
    """Junk input must be counted or rejected, never raise."""
    for bad in ("", "   ", "\x00", "a" * 5000, "üñï©ødé", "../../etc/passwd", "@@@@"):
        r = _login(_client(app_client, "203.0.113.9"), bad, "wrong")
        assert r.status_code in (400, 401, 422, 429), f"{bad!r} produced {r.status_code}"


# ---------------------------------------------------------------------------
# Privacy of the account key (tests 9-11)
# ---------------------------------------------------------------------------
def test_39_account_key_contains_no_plaintext_username(app_client):
    """
    Keys live in Redis, in the memory store, and in any `SCAN` an operator runs. A plaintext
    username there is a leak of the customer list.
    """
    _account_policy()
    for i in range(3):
        _login(_client(app_client, f"203.0.113.{i + 60}"), ACME, "wrong")

    store = rate_limit.get_limiter()._store
    keys = list(getattr(store, "_counters", {}).keys())
    account_keys = [k for k in keys if "account" in k]
    assert account_keys, "no account-scoped key was created"
    for k in account_keys:
        assert ACME.lower() not in k.lower(), f"plaintext username in key: {k!r}"
        assert "acme" not in k.lower(), f"plaintext username in key: {k!r}"


def test_40_account_key_is_keyed_and_differs_from_a_plain_hash(app_client):
    """
    A bare SHA-256 of a username is reversible by dictionary, so it is not a privacy
    mechanism. The key must be a keyed digest.
    """
    _account_policy()
    import hashlib

    account_key = rate_limit.account_rate_limit_key(ACME)
    plain_sha = hashlib.sha256(ACME.lower().encode()).hexdigest()
    assert plain_sha not in account_key, (
        "the account key is an unkeyed SHA-256 of the username, which is reversible for "
        "low-entropy usernames"
    )
    # And it must actually be keyed: changing the secret changes the key.
    os.environ["E02_ACCOUNT_KEY_SECRET"] = "a-completely-different-secret-9876543210"
    rate_limit.refresh_account_key_secret()
    try:
        other = rate_limit.account_rate_limit_key(ACME)
        assert other != account_key, "the key does not depend on the secret"
    finally:
        os.environ["E02_ACCOUNT_KEY_SECRET"] = TEST_SECRET
        rate_limit.refresh_account_key_secret()


def test_41_no_usable_secret_means_no_account_keying(monkeypatch):
    """
    Fail closed on privacy. Without a secret there must be NO account key derived — never a
    silent unkeyed hash, which would leak the username.
    """
    monkeypatch.delenv("E02_ACCOUNT_KEY_SECRET", raising=False)
    rate_limit.refresh_account_key_secret()
    assert rate_limit.account_rate_limit_key(ACME) is None, (
        "a key was produced without a configured secret; that can only be an unkeyed hash"
    )


# ---------------------------------------------------------------------------
# Counter behaviour (tests 12-19)
# ---------------------------------------------------------------------------
def test_42_failed_login_increments_the_account_counter(app_client):
    _account_policy()
    c = _client(app_client, "203.0.113.30")
    before = rate_limit.get_account_failure_count(ACME)
    _login(c, ACME, "wrong")
    after = rate_limit.get_account_failure_count(ACME)
    assert after == before + 1, f"counter did not increment ({before} -> {after})"


def test_43_threshold_produces_temporary_throttling_not_lockout(app_client):
    """
    Throttled != locked. The response must be a rate-limit refusal with a bounded
    `Retry-After`, not a permanent denial.
    """
    threshold, window = _account_policy()
    codes = []
    for i in range(threshold + 6):
        codes.append(_login(_client(app_client, f"203.0.113.{i + 100}"), ACME, "wrong").status_code)
    assert 429 in codes
    index = codes.index(429)
    assert index >= threshold - 1, (
        f"throttled after only {index} failures but the threshold is {threshold}"
    )
    assert window <= 3600, f"the throttle window {window}s is long enough to be a lockout"


def test_44_counter_expires(app_client):
    """The counter must be time-bounded so the owner recovers without intervention."""
    _account_policy()
    clock = _Clock()
    previous = rate_limit.get_limiter()
    rate_limit.set_limiter(rate_limit.RateLimiter(redis_url="", clock=clock))
    try:
        for i in range(3):
            _login(_client(app_client, f"203.0.113.{i + 120}"), ACME, "wrong")
        assert rate_limit.get_account_failure_count(ACME) >= 3
        clock.advance(rate_limit.ACCOUNT_FAILURE_WINDOW + 1)
        assert rate_limit.get_account_failure_count(ACME) == 0, "the counter did not expire"
    finally:
        rate_limit.set_limiter(previous)


def test_45_successful_login_refunds_only_its_own_slot(app_client):
    """
    E-02 Phase 4.1 revised the reset semantics; this test was updated to match, and it is
    strictly stronger than before.

    Phase 4 deleted the whole counter on success. Under admission-then-verify ordering that
    cannot distinguish a failure recorded *after* the success was admitted, so it silently
    erased it (Phase 4.1 finding C). The guarantee now is: a success refunds exactly the one
    slot it consumed, and nothing else.

    So N failures followed by a success leave N — not 0 — and the assertion below pins that
    exact value, which the old "== 0" did not: "== 0" was also satisfied by a build that
    erased a concurrent failure.
    """
    threshold, _ = _account_policy()
    failures = threshold - 2
    for i in range(failures):
        _login(_client(app_client, f"203.0.113.{i + 130}"), ACME, "wrong")
    assert rate_limit.get_account_failure_count(ACME) == failures

    r = _login(_client(app_client, "203.0.113.180"), ACME, ACME_PW)
    assert r.status_code == 200, f"legitimate login failed: {r.status_code} {r.text}"
    assert rate_limit.get_account_failure_count(ACME) == failures, (
        "a successful login must refund the one slot it consumed and leave every earlier "
        "failure recorded"
    )


def test_46_successful_login_does_not_reset_the_ip_counter(app_client):
    """
    If success cleared the IP counter, an attacker holding one valid credential could
    launder an abusive source address indefinitely.
    """
    limiter = rate_limit.get_limiter()
    c = _client(app_client, "203.0.113.190")
    for _ in range(3):
        _login(c, ACME, "wrong")

    ip_scope = "ratelimit:auth_login:203.0.113.190"
    before = limiter.peek(ip_scope, 60)
    assert before == 3, f"expected the IP counter at 3, found {before}"
    account_before = rate_limit.get_account_failure_count(ACME)
    assert account_before == 3

    assert _login(c, ACME, ACME_PW).status_code == 200

    # The successful request is itself one more request from this IP, so the IP counter is
    # expected to be 4 — what must NOT happen is a reset to 0.
    after = limiter.peek(ip_scope, 60)
    assert after == before + 1, (
        f"the IP counter went {before} -> {after}; a successful login must not clear the IP "
        "counter (only the account counter)"
    )
    # The account counter is unchanged: the successful login's own admission (+1) is
    # immediately refunded (-1), so the failures recorded before it remain. What must NOT
    # happen is a drop to 0, which is what deleting the whole key would do.
    assert rate_limit.get_account_failure_count(ACME) == account_before, (
        f"the account counter went {account_before} -> "
        f"{rate_limit.get_account_failure_count(ACME)}; a success must refund exactly its own "
        "admission and leave earlier failures recorded"
    )


def test_47_unknown_username_is_also_counted(app_client):
    """
    An unknown account must follow the same protective path, or an attacker learns which
    names exist by watching which ones start returning 429.
    """
    threshold, _ = _account_policy()
    codes = []
    for i in range(threshold + 6):
        codes.append(_login(_client(app_client, f"203.0.113.{i + 140}"), "ghost-account-xyz", "wrong").status_code)
    assert 429 in codes, f"an unknown account was never throttled: {set(codes)}"


# ---------------------------------------------------------------------------
# Concurrency, atomicity, multi-process, restart (tests 20-26)
# ---------------------------------------------------------------------------
def test_48_concurrent_failures_are_counted_atomically(app_client):
    """Concurrent increments must not under-count."""
    threshold, _ = _account_policy()
    errors = []
    lock = threading.Lock()

    def attempt(i):
        try:
            _login(_client(app_client, f"198.18.{i}.1"), ACME, "wrong")
        except Exception as exc:  # noqa: BLE001
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(threshold + 10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"concurrent logins raised: {errors[:3]}"
    assert rate_limit.get_account_failure_count(ACME) >= threshold, (
        f"only {rate_limit.get_account_failure_count(ACME)} of {len(threads)} concurrent "
        "failures were counted"
    )


def test_49_account_counter_is_shared_across_processes(tmp_path):
    """
    Two real interpreter processes against one Redis. Skipped without REDIS_URL, because a
    shared counter cannot be demonstrated inside one process.
    """
    redis_url = os.getenv("REDIS_URL", "").strip()
    if not redis_url:
        pytest.skip("needs REDIS_URL: a shared counter cannot be proven in one process")

    from core.rate_limit import RateLimiter

    RateLimiter(redis_url=redis_url).reset("auth_account")
    threshold, _ = _account_policy()
    script = textwrap.dedent(
        f"""
        import os, sys
        sys.path.insert(0, {REPO_ROOT!r})
        os.environ.pop("DATABASE_URL", None)
        os.environ["DB_PATH"] = {str(tmp_path / 'shared.db')!r}
        os.environ["REDIS_URL"] = {redis_url!r}
        os.environ["E02_ACCOUNT_KEY_SECRET"] = {TEST_SECRET!r}
        os.environ.setdefault("ADMIN_PASSWORD", "P4-Test-Pw-2026")
        import database, main
        from fastapi.testclient import TestClient
        from core import rate_limit
        rate_limit.set_limiter(rate_limit.RateLimiter(redis_url={redis_url!r}))
        os.environ.pop("DB_PATH")
        database.DB_PATH = {str(tmp_path / 'shared.db')!r}
        from core.schema_manager import ensure_schema
        ensure_schema()
        database.save_page(page_id="Shared", name="Shared", category="general")
        database.set_client_credentials(page_id="Shared", username="Shared", password="x")
        c = TestClient(main.app, raise_server_exceptions=False)
        blocked = 0
        for i in range({threshold}):
            r = c.post("/api/auth/login", json={{"type": "client", "identifier": "Shared",
                       "password": "wrong"}})
            if r.status_code == 429:
                blocked += 1
        print("BLOCKED", blocked)
        """
    )
    runs = [
        subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                       timeout=240, cwd=REPO_ROOT)
        for _ in range(2)
    ]
    for r in runs:
        assert r.returncode == 0, f"subprocess failed: {r.stderr[-900:]}"

    blocked = sum(int(r.stdout.split("BLOCKED")[-1].strip()) for r in runs)
    assert blocked > 0, (
        f"E-02: two processes made {2 * threshold} failures against one account through one "
        "Redis and none was throttled; the account counter is not shared"
    )


def test_50_account_counter_survives_a_restart():
    """A process-local dict is lost on every deploy — exactly what an attacker wants."""
    redis_url = os.getenv("REDIS_URL", "").strip()
    if not redis_url:
        pytest.skip("needs REDIS_URL: restart-safety cannot be shown with a memory store")
    from core.rate_limit import RateLimiter

    first = RateLimiter(redis_url=redis_url)
    first.reset("auth_account")
    for _ in range(5):
        first.check("auth_account", rate_limit.account_rate_limit_key(ACME) or "x", 1000, 900)

    second = RateLimiter(redis_url=redis_url)  # stands in for a fresh worker
    result = second.check("auth_account", rate_limit.account_rate_limit_key(ACME) or "x", 1000, 900)
    assert result["count"] == 6, f"a restarted limiter saw count={result['count']}, expected 6"
    second.reset("auth_account")


def test_51_success_does_not_erase_a_newer_failure(app_client):
    """
    A failure recorded after a successful login must survive it.

    This is the concrete form of Phase 4.1 finding C. Under whole-key deletion the counter
    went back to 0 and the later failure was lost; under refund-on-success it stays counted.
    The exact value is asserted, so a revert to deletion fails here.
    """
    _account_policy()
    c = _client(app_client, "203.0.113.210")
    _login(c, ACME, "wrong")
    _login(c, ACME, "wrong")
    assert rate_limit.get_account_failure_count(ACME) == 2
    assert _login(c, ACME, ACME_PW).status_code == 200
    # Two failures consumed two slots; the success refunds only its own.
    assert rate_limit.get_account_failure_count(ACME) == 2, (
        "the successful login cleared failures it did not own"
    )

    _login(c, ACME, "wrong")
    assert rate_limit.get_account_failure_count(ACME) == 3, (
        "the failure after a successful login was lost"
    )


def test_52_counters_are_bounded_and_expire(monkeypatch):
    """Keys must carry a TTL, so a hostile client cannot grow storage without limit."""
    redis_url = os.getenv("REDIS_URL", "").strip()
    if not redis_url:
        pytest.skip("needs REDIS_URL to inspect a real TTL")
    import redis

    _account_policy()
    client = redis.from_url(redis_url, decode_responses=True)
    key = rate_limit.account_rate_limit_key(ACME)
    limit, window = rate_limit.ACCOUNT_FAILURE_THRESHOLD, rate_limit.ACCOUNT_FAILURE_WINDOW
    limiter = rate_limit.RateLimiter(redis_url=redis_url)
    limiter.check("auth_account", key, limit, window)
    full = f"ratelimit:auth_account:{key}"
    ttl = client.ttl(full)
    assert 0 < ttl <= window, f"TTL is {ttl}, expected between 1 and {window}"
    client.delete(full)


# ---------------------------------------------------------------------------
# Enumeration protection (tests 27-30)
# ---------------------------------------------------------------------------
def test_53_unknown_account_and_wrong_password_are_indistinguishable(app_client):
    existing = _login(_client(app_client, "203.0.113.220"), ACME, "wrong")
    missing = _login(_client(app_client, "203.0.113.221"), "no-such-account-at-all", "wrong")
    assert existing.status_code == missing.status_code, (
        f"status differs by account existence ({existing.status_code} vs {missing.status_code})"
    )
    assert existing.json() == missing.json(), (
        f"body differs by account existence: {existing.json()} vs {missing.json()}"
    )


def test_54_throttled_response_does_not_reveal_account_existence(app_client):
    """
    Throttling must not become the oracle that the error message no longer is. A known
    account and an unknown one must reach 429 on the same attempt number.
    """
    threshold, _ = _account_policy()
    known, unknown = [], []
    for i in range(threshold + 6):
        known.append(_login(_client(app_client, f"198.19.{i}.1"), ACME, "wrong").status_code)
        unknown.append(_login(_client(app_client, f"198.19.{i}.2"), "ghost-xyz", "wrong").status_code)

    first_known = next((i for i, c in enumerate(known) if c == 429), None)
    first_unknown = next((i for i, c in enumerate(unknown) if c == 429), None)
    assert first_known == first_unknown, (
        f"throttling reveals account existence: known 429 at {first_known}, unknown at {first_unknown}"
    )


def test_55_password_verification_time_does_not_reveal_existence(app_client):
    """
    An unknown account that skips PBKDF2 answers ~6x faster than a real one (measured:
    6.3 ms vs 37.7 ms before this phase), which is a practical enumeration oracle.

    A dummy verification must run on the unknown path. It has to be a real PBKDF2 of the
    configured cost — not a sleep, and not a cheap hash.
    """
    def median_ms(identifier, n=9):
        samples = []
        for i in range(n):
            c = _client(app_client, f"203.0.113.{i + 230}")
            start = time.perf_counter()
            _login(c, identifier, "wrong")
            samples.append((time.perf_counter() - start) * 1000)
        samples.sort()
        return samples[len(samples) // 2]

    known = median_ms(ACME)
    unknown = median_ms("absent-account-timing")
    ratio = unknown / known if known else 0
    assert 0.5 <= ratio <= 2.0, (
        f"unknown accounts answer {known / unknown:.1f}x faster ({known:.1f} ms vs "
        f"{unknown:.1f} ms); the unknown path must do a dummy password verification"
    )


def test_56_logs_do_not_contain_plaintext_usernames(app_client, caplog):
    """Audit and application logs must not accumulate the customer list."""
    import logging

    with caplog.at_level(logging.DEBUG):
        for i in range(3):
            _login(_client(app_client, f"203.0.113.{i + 240}"), ACME, "wrong")

    text = "\n".join(r.getMessage() for r in caplog.records).lower()
    assert "acme-mn" not in text, "the plaintext username appears in logs"


# ---------------------------------------------------------------------------
# Regression guards for the layers below (tests 31-32)
# ---------------------------------------------------------------------------
def test_57_ip_limit_still_works_with_account_protection_in_place(app_client):
    """The IP limiter must not be replaced by the account limiter."""
    ip_codes = []
    for i in range(rate_limit.DEFAULT_LIMITS["auth_login"][0] + 5):
        ip_codes.append(
            _login(_client(app_client, "203.0.113.250"), f"tenant-{i}", "wrong").status_code
        )
    assert 429 in ip_codes, f"many accounts from one IP were never throttled: {set(ip_codes)}"


def test_58_successful_login_is_unaffected(app_client):
    r = _login(_client(app_client, "203.0.113.251"), ACME, ACME_PW)
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    assert body["token"]
    assert body["role"] in {"client", "manager", "agent", "read_only", "admin", "super_admin"}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
class _Clock:
    def __init__(self, now: float = 2_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds
