"""
Stage E — E-02 regression tests: login rate-limit bypass and account-level protection.

Status: written **before** the fix. Every test here is expected to FAIL on the current
code; the failing output is the evidence the audit report cites. Nothing in this file is
allowed to pass by accident — see "no vacuous tests" below.

Root cause being pinned
-----------------------
`core/rate_limit.py::client_identity()` builds the rate-limit key like this:

    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()      # left-most, client-controlled
    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip
    return request.client.host

There is **no trust check at all**: any client that sends `X-Forwarded-For: <random>` is
counted under `<random>`, so the `auth_login` limit of 10/60s is bypassed by rotating one
header. Separately, nothing anywhere counts failed logins per *account*, so an attacker
with a botnet (or just a rotating header) can spread attempts across identities and still
hammer one account.

A second, independent parser
----------------------------
`Dockerfile` runs `uvicorn main:app ... --workers 2` without `--forwarded-allow-ips`, and
uvicorn 0.54 defaults `proxy_headers=True` with `forwarded_allow_ips="127.0.0.1"`. Measured
against a live server, with the default trust list:

    XFF: 1.2.3.4            -> request.client.host == "1.2.3.4"   (port forced to 0)
    XFF: 1.1.1.1, 2.2.2.2   -> request.client.host == "2.2.2.2"   (RIGHT-most)
    X-Real-IP               -> request.client.host unchanged
    Forwarded: for=7.7.7.7  -> request.client.host unchanged

and uvicorn does **not** validate that the value is an IP address (`not-an-ip` is accepted
verbatim). So `request.client.host` is not the TCP peer when a peer is trusted, and the
framework and the application disagree about which element of the list is the client. Any
fix that just swaps `client_identity()` over to `request.client.host` is therefore a
deployment-dependent guess, not a fix.

No vacuous tests
----------------
A test that only asserts `status_code == 429` proves nothing: it passes if the endpoint
happens to fail, and it cannot distinguish "the limiter counted me" from "something else
broke". The tests below assert the underlying invariant instead — that the *counter for a
given identity actually increments*, that a spoofed identity does *not* open a fresh
budget, that two different accounts do not share a budget, and so on.

Every test talks to the single existing login endpoint through the HTTP surface. Nothing
here writes to the database to manufacture a bypass.
"""
import math
import os
import subprocess
import sys
import textwrap

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402
from core import rate_limit  # noqa: E402
from core.rate_limit import client_identity  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ACME_USER = "Acme-Mn"
ACME_PASS = "Acme-Pass-2026"
GLOBEX_USER = "Globex-Mn"
GLOBEX_PASS = "Globex-Pass-2026"

#: The configured login limit. Read from the code, not hard-coded, so a policy change
#: does not silently invalidate the tests.
LOGIN_LIMIT, LOGIN_WINDOW = rate_limit.DEFAULT_LIMITS["auth_login"]


def _redis_url() -> str:
    return os.getenv("REDIS_URL", "").strip()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    """A client backed by its own SQLite file and its own limiter store."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db = tmp_path / "e02.db"
    monkeypatch.setenv("DB_PATH", str(db))
    monkeypatch.setattr(database, "DB_PATH", str(db))
    database.init_db()

    for page_id, user, pw in ((ACME_USER, ACME_USER, ACME_PASS), (GLOBEX_USER, GLOBEX_USER, GLOBEX_PASS)):
        database.save_page(page_id=page_id, name=page_id, category="general")
        database.set_client_credentials(page_id=page_id, username=user, password=pw)

    import main

    return TestClient(main.app, raise_server_exceptions=False)


@pytest.fixture()
def fresh_limiter():
    """A private memory-backed limiter, so an assertion cannot be satisfied by leftovers."""
    limiter = rate_limit.RateLimiter(redis_url="")
    previous = rate_limit.get_limiter()
    rate_limit.set_limiter(limiter)
    try:
        yield limiter
    finally:
        rate_limit.set_limiter(previous)


def _login(client, username, password, headers=None, payload_type_override=None, **extra):
    payload = {
        "type": payload_type_override or "client",
        "identifier": username,
        "password": password,
    }
    payload.update(extra)
    return client.post("/api/auth/login", json=payload, headers=headers or {})


def _login_via_peer(app, username, password, peer_ip):
    """
    One login from a specific, real source address.

    `TestClient(app)` with no `client=` presents an unparseable peer, which collapses every
    request into the single IP identity "unknown". That is fine for testing the IP limiter's
    own behaviour, but it makes it impossible to isolate the account layer — so tests that
    vary the account must also vary the peer.
    """
    # `app_client` yields a TestClient, other callers may pass an ASGI app.
    app = getattr(app, "app", app)
    peer = TestClient(app, raise_server_exceptions=False, client=(peer_ip, 41000))
    return _login(peer, username, password)


def _login_failures_until_blocked(client, headers_for, max_attempts=40):
    """
    Drive failed logins, changing only the transport identity via `headers_for(i)`.

    Returns the number of attempts that were *not* blocked with 429. A correct IP-level
    limiter returns 429 within ``LOGIN_LIMIT`` attempts; a bypassed one never blocks.
    """
    allowed = 0
    for i in range(max_attempts):
        r = _login(client, ACME_USER, "definitely-wrong", headers=headers_for(i))
        if r.status_code == 429:
            return allowed
        allowed += 1
    return allowed


# ---------------------------------------------------------------------------
# Group A — Forwarded-IP trust (tests 1-7)
# ---------------------------------------------------------------------------
def test_01_rotating_x_forwarded_for_cannot_bypass_the_ip_limit(app_client, fresh_limiter):
    """
    Test 1. The audit's original bypass: a fresh `X-Forwarded-For` per request.

    Invariant: rotating the header must not buy unlimited attempts. Either the header is
    ignored (limit reached at ~10) or it is honoured only as a rate-limit key *and* the
    account limit still stops the run — but it must never yield ``max_attempts`` allowed.
    """
    allowed = _login_failures_until_blocked(
        app_client, lambda i: {"X-Forwarded-For": f"203.0.113.{i % 250}"}
    )
    assert allowed < 40, (
        f"E-02: {allowed} failed logins were accepted with a rotating X-Forwarded-For; "
        f"the configured login limit is {LOGIN_LIMIT}/{LOGIN_WINDOW}s. The limiter is being "
        "keyed on a client-controlled header with no trust check."
    )


def test_02_rotating_x_real_ip_cannot_bypass_the_ip_limit(app_client, fresh_limiter):
    """Test 2. Same invariant, rotating `X-Real-IP` instead."""
    allowed = _login_failures_until_blocked(
        app_client, lambda i: {"X-Real-IP": f"198.51.100.{i % 250}"}
    )
    assert allowed < 40, (
        f"E-02: {allowed} failed logins were accepted with a rotating X-Real-IP"
    )


def test_03_rotating_forwarded_header_cannot_bypass_the_ip_limit(app_client, fresh_limiter):
    """
    Test 3. RFC 7239 `Forwarded:` is honoured by some stacks; rotating it must not help.

    This test currently PASSES for the unhelpful reason that the code ignores `Forwarded:`
    entirely — uvicorn 0.54 also ignores it (measured: client.host unchanged). It is kept
    as a **regression guard**: a naive fix that starts parsing `Forwarded` without a trust
    check would introduce a new bypass, and this is what would catch it. The positive half
    of the policy is asserted in test_04.
    """
    allowed = _login_failures_until_blocked(
        app_client, lambda i: {"Forwarded": f"for=192.0.2.{i % 250}"}
    )
    assert allowed < 40, (
        f"E-02: {allowed} failed logins were accepted with a rotating Forwarded header"
    )


def test_04_forwarded_header_is_used_only_when_a_trusted_proxy_is_configured(fresh_limiter):
    """
    Test 4. Under an explicit trusted-proxy configuration, the forwarded value must be
    what the limiter keys on — otherwise a real deployment behind a load balancer would
    collapse every user into the proxy's IP and lock out the world.

    This asserts the *positive* half of the policy, so a fix that simply ignores all
    forwarding headers everywhere does not pass.
    """
    _apply_trusted_proxy_config(proxy_count=1, peer="10.1.2.3")
    try:
        assert _identity(peer="10.1.2.3", xff="203.0.113.77") == "203.0.113.77", (
            "E-02: with a trusted proxy configured, the forwarded client IP must be used"
        )
    finally:
        _clear_trusted_proxy_config()


def test_05_forwarding_headers_from_an_untrusted_peer_are_ignored(fresh_limiter):
    """
    Test 5. Send `X-Forwarded-For` from a peer that is NOT in the allowlist: the peer's own
    address must be the identity.
    """
    _apply_trusted_proxy_config(proxy_count=1, peer="10.1.2.3")
    try:
        assert _identity(peer="203.0.113.9", xff="1.2.3.4") == "203.0.113.9", (
            "E-02: a forwarding header from an untrusted peer was believed"
        )
    finally:
        _clear_trusted_proxy_config()


def test_06_multi_hop_forwarding_picks_the_client_and_ignores_spoofed_prefix(fresh_limiter):
    """
    Test 6. Two trusted hops. The attacker prepends a fake address.

    `X-Forwarded-For: 1.2.3.4, 203.0.113.50, 10.0.0.5` arriving from the outer trusted
    proxy means: client 203.0.113.50, then proxy 10.0.0.5. The left-most value is the
    attacker's own invention and must not be selected — that is exactly what the current
    implementation does.
    """
    _apply_trusted_proxy_config(proxy_count=2, peer="10.0.0.9")
    try:
        got = _identity(peer="10.0.0.9", xff="1.2.3.4, 203.0.113.50, 10.0.0.5")
        assert got == "203.0.113.50", (
            f"E-02: multi-hop identity resolved to {got!r}; a trusted-proxy walk from the "
            "right must skip trusted hops and stop at the first untrusted address"
        )
    finally:
        _clear_trusted_proxy_config()


def test_07_malformed_forwarding_headers_are_handled_safely(fresh_limiter):
    """
    Test 7. Empty, junk, over-long and deeply nested headers must not crash the limiter and
    must not let an attacker choose an arbitrary identity.

    Measured against uvicorn 0.54: it accepts `not-an-ip` verbatim, takes the right-most
    list element, and tolerates 3.6 KB of header. So "the proxy already parsed it" is not
    an argument — the app has to be defensive here.
    """
    _apply_trusted_proxy_config(proxy_count=1, peer="10.1.2.3")
    try:
        cases = [
            ("empty", "", "10.1.2.3"),
            ("whitespace", "   ", "10.1.2.3"),
            ("commas", ",,,", "10.1.2.3"),
            ("junk", "not-an-ip", "10.1.2.3"),
            # Over-long input is REJECTED, not parsed. Phase 3 bounds the header at
            # _MAX_FORWARDED_HEADER_BYTES precisely so a multi-kilobyte value cannot be
            # walked; falling back to the peer is the safe answer, and asserting
            # "203.0.113.5" here would have required raising the bound for no reason.
            ("over-long", "1.1.1.1, " * 500 + "203.0.113.5", "10.1.2.3"),
            # A chain within the byte budget but beyond the hop budget is also rejected.
            ("too-many-hops", ", ".join(["10.0.0.1"] * 20), "10.1.2.3"),
        ]
        for label, xff, expected in cases:
            got = _identity(peer="10.1.2.3", xff=xff)
            assert got == expected, (
                f"E-02: malformed header {label!r} produced identity {got!r}, expected "
                f"{expected!r} — junk must fall back to the peer, not become the key"
            )
    finally:
        _clear_trusted_proxy_config()


# ---------------------------------------------------------------------------
# Group B — Account-level protection (tests 8-14)
# ---------------------------------------------------------------------------
def test_08_account_is_protected_across_many_source_ips(app_client, fresh_limiter):
    """
    Test 8. The core requirement: one account, many source IPs.

    Every attempt uses a different source address, so no IP-level counter can ever reach
    its limit. The account must still be throttled.
    """
    allowed = _login_failures_until_blocked(
        app_client, lambda i: {"X-Forwarded-For": f"203.0.113.{i % 250}"}
    )
    assert allowed < 40, (
        f"E-02: {allowed} failed logins against ONE account from rotating IPs were all "
        "accepted. There is no account-level failed-login protection."
    )


def test_09_hundred_rotations_still_hit_the_account_limit(app_client, fresh_limiter):
    """Test 9. The audit's specific scenario, at 100 distinct X-Forwarded-For values."""
    allowed = 0
    for i in range(100):
        r = _login(app_client, ACME_USER, "wrong", headers={"X-Forwarded-For": f"10.{i // 256}.{i % 256}.7"})
        if r.status_code == 429:
            break
        allowed += 1
    assert allowed < 100, f"E-02: 100/100 failed logins accepted across 100 spoofed IPs"


def test_10_username_case_and_whitespace_variants_share_one_budget(app_client, fresh_limiter):
    """
    Test 10. `Acme-Mn`, ` acme-mn `, `ACME-MN` are the same account.

    Invariant: the union of attempts across all spellings must hit the limit at roughly the
    same total as a single spelling. If each spelling got its own budget, the effective
    limit would be multiplied by the number of spellings.
    """
    variants = [ACME_USER, ACME_USER.lower(), ACME_USER.upper(), f"  {ACME_USER}  ",
                ACME_USER.title(), ACME_USER.swapcase()]
    allowed = 0
    for i in range(40):
        r = _login(app_client, variants[i % len(variants)], "wrong",
                   headers={"X-Forwarded-For": f"203.0.113.{i}"})
        if r.status_code == 429:
            break
        allowed += 1
    # The budget belongs to the ACCOUNT, so cycling spellings must not multiply it. The
    # first version of this assertion allowed `len(variants) * LOGIN_LIMIT` and therefore
    # PASSED while 40/40 attempts were accepted — a vacuous test. Measured on the unfixed
    # code: 40 attempts in 40 tries, i.e. every spelling got its own budget.
    assert allowed <= LOGIN_LIMIT + 2, (
        f"E-02: {allowed} attempts accepted by cycling username spelling (single-spelling "
        f"budget is {LOGIN_LIMIT}); each variant is counted as a separate account"
    )


def test_11_unknown_account_and_wrong_password_are_indistinguishable(app_client, fresh_limiter):
    """
    Test 11. Account enumeration.

    The response must not reveal whether the account exists. Today
    `authenticate_client_detailed` returns `'X' нэртэй ... олдсонгүй` for an unknown user
    and `Нууц үг буруу байна!` for a wrong password — a textbook oracle.
    """
    existing = _login(app_client, ACME_USER, "wrong-password")
    missing = _login(app_client, "no-such-account-at-all", "wrong-password")

    assert existing.status_code == missing.status_code, (
        f"E-02: status differs by account existence ({existing.status_code} vs "
        f"{missing.status_code})"
    )
    assert existing.json().get("error") == missing.json().get("error"), (
        "E-02: the error message reveals whether the account exists: "
        f"{existing.json().get('error')!r} vs {missing.json().get('error')!r}"
    )


def test_11b_enumeration_oracle_is_not_available_through_any_login_type(app_client, fresh_limiter):
    """
    Test 11 (second half). The admin branch and the client branch must not differ in a way
    that discloses whether a *tenant* exists, and the magic-token branch must not leak it
    either.
    """
    known = _login(app_client, ACME_USER, "", payload_type_override="client")
    unknown = _login(app_client, "ghost-tenant-xyz", "", payload_type_override="client")
    assert known.json().get("error") == unknown.json().get("error"), (
        "E-02: empty-password response differs for known vs unknown tenant: "
        f"{known.json().get('error')!r} vs {unknown.json().get('error')!r}"
    )


def test_12_successful_login_refunds_only_its_own_slot(app_client, fresh_limiter):
    """
    Test 12. A legitimate user who mistypes a few times and then succeeds must not be treated
    as a brute-forcer — but their earlier mistyping is not erased either.

    Policy asserted: a successful login refunds exactly the one slot it consumed and leaves
    every earlier failure recorded. Success must NOT clear the IP counter (that would let an
    attacker with one valid credential launder an abusive IP), and — as of E-02 Phase 4.1 — it
    must not clear the *account* counter either, because deleting the counter cannot
    distinguish a failure recorded after the success was admitted and would silently erase it.

    History of this test, both defects recorded rather than quietly patched:
      * Phase 2 version: every request shared the IP identity "unknown", so the IP limiter
        decided the outcome and it failed for the wrong reason.
      * Phase 4 version: with a realistic peer it asserted `== threshold` attempts after a
        success, which is only true if the whole counter is deleted — the very behaviour
        Phase 4.1 identifies as losing concurrent failures. It is now `== threshold - spent`,
        the count a refund-only implementation produces, so a revert to deletion fails here.
    See docs/audit/E02_LOGIN_RATE_LIMIT.md section 4.3 and
    docs/audit/evidence/e02_phase41_before.txt.
    """
    threshold = rate_limit.ACCOUNT_FAILURE_THRESHOLD
    spent = threshold - 3

    # (a) Spend most of the budget, one distinct peer per attempt so the per-IP limit can
    # never be what decides the outcome.
    for i in range(spent):
        r = _login_via_peer(app_client, ACME_USER, "wrong", f"203.0.113.{i + 1}")
        assert r.status_code == 401, (
            f"attempt {i + 1} of {spent} answered {r.status_code}; it is below the threshold "
            f"{threshold} and must not be throttled"
        )

    # (b) The real user now remembers the password.
    ok = _login_via_peer(app_client, ACME_USER, ACME_PASS, "203.0.113.249")
    assert ok.status_code == 200, f"legitimate login blocked: {ok.status_code} {ok.text}"

    # (c) The `spent` failures remain recorded; only the successful login's own admission was
    # refunded. So exactly `threshold - spent` attempts are admitted before the next 429.
    # A whole-key reset would admit `threshold`; no account layer at all would never throttle.
    allowed = 0
    for i in range(threshold + 5):
        r = _login_via_peer(app_client, ACME_USER, "wrong", f"198.51.100.{i + 1}")
        if r.status_code == 429:
            break
        allowed += 1
    remaining = threshold - spent
    assert allowed == remaining, (
        f"E-02: after a successful login {allowed} further attempts were allowed, expected "
        f"exactly {remaining}. {threshold} means the successful login erased the earlier "
        f"failures (and any failure recorded concurrently with it); more than {remaining} means "
        f"the counter was cleared; fewer means the failures were double-counted."
    )


def test_13_concurrent_failed_logins_are_counted_accurately(app_client, fresh_limiter):
    """
    Test 13. 30 concurrent wrong passwords for one account.

    Invariant: concurrent increments must not under-count. A read-modify-write without
    atomicity (or a per-request retry) lets a burst slip past the limit. The store must
    report at least ``LOGIN_LIMIT`` increments.
    """
    import threading

    results = []
    lock = threading.Lock()

    def attempt(i):
        r = _login(app_client, ACME_USER, "wrong", headers={"X-Forwarded-For": f"203.0.113.{i}"})
        with lock:
            results.append(r.status_code)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(30)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    blocked = results.count(429)
    assert blocked > 0, (
        f"E-02: none of 30 concurrent failed logins was blocked (statuses: {sorted(set(results))})"
    )
    assert len(results) == 30


def test_14_account_protection_is_shared_across_processes(tmp_path):
    """
    Test 14. Two real interpreter processes, one Redis, one account.

    This is the only way to prove the guarantee: the production image runs
    `uvicorn --workers 2` plus a separate worker container, so an in-process counter is
    simply not the thing being relied on. Skipped without REDIS_URL (CI supplies it).
    """
    if not _redis_url():
        pytest.skip("needs REDIS_URL: a shared counter cannot be proven in one process")

    db_path = tmp_path / "shared.db"
    script = textwrap.dedent(
        f"""
        import os, sys
        sys.path.insert(0, {REPO_ROOT!r})
        os.environ.pop("DATABASE_URL", None)
        os.environ["DB_PATH"] = {str(db_path)!r}
        os.environ["REDIS_URL"] = {_redis_url()!r}
        os.environ.setdefault("ADMIN_PASSWORD", "E02-Test-Pw-2026")
        import database, main
        from fastapi.testclient import TestClient
        from core import rate_limit
        rate_limit.set_limiter(rate_limit.RateLimiter(redis_url={_redis_url()!r}))
        database.init_db()
        database.save_page(page_id="Shared", name="Shared", category="general")
        database.set_client_credentials(page_id="Shared", username="Shared", password="Right-Pass-1")
        c = TestClient(main.app, raise_server_exceptions=False)
        blocked = 0
        for i in range(8):
            r = c.post("/api/auth/login", json={{"type": "client", "identifier": "Shared",
                       "password": "wrong"}},
                       headers={{"X-Forwarded-For": "203.0.113.%d" % i}})
            if r.status_code == 429:
                blocked += 1
        print("BLOCKED", blocked)
        """
    )
    from core.rate_limit import RateLimiter

    RateLimiter(redis_url=_redis_url()).reset("auth_login")
    runs = [subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                           timeout=180, cwd=REPO_ROOT) for _ in range(2)]
    for r in runs:
        assert r.returncode == 0, f"subprocess failed: {r.stderr[-800:]}"

    blocked = sum(int(r.stdout.split("BLOCKED")[-1].strip()) for r in runs)
    assert blocked > 0, (
        "E-02: two processes made 16 failed logins against one account through one Redis "
        "and none was blocked; the account counter is not shared"
    )


# ---------------------------------------------------------------------------
# Group C — Abuse resistance (tests 15-20)
# ---------------------------------------------------------------------------
def test_15_attacker_cannot_lock_a_victim_out_of_their_account(app_client, fresh_limiter):
    """
    Test 15. The DoS half of account lockout.

    An attacker who knows a username can burn its budget. A permanent hard lock would let
    them deny service indefinitely. Policy asserted: the block is *temporary* (bounded by a
    window) and the victim can still log in once it lapses, with the CORRECT password, even
    while the attacker keeps trying from another IP.

    The window is advanced with an injected clock rather than by sleeping.
    """
    clock = _AdvanceableClock()
    limiter = rate_limit.RateLimiter(redis_url="", clock=clock)
    rate_limit.set_limiter(limiter)
    try:
        # Attacker exhausts the account budget from rotating IPs.
        for i in range(LOGIN_LIMIT + 2):
            _login(app_client, ACME_USER, "wrong", headers={"X-Forwarded-For": f"203.0.113.{i}"})
        victim = _login(app_client, ACME_USER, ACME_PASS, headers={"X-Forwarded-For": "198.51.100.1"})
        assert victim.status_code == 429, "precondition: account should be throttled"

        # A bounded window must elapse, not a permanent lock.
        assert _ACCOUNT_LOCK_WINDOW <= 3600, "account lockout must be bounded by an hour or less"
        clock.advance(_ACCOUNT_LOCK_WINDOW + 1)

        recovered = _login(app_client, ACME_USER, ACME_PASS,
                           headers={"X-Forwarded-For": "198.51.100.1"})
        assert recovered.status_code == 200, (
            "E-02: the account did not recover after the lockout window — an attacker can "
            "deny service to any known username permanently"
        )
    finally:
        rate_limit.set_limiter(rate_limit.RateLimiter(redis_url=""))


def test_16_no_account_enumeration_through_the_throttle_response(app_client, fresh_limiter):
    """
    Test 16. Throttling must not itself become an oracle.

    If a known account starts returning 429 at attempt 10 while an unknown one never does,
    an attacker learns which usernames exist. Both must follow the same shape.
    """
    # Each probe uses its OWN source IP. Sharing one address lets the IP-level limiter
    # exhaust itself during the first loop and make the second loop look blocked from the
    # very first attempt — which has nothing to do with account enumeration.
    known_codes, unknown_codes = [], []
    for i in range(LOGIN_LIMIT + 3):
        known_codes.append(
            _login(app_client, ACME_USER, "wrong",
                   headers={"X-Forwarded-For": "203.0.113.10"}).status_code
        )
        unknown_codes.append(
            _login(app_client, "ghost-xyz", "wrong",
                   headers={"X-Forwarded-For": "198.51.100.20"}).status_code
        )

    first_429_known = next((i for i, c in enumerate(known_codes) if c == 429), None)
    first_429_unknown = next((i for i, c in enumerate(unknown_codes) if c == 429), None)
    assert first_429_known == first_429_unknown, (
        f"E-02: throttling reveals account existence — known 429 at attempt "
        f"{first_429_known}, unknown at {first_429_unknown}"
    )


def test_17_ip_limit_and_account_limit_are_independent(app_client, fresh_limiter):
    """
    Test 17. Both limits must exist and neither may substitute for the other.

    * One IP, many accounts: the IP limit must stop it even though no single account
      reaches its own threshold.
    * One account, many IPs: the account limit must stop it even though no IP does.
    """
    # (a) one IP, many accounts
    ip_blocked = 0
    for i in range(40):
        user = f"{ACME_USER}-{i}"
        r = _login(app_client, user, "wrong", headers={"X-Forwarded-For": "203.0.113.99"})
        if r.status_code == 429:
            ip_blocked += 1
            break
    assert ip_blocked, "E-02: 40 different accounts from ONE IP were never blocked"

    # (b) one account, many IPs
    rate_limit.set_limiter(rate_limit.RateLimiter(redis_url=""))
    acct_blocked = False
    for i in range(40):
        r = _login(app_client, ACME_USER, "wrong", headers={"X-Forwarded-For": f"198.51.100.{i % 250}"})
        if r.status_code == 429:
            acct_blocked = True
            break
    assert acct_blocked, "E-02: 40 attempts on ONE account from many IPs were never blocked"


def test_18_throttle_response_is_usable_by_a_client(app_client, fresh_limiter):
    """
    Test 18. A 429 must tell the client when to come back.

    Asserted: a `Retry-After` header exists, parses as a positive integer, and is not
    longer than the configured window (a client told to sleep for an hour will just retry
    or give up).
    """
    last = None
    for i in range(LOGIN_LIMIT + 3):
        last = _login(app_client, ACME_USER, "wrong", headers={"X-Forwarded-For": "203.0.113.5"})
        if last.status_code == 429:
            break
    assert last is not None and last.status_code == 429, "precondition: expected a 429"

    retry_after = last.headers.get("Retry-After")
    assert retry_after is not None, "E-02: 429 response has no Retry-After header"
    retry_after = retry_after.strip()
    assert retry_after.isdigit(), f"Retry-After is not an integer number of seconds: {retry_after!r}"
    seconds = int(retry_after)
    assert 0 < seconds <= max(LOGIN_WINDOW, _ACCOUNT_LOCK_WINDOW), (
        f"Retry-After of {seconds}s is outside the configured window"
    )


def test_19_failure_then_success_does_not_corrupt_the_counter(app_client, fresh_limiter):
    """
    Test 19. Interleaving must not produce a wrong verdict.

    Sequence: N failures, one success, then confirm the account counter was reset while a
    subsequent genuine flood is *still* blocked. A counter that just goes to zero on
    success and never increments again would pass a naive test but fail the second half.
    """
    for i in range(LOGIN_LIMIT - 1):
        _login(app_client, ACME_USER, "wrong", headers={"X-Forwarded-For": f"203.0.113.{i}"})
    assert _login(app_client, ACME_USER, ACME_PASS,
                  headers={"X-Forwarded-For": "203.0.113.201"}).status_code == 200

    blocked = False
    for i in range(LOGIN_LIMIT + 5):
        r = _login(app_client, ACME_USER, "wrong", headers={"X-Forwarded-For": f"192.0.2.{i}"})
        if r.status_code == 429:
            blocked = True
            break
    assert blocked, "E-02: after a reset the account counter no longer blocks at all"


def test_20_account_state_survives_an_app_restart(tmp_path):
    """
    Test 20. Restart resilience.

    A process-local dict is lost on every deploy, worker recycle or crash — which is
    precisely what an attacker wants. Asserted: with a shared store configured, the failure
    count is still visible to a *fresh* limiter instance built from the same configuration.
    Skipped without REDIS_URL.
    """
    if not _redis_url():
        pytest.skip("needs REDIS_URL: restart-safety cannot be shown with a memory store")

    key = "e02-restart-probe"
    first = rate_limit.RateLimiter(redis_url=_redis_url())
    first.reset(key)
    for _ in range(5):
        first.check(key, "acct", 100, 60)

    # A brand new instance stands in for a freshly started worker.
    second = rate_limit.RateLimiter(redis_url=_redis_url())
    result = second.check(key, "acct", 100, 60)
    assert result["count"] == 6, (
        f"E-02: a restarted limiter saw count={result['count']} instead of 6; counter "
        "state did not survive the restart"
    )
    second.reset(key)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
#: Policy the fix is expected to adopt. Declared here so the tests encode the requirement
#: rather than whatever the implementation happens to do.
_ACCOUNT_LOCK_WINDOW = 15 * 60


class _AdvanceableClock:
    """A clock the test moves by hand, so lockout expiry needs no sleeping."""

    def __init__(self, now: float = 1_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


_ORIGINAL_TRUSTED_PROXIES_ENV = "TRUSTED_PROXIES"


def _apply_trusted_proxy_config(proxy_count: int, peer: str) -> None:
    """
    Configure the trusted-proxy policy.

    Phase 3 implemented this as `TRUSTED_PROXIES` (environment-only, per the strict scope),
    so the helper drives that. It is kept in one place so a future change to the
    configuration surface fails once, clearly, instead of across six call sites.
    """
    refresh = getattr(rate_limit, "refresh_trusted_proxies", None)
    assert refresh is not None, (
        "E-02: core.rate_limit has no trusted-proxy configuration entry point. There is no "
        "way to express 'trust X-Forwarded-For only from these peers' today, which is why "
        "the header is believed unconditionally."
    )
    if proxy_count == 1:
        os.environ[_ORIGINAL_TRUSTED_PROXIES_ENV] = "10.1.2.3"
    else:
        # Two hops: the peer that talks to us plus the inner proxy it forwards for.
        os.environ[_ORIGINAL_TRUSTED_PROXIES_ENV] = "10.0.0.9,10.0.0.5"
    refresh()


def _clear_trusted_proxy_config() -> None:
    os.environ.pop(_ORIGINAL_TRUSTED_PROXIES_ENV, None)
    refresh = getattr(rate_limit, "refresh_trusted_proxies", None)
    if refresh is not None:
        refresh()


def _identity(peer: str, xff: str) -> str:
    """
    Build a minimal ASGI request and ask the limiter what identity it derives.

    `peer` is the TCP peer the server saw; `xff` is what the attacker sent.
    """
    headers = [(b"host", b"testserver")]
    if xff is not None:
        headers.append((b"x-forwarded-for", xff.encode()))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/auth/login",
        "raw_path": b"/api/auth/login",
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": (peer, 4321),
        "server": ("testserver", 80),
    }
    from starlette.requests import Request

    return client_identity(Request(scope))
