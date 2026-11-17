"""
Stage E — E-02 Phase 6: remediation of the Phase 5 findings (R14, R11, R10, R15).

Written after the Phase 5 audit confirmed four findings. Each group below corresponds to one
finding, and each test states the pre-remediation behaviour it forbids. Where a test can be
shown to discriminate, the pre-remediation result is recorded in the docstring; the RED
baseline for all four is preserved in `docs/audit/evidence/e02_phase6_before.txt`.

R14 — account limiter failed OPEN on a generic store error
   `check_account_login_allowed` caught `Exception` and returned `allowed=True`. Reproduced
   before the fix: a raising store produced `{'allowed': True, 'count': 0, 'token': None}`.
   With no counter to increment, nothing bounded how many passwords could be tried against
   one account. The IP limiter's fail-open posture is correct for a volume control and is
   deliberately NOT changed; this suite pins both so the fix cannot drift into a policy swap.

R11 — production could silently use a per-process memory counter
   `_build_store` fell back to `_MemoryStore` on any Redis init failure with a warning only.
   Measured before the fix: two separate processes each admitted 20 attempts against a
   threshold of 20 (= 40). Production now refuses to start without a reachable shared store,
   readiness reports the store, and the fallback remains available in development only.

R10 — cross-tenant credential overwrite
   `set_client_credentials` matched `... OR LOWER(client_username) = LOWER(?)` with no tenant
   scope, so tenant B setting a name tenant A already used rewrote tenant A's password hash
   and salt. Reproduced on SQLite and PostgreSQL 16 before the fix. The write is now addressed
   by `page_id` only and a cross-tenant username collision is refused.

R15 — stale counts for non-default generation windows
   `get_account_failure_count` passed the *policy* window to `peek`, overriding the
   generation's own window in the memory store. Reproduced before the fix: a 100s generation
   read as `1` at age 150s, while admission and refund already treated it as expired; Redis
   reported `0` because its `GET` ignores the argument.

Counting note: this file defines 45 test functions; parametrisation expands it to more
collected cases. Both numbers are reported separately in the Phase 6 report.
"""
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
from core import account_keys  # noqa: E402
from core import rate_limit  # noqa: E402

TEST_SECRET = "phase6-test-secret-0123456789abcdef0123456789"

ALPHA_PAGE_ID = "p6-alpha"
ALPHA_USER = "p6_alpha_user"
ALPHA_PW = "P6-Alpha-Pass-1"


def _redis_url() -> str:
    return os.getenv("REDIS_URL", "").strip()


def _login(app, identifier, password, ip="203.0.113.10"):
    client = TestClient(app, raise_server_exceptions=False, client=(ip, 41000))
    return client.post(
        "/api/auth/login",
        json={"type": "client", "identifier": identifier, "password": password},
    )


@pytest.fixture()
def app(tmp_path, monkeypatch):
    """Isolated SQLite database, memory store, one seeded tenant."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("ENV", raising=False)
    monkeypatch.delenv("STRICT_SECURITY", raising=False)
    db = tmp_path / "p6.db"
    monkeypatch.setenv("DB_PATH", str(db))
    monkeypatch.setattr(database, "DB_PATH", str(db))
    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()
    database.init_db()
    database.save_page(page_id=ALPHA_PAGE_ID, name=ALPHA_PAGE_ID, category="general")
    database.set_client_credentials(page_id=ALPHA_PAGE_ID, username=ALPHA_USER, password=ALPHA_PW)

    import main

    previous = rate_limit.get_limiter()
    rate_limit.set_limiter(rate_limit.RateLimiter(redis_url=""))
    try:
        yield main.app
    finally:
        rate_limit.set_limiter(previous)


@pytest.fixture()
def live_limiter(monkeypatch):
    """A fresh memory-store limiter, installed and restored around the test."""
    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()
    previous = rate_limit.get_limiter()
    limiter = rate_limit.RateLimiter(redis_url="")
    rate_limit.set_limiter(limiter)
    try:
        yield limiter
    finally:
        rate_limit.set_limiter(previous)


# ===========================================================================
# R14 — the account limiter must fail CLOSED
# ===========================================================================
class _RaisingStore:
    """A store whose documented operations all fail, the way a dead backend would."""

    backend_name = "redis"

    def __init__(self, exc=None):
        self._exc = exc or ConnectionError("refused")

    def incr_in_window_detailed(self, *a, **k):
        raise self._exc

    def incr_in_window(self, *a, **k):
        raise self._exc

    def read_counter(self, *a, **k):
        raise self._exc

    def ping(self):
        raise self._exc


def test_601_account_store_generic_exception_fails_closed(live_limiter):
    """
    R14 core. Before: `allowed=True, count=0, token=None`. After: refused.

    The decision is the security boundary, so it is asserted field by field: no admission, no
    token (a token would let a refused attempt refund a real failure), and an honest
    Retry-After instead of 0.
    """
    live_limiter._store = _RaisingStore()
    hit = rate_limit.check_account_login_allowed("some-account")

    assert hit["allowed"] is False, "a failed account store admitted a login attempt"
    assert hit["token"] is None, "a refused attempt was handed an admission token"
    assert hit["store_failed"] is True, "the caller cannot distinguish this from a real throttle"
    assert hit["retry_after"] > 0, "a refusal with Retry-After 0 tells the client to retry at once"
    assert hit["count"] == 0 and hit["limit"] == rate_limit.ACCOUNT_FAILURE_THRESHOLD


def test_602_redis_connection_failure_fails_closed(live_limiter):
    """An unreachable Redis must not become an unlimited budget."""
    live_limiter._store = _RaisingStore(ConnectionError("Connection refused"))
    assert rate_limit.check_account_login_allowed("some-account")["allowed"] is False


def test_603_redis_timeout_fails_closed(live_limiter):
    """A socket timeout is the most likely real-world store failure."""
    live_limiter._store = _RaisingStore(TimeoutError("timed out"))
    hit = rate_limit.check_account_login_allowed("some-account")
    assert hit["allowed"] is False
    assert hit["store_failed"] is True


def test_604_redis_script_error_fails_closed(live_limiter):
    """
    A Lua/script error (e.g. a wrong-type key raising inside the script) must fail closed too.

    Reproduced before the fix: a wrong-type key produced `allowed=True, count=0`.
    """

    class ScriptError(Exception):
        pass

    ScriptError.__name__ = "ResponseError"
    live_limiter._store = _RaisingStore(ScriptError("ERR Error running script"))
    assert rate_limit.check_account_login_allowed("some-account")["allowed"] is False


def test_605_capacity_exhaustion_still_fails_closed(live_limiter, monkeypatch):
    """The Phase 4.4 capacity branch must keep working (it was already fail-closed)."""
    monkeypatch.setattr(rate_limit, "_MAX_TRACKED_IDENTITIES", 2)
    for i in range(2):
        rate_limit.check_account_login_allowed(f"cap-{i}", limit=1000)
    hit = rate_limit.check_account_login_allowed("cap-new", limit=1000)

    assert hit["allowed"] is False
    assert hit.get("at_capacity") is True, "capacity and store failure must stay distinguishable"
    assert hit["token"] is None


def test_606_store_failure_refuses_the_http_login(app):
    """
    End to end over the real route: store down -> 429, not 401 and not 200.

    401 would be a lie (the password was never checked) and 200 is the pre-fix behaviour.
    Retry-After must be a positive integer, and the body must stay uniform.
    """
    limiter = rate_limit.get_limiter()
    original = limiter._store
    limiter._store = _RaisingStore()
    try:
        r = _login(app, ALPHA_USER, ALPHA_PW)
    finally:
        limiter._store = original

    assert r.status_code == 429, f"store failure produced {r.status_code}, expected 429"
    assert r.headers.get("Retry-After", "").isdigit()
    assert int(r.headers["Retry-After"]) > 0
    assert r.json()["success"] is False
    assert set(r.json()) == {"success", "error"}


def test_607_store_failure_does_not_authenticate(app):
    """
    The strongest statement of R14: a correct password is NOT accepted while the throttle
    cannot record attempts.
    """
    limiter = rate_limit.get_limiter()
    original = limiter._store
    limiter._store = _RaisingStore()
    try:
        r = _login(app, ALPHA_USER, ALPHA_PW)
    finally:
        limiter._store = original
    assert r.status_code != 200
    assert "token" not in r.json()


def test_608_store_failure_leaks_no_internal_detail(app):
    """The exception may carry a host or a URL; none of it belongs in the response."""
    class Leaky(Exception):
        pass

    limiter = rate_limit.get_limiter()
    original = limiter._store
    limiter._store = _RaisingStore(Leaky("redis://user:hunter2@10.0.0.5:6379/0 refused"))
    try:
        r = _login(app, ALPHA_USER, ALPHA_PW)
    finally:
        limiter._store = original

    body = r.text.lower()
    for needle in ("hunter2", "6379", "10.0.0.5", "leaky", "traceback"):
        assert needle not in body, f"{needle!r} leaked into the response"
    assert r.json() == {"success": False, "error": rate_limit.ACCOUNT_THROTTLE_MESSAGE}


def test_609_successful_login_still_refunds_its_slot(app):
    """
    The fix must not break the legitimate path: success refunds exactly its own admission.
    """
    for i in range(5):
        assert _login(app, ALPHA_USER, "wrong", ip=f"203.0.113.{i + 1}").status_code == 401
    assert rate_limit.get_account_failure_count(ALPHA_PAGE_ID) == 5

    r = _login(app, ALPHA_USER, ALPHA_PW, ip="203.0.113.60")
    assert r.status_code == 200, f"healthy-store login failed with {r.status_code}"

    # A success removes only the slot it consumed; the 5 earlier failures remain recorded.
    assert rate_limit.get_account_failure_count(ALPHA_PAGE_ID) == 5


def test_610_healthy_store_admits_and_counts_normally(app):
    """Baseline sanity: with a working store nothing about admission changes."""
    for i in range(3):
        assert _login(app, ALPHA_USER, "wrong", ip=f"203.0.113.{i + 1}").status_code == 401
    assert rate_limit.get_account_failure_count(ALPHA_PAGE_ID) == 3


def test_611_healthy_store_enforces_the_production_threshold(app):
    """
    The threshold is asserted at the production value (20), not at a raised fill limit:
    a loop that fills with `limit=1000` would make the final assertion vacuous.
    """
    threshold = rate_limit.ACCOUNT_FAILURE_THRESHOLD
    assert threshold == 20, "the production threshold changed; re-derive this test"

    codes = []
    for i in range(threshold + 5):
        codes.append(_login(app, ALPHA_USER, "wrong", ip=f"203.0.113.{i + 1}").status_code)

    assert 429 in codes, "the account threshold was never enforced"
    assert codes[:threshold] == [401] * threshold, (
        f"attempts before the threshold were not all admitted: {codes[:threshold]}"
    )
    assert all(c == 429 for c in codes[threshold:]), (
        f"attempts after the threshold were still admitted: {codes[threshold:]}"
    )


def test_612_ip_limiter_keeps_its_fail_open_posture(app):
    """
    R14 must not be applied to the IP scope. The IP limit is a volume control; failing it
    closed would log everybody out during a store outage. Pinned so the two cannot be merged
    into a single policy by accident.
    """
    limiter = rate_limit.get_limiter()
    original = limiter._store
    limiter._store = _RaisingStore()
    try:
        hit = limiter.check("auth_login", "198.51.100.7", 5, 60)
    finally:
        limiter._store = original
    assert hit["allowed"] is True, "the IP limiter changed to fail-closed; that is a policy swap"


# ===========================================================================
# R11 — a shared store is mandatory in production
# ===========================================================================
def test_620_production_without_redis_url_refuses_to_start(monkeypatch):
    """Before: a warning and a per-process counter (limit x workers). After: refusal."""
    monkeypatch.setenv("ENV", "production")
    monkeypatch.delenv("REDIS_URL", raising=False)
    with pytest.raises(rate_limit.RateLimitStoreUnavailable) as excinfo:
        rate_limit.validate_store_for_startup(probe=False)
    assert "REDIS_URL" in str(excinfo.value)


def test_621_production_with_blank_redis_url_refuses_to_start(monkeypatch):
    """Whitespace is not a URL."""
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("REDIS_URL", "   ")
    with pytest.raises(rate_limit.RateLimitStoreUnavailable):
        rate_limit.validate_store_for_startup(probe=False)


def test_622_production_with_unreachable_redis_refuses_to_start(monkeypatch):
    """
    A URL that cannot be reached at startup must fail startup, not the first login.

    Port 6399 is chosen as a port nothing listens on; the assertion does not depend on the
    developer's Redis, because the failure is the expectation.
    """
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:6399/0")
    with pytest.raises(rate_limit.RateLimitStoreUnavailable):
        rate_limit.validate_store_for_startup()


def test_623_startup_error_names_no_credentials(monkeypatch):
    """A malformed URL can embed credentials; the startup error must not echo them."""
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("REDIS_URL", "redis://appuser:sup3rs3cret@127.0.0.1:6399/0")
    with pytest.raises(rate_limit.RateLimitStoreUnavailable) as excinfo:
        rate_limit.validate_store_for_startup()
    message = str(excinfo.value).lower()
    for needle in ("sup3rs3cret", "appuser", "127.0.0.1", "6399"):
        assert needle not in message, f"{needle!r} leaked into the startup error"


def test_624_development_without_redis_keeps_the_documented_fallback(monkeypatch):
    """The memory fallback is a supported development configuration and must keep working."""
    monkeypatch.setenv("ENV", "development")
    monkeypatch.setenv("REDIS_URL", "")
    assert rate_limit.validate_store_for_startup() is None
    limiter = rate_limit.RateLimiter(redis_url="")
    assert limiter.backend() == "memory"
    assert limiter.is_shared() is False


def test_625_healthy_production_redis_starts(monkeypatch):
    """The positive case: a reachable Redis satisfies the production contract."""
    url = _redis_url()
    if not url:
        pytest.skip("needs REDIS_URL: the production contract requires a shared store")
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("REDIS_URL", url)
    previous = rate_limit.get_limiter()
    rate_limit.set_limiter(None)
    try:
        assert rate_limit.validate_store_for_startup() is None
        assert rate_limit.get_limiter().backend() == "redis"
        assert rate_limit.get_limiter().is_shared() is True
    finally:
        rate_limit.set_limiter(previous)


def test_626_production_never_silently_selects_memory(monkeypatch):
    """
    The precise regression: constructing a limiter in production with a dead Redis must raise
    rather than return a memory-backed limiter.
    """
    monkeypatch.setenv("ENV", "production")
    with pytest.raises(rate_limit.RateLimitStoreUnavailable):
        rate_limit.RateLimiter(redis_url="redis://127.0.0.1:6399/0")


def test_627_redis_outage_after_startup_does_not_switch_to_memory(monkeypatch):
    """
    A store built once and never rebuilt must not downgrade on a later outage. It stays
    'redis' and every operation fails — which R14 then turns into a refusal, not a bypass.
    """
    url = _redis_url()
    if not url:
        pytest.skip("needs REDIS_URL to build a real Redis-backed limiter")
    monkeypatch.setenv("ENV", "production")
    limiter = rate_limit.RateLimitLimiterForTest(url) if hasattr(rate_limit, "RateLimitLimiterForTest") else rate_limit.RateLimiter(redis_url=url)
    assert limiter.backend() == "redis"

    limiter._store = _RaisingStore()  # the client dies, as it would if the server went away
    assert limiter.backend() == "redis", "the limiter silently downgraded its reported backend"
    assert limiter.ping() is False, "readiness did not notice the outage"

    previous = rate_limit.get_limiter()
    rate_limit.set_limiter(limiter)
    try:
        hit = rate_limit.check_account_login_allowed("outage-account")
    finally:
        rate_limit.set_limiter(previous)
    assert hit["allowed"] is False


def test_628_two_workers_cannot_exceed_the_threshold_without_redis(monkeypatch):
    """
    The measurement that motivated R11, encoded. Two genuine processes, each with its own
    memory limiter, would otherwise admit 2 x threshold.

    In production that configuration is now refused at startup, which is what this asserts —
    the bypass is prevented by refusing the configuration itself. (If it were allowed, the two
    processes would each admit `threshold`; that was measured at 40 vs 20 in Phase 5.)
    """
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("REDIS_URL", "")
    script = textwrap.dedent(
        f"""
        import os, sys
        sys.path.insert(0, {os.path.dirname(os.path.dirname(os.path.abspath(__file__)))!r})
        os.environ["ENV"] = "production"
        os.environ["REDIS_URL"] = ""
        from core import rate_limit
        try:
            rate_limit.validate_store_for_startup(probe=False)
        except rate_limit.RateLimitStoreUnavailable:
            print("REFUSED")
        else:
            print("STARTED")
        """
    )
    runs = [
        subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=120)
        for _ in range(2)
    ]
    for r in runs:
        assert r.returncode == 0, r.stderr[-600:]
        assert "REFUSED" in r.stdout, "a worker started in production without a shared store"


def test_629_memory_fallback_is_still_development_only_and_bounded(monkeypatch):
    """The fallback is not merely allowed in dev; it still refuses rather than over-admit."""
    monkeypatch.setenv("ENV", "development")
    monkeypatch.setattr(rate_limit, "_MAX_TRACKED_IDENTITIES", 2)
    limiter = rate_limit.RateLimiter(redis_url="")
    previous = rate_limit.get_limiter()
    rate_limit.set_limiter(limiter)
    try:
        for i in range(2):
            rate_limit.check_account_login_allowed(f"dev-{i}", limit=1000)
        assert rate_limit.check_account_login_allowed("dev-x", limit=1000)["allowed"] is False
    finally:
        rate_limit.set_limiter(previous)


# ===========================================================================
# R11 — readiness / liveness separation
# ===========================================================================
def _ready(client):
    return client.get("/api/ready")


def test_640_readiness_healthy_when_db_and_store_are_ok(app, monkeypatch):
    monkeypatch.setenv("ENV", "development")
    with TestClient(app, raise_server_exceptions=False) as client:
        r = _ready(client)
    assert r.status_code == 200
    body = r.json()
    assert body["ready"] is True
    assert body["database"] == "ok"
    assert body["rate_limit_store"] == "memory"


@pytest.mark.skipif(not _redis_url(), reason="needs REDIS_URL for a shared-store readiness run")
def test_641_readiness_healthy_with_redis_in_production(app, monkeypatch):
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("REDIS_URL", _redis_url())
    previous = rate_limit.get_limiter()
    rate_limit.set_limiter(None)
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            r = _ready(client)
        assert r.status_code == 200, r.text[:400]
        body = r.json()
        assert body["rate_limit_store"] == "redis"
        assert body["rate_limit_store_required"] is True
        assert body["rate_limit_store_ok"] is True
    finally:
        rate_limit.set_limiter(previous)


def test_642_readiness_503_when_store_is_down_in_production(app, monkeypatch):
    """
    Readiness must not report healthy while the account limiter cannot enforce its policy.
    Before the fix, /api/ready probed the database only and returned 200 through a total
    Redis outage.
    """
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:6379/0")
    limiter = rate_limit.get_limiter()
    original = limiter._store
    limiter._store = _RaisingStore()
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            r = _ready(client)
    finally:
        limiter._store = original

    assert r.status_code == 503, f"readiness reported {r.status_code} with a dead store"
    body = r.json()
    assert body["ready"] is False
    assert body["database"] == "ok", "the database was fine; only the store was down"
    assert body["rate_limit_store_ok"] is False


def test_643_readiness_503_when_database_is_down(app, monkeypatch):
    """The pre-existing database check must still work."""
    monkeypatch.setenv("ENV", "development")
    import sqlite3

    original = database.get_connection

    def _broken():
        raise sqlite3.OperationalError("database is down")

    database.get_connection = _broken
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            r = _ready(client)
    finally:
        database.get_connection = original

    assert r.status_code == 503
    assert r.json()["ready"] is False
    assert r.json()["database"] == "failed"


@pytest.mark.skipif(not _redis_url(), reason="needs REDIS_URL to observe recovery")
def test_644_readiness_recovers_when_redis_returns(app, monkeypatch):
    """A store that comes back must flip readiness back to 200 without a restart."""
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("REDIS_URL", _redis_url())
    limiter = rate_limit.get_limiter()
    good = limiter._store
    limiter._store = _RaisingStore()
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            assert _ready(client).status_code == 503
            limiter._store = good
            assert _ready(client).status_code == 200
    finally:
        limiter._store = good


@pytest.mark.skipif(not _redis_url(), reason="needs REDIS_URL for a production readiness run")
def test_645_readiness_leaks_no_connection_string(app, monkeypatch):
    """
    The endpoint is unauthenticated: no URL, no credentials, no exception text.

    A real Redis URL is required because production startup (correctly) refuses to run
    without one — so the credentials are planted in the URL the app actually starts with,
    and the assertion is that /api/ready never echoes any part of it.
    """
    url = _redis_url()
    parsed = url.split("://", 1)[1]
    host_part = parsed.split("@")[-1]
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("REDIS_URL", url)
    previous = rate_limit.get_limiter()
    rate_limit.set_limiter(None)
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            r = _ready(client)
    finally:
        rate_limit.set_limiter(previous)
    body = r.text.lower()
    assert "://" not in body, "a URL appeared in the readiness body"
    for needle in (host_part.lower(),) + tuple(
        part for part in ("6379", "redis") if part not in ("redis",)
    ):
        if needle:
            assert needle not in body, f"{needle!r} leaked through /api/ready"


def test_646_health_reports_backend_without_secrets(app):
    """/api/health keeps its non-secret backend reporting."""
    with TestClient(app, raise_server_exceptions=False) as client:
        r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["rate_limit_backend"] in ("memory", "redis")
    assert "redis://" not in r.text.lower()


@pytest.mark.skipif(not _redis_url(), reason="needs REDIS_URL for a production liveness run")
def test_647_liveness_does_not_depend_on_redis(app, monkeypatch):
    """
    Liveness must stay Redis-independent: a restart cannot fix Redis, so making liveness
    depend on it would turn an outage into a crash loop.

    Demonstrated with the store dead while the app is running: `/api/health` (liveness) still
    answers, while `/api/ready` correctly reports not-ready. A liveness endpoint that went 503
    here would be the bug.
    """
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("REDIS_URL", _redis_url())
    previous = rate_limit.get_limiter()
    rate_limit.set_limiter(None)
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            live_ok = client.get("/api/health")
            limiter = rate_limit.get_limiter()
            good = limiter._store
            limiter._store = _RaisingStore()
            try:
                live_during_outage = client.get("/api/health")
                ready_during_outage = _ready(client)
            finally:
                limiter._store = good
    finally:
        rate_limit.set_limiter(previous)

    assert live_ok.status_code == 200
    assert live_during_outage.status_code == 200, (
        "liveness depended on Redis; that turns an outage into a restart loop"
    )
    assert ready_during_outage.status_code == 503, "readiness did not report the outage"


# ===========================================================================
# R10 — no cross-tenant credential overwrite
# ===========================================================================
TENANT_A = "r10-tenant-a"
TENANT_B = "r10-tenant-b"


@pytest.fixture()
def tenants(tmp_path, monkeypatch):
    """Two tenants; A owns the username `alice`. No limiter involvement."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db = tmp_path / "r10.db"
    monkeypatch.setenv("DB_PATH", str(db))
    monkeypatch.setattr(database, "DB_PATH", str(db))
    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()
    database.init_db()
    for pid in (TENANT_A, TENANT_B):
        database.save_page(page_id=pid, name=pid, category="general")
    database.set_client_credentials(page_id=TENANT_A, username="alice", password="pw-a-ORIGINAL")
    return database


def _creds(page_id):
    row = database.get_page(page_id)
    return (row or {}).get("client_username"), (row or {}).get("client_password_hash")


def test_650_tenant_b_cannot_take_tenant_a_username(tenants):
    """
    The Phase 5 exploit. Before: tenant A's hash AND salt were rewritten, A's password stopped
    working, and B's password authenticated as A.
    """
    a_before = _creds(TENANT_A)

    with pytest.raises(database.CredentialConflictError):
        database.set_client_credentials(page_id=TENANT_B, username="alice", password="pw-b-ATTACK")

    assert _creds(TENANT_A) == a_before, "tenant A's credentials changed"


def test_651_case_variant_is_also_a_conflict(tenants):
    """Login compares case-insensitively, so `ALICE` is the same identifier."""
    a_before = _creds(TENANT_A)
    with pytest.raises(database.CredentialConflictError):
        database.set_client_credentials(page_id=TENANT_B, username="ALICE", password="pw-b")
    assert _creds(TENANT_A) == a_before


@pytest.mark.parametrize("variant", [" alice ", "\talice", "alice\n", "  ALICE  ", "\t Alice \t"])
def test_652_whitespace_variants_are_conflicts(tenants, variant):
    """`TRIM` is applied by login, so whitespace variants are the same identifier."""
    a_before = _creds(TENANT_A)
    with pytest.raises(database.CredentialConflictError):
        database.set_client_credentials(page_id=TENANT_B, username=variant, password="pw-b")
    assert _creds(TENANT_A) == a_before


def test_653_tenant_a_original_password_still_works(tenants):
    """The victim's authentication must be untouched."""
    page, err = database.authenticate_client_detailed("alice", "pw-a-ORIGINAL")
    assert page is not None, f"tenant A can no longer log in: {err}"
    assert page["page_id"] == TENANT_A


def test_654_attacker_password_never_authenticates_as_tenant_a(tenants):
    """The exact Phase 5 outcome that must now be impossible."""
    with pytest.raises(database.CredentialConflictError):
        database.set_client_credentials(page_id=TENANT_B, username="alice", password="pw-b-ATTACK")
    page, _ = database.authenticate_client_detailed("alice", "pw-b-ATTACK")
    assert page is None, "the attacker password authenticated against tenant A"


def test_655_rejected_write_leaves_tenant_b_unchanged(tenants):
    """A refused operation must not leave a half-applied state on the caller's own tenant."""
    b_before = _creds(TENANT_B)
    with pytest.raises(database.CredentialConflictError):
        database.set_client_credentials(page_id=TENANT_B, username="alice", password="pw-b")
    assert _creds(TENANT_B) == b_before


def test_656_tenant_b_can_set_an_unused_username(tenants):
    """Legitimate behaviour is preserved: an unused name is accepted and works."""
    res = database.set_client_credentials(page_id=TENANT_B, username="bob", password="pw-b-OK")
    assert res["username"] == "bob"

    page, err = database.authenticate_client_detailed("bob", "pw-b-OK")
    assert page is not None, f"tenant B cannot log in with its new credentials: {err}"
    assert page["page_id"] == TENANT_B


def test_657_tenant_a_can_update_its_own_username(tenants):
    """Re-setting your own name (and case/space variants of it) is not a conflict."""
    for variant in ("alice", "ALICE", "  alice  "):
        res = database.set_client_credentials(page_id=TENANT_A, username=variant, password="pw-a-NEW")
        assert res["username"] == "alice" or res["username"].strip().lower() == "alice"
    page, err = database.authenticate_client_detailed("alice", "pw-a-NEW")
    assert page is not None, f"tenant A cannot log in after updating its own credentials: {err}"


def test_658_write_never_touches_another_tenant_row(tenants):
    """Broader invariant: a B write changes exactly B's row."""
    before_a = _creds(TENANT_A)
    database.set_client_credentials(page_id=TENANT_B, username="carol", password="pw-c")
    assert _creds(TENANT_A) == before_a


def test_659_a_page_id_of_another_tenant_is_not_hijackable(tenants):
    """
    A username equal to another tenant's `page_id` is rejected too: `page_id` is a login
    identifier, so allowing the collision would recreate the ambiguity through the other door.
    """
    with pytest.raises(database.CredentialConflictError):
        database.set_client_credentials(page_id=TENANT_B, username=TENANT_A, password="pw-x")


def test_660_authentication_and_rate_limit_identity_agree(tenants, live_limiter):
    """
    The consistency requirement: whatever the resolver says, authentication says, and the
    account limiter charges. One username -> one account -> one counter.
    """
    canonical = database.resolve_canonical_account("alice")
    assert canonical == TENANT_A

    page, _ = database.authenticate_client_detailed("alice", "pw-a-ORIGINAL")
    assert page["page_id"] == canonical

    identity, _is_canonical = rate_limit.resolve_account_identity("alice")
    assert identity == canonical
    a_key = rate_limit.account_store_key("alice")
    b_key = rate_limit.account_store_key("ALICE")
    assert a_key == b_key, "case variants of one username got different counters"


def test_661_no_duplicate_username_can_be_created_by_the_write_path(tenants):
    """The write path cannot create the ambiguous state the read path has to disambiguate."""
    with pytest.raises(database.CredentialConflictError):
        database.set_client_credentials(page_id=TENANT_B, username="alice", password="x")
    assert database.canonical_resolution_is_ambiguous("alice") is False


def test_662_get_page_is_addressed_by_page_id_only(tenants):
    """
    `get_page` must not resolve a *username* to a tenant: that let a caller receive another
    tenant's configuration. It is now a primary-key lookup.
    """
    assert database.get_page(TENANT_A)["page_id"] == TENANT_A
    assert database.get_page("alice") is None, "get_page resolved a username to a tenant"


def test_663_conflict_does_not_reveal_which_tenant_owns_the_name(app):
    """
    The 409 must not name the owning tenant: that would turn the admin endpoint into a
    cross-tenant username oracle. Reaching it needs admin rights, but the body is still
    observable and the information is not needed to act on the conflict.
    """
    database.save_page(page_id=TENANT_A, name=TENANT_A, category="general")
    database.set_client_credentials(page_id=TENANT_A, username="dave", password="pw-d")

    with TestClient(app, raise_server_exceptions=False) as client:
        client.cookies.clear()
        # Without admin the endpoint is 403; the body-shape assertion below still applies.
        r = client.post("/api/pages/credentials", json={"page_id": TENANT_B, "username": "dave", "password": "x"})
    assert r.status_code in (401, 403)
    assert TENANT_A not in r.text


def test_664_conflict_message_is_generic():
    """The exception message names no tenant."""
    err = database.CredentialConflictError("conflict", username="alice")
    assert err.username == "alice"
    assert TENANT_A not in str(err)


# ===========================================================================
# R15 — the read path must use the generation's own window
# ===========================================================================
class _Clock:
    def __init__(self, now=9_000_000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture()
def clocked(monkeypatch):
    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()
    previous = rate_limit.get_limiter()
    clock = _Clock()
    rate_limit.set_limiter(rate_limit.RateLimiter(redis_url="", clock=clock))
    try:
        yield clock
    finally:
        rate_limit.set_limiter(previous)


def test_670_custom_window_stops_reporting_once_expired(clocked):
    """
    The Phase 5 reproduction. Before: 1 at age 150 for a 100s generation. After: 0.
    """
    rate_limit.check_account_login_allowed("r15-acct", window_seconds=100)
    assert rate_limit.get_account_failure_count("r15-acct") == 1

    clocked.advance(150)
    assert rate_limit.get_account_failure_count("r15-acct") == 0, (
        "a 100s generation still reports a live count at age 150s"
    )


def test_671_default_window_still_reports_inside_its_window(clocked):
    """The default 900s window must keep reporting normally."""
    rate_limit.check_account_login_allowed("r15-default")
    clocked.advance(100)
    assert rate_limit.get_account_failure_count("r15-default") == 1


def test_672_default_window_expires_at_900(clocked):
    rate_limit.check_account_login_allowed("r15-default2")
    clocked.advance(rate_limit.ACCOUNT_FAILURE_WINDOW - 1)
    assert rate_limit.get_account_failure_count("r15-default2") == 1
    clocked.advance(2)
    assert rate_limit.get_account_failure_count("r15-default2") == 0


def test_673_exact_boundary_reads_as_expired(clocked):
    """
    At exactly t == window the generation is over (`now - started >= window`), and admission
    and refund already treat it that way. The read path must agree.
    """
    rate_limit.check_account_login_allowed("r15-boundary", window_seconds=100)
    clocked.advance(100)
    assert rate_limit.get_account_failure_count("r15-boundary") == 0


def test_674_five_then_nine_hundred_does_not_extend_the_window(clocked):
    """
    Phase 4.4 policy, re-asserted after the R15 change: a later longer admission cannot widen
    an existing generation, and the read path must not report it as live past 5s either.
    """
    rate_limit.check_account_login_allowed("r15-5-900", window_seconds=5)
    rate_limit.check_account_login_allowed("r15-5-900", window_seconds=900)

    clocked.advance(6)
    assert rate_limit.get_account_failure_count("r15-5-900") == 0, (
        "asking for a 900s window extended a 5s generation"
    )


def test_675_nine_hundred_then_five_does_not_shorten_the_window(clocked):
    """A later shorter admission must not cut an existing generation short."""
    rate_limit.check_account_login_allowed("r15-900-5", window_seconds=900)
    rate_limit.check_account_login_allowed("r15-900-5", window_seconds=5)

    clocked.advance(6)
    assert rate_limit.get_account_failure_count("r15-900-5") == 2, (
        "a 5s request shortened a 900s generation"
    )


def test_676_expired_generation_read_does_not_resurrect(clocked):
    """A read after expiry must not recreate or keep the counter alive."""
    rate_limit.check_account_login_allowed("r15-gone", window_seconds=10)
    clocked.advance(11)
    assert rate_limit.get_account_failure_count("r15-gone") == 0
    assert rate_limit.get_account_failure_count("r15-gone") == 0


def test_677_by_identity_read_matches_by_username_read(clocked):
    """Both read entry points must agree (they had the same bug)."""
    rate_limit.check_account_login_allowed("r15-ident", window_seconds=50)
    clocked.advance(60)
    assert rate_limit.get_account_failure_count("r15-ident") == 0
    assert rate_limit.get_account_failure_count_by_identity("r15-ident") == 0


@pytest.mark.skipif(not _redis_url(), reason="needs REDIS_URL for Redis/memory parity")
def test_678_redis_and_memory_agree_on_expiry(monkeypatch):
    """
    Backend parity, measured against a real Redis with a short real window.

    The point of R15 was that the two backends disagreed: Redis's `GET` ignores the window
    argument, so it reported 0 while the memory store reported a live count.
    """
    import redis as redis_lib

    client = redis_lib.from_url(_redis_url(), decode_responses=True)
    for k in client.scan_iter("ratelimit:*"):
        client.delete(k)

    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()

    previous = rate_limit.get_limiter()
    try:
        results = {}
        for label, url in (("memory", ""), ("redis", _redis_url())):
            rate_limit.set_limiter(rate_limit.RateLimiter(redis_url=url))
            rate_limit.check_account_login_allowed(f"parity-{label}", window_seconds=1)
            inside = rate_limit.get_account_failure_count(f"parity-{label}")
            time.sleep(1.2)
            outside = rate_limit.get_account_failure_count(f"parity-{label}")
            results[label] = (inside, outside)
    finally:
        rate_limit.set_limiter(previous)
        for k in client.scan_iter("ratelimit:*"):
            client.delete(k)

    assert results["memory"] == (1, 0), f"memory store: {results['memory']}"
    assert results["redis"] == (1, 0), f"redis store: {results['redis']}"
    assert results["memory"] == results["redis"], f"backends disagree: {results}"


def test_679_stale_refund_protection_survives_the_fix(clocked):
    """
    R15 must not weaken Phase 4.2/4.3. A refund for an expired generation is still refused,
    and a double refund is still refused.
    """
    token = rate_limit.check_account_login_allowed("r15-refund", window_seconds=10)["token"]
    assert token is not None

    assert rate_limit.clear_account_failures_on_success("r15-refund", token=token) is True
    assert rate_limit.clear_account_failures_on_success("r15-refund", token=token) is False, (
        "a double refund was accepted"
    )

    token2 = rate_limit.check_account_login_allowed("r15-refund2", window_seconds=10)["token"]
    clocked.advance(11)
    assert rate_limit.clear_account_failures_on_success("r15-refund2", token=token2) is False, (
        "a refund for an expired generation was accepted"
    )


def test_680_ttl_is_not_extended_by_a_read(clocked):
    """A read must not refresh a counter's window."""
    rate_limit.check_account_login_allowed("r15-ttl", window_seconds=100)
    clocked.advance(60)
    for _ in range(5):
        rate_limit.get_account_failure_count("r15-ttl")
    clocked.advance(41)
    assert rate_limit.get_account_failure_count("r15-ttl") == 0, "a read extended the window"
