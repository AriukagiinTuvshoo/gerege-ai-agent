"""
Stage D — SEC-07: rate limiting was per-process, and three public endpoints had none.

The only limit was `_LOGIN_ATTEMPTS: Dict[str, List[float]]` in `main.py`. Production runs
`uvicorn --workers 2` plus a separate worker process, so the effective login limit was
10 × (processes) per minute and it reset on every deploy. `POST /api/chat`,
`POST /api/upload-receipt` and `GET /r/{code}` were unlimited: the widget is callable by
anyone on the internet, receipt uploads drive Pillow (attacker-controlled CPU), and the
redirect is a free traffic amplifier.

The tests are split deliberately:

* Window/counter logic is tested with an injected clock, so nothing sleeps.
* The cross-process guarantee is tested with two *separate interpreters* against one
  Redis. An in-process test cannot fail for the original bug, because the original bug was
  precisely that state lived inside one process.
"""
import os
import subprocess
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402
from core import rate_limit  # noqa: E402
from core.rate_limit import RateLimiter, _MemoryStore  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _redis_url():
    return os.getenv("REDIS_URL", "").strip()


# ---------------------------------------------------------------------------
# Counter semantics (no sleeping)
# ---------------------------------------------------------------------------
class _FakeClock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


def test_limit_is_enforced_within_one_window():
    clock = _FakeClock()
    limiter = RateLimiter(redis_url="", clock=clock, store=_MemoryStore(clock))
    results = [limiter.check("s", "ip1", 2, 60)["allowed"] for _ in range(3)]
    assert results == [True, True, False]


def test_window_expiry_allows_requests_again():
    clock = _FakeClock()
    limiter = RateLimiter(redis_url="", clock=clock, store=_MemoryStore(clock))
    assert limiter.check("s", "ip1", 1, 60)["allowed"] is True
    assert limiter.check("s", "ip1", 1, 60)["allowed"] is False
    clock.now += 61  # window elapsed
    assert limiter.check("s", "ip1", 1, 60)["allowed"] is True, "limit must reset per window"


def test_identities_are_independent():
    clock = _FakeClock()
    limiter = RateLimiter(redis_url="", clock=clock, store=_MemoryStore(clock))
    assert limiter.check("s", "ip1", 1, 60)["allowed"] is True
    assert limiter.check("s", "ip2", 1, 60)["allowed"] is True, "one client must not limit another"


def test_scopes_are_independent():
    clock = _FakeClock()
    limiter = RateLimiter(redis_url="", clock=clock, store=_MemoryStore(clock))
    assert limiter.check("login", "ip", 1, 60)["allowed"] is True
    assert limiter.check("chat", "ip", 1, 60)["allowed"] is True


def test_rejection_reports_retry_after():
    clock = _FakeClock()
    limiter = RateLimiter(redis_url="", clock=clock, store=_MemoryStore(clock))
    limiter.check("s", "ip", 1, 60)
    result = limiter.check("s", "ip", 1, 60)
    assert result["allowed"] is False
    assert result["retry_after"] == 60


def test_a_store_outage_fails_open_rather_than_locking_everyone_out():
    """A Redis blip must not become a total login outage."""

    class BrokenStore:
        backend_name = "broken"

        def incr_in_window(self, key, window_seconds):
            raise RuntimeError("store down")

    limiter = RateLimiter(store=BrokenStore())
    result = limiter.check("login", "ip", 1, 60)
    assert result["allowed"] is True, "must fail open, and log, rather than block everything"


def test_fallback_backend_is_reported_honestly():
    """A per-process limiter must not masquerade as a shared one."""
    limiter = RateLimiter(redis_url="")
    assert limiter.backend() == "memory"
    assert limiter.is_shared() is False


# ---------------------------------------------------------------------------
# Shared state across processes (the actual SEC-07 guarantee)
# ---------------------------------------------------------------------------
@pytest.mark.skipif(not _redis_url(), reason="needs REDIS_URL for a shared store")
def test_limit_is_shared_between_two_limiter_instances():
    a = RateLimiter(redis_url=_redis_url())
    b = RateLimiter(redis_url=_redis_url())
    a.reset("sec07_instances")
    assert a.check("sec07_instances", "ip", 1, 60)["allowed"] is True
    assert b.check("sec07_instances", "ip", 1, 60)["allowed"] is False, (
        "two limiters against one Redis must share the counter — this is what two "
        "worker processes are"
    )


@pytest.mark.skipif(not _redis_url(), reason="needs REDIS_URL for a shared store")
def test_login_limit_is_shared_across_real_processes(tmp_path):
    db_path = tmp_path / "rl.db"
    RateLimiter(redis_url=_redis_url()).reset("auth_login")
    script = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, {REPO_ROOT!r})
        import os
        os.environ["DB_PATH"] = {str(db_path)!r}
        os.environ.pop("DATABASE_URL", None)
        os.environ["REDIS_URL"] = {_redis_url()!r}
        os.environ.setdefault("ADMIN_PASSWORD", "Sec07-Test-Pw-2026")
        import database
        database.init_db()
        from fastapi.testclient import TestClient
        import main
        c = TestClient(main.app)
        n = int(sys.argv[1])
        codes = [c.post("/api/auth/login", json={{"type": "admin", "password": "wrong"}}).status_code
                 for _ in range(n)]
        print(",".join(str(x) for x in codes))
        """
    )

    def run(n):
        proc = subprocess.run(
            [sys.executable, "-c", script, str(n)],
            capture_output=True, text=True, cwd=REPO_ROOT, timeout=300,
        )
        assert proc.returncode == 0, proc.stderr[-2000:]
        return [int(x) for x in proc.stdout.strip().splitlines()[-1].split(",")]

    first = run(10)
    assert first == [401] * 10, first
    second = run(2)
    assert second == [429, 429], (
        f"a second process was not limited by the first process's attempts: {second}"
    )


# ---------------------------------------------------------------------------
# Endpoint coverage
# ---------------------------------------------------------------------------
@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db = tmp_path / "app.db"
    monkeypatch.setenv("DB_PATH", str(db))
    monkeypatch.setattr(database, "DB_PATH", str(db))
    database.init_db()
    database.save_page(page_id="PAGE1", name="Tenant One", category="general")
    from fastapi.testclient import TestClient

    import main

    rate_limit.get_limiter().reset()
    return TestClient(main.app, raise_server_exceptions=False)


def test_login_returns_429_and_retry_after_once_exhausted(client):
    codes = [
        client.post("/api/auth/login", json={"type": "admin", "password": "wrong"}).status_code
        for _ in range(11)
    ]
    assert codes[:10] == [401] * 10, codes
    assert codes[10] == 429, codes
    r = client.post("/api/auth/login", json={"type": "admin", "password": "wrong"})
    assert r.headers.get("Retry-After"), "a 429 must tell the client when to retry"


def test_chat_endpoint_is_rate_limited(client, monkeypatch):
    """`POST /api/chat` is reachable by anyone; it had no limit at all."""
    monkeypatch.setitem(rate_limit.DEFAULT_LIMITS, "api_chat", (2, 60))
    rate_limit.get_limiter().reset("api_chat")
    body = {"message": "hi", "sender_id": "probe", "page_id": "PAGE1"}
    codes = [client.post("/api/chat", json=body).status_code for _ in range(4)]
    assert 429 in codes, f"chat endpoint was never limited: {codes}"


def test_tracked_redirect_is_rate_limited(client, monkeypatch):
    monkeypatch.setitem(rate_limit.DEFAULT_LIMITS, "tracked_redirect", (2, 60))
    rate_limit.get_limiter().reset("tracked_redirect")
    codes = [client.get("/r/nonexistent-code").status_code for _ in range(4)]
    assert 429 in codes, f"redirect endpoint was never limited: {codes}"


def test_upload_receipt_is_rate_limited(client, monkeypatch):
    monkeypatch.setitem(rate_limit.DEFAULT_LIMITS, "api_upload_receipt", (2, 60))
    rate_limit.get_limiter().reset("api_upload_receipt")
    files = {"file": ("x.png", b"\x89PNG\r\n\x1a\n", "image/png")}
    codes = [
        client.post("/api/upload-receipt", files=files, data={"page_id": "PAGE1"}).status_code
        for _ in range(4)
    ]
    assert 429 in codes, f"receipt upload was never limited: {codes}"


def test_health_reports_the_limiter_backend(client):
    payload = client.get("/api/health").json()
    assert "rate_limit_backend" in payload
    assert isinstance(payload["rate_limits_shared_across_workers"], bool)
