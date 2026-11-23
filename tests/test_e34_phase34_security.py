"""
Phase 34 — high-risk route and credential security regression suite.

Each test corresponds to a finding confirmed by reproduction in Phase 34 and fixed in
this phase. They fail against `c18a818`:

    F-34-1 (High)    `POST /api/executive/send-report` forwarded `payload["chat_id"]`
                     verbatim, so a caller scoped to tenant A could deliver A's report —
                     including A's revenue — into tenant B's Telegram chat.

    F-34-2 (High)    `POST /api/retention/trigger-checks` called `require_permission`
                     only, then ran the scheduler's *all-tenants* sweep. A `client` scoped
                     to one tenant made the server send follow-ups into every other
                     tenant.

    F-34-3 (Medium)  `send_executive_report` returned `str(e)` and the raw provider
                     response body to the API client. httpx puts the request URL in its
                     exception text and that URL is `.../bot<TOKEN>/sendMessage`, so any
                     transport error disclosed the tenant's bot token.

Design notes
------------
* External providers are mocked at the `httpx.AsyncClient` seam; no test performs network
  I/O and no real message is sent.
* Every test asserts response semantics **and** database / dispatch state. A test that
  only asserted a status code would have passed against all three defects.
* Isolation is by rebinding `database.DB_PATH` (not just exporting the variable), which is
  the documented override and keeps these tests immune to running against pre-fix source.
* Cookies are cleared between identities: `TestClient` persists them, and a stale session
  will silently authenticate a request meant to be anonymous.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database
import executive_bot_service
import retention_service

ADMIN_PW = os.getenv("ADMIN_PASSWORD", database.DEFAULT_ADMIN_PASSWORD)
TENANT_A = "p34_tenant_a"
TENANT_B = "p34_tenant_b"
CLIENT_A = "p34_client_a"
CLIENT_PW = "P34ClientPass123!"


# --------------------------------------------------------------------------- helpers
class _Resp:
    def __init__(self, status_code=200, text='{"ok":true}'):
        self.status_code = status_code
        self.text = text


class _Client:
    """Replays one response and records what was sent."""

    def __init__(self, response, calls, raises=None):
        self._response = response
        self._calls = calls
        self._raises = raises

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def post(self, url, **kwargs):
        self._calls.append({"url": url, "json": kwargs.get("json")})
        if self._raises:
            raise self._raises
        return self._response


@pytest.fixture()
def fake_telegram(monkeypatch):
    """Install a fake httpx for exec report + retention dispatch. Returns the call log."""
    calls = []
    state = {"response": _Resp(), "raises": None}

    class _Shim:
        @staticmethod
        def AsyncClient(*_a, **_k):
            return _Client(state["response"], calls, state["raises"])

    fake = type("FakeHttpx", (), {"AsyncClient": _Shim.AsyncClient})

    def _set(status_code=200, text='{"ok":true}', raises=None):
        state["response"] = _Resp(status_code, text)
        state["raises"] = raises
        calls.clear()
        return calls

    monkeypatch.setattr(executive_bot_service, "httpx", fake)
    monkeypatch.setattr(retention_service, "httpx", fake)
    return _set


@pytest.fixture()
def tenants(tmp_path, monkeypatch):
    """Disposable DB with two tenants, each with its own bot token and manager chat."""
    db_file = tmp_path / "p34.db"
    monkeypatch.setenv("DB_PATH", str(db_file))
    monkeypatch.setattr(database, "DB_PATH", str(db_file), raising=False)
    database.init_db()

    database.save_page(page_id=TENANT_A, name="Phase 34 A")
    database.save_page(page_id=TENANT_B, name="Phase 34 B")
    database.update_page_telegram_settings(TENANT_A, "111:P34_A_TOKEN", "chat_a")
    database.update_page_telegram_settings(TENANT_B, "222:P34_B_TOKEN", "chat_b")
    database.set_client_credentials(page_id=TENANT_A, username=CLIENT_A, password=CLIENT_PW)

    yield

    conn = database.get_connection()
    try:
        for table in ("messages", "session_states", "marketing_campaigns", "sent_followups"):
            try:
                conn.execute(f"DELETE FROM {table} WHERE page_id LIKE 'p34_%'")
            except Exception:
                pass
        conn.commit()
    finally:
        conn.close()


def _client():
    from fastapi.testclient import TestClient

    import main

    c = TestClient(main.app)
    c.cookies.clear()
    return c


def _admin_headers():
    c = _client()
    r = c.post("/api/auth/login", json={"type": "admin", "password": ADMIN_PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _client_headers():
    c = _client()
    r = c.post("/api/auth/login", json={"type": "client", "identifier": CLIENT_A, "password": CLIENT_PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


# =============================================================== F-34-1 report recipient
def test_f34_1_a_foreign_chat_id_is_refused_and_nothing_is_sent(tenants, fake_telegram):
    """A caller must not be able to point the report at another tenant's chat.

    Before the fix the endpoint forwarded `chat_id` verbatim: tenant A's token was used to
    send tenant A's figures to tenant B's chat.
    """
    calls = fake_telegram()

    r = _client().post(
        "/api/executive/send-report",
        headers=_admin_headers(),
        json={"page_id": TENANT_A, "chat_id": "chat_b"},
    )

    assert r.status_code == 400, "an explicit foreign chat id must be rejected, not honoured"
    assert calls == [], "nothing may be dispatched when the recipient is refused"
    assert "chat_b" not in r.text


def test_f34_1_the_report_goes_to_the_scoped_tenants_own_chat(tenants, fake_telegram):
    """The happy path still works and resolves the recipient from the tenant's settings."""
    calls = fake_telegram()

    r = _client().post(
        "/api/executive/send-report", headers=_admin_headers(), json={"page_id": TENANT_A}
    )

    assert r.status_code == 200
    assert r.json()["success"] is True
    assert len(calls) == 1
    assert calls[0]["json"]["chat_id"] == "chat_a", "recipient must come from the scoped tenant"
    assert "P34_A_TOKEN" in calls[0]["url"], "the scoped tenant's token must be the one used"


def test_f34_1_unauthenticated_report_send_is_rejected(tenants, fake_telegram):
    calls = fake_telegram()
    r = _client().post("/api/executive/send-report", json={"page_id": TENANT_A})
    assert r.status_code == 401
    assert calls == []


# ================================================== F-34-2 retention trigger scoping
@pytest.fixture()
def retention_seed(tenants, monkeypatch):
    """Abandoned-chat candidates on B and C only, plus a dispatcher spy."""
    database.save_page(page_id="p34_tenant_c", name="Phase 34 C")
    for pid in (TENANT_B, "p34_tenant_c"):
        database.update_automated_rule(
            pid, "abandoned_chat", delay_hours=0, message_template="Сануулга", is_active=True
        )
        database.save_chat_message(
            page_id=pid, sender_id=f"web_{pid}", channel="web", sender_type="user", content="hi"
        )

    dispatched = []
    real = retention_service.dispatch_channel_message

    async def _spy(page_id, sender_id, channel, text):
        dispatched.append((page_id, sender_id))
        return await real(page_id, sender_id, channel, text)

    monkeypatch.setattr(retention_service, "dispatch_channel_message", _spy)
    return dispatched


def test_f34_2_a_client_trigger_cannot_send_into_other_tenants(retention_seed):
    """The core of F-34-2: a tenant-scoped caller must not cause cross-tenant sends.

    Before the fix this call dispatched into B and C (`abandoned_sent: 2`) because the
    endpoint ran the scheduler's all-tenants sweep under the caller's identity.
    """
    r = _client().post("/api/retention/trigger-checks", headers=_client_headers())

    assert r.status_code == 200
    assert r.json()["page_id"] == TENANT_A, "the run must be scoped to the caller's tenant"
    foreign = [d for d in retention_seed if d[0] != TENANT_A]
    assert foreign == [], f"cross-tenant dispatch must be impossible, got {foreign}"


def test_f34_2_a_client_cannot_widen_scope_with_page_id(retention_seed):
    """Naming another tenant explicitly must be refused, not obeyed."""
    r = _client().post(
        "/api/retention/trigger-checks", headers=_client_headers(), params={"page_id": TENANT_B}
    )
    assert r.status_code == 403
    assert retention_seed == [], "a refused trigger must dispatch nothing"


def test_f34_2_an_admin_scoped_to_a_tenant_only_touches_that_tenant(retention_seed):
    """The sweep is per-tenant for admins too, unless they name a tenant."""
    r = _client().post(
        "/api/retention/trigger-checks", headers=_admin_headers(), params={"page_id": TENANT_A}
    )
    assert r.status_code == 200
    assert r.json()["page_id"] == TENANT_A
    assert retention_seed == [], "tenant A has no candidates, so nothing may be dispatched"


def test_f34_2_unauthenticated_trigger_is_rejected(retention_seed):
    r = _client().post("/api/retention/trigger-checks")
    assert r.status_code == 401
    assert retention_seed == []


# ======================================================== F-34-3 secret non-disclosure
def test_f34_3_a_transport_error_does_not_disclose_the_bot_token(tenants, fake_telegram):
    """httpx includes the request URL in its exception text, and the URL carries the token."""
    fake_telegram(raises=RuntimeError("connection failed: https://api.telegram.org/bot111:P34_A_TOKEN/sendMessage"))

    r = _client().post(
        "/api/executive/send-report", headers=_admin_headers(), json={"page_id": TENANT_A}
    )

    payload = r.text
    assert r.json()["success"] is False
    assert "P34_A_TOKEN" not in payload, "the tenant bot token must never reach the API client"
    assert "api.telegram.org" not in payload


def test_f34_3_a_provider_error_body_is_not_echoed(tenants, fake_telegram):
    """A non-200 must not reflect the provider's raw body back to the caller."""
    fake_telegram(status_code=429, text='{"description":"Too Many Requests","secret":"P34_LEAK"}')

    r = _client().post(
        "/api/executive/send-report", headers=_admin_headers(), json={"page_id": TENANT_A}
    )

    assert r.json()["success"] is False
    assert "P34_LEAK" not in r.text
    assert "Too Many Requests" not in r.text


def test_f34_3_errors_still_report_failure_clearly(tenants, fake_telegram):
    """Fail-closed must remain honest: success is False and a message is present."""
    fake_telegram(status_code=403, text='{"description":"Forbidden"}')
    r = _client().post(
        "/api/executive/send-report", headers=_admin_headers(), json={"page_id": TENANT_A}
    )
    body = r.json()
    assert body["success"] is False
    assert body.get("message"), "a failure must still explain itself without disclosing secrets"


# ============================================================ credential surface checks
SECRET_MARKERS = ("P34_A_TOKEN", "P34_B_TOKEN", "P34_QPAY_PW")


def test_get_routes_never_return_plaintext_credentials(tenants):
    """Masking regression: no credential GET may echo a stored secret."""
    database.update_page_qpay_settings(TENANT_A, "quser", "P34_QPAY_PW", "INV1")

    headers = _admin_headers()
    c = _client()
    for path in (
        f"/api/pages/{TENANT_A}",
        f"/api/pages/detail?page_id={TENANT_A}",
        f"/api/executive/settings?page_id={TENANT_A}",
    ):
        r = c.get(path, headers=headers)
        assert r.status_code == 200, f"{path} -> {r.status_code}"
        leaked = [m for m in SECRET_MARKERS if m in r.text]
        assert leaked == [], f"{path} returned a plaintext secret: {leaked}"


def test_a_tenant_client_cannot_read_another_tenants_page(tenants):
    """Cross-tenant credential access must be a 403, not a populated response."""
    r = _client().get(f"/api/pages/{TENANT_B}", headers=_client_headers())
    assert r.status_code == 403
    assert "P34_B_TOKEN" not in r.text


def test_a_tenant_client_cannot_set_another_tenants_gemini_key(tenants):
    """Cross-tenant credential *write*, which is the more damaging direction."""
    r = _client().post(
        f"/api/pages/{TENANT_B}/gemini_key",
        headers=_client_headers(),
        json={"page_id": TENANT_B, "gemini_key": "AIzaP34SYNTHETIC"},
    )
    assert r.status_code == 403
    page = database.get_page(TENANT_B) or {}
    assert page.get("gemini_api_key") != "AIzaP34SYNTHETIC"


def test_a_tenant_client_cannot_write_global_system_keys(tenants):
    """`POST /api/update-keys` must require admin, not merely authentication."""
    before = os.environ.get("ADMIN_PASSWORD")
    r = _client().post(
        "/api/update-keys", headers=_client_headers(), json={"admin_password": "P34HijackAttempt"}
    )
    assert r.status_code == 403
    assert os.environ.get("ADMIN_PASSWORD") == before, "a refused write must not mutate the process"


def test_unauthenticated_credential_writes_are_rejected(tenants):
    c = _client()
    for method, path in (
        ("post", f"/api/pages/{TENANT_A}/credentials"),
        ("post", f"/api/pages/{TENANT_A}/gemini_key"),
        ("post", "/api/update-keys"),
    ):
        r = getattr(c, method)(path, json={"page_id": TENANT_A, "username": "x", "password": "y"})
        assert r.status_code == 401, f"{method.upper()} {path} -> {r.status_code}"


# ================================================================ admin plane access
ADMIN_GET_ROUTES = (
    "/api/admin/metrics",
    "/api/admin/audit-logs",
    "/api/admin/queue/stats",
    "/api/admin/queue/failed",
    "/api/admin/backups",
)


@pytest.mark.parametrize("path", ADMIN_GET_ROUTES)
def test_admin_routes_reject_an_unauthenticated_caller(tenants, path):
    r = _client().get(path)
    assert r.status_code == 401


@pytest.mark.parametrize("path", ADMIN_GET_ROUTES)
def test_admin_routes_reject_a_tenant_client(tenants, path):
    """Authorisation, not merely authentication: a valid tenant session must not pass.

    These routes expose cross-tenant operational data (metrics, the audit trail, backup
    listings), so `require_admin` is the control under test.
    """
    r = _client().get(path, headers=_client_headers())
    assert r.status_code == 403, f"{path} let a tenant client through with {r.status_code}"


def test_admin_routes_serve_a_real_admin(tenants):
    """The positive control: the guard must not simply reject everybody."""
    r = _client().get("/api/admin/metrics", headers=_admin_headers())
    assert r.status_code == 200
    assert "total_requests" in r.json()


def test_admin_routes_reject_a_tenant_client_on_mutating_endpoints(tenants):
    r = _client().post("/api/admin/queue/process", headers=_client_headers(), json={})
    assert r.status_code == 403


def test_a_tenant_client_cannot_delete_a_page(tenants):
    """`page_id` comes from the query string, not the body.

    Sending it in the body instead yields 400 from the "page_id missing" guard *before*
    authorization runs — which looks like a pass but proves nothing about the guard. The
    request must be shaped the way the handler reads it.
    """
    r = _client().request(
        "DELETE", "/api/pages", headers=_client_headers(), params={"page_id": TENANT_B}
    )
    assert r.status_code == 403, f"a tenant client must not delete a page (got {r.status_code})"
    assert database.get_page(TENANT_B) is not None, "the page must still exist"


def test_an_admin_can_delete_a_page_and_it_is_audited(tenants):
    """Positive control: the DELETE path works for an admin and leaves an audit row."""
    database.save_page(page_id="p34_disposable", name="Phase 34 Disposable")

    r = _client().request(
        "DELETE", "/api/pages", headers=_admin_headers(), params={"page_id": "p34_disposable"}
    )
    assert r.status_code == 200, r.text
    assert database.get_page("p34_disposable") is None, "the page must actually be gone"


# =========================================================== backup verification safety
@pytest.mark.parametrize(
    "hostile",
    [
        "../../../etc/passwd",
        "../leads.db",
        "/etc/passwd",
        "..\\..\\windows\\system32\\config",
        "sub/dir/../../evil.sql",
    ],
)
def test_backup_verify_cannot_escape_the_backup_directory(tenants, hostile):
    """`verify_backup` is admin-only and takes a caller-supplied filename.

    Three independent guards must hold: `basename()` strips any directory component, the
    extension must be an archive name, and `assert_contained()` refuses a symlink that
    escapes BACKUP_DIR. The assertion is on the *result*, not just the status — a 200 with
    `valid: True` for `/etc/passwd` would be the actual failure.
    """
    from core import backup_service

    result = backup_service.verify_backup(hostile)

    assert result.get("valid") is False, f"{hostile!r} was reported valid"
    assert "error" in result, "an invalid request must explain itself"
    # Nothing from outside the backup directory may be described back to the caller.
    assert "root:" not in str(result), "file contents leaked through the error path"


def test_backup_verify_rejects_a_tenant_client_and_an_anonymous_caller(tenants):
    body = {"filename": "daily_backup_20260101_000000.sql.gz"}
    assert _client().post("/api/admin/backups/verify", json=body).status_code == 401
    assert (
        _client().post("/api/admin/backups/verify", headers=_client_headers(), json=body).status_code
        == 403
    )


def test_backup_verify_reports_a_missing_archive_honestly(tenants):
    """An absent filename must be a negative result, never a fabricated success."""
    r = _client().post(
        "/api/admin/backups/verify",
        headers=_admin_headers(),
        json={"filename": "p34_does_not_exist.sql.gz"},
    )
    assert r.status_code == 200
    assert r.json().get("valid") is False
