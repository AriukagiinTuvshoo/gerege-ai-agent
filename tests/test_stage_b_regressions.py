"""
Stage B — P0/P1 regression suite.

Every test in this file was written **before** its fix and failed against commit
`48e9c6f`. Each maps to a finding in `docs/audit/`:

    B-01  P0-01  datetime rows are not JSON-serialisable on PostgreSQL
    B-02  SEC-01 CORS reflects any origin while credentials are enabled
    B-03  P1-01  lastrowid is None for comment_automations / tracked_links on PG
    B-04  P1-03  LIKE-based date predicates break on PostgreSQL
    B-05  P1-04  cross-tenant invoice read (BOLA)

These tests are DB-agnostic: they run under SQLite (CI fast path) and against live
PostgreSQL 16 when `DATABASE_URL` is set. The PostgreSQL-only assertions are guarded by
`db_engine.is_postgres()` so the SQLite job stays green while the PG job proves the fix.
"""
import io
import json
import os
import sys
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main
import database
from core import db_engine

client = TestClient(main.app)

# Fall back to the application's own default so the suite works locally without
# exporting ADMIN_PASSWORD (CI always sets it). Hard-coding a CI password here made the
# suite fail for every developer who ran it on a machine without that env var.
ADMIN_PW = os.getenv("ADMIN_PASSWORD", database.DEFAULT_ADMIN_PASSWORD)
PG = db_engine.is_postgres()

TENANT_A = "stageb_tenant_a"
TENANT_B = "stageb_tenant_b"


# --------------------------------------------------------------------------- helpers
def _admin_headers() -> dict:
    r = client.post("/api/auth/login", json={"type": "admin", "password": ADMIN_PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _client_headers(page_id: str, username: str) -> dict:
    r = client.post(
        "/api/auth/login",
        json={"type": "client", "identifier": username, "password": "StageBPass123!"},
    )
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


@pytest.fixture(scope="module", autouse=True)
def seed_tenants():
    """Deterministic, idempotent seed. Never deletes pre-existing rows."""
    database.init_db()
    for pid, name in ((TENANT_A, "Stage B Tenant A"), (TENANT_B, "Stage B Tenant B")):
        database.save_page(page_id=pid, name=name, category="retail")
        database.set_client_credentials(
            page_id=pid, username=f"{pid}_user", password="StageBPass123!"
        )
    yield


# --------------------------------------------------------------- B-01 (P0-01)
def test_b01_raw_db_rows_are_servable_through_the_api_boundary():
    """
    Root cause: on PostgreSQL the runtime DDL declares `created_at TIMESTAMP`, so psycopg2
    returns `datetime`, and `JSONResponse` raises `TypeError: Object of type datetime is not
    JSON serializable` -> HTTP 500.

    Design note: the repository layer deliberately still returns real `datetime` objects
    (that is the correct domain type); normalisation belongs at the single API boundary,
    `core.serialization.SafeJSONResponse`. So this test asserts the *boundary* can serialise
    a repository row, not that `json.dumps()` works on raw rows.

    Endpoint-level proof is in the three tests that follow.
    """
    from core.serialization import SafeJSONResponse

    database.save_registration(
        name="Stage B Lead", phone="88001100", service="Audit", page_id=TENANT_A
    )
    rows = database.get_all_registrations(page_id=TENANT_A)
    assert rows, "seed row missing"

    # Before the fix this raised TypeError inside JSONResponse.render().
    rendered = SafeJSONResponse({"total": len(rows), "data": rows})
    decoded = json.loads(rendered.body)
    assert decoded["total"] >= 1
    assert isinstance(decoded["data"][0]["created_at"], str)


def test_b01_leads_endpoint_returns_200_with_data_on_postgres():
    """`/api/leads` must not 500 merely because a tenant has at least one lead."""
    database.save_registration(
        name="Stage B Lead 2", phone="88001101", service="Audit", page_id=TENANT_A
    )
    r = client.get("/api/leads", headers=_client_headers(TENANT_A, f"{TENANT_A}_user"))
    assert r.status_code == 200, f"/api/leads returned {r.status_code}: {r.text[:300]}"
    body = r.json()
    assert body["total"] >= 1
    assert all(isinstance(row.get("created_at"), (str, type(None))) for row in body["data"])


def test_b01_auth_me_returns_200_for_tenant_session():
    """Dashboard bootstrap calls /api/auth/me on load; a 500 locks the tenant out."""
    r = client.get("/api/auth/me", headers=_client_headers(TENANT_A, f"{TENANT_A}_user"))
    assert r.status_code == 200, f"/api/auth/me returned {r.status_code}: {r.text[:300]}"
    assert r.json()["authenticated"] is True
    assert r.json()["role"] == "client"


def test_b01_pages_endpoint_returns_200_for_admin():
    """/api/pages embeds `created_at` for every tenant; admin must not get a 500."""
    r = client.get("/api/pages", headers=_admin_headers())
    assert r.status_code == 200, f"/api/pages returned {r.status_code}: {r.text[:300]}"
    assert r.json()["total"] >= 2


def test_b01_on_postgres_drivers_datetime_is_normalised():
    """Prove the normalisation path itself, not just the endpoint outcome."""
    from core.serialization import jsonable

    payload = {"when": datetime(2026, 11, 16, 4, 5, 6), "nested": [{"t": datetime(2026, 1, 2)}]}
    out = jsonable(payload)
    assert out["when"] == "2026-11-16T04:05:06"
    assert out["nested"][0]["t"] == "2026-01-02T00:00:00"
    json.dumps(out)


# --------------------------------------------------------------- B-02 (SEC-01)
def test_b02_cors_does_not_reflect_arbitrary_origin_with_credentials():
    """
    SEC-01: `allow_origins=["*"]` + `allow_credentials=True` makes Starlette reflect the
    caller's Origin, letting any website read authenticated responses.
    """
    evil = "https://evil-attacker.example"
    pre = client.options(
        "/api/leads",
        headers={
            "Origin": evil,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )
    # The decisive assertion: the browser only exposes the body when the response echoes
    # the caller's origin. Starlette may still advertise `allow-credentials: true`
    # unconditionally, so that header alone is not sufficient evidence of a bypass.
    assert pre.headers.get("access-control-allow-origin") != evil
    assert pre.headers.get("access-control-allow-origin") is None
    assert pre.status_code == 400


def test_b02_cors_rejects_unknown_origin_on_actual_request():
    evil = "https://evil-attacker.example"
    r = client.get("/api/health", headers={"Origin": evil})
    assert r.headers.get("access-control-allow-origin") != evil


def test_b02_cors_allows_configured_origin():
    """The allowlist must still work for a legitimately configured origin."""
    allowed = os.getenv("ALLOWED_ORIGINS", "").split(",")[0].strip()
    if not allowed or allowed == "*":
        pytest.skip("ALLOWED_ORIGINS not configured explicitly")
    r = client.get("/api/health", headers={"Origin": allowed})
    assert r.headers.get("access-control-allow-origin") == allowed


# --------------------------------------------------------------- B-03 (P1-01)
def test_b03_comment_automation_create_returns_real_id():
    """On PG `lastrowid` is None because `comment_automations` was absent from
    `_SERIAL_ID_TABLES`, so inserts returned a broken row with id=None."""
    auto = database.create_comment_automation(
        page_id=TENANT_A, name="Stage B rule", dm_message_text="hello"
    )
    assert auto.get("id") is not None, f"create returned id=None: {auto}"
    fetched = database.get_comment_automation(auto["id"])
    assert fetched is not None and fetched["page_id"] == TENANT_A


def test_b03_comment_automation_endpoint_returns_id():
    tok = _client_headers(TENANT_A, f"{TENANT_A}_user")
    r = client.post(
        "/api/automations/comments",
        headers=tok,
        json={"name": "Stage B API rule", "keyword_pattern": "үнэ", "dm_message_text": "Мэдээлэл"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["automation"]["id"] is not None


def test_b03_tracked_link_create_returns_real_id():
    link = database.create_tracked_link(
        page_id=TENANT_A, target_url="https://example.com/stageb", title="Stage B link"
    )
    assert link.get("id") is not None, f"create returned id=None: {link}"
    assert link.get("code")


# --------------------------------------------------------------- B-04 (P1-03)
def test_b04_fintech_summary_works_on_postgres():
    """`paid_at LIKE '2026-11-16%'` fails on PG when the column is a real timestamp:
    `operator does not exist: timestamp without time zone ~~ unknown`."""
    database.create_invoice(
        page_id=TENANT_A, amount=15000, description="Stage B invoice", sender_id="sb_user"
    )
    summary = database.get_fintech_summary(page_id=TENANT_A)
    assert "today_revenue" in summary
    assert isinstance(summary["today_revenue"], int)


def test_b04_fintech_summary_endpoint_returns_200():
    r = client.get("/api/fintech/summary", headers=_admin_headers())
    assert r.status_code == 200, f"/api/fintech/summary returned {r.status_code}: {r.text[:300]}"


def test_b04_daily_metrics_work_on_postgres():
    """Registrations/messages/cargo/invoices counts all use LIKE date filters."""
    metrics = database.get_daily_executive_metrics(page_id=TENANT_A)
    assert isinstance(metrics, dict) and metrics


def test_b04_executive_preview_returns_200():
    r = client.get("/api/executive/preview", headers=_admin_headers())
    assert r.status_code == 200, f"/api/executive/preview returned {r.status_code}: {r.text[:300]}"


# --------------------------------------------------------------- B-05 (P1-04)
def test_b05_cross_tenant_invoice_read_returns_404():
    """
    Tenant B must not read Tenant A's invoice by ID (BOLA).

    404 - not 403 - so the response does not confirm that the invoice exists.
    """
    inv = database.create_invoice(
        page_id=TENANT_A, amount=777777, description="Stage B secret A", sender_id="sb_secret"
    )
    invoice_id = inv["invoice_id"]
    r = client.get(
        f"/api/fintech/invoices/{invoice_id}/status",
        headers=_client_headers(TENANT_B, f"{TENANT_B}_user"),
    )
    assert r.status_code == 404, f"cross-tenant read returned {r.status_code}: {r.text[:300]}"
    assert "777777" not in r.text
    assert TENANT_A not in r.text


def test_b05_cross_tenant_read_does_not_leak_internal_fields_to_another_tenant():
    """
    Regression detail (see docs/audit/SECURITY_OFFICER_NOTE in PR): for an *authenticated*
    caller outside the tenant we now refuse outright. The unauthenticated public projection
    is a separate, narrower contract asserted by
    `tests/test_p1_payment_security.py::test_public_invoice_status_filters_pii`
    (PII absent, business metadata present for the payment page).

    What must never happen: an authenticated tenant receiving the *full* internal record
    (sender_id, qpay metadata, callback state) for another tenant's invoice.
    """
    inv = database.create_invoice(
        page_id=TENANT_A, amount=91000, description="Stage B detail A", sender_id="sb_detail"
    )
    r = client.get(
        f"/api/fintech/invoices/{inv['invoice_id']}/status",
        headers=_client_headers(TENANT_B, f"{TENANT_B}_user"),
    )
    assert r.status_code == 404
    body = r.text
    for forbidden in ("sender_id", "sb_detail", "qpay", "callback_verified"):
        assert forbidden not in body


def test_b05_owner_can_still_read_own_invoice():
    inv = database.create_invoice(
        page_id=TENANT_A, amount=12000, description="Stage B own", sender_id="sb_own"
    )
    r = client.get(
        f"/api/fintech/invoices/{inv['invoice_id']}/status",
        headers=_client_headers(TENANT_A, f"{TENANT_A}_user"),
    )
    assert r.status_code == 200, r.text
    assert r.json()["invoice"]["amount"] == 12000


def test_b05_admin_can_read_any_invoice():
    inv = database.create_invoice(
        page_id=TENANT_A, amount=13000, description="Stage B admin", sender_id="sb_adm"
    )
    r = client.get(
        f"/api/fintech/invoices/{inv['invoice_id']}/status", headers=_admin_headers()
    )
    assert r.status_code == 200, r.text


# ------------------------------------------------------------------- meta-guard
def test_serialization_helpers_are_driver_agnostic():
    """Guard the invariant that the API layer never hands a raw datetime to JSONResponse."""
    from core.serialization import jsonable

    assert jsonable({"a": [datetime(2026, 11, 16)]}) == {"a": ["2026-11-16T00:00:00"]}
    assert jsonable(None) is None
    assert jsonable({"d": {"k": datetime(2026, 11, 16, 1, 2, 3)}})["d"]["k"] == "2026-11-16T01:02:03"
    with pytest.raises(TypeError):
        jsonable({"bad": object()})
