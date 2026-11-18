"""
Stage E — E-03 Phase 3: rotation must survive an audit outage (finding F-C).

`set_client_credentials()` rotates `client_magic_token` and revokes every session for
the page, inside its own transaction, and commits. The endpoint then attempted the
audit and returned the audit error *instead of* `{"status": "success", "data": res}`.

Phase 12 measured what that costs during an audit-store outage:

    rotate attempt 1: HTTP 500 | token delivered: False
    rotate attempt 2: HTTP 500 | token delivered: False
    rotate attempt 3: HTTP 500 | token delivered: False
    token1 (already distributed) valid? : False
    password login still works?         : True

Every retry rotated again and revoked again, so the token the operator still held
stopped working, the replacement was never returned to anyone, and the only way back
in was the password. The first rotation had already succeeded — its result was
discarded.

The correction is deliberately narrow: the audit still fails loudly (500,
`audit_write_failed`, `operation_completed: true`), but the body carries the `data`
that is *already live* in the database. Nothing about the token changes — same
generator, same lifetime, same revocation rules, same authentication path.

These tests also pin what must NOT change: no password in the response, the old token
still dies on rotation, and the conflict/validation contracts are untouched.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402
from core import account_keys  # noqa: E402

TEST_SECRET = "e03-phase3-test-secret-0123456789abcdef0123"
USERNAME = "e03_rot_user"
PASSWORD = "Pw-E03-Rotation!1"


@pytest.fixture()
def db(tmp_path, monkeypatch):
    db_url = (os.getenv("DATABASE_URL") or "").strip()
    require_pg = (os.getenv("R10_REQUIRE_POSTGRES") or "").strip() == "1"

    if db_url:
        monkeypatch.setenv("DATABASE_URL", db_url)
    else:
        if require_pg:
            pytest.fail("R10_REQUIRE_POSTGRES=1 but DATABASE_URL is unset")
        monkeypatch.delenv("DATABASE_URL", raising=False)
        path = tmp_path / "e03p3.db"
        monkeypatch.setenv("DB_PATH", str(path))
        monkeypatch.setattr(database, "DB_PATH", str(path))

    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()
    database.init_db()
    return database


@pytest.fixture()
def admin(db):
    """A factory: rotation revokes sessions, so a test that retries needs a new one."""
    from fastapi.testclient import TestClient

    import main

    def make():
        client = TestClient(main.app, raise_server_exceptions=False)
        token = database.create_session(role="admin", page_id=database.DEFAULT_PAGE_ID)
        client.headers.update({"Authorization": f"Bearer {token}"})
        return client

    return make


@pytest.fixture()
def audit_fails(monkeypatch):
    def boom(*args, **kwargs):
        raise database.AuditLogWriteError(
            args[0] if args else "page.credentials.updated", RuntimeError("audit store down")
        )

    monkeypatch.setattr(database, "record_audit_log", boom)


def _rotate(admin, username=USERNAME, password=PASSWORD):
    client = admin()
    return client.post(
        "/api/pages/credentials",
        json={
            "page_id": database.DEFAULT_PAGE_ID,
            "username": username,
            "password": password,
        },
    )


def _live_token():
    page = database.get_page(
        database.DEFAULT_PAGE_ID, mask_secrets=False, include_magic_token=True
    )
    return page.get("client_magic_token")


# ===========================================================================
# The regression that fails on the pre-fix implementation
# ===========================================================================


def test_3001_a_committed_rotation_is_delivered_even_when_the_audit_fails(admin, db, audit_fails):
    """
    Pre-fix: HTTP 500 with no `data`, so the caller never learns the token that is
    already live in the database and that replaced the one they were holding.
    """
    response = _rotate(admin)

    assert response.status_code == 500, "the audit gap must stay loud"
    body = response.json()
    assert body["code"] == "audit_write_failed"
    assert body["operation_completed"] is True
    assert "data" in body, (
        "the rotation already committed; withholding the new token leaves the caller "
        "holding a dead one with no replacement"
    )
    assert body["data"]["magic_token"], "a live token must be returned, not a placeholder"


def test_3002_the_delivered_token_is_the_one_the_database_holds(admin, db, audit_fails):
    """Not a copy, not a stale value: the exact token the authentication path reads."""
    body = _rotate(admin).json()
    delivered = body["data"]["magic_token"]

    assert delivered == _live_token()
    assert database.authenticate_client(delivered) is not None


def test_3003_rotation_still_invalidates_the_previously_distributed_token(admin, db):
    """
    Negative control for the fix: it must not have quietly made rotation
    non-destructive. The old token dies, exactly as before.
    """
    first = _rotate(admin).json()["data"]["magic_token"]
    assert database.authenticate_client(first) is not None

    second = _rotate(admin).json()["data"]["magic_token"]

    assert second != first
    assert database.authenticate_client(first) is None, "the rotated-out token must stop working"
    assert database.authenticate_client(second) is not None


def test_3004_repeated_retries_during_an_outage_always_hand_back_a_working_token(
    admin, db, audit_fails
):
    """
    The measured failure mode: three retries, three rotations, three revocations, and
    the operator's token was silently killed each time. Now every attempt returns the
    live token, so the caller is never left holding only a dead one.
    """
    for attempt in range(3):
        response = _rotate(admin)
        body = response.json()
        token = body.get("data", {}).get("magic_token")

        assert token, f"attempt {attempt + 1} withheld the token during the outage"
        assert database.authenticate_client(token) is not None, (
            f"attempt {attempt + 1} returned a token that does not authenticate"
        )
        assert body["code"] == "audit_write_failed"


def test_3005_the_audit_gap_is_reported_on_every_outage_retry(admin, db, audit_fails):
    """Delivery must not become a way to hide the audit failure."""
    for _ in range(2):
        body = _rotate(admin).json()
        assert body["code"] == "audit_write_failed"
        assert body["operation_completed"] is True
        assert body["audit_action"] == "page.credentials.updated"


def test_3006_recovery_after_the_outage_is_a_normal_success(admin, db):
    """When the audit store comes back the endpoint returns its documented shape."""
    _rotate(admin)
    response = _rotate(admin)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["data"]["magic_token"]
    assert "code" not in body


# ===========================================================================
# Contracts that must NOT move
# ===========================================================================


def test_3011_no_password_ever_appears_in_a_rotation_response(admin, db, audit_fails):
    response = _rotate(admin)
    assert PASSWORD not in response.text
    assert "password" not in response.text.lower()


def test_3012_token_format_and_entropy_are_unchanged(admin, db):
    """Same generator: `secrets.token_urlsafe(24)`, unchanged by this phase."""
    token = _rotate(admin).json()["data"]["magic_token"]
    assert isinstance(token, str)
    assert len(token) >= 32, "token_urlsafe(24) yields ~32 chars; the fix must not shorten it"
    assert len(set(token)) > 8, "must still look like a random token"


def test_3013_username_conflict_still_returns_409_not_500(admin, db, audit_fails):
    """The Phase 4.1 / 0005 non-disclosure contract is untouched by the F-C fix."""
    _rotate(admin, username="e03_owner_a", password=PASSWORD)

    other = database.get_all_pages()
    target = next((p["page_id"] for p in other if p["page_id"] != database.DEFAULT_PAGE_ID), None)
    if target is None:
        database.save_page(page_id="e03-tenant-b", name="B", category="general")
        target = "e03-tenant-b"

    client = admin()
    response = client.post(
        "/api/pages/credentials",
        json={"page_id": target, "username": "e03_owner_a", "password": PASSWORD},
    )
    assert response.status_code == 409, (
        "a username conflict must stay a 409 even while the audit store is down"
    )
    assert "audit_write_failed" not in response.text


def test_3014_missing_username_still_returns_400(admin, db):
    client = admin()
    response = client.post(
        "/api/pages/credentials",
        json={"page_id": database.DEFAULT_PAGE_ID, "username": "", "password": PASSWORD},
    )
    assert response.status_code == 400


def test_3015_rotation_does_not_expose_internal_error_detail(admin, db, audit_fails):
    raw = _rotate(admin).text
    assert "audit store down" not in raw
    assert "Traceback" not in raw
    assert "AuditLogWriteError" not in raw
