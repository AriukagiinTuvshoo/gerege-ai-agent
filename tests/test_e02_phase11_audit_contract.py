"""
Stage E — E-02 Phase 11: the audit-logging contract (R17) and R18.

Written after R17 was reported as a naming mismatch that turned three admin
endpoints into 500s. Phase 11 verified that first, and the report was incomplete in
three ways that each matter more than the original symptom:

  * five call sites were wrong, not three — `fintech_service.py` also used
    `target_type`/`target_id`, inside an `except Exception: pass`, so every payment
    confirmation was silently unaudited with no error anywhere;
  * the business write COMMITS before the audit call runs, so the 500 told the
    caller the operation had failed when it had in fact succeeded;
  * the credential-conflict path raised before its return, so a 409 became a 500,
    breaking the Phase 4.1/`0005` non-disclosure contract.

And one defect that R17 had been masking:

  * R18 — `audit_logs.page_id` is `ON DELETE SET NULL`, so auditing a deletion with
    the just-deleted `page_id` fails the foreign key. Every deletion audit failed;
    nobody could see it because the request died one line earlier on the TypeError.

===============================================================================
WHAT THESE TESTS ARE ALLOWED TO ASSERT
===============================================================================
Auditing is NOT atomic with the business write, and these tests do not pretend it
is. `save_page`, `delete_page` and `set_client_credentials` each own their
transaction; a shared one would mean rewriting all three. The contract under test
is therefore:

  * a successful operation writes exactly one correct audit row, and
  * an operation whose audit write FAILS is reported as `audit_write_failed` with
    `operation_completed: true` — never as "the operation failed", and never
    silently.

The audit-failure tests inject a failure at `record_audit_log`, which is the real
boundary, so they exercise the endpoint's actual error path rather than a mock of it.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402
from core import account_keys  # noqa: E402

TEST_SECRET = "phase11-test-secret-0123456789abcdef0123456789"

SECRET_TOKEN = "EAAB-secret-page-token-do-not-log"
SECRET_VERIFY = "verify-secret-do-not-log"
SECRET_GEMINI = "AIza-secret-gemini-do-not-log"
SECRET_PASSWORD = "Pw-Phase11-Sup3rSecret"


def _require_postgres_or_sqlite():
    from core import db_engine

    return "postgresql" if db_engine.is_postgres() else "sqlite"


def engine_id() -> str:
    from core import db_engine

    if db_engine.is_postgres():
        try:
            conn = database.get_connection()
            cur = conn.cursor()
            cur.execute("SHOW server_version")
            return f"postgresql {cur.fetchone()[0]}"
        except Exception:
            return "postgresql"
    return f"sqlite {__import__('sqlite3').sqlite_version}"


@pytest.fixture()
def db(tmp_path, monkeypatch):
    """A private database at head. Same PostgreSQL contract as the Phase 8/10 suites."""
    db_url = (os.getenv("DATABASE_URL") or "").strip()
    require_pg = (os.getenv("R10_REQUIRE_POSTGRES") or "").strip() == "1"

    if db_url:
        monkeypatch.setenv("DATABASE_URL", db_url)
    else:
        if require_pg:
            pytest.fail(
                "R10_REQUIRE_POSTGRES=1 but DATABASE_URL is unset: these tests would run "
                "on SQLite and would not prove PostgreSQL behaviour."
            )
        monkeypatch.delenv("DATABASE_URL", raising=False)
        path = tmp_path / "p11.db"
        monkeypatch.setenv("DB_PATH", str(path))
        monkeypatch.setattr(database, "DB_PATH", str(path))

    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()

    database.init_db()

    from core import db_engine

    if require_pg and not db_engine.is_postgres():
        pytest.fail("R10_REQUIRE_POSTGRES=1 but the active engine is not PostgreSQL")

    _delete_all()
    return database


def _delete_all():
    """Clear test-owned rows so audit counts are attributable to the test that made them.

    Deliberately does NOT delete every page: `create_session()` writes a session row
    that references `DEFAULT_PAGE_ID`, so removing the seeded tenant makes session
    creation fail with a foreign-key error. Only the seeded default page is kept; every
    test uses its own `p11-*` ids, and the audit table is cleared wholesale because
    `audit_logs.page_id` is `ON DELETE SET NULL` and no row is orphaned by doing so.
    """
    conn = database.get_connection()
    try:
        # Phase 13: `audit_logs` is append-only now, so clearing it goes through the
        # sanctioned test-only helper, which lifts the guard, clears, and verifies the
        # guard is back before returning. Same rows cleared as before; no assertion in
        # this file is weakened by it.
        from conftest import clear_audit_logs_for_test

        clear_audit_logs_for_test(conn)
        cur = conn.cursor()
        cur.execute("DELETE FROM pages WHERE page_id <> ?", (database.DEFAULT_PAGE_ID,))
        conn.commit()
    finally:
        conn.close()


@pytest.fixture()
def client(db):
    from fastapi.testclient import TestClient

    import main

    test_client = TestClient(main.app, raise_server_exceptions=False)
    token = database.create_session(role="admin", page_id=database.DEFAULT_PAGE_ID)
    test_client.headers.update({"Authorization": f"Bearer {token}"})
    return test_client


def audit_rows(action=None):
    conn = database.get_connection()
    try:
        cur = conn.cursor()
        sql = (
            "SELECT action, page_id, actor_role, resource_type, resource_id, details_json "
            "FROM audit_logs"
        )
        if action is not None:
            cur.execute(sql + " WHERE action = ?", (action,))
        else:
            cur.execute(sql)
        return [tuple(r) for r in cur.fetchall()]
    finally:
        conn.close()


def audit_count(action=None):
    return len(audit_rows(action))


# ===========================================================================
# The regression that fails on the pre-fix implementation
# ===========================================================================


def test_1101_all_audit_callers_use_the_supported_keyword_names(db):
    """
    No call site may pass a keyword `record_audit_log` does not accept.

    Pre-fix: 5 call sites passed `target_type`/`target_id`, which the function has
    never accepted in any commit in this repository. This is checked statically
    across the whole tree so a NEW bad call site cannot be introduced either —
    the defect was copy-pasted five times within one commit, so a test that only
    covered the three reported endpoints would miss the fourth and fifth.
    """
    import ast
    import inspect
    import pathlib

    signature = inspect.signature(database.record_audit_log)
    accepted = set(signature.parameters)
    assert "resource_type" in accepted and "resource_id" in accepted
    assert "target_type" not in accepted and "target_id" not in accepted, (
        "the function signature changed: this contract is the one 8 other callers use"
    )

    root = pathlib.Path(__file__).resolve().parent.parent
    offenders = []
    for path in root.rglob("*.py"):
        text = str(path)
        if "/.scratch/" in text or "/tests/" in text or "/.git/" in text:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "record_audit_log"
            ):
                for kw in node.keywords:
                    if kw.arg is not None and kw.arg not in accepted:
                        offenders.append(
                            f"{path.relative_to(root)}:{node.lineno} passes {kw.arg}="
                        )
    assert offenders == [], (
        "call site(s) pass keywords record_audit_log does not accept:\n  "
        + "\n  ".join(offenders)
    )


# ===========================================================================
# POST /api/pages -- page.upsert
# ===========================================================================


def test_1111_page_create_succeeds_and_writes_one_audit_row(client, db):
    """
    Pre-fix: HTTP 500, page created anyway, ZERO audit rows.
    This is the test that fails on the old code, on both engines.
    """
    response = client.post(
        "/api/pages",
        json={
            "page_id": "p11-create",
            "name": "Phase 11",
            "page_access_token": SECRET_TOKEN,
            "verify_token": SECRET_VERIFY,
            "gemini_api_key": SECRET_GEMINI,
        },
    )
    assert response.status_code == 200, response.text
    assert db.get_page("p11-create") is not None, "the page was not created"

    rows = audit_rows("page.upsert")
    assert len(rows) == 1, f"expected exactly one page.upsert row, got {rows}"
    action, page_id, actor_role, resource_type, resource_id, details = rows[0]
    assert action == "page.upsert"
    assert page_id == "p11-create", "the audit row is not associated with the page"
    assert actor_role == "admin"
    assert (resource_type, resource_id) == ("page", "p11-create")


def test_1112_page_create_audit_details_contain_no_secrets(client, db):
    """
    The endpoint receives three secrets. An audit log that records them is itself a
    disclosure, so the details are checked for every one, and the whole serialised
    row is checked so a new field cannot leak by accident.
    """
    response = client.post(
        "/api/pages",
        json={
            "page_id": "p11-secrets",
            "name": "Secrets",
            "page_access_token": SECRET_TOKEN,
            "verify_token": SECRET_VERIFY,
            "gemini_api_key": SECRET_GEMINI,
        },
    )
    assert response.status_code == 200

    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM audit_logs WHERE action = 'page.upsert'")
        raw = repr(cur.fetchall()).lower()
    finally:
        conn.close()

    for secret in (SECRET_TOKEN, SECRET_VERIFY, SECRET_GEMINI):
        assert secret.lower() not in raw, f"a secret leaked into audit_logs: {secret!r}"


def test_1113_page_update_writes_one_row_not_two(client, db):
    """
    POST /api/pages is an upsert. Re-saving an existing page must produce exactly one
    additional `page.upsert` event — not one per column and not a duplicate.
    """
    for _ in range(2):
        response = client.post("/api/pages", json={"page_id": "p11-twice", "name": "T"})
        assert response.status_code == 200
    assert audit_count("page.upsert") == 2, audit_rows("page.upsert")


def test_1114_page_create_unauthorized_writes_no_audit_row(db):
    """401 before any work: no page, no audit row. Authorization is unchanged."""
    from fastapi.testclient import TestClient

    import main

    anonymous = TestClient(main.app, raise_server_exceptions=False)
    response = anonymous.post("/api/pages", json={"page_id": "p11-anon", "name": "A"})
    assert response.status_code == 401
    assert db.get_page("p11-anon") is None
    assert audit_count() == 0, "an unauthenticated request produced an audit row"


def test_1115_page_create_validation_failure_writes_no_audit_row(client, db):
    """400 before any work: no page, no `page.upsert`, and nothing claiming success."""
    response = client.post("/api/pages", json={"page_id": "p11-noname", "name": ""})
    assert response.status_code == 400
    assert db.get_page("p11-noname") is None
    assert audit_count("page.upsert") == 0


def test_1116_page_create_audit_failure_is_reported_as_completed_but_unaudited(
    client, db, monkeypatch
):
    """
    The contract that replaces silent loss.

    When the audit store fails, the endpoint must NOT say the operation failed — it
    did not. It must say the operation completed and was not audited. Status stays
    500 because an invariant was not met, but the body carries `operation_completed`.
    """
    monkeypatch.setattr(
        database,
        "record_audit_log",
        lambda *a, **k: (_ for _ in ()).throw(
            database.AuditLogWriteError("page.upsert", RuntimeError("audit store down"))
        ),
    )
    response = client.post("/api/pages", json={"page_id": "p11-auditfail", "name": "AF"})

    assert response.status_code == 500
    body = response.json()
    assert body["code"] == "audit_write_failed"
    assert body["operation_completed"] is True, (
        "the response must not imply the page was not created"
    )
    assert body["audit_action"] == "page.upsert"
    # ...and it must not lie in the other direction either.
    assert db.get_page("p11-auditfail") is not None, "the write should have committed"


# ===========================================================================
# DELETE /api/pages -- page.delete (and R18)
# ===========================================================================


def test_1121_page_delete_succeeds_and_writes_one_audit_row(client, db):
    """
    Pre-fix: HTTP 500, page deleted anyway, zero audit rows.

    This also pins R18: the audit row must record the deleted page in `resource_id`
    with `page_id = NULL`, because `audit_logs.page_id` is `ON DELETE SET NULL` and a
    row may not reference a page that no longer exists.
    """
    client.post("/api/pages", json={"page_id": "p11-del", "name": "D"})
    assert db.get_page("p11-del") is not None

    response = client.delete("/api/pages/p11-del")
    assert response.status_code == 200, response.text
    assert db.get_page("p11-del") is None, "the page was not deleted"

    rows = audit_rows("page.delete")
    assert len(rows) == 1, f"expected exactly one page.delete row, got {rows}"
    action, page_id, actor_role, resource_type, resource_id, details = rows[0]
    assert page_id is None, (
        "R18: a row may not reference the deleted page, or the foreign key fails"
    )
    assert (resource_type, resource_id) == ("page", "p11-del"), (
        "the deleted page must still be identifiable from resource_id"
    )
    assert "p11-del" in (details or "")


def test_1122_audit_row_survives_the_tenant_it_describes(client, db):
    """
    The whole point of `ON DELETE SET NULL` on this column: audit history outlives
    the tenant. A deletion must not erase the history.
    """
    client.post("/api/pages", json={"page_id": "p11-survive", "name": "S"})
    assert audit_count("page.upsert") == 1
    client.delete("/api/pages/p11-survive")
    assert audit_count("page.upsert") == 1, "deleting the page erased its history"
    assert audit_count("page.delete") == 1


def test_1123_page_delete_unauthorized_writes_no_audit_row(client, db):
    from fastapi.testclient import TestClient

    import main

    client.post("/api/pages", json={"page_id": "p11-del-anon", "name": "A"})
    before = audit_count()
    anonymous = TestClient(main.app, raise_server_exceptions=False)
    assert anonymous.delete("/api/pages/p11-del-anon").status_code == 401
    assert db.get_page("p11-del-anon") is not None, "an unauthenticated delete succeeded"
    assert audit_count() == before, "an unauthenticated request produced an audit row"


def test_1124_page_delete_validation_failure_writes_no_audit_row(client, db):
    """Deleting the default page is refused with 400 and must not be audited as deleted."""
    response = client.delete(f"/api/pages/{database.DEFAULT_PAGE_ID}")
    assert response.status_code == 400
    assert audit_count("page.delete") == 0
    assert db.get_page(database.DEFAULT_PAGE_ID) is not None


def test_1125_page_delete_audit_failure_does_not_un_delete_or_mislead(client, db, monkeypatch):
    client.post("/api/pages", json={"page_id": "p11-del-af", "name": "AF"})
    monkeypatch.setattr(
        database,
        "record_audit_log",
        lambda *a, **k: (_ for _ in ()).throw(
            database.AuditLogWriteError("page.delete", RuntimeError("audit store down"))
        ),
    )
    response = client.delete("/api/pages/p11-del-af")
    assert response.status_code == 500
    body = response.json()
    assert body["code"] == "audit_write_failed"
    assert body["operation_completed"] is True
    assert db.get_page("p11-del-af") is None, "the delete had already committed"


# ===========================================================================
# POST /api/pages/credentials -- page.credentials.updated / .conflict
# ===========================================================================


def test_1131_credentials_update_succeeds_and_writes_one_audit_row(client, db):
    """Pre-fix: HTTP 500, credential written anyway, zero audit rows."""
    client.post("/api/pages", json={"page_id": "p11-cred", "name": "C"})
    response = client.post(
        "/api/pages/credentials",
        json={"page_id": "p11-cred", "username": "p11_user", "password": SECRET_PASSWORD},
    )
    assert response.status_code == 200, response.text

    row = db.get_page("p11-cred")
    assert row and row.get("client_username") == "p11_user", "the credential was not set"

    rows = audit_rows("page.credentials.updated")
    assert len(rows) == 1, f"expected exactly one row, got {rows}"
    action, page_id, actor_role, resource_type, resource_id, details = rows[0]
    assert page_id == "p11-cred", "the audit row is not associated with the page"
    assert (resource_type, resource_id) == ("page", "p11-cred")


def test_1132_credentials_audit_contains_no_password(client, db):
    """The audit row must never carry the password that was set."""
    client.post("/api/pages", json={"page_id": "p11-cred-secret", "name": "C"})
    client.post(
        "/api/pages/credentials",
        json={
            "page_id": "p11-cred-secret",
            "username": "p11_secret_user",
            "password": SECRET_PASSWORD,
        },
    )
    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM audit_logs WHERE action = 'page.credentials.updated'")
        rows = cur.fetchall()
        raw = repr(rows).lower()
    finally:
        conn.close()

    # Assert the row EXISTS first. Without this the test passes on the pre-fix code for
    # the wrong reason: there is no row to leak a secret from, which says nothing about
    # redaction. Measured -- pre-fix this endpoint wrote zero audit rows.
    assert len(rows) == 1, (
        f"no audit row exists, so this test cannot speak about redaction: {rows!r}"
    )
    assert SECRET_PASSWORD.lower() not in raw, "the password leaked into audit_logs"
    # The username may be a phone number or an email, so only its length is recorded.
    assert "p11_secret_user" not in raw, "the username itself was recorded"


def test_1133_credential_conflict_returns_409_and_audits_the_refusal(client, db):
    """
    Pre-fix: HTTP 500 instead of 409, and no audit row for the refusal.

    The 409 is the Phase 4.1/`0005` non-disclosure contract. Auditing the refusal is
    best-effort and must never mask it.
    """
    client.post("/api/pages", json={"page_id": "p11-owner", "name": "O"})
    client.post("/api/pages", json={"page_id": "p11-thief", "name": "T"})
    client.post(
        "/api/pages/credentials",
        json={"page_id": "p11-owner", "username": "p11_shared", "password": SECRET_PASSWORD},
    )

    response = client.post(
        "/api/pages/credentials",
        json={"page_id": "p11-thief", "username": "p11_shared", "password": "Other-Pw-1"},
    )
    assert response.status_code == 409, f"expected 409, got {response.status_code}: {response.text}"
    # The non-disclosure contract: the body must not name the other tenant.
    assert "p11-owner" not in response.text, "the 409 leaks the owning tenant"

    rows = audit_rows("page.credentials.conflict")
    assert len(rows) == 1, f"the refusal was not audited: {audit_rows()}"
    assert rows[0][1] == "p11-thief", "the refusal is associated with the wrong page"
    # The other tenant must not be named in the audit row either.
    assert "p11_shared" not in (rows[0][5] or ""), "the audit row stores the shared username"


def test_1134_credential_conflict_still_returns_409_when_auditing_fails(client, db, monkeypatch):
    """An audit outage must not turn a 409 into a 500."""
    client.post("/api/pages", json={"page_id": "p11-owner2", "name": "O"})
    client.post("/api/pages", json={"page_id": "p11-thief2", "name": "T"})
    client.post(
        "/api/pages/credentials",
        json={"page_id": "p11-owner2", "username": "p11_shared2", "password": SECRET_PASSWORD},
    )

    monkeypatch.setattr(
        database,
        "record_audit_log",
        lambda *a, **k: (_ for _ in ()).throw(
            database.AuditLogWriteError("page.credentials.conflict", RuntimeError("down"))
        ),
    )
    response = client.post(
        "/api/pages/credentials",
        json={"page_id": "p11-thief2", "username": "p11_shared2", "password": "Other-Pw-1"},
    )
    assert response.status_code == 409, "an audit failure masked the 409"


def test_1135_credentials_unauthorized_writes_no_audit_row(client, db):
    from fastapi.testclient import TestClient

    import main

    client.post("/api/pages", json={"page_id": "p11-cred-anon", "name": "A"})
    before = audit_count()
    anonymous = TestClient(main.app, raise_server_exceptions=False)
    response = anonymous.post(
        "/api/pages/credentials",
        json={"page_id": "p11-cred-anon", "username": "x", "password": "y"},
    )
    assert response.status_code == 401
    assert audit_count() == before


def test_1136_credentials_validation_failure_writes_no_audit_row(client, db):
    client.post("/api/pages", json={"page_id": "p11-cred-val", "name": "V"})
    response = client.post(
        "/api/pages/credentials", json={"page_id": "p11-cred-val", "username": ""}
    )
    assert response.status_code == 400
    assert audit_count("page.credentials.updated") == 0


def test_1137_credentials_audit_failure_is_reported_as_completed(client, db, monkeypatch):
    client.post("/api/pages", json={"page_id": "p11-cred-af", "name": "AF"})
    monkeypatch.setattr(
        database,
        "record_audit_log",
        lambda *a, **k: (_ for _ in ()).throw(
            database.AuditLogWriteError("page.credentials.updated", RuntimeError("down"))
        ),
    )
    response = client.post(
        "/api/pages/credentials",
        json={"page_id": "p11-cred-af", "username": "p11_af_user", "password": SECRET_PASSWORD},
    )
    assert response.status_code == 500
    assert response.json()["operation_completed"] is True
    row = db.get_page("p11-cred-af")
    assert row and row.get("client_username") == "p11_af_user", "the credential committed"


# ===========================================================================
# Database failure, and the boundary of the contract
# ===========================================================================


def test_1141_database_failure_on_the_business_write_is_not_reported_as_success(client, db, monkeypatch):
    """If the write itself fails, the response must not claim success or emit an audit row."""
    monkeypatch.setattr(
        database, "save_page", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("db down"))
    )
    response = client.post("/api/pages", json={"page_id": "p11-dbfail", "name": "X"})
    assert response.status_code == 500
    assert audit_count("page.upsert") == 0, "an audit row was written for a failed write"


def test_1142_record_audit_log_raises_a_typed_error_and_never_leaks_the_connection(db):
    """
    The helper must convert any driver failure into `AuditLogWriteError` (so callers
    can distinguish it) and must always close its connection. An unclosed SQLite
    connection blocks every later writer, which Phase 10 measured the hard way.
    """
    with pytest.raises(database.AuditLogWriteError) as excinfo:
        database.record_audit_log("page.upsert", page_id="no-such-page-exists")
    assert excinfo.value.action == "page.upsert"
    assert isinstance(excinfo.value.__cause__, Exception)

    # The database must still be usable: the failed call released its connection.
    database.save_page(page_id="p11-after-audit-failure", name="A", category="general")
    assert database.get_page("p11-after-audit-failure") is not None


def test_1143_audit_write_succeeds_and_returns_the_row_id(db):
    log_id = database.record_audit_log(
        "page.upsert", page_id=None, actor_role="admin", resource_type="page", resource_id="x"
    )
    assert isinstance(log_id, int) and log_id > 0
    assert audit_count("page.upsert") == 1
