"""
Stage E — E-03: the audit-failure contract must cover *reaching* the database.

Phase 12 (finding F-A) found that Phase 11 tightened `record_audit_log` only from the
point the connection already existed:

    conn = get_connection()      # <-- outside the try
    try:
        cursor = conn.cursor()
        ...

so a failure to *acquire* a connection — PostgreSQL "too many clients", pool
exhaustion, a mid-failover refusal — escaped as a raw driver exception. The callers
catch only `database.AuditLogWriteError`, so the exception travelled all the way to
the framework and the client received the bare

    500 {"detail": "Internal server error"}

*after* the business write had already committed. That is precisely the R17
signature Phase 11 existed to remove: a response that says "nothing happened" about
something that did happen, with no audit row to show for it.

===============================================================================
HOW THESE TESTS INJECT THE FAILURE
===============================================================================
They do NOT mock `record_audit_log`. Mocking it would assert that the endpoint
handles a typed error the mock itself constructed — circular, and blind to the very
hole being fixed. Instead each test patches `database.get_connection` and fails it
**only when the immediate caller is `record_audit_log`**. The business write
(`save_page`, `delete_page`, `set_client_credentials`) goes through the real code
path and commits for real; only the audit's own connection attempt is broken. That
is the narrowest faithful reproduction of the production condition.

The frame check is what keeps the test honest: a blanket patch would fail the
business write too, and the endpoint would then — correctly — report a failed
operation, and the test would pass for the wrong reason.
"""
import inspect
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402
from core import account_keys  # noqa: E402

TEST_SECRET = "phase12-test-secret-0123456789abcdef0123456789"

AUDIT_CALLER = "record_audit_log"


class ConnectionAcquisitionFailure(Exception):
    """Stands in for `too many clients already` / pool exhaustion / refused connect."""


def _require_postgres_or_sqlite():
    from core import db_engine

    return "postgresql" if db_engine.is_postgres() else "sqlite"


@pytest.fixture()
def db(tmp_path, monkeypatch):
    """A private database at head. Same PostgreSQL contract as the Phase 8/10/11 suites."""
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
        path = tmp_path / "p12.db"
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
    """Clear test-owned rows; keep the seeded default page (sessions reference it)."""
    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM audit_logs")
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


@pytest.fixture()
def audit_connection_fails(monkeypatch):
    """Fail `get_connection` ONLY for calls made by `record_audit_log`.

    The business write keeps a working database, exactly as it does in production
    when the pool is full only for the connection the audit tries to take.
    """
    real_get_connection = database.get_connection
    calls = {"audit": 0, "other": 0}

    def patched(*args, **kwargs):
        frame = inspect.currentframe().f_back
        if frame is not None and frame.f_code.co_name == AUDIT_CALLER:
            calls["audit"] += 1
            raise ConnectionAcquisitionFailure("simulated pool exhaustion")
        calls["other"] += 1
        return real_get_connection(*args, **kwargs)

    monkeypatch.setattr(database, "get_connection", patched)
    return calls


def audit_count(action=None):
    conn = database.get_connection()
    try:
        cur = conn.cursor()
        if action is None:
            cur.execute("SELECT COUNT(*) FROM audit_logs")
        else:
            cur.execute("SELECT COUNT(*) FROM audit_logs WHERE action = ?", (action,))
        return int(cur.fetchone()[0])
    finally:
        conn.close()


# ===========================================================================
# The regression that fails on the pre-fix implementation
# ===========================================================================


def test_1201_acquisition_failure_is_converted_into_the_typed_audit_error(db, audit_connection_fails):
    """
    Pre-fix: the raw driver exception escaped `record_audit_log` untyped, so no
    caller that catches `AuditLogWriteError` could ever see it.

    Post-fix: acquisition is inside the protected region and arrives as the same
    explicit contract as any other audit failure.
    """
    with pytest.raises(database.AuditLogWriteError) as excinfo:
        database.record_audit_log("page.upsert", page_id=database.DEFAULT_PAGE_ID)

    assert excinfo.value.action == "page.upsert"
    assert audit_connection_fails["audit"] >= 1, "the injection never fired"


def test_1202_acquisition_failure_preserves_the_original_exception_as_the_cause(db, audit_connection_fails):
    """`raise ... from exc` must survive the widening: the cause is how an operator
    tells 'pool exhausted' apart from 'constraint violated'."""
    with pytest.raises(database.AuditLogWriteError) as excinfo:
        database.record_audit_log("page.upsert", page_id=database.DEFAULT_PAGE_ID)

    assert isinstance(excinfo.value.__cause__, ConnectionAcquisitionFailure)
    assert isinstance(excinfo.value.original, ConnectionAcquisitionFailure)


def test_1203_acquisition_failure_leaves_the_database_usable(db, audit_connection_fails):
    """Nothing was acquired, so nothing may be leaked or half-closed.

    Pre-fix this test also passed — but only because the exception never entered the
    handler at all. It is kept as a guard on the new `conn is not None` branch: a
    botched fix that called `conn.close()` on `None` would surface here.
    """
    for _ in range(5):
        with pytest.raises(database.AuditLogWriteError):
            database.record_audit_log("page.upsert", page_id=database.DEFAULT_PAGE_ID)

    # SQLite blocks every later writer if a connection is leaked; PostgreSQL exhausts
    # the pool. Both are caught by simply writing afterwards.
    database.save_page(page_id="p12-after-acq-failure", name="A", category="general")
    assert database.get_page("p12-after-acq-failure") is not None


def test_1204_page_create_reports_completed_but_unaudited_when_acquisition_fails(
    client, db, audit_connection_fails
):
    """
    THE regression. Pre-fix: 500 `{"detail":"Internal server error"}`, page committed,
    zero audit rows — the caller is told the create failed when it succeeded.
    """
    response = client.post("/api/pages", json={"page_id": "p12-aq-create", "name": "AQ"})

    assert response.status_code == 500
    body = response.json()
    assert body.get("code") == "audit_write_failed", (
        "an acquisition failure must use the same explicit contract as any other "
        f"audit failure, not the framework's opaque 500. Got: {body!r}"
    )
    assert body.get("operation_completed") is True
    assert body.get("audit_action") == "page.upsert"
    assert "Internal server error" not in str(body)

    assert db.get_page("p12-aq-create") is not None, "the business write must have committed"
    assert audit_count("page.upsert") == 0


def test_1205_page_delete_reports_completed_but_unaudited_when_acquisition_fails(
    client, db, audit_connection_fails
):
    """Deletion commits, audit cannot even connect: still `operation_completed: true`."""
    db.save_page(page_id="p12-aq-delete", name="D", category="general")

    response = client.delete("/api/pages/p12-aq-delete")

    assert response.status_code == 500
    body = response.json()
    assert body.get("code") == "audit_write_failed"
    assert body.get("operation_completed") is True
    assert body.get("audit_action") == "page.delete"

    assert db.get_page("p12-aq-delete") is None, "the delete must have committed"


def test_1206_credentials_report_completed_but_unaudited_when_acquisition_fails(
    client, db, audit_connection_fails
):
    """The credential write commits; only the audit connection is unavailable."""
    response = client.post(
        "/api/pages/credentials",
        json={
            "page_id": database.DEFAULT_PAGE_ID,
            "username": "p12_aq_user",
            "password": "P12-Aq-Passw0rd!",
        },
    )

    assert response.status_code == 500
    body = response.json()
    assert body.get("code") == "audit_write_failed"
    assert body.get("operation_completed") is True
    assert body.get("audit_action") == "page.credentials.updated"
    assert audit_count("page.credentials.updated") == 0


def test_1207_acquisition_failure_does_not_leak_internal_detail(client, db, audit_connection_fails):
    """
    The response is served to an admin over the network, and the error text of a
    driver exception routinely contains host, port, user and — for some drivers —
    the password. The typed contract names the *action*, never the cause.
    """
    response = client.post("/api/pages", json={"page_id": "p12-aq-leak", "name": "L"})
    raw = response.text

    assert "simulated pool exhaustion" not in raw
    assert "ConnectionAcquisitionFailure" not in raw
    assert "Traceback" not in raw
    assert "too many clients" not in raw.lower()


def test_1208_failure_after_acquisition_still_cleans_up(db, monkeypatch):
    """`conn` exists but `cursor()` fails: the connection must be rolled back and closed.

    This is the neighbouring case the fix must not break. Unlike the acquisition
    failure, `conn` is live here, so the cleanup branch has real work to do.
    """
    real_get_connection = database.get_connection
    opened = []

    class CursorFailsProxy:
        """A live connection whose `cursor()` fails.

        The driver connection object does not allow attribute assignment
        (`sqlite3.Connection.cursor` is read-only), so the failure is injected with a
        proxy rather than by patching the object in place.
        """

        def __init__(self, conn):
            self._conn = conn

        def cursor(self):
            raise ConnectionAcquisitionFailure("cursor construction failed")

        def rollback(self):
            return self._conn.rollback()

        def close(self):
            return self._conn.close()

        def __getattr__(self, name):
            return getattr(self._conn, name)

    def patched(*args, **kwargs):
        frame = inspect.currentframe().f_back
        if frame is not None and frame.f_code.co_name == AUDIT_CALLER:
            conn = real_get_connection(*args, **kwargs)
            opened.append(conn)
            return CursorFailsProxy(conn)
        return real_get_connection(*args, **kwargs)

    monkeypatch.setattr(database, "get_connection", patched)

    with pytest.raises(database.AuditLogWriteError) as excinfo:
        database.record_audit_log("page.upsert", page_id=database.DEFAULT_PAGE_ID)
    assert isinstance(excinfo.value.__cause__, ConnectionAcquisitionFailure)
    assert opened, "the injection never fired"

    monkeypatch.setattr(database, "get_connection", real_get_connection)

    # If that connection had been leaked, this write would block on SQLite.
    database.save_page(page_id="p12-after-cursor-failure", name="C", category="general")
    assert database.get_page("p12-after-cursor-failure") is not None


def test_1209_business_write_failure_is_not_reported_as_an_audit_failure(client, db, monkeypatch):
    """
    Negative control. The fix must not blur the two failure classes together: if the
    *business* write fails, the answer must still be a failed operation, and there
    must be no `operation_completed: true` and no audit row.

    Pre-fix and post-fix this passes; it exists so a future 'simplification' that
    routes every exception through `_audit_or_report` is caught.
    """
    def boom(*args, **kwargs):
        raise RuntimeError("business write exploded")

    monkeypatch.setattr(database, "save_page", boom)

    response = client.post("/api/pages", json={"page_id": "p12-bizfail", "name": "B"})

    assert response.status_code == 500
    body = response.json()
    assert body.get("code") != "audit_write_failed"
    assert body.get("operation_completed") is not True
    assert audit_count("page.upsert") == 0


# ===========================================================================
# Structural gate — the shape of the fix itself
# ===========================================================================


def test_1210_get_connection_is_inside_record_audit_logs_protected_region():
    """A source-level gate: acquisition must stay inside the `try`.

    A behavioural test cannot distinguish 'inside the try' from 'wrapped in another
    try that re-raises the same type' — and the maintenance hazard is that someone
    moves the call back out for a trivial reason. This pins the structure directly.

    The check is deliberately strict about *where*: an acquisition evaluated before
    the try is the defect, even if an identical call also appears inside it. A first
    draft of this test only asked "does `get_connection` appear anywhere under the
    try", and it passed a hand-written regression of the form

        conn = get_connection()
        try:
            conn = conn or get_connection()

    which is exactly the shape F-A had. The assertion below rejects it.
    """
    import ast

    source = inspect.getsource(database.record_audit_log)
    tree = ast.parse(source.strip())
    func = tree.body[0]
    assert isinstance(func, ast.FunctionDef)

    outer_try = None
    for node in ast.walk(func):
        if isinstance(node, ast.Try) and outer_try is None:
            outer_try = node
            break
    assert outer_try is not None, "record_audit_log no longer has a try block"

    def acquires(node):
        return any(
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "get_connection"
            for n in ast.walk(node)
        )

    # Nothing may acquire the connection before the try is entered.
    for node in func.body:
        if node is outer_try:
            break
        if isinstance(node, ast.Assign) and acquires(node.value):
            raise AssertionError(
                "`get_connection()` is evaluated before the try block of "
                "record_audit_log; that is finding F-A (an untyped audit failure "
                "reported as a 500 after the business write committed)."
            )

    assert outer_try.body, "record_audit_log's try block is empty"
    assert acquires(outer_try.body[0]), (
        "the first statement of record_audit_log's try block must acquire the "
        "connection, so that acquisition failures are converted into "
        "AuditLogWriteError like every other audit failure."
    )


def test_1211_records_which_engine_these_tests_ran_on(db):
    """Diagnostic, not an assertion of behaviour: makes a SQLite-only CI leg visible."""
    from core import db_engine

    engine = "postgresql" if db_engine.is_postgres() else "sqlite"
    print(f"\n[E-03] audit-acquisition contract verified on: {engine}")
    assert engine in {"sqlite", "postgresql"}
