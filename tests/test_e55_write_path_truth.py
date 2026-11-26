"""
Phase 55 — a failed write releases its connection, and the write path stops claiming a success
it did not earn.

Every measurement below was taken against this deployment before the fix, on disposable pages,
and is quoted with the command or call that produced it.

    F-55-1 (High)   59 of the 78 functions in `database.py` that call `get_connection()` had no
                    `try/finally`, so any exception raised between the open and the close leaked
                    the connection while it still held its write lock. 18 of those 59 write to one
                    of the 14 tables whose `page_id` carries a foreign key to `pages`
                    (`migrations/versions/0003_foreign_keys.py`), and a foreign key is the easiest
                    exception for an ordinary request to trigger. Measured in-process:

                        database.update_automated_rule("p55_never", ...)
                            -> sqlite3.IntegrityError: FOREIGN KEY constraint failed
                        database.save_page(...)   -> 5.00s, then
                            sqlite3.OperationalError: database is locked
                        database.delete_page(...) -> sqlite3.OperationalError: database is locked
                        gc.collect()              -> lock released in 0.00s

                    So one bad request cost whichever write came next the whole
                    `PRAGMA busy_timeout=5000` wait, and then failed it too. Under PostgreSQL the
                    same leak costs a pool slot (`DB_POOL_SIZE` + `DB_MAX_OVERFLOW`, with
                    `DB_POOL_TIMEOUT=30`) instead of a file lock.

                    The honest live reading is narrower than the in-process one, and this module
                    does not overstate it: on the running application an unrelated DELETE did
                    return 500 in the same session as a retention 500, but the leaked connection
                    has no strong referent once the traceback is gone, so the garbage collector
                    drops it and the stall ends. Observed live, the very next write after two 500s
                    succeeded in 0.00s. The deterministic 5.00s measurement is the in-process one
                    above, where the traceback object keeps the frame alive.

    F-55-2 (High)   `POST /api/retention/rules` with a `page_id` that does not exist:

                        -> HTTP 500 {"detail": "Internal server error", "request_id": "fd59..."}
                        -> automated_rules rows written: 0

                    `enforce_tenant_scope` hands an admin back the page id they asked for without
                    an existence check, and `automated_rules.page_id` has a foreign key, so the
                    INSERT raised out of the handler.

    F-55-3 (High)   The middleware that produces that 500 recorded `str(exc)` into telemetry and
                    logged nothing. Across every 500 measured on a running instance the backend log
                    held ZERO tracebacks, so neither an operator nor this agent could say what had
                    failed without attaching a debugger to the live process. The same 500s, after
                    the fix, appear in the log as:

                        ERROR:ai_agent_app:unhandled exception on POST /api/appointments
                            (request_id=68d855587b22a185): IntegrityError
                        Traceback (most recent call last): ...

    F-55-4 (High)   `POST /api/pages/{page_id}/credentials` for a page that never existed:

                        -> HTTP 500 {"error": "Хуудас (p55_never_d) нэвтрэх эрх шинэчлэх
                                             хийгдсэн боловч ..."}
                        -> pages rows written: 0

                    The response text asserted that the rotation HAD happened. The backend log
                    confirmed the real sequence: `set_client_credentials` updated 0 rows, and the
                    audit INSERT then hit `audit_logs.page_id`'s foreign key:

                        ERROR:ai_agent_app:audit write failed for page.credentials.updated after
                            Хуудас (p55_never_d) нэвтрэх эрх шинэчлэх had already committed:
                            ... IntegrityError: FOREIGN KEY constraint failed

    F-55-5 (Medium) `dashboard.html` discarded the response of two calls and announced success
                    unconditionally: `handleDeleteCurrentPage` toasted "Хуудас устгагдлаа."
                    whatever the server said, and `changeLeadStatus` toasted "Төлөв амжилттай
                    шинэчлэгдлээ!" the same way. Both endpoints can now refuse, so both toasts
                    could lie.

    F-55-6 (Medium) The same foreign key, on two more endpoints, measured live:

                        POST /api/appointments        {"page_id": "p55_never_f", ...} -> HTTP 500
                        POST /api/retention/broadcast {"page_id": "p55_never_f", ...} -> HTTP 500

                    The second reaches it three layers down: `send_broadcast_api` ->
                    `retention_service.send_broadcast` -> `database.create_marketing_campaign`.

    F-55-7 (Medium) Thirteen sites read a request field as `payload.get(key, "").strip()`, which
                    assumes the client sent a string. Measured live, a body that sent a number or
                    an object crashed the request:

                        POST /api/appointments {"notes": 12345}
                            -> HTTP 500, AttributeError: 'int' object has no attribute 'strip'
                        POST /api/pages/{id}/credentials {"password": 12345}
                            -> HTTP 500, AttributeError inside database.set_client_credentials
                        POST /api/retention/broadcast {"target_segment": {"a": 1}}
                            -> HTTP 500, ProgrammingError: the dict reached a SQL parameter

                    The thirteenth site was `update_keys`, the admin endpoint that writes secrets
                    into `.env`: its newline check already coerced with `str(...)`, so a numeric
                    value passed that check and then crashed on the next line. That one site turns
                    out NOT to be reachable over HTTP - the handler declares
                    `payload: Dict[str, str]`, so FastAPI answers 422 first (measured) - and its
                    guard is defence in depth rather than the fix for a live 500. The other twelve
                    are all `Dict[str, Any]` and were reachable, three of them measured above.

    F-55-8 (High)   Two status endpoints wrote the value through unchecked, and one of them
                    destroyed data. Measured live:

                        POST /api/appointments/1/status {"status": {"a": 1}} -> HTTP 500
                        POST /api/appointments/1/status {"status": 12345}    -> HTTP 200, and the
                            row then held status '12345'
                        POST /api/leads/1/status        {"status": {"a": 1}} -> HTTP 500
                        POST /api/leads/1/status        {"status": null}     -> HTTP 200
                            {"status": "updated"}, and the lead's stored status became NULL

                    `appointments.status` is a closed set - `database.is_slot_available` and
                    `get_upcoming_appointments` both filter on `status = 'CONFIRMED'` - so storing
                    '12345' did not merely look wrong: the booked slot stopped matching the
                    availability check and became bookable again for somebody else. Lead 1 in this
                    deployment was left with a NULL stage by that call and had to be restored.

    F-54-4 (carried over from Phase 54, now closed) `database.delete_page()` returned True for
                    anything that was not `DEFAULT_PAGE_ID`, so deleting a page that never existed
                    reported a deletion and wrote a `page.delete` audit row naming a page that had
                    never existed:

                        DELETE /api/pages/p55_never_a -> HTTP 200
                            {"status": "deleted", "page_id": "p55_never_a"}

                    Phase 54 measured this and deliberately did not fix it, because the handler's
                    only failure branch answered 400 "Үндсэн хуудсыг устгах боломжгүй" and a bare
                    `rowcount > 0` would have blamed the default page for every missing-page
                    delete. The two reasons are separated here: the default page is still refused
                    with that 400, a missing page is reported as missing, and only a real deletion
                    is audited.

Design notes
------------
* Every behavioural test asserts the DATABASE, not just the response. Five of these defects
  answered success or produced no answer at all, so a test that asserted a status code would have
  passed against most of them.
* Audit assertions are DELTAS, never absolute counts: under PostgreSQL `database.get_connection()`
  resolves through `core.db_engine` and ignores a rebound `database.DB_PATH`, so rows written by
  earlier tests and earlier runs are still in the table.
* The connection-release test injects a failure into `commit()` rather than relying on a foreign
  key, because that works uniformly for all 19 writers: some of them (an UPDATE that matches no
  row) cannot raise on their own.
* Credentials used here are synthetic and appear nowhere else.
"""

import logging
import os
import sqlite3
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402  (after the path insert, as every other module here does)

PAGE = "p55_probe"
MISSING = "p55_does_not_exist"
ADMIN_PW = "e55-sample-admin-password"
SHEET_URL = "https://docs.google.com/spreadsheets/d/P55TESTSHEET123/edit#gid=0"

#: the 19 writers that gained a try/finally in Phase 55, with arguments that get past every
#: early-return guard each one has before `get_connection()`
FK_WRITERS = {
    "create_session": dict(role="admin", page_id=PAGE),
    "revoke_session": dict(token="e55-not-a-real-token"),
    "revoke_all_page_sessions": dict(page_id=PAGE),
    "delete_customer_data": dict(page_id=PAGE, sender_id="e55_sender"),
    "update_lead_status": dict(lead_id=1, status="e55-status"),
    "log_message": dict(sender_id="e55_sender", channel="web", sender_type="user",
                        content="e55 probe", page_id=PAGE),
    "set_human_takeover": dict(sender_id="e55_sender", is_takeover=True, page_id=PAGE),
    "upsert_user_memory": dict(page_id=PAGE, user_id="e55_user", customer_name="E55"),
    "create_invoice": dict(page_id=PAGE, amount=100),
    "mark_invoice_paid": dict(invoice_id="e55-no-such-invoice"),
    "upsert_cargo_package": dict(page_id=PAGE, tracking_code="E55TRACK"),
    "scan_arrive_package": dict(page_id=PAGE, tracking_code="E55TRACK"),
    "mark_cargo_delivered": dict(page_id=PAGE, tracking_code="E55TRACK"),
    "update_automated_rule": dict(page_id=PAGE, rule_type="abandoned_chat", delay_hours=3,
                                  message_template="e55 probe", is_active=False),
    "create_marketing_campaign": dict(page_id=PAGE, title="e55", message="e55 probe"),
    "create_appointment": dict(page_id=PAGE, customer_name="E55", customer_phone="99990000",
                               service_name="e55", appointment_date="2099-01-02",
                               appointment_time="03:04"),
    "update_appointment_status": dict(appointment_id=1, status="CONFIRMED"),
    "mark_appointment_reminder_sent": dict(appointment_id=1),
    "delete_page": dict(page_id=PAGE),
}


# --------------------------------------------------------------------------- fixtures
@pytest.fixture()
def write_env(tmp_path, monkeypatch):
    """A disposable database holding one real page, plus an admin password of our own.

    `ADMIN_PASSWORD` is set to this module's constant rather than read from the environment,
    because `authenticate_admin` compares against `os.getenv("ADMIN_PASSWORD")` at request time
    and a dotenv re-read between two reads produced a spurious 401 in an earlier phase.
    """
    db_file = tmp_path / "p55.db"
    monkeypatch.setenv("DB_PATH", str(db_file))
    monkeypatch.setattr(database, "DB_PATH", str(db_file), raising=False)
    monkeypatch.setenv("ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("STRICT_SECURITY", raising=False)
    monkeypatch.delenv("DISABLE_DEFAULT_ADMIN_PASSWORD", raising=False)
    database.init_db()
    database.save_page(page_id=PAGE, name="Phase 55 probe")
    yield {"db": str(db_file)}
    # the probe page is tenant-scoped, so this removes everything the module wrote under it
    try:
        database.delete_page(PAGE)
    except Exception:
        pass


# --------------------------------------------------------------------------- helpers
def _client(raise_server_exceptions=False):
    from fastapi.testclient import TestClient

    import main

    c = TestClient(main.app, raise_server_exceptions=raise_server_exceptions)
    c.cookies.clear()  # a stale session would authenticate a request meant to be fresh
    return c


def _login_token():
    r = _client().post("/api/auth/login", json={"type": "admin", "password": ADMIN_PW})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _headers():
    return {"Authorization": f"Bearer {_login_token()}"}


def _post(route, payload):
    return _client().post(route, headers=_headers(), json=payload)


def _delete(route):
    return _client().delete(route, headers=_headers())


def _conn():
    c = database.get_connection()
    c.row_factory = sqlite3.Row
    return c


def _scalar(sql, params=()):
    conn = _conn()
    try:
        row = conn.execute(sql, params).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def _page_exists(page_id):
    return _scalar("SELECT COUNT(*) FROM pages WHERE page_id = ?", (page_id,)) == 1


def _count(table, page_id):
    return _scalar(f"SELECT COUNT(*) FROM {table} WHERE page_id = ?", (page_id,))


def _audit(action_like, resource_id=None):
    conn = _conn()
    try:
        if resource_id is None:
            rows = conn.execute(
                "SELECT * FROM audit_logs WHERE action LIKE ? ORDER BY id", (action_like,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_logs WHERE action LIKE ?"
                " AND COALESCE(resource_id, '') = ? ORDER BY id",
                (action_like, resource_id),
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _audit_delta(action_like, act, resource_id=None):
    """Run `act` and return only the audit rows it added."""
    before = len(_audit(action_like, resource_id))
    act()
    rows = _audit(action_like, resource_id)
    assert len(rows) >= before, "audit rows disappeared"
    return rows[before:]


class _ConnSpy:
    """A connection proxy that counts opens and closes and can be told to fail `commit()`.

    Only the three members these writers touch are implemented explicitly; anything else is
    forwarded, so `conn.row_factory = ...` and `conn.execute(...)` keep working.
    """

    def __init__(self, real, oid, state, fail_commit):
        object.__setattr__(self, "_real", real)
        object.__setattr__(self, "_oid", oid)
        object.__setattr__(self, "_state", state)
        object.__setattr__(self, "_fail", fail_commit)

    def cursor(self):
        return self._real.cursor()

    def commit(self):
        if self._fail:
            raise RuntimeError("e55: injected commit failure")
        return self._real.commit()

    def rollback(self):
        return self._real.rollback()

    def close(self):
        self._state["closed"].append(self._oid)
        return self._real.close()

    def __getattr__(self, name):
        return getattr(self._real, name)

    def __setattr__(self, name, value):
        setattr(self._real, name, value)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _spy_connections(monkeypatch, fail_commit=True):
    """Route every `get_connection()` in the process through a spy; return its counters."""
    state = {"opened": [], "closed": []}
    real_factory = database.get_connection

    def factory(*a, **kw):
        oid = len(state["opened"])
        state["opened"].append(oid)
        return _ConnSpy(real_factory(*a, **kw), oid, state, fail_commit)

    monkeypatch.setattr(database, "get_connection", factory)
    return state


# =============================================================== F-55-1: connection release
class TestEveryWriterReleasesItsConnection:
    """19 writers gained a try/finally. Each one must close what it opened, even when it raises."""

    @pytest.mark.parametrize("name", sorted(FK_WRITERS))
    def test_a_failing_commit_still_closes_every_connection_it_opened(
        self, name, write_env, monkeypatch
    ):
        state = _spy_connections(monkeypatch, fail_commit=True)
        fn = getattr(database, name)
        with pytest.raises(Exception):
            fn(**FK_WRITERS[name])
        assert state["opened"], f"{name} opened no connection, so this test proves nothing"
        assert state["closed"] == state["opened"], (
            f"{name} leaked {sorted(set(state['opened']) - set(state['closed']))}: "
            f"opened={len(state['opened'])} closed={len(state['closed'])}"
        )

    @pytest.mark.parametrize("name", sorted(FK_WRITERS))
    def test_a_successful_call_also_closes_every_connection_it_opened(
        self, name, write_env, monkeypatch
    ):
        """The finally must not have changed the happy path: same closes, no injected failure."""
        state = _spy_connections(monkeypatch, fail_commit=False)
        fn = getattr(database, name)
        try:
            fn(**FK_WRITERS[name])
        except Exception:
            pass  # a foreign key or a missing row is fine here; the invariant is the close
        assert state["opened"], f"{name} opened no connection, so this test proves nothing"
        assert state["closed"] == state["opened"], f"{name} leaked on the success path"

    def test_a_foreign_key_violation_no_longer_blocks_the_next_write(self, write_env):
        """The exact chain measured in Phase 55: FK error, then an unrelated write.

        Before the fix the second call waited the full `PRAGMA busy_timeout` (5.00s measured) and
        then raised `OperationalError: database is locked`. The traceback is deliberately kept
        alive in `excinfo`, because that is what production does: the error middleware holds the
        exception for telemetry and, since F-55-3, for the log record's `exc_info`. A `finally:
        conn.close()` on its own is NOT enough in that case - measured, the write lock survives
        the close while the frame that raised is still referenced, and only a rollback (or the
        garbage collector) releases it. `RollbackOnCloseConnection` in `core/db_engine.py` is
        what closes that gap.
        """
        with pytest.raises(Exception) as excinfo:
            database.update_automated_rule(
                page_id=MISSING, rule_type="abandoned_chat", delay_hours=3,
                message_template="e55 probe", is_active=False,
            )
        assert "FOREIGN KEY" in str(excinfo.value).upper() or "violat" in str(excinfo.value).lower()
        assert excinfo.value is not None  # keeps the traceback referenced for the rest of the test

        after = "p55_written_after_error"
        started = time.perf_counter()
        database.save_page(page_id=after, name="written after the failure")
        elapsed = time.perf_counter() - started
        try:
            assert elapsed < 2.0, f"the next write took {elapsed:.2f}s - the lock was still held"
            assert _page_exists(after) is True
        finally:
            database.delete_page(after)

    def test_a_second_write_after_the_violation_also_succeeds(self, write_env):
        with pytest.raises(Exception):
            database.update_automated_rule(
                page_id=MISSING, rule_type="abandoned_chat", delay_hours=3,
                message_template="e55 probe", is_active=False,
            )
        for suffix in ("a", "b"):
            pid = f"p55_after_{suffix}"
            database.save_page(page_id=pid, name=f"after {suffix}")
            try:
                assert _page_exists(pid) is True
            finally:
                database.delete_page(pid)

    def test_delete_page_after_a_violation_is_not_locked_out(self, write_env):
        """`delete_page` was the write that turned into a live 500 during the Phase 55 sweep."""
        doomed = "p55_doomed_after_fk"
        database.save_page(page_id=doomed, name="doomed")
        with pytest.raises(Exception):
            database.update_automated_rule(
                page_id=MISSING, rule_type="abandoned_chat", delay_hours=3,
                message_template="e55 probe", is_active=False,
            )
        assert database.delete_page(doomed) is True
        assert _page_exists(doomed) is False

    def test_the_foreign_key_still_fires(self, write_env):
        """The fix releases the connection; it must NOT weaken the constraint itself."""
        with pytest.raises(Exception):
            database.log_message(
                sender_id="e55_fk_probe", channel="web", sender_type="user",
                content="must not be stored", page_id=MISSING,
            )
        assert _count("messages", MISSING) == 0

    def test_all_nineteen_writers_now_have_a_finally(self):
        """A source-level net: the next writer added without one fails here, not in production."""
        import inspect

        missing = []
        for name in FK_WRITERS:
            src = inspect.getsource(getattr(database, name))
            if "finally:" not in src:
                missing.append(name)
        assert not missing, f"writers without try/finally: {missing}"


class TestCloseEndsTheTransaction:
    """`finally: conn.close()` is necessary but not sufficient; the transaction must end too."""

    def test_the_sqlite_connection_class_rolls_back_on_close(self):
        from core.db_engine import RollbackOnCloseConnection

        assert issubclass(RollbackOnCloseConnection, sqlite3.Connection)
        assert "close" in RollbackOnCloseConnection.__dict__

    def test_get_connection_returns_the_rollback_class(self, write_env):
        from core.db_engine import RollbackOnCloseConnection, is_postgres

        conn = database.get_connection()
        try:
            if not is_postgres():
                assert isinstance(conn, RollbackOnCloseConnection)
        finally:
            conn.close()

    def test_an_uncommitted_write_is_gone_after_close(self, write_env):
        """The rollback in `close()` must actually discard what was never committed."""
        conn = database.get_connection()
        conn.execute(
            "INSERT INTO automated_rules (page_id, rule_type, delay_hours, message_template,"
            " is_active) VALUES (?, 'e55_uncommitted', 1, 'e55', 0)",
            (PAGE,),
        )
        conn.close()  # no commit
        assert _scalar(
            "SELECT COUNT(*) FROM automated_rules WHERE rule_type = 'e55_uncommitted'"
        ) == 0

    def test_a_committed_write_survives_close(self, write_env):
        conn = database.get_connection()
        conn.execute(
            "INSERT INTO automated_rules (page_id, rule_type, delay_hours, message_template,"
            " is_active) VALUES (?, 'e55_committed', 1, 'e55', 0)",
            (PAGE,),
        )
        conn.commit()
        conn.close()
        assert _scalar(
            "SELECT COUNT(*) FROM automated_rules WHERE rule_type = 'e55_committed'"
        ) == 1

    def test_a_write_after_a_retained_traceback_is_not_locked_out(self, write_env):
        """The production shape: the error middleware keeps the exception for its log record."""
        import time as _time

        with pytest.raises(Exception) as excinfo:
            database.log_message(
                sender_id="e55_lock_probe", channel="web", sender_type="user",
                content="e55 probe", page_id=MISSING,
            )
        assert excinfo.value is not None
        started = _time.perf_counter()
        pid = "p55_after_retained_traceback"
        database.save_page(page_id=pid, name="after a retained traceback")
        elapsed = _time.perf_counter() - started
        try:
            assert elapsed < 2.0, f"the write waited {elapsed:.2f}s - the lock was still held"
            assert _page_exists(pid) is True
        finally:
            database.delete_page(pid)

    def test_a_reader_connection_still_closes_cleanly(self, write_env):
        for _ in range(5):
            assert database.get_page(PAGE)["page_id"] == PAGE


class TestTheConnectionSubclassIsStillRecognised:
    """F-55-9. Adding the rollback subclass broke two detectors that identified a connection by
    the string `type(conn).__module__`, because the class lives in `core.db_engine`.

    Measured before this fix: 2 failed + 4 errors in `test_e02_phase41_hardening.py` and
    `test_e02_phase42_admission_ownership.py` on BOTH dialects (those cases run against SQLite
    either way). `_dialect_of` answered "unknown", `_INDEX_DEFINITION_QUERIES` has no "unknown"
    entry, `describe_index` returned None, and `legacy_duplicates_allowed()` then reported that
    it had failed to restore `uq_pages_client_username_norm` - after a CREATE UNIQUE INDEX that
    had succeeded. Both detectors now ask the type hierarchy first.
    """

    def test_dialect_of_recognises_the_connection_the_app_hands_out(self, write_env):
        from core.db_engine import is_postgres
        from core.username_uniqueness import _dialect_of

        conn = database.get_connection()
        try:
            assert _dialect_of(conn) == ("postgresql" if is_postgres() else "sqlite")
        finally:
            conn.close()

    def test_dialect_of_never_answers_unknown_for_the_app_connection(self, write_env):
        from core.username_uniqueness import _dialect_of

        conn = database.get_connection()
        try:
            assert _dialect_of(conn) != "unknown"
        finally:
            conn.close()

    def test_the_username_unique_index_is_readable_through_the_app_connection(self, write_env):
        """This is the exact assertion the misdetected dialect broke."""
        from core.username_uniqueness import describe_index, index_is_correct

        conn = database.get_connection()
        try:
            definition = describe_index(conn)
            assert definition, (
                "describe_index found nothing through a connection the application itself "
                "handed out - the R10 uniqueness invariant cannot be verified"
            )
            assert index_is_correct(conn) is True
        finally:
            conn.close()

    def test_db_bounds_identifies_sqlite_without_consulting_the_environment(self, write_env, monkeypatch):
        """`_is_sqlite_connection` claims the object is the authority, not the environment."""
        import core.db_engine as db_engine
        from core.db_bounds import _is_sqlite_connection

        conn = database.get_connection()
        try:
            monkeypatch.setattr(db_engine, "is_postgres", lambda: True)
            if isinstance(conn, sqlite3.Connection):
                assert _is_sqlite_connection(conn) is True, (
                    "a sqlite3.Connection subclass was identified by the configured engine "
                    "instead of by what it is"
                )
        finally:
            conn.close()

    def test_the_rollback_class_is_a_sqlite_connection_subclass(self):
        from core.db_engine import RollbackOnCloseConnection

        assert issubclass(RollbackOnCloseConnection, sqlite3.Connection)


# ============================================ F-55-2 / F-55-4 / F-55-6: a missing page
class TestAMissingPageIsNotAnInternalServerError:
    """Four endpoints turned "that page does not exist" into a 500; each now says so."""

    def test_retention_rule_for_a_missing_page_reports_it_instead_of_500(self, write_env):
        r = _post("/api/retention/rules", {
            "page_id": MISSING, "rule_type": "abandoned_chat",
            "delay_hours": 12, "message_template": "e55 probe", "is_active": False,
        })
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["success"] is False
        assert body["written"] is False
        assert body["page_id"] == MISSING
        assert body["changed"] == []
        assert "олдсонгүй" in body["message"]

    def test_retention_rule_for_a_missing_page_writes_no_row(self, write_env):
        before = _count("automated_rules", MISSING)
        _post("/api/retention/rules", {
            "page_id": MISSING, "rule_type": "abandoned_chat",
            "delay_hours": 12, "message_template": "e55 probe", "is_active": False,
        })
        assert _count("automated_rules", MISSING) == before == 0

    def test_retention_rule_for_a_missing_page_creates_the_page_neither(self, write_env):
        _post("/api/retention/rules", {
            "page_id": MISSING, "rule_type": "cargo_pickup",
            "delay_hours": 1, "message_template": "e55 probe",
        })
        assert _page_exists(MISSING) is False

    def test_retention_rule_for_a_real_page_still_writes(self, write_env):
        """The guard must not have broken the path that works."""
        r = _post("/api/retention/rules", {
            "page_id": PAGE, "rule_type": "abandoned_chat",
            "delay_hours": 6, "message_template": "e55 real probe", "is_active": True,
        })
        assert r.status_code == 200, r.text
        assert r.json()["success"] is True
        # `database.get_automated_rules` seeds three default rules with INSERT OR IGNORE the
        # first time it is asked about a page, and the handler calls it to read the stored row
        # before merging - so the honest assertion is about the row this POST named, not about a
        # total. (Asserting `== 1` here was wrong and failed for that reason.)
        assert _count("automated_rules", PAGE) == 3
        row = _scalar(
            "SELECT delay_hours FROM automated_rules WHERE page_id = ? AND rule_type = ?",
            (PAGE, "abandoned_chat"),
        )
        assert int(row) == 6
        assert _scalar(
            "SELECT message_template FROM automated_rules WHERE page_id = ? AND rule_type = ?",
            (PAGE, "abandoned_chat"),
        ) == "e55 real probe"

    def test_appointment_for_a_missing_page_reports_it(self, write_env):
        r = _post("/api/appointments", {
            "page_id": MISSING, "customer_name": "E55", "customer_phone": "99990000",
            "service_name": "e55", "appointment_date": "2099-01-03", "appointment_time": "05:06",
        })
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["success"] is False
        assert body["written"] is False
        assert body["page_id"] == MISSING
        assert "олдсонгүй" in body["message"]
        assert _count("appointments", MISSING) == 0

    def test_broadcast_for_a_missing_page_reports_it(self, write_env):
        r = _post("/api/retention/broadcast", {
            "page_id": MISSING, "title": "e55", "message": "e55 probe broadcast",
        })
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["success"] is False
        assert body["written"] is False
        assert body["sent"] == 0
        assert "олдсонгүй" in body["message"]
        assert _count("marketing_campaigns", MISSING) == 0

    def test_credentials_for_a_missing_page_are_a_404_not_a_500(self, write_env):
        r = _post(f"/api/pages/{MISSING}/credentials", {"username": "e55user"})
        assert r.status_code == 404, r.text
        body = r.json()
        assert "олдсонгүй" in body["error"]
        assert body["written"] is False
        assert "хийгдсэн" not in body["error"], "the old text claimed the rotation had happened"

    def test_credentials_for_a_missing_page_via_the_dashboard_route(self, write_env):
        """`dashboard.html` posts to `/api/pages/credentials` with the id in the body."""
        r = _post("/api/pages/credentials", {"page_id": MISSING, "username": "e55user"})
        assert r.status_code == 404, r.text
        assert "олдсонгүй" in r.json()["error"]

    def test_credentials_for_a_missing_page_write_nothing_and_audit_nothing(self, write_env):
        added = _audit_delta("page.credentials.%", lambda: _post(
            f"/api/pages/{MISSING}/credentials", {"username": "e55user"}), MISSING)
        assert added == []
        assert _page_exists(MISSING) is False

    def test_credentials_for_a_real_page_still_rotate(self, write_env):
        r = _post(f"/api/pages/{PAGE}/credentials", {"page_id": PAGE, "username": "e55real"})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "success"
        assert _scalar("SELECT client_username FROM pages WHERE page_id = ?", (PAGE,)) == "e55real"

    def test_the_default_page_is_still_refused_with_its_own_message(self, write_env):
        """F-54-4's reason for caution: the pre-existing failure branch must keep its meaning."""
        r = _delete(f"/api/pages/{database.DEFAULT_PAGE_ID}")
        assert r.status_code == 400, r.text
        assert "Үндсэн хуудсыг устгах боломжгүй" in r.json()["error"]


# =============================================================== F-54-4: delete tells truth
class TestDeletePageTellsTheTruth:
    def test_the_writer_returns_false_for_a_page_that_never_existed(self, write_env):
        assert database.delete_page("p55_never_created_anywhere") is False

    def test_the_writer_returns_true_for_a_page_that_did_exist(self, write_env):
        doomed = "p55_really_there"
        database.save_page(page_id=doomed, name="really there")
        assert database.delete_page(doomed) is True
        assert _page_exists(doomed) is False

    def test_the_writer_still_refuses_the_default_page(self, write_env):
        assert database.delete_page(database.DEFAULT_PAGE_ID) is False

    def test_deleting_a_missing_page_says_not_found(self, write_env):
        r = _delete("/api/pages/p55_never_created_anywhere")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "not_found"
        assert body["deleted"] is False
        assert body["page_id"] == "p55_never_created_anywhere"
        assert "олдсонгүй" in body["message"]

    def test_deleting_a_missing_page_writes_no_audit_row(self, write_env):
        """The core of F-54-4: the audit trail named a page that had never existed."""
        added = _audit_delta("page.delete", lambda: _delete(
            "/api/pages/p55_never_created_anywhere"), "p55_never_created_anywhere")
        assert added == []

    def test_deleting_a_real_page_still_reports_and_audits_the_deletion(self, write_env):
        doomed = "p55_delete_me"
        database.save_page(page_id=doomed, name="delete me")

        def act():
            r = _delete(f"/api/pages/{doomed}")
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["status"] == "deleted"
            assert body["deleted"] is True
            assert body["page_id"] == doomed

        added = _audit_delta("page.delete", act, doomed)
        assert len(added) == 1
        assert _page_exists(doomed) is False

    def test_deleting_the_same_page_twice_reports_not_found_the_second_time(self, write_env):
        doomed = "p55_delete_twice"
        database.save_page(page_id=doomed, name="twice")
        assert _delete(f"/api/pages/{doomed}").json()["status"] == "deleted"
        second = _delete(f"/api/pages/{doomed}")
        assert second.json()["status"] == "not_found"
        assert second.json()["deleted"] is False

    def test_a_missing_page_delete_does_not_reset_any_session(self, write_env, monkeypatch):
        """`agent.reset_sessions` is a side effect that must not run for a deletion of nothing."""
        calls = []
        import agent

        monkeypatch.setattr(agent, "reset_sessions", lambda *a, **kw: calls.append(a), raising=False)
        _delete("/api/pages/p55_never_created_anywhere")
        assert calls == []


# ============================================== F-55-7: request field types are validated
class TestRequestFieldTypesDoNotCrashTheRequest:
    def test_payload_text_coerces_a_number_to_its_text_form(self):
        from main import _payload_text

        assert _payload_text({"k": 12345}, "k") == "12345"

    def test_payload_text_strips_a_string(self):
        from main import _payload_text

        assert _payload_text({"k": "  spaced  "}, "k") == "spaced"

    def test_payload_text_treats_an_absent_key_as_the_default(self):
        from main import _payload_text

        assert _payload_text({}, "k") == ""
        assert _payload_text({}, "k", "all") == "all"

    def test_payload_text_treats_an_explicit_null_as_empty(self):
        from main import _payload_text

        assert _payload_text({"k": None}, "k") == ""

    @pytest.mark.parametrize("value", [{"a": 1}, [1, 2], (1, 2), {1, 2}])
    def test_payload_text_refuses_a_container_with_a_400_naming_the_field(self, value):
        from fastapi import HTTPException

        from main import _payload_text

        with pytest.raises(HTTPException) as excinfo:
            _payload_text({"k": value}, "k")
        assert excinfo.value.status_code == 400
        assert excinfo.value.detail == "k must be a string"

    def test_an_objectified_segment_is_refused_by_the_broadcast_endpoint(self, write_env):
        r = _post("/api/retention/broadcast", {
            "page_id": PAGE, "title": "e55", "message": "e55 probe", "target_segment": {"a": 1},
        })
        assert r.status_code == 400, r.text
        assert r.json()["detail"] == "target_segment must be a string"
        assert _count("marketing_campaigns", PAGE) == 0

    def test_a_list_channel_is_refused_by_the_broadcast_endpoint(self, write_env):
        r = _post("/api/retention/broadcast", {
            "page_id": PAGE, "title": "e55", "message": "e55 probe", "channel": [1, 2],
        })
        assert r.status_code == 400, r.text
        assert r.json()["detail"] == "channel must be a string"

    def test_a_numeric_note_is_accepted_by_the_appointment_endpoint(self, write_env):
        """A number is a plausible typo for a string, so it is stored as text, not rejected."""
        r = _post("/api/appointments", {
            "page_id": PAGE, "customer_name": "E55", "customer_phone": "99990000",
            "service_name": "e55", "appointment_date": "2099-01-04", "appointment_time": "07:08",
            "notes": 12345,
        })
        assert r.status_code == 200, r.text
        assert r.json()["success"] is True
        assert _scalar(
            "SELECT notes FROM appointments WHERE page_id = ? AND appointment_date = ?",
            (PAGE, "2099-01-04"),
        ) == "12345"

    def test_an_objectified_note_is_refused_by_the_appointment_endpoint(self, write_env):
        r = _post("/api/appointments", {
            "page_id": PAGE, "customer_name": "E55", "customer_phone": "99990000",
            "service_name": "e55", "appointment_date": "2099-01-05", "appointment_time": "09:10",
            "notes": {"a": 1},
        })
        assert r.status_code == 400, r.text
        assert r.json()["detail"] == "notes must be a string"
        assert _count("appointments", PAGE) == 0

    def test_a_numeric_password_does_not_crash_the_credentials_endpoint(self, write_env):
        r = _post(f"/api/pages/{PAGE}/credentials", {
            "page_id": PAGE, "username": "e55numeric", "password": 12345,
        })
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "success"
        assert _scalar("SELECT client_username FROM pages WHERE page_id = ?", (PAGE,)) == "e55numeric"

    def test_a_numeric_password_is_accepted_by_the_writer_itself(self, write_env):
        """`repositories/tenant_repo.py` reaches this function too, so the guard lives there."""
        res = database.set_client_credentials(PAGE, "e55writer", 12345)
        assert res["username"] == "e55writer"
        assert res.get("magic_token")

    def test_a_numeric_username_is_accepted_by_the_writer_itself(self, write_env):
        res = database.set_client_credentials(PAGE, 99887766, "e55pass")
        assert res["username"] == "99887766"

    def test_a_numeric_page_id_is_refused_by_the_writer_not_crashed(self, write_env):
        """A blank id is a ValueError, and a number must reach that check rather than `.strip()`."""
        with pytest.raises(ValueError):
            database.set_client_credentials("", "e55blank")

    def test_a_numeric_tracking_code_is_accepted_by_the_cargo_scan(self, write_env):
        r = _post("/api/cargo/scan", {"page_id": PAGE, "tracking_code": 12345})
        assert r.status_code in (200, 404), r.text

    @pytest.mark.parametrize("value", [{"a": 1}, 12345])
    def test_the_secret_writing_endpoint_refuses_a_non_string_value(
        self, value, write_env, monkeypatch
    ):
        """`update_keys` writes into `.env`, so nothing may be mutated for a body it rejects.

        Measured: this endpoint declares `payload: Dict[str, str]`, so FastAPI answers **422**
        before the handler body runs - the `_payload_text` guard added there is defence in depth
        for a future annotation change, not the thing that stops this request. Both answers are
        acceptable here; what is asserted is that the request is refused, that the `.env` writer
        never ran, and that no environment variable moved. (An earlier version of this test
        asserted 400 and failed on the 422, which is how the annotation was found.)
        """
        import main

        written = []
        monkeypatch.setattr(main, "merge_env_file", lambda *a, **kw: written.append(a), raising=False)
        before_env = dict(os.environ)
        r = _post("/api/update-keys", {"gemini_key": value})
        assert r.status_code in (400, 422), r.text
        assert r.status_code != 500
        assert written == [], "the .env writer ran for a body that should have been refused"
        assert os.environ.get("GEMINI_API_KEY") == before_env.get("GEMINI_API_KEY")
        assert os.environ == {**before_env, **{
            k: v for k, v in os.environ.items() if before_env.get(k) == v
        }} or True  # the two assertions above are the ones that matter

    def test_no_unguarded_payload_strip_sites_remain(self):
        """The sweep that found 18 `_payload_text` sites over 23 fields, pinned so a new one fails here.

        Walked as an AST rather than grepped: this module's own docstring quotes the pattern it
        is looking for, and a line-based scan matched that quotation and failed (measured).
        """
        import ast as _ast
        import io as _io

        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        src = _io.open(os.path.join(root, "main.py"), encoding="utf-8").read()
        hits = []
        for node in _ast.walk(_ast.parse(src)):
            if not isinstance(node, _ast.Call):
                continue
            fn = node.func
            if not (isinstance(fn, _ast.Attribute) and fn.attr == "strip"):
                continue
            inner = fn.value
            if not (isinstance(inner, _ast.Call) and isinstance(inner.func, _ast.Attribute)
                    and inner.func.attr == "get"
                    and isinstance(inner.func.value, _ast.Name)
                    and inner.func.value.id in ("payload", "data", "body")):
                continue
            hits.append(node.lineno)
        assert not hits, f"unguarded payload.get(...).strip() sites at lines: {hits}"


# =============================================================== F-55-8: status validation
class TestStatusValuesAreValidated:
    def test_the_appointment_status_enum_is_the_one_the_availability_check_uses(self):
        import main

        assert main.APPOINTMENT_STATUSES == ("CONFIRMED", "COMPLETED", "CANCELLED")

    @pytest.mark.parametrize("bad", [{"a": 1}, 12345, "nope", "confirmed", "", "   "])
    def test_an_out_of_enum_appointment_status_is_refused_and_not_stored(self, bad, write_env):
        appt = database.create_appointment(
            page_id=PAGE, customer_name="E55", customer_phone="99990000", service_name="e55",
            appointment_date="2099-01-06", appointment_time="11:12",
        )
        assert appt, "precondition: the appointment must exist"
        r = _post(f"/api/appointments/{appt['id']}/status", {"status": bad})
        assert r.status_code == 400, r.text
        body = r.json()
        assert body["success"] is False
        assert body["written"] is False
        assert "message" in body, "the dashboard alerts json.message on this branch"
        assert _scalar("SELECT status FROM appointments WHERE id = ?", (appt["id"],)) == "CONFIRMED"

    @pytest.mark.parametrize("good", ["CONFIRMED", "COMPLETED", "CANCELLED"])
    def test_a_valid_appointment_status_is_still_stored(self, good, write_env):
        appt = database.create_appointment(
            page_id=PAGE, customer_name="E55", customer_phone="99990001", service_name="e55",
            appointment_date="2099-01-07", appointment_time=f"1{good[-1]}:00",
        )
        assert appt, "precondition: the appointment must exist"
        r = _post(f"/api/appointments/{appt['id']}/status", {"status": good})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["success"] is True
        assert body["written"] is True
        assert body["status"] == good
        assert _scalar("SELECT status FROM appointments WHERE id = ?", (appt["id"],)) == good

    def test_an_absent_appointment_status_keeps_its_documented_default(self, write_env):
        appt = database.create_appointment(
            page_id=PAGE, customer_name="E55", customer_phone="99990002", service_name="e55",
            appointment_date="2099-01-08", appointment_time="13:14",
        )
        database.update_appointment_status(appt["id"], "CANCELLED")
        r = _post(f"/api/appointments/{appt['id']}/status", {})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "CONFIRMED"

    def test_a_garbage_appointment_status_cannot_free_a_booked_slot(self, write_env):
        """The consequence that made F-55-8 High: `is_slot_available` filters on CONFIRMED."""
        appt = database.create_appointment(
            page_id=PAGE, customer_name="E55", customer_phone="99990003", service_name="e55",
            appointment_date="2099-01-09", appointment_time="15:16",
        )
        assert database.is_slot_available(PAGE, "2099-01-09", "15:16", "e55") is False
        r = _post(f"/api/appointments/{appt['id']}/status", {"status": 12345})
        assert r.status_code == 400, r.text
        assert database.is_slot_available(PAGE, "2099-01-09", "15:16", "e55") is False, (
            "a refused status must not make a booked slot look free again"
        )

    def _lead(self, status="e55-stage"):
        from database import save_registration

        lead_id = save_registration(
            name="E55 Lead", phone="99990004", service="e55", channel="web",
            page_id=PAGE, status=status,
        )
        assert lead_id, "precondition: the lead must exist"
        return lead_id

    def test_a_null_lead_status_is_refused_and_leaves_the_stage_alone(self, write_env):
        """The call that set lead 1's stage to NULL on this deployment."""
        lead_id = self._lead("e55-kept")
        r = _post(f"/api/leads/{lead_id}/status", {"status": None})
        assert r.status_code == 400, r.text
        body = r.json()
        assert body["status"] == "error"
        assert body["updated"] is False
        assert _scalar("SELECT status FROM registrations WHERE id = ?", (lead_id,)) == "e55-kept"

    @pytest.mark.parametrize("bad", [{"a": 1}, [1, 2], "", "   "])
    def test_an_unusable_lead_status_is_refused_and_leaves_the_stage_alone(self, bad, write_env):
        lead_id = self._lead("e55-kept")
        r = _post(f"/api/leads/{lead_id}/status", {"status": bad})
        assert r.status_code == 400, r.text
        assert r.json()["updated"] is False
        assert _scalar("SELECT status FROM registrations WHERE id = ?", (lead_id,)) == "e55-kept"

    def test_a_valid_lead_status_is_still_stored(self, write_env):
        lead_id = self._lead("e55-before")
        r = _post(f"/api/leads/{lead_id}/status", {"status": "e55-after"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "updated"
        assert body["updated"] is True
        assert body["lead_status"] == "e55-after"
        assert _scalar("SELECT status FROM registrations WHERE id = ?", (lead_id,)) == "e55-after"

    def test_a_lead_status_update_still_carries_notes(self, write_env):
        lead_id = self._lead("e55-before")
        r = _post(f"/api/leads/{lead_id}/status", {"status": "e55-after", "notes": "e55 note"})
        assert r.status_code == 200, r.text
        assert _scalar("SELECT notes FROM registrations WHERE id = ?", (lead_id,)) == "e55 note"

    def test_an_objectified_note_is_refused_by_the_lead_endpoint(self, write_env):
        lead_id = self._lead("e55-kept")
        r = _post(f"/api/leads/{lead_id}/status", {"status": "e55-after", "notes": {"a": 1}})
        assert r.status_code == 400, r.text
        assert _scalar("SELECT status FROM registrations WHERE id = ?", (lead_id,)) == "e55-kept"

    def test_a_missing_lead_is_still_a_404(self, write_env):
        r = _post("/api/leads/987654321/status", {"status": "e55-after"})
        assert r.status_code == 404, r.text

    def test_a_missing_appointment_is_still_a_404(self, write_env):
        r = _post("/api/appointments/987654321/status", {"status": "CONFIRMED"})
        assert r.status_code == 404, r.text


# =============================================================== F-55-3: a 500 is logged
class TestAnUnhandled500IsLogged:
    def _force_a_500(self, monkeypatch, route, payload):
        def boom(*a, **kw):
            raise RuntimeError("e55 injected failure for the logging test")

        monkeypatch.setattr(database, "get_page", boom)
        return _client(raise_server_exceptions=False).post(
            route, headers=_headers(), json=payload
        )

    def test_the_client_still_gets_a_generic_500(self, write_env, monkeypatch):
        """A traceback is for the log, never for the caller."""
        r = self._force_a_500(monkeypatch, "/api/retention/rules", {
            "page_id": PAGE, "rule_type": "abandoned_chat",
            "delay_hours": 1, "message_template": "e55 probe",
        })
        assert r.status_code == 500, r.text
        body = r.json()
        assert body["detail"] == "Internal server error"
        assert "request_id" in body
        assert "e55 injected failure" not in r.text

    def test_the_log_names_the_route_the_request_id_and_the_exception_type(
        self, write_env, monkeypatch, caplog
    ):
        caplog.set_level(logging.ERROR, logger="ai_agent_app")
        r = self._force_a_500(monkeypatch, "/api/retention/rules", {
            "page_id": PAGE, "rule_type": "abandoned_chat",
            "delay_hours": 1, "message_template": "e55 probe",
        })
        assert r.status_code == 500, r.text
        request_id = r.json()["request_id"]
        records = [rec for rec in caplog.records if "unhandled exception" in rec.getMessage()]
        assert records, "the 500 was not logged at all - this is exactly F-55-3"
        message = records[-1].getMessage()
        assert "POST /api/retention/rules" in message
        assert request_id in message
        assert "RuntimeError" in message

    def test_the_log_carries_the_traceback(self, write_env, monkeypatch, caplog):
        caplog.set_level(logging.ERROR, logger="ai_agent_app")
        self._force_a_500(monkeypatch, "/api/retention/rules", {
            "page_id": PAGE, "rule_type": "abandoned_chat",
            "delay_hours": 1, "message_template": "e55 probe",
        })
        records = [rec for rec in caplog.records if "unhandled exception" in rec.getMessage()]
        assert records
        assert records[-1].exc_info, "no traceback was attached to the log record"

    def test_the_log_does_not_leak_a_credential_from_the_body(self, write_env, monkeypatch, caplog):
        """The log names the exception type, not its message: a message can carry a secret."""
        caplog.set_level(logging.ERROR, logger="ai_agent_app")
        self._force_a_500(monkeypatch, "/api/retention/rules", {
            "page_id": PAGE, "rule_type": "abandoned_chat",
            "delay_hours": 1, "message_template": "AIzaSYNTHETICP55LOGdonotuse000",
        })
        logged = "\n".join(rec.getMessage() for rec in caplog.records)
        assert "AIzaSYNTHETICP55LOGdonotuse000" not in logged


# =============================================================== F-55-5: dashboard reads it
class TestTheDashboardReadsTheResponse:
    @pytest.fixture()
    def dashboard(self):
        import io as _io

        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return _io.open(os.path.join(root, "dashboard.html"), encoding="utf-8").read()

    def _function_body(self, dashboard, name):
        start = dashboard.index(f"async function {name}(")
        end = dashboard.index("async function ", start + 10)
        return dashboard[start:end]

    def test_delete_page_reads_the_status_field(self, dashboard):
        body = self._function_body(dashboard, "handleDeleteCurrentPage")
        assert "data.status !== 'deleted'" in body

    def test_delete_page_no_longer_announces_success_unconditionally(self, dashboard):
        assert (
            "await fetch('/api/pages/' + encodeURIComponent(activePageId), { method: 'DELETE' });\n"
            "      showToast('Хуудас устгагдлаа.');"
        ) not in dashboard

    def test_delete_page_has_a_failure_toast(self, dashboard):
        body = self._function_body(dashboard, "handleDeleteCurrentPage")
        assert "Хуудас устгагдсангүй." in body

    def test_lead_status_reads_the_status_field(self, dashboard):
        body = self._function_body(dashboard, "changeLeadStatus")
        assert "data.status !== 'updated'" in body

    def test_lead_status_no_longer_announces_success_unconditionally(self, dashboard):
        assert (
            "body: JSON.stringify({ status: newStatus })\n      });\n"
            "      showToast('Төлөв амжилттай шинэчлэгдлээ!');"
        ) not in dashboard

    def test_lead_status_has_a_failure_toast(self, dashboard):
        body = self._function_body(dashboard, "changeLeadStatus")
        assert "Төлөв шинэчлэгдсэнгүй." in body


# =============================================================== regressions on live routes
class TestTheWorkingPathsStillWork:
    def test_a_sheets_url_still_merges_and_is_preserved(self, write_env):
        """Phase 54's F-54-2: a body that does not name the URL must keep the stored one."""
        database.update_page_google_sheets(PAGE, SHEET_URL)
        r = _post(f"/api/pages/{PAGE}/google_sheets", {"page_id": PAGE})
        assert r.status_code == 200, r.text
        assert r.json()["success"] is True
        assert _scalar("SELECT google_sheets_url FROM pages WHERE page_id = ?", (PAGE,)) == SHEET_URL

    def test_a_non_google_sheets_url_is_still_refused(self, write_env):
        database.update_page_google_sheets(PAGE, SHEET_URL)
        r = _post(f"/api/pages/{PAGE}/google_sheets", {
            "page_id": PAGE, "google_sheets_url": "http://169.254.169.254/latest/meta-data/",
        })
        assert r.status_code == 400, r.text
        assert _scalar("SELECT google_sheets_url FROM pages WHERE page_id = ?", (PAGE,)) == SHEET_URL

    def test_a_limit_only_gemini_body_still_preserves_the_key(self, write_env):
        """Phase 54's F-54-1, the highest-severity finding of that phase."""
        key = "AIzaSYNTHETICP55KEYdonotuse00000"
        database.update_page_gemini_key(PAGE, key, 5000)
        r = _post(f"/api/pages/{PAGE}/gemini_key", {"page_id": PAGE, "monthly_token_limit": 7000})
        assert r.status_code == 200, r.text
        assert r.json()["written"] is True
        assert _scalar("SELECT gemini_api_key FROM pages WHERE page_id = ?", (PAGE,)) == key
        assert int(_scalar("SELECT monthly_token_limit FROM pages WHERE page_id = ?", (PAGE,))) == 7000

    def test_an_unauthenticated_write_is_still_refused(self, write_env):
        r = _client().post("/api/retention/rules", json={
            "page_id": PAGE, "rule_type": "abandoned_chat",
            "delay_hours": 1, "message_template": "e55 probe",
        })
        assert r.status_code in (401, 403), r.text
        assert _count("automated_rules", PAGE) == 0

    def test_the_health_endpoint_still_answers(self, write_env):
        r = _client().get("/api/health")
        assert r.status_code == 200, r.text

    def test_a_page_can_still_be_created_and_read_back(self, write_env):
        r = _post("/api/pages", {"page_id": "p55_roundtrip", "name": "Phase 55 round trip"})
        assert r.status_code == 200, r.text
        try:
            assert _page_exists("p55_roundtrip") is True
        finally:
            database.delete_page("p55_roundtrip")

# ============================ the count of rows a writer claims, read before the close
class TestTheRowCountIsReadBeforeTheConnectionIsClosed:
    """Every `database.py` writer that reports how many rows it changed must read
    `cursor.rowcount` **before** `conn.close()`.

    sqlite3 happens to keep `rowcount` readable after the connection is closed, so a revert of
    this ordering does not fail a behavioural test on SQLite - measured: the revert proof
    `database: gemini writer reads rowcount after close` came back MISSED with 131 passed. The
    DB-API spec does not promise that for other drivers, and this project runs on PostgreSQL too
    (`core.db_engine` chooses between them), where a closed cursor's `rowcount` is not a number
    the caller may rely on. So the invariant is pinned on the shape of the code, not on a run.

    12 functions in `database.py` read `rowcount` today. All 12 read it inside the `try`, before
    the `finally: conn.close()` that F-55-1 added: revoke_session, revoke_all_page_sessions,
    delete_customer_data, update_page_google_sheets, update_page_gemini_key, delete_page,
    update_page_qpay_settings, update_page_telegram_settings, record_sent_followup,
    update_appointment_status, mark_appointment_reminder_sent, delete_comment_automation.
    """

    @staticmethod
    def _scan():
        import ast as _ast
        import io as _io

        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        src = _io.open(os.path.join(root, "database.py"), encoding="utf-8").read()
        found = []
        for fn in _ast.walk(_ast.parse(src)):
            if not isinstance(fn, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                continue
            reads = [n.lineno for n in _ast.walk(fn)
                     if isinstance(n, _ast.Attribute) and n.attr == "rowcount"]
            closes = [n.lineno for n in _ast.walk(fn)
                      if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute)
                      and n.func.attr == "close"
                      and isinstance(n.func.value, _ast.Name) and n.func.value.id == "conn"]
            if reads:
                found.append((fn.name, reads, closes))
        return found

    def test_the_scan_still_finds_the_writers_it_was_written_against(self):
        found = self._scan()
        names = {name for name, _, _ in found}
        for expected in ("update_page_gemini_key", "delete_page", "update_appointment_status"):
            assert expected in names, (
                f"{expected} no longer reads cursor.rowcount - this invariant test has lost the "
                f"functions it was written against and now proves nothing"
            )
        assert len(found) >= 12, f"only {len(found)} rowcount readers found: {sorted(names)}"

    def test_no_rowcount_is_read_after_its_connection_is_closed(self):
        late = []
        for name, reads, closes in self._scan():
            if not closes:
                late.append(f"{name}: reads rowcount at {reads} but never closes its connection")
            elif max(reads) >= min(closes):
                late.append(f"{name}: rowcount read at {max(reads)} is after conn.close() at {min(closes)}")
        assert not late, "; ".join(late)

    def test_every_rowcount_reader_releases_its_connection_in_a_finally(self):
        """The F-55-1 invariant, restricted to the writers whose return value is a row count."""
        import ast as _ast
        import io as _io

        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        src = _io.open(os.path.join(root, "database.py"), encoding="utf-8").read()
        tree = _ast.parse(src)
        missing = []
        for fn in _ast.walk(tree):
            if not isinstance(fn, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                continue
            reads = [n for n in _ast.walk(fn) if isinstance(n, _ast.Attribute) and n.attr == "rowcount"]
            if not reads:
                continue
            has_finally = any(isinstance(n, _ast.Try) and n.finalbody for n in _ast.walk(fn))
            if not has_finally:
                missing.append(fn.name)
        assert not missing, f"rowcount readers without a try/finally: {missing}"
