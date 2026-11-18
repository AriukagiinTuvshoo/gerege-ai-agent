"""
Stage E — Phase 13: the audit trail is append-only (finding F-D).

Phase 12 found that `audit_logs` had no tamper protection at all: zero triggers on
either engine, and an application-level `UPDATE` or `DELETE` succeeded on SQLite and
PostgreSQL alike. Phase 13 re-measured that baseline before changing anything.

Revision `0007_audit_append_only` installs a rejection guard. These tests pin four
things, and the fourth is the one that makes the others meaningful:

  1. the guard REJECTS mutation — on both engines, and for `TRUNCATE` on PostgreSQL,
     which a row-level trigger does not see at all;
  2. the data is proven UNCHANGED after every rejection, so a trigger that "rejects"
     without protecting cannot pass;
  3. `INSERT` and `SELECT` are untouched, because the table must stay writable;
  4. the ONE permitted `UPDATE` — the `ON DELETE SET NULL` foreign-key retention
     action — still works, while every attempt to borrow that permission is refused.

===============================================================================
A DESIGN BUG THIS SUITE WOULD HAVE CAUGHT
===============================================================================
The first implementation was a blanket `BEFORE UPDATE` trigger. `audit_logs.page_id`
is `ON DELETE SET NULL`, and the engine performs that action as an `UPDATE` on this
table — so the blanket trigger broke tenant deletion outright (measured:
`IntegrityError` on SQLite, `InsufficientPrivilege` on PostgreSQL). That would have
regressed the R18 contract Phase 11 established, and it was caught by the Phase 11
suite before this file existed. Tests 13xx below lock the corrected behaviour so it
cannot regress again.
"""
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402
from core import account_keys, audit_integrity  # noqa: E402

TEST_SECRET = "phase13-test-secret-0123456789abcdef0123456789"

PAGE_LIVE = "p13-tenant-live"

#: Each test gets its own doomed tenant. On PostgreSQL the database persists across
#: tests in a run (only SQLite gets a fresh file per test), so a shared constant made
#: test_1332 depend on whether test_1331 had already deleted it — it passed alone and
#: failed in a full run. Unique ids keep the tests independent on both engines.
def _doomed(name: str) -> str:
    return f"p13-tenant-doomed-{name}"


@pytest.fixture()
def db(tmp_path, monkeypatch):
    db_url = (os.getenv("DATABASE_URL") or "").strip()
    require_pg = (os.getenv("R10_REQUIRE_POSTGRES") or "").strip() == "1"

    if db_url:
        monkeypatch.setenv("DATABASE_URL", db_url)
    else:
        if require_pg:
            pytest.fail(
                "R10_REQUIRE_POSTGRES=1 but DATABASE_URL is unset: these tests would "
                "run on SQLite and would not prove PostgreSQL behaviour."
            )
        monkeypatch.delenv("DATABASE_URL", raising=False)
        path = tmp_path / "p13.db"
        monkeypatch.setenv("DB_PATH", str(path))
        monkeypatch.setattr(database, "DB_PATH", str(path))

    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()
    database.init_db()
    return database


def engine_name() -> str:
    from core import db_engine

    return "postgresql" if db_engine.is_postgres() else "sqlite"


def _rows(action=None):
    conn = database.get_connection()
    try:
        cur = conn.cursor()
        if action is None:
            cur.execute("SELECT id, action, page_id, resource_id, details_json FROM audit_logs ORDER BY id")
        else:
            cur.execute(
                "SELECT id, action, page_id, resource_id, details_json "
                "FROM audit_logs WHERE action = ? ORDER BY id",
                (action,),
            )
        return [tuple(r) for r in cur.fetchall()]
    finally:
        conn.close()


def _attempt(sql, params=None):
    """Run a mutating statement. Returns ("REJECTED"|"ALLOWED", error name)."""
    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute(sql) if params is None else cur.execute(sql, params)
        conn.commit()
        return "ALLOWED", None
    except Exception as exc:
        try:
            conn.rollback()
        except Exception:
            pass
        return "REJECTED", type(exc).__name__
    finally:
        conn.close()


def _seed_two(action="probe.event"):
    database.record_audit_log(
        action, page_id=None, actor_role="system", resource_type="probe", resource_id="1",
        details={"k": "v1"},
    )
    database.record_audit_log(
        action, page_id=None, actor_role="system", resource_type="probe", resource_id="2",
        details={"k": "v2"},
    )


# ===========================================================================
# The guard is installed, and installed CORRECTLY
# ===========================================================================


def test_1301_the_guard_is_installed_with_the_expected_shape(db):
    """Not merely 'a trigger exists' — the right events, timing and level.

    This is the Phase 8 lesson applied to triggers: an object under the expected name
    that enforces the wrong statement protects nothing while looking installed.
    """
    conn = database.get_connection()
    try:
        described = audit_integrity.describe_triggers(conn)
        assert described["dialect"] == engine_name()
        assert audit_integrity.missing_triggers(conn) == []
        assert audit_integrity.wrongly_defined_triggers(conn) == []
        assert audit_integrity.guard_is_correct(conn) is True

        required = set(audit_integrity.REQUIRED_TRIGGERS[described["dialect"]])
        assert required <= described["present"]

        if described["dialect"] == "postgresql":
            update_def = described["details"][audit_integrity.PG_TRIGGER_UPDATE]
            assert update_def["event"] == "UPDATE" and update_def["level"] == "ROW"
            truncate_def = described["details"][audit_integrity.PG_TRIGGER_TRUNCATE]
            assert truncate_def["event"] == "TRUNCATE"
            assert truncate_def["level"] == "STATEMENT", (
                "TRUNCATE is not a row operation; FOR EACH ROW would never fire"
            )
    finally:
        conn.close()


def test_1302_the_update_guard_is_narrowed_to_the_retention_action_only(db):
    """The UPDATE trigger must carry its `WHEN`/IF predicate, not be a blanket refusal.

    A blanket version breaks tenant deletion. A silently *widened* version would exist,
    be wired correctly, and protect nothing — so the predicate itself is asserted.
    """
    conn = database.get_connection()
    try:
        assert audit_integrity.update_guard_allows_only_retention(conn) is True
    finally:
        conn.close()


# ===========================================================================
# INSERT and SELECT must keep working
# ===========================================================================


def test_1311_insert_succeeds(db):
    before = len(_rows())
    database.record_audit_log(
        "probe.insert", page_id=None, actor_role="system", resource_type="probe",
        resource_id="fresh", details={"a": 1},
    )
    after = _rows("probe.insert")
    assert len(_rows()) == before + 1
    assert len(after) == 1
    assert after[0][3] == "fresh"


def test_1312_select_succeeds(db):
    _seed_two("probe.select")
    assert len(_rows("probe.select")) == 2
    assert database.list_audit_logs(limit=10) is not None


def test_1313_concurrent_inserts_all_succeed(db):
    """The guard must not serialise or drop audit writes under concurrency.

    No INSERT trigger exists, so this is a regression guard on that decision: an
    implementation that guarded INSERT (or fired on every statement) would show up
    here as lost or failed rows.
    """
    errors = []

    def worker(n):
        try:
            database.record_audit_log(
                "probe.concurrent", page_id=None, actor_role="system",
                resource_type="probe", resource_id=str(n), details={},
            )
        except Exception as exc:  # pragma: no cover - only on failure
            errors.append((n, type(exc).__name__, str(exc)[:80]))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, f"concurrent audit inserts failed: {errors}"
    assert len(_rows("probe.concurrent")) == 8


# ===========================================================================
# Mutation is rejected — and the data is proven unchanged
# ===========================================================================


def test_1321_update_is_rejected_and_the_row_is_unchanged(db):
    _seed_two("probe.update")
    before = _rows("probe.update")

    outcome, error = _attempt("UPDATE audit_logs SET action = 'TAMPERED'")

    assert outcome == "REJECTED", "an application UPDATE must not be permitted"
    assert error is not None
    assert _rows("probe.update") == before, "the row must be byte-for-byte unchanged"


def test_1322_delete_is_rejected_and_the_rows_survive(db):
    _seed_two("probe.delete")
    before = _rows("probe.delete")

    outcome, error = _attempt("DELETE FROM audit_logs")

    assert outcome == "REJECTED"
    assert error is not None
    assert _rows("probe.delete") == before, "no audit row may be erased"


def test_1323_truncate_is_rejected_on_postgresql(db):
    """The case a row-level trigger misses entirely.

    Measured during Phase 13 design: with only BEFORE UPDATE/DELETE FOR EACH ROW in
    place, `DELETE FROM` was refused while `TRUNCATE` emptied the table.
    """
    if engine_name() != "postgresql":
        pytest.skip("SQLite has no TRUNCATE statement; DELETE FROM is its equivalent")

    _seed_two("probe.truncate")
    before = _rows("probe.truncate")

    outcome, error = _attempt("TRUNCATE audit_logs")

    assert outcome == "REJECTED", "TRUNCATE must not empty the audit trail"
    assert error is not None
    assert _rows("probe.truncate") == before


def test_1324_targeted_delete_cannot_erase_one_incriminating_row(db):
    """A surgical `DELETE ... WHERE id = ?` — the realistic tampering attempt."""
    _seed_two("probe.targeted")
    before = _rows("probe.targeted")
    victim_id = before[0][0]

    outcome, _ = _attempt("DELETE FROM audit_logs WHERE id = ?", (victim_id,))

    assert outcome == "REJECTED"
    assert _rows("probe.targeted") == before


def test_1325_repeated_attempts_fail_every_time(db):
    """The guard is a property, not a one-shot: it must not 'consume' or weaken."""
    _seed_two("probe.repeat")
    before = _rows("probe.repeat")
    for _ in range(4):
        assert _attempt("UPDATE audit_logs SET action = 'X'")[0] == "REJECTED"
        assert _attempt("DELETE FROM audit_logs")[0] == "REJECTED"
    assert _rows("probe.repeat") == before


def test_1326_a_rejected_mutation_does_not_poison_the_connection(db):
    """After a refusal the application must still be able to read and write.

    On PostgreSQL a failed statement aborts the transaction; the application's
    connection handling has to cope. If it did not, one refused tampering attempt
    would take the request path down with it.
    """
    _seed_two("probe.poison")
    assert _attempt("UPDATE audit_logs SET action = 'X'")[0] == "REJECTED"

    database.record_audit_log(
        "probe.after_refusal", page_id=None, actor_role="system",
        resource_type="probe", resource_id="ok", details={},
    )
    assert len(_rows("probe.after_refusal")) == 1


# ===========================================================================
# The retention contract: tenant deletion still works, evidence survives
# ===========================================================================


def test_1331_tenant_deletion_still_succeeds_under_the_guard(db):
    """The `ON DELETE SET NULL` action is implemented as an UPDATE on this table.

    A blanket BEFORE UPDATE trigger breaks this outright. This test exists because the
    first implementation did exactly that, and the Phase 11 suite caught it.
    """
    doomed = _doomed("delete")
    database.save_page(page_id=doomed, name="Doomed", category="general")
    database.record_audit_log(
        "page.delete", page_id=doomed, actor_role="admin",
        resource_type="page", resource_id=doomed, details={"deleted_page_id": doomed},
    )

    assert database.delete_page(doomed) is True
    assert database.get_page(doomed) is None


def test_1332_the_audit_row_survives_with_its_resource_id_intact(db):
    """R18 retention: the row outlives the tenant and still names it."""
    doomed = _doomed("retention")
    database.save_page(page_id=doomed, name="Doomed", category="general")
    database.record_audit_log(
        "page.delete", page_id=doomed, actor_role="admin",
        resource_type="page", resource_id=doomed, details={"deleted_page_id": doomed},
    )
    database.delete_page(doomed)

    rows = [r for r in _rows("page.delete") if r[3] == doomed]
    assert len(rows) == 1, "deleting the tenant must not delete its audit history"
    _id, action, page_id, resource_id, details = rows[0]
    assert page_id is None, "the FK sets the tenant id to NULL"
    assert resource_id == doomed, "the deleted tenant must still be identified"
    assert doomed in (details or ""), "details must still record which page went"


def test_1333_the_retention_permission_cannot_be_borrowed_to_rewrite_history(db):
    """The sharpest test in this file.

    The guard admits `page_id -> NULL` when the parent is gone. That permission must
    not let an attacker change *what the row says happened* in the same statement.
    """
    database.save_page(page_id=PAGE_LIVE, name="Live", category="general")
    database.record_audit_log(
        "payment.confirmed", page_id=PAGE_LIVE, actor_role="system",
        resource_type="invoice", resource_id="INV-1", details={"amount": 1000},
    )

    combined, _ = _attempt(
        "UPDATE audit_logs SET page_id = NULL, action = 'harmless' WHERE resource_id = 'INV-1'"
    )
    details, _ = _attempt(
        "UPDATE audit_logs SET details_json = '{\"amount\": 0}' WHERE resource_id = 'INV-1'"
    )
    nulling, _ = _attempt("UPDATE audit_logs SET page_id = NULL WHERE resource_id = 'INV-1'")

    assert combined == "REJECTED", "cannot borrow the retention allowance to rewrite the action"
    assert details == "REJECTED", "cannot rewrite details_json"
    assert nulling == "REJECTED", (
        "cannot null page_id while the tenant still exists — that is not the FK action"
    )

    rows = _rows("payment.confirmed")
    assert len(rows) == 1
    assert "1000" in (rows[0][4] or ""), "the confirmed amount must be untouched"


# ===========================================================================
# The startup guard
# ===========================================================================


def test_1341_startup_guard_passes_when_the_guard_is_installed(db):
    from core.schema_manager import assert_security_invariants

    assert_security_invariants()  # must not raise


def test_1342_startup_guard_detects_a_missing_trigger(db):
    """A dropped guard must fail startup loudly, naming the remedy."""
    from core.schema_manager import assert_security_invariants

    conn = database.get_connection()
    try:
        dialect = audit_integrity.describe_triggers(conn)["dialect"]
        drop_name = audit_integrity.REQUIRED_TRIGGERS[dialect][-1]
        for statement in audit_integrity.drop_sql(dialect):
            audit_integrity._exec(conn, statement)
        # Re-create only the ones we are not testing, so exactly one is missing.
        for statement in audit_integrity.create_sql(dialect):
            if drop_name not in statement:
                audit_integrity._exec(conn, statement)

        with pytest.raises(RuntimeError) as excinfo:
            assert_security_invariants()
        message = str(excinfo.value)
        assert "append-only" in message
        assert "repair_audit_integrity.py" in message
    finally:
        # ALWAYS restore, even if the assertion above failed.
        for statement in audit_integrity.create_sql(
            audit_integrity.describe_triggers(conn)["dialect"]
        ):
            try:
                audit_integrity._exec(conn, statement)
            except Exception:
                pass
        conn.close()

    from core.schema_manager import assert_security_invariants as recheck

    recheck()  # the database is guarded again


def test_1343_startup_guard_detects_a_wrongly_wired_trigger(db):
    """A trigger under the right name but on the wrong event protects nothing."""
    if engine_name() != "postgresql":
        pytest.skip("event/level wiring is only introspectable on PostgreSQL here")

    from core.schema_manager import assert_security_invariants

    conn = database.get_connection()
    try:
        # Replace the DELETE trigger with an UPDATE trigger of the same name.
        for statement in (
            f"DROP TRIGGER IF EXISTS {audit_integrity.PG_TRIGGER_DELETE} ON audit_logs",
            f"CREATE TRIGGER {audit_integrity.PG_TRIGGER_DELETE} BEFORE UPDATE ON audit_logs "
            f"FOR EACH ROW EXECUTE FUNCTION {audit_integrity.PG_FUNCTION}()",
        ):
            audit_integrity._exec(conn, statement)

        assert audit_integrity.wrongly_defined_triggers(conn) == [
            audit_integrity.PG_TRIGGER_DELETE
        ]
        with pytest.raises(RuntimeError) as excinfo:
            assert_security_invariants()
        assert "append-only" in str(excinfo.value)
    finally:
        for statement in audit_integrity.pg_create_sql():
            try:
                audit_integrity._exec(conn, statement)
            except Exception:
                pass
        conn.close()

    from core.schema_manager import assert_security_invariants as recheck

    recheck()


def test_1344_the_test_helper_never_leaks_out_of_tests():
    """`temporarily_unguarded` is test infrastructure, not a production escape hatch.

    It is the only thing that can lift the guard, so if it were reachable from
    application code the protection would be nominal. This scans the tree.
    """
    import re

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    offenders = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in {".git", "__pycache__", ".scratch", "node_modules", "tests", ".venv"}
        ]
        for filename in filenames:
            if not filename.endswith(".py"):
                continue
            path = os.path.join(dirpath, filename)
            if path.endswith(os.path.join("core", "audit_integrity.py")):
                continue  # the definition itself
            try:
                text = open(path, encoding="utf-8", errors="ignore").read()
            except Exception:  # pragma: no cover
                continue
            if re.search(r"\btemporarily_unguarded\b", text):
                offenders.append(os.path.relpath(path, root))

    assert not offenders, (
        "the guard-bypass helper is referenced outside tests/: " + repr(offenders)
    )


def test_1345_the_reset_helper_restores_the_guard(db):
    """The sanctioned test reset must leave the table protected, not open."""
    from conftest import clear_audit_logs_for_test

    conn = database.get_connection()
    try:
        clear_audit_logs_for_test(conn)
        assert audit_integrity.guard_is_correct(conn) is True, (
            "clear_audit_logs_for_test left the audit table unguarded"
        )
        assert _rows() == []

        # ...and it is genuinely closed again. A row must be present first: a
        # `FOR EACH ROW` trigger cannot fire on a statement that matches no rows, so
        # asserting against an empty table would pass whatever the guard did. (That is
        # exactly how this test failed its first draft — it proved nothing.)
        database.record_audit_log(
            "probe.reset_verified", page_id=None, actor_role="system",
            resource_type="probe", resource_id="v", details={},
        )
        assert _attempt("DELETE FROM audit_logs")[0] == "REJECTED", (
            "the table must be append-only again after the test reset"
        )
        assert len(_rows("probe.reset_verified")) == 1
    finally:
        conn.close()


# ===========================================================================
# Migration and backup/restore
# ===========================================================================


def test_1351_downgrade_removes_the_guard_and_upgrade_restores_it(db):
    """The revision must toggle cleanly, and no audit row may be lost doing it.

    A downgrade legitimately removes the protection — dropping a trigger is a
    deliberate DDL act by someone who already holds DDL rights. What it must NOT do is
    touch a single row.
    """
    import subprocess

    from core import db_engine

    if not db_engine.is_postgres():
        pytest.skip("alembic downgrade/upgrade is exercised on PostgreSQL in CI")

    database.record_audit_log(
        "probe.migration", page_id=None, actor_role="system", resource_type="probe",
        resource_id="survives", details={},
    )
    before = len(_rows())

    def alembic(*args):
        return subprocess.run(
            [sys.executable, "-m", "alembic", *args],
            capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )

    try:
        assert alembic("downgrade", "0006_login_identity").returncode == 0
        conn = database.get_connection()
        try:
            assert audit_integrity.missing_triggers(conn), "downgrade must remove the guard"
        finally:
            conn.close()
        assert len(_rows()) == before, "a downgrade must not delete audit rows"
    finally:
        assert alembic("upgrade", "head").returncode == 0

    conn = database.get_connection()
    try:
        assert audit_integrity.guard_is_correct(conn) is True
    finally:
        conn.close()
    assert len(_rows()) == before, "rows must survive the round trip"


def test_1352_backup_and_restore_keep_the_guard_installed(db, tmp_path, monkeypatch):
    """The documented restore path must not silently leave the table unprotected.

    PostgreSQL restores with `pg_dump --clean`, which emits `DROP TRIGGER` /
    `DROP TABLE` / `CREATE TABLE` / `CREATE TRIGGER` — so the guard is recreated and the
    `BEFORE DELETE` triggers are never asked to fire. SQLite restores by replacing the
    file with a page-level copy, which carries the triggers with it. Both are asserted
    here, because "our backup tooling bypasses our own guard" would be a quiet disaster.
    """
    import database as _database
    from core import backup_service

    monkeypatch.setattr(backup_service, "BACKUP_DIR", str(tmp_path / "backups"))
    os.makedirs(str(tmp_path / "backups"), exist_ok=True)

    _database.record_audit_log(
        "probe.backup", page_id=None, actor_role="system", resource_type="probe",
        resource_id="in_snapshot", details={},
    )
    rows_at_backup = len(_rows())

    created = backup_service.create_backup(label="p13_test")
    assert created.get("success"), created

    _database.record_audit_log(
        "probe.backup", page_id=None, actor_role="system", resource_type="probe",
        resource_id="after_snapshot", details={},
    )
    assert len(_rows()) == rows_at_backup + 1, "the extra row must exist before restoring"

    restored = backup_service.restore_backup(created["filename"])
    assert restored.get("success"), restored

    assert len(_rows()) == rows_at_backup, "the restore must replace the data with the snapshot"

    conn = database.get_connection()
    try:
        assert audit_integrity.guard_is_correct(conn) is True, (
            "the guard must be installed again after a restore"
        )
    finally:
        conn.close()

    # ...and it must actually enforce, not merely exist.
    _database.record_audit_log(
        "probe.backup_after", page_id=None, actor_role="system", resource_type="probe",
        resource_id="v", details={},
    )
    assert _attempt("DELETE FROM audit_logs")[0] == "REJECTED"
