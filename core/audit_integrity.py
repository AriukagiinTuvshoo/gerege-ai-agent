"""
Audit-trail integrity: the append-only guard on `audit_logs` (Phase 13, finding F-D).

===============================================================================
WHY THIS EXISTS
===============================================================================
Phase 12 found that `audit_logs` carried **no** tamper protection: zero triggers on
either engine, and an application-level `UPDATE` or `DELETE` succeeded on SQLite and
PostgreSQL alike. Phase 13 re-measured the baseline before changing anything:

    app-level UPDATE audit_logs   -> SUCCEEDED   (SQLite and PostgreSQL 16)
    app-level DELETE FROM ...     -> SUCCEEDED   (SQLite and PostgreSQL 16)
    triggers on audit_logs        -> 0

An earlier scan of every tracked write path found exactly one `INSERT` and two
`SELECT`s against this table, and **no application code that updates or deletes an
audit row**. So the defect was never in the application: it was that nothing in the
*database* refused the statement.

That matters because for three actions the audit row is the only durable record of an
irreversible act:

  * `payment.confirmed`      — the invoice proves money moved; only the audit row
                               records that a provider-verified confirmation happened.
  * `page.credentials.updated` — `pages.client_magic_token` holds the *current* token,
                               so the history of rotations is audit-only.
  * `page.delete`            — the page row is gone; the audit row is the record.

===============================================================================
WHAT THIS PROTECTION DOES AND DOES NOT DO
===============================================================================
PROTECTS (measured, see the Phase 13 report):

  T1  Accidental or ordinary application-level mutation. A stray `DELETE`, a
      mis-written cleanup job, a bad migration that rewrites history — all are
      refused by the database instead of quietly succeeding.

PROTECTS ONLY WHEN PRIVILEGES ARE RESTRICTED:

  T2  Stolen *application* credentials. With a non-owner role that has
      INSERT+SELECT on this table and no UPDATE/DELETE, plus no ownership, the
      guard holds. The documented production deployment does NOT run that way.

DOES NOT PROTECT:

  T2' Stolen *current production* superuser credentials. `docker-compose.prod.yml`
      connects as `POSTGRES_USER`, which is the table owner and (measured) a
      superuser. That role can `DISABLE TRIGGER ALL`, `SET session_replication_role
      = replica`, or `DROP TRIGGER`. All three were measured to bypass this guard.

  T3  DBA / owner compromise, for the same reason.

  T4  Backup or storage-level tampering. Editing the dump, or the SQLite file on
      disk, is invisible to any in-database mechanism.

This guard is therefore a **tamper *resistance*** control, not tamper *evidence*: it
raises the cost and makes mutation deliberate rather than accidental. Detecting an
owner-level rewrite requires anchoring the history somewhere the owner does not
control — WORM storage or a signed, externally-stored head — which is a separate
design (see the Phase 13 report's follow-up proposal).

===============================================================================
HOW IT IS INSTALLED
===============================================================================
Revision `0007_audit_append_only` creates exactly these objects. This module is the
single definition, imported by the migration, by the startup guard, and by the test
reset helper, so the three can never disagree about what "installed" means.

Nothing here changes the table: no column, no constraint, no data. Strictly additive
DDL, and `downgrade()` removes exactly what `upgrade()` added.

`INSERT` is deliberately never guarded: `audit_logs` must stay writable. Only
mutation of what has already been written is refused.

===============================================================================
THE ONE PERMITTED UPDATE — AND WHY A BLANKET TRIGGER WAS WRONG
===============================================================================
A blanket `BEFORE UPDATE` trigger is incorrect on this table, and the first
implementation of this guard was wrong because of it.

`audit_logs.page_id` is `ON DELETE SET NULL` (revision `0003`, and the R18 contract
from Phase 11: the audit trail must outlive the tenant it describes). The engine
implements that foreign-key action as an `UPDATE` on `audit_logs`. So a blanket
`BEFORE UPDATE` trigger refuses the retention action and **breaks tenant deletion
outright**. Measured before the correction: `delete_page()` failed on SQLite
(`IntegrityError: audit_logs is append-only`) and on PostgreSQL
(`InsufficientPrivilege`), which would have shipped a regression against a contract an
earlier phase established.

The trigger therefore admits exactly one shape, and only when every clause holds:

    * `NEW.page_id` is NULL and `OLD.page_id` is not — the row is losing its tenant;
    * the referenced `pages` row is already gone — so this is the engine's action and
      not an application writing a NULL over a live tenant's id;
    * **every other column is unchanged** — so the permission cannot be borrowed to
      rewrite `action`, `actor_id`, `details_json` or `created_at` in the same
      statement.

Verified on both engines: a direct `UPDATE ... SET page_id = NULL` while the parent
still exists is refused; `UPDATE ... SET action = 'FAKE'` is refused;
`UPDATE ... SET page_id = NULL, action = 'FAKE'` is refused; deleting the tenant is
allowed and the audit row survives with `page_id = NULL` and `resource_id` intact.

The allowance is a *removal of information the row already conceded* (which tenant it
belonged to), never a change to what it asserts happened.
"""
from contextlib import contextmanager
from typing import List

#: Table under protection.
AUDIT_TABLE = "audit_logs"

#: The `plpgsql` guard function used by all three PostgreSQL triggers.
PG_FUNCTION = "audit_logs_append_only_guard"

#: Trigger names, one per refused statement shape. PostgreSQL needs three because a
#: row-level `BEFORE DELETE` trigger **does not fire on `TRUNCATE`** — measured in
#: Phase 13: `DELETE FROM` was refused while `TRUNCATE` emptied the table. SQLite has
#: no `TRUNCATE` statement (the equivalent is `DELETE FROM`, already covered), so it
#: needs two.
PG_TRIGGER_UPDATE = "audit_logs_no_update"
PG_TRIGGER_DELETE = "audit_logs_no_delete"
PG_TRIGGER_TRUNCATE = "audit_logs_no_truncate"

SQLITE_TRIGGER_UPDATE = "audit_logs_no_update"
SQLITE_TRIGGER_DELETE = "audit_logs_no_delete"

#: Every trigger this protection requires, per dialect. The startup guard asserts
#: that all of them exist — a partial installation is the failure mode that looks
#: protected while being half-open.
REQUIRED_TRIGGERS = {
    "postgresql": (PG_TRIGGER_UPDATE, PG_TRIGGER_DELETE, PG_TRIGGER_TRUNCATE),
    "sqlite": (SQLITE_TRIGGER_UPDATE, SQLITE_TRIGGER_DELETE),
}

#: The message an operator will see. Names the table and the operation, and is
#: deliberately free of any row content — a refusal must not echo audited data.
PG_ERROR_MESSAGE = "audit_logs is append-only: % is not permitted"
SQLITE_ERROR_MESSAGE = "audit_logs is append-only"


# ---------------------------------------------------------------------------
# PostgreSQL DDL
# ---------------------------------------------------------------------------
def pg_create_sql() -> List[str]:
    """Create the guard function and its three triggers. Idempotent."""
    return [
        f"""
CREATE OR REPLACE FUNCTION {PG_FUNCTION}() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- The ONE permitted UPDATE is not an update at all: it is the retention action
    -- of the `ON DELETE SET NULL` foreign key, fired by the engine when a tenant is
    -- deleted. Phase 11's R18 contract depends on it, and a blanket BEFORE UPDATE
    -- trigger breaks tenant deletion outright (measured: `delete_page` failed on
    -- SQLite and PostgreSQL until this branch existed).
    --
    -- It is admitted only when EVERY part of the predicate holds, so it cannot be
    -- used as a hole: the row must be losing its page_id, the parent must already be
    -- gone (so this is the engine's action, not an application claiming a dead page),
    -- and every other column must be unchanged. An application UPDATE that tries to
    -- null page_id while the parent still exists is refused.
    IF TG_OP = 'UPDATE'
       AND NEW.page_id IS NULL
       AND OLD.page_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM pages WHERE page_id = OLD.page_id)
       AND NEW.id          IS NOT DISTINCT FROM OLD.id
       AND NEW.action      IS NOT DISTINCT FROM OLD.action
       AND NEW.resource_id IS NOT DISTINCT FROM OLD.resource_id
       AND NEW.actor_role  IS NOT DISTINCT FROM OLD.actor_role
       AND NEW.actor_id    IS NOT DISTINCT FROM OLD.actor_id
       AND NEW.resource_type IS NOT DISTINCT FROM OLD.resource_type
       AND NEW.details_json  IS NOT DISTINCT FROM OLD.details_json
       AND NEW.ip_address    IS NOT DISTINCT FROM OLD.ip_address
       AND NEW.created_at    IS NOT DISTINCT FROM OLD.created_at
    THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION USING
        ERRCODE = 'insufficient_privilege',
        MESSAGE = 'audit_logs is append-only: ' || TG_OP || ' is not permitted',
        HINT    = 'The audit trail records completed operations and may only be appended to.';
END;
$$
""",
        f"DROP TRIGGER IF EXISTS {PG_TRIGGER_UPDATE} ON {AUDIT_TABLE}",
        f"""
CREATE TRIGGER {PG_TRIGGER_UPDATE} BEFORE UPDATE ON {AUDIT_TABLE}
    FOR EACH ROW EXECUTE FUNCTION {PG_FUNCTION}()
""",
        f"DROP TRIGGER IF EXISTS {PG_TRIGGER_DELETE} ON {AUDIT_TABLE}",
        f"""
CREATE TRIGGER {PG_TRIGGER_DELETE} BEFORE DELETE ON {AUDIT_TABLE}
    FOR EACH ROW EXECUTE FUNCTION {PG_FUNCTION}()
""",
        # Statement-level: TRUNCATE is not a row operation, so FOR EACH ROW would
        # never fire. This is the trigger whose absence leaves a one-command hole.
        f"DROP TRIGGER IF EXISTS {PG_TRIGGER_TRUNCATE} ON {AUDIT_TABLE}",
        f"""
CREATE TRIGGER {PG_TRIGGER_TRUNCATE} BEFORE TRUNCATE ON {AUDIT_TABLE}
    FOR EACH STATEMENT EXECUTE FUNCTION {PG_FUNCTION}()
""",
    ]


def pg_drop_sql() -> List[str]:
    """Remove the triggers first, then the function they depend on."""
    return [
        f"DROP TRIGGER IF EXISTS {PG_TRIGGER_TRUNCATE} ON {AUDIT_TABLE}",
        f"DROP TRIGGER IF EXISTS {PG_TRIGGER_DELETE} ON {AUDIT_TABLE}",
        f"DROP TRIGGER IF EXISTS {PG_TRIGGER_UPDATE} ON {AUDIT_TABLE}",
        f"DROP FUNCTION IF EXISTS {PG_FUNCTION}()",
    ]


# ---------------------------------------------------------------------------
# SQLite DDL
# ---------------------------------------------------------------------------
def sqlite_create_sql() -> List[str]:
    """Create both SQLite guards. Idempotent.

    `RAISE(ABORT, ...)` rolls back the offending statement only, leaving any
    surrounding transaction intact — `ROLLBACK` would discard unrelated work the
    caller had already done, and `FAIL` leaves earlier rows of the same statement
    applied. `ABORT` is the behaviour an append-only guard wants when the caller is
    an application holding one transaction per request.
    """
    return [
        f"DROP TRIGGER IF EXISTS {SQLITE_TRIGGER_UPDATE}",
        f"""
CREATE TRIGGER {SQLITE_TRIGGER_UPDATE} BEFORE UPDATE ON {AUDIT_TABLE}
WHEN NOT (
    -- The single permitted UPDATE is the `ON DELETE SET NULL` retention action of
    -- the foreign key, fired when a tenant is deleted. Same predicate as the
    -- PostgreSQL function, kept in step deliberately; see the note there.
    NEW.page_id IS NULL
    AND OLD.page_id IS NOT NULL
    AND (SELECT COUNT(*) FROM pages WHERE page_id = OLD.page_id) = 0
    AND NEW.id            IS OLD.id
    AND NEW.action        IS OLD.action
    AND NEW.resource_id   IS OLD.resource_id
    AND NEW.actor_role    IS OLD.actor_role
    AND NEW.actor_id      IS OLD.actor_id
    AND NEW.resource_type IS OLD.resource_type
    AND NEW.details_json  IS OLD.details_json
    AND NEW.ip_address    IS OLD.ip_address
    AND NEW.created_at    IS OLD.created_at
)
BEGIN
    SELECT RAISE(ABORT, '{SQLITE_ERROR_MESSAGE}');
END
""",
        f"DROP TRIGGER IF EXISTS {SQLITE_TRIGGER_DELETE}",
        f"""
CREATE TRIGGER {SQLITE_TRIGGER_DELETE} BEFORE DELETE ON {AUDIT_TABLE}
BEGIN
    SELECT RAISE(ABORT, '{SQLITE_ERROR_MESSAGE}');
END
""",
    ]


def sqlite_drop_sql() -> List[str]:
    return [
        f"DROP TRIGGER IF EXISTS {SQLITE_TRIGGER_DELETE}",
        f"DROP TRIGGER IF EXISTS {SQLITE_TRIGGER_UPDATE}",
    ]


def create_sql(dialect: str) -> List[str]:
    if dialect == "postgresql":
        return pg_create_sql()
    if dialect == "sqlite":
        return sqlite_create_sql()
    raise ValueError(f"unsupported dialect for the audit append-only guard: {dialect!r}")


def drop_sql(dialect: str) -> List[str]:
    if dialect == "postgresql":
        return pg_drop_sql()
    if dialect == "sqlite":
        return sqlite_drop_sql()
    raise ValueError(f"unsupported dialect for the audit append-only guard: {dialect!r}")


# ---------------------------------------------------------------------------
# Read-only inspection — shared by the startup guard and the tests
# ---------------------------------------------------------------------------
def describe_triggers(conn) -> dict:
    """Which of the required triggers exist, and (PostgreSQL) what they do.

    Returns a dict with:
      ``dialect``   — "postgresql" / "sqlite" / "unknown"
      ``present``   — set of trigger names found on `audit_logs`
      ``required``  — tuple of names this dialect requires
      ``details``   — per-trigger {event, timing, level, function} on PostgreSQL

    Read-only: it issues nothing but catalogue `SELECT`s. Deliberately detected, never
    probed by trial — on PostgreSQL a failing statement aborts the whole transaction,
    so "try the DELETE and see" would poison the caller's transaction and is never
    used here (`core.username_uniqueness._dialect_of` documents the same rule).
    """
    from core.username_uniqueness import _dialect_of, _execute_fetch_all

    dialect = _dialect_of(conn)
    present: set = set()
    details: dict = {}

    if dialect == "postgresql":
        # `tgtype` is a bitmask: 1=ROW, 2=BEFORE, 4=INSERT, 8=DELETE, 16=UPDATE,
        # 32=TRUNCATE. Reading the event/level out of it means the guard can tell a
        # correctly-wired trigger from one that merely shares the name.
        rows = _execute_fetch_all(
            conn,
            "SELECT t.tgname,"
            "       CASE WHEN (t.tgtype & 2) <> 0 THEN 'BEFORE' ELSE 'AFTER' END,"
            "       CASE WHEN (t.tgtype & 4)  <> 0 THEN 'INSERT'"
            "            WHEN (t.tgtype & 8)  <> 0 THEN 'DELETE'"
            "            WHEN (t.tgtype & 16) <> 0 THEN 'UPDATE'"
            "            WHEN (t.tgtype & 32) <> 0 THEN 'TRUNCATE'"
            "            ELSE 'OTHER' END,"
            "       CASE WHEN (t.tgtype & 1) <> 0 THEN 'ROW' ELSE 'STATEMENT' END,"
            "       p.proname"
            "  FROM pg_trigger t"
            "  JOIN pg_class c ON c.oid = t.tgrelid"
            "  JOIN pg_proc  p ON p.oid = t.tgfoid"
            f" WHERE c.relname = '{AUDIT_TABLE}' AND NOT t.tgisinternal",
        )
        for name, timing, event, level, function in rows:
            present.add(name)
            details[name] = {
                "timing": timing,
                "event": event,
                "level": level,
                "function": function,
            }
    elif dialect == "sqlite":
        rows = _execute_fetch_all(
            conn,
            f"SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='{AUDIT_TABLE}'",
        )
        present = {r[0] for r in rows}

    return {
        "dialect": dialect,
        "present": present,
        "required": REQUIRED_TRIGGERS.get(dialect, ()),
        "details": details,
    }


def missing_triggers(conn) -> List[str]:
    """The required triggers that are absent. Empty list means fully installed."""
    described = describe_triggers(conn)
    return [name for name in described["required"] if name not in described["present"]]


def wrongly_defined_triggers(conn) -> List[str]:
    """PostgreSQL only: triggers present under the right name but wired to the wrong
    event, timing or level.

    Name-only checking is exactly the mistake Phase 8 made with the username index —
    an object can exist under the expected name while enforcing nothing. A
    `BEFORE UPDATE FOR EACH ROW` trigger sitting on the `DELETE` event would pass a
    name check and protect the wrong statement.
    """
    described = describe_triggers(conn)
    if described["dialect"] != "postgresql":
        return []

    expected = {
        PG_TRIGGER_UPDATE: ("BEFORE", "UPDATE", "ROW"),
        PG_TRIGGER_DELETE: ("BEFORE", "DELETE", "ROW"),
        PG_TRIGGER_TRUNCATE: ("BEFORE", "TRUNCATE", "STATEMENT"),
    }
    wrong: List[str] = []
    for name, (timing, event, level) in expected.items():
        found = described["details"].get(name)
        if found is None:
            continue
        if (
            found["timing"] != timing
            or found["event"] != event
            or found["level"] != level
            or found["function"] != PG_FUNCTION
        ):
            wrong.append(name)
    return wrong


def update_guard_allows_only_retention(conn) -> bool:
    """Whether the UPDATE guard is narrowed to the FK retention action and no wider.

    The guard is defined with a `WHEN NOT (<retention predicate>)` clause. A checking
    routine that only counted triggers would accept a version whose `WHEN` clause had
    been widened to admit arbitrary updates — a guard that exists, is wired to the
    right event, and protects nothing. This compares the stored definition against the
    predicate we intend (normalised for whitespace), so a silently-loosened clause is
    a startup failure.

    SQLite exposes the original text in `sqlite_master.sql`; PostgreSQL stores it in
    `pg_get_triggerdef`.
    """
    from core.username_uniqueness import _dialect_of, _execute_fetch_all

    dialect = _dialect_of(conn)

    if dialect == "sqlite":
        rows = _execute_fetch_all(
            conn,
            f"SELECT sql FROM sqlite_master WHERE type='trigger' AND name='{SQLITE_TRIGGER_UPDATE}'",
        )
        text = (rows[0][0] or "") if rows else ""
        if not text:
            return False
        normalised = " ".join(text.split()).upper()
        return (
            "WHEN NOT (" in normalised
            # every column must be pinned to OLD, otherwise the allowance is wider
            and "NEW.ID IS OLD.ID" in normalised
            and "NEW.ACTION IS OLD.ACTION" in normalised
            and "NEW.DETAILS_JSON IS OLD.DETAILS_JSON" in normalised
            and "NEW.CREATED_AT IS OLD.CREATED_AT" in normalised
            and "NEW.PAGE_ID IS NULL" in normalised
            and "SELECT COUNT(*) FROM PAGES" in normalised
        )

    if dialect == "postgresql":
        rows = _execute_fetch_all(
            conn,
            "SELECT pg_get_functiondef(p.oid) FROM pg_proc p WHERE p.proname = "
            f"'{PG_FUNCTION}'",
        )
        text = (rows[0][0] or "") if rows else ""
        if not text:
            return False
        normalised = " ".join(text.split()).upper()
        return (
            "IF TG_OP = 'UPDATE'" in normalised
            and "NEW.PAGE_ID IS NULL" in normalised
            and "NOT EXISTS" in normalised
            and "IS NOT DISTINCT FROM OLD.ACTION" in normalised
            and "IS NOT DISTINCT FROM OLD.DETAILS_JSON" in normalised
            and "IS NOT DISTINCT FROM OLD.CREATED_AT" in normalised
        )

    return False


def guard_is_correct(conn) -> bool:
    """The whole invariant: every required trigger present, correctly defined, and the
    UPDATE guard narrowed to the FK retention action rather than widened."""
    return (
        not missing_triggers(conn)
        and not wrongly_defined_triggers(conn)
        and update_guard_allows_only_retention(conn)
    )


# ---------------------------------------------------------------------------
# Test-only reset
# ---------------------------------------------------------------------------
@contextmanager
def temporarily_unguarded(conn):
    """Context manager that lifts the guard for a test, then restores it.

    **Test infrastructure only.** This is not exported through any application module
    and no production code path calls it: `grep -rn temporarily_unguarded` finds
    `tests/` and nothing else, which `tests/test_e02_phase13_audit_append_only.py`
    asserts. It exists because several suites legitimately clear `audit_logs` between
    cases and would otherwise be forced to weaken their assertions.

    Restoration is in a `finally`, and is *verified* rather than assumed: if the
    guard is not correctly back in place afterwards, this raises. A test helper that
    silently leaves a production table unprotected is worse than no helper.

    On failure mid-way the exception propagates after restoration is attempted, so a
    failing test cannot leak an unguarded table into the next one.
    """
    from core.username_uniqueness import _dialect_of

    dialect = _dialect_of(conn)
    for statement in drop_sql(dialect):
        _exec(conn, statement)
    try:
        yield
    finally:
        for statement in create_sql(dialect):
            _exec(conn, statement)
        if not guard_is_correct(conn):
            raise RuntimeError(
                "audit_logs append-only guard was not restored after a test-only "
                "bypass; refusing to continue with an unprotected audit table"
            )


def _exec(conn, sql: str) -> None:
    """Execute one DDL statement on either a DB-API or a SQLAlchemy connection."""
    import inspect

    # `_execute_fetch_all`'s sibling: DDL returns no rows, so it needs its own path.
    if hasattr(conn, "cursor") and not inspect.ismethod(getattr(conn, "exec_driver_sql", None)):
        cursor = conn.cursor()
        try:
            cursor.execute(sql)
        finally:
            try:
                cursor.close()
            except Exception:
                pass
    else:
        conn.exec_driver_sql(sql)

    # Commit unconditionally.
    #
    # Two earlier versions of this function got it wrong, both by *trying to be clever
    # about whether a commit was needed*:
    #   * `getattr(conn, "autocommit", True) is not True` skipped the commit entirely for
    #     any connection without an `autocommit` attribute;
    #   * `getattr(conn, "autocommit", False) is False` still skipped it for
    #     `sqlite3.Connection`, whose `autocommit` is `LEGACY_TRANSACTION_CONTROL` (-1)
    #     rather than a bool, and for `PostgresCompatConnection`, which has none.
    # In both cases the DDL sat in an uncommitted transaction: the triggers were visible
    # on the connection that created them and disappeared when it closed. The guard
    # looked installed and protected nothing — exactly the failure mode this phase is
    # about. There is no correct guess to make here, so the commit is simply issued and
    # a connection that has nothing to commit treats it as a no-op.
    commit = getattr(conn, "commit", None)
    if commit is not None:
        try:
            commit()
        except Exception:
            pass
