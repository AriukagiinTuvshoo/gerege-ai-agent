"""
Test-only helper: simulate a *legacy* database that predates the R10 unique index.

===============================================================================
WHY THIS EXISTS
===============================================================================
Several suites (Phase 4.1, Phase 4.2, Phase 8) need to assert how the application
behaves when two pages already share a normalized username. That state is now
forbidden by the database, which is the whole point of the Phase 8 remediation.

Those tests are still valuable: a real installation that upgrades from an older
build may already contain duplicates (the migration refuses to install the index
until an operator resolves them — see docs/operations/USERNAME_UNIQUENESS_MIGRATION.md),
and the read path must behave safely on such a database. But they cannot fabricate
the state through the normal write path any more, and they must not silently
disable the index and leave it disabled.

`legacy_duplicates_allowed()` is the explicit, scoped, self-restoring way to say
"pretend this database predates the invariant". It:

  * drops the index, runs the body, and **always** re-creates it in `finally`;
  * asserts afterwards that the invariant is back, so a failure cannot silently
    leave a suite running without the guarantee;
  * is test-only and lives in `tests/`, so it can never be imported by production code.

It is deliberately *not* a general-purpose escape hatch: production code must never
have a way to bypass the constraint, and nothing outside `tests/` imports this.
"""
import contextlib

import database
from core import username_uniqueness as uniq


def _dialect() -> str:
    from core import db_engine

    return "postgresql" if db_engine.is_postgres() else "sqlite"


@contextlib.contextmanager
def legacy_duplicates_allowed():
    """
    Temporarily remove the username uniqueness index to simulate legacy data.

    Use as a context manager around the fabrication of duplicate rows only::

        with legacy_duplicates_allowed():
            <insert duplicates via direct SQL>

    The index is restored on exit even if the body raises, and the restoration is
    verified rather than assumed.
    """
    dialect = _dialect()
    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute(uniq.drop_index_sql(dialect))
        conn.commit()
    finally:
        conn.close()

    # Revision `0006` (E-02 Phase 10, R16) polices this same state with a second,
    # independent mechanism: the namespace triggers refuse a duplicate username no
    # matter whether the R10 index exists. A "legacy" database therefore predates
    # BOTH, so both have to go or the fabrication this context manager exists for is
    # impossible. Suspending one and not the other would make this helper silently
    # stop working rather than cleanly fail.
    identity_dialect = suspend_login_identity()

    try:
        yield
    finally:
        # The index cannot be re-created while a duplicate still exists — the engine refuses,
        # which is the invariant working correctly. Callers that need to *assert on* the
        # duplicate (resolution, ambiguity reporting) therefore clean up first, via
        # `clear_legacy_duplicates()`, and then leave the context. Anything they miss is
        # cleared here so the index can always be restored.
        clear_legacy_duplicates()
        conn = database.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(uniq.create_index_sql(dialect))
            conn.commit()
            if not uniq.index_is_correct(conn):
                raise AssertionError(
                    "legacy_duplicates_allowed() failed to restore "
                    f"{uniq.USERNAME_UNIQUE_INDEX}: the suite would continue without the "
                    "R10 uniqueness invariant in force"
                )
        finally:
            conn.close()
        # Restore R16 as well, in the same verified-not-assumed way.
        restore_login_identity(identity_dialect)


#: Page-id prefixes these legacy-data tests create. Cleanup is scoped to them so it can
#: never touch a row a real tenant could own.
LEGACY_TEST_PREFIXES = ("page-dup%", "p8-seq-%", "p8-empty-%")


def like_pattern(prefix: str) -> str:
    """
    A LIKE pattern usable in a parameterised statement on both engines.

    psycopg2 treats every `%` in the SQL text as a placeholder marker, so a literal
    `LIKE 'p8-%'` raises `IndexError: tuple index out of range`. Doubling the percent
    escapes it for psycopg2; SQLite uses `?` placeholders and wants the single form.
    """
    from core import db_engine

    return prefix.replace("%", "%%") if db_engine.is_postgres() else prefix


def clear_legacy_duplicates() -> int:
    """
    Remove the fabricated duplicate usernames so the index can be restored.

    Scoped to `LEGACY_TEST_PREFIXES`. Returns how many page rows were cleared, which lets a
    test assert its own cleanup rather than trusting it.
    """
    conn = database.get_connection()
    cleared = 0
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT LOWER(TRIM(client_username)) AS norm FROM pages "
            "WHERE client_username IS NOT NULL AND TRIM(client_username) <> '' "
            "GROUP BY 1 HAVING COUNT(*) > 1"
        )
        groups = [row[0] for row in cur.fetchall()]
        for norm in groups:
            for pattern in LEGACY_TEST_PREFIXES:
                cur.execute(
                    "UPDATE pages SET client_username = NULL, client_password_hash = NULL, "
                    "client_salt = NULL WHERE LOWER(TRIM(client_username)) = ? "
                    "AND page_id LIKE ?",
                    (norm, like_pattern(pattern)),
                )
                cleared += getattr(cur, "rowcount", 0) or 0
        conn.commit()
    finally:
        conn.close()
    return cleared


# ===========================================================================
# Fixture-style API for tests whose whole body depends on the duplicate existing
# ===========================================================================
# A context manager is the wrong shape for a fixture like `dup_db`, whose duplicate must be
# alive for the entire test. These two functions are the same mechanism without the block:
# `suspend_username_uniqueness()` before fabricating, `restore_username_uniqueness()` after
# the test has asserted — with the restoration verified rather than assumed.


def suspend_username_uniqueness() -> str:
    """
    Drop the unique index so legacy duplicates can be fabricated. Returns the dialect used,
    which must be passed to `restore_username_uniqueness()`.

    Never leaves the suspension in place: pairs with `restore_username_uniqueness()` in the
    fixture's teardown, which asserts that the invariant really came back.
    """
    dialect = _dialect()
    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute(uniq.drop_index_sql(dialect))
        conn.commit()
    finally:
        conn.close()
    return dialect


def restore_username_uniqueness(dialect: str) -> None:
    """
    Clear fabricated duplicates and re-create the index, asserting the invariant is back.
    """
    clear_legacy_duplicates()
    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute(uniq.create_index_sql(dialect))
        conn.commit()
        if not uniq.index_is_correct(conn):
            raise AssertionError(
                "restore_username_uniqueness() could not restore "
                f"{uniq.USERNAME_UNIQUE_INDEX}: the suite would continue without the R10 "
                "uniqueness invariant in force"
            )
    finally:
        conn.close()


# ===========================================================================
# E-02 Phase 10: simulating a database that predates revision `0006` too
# ===========================================================================
# Revision `0006` adds a *second* database-enforced invariant: a normalized login
# identifier (page_id or client_username, lower-cased and trimmed) names at most one
# tenant. Its triggers police raw SQL as well as the ORM, so dropping only the R10
# index is no longer enough to fabricate a "legacy" duplicate username — the trigger
# refuses exactly the state the test is trying to create, with
#   UNIQUE constraint failed: page_login_namespace.normalized_identifier
#
# That refusal is correct behaviour, not a regression. These helpers let a test say
# "pretend this database predates 0006 as well", which is the honest shape of the
# situation the migration actually faces: an installation upgrading from an older
# build carries duplicates that were written before ANY constraint existed.
#
# Same guarantees as `suspend_username_uniqueness`: scoped, explicit, and restored
# with a verification that raises if the invariant did not really come back.


def suspend_login_identity() -> str:
    """Drop the 0006 triggers and projection so pre-0006 state can be fabricated."""
    from core import login_identity

    dialect = _dialect()
    conn = database.get_connection()
    try:
        cur = conn.cursor()
        for stmt in login_identity.drop_triggers_sql(dialect):
            cur.execute(stmt)
        cur.execute(login_identity.drop_table_sql(dialect))
        conn.commit()
    finally:
        conn.close()
    return dialect


def restore_login_identity(dialect: str) -> None:
    """Re-create the projection and triggers, then assert they are really enforcing."""
    from core import login_identity

    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute(login_identity.create_table_sql(dialect))
        # Rebuild from `pages`, which is the only source of truth: a trigger that is
        # created over a stale projection would pass `trigger_present()` while being
        # wrong. Duplicates must already be gone by the caller.
        login_identity.assert_no_identifier_collisions(conn)
        cur.execute(login_identity.backfill_namespace_sql(dialect))
        for stmt in login_identity.create_triggers_sql(dialect):
            cur.execute(stmt)
        conn.commit()
        if not login_identity.namespace_is_correct(conn):
            raise AssertionError(
                "restore_login_identity() left a projection that does not match `pages`: "
                "the suite would continue without the R16 cross-column invariant in force"
            )
        if not login_identity.trigger_present(conn):
            raise AssertionError(
                "restore_login_identity() could not re-create the namespace triggers: "
                "the suite would continue without the R16 invariant in force"
            )
    finally:
        conn.close()
