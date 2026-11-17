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
