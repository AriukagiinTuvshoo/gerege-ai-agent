#!/usr/bin/env python3
"""
Rebuild the R16 cross-column login-identity projection without running a migration.

===============================================================================
WHY THIS EXISTS
===============================================================================
The startup guard (`core.schema_manager.assert_security_invariants`) refuses to boot a
database whose cross-column login-identity invariant is not in force. As with the R10
index (finding R10, revision `0005`), the first remedy it names — "run
`alembic upgrade head`" — is **not sufficient on its own**, and for the same reason:

Alembic decides what to run by comparing the version stamped in `alembic_version`
against the script directory. If a database is already stamped at `0006` but the
projection table or its triggers were dropped afterwards (a manual `DROP TABLE`, a
partial restore, a crashed upgrade), `alembic upgrade head` prints success and changes
nothing. The invariant stays missing. That is not a hypothetical: it is the exact shape
of the failure this whole finding is about — a control that appears to be present.

This script closes that gap. It is idempotent and revision-independent.

===============================================================================
WHAT IT WILL AND WILL NOT DO
===============================================================================
WILL:  detect whether the projection is present, correctly shaped, and in agreement
       with `pages`; if not, run the read-only collision preflight and — only when
       there are zero collisions — rebuild the projection from `pages` and re-create
       the triggers; verify the result and exit non-zero if it is still not in force.

WILL NOT: choose a winner between two tenants that share an identifier, merge
          accounts, clear a username, rewrite a page_id, or delete any row. If
          collisions exist it prints them and stops, exactly like the migration gate.

Why it may legitimately need to DROP and rebuild (the "re-derive from `pages`" case):
the projection is a cache of `pages`, and a crash between "create table" and "create
triggers" — or a restore that copied `pages` but not the projection — can leave it
stale. Re-deriving is safe by construction because `pages` is the only source of truth
and the preflight has already proven the two agree set-wise.

===============================================================================
USAGE
===============================================================================
    python scripts/repair_login_identity.py --check   # report only; exit 1 if broken
    python scripts/repair_login_identity.py           # repair if it is safe
    python scripts/repair_login_identity.py --dry-run # print the planned SQL

Exit codes: 0 = invariant is (now) in force; 1 = collisions block repair (or --check
found it broken); 2 = repair ran but the invariant still is not in force.

Resolving a collision is a human decision involving the tenant owners. See
docs/operations/USERNAME_UNIQUENESS_MIGRATION.md.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _connection():
    """A DB-API connection to the configured database (SQLite or PostgreSQL)."""
    import database

    return database.get_connection()


def _dialect(conn) -> str:
    from core import username_uniqueness

    return username_uniqueness._dialect_of(conn)


def cmd(args: argparse.Namespace) -> int:
    from core import login_identity as li

    conn = _connection()
    try:
        dialect = _dialect(conn)

        # There is nothing to repair on a database that has not been migrated: `pages`
        # itself is absent, and every statement below would fail with a driver error
        # that says nothing useful. Point at the actual remedy instead.
        if not li.table_present(conn, "pages"):
            print(
                f"No `pages` table in this database ({dialect}).\n"
                "This tool repairs an EXISTING schema; it does not create one.\n"
                "Run `alembic upgrade head` (or start the application once) first."
            )
            return 2

        table_ok = li.namespace_present(conn)
        shape_ok = table_ok and li.namespace_is_correct(conn)
        trigger_ok = li.trigger_present(conn)

        if shape_ok and trigger_ok:
            print(
                f"OK  {li.NAMESPACE_TABLE} is in force and agrees with `pages` ({dialect})."
            )
            return 0

        print(f"Not in force: cross-column login-identity uniqueness ({dialect})")
        print(f"  projection present : {table_ok}")
        print(f"  projection correct : {shape_ok}")
        print(f"  triggers present   : {trigger_ok}")

        if args.check:
            # Exit 1 means "the invariant is NOT in force" — the signal CI and operators
            # rely on. --check returning 0 on a broken database would be worse than useless.
            print("\n--check: no changes made (invariant NOT in force).")
            return 1

        # Read-only preflight, BEFORE any DDL and before any row is touched. This is the
        # same gate the migration uses, and it is what makes the rebuild safe: if it
        # passes, `pages` already holds at most one owner per identifier.
        collisions = li.find_identifier_collisions(conn)
        if collisions:
            print("\nCannot enforce the invariant: one identifier is claimed by two pages.")
            print(li.collision_report_text(collisions))
            print(
                "\nThis tool will not choose a winner, merge accounts, clear a username,\n"
                "rewrite a page_id, or delete anything. Resolve each collision with the\n"
                "tenant owners, then re-run.\n"
                "Procedure: docs/operations/USERNAME_UNIQUENESS_MIGRATION.md"
            )
            return 1

        create_table = li.create_table_sql(dialect)
        drop_table = li.drop_table_sql(dialect)
        drop_triggers = li.drop_triggers_sql(dialect)
        create_triggers = li.create_triggers_sql(dialect)
        backfill = li.backfill_namespace_sql(dialect)

        if args.dry_run:
            print("\nPlanned SQL (not executed):")
            for stmt in (*drop_triggers, drop_table, create_table, backfill, *create_triggers):
                print(f"  {stmt.strip()}")
            return 0

        # Triggers first: they reference the projection, and leaving them attached to a
        # half-rebuilt table is the state that produces a silent identity gap.
        cur = conn.cursor()
        for stmt in drop_triggers:
            cur.execute(stmt)
        # `pages` is the only source of truth, so a stale projection is discarded rather
        # than trusted. The preflight above already proved no identifier has two owners.
        cur.execute(drop_table)
        conn.commit()

        print(f"\nRebuilding {li.NAMESPACE_TABLE} from `pages`...")
        cur.execute(create_table)
        cur.execute(backfill)
        conn.commit()

        print("Creating triggers...")
        for stmt in create_triggers:
            cur.execute(stmt)
        conn.commit()

        if not li.namespace_is_correct(conn):
            print(
                "\nFAILED: the projection still does not agree with `pages`.\n"
                "  The triggers are not installed, so the database is still UNPROTECTED."
            )
            return 2
        if not li.trigger_present(conn):
            print(
                "\nFAILED: the projection is correct but the triggers are missing, so it\n"
                "  will drift on the next write. The database is still UNPROTECTED."
            )
            return 2
        print(f"\nOK  cross-column login-identity uniqueness is now in force ({dialect}).")
        return 0
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--check", action="store_true", help="report only; no writes")
    parser.add_argument("--dry-run", action="store_true", help="print the SQL; no writes")
    args = parser.parse_args(argv)

    from core import login_identity as li

    try:
        return cmd(args)
    except li.IdentifierCollisionBlocked as exc:
        # Raised by the verification helper if the world changed between the preflight and
        # the rebuild (for example a write landed from another process). Report it as a
        # collision, not as a crash: the operator action is identical.
        print(f"\nCollision detected during repair:\n{exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
