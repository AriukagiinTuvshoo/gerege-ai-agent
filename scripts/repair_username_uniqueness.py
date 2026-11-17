#!/usr/bin/env python3
"""
Re-create the R10 username-uniqueness index without running a migration.

===============================================================================
WHY THIS EXISTS
===============================================================================
The startup guard (`core.schema_manager.assert_security_invariants`) refuses to boot
a database whose unique username index is missing or is an impostor look-alike. Its
first remedy — "run the migration to revision 0005" — is **not sufficient on its own**:

Alembic decides what to run by comparing the version stamped in `alembic_version`
against the script directory. If a database is already stamped at `0005` but the index
was dropped afterwards (a manual `DROP INDEX`, a partial restore, a crashed upgrade,
or an `_sync_indexes()` impostor), `alembic upgrade head` is a **no-op**. It prints
success and the index stays missing. This was observed directly during Phase 8
migration validation, so the previous error text could send an operator round a loop
that never terminates.

This script closes that gap. It is idempotent, revision-independent, and it never
touches credential data.

===============================================================================
WHAT IT WILL AND WILL NOT DO
===============================================================================
WILL:  detect whether the correct index is present; if not, run the read-only
       duplicate preflight and — only when there are zero collisions — remove an
       impostor index of the same name and create the correct one; verify the
       resulting shape and exit non-zero if it is not in force.

WILL NOT: choose a winner between two tenants that share a username, merge accounts,
          clear or rewrite any username or password, or delete any row. If collisions
          exist it prints them and stops, exactly like the migration gate.

Resolving a collision is a human decision involving the tenant owners. See
docs/operations/USERNAME_UNIQUENESS_MIGRATION.md.

===============================================================================
USAGE
===============================================================================
    python scripts/repair_username_uniqueness.py --check   # report only; exit 1 if broken
    python scripts/repair_username_uniqueness.py           # repair if it is safe
    python scripts/repair_username_uniqueness.py --dry-run # print the planned SQL

Exit codes: 0 = invariant is (now) in force; 1 = collisions block repair; 2 = repair
attempted but the invariant did not come into force; 3 = unexpected error.
"""
from __future__ import annotations

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
    from core import username_uniqueness as uniq

    conn = _connection()
    try:
        dialect = _dialect(conn)

        if uniq.index_is_correct(conn):
            print(f"OK  {uniq.USERNAME_UNIQUE_INDEX} is in force ({dialect}).")
            return 0

        found = uniq.describe_index(conn)
        print(f"Missing or incorrect: {uniq.USERNAME_UNIQUE_INDEX} ({dialect})")
        print(f"  found: {found!r}")

        if args.check:
            # Exit 1 means "the invariant is NOT in force" — the same failure signal CI and
            # operators rely on. A --check that returns 0 on a broken database would be worse
            # than useless in a pre-deployment gate.
            print("\n--check: no changes made (invariant NOT in force).")
            return 1

        # Read-only preflight. Runs BEFORE any DDL and never modifies a row.
        duplicates = uniq.find_duplicate_usernames(conn)
        if duplicates:
            print("\nCannot install the index: duplicate normalized usernames exist.")
            print(uniq.duplicate_report_text(duplicates))
            print(
                "\nThis tool will not choose a winner, merge accounts, or clear a username.\n"
                "Resolve each collision with the tenant owners, then re-run.\n"
                "Procedure: docs/operations/USERNAME_UNIQUENESS_MIGRATION.md"
            )
            return 1

        sql_drop = uniq.drop_index_sql(dialect) if found else None
        sql_create = uniq.create_index_sql(dialect)

        if args.dry_run:
            print("\nPlanned SQL (not executed):")
            if sql_drop:
                print(f"  {sql_drop}")
            print(f"  {sql_create}")
            return 0

        if sql_drop:
            # A wrongly-shaped index of this name enforces nothing, so dropping it loses
            # no guarantee. `CREATE INDEX IF NOT EXISTS` would silently keep the impostor,
            # which is precisely the bug this replaces.
            print(f"\nRemoving impostor index:\n  {sql_drop}")
            conn.cursor().execute(sql_drop)
            conn.commit()

        print(f"Creating:\n  {sql_create}")
        conn.cursor().execute(sql_create)
        conn.commit()

        if not uniq.index_is_correct(conn):
            print(
                "\nFAILED: the index is still not in force.\n"
                f"  found: {uniq.describe_index(conn)!r}"
            )
            return 2
        print(f"\nOK  {uniq.USERNAME_UNIQUE_INDEX} is now in force ({dialect}).")
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
    try:
        return cmd(args)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - operator tool must not traceback silently
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
