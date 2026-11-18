#!/usr/bin/env python3
"""
Re-install the `audit_logs` append-only guard without running a migration.

===============================================================================
WHY THIS EXISTS
===============================================================================
The startup guard (`core.schema_manager.assert_security_invariants`) refuses to boot a
database whose audit trail is not append-only. Its first suggested remedy — "run
`alembic upgrade head`" — is **not sufficient on its own**, for the same reason the
R10 and R16 repair scripts exist:

Alembic decides what to run by comparing the revision stamped in `alembic_version`
against the script directory. If a database is already stamped at
`0007_audit_append_only` but the triggers were dropped afterwards — a manual
`DROP TRIGGER`, a partial restore, a crashed upgrade, or (the case this whole finding
is about) a schema-owner who wanted a clean table — then `alembic upgrade head` prints
success and changes nothing. The invariant stays missing while the version table says
the work is done. That is precisely the failure shape of a control that *appears* to
be present.

This script closes that gap. It is idempotent and revision-independent.

===============================================================================
WHAT IT WILL AND WILL NOT DO
===============================================================================
WILL:  report exactly which guard objects are missing or wrongly defined; re-install
       the guard function and triggers when asked; verify the result by shape and
       exit non-zero if it is still not in force.

WILL NOT: touch a single row of `audit_logs`; drop or recreate the table; alter any
          column; run `downgrade`; or change the schema version stamp. It creates
          only the objects revision `0007` creates.

===============================================================================
USAGE
===============================================================================
    python scripts/repair_audit_integrity.py --check     # report only; exit 1 if broken
    python scripts/repair_audit_integrity.py --dry-run   # print the planned SQL
    python scripts/repair_audit_integrity.py             # install if missing

Exit codes: 0 = guard is (now) in force, 1 = still not in force, 2 = usage error.

NOTE ON WHAT THIS CANNOT DO
    A database owner or superuser can re-drop these triggers at any time, and can
    `DISABLE TRIGGER ALL` or `SET session_replication_role = replica` to bypass them.
    This script restores the guard; it cannot make the guard unremovable. See the
    Phase 13 report's follow-up proposal on non-owner runtime roles.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _dialect(conn) -> str:
    from core.username_uniqueness import _dialect_of

    return _dialect_of(conn)


def report(conn) -> int:
    """Print the guard's state. Read-only."""
    from core import audit_integrity

    described = audit_integrity.describe_triggers(conn)
    dialect = described["dialect"]
    print(f"engine: {dialect}")
    print(f"table : {audit_integrity.AUDIT_TABLE}")

    required = described["required"]
    if not required:
        print(f"  ! no guard is defined for dialect {dialect!r}")
        return 1

    ok = True
    for name in required:
        entry = described["details"].get(name)
        if entry is None:
            present = name in described["present"]
            print(f"  - {name}: MISSING")
            ok = False
        else:
            wiring = (
                f"{entry['timing']} {entry['event']} FOR EACH {entry['level']} "
                f"-> {entry['function']}()"
            )
            expected = {
                audit_integrity.PG_TRIGGER_UPDATE: ("BEFORE", "UPDATE", "ROW"),
                audit_integrity.PG_TRIGGER_DELETE: ("BEFORE", "DELETE", "ROW"),
                audit_integrity.PG_TRIGGER_TRUNCATE: ("BEFORE", "TRUNCATE", "STATEMENT"),
            }.get(name)
            if dialect == "postgresql" and expected and (
                entry["timing"], entry["event"], entry["level"]
            ) != expected:
                print(f"  - {name}: WRONGLY DEFINED ({wiring})")
                ok = False
            else:
                print(f"  - {name}: ok ({wiring})" if dialect == "postgresql" else f"  - {name}: ok")

    wrong = audit_integrity.wrongly_defined_triggers(conn)
    if wrong:
        print(f"\nWrongly defined: {wrong}")
    print("\nGUARD IS IN FORCE" if ok else "\nGUARD IS NOT IN FORCE")
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--check", action="store_true", help="report only; never modify")
    parser.add_argument("--dry-run", action="store_true", help="print the SQL that would run")
    args = parser.parse_args()

    import database
    from core import audit_integrity

    conn = database.get_connection()
    try:
        dialect = _dialect(conn)

        if args.check:
            return report(conn)

        if audit_integrity.guard_is_correct(conn):
            print("The audit append-only guard is already in force; nothing to do.")
            return 0

        statements = audit_integrity.create_sql(dialect)

        if args.dry_run:
            print(f"-- would install the guard for {dialect} on {audit_integrity.AUDIT_TABLE}")
            for statement in statements:
                print(statement.strip().rstrip(";") + ";")
            return 0

        print(f"Installing the audit append-only guard on {dialect} ...")
        for statement in statements:
            audit_integrity._exec(conn, statement)

        if not audit_integrity.guard_is_correct(conn):
            print(
                "ERROR: the guard is still not in force after installation. "
                "Inspect with --check and see the Phase 13 report.",
                file=sys.stderr,
            )
            return 1

        print("Installed. Audit rows were not touched.")
        print(
            "NOTE: this guard is tamper RESISTANCE, not tamper evidence. A database "
            "owner or superuser can DISABLE or DROP these triggers."
        )
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
