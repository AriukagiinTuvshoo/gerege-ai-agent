#!/usr/bin/env python3
"""Operator entry point for schema migrations.

Usage::

    python scripts/migrate.py --check     # what would change? (no writes)
    python scripts/migrate.py --dry-run   # print the SQL, change nothing
    python scripts/migrate.py             # apply, with a backup first
    python scripts/migrate.py --no-backup # apply without a backup (not recommended)
    python scripts/migrate.py --verify    # assert the schema matches the models

Why a wrapper instead of calling `alembic` directly: applying `0002` rewrites column
types across 17 tables. On PostgreSQL the operation is transactional, but on SQLite
each table is rebuilt, so a crash mid-way would leave some tables converted. The
wrapper therefore takes a backup before touching anything and verifies afterwards,
which is the procedure required for risky operations in this project.

Exit codes: 0 success, 1 failure, 2 "not at head after migrating".
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _print(title: str, payload) -> None:
    print(f"\n{title}")
    if isinstance(payload, (dict, list)):
        print(json.dumps(payload, indent=2, default=str))
    else:
        print(payload)


def cmd_check() -> int:
    from core.schema_manager import preflight

    report = preflight()
    _print("Preflight", report)
    return 0


def cmd_dry_run() -> int:
    """Render the pending migration as SQL without executing it."""
    from alembic import command

    from core.schema_manager import _alembic_config, current_revision, head_revision

    cur = current_revision()
    if cur == head_revision():
        print("Already at head; nothing to do.")
        return 0
    print(f"-- SQL for {cur or '<empty>'} -> {head_revision()}")
    command.upgrade(_alembic_config(), "head", sql=True)
    return 0


def cmd_upgrade(backup: bool) -> int:
    from core.schema_manager import current_revision, ensure_schema, head_revision

    before = current_revision()

    if backup:
        try:
            from core.backup_service import create_backup

            result = create_backup(label="pre_migrate")
            if not result.get("success"):
                print(f"Backup failed, refusing to migrate: {result}", file=sys.stderr)
                return 1
            print(f"Backup created: {result.get('filename')}")
        except Exception as exc:
            print(f"Backup unavailable ({exc}); refusing to migrate.", file=sys.stderr)
            print("Re-run with --no-backup to override (make your own backup first).", file=sys.stderr)
            return 1

    report = ensure_schema()
    _print("Migration result", report)

    if current_revision() != head_revision():
        print("Database is NOT at head after migrating.", file=sys.stderr)
        return 2
    print(f"OK: at head ({head_revision()}), was {before or '<empty>'}")
    return 0


def cmd_verify() -> int:
    from core.schema_manager import compare_with_models, current_revision, head_revision

    diffs = compare_with_models()
    flat = [x for d in diffs for x in (d if isinstance(d, list) else [d])]
    _print(
        "Verification",
        {
            "current_revision": current_revision(),
            "head_revision": head_revision(),
            "diff_count": len(flat),
            "diffs": [str(d)[:200] for d in flat[:20]],
        },
    )
    return 0 if not flat else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="report pending revisions")
    group.add_argument("--dry-run", action="store_true", help="print SQL, change nothing")
    group.add_argument("--verify", action="store_true", help="assert schema matches models")
    parser.add_argument("--no-backup", action="store_true", help="skip the pre-migration backup")
    args = parser.parse_args(argv)

    if args.check:
        return cmd_check()
    if args.dry_run:
        return cmd_dry_run()
    if args.verify:
        return cmd_verify()
    return cmd_upgrade(backup=not args.no_backup)


if __name__ == "__main__":
    raise SystemExit(main())
