#!/usr/bin/env python3
"""
Safe, Idempotent SQLite-to-PostgreSQL Data Migration Tool (Phase 2.4)

Usage:
    python scripts/migrate_sqlite_to_postgres.py --dry-run
    python scripts/migrate_sqlite_to_postgres.py --sqlite-path registrations.db --postgres-url postgresql://user:pass@localhost:5432/gerege_db
"""
import os
import sys
import json
import sqlite3
import tempfile
import argparse
from datetime import datetime
from typing import Dict, Any, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MIGRATION_TABLES: List[Dict[str, Any]] = [
    {"table": "pages", "conflict_cols": ["page_id"]},
    {"table": "registrations", "conflict_cols": ["id"], "has_serial_id": True},
    {"table": "messages", "conflict_cols": ["id"], "has_serial_id": True},
    {"table": "session_states", "conflict_cols": ["sender_id"]},
    {"table": "sessions", "conflict_cols": ["session_token"]},
    {"table": "user_memories", "conflict_cols": ["page_id", "user_id"], "has_serial_id": True},
    {"table": "invoices", "conflict_cols": ["invoice_id"], "has_serial_id": True},
    {"table": "cargo_packages", "conflict_cols": ["page_id", "tracking_code"], "has_serial_id": True},
    {"table": "automated_rules", "conflict_cols": ["page_id", "rule_type"], "has_serial_id": True},
    {"table": "marketing_campaigns", "conflict_cols": ["id"], "has_serial_id": True},
    {"table": "sent_followups", "conflict_cols": ["page_id", "rule_type", "sender_id"], "has_serial_id": True},
    {"table": "appointments", "conflict_cols": ["id"], "has_serial_id": True},
    {"table": "notification_locks", "conflict_cols": ["idempotency_key"]},
    {"table": "task_jobs", "conflict_cols": ["idempotency_key"], "has_serial_id": True},
    {"table": "audit_logs", "conflict_cols": ["id"], "has_serial_id": True},
]


def create_sqlite_snapshot(sqlite_path: Optional[str] = None) -> str:
    """Create a consistent point-in-time snapshot of the SQLite database using sqlite3.backup."""
    import database
    if not sqlite_path:
        sqlite_path = database.DB_PATH
    if not os.path.exists(sqlite_path):
        database.init_db()
    if not os.path.exists(sqlite_path):
        raise FileNotFoundError(f"SQLite database not found: {sqlite_path}")
    fd, snap_path = tempfile.mkstemp(prefix="gerege_sqlite_snap_", suffix=".db")
    os.close(fd)
    src = sqlite3.connect(sqlite_path)
    dst = sqlite3.connect(snap_path)
    with dst:
        src.backup(dst)
    dst.close()
    src.close()
    return snap_path


def inspect_sqlite_snapshot(snap_path: str) -> Dict[str, Any]:
    """Read row counts, column names, and financial totals from SQLite snapshot."""
    conn = sqlite3.connect(snap_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    existing_tables = {
        r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }

    table_stats: Dict[str, Any] = {}
    for item in MIGRATION_TABLES:
        tname = item["table"]
        if tname not in existing_tables:
            table_stats[tname] = {"exists": False, "row_count": 0, "columns": []}
            continue
        cols = [r[1] for r in cur.execute(f"PRAGMA table_info({tname})").fetchall()]
        cnt = cur.execute(f"SELECT COUNT(*) FROM {tname}").fetchone()[0]
        table_stats[tname] = {"exists": True, "row_count": int(cnt), "columns": cols}

    financials = {
        "invoices_total_amount": 0,
        "invoices_paid_amount": 0,
        "cargo_total_price": 0,
    }
    if "invoices" in existing_tables:
        financials["invoices_total_amount"] = int(
            cur.execute("SELECT COALESCE(SUM(amount), 0) FROM invoices").fetchone()[0] or 0
        )
        financials["invoices_paid_amount"] = int(
            cur.execute("SELECT COALESCE(SUM(amount), 0) FROM invoices WHERE status = 'PAID'").fetchone()[0] or 0
        )
    if "cargo_packages" in existing_tables:
        financials["cargo_total_price"] = int(
            cur.execute("SELECT COALESCE(SUM(price_amount), 0) FROM cargo_packages").fetchone()[0] or 0
        )

    conn.close()
    return {"tables": table_stats, "financials": financials}


def run_migration(
    sqlite_path: Optional[str] = None,
    postgres_url: Optional[str] = None,
    dry_run: bool = False,
    report_path: Optional[str] = None,
) -> Dict[str, Any]:
    if not sqlite_path:
        import database
        sqlite_path = database.DB_PATH
    snap_path = create_sqlite_snapshot(sqlite_path)
    try:
        source_summary = inspect_sqlite_snapshot(snap_path)
        report: Dict[str, Any] = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sqlite_source": os.path.abspath(sqlite_path),
            "dry_run": dry_run,
            "source_summary": source_summary,
            "migrated_tables": {},
            "verification": {},
            "status": "DRY_RUN_OK" if dry_run else "PENDING",
        }

        if dry_run:
            if report_path:
                with open(report_path, "w", encoding="utf-8") as f:
                    json.dump(report, f, ensure_ascii=False, indent=2)
            return report

        if not postgres_url:
            raise ValueError("PostgreSQL URL (--postgres-url or DATABASE_URL) is required when not running --dry-run")

        from sqlalchemy import create_engine, text
        from core.models import Base

        pg_engine = create_engine(postgres_url, pool_pre_ping=True, future=True)
        Base.metadata.create_all(bind=pg_engine)

        src_conn = sqlite3.connect(snap_path)
        src_conn.row_factory = sqlite3.Row
        src_cur = src_conn.cursor()

        with pg_engine.begin() as pg_conn:
            for item in MIGRATION_TABLES:
                tname = item["table"]
                tinfo = source_summary["tables"].get(tname, {})
                if not tinfo.get("exists") or tinfo.get("row_count", 0) == 0:
                    report["migrated_tables"][tname] = {"source_rows": 0, "inserted_or_verified": 0}
                    continue

                rows = src_cur.execute(f"SELECT * FROM {tname}").fetchall()
                cols = tinfo["columns"]
                col_list = ", ".join(cols)
                bind_list = ", ".join(f":{c}" for c in cols)
                conflict_cols = ", ".join(item["conflict_cols"])

                sql = text(
                    f"INSERT INTO {tname} ({col_list}) VALUES ({bind_list}) "
                    f"ON CONFLICT ({conflict_cols}) DO NOTHING"
                )
                payloads = [dict(r) for r in rows]
                pg_conn.execute(sql, payloads)

                if item.get("has_serial_id") and "id" in cols:
                    pg_conn.execute(
                        text(
                            f"SELECT setval(pg_get_serial_sequence('{tname}', 'id'), "
                            f"COALESCE((SELECT MAX(id) FROM {tname}), 1), true)"
                        )
                    )

                pg_count = pg_conn.execute(text(f"SELECT COUNT(*) FROM {tname}")).scalar() or 0
                report["migrated_tables"][tname] = {
                    "source_rows": len(rows),
                    "target_rows": int(pg_count),
                    "match": int(pg_count) >= len(rows),
                }

            # Verify financial totals on target PostgreSQL
            pg_inv_total = int(
                pg_conn.execute(text("SELECT COALESCE(SUM(amount), 0) FROM invoices")).scalar() or 0
            )
            pg_inv_paid = int(
                pg_conn.execute(text("SELECT COALESCE(SUM(amount), 0) FROM invoices WHERE status = 'PAID'")).scalar() or 0
            )
            pg_cargo_total = int(
                pg_conn.execute(text("SELECT COALESCE(SUM(price_amount), 0) FROM cargo_packages")).scalar() or 0
            )

        src_conn.close()

        src_fin = source_summary["financials"]
        fin_ok = (
            pg_inv_total >= src_fin["invoices_total_amount"]
            and pg_inv_paid >= src_fin["invoices_paid_amount"]
            and pg_cargo_total >= src_fin["cargo_total_price"]
        )
        rows_ok = all(v.get("match", True) for v in report["migrated_tables"].values())

        report["verification"] = {
            "rows_verified": rows_ok,
            "financials_verified": fin_ok,
            "target_financials": {
                "invoices_total_amount": pg_inv_total,
                "invoices_paid_amount": pg_inv_paid,
                "cargo_total_price": pg_cargo_total,
            },
        }
        report["status"] = "SUCCESS" if (rows_ok and fin_ok) else "VERIFICATION_MISMATCH"

        if report_path:
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
        return report
    finally:
        if os.path.exists(snap_path):
            try:
                os.remove(snap_path)
            except Exception:
                pass


def main() -> None:
    import database
    parser = argparse.ArgumentParser(description="Safe SQLite-to-PostgreSQL Migration Tool")
    parser.add_argument("--sqlite-path", default=os.getenv("DB_PATH", database.DB_PATH))
    parser.add_argument("--postgres-url", default=os.getenv("POSTGRES_URL") or os.getenv("DATABASE_URL"))
    parser.add_argument("--dry-run", action="store_true", help="Inspect SQLite snapshot and verify schema without writing to PostgreSQL")
    parser.add_argument("--report", default="", help="Optional path to write JSON migration report")
    args = parser.parse_args()

    res = run_migration(
        sqlite_path=args.sqlite_path,
        postgres_url=args.postgres_url,
        dry_run=args.dry_run,
        report_path=args.report or None,
    )
    print(json.dumps(res, ensure_ascii=False, indent=2))
    if res["status"] not in ("DRY_RUN_OK", "SUCCESS"):
        sys.exit(1)


if __name__ == "__main__":
    main()
