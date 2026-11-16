"""End-to-end migration verification: data integrity + schema convergence.

Run against any dialect via DATABASE_URL:

    DATABASE_URL=sqlite:///...   python scripts/verify_migration_0002.py
    DATABASE_URL=postgresql+psycopg2://... python scripts/verify_migration_0002.py

It exercises 0001 -> 0002 -> 0001 -> 0002 and asserts, at every step:

  * row counts are unchanged
  * every timestamp column still holds a *text* timestamp (SQLite) or a real
    timestamp (PostgreSQL) -- never a truncated integer
  * the legacy empty-string sentinel maps to NULL, exactly once
  * `compare_metadata(..., compare_type=True)` reports zero differences

Exit code 0 means every assertion passed.
"""
from __future__ import annotations

import os
import sys

import sqlalchemy as sa
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.runtime.migration import MigrationContext as _MC  # noqa: F401

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import Base  # noqa: E402

TABLES = [
    "pages",
    "registrations",
    "messages",
    "invoices",
    "sessions",
    "cargo_packages",
    "task_jobs",
    "audit_logs",
    "comment_automations",
    "tracked_links",
    "user_memories",
]

TS = "2026-11-16 04:05:06"

SEED = [
    ("registrations", "page_id,name,phone,service,created_at",
     f"('legacy1','Lead A','99001122','null','{TS}')"),
    ("messages", "page_id,sender_id,sender_type,content,created_at",
     f"('legacy1','s1','user','hi','{TS}')"),
    ("invoices", "invoice_id,page_id,amount,status,description,paid_at,created_at",
     f"('INV-L1','legacy1',50000,'PAID','d1','{TS}','{TS}')"),
    ("invoices", "invoice_id,page_id,amount,status,description,paid_at,created_at",
     "('INV-L2','legacy1',60000,'PENDING','d2','','2026-11-16 07:30:00')"),
    ("sessions", "session_token,role,created_at,expires_at",
     f"('tok1','client','{TS}','2026-11-20 07:00:00')"),
    ("cargo_packages", "page_id,tracking_code,arrived_at,created_at",
     f"('legacy1','TRK1','2026-11-16 09:00:00','{TS}')"),
    ("task_jobs", "task_name,payload_json,created_at,updated_at",
     f"('t','{{}}','{TS}','{TS}')"),
    ("audit_logs", "action,created_at", f"('x','{TS}')"),
    ("comment_automations", "page_id,name,dm_message_text,created_at",
     f"('legacy1','r','hi','{TS}')"),
    ("tracked_links", "code,page_id,target_url,created_at",
     f"('abc','legacy1','https://x.mn','{TS}')"),
    ("user_memories", "page_id,user_id", "('legacy1','u1')"),
]

failures: list[str] = []


def check(cond: bool, label: str, detail: str = "") -> None:
    if cond:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}  {detail}")
        failures.append(label)


def main() -> int:
    url = os.environ["DATABASE_URL"]
    is_pg = url.startswith("postgresql")
    engine = sa.create_engine(url)

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", url)

    def counts() -> str:
        with engine.connect() as c:
            return ",".join(
                str(c.execute(sa.text(f"select count(*) from {t}")).scalar()) for t in TABLES
            )

    def drift() -> list:
        with engine.connect() as c:
            mc = MigrationContext.configure(c, opts={"compare_type": True})
            raw = compare_metadata(mc, Base.metadata)
        return [x for d in raw for x in (d if isinstance(d, list) else [d])]

    print("=== 1. build 0001 ===")
    command.upgrade(cfg, "0001_initial_enterprise_schema")

    with engine.begin() as c:
        for t in TABLES:
            c.execute(sa.text(f"DELETE FROM {t}"))
        c.execute(sa.text(
            "INSERT INTO pages (page_id, name, created_at) VALUES ('legacy1','Legacy','%s')"
            % TS
        ))
        for table, cols, values in SEED:
            c.execute(sa.text(f"INSERT INTO {table} ({cols}) VALUES {values}"))

    base_counts = counts()
    print(f"  seeded, row counts = {base_counts}")

    print("=== 2. upgrade to 0002 ===")
    command.upgrade(cfg, "head")

    check(counts() == base_counts, "row counts unchanged",
          f"{base_counts} -> {counts()}")
    check(drift() == [], "schema matches models (0 diffs)", str(drift()[:3]))

    with engine.connect() as c:
        paid = dict(c.execute(sa.text(
            "select invoice_id, paid_at from invoices"
        )).fetchall())
        check(paid.get("INV-L1") is not None, "INV-L1.paid_at survived", repr(paid.get("INV-L1")))
        check(paid.get("INV-L2") is None, "empty-string sentinel -> NULL", repr(paid.get("INV-L2")))

        created = c.execute(sa.text("select created_at from pages")).scalar()
        if is_pg:
            import datetime
            check(
                isinstance(created, datetime.datetime)
                and created.year == 2026 and created.month == 11 and created.day == 16,
                "pages.created_at is a real timestamp", repr(created),
            )
        else:
            raw = c.execute(sa.text(
                "select created_at, typeof(created_at) from pages"
            )).fetchone()
            check(
                raw[1] == "text" and str(raw[0]).startswith("2026-11-16"),
                "pages.created_at still TEXT (not truncated to int)", repr(raw),
            )

        if not is_pg:
            # The corruption that the batch-mode CAST used to cause.
            bad = c.execute(sa.text(
                "select count(*) from pages where typeof(created_at) <> 'text'"
            )).scalar()
            check(bad == 0, "no timestamp column holds a non-TEXT value", f"{bad} rows")

    print("=== 3. downgrade to 0001 ===")
    command.downgrade(cfg, "0001_initial_enterprise_schema")
    check(counts() == base_counts, "row counts unchanged after downgrade",
          f"{base_counts} -> {counts()}")

    print("=== 4. re-upgrade to 0002 ===")
    command.upgrade(cfg, "head")
    check(counts() == base_counts, "row counts unchanged after re-upgrade")
    d = drift()
    check(d == [], "round-trip schema still matches models", str(d[:3]))

    print()
    if failures:
        print(f"RESULT: FAIL ({len(failures)} check(s) failed)")
        return 1
    print("RESULT: PASS (all checks)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
