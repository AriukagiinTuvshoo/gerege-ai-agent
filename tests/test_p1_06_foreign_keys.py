"""
Stage D — P1-06: the schema had **zero foreign keys**.

Before revision `0003_foreign_keys`, every tenant relation was enforced only by
application code, and `database.delete_page()` walked a hand-maintained list of twelve
table names. That list had already drifted from the schema: `comment_automations`,
`tracked_links`, `audit_logs` and `task_jobs` rows were never deleted with their tenant,
so they were stranded permanently.

These tests assert the database itself now enforces the relations:

1. `models.py` and the migration agree on every foreign key (this is what the drift gate
   checks, isolated here so a failure names the constraint).
2. A child row for a non-existent tenant is rejected.
3. Deleting a tenant cascades to its data.
4. Deleting a tenant does **not** delete audit history — `audit_logs.page_id` is
   `ON DELETE SET NULL`, so the trail outlives the tenant it describes.
5. `delete_page()` therefore needs no table list and leaves no orphans.
"""
import os
import sqlite3
import sys

import pytest
import sqlalchemy as sa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402
from core.models import Base  # noqa: E402

ALEMBIC_INI = "alembic.ini"


def _head_db(tmp_path):
    """Build a database at head via the migrations, returning its path."""
    from alembic import command
    from alembic.config import Config

    for var in ("DATABASE_URL", "DB_PATH"):
        os.environ.pop(var, None)
    db_path = tmp_path / "fk.db"
    cfg = Config(ALEMBIC_INI)
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    command.upgrade(cfg, "head")
    return db_path


def _connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def test_models_declare_the_expected_foreign_keys():
    """Every tenant table references pages, plus the two optional cross-references."""
    fks = {
        (t.name, c.name, fk.target_fullname, fk.ondelete)
        for t in Base.metadata.sorted_tables
        for c in t.columns
        for fk in c.foreign_keys
    }
    tenant_tables = {
        t.name for t in Base.metadata.sorted_tables
        if "page_id" in t.columns and t.name != "pages"
    }
    pages_fks = {f for f in fks if f[2] == "pages.page_id"}
    assert {f[0] for f in pages_fks} == tenant_tables, (
        "every table with a page_id column must reference pages: "
        f"missing={tenant_tables - {f[0] for f in pages_fks}}"
    )
    # The audit trail must survive tenant deletion.
    assert ("audit_logs", "page_id", "pages.page_id", "SET NULL") in pages_fks
    assert all(
        od == "CASCADE" for (t, c, _tf, od) in pages_fks if t != "audit_logs"
    ), "ordinary tenant data should cascade"
    # Optional cross-references clear rather than delete the record.
    assert ("cargo_packages", "invoice_id", "invoices.invoice_id", "SET NULL") in fks
    assert ("tracked_links", "automation_id", "comment_automations.id", "SET NULL") in fks


def test_migration_creates_one_constraint_per_model_foreign_key(tmp_path):
    """Revision 0003 must materialise exactly the FKs that models.py declares."""
    db_path = _head_db(tmp_path)
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        inspector = sa.inspect(engine)
        created = set()
        for table in inspector.get_table_names():
            for fk in inspector.get_foreign_keys(table):
                created.add((table, tuple(fk["constrained_columns"])))
        expected = {
            (t.name, (c.name,))
            for t in Base.metadata.sorted_tables
            for c in t.columns
            for _ in c.foreign_keys
        }
        assert expected <= created, f"migration is missing: {expected - created}"
    finally:
        engine.dispose()


def test_child_row_for_unknown_tenant_is_rejected(tmp_path):
    db_path = _head_db(tmp_path)
    conn = _connect(db_path)
    try:
        conn.execute("INSERT INTO pages (page_id, name) VALUES ('real','Real')")
        conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO messages (page_id, sender_id, channel, sender_type, content)"
                " VALUES ('ghost','s','tg','user','hi')"
            )
    finally:
        conn.close()


def test_deleting_a_tenant_cascades_to_its_data(tmp_path):
    db_path = _head_db(tmp_path)
    conn = _connect(db_path)
    try:
        conn.execute("INSERT INTO pages (page_id, name) VALUES ('t1','T1')")
        conn.execute(
            "INSERT INTO messages (page_id, sender_id, channel, sender_type, content)"
            " VALUES ('t1','s','tg','user','hi')"
        )
        conn.execute(
            "INSERT INTO invoices (invoice_id, page_id, amount, status)"
            " VALUES ('INV-1','t1',100,'PENDING')"
        )
        conn.execute(
            "INSERT INTO comment_automations (page_id, name, dm_message_text)"
            " VALUES ('t1','a','dm')"
        )
        conn.commit()
        conn.execute("DELETE FROM pages WHERE page_id='t1'")
        conn.commit()
        for table in ("messages", "invoices", "comment_automations"):
            left = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            assert left == 0, f"{table} was not cascaded (this table was missed before P1-06)"
    finally:
        conn.close()


def test_deleting_a_tenant_preserves_audit_history(tmp_path):
    """The audit trail must outlive the tenant — otherwise anyone can erase it."""
    db_path = _head_db(tmp_path)
    conn = _connect(db_path)
    try:
        conn.execute("INSERT INTO pages (page_id, name) VALUES ('t1','T1')")
        conn.execute(
            "INSERT INTO audit_logs (page_id, actor_role, action) VALUES ('t1','admin','x')"
        )
        conn.commit()
        conn.execute("DELETE FROM pages WHERE page_id='t1'")
        conn.commit()
        rows = conn.execute("SELECT page_id FROM audit_logs").fetchall()
        assert rows == [(None,)], f"audit rows should survive with page_id NULL, got {rows}"
    finally:
        conn.close()


def test_delete_page_leaves_no_orphans(tmp_path, monkeypatch):
    """`delete_page()` no longer needs a table list — the cascade does the work."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db_path = tmp_path / "app.db"
    monkeypatch.setenv("DB_PATH", str(db_path))
    monkeypatch.setattr(database, "DB_PATH", str(db_path))
    database.init_db()

    database.save_page(page_id="tp", name="Tenant P", category="general")
    database.save_registration(page_id="tp", name="A", phone="111", service="x")
    conn = database.get_connection()
    try:
        conn.execute(
            "INSERT INTO audit_logs (page_id, actor_role, action) VALUES ('tp','admin','x')"
        )
        conn.commit()
    finally:
        conn.close()

    assert database.delete_page("tp") is True

    conn = database.get_connection()
    try:
        assert conn.execute("SELECT COUNT(*) FROM pages WHERE page_id='tp'").fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM registrations WHERE page_id='tp'"
        ).fetchone()[0] == 0
        # No orphaned audit row: its page_id was nulled by the FK.
        assert conn.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE page_id='tp'"
        ).fetchone()[0] == 0
    finally:
        conn.close()
    assert database.delete_page(database.DEFAULT_PAGE_ID) is False
