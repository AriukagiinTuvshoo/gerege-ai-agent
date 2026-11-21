"""0003 — add foreign-key constraints (P1-06)

Revision ID: 0003_foreign_keys
Revises: 0002_schema_authority

===============================================================================
WHY THIS MIGRATION EXISTS  (audit finding P1-06)
===============================================================================
Neither `0001` nor the legacy runtime DDL declared a **single** foreign key. Verified
on both live databases:

    SELECT count(*) FROM information_schema.table_constraints
     WHERE constraint_type = 'FOREIGN KEY'      ->  0

Every tenant relation was enforced only by application code. The consequence is not
theoretical: `database.delete_page()` deletes from a hand-maintained list of twelve
tables, and that list had already drifted from the schema. Deleting a tenant left
`comment_automations`, `tracked_links`, `audit_logs` and `task_jobs` rows behind
permanently — rows that no longer belong to any page, are never returned by any
tenant-scoped query, and cannot be cleaned up because the page they referenced is gone.

After this migration the database itself refuses to create such rows.

===============================================================================
DELETE POLICY  (deliberate, not incidental)
===============================================================================
* ``ON DELETE CASCADE`` — ordinary tenant data (messages, invoices, jobs, automations,
  …). Deleting a tenant should remove its data; this is what `delete_page()` was trying
  to do.
* ``ON DELETE SET NULL`` on ``audit_logs.page_id`` — the audit trail must outlive the
  tenant it describes. Cascading it would let anyone erase their own audit history by
  deleting a page. The column is nullable precisely so this is expressible.
* ``ON DELETE SET NULL`` on ``cargo_packages.invoice_id`` and
  ``tracked_links.automation_id`` — both are optional links. Deleting the invoice or
  automation must not delete the cargo record or the link (its click history is
  revenue data), so the reference is cleared instead.

===============================================================================
SAFETY
===============================================================================
A foreign key cannot be added while orphan rows exist. This migration therefore
**checks first** and aborts with a precise, actionable message rather than failing with
a cryptic server error:

    table 'messages' has 3 row(s) whose page_id has no matching pages.page_id

On the tested databases there are zero orphans (checked across all 13 child tables), so
the constraints apply cleanly. If an operator's database does have orphans, the fix is
to delete or re-parent those rows explicitly — silently discarding them inside a
migration would be data loss.

SQLite cannot `ADD CONSTRAINT`. Each affected table is rebuilt with
`batch_alter_table(recreate="always")`, which copies rows through the
`sqlite_compat` datetime shim (without it, batch mode truncates timestamps — see
`migrations/sqlite_compat.py`).

===============================================================================
ROLLBACK
===============================================================================
`downgrade()` drops exactly the constraints this revision created, by name, so a
downgraded database is identical to `0002`. Constraint names are given explicitly
(Alembic's default `fk_%(table)s_%(column_0_name)s_%(referred_table)s` naming is left in
place for future autogeneration but not relied upon here).
"""
import logging
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

from migrations.sqlite_compat import install_sqlite_datetime_transfer_patch

logger = logging.getLogger("migrations.0003")

revision: str = "0003_foreign_keys"
down_revision: Union[str, None] = "0002_schema_authority"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


#: (child table, child column, referred table, referred column, ondelete)
#:
#: Keep in sync with the `ForeignKey` declarations in `core/models.py`; the drift gate
#: (`compare_metadata`) fails the build if the two disagree.
FOREIGN_KEYS: list[tuple[str, str, str, str, str]] = [
    # Tenant scoping — every one of these columns has a `page_id` in models.py.
    ("registrations", "page_id", "pages", "page_id", "CASCADE"),
    ("messages", "page_id", "pages", "page_id", "CASCADE"),
    ("session_states", "page_id", "pages", "page_id", "CASCADE"),
    ("sessions", "page_id", "pages", "page_id", "CASCADE"),
    ("user_memories", "page_id", "pages", "page_id", "CASCADE"),
    ("invoices", "page_id", "pages", "page_id", "CASCADE"),
    ("cargo_packages", "page_id", "pages", "page_id", "CASCADE"),
    ("automated_rules", "page_id", "pages", "page_id", "CASCADE"),
    ("marketing_campaigns", "page_id", "pages", "page_id", "CASCADE"),
    ("sent_followups", "page_id", "pages", "page_id", "CASCADE"),
    ("appointments", "page_id", "pages", "page_id", "CASCADE"),
    ("comment_automations", "page_id", "pages", "page_id", "CASCADE"),
    ("tracked_links", "page_id", "pages", "page_id", "CASCADE"),
    # The audit trail survives tenant deletion.
    ("audit_logs", "page_id", "pages", "page_id", "SET NULL"),
    # Optional cross-references: clear the link, keep the record.
    ("cargo_packages", "invoice_id", "invoices", "invoice_id", "SET NULL"),
    ("tracked_links", "automation_id", "comment_automations", "id", "SET NULL"),
]


def _constraint_name(table: str, column: str, referred_table: str) -> str:
    """Deterministic, explicit name — never rely on autogenerated names in a migration."""
    return f"fk_{table}_{column}_{referred_table}"


def _existing_foreign_keys() -> set[tuple[str, str]]:
    """(table, constraint_name) pairs already present, so the migration is re-runnable."""
    inspector = sa.inspect(op.get_bind())
    found: set[tuple[str, str]] = set()
    for table, _column, _rt, _rc, _od in FOREIGN_KEYS:
        for fk in inspector.get_foreign_keys(table):
            name = fk.get("name")
            if name:
                found.add((table, name))
    return found


def _assert_no_orphans() -> None:
    """
    Refuse to add a constraint that the data cannot satisfy.

    Runs before any DDL so a failure leaves the database exactly as it was. The message
    names the offending table and count so an operator can act on it directly.
    """
    bind = op.get_bind()
    problems: list[str] = []
    for table, column, referred_table, referred_column, _ondelete in FOREIGN_KEYS:
        # `SET NULL` links can legitimately hold NULL; SQL treats those as satisfied.
        sql = sa.text(
            f"""
            SELECT COUNT(*) FROM "{table}" AS c
             WHERE c."{column}" IS NOT NULL
               AND NOT EXISTS (
                   SELECT 1 FROM "{referred_table}" AS p
                    WHERE p."{referred_column}" = c."{column}"
               )
            """
        )
        count = int(bind.execute(sql).scalar() or 0)
        if count:
            problems.append(
                f"table '{table}' has {count} row(s) whose {column} has no matching "
                f"{referred_table}.{referred_column}"
            )
    if problems:
        detail = "\n  - ".join(problems)
        raise RuntimeError(
            "Cannot add foreign keys: orphan rows would violate them.\n"
            f"  - {detail}\n"
            "Delete or re-parent these rows, then re-run `alembic upgrade head`. "
            "They are not removed automatically because that would be silent data loss."
        )


def _is_sqlite() -> bool:
    return op.get_bind().dialect.name == "sqlite"


def upgrade() -> None:
    _assert_no_orphans()

    if _is_sqlite():
        # SQLite has no ADD CONSTRAINT; rebuild each table. The datetime shim must be
        # installed first or the table copy truncates timestamps to integers.
        install_sqlite_datetime_transfer_patch()
        existing = _existing_foreign_keys()
        for table, column, referred_table, referred_column, ondelete in FOREIGN_KEYS:
            name = _constraint_name(table, column, referred_table)
            if (table, name) in existing:
                continue
            with op.batch_alter_table(table, recreate="always") as batch:
                batch.create_foreign_key(
                    name, referred_table, [column], [referred_column], ondelete=ondelete
                )
        logger.info("0003: added %d foreign keys (SQLite, table rebuild)", len(FOREIGN_KEYS))
        return

    existing = _existing_foreign_keys()
    added = 0
    for table, column, referred_table, referred_column, ondelete in FOREIGN_KEYS:
        name = _constraint_name(table, column, referred_table)
        if (table, name) in existing:
            continue
        op.create_foreign_key(
            name,
            table,
            referred_table,
            [column],
            [referred_column],
            ondelete=ondelete,
        )
        added += 1
    logger.info("0003: added %d foreign keys", added)


def downgrade() -> None:
    if _is_sqlite():
        install_sqlite_datetime_transfer_patch()
        existing = _existing_foreign_keys()
        for table, column, referred_table, _referred_column, _ondelete in FOREIGN_KEYS:
            name = _constraint_name(table, column, referred_table)
            if (table, name) not in existing:
                continue
            with op.batch_alter_table(table, recreate="always") as batch:
                batch.drop_constraint(name, type_="foreignkey")
        logger.info("0003: dropped all foreign keys (SQLite, table rebuild)")
        return

    existing = _existing_foreign_keys()
    for table, column, referred_table, _referred_column, _ondelete in reversed(FOREIGN_KEYS):
        name = _constraint_name(table, column, referred_table)
        if (table, name) in existing:
            op.drop_constraint(name, table, type_="foreignkey")
    logger.info("0003: dropped all foreign keys")
