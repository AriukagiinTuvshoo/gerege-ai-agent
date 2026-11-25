"""0008 — a lead must always name its tenant (Phase 45, finding F-44-A)

Revision ID: 0008_tenant_not_null
Revises: 0007_audit_append_only

===============================================================================
WHY THIS MIGRATION EXISTS
===============================================================================
`registrations.page_id` carried a default but was **nullable**. Phase 44 measured the
consequence at the authorisation layer:

    verify_resource_tenant_ownership(user_of_pageA, 'pageA')  -> ALLOWED   (correct)
    verify_resource_tenant_ownership(user_of_pageA, 'pageB')  -> DENIED    (correct)
    verify_resource_tenant_ownership(user_of_pageA, None)     -> ALLOWED   (wrong)
    verify_resource_tenant_ownership(user_of_pageA, '')       -> ALLOWED   (wrong)

The guard's condition was `resource_page_id and str(resource_page_id) != str(user_pid)`,
so a resource that could not name its tenant skipped the comparison entirely. Phase 45
fixed the guard to fail closed (`core/security.py`), and this migration removes the *other*
half of the problem: the state it was reasoning about.

Two defences are better than one here because they fail differently. The guard protects
the read path and would also cover a future table; the constraint protects the write path
and cannot be bypassed by a new caller that forgets the guard.

===============================================================================
WHAT THIS REVISION DOES
===============================================================================
`ALTER TABLE registrations ALTER COLUMN page_id SET NOT NULL` (PostgreSQL) or the
equivalent table rebuild (SQLite, which has no ALTER COLUMN).

Strictly tightening. No row is rewritten, no column type changes, no data is deleted.

**Backfill is deliberately absent.** A row with a NULL tenant cannot be assigned to one
by guessing — `DEFAULT_PAGE_ID` is one specific customer's page, and silently adopting
orphaned leads into it would be a cross-tenant data movement disguised as a repair. If a
NULL row exists this migration *fails* and says so, which is the correct outcome for an
operator to see. Measured before writing it: `SELECT count(*) FROM registrations WHERE
page_id IS NULL` returned 0 on a fully migrated database.

===============================================================================
REVERSIBILITY
===============================================================================
`downgrade()` drops the NOT NULL. It does not recreate any NULL row, because none can
exist while the constraint holds. Reverting therefore restores the *permissive schema*
and nothing else — the guard in `core/security.py` still fails closed, which is why
reverting this migration alone cannot reopen F-44-A.
"""

from __future__ import annotations

import logging

import sqlalchemy as sa
from alembic import op

logger = logging.getLogger("alembic.runtime.migration")

revision = "0008_tenant_not_null"
down_revision = "0007_audit_append_only"
branch_labels = None
depends_on = None

TABLE = "registrations"
COLUMN = "page_id"


def _dialect() -> str:
    return op.get_bind().dialect.name


def _exec(statement: str) -> None:
    op.execute(sa.text(statement))


def _sqlite_rebuild(nullable: bool) -> None:
    """SQLite cannot ALTER COLUMN, so the table is rebuilt.

    **Only the NOT NULL attribute of `page_id` changes.** Every other column is reproduced
    from the live table's own `PRAGMA table_info`, carrying its declared type, its NOT NULL
    flag, its default and its place in the primary key. My first version of this function
    wrote the non-target columns as bare ``"col"`` placeholders, which silently dropped
    `id`/`name`/`phone` NOT NULL and the `created_at` server default - caught by
    `tests/test_stage_c_schema.py`, which compares `init_db()`'s result against
    `core/models.py` and reported 7 diffs. A migration that rebuilds a table must not lose
    constraints it was not asked to change.
    """
    bind = op.get_bind()
    exists = bind.execute(
        sa.text("SELECT name FROM sqlite_master WHERE type='table' AND name=:t"),
        {"t": TABLE},
    ).fetchone()
    if not exists:
        return

    # (cid, name, type, notnull, dflt_value, pk)
    info = bind.execute(sa.text(f"PRAGMA table_info({TABLE})")).fetchall()
    if not info:
        return

    defs = []
    pk_columns = [row[1] for row in sorted(info, key=lambda r: r[5]) if row[5]]
    for _cid, name, decl_type, notnull, dflt, _pk in info:
        if name == "id" and len(pk_columns) == 1:
            # `INTEGER PRIMARY KEY` is the rowid alias; re-declaring it keeps rowids stable.
            # SQLite reports `notnull=0` for a rowid-alias primary key even though it can
            # never be NULL, so NOT NULL is stated explicitly - without it the drift gate
            # reports `Detected NOT NULL on column 'registrations.id'` (measured: 1 diff).
            defs.append(f'"{name}" INTEGER PRIMARY KEY NOT NULL')
            continue
        part = f'"{name}" {decl_type}'
        target_notnull = notnull
        if name == COLUMN:
            target_notnull = 0 if nullable else 1
        if target_notnull:
            part += " NOT NULL"
        if dflt is not None:
            part += f" DEFAULT {dflt}"
        defs.append(part)
    if len(pk_columns) > 1:
        cols = ", ".join(f'"{c}"' for c in pk_columns)
        defs.append(f"PRIMARY KEY ({cols})")

    # Everything that hangs off the table must be replayed: indexes, triggers and the
    # foreign key. `PRAGMA table_info` reports only columns, so my second version rebuilt
    # the columns correctly and silently dropped the indexes and the FK - caught by the
    # same drift test, which then reported 5 differences. SQLite has no ALTER for any of
    # this, so the DDL is captured from `sqlite_master` before the drop and replayed after.
    dependent = [
        row[0]
        for row in bind.execute(
            sa.text(
                "SELECT sql FROM sqlite_master WHERE tbl_name=:t AND type IN "
                "('index','trigger') AND sql IS NOT NULL"
            ),
            {"t": TABLE},
        ).fetchall()
    ]
    # SQLite has no `ALTER TABLE ... ADD CONSTRAINT`, so the foreign key must be declared
    # inside the rebuilt CREATE TABLE rather than replayed afterwards.
    fk_rows = bind.execute(sa.text(f"PRAGMA foreign_key_list({TABLE})")).fetchall()
    # (id, seq, table, from, to, on_update, on_delete, match)
    for _id, _seq, ref_table, from_col, to_col, on_update, on_delete, _match in fk_rows:
        defs.append(
            f'FOREIGN KEY ("{from_col}") REFERENCES "{ref_table}"("{to_col}") '
            f"ON UPDATE {on_update} ON DELETE {on_delete}"
        )

    quoted = ", ".join(f'"{row[1]}"' for row in info)
    _exec("PRAGMA foreign_keys=OFF")
    try:
        _exec(f"DROP TABLE IF EXISTS {TABLE}__p45")
        _exec(f"CREATE TABLE {TABLE}__p45 (  {', '.join(defs)}  )")
        _exec(f"INSERT INTO {TABLE}__p45 ({quoted}) SELECT {quoted} FROM {TABLE}")
        _exec(f"DROP TABLE {TABLE}")
        _exec(f"ALTER TABLE {TABLE}__p45 RENAME TO {TABLE}")
        for ddl in dependent:
            _exec(ddl)
    finally:
        _exec("PRAGMA foreign_keys=ON")


def upgrade() -> None:
    dialect = _dialect()

    bind = op.get_bind()
    orphans = bind.execute(
        sa.text(f"SELECT count(*) FROM {TABLE} WHERE {COLUMN} IS NULL")
    ).scalar()
    if orphans:
        raise RuntimeError(
            f"0008: {TABLE}.{COLUMN} has {orphans} NULL row(s). Refusing to assign them "
            "to a tenant by guessing: DEFAULT_PAGE_ID belongs to one customer, and "
            "adopting orphaned rows into it would move data between tenants. Resolve "
            "the rows deliberately, then re-run this migration."
        )

    if dialect == "postgresql":
        _exec(f"ALTER TABLE {TABLE} ALTER COLUMN {COLUMN} SET NOT NULL")
    else:
        _sqlite_rebuild(nullable=False)

    # Verify the SHAPE, not the name: the Phase 8 lesson. A column that merely *exists*
    # is not the same as one that refuses NULL, and a migration that reports success
    # without checking is worse than one that refuses to run.
    inspector = sa.inspect(bind)
    column = next(c for c in inspector.get_columns(TABLE) if c["name"] == COLUMN)
    if column.get("nullable", True):
        raise RuntimeError(
            f"0008: {TABLE}.{COLUMN} is still nullable on {dialect}. The constraint did "
            "not take effect, so F-44-A's schema half is not fixed."
        )

    logger.info(
        "0008: %s.%s is NOT NULL on %s (a lead always names its tenant)",
        TABLE, COLUMN, dialect,
    )


def downgrade() -> None:
    dialect = _dialect()
    if dialect == "postgresql":
        _exec(f"ALTER TABLE {TABLE} ALTER COLUMN {COLUMN} DROP NOT NULL")
    else:
        _sqlite_rebuild(nullable=True)

    logger.warning(
        "0008 downgraded: %s.%s is nullable again on %s. No NULL row was created by this "
        "downgrade, and core.security.verify_resource_tenant_ownership still fails "
        "closed, so F-44-A stays closed at the application layer.",
        TABLE, COLUMN, dialect,
    )
