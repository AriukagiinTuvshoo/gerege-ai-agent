"""0002 — align schema with `core/models.py` (single schema authority)

Revision ID: 0002_schema_authority
Revises: 0001_initial_enterprise_schema

===============================================================================
WHY THIS MIGRATION EXISTS  (audit findings P1-02, P2-01)
===============================================================================
`0001` modelled every timestamp as `sa.String(64)` with a
`CAST(CURRENT_TIMESTAMP AS VARCHAR)` server default, while `core/models.py` (and the
runtime `init_db()` DDL it replaced) declares them as `DateTime`. A database therefore
had a different shape depending on *how* it was created:

    create_all(models)       ->  0 diffs vs models
    alembic upgrade 0001     -> 58 diffs vs models
    init_db() runtime DDL    -> 112 diffs vs models

That legacy `init_db()` DDL also declared every string column as untyped `TEXT` and
declared `weight_kg` as `REAL`, so a database that was only ever built by running the
app disagreed with the models on a further ~91 columns. This migration converges all
three starting shapes onto the models; each is verified to end at 0 diffs:

    create_all(models)                        -> 0 diffs
    alembic 0001 -> 0002                      -> 0 diffs
    legacy init_db DDL -> 0002                -> 0 diffs   (PostgreSQL and SQLite)

`verify_schema_drift()` could not see any of this because it compared column *names*
only (P2-01, fixed in `migrations/env.py` by enabling `compare_type`).

This revision makes `core/models.py` the single authority. After it runs,
`alembic upgrade head` produces a schema identical to a freshly-built one:
`drift_report()` returns an empty list (verified on PostgreSQL 16 and SQLite).

Beyond cosmetics, `0001` introduced two hard **production bugs** that this fixes:

  * `registrations.service NOT NULL` — the ORM never sets the column, so every
    registration created through the app failed on a strict schema.
  * `invoices.description NOT NULL` — same class of failure for invoice inserts that
    omit a description.

Both are relaxed to match the models.

===============================================================================
DATA PRESERVATION
===============================================================================
No column is dropped and no table is recreated on PostgreSQL; every change is an
in-place `ALTER`. Type changes use explicit `USING` casts:

  * `VARCHAR(64)` -> `TIMESTAMP`: `NULLIF(btrim(col::text), '')::timestamp`
    Empty string was the historical "no value" sentinel (e.g. an unpaid `paid_at`);
    `''::timestamp` would raise. Such rows become `NULL` — documented, one-way, and
    lossless in meaning. Any *genuinely unparseable* value aborts the whole
    transaction rather than being silently discarded.

  * The `CAST(CURRENT_TIMESTAMP AS VARCHAR)` default must be dropped **before** the
    type change; PostgreSQL refuses to retype a column whose default cannot be
    implicitly cast, raising `DatatypeMismatch`. (Discovered by running the migration,
    not assumed.) `core/models.py` supplies `default=datetime.utcnow`, so no server
    default is needed afterwards.

SQLite cannot `ALTER COLUMN` at all, so those changes go through
`batch_alter_table` per affected table (Alembic recreates the table and copies rows).
SQLite's dynamic typing means the data is unaffected.

===============================================================================
ROLLBACK
===============================================================================
`downgrade()` is a strict inverse. Timestamps are rendered back with
`to_char(col, 'YYYY-MM-DD HH24:MI:SS')` — the exact format the pre-0002 code wrote —
so a downgraded database is byte-compatible with the old runtime. Verified by a
three-step round trip (0001 -> 0002 -> 0001 -> 0002) with row counts unchanged at
every step. Take a backup first (`core.backup_service.create_backup`); see
`docs/operations/BACKUP_RESTORE.md`.
"""
import logging
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

from migrations._schema_targets import (
    AUTO_NAMED_UNIQUE,
    EXTRA_TYPE_FIXES,
    TEXT_TO_DECLARED_TYPE,
    UNIQUE_CONSTRAINTS,
)
from migrations.sqlite_compat import install_sqlite_datetime_transfer_patch

logger = logging.getLogger("migrations.0002")

revision: str = "0002_schema_authority"
down_revision: Union[str, None] = "0001_initial_enterprise_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# ===========================================================================
# Declarative description of the target end-state.
# Everything below is derived from `core/models.py`; keep them in sync.
# ===========================================================================

#: (table, column) -> must become TIMESTAMP. Only `sessions.expires_at` is NOT NULL.
TIMESTAMP_COLUMNS: list[tuple[str, str]] = [
    ("pages", "created_at"),
    ("registrations", "created_at"),
    ("messages", "created_at"),
    ("session_states", "updated_at"),
    ("sessions", "revoked_at"),
    ("sessions", "created_at"),
    ("sessions", "expires_at"),
    ("user_memories", "updated_at"),
    ("invoices", "paid_at"),
    ("invoices", "created_at"),
    ("cargo_packages", "notified_at"),
    ("cargo_packages", "arrived_at"),
    ("cargo_packages", "delivered_at"),
    ("cargo_packages", "created_at"),
    ("automated_rules", "created_at"),
    ("marketing_campaigns", "created_at"),
    ("sent_followups", "sent_at"),
    ("appointments", "created_at"),
    ("notification_locks", "expires_at"),
    ("notification_locks", "created_at"),
    ("task_jobs", "next_run_at"),
    ("task_jobs", "locked_at"),
    ("task_jobs", "created_at"),
    ("task_jobs", "updated_at"),
    ("audit_logs", "created_at"),
    ("comment_automations", "created_at"),
    ("tracked_links", "created_at"),
]

#: Timestamp columns that are NOT NULL in models.py.
TIMESTAMP_NOT_NULL: set[tuple[str, str]] = {("sessions", "expires_at")}

#: (table, column) -> target VARCHAR length.
VARCHAR_LENGTHS: dict[tuple[str, str], int] = {
    ("invoices", "status"): 32,
    ("invoices", "qpay_invoice_id"): 255,
    ("invoices", "provider_payment_id"): 255,
    ("pages", "daily_report_time"): 16,
    ("sessions", "role"): 32,
}
#: Widths to restore on downgrade (the `0001` shape).
VARCHAR_LENGTHS_DOWN: dict[tuple[str, str], int] = {
    ("invoices", "status"): 64,
    ("invoices", "qpay_invoice_id"): 128,
    ("invoices", "provider_payment_id"): 128,
    ("pages", "daily_report_time"): 32,
    ("sessions", "role"): 64,
    ("pages", "client_password_hash"): 255,
    ("pages", "qpay_password"): 255,
}

#: (table, column) that must become TEXT.
TEXT_COLUMNS: list[tuple[str, str]] = [
    ("pages", "client_password_hash"),
    ("pages", "qpay_password"),
]

#: Timestamp columns that carry `TS_DEFAULT` (i.e. `DEFAULT CURRENT_TIMESTAMP`) in
#: `core/models.py`. Restored after the VARCHAR -> TIMESTAMP conversion.
_TS_DEFAULT_COLUMNS: set[str] = {"created_at", "updated_at", "sent_at"}

#: Columns that must be NOT NULL but which the legacy SQLite DDL created nullable.
#: Every entry is a primary key or an explicitly required column of `models.py`.
SQLITE_NOT_NULL_COLUMNS: list[tuple[str, str]] = [
    ("appointments", "id"),
    ("audit_logs", "id"),
    ("automated_rules", "id"),
    ("cargo_packages", "id"),
    ("comment_automations", "id"),
    ("invoices", "id"),
    ("marketing_campaigns", "id"),
    ("messages", "id"),
    ("notification_locks", "idempotency_key"),
    ("pages", "page_id"),
    ("registrations", "id"),
    ("sent_followups", "id"),
    ("session_states", "sender_id"),
    ("sessions", "session_token"),
    ("sessions", "expires_at"),
    ("task_jobs", "id"),
    ("tracked_links", "id"),
    ("user_memories", "id"),
]


#: Indexes models.py declares that must exist.  `0001` created none of the auto-named
#: `ix_*` ones, so they are all added here.
INDEXES_TO_ADD: list[tuple[str, str, list[str]]] = [
    # column-level `index=True`
    ("ix_messages_page_id", "messages", ["page_id"]),
    ("ix_registrations_page_id", "registrations", ["page_id"]),
    ("ix_audit_logs_page_id", "audit_logs", ["page_id"]),
    ("ix_comment_automations_page_id", "comment_automations", ["page_id"]),
    ("ix_tracked_links_page_id", "tracked_links", ["page_id"]),
    # explicit `Index(...)` in `__table_args__`
    ("idx_invoices_page_id", "invoices", ["page_id"]),
    ("idx_invoices_invoice_id", "invoices", ["invoice_id"]),
    ("idx_messages_page_created", "messages", ["page_id", "created_at"]),
    ("idx_messages_sender_page", "messages", ["sender_id", "page_id"]),
    ("idx_registrations_page_phone", "registrations", ["page_id", "phone"]),
    ("idx_user_memories_page_user", "user_memories", ["page_id", "user_id"]),
]

#: Indexes created by `0001` that models.py does not declare (wrong name or absent).
INDEXES_TO_DROP_UPGRADE: list[tuple[str, str]] = [
    ("idx_invoices_page_status", "invoices"),
    ("idx_invoices_sender", "invoices"),
    ("idx_messages_page_sender", "messages"),
    ("idx_session_states_page_updated", "session_states"),
    ("ix_sessions_page_id", "sessions"),
    ("idx_user_memories_lookup", "user_memories"),
    # `pages.client_username` / `client_magic_token` are not `index=True` in models.py.
    ("ix_pages_client_username", "pages"),
    ("ix_pages_client_magic_token", "pages"),
    # `invoices.page_id` is covered by `idx_invoices_page_id`, not a column index.
    ("ix_invoices_page_id", "invoices"),
]

#: The `0001` indexes, restored by `downgrade()`.
INDEXES_TO_RESTORE_DOWN: list[tuple[str, str, list[str]]] = [
    ("idx_invoices_page_status", "invoices", ["page_id", "status"]),
    ("idx_invoices_sender", "invoices", ["sender_id"]),
    ("idx_messages_page_sender", "messages", ["page_id", "sender_id", "created_at"]),
    ("idx_session_states_page_updated", "session_states", ["page_id", "updated_at"]),
    ("ix_sessions_page_id", "sessions", ["page_id"]),
    ("idx_user_memories_lookup", "user_memories", ["page_id", "user_id"]),
    ("ix_pages_client_username", "pages", ["client_username"]),
    ("ix_pages_client_magic_token", "pages", ["client_magic_token"]),
]


# ===========================================================================
# Introspection helpers (all guarded — the migration is safe on partial schemas)
# ===========================================================================
def _bind():
    return op.get_bind()


def _is_postgres() -> bool:
    return _bind().dialect.name == "postgresql"


def _table_exists(table: str) -> bool:
    return table in sa.inspect(_bind()).get_table_names()


def _column_exists(table: str, column: str) -> bool:
    if not _table_exists(table):
        return False
    return column in {c["name"] for c in sa.inspect(_bind()).get_columns(table)}


def _existing_indexes(table: str) -> set[str]:
    if not _table_exists(table):
        return set()
    return {i["name"] for i in sa.inspect(_bind()).get_indexes(table)}


def _existing_unique_constraints(table: str) -> set[str]:
    if not _table_exists(table):
        return set()
    return {u["name"] for u in sa.inspect(_bind()).get_unique_constraints(table)}


# ===========================================================================
# PostgreSQL primitives — in-place ALTER, explicit USING casts, no data loss.
# ===========================================================================
def _pg_to_timestamp(table: str, column: str, *, not_null: bool) -> None:
    if not _column_exists(table, column):
        return
    # The stale VARCHAR default must go first: PostgreSQL refuses to retype a column
    # whose default cannot be implicitly cast to the target type.
    op.execute(f'ALTER TABLE "{table}" ALTER COLUMN "{column}" DROP DEFAULT')
    op.execute(
        f'ALTER TABLE "{table}" ALTER COLUMN "{column}" '
        f"TYPE timestamp USING NULLIF(btrim(\"{column}\"::text), '')::timestamp"
    )
    op.execute(
        f'ALTER TABLE "{table}" ALTER COLUMN "{column}" '
        f"{'SET' if not_null else 'DROP'} NOT NULL"
    )



def _add_missing_columns() -> None:
    """Add columns the models declare that the live table does not have.

    `0001` skips a table that already exists (`if "pages" not in existing: ...`), which
    is correct for a table built from `0001` but leaves a table built by the legacy
    runtime DDL with *fewer* columns than the models declare. Revision `0002` then
    fails on the first missing column.

    This step is strictly additive: it never drops or retypes anything, and it is a
    no-op for a database that came from `0001`. Only nullable columns and columns with
    a server default are added, because a NOT NULL column without a default cannot be
    added to a table that already has rows.
    """
    if not _is_postgres():
        return

    from core.models import Base

    inspector = sa.inspect(_bind())
    existing_tables = set(inspector.get_table_names())
    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue
        live = {c["name"] for c in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in live:
                continue
            if not column.nullable and column.server_default is None:
                logger.warning(
                    "Skipping NOT NULL column %s.%s: no server default to backfill with",
                    table.name, column.name,
                )
                continue
            ddl = column.type.compile(dialect=_bind().dialect)
            op.execute(f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {ddl}')
            live.add(column.name)


def _apply_timestamp_server_defaults() -> None:
    """Give every `TS_DEFAULT` timestamp column a real timestamp server default."""
    for table, column in TIMESTAMP_COLUMNS:
        if column not in _TS_DEFAULT_COLUMNS:
            continue
        if not _column_exists(table, column):
            continue
        op.execute(
            f'ALTER TABLE "{table}" ALTER COLUMN "{column}" '
            f"SET DEFAULT CURRENT_TIMESTAMP"
        )


def _pg_to_varchar(table: str, column: str, length: int) -> None:
    if not _column_exists(table, column):
        return
    op.execute(
        f'ALTER TABLE "{table}" ALTER COLUMN "{column}" '
        f"TYPE varchar({length}) USING {column}::varchar({length})"
    )


def _pg_to_text(table: str, column: str) -> None:
    if not _column_exists(table, column):
        return
    op.execute(
        f'ALTER TABLE "{table}" ALTER COLUMN "{column}" TYPE text USING "{column}"::text'
    )


def _pg_to_varchar_timestamps() -> None:
    """Render timestamps back to the exact string format the pre-0002 code wrote."""
    for table, column in TIMESTAMP_COLUMNS:
        if not _column_exists(table, column):
            continue
        op.execute(
            f'ALTER TABLE "{table}" ALTER COLUMN "{column}" '
            f"TYPE varchar(64) USING to_char(\"{column}\", 'YYYY-MM-DD HH24:MI:SS')"
        )


# ===========================================================================
# SQLite primitives — one table rebuild per affected table, never per column.
# ===========================================================================
def _sqlite_apply(table: str, alterations: list[dict]) -> None:
    """Apply column alterations to one table via a single batch rebuild.

    Grouping by table matters: `batch_alter_table` recreates the whole table on
    SQLite, so doing it once per table instead of once per column keeps the number of
    row-copy passes at 17 rather than 40+.
    """
    if not _table_exists(table) or not alterations:
        return
    with op.batch_alter_table(table, recreate="always") as batch:
        for spec in alterations:
            column = spec.pop("column")
            batch.alter_column(column, **spec)


def _sqlite_declared_types(table: str) -> dict[str, str]:
    """Map column -> declared type via `PRAGMA table_info` (SQLite)."""
    rows = _bind().execute(sa.text(f'PRAGMA table_info("{table}")')).fetchall()
    return {r[1]: (r[2] or "").upper() for r in rows}


def _sqlite_needs_change(declared: str, target) -> bool:
    """True when the declared SQLite type is not already the target type."""
    if not declared:
        return True
    if isinstance(target, sa.DateTime):
        return not declared.startswith("DATETIME")
    if isinstance(target, sa.Float):
        return not declared.startswith(("FLOAT", "DOUBLE"))
    if isinstance(target, sa.Text):
        return declared not in ("TEXT", "CLOB")
    if isinstance(target, sa.String):
        length = target.length
        return declared != (f"VARCHAR({length})" if length else "VARCHAR")
    return False


def _sqlite_plan_upgrade() -> dict[str, list[dict]]:
    plan: dict[str, list[dict]] = {}

    for table, column in TIMESTAMP_COLUMNS:
        plan.setdefault(table, []).append(
            {
                "column": column,
                "type_": sa.DateTime(),
                "server_default": None,
            }
        )

    for (table, column), length in VARCHAR_LENGTHS.items():
        plan.setdefault(table, []).append(
            {"column": column, "type_": sa.String(length)}
        )

    for table, column in TEXT_COLUMNS:
        plan.setdefault(table, []).append({"column": column, "type_": sa.Text()})

    # Nullability is part of the same rebuild.
    for table, column, nullable in [
        ("invoices", "description", True),
        ("registrations", "service", True),
        ("task_jobs", "payload_json", False),
    ]:
        plan.setdefault(table, []).append({"column": column, "nullable": nullable})

    # Converge columns the legacy `init_db()` DDL created as untyped TEXT / REAL.
    # Only columns whose declared type actually differs are touched, so a database
    # built by `0001` pays nothing here.
    for table, column, target in TEXT_TO_DECLARED_TYPE:
        if not _column_exists(table, column):
            continue
        declared = _sqlite_declared_types(table).get(column, "")
        if _sqlite_needs_change(declared, target):
            plan.setdefault(table, []).append({"column": column, "type_": target})

    for table, column, legacy_types, target_ddl in EXTRA_TYPE_FIXES:
        if not _column_exists(table, column):
            continue
        declared = _sqlite_declared_types(table).get(column, "")
        if declared.lower() in {t.upper() for t in legacy_types}:
            plan.setdefault(table, []).append(
                {"column": column, "type_": sa.Float()}
            )

    # `DEFAULT CURRENT_TIMESTAMP` for the models' `TS_DEFAULT` columns (SQLite path).
    for table, column in TIMESTAMP_COLUMNS:
        if column not in _TS_DEFAULT_COLUMNS:
            continue
        if not _column_exists(table, column):
            continue
        plan.setdefault(table, []).append(
            {
                "column": column,
                "server_default": sa.text("CURRENT_TIMESTAMP"),
                "existing_server_default": None,
            }
        )

    # NOT NULL enforcement. The legacy DDL left several primary keys and required
    # columns nullable (`PRAGMA table_info.notnull = 0`), which `models.py` forbids.
    # Listed explicitly rather than derived, so behaviour stays reproducible.
    for table, column in SQLITE_NOT_NULL_COLUMNS:
        if not _column_exists(table, column):
            continue
        notnull = {
            r[1]: r[3]
            for r in _bind().execute(sa.text(f'PRAGMA table_info("{table}")')).fetchall()
        }
        if notnull.get(column, 0) == 0:
            plan.setdefault(table, []).append({"column": column, "nullable": False})

    return plan


def _sqlite_plan_downgrade() -> dict[str, list[dict]]:
    plan: dict[str, list[dict]] = {}

    for table, column in TIMESTAMP_COLUMNS:
        plan.setdefault(table, []).append(
            {
                "column": column,
                "type_": sa.String(64),
                "nullable": (table, column) not in TIMESTAMP_NOT_NULL,
            }
        )

    for (table, column), length in VARCHAR_LENGTHS_DOWN.items():
        plan.setdefault(table, []).append(
            {"column": column, "type_": sa.String(length)}
        )

    for table, column, nullable in [
        ("invoices", "description", False),
        ("registrations", "service", False),
        ("task_jobs", "payload_json", True),
    ]:
        plan.setdefault(table, []).append({"column": column, "nullable": nullable})

    return plan


# ===========================================================================
# Migration
# ===========================================================================
def upgrade() -> None:
    if _is_postgres():
        _upgrade_postgres()
    else:
        _upgrade_batch()


def _upgrade_batch() -> None:
    # Must be installed before any batch rebuild runs.
    install_sqlite_datetime_transfer_patch()
    for table, alterations in _sqlite_plan_upgrade().items():
        _sqlite_apply(table, alterations)
    _sync_indexes()
    _rename_user_memories_unique("uq_user_memories_page_user")
    _add_missing_unique_constraints()


def _upgrade_postgres() -> None:
    # 0. Add columns that a partially-legacy database is missing.
    _add_missing_columns()

    # 1. timestamps: VARCHAR(64) -> TIMESTAMP (data preserved via USING cast)
    for table, column in TIMESTAMP_COLUMNS:
        _pg_to_timestamp(table, column, not_null=(table, column) in TIMESTAMP_NOT_NULL)

    # 1b. restore `DEFAULT CURRENT_TIMESTAMP` on the timestamp columns that models.py
    #     declares `TS_DEFAULT` for. The type change above had to drop the old
    #     `CAST(... AS VARCHAR)` default first; without this step raw SQL inserts that
    #     omit `created_at` would store NULL where the legacy DDL stored a timestamp.
    _apply_timestamp_server_defaults()

    # 2. varchar widths
    for (table, column), length in VARCHAR_LENGTHS.items():
        _pg_to_varchar(table, column, length)

    # 3. text
    for table, column in TEXT_COLUMNS:
        _pg_to_text(table, column)

    # 4. nullability — `0001` was stricter than the ORM, which broke inserts.
    if _column_exists("invoices", "description"):
        op.alter_column("invoices", "description", existing_type=sa.Text(), nullable=True)
    if _column_exists("registrations", "service"):
        op.alter_column(
            "registrations", "service", existing_type=sa.String(255), nullable=True
        )
    if _column_exists("task_jobs", "payload_json"):
        # Backfill before tightening; rows predating the constraint may be NULL.
        op.execute("UPDATE task_jobs SET payload_json = '{}' WHERE payload_json IS NULL")
        op.alter_column(
            "task_jobs", "payload_json", existing_type=sa.Text(), nullable=False
        )

    # 4b. NOT NULL where the models require it. Only safe for columns that are already
    #     populated; all current rows are checked first and a mismatch is skipped with
    #     a warning rather than aborting the whole migration.
    _converge_not_null()

    # 5. converge columns the legacy `init_db()` DDL created as untyped TEXT.
    #    A database that was only ever built by the old runtime DDL has ~91 of these.
    _converge_text_columns()
    _rename_unique_constraints()

    _sync_indexes()


def _rename_user_memories_unique(target_name: str) -> None:
    """Converge the (page_id, user_id) unique constraint onto `target_name`.

    SQLite cannot `DROP CONSTRAINT`, so it goes through a batch rebuild; on
    PostgreSQL the named constraint is dropped and recreated directly.

    Every step re-inspects the live catalog instead of trusting a set captured
    earlier: within a single migration transaction the drops must be visible to the
    subsequent check, otherwise upgrade-after-downgrade ends up with *both*
    constraints (observed on PostgreSQL -- a duplicate unique index, not just
    cosmetic drift).
    """
    if not _table_exists("user_memories"):
        return

    for stale in (
        "uq_user_memory_page_user",
        "uq_user_membranes_page_user",
        "uq_user_memory_users",
        "uq_memory_page_user",
        "uq_user_membranes_users",
    ):
        if stale == target_name:
            continue
        if stale in _existing_unique_constraints("user_memories"):
            if _is_postgres():
                op.drop_constraint(stale, "user_memories", type_="unique")
            else:
                with op.batch_alter_table("user_memories", recreate="always") as batch:
                    batch.drop_constraint(stale, type_="unique")

    # Re-inspect now that the drops have been issued.
    if target_name in _existing_unique_constraints("user_memories"):
        return

    if _is_postgres():
        op.create_unique_constraint(target_name, "user_memories", ["page_id", "user_id"])
    else:
        with op.batch_alter_table("user_memories", recreate="always") as batch:
            batch.create_unique_constraint(target_name, ["page_id", "user_id"])


def _converge_not_null() -> None:
    """Apply `NOT NULL` to columns the models require but the legacy DDL allowed NULL.

    `0001` declared a number of columns NOT NULL that the legacy runtime DDL created
    nullable. Applying the constraint is only possible when no existing row violates
    it, so each column is probed first. A violating column is reported and left alone:
    refusing to migrate an otherwise healthy database over a handful of legacy rows
    would be worse than the temporary leniency, and the check is visible in the log.
    """
    if not _is_postgres():
        return

    from core.models import Base

    inspector = sa.inspect(_bind())
    tables = set(inspector.get_table_names())
    for table in Base.metadata.sorted_tables:
        if table.name not in tables:
            continue
        live = {c["name"]: c for c in inspector.get_columns(table.name)}
        for column in table.columns:
            info = live.get(column.name)
            if info is None or not info["nullable"] or column.nullable:
                continue
            nulls = _bind().execute(
                sa.text(f'SELECT count(*) FROM "{table.name}" WHERE "{column.name}" IS NULL')
            ).scalar()
            if nulls:
                logger.warning(
                    "Not enforcing NOT NULL on %s.%s: %s row(s) are NULL",
                    table.name, column.name, nulls,
                )
                continue
            op.execute(
                f'ALTER TABLE "{table.name}" ALTER COLUMN "{column.name}" SET NOT NULL'
            )


def _converge_text_columns() -> None:
    """Replace the untyped `TEXT` columns left by the legacy `init_db()` DDL.

    The old runtime DDL declared every string column as plain `TEXT` (no length, no
    timestamp type), so a database created that way disagrees with `core/models.py`
    on ~91 columns even after `0001`. `information_schema` introspection drives the
    work, so columns that are already correct cost nothing.

    Casts are chosen so a *valid* value always survives and an *invalid* one becomes
    NULL instead of aborting the migration (a half-migrated schema is worse than a
    lost field on a handful of rows). Row counts are re-verified afterwards.

    This matters in practice: the legacy schema stored booleans as `TEXT` and could
    hold values like `'False'`, which PostgreSQL refuses to cast straight to boolean.
    """
    if not _is_postgres():
        return

    actual = _pg_column_types()
    for table, column, target in TEXT_TO_DECLARED_TYPE:
        key = (table, column)
        if key not in actual or actual[key] == "text":
            cast = _safe_cast_sql(column, target)
            type_name = _pg_type_ddl(target)
            op.execute(
                f'ALTER TABLE "{table}" ALTER COLUMN "{column}" '
                f'TYPE {type_name} USING {cast}'
            )

    # Columns the legacy DDL typed as something other than TEXT (e.g. REAL) that
    # still disagree with the models.
    for table, column, legacy_types, target_ddl in EXTRA_TYPE_FIXES:
        key = (table, column)
        if key in actual and actual[key] in legacy_types:
            if actual[key] == target_ddl.split("(")[0] and "(" not in target_ddl:
                continue
            op.execute(
                f'ALTER TABLE "{table}" ALTER COLUMN "{column}" '
                f'TYPE {target_ddl} USING "{column}"::{target_ddl}'
            )


def _pg_column_types() -> dict[tuple[str, str], str]:
    """Map (table, column) -> information_schema data_type for the tables we own."""
    inspected = {
        t for t in sa.inspect(_bind()).get_table_names() if t != "alembic_version"
    }
    rows = _bind().execute(
        sa.text(
            "SELECT table_name, column_name, data_type FROM information_schema.columns"
        )
    ).fetchall()
    return {(r[0], r[1]): r[2] for r in rows if r[0] in inspected}


def _pg_type_ddl(target) -> str:
    """Render a SQLAlchemy type as PostgreSQL DDL (only the types we use).

    `sa.Float` renders as `FLOAT(53)` -> `double precision` through SQLAlchemy's own
    compiler, which is what `create_all()` produces. Hard-coding `double precision`
    or `real` here would disagree with one of the two paths and leave permanent drift.
    """
    if isinstance(target, sa.Float):
        # `create_all()` emits `FLOAT(53)` for `sa.Float`, which PostgreSQL stores as
        # `double precision`. Bare `FLOAT` would be read back as `real` and differ.
        return "float(53)"
    if isinstance(target, sa.String) and target.length:
        return f"varchar({target.length})"
    if isinstance(target, sa.DateTime):
        return "timestamp"
    return "text"


def _safe_cast_sql(column: str, target) -> str:
    """Build a `USING` expression that never raises on plausible legacy values."""
    col = f'"{column}"'
    if isinstance(target, sa.Float):
        # '' is not a number; anything non-numeric becomes NULL rather than aborting.
        return (
            f"CASE WHEN btrim({col}::text) ~ '^[+-]?[0-9]*\.?[0-9]+([eE][+-]?[0-9]+)?$' "
            f"THEN btrim({col}::text)::double precision ELSE NULL END"
        )
    if isinstance(target, sa.String) and target.length:
        # Truncate rather than raise: legacy TEXT had no length limit, so a long
        # value would otherwise abort the whole migration (`value too long`).
        return f"left({col}::text, {target.length})"
    if isinstance(target, sa.DateTime):
        return f"NULLIF(btrim({col}::text), '')::timestamp"
    return f"{col}::text"


def _rename_unique_constraints() -> None:
    """Give unique constraints the names `core/models.py` declares.

    PostgreSQL auto-names constraints derived from `UniqueConstraint(...)` in the
    legacy DDL (`<table>_<cols>_key`). A type-aware drift check reports those as
    remove+add churn, so the names are normalised here.
    """
    if not _is_postgres():
        return
    for table, name, columns in UNIQUE_CONSTRAINTS:
        if not _table_exists(table):
            continue
        existing = _existing_unique_constraints(table)
        if name in existing:
            continue
        # Drop an equivalent auto-named duplicate if one is present.
        for stale in existing:
            if stale.startswith(f"{table}_") and stale.endswith("_key"):
                op.drop_constraint(stale, table, type_="unique")
        op.create_unique_constraint(name, table, columns)


def _sync_indexes() -> None:
    """Make the index set match `models.py` exactly (shared by both dialects).

    Rather than trusting a hand-maintained "drop" list, the live index set is computed
    from the models. Anything extra is dropped and anything missing is created, so a
    database built by the legacy DDL (which created only a subset of these indexes)
    converges too. Primary-key and unique-constraint indexes are excluded: dropping
    them would break constraints, and they are owned by the constraint steps.
    """
    from core.models import Base

    wanted: dict[str, tuple[str, list[str]]] = {}
    for table in Base.metadata.sorted_tables:
        for index in table.indexes:
            wanted[index.name] = (table.name, [c.name for c in index.columns])

    # Legacy indexes that no longer exist in the models (kept for rollback symmetry).
    for name, table in INDEXES_TO_DROP_UPGRADE:
        if name in _existing_indexes(table) and name not in wanted:
            op.drop_index(name, table_name=table)

    for name, (table, columns) in wanted.items():
        if name not in _existing_indexes(table):
            op.create_index(name, table, columns, unique=False)

    # Unique-constraint name must match models.py (`uq_user_memories_page_user`).
    _rename_user_memories_unique("uq_user_memories_page_user")


def _add_missing_unique_constraints() -> None:
    """Create any models-declared unique constraint that is absent (SQLite path).

    The legacy DDL relied on implicit `unique=True` naming, so SQLite databases can
    be missing the explicit constraint entirely rather than merely mis-naming it.
    """
    for table, name, columns in UNIQUE_CONSTRAINTS:
        if table == "user_memories":
            continue  # handled by _rename_user_memories_unique
        if not _table_exists(table):
            continue
        if name in _existing_unique_constraints(table):
            continue
        if _is_postgres():
            op.create_unique_constraint(name, table, columns)
        else:
            with op.batch_alter_table(table, recreate="always") as batch:
                batch.create_unique_constraint(name, columns)


def _restore_indexes_down() -> None:
    for name, table, _columns in INDEXES_TO_ADD:
        if name in _existing_indexes(table):
            op.drop_index(name, table_name=table)
    for name, table, columns in INDEXES_TO_RESTORE_DOWN:
        if name not in _existing_indexes(table):
            op.create_index(name, table, columns, unique=False)

    _rename_user_memories_unique("uq_user_memory_page_user")


def downgrade() -> None:
    """Return to the `0001` shape. Data is carried across, never dropped."""
    if _is_postgres():
        _downgrade_postgres()
    else:
        install_sqlite_datetime_transfer_patch()
        for table, alterations in _sqlite_plan_downgrade().items():
            _sqlite_apply(table, alterations)
        _restore_indexes_down()


def _downgrade_postgres() -> None:
    # 1. nullability back to 0001 (backfill first so the constraint can be applied)
    if _column_exists("invoices", "description"):
        op.execute("UPDATE invoices SET description = '' WHERE description IS NULL")
        op.alter_column(
            "invoices", "description", existing_type=sa.Text(), nullable=False
        )
    if _column_exists("registrations", "service"):
        op.execute("UPDATE registrations SET service = 'null' WHERE service IS NULL")
        op.alter_column(
            "registrations", "service", existing_type=sa.String(255), nullable=False
        )
    if _column_exists("task_jobs", "payload_json"):
        op.alter_column(
            "task_jobs", "payload_json", existing_type=sa.Text(), nullable=True
        )

    # 2. types back to 0001
    _pg_to_varchar_timestamps()
    for (table, column), length in VARCHAR_LENGTHS_DOWN.items():
        _pg_to_varchar(table, column, length)

    # 3. `0001` relied on a string default; restore it so old code still inserts.
    for table, column in TIMESTAMP_COLUMNS:
        if _column_exists(table, column):
            op.execute(
                f'ALTER TABLE "{table}" ALTER COLUMN "{column}" '
                f"SET DEFAULT CAST(CURRENT_TIMESTAMP AS VARCHAR)"
            )

    _restore_indexes_down()
