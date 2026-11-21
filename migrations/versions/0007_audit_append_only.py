"""0007 — append-only audit trail (Phase 13, finding F-D)

Revision ID: 0007_audit_append_only
Revises: 0006_login_identity

===============================================================================
WHY THIS MIGRATION EXISTS
===============================================================================
A scan of every tracked write path found exactly one `INSERT` and two `SELECT`s
against `audit_logs` — and **no application code that updates or deletes an audit
row**. The defect was never in the application: it was that nothing in the database
refused the statement.

Phase 12 measured the baseline; Phase 13 re-measured it before changing anything:

    app-level UPDATE audit_logs   -> SUCCEEDED   (SQLite and PostgreSQL 16)
    app-level DELETE FROM ...     -> SUCCEEDED   (SQLite and PostgreSQL 16)
    triggers on audit_logs        -> 0

That matters because for three actions the audit row is the only durable record of
an irreversible act: `payment.confirmed`, `page.credentials.updated` and
`page.delete`. The invoice proves money moved, not that a verified confirmation was
audited; `pages.client_magic_token` holds only the *current* token; and the page row
is gone after a tenant deletion.

===============================================================================
WHAT THIS REVISION DOES
===============================================================================
Strictly additive DDL. No column change, no constraint change, no data change.

  PostgreSQL: one `plpgsql` guard function, and three triggers —
                BEFORE UPDATE   FOR EACH ROW
                BEFORE DELETE   FOR EACH ROW
                BEFORE TRUNCATE FOR EACH STATEMENT

  SQLite:     two triggers — BEFORE UPDATE, BEFORE DELETE.

`TRUNCATE` gets its own statement-level trigger because a row-level `BEFORE DELETE`
trigger **does not fire on `TRUNCATE`**. Measured in Phase 13: `DELETE FROM` was
refused while `TRUNCATE` emptied the table. A row-trigger-only protection leaves a
one-command hole.

`INSERT` is never guarded on purpose: the audit table must stay writable. Only
mutation of what has already been written is refused.

===============================================================================
THE ONE PERMITTED UPDATE
===============================================================================
The guard is NOT a blanket `BEFORE UPDATE`. `audit_logs.page_id` is
`ON DELETE SET NULL`, and the engine implements that foreign-key action as an
`UPDATE `on this table. A blanket trigger therefore refuses the retention action and
**breaks tenant deletion outright** — measured on both engines before this was
corrected (`delete_page()` raised `IntegrityError` on SQLite and
`InsufficientPrivilege` on PostgreSQL), which would have regressed the R18 contract
Phase 11 established.

The trigger admits one exact shape and nothing else: `page_id` going NULL while the
referenced `pages` row is already gone, with **every other column unchanged**. A
direct `UPDATE ... SET page_id = NULL` against a live tenant is still refused, and so
is `SET action = 'FAKE'`, alone or combined with a NULL `page_id`. The permission
removes information the row already conceded; it never changes what the row asserts
happened.

===============================================================================
WHAT THIS DOES *NOT* PROTECT
===============================================================================
This is tamper *resistance*, not tamper *evidence*.

The documented production deployment connects as `POSTGRES_USER`, which owns these
tables and was measured to be a superuser. That role can `DISABLE TRIGGER ALL`,
`SET session_replication_role = replica`, or `DROP TRIGGER` — all three measured to
bypass this guard. Database-owner compromise and backup/storage tampering are
therefore **out of scope for any in-database mechanism** and require a non-owner
runtime role plus external anchoring (separate design).

===============================================================================
RESTORE SAFETY — verified, not assumed
===============================================================================
`core/backup_service.py` restores PostgreSQL with `pg_dump --clean --if-exists`.
That dump emits the guard's own DDL:

    DROP TRIGGER IF EXISTS ... ; DROP TABLE IF EXISTS public.audit_logs;
    CREATE TABLE ... ; COPY ... FROM stdin;
    CREATE TRIGGER ... (all three, again)

so a restore **recreates the protection** and never issues a `DELETE`/`TRUNCATE`
that the guard would refuse. Measured in Phase 13: a dump of a protected table,
re-applied to itself, restored every row and left all three triggers installed.

SQLite backups use `sqlite3.Connection.backup()`, a page-level copy that carries the
schema — including triggers — with it.

===============================================================================
DOWNGRADE
===============================================================================
Drops exactly what `upgrade()` created, in reverse dependency order. **Every audit
row survives untouched** — dropping a trigger is not a data operation. Downgrading
does remove the protection, which is inherent to any reversible DDL and is stated
plainly rather than glossed: a downgrade is a deliberate act by someone who already
has DDL rights.
"""
import logging
from typing import Sequence, Union

from alembic import op

from core.audit_integrity import create_sql, drop_sql, guard_is_correct

logger = logging.getLogger("alembic.runtime.migration")

revision: str = "0007_audit_append_only"
down_revision: Union[str, None] = "0006_login_identity"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _dialect_name() -> str:
    return op.get_bind().dialect.name


def _exec(sql: str) -> None:
    """Execute one statement through the DB-API surface Alembic gave us."""
    op.get_bind().exec_driver_sql(sql)


def upgrade() -> None:
    dialect = _dialect_name()

    # The DDL is idempotent (`DROP ... IF EXISTS` precedes each `CREATE`), so a
    # revision that was interrupted midway converges on re-run instead of failing on
    # a half-created object.
    for statement in create_sql(dialect):
        _exec(statement)

    # Verify the SHAPE, not the name — the Phase 8 lesson. An object can exist under
    # the expected name while enforcing nothing, and a guard that *looks* installed is
    # worse than an absent one because nobody re-checks it.
    bind = op.get_bind()
    if not guard_is_correct(bind):
        raise RuntimeError(
            f"0007: the audit_logs append-only guard is not in force on {dialect}. "
            "Refusing to report success for a migration whose security invariant is "
            "not actually installed."
        )

    logger.info(
        "0007: audit_logs is append-only on %s (UPDATE%s rejected)", dialect,
        ", DELETE, TRUNCATE" if dialect == "postgresql" else " and DELETE",
    )


def downgrade() -> None:
    dialect = _dialect_name()

    # Triggers first, then the function they depend on. `IF EXISTS` throughout, so a
    # partially-applied upgrade can still be rolled back.
    for statement in drop_sql(dialect):
        _exec(statement)

    logger.warning(
        "0007 downgraded: audit_logs is MUTABLE again on %s. Audit rows are intact; "
        "the protection is not. This is a deliberate act and should be recorded.",
        dialect,
    )
