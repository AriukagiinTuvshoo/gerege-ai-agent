"""0006 — cross-column login-identity uniqueness (E-02 Phase 10, finding R16)

Revision ID: 0006_login_identity
Revises: 0005_username_uniqueness

===============================================================================
WHY THIS MIGRATION EXISTS  (findings R16a / R16b)
===============================================================================
`authenticate_client_detailed()` resolves an identifier against TWO columns:

    WHERE LOWER(TRIM(client_username)) = LOWER(?) OR LOWER(TRIM(page_id)) = LOWER(?)

Revision `0005` made usernames unique *against other usernames*. It cannot see a
username that equals another row's `page_id`, because that is a cross-row
constraint between two different columns — no index on `pages` can express it.

Measured on the Phase 9 audit (reproduced in this phase's tests):

  R16a  A page's `client_username` equals another page's `page_id`.
        Reproduced 12/12 on PostgreSQL 16 and 8/12 on SQLite, and also reachable
        with NO race at all by claiming the name before the page exists.
        `canonical_resolution_is_ambiguous()` returns True and, depending on
        page_id sort order, the shadowed tenant can no longer log in with its own
        page_id.

  R16b  Two `page_id` values differing only by case or surrounding whitespace
        (`'Alice'` / `'alice'`). They are distinct PRIMARY KEYs, so nothing
        rejects them, yet the login predicate collapses them into one identifier.

Both are one fault: the identity namespace is defined by two normalized columns
instead of one.

===============================================================================
THE INVARIANT
===============================================================================
    A normalized login identifier identifies at most one tenant,
    across both `client_username` and `page_id`.

Enforced by a projection table whose PRIMARY KEY is the identifier:

    page_login_namespace(normalized_identifier TEXT PRIMARY KEY, page_id TEXT)

plus triggers that keep it in step with `pages`.

Why this shape:

  * A PRIMARY KEY is the engine's own uniqueness authority. Two concurrent
    transactions claiming one identifier collide on the same B-tree key and the
    engine serialises them — the loser gets a constraint violation. No
    application check, no advisory lock, no SERIALIZABLE isolation. Phase 7
    already demonstrated that check-then-act is defeated 12/12 by ordinary
    concurrency on both engines.
  * Triggers mean EVERY write path is covered — `save_page`,
    `set_client_credentials`, a migration script, or an operator's psql session.
    The enforcement is not something the application has to remember.

Triggers are mandatory, not optional: a table without triggers is a stale
projection that silently permits collisions. `assert_login_identity_invariant()`
therefore requires BOTH, and the startup guard refuses to serve if either is
missing.

===============================================================================
DATA SAFETY
===============================================================================
The read-only preflight runs BEFORE any DDL. If it finds a collision the revision
aborts with the affected groups named. It never chooses a winner, never merges
accounts, never clears a username, never rewrites a `page_id` and never deletes a
row. The database is left byte-identical to its pre-migration state.
"""
from __future__ import annotations

import logging
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

from core.login_identity import (
    NAMESPACE_TABLE,
    assert_no_identifier_collisions,
    backfill_namespace_sql,
    create_table_sql,
    create_triggers_sql,
    drop_table_sql,
    drop_triggers_sql,
    namespace_is_correct,
    trigger_present,
)

logger = logging.getLogger("alembic.runtime.migration")

revision: str = "0006_login_identity"
down_revision: Union[str, None] = "0005_username_uniqueness"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _dialect_name() -> str:
    return op.get_bind().dialect.name


def _exec(sql: str) -> None:
    """Execute one statement through the DB-API surface Alembic gave us."""
    op.get_bind().exec_driver_sql(sql)


def upgrade() -> None:
    bind = op.get_bind()
    dialect = _dialect_name()

    # 1. Read-only gate, before ANY DDL. Raises `IdentifierCollisionBlocked` with the
    #    groups named; the revision then aborts and the database is untouched.
    assert_no_identifier_collisions(bind)

    # 2. Build the namespace. `IF NOT EXISTS` keeps a re-run idempotent; the content is
    #    re-derived below regardless, so a stale projection heals itself.
    _exec(create_table_sql(dialect))

    # 3. Clear and re-derive. Re-deriving rather than trusting existing rows means a
    #    table left behind by an interrupted run converges instead of ossifying.
    _exec(f"DELETE FROM {NAMESPACE_TABLE}")
    _exec(backfill_namespace_sql(dialect))

    # 4. Triggers keep it in step from now on.
    for statement in create_triggers_sql(dialect):
        _exec(statement)

    # 5. Verify the SHAPE, not the name — the Phase 8 lesson. A table without its
    #    triggers is a projection that will drift on the next write, which is worse
    #    than no table at all because it looks enforced.
    if not namespace_is_correct(bind):
        raise RuntimeError(
            f"0006: {NAMESPACE_TABLE} is absent or does not carry a PRIMARY KEY on "
            "normalized_identifier. Refusing to report success for a migration whose "
            "security invariant is not actually in force."
        )
    if not trigger_present(bind):
        raise RuntimeError(
            f"0006: {NAMESPACE_TABLE} exists but its maintenance triggers on `pages` do "
            "not. The namespace would drift on the next credential write. Refusing to "
            "report success."
        )

    rows = bind.exec_driver_sql(f"SELECT COUNT(*) FROM {NAMESPACE_TABLE}").scalar()
    logger.info(
        "0006: cross-column login-identity uniqueness installed "
        "(%s identifiers projected, triggers verified)", rows,
    )


def downgrade() -> None:
    """
    Remove the cross-column invariant.

    **This is a security downgrade.** After it, a username may once again equal
    another tenant's page_id, and two page_ids differing only in case are once
    again two tenants behind one login identifier. Both were measured as
    reproducible on both engines. It exists so a failed deploy can be reversed,
    and it logs the consequence rather than presenting itself as an ordinary
    revert.
    """
    dialect = _dialect_name()
    logger.warning(
        "0006: dropping %s and its triggers. This REMOVES cross-column login-identity "
        "uniqueness: a username may again equal another tenant's page_id, and page_ids "
        "differing only by case again collapse into one login identifier. Treat the "
        "resulting deployment as having an open R16 finding.",
        NAMESPACE_TABLE,
    )
    for statement in drop_triggers_sql(dialect):
        _exec(statement)
    _exec(drop_table_sql(dialect))
