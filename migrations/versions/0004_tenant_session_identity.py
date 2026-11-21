"""0004 — tenant-scoped session identity (E-01)

Revision ID: 0004_tenant_session_identity
Revises: 0003_foreign_keys

===============================================================================
WHY THIS MIGRATION EXISTS  (finding E-01, P0)
===============================================================================
`session_states` was keyed on `sender_id` alone. A single customer who contacts two
businesses produces the same sender ID in both, so the row was reassigned to whichever
tenant spoke last. Consequences, all reproduced through the public HTTP API:

  * tenant B was shown the customer phone number and name tenant A collected;
  * tenant A's conversation disappeared from tenant A's own dashboard;
  * message counts and human-takeover state were shared across tenants.

This revision changes the primary key to `(page_id, sender_id)`, so the storage layer —
not just application queries — guarantees the isolation.

===============================================================================
DATA SAFETY
===============================================================================
`page_id` is NOT NULL in `models.py`, but the legacy `0001` schema declared it nullable
(the default was only a server default). So the first step backfills NULL owners and the
resulting constraint is stricter than before.

**The original row cannot be split.** When two tenants genuinely shared one `sender_id`,
the old primary key stored exactly one row and the other tenant's phone/name were already
overwritten — that information no longer exists in the database. This migration therefore
cannot restore it, and it will not invent an owner for it either:

    it derives the owner from the tenant's own `messages` when they all agree,
    and STOPS with a named report when they disagree.

Silently assigning a guess would move one tenant's data into the other's account. Stopping
is the only safe behaviour, and the report names the affected sender IDs so an operator can
resolve them deliberately.

Nothing is dropped: no column is removed and no row is deleted. On SQLite the table is
rebuilt by Alembic's batch mode, which copies every row through the datetime transfer shim
(without it, batch mode truncates timestamps — see `migrations/sqlite_compat.py`).

===============================================================================
ROLLBACK
===============================================================================
`downgrade()` restores the single-column primary key. It refuses to run when two tenants
hold a row for the same sender, because collapsing them would destroy data.
"""
import logging
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

from migrations.sqlite_compat import install_sqlite_datetime_transfer_patch

logger = logging.getLogger("migrations.0004")

revision: str = "0004_tenant_session_identity"
down_revision: Union[str, None] = "0003_foreign_keys"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

#: Fallback owner for rows whose `page_id` was never set and which have no messages.
DEFAULT_PAGE_ID = "100799479495809"


def _primary_key_name() -> Union[str, None]:
    """
    Real name of the existing primary key, or None when the table never had one.

    `0001` created the SQLite table with an inline `PRIMARY KEY (sender_id)` and no
    `CONSTRAINT` clause, so the catalog reports `name: NULL`. Assuming a name raises
    `ValueError: No such constraint` — discovered by running the migration, not from
    reading the docs.
    """
    inspector = sa.inspect(op.get_bind())
    return inspector.get_pk_constraint("session_states").get("name")


def _is_sqlite() -> bool:
    return op.get_bind().dialect.name == "sqlite"


def _primary_key_columns() -> list[str]:
    """Current PK columns, read from the live catalog rather than assumed."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    for pk in inspector.get_pk_constraint("session_states").get("constrained_columns") or []:
        pass
    return list(inspector.get_pk_constraint("session_states").get("constrained_columns") or [])


def _backfill_null_page_ids() -> None:
    bind = op.get_bind()
    nulls = bind.execute(
        sa.text("SELECT COUNT(*) FROM session_states WHERE page_id IS NULL")
    ).scalar()
    if not nulls:
        return
    logger.warning(
        "%s session_states row(s) had no page_id; cannot infer the tenant.", nulls
    )
    bind.execute(
        sa.text(
            "UPDATE session_states SET page_id = :d WHERE page_id IS NULL"
        ),
        {"d": DEFAULT_PAGE_ID},
    )


def _ambiguous_senders() -> list[tuple[str, str]]:
    """
    sender IDs whose stored `page_id` disagrees with the tenants that actually messaged them.

    If every message for a sender belongs to one tenant, that tenant is the owner and the
    stored value can be corrected with confidence. If messages come from several tenants
    there is no defensible single owner, and the migration must stop.
    """
    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            """
            SELECT s.sender_id,
                   s.page_id                                       AS stored_page,
                   COUNT(DISTINCT m.page_id)                        AS tenant_count,
                   MIN(m.page_id)                                   AS only_tenant
              FROM session_states s
              JOIN messages m ON m.sender_id = s.sender_id
             GROUP BY s.sender_id, s.page_id
            """
        )
    ).fetchall()
    problems: list[tuple[str, str]] = []
    for sender_id, stored_page, tenant_count, only_tenant in rows:
        if tenant_count and int(tenant_count) > 1:
            problems.append((str(sender_id), f"{int(tenant_count)} tenants: messages span several page_id values"))
        elif only_tenant and str(only_tenant) != str(stored_page):
            # Unambiguous: all messages agree, so the stored value is simply stale.
            bind.execute(
                sa.text("UPDATE session_states SET page_id = :p WHERE sender_id = :s"),
                {"p": str(only_tenant), "s": str(sender_id)},
            )
    return problems


def _assert_no_duplicate_identity() -> None:
    bind = op.get_bind()
    dupes = bind.execute(
        sa.text(
            """
            SELECT sender_id, page_id, COUNT(*) AS n
              FROM session_states
             GROUP BY sender_id, page_id
            HAVING COUNT(*) > 1
            """
        )
    ).fetchall()
    if dupes:
        detail = "\n  - ".join(f"sender_id={s!r} page_id={p!r}: {n} rows" for s, p, n in dupes)
        raise RuntimeError(
            "Cannot create the (page_id, sender_id) primary key: duplicate rows exist.\n"
            f"  - {detail}\n"
            "Resolve these rows deliberately before migrating."
        )


def upgrade() -> None:
    existing_pk = _primary_key_columns()
    if existing_pk == ["page_id", "sender_id"] or set(existing_pk) == {"page_id", "sender_id"}:
        logger.info("0004: session_states already uses the tenant-scoped primary key")
        return

    _backfill_null_page_ids()

    ambiguous = _ambiguous_senders()
    if ambiguous:
        detail = "\n  - ".join(f"sender_id={s!r} ({reason})" for s, reason in ambiguous)
        raise RuntimeError(
            "Cannot make session identity tenant-scoped: these sender IDs belong to more "
            "than one tenant and the correct owner cannot be determined.\n"
            f"  - {detail}\n"
            "The original single-tenant row no longer contains the other tenant's data, so "
            "this migration cannot restore it and will not guess an owner.\n"
            "Resolve these senders (e.g. re-key them per tenant) and re-run the migration."
        )

    _assert_no_duplicate_identity()

    bind = op.get_bind()
    # Enforce NOT NULL so the composite key is well defined.
    bind.execute(
        sa.text("UPDATE session_states SET page_id = :d WHERE page_id IS NULL"),
        {"d": DEFAULT_PAGE_ID},
    )

    if _is_sqlite():
        install_sqlite_datetime_transfer_patch()
        pk_name = _primary_key_name()
        with op.batch_alter_table("session_states", recreate="always") as batch:
            if pk_name:
                batch.drop_constraint(pk_name, type_="primary")
            batch.alter_column("page_id", existing_type=sa.String(128), nullable=False)
            batch.create_primary_key("pk_session_states", ["page_id", "sender_id"])
    else:
        pk_name = _primary_key_name() or "session_states_pkey"
        op.execute(f'ALTER TABLE session_states DROP CONSTRAINT IF EXISTS "{pk_name}"')
        op.alter_column("session_states", "page_id", existing_type=sa.String(128), nullable=False)
        op.create_primary_key("pk_session_states", "session_states", ["page_id", "sender_id"])

    logger.info("0004: session_states primary key is now (page_id, sender_id)")


def downgrade() -> None:
    bind = op.get_bind()
    collisions = bind.execute(
        sa.text(
            """
            SELECT sender_id, COUNT(*) AS n
              FROM session_states
             GROUP BY sender_id
            HAVING COUNT(*) > 1
            """
        )
    ).fetchall()
    if collisions:
        detail = "\n  - ".join(f"sender_id={s!r}: {n} tenants" for s, n in collisions)
        raise RuntimeError(
            "Cannot downgrade to a sender-only primary key: several tenants hold a row for "
            "the same sender, and collapsing them would destroy data.\n"
            f"  - {detail}\n"
            "This is intentional. Remove or merge those sessions deliberately first."
        )

    if _is_sqlite():
        install_sqlite_datetime_transfer_patch()
        pk_name = _primary_key_name()
        with op.batch_alter_table("session_states", recreate="always") as batch:
            if pk_name:
                batch.drop_constraint(pk_name, type_="primary")
            batch.alter_column("page_id", existing_type=sa.String(128), nullable=True)
            batch.create_primary_key("pk_session_states", ["sender_id"])
    else:
        op.execute(f'ALTER TABLE session_states DROP CONSTRAINT IF EXISTS "{( _primary_key_name() or "pk_session_states")}"')
        op.alter_column("session_states", "page_id", existing_type=sa.String(128), nullable=True)
        op.create_primary_key("pk_session_states", "session_states", ["sender_id"])
    logger.info("0004: reverted session_states primary key to (sender_id)")
