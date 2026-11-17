"""0005 — database-enforced username uniqueness (E-02 Phase 8, finding R10)

Revision ID: 0005_username_uniqueness
Revises: 0004_tenant_session_identity

===============================================================================
WHY THIS MIGRATION EXISTS  (finding R10, High)
===============================================================================
`set_client_credentials()` decided whether a username was free with a `SELECT`, then wrote
with a separate `UPDATE`/`INSERT` on its own connection. Under PostgreSQL's default READ
COMMITTED — and under SQLite's per-connection deferred transactions — two tenants could
both observe "free" and both commit. Phase 7 reproduced the result deterministically:

  * PostgreSQL 16.2: 12/12 natural-concurrency trials created duplicate usernames;
  * SQLite 3.40.1: 12/12 trials;
  * four concurrent claimants produced four rows holding one normalized username.

A duplicate is not cosmetic. Login, the account failed-login throttle and
`resolve_canonical_account()` all treat `LOWER(TRIM(client_username))` as the identity, so
two rows sharing one normalized name means:

  * "who is this identifier?" is answered by `ORDER BY page_id LIMIT 1` — deterministic but
    arbitrary, and the loser cannot log in with their own username at all;
  * the two tenants share one failure budget, so one tenant's failed logins can throttle
    the other out of its own account.

Phase 6 fixed the *sequential* form of this by refusing a cross-tenant username. This
revision fixes the *concurrent* form by making the database the authority. No application
check can be, because it is separated from the write.

===============================================================================
THE INVARIANT
===============================================================================
    CREATE UNIQUE INDEX uq_pages_client_username_norm
        ON pages (LOWER(TRIM(client_username)))
        WHERE client_username IS NOT NULL AND TRIM(client_username) <> '';

* The expression is byte-for-byte the comparison the login path performs
  (`core/username_uniqueness.normalized_username_sql`), so the index protects exactly the
  identity the application treats as unique.
* The predicate excludes NULL / empty / whitespace-only usernames. Pages without a client
  login are not identities, and there may be arbitrarily many of them. Verified on both
  engines: those rows never collide under this index.
* SQLite 3.40.1 and PostgreSQL 16.2 both support expression + partial indexes; both reject
  a duplicate and both permit multiple blank rows.

===============================================================================
DATA SAFETY  (the reason this migration can refuse to run)
===============================================================================
Creating the index on a database that already contains duplicates would fail with a raw
engine error and no guidance. Worse, "make it fit" tempts an automatic resolution — null
one tenant's username, merge two accounts, delete a row.

**This revision will not do that.** It runs a read-only preflight
(`core.username_uniqueness.find_duplicate_usernames`) before any DDL and, if any group
exists, aborts with a report naming the normalized username and the affected `page_id`s.

Choosing which of two tenants keeps a login name decides who can access which customer
account. That is a business decision made with the tenant owners, not a migration step, and
silently picking a winner would convert a security fix into a data-loss incident. The
operator procedure is `docs/operations/USERNAME_UNIQUENESS_MIGRATION.md`.

Nothing is deleted, merged or rewritten by this revision in any case.

===============================================================================
TRANSACTIONAL EXECUTION  (why there is no CONCURRENTLY)
===============================================================================
`migrations/env.py::run_migrations_online` runs every revision inside
`context.begin_transaction()`. PostgreSQL rejects `CREATE INDEX CONCURRENTLY` inside a
transaction block, so a `CONCURRENTLY` variant would look correct and fail on deploy. The
index is therefore created transactionally. Consequences, stated plainly:

  * on PostgreSQL, `CREATE UNIQUE INDEX` takes a `SHARE` lock on `pages` for the duration,
    blocking writes (not reads) to that one table. It is fast at this table's size; large
    installations should create it during a maintenance window. See the operations doc.
  * on SQLite, the statement runs inside the migration's transaction like any other DDL.

`IF NOT EXISTS` makes the revision idempotent, so a retry after a later failure does not
fail on the index itself.
"""
import logging
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

from core.username_uniqueness import (
    USERNAME_UNIQUE_INDEX,
    assert_no_duplicate_usernames,
    create_index_sql,
    describe_index,
    drop_index_sql,
    index_exists,
    index_is_correct,
)

logger = logging.getLogger("alembic.runtime.migration")

revision: str = "0005_username_uniqueness"
down_revision: Union[str, None] = "0004_tenant_session_identity"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _dialect_name() -> str:
    return op.get_bind().dialect.name


def upgrade() -> None:
    bind = op.get_bind()

    if index_is_correct(bind, USERNAME_UNIQUE_INDEX):
        # Idempotent: a previous run already installed the correct invariant.
        logger.info("0005: correct unique index %s already present", USERNAME_UNIQUE_INDEX)
        return

    if index_exists(bind, USERNAME_UNIQUE_INDEX):
        # Something owns this name but is not the invariant (e.g. the pre-Phase-8
        # `_sync_indexes` impostor: a NON-unique index on the raw column). Creating with
        # IF NOT EXISTS would silently leave that in place, so it must be removed first.
        # Safe: a wrong-shaped index enforces nothing, so dropping it loses no guarantee.
        logger.warning(
            "0005: an index named %s exists but is not the uniqueness invariant (%s); "
            "replacing it",
            USERNAME_UNIQUE_INDEX,
            describe_index(bind, USERNAME_UNIQUE_INDEX),
        )
        op.execute(sa.text(drop_index_sql(_dialect_name())))

    # Read-only safety gate FIRST, before any DDL. If this raises, the revision aborts and
    # the database is untouched — no partial index, no changed rows.
    assert_no_duplicate_usernames(bind)

    # Confirm the gate agrees with what the engine will accept. If a duplicate were created
    # between the preflight and the DDL (possible on a live database, since the preflight is
    # not serializable with respect to concurrent credential writes), the CREATE below fails
    # and the whole revision rolls back — which is the correct outcome: no index, no change,
    # and an error an operator can act on.
    dialect = _dialect_name()
    op.execute(sa.text(create_index_sql(dialect)))

    # Verify the SHAPE, not the name. A migration that reports success while the invariant
    # is absent (or is a look-alike that enforces nothing) is worse than one that fails.
    if not index_is_correct(bind, USERNAME_UNIQUE_INDEX):
        raise RuntimeError(
            f"0005: {USERNAME_UNIQUE_INDEX} is absent or is not a UNIQUE index on "
            "LOWER(TRIM(client_username)) with the partial predicate. "
            f"Found: {describe_index(bind, USERNAME_UNIQUE_INDEX)!r}. "
            "Refusing to report success for a migration whose security invariant is not "
            "actually in force."
        )

    logger.info("0005: created unique index %s on LOWER(TRIM(client_username))",
                USERNAME_UNIQUE_INDEX)


def downgrade() -> None:
    """
    Drop the index.

    **This is a security downgrade**, not a neutral rollback: it returns credential writes
    to application-level check-then-act, which Phase 7 proved is racy (12/12 duplicate
    creation on both engines). It exists so a failed deploy can be reversed, and it logs
    that consequence loudly rather than presenting itself as an ordinary revert.
    """
    bind = op.get_bind()
    if not index_exists(bind, USERNAME_UNIQUE_INDEX):
        logger.info("0005: %s is already absent", USERNAME_UNIQUE_INDEX)
        return

    logger.warning(
        "0005: dropping %s. This REMOVES the database-enforced username uniqueness "
        "guarantee: concurrent tenants can once again claim the same normalized username. "
        "Treat the resulting deployment as having an open R10 finding.",
        USERNAME_UNIQUE_INDEX,
    )
    op.execute(sa.text(drop_index_sql(_dialect_name())))
