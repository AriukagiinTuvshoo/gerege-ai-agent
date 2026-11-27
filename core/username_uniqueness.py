"""
Username uniqueness preflight and the R10 invariant it protects (E-02 Phase 8).

===============================================================================
WHY THIS EXISTS
===============================================================================
`set_client_credentials()` used to decide "is this username free?" with a `SELECT` and
then write with a separate `UPDATE`/`INSERT` on its own connection, under PostgreSQL's
default READ COMMITTED. Two tenants could both see "free" and both write. Phase 7
reproduced that: 12/12 natural-concurrency trials created duplicates on PostgreSQL 16,
and SQLite behaved the same.

The fix is **not** a better `SELECT`. It is a database-enforced invariant:

    CREATE UNIQUE INDEX uq_pages_client_username_norm
        ON pages (LOWER(TRIM(client_username)))
        WHERE client_username IS NOT NULL AND TRIM(client_username) <> '';

Two claimants can no longer both commit, because the second insert/update violates a
uniqueness constraint that the engine evaluates atomically. The application still checks
first (so the common case returns a clean conflict without an exception), but that check
is an optimisation. The index is the security boundary.

Why `LOWER(TRIM(...))` and not plain `client_username`: login matches
`LOWER(TRIM(client_username)) = LOWER(?)` (see `authenticate_client_detailed`), and the
account throttle keys on the same comparison (see `resolve_canonical_account`). A unique
index on the raw column would permit `alice` and `  ALICE  ` as separate rows while the
login path treats them as one identity — recreating the ambiguity through a different
door. The index expression is therefore deliberately identical to the login predicate.

Why the `WHERE` clause: a page may legitimately have no client username (NULL, '', or
whitespace only), and there may be many such pages. They are not login identities, so
they must not collide with each other. Verified on both engines: SQLite 3.40.1 and
PostgreSQL 16.2 permit arbitrary NULL/empty rows under this partial index while rejecting
any duplicate normalized non-empty value.

===============================================================================
WHAT THIS MODULE DOES
===============================================================================
* `normalized_username_sql()` — the single definition of the normalization expression, so
  the migration, the preflight and the tests cannot drift apart.
* `find_duplicate_usernames()` — READ-ONLY. Returns every group of pages that share one
  normalized, non-empty username. It never picks a winner and never modifies anything.
* `duplicate_report_text()` — an operator-facing rendering of the same data.
* `assert_no_duplicate_usernames()` — the migration safety gate. Raises with an actionable
  message instead of letting a unique-index creation fail with a raw engine error, and
  without ever resolving a conflict automatically.

===============================================================================
MIGRATION SAFETY POSTURE
===============================================================================
If duplicates exist, the migration **stops**. It does not choose a tenant, does not null a
column, does not merge accounts and does not delete credentials. Choosing which of two
tenants keeps a username is a business decision about a customer relationship, and it is
not one a migration is allowed to make. The operator procedure for resolving a genuine
collision is in `docs/operations/USERNAME_UNIQUENESS_MIGRATION.md`.
"""
import sqlite3
from typing import Any, Dict, List, Optional

#: The index that enforces the invariant. Referenced by the migration, the CI gate and the
#: tests, so a rename cannot silently disable the checks.
USERNAME_UNIQUE_INDEX = "uq_pages_client_username_norm"


def normalized_username_sql(column: str = "client_username") -> str:
    """
    The normalization expression, in SQL, matching the login predicate exactly.

    Kept in one place because it appears in an index definition, in a preflight query and
    in tests. If those three ever disagreed, the index would protect a different identity
    than the login path uses.
    """
    return f"LOWER(TRIM({column}))"


def username_index_where_clause(column: str = "client_username") -> str:
    """The partial-index predicate: only real, non-blank usernames participate."""
    return f"{column} IS NOT NULL AND TRIM({column}) <> ''"


def create_index_sql(
    dialect: str,
    index_name: str = USERNAME_UNIQUE_INDEX,
    table: str = "pages",
    column: str = "client_username",
) -> str:
    """
    The `CREATE UNIQUE INDEX` statement for the given dialect.

    Deliberately *not* `CONCURRENTLY`: this project's Alembic environment
    (`migrations/env.py`, `run_migrations_online`) executes every migration inside
    `context.begin_transaction()`, and PostgreSQL refuses `CREATE INDEX CONCURRENTLY`
    inside a transaction block. Emitting it would produce a migration that looks correct
    but fails at exactly the moment it matters. Index creation is therefore transactional
    and briefly locks writes to `pages`; see the operations doc for the maintenance-window
    requirement on large installations.

    `IF NOT EXISTS` makes the migration idempotent, which matters because the runner may
    retry after an unrelated failure later in the same revision.
    """
    expr = normalized_username_sql(column)
    where = username_index_where_clause(column)
    return (
        f"CREATE UNIQUE INDEX IF NOT EXISTS {index_name} "
        f"ON {table} ({expr}) WHERE {where}"
    )


def drop_index_sql(dialect: str, index_name: str = USERNAME_UNIQUE_INDEX) -> str:
    """
    The rollback statement.

    **This removes the security boundary.** Dropping the index returns the system to
    application-level check-then-act, which Phase 7 proved is racy. The `downgrade()` that
    calls this logs a warning for that reason; it exists so a failed deploy can be
    reversed, not as a safe steady state.
    """
    return f"DROP INDEX IF EXISTS {index_name}"


def _execute_fetch_all(conn, sql: str, params=None) -> List[Any]:
    """
    Run a read-only query on either a DB-API connection or a SQLAlchemy connection.

    The application uses DB-API connections (`database.get_connection()`), while Alembic
    hands a revision a SQLAlchemy `Connection`. Both must be able to run the preflight —
    that is the whole point of sharing one definition — so this adapts rather than forcing
    callers to know which kind they hold.
    """
    if hasattr(conn, "cursor"):
        cursor = conn.cursor()
        try:
            if params is None:
                cursor.execute(sql)
            else:
                cursor.execute(sql, params)
            return cursor.fetchall()
        finally:
            try:
                cursor.close()
            except Exception:
                pass
    # SQLAlchemy Connection (Alembic's `op.get_bind()`).
    result = conn.exec_driver_sql(sql, params) if params is not None else conn.exec_driver_sql(sql)
    return result.fetchall()


def find_duplicate_usernames(conn) -> List[Dict[str, Any]]:
    """
    Every group of pages sharing one normalized non-empty username. READ ONLY.

    Returns one dict per group::

        {"normalized": "alice", "page_ids": ["tenant-a", "tenant-b"], "count": 2}

    Rows whose username is NULL, empty, or whitespace-only are excluded: they are not
    login identities and the partial index deliberately ignores them, so they are not
    conflicts. This is the difference between "several pages have no username" (normal)
    and "two tenants can log in as the same name" (the defect).

    The query uses the same expression the index uses, so the preflight cannot report
    "clean" for a database the index would then reject.
    """
    expr = normalized_username_sql()
    where = username_index_where_clause()
    sql = (
        f"SELECT {expr} AS normalized, page_id FROM pages "
        f"WHERE {where} ORDER BY normalized, page_id"
    )
    rows = _execute_fetch_all(conn, sql)

    grouped: Dict[str, List[str]] = {}
    for row in rows:
        # `row` may be a tuple or a sqlite3.Row / mapping-like object.
        try:
            normalized, page_id = row[0], row[1]
        except (TypeError, IndexError):
            normalized, page_id = row["normalized"], row["page_id"]
        if normalized is None:
            continue
        grouped.setdefault(str(normalized), []).append(str(page_id))

    return [
        {"normalized": normalized, "page_ids": page_ids, "count": len(page_ids)}
        for normalized, page_ids in sorted(grouped.items())
        if len(page_ids) > 1
    ]


def duplicate_report_text(duplicates: List[Dict[str, Any]]) -> str:
    """
    Operator-facing report. Names the normalized username and the tenants involved.

    It deliberately does **not** suggest which tenant should keep the name: that requires
    knowing who the customer is, which a query cannot establish.
    """
    lines = []
    for group in duplicates:
        owners = ", ".join(repr(p) for p in group["page_ids"])
        lines.append(
            f"  username {group['normalized']!r} is claimed by {group['count']} tenants: {owners}"
        )
    return "\n".join(lines)


def assert_no_duplicate_usernames(conn) -> None:
    """
    The migration safety gate.

    Raises `UsernameUniquenessBlocked` (a RuntimeError, so Alembic aborts the revision and
    rolls back) when duplicates exist. Nothing is modified: the check runs before any DDL,
    so a blocked migration leaves the database exactly as it was.
    """
    duplicates = find_duplicate_usernames(conn)
    if duplicates:
        raise UsernameUniquenessBlocked(duplicates)


class UsernameUniquenessBlocked(RuntimeError):
    """
    Duplicate normalized usernames exist, so the unique index cannot be created.

    Subclasses RuntimeError so it aborts an Alembic revision. Carries the parsed groups so
    a caller (or a test) can inspect them without re-parsing the message.
    """

    def __init__(self, duplicates: List[Dict[str, Any]]) -> None:
        self.duplicates = duplicates
        detail = duplicate_report_text(duplicates)
        super().__init__(
            "Cannot create the unique username index: duplicate normalized usernames exist.\n"
            f"{detail}\n"
            "Each group above is a set of tenants that can currently log in as the same "
            "name, which is the ambiguity this index exists to remove.\n"
            "This migration will NOT choose a winner, merge accounts, clear a username or "
            "delete anything. Resolve each collision deliberately, with the tenant owners, "
            "then re-run the migration. Procedure:\n"
            "  docs/operations/USERNAME_UNIQUENESS_MIGRATION.md"
        )


def _dialect_of(conn) -> str:
    """
    Which SQL dialect this connection speaks: "postgresql", "sqlite", or "unknown".

    Deliberately *detected*, never probed by trial. On PostgreSQL any failing statement
    aborts the whole transaction (`current transaction is aborted, commands ignored until
    end of transaction block`), so "try it and catch the exception" is not a harmless
    technique inside a migration: it poisons the revision and every later statement fails.
    Phase 8 hit exactly that. This function therefore inspects the connection's own
    identity, which cannot fail.
    """
    # SQLAlchemy Connection (Alembic's bind) or Engine.
    dialect = getattr(conn, "dialect", None)
    name = getattr(dialect, "name", None)
    if name:
        return str(name)

    # Application DB-API connections. The type hierarchy is asked first, because it is the
    # only check that cannot be fooled by where a class happens to be defined.
    #
    # Phase 55 (F-55-9): `core.db_engine.RollbackOnCloseConnection` subclasses
    # `sqlite3.Connection`, so `type(conn).__module__` is "core.db_engine" and contains no
    # "sqlite". The `core.db_engine` fallback below was not reached either, because it sits
    # inside `if inner is not None:` and a sqlite3 subclass has no `_conn` attribute. The
    # answer was therefore "unknown", `_INDEX_DEFINITION_QUERIES` has no "unknown" entry, and
    # `describe_index` returned None - so `legacy_duplicates_allowed()` reported that it had
    # failed to restore `uq_pages_client_username_norm` after a CREATE UNIQUE INDEX that had
    # succeeded. Measured: 2 failed + 4 errors across `test_e02_phase41_hardening.py` and
    # `test_e02_phase42_admission_ownership.py`, on both dialects, because both run these
    # cases against SQLite.
    if isinstance(conn, sqlite3.Connection):
        return "sqlite"
    module = (type(conn).__module__ or "").lower()
    if "sqlite" in module:
        return "sqlite"
    if "psycopg" in module or "postgres" in module:
        return "postgresql"

    # `core.db_engine.PostgresCompatConnection` wraps a SQLAlchemy `_ConnectionFairy`, whose
    # own module is `sqlalchemy.pool.base` and which exposes no dialect. The connection is
    # therefore identified through the application's own engine selection, which is the same
    # authority `get_connection()` used to hand this object out.
    inner = getattr(conn, "_conn", None)
    if inner is not None:
        pool = getattr(inner, "dbapi_connection", None)
        dbapi_module = (type(pool).__module__ or "").lower() if pool is not None else ""
        if "psycopg" in dbapi_module or "postgres" in dbapi_module:
            return "postgresql"
        inner_module = (type(inner).__module__ or "").lower()
        if "psycopg" in inner_module or "postgres" in inner_module:
            return "postgresql"
        if "sqlite" in inner_module or "sqlite" in dbapi_module:
            return "sqlite"
        # Known application wrapper (`core.db_engine`): defer to the engine selector.
        if type(conn).__module__ == "core.db_engine":
            try:
                from core.db_engine import is_postgres

                return "postgresql" if is_postgres() else "sqlite"
            except Exception:
                return "unknown"

    # Last resort: the connection's own driver name attribute, if present.
    for attr in ("driver", "drivername"):
        value = getattr(conn, attr, None)
        if isinstance(value, str) and value:
            lowered = value.lower()
            if "postgres" in lowered or "psycopg" in lowered:
                return "postgresql"
            if "sqlite" in lowered:
                return "sqlite"
    return "unknown"


_INDEX_DEFINITION_QUERIES = {
    "postgresql": (
        "SELECT indexdef FROM pg_indexes "
        "WHERE schemaname = current_schema() AND indexname = {p}"
    ),
    "sqlite": "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = {p}",
}


def describe_index(conn, index_name: str = USERNAME_UNIQUE_INDEX) -> Optional[str]:
    """
    The engine's own definition of the index, or None when it does not exist.

    Used to prove the invariant is the *right* index, not merely one with the right name.
    A non-unique index on the raw column under this name enforces nothing, and a
    name-only check would pass it — that exact impostor was produced by
    `0002_schema_authority._sync_indexes` before Phase 8 hardened it.
    """
    dialect = _dialect_of(conn)
    template = _INDEX_DEFINITION_QUERIES.get(dialect)
    if template is None:
        return None
    sql = template.format(p=_placeholder(dialect))
    try:
        rows = _execute_fetch_all(conn, sql, (index_name,))
    except Exception:
        return None
    if not rows:
        return None
    first = rows[0]
    value = first[0] if not isinstance(first, dict) else list(first.values())[0]
    return None if value is None else str(value)


def _placeholder(dialect: str) -> str:
    """DB-API paramstyle for the detected dialect."""
    return "%s" if dialect == "postgresql" else "?"


def index_is_correct(conn, index_name: str = USERNAME_UNIQUE_INDEX) -> bool:
    """
    True only when the live index is UNIQUE, on LOWER(TRIM(...)), with the partial predicate.

    The check is on the engine's normalized definition text rather than on the name,
    because a name proves nothing. Both engines render the expression differently — SQLite
    gives ``CREATE UNIQUE INDEX name ON pages (LOWER(TRIM(client_username))) WHERE ...`` and
    PostgreSQL gives ``CREATE UNIQUE INDEX name ON public.pages USING btree (lower(TRIM(...)))
    WHERE ...`` — so the assertions are deliberately case-insensitive and whitespace-
    tolerant while still requiring every semantic component.
    """
    definition = describe_index(conn, index_name)
    if not definition:
        return False
    normalized = " ".join(definition.lower().split())
    return (
        "unique" in normalized
        and "lower" in normalized
        and "trim" in normalized
        and "where" in normalized
    )


def index_exists(conn, index_name: str = USERNAME_UNIQUE_INDEX) -> bool:
    """
    Whether any index with this name is present. Portable, dialect-detected, never probing.

    Used by the migration (idempotence) and by tests/CI (assert the invariant is installed).
    `index_is_correct` is the stronger check; this one only answers "is the name taken".
    """
    dialect = _dialect_of(conn)
    templates = {
        "postgresql": "SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = {p}",
        "sqlite": "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = {p}",
    }
    template = templates.get(dialect)
    if template is None:
        return False
    sql = template.format(p=_placeholder(dialect))
    try:
        return bool(_execute_fetch_all(conn, sql, (index_name,)))
    except Exception:
        return False


