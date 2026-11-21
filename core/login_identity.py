"""
Cross-column login-identity uniqueness (E-02 Phase 10, finding R16).

===============================================================================
THE DEFECT
===============================================================================
`authenticate_client_detailed` resolves an identifier as::

    WHERE LOWER(TRIM(client_username)) = LOWER(?) OR LOWER(TRIM(page_id)) = LOWER(?)

Two different columns, one namespace. Revision `0005` added a unique index on
`LOWER(TRIM(client_username))`, which protects usernames against *other usernames*
— but it cannot see a username that equals another row's `page_id`. The
constraint is cross-row (column A of row 1 vs column B of row 2), so no index on
`pages` alone can express it.

Two ambiguities follow:

  R16a  `pages(1).client_username == pages(2).page_id`
        A page created ahead of another can occupy the name that the later page
        will use as its page_id. `ORDER BY page_id LIMIT 1` then silently picks
        one row, so the shadowed tenant can no longer authenticate with its own
        page_id, and `canonical_resolution_is_ambiguous()` reports True.

  R16b  `page_id` differing only by case or surrounding whitespace
        `page_id` is the PRIMARY KEY, so `'Alice'` and `'alice'` are two distinct
        rows that the login predicate treats as ONE identifier. No existing
        constraint catches this either.

Both are the same underlying fault: the identity namespace is defined by two
normalized columns instead of one.

===============================================================================
THE INVARIANT
===============================================================================
**A normalized login identifier identifies at most one tenant, across both
`client_username` and `page_id`.**

===============================================================================
WHY A SEPARATE TABLE, NOT ANOTHER INDEX ON `pages`
===============================================================================
An index can only constrain values within one row's columns. The invariant is
about values *between* rows, so it needs a single namespace holding one key per
identifier:

    page_login_namespace(normalized_identifier TEXT PRIMARY KEY, page_id TEXT)

The PRIMARY KEY is the authority. Two concurrent transactions that try to claim
the same identifier collide on the same B-tree key, and the engine serialises
them — the loser gets a constraint violation, which is the correct outcome and
requires no advisory locking, no `SERIALIZABLE`, and no pre-SELECT.

This is deliberately NOT application-level locking: Phase 7 already demonstrated
that a check-then-act guard is defeated by ordinary concurrency (12/12 duplicate
rows on both engines).

===============================================================================
MAINTENANCE
===============================================================================
The table is a projection of `pages`, kept in step by triggers:

  * PostgreSQL — one trigger function, fired AFTER INSERT OR UPDATE OF
    page_id, client_username, and a DELETE trigger.
  * SQLite     — three triggers (AFTER INSERT, AFTER UPDATE, AFTER DELETE),
    since SQLite has no trigger function shared across events.

Every application write path (`save_page`, `set_client_credentials`, direct SQL,
an operator's psql session) goes through the triggers, which is why enforcement
does not depend on the application remembering to check.

A page contributes up to two identifiers (its `page_id` and its non-blank
`client_username`), deduplicated and inserted in sorted order. Sorting matters on
PostgreSQL: two transactions inserting the same *pair* of keys in opposite orders
would deadlock, so the order is made canonical inside the trigger function.

Blank usernames contribute nothing — consistent with `0005`'s partial predicate,
so credential-less pages still coexist in unlimited numbers.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

#: Name of the namespace table.
NAMESPACE_TABLE = "page_login_namespace"

#: Trigger names, kept as constants so the migration, the preflight and the tests
#: cannot drift apart.
PG_FUNCTION = "page_login_namespace_sync"
PG_TRIGGER_AIUD = "trg_page_login_namespace_aiud"
PG_TRIGGER_AD = "trg_page_login_namespace_ad"
SQLITE_TRIGGER_AI = "trg_page_login_ns_ai"
SQLITE_TRIGGER_AU = "trg_page_login_ns_au"
SQLITE_TRIGGER_AD = "trg_page_login_ns_ad"

#: Error text PostgreSQL raises when the namespace PK is violated. Used by the
#: application matcher; matching the table name is what makes it narrow.
NAMESPACE_TABLE_MARKER = NAMESPACE_TABLE

#: The normalization expression, matching the login predicate exactly. If this
#: ever disagreed with `authenticate_client_detailed`, the namespace would guard
#: a different identity than the one logins use.
def normalized_identifier_sql(column: str) -> str:
    return f"LOWER(TRIM({column}))"


def normalization_matches_login(sql: str) -> bool:
    """
    Whether a normalization expression is the one the login path uses.

    Deliberately strict: `LOWER(TRIM(x))`, in that order. `TRIM(LOWER(x))` happens
    to be equivalent for ASCII but is a different expression, and the point of
    this check is that the two definitions are the *same*, not merely compatible.
    """
    squeezed = "".join(str(sql).split()).lower()
    return squeezed == "lower(trim(" or (
        squeezed.startswith("lower(trim(") and squeezed.endswith("))")
    )


# ---------------------------------------------------------------------------
# Definition SQL
# ---------------------------------------------------------------------------
# The column types below are `VARCHAR(255)` / `VARCHAR(128)` and the primary key is
# explicitly `NOT NULL` because they must match `core.models.PageLoginNamespaceModel`
# EXACTLY. `tests/test_stage_c_schema.py` compares the schema `init_db()` builds against
# the ORM and fails on a difference, and `verify_schema_drift_reports_clean_on_a_converged_database`
# treats drift as an error. Plain `TEXT` here would silently make every future schema
# check fail -- a worse outcome than the drift it causes, because it teaches operators
# to ignore the drift report. SQLite keeps the same declared types for the same reason.
_CLASS_PAGE_ID_LEN = 128
_CLASS_IDENTIFIER_LEN = 255


def create_table_sql(dialect: str) -> str:
    """The namespace table itself. Types mirror the ORM model (see above).

    `page_id` carries a real FOREIGN KEY to `pages` with ON DELETE CASCADE, matching
    every other tenant-scoped table (P1-06, revision `0003_foreign_keys`). Two reasons:

      * `tests/test_p1_06_foreign_keys.py` asserts that *every* table with a `page_id`
        column references `pages`, so a projection without the key would either break
        that rule or force an exemption in it. The rule is load-bearing: it is what
        guarantees a deleted tenant strands no child rows.
      * it makes the cascade a database guarantee rather than a property of the trigger
        surviving a future edit.

    The triggers remain responsible for the *identifiers* (which are not the page row's
    key), and `delete_page()`'s cascade is what actually removes these rows; the
    AFTER DELETE trigger is the belt to that braces and is verified independently.
    """
    return (
        f"CREATE TABLE IF NOT EXISTS {NAMESPACE_TABLE} ("
        f" normalized_identifier VARCHAR({_CLASS_IDENTIFIER_LEN}) PRIMARY KEY NOT NULL,"
        f" page_id VARCHAR({_CLASS_PAGE_ID_LEN}) NOT NULL,"
        f" FOREIGN KEY (page_id) REFERENCES pages(page_id) ON DELETE CASCADE)"
    )


def drop_table_sql(dialect: str) -> str:
    return f"DROP TABLE IF EXISTS {NAMESPACE_TABLE}"


def drop_triggers_sql(dialect: str) -> Sequence[str]:
    """Remove the triggers. Used by the downgrade and by the repair path."""
    if dialect == "postgresql":
        return (
            f"DROP TRIGGER IF EXISTS {PG_TRIGGER_AIUD} ON pages",
            f"DROP TRIGGER IF EXISTS {PG_TRIGGER_AD} ON pages",
            f"DROP FUNCTION IF EXISTS {PG_FUNCTION}()",
        )
    return (
        f"DROP TRIGGER IF EXISTS {SQLITE_TRIGGER_AI}",
        f"DROP TRIGGER IF EXISTS {SQLITE_TRIGGER_AU}",
        f"DROP TRIGGER IF EXISTS {SQLITE_TRIGGER_AD}",
    )


def create_triggers_sql(dialect: str) -> Sequence[str]:
    """
    Create the maintenance triggers.

    PostgreSQL uses a single function because the logic is identical for INSERT,
    UPDATE and DELETE; SQLite needs one trigger body per event. Both versions
    compute the identifier set the same way.
    """
    if dialect == "postgresql":
        function = f"""
CREATE OR REPLACE FUNCTION {PG_FUNCTION}() RETURNS trigger AS $$
DECLARE
    new_id  TEXT;
    new_un  TEXT;
    old_id  TEXT;
    old_un  TEXT;
BEGIN
    IF (TG_OP = 'UPDATE' OR TG_OP = 'DELETE') THEN
        old_id := LOWER(TRIM(OLD.page_id));
        old_un := NULLIF(LOWER(TRIM(OLD.client_username)), '');
        DELETE FROM {NAMESPACE_TABLE}
         WHERE page_id = OLD.page_id
           AND (normalized_identifier = old_id
                OR normalized_identifier = COALESCE(old_un, '\\x00'));
    END IF;

    IF (TG_OP = 'UPDATE' OR TG_OP = 'INSERT') THEN
        new_id := LOWER(TRIM(NEW.page_id));
        new_un := NULLIF(LOWER(TRIM(NEW.client_username)), '');
        INSERT INTO {NAMESPACE_TABLE} (normalized_identifier, page_id)
        SELECT k, NEW.page_id
          FROM (SELECT new_id AS k
                UNION
                SELECT new_un) AS keys
         WHERE k IS NOT NULL AND k <> ''
         ORDER BY k;
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql
"""
        trigger = f"""
CREATE TRIGGER {PG_TRIGGER_AIUD}
AFTER INSERT OR UPDATE OF page_id, client_username OR DELETE ON pages
FOR EACH ROW EXECUTE FUNCTION {PG_FUNCTION}()
"""
        return (function, trigger)

    # SQLite. `RAISE(ABORT, ...)` is not needed: the PK violation propagates.
    ai = f"""
CREATE TRIGGER {SQLITE_TRIGGER_AI}
AFTER INSERT ON pages
BEGIN
    INSERT INTO {NAMESPACE_TABLE} (normalized_identifier, page_id)
        SELECT LOWER(TRIM(NEW.page_id)), NEW.page_id
         WHERE LOWER(TRIM(NEW.page_id)) <> '';
    INSERT INTO {NAMESPACE_TABLE} (normalized_identifier, page_id)
        SELECT LOWER(TRIM(NEW.client_username)), NEW.page_id
         WHERE NEW.client_username IS NOT NULL
           AND LOWER(TRIM(NEW.client_username)) <> ''
           AND LOWER(TRIM(NEW.client_username)) <> LOWER(TRIM(NEW.page_id));
END
"""
    au = f"""
CREATE TRIGGER {SQLITE_TRIGGER_AU}
AFTER UPDATE OF page_id, client_username ON pages
BEGIN
    -- Remove only THIS page's claims, so a page keeping its own identifier does not
    -- collide with itself, while another page's claim of the same key is untouched and
    -- will block the INSERT below.
    DELETE FROM {NAMESPACE_TABLE} WHERE page_id = OLD.page_id;
    DELETE FROM {NAMESPACE_TABLE} WHERE page_id = NEW.page_id;
    INSERT INTO {NAMESPACE_TABLE} (normalized_identifier, page_id)
        SELECT LOWER(TRIM(NEW.page_id)), NEW.page_id
         WHERE LOWER(TRIM(NEW.page_id)) <> '';
    INSERT INTO {NAMESPACE_TABLE} (normalized_identifier, page_id)
        SELECT LOWER(TRIM(NEW.client_username)), NEW.page_id
         WHERE NEW.client_username IS NOT NULL
           AND LOWER(TRIM(NEW.client_username)) <> ''
           AND LOWER(TRIM(NEW.client_username)) <> LOWER(TRIM(NEW.page_id));
END
"""
    ad = f"""
CREATE TRIGGER {SQLITE_TRIGGER_AD}
AFTER DELETE ON pages
BEGIN
    DELETE FROM {NAMESPACE_TABLE} WHERE page_id = OLD.page_id;
END
"""
    return (ai, au, ad)


# ---------------------------------------------------------------------------
# Read-only preflight
# ---------------------------------------------------------------------------
def find_identifier_collisions(conn) -> list[dict[str, Any]]:
    """
    Every normalized identifier claimed by more than one tenant. READ-ONLY.

    Computed from `pages` directly rather than from the namespace table, so it
    works on a database where the triggers do not exist yet (which is exactly the
    migration's situation) and so it cannot be fooled by a stale projection.

    Never chooses a winner and never writes.

    Grouping is done in Python, not with `GROUP_CONCAT`, for two reasons: the
    function is spelled `STRING_AGG` on PostgreSQL, and the delimiter would
    corrupt a page_id containing a comma. The page set is bounded by the number
    of rows claiming one identifier, which is small by construction — a large set
    here is itself the finding.
    """
    from core.username_uniqueness import _execute_fetch_all, normalized_username_sql

    ident = normalized_username_sql
    sql = (
        "SELECT k, p FROM ("
        f"  SELECT {ident('page_id')} AS k, page_id AS p FROM pages WHERE TRIM(page_id) <> ''"
        "   UNION"
        f"  SELECT {ident('client_username')} AS k, page_id AS p FROM pages"
        "    WHERE client_username IS NOT NULL AND TRIM(client_username) <> ''"
        ") AS ident ORDER BY k"
    )
    owners: dict[str, set[str]] = {}
    for row in _execute_fetch_all(conn, sql, ()):
        key, page_id = row[0], row[1]
        if key is None or key == "":
            continue
        owners.setdefault(str(key), set()).add(str(page_id))

    return [
        {"normalized": key, "count": len(pids), "page_ids": sorted(pids)}
        for key, pids in sorted(owners.items())
        if len(pids) > 1
    ]


def collision_report_text(groups: Iterable[Mapping[str, Any]]) -> str:
    """Operator-facing rendering of `find_identifier_collisions`."""
    lines = [
        "Login identifiers must identify exactly one tenant across BOTH columns.",
        "These normalized identifiers are claimed by more than one page:",
    ]
    for i, g in enumerate(groups, 1):
        owners = "', '".join(g["page_ids"])
        kind = _collision_kind(g)
        lines.append(f"  {i}. '{g['normalized']}' is claimed by {g['count']} pages: '{owners}'  [{kind}]")
    return "\n".join(lines)


def _collision_kind(group: Mapping[str, Any]) -> str:
    """Classify the collision to make the operator's decision obvious."""
    return "two pages share one identifier (username/page_id or page_id casing)"


def assert_no_identifier_collisions(conn) -> None:
    """
    Migration safety gate. Raises instead of letting a trigger creation or a
    backfill fail with a raw engine error, and never modifies a row.
    """
    groups = find_identifier_collisions(conn)
    if groups:
        raise IdentifierCollisionBlocked(groups)


class IdentifierCollisionBlocked(RuntimeError):
    """Raised when existing data makes the cross-column invariant unenforceable."""

    def __init__(self, groups: Sequence[Mapping[str, Any]]):
        self.groups = list(groups)
        super().__init__(
            "Cannot enforce cross-column login uniqueness: the same normalized "
            "identifier is already claimed by more than one page.\n"
            f"{collision_report_text(self.groups)}\n"
            "This will NOT choose a winner, merge accounts, clear a username, "
            "rewrite a page_id or delete anything.\n"
            "Resolve each group deliberately, with the tenant owners, then re-run. "
            "Procedure: docs/operations/USERNAME_UNIQUENESS_MIGRATION.md"
        )


# ---------------------------------------------------------------------------
# Backfill (used by the migration, after the gate has passed)
# ---------------------------------------------------------------------------
def backfill_namespace_sql(dialect: str) -> str:
    """
    Populate the namespace from `pages`.

    Runs only after `assert_no_identifier_collisions` has returned cleanly, and
    inserts in sorted order for the same deadlock-avoidance reason as the trigger.
    """
    ident = normalized_identifier_sql
    return (
        f"INSERT INTO {NAMESPACE_TABLE} (normalized_identifier, page_id) "
        f"SELECT k, p FROM ("
        f"  SELECT {ident('page_id')} AS k, page_id AS p FROM pages WHERE TRIM(page_id) <> ''"
        f"  UNION"
        f"  SELECT {ident('client_username')} AS k, page_id AS p FROM pages"
        f"   WHERE client_username IS NOT NULL AND TRIM(client_username) <> ''"
        f") AS keys WHERE k IS NOT NULL AND k <> '' ORDER BY k"
    )


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
def table_present(conn, name: str) -> bool:
    """Whether any table by this name exists. Used to tell "un-migrated" from "broken"."""
    from core.username_uniqueness import _dialect_of, _execute_fetch_all

    dialect = _dialect_of(conn)
    try:
        if dialect == "postgresql":
            rows = _execute_fetch_all(conn, "SELECT to_regclass(%s)", (name,))
            return bool(rows) and rows[0][0] is not None
        if dialect == "sqlite":
            rows = _execute_fetch_all(
                conn, "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
            )
            return bool(rows)
    except Exception:
        return False
    return False


def namespace_present(conn) -> bool:
    """Whether the projection table exists at all, independent of its contents.

    Separate from `namespace_is_correct()` because the repair tool has to tell an
    operator *which* half is missing: "table absent" is a very different repair from
    "table present but stale" and from "table correct but triggers gone". Collapsing
    them into one boolean produces an error message that cannot be acted on.
    """
    from core.username_uniqueness import _dialect_of, _execute_fetch_all

    dialect = _dialect_of(conn)
    try:
        if dialect == "postgresql":
            rows = _execute_fetch_all(
                conn, "SELECT to_regclass(%s)", (NAMESPACE_TABLE,)
            )
            return bool(rows) and rows[0][0] is not None
        if dialect == "sqlite":
            rows = _execute_fetch_all(
                conn,
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (NAMESPACE_TABLE,),
            )
            return bool(rows)
    except Exception:
        return False
    return False


def namespace_is_correct(conn, expected_rows: int | None = None) -> bool:
    """
    Whether the namespace exists, carries a PRIMARY KEY, and (optionally) holds
    the expected number of identifiers.

    Shape-checked rather than name-checked: Phase 8 established that a
    right-named look-alike enforces nothing, and the same trap applies here.
    """
    from core.username_uniqueness import _dialect_of, _execute_fetch_all, _placeholder

    dialect = _dialect_of(conn)
    if dialect == "postgresql":
        sql = (
            "SELECT 1 FROM pg_constraint c"
            " JOIN pg_class t ON t.oid = c.conrelid"
            " WHERE t.relname = %s AND c.contype = 'p'"
        )
    elif dialect == "sqlite":
        sql = (
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?"
            " AND sql LIKE '%PRIMARY KEY%'"
        )
    else:
        return False
    try:
        if not _execute_fetch_all(conn, sql, (NAMESPACE_TABLE,)):
            return False
        if expected_rows is not None:
            rows = _execute_fetch_all(
                conn,
                f"SELECT COUNT(*) FROM {NAMESPACE_TABLE}",
                (),
            )
            if not rows or int(rows[0][0]) != expected_rows:
                return False
        return True
    except Exception:
        return False


def trigger_present(conn) -> bool:
    """Whether the maintenance triggers exist (all of them, per dialect)."""
    from core.username_uniqueness import _dialect_of, _execute_fetch_all

    dialect = _dialect_of(conn)
    try:
        if dialect == "postgresql":
            rows = _execute_fetch_all(
                conn,
                "SELECT tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid"
                " WHERE c.relname = 'pages' AND NOT t.tgisinternal",
                (),
            )
            names = {r[0] for r in rows}
            return PG_TRIGGER_AIUD in names
        if dialect == "sqlite":
            rows = _execute_fetch_all(
                conn,
                "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='pages'",
                (),
            )
            names = {r[0] for r in rows}
            return {SQLITE_TRIGGER_AI, SQLITE_TRIGGER_AU, SQLITE_TRIGGER_AD} <= names
    except Exception:
        return False
    return False


_VIOLATION_MARKERS = (
    NAMESPACE_TABLE,
    "page_login_namespace_pkey",
    "uq_page_login_namespace",
)


def is_identifier_violation(exc: BaseException) -> bool:
    """True when `exc` is the namespace table refusing a cross-column collision.

    The check is deliberately narrow. Callers use it to turn a raw driver
    `IntegrityError` into a 409 instead of a 500, and a false positive would
    mislabel an unrelated constraint failure (for example a duplicate primary
    key on `pages`) as an identity conflict.

    Both engines name the table or the constraint in the message:
      SQLite   "UNIQUE constraint failed: page_login_namespace.normalized_identifier"
      psycopg2 'duplicate key value violates unique constraint "page_login_namespace_pkey"'
    but this is a *message* match and therefore a convenience, not the
    enforcement. The enforcement is the PRIMARY KEY itself; this only shapes
    the HTTP response for a request that has already been refused.
    """
    if not isinstance(exc, Exception):
        return False
    text = str(exc)
    return any(marker in text for marker in _VIOLATION_MARKERS)
