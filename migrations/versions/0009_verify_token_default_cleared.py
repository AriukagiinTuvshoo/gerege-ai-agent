"""0009 — the schema must not hand out a published verify token (Phase 52, item B1)

Revision ID: 0009_verify_token_default
Revises: 0008_tenant_not_null

===============================================================================
WHY THIS MIGRATION EXISTS
===============================================================================
`0001` created `pages.verify_token` with

    server_default="agent_verify_secret_token_123"

That string is printed in this repository. It was also the `core/models.py` column default,
the value `database.init_db()` inserted for the default page on a first boot, and
`database.save_page`'s parameter default. Four independent paths, one published value.

Phase 45 (F-44-B) closed the *read* side of this defect: `core.security` gained
`PUBLIC_VERIFY_TOKEN_PLACEHOLDER`, `meta_verify_token_is_placeholder()` and
`meta_verify_token_is_usable()`, and `GET /webhook` now fails closed in production instead
of completing Meta's subscription handshake with a value a reader of the public repository
already knows. Phase 49 (F-49-2/F-49-4) stopped the dashboard and the sheet editor from
overwriting a real token with the placeholder, and started shipping
`verify_token_is_placeholder` to the client so the UI can warn about a value that carries no
secrecy.

What none of that touched is the *write* side. A column default is not documentation: it is
a value the schema supplies to any row that does not name one. Measured on a database
migrated to `0008`, before this revision:

    PRAGMA table_info(pages) -> verify_token | VARCHAR(255) | dflt_value = "'agent_verify_secret_token_123'"
    INSERT INTO pages (page_id, name) VALUES (…)  -> verify_token = 'agent_verify_secret_token_123'

so an INSERT that omitted the column — from a support script, a data-fix run, a future
caller, or `sqlite3`/`psql` by hand — silently minted a page whose webhook verify token is
public knowledge, and reported success while doing it. Phase 52 fixed the three application
paths (`core/models.py`, `database.init_db`, `database.save_page`). This revision removes the
fourth, which lives in already-deployed databases and therefore cannot be fixed by editing
Python.

Two defences fail differently, which is why both exist. The predicates in `core.security`
protect the read path and also cover a value an operator typed by hand; this revision
protects the write path and cannot be bypassed by a new caller that forgets the predicate.

===============================================================================
WHAT THIS REVISION DOES
===============================================================================
PostgreSQL: `ALTER TABLE pages ALTER COLUMN verify_token DROP DEFAULT`.

SQLite has no `ALTER COLUMN`, so the table is swapped for a rebuild. **The rebuild does not
reconstruct the schema from `PRAGMA table_info`.** It takes the table's own DDL text from
`sqlite_master` and removes exactly one thing from it: the `DEFAULT` clause of the
`verify_token` column definition. That distinction was measured, not stylistic. `table_info`
reports columns, not table-level constraints, and `pages` carries an inline `UNIQUE` whose
autoindex (`sqlite_autoindex_pages_1`) is invisible to it — a rebuild from `table_info` would
have dropped that constraint and reported success. Editing the DDL text preserves the type,
the nullability, every inline `UNIQUE`/`CHECK`, the column order and the primary key exactly
as the live table declares them.

The swap itself needs one non-obvious pragma. The obvious version fails:

    CREATE TABLE pages__p52 (…);  INSERT …;  DROP TABLE pages;  ALTER TABLE pages__p52 RENAME TO pages
    -> sqlite3.OperationalError: error in trigger audit_logs_no_update: no such table: main.pages

`ALTER TABLE … RENAME TO` re-parses every trigger body in the schema so it can rewrite
references to the renamed table, and revision `0007`'s append-only guard
`audit_logs_no_update` contains `SELECT COUNT(*) FROM pages …` in its `WHEN` clause. During
the rename `pages` does not exist — it was just dropped and the new table still has its
temporary name — so the guard's own predicate fails to compile and takes the migration with
it. `PRAGMA legacy_alter_table=ON` for the rename step alone skips that fix-up pass; the
triggers of this schema reference `pages` by name, and the rebuilt table keeps that name, so
there is nothing to rewrite. Measured: with the pragma the swap commits, without it the whole
migration rolls back and the database is left exactly as it was (28 pages, version `0008`).

Indexes and triggers attached to `pages` are dropped with it, so their DDL is captured from
`sqlite_master` first and replayed after the rename — `tbl_name='pages'`, which deliberately
excludes triggers on *other* tables whose bodies merely mention `pages` (`audit_logs_no_update`
is one of those, and it must survive untouched).

**Strictly a default change. No row is rewritten, no column type changes, no data is
deleted.** The revision verifies that instead of assuming it: identical row count, an empty
`PRAGMA foreign_key_check`, `PRAGMA integrity_check = ok`, all 14 tables that reference
`pages` still referencing it, every captured index and trigger present again, and a
per-column shape comparison (`PRAGMA table_info`) that must show `verify_token`'s default as
the *only* difference. Any mismatch raises, so a partial rebuild cannot be reported as
success.

===============================================================================
WHAT THIS REVISION DELIBERATELY DOES NOT DO
===============================================================================
It does **not** blank rows that already hold the published literal. That is a data change
with an operational consequence: a page whose ManyChat/Meta secret is the published value
would stop authenticating the moment the migration ran, silently, from a change whose stated
purpose was to stop *new* rows inheriting the value. Deciding what to do about an existing
row is an operator decision, and the codebase already surfaces it — `_sanitize_page_secrets()`
ships `verify_token_is_placeholder` to the dashboard, which warns on exactly that condition,
and `meta_verify_token_is_usable()` refuses the value in production. The correct sequence is:
operator sets a real token, then the stale rows are cleaned deliberately, if at all.

This is `0008`'s reasoning applied in the opposite direction. There, refusing to backfill was
right because assigning a NULL tenant would move data between tenants; here, refusing to
rewrite is right because clearing a credential that is in use breaks a working integration
without telling anyone. A migration that guesses is worse than one that reports.

`0001` is left exactly as written. It is applied history: editing an already-released
migration desynchronises every database that ran it from every database that runs it fresh,
which is a worse defect than the one being fixed. The default is removed by a new revision,
the way schema history is meant to move.

After this revision an INSERT that omits the column leaves `verify_token` NULL, on both
dialects. That matches `core/models.py`, whose `default=""` is a Python-side default and
emits no DDL at all, so a `create_all`-built database and a migration-built one now agree:
neither supplies a value, and `meta_verify_token_is_usable(None)` is False in every
environment, which fails closed.

Revision ID: 0009_verify_token_default
Revises: 0008_tenant_not_null
"""

from __future__ import annotations

import logging
import re

import sqlalchemy as sa
from alembic import op

logger = logging.getLogger("alembic.runtime.migration")

revision = "0009_verify_token_default"
down_revision = "0008_tenant_not_null"
branch_labels = None
depends_on = None

TABLE = "pages"
COLUMN = "verify_token"
#: The published value this revision removes as a default. Spelled out because `downgrade()`
#: has to be able to put it back for the round trip to be reversible.
PUBLISHED = "agent_verify_secret_token_123"
_TMP = f"{TABLE}__p52"

_CREATE_HEAD = re.compile(
    r"^(\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?)"
    r"(?:\"[^\"]+\"|'[^']+'|`[^`]+`|\[[^\]]+\]|[A-Za-z_][A-Za-z0-9_]*)",
    re.I,
)
_NAME_RE = re.compile(
    r"\s*(?:\"([^\"]+)\"|'([^']+)'|`([^`]+)`|\[([^\]]+)\]|([A-Za-z_][A-Za-z0-9_]*))"
)
_DEFAULT_RE = re.compile(
    r"\s+DEFAULT\s+(?:'[^']*'|\"[^\"]*\"|\([^)]*\)|[^\s,]+)", re.I
)


def _dialect() -> str:
    return op.get_bind().dialect.name


def _exec(statement: str) -> None:
    op.execute(sa.text(statement))


def _split_definitions(body: str) -> list[str]:
    """Split a CREATE TABLE body on top-level commas, respecting parens and quotes.

    A naive `body.split(",")` cuts through `DECIMAL(10,2)` and through quoted strings that
    contain a comma, which is exactly how a rebuild loses a column.
    """
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    current: list[str] = []
    for ch in body:
        if quote is not None:
            current.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"`":
            quote = ch
            current.append(ch)
            continue
        if ch == "[":
            quote = "]"
            current.append(ch)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if "".join(current).strip():
        parts.append("".join(current))
    return parts


def _definition_name(fragment: str) -> str | None:
    """The identifier a column/constraint definition starts with, unquoted."""
    match = _NAME_RE.match(fragment)
    if not match:
        return None
    return next((g for g in match.groups() if g is not None), None)


def _parse_create_table(sql: str) -> tuple[str, str, str]:
    """(prefix, body, suffix) of a plain `CREATE TABLE <name> ( <body> )`."""
    match = re.match(r"\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?", sql, re.I)
    if not match:
        raise RuntimeError(f"0009: {TABLE}'s DDL is not a plain CREATE TABLE; refusing to edit it")
    open_paren = sql.index("(", match.end())
    close_paren = sql.rindex(")")
    if close_paren <= open_paren:
        raise RuntimeError(f"0009: {TABLE}'s DDL has no column list; refusing to edit it")
    return sql[: open_paren + 1], sql[open_paren + 1 : close_paren], sql[close_paren:]


def _column_definitions(body: str) -> tuple[list[str], list[str | None]]:
    definitions = _split_definitions(body)
    return definitions, [_definition_name(d) for d in definitions]


def _edit_column_default(sql: str, published: str | None) -> tuple[str, str]:
    """Return ``sql`` with `verify_token`'s DEFAULT removed (``published=None``) or set to it.

    Only that one column definition is touched, and the edit is refused unless the DDL is in
    the shape this revision expects. Editing the table's own DDL text is what preserves
    inline `UNIQUE`/`CHECK` constraints and column order, which `PRAGMA table_info` cannot
    report and a reconstructed CREATE TABLE would therefore lose.
    """
    prefix, body, suffix = _parse_create_table(sql)
    definitions, names = _column_definitions(body)
    occurrences = names.count(COLUMN)
    if occurrences != 1:
        raise RuntimeError(
            f"0009: expected exactly one column definition named {COLUMN} in {TABLE}, "
            f"found {occurrences}. Refusing to edit a DDL it cannot parse confidently."
        )

    out: list[str] = []
    action = "removed"
    for name, definition in zip(names, definitions):
        if name != COLUMN:
            out.append(definition)
            continue
        existing = _DEFAULT_RE.findall(definition)
        if published is None:
            if len(existing) != 1:
                raise RuntimeError(
                    f"0009: {TABLE}.{COLUMN} has {len(existing)} DEFAULT clause(s), expected 1"
                )
            if PUBLISHED not in existing[0]:
                # Somebody already replaced the published default with a real one. Changing
                # that would destroy an operator's choice, and the defect this revision
                # exists to remove is not present. Reported as a no-op, not an error.
                return sql, f"left alone (already {existing[0].strip()!r})"
            definition = _DEFAULT_RE.sub("", definition, count=1)
        else:
            if existing:
                action = "replaced"
                definition = _DEFAULT_RE.sub("", definition, count=1)
            definition = definition.rstrip().rstrip(",") + f" DEFAULT '{published}'"
        out.append(definition)

    rebuilt = prefix + ",".join(out) + suffix
    if published is None and PUBLISHED in rebuilt:
        raise RuntimeError(
            f"0009: {TABLE}'s rebuilt DDL still contains the published value; the edit did "
            "not do what it claimed."
        )
    return rebuilt, action


def _sqlite_current_default(bind) -> str | None:
    for row in bind.execute(sa.text(f"PRAGMA table_info({TABLE})")).fetchall():
        if row[1] == COLUMN:
            return row[4]
    return None


def _sqlite_child_references(bind) -> int:
    """How many tables' DDL still references `pages`. Measured 14 in this schema."""
    rows = bind.execute(
        sa.text("SELECT sql FROM sqlite_master WHERE type='table' AND sql IS NOT NULL")
    ).fetchall()
    return sum(1 for (sql,) in rows if "REFERENCES pages" in sql.replace('"', ""))


def _sqlite_swap(target_sql: str) -> dict:
    """Replace `pages` with `target_sql`, moving the rows and replaying what hangs off it.

    Returns the measurements `upgrade()`/`downgrade()` assert on, so the verification sits
    next to the refusal instead of buried in here.
    """
    bind = op.get_bind()
    info = bind.execute(sa.text(f"PRAGMA table_info({TABLE})")).fetchall()
    if not info:
        return {}
    columns = ", ".join(f'"{row[1]}"' for row in info)
    shape_before = {row[1]: (row[2], row[3], row[4], row[5]) for row in info}
    rows_before = bind.execute(sa.text(f"SELECT count(*) FROM {TABLE}")).scalar()
    references_before = _sqlite_child_references(bind)

    # Captured before the drop: `DROP TABLE` removes the indexes and triggers attached to
    # `pages` along with it. `tbl_name=:t` deliberately excludes triggers on other tables
    # whose bodies mention `pages` - `audit_logs_no_update` is one, and it must survive.
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

    tmp_sql = _CREATE_HEAD.sub(lambda m: f'{m.group(1)}"{_TMP}"', target_sql, count=1)
    if f'"{_TMP}"' not in tmp_sql:
        raise RuntimeError("0009: could not rename the CREATE TABLE statement for the swap")

    # `legacy_alter_table=ON` for the rename only - see the module docstring for the measured
    # failure this avoids (revision 0007's audit guard cannot compile while `pages` is absent).
    _exec("PRAGMA legacy_alter_table=ON")
    try:
        _exec(f"DROP TABLE IF EXISTS {_TMP}")
        _exec(tmp_sql)
        _exec(f"INSERT INTO {_TMP} ({columns}) SELECT {columns} FROM {TABLE}")
        _exec(f"DROP TABLE {TABLE}")
        _exec(f"ALTER TABLE {_TMP} RENAME TO {TABLE}")
    finally:
        _exec("PRAGMA legacy_alter_table=OFF")
    for ddl in dependent:
        _exec(ddl)

    after = bind.execute(sa.text(f"PRAGMA table_info({TABLE})")).fetchall()
    present = {
        row[0]
        for row in bind.execute(
            sa.text(
                "SELECT name FROM sqlite_master WHERE tbl_name=:t AND type IN ('index','trigger')"
            ),
            {"t": TABLE},
        ).fetchall()
    }
    return {
        "rows_before": rows_before,
        "rows_after": bind.execute(sa.text(f"SELECT count(*) FROM {TABLE}")).scalar(),
        "shape_before": shape_before,
        "shape_after": {row[1]: (row[2], row[3], row[4], row[5]) for row in after},
        "references_before": references_before,
        "references_after": _sqlite_child_references(bind),
        "dependent": dependent,
        "dependent_present": present,
        "fk_violations": list(bind.execute(sa.text("PRAGMA foreign_key_check")).fetchall()),
        "integrity": bind.execute(sa.text("PRAGMA integrity_check")).scalar(),
    }


def _verify_sqlite_swap(measured: dict) -> None:
    """Refuse to report success unless the swap demonstrably lost nothing."""
    if not measured:
        return
    if measured["rows_before"] != measured["rows_after"]:
        raise RuntimeError(
            f"0009: {TABLE} held {measured['rows_before']} row(s) before the rebuild and "
            f"{measured['rows_after']} after. A default change must not move data."
        )
    if measured["references_before"] != measured["references_after"]:
        raise RuntimeError(
            f"0009: {measured['references_before']} table(s) referenced {TABLE} before the "
            f"rebuild and {measured['references_after']} do afterwards. Foreign keys were lost."
        )
    if measured["fk_violations"]:
        raise RuntimeError(
            f"0009: PRAGMA foreign_key_check reported {len(measured['fk_violations'])} "
            f"violation(s) after rebuilding {TABLE}."
        )
    if str(measured["integrity"]).lower() != "ok":
        raise RuntimeError(f"0009: PRAGMA integrity_check reported {measured['integrity']!r}")
    missing = [
        ddl.split()[2].strip('"')
        for ddl in measured["dependent"]
        if not any(name in ddl for name in measured["dependent_present"])
    ]
    named = {ddl for ddl in measured["dependent"]}
    absent = [
        ddl for ddl in named
        if not any(f'"{name}"' in ddl or f" {name} " in ddl or f" {name}\n" in ddl
                   for name in measured["dependent_present"])
    ]
    if absent or missing:
        raise RuntimeError(
            f"0009: {len(set(absent) | set(missing))} index/trigger definition(s) attached to "
            f"{TABLE} were not restored by the rebuild."
        )
    unexpected = {
        name: (measured["shape_before"][name], measured["shape_after"].get(name))
        for name in measured["shape_before"]
        if name != COLUMN and measured["shape_before"][name] != measured["shape_after"].get(name)
    }
    if unexpected:
        raise RuntimeError(
            f"0009: rebuilding {TABLE} changed {len(unexpected)} column(s) it was not asked to "
            f"change: {sorted(unexpected)}. Refusing to report success."
        )


def _postgresql_default(bind) -> str | None:
    return bind.execute(
        sa.text(
            "SELECT column_default FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ),
        {"t": TABLE, "c": COLUMN},
    ).scalar()


def upgrade() -> None:
    dialect = _dialect()
    bind = op.get_bind()

    if not sa.inspect(bind).has_table(TABLE):
        # Reported, not silently swallowed: a run that skipped the table it was written for
        # should say so in the log an operator reads.
        logger.warning("0009: table %s does not exist on %s; nothing to change", TABLE, dialect)
        return

    if dialect == "postgresql":
        before = _postgresql_default(bind)
        if before is None:
            logger.info("0009: %s.%s already has no DEFAULT on postgresql", TABLE, COLUMN)
            return
        _exec(f"ALTER TABLE {TABLE} ALTER COLUMN {COLUMN} DROP DEFAULT")
        after = _postgresql_default(bind)
    else:
        before = _sqlite_current_default(bind)
        if before is None:
            logger.info("0009: %s.%s already has no DEFAULT on sqlite", TABLE, COLUMN)
            return
        ddl = bind.execute(
            sa.text("SELECT sql FROM sqlite_master WHERE type='table' AND name=:t"),
            {"t": TABLE},
        ).scalar()
        if not ddl:
            raise RuntimeError(f"0009: {TABLE} has no readable DDL in sqlite_master")
        target, action = _edit_column_default(ddl, None)
        if target == ddl:
            logger.info("0009: %s.%s DEFAULT %s; no rebuild performed", TABLE, COLUMN, action)
            return
        measured = _sqlite_swap(target)
        _verify_sqlite_swap(measured)
        after = _sqlite_current_default(bind)

    if after is not None:
        raise RuntimeError(
            f"0009: {TABLE}.{COLUMN} still carries DEFAULT {after!r} on {dialect}. New rows "
            "would still be minted with the published value, so B1 is not fixed."
        )
    logger.info(
        "0009: %s.%s has no DEFAULT on %s (was %s) - the schema no longer mints a published "
        "verify token",
        TABLE, COLUMN, dialect, before,
    )


def downgrade() -> None:
    """Restore `0001`'s default, so an `upgrade`/`downgrade` round trip is reversible.

    This puts the published literal back, which is the point of a downgrade, and it is logged
    as a warning for the same reason `0008`'s downgrade warns: the operator should see that
    the database is back in the state B1 was written to leave. No existing row is changed.
    """
    dialect = _dialect()
    bind = op.get_bind()
    if not sa.inspect(bind).has_table(TABLE):
        logger.warning("0009 downgrade: table %s does not exist on %s", TABLE, dialect)
        return

    if dialect == "postgresql":
        _exec(f"ALTER TABLE {TABLE} ALTER COLUMN {COLUMN} SET DEFAULT '{PUBLISHED}'")
        after = _postgresql_default(bind)
    else:
        ddl = bind.execute(
            sa.text("SELECT sql FROM sqlite_master WHERE type='table' AND name=:t"),
            {"t": TABLE},
        ).scalar()
        if not ddl:
            raise RuntimeError(f"0009 downgrade: {TABLE} has no readable DDL in sqlite_master")
        if _sqlite_current_default(bind) is not None:
            logger.info("0009 downgrade: %s.%s already has a DEFAULT on sqlite", TABLE, COLUMN)
            return
        target, _action = _edit_column_default(ddl, PUBLISHED)
        measured = _sqlite_swap(target)
        _verify_sqlite_swap(measured)
        after = _sqlite_current_default(bind)

    if after is None:
        raise RuntimeError(
            f"0009 downgrade: {TABLE}.{COLUMN} has no DEFAULT on {dialect}; the downgrade did "
            "not restore 0001's state."
        )
    logger.warning(
        "0009 downgraded: %s.%s defaults to the published placeholder again on %s. Any row "
        "inserted without naming a verify token is now minted with a value this repository "
        "prints. No existing row was changed by this downgrade.",
        TABLE, COLUMN, dialect,
    )
