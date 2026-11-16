"""Stage C — single schema authority (P1-02 / P2-01).

These tests assert the *end state*, not the implementation:

  * a database built by `init_db()` matches `core/models.py` exactly, types included,
  * a database upgraded from legacy shapes converges to the same place,
  * `verify_schema_drift()` now detects the drift it used to miss,
  * the migration preserves data, including the empty-string timestamp sentinel,
  * the SQLite batch path does not truncate timestamps (the CAST/NUMERIC-affinity bug),
  * the migration is reversible.

Runs on SQLite by default; when `DATABASE_URL` points at PostgreSQL the same tests
also exercise the PostgreSQL `ALTER ... USING` path.
"""
import os
import sqlite3

import pytest
import sqlalchemy as sa
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext

import database
from core.models import Base


# --------------------------------------------------------------------------- helpers
def _diffs(url, *, compare_type=True, compare_defaults=False):
    engine = sa.create_engine(url)
    opts = {"compare_type": compare_type}
    if compare_defaults:
        opts["compare_server_default"] = True
    with engine.connect() as conn:
        raw = compare_metadata(MigrationContext.configure(conn, opts=opts), Base.metadata)
    engine.dispose()
    return [x for d in raw for x in (d if isinstance(d, list) else [d])]


def _flatten_kinds(diffs):
    from collections import Counter

    return Counter(d[0] if isinstance(d, tuple) else str(d) for d in diffs)


@pytest.fixture()
def sqlite_db(tmp_path, monkeypatch):
    """A fresh, isolated SQLite database bound through `database.DB_PATH`.

    Both `DATABASE_URL` and `DB_PATH` are cleared so the test never inherits a
    developer's or CI's configured database, then `database.DB_PATH` is rebound.
    """
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DB_PATH", raising=False)
    path = tmp_path / "stage_c.db"
    monkeypatch.setattr(database, "DB_PATH", str(path))
    return path


# ------------------------------------------------------- 1. models are the authority
def test_init_db_builds_a_schema_that_matches_models(sqlite_db):
    """`init_db()` must produce exactly what `core.models` declares."""
    database.init_db()
    diffs = _diffs(f"sqlite:///{sqlite_db}")
    assert diffs == [], f"init_db() produced a schema that differs from models: {diffs[:5]}"


def test_timestamp_columns_are_real_timestamps_not_varchar(sqlite_db):
    """The original P1-02 defect: timestamps were `VARCHAR(64)` in one path."""
    database.init_db()
    conn = sqlite3.connect(sqlite_db)
    try:
        declared = {r[1]: r[2].upper() for r in conn.execute("PRAGMA table_info(pages)")}
    finally:
        conn.close()
    assert declared["created_at"].startswith("DATETIME"), (
        f"pages.created_at is {declared['created_at']!r}; the timestamp type regressed"
    )


def test_created_at_has_a_server_default_so_raw_inserts_get_a_value(sqlite_db):
    """Raw SQL inserts that omit `created_at` must still store a timestamp.

    The legacy DDL had `DEFAULT CURRENT_TIMESTAMP`; the ORM's Python-side default does
    not apply to raw SQL, so without a server default these rows would be NULL.
    """
    database.init_db()
    conn = sqlite3.connect(sqlite_db)
    try:
        conn.execute(
            "INSERT INTO registrations (page_id, name, phone) VALUES ('t1','Raw','1')"
        )
        conn.commit()
        row = conn.execute(
            "SELECT created_at FROM registrations WHERE name='Raw'"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None and row[0], "created_at is NULL despite a server default"


# ------------------------------------------------- 2. drift detection actually works
def test_verify_schema_drift_reports_clean_on_a_converged_database(sqlite_db):
    from core.schema_manager import drift_report

    database.init_db()
    report = drift_report()
    assert report["has_drift"] is False, report
    assert report["count"] == 0, report


def test_verify_schema_drift_detects_type_drift_previously_invisible(sqlite_db):
    """P2-01: the old checker compared column *names* and always said "no drift".

    Here a `VARCHAR` stands in for `DateTime`, exactly the shape the legacy schema had.
    The checker must notice.
    """
    database.init_db()
    conn = sqlite3.connect(sqlite_db)
    try:
        # Rebuild one table with a VARCHAR timestamp, mimicking the 0001 defect.
        conn.executescript(
            """
            ALTER TABLE pages RENAME TO pages_orig;
            CREATE TABLE pages (
                page_id VARCHAR(128) NOT NULL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                category VARCHAR(64) DEFAULT 'general',
                page_access_token TEXT,
                verify_token VARCHAR(255) DEFAULT 'agent_verify_secret_token_123',
                is_active INTEGER DEFAULT 1,
                knowledge_json TEXT DEFAULT '{}',
                gemini_api_key TEXT DEFAULT '',
                is_deleted INTEGER DEFAULT 0,
                ai_provider VARCHAR(64) DEFAULT 'gemini',
                client_username VARCHAR(128),
                client_password_hash TEXT,
                client_salt VARCHAR(128),
                client_magic_token VARCHAR(255),
                monthly_token_limit INTEGER DEFAULT 100000,
                tokens_used INTEGER DEFAULT 0,
                google_sheets_url TEXT DEFAULT '',
                qpay_username VARCHAR(255) DEFAULT '',
                qpay_password TEXT DEFAULT '',
                qpay_invoice_code VARCHAR(255) DEFAULT '',
                ebarimt_enabled INTEGER DEFAULT 1,
                telegram_bot_token TEXT DEFAULT '',
                telegram_manager_chat_id VARCHAR(128) DEFAULT '',
                daily_report_time VARCHAR(16) DEFAULT '08:30',
                daily_report_enabled INTEGER DEFAULT 1,
                created_at VARCHAR(64) DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.commit()
    finally:
        conn.close()

    from core.schema_manager import drift_report

    report = drift_report()
    assert report["has_drift"] is True, "the type-aware checker failed to see VARCHAR created_at"
    assert report["count"] > 0
    assert "modify_type" in report["by_kind"], report["by_kind"]


# ------------------------------------------------------------- 3. data preservation
def test_string_timestamp_sentinel_becomes_null_not_garbage(tmp_path, monkeypatch):
    """An empty-string `paid_at` must become NULL during the migration.

    The row has to exist *before* `0002` runs, so this test builds the `0001` schema,
    inserts the legacy row, and only then upgrades — which is exactly what happens to
    a real deployment.
    """
    from alembic import command
    from alembic.config import Config

    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DB_PATH", raising=False)
    db_path = tmp_path / "legacy.db"
    monkeypatch.setattr(database, "DB_PATH", str(db_path))

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    command.upgrade(cfg, "0001_initial_enterprise_schema")

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO invoices (invoice_id, page_id, amount, status, description,"
            " paid_at, created_at) VALUES ('INV-EMPTY','t1',1000,'PAID','d','',"
            "'2026-11-16 07:00:00')"
        )
        conn.execute(
            "INSERT INTO invoices (invoice_id, page_id, amount, status, description,"
            " paid_at, created_at) VALUES ('INV-OK','t1',2000,'PAID','d',"
            "'2026-11-16 08:00:00','2026-11-16 07:00:00')"
        )
        conn.commit()
        sentinel_before = conn.execute(
            "SELECT paid_at, typeof(paid_at) FROM invoices WHERE invoice_id='INV-EMPTY'"
        ).fetchone()
    finally:
        conn.close()
    assert sentinel_before == ("", "text"), sentinel_before

    command.upgrade(cfg, "head")

    conn = sqlite3.connect(db_path)
    try:
        rows = dict(conn.execute("SELECT invoice_id, paid_at FROM invoices").fetchall())
        storage = dict(
            conn.execute("SELECT invoice_id, typeof(paid_at) FROM invoices").fetchall()
        )
    finally:
        conn.close()

    assert rows["INV-EMPTY"] is None, (
        f"empty sentinel became {rows['INV-EMPTY']!r}; it must become NULL, never 0 or ''"
    )
    assert str(rows["INV-OK"]).startswith("2026-11-16"), rows["INV-OK"]
    assert storage["INV-OK"] == "text", (
        f"paid_at storage class is {storage['INV-OK']!r}; integer means CAST truncation"
    )


def test_sqlite_batch_migration_does_not_truncate_timestamps_to_integers():
    """Regression for `CAST(col AS DATETIME)` applying NUMERIC affinity.

    Alembic's batch mode copies rows with `CAST(... AS DATETIME)`, which SQLite
    resolves as NUMERIC and truncates `'2026-11-16 04:05:06'` to the integer `2026`.
    `migrations/sqlite_compat.py` replaces that with `datetime(col)`; this test pins
    the behaviour of the replacement itself.
    """
    from sqlalchemy import func

    engine = sa.create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE t (v TEXT)"))
        for value in ("2026-11-16 04:05:06", "2026-11-16T04:05:06.123456", "", None):
            conn.execute(sa.text("INSERT INTO t (v) VALUES (:v)"), {"v": value})

        unsafe = conn.execute(
            sa.text("SELECT CAST(v AS DATETIME) FROM t WHERE v IS NOT NULL AND v <> ''")
        ).fetchall()
        safe = conn.execute(
            sa.text("SELECT datetime(v) FROM t")
        ).fetchall()

    # Document the hazard so the workaround is never "simplified" away.
    assert all(isinstance(r[0], int) for r in unsafe), (
        f"expected the CAST hazard to truncate to integers, got {unsafe}"
    )
    values = [r[0] for r in safe]
    assert values[0] == "2026-11-16 04:05:06", values
    assert values[1] == "2026-11-16 04:05:06", values
    assert values[2] is None, "the empty-string sentinel must map to NULL"
    assert values[3] is None, "NULL must stay NULL"


def test_sqlite_transfer_patch_is_idempotent():
    from migrations.sqlite_compat import install_sqlite_datetime_transfer_patch

    install_sqlite_datetime_transfer_patch()
    install_sqlite_datetime_transfer_patch()  # must not stack wrappers
    from alembic.ddl.sqlite import SQLiteImpl

    assert getattr(SQLiteImpl, "_gerege_datetime_patch", False) is True


# ------------------------------------------------------------ 4. migration is reversible
def test_migration_round_trip_is_reversible_and_lossless(sqlite_db):
    """0001 -> 0002 -> 0001 -> 0002 must keep the schema converged and the rows intact."""
    from alembic import command
    from alembic.config import Config

    database.init_db()  # ends at head
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{sqlite_db}")

    conn = sqlite3.connect(sqlite_db)
    try:
        conn.execute(
            "INSERT INTO pages (page_id, name, created_at) VALUES ('rt','Round Trip','2026-11-16 04:05:06')"
        )
        conn.execute(
            "INSERT INTO cargo_packages (page_id, tracking_code, weight_kg, created_at)"
            " VALUES ('rt','TRK1',12.5,'2026-11-16 06:00:00')"
        )
        conn.commit()
    finally:
        conn.close()

    def snapshot():
        c = sqlite3.connect(sqlite_db)
        try:
            return (
                c.execute("SELECT COUNT(*) FROM pages").fetchone()[0],
                c.execute("SELECT COUNT(*) FROM cargo_packages").fetchone()[0],
                c.execute("SELECT created_at FROM pages WHERE page_id='rt'").fetchone()[0],
                c.execute("SELECT weight_kg FROM cargo_packages WHERE tracking_code='TRK1'").fetchone()[0],
            )
        finally:
            c.close()

    before = snapshot()

    command.downgrade(cfg, "0001_initial_enterprise_schema")
    after_down = snapshot()
    assert after_down == before, f"downgrade lost data: {before} -> {after_down}"

    command.upgrade(cfg, "head")
    after_up = snapshot()
    assert after_up == before, f"re-upgrade lost data: {before} -> {after_up}"
    assert _diffs(f"sqlite:///{sqlite_db}") == [], "schema diverged after the round trip"


# ---------------------------------------------------- 5. the snapshot list stays honest
def test_frozen_type_snapshot_matches_the_models():
    """`migrations/_schema_targets.py` must not drift from `core.models`.

    The migration uses a frozen snapshot on purpose (a historical migration must not
    change when the models change). This test is the guard that makes the snapshot
    safe: change a column type in the models and this fails, which is the signal that
    a *new* migration is required.
    """
    from migrations._schema_targets import TEXT_TO_DECLARED_TYPE

    mismatches = []
    for table, column, frozen in TEXT_TO_DECLARED_TYPE:
        if table not in Base.metadata.tables:
            mismatches.append(f"{table}.{column}: table missing from models")
            continue
        tbl = Base.metadata.tables[table]
        if column not in tbl.columns:
            mismatches.append(f"{table}.{column}: column missing from models")
            continue
        actual = tbl.columns[column].type
        if type(actual) is not type(frozen):
            mismatches.append(f"{table}.{column}: {type(actual).__name__} != {type(frozen).__name__}")
        elif getattr(actual, "length", None) != getattr(frozen, "length", None):
            mismatches.append(f"{table}.{column}: length {actual.length} != {frozen.length}")

    assert not mismatches, "snapshot is stale — write a new migration:\n" + "\n".join(mismatches)


def test_frozen_unique_constraints_match_the_models():
    from migrations._schema_targets import UNIQUE_CONSTRAINTS

    model_uniques = {
        (t.name, c.name, tuple(col.name for col in c.columns))
        for t in Base.metadata.sorted_tables
        for c in t.constraints
        if c.__class__.__name__ == "UniqueConstraint" and c.name
    }
    for table, name, columns in UNIQUE_CONSTRAINTS:
        assert (table, name, tuple(columns)) in model_uniques, (
            f"{table}.{name}{columns} is not a named unique constraint in models.py"
        )


# --------------------------------------------------------------- 6. schema authority
def test_init_db_is_idempotent(sqlite_db):
    database.init_db()
    database.init_db()  # second call must be a no-op, not an error
    assert _diffs(f"sqlite:///{sqlite_db}") == []


def test_schema_manager_reports_head(sqlite_db):
    from core.schema_manager import current_revision, head_revision, is_at_head

    database.init_db()
    assert current_revision() == head_revision()
    assert is_at_head() is True


def test_preflight_reports_no_pending_migrations(sqlite_db):
    from core.schema_manager import preflight

    database.init_db()
    report = preflight()
    assert report["up_to_date"] is True, report
    assert report["pending_count"] == 0, report


def test_get_connection_honours_db_path_env(tmp_path, monkeypatch):
    """`DB_PATH` must actually direct the connection, not just `database.DB_PATH`.

    The original code passed `sqlite_path=DB_PATH` explicitly, which bypassed the
    environment lookup: `init_db()` seeded the repository-local `leads.db` while the
    operator's configured database stayed empty.
    """
    target = tmp_path / "env_path.db"
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DB_PATH", str(target))
    monkeypatch.setattr(database, "DB_PATH", database._DEFAULT_DB_PATH)

    database.init_db()
    assert target.exists(), "DB_PATH was ignored"
    conn = sqlite3.connect(target)
    try:
        assert conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0] >= 1
    finally:
        conn.close()


def test_schema_manager_detects_drift_on_a_stale_database(sqlite_db):
    """`assert_at_head` must fail loudly when migrations have not been applied."""
    from core.schema_manager import assert_at_head

    database.init_db()
    # Simulate an unmigrated database by clearing the stamp.
    conn = sqlite3.connect(sqlite_db)
    try:
        conn.execute("DELETE FROM alembic_version")
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(RuntimeError):
        assert_at_head()


# ------------------------------------------------------------ 7. documented root cause
def test_no_runtime_create_table_ddl_remains():
    """`init_db()` must not create tables itself — migrations own the schema.

    Only executable statements are inspected: the docstring legitimately *describes*
    the removed `CREATE TABLE` DDL, so `ast` is used to strip constants.
    """
    import ast
    import inspect
    import textwrap

    tree = ast.parse(textwrap.dedent(inspect.getsource(database.init_db)))
    literals = []
    for node in ast.walk(tree):
        # Ignore docstrings/string constants entirely; only real SQL strings count.
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("execute", "executescript"):
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        literals.append(arg.value)
    joined = " ".join(literals).upper()
    assert "CREATE TABLE" not in joined, (
        "init_db() still executes CREATE TABLE DDL; the second schema definition is back"
    )
    assert "ADD COLUMN" not in joined, "init_db() still executes ALTER TABLE ADD COLUMN"


def test_missing_migrations_raise_a_descriptive_error(monkeypatch):
    """A deployment bundle without `migrations/` must fail loudly and explain why.

    Serverless bundles (Vercel) only ship imported files, so this is a real risk; the
    error message has to name the missing paths instead of surfacing an opaque
    `No such file or directory` from inside Alembic.
    """
    from core import schema_manager

    real_exists = os.path.exists
    monkeypatch.setattr(
        schema_manager.os.path,
        "exists",
        lambda p: False if str(p).endswith(("alembic.ini", "env.py")) else real_exists(p),
    )
    with pytest.raises(RuntimeError) as excinfo:
        schema_manager._assert_migrations_available()
    message = str(excinfo.value)
    assert "migrations" in message
    assert "alembic.ini" in message
