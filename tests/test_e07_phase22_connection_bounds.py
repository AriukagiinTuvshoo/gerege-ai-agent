"""Phase 22 / P21-09 - connection cleanup, and the bounds that make a leak survivable.

Phase 21's finding was precise: ~53 helpers acquire a connection and close it without
`try/finally`, and while `__del__` reclaims the connection when a frame is destroyed, a
**retained traceback keeps the frame alive** - so the connection stays checked out and
`idle in transaction`, holding its row locks. PostgreSQL's
`idle_in_transaction_session_timeout` was `0`, set nowhere in the repository, so nothing on
the server reclaimed it. That is the mechanism that blocked `_reset_public_schema`'s ACCESS
EXCLUSIVE lock and turned a recoverable restore rollback into a hang.

Two things are tested here:

1. The leak is real and reproduces (the control). Five unguarded helpers whose tracebacks are
   retained hold five connections `idle in transaction`.
2. The application pool now bounds every session, so an abandoned transaction is rolled back
   by the server and its locks released.

`core.db_bounds` (Phase 22 / P21-10) already bounded the *maintenance* path. The application
pool was left at `0` for all three timeouts; this closes that half.
"""

import os
import sys
import time
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def _postgres_available() -> bool:
    url = os.getenv("DATABASE_URL", "")
    return "postgres" in url


requires_pg = pytest.mark.skipif(
    not _postgres_available(), reason="needs a PostgreSQL DATABASE_URL"
)


def _admin_conn():
    import psycopg2

    return psycopg2.connect(
        host=os.getenv("PGHOST", "127.0.0.1"),
        port=int(os.getenv("PGPORT", "5432")),
        user=os.getenv("PGUSER", "gerege"),
        password=os.getenv("PGPASSWORD", "ci_pg_password_2026"),
        dbname=os.getenv("PGDATABASE", "postgres"),
        connect_timeout=10,
    )


def _idle_in_transaction(dbname: str) -> int:
    conn = _admin_conn()
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE datname = %s AND state = 'idle in transaction'",
                (dbname,),
            )
            return cur.fetchone()[0]
    finally:
        conn.close()


def _dbname() -> str:
    return os.getenv("DATABASE_URL", "").rsplit("/", 1)[-1].split("?")[0]


# ---------------------------------------------------------------------------
# Structural: the pool must set the bounds
# ---------------------------------------------------------------------------


def test_pool_applies_session_bounds_on_connect():
    """The engine must install a `connect` listener for PostgreSQL.

    Structural because the observable effect depends on the live server; the behavioural
    test below covers that, and this one fails fast if the listener is removed.
    """
    source = (REPO_ROOT / "core" / "db_engine.py").read_text(encoding="utf-8")
    assert 'listens_for(engine, "connect")' in source
    assert "idle_in_transaction_session_timeout" in source
    assert "statement_timeout" in source
    assert "lock_timeout" in source


def test_bounds_are_overridable_and_documented():
    """An operator must be able to tune or disable a bound without editing code."""
    source = (REPO_ROOT / "core" / "db_engine.py").read_text(encoding="utf-8")
    for knob in (
        "DB_IDLE_IN_TRANSACTION_TIMEOUT_MS",
        "DB_STATEMENT_TIMEOUT_MS",
        "DB_LOCK_TIMEOUT_MS",
    ):
        assert knob in source, f"{knob} is not configurable"


# ---------------------------------------------------------------------------
# Behavioural: the bound actually reaches the server
# ---------------------------------------------------------------------------


@requires_pg
def test_pooled_session_has_nonzero_timeouts():
    """A connection from the application pool must not have all three at zero."""
    import database

    conn = database.get_connection()
    try:
        values = {
            name: conn.execute(f"SHOW {name}").fetchone()[0]
            for name in (
                "idle_in_transaction_session_timeout",
                "statement_timeout",
                "lock_timeout",
            )
        }
    finally:
        conn.close()

    # PostgreSQL renders milliseconds as e.g. "1min", "5min", "30s"; zero is "0".
    for name, rendered in values.items():
        assert rendered not in ("0", "0ms"), f"{name} is still unbounded ({rendered})"


# ---------------------------------------------------------------------------
# The control, and the backstop
# ---------------------------------------------------------------------------


@requires_pg
def test_retained_traceback_holds_a_connection_idle_in_transaction(monkeypatch):
    """The control: the leak Phase 21 described, reproduced.

    Uses a long `idle_in_transaction_session_timeout` so the server does not reclaim the
    sessions during the measurement - otherwise the test would race the very backstop it is
    demonstrating is unnecessary when the traceback is dropped.
    """
    monkeypatch.setenv("DB_IDLE_IN_TRANSACTION_TIMEOUT_MS", "600000")
    import importlib

    import core.db_engine as db_engine

    db_engine.dispose_shared_engine()
    importlib.reload(db_engine)

    import database

    dbname = _dbname()
    before = _idle_in_transaction(dbname)

    def unguarded_helper():
        """Shaped like the 53 helpers P21-09 counted: acquire, work, raise, no finally."""
        conn = database.get_connection()
        conn.execute("SELECT 1")
        raise RuntimeError("boom before close")

    retained = []
    try:
        for _ in range(3):
            try:
                unguarded_helper()
            except RuntimeError as exc:
                retained.append(exc.__traceback__)

        leaked = _idle_in_transaction(dbname) - before
        assert leaked >= 3, (
            f"expected the retained tracebacks to hold >=3 idle-in-transaction sessions, "
            f"saw {leaked}"
        )
    finally:
        retained.clear()
        db_engine.dispose_shared_engine()


@requires_pg
def test_server_reclaims_an_abandoned_transaction(monkeypatch):
    """The backstop: with the bound applied, the server releases the locks it held.

    This is what makes the 53 unguarded helpers survivable rather than fatal. Without it a
    leaked session holds its locks for the life of the process.
    """
    monkeypatch.setenv("DB_IDLE_IN_TRANSACTION_TIMEOUT_MS", "1500")
    import importlib

    import core.db_engine as db_engine

    db_engine.dispose_shared_engine()
    engine = db_engine.get_shared_engine()

    # Take a raw pooled connection and start a transaction, exactly as a leaked helper would.
    raw = engine.raw_connection()
    try:
        cur = raw.cursor()
        cur.execute("SELECT 1")
        cur.close()
        assert _idle_in_transaction(_dbname()) >= 1

        deadline = time.time() + 20
        reclaimed = False
        while time.time() < deadline:
            if _idle_in_transaction(_dbname()) == 0:
                reclaimed = True
                break
            time.sleep(1)
        assert reclaimed, "the server did not reclaim the abandoned transaction"
    finally:
        try:
            raw.close()
        except Exception:
            pass
        db_engine.dispose_shared_engine()


# ---------------------------------------------------------------------------
# Guard against regressing to unbounded sessions
# ---------------------------------------------------------------------------


def test_no_production_code_disables_the_session_bound():
    """Nothing may set the bound back to zero for the application pool.

    Comments and docstrings are stripped first. A first version of this test scanned raw
    text and flagged the *prose* that documents the fix - two docstrings that explain
    `idle_in_transaction_session_timeout = 0` was the old value. Structural guards must
    look at code, not at the commentary about the code.
    """
    import ast
    import io
    import tokenize

    needle = "idle_in_transaction_session_timeout = 0"
    offenders = []
    for path in list(REPO_ROOT.glob("core/*.py")) + list(REPO_ROOT.glob("scripts/*.py")):
        source = path.read_text(encoding="utf-8", errors="ignore")
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue

        docstring_lines = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                body = getattr(node, "body", None)
                if body and isinstance(body[0], ast.Expr) and isinstance(
                    getattr(body[0], "value", None), ast.Constant
                ) and isinstance(body[0].value.value, str):
                    doc = body[0]
                    docstring_lines.update(range(doc.lineno, (doc.end_lineno or doc.lineno) + 1))

        comment_lines = set()
        try:
            for tok in tokenize.generate_tokens(io.StringIO(source).readline):
                if tok.type == tokenize.COMMENT:
                    comment_lines.add(tok.start[0])
        except (tokenize.TokenError, IndentationError):
            pass

        for number, line in enumerate(source.splitlines(), start=1):
            if number in docstring_lines or number in comment_lines:
                continue
            if needle in line:
                offenders.append(f"{path.name}:{number}: {line.strip()}")

    assert not offenders, f"session bound disabled in code: {offenders}"
