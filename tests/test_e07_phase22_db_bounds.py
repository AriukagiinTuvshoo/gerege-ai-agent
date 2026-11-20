"""Phase 22 regression tests: P21-10 bounded database operations.

Phase 21 reproduced a full hang:

    # another session holds ACCESS EXCLUSIVE on `pages`
    $ timeout 398 maintenance.py backup --label lockrepro
    -> no output, no alert, exit 124 (harness kill), zero files published

The dump never started. ``_collect_db_table_counts()`` ran seventeen ``SELECT COUNT(*)``
statements on a connection with ``statement_timeout = 0``, blocked on the first one, and
the 120 s ``pg_dump`` timeout was never reached.

Two behaviours are pinned here:

1. **A blocked operation fails inside its bound.** The tests hold a real
   ``ACCESS EXCLUSIVE`` lock in a separate connection and assert wall-clock duration, not
   just the return value, because "returns an error" and "returns an error after four
   minutes" are different products.
2. **A blocked query never becomes a plausible zero.** The old code caught every exception
   and recorded ``counts[tbl] = 0``, so a lock-blocked backup printed ``pages=0``. A test
   that only checked ``success is False`` would have passed against the buggy code.

The last test is a static guard: it fails if a ``SELECT COUNT(*)`` is ever added back to the
backup path outside :mod:`core.db_bounds`, which is how this regression would return.
"""

from __future__ import annotations

import ast
import pathlib
import re
import sys
import threading
import time

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core import db_bounds  # noqa: E402

LOCK_TABLE = "pages"


def _owner_dsn() -> str:
    import os

    return os.getenv("DATABASE_OWNER_URL") or os.getenv("DATABASE_URL") or ""


def _require_postgres():
    from core.db_engine import is_postgres

    if not is_postgres():
        pytest.skip("needs PostgreSQL")
    dsn = _owner_dsn()
    if not dsn or dsn.startswith("sqlite"):
        pytest.skip("needs a PostgreSQL DSN")


class _LockHolder:
    """Hold ACCESS EXCLUSIVE on one table from a separate connection.

    A separate *connection* rather than a session is what makes this a real lock conflict:
    a lock taken in this process would still conflict, but keeping it out of the pool makes
    the test independent of how the code under test acquires connections.
    """

    def __init__(self, table: str = LOCK_TABLE):
        self.table = table
        self._conn = None
        self._ready = threading.Event()
        self._release = threading.Event()
        self._thread = None
        self.error = None

    def __enter__(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        if not self._ready.wait(15):
            raise RuntimeError("lock holder did not acquire the lock in time")
        if self.error is not None:
            raise RuntimeError(f"lock holder failed: {self.error}")
        return self

    def _run(self):
        import psycopg2

        dsn = _owner_dsn().replace("postgresql+psycopg2://", "postgresql://")
        try:
            self._conn = psycopg2.connect(dsn)
            self._conn.autocommit = False
            cur = self._conn.cursor()
            cur.execute(f"LOCK TABLE {self.table} IN ACCESS EXCLUSIVE MODE")
            cur.close()
            self._ready.set()
            self._release.wait(120)
            self._conn.rollback()
        except Exception as exc:  # pragma: no cover - diagnostic path
            self.error = exc
            self._ready.set()
        finally:
            try:
                if self._conn is not None:
                    self._conn.close()
            except Exception:
                pass

    def __exit__(self, *exc_info):
        self._release.set()
        if self._thread is not None:
            self._thread.join(timeout=30)
        return False


# ---------------------------------------------------------------------------
# deadline primitives
# ---------------------------------------------------------------------------

def test_deadline_expires_and_reports_elapsed():
    dl = db_bounds.Deadline(0.2, label="unit")
    assert dl.expired() is False
    time.sleep(0.25)
    assert dl.expired() is True
    with pytest.raises(db_bounds.BoundedOperationTimeout) as info:
        dl.check()
    assert "unit" in str(info.value)
    assert "deadline" in str(info.value)


def test_deadline_budget_shrinks_but_never_goes_negative():
    dl = db_bounds.Deadline(10.0, label="unit")
    assert 9.0 < dl.budget(30.0) <= 10.0
    assert dl.budget(1.0) == 1.0
    dl.total_s = 0.0
    with pytest.raises(db_bounds.BoundedOperationTimeout):
        dl.budget(1.0)


def test_session_bounds_are_actually_applied():
    """The SET calls must take effect: an unbounded session is the defect."""
    _require_postgres()
    with db_bounds.bounded_session(label="bounds-check") as (conn, _dl):
        cur = conn.cursor()
        cur.execute("SHOW statement_timeout")
        stmt = cur.fetchone()[0]
        cur.execute("SHOW lock_timeout")
        lock = cur.fetchone()[0]
        cur.execute("SHOW idle_in_transaction_session_timeout")
        idle = cur.fetchone()[0]
        cur.close()
    assert stmt not in ("0", "0ms"), f"statement_timeout is unbounded: {stmt}"
    assert lock not in ("0", "0ms"), f"lock_timeout is unbounded: {lock}"
    assert idle not in ("0", "0ms"), f"idle_in_transaction_session_timeout is unbounded: {idle}"


def test_run_scalar_raises_instead_of_inventing_zero():
    """The Phase 21 preflight recorded 0 for a table it could not read."""
    _require_postgres()
    with _LockHolder(LOCK_TABLE):
        start = time.monotonic()
        with pytest.raises(db_bounds.BoundedOperationTimeout):
            db_bounds.run_scalar(f"SELECT COUNT(*) FROM {LOCK_TABLE}", label="locked count")
        elapsed = time.monotonic() - start
    # lock_timeout is 5 s by default; allow scheduler slack but not minutes.
    assert elapsed < 30, f"did not fail inside its bound: {elapsed:.1f}s"


def test_table_counts_fail_rather_than_report_zero_under_a_lock():
    """The exact Phase 21 defect: ``pages=0`` for a locked table."""
    _require_postgres()
    from core import backup_service

    with _LockHolder(LOCK_TABLE):
        with pytest.raises((db_bounds.BoundedOperationTimeout, Exception)) as info:
            backup_service._collect_db_table_counts()
    assert not isinstance(info.value, AssertionError)
    # It must not have silently succeeded with zeros.
    assert "database preflight" not in str(info.value)


def test_backup_under_lock_fails_inside_a_deadline_and_publishes_nothing(tmp_path, monkeypatch):
    """End-to-end P21-10: the number the operator cares about is wall-clock time."""
    _require_postgres()
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()

    import os as _os

    keyfile = tmp_path / "k"
    keyfile.write_bytes(_os.urandom(32))

    from core import backup_service

    monkeypatch.setattr(backup_service, "BACKUP_DIR", str(backup_dir), raising=True)
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", str(keyfile))

    with _LockHolder(LOCK_TABLE):
        start = time.monotonic()
        result = backup_service.create_backup(label="lock-bound")
        elapsed = time.monotonic() - start

    assert result.get("success") is False
    assert result.get("timeout") is True
    assert result.get("exit_code") not in (0, None)
    # 398 s was the observed hang; the bound is 120 s by default with a 5 s lock_timeout.
    assert elapsed < 90, f"backup took {elapsed:.1f}s under a lock; the bound did not apply"
    published = [p for p in backup_dir.iterdir() if p.is_file() and p.suffix != ".json"]
    assert published == [], f"a failed backup published {published}"


def test_backup_succeeds_after_the_lock_is_released(tmp_path, monkeypatch):
    """No residue: the bound must not have poisoned the pool or left a session open."""
    _require_postgres()
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    keyfile = tmp_path / "k"
    import os as _os

    keyfile.write_bytes(_os.urandom(32))

    from core import backup_service

    monkeypatch.setattr(backup_service, "BACKUP_DIR", str(backup_dir), raising=True)
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", str(keyfile))

    with _LockHolder(LOCK_TABLE):
        first = backup_service.create_backup(label="blocked")
    assert first.get("success") is False

    second = backup_service.create_backup(label="after-release")
    assert second.get("success") is True, second.get("error")
    assert second["filename"].endswith(".enc")


def test_deadline_message_is_operator_readable_and_leaks_no_sql():
    """A raw driver traceback leaks paths and table layout; the translated one must not."""
    class FakeDriverError(Exception):
        pgcode = "55P03"

    translated = db_bounds.translate_driver_error(FakeDriverError("boom"), "table row counts")
    assert isinstance(translated, db_bounds.BoundedOperationTimeout)
    text = str(translated)
    assert "table row counts" in text
    assert "lock_timeout" in text
    assert "Traceback" not in text
    assert "SELECT" not in text


def test_untranslatable_errors_are_passed_through_unchanged():
    """A real error must not be mislabelled as a timeout, or it will never be diagnosed."""
    original = ValueError("something else entirely")
    assert db_bounds.translate_driver_error(original, "x") is original


# ---------------------------------------------------------------------------
# static guard: unbounded maintenance queries must not come back
# ---------------------------------------------------------------------------

def test_backup_service_has_no_unbounded_count_queries():
    """Fails if a ``SELECT COUNT(*)`` returns to the backup path outside db_bounds.

    This is the regression that would reintroduce P21-10: someone adds a cheap-looking
    count to the preflight, it runs on the application engine with statement_timeout = 0,
    and a lock makes every backup hang again. Any count query must go through
    :func:`core.db_bounds.bounded_session`.
    """
    source = (REPO_ROOT / "core" / "backup_service.py").read_text()
    tree = ast.parse(source)

    # SQLite has no server-side lock timeouts: a blocked writer gets SQLITE_BUSY from the
    # busy timeout, not a statement that waits. Bounding it is `timeout=` on connect, which
    # is set in _verify_restored_sqlite; there is no db_bounds equivalent to call.
    _no_lock_concept = {"_verify_restored_sqlite"}

    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        body_source = ast.get_source_segment(source, node) or ""
        # Any of the bounds helpers counts: the session context manager for plain queries,
        # bound_sqlalchemy_connection for the restore verifier's own engine, and
        # bound_dbapi_connection for the catalog checks.
        if any(
            marker in body_source
            for marker in (
                "db_bounds.bounded_session",
                "bound_sqlalchemy_connection",
                "bound_dbapi_connection",
                # psql subprocesses cannot use a connection helper; they carry the same
                # SETs inside the SQL they are given, which is equally binding.
                "SET lock_timeout",
                "SET statement_timeout",
            )
        ):
            continue
        if node.name in _no_lock_concept:
            continue
        if re.search(r"SELECT\s+COUNT\s*\(\s*\*\s*\)", body_source, re.IGNORECASE):
            offenders.append(node.name)

    assert offenders == [], (
        "these functions run COUNT(*) without db_bounds.bounded_session, so a lock can "
        f"hang them indefinitely: {offenders}"
    )


def test_every_backup_db_entry_point_is_bounded():
    """The preflight, the dump and the restore's reset must all consult the bounds module."""
    source = (REPO_ROOT / "core" / "backup_service.py").read_text()
    assert "db_bounds.Deadline" in source
    assert "db_bounds.bounded_session" in source
    # Reading the env var here would create a second source of truth for the deadline.
    assert 'getenv("BACKUP_DB_OPERATION_DEADLINE"' not in source, (
        "the deadline must be read from core.db_bounds, not duplicated in the service"
    )


def test_restore_statements_carry_their_own_lock_and_statement_timeouts():
    """The reset path already bounded itself before P21-10; that must not regress."""
    source = (REPO_ROOT / "core" / "backup_service.py").read_text()
    assert "lock_timeout" in source
    assert "statement_timeout" in source
