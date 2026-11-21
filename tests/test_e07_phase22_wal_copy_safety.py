"""Phase 22 - CI step 17 root cause, as a regression test.

Step 17 ("Run Pytest Regression, Enterprise, AI Eval & Failure Suites (SQLite mode)") failed
on every Phase 22 push while passing locally. The failing test was:

    tests/test_failure_scenarios.py::test_scenario_11_migration_conflict_detected_and_aborted_without_overwrite

with:

    sqlite3.OperationalError: no such table: pages

Root cause, not environmental: the application opens SQLite in **WAL mode**, and the test
prepared its fixtures with `shutil.copy2(database.DB_PATH, ...)`. A WAL-mode database keeps
committed data - including `CREATE TABLE` - in the `-wal` sidecar until SQLite checkpoints.
`shutil.copy2` copies only the main file, so the copy is a database that may be missing
entire tables. Whether it is missing them depends on when the last checkpoint happened,
which differs between machines and is why the same commit passed locally 151/151 and failed
in CI.

The tests below pin the mechanism rather than the symptom, so the suite cannot silently
regress to an unsound copy:

* `test_shutil_copy2_of_a_wal_database_is_incomplete` demonstrates the defect exists and is
  reachable (it is the negative control - it asserts the *broken* behaviour of the wrong
  API, which is what makes the fix meaningful);
* `test_backup_api_reads_through_the_wal` proves the helper the suite now uses does not have
  the defect;
* `test_scenario_11_uses_the_wal_safe_copy` is a structural guard so the scenario cannot
  drift back to `shutil.copy2`.
"""

import os
import pathlib
import shutil
import sqlite3
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tests.conftest import copy_sqlite_database  # noqa: E402


def _wal_resident_database(path: pathlib.Path) -> sqlite3.Connection:
    """Create a database whose whole schema lives in the `-wal` file.

    Returns the open connection; the caller must keep it open, because closing it is what
    triggers SQLite's last-connection checkpoint and would move the schema into the main
    file - destroying the state this fixture exists to create.
    """
    if path.exists():
        path.unlink()
    for sidecar in (path.with_suffix(path.suffix + "-wal"),
                    path.with_suffix(path.suffix + "-shm")):
        if sidecar.exists():
            sidecar.unlink()

    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=WAL")
    # Nothing is committed to the main database file until a checkpoint, so creating the
    # schema here leaves it reachable only through the WAL.
    conn.execute("CREATE TABLE pages (page_id TEXT PRIMARY KEY, name TEXT)")
    conn.execute("INSERT INTO pages VALUES ('BASE', 'base row')")
    conn.commit()
    return conn


def test_a_wal_database_really_can_be_main_file_incomplete(tmp_path):
    """Precondition: the scenario is real, not hypothetical."""
    live = tmp_path / "live.db"
    holder = _wal_resident_database(live)
    try:
        assert live.stat().st_size > 0
        wal = pathlib.Path(str(live) + "-wal")
        assert wal.exists() and wal.stat().st_size > 0, (
            "the fixture failed to keep the schema WAL-resident"
        )
    finally:
        holder.close()


def test_shutil_copy2_of_a_wal_database_is_incomplete(tmp_path):
    """NC: the unsound API, demonstrated. This is what failed in CI.

    Asserts the *broken* behaviour deliberately. If a future change makes this pass
    differently, the premise of the fix has changed and someone should re-examine it.
    """
    live = tmp_path / "live.db"
    holder = _wal_resident_database(live)
    try:
        copy = tmp_path / "copy.db"
        shutil.copy2(live, copy)
        tables = sqlite3.connect(str(copy)).execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        assert tables == [], (
            "expected the main-file-only copy to lack the schema; if SQLite checkpointed "
            "before the copy this check cannot observe the defect"
        )
        with pytest.raises(sqlite3.OperationalError, match="no such table: pages"):
            sqlite3.connect(str(copy)).execute("UPDATE pages SET name='x' WHERE page_id='BASE'")
    finally:
        holder.close()


def test_backup_api_reads_through_the_wal(tmp_path):
    """The fix: `copy_sqlite_database` produces a complete database in the same state."""
    live = tmp_path / "live.db"
    holder = _wal_resident_database(live)
    try:
        copy = tmp_path / "copy.db"
        copy_sqlite_database(str(live), str(copy))

        conn = sqlite3.connect(str(copy))
        try:
            tables = {row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
            assert "pages" in tables, f"WAL-resident schema was lost: {tables}"
            assert conn.execute("SELECT page_id FROM pages").fetchall() == [("BASE",)]
            # And the caller's next statement - the one that failed in CI - works.
            conn.execute("UPDATE pages SET name='CONFLICTING_TARGET_NAME' WHERE page_id='BASE'")
            conn.commit()
        finally:
            conn.close()
    finally:
        holder.close()


def test_copy_sqlite_database_refuses_a_missing_source(tmp_path):
    """A missing source must raise, never yield a silently empty database."""
    with pytest.raises(FileNotFoundError):
        copy_sqlite_database(str(tmp_path / "absent.db"), str(tmp_path / "out.db"))


def test_scenario_11_uses_the_wal_safe_copy():
    """Structural guard: the failing scenario must not drift back to `shutil.copy2`."""
    source = (REPO_ROOT / "tests" / "test_failure_scenarios.py").read_text(encoding="utf-8")
    start = source.index("def test_scenario_11_migration_conflict_detected_and_aborted_without_overwrite")
    end = source.index("\ndef test_scenario_12_", start)
    body = source[start:end]
    assert "shutil.copy2(database.DB_PATH" not in body, (
        "scenario 11 copies the live WAL-mode database with shutil.copy2 again; the copy "
        "can be missing tables"
    )
    assert "copy_sqlite_database(database.DB_PATH" in body


def test_live_database_is_actually_in_wal_mode():
    """The premise of all of the above: the product really does run SQLite in WAL mode.

    If this ever stops being true the WAL-safe helper is unnecessary, and this test is the
    place that says so.
    """
    url = os.environ.get("DATABASE_URL", "")
    if url and "postgres" in url:
        pytest.skip("PostgreSQL is the engine under test; WAL mode does not apply")
    import database

    conn = database.get_connection()
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    finally:
        conn.close()
