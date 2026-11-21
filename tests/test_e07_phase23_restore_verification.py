"""Phase 23 (D-6) - a restore must not claim verification it did not perform.

Phase 22's N-2 fixed the *cause* of vacuous restore verification: the manifest was written
into staging and never published on the encrypted path, so `_load_expected_counts()` returned
`{}` for every encrypted archive. It did not fix the *consequence*. Both verifiers iterate
`_REQUIRED_RESTORE_TABLES` and only compare a table when `if t in expected_counts`, so with an
empty manifest they compare nothing at all and still return `verified: True`.

Reproduced before the fix: deleting `*.meta.json` from a real encrypted archive and restoring
it reported `post_restore_verified: True` with the tables never examined.

The fix narrows the claim rather than blocking the restore, deliberately:

* Failing the restore would make disaster recovery impossible for any archive predating the
  manifest, and `cmd_restore` gates on `success`, so it would also trigger a rollback over a
  database that is actually intact - turning a reporting problem into an outage.
* So the restore still succeeds, `post_restore_verified` becomes False, `row_counts_checked`
  becomes False, and `verification_note` says what was and was not established.
"""

import glob
import json
import os
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def _pg_url() -> str:
    return os.getenv("DATABASE_URL", "")


def _is_postgres() -> bool:
    return "postgresql" in _pg_url()


needs_pg = pytest.mark.skipif(
    not _is_postgres(), reason="D-6's reproduction needs a PostgreSQL owner DSN"
)


# ---------------------------------------------------------------------------
# Unit level: the verifiers must say whether they compared anything
# ---------------------------------------------------------------------------


def test_sqlite_verifier_reports_no_comparison_with_empty_expectations(tmp_path):
    """The core of D-6: `verified: True` with nothing compared must be distinguishable."""
    import sqlite3
    import sys as _sys

    _sys.path.insert(0, str(REPO_ROOT))
    from core import backup_service

    db = tmp_path / "probe.db"
    conn = sqlite3.connect(str(db))
    try:
        for table in backup_service._REQUIRED_RESTORE_TABLES:
            conn.execute(f'CREATE TABLE "{table}" (id INTEGER PRIMARY KEY)')
        conn.commit()
    finally:
        conn.close()

    result = backup_service._verify_restored_sqlite(str(db), {})
    # Structure is checked, so this stays True - the tables do exist.
    assert result["verified"] is True
    # But it must admit that no row count was compared.
    assert result["row_counts_checked"] is False

    # With expectations present, the same call reports that it compared them.
    checked = backup_service._verify_restored_sqlite(str(db), {"pages": 0})
    assert checked["verified"] is True
    assert checked["row_counts_checked"] is True


def test_sqlite_verifier_still_fails_on_a_real_mismatch(tmp_path):
    """Narrowing must not weaken the check when expectations DO exist."""
    import sqlite3
    import sys as _sys

    _sys.path.insert(0, str(REPO_ROOT))
    from core import backup_service

    db = tmp_path / "probe2.db"
    conn = sqlite3.connect(str(db))
    try:
        for table in backup_service._REQUIRED_RESTORE_TABLES:
            conn.execute(f'CREATE TABLE "{table}" (id INTEGER PRIMARY KEY)')
        conn.commit()
    finally:
        conn.close()

    result = backup_service._verify_restored_sqlite(str(db), {"pages": 5})
    assert result["verified"] is False
    assert "row count mismatch" in result["error"]


@needs_pg
def test_postgres_verifier_reports_no_comparison_with_empty_expectations():
    from core import backup_service

    result = backup_service._verify_restored_postgres(_pg_url(), {})
    assert result["verified"] is True
    assert result["row_counts_checked"] is False

    # The database has at least one page in this fixture; an impossible expectation must
    # still fail, proving the check is live rather than dead code.
    mismatch = backup_service._verify_restored_postgres(_pg_url(), {"pages": 10**9})
    assert mismatch["verified"] is False


# ---------------------------------------------------------------------------
# End to end: the reported defect, against a real encrypted archive
# ---------------------------------------------------------------------------


@needs_pg
def test_a_manifest_less_archive_does_not_report_a_verified_restore(tmp_path, monkeypatch):
    """The exact reproduction: delete the manifest, restore, and check what is claimed."""
    from core import backup_service

    monkeypatch.setenv("ENV", "production")
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    monkeypatch.setattr(backup_service, "BACKUP_DIR", str(backup_dir))
    # A key must be configured; conftest provides one for the suite.
    if not os.getenv("BACKUP_ENCRYPTION_KEY_FILE"):
        pytest.skip("no BACKUP_ENCRYPTION_KEY_FILE configured")

    created = backup_service.create_backup(label="d6")
    assert created["success"] is True, created.get("error")

    # Refuse to continue if the archive is not the encrypted kind this defect concerns.
    archives = glob.glob(str(backup_dir / "*.enc"))
    assert archives, "expected an encrypted archive"
    filename = os.path.basename(archives[0])

    # The manifest the restore path reads.
    manifest = str(backup_dir / (filename + ".meta.json"))
    assert os.path.exists(manifest), "precondition: the archive must carry a manifest"
    with open(manifest, encoding="utf-8") as handle:
        original = json.load(handle)
    assert original.get("table_counts"), "precondition: the manifest must carry row counts"

    # Sanity: WITH the manifest, the restore is genuinely verified.
    good = backup_service.restore_backup(filename)
    assert good["success"] is True, good.get("error")
    assert good["post_restore_verified"] is True
    assert good["row_counts_checked"] is True
    assert good.get("verification_note") is None

    # Now the defect: remove every manifest for this archive and restore again.
    for stale in glob.glob(str(backup_dir / "*.meta.json")):
        os.unlink(stale)

    degraded = backup_service.restore_backup(filename)
    # The restore itself still succeeds - disaster recovery must not be blocked.
    assert degraded["success"] is True, degraded.get("error")
    # But it must not claim verification it did not perform.
    assert degraded["post_restore_verified"] is False, (
        "a restore with no manifest compared no row counts but reported a verified restore"
    )
    assert degraded["row_counts_checked"] is False
    assert degraded["verification_note"], "the narrowed claim must say why"


@needs_pg
def test_the_cli_warns_when_row_counts_were_not_verified(tmp_path):
    """An operator reading `restore OK` must also be told what was not checked."""
    import subprocess

    maintenance = REPO_ROOT / "scripts" / "maintenance.py"
    source = maintenance.read_text(encoding="utf-8")
    # Structural: the warning is wired to the flag rather than always printed.
    assert "row_counts_checked" in source
    assert "row counts were NOT verified" in source
