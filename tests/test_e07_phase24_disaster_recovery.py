"""Phase 24 - disaster recovery scenarios on a disposable PostgreSQL database.

Every scenario here manipulates a real encrypted archive and a real database, because the
failures that matter (a truncated ciphertext, a wrong key, a manifest that disagrees with the
data) cannot be reproduced with mocks. Nothing touches a shared or production database: the
tests require an explicit `P24_DR_DATABASE_URL` and refuse to run without one.

The distinction these tests exist to protect:

* `success` - the data was restored.
* `post_restore_verified` - the row counts were compared against a manifest and matched.

They are separate. A pre-manifest archive restores correctly and cannot be verified; that is a
reduced claim, not a failure, and collapsing the two would either break recovery of old
archives or let an unverified restore masquerade as a verified one.

Timings are recorded, not asserted. They describe a 19-table fixture on a local cluster and
say nothing about a production dataset - see docs/DISASTER-RECOVERY.md.
"""

import glob
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

DR_URL = os.getenv("P24_DR_DATABASE_URL", "")


def _configured() -> bool:
    return bool(DR_URL) and "postgresql" in DR_URL


pytestmark = pytest.mark.skipif(
    not _configured(),
    reason="P24_DR_DATABASE_URL not set: DR scenarios need a disposable PostgreSQL database",
)


@pytest.fixture()
def dr(tmp_path, monkeypatch):
    """Point the backup service at a private directory and a disposable database."""
    from core import backup_service

    if not os.getenv("BACKUP_ENCRYPTION_KEY_FILE"):
        pytest.skip("no BACKUP_ENCRYPTION_KEY_FILE configured")

    monkeypatch.setenv("DATABASE_URL", DR_URL)
    monkeypatch.setenv("DATABASE_OWNER_URL", DR_URL.replace("+psycopg2", ""))
    monkeypatch.setenv("ENV", "production")
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    monkeypatch.setattr(backup_service, "BACKUP_DIR", str(backup_dir))

    return {"service": backup_service, "dir": backup_dir, "tmp": tmp_path}


def _rows_in_db(url: str, table: str = "pages") -> int:
    """Read a row count directly, bypassing the code under test."""
    libpq = url.replace("postgresql+psycopg2://", "postgresql://")
    password = libpq.split("://")[1].split("@")[0].split(":")[1]
    result = subprocess.run(
        ["psql", "-h", "127.0.0.1", "-U", "gerege_owner", "-d", libpq.rsplit("/", 1)[-1],
         "-tAc", f"select count(*) from {table}"],
        capture_output=True, text=True, env={**os.environ, "PGPASSWORD": password},
    )
    return int((result.stdout or "0").strip() or 0)


def _archive(directory) -> str:
    found = sorted(glob.glob(str(directory / "*.enc")))
    assert found, "a backup run produced no .enc archive"
    return os.path.basename(found[-1])


# ---------------------------------------------------------------------------
# Normal operation, measured
# ---------------------------------------------------------------------------


def test_normal_backup_verify_restore_round_trip_with_timings(dr):
    service, directory = dr["service"], dr["dir"]
    started = time.time()
    created = service.create_backup(label="p24-dr")
    backup_s = time.time() - started
    assert created["success"] is True, created.get("error")

    filename = _archive(directory)

    started = time.time()
    verified = service.verify_backup(filename)
    verify_s = time.time() - started
    assert verified.get("valid") is True

    started = time.time()
    restored = service.restore_backup(filename)
    restore_s = time.time() - started

    assert restored["success"] is True, restored.get("error")
    assert restored["post_restore_verified"] is True
    assert restored["row_counts_checked"] is True

    print(
        f"\n  measured: backup={backup_s:.2f}s verify={verify_s:.2f}s restore={restore_s:.2f}s "
        f"archive={created.get('size_bytes')}B"
    )
    # Loose upper bounds only: these catch a pathological regression (a hang), not a slow
    # machine. They are not an RTO and must not be quoted as one.
    assert backup_s < 300
    assert restore_s < 300


# ---------------------------------------------------------------------------
# Adversarial inputs
# ---------------------------------------------------------------------------


def test_a_truncated_archive_is_rejected(dr):
    service, directory = dr["service"], dr["dir"]
    service.create_backup(label="p24-trunc")
    path = directory / _archive(directory)

    data = path.read_bytes()
    path.write_bytes(data[: len(data) // 2])

    result = service.restore_backup(path.name)
    assert result["success"] is False
    assert result["post_restore_verified"] is False
    assert "checksum" in str(result.get("error", "")).lower()


def test_a_wrong_encryption_key_is_rejected(dr, tmp_path, monkeypatch):
    service, directory = dr["service"], dr["dir"]
    service.create_backup(label="p24-key")
    filename = _archive(directory)

    wrong = tmp_path / "wrong.key"
    wrong.write_bytes(os.urandom(32))
    wrong.chmod(0o600)
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", str(wrong))

    result = service.restore_backup(filename)
    assert result["success"] is False
    assert "authentication" in str(result.get("error", "")).lower()


def test_a_missing_encryption_key_is_rejected(dr, tmp_path, monkeypatch):
    service, directory = dr["service"], dr["dir"]
    service.create_backup(label="p24-nokey")
    filename = _archive(directory)

    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", str(tmp_path / "absent.key"))

    result = service.restore_backup(filename)
    assert result["success"] is False
    assert "key" in str(result.get("error", "")).lower()


def test_a_missing_manifest_restores_but_does_not_claim_verification(dr):
    """The D-6 property, at the disaster-recovery level.

    A pre-manifest archive must remain recoverable - refusing it would make old backups
    unusable - but the restore must not report a content verification it did not perform.
    """
    service, directory = dr["service"], dr["dir"]
    service.create_backup(label="p24-nomanifest")
    filename = _archive(directory)

    for manifest in glob.glob(str(directory / "*.meta.json")):
        os.unlink(manifest)

    result = service.restore_backup(filename)
    assert result["success"] is True, "a legacy archive must still be recoverable"
    assert result["post_restore_verified"] is False, (
        "nothing was compared, so a verified restore must not be claimed"
    )
    assert result["row_counts_checked"] is False
    assert result.get("verification_note")


def test_an_incorrect_manifest_is_caught_and_rolled_back(dr):
    """A manifest that disagrees with the data proves the verification is real."""
    service, directory = dr["service"], dr["dir"]
    service.create_backup(label="p24-badmanifest")
    filename = _archive(directory)

    for manifest in glob.glob(str(directory / "*.enc.meta.json")):
        with open(manifest, encoding="utf-8") as handle:
            data = json.load(handle)
        data["table_counts"]["pages"] = 999_999
        with open(manifest, "w", encoding="utf-8") as handle:
            json.dump(data, handle)

    result = service.restore_backup(filename)
    assert result["success"] is False
    assert result["post_restore_verified"] is False
    assert "row count mismatch" in str(result.get("error", "")).lower()


def test_a_failed_restore_rolls_back_and_preserves_the_original_data(dr):
    """The property that makes rollback worth having: a bad restore must not destroy data."""
    service, directory = dr["service"], dr["dir"]
    service.create_backup(label="p24-rollback")
    filename = _archive(directory)

    before = _rows_in_db(DR_URL)
    assert before >= 1, "fixture database has no rows to protect"

    for manifest in glob.glob(str(directory / "*.enc.meta.json")):
        with open(manifest, encoding="utf-8") as handle:
            data = json.load(handle)
        data["table_counts"]["pages"] = 999_999
        with open(manifest, "w", encoding="utf-8") as handle:
            json.dump(data, handle)

    result = service.restore_backup(filename)
    assert result["success"] is False
    assert result["rolled_back"] is True
    assert result["rollback_status"] == "ROLLED_BACK_TO_PRE_SNAPSHOT"

    after = _rows_in_db(DR_URL)
    assert after == before, f"rollback lost data: {before} rows before, {after} after"


def test_restore_is_idempotent(dr):
    """Running the same restore twice must converge, not accumulate."""
    service, directory = dr["service"], dr["dir"]
    service.create_backup(label="p24-idem")
    filename = _archive(directory)

    first = service.restore_backup(filename)
    second = service.restore_backup(filename)
    assert first["success"] is True
    assert second["success"] is True
    assert first["restored_table_counts"]["pages"] == second["restored_table_counts"]["pages"]


def test_the_pre_restore_snapshot_is_itself_encrypted(dr):
    """A rollback path that writes a plaintext dump defeats the encryption policy."""
    service, directory = dr["service"], dr["dir"]
    service.create_backup(label="p24-presnap")
    filename = _archive(directory)
    service.restore_backup(filename)

    plaintext = glob.glob(str(directory / "*.sql.gz")) + glob.glob(str(directory / "*.db"))
    assert plaintext == [], f"restore left plaintext archives behind: {plaintext}"


# ---------------------------------------------------------------------------
# Database unavailability
# ---------------------------------------------------------------------------


def test_a_backup_against_an_unreachable_database_fails_without_publishing(dr, monkeypatch):
    """PostgreSQL unavailable: nothing is published, the failure is bounded, and it is named.

    `create_backup` RAISES `MaintenanceCredentialRequired` here rather than returning a
    failure dict: an unreachable database is a precondition it cannot satisfy, and the
    caller is expected to be the CLI (which now turns it into exit 15 and one line). An
    earlier draft of this test asserted a failure dict and was wrong about the contract -
    the exception is deliberate, so the test asserts it instead of papering over it.
    """
    service, directory = dr["service"], dr["dir"]
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg2://gerege_owner:wrong@127.0.0.1:59999/nope")
    monkeypatch.setenv("DATABASE_OWNER_URL", "postgresql://gerege_owner:wrong@127.0.0.1:59999/nope")

    from core.backup_service import MaintenanceCredentialRequired

    started = time.time()
    with pytest.raises(MaintenanceCredentialRequired) as raised:
        service.create_backup(label="p24-unreachable")
    elapsed = time.time() - started

    assert "cannot reach the database" in str(raised.value)
    assert elapsed < 120, f"an unreachable database took {elapsed:.1f}s to fail"
    published = glob.glob(str(directory / "*.enc"))
    assert published == [], "a failed backup published an archive"


def test_the_cli_reports_an_unreachable_database_without_a_traceback(tmp_path):
    """D-8: an operator gets one diagnostic line, not 20 frames of SQLAlchemy internals."""
    import subprocess

    env = {
        **os.environ,
        "DATABASE_URL": "postgresql+psycopg2://gerege_owner:wrong@127.0.0.1:59999/nope",
        "DATABASE_OWNER_URL": "postgresql://gerege_owner:wrong@127.0.0.1:59999/nope",
        "BACKUP_DIR": str(tmp_path / "unreachable"),
        "ENV": "production",
    }
    if os.getenv("BACKUP_ENCRYPTION_KEY_FILE"):
        env["BACKUP_ENCRYPTION_KEY_FILE"] = os.environ["BACKUP_ENCRYPTION_KEY_FILE"]

    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "maintenance.py"), "backup", "--label", "x"],
        capture_output=True, text=True, env=env, timeout=180,
    )
    combined = result.stdout + result.stderr
    assert result.returncode == 15, f"expected the not-configured code, got {result.returncode}"
    assert "Traceback" not in combined, f"a traceback reached the operator:\n{combined[:600]}"
    assert "cannot reach the database" in combined
    # And nothing was published.
    assert list(pathlib.Path(env["BACKUP_DIR"]).glob("*.enc")) == []
