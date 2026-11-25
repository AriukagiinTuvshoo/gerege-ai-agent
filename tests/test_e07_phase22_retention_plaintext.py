"""Phase 22 / P21-03 - retention, plaintext detection, quarantine and staging sweep.

Phase 21 found the retention code and its own documentation on opposite sides of a promise:
`prune()` deleted plaintext archives under the age rule, while `legacy_plaintext_archives()`
- which existed to detect exactly those files - had no callers and its docstring said they
are "detected and reported but never removed automatically".

The tests below pin the behaviour rather than the prose, because the prose was already
correct and the code was not.
"""

import gzip
import os
import pathlib
import subprocess
import sys
import time

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def _plaintext(directory: pathlib.Path, name: str, age_days: int = 100) -> pathlib.Path:
    path = directory / name
    with gzip.open(path, "wb") as handle:
        handle.write(b"tenant data in the clear")
    stamp = time.time() - age_days * 86400
    os.utime(path, (stamp, stamp))
    return path


_KEY_FILE = None


def _key_file() -> str:
    """A 32-byte key file for archive creation, created once per process."""
    global _KEY_FILE
    if _KEY_FILE and os.path.exists(_KEY_FILE):
        return _KEY_FILE
    import tempfile

    handle, path = tempfile.mkstemp(prefix="p22-key-", suffix=".bin")
    with os.fdopen(handle, "wb") as fh:
        fh.write(bytes(range(32)))
    os.chmod(path, 0o600)
    _KEY_FILE = path
    return path


def _encrypted(directory: pathlib.Path, name: str, age_days: int = 100,
               tmp_path_factory=None) -> pathlib.Path:
    """A genuinely authenticated archive.

    Deliberately not fake bytes: `prune()` now refuses to delete anything it cannot
    classify, so a placeholder file would be exempt for the wrong reason and the test would
    pass without exercising the retention rule it claims to test.

    The key is written once per process into a temp file, because `encrypt_file` takes a
    key *path* - the key never leaves this helper as a literal in a tracked file.
    """
    from core import backup_crypto

    key_file = _key_file()
    path = directory / name
    source = directory / (name + ".src")
    source.write_bytes(b"dump payload " * 16)
    info = backup_crypto.encrypt_file(str(source), str(path), key_file)
    assert info, "encryption returned nothing"
    source.unlink()
    stamp = time.time() - age_days * 86400
    os.utime(path, (stamp, stamp))
    return path


# ---------------------------------------------------------------------------
# Retention must not delete plaintext
# ---------------------------------------------------------------------------


def test_prune_never_deletes_a_plaintext_archive(tmp_path):
    """The finding, as a test.

    An aged plaintext dump next to an aged encrypted archive: before the fix, `prune()`
    deleted both plaintext files and kept the encrypted one, which is the inverse of the
    documented rule. Plaintext may only be removed by an explicit quarantine.
    """
    from core import backup_automation

    _plaintext(tmp_path, "pg_backup_old1_20200101.sql.gz")
    _plaintext(tmp_path, "pg_backup_old2_20200101.sql.gz")
    _encrypted(tmp_path, "pg_backup_enc_20200101.sql.gz.enc")

    removed = backup_automation.prune(str(tmp_path), days=30, keep_min=1)

    assert not any(name.endswith(".sql.gz") for name in removed), (
        f"prune deleted plaintext: {removed}"
    )
    remaining = sorted(p.name for p in tmp_path.iterdir())
    assert "pg_backup_old1_20200101.sql.gz" in remaining
    assert "pg_backup_old2_20200101.sql.gz" in remaining


def test_prune_still_deletes_aged_encrypted_archives(tmp_path):
    """The fix must not disable retention itself - only plaintext and unknown deletion."""
    from core import backup_automation

    for index in range(3):
        _encrypted(tmp_path, f"pg_backup_e{index}_20200101.sql.gz.enc", age_days=100 + index)

    removed = backup_automation.prune(str(tmp_path), days=30, keep_min=1)
    assert len(removed) == 2, removed
    assert len(list(tmp_path.iterdir())) == 1


def test_prune_floor_counts_encrypted_not_plaintext(tmp_path):
    """A plaintext leftover must not satisfy the retention floor.

    Phase 20 fixed this for the floor calculation; the exclusion added here must not
    re-open it by accident.
    """
    from core import backup_automation

    _plaintext(tmp_path, "pg_backup_p_20200101.sql.gz", age_days=200)
    _encrypted(tmp_path, "pg_backup_a_20200101.sql.gz.enc", age_days=100)
    _encrypted(tmp_path, "pg_backup_b_20200101.sql.gz.enc", age_days=101)

    removed = backup_automation.prune(str(tmp_path), days=30, keep_min=1)
    # The newest encrypted archive survives; the older encrypted one goes; plaintext stays.
    assert (tmp_path / "pg_backup_a_20200101.sql.gz.enc").exists()
    assert not (tmp_path / "pg_backup_b_20200101.sql.gz.enc").exists()
    assert (tmp_path / "pg_backup_p_20200101.sql.gz").exists()
    assert removed == ["pg_backup_b_20200101.sql.gz.enc"]


def test_dry_run_reports_but_does_not_delete_anything(tmp_path):
    from core import backup_automation

    _plaintext(tmp_path, "pg_backup_p_20200101.sql.gz")
    _encrypted(tmp_path, "pg_backup_a_20200101.sql.gz.enc")

    before = sorted(p.name for p in tmp_path.iterdir())
    removed = backup_automation.prune(str(tmp_path), days=1, keep_min=1, dry_run=True)
    assert sorted(p.name for p in tmp_path.iterdir()) == before
    assert not any(name.endswith(".sql.gz") for name in removed)


def test_unknown_files_are_never_deleted(tmp_path):
    """`.enc` with no recognisable magic is not a backup and must not be swept."""
    from core import backup_automation

    stray = tmp_path / "pg_backup_unknown_20200101.sql.gz.enc"
    stray.write_bytes(b"not our format")
    stamp = time.time() - 500 * 86400
    os.utime(stray, (stamp, stamp))
    # Not an archive by name at all:
    other = tmp_path / "notes.gz"
    other.write_bytes(b"x")
    os.utime(other, (stamp, stamp))

    removed = backup_automation.prune(str(tmp_path), days=1, keep_min=1)
    assert removed == []
    assert stray.exists()
    assert other.exists()


# ---------------------------------------------------------------------------
# Detection inventory: the helper that had no callers
# ---------------------------------------------------------------------------


def test_plaintext_inventory_is_not_dead_code():
    """`legacy_plaintext_archives()` must have a caller, or it is documentation.

    Guarding this structurally because the defect WAS dead code: the function existed, was
    correct, and nothing called it while a different code path did the opposite.
    """
    callers = []
    for path in REPO_ROOT.rglob("*.py"):
        if "tests" in path.parts:
            continue
        if path.name == "backup_automation.py":
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "legacy_plaintext_archives(" in text:
            callers.append(str(path.relative_to(REPO_ROOT)))
    assert callers, "legacy_plaintext_archives() has no callers again"


def test_plaintext_inventory_agrees_with_classification(tmp_path):
    from core import backup_automation

    _plaintext(tmp_path, "pg_backup_p_20200101.sql.gz")
    (tmp_path / "pg_backup_u_20200101.sql.gz.enc").write_bytes(b"not our format")

    inventory = {name for name, _st in backup_automation.legacy_plaintext_archives(str(tmp_path))}
    classified = {
        name for name in (p.name for p in tmp_path.iterdir())
        if backup_automation.classify_archive(str(tmp_path / name)) == "plaintext"
    }
    assert inventory == classified == {"pg_backup_p_20200101.sql.gz"}


# ---------------------------------------------------------------------------
# Quarantine: the only path that may move plaintext, and it moves, never deletes
# ---------------------------------------------------------------------------


def _legacy_cli(tmp_path, *extra, backdir=None):
    env = {**os.environ, "BACKUP_DIR": str(backdir or tmp_path), "PYTHONPATH": str(REPO_ROOT)}
    env.pop("DATABASE_URL", None)
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "maintenance.py"), "legacy", *extra],
        cwd=str(REPO_ROOT), env=env, capture_output=True, text=True, timeout=120,
    )


def test_legacy_reports_plaintext_and_exits_17(tmp_path):
    _plaintext(tmp_path, "pg_backup_p_20200101.sql.gz")
    result = _legacy_cli(tmp_path)
    assert result.returncode == 17
    assert "pg_backup_p_20200101.sql.gz" in result.stdout


def test_legacy_clean_directory_exits_zero(tmp_path):
    result = _legacy_cli(tmp_path)
    assert result.returncode == 0


def test_quarantine_requires_confirmation(tmp_path):
    _plaintext(tmp_path, "pg_backup_p_20200101.sql.gz")
    target = tmp_path.parent / (tmp_path.name + "_q")
    result = _legacy_cli(tmp_path, "--quarantine", str(target))
    assert result.returncode == 17
    assert (tmp_path / "pg_backup_p_20200101.sql.gz").exists()
    assert not target.exists()


def test_quarantine_moves_and_never_deletes(tmp_path):
    source = _plaintext(tmp_path, "pg_backup_p_20200101.sql.gz")
    original = source.read_bytes()
    target = tmp_path.parent / (tmp_path.name + "_q")
    try:
        result = _legacy_cli(tmp_path, "--quarantine", str(target), "--yes")
        assert result.returncode == 0, result.stderr
        assert not source.exists()
        moved = target / "pg_backup_p_20200101.sql.gz"
        assert moved.exists()
        # Byte-identical: this is a move, not a rewrite or a delete.
        assert moved.read_bytes() == original
        assert oct(target.stat().st_mode & 0o777) == "0o700"
    finally:
        if target.exists():
            for item in target.iterdir():
                item.unlink()
            target.rmdir()


def test_quarantine_refuses_to_target_the_backup_directory_itself(tmp_path):
    _plaintext(tmp_path, "pg_backup_p_20200101.sql.gz")
    result = _legacy_cli(tmp_path, "--quarantine", str(tmp_path), "--yes")
    assert result.returncode == 17
    assert (tmp_path / "pg_backup_p_20200101.sql.gz").exists()


# ---------------------------------------------------------------------------
# Staging sweep
# ---------------------------------------------------------------------------


def test_staging_residue_is_swept_and_fresh_residue_is_not(tmp_path):
    """A crash leaves `.staging-<pid>-*` behind. Sweep the dead, never the live.

    The directory name embeds the owning PID, and the sweep skips a directory whose process
    is still alive (or that is younger than `max_age`). Both guards are exercised here: a
    dead PID with old mtime goes, a live PID with old mtime stays.
    """
    import os as _os

    from core import backup_staging

    prefix = backup_staging.STAGING_PREFIX

    # Dead PID (one that cannot be running: well above the usual pid_max) + old mtime.
    dead = tmp_path / f"{prefix}999999-deadbeef"
    dead.mkdir()
    (dead / "half-written.enc").write_bytes(b"partial plaintext")
    stamp = time.time() - 24 * 3600
    _os.utime(dead, (stamp, stamp))

    # A live PID *and* old mtime: the liveness check, not the age check, must save it.
    live = tmp_path / f"{prefix}{_os.getpid()}-cafe0000"
    live.mkdir()
    (live / "in-progress.enc").write_bytes(b"live")
    _os.utime(live, (stamp, stamp))

    removed = backup_staging.sweep_stale_staging(str(tmp_path), max_age=3600)

    assert dead.name in removed
    assert not dead.exists(), "stale staging residue was not swept"
    assert live.exists(), "a staging directory whose process is alive must not be swept"
    assert live.name not in removed
