"""Phase 24 (F-1) - a backup directory entry must not escape the backup directory.

Reproduced before the fix, on a disposable database: a symlink inside `BACKUP_DIR` pointing at
a valid `pg_dump` elsewhere on the filesystem was accepted by `verify_backup()`, extracted, and
executed by `psql` during `restore_backup()`. The restore failed only because the dump
contained a trigger the disposable database did not have - the SQL was already running.

Who can reach this: anything that can write to `BACKUP_DIR`. That is the maintenance service
account and any operator who runs `prune`, so it is a wider set than "root". The threat is
choosing the contents of a restore, not reading the destination.

`resolve()` guarded the encrypted path; `verify_backup()` joined `BACKUP_DIR + name` directly
for everything else, so a first attempt at the fix left the plaintext path open. Both entry
points now share one check.
"""

import gzip
import hashlib
import os
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from core import backup_archive  # noqa: E402


@pytest.fixture()
def backup_dir(tmp_path):
    directory = tmp_path / "backups"
    directory.mkdir()
    return directory


@pytest.fixture()
def outside(tmp_path):
    directory = tmp_path / "outside"
    directory.mkdir()
    return directory


def test_a_symlink_escaping_the_directory_is_refused(backup_dir, outside):
    target = outside / "payload.sql.gz"
    target.write_bytes(gzip.compress(b"-- not really a dump\n"))
    link = backup_dir / "innocent.sql.gz"
    link.symlink_to(target)

    with pytest.raises(backup_archive.ArchiveError) as raised:
        backup_archive.assert_contained(str(backup_dir), "innocent.sql.gz")
    assert "outside the backup directory" in str(raised.value)


def test_a_symlink_inside_the_directory_is_allowed(backup_dir):
    """A link that stays inside is a legitimate layout and must keep working."""
    target = backup_dir / "real.sql.gz"
    target.write_bytes(gzip.compress(b"-- dump\n"))
    (backup_dir / "alias.sql.gz").symlink_to(target)

    result = backup_archive.assert_contained(str(backup_dir), "alias.sql.gz")
    assert result.endswith("alias.sql.gz")


def test_a_plain_file_is_allowed(backup_dir):
    (backup_dir / "plain.sql.gz").write_bytes(b"x")
    assert backup_archive.assert_contained(str(backup_dir), "plain.sql.gz")


def test_traversal_in_the_name_cannot_escape(backup_dir):
    """A traversal name must never resolve outside the directory.

    `basename()` strips the traversal, so the result is a name *inside* the backup directory
    rather than an exception - there is nothing outside to reach, which is the property that
    matters. An absolute path is handled the same way: `/etc/passwd` becomes
    `<backup_dir>/passwd`, and only resolves if such a file exists there.
    """
    for name in ("../../x.sql.gz", "..%2fx.sql.gz", "/etc/passwd", "..\\..\\x.sql.gz"):
        resolved = backup_archive.assert_contained(str(backup_dir), name)
        # The only property that matters: whatever the name, the result is a plain entry
        # inside the backup directory. On Linux a backslash is not a separator, so such a
        # name stays whole - as a harmless literal filename, still inside the directory.
        assert os.path.dirname(resolved) == str(backup_dir), resolved
        assert os.path.basename(resolved) == os.path.basename(name)


def test_resolve_refuses_an_escaping_symlink(backup_dir, outside, monkeypatch):
    target = outside / "payload.sql.gz.enc"
    target.write_bytes(b"SYNTHETICX" + b"\x00" * 64)
    (backup_dir / "disguised.sql.gz.enc").symlink_to(target)

    with pytest.raises(backup_archive.ArchiveError) as raised:
        backup_archive.resolve(str(backup_dir), "disguised.sql.gz.enc", None)
    assert "outside the backup directory" in str(raised.value)


def test_verify_backup_refuses_an_escaping_symlink(backup_dir, outside, monkeypatch):
    """The entry point the first fix missed: the plaintext branch never called resolve()."""
    from core import backup_service

    target = outside / "valid.sql.gz"
    target.write_bytes(gzip.compress(b"-- a dump that would otherwise pass\n"))
    (backup_dir / "valid.sql.gz").symlink_to(target)

    monkeypatch.setattr(backup_service, "BACKUP_DIR", str(backup_dir))
    result = backup_service.verify_backup("valid.sql.gz")
    assert result["valid"] is False
    assert "outside the backup directory" in result["error"]


def test_restore_backup_refuses_an_escaping_symlink(backup_dir, outside, monkeypatch):
    """The operation that matters: an escaping link must never be executed."""
    from core import backup_service

    target = outside / "valid.sql.gz"
    target.write_bytes(gzip.compress(b"-- a dump that would otherwise pass\n"))
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    (backup_dir / "valid.sql.gz").symlink_to(target)
    (backup_dir / "valid.sql.gz.sha256").write_text(f"{digest}  valid.sql.gz\n", encoding="utf-8")

    monkeypatch.setattr(backup_service, "BACKUP_DIR", str(backup_dir))
    result = backup_service.restore_backup("valid.sql.gz")
    assert result["success"] is False
    assert "outside the backup directory" in str(result.get("error"))


def test_both_entry_points_share_one_check():
    """Structural: two copies of a security check drift apart - that already happened once."""
    archive_source = (REPO_ROOT / "core" / "backup_archive.py").read_text(encoding="utf-8")
    service_source = (REPO_ROOT / "core" / "backup_service.py").read_text(encoding="utf-8")
    assert "def assert_contained" in archive_source
    # resolve() must delegate, not reimplement.
    assert "assert_contained(directory, clean)" in archive_source
    # verify_backup must call it.
    assert "backup_archive.assert_contained(BACKUP_DIR" in service_source
    # And the escape message must be built in exactly one place. The f-string is split
    # across two source lines, so count the opening phrase instead.
    assert archive_source.count("resolves to {real_path}") == 1
    assert "outside the backup directory" not in service_source
