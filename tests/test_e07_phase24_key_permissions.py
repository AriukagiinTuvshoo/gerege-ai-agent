"""Phase 24 (F-2) - a key file readable by others is reported, never enforced.

A mode-0644 encryption key is readable by every local account, and that is enough to decrypt
every archive on the host: the encryption stops protecting against local users entirely.

The check warns and does not deny, deliberately. Denying would also deny *restore* during the
incident the key exists for, and an over-permissive key is not a reason to be unable to
recover. That is the same reasoning that kept the missing-manifest defect from being turned
into a destructive restore failure.
"""

import os
import pathlib
import stat
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from core import backup_policy  # noqa: E402

pytestmark = pytest.mark.skipif(
    not hasattr(os, "getuid"), reason="POSIX permission bits are the subject of this test"
)


@pytest.fixture()
def key_file(tmp_path):
    path = tmp_path / "backup.key"
    path.write_bytes(os.urandom(32))
    return path


def evaluate_with(monkeypatch, key_path):
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", str(key_path))
    monkeypatch.setenv("ENV", "production")
    return backup_policy.evaluate()


def test_a_private_key_produces_no_warning(key_file, monkeypatch):
    os.chmod(key_file, 0o600)
    policy = evaluate_with(monkeypatch, key_file)
    assert policy.allowed is True
    assert policy.warning == ""


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660])
def test_a_key_readable_by_others_warns_but_does_not_block(key_file, monkeypatch, mode):
    os.chmod(key_file, mode)
    policy = evaluate_with(monkeypatch, key_file)
    # The property that matters: still usable, so recovery is still possible.
    assert policy.allowed is True
    assert policy.code == "ENCRYPTED"
    assert "accessible to group/others" in policy.warning
    assert "chmod 600" in policy.warning


def test_the_warning_names_the_mode_but_not_the_key(key_file, monkeypatch):
    os.chmod(key_file, 0o644)
    policy = evaluate_with(monkeypatch, key_file)
    assert f"{0o644:03o}" in policy.warning
    # Never the key material, and never the full path - only the basename.
    raw = key_file.read_bytes()
    assert raw.hex() not in policy.warning
    assert str(key_file.parent) not in policy.warning


def test_execute_only_for_others_still_warns(key_file, monkeypatch):
    """0o601 grants no read to others, but a mode that odd is worth mentioning."""
    os.chmod(key_file, 0o601)
    policy = evaluate_with(monkeypatch, key_file)
    assert policy.allowed is True
    assert policy.warning != ""


def test_describe_surfaces_the_warning(key_file, monkeypatch):
    """`maintenance.py status` must show it, or nobody will ever see it."""
    os.chmod(key_file, 0o644)
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", str(key_file))
    monkeypatch.setenv("ENV", "production")
    summary = backup_policy.describe()
    assert "accessible to group/others" in summary["warning"]


def test_restore_is_not_blocked_by_a_permissive_key(key_file, monkeypatch):
    """The explicit non-goal: an exposed key must not cost us the restore."""
    os.chmod(key_file, 0o644)
    policy = evaluate_with(monkeypatch, key_file)
    assert policy.allowed is True, "a permissive key must never prevent a restore"


def test_the_check_never_raises_on_an_unreadable_stat(tmp_path, monkeypatch):
    missing = tmp_path / "gone.key"
    assert backup_policy._key_permission_warning(str(missing)) == ""
