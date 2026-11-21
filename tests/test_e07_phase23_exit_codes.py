"""Phase 23 (D-7) - the *scheduled* path must not flatten a specific exit code.

Phase 22 fixed `cmd_backup` returning a blanket 1 and `create_backup` overwriting a specific
code with 10 - but only on the manual path. `run_scheduled_backup()` had the identical bug and
it survived, which matters more: `backup-run` is what a systemd timer invokes. Reproduced with
an ACCESS EXCLUSIVE lock held on `pages`:

    maintenance.py backup      -> exit 18   (correct)
    maintenance.py backup-run  -> exit 10   (wrong: reported a lock timeout as a generic
                                             backup failure)

The unit templates document 18 as "a configured bound was exceeded", so an `OnFailure=` handler
or alerting rule could not distinguish "slow database" from "the backup broke".
"""

import pathlib
import re

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _automation_source() -> str:
    return (REPO_ROOT / "core" / "backup_automation.py").read_text(encoding="utf-8")


def test_exit_timeout_is_a_named_constant():
    """18 must be named where alerting and status read the other codes.

    It lived only as a bare literal in `backup_service.py`, so the automation layer - which
    builds the alert payload and the status file - had no constant for it.
    """
    import sys

    sys.path.insert(0, str(REPO_ROOT))
    from core import backup_automation

    assert backup_automation.EXIT_TIMEOUT == 18
    # And it must not collide with the other documented codes.
    codes = {
        backup_automation.EXIT_OK,
        backup_automation.EXIT_BACKUP_FAILED,
        backup_automation.EXIT_ENCRYPTION_FAILED,
        backup_automation.EXIT_INTEGRITY_FAILED,
        backup_automation.EXIT_CREDENTIAL_INVALID,
        backup_automation.EXIT_OFFSITE_FAILED,
        backup_automation.EXIT_NOT_CONFIGURED,
        backup_automation.EXIT_LOCKED,
        backup_automation.EXIT_TIMEOUT,
    }
    assert len(codes) == 9, f"exit codes collide: {sorted(codes)}"


def test_scheduled_failure_preserves_the_services_exit_code():
    """Structural guard: the scheduled path must default, not override.

    The regression was `exit_code=EXIT_BACKUP_FAILED` unconditionally at the point where
    `create_backup` had already chosen a more specific code.
    """
    source = _automation_source()
    assert 'exit_code=created.get("exit_code") or EXIT_BACKUP_FAILED' in source, (
        "run_scheduled_backup overwrites the specific exit code again"
    )


def test_scheduled_timeout_is_flagged_and_coded(monkeypatch):
    """Behavioural: a timeout result keeps 18 and is marked `timeout`."""
    import sys

    sys.path.insert(0, str(REPO_ROOT))
    from core import backup_automation, backup_service

    # Make the dump step return exactly what a lock timeout produces.
    def fake_create_backup(label=None, staging_dir=None):
        return {
            "success": False,
            "exit_code": 18,
            "timeout": True,
            "error": "database preflight exceeded its deadline - lock_timeout",
        }

    monkeypatch.setattr(backup_service, "create_backup", fake_create_backup)
    monkeypatch.setattr(backup_automation, "_finish", lambda *a, **k: None)
    # Keep the policy out of the way: encryption is configured in the test env.
    monkeypatch.setenv("BACKUP_ENCRYPTION", "off")
    monkeypatch.setenv("ENV", "development")

    result = backup_automation.run_scheduled_backup(label="d7")
    assert result["success"] is False
    assert result["exit_code"] == 18, (
        f"a timeout was reported as {result['exit_code']}, losing the distinction"
    )
    assert result.get("timeout") is True


def test_scheduled_generic_failure_still_defaults_to_10(monkeypatch):
    """The default must still apply when the service supplies no code."""
    import sys

    sys.path.insert(0, str(REPO_ROOT))
    from core import backup_automation, backup_service

    monkeypatch.setattr(
        backup_service,
        "create_backup",
        lambda label=None, staging_dir=None: {"success": False, "error": "boom"},
    )
    monkeypatch.setattr(backup_automation, "_finish", lambda *a, **k: None)
    monkeypatch.setenv("BACKUP_ENCRYPTION", "off")
    monkeypatch.setenv("ENV", "development")

    result = backup_automation.run_scheduled_backup(label="d7b")
    assert result["exit_code"] == backup_automation.EXIT_BACKUP_FAILED == 10


def test_unit_templates_document_the_real_code_set():
    """The systemd unit's comment must match the codes the code emits."""
    unit = (REPO_ROOT / "deploy" / "systemd" / "gerege-backup.service").read_text(encoding="utf-8")
    for code in ("10", "11", "12", "13", "14", "15", "16", "18"):
        assert re.search(rf"\b{code}\b", unit), f"unit template omits exit code {code}"
    assert "17" in unit, "the template should mention 17 to say it is reserved"
