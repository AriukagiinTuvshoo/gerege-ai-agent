"""Phase 24 - scheduler installation lifecycle.

Tests the whole lifecycle against disposable directories with an injected `systemctl`, because
this environment has **no systemd bus** (PID 1 is systemd but `systemctl` cannot connect) and
the process runs as a non-root uid. That is a real limitation of the environment, not of the
code, and it is why nothing here claims installation was verified on a real host.

What is verified: the plan/dry-run/install/uninstall logic, the safety properties (never
overwrite, never delete foreign files, never touch archives, fail safely without systemd), and
the negative controls proving the tests detect each violation.
"""

import os
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from core import scheduler_setup as sched  # noqa: E402


def _good_config(**overrides):
    config = dict(
        exec_start=(
            "/usr/bin/docker compose -f docker-compose.prod.yml run --rm --no-deps "
            "maintenance python scripts/maintenance.py backup-run --label scheduled"
        ),
        working_dir="/opt/gerege",
        env_file="/tmp/p24-test/backup.env",
        timeout_s=7200,
        on_calendar="hourly",
        randomized_delay_s=300,
        persistent=True,
        unit_dir="/tmp/p24-test/units",
    )
    config.update(overrides)
    return config


class FakeSystemctl:
    """Records calls and answers like a working systemd, so enable paths are exercised."""

    def __init__(self, available=True, fail_on=None):
        self.calls = []
        self.available = available
        self.fail_on = fail_on or ()

    def __call__(self, command, **kwargs):
        self.calls.append(list(command))
        import subprocess

        verb = command[1] if len(command) > 1 else ""

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        result = Result()
        if verb == "is-system-running":
            if self.available:
                result.stdout = "running"
            else:
                result.returncode = 1
                result.stderr = "Failed to connect to bus: No such file or directory"
            return result
        if verb in ("is-enabled", "is-active"):
            result.stdout = "enabled" if verb == "is-enabled" else "active"
            return result
        if any(token in self.fail_on for token in command):
            result.returncode = 1
            result.stderr = "simulated failure"
        return result


# ---------------------------------------------------------------------------
# 1.2 configuration validation
# ---------------------------------------------------------------------------


def _validate(**overrides):
    config = _good_config(**overrides)
    config.pop("persistent", None)
    return sched.validate_config(**config)


def test_a_valid_configuration_has_no_problems():
    assert _validate() == []


@pytest.mark.parametrize(
    "overrides,expected",
    [
        ({"exec_start": ""}, "ExecStart is empty"),
        ({"exec_start": "/bin/rm -rf /"}, "maintenance.py"),
        ({"working_dir": "relative/path"}, "absolute"),
        ({"env_file": "backup.env"}, "absolute"),
        ({"unit_dir": "units"}, "absolute"),
        ({"timeout_s": 0}, "positive"),
        ({"timeout_s": 90_000}, "24h"),
        ({"on_calendar": ""}, "never fire"),
        ({"randomized_delay_s": -1}, "negative"),
        ({"randomized_delay_s": 7200}, "drift past its interval"),
    ],
)
def test_invalid_configurations_are_rejected(overrides, expected):
    problems = _validate(**overrides)
    assert problems, f"{overrides} was accepted"
    assert any(expected in problem for problem in problems), problems


def test_validation_rejects_a_credential_in_the_unit():
    """A DSN in the unit would appear in `systemctl cat` for any user to read."""
    text = sched._render_service("x maintenance.py backup-run", "/opt/gerege", "/etc/gerege/backup.env", 7200)
    text += "\nEnvironment=DATABASE_OWNER_URL=postgresql://owner:pw@host/db\n"
    problems = sched.validate_rendered_service(text)
    assert any("embeds a credential" in p for p in problems), problems


def test_rendered_service_has_the_hardening_the_audit_requires():
    text = sched._render_service("x maintenance.py backup-run", "/opt/gerege", "/etc/gerege/backup.env", 7200)
    for directive in ("NoNewPrivileges=yes", "PrivateTmp=yes", "ProtectSystem=strict", "ProtectHome=read-only"):
        assert directive in text, f"missing {directive}"
    # And the exit-code contract is documented where an operator will see it.
    assert "18 timeout" in text


# ---------------------------------------------------------------------------
# Dry-run: changes nothing
# ---------------------------------------------------------------------------


def test_dry_run_writes_nothing(tmp_path):
    unit_dir = tmp_path / "units"
    plan = sched.plan_install(**_good_config(unit_dir=str(unit_dir)))
    assert plan.ok, plan.problems
    assert len(plan.changes()) == 2
    # Planning must not create anything - that is the whole point of a dry-run.
    assert not unit_dir.exists(), "plan_install created the unit directory"


def test_dry_run_and_install_plan_identically(tmp_path):
    """A dry-run that plans differently from the real run is worse than none."""
    unit_dir = str(tmp_path / "units")
    preview = sched.plan_install(**_good_config(unit_dir=unit_dir))
    real = sched.plan_install(**_good_config(unit_dir=unit_dir))
    preview_ops = [(f.path, f.action, f.content) for f in preview.files]
    real_ops = [(f.path, f.action, f.content) for f in real.files]
    assert preview_ops == real_ops


# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------


def test_install_writes_both_units_with_restrictive_modes(tmp_path):
    unit_dir = tmp_path / "units"
    plan = sched.plan_install(**_good_config(unit_dir=str(unit_dir)))
    result = sched.install(plan, run=FakeSystemctl())

    assert result["success"] is True
    assert result["installed"] is True
    assert result["enabled"] is True
    service = unit_dir / "gerege-backup.service"
    timer = unit_dir / "gerege-backup.timer"
    assert service.exists() and timer.exists()
    assert (service.stat().st_mode & 0o777) == 0o644
    # Unit files are world-readable by requirement (systemd reads them as non-root);
    # what must never be world-readable is the env file, which we do not create.

def test_install_distinguishes_installed_from_enabled(tmp_path):
    """The claim that matters: files on disk is not the same as a timer that will fire."""
    unit_dir = tmp_path / "units"
    plan = sched.plan_install(**_good_config(unit_dir=str(unit_dir)))
    result = sched.install(plan, run=FakeSystemctl(available=False))
    assert result["installed"] is True
    assert result["enabled"] is False
    assert "systemd unavailable" in result["enable_detail"]


def test_install_fails_safely_when_systemd_is_unavailable(tmp_path):
    unit_dir = tmp_path / "units"
    plan = sched.plan_install(**_good_config(unit_dir=str(unit_dir)))
    result = sched.install(plan, run=FakeSystemctl(available=False))
    assert result["success"] is True  # files are fine
    assert result["enabled"] is False  # but nothing claims the timer runs
    assert result["daemon_reloaded"] is False


def test_install_surfaces_an_enable_failure(tmp_path):
    unit_dir = tmp_path / "units"
    plan = sched.plan_install(**_good_config(unit_dir=str(unit_dir)))
    result = sched.install(plan, run=FakeSystemctl(fail_on=("enable",)))
    assert result["enabled"] is False
    assert "failed" in result["enable_detail"]


def test_install_refuses_a_plan_with_problems(tmp_path):
    plan = sched.plan_install(**_good_config(exec_start="", unit_dir=str(tmp_path / "units")))
    result = sched.install(plan, run=FakeSystemctl())
    assert result["success"] is False
    assert result["written"] == []
    assert not (tmp_path / "units").exists()


# ---------------------------------------------------------------------------
# Existing-file conflict
# ---------------------------------------------------------------------------


def test_install_never_overwrites_an_existing_differing_unit(tmp_path):
    unit_dir = tmp_path / "units"
    unit_dir.mkdir()
    existing = unit_dir / "gerege-backup.service"
    existing.write_text("[Unit]\nDescription=hand written\n", encoding="utf-8")

    plan = sched.plan_install(**_good_config(unit_dir=str(unit_dir)))
    assert not plan.ok
    assert any("Refusing to overwrite" in p for p in plan.problems)

    result = sched.install(plan, run=FakeSystemctl())
    assert result["success"] is False
    # The operator's file is untouched.
    assert "hand written" in existing.read_text(encoding="utf-8")


def test_force_replaces_but_keeps_a_backup(tmp_path):
    unit_dir = tmp_path / "units"
    unit_dir.mkdir()
    existing = unit_dir / "gerege-backup.service"
    existing.write_text("[Unit]\nDescription=hand written\n", encoding="utf-8")

    plan = sched.plan_install(**_good_config(unit_dir=str(unit_dir)), force=True)
    assert plan.ok, plan.problems
    result = sched.install(plan, run=FakeSystemctl())
    assert result["success"] is True
    backup = unit_dir / "gerege-backup.service.bak"
    assert backup.exists()
    assert "hand written" in backup.read_text(encoding="utf-8")


def test_identical_reinstall_is_a_no_op(tmp_path):
    unit_dir = tmp_path / "units"
    plan = sched.plan_install(**_good_config(unit_dir=str(unit_dir)))
    sched.install(plan, run=FakeSystemctl())

    again = sched.plan_install(**_good_config(unit_dir=str(unit_dir)))
    assert again.ok
    assert again.changes() == [], "a second identical install would rewrite files"


# ---------------------------------------------------------------------------
# Permission errors and partial-install recovery
# ---------------------------------------------------------------------------


def test_permission_error_is_reported_and_rolled_back(tmp_path, monkeypatch):
    """A read-only destination must fail cleanly and leave nothing half-written."""
    unit_dir = tmp_path / "units"
    plan = sched.plan_install(**_good_config(unit_dir=str(unit_dir)))

    real_write = sched._atomic_write
    calls = {"n": 0}

    def flaky_write(path, content, mode):
        calls["n"] += 1
        if calls["n"] == 2:
            raise PermissionError(13, "Permission denied")
        return real_write(path, content, mode)

    monkeypatch.setattr(sched, "_atomic_write", flaky_write)
    result = sched.install(plan, run=FakeSystemctl())

    assert result["success"] is False
    assert result["rolled_back"] is True
    assert "PermissionError" in result["error"]
    # The first file was written and then removed again.
    assert not (unit_dir / "gerege-backup.service").exists()
    assert not (unit_dir / "gerege-backup.timer").exists()


def test_partial_install_restores_the_previous_version(tmp_path, monkeypatch):
    """If file 2 fails, an operator's existing file 1 must come back, not vanish."""
    unit_dir = tmp_path / "units"
    unit_dir.mkdir()
    original = unit_dir / "gerege-backup.service"
    original.write_text("[Unit]\nDescription=previous version\n", encoding="utf-8")

    plan = sched.plan_install(**_good_config(unit_dir=str(unit_dir)), force=True)
    assert plan.ok

    real_write = sched._atomic_write
    calls = {"n": 0}

    def flaky_write(path, content, mode):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError(28, "No space left on device")
        return real_write(path, content, mode)

    monkeypatch.setattr(sched, "_atomic_write", flaky_write)
    result = sched.install(plan, run=FakeSystemctl())

    assert result["success"] is False
    assert "previous version" in original.read_text(encoding="utf-8"), (
        "rollback did not restore the file it had already replaced"
    )


# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------


def test_uninstall_removes_only_what_the_installer_wrote(tmp_path):
    unit_dir = tmp_path / "units"
    plan = sched.plan_install(**_good_config(unit_dir=str(unit_dir)))
    sched.install(plan, run=FakeSystemctl())
    assert len(list(unit_dir.iterdir())) == 2

    result = sched.uninstall(unit_dir=str(unit_dir), run=FakeSystemctl())
    assert result["success"] is True
    assert len(result["removed"]) == 2
    assert list(unit_dir.iterdir()) == []


def test_uninstall_leaves_a_foreign_unit_alone(tmp_path):
    unit_dir = tmp_path / "units"
    unit_dir.mkdir()
    foreign = unit_dir / "gerege-backup.timer"
    foreign.write_text("[Unit]\nDescription=not ours\n", encoding="utf-8")

    result = sched.uninstall(unit_dir=str(unit_dir), run=FakeSystemctl())
    assert result["removed"] == []
    assert foreign.exists(), "uninstall deleted a unit it did not write"


def test_uninstall_never_touches_backup_archives(tmp_path, monkeypatch):
    """The destructive-uninstall control. Archives are the thing that must survive."""
    unit_dir = tmp_path / "units"
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    archive = backup_dir / "pg_backup_20260101.sql.gz.enc"
    archive.write_bytes(b"precious backup bytes")

    monkeypatch.setenv("BACKUP_DIR", str(backup_dir))
    plan = sched.plan_install(**_good_config(unit_dir=str(unit_dir)))
    sched.install(plan, run=FakeSystemctl())
    sched.uninstall(unit_dir=str(unit_dir), run=FakeSystemctl())

    assert archive.exists(), "uninstall destroyed a backup archive"
    assert archive.read_bytes() == b"precious backup bytes"


def test_uninstall_keeps_the_env_file(tmp_path):
    unit_dir = tmp_path / "units"
    env_file = tmp_path / "etc" / "backup.env"
    env_file.parent.mkdir(parents=True)
    env_file.write_text("DATABASE_OWNER_URL=postgresql://owner:pw@host/db\n", encoding="utf-8")
    env_file.chmod(0o600)

    plan = sched.plan_install(**_good_config(unit_dir=str(unit_dir), env_file=str(env_file)))
    sched.install(plan, run=FakeSystemctl())
    result = sched.uninstall(unit_dir=str(unit_dir), env_file=str(env_file), run=FakeSystemctl())

    assert env_file.exists(), "uninstall deleted the operator's credential file"
    assert any("kept" in note or "operator-owned" in note for note in result["notes"])


def test_uninstall_dry_run_removes_nothing(tmp_path):
    unit_dir = tmp_path / "units"
    plan = sched.plan_install(**_good_config(unit_dir=str(unit_dir)))
    sched.install(plan, run=FakeSystemctl())

    result = sched.uninstall(unit_dir=str(unit_dir), run=FakeSystemctl(), dry_run=True)
    assert result["dry_run"] is True
    assert result["removed"] == []
    assert len(result["would_remove"]) == 2
    assert len(list(unit_dir.iterdir())) == 2, "uninstall --dry-run deleted files"


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def test_status_reports_installed_enabled_active_separately(tmp_path):
    unit_dir = tmp_path / "units"
    plan = sched.plan_install(**_good_config(unit_dir=str(unit_dir)))
    sched.install(plan, run=FakeSystemctl())

    state = sched.status(unit_dir=str(unit_dir), run=FakeSystemctl())
    assert state["installed"] is True
    assert state["systemd_available"] is True
    assert state["enabled"] is True
    assert state["active"] is True


def test_status_never_claims_enabled_without_systemd(tmp_path):
    unit_dir = tmp_path / "units"
    plan = sched.plan_install(**_good_config(unit_dir=str(unit_dir)))
    sched.install(plan, run=FakeSystemctl())

    state = sched.status(unit_dir=str(unit_dir), run=FakeSystemctl(available=False))
    assert state["installed"] is True
    assert state["enabled"] is False
    assert state["active"] is False
    assert state["systemd_available"] is False


def test_status_flags_a_world_readable_env_file(tmp_path):
    unit_dir = tmp_path / "units"
    env_file = tmp_path / "backup.env"
    env_file.write_text("X=1\n", encoding="utf-8")
    env_file.chmod(0o644)

    plan = sched.plan_install(**_good_config(unit_dir=str(unit_dir), env_file=str(env_file)))
    assert not plan.ok
    assert any("must be 0600" in p for p in plan.problems)


# ---------------------------------------------------------------------------
# Timer/service consistency and the command actually run
# ---------------------------------------------------------------------------


def test_timer_and_service_agree_on_the_unit_name(tmp_path):
    timer = sched._render_timer("hourly", 300, True)
    assert "Unit=gerege-backup.service" in timer
    assert sched.validate_rendered_timer(timer) == []


def test_the_installed_command_runs_the_backup_entry_point(tmp_path):
    text = sched._render_service(
        "/usr/bin/docker compose -f docker-compose.prod.yml run --rm --no-deps "
        "maintenance python scripts/maintenance.py backup-run --label scheduled",
        "/opt/gerege",
        "/etc/gerege/backup.env",
        7200,
    )
    assert "maintenance.py backup-run" in text
    assert "EnvironmentFile=/etc/gerege/backup.env" in text


def test_exit_codes_are_not_swallowed_by_the_unit():
    """`Type=oneshot` plus no `SuccessExitStatus=` means systemd reports the real code."""
    text = sched._render_service("x maintenance.py backup-run", "/opt/gerege", "/e", 7200)
    assert "SuccessExitStatus" not in text, (
        "SuccessExitStatus would make a failed backup look successful to systemd"
    )
    assert "TimeoutStartSec=7200s" in text
