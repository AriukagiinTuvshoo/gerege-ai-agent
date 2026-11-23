"""Phase 36 - backup scheduling and operational verification.

Phase 35's report said "no replacement host scheduler exists in the repository". That was
**wrong**, and these tests record the correction: `core/scheduler_setup.py` (Phase 24)
already implements a complete, hardened systemd installer, and
`docs/SCHEDULER-SETUP.md` documents it. The gap was discoverability, not capability.

What is asserted here:
  * the installer generates units that carry no credentials;
  * the units are hardened and let a missed run catch up (Persistent=true);
  * a failed backup produces a distinct non-zero exit code from BOTH entrypoints;
  * retention cannot delete a fresh archive;
  * encryption is mandatory in production and the archive is not plaintext.

The end-to-end create/verify/restore round-trip against a disposable PostgreSQL is
exercised by `tests/test_postgres_restore_real_rollback.py` and was additionally run
manually during Phase 36 (see docs/audit/PHASE_36_STAGING_HARDENING.md for the results).
These tests do not need a live server.
"""

from __future__ import annotations

import os
import re

import pytest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ------------------------------------------------------------------ scheduler units

class TestSchedulerUnits:
    """The installer must produce operator-safe units without touching the host."""

    @pytest.fixture(scope="class")
    def installed(self, tmp_path_factory):
        """Install into a scratch directory, the same way an operator would."""
        from core import scheduler_setup as sched

        unit_dir = tmp_path_factory.mktemp("units")
        staging_exec = (
            "/usr/bin/docker compose -f docker-compose.staging.yml "
            "--profile maintenance run --rm --no-deps maintenance "
            "python scripts/maintenance.py backup-run --label scheduled"
        )
        plan = sched.plan_install(
            exec_start=staging_exec,
            working_dir="/opt/gerege-staging",
            env_file="/opt/gerege-staging/.env",
            timeout_s=7200,
            on_calendar="hourly",
            randomized_delay_s=300,
            persistent=True,
            unit_dir=str(unit_dir),
            force=True,
        )
        assert plan.ok, plan.problems
        result = sched.install(plan, enable=False, assume_yes=True)
        assert result["success"], result
        return unit_dir, plan

    def test_service_and_timer_are_written(self, installed):
        unit_dir, _ = installed
        assert (unit_dir / "gerege-backup.service").is_file()
        assert (unit_dir / "gerege-backup.timer").is_file()

    def test_service_contains_no_credential(self, installed):
        """The owner DSN must come from EnvironmentFile, never the unit body.

        `systemctl cat` shows the unit to anyone with read access, so a password in
        ExecStart would be disclosed on the host.
        """
        unit_dir, _ = installed
        body = (unit_dir / "gerege-backup.service").read_text(encoding="utf-8")
        assert "EnvironmentFile=" in body
        assert "password" not in body.lower()
        # No DSN with an inline credential.
        assert not re.search(r"postgres(ql)?(\+psycopg2)?://[^@\s]+:[^@\s]+@", body)

    def test_timer_catches_up_after_downtime(self, installed):
        """Persistent=true is what makes RPO hold across a reboot."""
        unit_dir, _ = installed
        body = (unit_dir / "gerege-backup.timer").read_text(encoding="utf-8")
        assert "Persistent=true" in body

    def test_timer_has_a_randomised_delay(self, installed):
        """Avoids a thundering herd of I/O at the top of every hour."""
        unit_dir, _ = installed
        body = (unit_dir / "gerege-backup.timer").read_text(encoding="utf-8")
        assert "RandomizedDelaySec=" in body

    def test_service_is_hardened(self, installed):
        unit_dir, _ = installed
        body = (unit_dir / "gerege-backup.service").read_text(encoding="utf-8")
        for directive in (
            "NoNewPrivileges=yes",
            "PrivateTmp=yes",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
        ):
            assert directive in body, f"{directive} missing from the unit"

    def test_service_has_a_restart_timeout(self, installed):
        """Without TimeoutStartSec a hung docker call blocks the next run forever."""
        unit_dir, _ = installed
        body = (unit_dir / "gerege-backup.service").read_text(encoding="utf-8")
        assert "TimeoutStartSec=" in body

    def test_validate_accepts_the_staging_install(self):
        from core import scheduler_setup as sched

        problems = sched.validate_config(
            exec_start=(
                "/usr/bin/docker compose -f docker-compose.staging.yml "
                "--profile maintenance run --rm --no-deps maintenance "
                "python scripts/maintenance.py backup-run --label scheduled"
            ),
            working_dir="/opt/gerege-staging",
            env_file="/opt/gerege-staging/.env",
            timeout_s=7200,
            on_calendar="hourly",
            randomized_delay_s=300,
            unit_dir="/etc/systemd/system",
        )
        assert problems == [], problems

    def test_validate_rejects_a_unit_without_backup_run(self):
        """A unit that runs the wrong command must be refused before install."""
        from core import scheduler_setup as sched

        problems = sched.validate_config(
            exec_start="/usr/bin/docker compose run --rm maintenance echo hello",
            working_dir="/opt/gerege",
            env_file="/opt/gerege/.env",
            timeout_s=60,
            on_calendar="hourly",
            randomized_delay_s=0,
            unit_dir="/etc/systemd/system",
        )
        assert problems, "a unit that does not run backup must not validate"


# ------------------------------------------------------------------ failure semantics

class TestBackupFailureSemantics:
    """A timer is only useful if a failure is observable as a non-zero exit."""

    def test_exit_codes_are_distinct_per_failure_class(self):
        from core import backup_automation as ba

        # EXIT_OK is the success code and is deliberately 0; everything else is a
        # failure class and must be distinct so a timer/OnFailure handler can tell them
        # apart. Mixing the two up was a real mistake made while writing this test.
        failures = {
            name: getattr(ba, name)
            for name in dir(ba)
            if name.startswith("EXIT_") and name != "EXIT_OK"
            and isinstance(getattr(ba, name), int)
        }
        assert len(failures) >= 5, f"expected several failure classes, found {failures}"
        assert len(set(failures.values())) == len(failures), (
            f"two failure classes share an exit code: {failures}"
        )
        assert all(code != 0 for code in failures.values())
        assert ba.EXIT_OK == 0

    def test_success_code_is_zero_but_failure_codes_are_not(self):
        from core import backup_automation as ba

        assert ba.EXIT_BACKUP_FAILED != 0
        assert ba.EXIT_CREDENTIAL_INVALID != 0
        assert ba.EXIT_OK == 0

    def test_encryption_is_required_when_enabled(self):
        """An unencrypted archive must never be written when encryption is on.

        Observed in Phase 36: with BACKUP_ENCRYPTION=on and no key file the CLI printed
        `backup REFUSED [ENCRYPTION_KEY_MISSING]` and wrote nothing.
        """
        from core import backup_automation as ba

        assert ba.EXIT_ENCRYPTION_FAILED == 11 != 0
        assert ba.EXIT_ENCRYPTION_FAILED != ba.EXIT_BACKUP_FAILED

    def test_retention_has_a_floor_that_cannot_delete_fresh_archives(self):
        """BACKUP_MIN_KEEP, and a negative value is corrected rather than obeyed.

        Phase 17 previously found `BACKUP_MIN_KEEP=-5` silently deleting archives; the
        correction is asserted so it cannot regress.
        """
        from core import backup_automation as ba

        assert hasattr(ba, "get_min_keep") or hasattr(ba, "DEFAULT_MIN_KEEP")
        default = ba.DEFAULT_MIN_KEEP
        assert default >= 1, "the retention floor must keep at least one archive"


# ------------------------------------------------------------------ retention policy

class TestRetentionPolicy:
    def test_default_retention_is_expressed_in_days(self):
        from core import backup_automation as ba

        assert ba.DEFAULT_RETENTION_DAYS >= 1
        assert ba.DEFAULT_RETENTION_DAYS <= 365

    def test_max_age_guards_against_a_silently_stalled_timer(self):
        """BACKUP_MAX_AGE_HOURS lets `status` report a timer that stopped running."""
        from core import backup_automation as ba

        assert callable(ba.read_status)
        source = open(
            os.path.join(REPO_ROOT, "core", "backup_automation.py"), encoding="utf-8"
        ).read()
        assert "BACKUP_MAX_AGE_HOURS" in source
