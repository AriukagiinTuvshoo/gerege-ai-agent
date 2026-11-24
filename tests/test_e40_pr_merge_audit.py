"""Phase 40 — PR #1 final audit: merge readiness.

This phase is an audit, so most of what it established is recorded in
`docs/audit/PHASE_40_PR_MERGE_AUDIT.md` rather than here. The tests below are the
findings that produced a code or documentation change, kept so the same drift cannot
return silently.

  F-40-A  HIGH  docs/operations/BACKUP_RESTORE.md documented a cron entry built on
                `maintenance.py backup`, which never posts to BACKUP_ALERT_WEBHOOK at
                all. The shipped `deploy/cron/gerege-backup.cron` and
                `deploy/systemd/gerege-backup.service` both use `backup-run`, and
                docs/ALERTING-SETUP.md describes `backup-run` as the alerting command.
                An operator following the runbook would have had a nightly backup that
                failed silently: no archive, an exit code in a log nobody reads, and no
                alert leaving the host. Measured on an identical `pg_dump` failure with
                no webhook configured — `backup` printed only `backup FAILED: ...`,
                while `backup-run` also printed
                `warning: BACKUP_ALERT_WEBHOOK is not configured: nobody is notified`.

The distinction is real and is asserted behaviourally below, not just by reading docs.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel: str) -> str:
    with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


# --------------------------------------------------------------------------------------
# F-40-A — only `backup-run` alerts, and every scheduling document must say so
# --------------------------------------------------------------------------------------


class TestOnlyTheAlertingCommandIsDocumentedForScheduling:
    SCHEDULING_DOCS = (
        "docs/operations/BACKUP_RESTORE.md",
        "docs/deployment/PRODUCTION_DEPLOYMENT.md",
        "docs/deployment/STAGING_DEPLOYMENT.md",
    )
    SHIPPED_SCHEDULERS = (
        "deploy/cron/gerege-backup.cron",
        "deploy/systemd/gerege-backup.service",
    )

    def test_the_shipped_schedulers_use_the_alerting_command(self):
        """These are the artefacts that actually run on a host."""
        for path in self.SHIPPED_SCHEDULERS:
            text = _read(path)
            assert "maintenance.py backup-run" in text, f"{path} does not use backup-run"
            assert not re.search(r"maintenance\.py\s+backup\s+--label", text), (
                f"{path} schedules the non-alerting `backup` command"
            )

    @pytest.mark.parametrize("path", SCHEDULING_DOCS)
    def test_no_scheduling_document_recommends_the_non_alerting_command(self, path):
        """The defect: BACKUP_RESTORE.md's cron block used `backup`, contradicting the
        shipped units and the alerting guide."""
        text = _read(path)
        offenders = re.findall(r"maintenance\.py\s+backup\s+--label\s+daily_auto", text)
        assert not offenders, (
            f"{path} schedules `maintenance.py backup --label daily_auto`, which never "
            "posts to BACKUP_ALERT_WEBHOOK"
        )

    @pytest.mark.parametrize("path", SCHEDULING_DOCS)
    def test_every_scheduling_document_names_backup_run(self, path):
        assert "maintenance.py backup-run" in _read(path), (
            f"{path} describes scheduled backups without naming the only command that alerts"
        )

    def test_the_alerting_guide_and_the_runbook_agree(self):
        alerting = _read("docs/ALERTING-SETUP.md")
        assert "backup-run" in alerting
        # The guide's claim is the authority the runbook must not contradict.
        assert "BACKUP_ALERT_WEBHOOK" in alerting

    def test_the_corrected_section_explains_why(self):
        """A doc fix without the reason is reverted by the next person who tidies up."""
        text = _read("docs/operations/BACKUP_RESTORE.md")
        assert "F-40-A" in text, "the correction does not record the finding that caused it"
        assert "does **not** post to" in text or "does not post to" in text


class TestTheTwoBackupCommandsDifferAsDocumented:
    """Behavioural, on the real CLI. No database is needed: the policy preflight refuses
    first, which is exactly the path Phase 38 fixed for F-38-C and is where the two
    command names diverge in what they tell an operator."""

    @staticmethod
    def _run(args, env_extra):
        env = dict(os.environ)
        env.pop("BACKUP_ALERT_WEBHOOK", None)  # the no-alert-configured case
        env.update(env_extra)
        return subprocess.run(
            [sys.executable, "scripts/maintenance.py", *args],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
        )

    def test_both_commands_exist_and_differ(self):
        listing = subprocess.run(
            [sys.executable, "scripts/maintenance.py", "--help"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        ).stdout
        assert "backup-run" in listing, "the alerting command is gone"
        assert re.search(r"\bbackup\b", listing), "the manual command is gone"

    def test_only_backup_run_documents_the_alert_behaviour(self):
        """`backup-run`'s docstring is where an operator learns that it alerts.

        Three wrong versions of this test before it was right, each caught the same way:
        its own negative control. `def cmd_backup(` is a PREFIX of `def cmd_backup_run(`,
        so any `split("def cmd_backup(")` finds the wrong function; and cmd_backup has NO
        docstring at all, so a naive "next triple-quoted string" read returns
        cmd_backup_run's. The assertion is therefore made with an AST, which cannot
        confuse two functions with a common prefix.
        """
        import ast

        tree = ast.parse(_read("scripts/maintenance.py"))
        docs = {
            node.name: ast.get_docstring(node) or ""
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

        assert "cmd_backup_run" in docs, "cmd_backup_run not found"
        assert "alert" in docs["cmd_backup_run"].lower(), (
            "backup-run's docstring no longer tells an operator that it alerts"
        )

        # cmd_backup must not claim to alert. It has no docstring today, which satisfies
        # this; if one is added that promises alerting, this fails.
        assert "alert" not in docs.get("cmd_backup", "").lower(), (
            "cmd_backup's docstring claims alerting, but it never posts to the webhook"
        )

    def test_the_two_commands_have_distinct_documented_contracts(self):
        """An operator must be able to tell them apart from `--help` alone."""
        text = _read("scripts/maintenance.py")
        assert '"backup-run", help="scheduled run: backup + encrypt + verify + retain + alert"' in text
        manual_help = re.search(r'"backup",\s*help="([^"]+)"', text)
        assert manual_help, "the manual command has no help text"
        assert "alert" not in manual_help.group(1).lower(), manual_help.group(1)


# --------------------------------------------------------------------------------------
# F-40-B  MEDIUM  .env.example shipped a backup setting that no code path reads
# --------------------------------------------------------------------------------------
#
# The template is the only configuration reference a new deployment has. It listed
#
#     BACKUP_OFFSITE_PATH=
#     BACKUP_OFFSITE_MOUNT=./backups
#
# and only the first exists: `grep -rn BACKUP_OFFSITE_MOUNT` matches nothing under
# core/, scripts/ or deploy/. The provider is chosen from BACKUP_OFFSITE_URL /
# BACKUP_OFFSITE_PATH alone (core/backup_offsite.py:860, core/backup_automation.py:122),
# so an operator who filled in the MOUNT form configured nothing, got
# `OFFSITE_NOT_CONFIGURED` plus a warning, and left every backup on the host it is
# supposed to survive. Measured on the shipped code before the fix:
# `evaluate_offsite(dict(BACKUP_OFFSITE_MOUNT="./backups"))` returns provider None.

#: Every variable name a comment may mention for historical context. Anything else that
#: looks like a setting but is not assigned must be a real, read variable.
def _assigned_env_names(text: str) -> set:
    return set(re.findall(r"^([A-Z][A-Z0-9_]*)\s*=", text, flags=re.MULTILINE))


def _documented_env_names(text: str) -> set:
    """Names the file presents as settings: assignments plus `NAME` in pointy/backticked form."""
    return _assigned_env_names(text) | set(re.findall(r"`([A-Z][A-Z0-9_]{3,})`", text))


class TestF40BDeadBackupSetting:
    def test_the_template_does_not_name_an_offsite_mount_setting(self):
        """The MOUNT spelling must not be offered as a setting — nothing reads it."""
        text = _read(".env.example")
        assigned = _assigned_env_names(text)
        assert "BACKUP_OFFSITE_MOUNT" not in assigned, (
            ".env.example still ASSIGNS BACKUP_OFFSITE_MOUNT, which no code path reads; "
            "the only recognised setting is BACKUP_OFFSITE_PATH"
        )

    def test_the_offsite_setting_the_template_offers_is_the_one_the_code_reads(self):
        """Positive control: the surviving name must be a name the backup plane reads."""
        text = _read(".env.example")
        assert "BACKUP_OFFSITE_PATH" in _assigned_env_names(text), (
            ".env.example must still offer BACKUP_OFFSITE_PATH: it is the variable that "
            "actually selects the offsite destination"
        )
        readers = (
            _read("core/backup_automation.py")
            + _read("core/backup_offsite.py")
        )
        assert "BACKUP_OFFSITE_PATH" in readers, (
            "BACKUP_OFFSITE_PATH is no longer read by the backup plane either — the "
            "template and the code have drifted apart again"
        )

    def test_no_backup_setting_in_the_template_is_unread_by_the_code(self):
        """Generalisation: every BACKUP_* the template assigns must appear in the code."""
        template = _read(".env.example")
        offered = {n for n in _assigned_env_names(template) if n.startswith("BACKUP_")}
        assert offered, "the template assigns no BACKUP_* settings at all"
        code = _read("core/backup_automation.py") + _read("core/backup_offsite.py") + _read(
            "core/backup_policy.py"
        ) + _read("core/backup_service.py") + _read("core/backup_crypto.py")
        unread = sorted(n for n in offered if n not in code)
        assert not unread, (
            f".env.example assigns backup setting(s) that no backup module reads: {unread}. "
            "An operator who sets these configures nothing."
        )


# --------------------------------------------------------------------------------------
# F-40-C  MEDIUM  the worker needs more than Docker's 10 s stop grace to finish a batch
# --------------------------------------------------------------------------------------
#
# Measured against a disposable PostgreSQL 16.2 and a live Redis, a single worker process
# running the shipped `worker_main_loop`:
#
#   * idle (loop waiting on the shutdown event)          -> stopped in 0.00 s
#   * after SIGTERM mid-tick, 25 x 1 s jobs in one batch  -> 23.34 s
#   * the same shape measured earlier, 25 x 3 s jobs      -> 13.88 s (partial batch)
#
# `run_worker_tick` awaits `process_pending_jobs(batch_size=25)`, and that loop awaits
# each handler, so the shutdown event is only observed between ticks. Docker's default
# stop grace is 10 s and no compose file sets `stop_grace_period`; after 10 s the
# container is SIGKILLed. The architecture is at-least-once with a 300 s visibility
# timeout, so no job is lost — but the "graceful shutdown" the readiness documents
# describe does not complete for the worker, and every redeploy can SIGKILL it mid-batch.
#
# The fix is configuration, not code: give the worker room to finish a batch.

WORKER_DEFAULT_BATCH = 25
DOCKER_DEFAULT_STOP_GRACE = 10


def _worker_batch_size() -> int:
    text = _read("worker.py")
    match = re.search(r"process_pending_jobs\(batch_size=(\d+)\)", text)
    assert match, "worker.py no longer calls process_pending_jobs(batch_size=N)"
    return int(match.group(1))


def _stop_grace_seconds(compose_text: str, service: str) -> int:
    """Parse `stop_grace_period` for one compose service; 0 when absent."""
    # `re.split` with a lookahead consumes nothing, so the two-space indent stays on the
    # block; match the service name at the start of the captured text.
    blocks = re.split(r"^  (?=[a-z_]+:)", compose_text, flags=re.MULTILINE)
    for block in blocks:
        if not block.startswith(f"{service}:"):
            continue
        match = re.search(r"stop_grace_period:\s*(\d+)\s*s", block)
        return int(match.group(1)) if match else 0
    raise AssertionError(f"service {service!r} not found in the compose file")


class TestF40CWorkerStopGrace:
    def test_the_worker_gets_more_stop_grace_than_docker_defaults_to(self):
        """A worker that finishes a whole batch needs longer than 10 s."""
        grace = _stop_grace_seconds(_read("docker-compose.prod.yml"), "worker")
        assert grace > DOCKER_DEFAULT_STOP_GRACE, (
            "docker-compose.prod.yml sets no stop_grace_period for `worker` (or one <= "
            f"Docker's {DOCKER_DEFAULT_STOP_GRACE}s default), but a tick can run "
            f"{_worker_batch_size()} handlers before the shutdown event is observed"
        )

    def test_staging_matches_production_so_the_rehearsal_measures_the_real_behaviour(self):
        prod = _stop_grace_seconds(_read("docker-compose.prod.yml"), "worker")
        staging = _stop_grace_seconds(_read("docker-compose.staging.yml"), "worker")
        assert staging == prod, (
            f"staging worker stop_grace_period={staging}s but production has {prod}s; the "
            "staging rehearsal would then not exercise the production shutdown budget"
        )

    def test_the_grace_covers_a_full_batch_of_realistic_handlers(self):
        """The configured grace must exceed a batch of handlers, not merely 10 s."""
        grace = _stop_grace_seconds(_read("docker-compose.prod.yml"), "worker")
        batch = _worker_batch_size()
        # A handler slow enough to matter: the task_queue default timeout is 60 s, but a
        # batch of those is not survivable by any sane grace, so the budget is stated for
        # a handler of up to 2 s — the network-bound shape of this codebase's handlers
        # (a Telegram send, a Sheets append, a Meta reply).
        per_handler_ceiling_s = 2
        assert grace >= batch * per_handler_ceiling_s, (
            f"stop_grace_period={grace}s cannot cover one batch of {batch} handlers at "
            f"{per_handler_ceiling_s}s each ({batch * per_handler_ceiling_s}s); the "
            "container would still be SIGKILLed mid-batch"
        )


# --------------------------------------------------------------------------------------
# F-40-D  MEDIUM  two thirds of a "227 tests" CI step skipped on every run
# --------------------------------------------------------------------------------------
#
# The Phase 22/23/24 step claimed 227 cases. Measured in the job's own environment
# (no P24_DR_DATABASE_URL, no DATABASE_URL, no offsite endpoint), 23 of those cases
# skip:
#
#   tests/test_e07_phase24_disaster_recovery.py          11  (P24_DR_DATABASE_URL unset)
#   tests/test_e07_phase22_db_bounds.py                   5  ("needs PostgreSQL")
#   tests/test_e07_phase22_connection_bounds.py           3  ("needs a PostgreSQL DATABASE_URL")
#   tests/test_e07_phase23_restore_verification.py        3  ("needs a PostgreSQL DATABASE_URL")
#   tests/test_e07_phase22_backup_policy.py               1  ("needs PostgreSQL")
#
# and the guard could not see any of it, for two reasons that compound:
#
#   * the step passed --no-skip-check, so a SKIPPED line was not a failure;
#   * --min-collected counts passed + skipped, so the skips satisfied the floor.
#
# A step that ran 204 cases while claiming 227, and silently dropped the whole disaster
# -recovery suite, reported success. With a migrated disposable database owned by
# gerege_owner and no offsite endpoint, the same selection is 227 passed, 1 skipped.


def _phase29_backup_step() -> str:
    """The workflow text of the Phase 22/23/24 backup step, plus its gate command."""
    text = _read(".github/workflows/ci.yml")
    start = text.index("Phase 22/23/24 — backup security")
    end = text.index("Phase 29 — CI test integrity")
    return text[start:end]


class TestF40DSkippedBackupSuite:
    def test_the_step_provides_the_dr_database_its_suite_requires(self):
        """The DR file skips on one variable; the step must set it."""
        step = _phase29_backup_step()
        assert "P24_DR_DATABASE_URL" in step, (
            "the backup step does not set P24_DR_DATABASE_URL, so every case in "
            "test_e07_phase24_disaster_recovery.py skips and the step still passes"
        )
        # Positive control: the test module really does gate on exactly this name.
        module = _read("tests/test_e07_phase24_disaster_recovery.py")
        assert 'os.getenv("P24_DR_DATABASE_URL"' in module

    def test_the_step_provides_the_postgresql_url_the_other_suites_require(self):
        """db_bounds / connection_bounds / restore_verification gate on DATABASE_URL."""
        step = _phase29_backup_step()
        assert "DATABASE_URL:" in step, (
            "the backup step does not set DATABASE_URL, so the PostgreSQL-only cases in "
            "db_bounds, connection_bounds, restore_verification and backup_policy skip"
        )
        for rel in (
            "tests/test_e07_phase22_db_bounds.py",
            "tests/test_e07_phase22_connection_bounds.py",
            "tests/test_e07_phase23_restore_verification.py",
        ):
            body = _read(rel)
            assert "DATABASE_URL" in body, rel

    def test_the_gate_no_longer_disables_the_skip_check(self):
        """A skip must be a failure unless it is named as the documented exception."""
        step = _phase29_backup_step()
        gate = step[step.index("check_pytest_log.py"):]
        assert "--no-skip-check" not in gate, (
            "the backup gate still passes --no-skip-check, which is what allowed 23 "
            "skipped cases to report as a passing step"
        )

    def test_the_gate_counts_passes_not_collected_cases(self):
        """`collected = passed + skipped`, so a collected floor is satisfied by skips."""
        step = _phase29_backup_step()
        gate = step[step.index("check_pytest_log.py"):]
        assert "--min-passed" in gate, (
            "the backup gate asserts collected cases (passed + skipped) rather than passes, "
            "so skipped cases count toward the floor"
        )
        # And the mechanism this guards against is real, not hypothetical.
        log_guard = _read("scripts/check_pytest_log.py")
        assert "collected_total = (int(matches[-1]) if matches else 0) + skipped" in log_guard

    def test_the_one_remaining_permitted_skip_is_the_sqlite_only_wal_case(self):
        """The narrowing must name a case that genuinely cannot run on PostgreSQL."""
        step = _phase29_backup_step()
        gate = step[step.index("check_pytest_log.py"):]
        allowed = re.findall(r'--allow-skip\s+"([^"]+)"', gate)
        assert allowed == ["test_live_database_is_actually_in_wal_mode"], allowed
        module = _read("tests/test_e07_phase22_wal_copy_safety.py")
        assert "WAL mode does not apply" in module, (
            "the named exception no longer carries the reason it was allowed"
        )
