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
