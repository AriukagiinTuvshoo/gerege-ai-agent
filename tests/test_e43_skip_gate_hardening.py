"""Phase 43 — the p20 skip gate must fail when the destructive suite did not run.

Phase 42 reported finding F-42-B: `/tmp/p20suite.log` is gated with `--no-skip-check`, so
`check_pytest_log.py` switches its skip check off wholesale and the step passes even when
cases skipped.

Fixing it turned up a worse shape, and that shape is what most of this file is about.

`test_p20_31` and `test_p20_32` are guarded like this::

    if os.getenv("GEREGE_DESTRUCTIVE_TESTS") != "1":
        print("[SKIP] set GEREGE_DESTRUCTIVE_TESTS=1 to run ...")
        return

That is not a pytest skip. The test RETURNS, pytest records PASSED, and the summary reads
"2 passed" with no skip in it anywhere. Measured in Phase 43 against a clean PostgreSQL
database with the variable unset:

    test_p20_31_a_stranded_connection_releases_its_locks           PASSED
    test_p20_32_schema_reset_actually_empties_the_schema           PASSED
    [SKIP] set GEREGE_DESTRUCTIVE_TESTS=1 to run (uses the live database)
    [SKIP] set GEREGE_DESTRUCTIVE_TESTS=1 to run (drops every object in public)
    ========================= 2 passed in 0.28s =========================

The `[SKIP]` lines go to pytest's captured-output trap, so CI's `-v` log does not contain
them. Removing `--no-skip-check` therefore does NOT fix this: I measured both the old and
the proposed gate returning 0 on that log.

The evidence that survives is the *absence* of work, so the fix is `--require-run NAME`:
the named case must appear in the log. These tests prove every branch of it behaviourally,
by constructing real logs and running the real script as a subprocess.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUARD = os.path.join(REPO_ROOT, "scripts", "check_pytest_log.py")

CASE_31 = "test_p20_31_a_stranded_connection_releases_its_locks"
CASE_32 = "test_p20_32_schema_reset_actually_empties_the_schema"


def _run(log, *args: str):
    """Run the real guard as a subprocess, exactly as CI does."""
    return subprocess.run(
        [sys.executable, str(GUARD), str(log), *args],
        capture_output=True,
        text=True,
    )


def _log(tmp_path, body: str, name: str = "log.txt"):
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------------------------
# The reproduction: this is the defect, before and after.
# --------------------------------------------------------------------------------------


class TestTheOriginalWeakness:
    def test_a_silent_return_produces_a_log_with_no_skip_evidence(self, tmp_path):
        """The log a real CI run makes when the opt-in is missing.

        Reconstructed from the measured run above rather than invented: two PASSED lines,
        no SKIPPED lines, and a summary of `2 passed`. The `[SKIP]` notices are absent
        because pytest captured stdout.
        """
        log = _log(
            tmp_path,
            "tests/x.py::test_a PASSED [ 50%]\n"
            "tests/x.py::test_b PASSED [100%]\n"
            "\n"
            "============================== 2 passed in 0.28s ===============================\n",
        )
        result = _run(log, "--min-passed", "2", "--require-summary", "--no-skip-check")
        assert result.returncode == 0, "the old gate passed this log - that is the defect"

    def test_removing_no_skip_check_alone_does_NOT_fix_it(self, tmp_path):
        """Phase 42 proposed dropping `--no-skip-check`. On this defect that is not enough.

        Same log, skip check switched back on. Nothing changes, because a silent return
        leaves no SKIPPED line for the check to find. This test exists so the fix cannot
        later be "simplified" back to the proposed one-liner.
        """
        log = _log(
            tmp_path,
            "tests/x.py::test_a PASSED [ 50%]\n"
            "tests/x.py::test_b PASSED [100%]\n"
            "\n"
            "============================== 2 passed in 0.28s ===============================\n",
        )
        without_flag = _run(log, "--min-passed", "2", "--require-summary")
        assert without_flag.returncode == 0, (
            "dropping --no-skip-check was expected to be insufficient here; if it now "
            "fails, the premise of F-42-B has changed and the docs must change with it"
        )
        # But the same log IS rejected once the case is required to have run.
        with_require = _run(
            log, "--min-passed", "2", "--require-summary",
            "--require-run", CASE_31, "--require-run", CASE_32,
        )
        assert with_require.returncode == 1, (
            "the fixed gate must fail a log where the destructive cases never ran"
        )
        assert "did not pass" in with_require.stdout

    def test_the_fixed_gate_fails_closed_with_the_case_named(self, tmp_path):
        """The message must name the case and explain the silent-return shape."""
        log = _log(tmp_path, "tests/x.py::test_a PASSED [100%]\n\n1 passed in 0.1s\n")
        result = _run(
            log, "--min-passed", "1", "--require-summary",
            "--require-run", CASE_32,
        )
        assert result.returncode == 1
        assert CASE_32 in result.stdout
        assert "::error::" in result.stdout, "only the ::error:: channel reaches annotations"
        assert "pytest.skip" in result.stdout, "the message must say what to do instead"


# --------------------------------------------------------------------------------------
# Case A / Case B, as the phase requires them.
# --------------------------------------------------------------------------------------


class TestCaseANormalCiConfiguration:
    """Opt-in present: the destructive cases run and the gate passes."""

    def test_a_full_run_with_both_cases_present_passes(self, tmp_path):
        body = "".join(f"tests/x.py::test_n{i} PASSED\n" for i in range(30))
        body += f"tests/x.py::{CASE_31} PASSED [ 96%]\n"
        body += f"tests/x.py::{CASE_32} PASSED [100%]\n"
        body += "\n32 passed in 3.5s\n"
        log = _log(tmp_path, body)
        result = _run(
            log, "--min-passed", "24", "--require-summary",
            "--require-run", CASE_31, "--require-run", CASE_32,
        )
        assert result.returncode == 0, result.stdout
        assert "required case passed" in result.stdout

    def test_the_measured_opt_in_run_is_reproduced(self, tmp_path):
        """The shape of the real `GEREGE_DESTRUCTIVE_TESTS=1` run: 32 passed, 0 skipped."""
        body = "".join(f"tests/x.py::test_n{i} PASSED\n" for i in range(32))
        body += "\n32 passed, 2 warnings in 3.50s\n"
        log = _log(tmp_path, body)
        result = _run(log, "--min-passed", "24", "--require-summary")
        assert result.returncode == 0


class TestCaseBMissingOptIn:
    """Opt-in missing: the gate fails, non-zero, naming the cases."""

    def test_the_gate_fails_when_neither_case_ran(self, tmp_path):
        log = _log(tmp_path, "tests/x.py::test_a PASSED\n\n26 passed in 0.7s\n")
        result = _run(
            log, "--min-passed", "24", "--require-summary",
            "--require-run", CASE_31, "--require-run", CASE_32,
        )
        assert result.returncode != 0, "a missing opt-in must not produce a green step"

    def test_a_partial_run_fails_and_names_only_the_missing_case(self, tmp_path):
        """One present, one absent: exactly the absent one is reported."""
        log = _log(
            tmp_path,
            f"tests/x.py::{CASE_31} PASSED\n\n25 passed in 0.7s\n",
        )
        result = _run(
            log, "--min-passed", "24", "--require-summary",
            "--require-run", CASE_31, "--require-run", CASE_32,
        )
        assert result.returncode == 1
        assert CASE_32 in result.stdout
        assert "did not pass" in result.stdout


# --------------------------------------------------------------------------------------
# Skip policy: allowed vs unexpected.
# --------------------------------------------------------------------------------------


class TestSkipPolicy:
    def test_six_unexpected_skips_fail(self, tmp_path):
        """Six skipped cases, none documented: the gate fails and names them."""
        body = "".join(f"tests/x.py::test_s{i} SKIPPED (no database)\n" for i in range(6))
        body += "".join(f"SKIPPED [1] tests/x.py:{40 + i}: no database\n" for i in range(6))
        body += "\n26 passed, 6 skipped in 0.7s\n"
        log = _log(tmp_path, body)
        result = _run(log, "--min-passed", "24", "--require-summary")
        assert result.returncode == 1
        assert "6 case(s) SKIPPED" in result.stdout

    def test_a_documented_allowed_skip_still_passes(self, tmp_path):
        """The exception mechanism must keep working - the fix narrows, it does not forbid."""
        body = (
            "tests/x.py::test_ok SKIPPED (SQLite locking property)\n"
            "SKIPPED [1] tests/x.py:669: SQLite locking property\n"
            "\n30 passed, 1 skipped in 0.7s\n"
        )
        log = _log(tmp_path, body)
        result = _run(log, "--min-passed", "24", "--require-summary", "--allow-skip", "test_ok")
        assert result.returncode == 0, result.stdout
        assert "documented skip(s) allowed" in result.stdout

    def test_one_unexpected_skip_beside_one_allowed_still_fails(self, tmp_path):
        body = (
            "tests/x.py::test_ok SKIPPED (documented)\n"
            "tests/x.py::test_surprise SKIPPED (nothing documented this)\n"
            "SKIPPED [1] tests/x.py:1: documented\n"
            "SKIPPED [1] tests/x.py:2: nothing documented this\n"
            "\n30 passed, 2 skipped in 0.7s\n"
        )
        log = _log(tmp_path, body)
        result = _run(log, "--min-passed", "24", "--require-summary", "--allow-skip", "test_ok")
        assert result.returncode == 1
        assert "test_surprise" in result.stdout


# --------------------------------------------------------------------------------------
# Fail-closed behaviour: unparseable, missing, empty, truncated, failed.
# --------------------------------------------------------------------------------------


class TestFailsClosed:
    def test_unparseable_skip_output_fails_closed(self, tmp_path):
        """A summary claims 6 skips but names none (a `-q` run): unverifiable, so fail."""
        log = _log(tmp_path, "26 passed, 6 skipped in 0.7s\n")
        result = _run(log, "--min-passed", "24", "--require-summary")
        assert result.returncode == 1, "an exception list that cannot be applied is not clean"
        assert "names none of them" in result.stdout

    def test_a_missing_log_fails(self, tmp_path):
        result = _run(tmp_path / "does-not-exist.log", "--min-passed", "24")
        assert result.returncode == 1
        assert "cannot read pytest log" in result.stdout

    def test_an_empty_log_fails_when_execution_was_expected(self, tmp_path):
        log = _log(tmp_path, "")
        result = _run(log, "--min-passed", "24", "--require-summary")
        assert result.returncode == 1
        assert "no pytest summary line" in result.stdout

    def test_an_empty_log_fails_even_without_a_floor(self, tmp_path):
        """`--require-summary` alone is enough to reject a run that never completed."""
        log = _log(tmp_path, "")
        result = _run(log, "--require-summary")
        assert result.returncode == 1

    def test_a_failed_case_propagates(self, tmp_path):
        log = _log(
            tmp_path,
            "FAILED tests/x.py::test_bad - AssertionError: nope\n"
            "\n31 passed, 1 failed in 0.7s\n",
        )
        result = _run(log, "--min-passed", "24", "--require-summary")
        assert result.returncode == 1
        assert "FAILED or ERRORED" in result.stdout

    def test_an_error_case_propagates(self, tmp_path):
        log = _log(
            tmp_path,
            "ERROR tests/x.py::test_broken\n"
            "\n31 passed, 1 error in 0.7s\n",
        )
        result = _run(log, "--min-passed", "24")
        assert result.returncode == 1

    def test_a_count_below_the_floor_fails(self, tmp_path):
        log = _log(tmp_path, "10 passed in 0.7s\n")
        result = _run(log, "--min-passed", "24", "--require-summary")
        assert result.returncode == 1
        assert "expected at least 24" in result.stdout

    def test_the_collection_floor_still_works(self, tmp_path):
        log = _log(tmp_path, "10 passed in 0.7s\n")
        result = _run(log, "--min-collected", "259")
        assert result.returncode == 1
        assert "collected" in result.stdout


# --------------------------------------------------------------------------------------
# An injected unexpected skip cannot produce exit 0. The headline negative control.
# --------------------------------------------------------------------------------------


class TestAnInjectedSkipCannotPass:
    @pytest.mark.parametrize("injected", ["test_p20_31_a_stranded_connection_releases_its_locks",
                                          "test_p20_32_schema_reset_actually_empties_the_schema"])
    def test_a_case_that_skipped_instead_of_running_fails(self, tmp_path, injected):
        """If the destructive case were changed to `pytest.skip()`, the skip gate catches it.

        This closes the loop: `--require-run` covers the silent return, and the skip check
        covers the honest skip. Between them there is no shape of "did not do the work"
        that reaches exit 0.
        """
        body = (
            f"tests/x.py::{injected} SKIPPED (needs opt-in)\n"
            f"SKIPPED [1] tests/x.py:780: needs opt-in\n"
            "\n31 passed, 1 skipped in 0.7s\n"
        )
        log = _log(tmp_path, body)
        result = _run(
            log, "--min-passed", "24", "--require-summary",
            "--require-run", CASE_31, "--require-run", CASE_32,
        )
        assert result.returncode == 1

    def test_an_injected_extra_passed_line_cannot_make_a_missing_case_pass(self, tmp_path):
        """Padding the pass count does not fake a required case.

        A count floor is satisfied by any passing test; `--require-run` is not. This is the
        difference the option exists to make.
        """
        log = _log(
            tmp_path,
            "".join(f"tests/x.py::test_pad{i} PASSED\n" for i in range(50))
            + "\n50 passed in 0.7s\n",
        )
        assert _run(log, "--min-passed", "24", "--require-summary").returncode == 0
        assert (
            _run(log, "--min-passed", "24", "--require-summary", "--require-run", CASE_31).returncode
            == 1
        )

    def test_the_real_ci_invocation_is_reproduced(self, tmp_path):
        """The exact flags CI now passes, against a log where the cases did not run."""
        log = _log(tmp_path, "tests/x.py::test_a PASSED\n\n26 passed in 0.7s\n")
        result = _run(
            log, "--min-passed", "24", "--require-summary",
            "--require-run", CASE_31, "--require-run", CASE_32,
        )
        assert result.returncode == 1
        assert CASE_31 in result.stdout and CASE_32 in result.stdout


# --------------------------------------------------------------------------------------
# The workflow itself: this is not a source-string check, it executes the real command.
# --------------------------------------------------------------------------------------


class TestTheWorkflowGateLine:
    def _gate_args(self) -> list[str]:
        import re

        text = open(os.path.join(REPO_ROOT, ".github/workflows/ci.yml"), encoding="utf-8").read()
        start = text.index("check_pytest_log.py /tmp/p20suite.log")
        # The invocation is a shell line continuation: read to the first line that does
        # not end with a backslash, then join. Doing it by lines rather than one regex
        # keeps the continuation handling obvious.
        lines = []
        for line in text[start:].splitlines():
            stripped = line.rstrip()
            if stripped.endswith("\\"):
                lines.append(stripped[:-1])
                continue
            lines.append(stripped)
            break
        return " ".join(lines).split()

    def test_no_skip_check_is_gone_from_the_p20_gate(self):
        assert "--no-skip-check" not in self._gate_args(), (
            "the p20 gate still disables its skip check, so F-42-B is not fixed"
        )

    def test_both_destructive_cases_are_required_to_run(self):
        args = self._gate_args()
        required = [args[i + 1] for i, a in enumerate(args) if a == "--require-run"]
        assert CASE_31 in required, f"--require-run does not pin {CASE_31}"
        assert CASE_32 in required, f"--require-run does not pin {CASE_32}"

    def test_the_count_floor_was_not_lowered(self):
        """24 was the measured floor; the fix must not weaken it to go green."""
        args = self._gate_args()
        assert "--min-passed" in args
        floor = int(args[args.index("--min-passed") + 1])
        assert floor == 24, f"the p20 pass floor changed from 24 to {floor}"
        assert "--require-summary" in args

    def test_the_opt_in_is_still_set_so_the_work_stays_safe(self):
        """The fix must not remove the thing that makes the destructive work deliberate."""
        text = open(os.path.join(REPO_ROOT, ".github/workflows/ci.yml"), encoding="utf-8").read()
        step = text[text.index("Phase 20 — backup confidentiality") :]
        step = step[: step.index("Phase 20: the critical property")]
        assert "GEREGE_DESTRUCTIVE_TESTS" in step
        assert '"1"' in step


class TestTheSourceGuardsUsePytestSkip:
    """The log-reading half is not sufficient on its own; the source had to change.

    Measured in Phase 43: with the destructive opt-in unset, `print("[SKIP] ..."); return`
    produced a log containing

        tests/...py::test_p20_31_... PASSED [ 96%]
        tests/...py::test_p20_32_... PASSED [100%]

    The case name is present AND marked PASSED, so neither a name check nor a count floor
    nor a skip check can tell that no work happened. The only place the truth exists is
    the guard itself, so it must call `pytest.skip()` - which puts a SKIPPED line in the
    log that the gate is already built to read.
    """

    def test_no_destructive_guard_returns_early_while_printing_a_skip_notice(self):
        body = open(
            os.path.join(REPO_ROOT, "tests/test_e06_phase20_backup_remediation.py"),
            encoding="utf-8",
        ).read()
        offenders = [
            line.strip()
            for line in body.splitlines()
            if line.strip().startswith('print("[SKIP]')
        ]
        assert not offenders, (
            "a silent `print(...); return` guard remains; pytest records it as PASSED and "
            f"no log-reading gate can see it: {offenders}"
        )

    def test_both_destructive_cases_call_pytest_skip_with_a_reason(self):
        body = open(
            os.path.join(REPO_ROOT, "tests/test_e06_phase20_backup_remediation.py"),
            encoding="utf-8",
        ).read()
        assert body.count('pytest.skip("GEREGE_DESTRUCTIVE_TESTS=1 is required') == 2, (
            "both destructive cases must skip honestly and state the requirement"
        )

    def test_a_skipped_destructive_case_is_rejected_even_with_the_skip_check_off(self, tmp_path):
        """Defence in depth: `--require-run` alone rejects a skipped case.

        This matters because a future step could re-add `--no-skip-check`; the requirement
        that the case PASSED must not depend on the skip check being enabled.
        """
        log = _log(
            tmp_path,
            f"tests/x.py::{CASE_31} SKIPPED [ 96%]\n"
            f"SKIPPED [1] tests/x.py:789: GEREGE_DESTRUCTIVE_TESTS=1 is required\n"
            "\n31 passed, 1 skipped in 0.7s\n",
        )
        result = _run(
            log, "--min-passed", "24", "--no-skip-check", "--require-run", CASE_31
        )
        assert result.returncode == 1, (
            "a skipped case satisfied --require-run; the check must match PASSED, not the name"
        )
        assert "it SKIPPED" in result.stdout


class TestTheStepProvidesARealDatabase:
    """A skip gate is only meaningful if the suite CAN run.

    CI run 45575674150 measured the other half of F-42-B: once the skip check was on, the
    step failed with "8 case(s) SKIPPED". Six were `@pytestmark_pg` cases and two were the
    destructive ones - because the step set no DATABASE_URL, so `db_engine.is_postgres()`
    was False and the whole module fell back to SQLite on every run since it was written.

    The module was therefore never exercised against PostgreSQL in CI. `--no-skip-check`
    is what kept that invisible, which is why removing it had to be paired with giving the
    step a database rather than with an exception for the skips.
    """

    def _step(self) -> str:
        text = open(os.path.join(REPO_ROOT, ".github/workflows/ci.yml"), encoding="utf-8").read()
        start = text.index("Phase 20 — backup confidentiality")
        return text[start : text.index("Phase 20: the critical property", start)]

    def test_the_step_names_a_postgresql_database(self):
        step = self._step()
        assert "DATABASE_URL:" in step, (
            "the step sets no DATABASE_URL, so is_postgres() is False and every "
            "PostgreSQL case in the module skips - which is what CI measured as 8 skips"
        )
        assert "postgresql+psycopg2://" in step, "the DATABASE_URL is not a PostgreSQL URL"

    def test_the_step_creates_and_migrates_its_own_disposable_database(self):
        """It must own one: two cases empty `public` and cannot share with another step."""
        step = self._step()
        assert "CREATE DATABASE gerege_p20_test" in step
        assert "alembic upgrade head" in step
        assert "provision_roles.py --apply" in step, (
            "without the grants the owner role connects to a database it cannot read"
        )

    def test_the_step_seeds_the_row_the_round_trip_case_protects(self):
        step = self._step()
        assert "p20_seed" in step

    def test_the_count_floor_still_matches_the_measured_run(self):
        """32 pass with a real database; the floor stays 24 as before."""
        step = self._step()
        assert "--min-passed 24" in step
        # Comments in this step legitimately mention the flag while explaining why it was
        # removed. What must not be present is the flag as an ARGUMENT, so only lines that
        # invoke the guard are examined.
        commands = [
            line for line in step.splitlines()
            if "check_pytest_log.py" in line
        ]
        assert commands, "the guard is not invoked in this step"
        for line in commands:
            assert "--no-skip-check" not in line, (
                f"the p20 gate still passes --no-skip-check: {line.strip()}"
            )
