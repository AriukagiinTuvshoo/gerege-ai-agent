"""Phase 29 - CI test integrity.

The finding this file exists for, stated plainly because the Phase 28 report got it wrong:

Phase 28 reported "30 full-suite failures, all pre-existing environment limits". That was
wrong on both counts. The 30 failures were caused by this sandbox lacking the PostgreSQL
client binaries that CI installs at step 2 (`apt-get install postgresql-client`). With
`pg_dump`/`pg_restore`/`psql` on PATH the same suite is **1249 passed, 0 failed**, and the
Phase 27 baseline is equally green. There was no pre-existing failure set to be pre-existing
of. The honest statement is the one in this file's tests: the suite is green when run in an
environment that matches CI's.

The second finding is separate and real, and it is what most of this file tests: CI could
pass with a failing test in 19 of its steps. GitHub runs `run:` steps as `bash -e` without
`pipefail`, so `pytest ... | tee log` returns `tee`'s status. The compensating checks were
"no SKIPPED" and `passed >= N`, and a file with 62 passing and 1 failing satisfies both.
That was measured against a synthetic log, not argued.
"""

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
GUARD = REPO_ROOT / "scripts" / "check_pytest_log.py"
VALIDATOR = REPO_ROOT / "scripts" / "validate_workflows.py"

sys.path.insert(0, str(REPO_ROOT / "scripts"))


# ===========================================================================
# 1. The exit-code masking defect
# ===========================================================================

def _steps():
    yaml = pytest.importorskip("yaml")
    with open(CI, encoding="utf-8") as handle:
        doc = yaml.safe_load(handle)
    steps = []
    for job_name, job in (doc.get("jobs") or {}).items():
        for index, step in enumerate((job or {}).get("steps") or []):
            steps.append((job_name, index, step))
    return steps


def test_every_piped_pytest_invocation_can_fail_its_step():
    """The defect, asserted directly against the workflow.

    Phase 28 introduced one of these itself (the Phase 28 security step), so this is not a
    criticism of older work only - it is the shape the whole file had.
    """
    offenders = []
    for job_name, index, step in _steps():
        run = str(step.get("run") or "")
        for line in run.splitlines():
            stripped = line.strip()
            if not stripped.startswith("pytest") or "|" not in stripped:
                continue
            guarded = "pipefail" in run or "check_pytest_log.py" in run
            if not guarded:
                offenders.append((job_name, index, step.get("name"), stripped[:70]))
    assert offenders == [], f"piped pytest without an exit-code guard: {offenders}"


def test_the_default_shell_really_does_mask_a_piped_failure():
    """The premise of the whole fix, executed rather than assumed.

    If a future GitHub change enabled `pipefail` by default this test would fail, and the
    guards would be redundant rather than wrong - which is the right way to find that out.
    """
    masked = subprocess.run(
        ["bash", "-e", "-c", "false | tee /dev/null >/dev/null"],
        capture_output=True,
    )
    assert masked.returncode == 0, "a piped failure did not mask; re-check the guards"

    caught = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", "false | tee /dev/null >/dev/null"],
        capture_output=True,
    )
    assert caught.returncode != 0, "pipefail did not surface the failure"


def test_pipefail_does_not_break_the_diagnostic_pipelines():
    """`grep | head | grep` legitimately finds nothing; under pipefail that would exit 1.

    Those assignments carry an explicit `|| true` fallback so the *threshold* decides, and
    the threshold reports what it saw. Without this a green run could go red for a reason
    that has nothing to do with the tests - which trains people to ignore the build.
    """
    for _job, _index, step in _steps():
        run = str(step.get("run") or "")
        if "pipefail" not in run:
            continue
        for line in run.splitlines():
            stripped = line.strip()
            if re.match(r"^(collected|got|failed_names|unexpected)=\$\(grep", stripped):
                assert stripped.endswith("|| true)"), (
                    "a diagnostic pipeline under pipefail needs an explicit fallback: "
                    f"{stripped}"
                )


# ===========================================================================
# 2. The guard script's behaviour
# ===========================================================================

def _run_guard(tmp_path, body, *args):
    log = tmp_path / "log.txt"
    log.write_text(body, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(GUARD), str(log), *args],
        capture_output=True,
        text=True,
    )


def test_the_guard_rejects_a_log_with_a_failing_test(tmp_path):
    """The exact case the count threshold could not see: many passed, one failed."""
    result = _run_guard(
        tmp_path,
        "a PASSED\nFAILED tests/x.py::test_y - AssertionError: no\n\n62 passed, 1 failed in 1s\n",
        "--min-passed", "62",
    )
    assert result.returncode == 1
    assert "test_y" in result.stdout, "the annotation must name the failing test"


def test_the_guard_accepts_a_clean_log(tmp_path):
    result = _run_guard(tmp_path, "a PASSED\n\n63 passed in 1s\n", "--min-passed", "62")
    assert result.returncode == 0, result.stdout


def test_the_guard_rejects_a_skip(tmp_path):
    """Skipping is not passing - the same rule the workflow already applied."""
    result = _run_guard(tmp_path, "a PASSED\nSKIPPED [1] x.py:12: not applicable\n1 passed, 1 skipped\n")
    assert result.returncode == 1
    assert "SKIPPED" in result.stdout


def test_the_guard_rejects_a_collection_error(tmp_path):
    """A collection error writes no FAILED line, so an exit-code check alone is not enough."""
    result = _run_guard(tmp_path, "ERROR tests/x.py - ImportError\n\n1 error in 0.1s\n")
    assert result.returncode == 1


def test_the_guard_rejects_an_under_collected_run(tmp_path):
    """A renamed file or a wrong selection collects fewer tests; the count still matters."""
    result = _run_guard(tmp_path, "a PASSED\n\n5 passed in 0.1s\n", "--min-passed", "62")
    assert result.returncode == 1
    assert "expected at least 62" in result.stdout


def test_the_guard_keeps_a_steps_documented_skip_exception_narrow(tmp_path):
    """`--allow-skip NAME` narrows the skip check; it does not disable it.

    Two steps legitimately skip one case by name. Passing `--no-skip-check` there would
    have quietly dropped an assertion the step already made, so the guard takes the
    exception instead and still fails on any other skip.
    """
    allowed = _run_guard(
        tmp_path,
        "SKIPPED [1] x.py:12: test_141_unicode_variants: engine does not fold\n10 passed\n",
        "--allow-skip", "test_141_unicode_variants",
    )
    assert allowed.returncode == 0, allowed.stdout

    other = _run_guard(
        tmp_path,
        "SKIPPED [1] x.py:99: some_other_case: not applicable\n10 passed\n",
        "--allow-skip", "test_141_unicode_variants",
    )
    assert other.returncode == 1, "a skip other than the named exception must still fail"


def test_each_steps_skip_policy_is_preserved_exactly():
    """The guard must reproduce the assertion the step already made - no more, no less.

    Phase 29 got this wrong on the first attempt in both directions, and CI caught it:

    * `/tmp/p20suite.log` was given a *stricter* rule than it had (phase 20 never asserted
      "no skips"), so a step that had always been allowed to skip began failing;
    * `/tmp/p10.log` lost its documented exception, so an allowed skip began failing.

    The rule asserted here: a log gets `--no-skip-check` only if the pre-Phase-29 step did
    not assert "no SKIPPED" for it, and it carries exactly the `--allow-skip` names the old
    step allowed by name.
    """
    # The policy is read from the workflow as it stands, not from `git show c31f6fe`:
    # CI checks out shallow, so that commit is not present and the test failed there while
    # passing locally. A test that only works with full history is a test that fails where
    # it matters. The mapping below is the c31f6fe policy, transcribed, and the assertion
    # is that the current workflow still honours it.
    EXPECTED_POLICY = {
        # log: (asserted "no SKIPPED" at c31f6fe, exceptions allowed by name)
        "/tmp/p4.log": (False, []),
        "/tmp/p41.log": (True, ["test_141_unicode_variants"]),
        "/tmp/p42.log": (True, []),
        "/tmp/p43.log": (True, []),
        "/tmp/p44.log": (True, []),
        "/tmp/p6.log": (True, []),
        "/tmp/p8.log": (True, []),
        "/tmp/p10.log": (True, ["test_1046_an_unclosed_connection"]),
        "/tmp/p11.log": (True, []),
        "/tmp/e03a.log": (True, []),
        "/tmp/e03b.log": (True, []),
        "/tmp/e03c.log": (True, []),
        "/tmp/p13.log": (True, []),
        "/tmp/e05.log": (True, []),
        "/tmp/p16.log": (True, []),
        "/tmp/p18suite.log": (True, []),
        "/tmp/p20suite.log": (False, []),
        "/tmp/p24suite.log": (True, []),
        "/tmp/p27suite.log": (True, []),
        "/tmp/p28suite.log": (True, []),
        "/tmp/p26suite.log": (True, []),
        "/tmp/p25suite.log": (True, []),
    }
    policy = {
        log: {"asserts": asserts, "exceptions": excs}
        for log, (asserts, excs) in EXPECTED_POLICY.items()
    }

    after = CI.read_text(encoding="utf-8")
    checked = 0
    for log, rules in policy.items():
        match = re.search(
            re.escape(log) + r"[^\n]*",
            "\n".join(l for l in after.splitlines() if "check_pytest_log.py" in l),
        )
        assert match, f"no guard line for {log}"
        line = match.group(0)
        if rules["asserts"]:
            # The step asserted "no SKIPPED" before Phase 29, so it must still do so.
            assert "--no-skip-check" not in line, f"{log} had a skip assertion; it must stay on"
        else:
            # The step never asserted it, so imposing one would be a new requirement - and
            # is exactly how CI run 45008517419 failed on Phase 20's always-allowed skip.
            assert "--no-skip-check" in line, (
                f"{log} had no skip assertion at c31f6fe; adding one changes the step's "
                "contract rather than enforcing it"
            )
        for exception in rules["exceptions"]:
            assert f"--allow-skip {exception}" in line, (
                f"{log} lost its documented exception {exception!r}"
            )
        checked += 1
    assert checked >= 18, f"expected at least 18 guarded logs, checked {checked}"


def test_the_guard_can_assert_collection_rather_than_passes(tmp_path):
    """`--min-collected` is stable where `--min-passed` is not.

    The backup-security step skips 79 cases without a live S3 endpoint, so it reported 184
    passes here and 148 in CI while collecting the same 227. A pass floor failed CI on a
    difference that said nothing about the code; a collection floor catches the case that
    does matter - a file quietly dropping out of the run.
    """
    log = tmp_path / "log.txt"
    log.write_text(
        "".join(f"t{i} PASSED\n" for i in range(148))
        + "".join(f"SKIPPED [1] x.py:{i}: no endpoint\n" for i in range(79))
        + "\n148 passed, 79 skipped in 30s\n",
        encoding="utf-8",
    )
    ok = subprocess.run(
        [sys.executable, str(GUARD), str(log), "--min-collected", "227", "--no-skip-check"],
        capture_output=True, text=True,
    )
    assert ok.returncode == 0, ok.stdout

    low = tmp_path / "low.txt"
    low.write_text("100 passed, 50 skipped in 1s\n", encoding="utf-8")
    bad = subprocess.run(
        [sys.executable, str(GUARD), str(low), "--min-collected", "227", "--no-skip-check"],
        capture_output=True, text=True,
    )
    assert bad.returncode == 1
    assert "collected" in bad.stdout


def test_the_guard_requires_a_summary_where_the_step_asks_for_one(tmp_path):
    """A killed run writes no summary. `--require-summary` turns that into a failure."""
    result = _run_guard(tmp_path, "partial output\n", "--require-summary")
    assert result.returncode == 1
    assert "did not complete" in result.stdout


def test_the_guard_reports_a_missing_log_rather_than_passing(tmp_path):
    result = subprocess.run(
        [sys.executable, str(GUARD), str(tmp_path / "absent.log")],
        capture_output=True, text=True,
    )
    assert result.returncode == 1
    assert "cannot read" in result.stdout


def test_the_threshold_alone_would_have_missed_a_real_failure(tmp_path):
    """The measured blind spot, encoded so the reasoning survives.

    This reproduces what the old threshold could not see: a log where the count still
    clears the bar because other tests passed, while one test genuinely failed. The
    threshold check passes; the guard must not.

    Measured end to end during Phase 29 by removing a real guard from the address
    classifier and adding passing filler tests: 64 passed, 1 failed, `>= 62` satisfied,
    step exit 0, regression shipped. With the guard, exit 1.
    """
    log = tmp_path / "log.txt"
    log.write_text(
        "".join(f"test_filler_{i} PASSED\n" for i in range(64))
        + "FAILED tests/x.py::test_the_classifier_is_a_positive_allowlist_not_a_blocklist"
          " - AssertionError: guard removed\n\n64 passed, 1 failed in 1s\n",
        encoding="utf-8",
    )
    # The old threshold logic, reproduced literally: no skip, count >= 62 -> pass.
    text = log.read_text(encoding="utf-8")
    passed = int(re.search(r"(\d+) passed", text).group(1))
    assert passed >= 62 and "SKIPPED" not in text, "the fixture must satisfy the old checks"

    result = subprocess.run(
        [sys.executable, str(GUARD), str(log), "--min-passed", "62"],
        capture_output=True, text=True,
    )
    assert result.returncode == 1, "the guard passed a log the threshold also passed"
    assert "test_the_classifier" in result.stdout


# ===========================================================================
# 3. The structural check that keeps this from regressing
# ===========================================================================

def test_the_validator_flags_an_unguarded_piped_pytest(tmp_path):
    """A negative control for the check itself: remove the guard, the check must fire."""
    import validate_workflows

    sample = tmp_path / "ci.yml"
    sample.write_text(
        "jobs:\n  j:\n    steps:\n      - name: unguarded\n"
        "        run: |\n          pytest tests/x.py -v | tee /tmp/x.log\n",
        encoding="utf-8",
    )
    problems = validate_workflows.validate(str(sample))
    assert any("pipes pytest" in p for p in problems), problems


def test_the_validator_accepts_the_guarded_form(tmp_path):
    import validate_workflows

    sample = tmp_path / "ci.yml"
    sample.write_text(
        "jobs:\n  j:\n    steps:\n      - name: guarded\n"
        "        run: |\n          set -euo pipefail\n"
        "          pytest tests/x.py -v | tee /tmp/x.log\n",
        encoding="utf-8",
    )
    assert validate_workflows.validate(str(sample)) == []


def test_the_validator_is_run_by_ci_and_guards_its_own_workflow():
    """A check nobody runs is documentation. This asserts CI executes it."""
    text = CI.read_text(encoding="utf-8")
    assert "scripts/validate_workflows.py" in text
    assert "scripts/check_pytest_log.py" in text


def test_the_repository_workflow_passes_its_own_validator():
    result = subprocess.run(
        [sys.executable, str(VALIDATOR), str(CI)],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    assert result.returncode == 0, result.stderr


# ===========================================================================
# 4. CI coverage of the security suites
# ===========================================================================

def test_every_security_phase_suite_is_executed_by_ci():
    """Phases 25-29 must each be wired in, by name, or a regression in them ships unchecked."""
    text = CI.read_text(encoding="utf-8")
    for suite in (
        "tests/test_e07_phase25_aidolab_critical.py",
        "tests/test_e07_phase26_sql_injection.py",
        "tests/test_e07_phase27_network_tempfiles.py",
        "tests/test_e07_phase28_ssrf_and_tempfiles.py",
        "tests/test_e29_ci_integrity.py",
    ):
        assert suite in text, f"{suite} is not run by CI"


def test_the_backup_security_suites_are_executed_by_ci():
    """Phase 29 closed this gap: 227 green tests across 16 files were never run.

    The files below cover backup confidentiality, offsite integrity, alerting and restore
    verification - security work that a later change could break silently.
    """
    text = CI.read_text(encoding="utf-8")
    for suite in (
        "tests/test_e07_phase22_alerting.py",
        "tests/test_e07_phase22_backup_policy.py",
        "tests/test_e07_phase22_offsite_integrity.py",
        "tests/test_e07_phase23_restore_verification.py",
        "tests/test_e07_phase24_disaster_recovery.py",
    ):
        assert suite in text, f"{suite} is not run by CI"
