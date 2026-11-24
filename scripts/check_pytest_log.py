#!/usr/bin/env python3
"""Fail a CI step when its pytest log recorded a failure.

Phase 29. Why this exists, stated as the defect it fixes rather than as a feature:

GitHub runs Linux `run:` steps as `bash -e {0}`. `pipefail` is **not** enabled. So
`pytest ... | tee /tmp/x.log` reports the exit status of `tee`, which is 0 whenever it
could write the log. The step could not fail on a test failure at all.

The workflow compensated with two weaker checks: "no SKIPPED" and a `passed >= N`
threshold. Both are satisfiable while a test is failing - a failing test simply is not
counted as passed, so a file with 62 passing and 1 failing still satisfies `>= 62`. That
was measured, not assumed: see tests/test_e29_ci_integrity.py.

The honest limit of this script: it reads the log, so it only catches failures pytest
actually reported there. If pytest dies before writing a summary (segfault, OOM kill),
`--require-summary` is what catches it. Both are checked here.
"""

from __future__ import annotations

import re
import sys

USAGE = (
    "usage: check_pytest_log.py <logfile> [--min-passed N] [--require-summary] "
    "[--allow-skip TESTNAME] [--allow-skip-file PATH] [--no-skip-check] [--min-collected N]"
)

#: Lines pytest writes for a failed or errored test. `-v` prints "FAILED path::test" and
#: the summary prints "FAILED path::test - AssertionError: ...". A bare "ERROR" also covers
#: collection errors, which produce no FAILED line but still mean nothing was verified.
_FAILURE_RE = re.compile(r"^(FAILED|ERROR)\b", re.MULTILINE)
_SKIP_RE = re.compile(r"\bSKIPPED\b")
_PASSED_RE = re.compile(r"(\d+) passed")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(USAGE, file=sys.stderr)
        return 2
    log_path = argv[1]
    want_skip_check = "--no-skip-check" not in argv
    # `--allow-skip NAME` mirrors a step's own documented exception, e.g. a unicode variant
    # test that skips where the engine does not fold the character. It is a narrowing, not a
    # blanket disable: every *other* skip still fails.
    allowed_skips = [
        argv[i + 1] for i, a in enumerate(argv) if a == "--allow-skip" and i + 1 < len(argv)
    ]
    # `--allow-skip-file PATH` permits any skip whose line names that file. Needed where a
    # whole MODULE is gated on an external service rather than individual tests: the four
    # offsite suites gate 46 cases on a live S3 endpoint, and listing 46 test names would
    # rot the moment one is renamed while a path stays stable. Like --allow-skip it is a
    # narrowing, not a blanket disable: a skip in any other file still fails.
    allowed_skip_files = [
        argv[i + 1] for i, a in enumerate(argv) if a == "--allow-skip-file" and i + 1 < len(argv)
    ]
    min_passed = None
    require_summary = "--require-summary" in argv
    # `--min-collected N` asserts how many cases were *collected*, which is stable across
    # environments, unlike `--min-passed`: a suite whose skips depend on a live service
    # reports fewer passes in CI than locally while collecting exactly the same tests.
    min_collected = None
    if "--min-collected" in argv:
        index = argv.index("--min-collected")
        try:
            min_collected = int(argv[index + 1])
        except (IndexError, ValueError):
            print(f"--min-collected needs an integer\n{USAGE}", file=sys.stderr)
            return 2
    if "--min-passed" in argv:
        index = argv.index("--min-passed")
        try:
            min_passed = int(argv[index + 1])
        except (IndexError, ValueError):
            print(f"--min-passed needs an integer\n{USAGE}", file=sys.stderr)
            return 2

    try:
        with open(log_path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError as exc:
        print(f"::error::cannot read pytest log {log_path}: {exc}")
        return 1

    failures = _FAILURE_RE.findall(text)
    failure_lines = [line for line in text.splitlines() if _FAILURE_RE.match(line)]

    if failures:
        # The first line goes into the annotation, which is the channel that reaches a
        # maintainer - the job log needs sign-in.
        names = ";".join(line.split(" - ")[0] for line in failure_lines[:5])
        print(f"::error::{log_path}: {len(failures)} test(s) FAILED or ERRORED: {names}")
        for line in failure_lines:
            print(f"  {line}")
        return 1

    skip_lines = [line for line in text.splitlines() if _SKIP_RE.search(line)]

    # `-rs` writes every skip twice, in two shapes carrying different information:
    #   per case:   tests/x.py::test_a SKIPPED (short reason...) [ 12%]
    #   summary:    SKIPPED [19] tests/x.py:40: the full reason
    # Only the per-case form names the TEST, which is what --allow-skip matches on; only
    # the summary form states a grouped count, a file and line, and the whole reason. So
    # the decision is made per case and the explanation is read from the summary.
    #
    # A `-q` run prints neither, only "=== 1 passed, 33 skipped ===", which means a log can
    # claim 33 skips and name none of them. That is unverifiable rather than clean, and this
    # gate refuses to call it clean: an exception list that cannot be applied is not an
    # exception. CI passes -v -rs, so a log without per-case lines is a misconfigured step,
    # not a suite with nothing to report.
    summary_skip_re = re.compile(
        r"^\s*SKIPPED \[(\d+)\]\s+([\w./-]+\.py):\d+:\s*(.*)$"
    )
    case_skip_lines = [line for line in skip_lines if "::" in line]
    summary_skips = [match for match in (summary_skip_re.match(line) for line in skip_lines) if match]
    total_skipped_match = re.findall(r"(\d+) skipped", text)
    total_skipped = int(total_skipped_match[-1]) if total_skipped_match else 0

    unexpected: list[str] = []
    unexpected_files: set[str] = set()
    if not case_skip_lines and summary_skips:
        # A log whose only skip evidence is the summary section (a truncated capture, or a
        # pytest that writes SKIPPED [n] without the per-case lines). The decision can only
        # be made per summary line, so a NAME exception is matched against the line itself -
        # pytest puts the test name in the reason position for these.
        unexpected = [
            match.group(0)
            for match in summary_skips
            if not any(name in match.group(0) for name in allowed_skips)
            and not any(path in match.group(2) for path in allowed_skip_files)
        ]
        unexpected_files = {
            match.group(2) for match in summary_skips if match.group(0) in unexpected
        }
    elif want_skip_check and total_skipped and not case_skip_lines:
        # Under `-q` pytest prints neither the per-case SKIPPED lines nor the summary
        # section: only "=== 1 passed, 33 skipped ===". A log can therefore claim 33 skips
        # and name none of them. That is unverifiable, not clean, and this gate will not
        # call it clean - an exception list that cannot be applied is not an exception.
        # CI passes -v -rs, so this means a misconfigured step, not a suite with no skips.
        print(
            f"::error::{log_path}: the summary reports {total_skipped} skipped case(s) but the "
            "log names none of them, so no exception can be checked; run pytest with -v so "
            "the per-case SKIPPED lines are written (CI passes -v -rs)"
        )
        return 1

    if case_skip_lines:
        # The normal path: -v names every skipped case, so the decision is per case.
        for line in case_skip_lines:
            if any(name in line for name in allowed_skips):
                continue
            if any(path in line for path in allowed_skip_files):
                continue
            unexpected.append(line)
            match = re.search(r"^\s*([\w./-]+\.py)::", line)
            unexpected_files.add(match.group(1) if match else "(unattributed line)")

    if want_skip_check and unexpected:
        # Report the FILES and the REASONS, not just the fact. The annotation channel is
        # capped and the job log needs a maintainer to sign in, so a message that says only
        # "a case was SKIPPED" costs a full CI cycle to interpret. The reason is the whole
        # difference between "no S3 endpoint in CI" and "the database this step provisions
        # is not reachable" - and the second is a bug in the step itself.
        per_file: dict[str, int] = {}
        reasons: dict[str, int] = {}
        for match in summary_skips:
            if match.group(2) not in unexpected_files:
                continue
            count = int(match.group(1))
            per_file[match.group(2)] = per_file.get(match.group(2), 0) + count
            reason = match.group(3).strip()
            if reason:
                reasons[reason] = reasons.get(reason, 0) + count
        if not per_file:
            # No summary section (-v without -rs): count the per-case lines instead, and
            # take the truncated reason pytest put in parentheses.
            for line in unexpected:
                match = re.search(r"^\s*([\w./-]+\.py)", line)
                key = match.group(1) if match else "(unattributed line)"
                per_file[key] = per_file.get(key, 0) + 1
                reason_match = re.search(r"SKIPPED \(([^)]*)\)", line)
                if reason_match and reason_match.group(1).strip():
                    reason = reason_match.group(1).strip().rstrip(".").strip()
                    reasons[reason] = reasons.get(reason, 0) + 1
        total = sum(per_file.values())
        digest = ", ".join(f"{name} {count}" for name, count in sorted(per_file.items()))
        print(
            f"::error::{log_path}: {total} case(s) SKIPPED in file(s) with no documented "
            f"exception: {digest or '(no attributable lines)'}"
        )
        if reasons:
            top = sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
            print("  reason(s): " + "; ".join(f"{reason} (x{count})" for reason, count in top))
        print(
            "  a case that skips is not a case that passed; each file above needs a "
            "database, an endpoint, or a named exception - and the first two are the fix"
        )
        for line in unexpected:
            print(f"  {line}")
        return 1
    if skip_lines and (allowed_skips or allowed_skip_files):
        # Report CASES, not log lines: -rs writes each skip twice, so the line count says 62
        # where the suite skipped 33, and a number that cannot be reconciled with the
        # summary line is worse than no number.
        counted = sum(int(match.group(1)) for match in summary_skips) or len(case_skip_lines)
        print(f"  {log_path}: {counted} documented skip(s) allowed")


    matches = _PASSED_RE.findall(text)
    # The summary line states the skip count outright ("195 passed, 33 skipped"), while the
    # per-case "SKIPPED [" markers exist only under -v. Counting listeners here rather than
    # reading the summary made --min-collected depend on the verbosity flag: the same suite
    # reported 195 collected under -q and 228 under -v. Prefer the summary, fall back to the
    # markers for a log that was truncated before the summary.
    summary_skips = re.findall(r"(\d+) skipped", text)
    skipped = (
        int(summary_skips[-1]) if summary_skips else len(re.findall(r"SKIPPED\s*\[", text))
    )

    if min_collected is not None:
        collected_total = (int(matches[-1]) if matches else 0) + skipped
        if collected_total < min_collected:
            print(
                f"::error::{log_path}: only {collected_total} collected "
                f"(passed+skipped), expected at least {min_collected}"
            )
            return 1
        print(f"  {log_path}: {collected_total} collected (>= {min_collected})")
    if not matches:
        if require_summary:
            print(f"::error::{log_path}: no pytest summary line; the run did not complete")
            return 1
        print(f"  {log_path}: no summary line (allowed for this step)")
    else:
        passed = int(matches[-1])
        if min_passed is not None and passed < min_passed:
            print(f"::error::{log_path}: only {passed} passed, expected at least {min_passed}")
            return 1
        print(f"  {log_path}: {passed} passed, 0 failed")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
