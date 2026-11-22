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
    "[--allow-skip TESTNAME] [--no-skip-check] [--min-collected N]"
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
    unexpected_skips = [
        line for line in skip_lines
        if not any(name in line for name in allowed_skips)
    ]
    if want_skip_check and unexpected_skips:
        print(f"::error::{log_path}: a case was SKIPPED; skipping is not passing")
        for line in unexpected_skips:
            print(f"  {line}")
        return 1
    if skip_lines and allowed_skips:
        print(f"  {log_path}: {len(skip_lines)} documented skip(s) allowed")


    matches = _PASSED_RE.findall(text)
    skipped = len(re.findall(r"SKIPPED\s*\[", text))

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
