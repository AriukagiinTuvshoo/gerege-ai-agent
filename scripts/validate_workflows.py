#!/usr/bin/env python3
"""
Structural validation for the CI workflow.

GitHub rejects a workflow whose step has neither `run:` nor `uses:` with the message
"This run likely failed because of a workflow file issue" and no further detail --
a 0-second failure that costs a round-trip to diagnose. YAML being valid is not
enough: the file parses fine and is still rejected.

This check exists because exactly that happened during Phase 8: an inserted block
left a step (`Expire Redis credentials`) with no body. `yaml.safe_load` accepted it.

Usage:  python scripts/validate_workflows.py [.github/workflows/ci.yml ...]
Exit:   0 valid, 1 invalid.
"""
from __future__ import annotations

import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a project dependency
    print("PyYAML is required", file=sys.stderr)
    raise SystemExit(2)


def validate(path: str) -> list[str]:
    problems: list[str] = []
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict) or "jobs" not in doc:
        return [f"{path}: no `jobs:` mapping"]

    for job_name, job in (doc.get("jobs") or {}).items():
        steps = (job or {}).get("steps")
        if not isinstance(steps, list):
            problems.append(f"{path}: job {job_name!r} has no `steps:` list")
            continue
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                problems.append(f"{path}: job {job_name!r} step {i} is not a mapping")
                continue
            if "run" not in step and "uses" not in step:
                problems.append(
                    f"{path}: job {job_name!r} step {i} ({step.get('name', '<unnamed>')!r}) "
                    "has neither `run:` nor `uses:` -- GitHub rejects the whole workflow"
                )
            if "run" in step and not str(step["run"]).strip():
                problems.append(
                    f"{path}: job {job_name!r} step {i} ({step.get('name', '<unnamed>')!r}) "
                    "has an empty `run:`"
                )
            if "run" in step:
                problems.extend(_check_pytest_exit_code(path, job_name, i, step))
    return problems


#: A `pytest ... | tee log` line inside a step body. The pipe makes the pipeline's exit
#: status `tee`'s, and GitHub's default shell is `bash -e` without `pipefail`.
_PIPED_PYTEST_RE = re.compile(r"^\s*pytest\b.*\|", re.MULTILINE)


def _check_pytest_exit_code(path: str, job_name: str, index: int, step: dict) -> list[str]:
    """A piped pytest must be guarded, or the step cannot fail on a test failure.

    Phase 29. This was a real defect, not a hypothetical: 19 steps piped pytest through
    `tee` under `bash -e` (no `pipefail`), so the step passed whenever `tee` could write
    its log. The compensating checks were "no SKIPPED" and `passed >= N`, and both are
    satisfiable while a test fails - 62 passing plus one failing still satisfies `>= 62`.

    Two acceptable guards, either of which makes a failure visible:

    * `set -euo pipefail` in the step - the pipeline returns pytest's own status;
    * `check_pytest_log.py` reading the recorded log - which additionally names the test.

    This is a structural check on the workflow text. It cannot know whether the tests
    themselves are any good; it only refuses the shape that silently discards the result.
    """
    run = str(step.get("run") or "")
    if not _PIPED_PYTEST_RE.search(run):
        return []

    # Phase 30 audit finding F-30-3: this check used `"pipefail" in run`, so a step whose
    # only mention of pipefail was a *comment* passed. Reproduced: a step containing
    # `# never mind pipefail, this is only a comment` plus `pytest ... | tee` validated
    # clean, and running it returned 0 with a failing test - the precise failure this
    # function exists to refuse. Comments are stripped before the guard is looked for, and
    # the guard must appear as an actual command, not as any substring.
    effective = "\n".join(
        line.split("#", 1)[0] for line in run.splitlines()
    )
    # `set -euo pipefail` / `set -o pipefail` / `set -eu -o pipefail`, as a real command.
    has_pipefail = bool(re.search(r"^\s*set\s+.*\bpipefail\b", effective, re.M))
    has_log_guard = bool(
        re.search(r"^\s*[\w./-]*python[\w./-]*\s+scripts/check_pytest_log\.py", effective, re.M)
    )
    if has_pipefail or has_log_guard:
        return []
    name = step.get("name", "<unnamed>")
    return [
        f"{path}: job {job_name!r} step {index} ({name!r}) pipes pytest through a command "
        "but sets neither `set -euo pipefail` nor check_pytest_log.py - the step would "
        "report the pipe's exit status instead of pytest's, so a failing test could pass"
    ]


def main(argv: list[str]) -> int:
    paths = argv or [".github/workflows/ci.yml"]
    problems: list[str] = []
    for path in paths:
        try:
            problems.extend(validate(path))
        except FileNotFoundError:
            problems.append(f"{path}: not found")
        except yaml.YAMLError as exc:
            problems.append(f"{path}: invalid YAML: {exc}")
    if problems:
        print("Workflow validation FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(f"Workflow validation OK ({len(paths)} file(s)).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
