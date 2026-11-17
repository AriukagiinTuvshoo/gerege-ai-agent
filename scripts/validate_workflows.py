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
    return problems


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
