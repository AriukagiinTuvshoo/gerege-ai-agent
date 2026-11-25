#!/usr/bin/env python
"""Fail if a backup directory contains anything but authenticated encrypted archives.

This is the CI enforcement point for the Phase 19 confidentiality finding: the manual
backup CLI published plaintext tenant data with ``BACKUP_ENCRYPTION=on`` even though the
scheduled path encrypted correctly. A green unit suite did not notice, because the tests
exercised a code path production had stopped using.

Deliberately a standalone script rather than an inline heredoc in the workflow: it is
independently runnable by an operator against a real host, and it keeps the YAML free of
nested-script indentation hazards.

Exit codes: 0 = every archive is authenticated; 1 = something else is present.
Never prints archive contents — only names and classes.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import backup_automation  # noqa: E402

SIDECAR_SUFFIXES = (".sha256", ".meta.json")


def main(argv: list) -> int:
    directory = argv[1] if len(argv) > 1 else os.getenv("BACKUP_DIR", "backups")
    if not os.path.isdir(directory):
        print(f"::error::backup directory does not exist: {directory}")
        return 1

    problems = []
    for name in sorted(os.listdir(directory)):
        if name.startswith(".") or name.endswith(SIDECAR_SUFFIXES):
            continue
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        klass = backup_automation.classify_archive(path)
        if klass != "authenticated":
            problems.append((name, klass))

    if problems:
        for name, klass in problems:
            print(f"::error file={os.path.join(directory, name)}::{name} is {klass}, not authenticated")
        print("::error::a backup directory contains non-encrypted or unverifiable archives")
        return 1

    archives = [
        f for f in os.listdir(directory)
        if not f.startswith(".") and not f.endswith(SIDECAR_SUFFIXES)
        and os.path.isfile(os.path.join(directory, f))
    ]
    if not archives:
        print(f"::error::no archive found in {directory}")
        return 1

    print(f"OK: {len(archives)} archive(s) in {directory} are all authenticated ciphertext")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
