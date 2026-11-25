"""Phase 37: the production lock must be hash-verified and scoped to the image's Python.

Phase 36 shipped an exact-version lock with no hashes, and the earlier attempt at hashing
broke the image build because the digests described cp311 wheels while the image runs 3.12.
These tests keep that from silently regressing. They are deliberately offline: the full
wheel-resolution sweep needs PyPI and is run by hand (and by CI's Docker build), so what is
asserted here is the file's own invariants.
"""

from __future__ import annotations

import os
import re

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCK = os.path.join(REPO_ROOT, "requirements.lock")
DOCKERFILE = os.path.join(REPO_ROOT, "Dockerfile")

PIN_RE = re.compile(r"^([a-zA-Z0-9_.\-]+)==([^\s\\]+)", re.MULTILINE)
HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})")


def _lock() -> str:
    with open(LOCK, encoding="utf-8") as handle:
        return handle.read()


def _blocks() -> dict:
    """Map canonical package name -> set of hashes declared for it."""
    out = {}
    for block in re.split(r"\n(?=[a-zA-Z0-9_.\-]+==)", _lock()):
        match = re.match(r"([a-zA-Z0-9_.\-]+)==([^\s\\]+)", block)
        if not match:
            continue
        key = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        out[key] = (match.group(2), set(HASH_RE.findall(block)))
    return out


class TestLockShape:
    def test_every_pin_is_exact_and_carries_a_hash(self):
        blocks = _blocks()
        assert len(blocks) == 46, f"expected 46 production packages, found {len(blocks)}"
        unhashed = [name for name, (_, hashes) in blocks.items() if not hashes]
        assert not unhashed, (
            f"{unhashed} are pinned without a hash; --require-hashes would refuse them"
        )

    def test_no_range_specifiers_leak_in(self):
        body = "\n".join(
            line for line in _lock().splitlines() if line and not line.startswith("#")
        )
        assert ">=" not in body and "~=" not in body, "a range specifier survived the lock"

    def test_hashes_are_well_formed(self):
        for hash_value in HASH_RE.findall(_lock()):
            assert len(hash_value) == 64
            assert re.fullmatch(r"[0-9a-f]{64}", hash_value)


class TestLockScope:
    def test_lock_is_documented_as_cp312_scoped(self):
        """The header is the only place a maintainer learns why 3.11 installs fail."""
        header = _lock().split("--hash=")[0]
        assert "3.12" in header
        assert "cp312" in header or "manylinux" in header
        assert "--require-hashes" in header or "require-hashes" in header

    def test_header_names_the_multiple_platform_requirement(self):
        """A single platform is provably insufficient (pillow vs cffi vs cryptography)."""
        header = _lock().split("--hash=")[0]
        for tag in ("manylinux_2_34", "manylinux_2_28", "manylinux2014"):
            assert tag in header, f"the header does not mention {tag}"
        assert "REPLACES" in header or "replaces" in header, (
            "the header does not warn that --platform replaces the tag set"
        )

    def test_no_test_only_packages_in_the_production_lock(self):
        names = " ".join(_blocks())
        for dev_only in ("pytest", "bandit", "pip-audit", "moto", "fakeredis", "pgserver"):
            assert dev_only not in names, f"{dev_only} leaked into the production lock"


class TestDockerfileEnforcesIt:
    def test_dockerfile_installs_with_require_hashes(self):
        with open(DOCKERFILE, encoding="utf-8") as handle:
            dockerfile = handle.read()
        assert "pip install" in dockerfile
        line = next(
            ln for ln in dockerfile.splitlines()
            if ln.strip().startswith("RUN pip install") and "requirements.lock" in ln
        )
        assert "--require-hashes" in line, (
            "the Dockerfile installs the lock without --require-hashes, so a tampered "
            "or substituted wheel would not be detected"
        )
        assert "--no-deps" in line, (
            "without --no-deps pip may resolve a transitive dependency the lock omits"
        )

    def test_dockerfile_no_longer_claims_hashes_are_unusable(self):
        """Phase 36's comment said hashing was abandoned; the file must not still say so."""
        with open(DOCKERFILE, encoding="utf-8") as handle:
            dockerfile = handle.read()
        assert "deliberately NOT used" not in dockerfile, (
            "the Dockerfile still explains why --require-hashes is disabled"
        )
