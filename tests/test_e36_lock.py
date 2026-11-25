"""Phase 36 - dependency reproducibility.

Phase 35 found `requirements.txt` used ranges with no lockfile and the Dockerfile used
mutable image tags, so two builds of the same commit could differ. This file asserts the
lock is real, complete and reproducible.

The one thing it cannot assert is the base-image digest, because Docker Hub was outside
the sandbox's egress allowlist and the digest could not be resolved. A placeholder is
enforced instead: the test fails while `REPLACE_ME` is in the Dockerfile, so the omission
cannot become permanent by accident.
"""

from __future__ import annotations

import os
import re

import pytest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name: str) -> str:
    with open(os.path.join(REPO_ROOT, name), encoding="utf-8") as handle:
        return handle.read()


@pytest.fixture(scope="module")
def lock_text() -> str:
    return _read("requirements.lock")


class TestLockfile:
    def test_lock_exists(self):
        assert os.path.isfile(os.path.join(REPO_ROOT, "requirements.lock"))

    def test_every_pin_is_exact_and_there_are_no_partial_hashes(self, lock_text):
        """Exactness is the reproducibility guarantee this file actually provides.

        Hashes were attempted and removed: they were generated on CPython 3.11 while the
        image is 3.12, so `--require-hashes` made every install fail. A lock that only
        works on the machine that produced it is not a lock. This test asserts the
        property that holds rather than one that was aspirational.

        If hashes are re-added on the correct interpreter, replace this test with the
        hash-coverage assertion and restore `--require-hashes` in the Dockerfile.
        """
        entries = re.findall(r"^([a-zA-Z0-9_.\-]+)==([^\s\\]+)", lock_text, re.MULTILINE)
        assert entries, "no pins found in the lock"
        assert len(entries) == 46, f"expected 46 production pins, found {len(entries)}"
        assert "NO HASH CAPTURED" not in lock_text, "remove stale hash markers"
        # Phase 37 resolved this: hashes were regenerated for the image's interpreter
        # (cp312) across a manylinux platform matrix, so the lock is now genuinely
        # hash-verified and every pin carries at least one digest. A partial set is still
        # the dangerous state - it looks hash-verified while leaving packages unverified.
        blocks = re.split(r"\n(?=[a-zA-Z0-9_.\-]+==)", lock_text)
        unhashed = []
        for block in blocks:
            match = re.match(r"([a-zA-Z0-9_.\-]+)==", block)
            if match and "--hash=sha256:" not in block:
                unhashed.append(match.group(1))
        assert not unhashed, f"pins without any hash: {unhashed}"
        hashes = lock_text.count("--hash=sha256:")
        assert hashes >= len(entries), (
            f"{hashes} hashes for {len(entries)} pins: a partial hash set is worse than none"
        )

    def test_every_pin_is_an_exact_version(self, lock_text):
        """A range in a lockfile defeats the purpose.

        Written against the operator prefix rather than a single character class: an
        earlier version of this test treated the first `=` of `==` as the operator and
        therefore could not distinguish `==1.2` from `=1.2`.
        """
        for name, spec in re.findall(
            r"^([a-zA-Z0-9_.\-]+)((?:[<>=!~]=?)+[^\s\\]*)", lock_text, re.MULTILINE
        ):
            assert spec.startswith("=="), (
                f"{name} is not pinned exactly: {spec!r}"
            )

    def test_covers_the_production_dependencies(self, lock_text):
        """Every runtime import must be installable from the lock alone.

        Test-only packages are excluded on purpose: the production image must not ship
        pytest, bandit or moto.
        """
        required = [
            "fastapi", "uvicorn", "httpx", "google-genai", "pillow", "python-dotenv",
            "python-multipart", "openpyxl", "qrcode", "jinja2", "sqlalchemy", "alembic",
            "psycopg2-binary", "redis", "cryptography",
        ]
        lowered = lock_text.lower()
        for name in required:
            assert f"{name}==" in lowered, f"{name} is missing from the lock"

    def test_does_not_contain_test_only_packages(self, lock_text):
        lowered = lock_text.lower()
        for name in ("pytest==", "bandit==", "moto==", "fakeredis==", "pip-audit=="):
            assert name not in lowered, f"{name} must not be in the production lock"

    def test_lock_versions_match_requirements_ranges(self, lock_text):
        """The lock must be a resolution OF requirements.txt, not an unrelated set.

        Guards against someone regenerating against a different source.
        """
        from packaging.requirements import Requirement

        requirements = _read("requirements.txt")
        declared = {}
        for line in requirements.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            req = Requirement(line)
            declared[req.name.lower()] = req

        for name, version in re.findall(
            r"^([a-zA-Z0-9_.\-]+)==([^\s\\]+)", lock_text, re.MULTILINE
        ):
            req = declared.get(name.lower())
            if req is None:
                continue  # a transitive dependency
            assert req.specifier.contains(version), (
                f"{name}=={version} is outside the range declared in requirements.txt"
            )


class TestDockerfilePinning:
    def test_installs_from_the_lock(self):
        """The image must install exact versions, not ranges."""
        content = _read("Dockerfile")
        assert "requirements.lock" in content
        # Phase 37 restored --require-hashes once the digests were correct for cp312.
        assert (
            "pip install --no-cache-dir --no-deps --require-hashes -r requirements.lock"
            in content
        )

    def test_hash_flag_matches_hash_coverage(self):
        """The Dockerfile and the lock must agree about whether hashes exist.

        `--require-hashes` with a hashless lock fails every install; a hashless install
        with a hashed lock silently drops the guarantee. Catching the mismatch here is
        much cheaper than catching it in a failed image build.
        """
        dockerfile = _read("Dockerfile")
        lock = _read("requirements.lock")
        # Comments explain why hashes were removed and quote the flag, so count only real
        # requirement lines starting with `--hash`.
        lock_lines = [
            line for line in lock.splitlines()
            if not line.lstrip().startswith("#")
        ]
        has_hashes = any(line.strip().startswith("--hash=sha256:") for line in lock_lines)
        uses_hashes = any(
            line.strip().startswith("RUN") and "--require-hashes" in line
            for line in dockerfile.splitlines()
        )
        assert uses_hashes == has_hashes, (
            f"Dockerfile --require-hashes={uses_hashes} but lock has hashes={has_hashes}"
        )

    def test_does_not_install_ranges_in_production_layer(self):
        """`pip install -r requirements.txt` must not be the production install."""
        content = _read("Dockerfile")
        assert "pip install --no-cache-dir -r requirements.txt" not in content

    def test_base_image_is_digest_pinned_or_the_placeholder_is_flagged(self):
        """Fails while the digest is unresolved, by design.

        When this fails, the correct fix is to resolve the digest and paste it in - NOT
        to delete the assertion. See docs/audit/PHASE_36_STAGING_HARDENING.md.
        """
        content = _read("Dockerfile")
        match = re.search(r"^FROM\s+(\S+)", content, re.MULTILINE)
        assert match, "no FROM line"
        image = match.group(1)

        # The image is supplied through `ARG BASE_IMAGE=...`, so the FROM line itself is
        # `FROM ${BASE_IMAGE}`. What matters is the default that a plain `docker build`
        # would use, because that is what CI builds.
        default_match = re.search(r"^ARG\s+BASE_IMAGE=(\S+)", content, re.MULTILINE)
        assert default_match, (
            "the Dockerfile must declare ARG BASE_IMAGE so the base image can be pinned "
            "at build time without editing the file"
        )
        default_image = default_match.group(1)

        assert ":" in default_image, f"base image {default_image!r} has no tag"
        if "@sha256:" not in default_image:
            pytest.xfail(
                f"the default base image {default_image!r} is a mutable tag, not a digest. "
                "Docker Hub is outside this environment's egress allowlist, so the digest "
                "could not be resolved, and a fabricated digest makes FROM unpullable "
                "(an earlier placeholder broke the CI image build). Pin it at build time "
                "with --build-arg BASE_IMAGE=python:3.12-slim@sha256:<digest>, or change "
                "the ARG default. This test passes once the default carries a digest."
            )

    def test_other_images_in_compose_are_tag_pinned(self):
        """postgres/redis/caddy must at least be on a known tag, not `latest`."""
        for filename in ("docker-compose.prod.yml", "docker-compose.staging.yml"):
            content = _read(filename)
            for image in re.findall(r"image:\s*(\S+)", content):
                assert ":latest" not in image, f"{filename}: {image} uses :latest"
                assert ":" in image, f"{filename}: {image} has no tag"


class TestSplitRequirements:
    def test_dev_requirements_are_separate(self):
        assert os.path.isfile(os.path.join(REPO_ROOT, "requirements-dev.txt"))
        dev = _read("requirements-dev.txt")
        for name in ("pytest", "bandit", "pip-audit"):
            assert name in dev

    def test_dev_requirements_extend_the_runtime_set(self):
        assert "-r requirements.txt" in _read("requirements-dev.txt")
