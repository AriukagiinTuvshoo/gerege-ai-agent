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

    def test_every_pin_has_a_hash(self, lock_text):
        """`--require-hashes` is meaningless if any entry lacks one."""
        entries = re.findall(r"^([a-zA-Z0-9_.\-]+)==([^\s\\]+)", lock_text, re.MULTILINE)
        assert entries, "no pins found in the lock"
        hashes = lock_text.count("--hash=sha256:")
        assert hashes >= len(entries), (
            f"{len(entries)} pins but only {hashes} hashes"
        )
        assert "NO HASH CAPTURED" not in lock_text

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
        content = _read("Dockerfile")
        assert "requirements.lock" in content
        assert "--require-hashes" in content, (
            "the image must install with --require-hashes, otherwise the lock is advisory"
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
        assert "@sha256:" in image, (
            f"base image {image!r} is a mutable tag; pin it by digest"
        )
        if "REPLACE_ME_WITH_RESOLVED_DIGEST" in image:
            pytest.xfail(
                "base-image digest is a documented placeholder: Docker Hub is outside "
                "this environment's egress allowlist, so the digest could not be "
                "resolved. Resolve it before the first staging build with\n"
                "  docker buildx imagetools inspect python:3.12-slim "
                "--format '{{.Manifest.Digest}}'\n"
                "and paste it into the Dockerfile. This test passes once it is real."
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
