"""Phase 41 — prove the 46 S3 cases EXECUTE, not merely collect.

Phase 40's report said "46 S3-related skips, a known and reported gap". The trap in
closing that gap is obvious and this repository has already fallen into it once: lower the
skip count without running anything. A gate that counts passes is satisfied by a test that
passes for the wrong reason, and a `skipif` that quietly evaluates to True everywhere looks
identical to coverage.

So this file checks three separate things:

  1. **the endpoint is reachable** when `BACKUP_OFFSITE_TEST_ENDPOINT` is set, by making a
     real request to it;
  2. **the code under test really talks to it** - an object uploaded through `S3Offsite`
     is visible through an independent boto3 client, and an object written by boto3 is
     readable through `S3Offsite`. A skipped or mocked path cannot satisfy both;
  3. **the CI step runs them** - the workflow selection includes all four suites, the gate
     no longer excuses them by file, and its floor is the measured count.

When no endpoint is configured this file skips, and the CI gate treats that skip as a
failure (there is no `--allow-skip` for it). Locally, `python -m moto.server -p 5062` plus
`BACKUP_OFFSITE_TEST_ENDPOINT=http://127.0.0.1:5062` is enough.
"""

from __future__ import annotations

import os
import re
import urllib.error
import urllib.request

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ENDPOINT = os.getenv("BACKUP_OFFSITE_TEST_ENDPOINT", "").strip()
BUCKET = "p41-execution-probe"

OFFSITE_SUITES = (
    "tests/test_e07_phase22_offsite_pagination.py",
    "tests/test_e07_phase22_offsite_integrity.py",
    "tests/test_e07_phase22_offsite_status.py",
    "tests/test_e07_phase24_offsite_integration.py",
)


def _read(rel: str) -> str:
    with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


requires_endpoint = pytest.mark.skipif(
    not ENDPOINT, reason="BACKUP_OFFSITE_TEST_ENDPOINT is not set; no S3 endpoint to run against"
)


# --------------------------------------------------------- the endpoint is a real server


@requires_endpoint
def test_the_configured_endpoint_answers_http():
    """A reachability probe. If this fails, every offsite case is about to skip."""
    try:
        with urllib.request.urlopen(ENDPOINT, timeout=5) as response:
            assert response.status in (200, 403), (
                f"{ENDPOINT} answered {response.status}; moto answers 200 on /"
            )
    except urllib.error.URLError as exc:
        pytest.fail(f"the S3 test endpoint named by the environment is not reachable: {exc}")


# ------------------------------------------------------- the code under test uses it


@requires_endpoint
def test_an_object_uploaded_by_the_code_is_visible_to_an_independent_client(tmp_path):
    """Round trip across two implementations, so a fake on either side is caught.

    `S3Offsite` is the code under test; boto3 is the independent observer. If the upload
    were mocked, boto3 would not see the object. If boto3's view were faked, reading the
    bytes back would not match.
    """
    import boto3
    from botocore.config import Config

    from core.backup_offsite import S3Offsite

    client = boto3.client(
        "s3",
        endpoint_url=ENDPOINT,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1",
        config=Config(s3={"addressing_style": "path"}),
    )
    try:
        client.create_bucket(Bucket=BUCKET)
    except Exception:
        pass  # already exists from a previous run in the same server

    payload = b"phase-41-execution-probe-" + os.urandom(8)
    source = tmp_path / "probe.bin"
    source.write_bytes(payload)

    provider = S3Offsite(ENDPOINT, BUCKET, "test", "test", "us-east-1")
    provider.upload(str(source), "probe/key.bin", _sha256(payload))

    # The independent client sees it.
    found = client.head_object(Bucket=BUCKET, Key="probe/key.bin")
    assert found["ContentLength"] == len(payload)

    # And the reverse direction: an object written by boto3 is readable by the code.
    client.put_object(Bucket=BUCKET, Key="probe/written-by-boto3.bin", Body=payload)
    target = tmp_path / "downloaded.bin"
    provider.download("probe/written-by-boto3.bin", str(target))
    assert target.read_bytes() == payload


@requires_endpoint
def test_the_code_reports_a_failure_rather_than_silently_succeeding(tmp_path):
    """The negative half: a missing object must report failure and write no file.

    The provider's contract is a `(ok, detail)` tuple, not an exception - so the assertion
    is on the tuple AND on the filesystem. A backup system whose failures look like
    successes is worse than one with no offsite at all, and returning `(False, ...)` while
    leaving a zero-byte file behind would be exactly that.
    """
    from core.backup_offsite import S3Offsite

    provider = S3Offsite(ENDPOINT, BUCKET, "test", "test", "us-east-1")
    target = tmp_path / "nope.bin"
    ok, detail = provider.download("probe/does-not-exist.bin", str(target))
    assert ok is False, f"downloading a missing object reported success: {detail}"
    assert detail, "a failure must say why"
    assert not target.exists(), "a failed download left a file behind"


@requires_endpoint
def test_a_wrong_digest_is_refused(tmp_path):
    """Integrity, not just transport: the bytes arrive but are not the bytes expected."""
    from core.backup_offsite import S3Offsite

    source = tmp_path / "src.bin"
    source.write_bytes(b"content")
    provider = S3Offsite(ENDPOINT, BUCKET, "test", "test", "us-east-1")
    wrong = "0" * 64
    ok, detail = provider.upload(str(source), "probe/bad-digest.bin", wrong)
    # `verify()` is metadata-only BY DESIGN and accepts same-size corruption - that gap is
    # Phase 21's P21-05 finding, and `test_metadata_only_verify_accepts_same_size_corruption`
    # in the Phase 22 suite asserts it deliberately. The check that closes it is
    # `verify_against_record`, which downloads the bytes and compares them with the digest
    # recorded locally.
    metadata_only, _ = provider.verify("probe/bad-digest.bin", len(b"content"), wrong)
    assert metadata_only is True, (
        "the metadata-only check changed behaviour; if that is intentional the Phase 22 "
        "test that documents the gap must change with it"
    )
    verified, why = provider.verify_against_record(
        "probe/bad-digest.bin", expected_sha256=wrong, expected_size=len(b"content")
    )
    assert verified is False, "verify_against_record accepted an object whose bytes differ"
    assert why


def _sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------- the CI step runs them


class TestTheCiSelectionIncludesAllFourSuites:
    def test_every_offsite_suite_is_in_the_pytest_selection(self):
        text = _read(".github/workflows/ci.yml")
        start = text.index("Phase 22/23/24 — backup security")
        end = text.index("Phase 29 — CI test integrity")
        step = text[start:end]
        for rel in OFFSITE_SUITES:
            name = os.path.basename(rel)
            assert name in step, f"{name} is not in the backup step's pytest selection"

    def test_the_gate_does_not_excuse_them(self):
        text = _read(".github/workflows/ci.yml")
        start = text.index("Phase 22/23/24 — backup security")
        end = text.index("Phase 29 — CI test integrity")
        gate = text[start:end]
        gate = gate[gate.index("check_pytest_log.py"):]
        assert "--allow-skip-file" not in gate, (
            "an --allow-skip-file remains, so a whole offsite suite may still skip unseen"
        )

    def test_the_skip_count_recorded_in_the_step_is_one(self):
        """46 S3 skips used to be permitted; now the only one is the SQLite WAL case."""
        text = _read(".github/workflows/ci.yml")
        step = text[
            text.index("Phase 22/23/24 — backup security") :
            text.index("Phase 29 — CI test integrity")
        ]
        measured = re.search(r"Measured with moto[^:]*: (\d+) passed, (\d+) skipped", step)
        assert measured, "the step no longer records a moto measurement"
        passed, skipped = int(measured.group(1)), int(measured.group(2))
        assert skipped == 1, f"the recorded skip count is {skipped}, expected the WAL case only"
        assert passed + skipped == 228 + 31, (
            f"the recorded measurement adds up to {passed + skipped}, expected 259"
        )
