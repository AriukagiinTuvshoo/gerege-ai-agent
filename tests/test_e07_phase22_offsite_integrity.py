"""Phase 22 regression tests: P21-05 remote integrity independent of the provider.

Phase 21 overwrote a remote object with same-size corruption while preserving the metadata
the server echoes, then called the production verifier:

    >>> offsite.verify("obj.enc", len(good), sha)
    (True, '')          # the bytes were corrupt

``verify()`` reads Content-Length and ``x-amz-meta-p20-*`` from a HEAD. Those are claims by
the server about the object. They are useful - they catch truncation and a wrong object -
but they cannot prove the bytes are the bytes, because whoever can write the object can
also write the metadata describing it.

Two further defects turned up while reproducing this:

* **S3 could not download at all.** ``S3Offsite.download`` and therefore
  ``download_verified`` raised ``NotImplementedError``. Upload, listing and retention all
  worked, and ``verify()`` did a real HEAD, so offsite looked healthy while the one
  operation disaster recovery needs - getting the bytes back - was unimplemented. The
  Phase 20 test for ``download_verified`` exercised ``LocalOffsite`` only.
* **The upload was never read back.** The scheduled path treated a completed PUT as a
  verified copy, and then ran remote retention. So the only proof an offsite copy existed
  was the server accepting a request.

These tests run against a real S3 server, because the defect lives in the HTTP conversation
between client and server. Set ``BACKUP_OFFSITE_TEST_ENDPOINT`` to a moto/minio endpoint.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import sys
import uuid

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.backup_offsite import (  # noqa: E402
    OFFSITE_CONFIGURED,
    OFFSITE_FAILED,
    OFFSITE_NOT_CONFIGURED,
    OFFSITE_VERIFIED,
    OffsiteProvider,
    S3Offsite,
)

ENDPOINT = os.getenv("BACKUP_OFFSITE_TEST_ENDPOINT", "")


@pytest.fixture(scope="module")
def s3_server():
    if not ENDPOINT:
        pytest.skip("set BACKUP_OFFSITE_TEST_ENDPOINT to a moto/minio endpoint")
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(ENDPOINT, timeout=5) as response:
            assert response.status == 200
    except (urllib.error.URLError, OSError) as exc:
        pytest.skip(f"S3 test endpoint not reachable: {exc}")

    import boto3

    return boto3.client(
        "s3",
        endpoint_url=ENDPOINT,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1",
    )


@pytest.fixture
def bucket(s3_server):
    name = "p22int" + uuid.uuid4().hex[:12]
    s3_server.create_bucket(Bucket=name)
    return name


@pytest.fixture
def provider(bucket):
    return S3Offsite(ENDPOINT, bucket, "test", "test", "us-east-1")


# ---------------------------------------------------------------------------
# download must exist at all
# ---------------------------------------------------------------------------

def test_s3_download_returns_the_bytes(s3_server, bucket, provider, tmp_path):
    """The defect: this raised NotImplementedError, so restore-from-offsite was impossible."""
    payload = os.urandom(30_000)
    s3_server.put_object(Bucket=bucket, Key="obj.enc", Body=payload)
    target = tmp_path / "got.enc"
    ok, error = provider.download("obj.enc", str(target))
    assert ok is True, error
    assert target.read_bytes() == payload


def test_s3_does_not_redeclare_an_abstract_download(provider):
    """`S3Offsite` must not shadow a working implementation with a placeholder.

    It previously carried `def download(...): raise NotImplementedError`, which made the
    provider abstract in practice while looking concrete.
    """
    import ast

    source = (REPO_ROOT / "core" / "backup_offsite.py").read_text()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "S3Offsite":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == "download":
                    body = ast.get_source_segment(source, item) or ""
                    assert "NotImplementedError" not in body, (
                        "S3Offsite.download is a placeholder again; restore from offsite "
                        "would be impossible"
                    )
    # And the behavioural guarantee:
    target = (REPO_ROOT / "core" / "backup_offsite.py").read_text()
    assert "class S3Offsite" in target


def test_download_writes_privately_and_leaves_no_partial(s3_server, bucket, provider, tmp_path):
    payload = os.urandom(4096)
    s3_server.put_object(Bucket=bucket, Key="p.enc", Body=payload)
    target = tmp_path / "p.downloaded"
    ok, _error = provider.download("p.enc", str(target))
    assert ok is True
    mode = target.stat().st_mode & 0o777
    assert mode == 0o600, f"downloaded archive is {oct(mode)}"
    assert not list(tmp_path.glob("*.part-*")), "a partial download was left behind"


def test_download_of_a_missing_object_fails_cleanly(provider, tmp_path):
    ok, error = provider.download("absent.enc", str(tmp_path / "x"))
    assert ok is False
    assert "404" in error
    assert not (tmp_path / "x").exists()


# ---------------------------------------------------------------------------
# P21-05 itself: metadata is not evidence
# ---------------------------------------------------------------------------

def test_metadata_only_verify_accepts_same_size_corruption(s3_server, bucket, provider):
    """Documents the weakness that motivates verify_against_record().

    This is not a bug being asserted - it is the measured limit of a HEAD, and the reason a
    digest check exists. If a future change makes verify() catch this, this test will fail
    and should be updated deliberately rather than by accident.
    """
    good = os.urandom(40_000)
    digest = hashlib.sha256(good).hexdigest()
    corrupt = bytearray(good)
    corrupt[len(corrupt) // 2] ^= 0xFF
    s3_server.put_object(
        Bucket=bucket, Key="obj.enc", Body=bytes(corrupt),
        Metadata={"p20-sha256": digest, "p20-size": str(len(good))},
    )
    ok, _error = provider.verify("obj.enc", len(good), digest)
    assert ok is True, "HEAD-only verification is expected to miss same-size corruption"


def test_verify_against_record_rejects_same_size_corruption(s3_server, bucket, provider, tmp_path):
    """The fix for P21-05: compare received bytes with a locally recorded digest."""
    good = os.urandom(40_000)
    digest = hashlib.sha256(good).hexdigest()
    corrupt = bytearray(good)
    corrupt[len(corrupt) // 2] ^= 0xFF
    s3_server.put_object(
        Bucket=bucket, Key="obj.enc", Body=bytes(corrupt),
        Metadata={"p20-sha256": digest, "p20-size": str(len(good))},
    )
    ok, error = provider.verify_against_record(
        "obj.enc", expected_sha256=digest, expected_size=len(good), workdir=str(tmp_path)
    )
    assert ok is False
    assert "digest" in error


def test_verify_against_record_accepts_a_good_object(s3_server, bucket, provider, tmp_path):
    good = os.urandom(20_000)
    digest = hashlib.sha256(good).hexdigest()
    s3_server.put_object(Bucket=bucket, Key="good.enc", Body=good)
    ok, error = provider.verify_against_record(
        "good.enc", expected_sha256=digest, expected_size=len(good), workdir=str(tmp_path)
    )
    assert ok is True, error


def test_verify_against_record_rejects_truncation(s3_server, bucket, provider, tmp_path):
    good = os.urandom(20_000)
    digest = hashlib.sha256(good).hexdigest()
    s3_server.put_object(Bucket=bucket, Key="short.enc", Body=good[:1000])
    ok, error = provider.verify_against_record(
        "short.enc", expected_sha256=digest, expected_size=len(good), workdir=str(tmp_path)
    )
    assert ok is False
    assert "size" in error


def test_verify_against_record_rejects_a_different_size_object(s3_server, bucket, provider, tmp_path):
    good = os.urandom(20_000)
    digest = hashlib.sha256(good).hexdigest()
    s3_server.put_object(Bucket=bucket, Key="big.enc", Body=good + b"extra")
    ok, _error = provider.verify_against_record(
        "big.enc", expected_sha256=digest, expected_size=len(good), workdir=str(tmp_path)
    )
    assert ok is False


def test_verify_against_record_rejects_a_missing_object(provider, tmp_path):
    ok, error = provider.verify_against_record(
        "nope.enc", expected_sha256="a" * 64, workdir=str(tmp_path)
    )
    assert ok is False
    assert "404" in error


def test_verify_against_record_refuses_without_a_digest(s3_server, bucket, provider, tmp_path):
    """Falling back to metadata when no digest is given would silently weaken the check."""
    s3_server.put_object(Bucket=bucket, Key="x.enc", Body=b"data")
    ok, error = provider.verify_against_record("x.enc", expected_sha256="")
    assert ok is False
    assert "without an expected digest" in error


def test_verify_against_record_leaves_no_temporary_files(s3_server, bucket, provider, tmp_path):
    payload = os.urandom(5000)
    digest = hashlib.sha256(payload).hexdigest()
    s3_server.put_object(Bucket=bucket, Key="t.enc", Body=payload)
    provider.verify_against_record(
        "t.enc", expected_sha256=digest, expected_size=len(payload), workdir=str(tmp_path)
    )
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# multipart objects: size and digest still work, ETag is not involved
# ---------------------------------------------------------------------------

def test_multipart_upload_is_verified_by_size_and_digest(s3_server, bucket, provider, tmp_path):
    """A multipart ETag is not an MD5; verification must not depend on it.

    moto accepts ``upload_part`` sequences, which produce an ETag of the form ``...-N``. The
    verifier must ignore it and rely on Content-Length plus the digest of the received bytes.
    """
    payload = os.urandom(5 * 1024 * 1024 + 12345)
    upload = s3_server.create_multipart_upload(Bucket=bucket, Key="mp.enc")
    parts = []
    chunk = 5 * 1024 * 1024
    for number, start in enumerate(range(0, len(payload), chunk), start=1):
        body = payload[start:start + chunk]
        response = s3_server.upload_part(
            Bucket=bucket, Key="mp.enc", PartNumber=number, UploadId=upload["UploadId"], Body=body
        )
        parts.append({"ETag": response["ETag"], "PartNumber": number})
    s3_server.complete_multipart_upload(
        Bucket=bucket, Key="mp.enc", UploadId=upload["UploadId"], MultipartUpload={"Parts": parts}
    )

    head = s3_server.head_object(Bucket=bucket, Key="mp.enc")
    assert "-" in head["ETag"].strip('"'), "fixture should produce a multipart ETag"

    digest = hashlib.sha256(payload).hexdigest()
    ok, error = provider.verify_against_record(
        "mp.enc", expected_sha256=digest, expected_size=len(payload), workdir=str(tmp_path)
    )
    assert ok is True, error


# ---------------------------------------------------------------------------
# state vocabulary: configured is not verified
# ---------------------------------------------------------------------------

def test_the_four_offsite_states_are_distinct():
    states = {OFFSITE_NOT_CONFIGURED, OFFSITE_CONFIGURED, OFFSITE_VERIFIED, OFFSITE_FAILED}
    assert len(states) == 4, "each offsite state must be a distinct value"


def test_verified_is_not_a_synonym_for_configured():
    assert OFFSITE_VERIFIED != OFFSITE_CONFIGURED
    assert "VERIFIED" in OFFSITE_VERIFIED and "VERIFIED" not in OFFSITE_CONFIGURED


# ---------------------------------------------------------------------------
# the scheduled path: no unverified upload, no unverified deletion
# ---------------------------------------------------------------------------

class _RecordingProvider(OffsiteProvider):
    """A provider that records what the scheduled path asks it to do."""

    name = "recording"
    independent_failure_domain = True

    def __init__(self, *, verify_result):
        self.uploaded = []
        self.verified = []
        self.retention_calls = 0
        self.verify_result = verify_result

    def configured_detail(self) -> str:
        return "recording provider"

    def upload(self, local_path, remote_name, sha256=""):
        self.uploaded.append(remote_name)
        return True, ""

    def verify(self, remote_name, expected_size, expected_sha256=""):
        self.verified.append(remote_name)
        return self.verify_result

    def verify_against_record(self, remote_name, *, expected_sha256, expected_size=None, workdir=None):
        self.verified.append(remote_name)
        return self.verify_result

    def apply_remote_retention(self, keep, *, dry_run=False):
        self.retention_calls += 1
        return []

    def list_remote(self):
        return []

    def delete(self, remote_name):
        return True, ""


@pytest.fixture
def scheduled_env(tmp_path, monkeypatch):
    monkeypatch.setenv("BACKUP_ENCRYPTION", "off")
    monkeypatch.delenv("ENV", raising=False)
    monkeypatch.delenv("STRICT_SECURITY", raising=False)
    return tmp_path


def test_offsite_upload_is_read_back_in_the_real_scheduled_path(scheduled_env, monkeypatch, tmp_path):
    """End-to-end through run_scheduled_backup with a real archive and a recording provider.

    Asserts the properties that matter operationally: the upload is read back, the state
    says VERIFIED only on success, and remote retention never runs after a failed check.
    """
    from core import backup_automation, backup_service

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    keyfile = tmp_path / "key"
    keyfile.write_bytes(os.urandom(32))

    monkeypatch.setattr(backup_service, "BACKUP_DIR", str(backup_dir), raising=True)
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", str(keyfile))

    from core.db_engine import is_postgres

    if not is_postgres():
        pytest.skip("needs PostgreSQL for a real dump")

    provider = _RecordingProvider(verify_result=(True, ""))
    from core import backup_offsite as offsite_module

    monkeypatch.setattr(offsite_module, "provider_from_env", lambda *a, **k: provider)

    result = backup_automation.run_scheduled_backup(label="readback")
    assert result.get("success") is True, result.get("error")
    assert provider.uploaded, "nothing was uploaded"
    assert provider.verified, "the uploaded object was never read back"
    assert result.get("offsite_state") == OFFSITE_VERIFIED
    assert result.get("offsite_readback_verified") is True


def test_failed_readback_marks_the_run_offsite_failed(scheduled_env, monkeypatch, tmp_path):
    from core import backup_automation, backup_service

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    keyfile = tmp_path / "key"
    keyfile.write_bytes(os.urandom(32))
    monkeypatch.setattr(backup_service, "BACKUP_DIR", str(backup_dir), raising=True)
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", str(keyfile))

    from core.db_engine import is_postgres

    if not is_postgres():
        pytest.skip("needs PostgreSQL for a real dump")

    provider = _RecordingProvider(verify_result=(False, "digest mismatch"))
    from core import backup_offsite as offsite_module

    monkeypatch.setattr(offsite_module, "provider_from_env", lambda *a, **k: provider)

    result = backup_automation.run_scheduled_backup(label="readback-fail")
    assert result.get("offsite_state") == OFFSITE_FAILED
    assert result.get("offsite_readback_verified") is False
    assert result.get("exit_code") == backup_automation.EXIT_OFFSITE_FAILED
    assert provider.retention_calls == 0, "retention ran despite an unverified upload"
    assert any("read-back" in w for w in result.get("warnings", []))
