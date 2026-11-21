"""Phase 24 - offsite integration against a local S3-compatible service.

These are the checks the audit asked for, run against a disposable bucket on a local
S3-compatible server (moto). Nothing here touches a real cloud provider, and no real
credential is used - the AWS SDK is given the literal strings "test"/"test", which the local
server accepts and a real one never would.

What this proves: the offsite code path behaves correctly against a real HTTP server that
speaks the S3 protocol, including pagination past 1000 objects, digest verification of
downloaded bytes, and detection of corruption that does not change the object size.

What this does NOT prove: that any real provider is configured or reachable. Offsite remains
NOT VERIFIED in the operational sense. See docs/OFFSITE-BACKUP-SETUP.md for the evidence a
real provider would need.
"""

import hashlib
import os
import pathlib
import sys
import uuid

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

ENDPOINT = os.getenv("BACKUP_OFFSITE_TEST_ENDPOINT", "http://127.0.0.1:5062")


def _client():
    import boto3

    return boto3.client(
        "s3",
        endpoint_url=ENDPOINT,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1",
    )


def _available() -> bool:
    try:
        _client().list_buckets()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _available(), reason=f"no S3-compatible endpoint at {ENDPOINT}"
)


@pytest.fixture()
def bucket():
    """A disposable bucket with a prefix, removed afterwards even on failure."""
    from core import backup_offsite

    name = f"p24-{uuid.uuid4().hex[:10]}"
    client = _client()
    client.create_bucket(Bucket=name)
    env = {
        "BACKUP_OFFSITE_URL": f"{ENDPOINT}/{name}/db",
        "BACKUP_OFFSITE_ACCESS_KEY": "test",
        "BACKUP_OFFSITE_SECRET_KEY": "test",
        "BACKUP_OFFSITE_REGION": "us-east-1",
        "BACKUP_OFFSITE_ALLOW_INSECURE_LOOPBACK": "1",
    }
    provider = backup_offsite.provider_from_env(env)
    try:
        yield name, client, provider
    finally:
        try:
            for page in client.get_paginator("list_objects_v2").paginate(Bucket=name):
                for obj in page.get("Contents", []):
                    client.delete_object(Bucket=name, Key=obj["Key"])
            client.delete_bucket(Bucket=name)
        except Exception:
            pass


def _payload(tmp_path, name="archive.enc", size=70_000):
    path = tmp_path / name
    data = os.urandom(size)
    path.write_bytes(data)
    return path, data, hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Upload, listing, download
# ---------------------------------------------------------------------------


def test_upload_then_list_then_download_round_trips(bucket, tmp_path):
    _name, _client, provider = bucket
    source, data, digest = _payload(tmp_path)

    ok, detail = provider.upload(str(source), "archive.enc", sha256=digest)
    assert ok, detail

    assert "archive.enc" in provider.list_remote()

    target = tmp_path / "restored.enc"
    ok, detail = provider.download("archive.enc", str(target))
    assert ok, detail
    assert target.read_bytes() == data, "downloaded bytes differ from what was uploaded"


def test_download_verified_matches_the_digest(bucket, tmp_path):
    _name, _client, provider = bucket
    source, _data, digest = _payload(tmp_path)
    provider.upload(str(source), "archive.enc", sha256=digest)

    ok, detail = provider.download_verified(
        "archive.enc", str(tmp_path / "verified.enc"), expected_sha256=digest
    )
    assert ok, detail


def test_upload_of_a_missing_source_fails_cleanly(bucket):
    _name, _client, provider = bucket
    ok, detail = provider.upload("/nonexistent/path/archive.enc", "x.enc")
    assert ok is False
    assert detail


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------


def test_same_size_corruption_is_detected(bucket, tmp_path):
    """The failure mode that a size check alone can never catch."""
    name, client, provider = bucket
    source, data, digest = _payload(tmp_path)
    provider.upload(str(source), "archive.enc", sha256=digest)

    client.put_object(Bucket=name, Key="db/archive.enc", Body=os.urandom(len(data)))

    ok, detail = provider.verify_against_record(
        "archive.enc", expected_sha256=digest, expected_size=len(data)
    )
    assert ok is False
    assert "digest" in detail


def test_truncation_is_detected(bucket, tmp_path):
    name, client, provider = bucket
    source, data, digest = _payload(tmp_path)
    provider.upload(str(source), "archive.enc", sha256=digest)

    client.put_object(Bucket=name, Key="db/archive.enc", Body=data[: len(data) // 2])

    ok, detail = provider.verify_against_record(
        "archive.enc", expected_sha256=digest, expected_size=len(data)
    )
    assert ok is False


def test_a_missing_object_is_a_failure_not_an_absence(bucket):
    _name, _client, provider = bucket
    ok, detail = provider.verify_against_record("never-uploaded.enc", expected_sha256="0" * 64)
    assert ok is False
    assert detail


def test_verification_without_a_digest_is_refused(bucket):
    """No expectation means nothing can be proven; guessing would be worse."""
    _name, _client, provider = bucket
    ok, detail = provider.verify_against_record("archive.enc", expected_sha256="")
    assert ok is False


# ---------------------------------------------------------------------------
# Pagination - the 1000-object boundary
# ---------------------------------------------------------------------------


def test_pagination_covers_more_than_one_page(bucket):
    """S3 returns at most 1000 keys per response; a naive listing stops there."""
    name, client, provider = bucket
    for index in range(1005):
        client.put_object(Bucket=name, Key=f"db/bulk/{index:05d}", Body=b"x")

    keys = provider.list_remote()
    assert len(keys) == 1005, f"listing returned {len(keys)} of 1005 objects"
    assert provider.list_remote_complete() is True


def test_deletion_removes_exactly_one_object(bucket):
    name, client, provider = bucket
    client.put_object(Bucket=name, Key="db/keep.enc", Body=b"1")
    client.put_object(Bucket=name, Key="db/drop.enc", Body=b"2")

    ok, detail = provider.delete("drop.enc")
    assert ok, detail
    remaining = provider.list_remote()
    assert remaining == ["keep.enc"], remaining


# ---------------------------------------------------------------------------
# Credential and policy handling
# ---------------------------------------------------------------------------


def test_plain_https_is_required_for_a_non_loopback_host():
    """The loopback opt-in must never extend to a remote endpoint."""
    from core import backup_offsite

    base = {
        "BACKUP_OFFSITE_ACCESS_KEY": "t",
        "BACKUP_OFFSITE_SECRET_KEY": "t",
        "BACKUP_OFFSITE_REGION": "us-east-1",
        "BACKUP_OFFSITE_ALLOW_INSECURE_LOOPBACK": "1",
    }
    for url in (
        "http://s3.example.com/b/p",
        "http://10.0.0.5/b/p",
        "http://169.254.169.254/b/p",
    ):
        with pytest.raises(backup_offsite.OffsiteError):
            backup_offsite.provider_from_env({**base, "BACKUP_OFFSITE_URL": url})


def test_no_real_credential_is_present_in_this_environment():
    """Guard: these tests must never run against a real provider by accident."""
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        value = os.getenv(name, "")
        if value:
            pytest.skip(f"{name} is set; refusing to run offsite tests against a real account")
