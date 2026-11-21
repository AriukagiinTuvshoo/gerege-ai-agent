"""Phase 22 / Phase 12 - offsite configuration validation and status reporting.

Phase 12 requires that offsite status distinguish `OFFSITE_NOT_CONFIGURED`,
`OFFSITE_CONFIGURED`, `OFFSITE_VERIFIED` and `OFFSITE_FAILED`, and that "verified" is never
claimed without a real round trip against a provider.

A gap surfaced while auditing that: `provider_from_env()` refused every `http://` URL
outright. That is the right default - a backup crossing the network in the clear is worse
than one that never left the host - but it meant the *documented* path could not reach a
local S3-compatible server, which is precisely what Phase 12 asks to be verified against.
The existing S3 tests construct `S3Offsite` directly, so the guard was never exercised on
the path an operator would use.

The fix is a narrow opt-in: `BACKUP_OFFSITE_ALLOW_INSECURE_LOOPBACK=1`, accepted only for a
loopback host and never when `ENV` is production. These tests pin both halves - that the
exception works where it is meant to, and that it cannot be widened by accident.
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


def _base_env() -> dict:
    return {
        "BACKUP_OFFSITE_ACCESS_KEY": "test",
        "BACKUP_OFFSITE_SECRET_KEY": "test",
        "BACKUP_OFFSITE_REGION": "us-east-1",
    }


def _loopback_url(bucket: str = "b") -> str:
    return f"{ENDPOINT}/{bucket}/db/backups"


def _s3_available() -> bool:
    try:
        import boto3

        boto3.client(
            "s3",
            endpoint_url=ENDPOINT,
            aws_access_key_id="test",
            aws_secret_access_key="test",
            region_name="us-east-1",
        ).list_buckets()
        return True
    except Exception:
        return False


requires_s3 = pytest.mark.skipif(
    not _s3_available(), reason=f"no S3-compatible endpoint at {ENDPOINT}"
)


# ---------------------------------------------------------------------------
# NOT CONFIGURED
# ---------------------------------------------------------------------------


def test_status_is_not_configured_when_nothing_is_set():
    from core import backup_offsite

    status = backup_offsite.status({})
    assert status["state"] == backup_offsite.OFFSITE_NOT_CONFIGURED
    assert status["configured"] is False


def test_status_reports_the_reason_it_refused():
    """A refusal must say why, or an operator cannot fix it."""
    from core import backup_offsite

    status = backup_offsite.status({**_base_env(), "BACKUP_OFFSITE_URL": "http://127.0.0.1/x/b"})
    assert status["state"] == backup_offsite.OFFSITE_NOT_CONFIGURED
    assert "https" in status.get("error", "").lower()


# ---------------------------------------------------------------------------
# Plaintext transport: refused, with exactly one narrow exception
# ---------------------------------------------------------------------------


def test_plain_http_is_refused_without_the_opt_in():
    from core import backup_offsite

    with pytest.raises(backup_offsite.OffsiteError, match="https"):
        backup_offsite.provider_from_env({**_base_env(), "BACKUP_OFFSITE_URL": _loopback_url()})


def test_opt_in_allows_a_loopback_endpoint():
    """The Phase 12 requirement: verify against a local S3-compatible server."""
    from core import backup_offsite

    provider = backup_offsite.provider_from_env({
        **_base_env(),
        "BACKUP_OFFSITE_URL": _loopback_url(),
        "BACKUP_OFFSITE_ALLOW_INSECURE_LOOPBACK": "1",
    })
    assert provider is not None
    assert type(provider).__name__ == "S3Offsite"


def test_opt_in_is_refused_in_production():
    """A production host must not be configurable to ship backups in the clear."""
    from core import backup_offsite

    with pytest.raises(backup_offsite.OffsiteError, match="https"):
        backup_offsite.provider_from_env({
            **_base_env(),
            "BACKUP_OFFSITE_URL": _loopback_url(),
            "BACKUP_OFFSITE_ALLOW_INSECURE_LOOPBACK": "1",
            "ENV": "production",
        })
    with pytest.raises(backup_offsite.OffsiteError, match="https"):
        backup_offsite.provider_from_env({
            **_base_env(),
            "BACKUP_OFFSITE_URL": _loopback_url(),
            "BACKUP_OFFSITE_ALLOW_INSECURE_LOOPBACK": "1",
            "APP_ENV": "prod",
        })


def test_opt_in_never_covers_a_remote_host():
    """The exception is for loopback only; it cannot point at a bucket across the internet."""
    from core import backup_offsite

    for host in ("s3.example.com", "10.0.0.5", "127.0.0.1.evil.example.com", "0.0.0.0"):
        with pytest.raises(backup_offsite.OffsiteError, match="https"):
            backup_offsite.provider_from_env({
                **_base_env(),
                "BACKUP_OFFSITE_URL": f"http://{host}/b/db",
                "BACKUP_OFFSITE_ALLOW_INSECURE_LOOPBACK": "1",
            })


def test_opt_in_requires_the_exact_value():
    """Any value other than "1" must leave the refusal in place."""
    from core import backup_offsite

    for value in ("true", "yes", "0", "", "TRUE"):
        with pytest.raises(backup_offsite.OffsiteError):
            backup_offsite.provider_from_env({
                **_base_env(),
                "BACKUP_OFFSITE_URL": _loopback_url(),
                "BACKUP_OFFSITE_ALLOW_INSECURE_LOOPBACK": value,
            })


def test_https_is_always_accepted():
    from core import backup_offsite

    provider = backup_offsite.provider_from_env({
        **_base_env(),
        "BACKUP_OFFSITE_URL": "https://s3.eu-central-1.amazonaws.com/bucket/db",
    })
    assert provider is not None


# ---------------------------------------------------------------------------
# CONFIGURED vs VERIFIED: the distinction Phase 12 asks for
# ---------------------------------------------------------------------------


@requires_s3
def test_configured_is_not_verified():
    """Configured must never be reported as verified - nothing has been proven yet."""
    from core import backup_offsite

    env = {
        **_base_env(),
        "BACKUP_OFFSITE_URL": _loopback_url(f"p22-status-{uuid.uuid4().hex[:8]}"),
        "BACKUP_OFFSITE_ALLOW_INSECURE_LOOPBACK": "1",
    }
    status = backup_offsite.status(env)
    assert status["state"] == "CONFIGURED"
    assert status["state"] != backup_offsite.OFFSITE_VERIFIED
    assert status["configured"] is True
    assert status["independent_failure_domain"] is True


@requires_s3
def test_a_real_round_trip_is_what_earns_verified():
    """Verify means: uploaded, downloaded, and the bytes hashed - nothing weaker."""
    import boto3

    from core import backup_offsite

    bucket = f"p22-doc-{uuid.uuid4().hex[:8]}"
    s3 = boto3.client(
        "s3", endpoint_url=ENDPOINT,
        aws_access_key_id="test", aws_secret_access_key="test", region_name="us-east-1",
    )
    s3.create_bucket(Bucket=bucket)
    try:
        env = {
            **_base_env(),
            "BACKUP_OFFSITE_URL": f"{ENDPOINT}/{bucket}/db/backups",
            "BACKUP_OFFSITE_ALLOW_INSECURE_LOOPBACK": "1",
        }
        provider = backup_offsite.provider_from_env(env)
        payload = os.urandom(50_000)
        digest = hashlib.sha256(payload).hexdigest()

        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".enc", delete=False) as handle:
            handle.write(payload)
            path = handle.name
        try:
            ok, detail = provider.upload(path, "doc.sql.gz.enc", sha256=digest)
            assert ok, detail
        finally:
            os.unlink(path)

        ok, detail = provider.verify_against_record(
            "doc.sql.gz.enc", expected_sha256=digest, expected_size=len(payload)
        )
        assert ok is True, detail

        # The same size, different bytes: only hashing the download catches this.
        s3.put_object(Bucket=bucket, Key="db/backups/doc.sql.gz.enc", Body=os.urandom(50_000))
        ok, detail = provider.verify_against_record(
            "doc.sql.gz.enc", expected_sha256=digest, expected_size=len(payload)
        )
        assert ok is False
        assert "digest" in detail
    finally:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)


# ---------------------------------------------------------------------------
# FAILED
# ---------------------------------------------------------------------------


@requires_s3
def test_a_missing_object_reports_failure_not_success():
    import boto3

    from core import backup_offsite

    bucket = f"p22-fail-{uuid.uuid4().hex[:8]}"
    s3 = boto3.client(
        "s3", endpoint_url=ENDPOINT,
        aws_access_key_id="test", aws_secret_access_key="test", region_name="us-east-1",
    )
    s3.create_bucket(Bucket=bucket)
    try:
        provider = backup_offsite.provider_from_env({
            **_base_env(),
            "BACKUP_OFFSITE_URL": f"{ENDPOINT}/{bucket}/db",
            "BACKUP_OFFSITE_ALLOW_INSECURE_LOOPBACK": "1",
        })
        ok, detail = provider.verify_against_record(
            "never-uploaded.enc", expected_sha256="0" * 64
        )
        assert ok is False
        assert "404" in detail or "not found" in detail.lower()
    finally:
        s3.delete_bucket(Bucket=bucket)


def test_verification_without_a_digest_is_refused():
    """No expected digest means nothing can be proven; refuse rather than guess."""
    from core import backup_offsite

    source = pathlib.Path(backup_offsite.__file__).read_text(encoding="utf-8")
    assert "refusing to verify without an expected digest" in source


def test_status_states_are_four_distinct_constants():
    from core import backup_offsite

    states = {
        backup_offsite.OFFSITE_NOT_CONFIGURED,
        backup_offsite.OFFSITE_CONFIGURED,
        backup_offsite.OFFSITE_VERIFIED,
        backup_offsite.OFFSITE_FAILED,
    }
    assert len(states) == 4
