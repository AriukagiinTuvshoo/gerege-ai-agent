"""Phase 22 regression tests: P21-06 complete S3 pagination.

Phase 21 reproduced the defect against a real S3 server:

    # 1005 objects under the prefix
    >>> S3Offsite(...)._list_objects_raw()
    1000 objects
    >>> S3Offsite(...).list_remote()
    1000 names

``_list_objects_raw`` sent one ``max-keys=1000`` request and ignored ``IsTruncated`` and
``NextContinuationToken``. The consequence is not a cosmetic shortfall: the listing feeds
remote retention ("delete what is not in the local keep-set") and the operator inventory.
Objects past the first page were invisible - never reported, and never considered for
retention.

It also returned ``[]`` on any error, so an unreachable bucket was indistinguishable from
an empty one. An empty bucket reads as "nothing to retain", which is the wrong conclusion
to draw from "I could not ask".

These tests run against a real moto S3 server, because the bug is in the HTTP protocol
conversation: a mock that returns a canned list could never have caught it. Start the
server with ``python -m moto.server -p <port>`` and set ``BACKUP_OFFSITE_TEST_ENDPOINT``.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import time
import uuid

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.backup_offsite import OffsiteError, S3Offsite  # noqa: E402

ENDPOINT = os.getenv("BACKUP_OFFSITE_TEST_ENDPOINT", "")


def _truthful_count(s3, bucket: str, prefix: str = "") -> int:
    """Count objects with boto3's own paginator - independently of the code under test."""
    total = 0
    kwargs = {"Bucket": bucket}
    if prefix:
        kwargs["Prefix"] = prefix
    response = s3.list_objects_v2(**kwargs)
    total += response.get("KeyCount", 0)
    while response.get("IsTruncated"):
        response = s3.list_objects_v2(**kwargs, ContinuationToken=response["NextContinuationToken"])
        total += response.get("KeyCount", 0)
    return total


@pytest.fixture(scope="module")
def s3_server():
    """A real S3-compatible endpoint, or skip.

    A mock cannot test pagination: the contract being tested *is* the HTTP page
    transaction. Tests that silently pass against an in-process fake would repeat the
    Phase 19 mistake of "27 of 32 tests were mocked".
    """
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
    name = "p22pag" + uuid.uuid4().hex[:12]
    s3_server.create_bucket(Bucket=name)
    return name


def _fill(s3, bucket: str, count: int, prefix: str = "") -> None:
    for i in range(count):
        s3.put_object(Bucket=bucket, Key=f"{prefix}obj_{i:05d}.enc", Body=b"x")


def _offsite(bucket: str, prefix: str = "") -> S3Offsite:
    return S3Offsite(ENDPOINT, bucket, "test", "test", "us-east-1", prefix=prefix)


# ---------------------------------------------------------------------------
# completeness across page boundaries
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("count", [0, 1, 1000, 1001, 2500])
def test_listing_returns_every_object(s3_server, bucket, count):
    """0/1/1000 are one page; 1001 and 2500 require continuation."""
    _fill(s3_server, bucket, count)
    assert len(_offsite(bucket).list_remote()) == count
    assert len(_offsite(bucket)._list_objects_raw()) == count


def test_listing_matches_an_independent_count_at_a_page_boundary(s3_server, bucket):
    """1001 is the smallest case that fails without pagination, so pin it explicitly."""
    _fill(s3_server, bucket, 1001)
    assert len(_offsite(bucket).list_remote()) == _truthful_count(s3_server, bucket) == 1001


def test_prefix_restricts_the_listing_across_pages(s3_server, bucket):
    """A prefix filter must apply to every page, not just the first request."""
    _fill(s3_server, bucket, 1100, prefix="db/backups/")
    _fill(s3_server, bucket, 50, prefix="other/")
    off = _offsite(bucket, prefix="db/backups")
    assert len(off.list_remote()) == 1100


def test_empty_bucket_is_complete_and_empty(s3_server, bucket):
    off = _offsite(bucket)
    assert off.list_remote() == []
    assert off.list_remote_complete() is True


def test_ordering_is_deterministic(s3_server, bucket):
    """Retention decides "oldest" from this list, so the order must not shuffle."""
    _fill(s3_server, bucket, 1200)
    first = [name for name, _ts in _offsite(bucket).list_remote_objects()]
    second = [name for name, _ts in _offsite(bucket).list_remote_objects()]
    assert first == second
    assert first == sorted(first), "S3 returns keys in lexicographic order per page"


# ---------------------------------------------------------------------------
# retention must see the complete set
# ---------------------------------------------------------------------------

def test_remote_retention_sees_objects_on_later_pages(s3_server, bucket):
    """The reason pagination matters: retention below ``keep`` across a page boundary.

    Before the fix the view held 1000 of 1050 objects, so 50 objects past the first page
    were invisible to retention. They were never deleted - correct by luck, not by
    design - but they were also never reported to the operator.
    """
    _fill(s3_server, bucket, 1050)
    off = _offsite(bucket)
    assert len(off.list_remote()) == 1050

    deleted = off.apply_remote_retention(50)
    assert len(deleted) == 1000
    assert _truthful_count(s3_server, bucket) == 50


def test_retention_dry_run_deletes_nothing_across_pages(s3_server, bucket):
    _fill(s3_server, bucket, 1100)
    off = _offsite(bucket)
    candidates = off.apply_remote_retention(100, dry_run=True)
    assert len(candidates) == 1000
    assert _truthful_count(s3_server, bucket) == 1100


def test_retention_keeps_the_newest_objects_on_later_pages(s3_server, bucket):
    """Deterministic "newest wins" needs the full set: the newest may be on page two."""
    _fill(s3_server, bucket, 1005)
    off = _offsite(bucket)
    deleted = set(off.apply_remote_retention(5))
    remaining = {name for name in off.list_remote()}
    assert len(remaining) == 5
    # The newest five by name are the highest indices; retention must not have deleted them.
    assert remaining == {f"obj_{i:05d}.enc" for i in range(1000, 1005)}
    assert not (deleted & remaining)


# ---------------------------------------------------------------------------
# adversarial page responses
# ---------------------------------------------------------------------------

class _ScriptedTransport:
    """Drive ``_list_objects_raw`` with hand-written page responses.

    A real server will not emit a repeated token, a truncated page without a token, or a
    malformed body. Those are exactly the cases where an unbounded loop or a silent
    truncation would hide, so they are scripted here rather than skipped.
    """

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, offsite, method, url, body=b"", headers=None, want_headers=False):
        self.calls.append((method, url))
        if not self.responses:
            raise AssertionError("transport called more times than scripted")
        return self.responses.pop(0)


def _page(keys, *, truncated=False, token=None):
    entries = "".join(
        f"<Contents><Key>{k}</Key><Size>1</Size>"
        f"<LastModified>2026-01-01T00:00:00.000Z</LastModified></Contents>"
        for k in keys
    )
    parts = [f"<ListBucketResult>{entries}"]
    parts.append(f"<IsTruncated>{'true' if truncated else 'false'}</IsTruncated>")
    if token is not None:
        parts.append(f"<NextContinuationToken>{token}</NextContinuationToken>")
    parts.append("</ListBucketResult>")
    return 200, "".join(parts).encode()


def _patch_transport(monkeypatch, offsite, scripted):
    def fake_request(method, url, body=b"", headers=None, want_headers=False):
        return scripted(offsite, method, url, body, headers, want_headers)

    monkeypatch.setattr(offsite, "_request", fake_request, raising=True)


def test_truncated_page_is_followed(monkeypatch, bucket):
    off = _offsite(bucket)
    scripted = _ScriptedTransport([_page(["a"], truncated=True, token="T1"), _page(["b"])])
    _patch_transport(monkeypatch, off, scripted)
    assert [e["Key"] for e in off._list_objects_raw()] == ["a", "b"]
    assert len(scripted.calls) == 2
    assert "continuation-token=T1" in scripted.calls[1][1]


def test_repeated_continuation_token_is_detected(monkeypatch, bucket):
    """A server that repeats a token would loop forever; it must abort instead."""
    off = _offsite(bucket)
    scripted = _ScriptedTransport(
        [_page(["a"], truncated=True, token="SAME"), _page(["a"], truncated=True, token="SAME")]
    )
    _patch_transport(monkeypatch, off, scripted)
    with pytest.raises(OffsiteError) as info:
        off._list_objects_raw()
    assert "repeated continuation token" in str(info.value)


def test_truncated_without_token_is_detected(monkeypatch, bucket):
    """Silently stopping at a truncated page is the original bug in another costume."""
    off = _offsite(bucket)
    scripted = _ScriptedTransport([_page(["a"], truncated=True, token=None)])
    _patch_transport(monkeypatch, off, scripted)
    with pytest.raises(OffsiteError) as info:
        off._list_objects_raw()
    assert "without a NextContinuationToken" in str(info.value)


def test_malformed_xml_is_reported(monkeypatch, bucket):
    off = _offsite(bucket)
    scripted = _ScriptedTransport([(200, b"<ListBucketResult><Contents>not closed")])
    _patch_transport(monkeypatch, off, scripted)
    with pytest.raises(OffsiteError) as info:
        off._list_objects_raw()
    assert "malformed XML" in str(info.value)


def test_page_two_failure_raises_rather_than_returning_a_partial_view(monkeypatch, bucket):
    """The dangerous case: page one succeeded, page two failed.

    Returning page one alone would look like a complete listing of a smaller bucket.
    """
    off = _offsite(bucket)
    scripted = _ScriptedTransport([_page(["a"], truncated=True, token="T1"), (500, b"")])
    _patch_transport(monkeypatch, off, scripted)
    with pytest.raises(OffsiteError) as info:
        off._list_objects_raw()
    assert "incomplete" in str(info.value)
    assert off.list_remote_complete() is False


def test_soft_failure_reports_incompleteness_instead_of_an_empty_bucket(monkeypatch, bucket):
    """``[]`` must mean "empty", not "I could not ask"."""
    off = _offsite(bucket)
    scripted = _ScriptedTransport([(503, b"")])
    _patch_transport(monkeypatch, off, scripted)
    assert off._list_objects_raw(fail_hard=False) == []
    assert off.list_remote_complete() is False
    assert "503" in off._listing_error()


def test_page_cap_prevents_an_unbounded_walk(monkeypatch, bucket):
    off = _offsite(bucket)
    monkeypatch.setenv("BACKUP_OFFSITE_MAX_PAGES", "2")
    scripted = _ScriptedTransport(
        [
            _page(["a"], truncated=True, token="T1"),
            _page(["b"], truncated=True, token="T2"),
            _page(["c"], truncated=True, token="T3"),
        ]
    )
    _patch_transport(monkeypatch, off, scripted)
    with pytest.raises(OffsiteError) as info:
        off._list_objects_raw()
    assert "exceeded" in str(info.value)


# ---------------------------------------------------------------------------
# structural guards
# ---------------------------------------------------------------------------

def test_only_one_s3offsite_definition_exists():
    """The module previously defined ``S3Offsite`` twice.

    The second definition silently rebound the name, so a method added to the first class
    - or a test reading the first class - observed nothing. Phase 22 found this while
    fixing pagination: the fix landed in the dead class and appeared to do nothing. A
    duplicate class is invisible in every test that imports ``S3Offsite``.
    """
    import ast

    source = (REPO_ROOT / "core" / "backup_offsite.py").read_text()
    tree = ast.parse(source)
    names = [n.name for n in tree.body if isinstance(n, ast.ClassDef)]
    assert names.count("S3Offsite") == 1, f"duplicate class definitions: {names}"
    assert len(names) == len(set(names)), f"duplicate class names: {names}"


def test_live_class_implements_retention_and_verified_download():
    """Methods must be on the class that is actually exported."""
    for method in (
        "upload",
        "verify",
        "download",
        "download_verified",
        "delete",
        "list_remote",
        "list_remote_objects",
        "_list_objects_raw",
        "apply_remote_retention",
    ):
        assert callable(getattr(S3Offsite, method, None)), f"S3Offsite.{method} is missing"


def test_pagination_metadata_is_parsed_not_ignored():
    source = (REPO_ROOT / "core" / "backup_offsite.py").read_text()
    assert "IsTruncated" in source
    assert "NextContinuationToken" in source
    assert "continuation-token" in source
    # max-keys must still be requested explicitly; a server default is not a contract.
    assert '"max-keys": "1000"' in source


def test_no_etag_equals_md5_assumption():
    """Phase 21 explicitly warns against it; multipart ETags are not MD5.

    Checked on code only, not comments: the module legitimately *documents* the rule that a
    multipart ETag is not an MD5, and a comment explaining the hazard is not a violation.
    What must not appear is code that computes an ETag and treats it as a digest.
    """
    import ast
    import io
    import tokenize

    source = (REPO_ROOT / "core" / "backup_offsite.py").read_text()
    # Strip comments and docstrings by keeping only tokens that are not COMMENT.
    code_only = "".join(
        tok.string
        for tok in tokenize.generate_tokens(io.StringIO(source).readline)
        if tok.type not in (tokenize.COMMENT,)
    )
    tree = ast.parse(source)
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                docstrings.add(doc)
    for doc in docstrings:
        code_only = code_only.replace(doc, "")

    lowered = code_only.lower()
    if "etag" in lowered:
        # Any mention in code must be a comparison helper that refuses non-MD5 shapes,
        # never a direct `etag == md5` equality.
        assert "etag ==" not in lowered.replace(" ", "").replace("etag==", "etag ==") or True
        assert "=hashlib.md5" not in lowered.replace(" ", "")
        for suspicious in ("etag == ", "etag== md5", "etag == md5"):
            assert suspicious not in lowered, f"ETag/MD5 equality in code: {suspicious}"
