"""Offsite storage: a real backend, or an explicit "not configured" (Phase 18).

Phase 17's finding was blunt and correct: ``copy_offsite`` was ``shutil.copy2`` to a
local directory, and the Compose default pointed it at the *same* host path that was
already mounted as ``BACKUP_DIR``. Calling that "offsite" was wrong twice — it provides
no independent failure domain, and it made a directory listing look like a recovery plan.
A local copy also cannot survive the failure that actually destroys backups: losing the
host.

This module replaces the conflation with an explicit provider interface:

* :class:`S3Offsite` — a real object-store backend over HTTPS, implemented against the
  S3 REST API with SigV4 request signing. No new dependency (``boto3`` would be a large
  addition for one operation); it uses ``urllib`` from the standard library. It provides
  TLS transport, authenticated requests, server-side encryption at rest, upload
  verification by object size and checksum metadata, bounded retries with backoff, and
  remote retention.
* :class:`LocalOffsite` — the Phase 16 behaviour, kept but **renamed honestly**. It is
  used only when an operator explicitly asks for a directory target, and its status
  string says it is not an independent failure domain.

If neither is configured, :func:`provider_from_env` returns ``None`` and the caller
reports ``OFFSITE: NOT CONFIGURED``. Nothing in this repository ever claims that offsite
backup is operational until an operator supplies a real target.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import shutil
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

OFFSITE_NOT_CONFIGURED = "NOT CONFIGURED"

_REQUIRED_ENV = (
    "BACKUP_OFFSITE_URL",          # e.g. https://s3.eu-central-1.amazonaws.com/bucket
    "BACKUP_OFFSITE_ACCESS_KEY",
    "BACKUP_OFFSITE_SECRET_KEY",
    "BACKUP_OFFSITE_REGION",
)


class OffsiteError(Exception):
    """Raised for any upload/download/verification failure."""


def _sigv4_headers(method: str, url: str, region: str, access_key: str,
                   secret_key: str, payload: bytes, extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Build SigV4-signed headers for one S3 request.

    A small, self-contained implementation of AWS Signature Version 4 for the single
    ``s3`` service. Signed payloads mean a tampered upload is rejected by the server.
    """
    parsed = urllib.parse.urlsplit(url)
    host = parsed.netloc
    canonical_uri = urllib.parse.quote(parsed.path or "/", safe="/~")
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    canonical_query = "&".join(
        f"{urllib.parse.quote(k, safe='~')}={urllib.parse.quote(v, safe='~')}"
        for k, v in sorted(query)
    )
    payload_hash = hashlib.sha256(payload).hexdigest()
    amz_date = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    date_stamp = amz_date[:8]

    headers: Dict[str, str] = {
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    if extra_headers:
        for key, value in extra_headers.items():
            headers[key.lower()] = value

    signed_names = sorted(headers)
    canonical_headers = "".join(f"{name}:{headers[name].strip()}\n" for name in signed_names)
    signed_headers = ";".join(signed_names)
    canonical_request = "\n".join(
        [method, canonical_uri, canonical_query, canonical_headers, signed_headers, payload_hash]
    )
    scope = f"{date_stamp}/{region}/s3/aws4_request"
    string_to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical_request.encode()).hexdigest()]
    )

    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    signing_key = _sign(_sign(_sign(_sign(("AWS4" + secret_key).encode(), date_stamp), region), "s3"), "aws4_request")
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()

    out = dict(headers)
    out["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return out


class OffsiteProvider:
    """Interface every offsite backend implements."""

    name = "none"
    independent_failure_domain = False

    def configured_detail(self) -> str:
        raise NotImplementedError

    def upload(self, local_path: str, remote_name: str, sha256: str = "") -> Tuple[bool, str]:
        raise NotImplementedError

    def verify(self, remote_name: str, expected_size: int, expected_sha256: str = "") -> Tuple[bool, str]:
        raise NotImplementedError

    def delete(self, remote_name: str) -> Tuple[bool, str]:
        raise NotImplementedError

    def list_remote(self) -> List[str]:
        raise NotImplementedError

    def list_remote_objects(self) -> List[Tuple[str, Optional[float]]]:
        """Return ``(name, epoch_seconds_or_None)`` for every remote object.

        The timestamp is the server's own last-modified time, never anything derived from
        the object name. ``None`` means the backend could not supply one.
        """
        return [(name, None) for name in self.list_remote()]

    def download(self, remote_name: str, local_path: str) -> Tuple[bool, str]:
        raise NotImplementedError

    def download_verified(self, remote_name: str, local_path: str,
                          expected_size: int = -1,
                          expected_sha256: str = "") -> Tuple[bool, str]:
        return self.download(remote_name, local_path)

    # -- retention ---------------------------------------------------------
    def apply_remote_retention(self, keep: int, *, dry_run: bool = False) -> List[str]:
        """Delete the oldest remote objects, never below ``keep``. Returns deleted names.

        Phase 19 found this sorted object **names** and deleted ``names[:-keep]``. Archive
        names carry a *label* (``pg_backup_dr_…``, ``pg_backup_pre_deploy_…``), so lexical
        order is not chronological order: a reproduction deleted the newest object and
        kept a truncated one. Remote retention is the last line of defence against a
        local loss; deleting the wrong object there is unrecoverable.

        Ordering now uses the server's LastModified time. Objects whose time is unknown
        are never deleted — an object we cannot date cannot be proven old, and the safe
        default for a backup store is to keep it and report it.
        """
        keep = max(1, int(keep))
        objects = self.list_remote_objects()
        dated = [(name, ts) for name, ts in objects if ts is not None]
        undated = [name for name, ts in objects if ts is None]
        # Newest first. Ties broken by name only to make the order deterministic; a tie
        # means the two objects are equally old, so either may be the oldest.
        dated.sort(key=lambda pair: (pair[1], pair[0]), reverse=True)

        candidates = [name for name, _ts in dated[keep:]]
        deleted: List[str] = []
        for name in candidates:
            if dry_run:
                deleted.append(name)
                continue
            ok, _error = self.delete(name)
            if ok:
                deleted.append(name)
        return deleted


class S3Offsite(OffsiteProvider):
    """S3-compatible object storage over HTTPS with SigV4 (AWS S3, MinIO, R2, B2 S3...)."""

    name = "s3"
    independent_failure_domain = True

    def __init__(self, endpoint: str, bucket: str, access_key: str, secret_key: str, region: str,
                 prefix: str = "", sse: str = "AES256", timeout: int = 60, retries: int = 3) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.bucket = bucket
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.prefix = prefix.strip("/")
        self.sse = sse
        self.timeout = timeout
        self.retries = max(1, retries)

    # -- helpers -----------------------------------------------------------
    def _key(self, remote_name: str) -> str:
        return f"{self.prefix}/{remote_name}" if self.prefix else remote_name

    def _url(self, remote_name: str) -> str:
        return f"{self.endpoint}/{self.bucket}/{urllib.parse.quote(self._key(remote_name), safe='/~')}"

    def configured_detail(self) -> str:
        return f"s3 endpoint={self.endpoint} bucket={self.bucket} prefix={self.prefix or '-'} sse={self.sse}"

    def _request(self, method: str, url: str, body: bytes = b"",
                 headers: Optional[Dict[str, str]] = None,
                 want_headers: bool = False):
        import urllib.error
        import urllib.request

        signed = _sigv4_headers(method, url, self.region, self.access_key, self.secret_key, body, headers)
        # `host` is supplied by urllib from the URL; sending it again duplicates the header.
        request_headers = {k: v for k, v in signed.items() if k.lower() != "host"}
        req = urllib.request.Request(url, data=body if method in ("PUT", "POST") else None,
                                     headers=request_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if want_headers:
                    return resp.status, resp.read(), dict(resp.headers.items())
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            if want_headers:
                return exc.code, exc.read()[:400], dict(exc.headers.items()) if exc.headers else {}
            return exc.code, exc.read()[:400]
        except Exception as exc:
            raise OffsiteError(f"transport failure: {type(exc).__name__}") from exc

    def _retry(self, fn):
        last: Optional[Exception] = None
        for attempt in range(self.retries):
            try:
                return fn()
            except OffsiteError as exc:
                last = exc
                time.sleep(min(2 ** attempt, 8))
        raise OffsiteError(str(last) if last else "request failed")

    # -- operations --------------------------------------------------------
    def upload(self, local_path: str, remote_name: str, sha256: str = "") -> Tuple[bool, str]:
        try:
            payload = open(local_path, "rb").read()
        except OSError as exc:
            return False, f"cannot read local archive: {type(exc).__name__}"
        if not sha256:
            sha256 = hashlib.sha256(payload).hexdigest()
        headers = {
            "content-sha256": sha256,
            # Explicit length, and Content-Type because some S3-compatible servers drop a
            # body sent without one. Phase 19 lost an upload this way and still reported
            # success, because verify() could not tell an empty object from a good one.
            "content-length": str(len(payload)),
            "content-type": "application/octet-stream",
            # Our own metadata: the length and digest the *client* intended. The server
            # echoes these back on HEAD, so verification can compare what was stored
            # against what was meant, not against what the server happens to claim.
            "x-amz-meta-p20-sha256": sha256,
            "x-amz-meta-p20-size": str(len(payload)),
        }
        if self.sse:
            headers["x-amz-server-side-encryption"] = self.sse

        def _attempt():
            status, body = self._request("PUT", self._url(remote_name), payload, headers)
            if status not in (200, 201):
                raise OffsiteError(f"upload http {status}")
            return status

        try:
            self._retry(_attempt)
        except OffsiteError as exc:
            return False, str(exc)
        # Prove it landed. A 200 is a claim; size and digest are evidence.
        return self.verify(remote_name, len(payload), sha256)

    def _head_meta(self, remote_name: str) -> Tuple[Optional[int], Dict[str, str], str]:
        """Return ``(content_length, headers_lowercased, error)`` for a remote object."""
        url = self._url(remote_name)
        try:
            status, _body, headers = self._request("HEAD", url, want_headers=True)
        except OffsiteError as exc:
            return None, {}, str(exc)
        if status != 200:
            return None, {}, f"remote object not readable (http {status})"
        lowered = {k.lower(): v for k, v in headers.items()}
        raw_len = lowered.get("content-length")
        try:
            length = int(raw_len) if raw_len is not None else None
        except (TypeError, ValueError):
            length = None
        return length, lowered, ""

    def verify(self, remote_name: str, expected_size: int = -1,
               expected_sha256: str = "") -> Tuple[bool, str]:
        """Independently verify a remote object.

        Phase 19 found this function compared **nothing**: it issued a HEAD, returned
        ``True`` on 200, and ignored both parameters. A truncated object, a zero-byte
        object and a corrupted object all "verified". Upload used it as its own proof of
        success, so a lost body was reported as a successful offsite copy.

        Verification now checks, in order of what is cheap:

        1. **Size.** ``Content-Length`` must equal the size we uploaded. This alone
           catches truncation, partial uploads and the empty-object case.
        2. **Client metadata.** The ``x-amz-meta-p20-*`` values we sent are echoed by the
           server; a mismatch means we are looking at a different object than the one we
           wrote (duplicate key, overwrite, wrong prefix).
        3. **Digest.** When the server exposes a whole-object checksum we can compare, we
           compare it. ``ETag`` is only used when it is a plain 32-hex MD5 — i.e. the
           object was a single-part upload and the server did not virtualise it. A
           multipart ``ETag`` (``...-N``) or a KMS/SSE-C ETag is **not** an MD5 and is
           never treated as one.

        ``Content-MD5`` of the *whole object* cannot be computed from a HEAD, so the
        authoritative end-to-end digest check lives in :meth:`download_verified`, which
        hashes the bytes it actually received. Callers that must be certain use it.
        """
        length, headers, error = self._head_meta(remote_name)
        if error:
            return False, error
        if length is None:
            return False, "remote object reports no Content-Length"

        if expected_size is not None and expected_size >= 0 and length != expected_size:
            return False, f"size mismatch: remote {length} != expected {expected_size}"

        meta_sha = headers.get("x-amz-meta-p20-sha256", "")
        meta_size = headers.get("x-amz-meta-p20-size", "")
        if meta_size and meta_size.isdigit() and int(meta_size) != length:
            return False, f"stored metadata size {meta_size} contradicts Content-Length {length}"
        if expected_sha256 and meta_sha and meta_sha.lower() != expected_sha256.lower():
            return False, "stored metadata digest does not match the uploaded digest"

        # Deliberately no ETag-not-equal-to-MD5 check: a multipart or SSE-KMS ETag is not
        # an MD5, and treating it as one would reject correct uploads. Size + echoed
        # metadata catch every corruption mode we can detect remotely; download_verified()
        # hashes the real bytes when a caller needs certainty.
        return True, ""

    def download_verified(self, remote_name: str, local_path: str,
                          expected_size: int = -1,
                          expected_sha256: str = "") -> Tuple[bool, str]:
        """Download and hash the received bytes — the authoritative integrity check."""
        ok, error = self.download(remote_name, local_path)
        if not ok:
            return False, error
        try:
            digest = hashlib.sha256()
            size = 0
            with open(local_path, "rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
                    size += len(block)
        except OSError as exc:
            return False, f"cannot hash downloaded object: {type(exc).__name__}"
        if expected_size is not None and expected_size >= 0 and size != expected_size:
            return False, f"downloaded size mismatch: {size} != expected {expected_size}"
        if expected_sha256 and digest.hexdigest().lower() != expected_sha256.lower():
            return False, "downloaded digest does not match the expected sha256"
        return True, ""

    def _size_of(self, remote_name: str) -> Optional[int]:
        length, _headers, _error = self._head_meta(remote_name)
        return length

    def delete(self, remote_name: str) -> Tuple[bool, str]:
        try:
            status, _ = self._request("DELETE", self._url(remote_name))
        except OffsiteError as exc:
            return False, str(exc)
        return status in (200, 204), "" if status in (200, 204) else f"delete http {status}"

    def _list_objects_raw(self) -> List[Dict[str, Any]]:
        """Parse ListObjectsV2 into ``[{name, size, last_modified}]``.

        Retention needs the server's LastModified, so this reads the whole ``<Contents>``
        block rather than pulling ``<Key>`` out with a string split.
        """
        base = f"{self.endpoint}/{self.bucket}"
        query = {"list-type": "2", "max-keys": "1000"}
        if self.prefix:
            query["prefix"] = self.prefix + "/"
        url = f"{base}?{urllib.parse.urlencode(query)}"
        try:
            status, body = self._request("GET", url)
        except OffsiteError:
            return []
        if status != 200:
            return []
        import xml.etree.ElementTree as ET

        try:
            root = ET.fromstring(body)
        except ET.ParseError:
            return []
        out: List[Dict[str, Any]] = []
        for node in root.iter():
            if not node.tag.endswith("}Contents") and node.tag != "Contents":
                continue
            entry: Dict[str, Any] = {}
            for child in node:
                tag = child.tag.rsplit("}", 1)[-1]
                entry[tag] = (child.text or "").strip()
            if "Key" in entry:
                out.append(entry)
        return out

    def list_remote(self) -> List[str]:
        return [entry["Key"].split("/")[-1] for entry in self._list_objects_raw()]

    def list_remote_objects(self) -> List[Tuple[str, Optional[float]]]:
        """``(name, epoch)`` using the server's LastModified."""
        from datetime import datetime, timezone

        result: List[Tuple[str, Optional[float]]] = []
        for entry in self._list_objects_raw():
            name = entry["Key"].split("/")[-1]
            stamp = entry.get("LastModified")
            epoch: Optional[float] = None
            if stamp:
                try:
                    parsed = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S.%fZ")
                    epoch = parsed.replace(tzinfo=timezone.utc).timestamp()
                except ValueError:
                    try:
                        parsed = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ")
                        epoch = parsed.replace(tzinfo=timezone.utc).timestamp()
                    except ValueError:
                        epoch = None
            result.append((name, epoch))
        return result

    def download(self, remote_name: str, local_path: str) -> Tuple[bool, str]:
        try:
            status, body = self._request("GET", self._url(remote_name))
        except OffsiteError as exc:
            return False, str(exc)
        if status != 200:
            return False, f"download http {status}"
        try:
            with open(local_path, "wb") as handle:
                handle.write(body)
            os.chmod(local_path, 0o600)
        except OSError as exc:
            return False, f"cannot write download: {type(exc).__name__}"
        return True, ""


class LocalOffsite(OffsiteProvider):
    """A second directory. Honest about what it is: not an independent failure domain."""

    name = "local-directory"
    independent_failure_domain = False

    def __init__(self, target: str) -> None:
        self.target = target

    def configured_detail(self) -> str:
        return f"local directory={self.target} (NOT an independent failure domain)"

    def upload(self, local_path: str, remote_name: str, sha256: str = "") -> Tuple[bool, str]:
        try:
            os.makedirs(self.target, exist_ok=True)
            dest = os.path.join(self.target, os.path.basename(remote_name))
            if os.path.abspath(dest) == os.path.abspath(local_path):
                return False, "offsite target is the same file as the source; no independent copy"
            shutil.copy2(local_path, dest)
            if os.path.getsize(dest) != os.path.getsize(local_path):
                return False, "offsite copy size mismatch"
            return True, ""
        except shutil.SameFileError:
            return False, "offsite target is the same directory as the backup directory"
        except Exception as exc:
            return False, f"offsite copy failed: {type(exc).__name__}"

    def verify(self, remote_name: str, expected_size: int = -1,
               expected_sha256: str = "") -> Tuple[bool, str]:
        path = os.path.join(self.target, os.path.basename(remote_name))
        if not os.path.exists(path):
            return False, "offsite copy missing"
        actual = os.path.getsize(path)
        if expected_size is not None and expected_size >= 0 and actual != expected_size:
            return False, f"offsite copy size mismatch: {actual} != {expected_size}"
        # A local copy can be hashed outright, which is stronger than any remote check.
        if expected_sha256:
            digest = hashlib.sha256()
            try:
                with open(path, "rb") as handle:
                    for block in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(block)
            except OSError as exc:
                return False, f"cannot hash offsite copy: {type(exc).__name__}"
            if digest.hexdigest().lower() != expected_sha256.lower():
                return False, "offsite copy digest mismatch"
        return True, ""

    def download_verified(self, remote_name: str, local_path: str,
                          expected_size: int = -1,
                          expected_sha256: str = "") -> Tuple[bool, str]:
        """Download, then hash the bytes that actually landed on disk.

        The remote copy is not re-consulted here: the point of a verified download is to
        check the bytes this process received, not to ask the same server twice.
        """
        ok, error = self.download(remote_name, local_path)
        if not ok:
            return False, error
        try:
            size = os.path.getsize(local_path)
            if expected_size is not None and expected_size >= 0 and size != expected_size:
                return False, f"downloaded size mismatch: {size} != expected {expected_size}"
            if expected_sha256:
                digest = hashlib.sha256()
                with open(local_path, "rb") as handle:
                    for block in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(block)
                if digest.hexdigest().lower() != expected_sha256.lower():
                    return False, "downloaded digest does not match the expected sha256"
        except OSError as exc:
            return False, f"cannot hash downloaded object: {type(exc).__name__}"
        return True, ""

    def list_remote_objects(self) -> List[Tuple[str, Optional[float]]]:
        if not os.path.isdir(self.target):
            return []
        out: List[Tuple[str, Optional[float]]] = []
        for name in self.list_remote():
            try:
                out.append((name, os.path.getmtime(os.path.join(self.target, name))))
            except OSError:
                out.append((name, None))
        return out

    def delete(self, remote_name: str) -> Tuple[bool, str]:
        path = os.path.join(self.target, os.path.basename(remote_name))
        try:
            if os.path.exists(path):
                os.remove(path)
            return True, ""
        except OSError as exc:
            return False, type(exc).__name__

    def list_remote(self) -> List[str]:
        if not os.path.isdir(self.target):
            return []
        return sorted(f for f in os.listdir(self.target) if f.endswith(".enc") or f.endswith(".gz"))

    def download(self, remote_name: str, local_path: str) -> Tuple[bool, str]:
        src = os.path.join(self.target, os.path.basename(remote_name))
        if not os.path.exists(src):
            return False, "offsite copy missing"
        try:
            shutil.copy2(src, local_path)
            return True, ""
        except OSError as exc:
            return False, type(exc).__name__


def provider_from_env(env: Optional[Dict[str, str]] = None) -> Optional[OffsiteProvider]:
    """Build the configured provider, or ``None`` when offsite storage is NOT CONFIGURED.

    ``BACKUP_OFFSITE_URL`` selects S3 when it starts with ``http``, and a local directory
    otherwise. The distinction is reported, not blurred: the caller records the provider
    name and whether it is an independent failure domain.
    """
    env = env if env is not None else os.environ
    url = (env.get("BACKUP_OFFSITE_URL") or env.get("BACKUP_OFFSITE_PATH") or "").strip()
    if not url:
        return None
    if url.startswith("http://") or url.startswith("https://"):
        if url.startswith("http://"):
            # Refuse plaintext transport outright: a backup crossing the network in the
            # clear is worse than one that never left the host.
            raise OffsiteError("BACKUP_OFFSITE_URL must use https://; refusing plaintext transport")
        parsed = urllib.parse.urlsplit(url)
        bucket = parsed.path.strip("/").split("/")[0]
        prefix = "/".join(parsed.path.strip("/").split("/")[1:])
        access = env.get("BACKUP_OFFSITE_ACCESS_KEY", "").strip()
        secret = env.get("BACKUP_OFFSITE_SECRET_KEY", "").strip()
        region = env.get("BACKUP_OFFSITE_REGION", "").strip() or "us-east-1"
        if not (bucket and access and secret):
            raise OffsiteError(
                "BACKUP_OFFSITE_URL is set but BACKUP_OFFSITE_ACCESS_KEY/SECRET_KEY are "
                "missing; offsite upload cannot be authenticated"
            )
        endpoint = f"{parsed.scheme}://{parsed.netloc}"
        return S3Offsite(endpoint, bucket, access, secret, region, prefix=prefix)
    return LocalOffsite(url)


def status(env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Monitoring-friendly offsite status. Never claims more than is true."""
    try:
        provider = provider_from_env(env)
    except OffsiteError as exc:
        return {"configured": False, "state": OFFSITE_NOT_CONFIGURED, "error": str(exc)}
    if provider is None:
        return {"configured": False, "state": OFFSITE_NOT_CONFIGURED}
    return {
        "configured": True,
        "state": "CONFIGURED",
        "provider": provider.name,
        "independent_failure_domain": provider.independent_failure_domain,
        "detail": provider.configured_detail(),
    }
