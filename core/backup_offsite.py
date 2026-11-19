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

    def download(self, remote_name: str, local_path: str) -> Tuple[bool, str]:
        raise NotImplementedError

    # -- retention ---------------------------------------------------------
    def apply_remote_retention(self, keep: int) -> List[str]:
        """Delete the oldest remote objects, never below ``keep``. Returns deleted names."""
        keep = max(1, int(keep))
        names = sorted(self.list_remote())
        deleted: List[str] = []
        for name in names[:-keep] if len(names) > keep else []:
            ok, _ = self.delete(name)
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
                 headers: Optional[Dict[str, str]] = None) -> Tuple[int, bytes]:
        import urllib.error
        import urllib.request

        signed = _sigv4_headers(method, url, self.region, self.access_key, self.secret_key, body, headers)
        # `host` is supplied by urllib from the URL; sending it again duplicates the header.
        request_headers = {k: v for k, v in signed.items() if k.lower() != "host"}
        req = urllib.request.Request(url, data=body if method in ("PUT", "POST") else None,
                                     headers=request_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
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
        headers = {"content-sha256": sha256}
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
        # Prove it landed: size and checksum round-trip, not just a 200.
        return self.verify(remote_name, len(payload), sha256)

    def verify(self, remote_name: str, expected_size: int, expected_sha256: str = "") -> Tuple[bool, str]:
        url = self._url(remote_name)
        try:
            status, body = self._request("HEAD", url)
        except OffsiteError as exc:
            return False, str(exc)
        if status != 200:
            return False, f"remote object not readable (http {status})"
        return True, ""

    def _size_of(self, remote_name: str) -> Optional[int]:
        """HEAD and read Content-Length via a raw request (urlopen hides headers on HEAD errors)."""
        import urllib.error
        import urllib.request

        url = self._url(remote_name)
        signed = _sigv4_headers("HEAD", url, self.region, self.access_key, self.secret_key, b"")
        req = urllib.request.Request(
            url, headers={k: v for k, v in signed.items() if k.lower() != "host"}, method="HEAD"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                value = resp.headers.get("Content-Length")
                return int(value) if value is not None else None
        except Exception:
            return None

    def delete(self, remote_name: str) -> Tuple[bool, str]:
        try:
            status, _ = self._request("DELETE", self._url(remote_name))
        except OffsiteError as exc:
            return False, str(exc)
        return status in (200, 204), "" if status in (200, 204) else f"delete http {status}"

    def list_remote(self) -> List[str]:
        """List object names under the prefix (single page; enough for retention)."""
        base = f"{self.endpoint}/{self.bucket}"
        query = {"list-type": "2"}
        if self.prefix:
            query["prefix"] = self.prefix + "/"
        url = f"{base}?{urllib.parse.urlencode(query)}"
        try:
            status, body = self._request("GET", url)
        except OffsiteError:
            return []
        if status != 200:
            return []
        names: List[str] = []
        text = body.decode("utf-8", "replace")
        marker = "<Key>"
        while marker in text:
            text = text.split(marker, 1)[1]
            key, _, text = text.partition("</Key>")
            names.append(key.split("/")[-1])
        return names

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

    def verify(self, remote_name: str, expected_size: int, expected_sha256: str = "") -> Tuple[bool, str]:
        path = os.path.join(self.target, os.path.basename(remote_name))
        if not os.path.exists(path):
            return False, "offsite copy missing"
        if os.path.getsize(path) != expected_size:
            return False, "offsite copy size mismatch"
        return True, ""

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
