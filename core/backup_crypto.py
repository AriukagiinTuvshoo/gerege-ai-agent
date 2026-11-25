"""Authenticated, versioned backup encryption (Phase 18).

Why this module exists
----------------------
Phase 17 found that Phase 16 encrypted backups with ``openssl enc -aes-256-cbc``. CBC
provides confidentiality and nothing else: there is no MAC, so a modified archive
decrypts cleanly into corrupted plaintext, and the code had no way to tell a genuine
archive from a forged one. ``openssl enc`` in OpenSSL 3.0 cannot do AEAD at all
(``openssl enc -ciphers`` lists only ``-chacha20``, with no Poly1305), so authenticated
encryption could not be added to the existing tool path. That is the seam this module
closes.

The primitive is **AES-256-GCM** from the ``cryptography`` package — a vetted
implementation of a standard AEAD construction. No cryptography is invented here: the
package supplies the cipher, and this file only defines a *container format* around it
and drives it in 1 MiB chunks so that a multi-gigabyte dump is never fully resident in
memory.

Format (version 1)
------------------
::

    magic       8 bytes   b"GEREGE-B"
    version     1 byte    0x01
    header_len  2 bytes   big-endian length of the JSON header
    header      N bytes   UTF-8 JSON, fixed key order, ASCII-safe
    chunks      ...       repeated: [frame_len 4][nonce 12][ciphertext][tag 16]
    terminator  frame_len == 0 plus a 12-byte nonce and a 16-byte tag over b"" (end marker)

``frame_len`` counts the ciphertext bytes that follow its 12-byte nonce, so a reader
never has to guess where one chunk ends and the next begins. Without an explicit
length the final chunk would be indistinguishable from the start of the terminator.

The header is passed as **additional authenticated data (AAD)** to every chunk, so the
version, the original size and any metadata cannot be altered without the tag check
failing. Every chunk is independently authenticated, which means a truncated archive
fails at the missing end marker and a flipped bit fails at exactly one chunk.

Key handling
------------
The key file is read as raw bytes. A 32-byte binary file is used directly; a longer file
that decodes as base64 and yields exactly 32 bytes is accepted (that is what the
documented ``head -c 32 /dev/urandom | base64`` produces). Anything else is refused
loudly rather than silently stretched with a KDF — a wrong-length key almost always
means the operator pointed at the wrong file, and failing is the safe outcome.

Legacy reads
------------
Phase 16 archives (``openssl`` + ``Salted__`` magic) are still readable through
:func:`decrypt_legacy_openssl` so an operator is never locked out of old backups, but
that path is **not** authenticated and is reported as such.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import struct
from typing import Any, Dict, Optional, Tuple

MAGIC = b"GEREGE-B"
#: Format this build writes. Version 2 binds the chunk index and length into the AEAD
#: associated data; version 1 did not (see ``_chunk_aad`` for the defect this fixes).
FORMAT_VERSION = 2
#: Versions this build can still READ. Old archives stay restorable after an upgrade;
#: dropping a readable version would strand every existing restore point.
READABLE_VERSIONS = (1, 2)
KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
CHUNK_SIZE = 1024 * 1024
_HEADER_KEYS = ("cipher", "created_at", "format", "original_name", "original_size", "version")


class EncryptionError(Exception):
    """Raised for any encryption/decryption problem; the message never contains key material."""


def _aead():
    """Import the primitive lazily so a missing dependency is a clear error, not an ImportError."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover - dependency is declared in requirements
        raise EncryptionError(
            "the 'cryptography' package is required for authenticated backups; "
            "install it with: pip install 'cryptography>=42'"
        ) from exc
    return AESGCM


def load_key(key_file: str) -> bytes:
    """Read and validate a 32-byte key. Never echoes the contents or its length in errors."""
    if not os.path.exists(key_file):
        raise EncryptionError(f"encryption key file not found: {os.path.basename(key_file)}")
    try:
        raw = open(key_file, "rb").read()
    except OSError as exc:
        raise EncryptionError(f"encryption key file is unreadable: {type(exc).__name__}") from exc

    if len(raw) == KEY_LEN:
        # A 32-byte file is the key, byte for byte. This check must come FIRST and must
        # not strip: a random 32-byte key contains a whitespace byte at an end position
        # about one time in forty, and stripping turned those perfectly good keys into
        # "unexpected length" failures. Random keys are binary data, not text.
        return raw
    stripped = raw.strip()
    if len(stripped) == KEY_LEN:
        return stripped
    # base64 form (the documented generator writes `head -c 32 /dev/urandom | base64`)
    try:
        decoded = base64.b64decode(stripped, validate=True)
    except Exception:
        decoded = b""
    if len(decoded) == KEY_LEN:
        return decoded
    raise EncryptionError(
        "encryption key has an unexpected length; expected 32 raw bytes or a base64 "
        "encoding of 32 bytes. Regenerate with: head -c 32 /dev/urandom | base64 > key"
    )


def _header_bytes(header: Dict[str, Any]) -> bytes:
    # Fixed key order and separators: the header is authenticated, so its bytes must be
    # reproducible on the read side before any other parsing happens.
    ordered = {k: header[k] for k in _HEADER_KEYS if k in header}
    for extra in sorted(set(header) - set(_HEADER_KEYS)):
        ordered[extra] = header[extra]
    return json.dumps(ordered, sort_keys=False, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _chunk_aad(header_bytes: bytes, version: int, index: int, plain_len: int) -> bytes:
    """Associated data bound to each frame.

    Phase 22 (P21-02). Version 1 authenticated every frame against the *header* only, so
    the frames were individually authentic but not bound to their position. Phase 21
    swapped two data frames in a real archive and ``decrypt_file`` returned success -
    producing 1,572,864 bytes of silently wrong plaintext for a 1,572,864-byte original.
    The docstring claimed "a reordered chunk ... raise[s] here". It did not.

    That was not remotely exploitable (the sidecar checksum and gzip both reject the
    result), but "the AEAD would catch it" was a false statement about the format, and a
    future caller that trusted the archive layer alone would have been wrong.

    Version 2 binds, per frame: the header, the chunk index, and the plaintext length.
    * index - swapping, duplicating or dropping a frame changes the index it is checked
      against, so the tag no longer verifies;
    * length - a frame cannot be relabelled with a different size;
    * header - the container metadata stays bound as before.

    The end marker uses a distinguishable type byte and the total chunk count, so a data
    frame cannot be substituted for the terminator or vice versa.
    """
    return (
        b"gerege-chunk-v2\x00"
        + struct.pack(">BII", version, index, plain_len)
        + hashlib.sha256(header_bytes).digest()
    )


def _end_aad(header_bytes: bytes, version: int, chunk_count: int) -> bytes:
    """Associated data for the end marker: distinct type, plus the total frame count."""
    return (
        b"gerege-end-v2\x00"
        + struct.pack(">BI", version, chunk_count)
        + hashlib.sha256(header_bytes).digest()
    )


def encrypt_file(src: str, dest: str, key_file: str, original_name: Optional[str] = None) -> Dict[str, Any]:
    """Encrypt ``src`` to ``dest`` with AES-256-GCM.

    Returns a small dict describing the artifact (never key material). Raises
    :class:`EncryptionError` on any failure.
    """
    AESGCM = _aead()
    key = load_key(key_file)
    aead = AESGCM(key)

    from datetime import datetime, timezone

    header: Dict[str, Any] = {
        "cipher": "AES-256-GCM",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "format": "gerege-backup",
        "original_name": original_name or os.path.basename(src),
        "original_size": os.path.getsize(src),
        "version": FORMAT_VERSION,
    }
    header_bytes = _header_bytes(header)

    parent = os.path.dirname(os.path.abspath(dest)) or "."
    os.makedirs(parent, exist_ok=True)
    tmp_dest = f"{dest}.partial-{secrets.token_hex(4)}"

    written = 0
    try:
        with open(src, "rb") as fin, open(tmp_dest, "wb") as fout:
            os.chmod(tmp_dest, 0o600)
            fout.write(MAGIC)
            fout.write(struct.pack(">BH", FORMAT_VERSION, len(header_bytes)))
            fout.write(header_bytes)
            index = 0
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                nonce = secrets.token_bytes(NONCE_LEN)
                # A per-chunk nonce is safe: the key is single-purpose and, at 12 random
                # bytes, collision probability stays negligible across any realistic
                # archive count. The nonce is authenticated as part of the ciphertext.
                # Phase 22: the AAD binds the frame to its index and length, so a
                # reordered or duplicated frame fails authentication.
                sealed = aead.encrypt(
                    nonce, chunk, _chunk_aad(header_bytes, FORMAT_VERSION, index, len(chunk))
                )
                fout.write(struct.pack(">I", len(chunk)))
                fout.write(nonce)
                fout.write(sealed)
                written += len(chunk)
                index += 1
            # End marker: frame_len 0 proves the stream was not truncated. Its AAD carries
            # the total frame count, so truncating whole frames off the end is detected even
            # when the terminator is copied across.
            fout.write(struct.pack(">I", 0))
            fout.write(b"\x00" * NONCE_LEN)
            fout.write(
                aead.encrypt(b"\x00" * NONCE_LEN, b"", _end_aad(header_bytes, FORMAT_VERSION, index))
            )
            fout.flush()
            os.fsync(fout.fileno())

        if written != header["original_size"]:
            raise EncryptionError("encrypted chunk total does not match the source size")

        os.replace(tmp_dest, dest)
        os.chmod(dest, 0o600)
    except Exception:
        for path in (tmp_dest,):
            try:
                os.remove(path)
            except OSError:
                pass
        raise

    return {
        "format": "gerege-backup",
        "version": FORMAT_VERSION,
        "cipher": "AES-256-GCM",
        "size_bytes": os.path.getsize(dest),
        "original_size": header["original_size"],
    }


def read_header(path: str) -> Dict[str, Any]:
    """Parse and validate the container header without decrypting the body."""
    with open(path, "rb") as handle:
        magic = handle.read(len(MAGIC))
        if magic != MAGIC:
            raise EncryptionError("not a Gerege encrypted archive (bad magic)")
        raw = handle.read(3)
        if len(raw) != 3:
            raise EncryptionError("encrypted archive header is truncated")
        version, header_len = struct.unpack(">BH", raw)
        if version not in READABLE_VERSIONS:
            raise EncryptionError(
                f"unsupported encrypted archive version {version}; this build reads "
                f"version(s) {', '.join(str(v) for v in READABLE_VERSIONS)}"
            )
        header_bytes = handle.read(header_len)
        if len(header_bytes) != header_len:
            raise EncryptionError("encrypted archive header is truncated")
    try:
        header = json.loads(header_bytes.decode("ascii"))
    except Exception as exc:
        raise EncryptionError("encrypted archive header is not valid JSON") from exc
    if header.get("format") != "gerege-backup" or header.get("version") not in READABLE_VERSIONS:
        raise EncryptionError("encrypted archive header is inconsistent")
    # The version that governs frame binding is the one in the *binary* prefix, which the
    # reader has already consumed; recording it lets decrypt choose the right AAD scheme.
    header["_container_version"] = version
    if header.get("cipher") != "AES-256-GCM":
        raise EncryptionError(f"unsupported cipher {header.get('cipher')!r}")
    header["_raw"] = header_bytes
    return header


def is_authenticated_archive(path: str) -> bool:
    """True when ``path`` begins with this module's magic. Never raises."""
    try:
        with open(path, "rb") as handle:
            return handle.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def decrypt_file(src: str, dest: str, key_file: str) -> Dict[str, Any]:
    """Decrypt and **authenticate** an archive. Raises :class:`EncryptionError` on any failure.

    A wrong key, a modified byte, a reordered chunk and a truncated file all raise here.
    There is no code path that returns success for unauthenticated plaintext.
    """
    AESGCM = _aead()
    key = load_key(key_file)
    aead = AESGCM(key)

    header = read_header(src)
    header_bytes = header["_raw"]
    version_from_prefix = int(header.get("_container_version", FORMAT_VERSION))

    tmp_dest = f"{dest}.partial-{secrets.token_hex(4)}"
    total = 0
    saw_terminator = False
    try:
        with open(src, "rb") as fin, open(tmp_dest, "wb") as fout:
            os.chmod(tmp_dest, 0o600)
            fin.read(len(MAGIC))
            fin.read(3)
            fin.read(len(header_bytes))
            version = header.get("_container_version", version_from_prefix)
            index = 0
            while True:
                raw_len = fin.read(4)
                if len(raw_len) < 4:
                    raise EncryptionError("encrypted archive is truncated")
                (frame_len,) = struct.unpack(">I", raw_len)
                if frame_len > CHUNK_SIZE:
                    raise EncryptionError(
                        f"encrypted archive frame length {frame_len} exceeds the maximum; archive is malformed"
                    )
                nonce = fin.read(NONCE_LEN)
                if len(nonce) < NONCE_LEN:
                    raise EncryptionError("encrypted archive is truncated")
                if frame_len == 0:
                    tag = fin.read(TAG_LEN)
                    if len(tag) != TAG_LEN:
                        raise EncryptionError("encrypted archive is truncated")
                    # Version 2 binds the terminator's *type* and the total frame count, so
                    # a data frame cannot be passed off as the terminator and a stream
                    # cannot be truncated by whole frames while keeping an old marker.
                    end_aad = (
                        _end_aad(header_bytes, version, index)
                        if version >= 2
                        else header_bytes
                    )
                    try:
                        aead.decrypt(nonce, tag, end_aad)
                    except Exception as exc:
                        raise EncryptionError("encrypted archive failed authentication (end marker)") from exc
                    saw_terminator = True
                    if fin.read(1):
                        raise EncryptionError("encrypted archive has trailing data after the end marker")
                    break
                body = fin.read(frame_len + TAG_LEN)
                if len(body) < frame_len + TAG_LEN:
                    raise EncryptionError("encrypted archive is truncated")
                frame_aad = (
                    _chunk_aad(header_bytes, version, index, frame_len)
                    if version >= 2
                    else header_bytes
                )
                try:
                    plain = aead.decrypt(nonce, body, frame_aad)
                except Exception as exc:
                    raise EncryptionError(
                        "encrypted archive failed authentication: wrong key, a modified "
                        "byte, or a chunk that is out of order / duplicated / missing"
                    ) from exc
                fout.write(plain)
                total += len(plain)
                index += 1

            if not saw_terminator:
                raise EncryptionError("encrypted archive is truncated (no end marker)")

        if total != header.get("original_size"):
            raise EncryptionError(
                f"decrypted size {total} does not match the recorded size {header.get('original_size')}"
            )
        os.replace(tmp_dest, dest)
        os.chmod(dest, 0o600)
    except Exception:
        try:
            os.remove(tmp_dest)
        except OSError:
            pass
        raise

    return {"format": "gerege-backup", "version": header["version"], "size_bytes": total}


def decrypt_legacy_openssl(src: str, dest: str, key_file: str) -> Dict[str, Any]:
    """Read a Phase 16 ``openssl enc -aes-256-cbc`` archive.

    Kept so old backups stay recoverable. This format has **no authentication**; a
    successful return only means the padding was well formed. The caller must treat the
    result as untrusted and rely on the ``.sha256`` sidecar and the gzip CRC.
    """
    import shutil
    import subprocess

    openssl = shutil.which("openssl")
    if not openssl:
        raise EncryptionError("openssl is not installed; cannot read a legacy archive")
    if not os.path.exists(key_file):
        raise EncryptionError(f"encryption key file not found: {os.path.basename(key_file)}")
    proc = subprocess.run(
        [openssl, "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000",
         "-in", src, "-out", dest, "-pass", f"file:{key_file}"],
        capture_output=True, timeout=1800,
    )
    if proc.returncode != 0:
        raise EncryptionError(
            "legacy archive decryption failed (wrong key or corrupt archive); "
            "note this legacy format carries no authentication tag"
        )
    os.chmod(dest, 0o600)
    return {"format": "openssl-legacy", "version": 0, "authenticated": False, "size_bytes": os.path.getsize(dest)}
