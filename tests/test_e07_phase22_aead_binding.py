"""Phase 22 regression tests: P21-02 the AEAD did not bind chunks to their position.

Phase 21 took a real archive, swapped its two data frames, and ran the real decryptor:

    frame spans: [(172, 1048780), (1048780, 1573100), (1573100, 1573132)]
    >>> decrypt_file(swapped)
    {'format': 'gerege-backup', 'version': 1, 'size_bytes': 1572864}
    >>> got == original
    False                              # 1,572,864 bytes of silently wrong plaintext

`decrypt_file`'s docstring said "a reordered chunk ... raise[s] here". Every frame was
authenticated against the *header* only, so the frames were individually authentic but
not bound to their position, and the claim was false.

Format version 2 binds the header, the chunk index and the plaintext length into each
frame's AAD, and binds the end marker to its own type plus the total frame count.
Version 1 stays readable, because archives written before this change are still the only
restore points some deployment has.

The tests below are adversarial: each one mutates a real archive and asserts rejection.
A plain round-trip test cannot catch this class of defect - the broken version round-tripped
perfectly, it just authenticated the wrong thing.
"""

from __future__ import annotations

import json
import os
import pathlib
import struct
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core import backup_crypto as bc  # noqa: E402


@pytest.fixture
def key_file(tmp_path):
    path = tmp_path / "backup.key"
    path.write_bytes(os.urandom(32))
    path.chmod(0o600)
    return str(path)


@pytest.fixture
def archive(tmp_path, key_file):
    """A real v2 archive with three frames: two full chunks and one short one."""
    plain = os.urandom(bc.CHUNK_SIZE) + os.urandom(bc.CHUNK_SIZE) + os.urandom(4096)
    src = tmp_path / "plain.bin"
    src.write_bytes(plain)
    enc = tmp_path / "archive.enc"
    bc.encrypt_file(str(src), str(enc), key_file)
    return {"path": enc, "plain": plain, "key": key_file, "dir": tmp_path}


def _spans(path: pathlib.Path):
    """Return the byte span of every frame, header excluded, plus the header length."""
    data = path.read_bytes()
    header = bc.read_header(str(path))
    offset = len(bc.MAGIC) + 3 + len(header["_raw"])
    spans = []
    while offset < len(data):
        start = offset
        (frame_len,) = struct.unpack(">I", data[offset:offset + 4])
        offset += 4 + bc.NONCE_LEN + frame_len + bc.TAG_LEN
        spans.append((start, offset, frame_len))
    return data, header, spans


def _write(path: pathlib.Path, blob: bytes) -> str:
    path.write_bytes(blob)
    path.chmod(0o600)
    return str(path)


def _decrypt(enc, out, key):
    return bc.decrypt_file(str(enc), str(out), key)


# ---------------------------------------------------------------------------
# the reported defect
# ---------------------------------------------------------------------------

def test_reordered_chunks_are_rejected(archive):
    """The exact Phase 21 reproduction, against the fixed format."""
    data, _header, spans = _spans(archive["path"])
    f0 = data[spans[0][0]:spans[0][1]]
    f1 = data[spans[1][0]:spans[1][1]]
    swapped = data[:spans[0][0]] + f1 + f0 + data[spans[1][1]:]
    target = _write(archive["path"].parent / "swapped.enc", swapped)

    with pytest.raises(bc.EncryptionError) as info:
        _decrypt(target, archive["path"].parent / "out.bin", archive["key"])
    assert "out of order" in str(info.value) or "authentication" in str(info.value)


def test_reordered_chunks_do_not_produce_a_verifiable_archive(archive):
    """Belt and braces: if a future change accepts the swap, the plaintext must differ."""
    data, _header, spans = _spans(archive["path"])
    f0 = data[spans[0][0]:spans[0][1]]
    f1 = data[spans[1][0]:spans[1][1]]
    swapped = data[:spans[0][0]] + f1 + f0 + data[spans[1][1]:]
    target = archive["path"].parent / "swapped2.enc"
    target.write_bytes(swapped)
    out = archive["path"].parent / "out2.bin"
    try:
        _decrypt(target, out, archive["key"])
    except bc.EncryptionError:
        return
    assert out.read_bytes() != archive["plain"], "reordering produced the original plaintext"


# ---------------------------------------------------------------------------
# structural attacks on a v2 archive
# ---------------------------------------------------------------------------

def test_dropped_chunk_is_rejected(archive):
    """Removing a middle frame shifts the indices of everything after it."""
    data, _header, spans = _spans(archive["path"])
    dropped = data[:spans[1][0]] + data[spans[1][1]:]
    target = _write(archive["path"].parent / "dropped.enc", dropped)
    with pytest.raises(bc.EncryptionError):
        _decrypt(target, archive["path"].parent / "o.bin", archive["key"])


def test_duplicated_chunk_is_rejected(archive):
    data, _header, spans = _spans(archive["path"])
    frame = data[spans[0][0]:spans[0][1]]
    duplicated = data[:spans[1][0]] + frame + data[spans[1][0]:]
    target = _write(archive["path"].parent / "dup.enc", duplicated)
    with pytest.raises(bc.EncryptionError):
        _decrypt(target, archive["path"].parent / "o.bin", archive["key"])


def test_substituting_the_end_marker_for_a_data_frame_is_rejected(archive):
    """The marker and a data frame have different AAD types, so they cannot be swapped."""
    data, _header, spans = _spans(archive["path"])
    end = data[spans[-1][0]:spans[-1][1]]
    # Replace the last data frame with the end marker bytes, keeping the real marker.
    forged = data[:spans[-2][0]] + end + data[spans[-1][0]:]
    target = _write(archive["path"].parent / "forged.enc", forged)
    with pytest.raises(bc.EncryptionError):
        _decrypt(target, archive["path"].parent / "o.bin", archive["key"])


def test_truncated_by_a_whole_frame_is_rejected(archive):
    """Cutting the stream between frames must not authenticate, even with a terminator."""
    data, _header, spans = _spans(archive["path"])
    # Drop the last data frame but keep the (now stale) end marker.
    truncated = data[:spans[-2][0]] + data[spans[-1][0]:]
    target = _write(archive["path"].parent / "trunc.enc", truncated)
    with pytest.raises(bc.EncryptionError):
        _decrypt(target, archive["path"].parent / "o.bin", archive["key"])


def test_trailing_bytes_after_the_end_marker_are_rejected(archive):
    data = archive["path"].read_bytes()
    target = _write(archive["path"].parent / "trailing.enc", data + b"\x00")
    with pytest.raises(bc.EncryptionError) as info:
        _decrypt(target, archive["path"].parent / "o.bin", archive["key"])
    assert "trailing" in str(info.value)


def test_single_bit_flip_in_a_frame_is_rejected(archive):
    data = bytearray(archive["path"].read_bytes())
    _d, _h, spans = _spans(archive["path"])
    # Flip a byte inside the first frame's ciphertext, past its nonce.
    data[spans[0][0] + 4 + bc.NONCE_LEN + 100] ^= 0x01
    target = _write(archive["path"].parent / "flip.enc", bytes(data))
    with pytest.raises(bc.EncryptionError):
        _decrypt(target, archive["path"].parent / "o.bin", archive["key"])


def test_wrong_key_is_rejected(archive, tmp_path):
    other = tmp_path / "other.key"
    other.write_bytes(os.urandom(32))
    with pytest.raises(bc.EncryptionError):
        _decrypt(archive["path"], archive["path"].parent / "o.bin", str(other))


def test_header_modification_is_rejected(archive):
    """The header is bound into every frame's AAD, so editing metadata breaks the archive."""
    data = bytearray(archive["path"].read_bytes())
    header = bc.read_header(str(archive["path"]))
    start = len(bc.MAGIC) + 3
    # Flip a byte inside the JSON header itself.
    data[start + 5] ^= 0x01
    target = _write(archive["path"].parent / "hdr.enc", bytes(data))
    with pytest.raises(bc.EncryptionError):
        _decrypt(target, archive["path"].parent / "o.bin", archive["key"])


def test_version_downgrade_is_rejected_or_handled_explicitly(archive):
    """A v2 archive relabelled as v1 must not authenticate.

    Downgrade is the interesting attack on a versioned AAD scheme: if the version came from
    the header the attacker could rewrite it and have the reader use the weaker scheme. The
    version is taken from the binary prefix and is itself covered by the header hash inside
    each AAD, so this must fail.
    """
    data = bytearray(archive["path"].read_bytes())
    offset = len(bc.MAGIC)
    assert data[offset] == 2, "fixture should be version 2"
    data[offset] = 1
    target = _write(archive["path"].parent / "downgrade.enc", bytes(data))
    with pytest.raises(bc.EncryptionError):
        _decrypt(target, archive["path"].parent / "o.bin", archive["key"])


def test_empty_archive_round_trips_and_authenticates(archive, tmp_path, key_file):
    src = tmp_path / "empty.bin"
    src.write_bytes(b"")
    enc = tmp_path / "empty.enc"
    bc.encrypt_file(str(src), str(enc), key_file)
    out = tmp_path / "empty.out"
    bc.decrypt_file(str(enc), str(out), key_file)
    assert out.read_bytes() == b""


def test_header_only_archive_is_rejected_as_truncated(tmp_path, key_file):
    src = tmp_path / "one.bin"
    src.write_bytes(b"abc")
    enc = tmp_path / "one.enc"
    bc.encrypt_file(str(src), str(enc), key_file)
    header = bc.read_header(str(enc))
    header_only = enc.read_bytes()[: len(bc.MAGIC) + 3 + len(header["_raw"])]
    target = tmp_path / "headeronly.enc"
    target.write_bytes(header_only)
    with pytest.raises(bc.EncryptionError):
        bc.decrypt_file(str(target), str(tmp_path / "o.bin"), key_file)


# ---------------------------------------------------------------------------
# backward compatibility: v1 archives must still restore
# ---------------------------------------------------------------------------

def _write_v1_archive(path: pathlib.Path, key: bytes, plain: bytes) -> None:
    """Reproduce the version 1 container exactly as the previous code wrote it.

    Version 1 authenticated every frame against the header alone. This fixture is how the
    old format is proven still readable rather than assumed readable.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import secrets

    aead = AESGCM(key)
    header = {
        "cipher": "AES-256-GCM",
        "created_at": "2026-01-01T00:00:00+00:00",
        "format": "gerege-backup",
        "original_name": "old.sql.gz",
        "original_size": len(plain),
        "version": 1,
    }
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("ascii")
    blob = bytearray()
    blob += bc.MAGIC
    blob += struct.pack(">BH", 1, len(header_bytes))
    blob += header_bytes
    for offset in range(0, len(plain), bc.CHUNK_SIZE):
        chunk = plain[offset:offset + bc.CHUNK_SIZE]
        nonce = secrets.token_bytes(bc.NONCE_LEN)
        blob += struct.pack(">I", len(chunk))
        blob += nonce
        blob += aead.encrypt(nonce, chunk, header_bytes)
    zero_nonce = b"\x00" * bc.NONCE_LEN
    blob += struct.pack(">I", 0)
    blob += zero_nonce
    blob += aead.encrypt(zero_nonce, b"", header_bytes)
    path.write_bytes(bytes(blob))


def test_version_one_archives_are_still_readable(tmp_path, key_file):
    """Dropping v1 support would strand every pre-Phase-22 restore point."""
    key = pathlib.Path(key_file).read_bytes()
    plain = os.urandom(300_000)
    path = tmp_path / "v1.enc"
    _write_v1_archive(path, key, plain)

    out = tmp_path / "v1.out"
    info = bc.decrypt_file(str(path), str(out), key_file)
    assert out.read_bytes() == plain
    assert info.get("version") == 1


def test_version_one_remains_restorable_through_the_service(tmp_path, key_file):
    """The restore path, not just the primitive, must accept a v1 archive."""
    key = pathlib.Path(key_file).read_bytes()
    path = tmp_path / "v1b.enc"
    _write_v1_archive(path, key, os.urandom(50_000))

    from core import backup_automation

    out = tmp_path / "v1b.out"
    ok, error = backup_automation.decrypt_file(str(path), str(out), key_file)
    assert ok is True, error
    assert out.exists() and out.stat().st_size == 50_000


def test_unknown_version_is_refused_with_a_clear_message(tmp_path, key_file):
    src = tmp_path / "x.bin"
    src.write_bytes(b"data")
    enc = tmp_path / "x.enc"
    bc.encrypt_file(str(src), str(enc), key_file)
    data = bytearray(enc.read_bytes())
    data[len(bc.MAGIC)] = 9
    target = tmp_path / "v9.enc"
    target.write_bytes(bytes(data))
    with pytest.raises(bc.EncryptionError) as info:
        bc.read_header(str(target))
    assert "unsupported encrypted archive version 9" in str(info.value)


def test_current_format_version_is_two_and_one_stays_readable():
    assert bc.FORMAT_VERSION == 2
    assert 1 in bc.READABLE_VERSIONS
    assert 2 in bc.READABLE_VERSIONS


# ---------------------------------------------------------------------------
# the AAD must actually contain what the docstring says
# ---------------------------------------------------------------------------

def test_chunk_aad_binds_index_and_length():
    header = b'{"x":1}'
    aad0 = bc._chunk_aad(header, 2, 0, 100)
    aad1 = bc._chunk_aad(header, 2, 1, 100)
    aad_len = bc._chunk_aad(header, 2, 0, 101)
    assert aad0 != aad1, "index is not bound"
    assert aad0 != aad_len, "length is not bound"


def test_end_aad_is_distinguishable_from_a_chunk_aad():
    header = b'{"x":1}'
    assert bc._chunk_aad(header, 2, 0, 0) != bc._end_aad(header, 2, 0)


def test_end_aad_binds_the_frame_count():
    header = b'{"x":1}'
    assert bc._end_aad(header, 2, 1) != bc._end_aad(header, 2, 2)


def test_docstring_no_longer_claims_something_untrue():
    """The old docstring promised reorder detection the format did not provide."""
    source = (REPO_ROOT / "core" / "backup_crypto.py").read_text()
    doc = bc.decrypt_file.__doc__ or ""
    assert "reordered" in doc or "out of order" in doc
    # And the format version that makes the claim true must be the one written.
    assert "FORMAT_VERSION = 2" in source


# ---------------------------------------------------------------------------
# the documented v1 trade-off must be true, not reassuring
# ---------------------------------------------------------------------------

def test_reordered_v1_archive_is_still_caught_by_the_sidecar(tmp_path, key_file, monkeypatch):
    """The doc says v1 is weaker but "still protected by the sidecar checksum, which
    rejects the reorder before any restore reaches the database". Prove that sentence.

    A v1 archive's frames are not position-bound, so the AEAD alone accepts a reorder.
    The checksum sidecar is what actually stops it in the restore path - which is why the
    documentation is allowed to keep v1 readable.
    """
    import hashlib

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import gzip
    import base64
    import secrets

    key = pathlib.Path(key_file).read_bytes()
    aead = AESGCM(key)
    # Enough incompressible rows to produce more than one 1 MiB frame; gzip would
    # otherwise collapse repetitive data and leave nothing to reorder.
    rows = b"".join(base64.b64encode(os.urandom(48)) + b"\n" for _ in range(40000))
    sql = (
        b"-- PostgreSQL database dump\nSET statement_timeout = 0;\n"
        b"COPY public.pages (page_id) FROM stdin;\n" + rows + b"\\.\n"
    )
    gz = gzip.compress(sql)
    header = {
        "cipher": "AES-256-GCM",
        "created_at": "2026-01-01T00:00:00+00:00",
        "format": "gerege-backup",
        "original_name": "old.sql.gz",
        "original_size": len(gz),
        "version": 1,
    }
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("ascii")
    prefix = bc.MAGIC + struct.pack(">BH", 1, len(header_bytes)) + header_bytes
    frames = []
    for offset in range(0, len(gz), bc.CHUNK_SIZE):
        chunk = gz[offset:offset + bc.CHUNK_SIZE]
        nonce = secrets.token_bytes(bc.NONCE_LEN)
        frames.append(struct.pack(">I", len(chunk)) + nonce + aead.encrypt(nonce, chunk, header_bytes))
    assert len(frames) >= 2, "fixture needs at least two frames to reorder"
    zero = b"\x00" * bc.NONCE_LEN
    terminator = struct.pack(">I", 0) + zero + aead.encrypt(zero, b"", header_bytes)

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    name = "pg_backup_old_20260101_000000_00.sql.gz.enc"
    archive = backup_dir / name
    original = prefix + b"".join(frames) + terminator
    archive.write_bytes(original)
    (backup_dir / (name + ".sha256")).write_text(
        f"{hashlib.sha256(original).hexdigest()}  {name}\n"
    )

    # Sanity: the untouched archive verifies.
    from core import backup_service

    monkeypatch.setattr(backup_service, "BACKUP_DIR", str(backup_dir), raising=True)
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", key_file)
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    assert backup_service.verify_backup(name).get("valid") is True

    # Reorder the two frames, keeping the ORIGINAL sidecar.
    archive.write_bytes(prefix + frames[1] + frames[0] + b"".join(frames[2:]) + terminator)
    result = backup_service.verify_backup(name)
    assert result.get("valid") is False
    assert "checksum" in str(result.get("error", "")).lower()
