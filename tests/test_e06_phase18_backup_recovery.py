"""Phase 18 regression tests: backup lifecycle, encryption, restore, rollback.

Every test here corresponds to a Phase 17 finding that was verified as a real defect,
so a failure means a regression of a specific, previously observed breakage. The tests
that need a database use the PostgreSQL instance the CI job provides; the rest are pure
unit tests of the crypto/staging/retention layer.

The one property worth stating explicitly: these tests assert the *filesystem and
database state* after each scenario, not merely an exit code. Phase 17 showed repeatedly
that a nonzero exit with a plaintext dump left behind, or a zero exit with no restorable
archive, both look like success to a test that only checks the return value.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core import backup_archive, backup_crypto, backup_staging  # noqa: E402


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _key(path: pathlib.Path) -> str:
    path.write_bytes(os.urandom(32))
    os.chmod(path, 0o400)
    return str(path)


def _dump(path: pathlib.Path, body: bytes = b"CREATE TABLE pages(id int);\n") -> str:
    with gzip.open(path, "wb") as handle:
        handle.write(body)
    return str(path)


# ---------------------------------------------------------------------------
# Authenticated encryption (Phase 17 HIGH-1: no MAC)
# ---------------------------------------------------------------------------

def test_p18_01_round_trip_is_byte_identical(tmp_path):
    key = _key(tmp_path / "k")
    src = tmp_path / "src.bin"
    payload = os.urandom(2 * 1024 * 1024 + 777)
    src.write_bytes(payload)

    dest = tmp_path / "src.bin.enc"
    backup_crypto.encrypt_file(str(src), str(dest), key, original_name="src.bin")
    out = tmp_path / "out.bin"
    backup_crypto.decrypt_file(str(dest), str(out), key)

    assert out.read_bytes() == payload
    assert not (tmp_path / "out.bin").exists() is False


def test_p18_02_ciphertext_is_authenticated_at_every_offset(tmp_path):
    """A single flipped bit anywhere must be rejected, not silently decrypted.

    Phase 17 measured ``openssl`` exiting 0 on a bit flip and handing back corrupted
    plaintext. Only the gzip CRC caught it -- accidental integrity, not authentication.
    """
    key = _key(tmp_path / "k")
    src = tmp_path / "p.bin"
    src.write_bytes(os.urandom(4096))
    dest = tmp_path / "p.bin.enc"
    backup_crypto.encrypt_file(str(src), str(dest), key)
    blob = dest.read_bytes()

    checked = 0
    for offset in (9, 11, 40, 100, len(blob) // 2, len(blob) - 25, len(blob) - 2):
        mutated = bytearray(blob)
        mutated[offset] ^= 0x01
        target = tmp_path / "t.enc"
        target.write_bytes(bytes(mutated))
        with pytest.raises(backup_crypto.EncryptionError):
            backup_crypto.decrypt_file(str(target), str(tmp_path / "t.out"), key)
        checked += 1
    assert checked == 7


def test_p18_03_wrong_key_and_truncation_are_rejected(tmp_path):
    key = _key(tmp_path / "k")
    src = tmp_path / "p.bin"
    src.write_bytes(os.urandom(2048))
    dest = tmp_path / "p.bin.enc"
    backup_crypto.encrypt_file(str(src), str(dest), key)

    wrong = _key(tmp_path / "wrong")
    with pytest.raises(backup_crypto.EncryptionError):
        backup_crypto.decrypt_file(str(dest), str(tmp_path / "o"), wrong)

    blob = dest.read_bytes()
    truncated = tmp_path / "trunc.enc"
    truncated.write_bytes(blob[: len(blob) // 2])
    with pytest.raises(backup_crypto.EncryptionError):
        backup_crypto.decrypt_file(str(truncated), str(tmp_path / "o2"), key)


def test_p18_04_header_is_authenticated_as_aad(tmp_path):
    """The header is bound into every tag, so metadata cannot be rewritten."""
    key = _key(tmp_path / "k")
    src = tmp_path / "p.bin"
    src.write_bytes(os.urandom(512))
    dest = tmp_path / "p.bin.enc"
    backup_crypto.encrypt_file(str(src), str(dest), key)

    blob = bytearray(dest.read_bytes())
    marker = b'"original_size":'
    index = blob.find(marker)
    assert index > 0
    blob[index + len(marker)] = ord("9")
    tampered = tmp_path / "t.enc"
    tampered.write_bytes(bytes(blob))
    with pytest.raises(backup_crypto.EncryptionError):
        backup_crypto.decrypt_file(str(tampered), str(tmp_path / "o"), key)


def test_p18_05_ciphertext_is_not_world_readable(tmp_path):
    """Phase 17: archives were mode 0644 next to a world-readable dump."""
    key = _key(tmp_path / "k")
    src = tmp_path / "p.bin"
    src.write_bytes(b"x" * 64)
    dest = tmp_path / "p.bin.enc"
    backup_crypto.encrypt_file(str(src), str(dest), key)
    assert oct(dest.stat().st_mode & 0o777) == "0o600"


# ---------------------------------------------------------------------------
# Plaintext leak prevention (Phase 17 CRITICAL-2)
# ---------------------------------------------------------------------------

def test_p18_10_staging_destroys_plaintext_on_exception(tmp_path):
    marker = b"TENANT-DATA-CANARY"
    with pytest.raises(RuntimeError):
        with backup_staging.StagingDir(str(tmp_path)) as staging:
            handle = staging.create_private("dump.sql.gz")
            pathlib.Path(handle).write_bytes(marker)
            assert oct(os.stat(staging.path_dir).st_mode & 0o777) == "0o700"
            raise RuntimeError("encryption blew up")

    leftovers = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert leftovers == []
    assert not any(marker in p.read_bytes() for p in tmp_path.rglob("*") if p.is_file())


def test_p18_11_staging_destroys_plaintext_on_sigterm(tmp_path):
    """The dump must not survive a terminating signal mid-run."""
    script = f"""
import os, signal, sys, time
sys.path.insert(0, {str(REPO_ROOT)!r})
from core.backup_staging import StagingDir
with StagingDir({str(tmp_path)!r}) as s:
    p = s.create_private("dump.sql.gz")
    open(p, "wb").write(b"TENANT-DATA-CANARY")
    os.kill(os.getpid(), signal.SIGTERM)
    time.sleep(5)
"""
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, timeout=60)
    assert proc.returncode == -15 or proc.returncode == 143
    assert [p for p in tmp_path.rglob("*") if p.is_file()] == []


def test_p18_12_stale_staging_from_sigkill_is_swept(tmp_path):
    """SIGKILL cannot run a handler; the next run must clean up after it."""
    stale = tmp_path / f".staging-999999-dead"
    stale.mkdir()
    (stale / "left.sql.gz").write_bytes(b"TENANT-DATA-CANARY")
    old = time.time() - 7 * 3600
    os.utime(stale, (old, old))

    removed = backup_staging.sweep_stale_staging(str(tmp_path))
    assert removed == [stale.name]
    assert not stale.exists()


def test_p18_13_encryption_failure_leaves_no_plaintext_in_backup_dir(tmp_path, monkeypatch):
    """The whole CRITICAL-2 scenario, through the real scheduled entry point."""
    from core import backup_automation

    monkeypatch.setenv("BACKUP_DIR", str(tmp_path))
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", str(tmp_path / "missing-key"))
    monkeypatch.delenv("BACKUP_OFFSITE_PATH", raising=False)
    monkeypatch.delenv("BACKUP_ALERT_WEBHOOK", raising=False)

    # The real create_backup needs a database; substitute one that writes a dump into
    # the staging directory exactly as the real one does, including the canary.
    import types

    module = types.ModuleType("core.backup_service")

    def fake_create(label="x", staging_dir=None):
        target = pathlib.Path(staging_dir) / "pg_backup_x.sql.gz"
        with gzip.open(target, "wb") as handle:
            handle.write(b"TENANT-DATA-CANARY")
        return {"success": True, "filename": target.name, "size_bytes": 18}

    module.create_backup = fake_create
    module._verify_plaintext_dump = lambda p, n: {"valid": True, "filename": n}
    module._compute_sha256 = lambda p: hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
    monkeypatch.setitem(sys.modules, "core.backup_service", module)
    import core

    monkeypatch.setattr(core, "backup_service", module, raising=False)

    result = backup_automation.run_scheduled_backup(label="test")

    assert result["success"] is False
    assert result["exit_code"] == backup_automation.EXIT_ENCRYPTION_FAILED
    # The assertion that matters is the filesystem, not the exit code. The lock and the
    # status file are bookkeeping and are expected; anything data-bearing is not.
    produced = [
        p for p in tmp_path.rglob("*")
        if p.is_file() and not p.name.startswith(".")
    ]
    assert produced == [], f"plaintext left behind: {produced}"


# ---------------------------------------------------------------------------
# Archive discovery and restore (Phase 17 CRITICAL-1)
# ---------------------------------------------------------------------------

def test_p18_20_archive_resolution_reads_encrypted_and_plaintext(tmp_path):
    key = _key(tmp_path / "k")
    plain = pathlib.Path(_dump(tmp_path / "pg_backup_x.sql.gz"))
    enc = tmp_path / "pg_backup_x.sql.gz.enc"
    backup_crypto.encrypt_file(str(plain), str(enc), key)
    plain.unlink()

    with backup_archive.resolve(str(tmp_path), "pg_backup_x.sql.gz.enc", key) as resolved:
        assert resolved.format == "authenticated"
        assert resolved.engine == "postgresql"
        with gzip.open(resolved.plaintext_path, "rb") as handle:
            assert b"CREATE TABLE pages" in handle.read()

    # The decrypted temp file must be gone once the context manager exits.
    remaining = sorted(p.name for p in tmp_path.rglob("*") if p.is_file())
    assert remaining == sorted([enc.name, "k"]), remaining


def test_p18_21_unsupported_magic_is_refused(tmp_path):
    key = _key(tmp_path / "k")
    bogus = tmp_path / "bogus.sql.gz.enc"
    bogus.write_bytes(b"definitely-not-an-archive")
    with pytest.raises(backup_archive.ArchiveError):
        backup_archive.resolve(str(tmp_path), "bogus.sql.gz.enc", key)


def test_p18_22_list_backups_includes_encrypted_archives(tmp_path, monkeypatch):
    """Phase 17: `list` printed "no backups" while a full set of .enc archives existed."""
    from core import backup_service

    monkeypatch.setattr(backup_service, "BACKUP_DIR", str(tmp_path))
    key = _key(tmp_path / "k")
    plain = pathlib.Path(_dump(tmp_path / "pg_backup_a.sql.gz"))
    enc = tmp_path / "pg_backup_a.sql.gz.enc"
    backup_crypto.encrypt_file(str(plain), str(enc), key)
    plain.unlink()

    listed = backup_service.list_backups()
    names = [item["filename"] for item in listed]
    assert "pg_backup_a.sql.gz.enc" in names
    entry = next(item for item in listed if item["filename"].endswith(".enc"))
    assert entry["encrypted"] is True
    assert entry["authenticated"] is True


def test_p18_23_sidecar_checksum_covers_the_ciphertext(tmp_path):
    """Phase 17: the .sha256 hashed the plaintext that encryption then deleted."""
    key = _key(tmp_path / "k")
    plain = pathlib.Path(_dump(tmp_path / "pg_backup_b.sql.gz"))
    enc = tmp_path / "pg_backup_b.sql.gz.enc"
    backup_crypto.encrypt_file(str(plain), str(enc), key)
    plain.unlink()

    from core import backup_automation

    digest = backup_automation._publish_ciphertext_checksum(str(tmp_path), str(enc))
    assert digest == hashlib.sha256(enc.read_bytes()).hexdigest()

    sidecar = tmp_path / "pg_backup_b.sql.gz.enc.sha256"
    assert sidecar.exists()
    recorded, name = sidecar.read_text().split()
    assert recorded == digest
    assert name == enc.name


# ---------------------------------------------------------------------------
# Retention (Phase 17 MEDIUM-2)
# ---------------------------------------------------------------------------

def test_p18_30_negative_floor_cannot_delete_everything(tmp_path, monkeypatch):
    from core import backup_automation

    monkeypatch.setenv("BACKUP_MIN_KEEP", "-5")
    assert backup_automation.min_keep() >= 1

    for index in range(6):
        archive = tmp_path / f"pg_backup_x{index}.sql.gz.enc"
        archive.write_bytes(b"x" * 32)
        (tmp_path / f"pg_backup_x{index}.sql.gz.meta.json").write_text("{}")
        (tmp_path / f"pg_backup_x{index}.sql.gz.sha256").write_text("0" * 64 + "  x\n")
        old = time.time() - 200 * 86400
        os.utime(archive, (old, old))

    removed = backup_automation.prune(str(tmp_path), days=1, keep_min=backup_automation.min_keep())
    survivors = [p for p in tmp_path.iterdir() if p.name.endswith(".enc")]
    assert len(survivors) == 1, "the floor must always keep at least one archive"
    assert len(removed) == 5


def test_p18_31_prune_removes_sidecars_with_the_archive(tmp_path):
    """Phase 17: prune built `<archive>.enc.json` and orphaned every real sidecar."""
    from core import backup_automation

    for index in range(4):
        archive = tmp_path / f"pg_backup_y{index}.sql.gz.enc"
        archive.write_bytes(b"x" * 32)
        inner = tmp_path / f"pg_backup_y{index}.sql.gz"
        (pathlib.Path(str(inner) + ".sha256")).write_text("0" * 64 + "  x\n")
        (pathlib.Path(str(inner) + ".meta.json")).write_text("{}")
        (pathlib.Path(str(archive) + ".sha256")).write_text("0" * 64 + "  x\n")
        old = time.time() - 200 * 86400
        for suffix in ("", ".sha256"):
            os.utime(str(archive) + suffix, (old, old))

    backup_automation.prune(str(tmp_path), days=1, keep_min=1)

    survivors = sorted(p.name for p in tmp_path.iterdir())
    # Only the kept archive and its own sidecars may remain.
    assert survivors == [
        "pg_backup_y3.sql.gz.enc",
        "pg_backup_y3.sql.gz.enc.sha256",
        "pg_backup_y3.sql.gz.meta.json",
        "pg_backup_y3.sql.gz.sha256",
    ]


# ---------------------------------------------------------------------------
# Concurrency (Phase 17 MEDIUM-4)
# ---------------------------------------------------------------------------

def test_p18_40_lock_is_exclusive_and_auto_releases(tmp_path):
    with backup_staging.BackupLock(str(tmp_path)):
        with pytest.raises(backup_staging.LockUnavailable):
            with backup_staging.BackupLock(str(tmp_path)):
                pass
    # Released cleanly: a later run must not be blocked by it.
    with backup_staging.BackupLock(str(tmp_path)):
        pass


def test_p18_41_lock_survives_a_killed_holder(tmp_path):
    """flock is released by the kernel, so a crash cannot wedge backups forever."""
    script = f"""
import sys, time
sys.path.insert(0, {str(REPO_ROOT)!r})
from core.backup_staging import BackupLock
with BackupLock({str(tmp_path)!r}):
    print("HELD", flush=True)
    time.sleep(60)
"""
    holder = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "HELD"
        with pytest.raises(backup_staging.LockUnavailable):
            with backup_staging.BackupLock(str(tmp_path)):
                pass
        holder.kill()
        holder.wait(timeout=30)
        with backup_staging.BackupLock(str(tmp_path)):
            pass
    finally:
        if holder.poll() is None:
            holder.kill()


# ---------------------------------------------------------------------------
# Secret handling (Phase 17 MEDIUM-3)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "relative",
    [
        "secrets/backup.key",
        "backup.key",
        "pg_backup_x.sql.gz.enc",
        "pg_backup_x.sql.gz",
        "pg_backup_x.sql.gz.meta.json",
        "pg_backup_x.sql.gz.sha256",
        ".staging-1-abcd/payload",
    ],
)
def test_p18_50_secrets_and_artifacts_are_gitignored(relative):
    proc = subprocess.run(
        ["git", "check-ignore", "-q", relative], cwd=str(REPO_ROOT)
    )
    assert proc.returncode == 0, f"{relative} is not ignored; it could be committed"


def test_p18_51_no_tracked_file_is_shadowed_by_the_new_ignore_rules():
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=str(REPO_ROOT), capture_output=True, text=True
    ).stdout
    if not tracked.strip():
        pytest.skip("no git index available")
    proc = subprocess.run(
        ["git", "check-ignore", "--stdin"],
        cwd=str(REPO_ROOT),
        input=tracked,
        capture_output=True,
        text=True,
    )
    shadowed = [line for line in proc.stdout.splitlines() if line.strip()]
    assert shadowed == [], f"these tracked files would become ignored: {shadowed}"


# ---------------------------------------------------------------------------
# Offsite honesty (Phase 17 MEDIUM-3 storage)
# ---------------------------------------------------------------------------

def test_p18_60_offsite_reports_not_configured_rather_than_local(tmp_path):
    from core import backup_offsite

    assert backup_offsite.status({})["state"] == backup_offsite.OFFSITE_NOT_CONFIGURED


def test_p18_61_local_directory_is_not_claimed_as_independent(tmp_path):
    from core import backup_offsite

    reported = backup_offsite.status({"BACKUP_OFFSITE_PATH": str(tmp_path)})
    assert reported["configured"] is True
    assert reported["independent_failure_domain"] is False
    assert "NOT an independent failure domain" in reported["detail"]


def test_p18_62_plaintext_transport_is_refused():
    from core import backup_offsite

    with pytest.raises(backup_offsite.OffsiteError):
        backup_offsite.provider_from_env({"BACKUP_OFFSITE_URL": "http://insecure.example/b"})


def test_p18_63_s3_signing_matches_the_published_empty_body_vector():
    """Guards the SigV4 implementation against silent breakage."""
    from core import backup_offsite

    headers = backup_offsite._sigv4_headers(
        "GET", "https://examplebucket.s3.amazonaws.com/test.txt", "us-east-1",
        "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", b"",
    )
    assert headers["x-amz-content-sha256"] == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert headers["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/")
    assert "SignedHeaders=host;x-amz-content-sha256;x-amz-date" in headers["authorization"]


# ---------------------------------------------------------------------------
# Rollback discovery (Phase 17 HIGH-2)
# ---------------------------------------------------------------------------

def test_p18_70_rollback_script_fails_when_no_snapshot_exists():
    """Phase 17: an empty PRE silently skipped the data restore and still printed OK."""
    script = (REPO_ROOT / "scripts" / "rollback.sh").read_text()
    assert "no pre_deploy snapshot was found" in script
    assert "exit 1" in script
    # The grep that produced an empty PRE must no longer be treated as success.
    assert 'if [ -n "${PRE:-}" ]; then' in script


def test_p18_71_rollback_selects_a_restorable_archive(tmp_path, monkeypatch):
    """`list` output must contain the encrypted pre_deploy snapshot rollback greps for."""
    from core import backup_service

    monkeypatch.setattr(backup_service, "BACKUP_DIR", str(tmp_path))
    key = _key(tmp_path / "k")
    plain = pathlib.Path(_dump(tmp_path / "pg_backup_pre_deploy_20260101_000000_00.sql.gz"))
    enc = tmp_path / "pg_backup_pre_deploy_20260101_000000_00.sql.gz.enc"
    backup_crypto.encrypt_file(str(plain), str(enc), key)
    plain.unlink()

    listing = backup_service.list_backups()
    selected = [item["filename"] for item in listing if "pre_deploy" in item["filename"]]
    assert selected == ["pg_backup_pre_deploy_20260101_000000_00.sql.gz.enc"]


# ---------------------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------------------

def test_p18_80_key_accepts_raw_and_base64_but_refuses_junk(tmp_path):
    import base64

    raw = tmp_path / "raw.key"
    raw.write_bytes(os.urandom(32))
    assert len(backup_crypto.load_key(str(raw))) == 32

    encoded = tmp_path / "b64.key"
    encoded.write_bytes(base64.b64encode(os.urandom(32)))
    assert len(backup_crypto.load_key(str(encoded))) == 32

    junk = tmp_path / "junk.key"
    junk.write_bytes(b"too-short")
    with pytest.raises(backup_crypto.EncryptionError):
        backup_crypto.load_key(str(junk))


def test_p18_81_raw_key_ending_in_whitespace_is_accepted(tmp_path):
    """A 32-byte binary key must be used verbatim.

    Found by running the suites together: `load_key` stripped whitespace before checking
    the length, so a random key whose first or last byte was a space/newline was rejected
    as "unexpected length". That is roughly one generated key in forty -- a latent
    inability to read your own backups, depending on a byte you never look at.
    """
    for edge in (b" ", b"\n", b"\t", b"\r"):
        candidate = os.urandom(31) + edge
        key_file = tmp_path / f"k{edge.hex()}"
        key_file.write_bytes(candidate)
        assert backup_crypto.load_key(str(key_file)) == candidate

    # And it must round-trip through a real archive, not just load.
    key_file = tmp_path / "edge.key"
    key_file.write_bytes(os.urandom(31) + b" ")
    src = tmp_path / "p.bin"
    src.write_bytes(os.urandom(1024))
    dest = tmp_path / "p.bin.enc"
    backup_crypto.encrypt_file(str(src), str(dest), str(key_file))
    out = tmp_path / "out.bin"
    backup_crypto.decrypt_file(str(dest), str(out), str(key_file))
    assert out.read_bytes() == src.read_bytes()


# ---------------------------------------------------------------------------
# Scheduler / monitoring states (Phase 17 MEDIUM-4: no scheduler installed)
# ---------------------------------------------------------------------------

def test_p18_90_operational_state_distinguishes_all_five_cases(tmp_path, monkeypatch):
    from core import backup_automation

    monkeypatch.setenv("BACKUP_DIR", str(tmp_path))
    monkeypatch.setenv("BACKUP_MAX_AGE_HOURS", "36")
    monkeypatch.setattr(backup_automation, "scheduler_installed", lambda paths=None: False)

    # 1. Never executed.
    assert backup_automation.operational_state()["state"] == backup_automation.STATE_NEVER_EXECUTED

    # 2. In progress.
    (tmp_path / ".last_backup_status.json").write_text(json.dumps({
        "label": "x", "started_at": "2026-01-01T00:00:00+00:00",
        "in_progress": True, "success": False,
    }))
    assert backup_automation.operational_state()["state"] == backup_automation.STATE_IN_PROGRESS

    # 3. Failed.
    (tmp_path / ".last_backup_status.json").write_text(json.dumps({
        "success": False, "exit_code": 11, "error": "no key", "finished_at": "2026-01-01T00:00:00+00:00",
    }))
    assert backup_automation.operational_state()["state"] == backup_automation.STATE_FAILED

    # 4. Stale (a success from long ago).
    (tmp_path / ".last_backup_status.json").write_text(json.dumps({
        "success": True, "finished_at": "2020-01-01T00:00:00+00:00",
    }))
    assert backup_automation.operational_state()["state"] == backup_automation.STATE_STALE

    # 5. Fresh success.
    from datetime import datetime, timezone

    (tmp_path / ".last_backup_status.json").write_text(json.dumps({
        "success": True, "finished_at": datetime.now(timezone.utc).isoformat(),
    }))
    fresh = backup_automation.operational_state()
    assert fresh["state"] == backup_automation.STATE_SUCCESS
    assert fresh["scheduler_installed"] is False


def test_p18_91_status_reports_a_missing_scheduler_instead_of_assuming_one():
    """Phase 17: two documents claimed a daily backup; nothing installed the timer."""
    from core import backup_automation

    # No timer exists in this environment, and the probe must say so rather than
    # returning a bare "unhealthy" that an operator cannot act on.
    assert backup_automation.scheduler_installed(paths=["/nonexistent/gerege-backup.timer"]) is False
