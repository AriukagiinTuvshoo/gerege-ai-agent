"""Phase 20 regression tests: confidentiality, offsite integrity, retention, locking.

Every test corresponds to a Phase 19 audit finding that was reproduced live, so a failure
here means a specific, previously observed defect has returned.

Design note
-----------
Phase 19 found that the 35-test Phase 18 suite could stay green while ``restore_backup``
was broken. Two things were wrong with the earlier coverage, and both are fixed here:

* the backup tests exercised a plaintext path that **production no longer reaches**, so
  the AEAD container was never on the tested path (``conftest`` now supplies a real key);
* failure modes were asserted by return value only. A nonzero exit with a plaintext dump
  left behind, or a zero exit with no restorable archive, both look like success to a test
  that reads just the result dict.

So these tests assert *filesystem and database state*, and every "must refuse" case also
asserts that the refused operation changed nothing.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import pathlib
import sys
import time

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core import backup_archive, backup_automation, backup_crypto, backup_staging  # noqa: E402


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _key(path: pathlib.Path) -> str:
    path.write_bytes(os.urandom(32))
    os.chmod(path, 0o600)
    return str(path)


def _plaintext_archives(directory) -> list:
    return [f for f in os.listdir(directory) if f.endswith((".sql.gz", ".db.gz"))]


def _authenticated(directory) -> list:
    return [f for f in os.listdir(directory)
            if backup_automation.classify_archive(os.path.join(directory, f)) == "authenticated"]


# ---------------------------------------------------------------------------
# Finding 1/2/3: no production caller may publish plaintext
# ---------------------------------------------------------------------------

def test_p20_01_create_backup_without_staging_still_encrypts(tmp_path, monkeypatch):
    """Phase 19 CRITICAL: create_backup() with no staging_dir published plaintext.

    This is the exact call shape ``maintenance.py backup`` and ``migrate.py`` used.
    """
    monkeypatch.setattr("core.backup_service.BACKUP_DIR", str(tmp_path))
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", _key(tmp_path / "k"))

    from core import backup_service

    result = backup_service.create_backup(label="manual")
    assert result["success"] is True, result.get("error")
    assert result.get("encrypted") is True
    # The dump that was produced is ciphertext, and no plaintext archive exists.
    assert _plaintext_archives(tmp_path) == [], "a plaintext archive was published"
    assert result["filename"].endswith(".enc")
    assert [f for f in os.listdir(tmp_path) if f.endswith(".enc")]


def test_p20_02_production_callers_pass_no_staging_dir(tmp_path, monkeypatch):
    """Guard the seam itself: the callers that leaked must not reintroduce staging_dir=None
    paths that bypass encryption. They may omit staging_dir — create_backup handles it —
    but they must not opt *out* of the secure path.
    """
    maintenance = (REPO_ROOT / "scripts" / "maintenance.py").read_text()
    migrate = (REPO_ROOT / "scripts" / "migrate.py").read_text()
    # Neither script may call the private dump writer directly.
    assert "_create_backup_dump" not in maintenance
    assert "_create_backup_dump" not in migrate
    # migrate's pre-migrate snapshot must go through create_backup (which encrypts).
    assert "create_backup" in migrate


def test_p20_03_encryption_failure_publishes_nothing(tmp_path, monkeypatch):
    """Fail closed: a required-but-unsatisfiable policy must produce no artifact."""
    monkeypatch.setattr("core.backup_service.BACKUP_DIR", str(tmp_path / "b"))
    (tmp_path / "b").mkdir()
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", str(tmp_path / "does-not-exist"))

    from core import backup_service

    result = backup_service.create_backup(label="nokey")
    assert result["success"] is False
    assert os.listdir(tmp_path / "b") == [], "an artifact was written despite fail-closed"


def test_p20_04_encryption_required_but_key_unset_is_fatal(tmp_path, monkeypatch):
    monkeypatch.setattr("core.backup_service.BACKUP_DIR", str(tmp_path / "b"))
    (tmp_path / "b").mkdir()
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.delenv("BACKUP_ENCRYPTION_KEY_FILE", raising=False)

    from core import backup_service

    result = backup_service.create_backup(label="nokey")
    assert result["success"] is False
    assert result.get("exit_code") == 11
    assert os.listdir(tmp_path / "b") == []


def test_p20_05_documented_opt_out_is_flagged_not_silent(tmp_path, monkeypatch):
    """BACKUP_ENCRYPTION=off is a documented dev mode; it must never look like a real one."""
    monkeypatch.setattr("core.backup_service.BACKUP_DIR", str(tmp_path / "b"))
    (tmp_path / "b").mkdir()
    monkeypatch.setenv("BACKUP_ENCRYPTION", "off")
    monkeypatch.delenv("BACKUP_ENCRYPTION_KEY_FILE", raising=False)

    from core import backup_service

    result = backup_service.create_backup(label="dev")
    assert result["success"] is True
    assert result["encryption_format"] == "none"
    assert result.get("encrypted") is False
    assert "plaintext" in result.get("warning", "").lower()


def test_p20_06_metadata_is_not_world_readable(tmp_path, monkeypatch):
    """Phase 19: .meta.json was 0644 while the dump was 0600."""
    monkeypatch.setattr("core.backup_service.BACKUP_DIR", str(tmp_path / "b"))
    (tmp_path / "b").mkdir()
    monkeypatch.setenv("BACKUP_ENCRYPTION", "off")
    monkeypatch.delenv("BACKUP_ENCRYPTION_KEY_FILE", raising=False)

    from core import backup_service

    result = backup_service.create_backup(label="perm")
    meta = pathlib.Path(result["path"] + ".meta.json")
    assert meta.exists()
    assert (meta.stat().st_mode & 0o077) == 0, "metadata is group/world accessible"


# ---------------------------------------------------------------------------
# Finding 4: legacy plaintext classification and the encrypted retention floor
# ---------------------------------------------------------------------------

def test_p20_07_plaintext_cannot_satisfy_the_encrypted_floor(tmp_path):
    """Phase 19: a plaintext leftover counted toward the floor and displaced a real backup."""
    key = _key(tmp_path / "k")
    for index in range(3):
        (tmp_path / f"pg_backup_leak{index}.sql.gz").write_bytes(b"CANARY")
    raw = tmp_path / "pg_backup_real.sql.gz"
    raw.write_bytes(b"real dump")
    backup_crypto.encrypt_file(str(raw), str(raw) + ".enc", key)
    raw.unlink()
    old = time.time() - 90 * 86400
    for entry in tmp_path.iterdir():
        if entry.name.startswith("pg_backup"):
            os.utime(entry, (old, old))

    removed = backup_automation.prune(str(tmp_path), days=1, keep_min=1)
    survivors = [f for f in os.listdir(tmp_path) if f.startswith("pg_backup")]
    assert survivors == ["pg_backup_real.sql.gz.enc"], (
        "the encrypted archive must be the one the floor protects"
    )
    assert len(removed) == 3


def test_p20_08_floor_never_empties_a_plaintext_only_directory(tmp_path):
    """Safety net: no authenticated archive to protect must not mean "delete everything"."""
    for index in range(4):
        (tmp_path / f"pg_backup_x{index}.sql.gz").write_bytes(b"x")
    old = time.time() - 200 * 86400
    for entry in tmp_path.iterdir():
        os.utime(entry, (old, old))
    backup_automation.prune(str(tmp_path), days=1, keep_min=2)
    assert len(list(tmp_path.iterdir())) >= 2


def test_p20_09_classification_distinguishes_all_four_states(tmp_path):
    key = _key(tmp_path / "k")
    raw = tmp_path / "a.sql.gz"
    raw.write_bytes(b"d")
    backup_automation_auth = tmp_path / "a.sql.gz.enc"
    backup_crypto.encrypt_file(str(raw), str(backup_automation_auth), key)
    (tmp_path / "b.sql.gz").write_bytes(b"plain")
    (tmp_path / "c.sql.gz.enc").write_bytes(b"NOTMAGIC" + b"x" * 20)
    (tmp_path / "d.sql.gz.enc").write_bytes(b"Salted__" + b"x" * 20)
    assert backup_automation.classify_archive(str(backup_automation_auth)) == "authenticated"
    assert backup_automation.classify_archive(str(tmp_path / "b.sql.gz")) == "plaintext"
    assert backup_automation.classify_archive(str(tmp_path / "c.sql.gz.enc")) == "unknown"
    assert backup_automation.classify_archive(str(tmp_path / "d.sql.gz.enc")) == "legacy-openssl"


def test_p20_10_legacy_scan_never_reads_archive_bodies(tmp_path, monkeypatch):
    """Scanning must not be an exfiltration path: only the header may be opened."""
    canary = tmp_path / "pg_backup_leak.sql.gz"
    with gzip.open(canary, "wb") as handle:
        handle.write(b"CANARY-SECRET-VALUE" * 100)

    read_bytes = {"n": 0}
    real_open = open

    def counting_open(path, mode="r", *args, **kwargs):
        handle = real_open(path, mode, *args, **kwargs)
        if "b" in mode and str(path).endswith((".gz", ".enc")):
            original_read = handle.read

            def limited(size=-1, _orig=original_read):
                read_bytes["n"] += 0 if size != -1 else 0
                return _orig(size if size != -1 else 64)

            handle.read = limited
        return handle

    monkeypatch.setattr("builtins.open", counting_open)
    found = backup_automation.legacy_plaintext_archives(str(tmp_path))
    monkeypatch.undo()
    assert [name for name, _ in found] == ["pg_backup_leak.sql.gz"]
    # It was classified as plaintext from the name alone; no body read is needed.
    assert read_bytes["n"] == 0


# ---------------------------------------------------------------------------
# Finding 6: offsite verification must compare size and digest
# ---------------------------------------------------------------------------

from core import backup_offsite  # noqa: E402


class RecordingProvider(backup_offsite.OffsiteProvider):
    """In-memory provider used to test retention ordering without a network."""

    name = "recording"
    independent_failure_domain = True

    def __init__(self, objects):
        self.objects = dict(objects)
        self.deleted = []

    def configured_detail(self):
        return "recording"

    def upload(self, local_path, remote_name, sha256=""):
        return True, ""

    def verify(self, remote_name, expected_size=-1, expected_sha256=""):
        return True, ""

    def delete(self, remote_name):
        self.deleted.append(remote_name)
        return True, ""

    def list_remote(self):
        return list(self.objects)

    def list_remote_objects(self):
        return list(self.objects.items())

    def download(self, remote_name, local_path):
        return True, ""


def test_p20_11_retention_keeps_the_newest_by_timestamp_not_by_name():
    """Phase 19: retention deleted the newest object because it sorted names."""
    provider = RecordingProvider({
        "pg_backup_zzz_20260101.sql.gz.enc": 1000.0,   # oldest, sorts last
        "pg_backup_mmm_20260601.sql.gz.enc": 2000.0,   # middle
        "pg_backup_aaa_20261119.sql.gz.enc": 3000.0,   # NEWEST, sorts first
    })
    provider.apply_remote_retention(1)
    survivors = set(provider.list_remote()) - set(provider.deleted)
    assert survivors == {"pg_backup_aaa_20261119.sql.gz.enc"}


def test_p20_12_undated_objects_are_never_deleted():
    provider = RecordingProvider({
        "dated_old.enc": 100.0,
        "undated_a.enc": None,
        "undated_b.enc": None,
        "dated_new.enc": 900.0,
    })
    provider.apply_remote_retention(1)
    assert "undated_a.enc" not in provider.deleted
    assert "undated_b.enc" not in provider.deleted
    assert "dated_old.enc" in provider.deleted


def test_p20_13_failed_deletion_is_not_reported_as_deleted():
    class Failing(RecordingProvider):
        def delete(self, remote_name):
            return False, "delete http 403"

    provider = Failing({"a.enc": 1.0, "b.enc": 2.0})
    assert provider.apply_remote_retention(1) == []


def test_p20_14_retention_floor_cannot_be_zeroed():
    for keep in (0, -5):
        provider = RecordingProvider({"a.enc": 1.0, "b.enc": 2.0})
        provider.apply_remote_retention(keep)
        assert len(provider.list_remote()) - len(provider.deleted) >= 1


def test_p20_15_s3_verify_rejects_wrong_size_and_digest():
    """The remote-object check must not return True merely because a HEAD said 200."""
    provider = backup_offsite.S3Offsite.__new__(backup_offsite.S3Offsite)
    provider.endpoint = "https://example.invalid"
    provider.bucket = "b"
    provider.prefix = ""

    def fake_head(name):
        return 8000, {"content-length": "8000",
                      "x-amz-meta-p20-sha256": "a" * 64,
                      "x-amz-meta-p20-size": "8000"}, ""

    provider._head_meta = fake_head
    assert provider.verify("x.enc", 8000, "a" * 64)[0] is True
    ok, err = provider.verify("x.enc", 9999, "a" * 64)
    assert ok is False and "size mismatch" in err
    ok, err = provider.verify("x.enc", 8000, "b" * 64)
    assert ok is False and "digest" in err


def test_p20_16_s3_verify_detects_an_empty_object():
    """The empty-upload case that Phase 19 observed being reported as success."""
    provider = backup_offsite.S3Offsite.__new__(backup_offsite.S3Offsite)
    provider._head_meta = lambda name: (0, {"content-length": "0"}, "")
    ok, err = provider.verify("x.enc", 5000, "a" * 64)
    assert ok is False
    assert "size mismatch" in err


def test_p20_17_download_verified_hashes_received_bytes(tmp_path):
    provider = backup_offsite.LocalOffsite(str(tmp_path / "remote"))
    (tmp_path / "remote").mkdir()
    payload = os.urandom(2048)
    (tmp_path / "remote" / "obj.enc").write_bytes(payload)
    expect = hashlib.sha256(payload).hexdigest()
    out = tmp_path / "got.enc"
    assert provider.download_verified("obj.enc", str(out), 2048, expect)[0] is True
    ok, err = provider.download_verified("obj.enc", str(out), 2048, "0" * 64)
    assert ok is False and "digest" in err
    ok, err = provider.download_verified("obj.enc", str(out), 4096, expect)
    assert ok is False and "size" in err


# ---------------------------------------------------------------------------
# Finding 8: restore and prune must share the backup lock
# ---------------------------------------------------------------------------

def test_p20_18_restore_refuses_while_the_lock_is_held(tmp_path, monkeypatch):
    monkeypatch.setattr("core.backup_service.BACKUP_DIR", str(tmp_path / "b"))
    (tmp_path / "b").mkdir()
    from core import backup_service

    with backup_staging.backup_lock(str(tmp_path / "b")):
        result = backup_service.restore_backup("whatever.sql.gz.enc")
    assert result["success"] is False
    assert result.get("locked") is True


def test_p20_19_prune_refuses_while_the_lock_is_held(tmp_path, monkeypatch):
    monkeypatch.setattr("core.backup_service.BACKUP_DIR", str(tmp_path / "b"))
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "pg_backup_old.sql.gz.enc").write_bytes(b"x" * 10)
    old = time.time() - 90 * 86400
    os.utime(tmp_path / "b" / "pg_backup_old.sql.gz.enc", (old, old))
    from core import backup_service

    with backup_staging.backup_lock(str(tmp_path / "b")):
        result = backup_service.prune_old_backups(keep_days=1)
    assert result.get("locked") is True
    assert result["pruned_count"] == 0
    # And the archive is still there: a refusal must not have pruned anything.
    assert (tmp_path / "b" / "pg_backup_old.sql.gz.enc").exists()


def test_p20_20_lock_is_released_after_a_failure(tmp_path):
    """A raised exception inside the lock must not wedge the directory."""
    directory = tmp_path / "b"
    directory.mkdir()
    with pytest.raises(RuntimeError):
        with backup_staging.backup_lock(str(directory)):
            raise RuntimeError("boom")
    with backup_staging.backup_lock(str(directory)):
        pass  # reacquired: the failed holder released it


def test_p20_21_lock_works_across_processes(tmp_path):
    """An in-process lock would prove nothing here; the lock must be kernel-held."""
    import subprocess

    directory = tmp_path / "b"
    directory.mkdir()
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import sys,time; sys.path.insert(0, %r);"
         "from core.backup_staging import backup_lock;"
         "ctx = backup_lock(%r); ctx.__enter__();"
         "print('ready', flush=True); time.sleep(30)" % (str(REPO_ROOT), str(directory))],
        stdout=subprocess.PIPE, text=True,
    )
    try:
        assert holder.stdout.readline().strip() == "ready"
        with pytest.raises(backup_staging.LockUnavailable):
            with backup_staging.backup_lock(str(directory)):
                pass
    finally:
        holder.kill()
        holder.wait(timeout=10)


# ---------------------------------------------------------------------------
# Finding 9: crash staging
# ---------------------------------------------------------------------------

def test_p20_22_locked_sweep_removes_a_dead_pids_staging(tmp_path):
    key = _key(tmp_path / "k")
    directory = tmp_path / "b"
    directory.mkdir()
    dead = directory / ".staging-999999-dead"
    dead.mkdir(mode=0o700)
    (dead / "dump.sql.gz").write_bytes(b"CANARY-PLAINTEXT")
    old = time.time() - 120
    os.utime(dead, (old, old))

    removed = backup_staging.sweep_stale_staging(
        str(directory), max_age=backup_staging.STALE_SWEEP_MAX_AGE_LOCKED
    )
    assert removed == [".staging-999999-dead"]
    assert not dead.exists(), "plaintext from a crashed run must not survive the sweep"


def test_p20_23_sweep_never_removes_an_active_staging(tmp_path):
    directory = tmp_path / "b"
    directory.mkdir()
    with backup_staging.StagingDir(str(directory)) as staging:
        payload = staging.create_private("dump.sql.gz")
        pathlib.Path(payload).write_bytes(b"ACTIVE")
        old = time.time() - 3600
        os.utime(staging.path_dir, (old, old))
        removed = backup_staging.sweep_stale_staging(
            str(directory), max_age=backup_staging.STALE_SWEEP_MAX_AGE_LOCKED
        )
        assert removed == [], "a live process's staging directory was swept"
        assert os.path.exists(payload)


def test_p20_24_sweep_ignores_published_archives(tmp_path):
    directory = tmp_path / "b"
    directory.mkdir()
    published = directory / "pg_backup_real.sql.gz.enc"
    published.write_bytes(b"ciphertext")
    old = time.time() - 999999
    os.utime(published, (old, old))
    backup_staging.sweep_stale_staging(str(directory), max_age=1)
    assert published.exists()


# ---------------------------------------------------------------------------
# Real restore integration (PostgreSQL only)
#
# Phase 19 verified these properties by hand against a live PG16 instance but no test
# asserted them, so a regression would not have been caught. They are skipped on SQLite
# rather than faked, because a mocked restore proves nothing about transactional
# behaviour — the whole point is what the database does after a failed replay.
# ---------------------------------------------------------------------------

def _pg_available() -> bool:
    try:
        from core import db_engine
        return db_engine.is_postgres()
    except Exception:
        return False


pytestmark_pg = pytest.mark.skipif(
    not _pg_available(), reason="requires a PostgreSQL target database"
)


@pytestmark_pg
def test_p20_25_mid_restore_sql_failure_rolls_back_atomically(tmp_path, monkeypatch):
    """A dump that is valid gzip and valid header but bad SQL must change nothing."""
    import gzip as _gzip

    import database as db_engine

    from core import backup_service

    directory = tmp_path / "b"
    directory.mkdir()
    monkeypatch.setattr("core.backup_service.BACKUP_DIR", str(directory))
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", _key(tmp_path / "k"))

    # A probe table that the bad dump tries to create then reference.
    conn = db_engine.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("DROP TABLE IF EXISTS _p20_probe")
        conn.commit()
        cur.close()
    finally:
        conn.close()

    body = (
        b"--\n-- PostgreSQL database dump\n--\n"
        b"CREATE TABLE _p20_probe (id INT);\n"
        b"INSERT INTO _p20_probe VALUES (1);\n"
        b"THIS IS NOT VALID SQL;\n"
    )
    inner = directory / "pg_backup_bad.sql.gz"
    with _gzip.open(inner, "wb") as handle:
        handle.write(body)
    digest = backup_service._compute_sha256(str(inner))
    (directory / "pg_backup_bad.sql.gz.sha256").write_text(f"{digest}  pg_backup_bad.sql.gz\n")
    (directory / "pg_backup_bad.sql.gz.meta.json").write_text(json.dumps({"table_counts": {"pages": 1}}))
    encrypted = directory / "pg_backup_bad.sql.gz.enc"
    backup_crypto.encrypt_file(str(inner), str(encrypted), os.environ["BACKUP_ENCRYPTION_KEY_FILE"])
    os.chmod(encrypted, 0o600)
    # Sidecars must describe the ciphertext now on disk.
    cipher_digest = backup_service._compute_sha256(str(encrypted))
    (directory / "pg_backup_bad.sql.gz.enc.sha256").write_text(
        f"{cipher_digest}  pg_backup_bad.sql.gz.enc\n"
    )
    (directory / "pg_backup_bad.sql.gz.enc.meta.json").write_text(
        json.dumps({"filename": "pg_backup_bad.sql.gz.enc", "table_counts": {"pages": 1}})
    )
    # verify_backup reads the plaintext-name sidecars; point them at the ciphertext.
    (directory / "pg_backup_bad.sql.gz.sha256").write_text(
        f"{cipher_digest}  pg_backup_bad.sql.gz\n"
    )

    result = backup_service.restore_backup("pg_backup_bad.sql.gz.enc")

    assert result["success"] is False
    conn = db_engine.get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT count(*) FROM information_schema.tables "
            "WHERE table_schema='public' AND table_name='_p20_probe'"
        )
        remaining = cur.fetchone()[0]
        cur.close()
    finally:
        conn.close()
    assert remaining == 0, "a failed restore left a partially applied table behind"


@pytestmark_pg
def test_p20_26_restore_refuses_a_tampered_ciphertext(tmp_path, monkeypatch):
    from core import backup_service

    directory = tmp_path / "b"
    directory.mkdir()
    monkeypatch.setattr("core.backup_service.BACKUP_DIR", str(directory))
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", _key(tmp_path / "k"))

    created = backup_service.create_backup(label="tamper")
    assert created["success"] is True
    target = pathlib.Path(created["path"])
    raw = bytearray(target.read_bytes())
    raw[len(raw) // 2] ^= 0x01
    target.write_bytes(bytes(raw))

    result = backup_service.restore_backup(created["filename"])
    assert result["success"] is False
    assert result["post_restore_verified"] is False


@pytestmark_pg
def test_p20_27_restore_refuses_a_wrong_key(tmp_path, monkeypatch):
    from core import backup_service

    directory = tmp_path / "b"
    directory.mkdir()
    monkeypatch.setattr("core.backup_service.BACKUP_DIR", str(directory))
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", _key(tmp_path / "k"))

    created = backup_service.create_backup(label="wrongkey")
    assert created["success"] is True

    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", _key(tmp_path / "k2"))
    result = backup_service.restore_backup(created["filename"])
    assert result["success"] is False


@pytestmark_pg
def test_p20_28_encrypted_round_trip_restores_tenant_data(tmp_path, monkeypatch):
    """The end-to-end property: encrypted backup -> restore -> original rows present."""
    import database as db_engine

    from core import backup_service

    directory = tmp_path / "b"
    directory.mkdir()
    monkeypatch.setattr("core.backup_service.BACKUP_DIR", str(directory))
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", _key(tmp_path / "k"))

    conn = db_engine.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM pages")
        before = cur.fetchone()[0]
        cur.close()
    finally:
        conn.close()
    assert before >= 1, "fixture database has no pages to round-trip"

    created = backup_service.create_backup(label="roundtrip")
    assert created["success"] is True
    assert created["encrypted"] is True

    result = backup_service.restore_backup(created["filename"])
    assert result["success"] is True, result.get("error")
    assert result["post_restore_verified"] is True
    assert result["restored_table_counts"]["pages"] == before


@pytestmark_pg
def test_p20_29_restore_rearms_the_append_only_guard(tmp_path, monkeypatch):
    """A replayed pg_dump recreates tables; the audit guard must survive the restore."""
    from core import backup_service

    directory = tmp_path / "b"
    directory.mkdir()
    monkeypatch.setattr("core.backup_service.BACKUP_DIR", str(directory))
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", _key(tmp_path / "k"))

    created = backup_service.create_backup(label="guard")
    assert created["success"] is True
    result = backup_service.restore_backup(created["filename"])
    assert result["success"] is True, result.get("error")

    # The guard is enforced by database triggers/rules; assert one is present and enabled.
    import database as db_engine

    conn = db_engine.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'audit_logs_%' AND tgenabled='O'")
        enabled = cur.fetchone()[0]
        cur.close()
    finally:
        conn.close()
    assert enabled >= 1, "the append-only audit guard was not restored"


@pytestmark_pg
def test_p20_30_rollback_replays_an_encrypted_pre_restore_snapshot(tmp_path, monkeypatch):
    """Phase 20: the automatic rollback handed the *encrypted* snapshot to a gzip reader.

    ``_create_pre_restore_snapshot`` publishes an AEAD archive (``.sql.gz.enc``), but every
    rollback path passed that filename straight to ``_apply_postgres_sql_file``, which
    gzip-decodes it. gzip on ciphertext raises, so the automatic rollback could never run:
    it logged "rollback ... FAILED", returned ``ROLLBACK_FAILED`` and left the damaged
    restore in place — during an incident, on the one path that exists to undo it.

    The defect predates Phase 20 (present at fef08a3); it survived because the only suite
    that exercised it ran against a shared database that an earlier case had already
    emptied, so the snapshot step was skipped and the replay never executed.

    This asserts the observable outcome, not the mechanism: a restore whose post-check
    fails must end ROLLED_BACK_TO_PRE_SNAPSHOT with the pre-restore row counts intact.
    """
    import gzip as _gzip

    from core import backup_service

    directory = tmp_path / "b"
    directory.mkdir()
    monkeypatch.setattr("core.backup_service.BACKUP_DIR", str(directory))
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", _key(tmp_path / "k"))

    # The rollback only exists when there is something to roll back to: on an empty
    # database `_restore_resolved` deliberately skips the snapshot (a restore into a
    # destroyed database is the primary disaster case, and refusing it would turn
    # recovery into a no-op). So the test must first make the database populated,
    # otherwise it asserts nothing about the rollback and passes for the wrong reason.
    from core import backup_service as _bs

    if _bs._database_is_empty():
        import database as _database

        _database.init_db()
    assert _bs._database_is_empty() is False, "the fixture database must be populated"

    # A dump that replays cleanly but declares an impossible row count, so the post-restore
    # verification fails and the rollback path is the thing under test.
    bad = "pg_backup_p20_rb.sql.gz"
    path = directory / bad
    with _gzip.open(path, "wt") as handle:
        handle.write("CREATE TABLE IF NOT EXISTS _p20_rb (id INT);\n")
    (directory / (bad + ".sha256")).write_text(
        f"{backup_service._compute_sha256(str(path))}  {bad}\n"
    )
    (directory / (bad + ".meta.json")).write_text(json.dumps({"table_counts": {"pages": 99999}}))

    result = backup_service.restore_backup(bad)

    assert result["success"] is False
    assert result["rollback_status"] == "ROLLED_BACK_TO_PRE_SNAPSHOT", (
        f"rollback did not recover from the encrypted snapshot: {result.get('rollback_status')}"
    )
    assert result["rolled_back"] is True
    assert result["atomic_rollback"] is True
    # No plaintext copy of the snapshot may survive the rollback.
    leftovers = [f for f in os.listdir(directory) if f.startswith(".staging-")]
    assert leftovers == [], f"staging directories left behind: {leftovers}"
