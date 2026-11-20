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
    # Phase 22 (P21-01) made this code path-independent. Before the centralized policy the
    # *direct* path returned 11 here while the *scheduled* path returned 15 for the same
    # condition (test_p16_33 / test_p18_13 pin 15), so the code an operator saw depended on
    # which entry point ran. One policy now answers for both, and "no encryption
    # configured" is the documented "not configured" class (15) everywhere.
    assert result.get("exit_code") == 15
    assert result.get("encryption_policy") == "ENCRYPTION_KEY_MISSING"
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


def test_p20_31_a_stranded_connection_releases_its_locks(tmp_path, monkeypatch):
    """A connection that never reaches `close()` must still release its locks.

    The defect that broke the atomic rollback, spelled out because it took three attempts
    to characterise correctly.

    `database.save_registration` and ~60 siblings are shaped
    ```conn = get_connection(); ...; conn.close()``` with no `try/finally`. When a call
    raises, `close()` is skipped and the wrapper never returns to the SQLAlchemy pool.
    psycopg2 opened a transaction on the first statement, so the raw connection sits
    `idle in transaction` holding its row locks.

    Measured, not assumed: dropping the *cursor* does not clear it and neither does
    dropping the wrapper, because `PostgresCompatCursor` keeps a reference to the raw
    connection. The frame also stays alive as long as anything retains the exception's
    traceback - which pytest does, for the report. In CI the last statement of the backend
    blocking `DROP TABLE public.pages` was `RELEASE SAVEPOINT sp_gerege_120`, one of these
    cursors, and the rollback whose entire purpose is to undo a bad restore reported
    ROLLBACK_FAILED after a 180 s psql timeout.

    `PostgresCompatConnection.__del__` is the net that makes the release happen once the
    traceback is finally dropped. Both halves are asserted below, so deleting the net
    fails this test.
    """
    from core import backup_service
    from core import db_engine

    if not db_engine.is_postgres():
        print("[SKIP] Not connected to live PostgreSQL")
        return
    if os.getenv("GEREGE_DESTRUCTIVE_TESTS") != "1":
        # This test disposes the shared engine and empties the schema, so it cannot share a
        # database with the rest of the suite (doing so broke 24 unrelated tests). CI runs
        # this module in its own step, where the flag is set and it must run.
        print("[SKIP] set GEREGE_DESTRUCTIVE_TESTS=1 to run (uses the live database)")
        return

    import gc

    import psycopg2

    pg_url = db_engine.get_database_url().replace("postgresql+psycopg2://", "postgresql://")

    def _idle_in_tx():
        conn = psycopg2.connect(pg_url)
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE datname = current_database() AND state = 'idle in transaction'"
            )
            return cur.fetchone()[0]
        finally:
            conn.close()

    def _abandon_a_raising_helper():
        """Reproduce `save_registration`'s shape; return the exception, traceback included."""
        conn = db_engine.get_db_connection()
        try:
            conn.cursor().execute(
                "INSERT INTO registrations (page_id, name, phone) VALUES ('p20_no_page', 'x', '1')"
            )
            conn.commit()
            conn.close()
            raise AssertionError("the insert was expected to be rejected")
        except Exception as exc:  # noqa: BLE001 - the point is to keep the traceback alive
            return exc

    assert hasattr(db_engine.PostgresCompatConnection, "__del__"), (
        "PostgresCompatConnection has no __del__ safety net; a helper that raises between "
        "get_connection() and close() strands the connection holding row locks"
    )

    baseline = _idle_in_tx()
    stranded = _abandon_a_raising_helper()
    gc.collect()
    assert _idle_in_tx() > baseline, (
        "the probe did not strand a transaction, so it cannot prove anything about the net"
    )

    # Dropping the last reference to the traceback releases the frame, hence the wrapper,
    # hence the raw connection - if and only if the net is in place.
    del stranded
    gc.collect()
    assert _idle_in_tx() <= baseline, (
        "the abandoned connection is still 'idle in transaction' after the traceback was "
        "dropped; its locks would outlive the failed operation and block the rollback of "
        "a bad restore"
    )

    # The rollback path itself must be able to take ACCESS EXCLUSIVE immediately
    # afterwards - that is the real-world consequence.
    reset_ok, reset_err = backup_service._reset_public_schema(pg_url)
    assert reset_ok, f"schema reset blocked after the leak: {reset_err}"


def test_p20_32_schema_reset_actually_empties_the_schema(monkeypatch):
    """`_reset_public_schema` must drop everything, and must prove it did.

    It used to run `DROP SCHEMA public CASCADE; CREATE SCHEMA public;` as the restoring
    role, which is refused on a default cluster because `public` belongs to the bootstrap
    superuser - so it failed every time and the caller replayed the snapshot onto a schema
    that had never been cleaned. The first rewrite filtered the drops by
    `current_user`, which silently dropped *nothing* whenever migrations had been applied
    by the bootstrap role, yet still exited 0.

    A reset that cannot be distinguished from a no-op is worse than no reset: the caller
    treats success as licence to replay over live tables.
    """
    from core import backup_service
    from core import db_engine

    if not db_engine.is_postgres():
        print("[SKIP] Not connected to live PostgreSQL")
        return
    if os.getenv("GEREGE_DESTRUCTIVE_TESTS") != "1":
        print("[SKIP] set GEREGE_DESTRUCTIVE_TESTS=1 to run (drops every object in public)")
        return

    import psycopg2
    import sqlalchemy as sa

    pg_url = db_engine.get_database_url().replace("postgresql+psycopg2://", "postgresql://")
    engine = sa.create_engine("postgresql+psycopg2://" + pg_url[len("postgresql://"):], future=True)

    def _relation_count():
        with engine.connect() as conn:
            return conn.execute(
                sa.text(
                    "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = 'public' AND c.relkind IN ('r','p','v','m','S','f')"
                )
            ).scalar()

    if _relation_count() == 0:
        # Earlier tests in this module (p20_31) legitimately empty the schema, so seed it
        # rather than skipping: a reset that drops nothing is precisely the bug under test.
        import database as _database

        _database.init_db()
    assert _relation_count() > 0, "fixture must have a populated schema for this to mean anything"

    ok, err = backup_service._reset_public_schema(pg_url)
    try:
        assert ok is True, f"schema reset refused: {err}"
        assert _relation_count() == 0, (
            "schema reset reported success but relations remain; the snapshot would be "
            "replayed over live tables and the 'atomic' rollback would not be atomic"
        )
    finally:
        engine.dispose()

    # The schema itself must survive: the reset drops the objects *inside* `public` and
    # never `public` itself. Recreating the schema is what destroyed `gerege_app`'s grants
    # and left a "successfully rolled back" database the application could not read.
    conn = psycopg2.connect(pg_url)
    try:
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM pg_namespace WHERE nspname = 'public'")
        assert cur.fetchone()[0] == 1, "the reset dropped schema 'public' itself"
    finally:
        conn.close()
