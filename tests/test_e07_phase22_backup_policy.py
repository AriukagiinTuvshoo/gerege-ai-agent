"""Phase 22 regression tests: P21-01 centralized, production-mandatory encryption policy.

Phase 21 reproduced the defect this module guards against:

    ENV=production BACKUP_ENCRYPTION=off python scripts/maintenance.py backup --label x
    -> exit 0, pg_backup_x_*.sql.gz written, canary recoverable with `gzip -dc`

The old policy was one inline `os.getenv("BACKUP_ENCRYPTION", "on")` read with no notion
of environment, while two docstrings claimed it "fails closed in production". Documentation
and behaviour had diverged, and the only guard was a variable an operator could set.

These tests fix the contract rather than the symptom:

* a refused policy publishes **no file** and returns **nonzero**, and the canary is not
  recoverable from ``BACKUP_DIR``;
* the refusal is decided **before the database is opened**, so a DSN pointing at a
  nonexistent database still produces the policy error and not a connection error;
* every entry point reaches the same verdict - direct ``create_backup()``, the scheduled
  runner, the CLI and ``migrate.py``;
* the positive path still produces a verifiable, restorable ciphertext archive.

Every negative test also asserts that nothing was left behind, because "exit 1 but the
plaintext is on disk" would otherwise pass.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core import backup_policy  # noqa: E402

CANARY = "P22POLICYCANARY4f2b9c1e"


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def env(monkeypatch):
    """A clean environment for policy evaluation: no stale ENV/STRICT_SECURITY."""

    class Env:
        def __init__(self):
            for name in (
                "ENV",
                "STRICT_SECURITY",
                "BACKUP_ENCRYPTION",
                "BACKUP_ENCRYPTION_KEY_FILE",
                "REQUIRE_LEAST_PRIVILEGE",
            ):
                monkeypatch.delenv(name, raising=False)

        @staticmethod
        def set(**kwargs):
            for key, value in kwargs.items():
                if value is None:
                    monkeypatch.delenv(key, raising=False)
                else:
                    monkeypatch.setenv(key, value)

    return Env()


@pytest.fixture
def keyfile(tmp_path):
    path = tmp_path / "backup.key"
    path.write_bytes(os.urandom(32))
    path.chmod(0o600)
    return path


@pytest.fixture
def backup_dir(tmp_path, monkeypatch):
    """Point *both* backup modules at a private directory.

    ``backup_automation`` resolves ``BACKUP_DIR`` per call, but ``backup_service`` binds it
    at import time. Setting only the environment variable therefore left
    ``backup_service`` writing to the repository's ``backups/`` directory, which made the
    "nothing was published" assertions vacuous. Both are redirected here so the
    assertions observe the files the code actually writes.
    """
    from core import backup_service

    directory = tmp_path / "backups"
    directory.mkdir()
    monkeypatch.setenv("BACKUP_DIR", str(directory))
    monkeypatch.setattr(backup_service, "BACKUP_DIR", str(directory), raising=True)

    from core import backup_automation

    monkeypatch.setattr(
        backup_automation, "_status_path", lambda: str(directory / ".last_backup_status.json")
    )
    return directory


def _published(directory: pathlib.Path) -> list:
    """Files in BACKUP_DIR that are archives, excluding the status/lock bookkeeping."""
    if not directory.exists():
        return []
    return sorted(
        p.name
        for p in directory.iterdir()
        if p.name not in (".last_backup_status.json", ".backup.lock") and p.is_file()
    )


def _contains_canary(directory: pathlib.Path) -> bool:
    """Search every byte of every file for the canary, compressed or not."""
    if not directory.exists():
        return False
    for path in directory.rglob("*"):
        if not path.is_file():
            continue
        try:
            blob = path.read_bytes()
        except OSError:
            continue
        if CANARY.encode() in blob:
            return True
        # Plaintext archives are gzip; look inside them too.
        import gzip

        try:
            if CANARY.encode() in gzip.decompress(blob):
                return True
        except Exception:
            pass
    return False


# ---------------------------------------------------------------------------
# policy unit tests: the decision table
# ---------------------------------------------------------------------------

def test_production_off_is_refused(env):
    env.set(ENV="production", BACKUP_ENCRYPTION="off")
    policy = backup_policy.evaluate()
    assert policy.allowed is False
    assert policy.encrypting is False
    assert policy.code == "ENCRYPTION_DISABLED_IN_PRODUCTION"
    assert "not permitted in production" in policy.error


@pytest.mark.parametrize("value", ["off", "0", "false", "no", "OFF", " Off ", "disabled", "none", "plaintext"])
def test_production_off_spellings_all_refused(env, value):
    """Whitespace and case are normalised, then still refused in production."""
    env.set(ENV="production", BACKUP_ENCRYPTION=value)
    assert backup_policy.evaluate().allowed is False


def test_prod_alias_is_treated_as_production(env):
    env.set(ENV="prod", BACKUP_ENCRYPTION="off")
    assert backup_policy.evaluate().allowed is False


def test_strict_security_counts_as_production(env):
    """The repo's second production signal must not be a bypass."""
    env.set(STRICT_SECURITY="1", BACKUP_ENCRYPTION="off")
    assert backup_policy.evaluate().allowed is False


@pytest.mark.parametrize("value", ["maybe", "of", "offf", "yes please", "TRUE?"])
def test_unrecognised_value_fails_closed(env, value):
    """A typo must never silently select the weaker mode."""
    env.set(ENV="production", BACKUP_ENCRYPTION=value)
    policy = backup_policy.evaluate()
    assert policy.allowed is False
    assert policy.code == "ENCRYPTION_CONFIG_INVALID"


def test_missing_key_is_refused(env):
    env.set(ENV="production", BACKUP_ENCRYPTION="on", BACKUP_ENCRYPTION_KEY_FILE=None)
    policy = backup_policy.evaluate()
    assert policy.allowed is False
    assert policy.code == "ENCRYPTION_KEY_MISSING"


def test_nonexistent_key_file_is_refused(env, tmp_path):
    env.set(BACKUP_ENCRYPTION="on", BACKUP_ENCRYPTION_KEY_FILE=str(tmp_path / "absent.key"))
    assert backup_policy.evaluate().allowed is False


def test_empty_key_file_is_refused(env, tmp_path):
    """A zero-length file is not an AES-256 key."""
    path = tmp_path / "empty.key"
    path.write_bytes(b"")
    env.set(BACKUP_ENCRYPTION="on", BACKUP_ENCRYPTION_KEY_FILE=str(path))
    policy = backup_policy.evaluate()
    assert policy.allowed is False
    assert policy.code == "ENCRYPTION_KEY_INVALID"


def test_directory_as_key_path_is_refused(env, tmp_path):
    env.set(BACKUP_ENCRYPTION="on", BACKUP_ENCRYPTION_KEY_FILE=str(tmp_path))
    assert backup_policy.evaluate().allowed is False


def test_error_message_never_discloses_key_material(env, tmp_path):
    """Only the basename may appear; a key path can disclose host layout."""
    secret_dir = tmp_path / "very-secret-tenant-location"
    secret_dir.mkdir()
    env.set(BACKUP_ENCRYPTION="on", BACKUP_ENCRYPTION_KEY_FILE=str(secret_dir / "nope.key"))
    error = backup_policy.evaluate().error
    assert "very-secret-tenant-location" not in error
    assert "nope.key" in error


def test_valid_config_is_allowed_and_encrypting(env, keyfile):
    env.set(ENV="production", BACKUP_ENCRYPTION="on", BACKUP_ENCRYPTION_KEY_FILE=str(keyfile))
    policy = backup_policy.evaluate()
    assert policy.allowed is True
    assert policy.encrypting is True
    assert policy.code == "ENCRYPTED"


def test_non_production_off_is_allowed_but_flagged(env):
    """Local development keeps its escape hatch, and it is labelled, not silent."""
    env.set(BACKUP_ENCRYPTION="off")
    policy = backup_policy.evaluate()
    assert policy.allowed is True
    assert policy.encrypting is False
    assert policy.code == "PLAINTEXT_NON_PRODUCTION"
    assert policy.warning


def test_no_env_defaults_to_encrypting(env, keyfile):
    """Absent configuration must not mean "plaintext"."""
    env.set(BACKUP_ENCRYPTION_KEY_FILE=str(keyfile))
    assert backup_policy.evaluate().encrypting is True


def test_encryption_required_legacy_shim_fails_closed(env):
    """A caller that only reads the boolean must still not write plaintext in production."""
    env.set(ENV="production", BACKUP_ENCRYPTION="off")
    from core import backup_automation

    assert backup_automation.encryption_required() is True


def test_policy_is_pure_and_does_not_need_a_database(env):
    """evaluate() performs no I/O beyond stat-ing the key file."""
    env.set(ENV="production", BACKUP_ENCRYPTION="off")
    policy = backup_policy.evaluate()
    assert policy.allowed is False


# ---------------------------------------------------------------------------
# end-to-end: no artifact may survive a refused run
# ---------------------------------------------------------------------------

def _make_db_rows(count=1):
    """Insert the canary into a real row so a dump has something to leak."""
    from core.db_engine import is_postgres

    if not is_postgres():
        pytest.skip("needs PostgreSQL")
    from core.db_engine import get_db_connection

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO pages (page_id,name,category,is_active,knowledge_json,ai_provider,"
            "monthly_token_limit,tokens_used,ebarimt_enabled,daily_report_enabled) "
            "VALUES ('P22CANARY',%s,'fintech',1,'{}','gemini',1,0,0,0)",
            (CANARY,),
        )
        conn.commit()
        cur.close()
    finally:
        conn.close()


@pytest.mark.parametrize(
    "envvars,expected_code",
    [
        ({"ENV": "production", "BACKUP_ENCRYPTION": "off"}, "ENCRYPTION_DISABLED_IN_PRODUCTION"),
        ({"ENV": "production", "BACKUP_ENCRYPTION": "OFF"}, "ENCRYPTION_DISABLED_IN_PRODUCTION"),
        ({"ENV": "production", "BACKUP_ENCRYPTION": "of"}, "ENCRYPTION_CONFIG_INVALID"),
        ({"ENV": "production", "BACKUP_ENCRYPTION": None}, "ENCRYPTION_KEY_MISSING"),
    ],
)
def test_refused_backup_publishes_nothing(monkeypatch, backup_dir, envvars, expected_code):
    """The defect, end to end: no file, no canary, nonzero exit, before the DB is read."""

    for name in ("ENV", "STRICT_SECURITY", "BACKUP_ENCRYPTION", "BACKUP_ENCRYPTION_KEY_FILE"):
        monkeypatch.delenv(name, raising=False)
    for name, value in envvars.items():
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    monkeypatch.setenv("BACKUP_DIR", str(backup_dir))
    # Deliberately unusable DSN: if the policy is checked after the connection, this test
    # fails with a connection error instead of the policy error, which is the regression.
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg2://nobody:wrong@127.0.0.1:1/absent_p22"
    )

    from core import backup_service

    result = backup_service.create_backup(label="refused")

    assert result.get("success") is False
    assert result.get("exit_code") not in (0, None)
    assert result.get("encryption_policy") == expected_code
    assert _published(backup_dir) == []
    assert _contains_canary(backup_dir) is False


def test_refused_backup_does_not_create_dotfiles_holding_data(backup_dir, monkeypatch):
    """The status file may record the refusal, but must not contain tenant data."""
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("BACKUP_ENCRYPTION", "off")

    from core import backup_automation

    result = backup_automation.run_scheduled_backup(label="refused-sched")
    assert result.get("success") is False
    assert _contains_canary(backup_dir) is False


def test_cli_refusal_precedes_database_access(tmp_path, monkeypatch):
    """The CLI must not even open a connection when the policy refuses.

    "No tenant data was read" is part of the claim, so the banner query that logs the
    connection identity must come *after* the policy check. A DSN pointing at a
    nonexistent database proves the ordering: we get the policy error, not a driver error.
    """
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    environment = {
        **os.environ,
        "ENV": "production",
        "BACKUP_ENCRYPTION": "off",
        "BACKUP_DIR": str(backup_dir),
        "DATABASE_URL": "postgresql+psycopg2://nobody:wrong@127.0.0.1:1/absent_p22",
    }

    proc = subprocess.run(
        [sys.executable, "scripts/maintenance.py", "backup", "--label", "cli-refused"],
        cwd=str(REPO_ROOT),
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
    )

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "not permitted in production" in combined
    assert "does not exist" not in combined.lower()
    assert "connection refused" not in combined.lower()
    assert "could not connect" not in combined.lower()
    assert _published(backup_dir) == []


def test_cli_backup_run_refusal_precedes_database_access(tmp_path):
    """Same ordering guarantee for the scheduled entry point the timer invokes."""
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    environment = {
        **os.environ,
        "ENV": "production",
        "BACKUP_ENCRYPTION": "off",
        "BACKUP_DIR": str(backup_dir),
        "DATABASE_URL": "postgresql+psycopg2://nobody:wrong@127.0.0.1:1/absent_p22",
    }

    proc = subprocess.run(
        [sys.executable, "scripts/maintenance.py", "backup-run", "--label", "cli-refused"],
        cwd=str(REPO_ROOT),
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
    )

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "not permitted in production" in combined
    assert "connection refused" not in combined.lower()
    assert _published(backup_dir) == []


def test_migrate_refuses_to_migrate_without_a_backup(tmp_path):
    """migrate.py must not proceed on an unprotected database.

    A pre-migration backup that silently downgraded to plaintext, or silently failed,
    would mean a migration ran with no restore point.
    """
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    environment = {
        **os.environ,
        "ENV": "production",
        "BACKUP_ENCRYPTION": "off",
        "BACKUP_DIR": str(backup_dir),
        "DATABASE_URL": "postgresql+psycopg2://nobody:wrong@127.0.0.1:1/absent_p22",
    }

    proc = subprocess.run(
        [sys.executable, "scripts/migrate.py"],
        cwd=str(REPO_ROOT),
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
    )

    assert proc.returncode != 0
    assert "refusing to migrate" in (proc.stdout + proc.stderr).lower()


def test_retention_does_not_count_a_refused_run_as_a_valid_archive(backup_dir, monkeypatch):
    """A refused run must not create the newest "backup" and so protect nothing.

    If the refusal wrote a placeholder archive, retention would count it toward
    BACKUP_MIN_KEEP and could delete the last genuinely encrypted restore point.
    """
    # Two pre-existing archives, one stale, so retention has something to consider.
    stale = backup_dir / "pg_backup_old_20200101_000000_00.sql.gz.enc"
    stale.write_bytes(b"x" * 64)
    fresh = backup_dir / "pg_backup_new_20260101_000000_00.sql.gz.enc"
    fresh.write_bytes(b"y" * 64)

    monkeypatch.setenv("BACKUP_DIR", str(backup_dir))
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("BACKUP_ENCRYPTION", "off")

    from core import backup_automation

    result = backup_automation.run_scheduled_backup(label="refused-retention")
    assert result.get("success") is False

    names = _published(backup_dir)
    assert "pg_backup_old_20200101_000000_00.sql.gz.enc" in names
    assert "pg_backup_new_20260101_000000_00.sql.gz.enc" in names
    assert not any("refused-retention" in name for name in names)


# ---------------------------------------------------------------------------
# documentation claims must be executable
# ---------------------------------------------------------------------------

def test_status_reports_policy_without_leaking_key_material(tmp_path, monkeypatch, keyfile):
    """`maintenance.py status` documents that it reports the policy; prove it, and prove
    it does not print the key. A status command that echoed the key would be worse than
    no status command at all."""
    import base64

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    environment = {
        **os.environ,
        "ENV": "production",
        "BACKUP_ENCRYPTION": "on",
        "BACKUP_ENCRYPTION_KEY_FILE": str(keyfile),
        "BACKUP_DIR": str(backup_dir),
        "DATABASE_URL": "postgresql+psycopg2://nobody:wrong@127.0.0.1:1/absent_p22",
    }

    proc = subprocess.run(
        [sys.executable, "scripts/maintenance.py", "status"],
        cwd=str(REPO_ROOT),
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
    )
    combined = proc.stdout + proc.stderr
    assert "encryption policy: ENCRYPTED" in combined
    assert keyfile.read_bytes().hex() not in combined
    assert base64.b64encode(keyfile.read_bytes()).decode() not in combined


def test_status_reports_refused_policy_as_a_configuration_fact(tmp_path, monkeypatch):
    """A refused policy must be visible before the first failed run, not only after it."""
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    environment = {
        **os.environ,
        "ENV": "production",
        "BACKUP_ENCRYPTION": "off",
        "BACKUP_DIR": str(backup_dir),
        "DATABASE_URL": "postgresql+psycopg2://nobody:wrong@127.0.0.1:1/absent_p22",
    }
    proc = subprocess.run(
        [sys.executable, "scripts/maintenance.py", "status"],
        cwd=str(REPO_ROOT),
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
    )
    combined = proc.stdout + proc.stderr
    assert "POLICY REFUSES BACKUPS" in combined
    assert "ENCRYPTION_DISABLED_IN_PRODUCTION" in combined


def test_production_positive_path_produces_a_verifiable_archive(backup_dir, monkeypatch, keyfile):
    """The docs claim production produces an encrypted, verifiable archive. Prove it.

    This is the positive half of P21-01: refusing plaintext is only useful if the correct
    configuration still works. Skips without a PostgreSQL DSN because the dump is real.
    """
    from core.db_engine import is_postgres

    if not is_postgres():
        pytest.skip("needs PostgreSQL")

    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", str(keyfile))
    monkeypatch.delenv("BACKUP_OFFSITE_PATH", raising=False)

    from core import backup_service

    result = backup_service.create_backup(label="pos")
    assert result.get("success") is True, result.get("error")
    name = result["filename"]
    assert name.endswith(".enc")
    assert result.get("encrypted") is True

    # No plaintext sibling, and the archive is not readable without the key.
    assert not (backup_dir / name.replace(".enc", "")).exists()
    blob = (backup_dir / name).read_bytes()
    assert CANARY.encode() not in blob

    from core import backup_service as svc

    check = svc.verify_backup(str(backup_dir / name))
    assert check.get("valid") is True, check


def test_non_production_plaintext_is_labelled_not_silent(backup_dir, monkeypatch):
    """The one remaining plaintext path must never be mistakable for an encrypted archive."""
    from core.db_engine import is_postgres

    if not is_postgres():
        pytest.skip("needs PostgreSQL")

    monkeypatch.delenv("ENV", raising=False)
    monkeypatch.delenv("STRICT_SECURITY", raising=False)
    monkeypatch.setenv("BACKUP_ENCRYPTION", "off")

    from core import backup_service

    result = backup_service.create_backup(label="dev-plain")
    assert result.get("success") is True, result.get("error")
    assert result.get("encryption_format") == "none"
    assert result.get("warning"), "a plaintext archive must carry a warning"


def test_exit_codes_preserve_the_preexisting_failure_classification(env, tmp_path):
    """Two distinct failures must not collapse into one exit code.

    The runbook and alerting already distinguish "not configured" (15) from "encryption
    failed" (11). A missing key *variable* means the encryption step never had a
    configuration; a key that is present but unusable means encryption was attempted and
    could not work. Collapsing them would silently reclassify a failure an operator has
    been told to handle differently.
    """
    env.set(BACKUP_ENCRYPTION="on")
    assert backup_policy.evaluate().exit_code == 15, "unset key variable is 'not configured'"

    # An empty value is indistinguishable from unset: there is no key configured.
    env.set(BACKUP_ENCRYPTION="on", BACKUP_ENCRYPTION_KEY_FILE="")
    assert backup_policy.evaluate().exit_code == 15

    # A configured path that does not work is a different failure class.
    for value in ("/nonexistent/key", str(tmp_path)):
        env.set(BACKUP_ENCRYPTION="on", BACKUP_ENCRYPTION_KEY_FILE=value)
        policy = backup_policy.evaluate()
        assert policy.allowed is False
        assert policy.exit_code == 11, f"{value!r} is 'encryption failed', not 'not configured'"

    empty = tmp_path / "empty.key"
    empty.write_bytes(b"")
    env.set(BACKUP_ENCRYPTION="on", BACKUP_ENCRYPTION_KEY_FILE=str(empty))
    assert backup_policy.evaluate().exit_code == 11


def test_production_plaintext_refusal_is_a_configuration_error(env):
    """`off` in production is a configuration fault, not an encryption failure."""
    env.set(ENV="production", BACKUP_ENCRYPTION="off")
    assert backup_policy.evaluate().exit_code == 15


def test_a_wrong_length_key_is_a_configuration_error_not_an_integrity_error(tmp_path, monkeypatch):
    """Phase 22: a 5-byte key used to pass the policy and fail later as exit 12.

    `ENCRYPTION_KEY_INVALID` (11) is meant to mean "configured, but unusable". The policy
    checked "is a file" and "is not empty", which let a key that cannot possibly be AES-256
    through as ENCRYPTED; the run then failed inside the crypto layer and reported 12 - an
    integrity failure - for what is a configuration mistake. The two codes exist so an
    operator can tell them apart.
    """
    from core import backup_policy

    bad = tmp_path / "short.key"
    bad.write_bytes(b"short")
    bad.chmod(0o600)
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", str(bad))
    monkeypatch.delenv("BACKUP_ENCRYPTION", raising=False)

    policy = backup_policy.evaluate()
    assert policy.allowed is False
    assert policy.code == "ENCRYPTION_KEY_INVALID"
    assert policy.exit_code == 11
    # The length may be reported; the content never.
    assert "5 bytes" in policy.error or "5" in policy.error
    assert "short" not in policy.error.replace("short.key", "")


def test_a_valid_32_byte_key_is_still_accepted(tmp_path, monkeypatch):
    """The new length check must not reject a correct key."""
    from core import backup_policy

    good = tmp_path / "good.key"
    good.write_bytes(bytes(range(32)))
    good.chmod(0o600)
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", str(good))
    monkeypatch.delenv("BACKUP_ENCRYPTION", raising=False)

    policy = backup_policy.evaluate()
    assert policy.allowed is True
    assert policy.code == "ENCRYPTED"
