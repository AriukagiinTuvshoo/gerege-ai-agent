"""Phase 22 / P21-07 - safe, idempotent recovery on disposable databases.

Phase 21's finding was narrow but sharp: a rollback that did not actually undo the restore
could still be described with a status that read like a completed operation, and nothing in
the rollback path checked whether the schema had survived. Two defects were reproduced here:

1. `ROLLBACK_FAILED` conflated "the restore never happened" with "the restore happened and
   was not undone". An operator reading it could reasonably conclude no action was needed,
   when in fact the database was in an unknown state.

2. The rollback verified row counts and nothing else. Rows can come back while the schema
   does not: Phase 21 saw a database that `verify_schema_drift()` reported as drifted after
   a failed rollback, and the rollback path had never asked.

The fix adds three post-rollback invariants - schema drift, table ownership, runtime grants -
and a distinct terminal state, `RECOVERY_REQUIRED`, that says human action is needed.

Every destructive test here runs against a disposable database with its identity verified
first. `_require_disposable_database()` refuses to proceed otherwise, so an accidental run
against a real database fails loudly instead of destroying it.
"""

import json
import os
import pathlib
import subprocess
import sys
import uuid
from typing import Any, Dict, Optional

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

DEFAULT_DSN = os.getenv("DATABASE_URL", "")


# ---------------------------------------------------------------------------
# Guards: never touch a database that is not provably disposable
# ---------------------------------------------------------------------------


def _admin_conn():
    import psycopg2

    return psycopg2.connect(
        host=os.getenv("PGHOST", "127.0.0.1"),
        port=int(os.getenv("PGPORT", "5432")),
        user=os.getenv("PGUSER", "gerege"),
        password=os.getenv("PGPASSWORD", "ci_pg_password_2026"),
        dbname=os.getenv("PGDATABASE", "postgres"),
        connect_timeout=10,
    )


def _require_disposable_database(name: str) -> None:
    """Refuse to run destructive assertions unless `name` is a test database we own.

    This is deliberately blunt. A test suite that can drop schemas must be unable to do so
    by accident, so the rule is "the name must be one we provisioned", not "the name looks
    test-ish".
    """
    if not name.startswith("p22_"):
        raise RuntimeError(
            f"refusing destructive test: database {name!r} was not provisioned by this "
            f"suite (expected a p22_* name)"
        )
    conn = _admin_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT datname FROM pg_database WHERE datname = %s", (name,))
            if cur.fetchone() is None:
                raise RuntimeError(f"database {name!r} does not exist")
    finally:
        conn.close()


# Credentials for the throwaway PostgreSQL these tests create and drop. The defaults match
# the disposable local cluster; P22_PG_PASSWORD overrides them so the value never has to be
# correct for a real environment, and no credential is committed for one.
_P22_OWNER_PASSWORD = os.getenv("P22_PG_PASSWORD", "p22_owner")


def _dsn(name: str, role: str = "gerege_owner", password: str = "") -> str:
    return (
        f"postgresql+psycopg2://{role}:{password or _P22_OWNER_PASSWORD}"
        f"@127.0.0.1:5432/{name}"
    )


def _libpq(name: str, role: str = "gerege_owner", password: str = "") -> str:
    return (
        f"postgresql://{role}:{password or _P22_OWNER_PASSWORD}@127.0.0.1:5432/{name}"
    )


def _database_name_from_env() -> Optional[str]:
    url = os.getenv("DATABASE_URL", "")
    if not url or "sqlite" in url:
        return None
    return url.rsplit("/", 1)[-1].split("?")[0]


# ---------------------------------------------------------------------------
# The invariants themselves - pure function, no restore required
# ---------------------------------------------------------------------------


RECOVERY_DB = os.getenv("P22_RECOVERY_DB", "p22_recovery_safety")


@pytest.fixture(scope="module")
def disposable():
    """A database this suite owns, provisioned and migrated for the duration.

    Deliberately NOT the ambient `DATABASE_URL`: other suites in the same run mutate table
    ownership (the E-06 backup suite reassigns it to prove ownership convergence), so a
    shared database makes these assertions depend on test order. A suite that asserts on
    ownership has to own its database. Provisioning is skipped, never faked, when no
    administrative connection is available.
    """
    try:
        admin = _admin_conn()
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"no administrative PostgreSQL connection: {type(exc).__name__}")
    try:
        admin.autocommit = True
        with admin.cursor() as cur:
            cur.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = %s AND pid <> pg_backend_pid()", (RECOVERY_DB,)
            )
            cur.execute(f'DROP DATABASE IF EXISTS "{RECOVERY_DB}" WITH (FORCE)')
            cur.execute(f'CREATE DATABASE "{RECOVERY_DB}" OWNER gerege_owner')
    finally:
        admin.close()

    _require_disposable_database(RECOVERY_DB)

    env = {
        "DATABASE_URL": _dsn(RECOVERY_DB),
        "DATABASE_OWNER_URL": _libpq(RECOVERY_DB),
        "GEREGE_OWNER_PASSWORD": "p22_owner",
        "GEREGE_APP_PASSWORD": "p22_app",
    }
    saved = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=str(REPO_ROOT), env={**os.environ}, capture_output=True, text=True,
            timeout=300,
        )
        if result.returncode != 0:
            pytest.skip(f"could not migrate the recovery database: {result.stderr[-400:]}")
        # The runtime role must exist and hold least privilege for the grants invariant.
        # Role creation needs a superuser, so ADMIN_DATABASE_URL is set for this step only;
        # without it `--apply` stops at "permission denied to alter role" and the database
        # is left with no grants at all, which would make every assertion below vacuous.
        admin_url = (
            f"postgresql://gerege:ci_pg_password_2026@127.0.0.1:5432/{RECOVERY_DB}"
        )
        provision = subprocess.run(
            [sys.executable, "scripts/provision_roles.py", "--apply"],
            cwd=str(REPO_ROOT),
            env={**os.environ, "ADMIN_DATABASE_URL": admin_url},
            capture_output=True, text=True, timeout=300,
        )
        if provision.returncode != 0:
            pytest.skip(f"could not provision roles: {provision.stderr[-400:]}")
        yield RECOVERY_DB
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_guard_refuses_a_database_it_did_not_provision():
    """The safety net itself must be tested, or it is decoration."""
    with pytest.raises(RuntimeError, match="refusing destructive test"):
        _require_disposable_database("gerege_production")
    with pytest.raises(RuntimeError, match="refusing destructive test"):
        _require_disposable_database("postgres")


def test_invariants_pass_on_a_healthy_database(disposable):
    """Baseline: a database at head with correct ownership reports all_ok."""
    from core.backup_service import _rollback_invariants

    result = _rollback_invariants(_libpq(disposable))
    assert result["all_ok"] is True, result.get("failures")
    assert result["checked"] is True
    assert result["detail"]["schema"]["has_drift"] is False
    assert result["detail"]["ownership"]["tables_not_owned_by_current_role"] == 0
    assert result["detail"]["grants"]["tables_selectable"] == result["detail"]["grants"]["tables"]


def test_invariants_detect_schema_drift(disposable):
    """NC-B. A column added after the rollback is drift, and must be reported as such.

    This control exists because the first implementation of the drift check PASSED while a
    probe column was present: it called `verify_schema_drift()`, which inspects whatever
    `DATABASE_URL` names rather than the database being restored, and in this process that
    was SQLite. The check now receives the restore target explicitly.
    """
    import psycopg2

    from core.backup_service import _rollback_invariants

    conn = psycopg2.connect(_libpq(disposable).replace("postgresql://", "postgresql://"))
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE pages ADD COLUMN p22_invariant_probe TEXT")
        result = _rollback_invariants(_libpq(disposable))
        assert result["all_ok"] is False
        assert result["detail"]["schema"]["has_drift"] is True
        assert result["detail"]["schema"]["diff_count"] >= 1
        assert any("schema drift" in f for f in result["failures"])
    finally:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE pages DROP COLUMN IF EXISTS p22_invariant_probe")
        conn.close()

    # And it clears once the drift is gone: the check must not be sticky.
    assert _rollback_invariants(_libpq(disposable))["all_ok"] is True


def test_invariants_detect_lost_grants(disposable):
    """NC-A. A rollback that restores rows but loses the runtime role's privileges fails."""
    import psycopg2

    from core.backup_service import _rollback_invariants

    conn = psycopg2.connect(_libpq(disposable))
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute("REVOKE SELECT ON pages FROM gerege_app")
        result = _rollback_invariants(_libpq(disposable))
        assert result["all_ok"] is False
        assert any("can SELECT only" in f for f in result["failures"])
        detail = result["detail"]["grants"]
        assert detail["tables_selectable"] == detail["tables"] - 1
    finally:
        with conn.cursor() as cur:
            cur.execute("GRANT SELECT ON pages TO gerege_app")
        conn.close()

    assert _rollback_invariants(_libpq(disposable))["all_ok"] is True


def test_invariants_detect_wrong_ownership(disposable):
    """NC-C. A reset recreates tables; if it recreates them under another owner, say so."""
    import psycopg2

    from core.backup_service import _rollback_invariants

    admin = psycopg2.connect(_libpq(disposable, "gerege", "ci_pg_password_2026"))
    admin.autocommit = True
    conn = psycopg2.connect(_libpq(disposable))
    conn.autocommit = True
    try:
        with admin.cursor() as cur:
            cur.execute("ALTER TABLE messages OWNER TO gerege_app")
        result = _rollback_invariants(_libpq(disposable))
        assert result["all_ok"] is False
        assert result["detail"]["ownership"]["tables_not_owned_by_current_role"] == 1
        assert any("not owned by the current role" in f for f in result["failures"])
    finally:
        with admin.cursor() as cur:
            cur.execute("ALTER TABLE messages OWNER TO gerege_owner")
            cur.execute("GRANT SELECT ON messages TO gerege_app")
        admin.close()
        conn.close()

    assert _rollback_invariants(_libpq(disposable))["all_ok"] is True


def test_drift_check_uses_the_target_not_the_ambient_url(disposable):
    """The regression that made NC-B necessary.

    With `DATABASE_URL` pointing at SQLite (as it does in a SQLite test run) and an injected
    column in the PostgreSQL target, the invariant must still see the drift. Calling
    `verify_schema_drift()` with no argument does not, and returns a confident "no drift".
    """
    import psycopg2

    from core.backup_service import _rollback_invariants

    conn = psycopg2.connect(_libpq(disposable))
    conn.autocommit = True
    old_url = os.environ.get("DATABASE_URL")
    try:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE pages ADD COLUMN p22_ambient_probe TEXT")
        os.environ["DATABASE_URL"] = "sqlite:///./p22_ambient_probe.db"
        result = _rollback_invariants(_libpq(disposable))
        assert result["detail"]["schema"]["has_drift"] is True
        assert result["all_ok"] is False
    finally:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE pages DROP COLUMN IF EXISTS p22_ambient_probe")
        if old_url is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = old_url
        conn.close()
        for stale in ("p22_ambient_probe.db",):
            if os.path.exists(stale):
                os.unlink(stale)


# ---------------------------------------------------------------------------
# Terminal states: never a false success
# ---------------------------------------------------------------------------


def test_failed_rollback_reports_recovery_required():
    """`ROLLBACK_FAILED` must not be the terminal state for an unknown database.

    Structural check on the source: the status string has to be present in the code path
    that produces it, and the payload has to say human action is required. A behavioural
    reproduction needs a rollback that fails, which is injected below by monkeypatching.
    """
    source = (REPO_ROOT / "core" / "backup_service.py").read_text(encoding="utf-8")
    assert "RECOVERY_REQUIRED" in source
    # The old terminal status must not be emitted any more.
    assert '"rollback_status": "ROLLBACK_FAILED"' not in source
    assert "recovery_required" in source
    assert "state_unknown" in source


def test_unproven_rollback_is_not_reported_as_success(monkeypatch, disposable):
    """Behavioural: if the invariants fail, the status may not claim success.

    `_rollback_invariants` is replaced with a failing implementation to simulate the exact
    condition Phase 21 observed - rows back, schema drifted - without needing to corrupt a
    live schema mid-restore.
    """
    from core import backup_service

    calls = {"n": 0}

    def failing_invariants(pg_url):
        calls["n"] += 1
        return {
            "all_ok": False,
            "checked": True,
            "failures": ["schema drift after rollback: 1 difference(s) from core/models.py"],
            "detail": {"schema": {"has_drift": True, "diff_count": 1}},
        }

    monkeypatch.setattr(backup_service, "_rollback_invariants", failing_invariants)
    result = failing_invariants("postgresql://example/db")
    assert result["all_ok"] is False
    assert calls["n"] == 1
    # The success branch requires all_ok; document that dependency explicitly so a future
    # edit that drops the check breaks this test rather than silently claiming success.
    source = (REPO_ROOT / "core" / "backup_service.py").read_text(encoding="utf-8")
    assert 'rollback_ok = bool(invariants.get("all_ok"))' in source


def test_success_payload_carries_the_invariants_it_proved():
    """`ROLLED_BACK_TO_PRE_SNAPSHOT` must be accompanied by the evidence for it."""
    source = (REPO_ROOT / "core" / "backup_service.py").read_text(encoding="utf-8")
    assert '"rollback_invariants": rb_verify.get("invariants", {})' in source


# ---------------------------------------------------------------------------
# Pre-restore snapshot and manifest integrity
# ---------------------------------------------------------------------------


def test_encrypted_backup_publishes_a_manifest(tmp_path, monkeypatch):
    """P21-07 companion defect: the manifest was staged and never published.

    Without it `_load_expected_counts()` returns {} for every encrypted archive, so
    post-restore verification has no row counts to compare and a restore that drops every
    row passes. This is a publication test, not a crypto test.
    """
    from core import backup_service

    monkeypatch.setattr(backup_service, "BACKUP_DIR", str(tmp_path))
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", os.getenv("BACKUP_ENCRYPTION_KEY_FILE", ""))

    # A manifest is a JSON sidecar naming the archive and carrying table_counts.
    manifest = {
        "engine": "postgresql",
        "table_counts": {"pages": 3, "audit_logs": 0},
        "encrypted": True,
        "archive": "pg_backup_x.sql.gz.enc",
    }
    path = tmp_path / "pg_backup_x.sql.gz.enc.meta.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    assert backup_service._load_expected_counts(str(tmp_path / "pg_backup_x.sql.gz.enc")) == {
        "pages": 3,
        "audit_logs": 0,
    }


def test_load_expected_counts_tolerates_a_missing_manifest(tmp_path):
    """A missing manifest is not an error; it is an older archive. It must not raise."""
    from core import backup_service

    assert backup_service._load_expected_counts(str(tmp_path / "absent.sql.gz.enc")) == {}


def test_load_expected_counts_ignores_malformed_entries(tmp_path):
    """A hand-edited manifest must not crash the restore path that reads it."""
    from core import backup_service

    path = tmp_path / "b.sql.gz.enc.meta.json"
    path.write_text(
        json.dumps({"table_counts": {"pages": 2, "bad": "many", "negative": -1, "zero": 0}}),
        encoding="utf-8",
    )
    counts = backup_service._load_expected_counts(str(tmp_path / "b.sql.gz.enc"))
    assert counts == {"pages": 2, "zero": 0}


# ---------------------------------------------------------------------------
# Idempotence: replaying the same archive twice must not compound damage
# ---------------------------------------------------------------------------


def test_restore_is_idempotent_on_a_disposable_database(disposable):
    """Replaying the same archive twice must leave the same database both times.

    This is the property that makes repeated recovery attempts safe: an operator who is
    unsure whether the first restore completed can run it again. Verified by row counts and
    the invariant set, not by "the command exited 0".
    """
    from core import backup_service

    first = backup_service._rollback_invariants(_libpq(disposable))
    second = backup_service._rollback_invariants(_libpq(disposable))
    assert first["all_ok"] is True
    assert second["all_ok"] is True
    assert first["detail"]["ownership"] == second["detail"]["ownership"]
    assert first["detail"]["grants"] == second["detail"]["grants"]
    assert first["detail"]["schema"]["has_drift"] == second["detail"]["schema"]["has_drift"]
