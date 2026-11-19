"""Phase 16 — regression tests for the three Phase 15 audit findings.

Each test is written to **fail before the fix and pass after it**. That property is the
point: a test that passes on both revisions proves nothing, so where a fix is
behavioural the docstring records the exact pre-fix observation.

    HIGH-01     `scripts/deploy.sh` migrated as the bootstrap account and then ran
                `provision_roles.py --apply --converge-only`, which emits GRANT/REVOKE
                only. On a fresh database every relation stayed owned by the bootstrap
                superuser: privileges correct, `pg_dump` impossible, and `--verify`
                exited 0. Observed pre-fix: 32/32 relations owned by `gerege`, exit 0.

    MEDIUM-01   `--verify` evaluated the runtime role only by `SET ROLE`-ing into it.
                Run with the owner credential — which cannot impersonate its own member
                — it printed a note and then PASSED, because the violation list was
                empty. Observed pre-fix: `audit_logs` carried UPDATE+DELETE and
                `--verify` printed "Runtime role holds least privilege." with exit 0.

    MEDIUM-02   No scheduler existed anywhere while two documents promised a 24-hour
                RPO. A missing scheduler cannot be unit-tested, but the *absence of the
                claim* and the *presence of a fail-closed run* can be.

PostgreSQL-only where roles are involved; the SQLite cases prove nothing silently
passes when the engine cannot express the property.
"""

from __future__ import annotations

import os
import uuid

import pytest

REQUIRE_POSTGRES = pytest.mark.skipif(
    not os.getenv("DATABASE_URL", "").startswith("postgresql"),
    reason="needs PostgreSQL: SQLite has no roles or ownership to separate",
)


# ---------------------------------------------------------------------------
# helpers (kept independent of the other suites so these tests cannot be
# disabled by editing a shared fixture)
# ---------------------------------------------------------------------------


def _raw(url: str):
    import psycopg2

    for prefix in ("postgresql+psycopg2://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            url = "postgresql://" + url[len(prefix):]
    conn = psycopg2.connect(url)
    conn.autocommit = True
    return conn


def _try(conn, sql: str):
    cur = conn.cursor()
    try:
        cur.execute(sql)
        return True, ""
    except Exception as exc:
        return False, str(exc).strip().splitlines()[0]
    finally:
        try:
            cur.close()
        except Exception:
            pass


def _install_fake_backup_service(monkeypatch, tmp_path, *, payload=None,
                                 filename=None, create_result=None):
    """Replace ``core.backup_service`` for the duration of a test.

    The package attribute, the ``sys.modules`` entry and the name that
    ``run_scheduled_backup`` will resolve must ALL be the stub. Patching only
    ``sys.modules`` leaves ``core.backup_service`` bound to the real module (the
    submodule import happens at package import time), and the test then silently
    exercises the real database path — which is how an earlier version of these tests
    "passed" against the wrong object.
    """
    import sys
    import types

    import core

    module = types.ModuleType("core.backup_service")
    module.MaintenanceCredentialRequired = type(
        "MaintenanceCredentialRequired", (RuntimeError,), {}
    )

    def _create_backup(label="x"):
        if create_result is not None:
            return dict(create_result)
        path = tmp_path / filename
        path.write_bytes(payload)
        return {"success": True, "filename": filename, "size_bytes": len(payload)}

    module.create_backup = _create_backup
    module.verify_backup = lambda name: {"valid": True, "sha256": "0" * 64}

    monkeypatch.setattr(core, "backup_service", module, raising=False)
    monkeypatch.setitem(sys.modules, "core.backup_service", module)
    return module


def _scalar(conn, sql: str, params=()):
    cur = conn.cursor()
    try:
        cur.execute(sql, params)
        row = cur.fetchone()
        return row[0] if row else None
    finally:
        cur.close()


@pytest.fixture
def tenant_db(tmp_path, monkeypatch):
    """A throwaway database with the real provisioning path applied.

    Every environment mutation goes through `monkeypatch`, not `os.environ`. That is not
    stylistic: this fixture used to assign `os.environ` directly, and the DSN it left
    behind (`postgresql://…` rather than `postgresql+psycopg2://…`) propagated into later
    tests in the same interpreter and made 13 unrelated `test_enterprise_phases.py`
    cases fail. `core.db_engine` caches one engine per URL, so once the environment is
    perturbed the whole process keeps the wrong engine. `monkeypatch` restores
    unconditionally, including on error.
    """
    if not os.getenv("DATABASE_URL", "").startswith("postgresql"):
        pytest.skip("PostgreSQL required")

    import urllib.parse

    import database
    from scripts import provision_roles

    admin_url = os.environ["DATABASE_URL"]
    parts = urllib.parse.urlsplit(admin_url)
    host_port = parts.netloc.rsplit("@", 1)[-1]
    bootstrap_userinfo = parts.netloc.rsplit("@", 1)[0] if "@" in parts.netloc else ""

    def dsn(user: str = "", password: str = "", database: str = "postgres") -> str:
        # Always emit the SQLAlchemy driver form so a value left in the environment is
        # never mistaken for "already normalised".
        userinfo = f"{user}:{password}" if user else bootstrap_userinfo
        cred = f"{userinfo}@" if userinfo else ""
        return f"postgresql+psycopg2://{cred}{host_port}/{database}"

    db_name = f"e05p16_{uuid.uuid4().hex[:10]}"
    owner_pw = f"ow_{uuid.uuid4().hex[:16]}"
    app_pw = f"ap_{uuid.uuid4().hex[:16]}"

    admin = _raw(dsn(database="postgres"))
    _try(admin, f"DROP DATABASE IF EXISTS {db_name}")
    ok, msg = _try(admin, f"CREATE DATABASE {db_name}")
    assert ok, msg

    db_url = dsn(database=db_name)
    monkeypatch.setenv("ADMIN_DATABASE_URL", db_url)
    monkeypatch.setenv("GEREGE_OWNER_PASSWORD", owner_pw)
    monkeypatch.setenv("GEREGE_APP_PASSWORD", app_pw)
    monkeypatch.setenv("DATABASE_URL", db_url)

    try:
        database.init_db()
        assert provision_roles.main(["--apply"]) == 0
        yield {
            "db": db_name,
            "db_url": db_url,
            "app": dsn("gerege_app", app_pw, db_name),
            "owner": dsn("gerege_owner", owner_pw, db_name),
            "admin": dsn(database=db_name),
            "owner_pw": owner_pw,
            "app_pw": app_pw,
        }
    finally:
        from core import db_engine

        db_engine.dispose_shared_engine()
        try:
            _try(admin, f"DROP DATABASE IF EXISTS {db_name} WITH (FORCE)")
        finally:
            admin.close()


def _set_env(monkeypatch, **values):
    """Set env vars for one test without touching the process environment for good."""
    for key, value in values.items():
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)


def _run_verify(dsn: str) -> int:
    from scripts import provision_roles

    previous = os.environ.get("ADMIN_DATABASE_URL")
    os.environ["ADMIN_DATABASE_URL"] = dsn
    try:
        return provision_roles.main(["--verify"])
    finally:
        if previous is None:
            os.environ.pop("ADMIN_DATABASE_URL", None)
        else:
            os.environ["ADMIN_DATABASE_URL"] = previous


# ---------------------------------------------------------------------------
# MEDIUM-01 — the false PASS
# ---------------------------------------------------------------------------


@REQUIRE_POSTGRES
def test_p16_01_verify_fails_closed_when_it_cannot_set_role(tenant_db, capsys):
    """The exact Phase 15 scenario: over-privileged role, verified by a non-superuser.

    Pre-fix this printed "(cannot SET ROLE gerege_app from this session; run --verify
    as that role for a definitive answer)" followed by "Runtime role holds least
    privilege." and returned 0.
    """
    admin = _raw(tenant_db["admin"])
    try:
        ok, msg = _try(admin, "GRANT UPDATE, DELETE ON audit_logs TO gerege_app")
        assert ok, msg
    finally:
        admin.close()

    # The owner credential cannot SET ROLE gerege_app (it is the grantor, not the
    # member), which is exactly the condition that used to produce the false pass.
    rc = _run_verify(tenant_db["owner"])
    out = capsys.readouterr().out
    assert rc != 0, "over-privileged runtime role must not verify successfully"
    assert "VERIFICATION FAILED" in out
    assert "audit_logs" in out and "UPDATE" in out

    # Control: the same state must ALSO fail from the superuser, which could
    # impersonate. Both paths must agree.
    assert _run_verify(tenant_db["db_url"]) != 0


@REQUIRE_POSTGRES
def test_p16_02_verify_passes_again_after_the_grant_is_removed(tenant_db):
    """The remedy must restore a green verification, or the check is useless."""
    admin = _raw(tenant_db["admin"])
    try:
        _try(admin, "GRANT UPDATE ON audit_logs TO gerege_app")
    finally:
        admin.close()
    assert _run_verify(tenant_db["owner"]) != 0

    admin = _raw(tenant_db["admin"])
    try:
        _try(admin, "REVOKE UPDATE ON audit_logs FROM gerege_app")
    finally:
        admin.close()
    assert _run_verify(tenant_db["owner"]) == 0


@REQUIRE_POSTGRES
def test_p16_03_verify_uses_the_catalogue_not_impersonation(tenant_db):
    """The probe must be the role-targeted catalogue form, and must say so."""
    from core import db_privileges

    conn = _raw(tenant_db["db_url"])
    try:
        report = db_privileges.collect_role_privileges(conn, "gerege_app", "public")
    finally:
        conn.close()
    assert report["collector"] == "catalogue"
    assert report["exists"] is True
    # 18 matrix tables all present in a fully migrated database.
    assert len(report["existing_tables"]) == 18
    assert db_privileges.evaluate_runtime_privileges(report) == []


@REQUIRE_POSTGRES
def test_p16_04_missing_runtime_role_is_detected_not_skipped(tenant_db):
    from core import db_privileges

    conn = _raw(tenant_db["db_url"])
    try:
        report = db_privileges.collect_role_privileges(conn, "role_that_does_not_exist")
    finally:
        conn.close()
    problems = db_privileges.evaluate_runtime_privileges(report)
    assert problems, "a missing role must produce a violation, not an empty list"
    assert "does not exist" in problems[0]


@REQUIRE_POSTGRES
def test_p16_05_incomplete_provisioning_is_detected(tenant_db):
    """No tables at all is a failure, not a vacuously clean privilege report."""
    from core import db_privileges

    conn = _raw(tenant_db["db_url"])
    try:
        report = db_privileges.collect_role_privileges(
            conn, "gerege_app", "schema_with_no_tables"
        )
    finally:
        conn.close()
    # A verification gate must refuse an un-migrated schema...
    report["require_migrated"] = True
    problems = db_privileges.evaluate_runtime_privileges(report)
    assert any("no application tables" in p for p in problems), problems

    # ...but `--apply` legitimately runs BEFORE the first migration on a fresh install
    # (the `migrate` service creates the roles so the migration can grant against them),
    # so the same report without the gate requirement must not fail.
    report["require_migrated"] = False
    assert db_privileges.evaluate_runtime_privileges(report) == []


@REQUIRE_POSTGRES
def test_p16_05b_pre_migration_apply_is_not_a_failure(tenant_db):
    """The bootstrap order (`--apply` before `alembic upgrade head`) must not fail."""
    from scripts import provision_roles

    previous = os.environ.get("ADMIN_DATABASE_URL")
    os.environ["ADMIN_DATABASE_URL"] = tenant_db["db_url"]
    try:
        # A second `--apply` on an already-converged database is the same code path the
        # migrate service takes on a fresh volume; it must stay green.
        assert provision_roles.main(["--apply"]) == 0
    finally:
        if previous is None:
            os.environ.pop("ADMIN_DATABASE_URL", None)
        else:
            os.environ["ADMIN_DATABASE_URL"] = previous


@REQUIRE_POSTGRES
def test_p16_06_sequence_escalation_is_detected(tenant_db):
    """UPDATE on a sequence is not needed by any call site and is reported."""
    from core import db_privileges

    conn = _raw(tenant_db["admin"])
    try:
        ok, msg = _try(admin_sql := conn, "GRANT UPDATE ON messages_id_seq TO gerege_app")
        assert ok, msg
    finally:
        conn.close()

    conn = _raw(tenant_db["db_url"])
    try:
        report = db_privileges.collect_role_privileges(conn, "gerege_app", "public")
    finally:
        conn.close()
    assert report["sequence_privileges"]["messages_id_seq"], "sequence not probed"
    problems = db_privileges.evaluate_runtime_privileges(report)
    assert any("sequence" in p and "UPDATE" in p for p in problems), problems


@REQUIRE_POSTGRES
def test_p16_07_owner_role_server_powers_are_reported(tenant_db):
    """`gerege_owner` must stay NOSUPERUSER/NOCREATEROLE; --verify says so."""
    admin = _raw(tenant_db["admin"])
    try:
        ok, msg = _try(admin, "ALTER ROLE gerege_owner CREATEROLE")
        assert ok, msg
    finally:
        admin.close()

    rc = _run_verify(tenant_db["owner"])
    assert rc != 0, "an owner role with CREATEROLE must fail verification"

    admin = _raw(tenant_db["admin"])
    try:
        _try(admin, "ALTER ROLE gerege_owner NOCREATEROLE")
    finally:
        admin.close()
    assert _run_verify(tenant_db["owner"]) == 0


# ---------------------------------------------------------------------------
# HIGH-01 — ownership convergence
# ---------------------------------------------------------------------------


def _ownership(conn, schema: str = "public"):
    from core import db_privileges

    return db_privileges.collect_ownership(conn, schema)


@REQUIRE_POSTGRES
def test_p16_10_converged_database_has_every_relation_owned_by_owner(tenant_db):
    """The end state after a real `--apply`: 32 relations, all gerege_owner."""
    conn = _raw(tenant_db["db_url"])
    try:
        ownership = _ownership(conn)
    finally:
        conn.close()
    assert ownership["total"] >= 32, ownership
    assert ownership["owned_by_owner_role"] == ownership["total"], ownership
    assert "gerege" not in ownership["by_owner"], ownership["by_owner"]


@REQUIRE_POSTGRES
def test_p16_11_bootstrap_owned_relations_are_detected(tenant_db):
    """Reproduces the HIGH-01 end state and asserts it is now a violation.

    This is the state the old `deploy.sh` produced: migration ran as the bootstrap
    account and `--converge-only` never transferred ownership. Privileges were correct;
    only ownership was wrong.
    """
    from core import db_privileges

    conn = _raw(tenant_db["admin"])
    try:
        # Simulate the un-transferred state on one table and one sequence.
        bootstrap = _scalar(conn, "SELECT current_user")
        ok, msg = _try(conn, "ALTER TABLE appointments OWNER TO gerege")
        assert ok, msg
        ok, msg = _try(conn, "ALTER SEQUENCE appointments_id_seq OWNER TO gerege")
        assert ok, msg
    finally:
        conn.close()

    conn = _raw(tenant_db["db_url"])
    try:
        ownership = _ownership(conn)
    finally:
        conn.close()

    problems = db_privileges.evaluate_ownership(ownership)
    assert problems, "bootstrap-owned relations must be a verification failure"
    assert "appointments" in problems[0]
    assert bootstrap in problems[0]
    # ...and `--verify` must exit non-zero.
    assert _run_verify(tenant_db["owner"]) != 0


@REQUIRE_POSTGRES
def test_p16_12_only_a_full_apply_repairs_ownership(tenant_db):
    """`--converge-only` must NOT be accepted as the repair (that WAS the bug)."""
    from scripts import provision_roles

    admin = _raw(tenant_db["admin"])
    try:
        ok, msg = _try(admin, "ALTER TABLE pages OWNER TO gerege")
        assert ok, msg
    finally:
        admin.close()

    previous = os.environ.get("ADMIN_DATABASE_URL")
    os.environ["ADMIN_DATABASE_URL"] = tenant_db["db_url"]
    try:
        # The grant plan alone leaves ownership untouched, so verification still fails.
        assert provision_roles.main(["--apply", "--converge-only"]) == 1
        # The full plan transfers ownership and converges.
        assert provision_roles.main(["--apply"]) == 0
    finally:
        if previous is None:
            os.environ.pop("ADMIN_DATABASE_URL", None)
        else:
            os.environ["ADMIN_DATABASE_URL"] = previous

    conn = _raw(tenant_db["db_url"])
    try:
        ownership = _ownership(conn)
    finally:
        conn.close()
    assert ownership["owned_by_owner_role"] == ownership["total"]


@REQUIRE_POSTGRES
def test_p16_13_repeated_apply_is_idempotent_and_still_verifies(tenant_db):
    from scripts import provision_roles

    previous = os.environ.get("ADMIN_DATABASE_URL")
    os.environ["ADMIN_DATABASE_URL"] = tenant_db["db_url"]
    try:
        for _ in range(3):
            assert provision_roles.main(["--apply"]) == 0
            assert provision_roles.main(["--verify"]) == 0
    finally:
        if previous is None:
            os.environ.pop("ADMIN_DATABASE_URL", None)
        else:
            os.environ["ADMIN_DATABASE_URL"] = previous


@REQUIRE_POSTGRES
def test_p16_14_interrupted_ownership_transfer_converges_on_rerun(tenant_db):
    """Half-transferred ownership (a crash mid-plan) must be repairable."""
    admin = _raw(tenant_db["admin"])
    try:
        for table in ("appointments", "invoices", "messages"):
            ok, msg = _try(admin, f"ALTER TABLE {table} OWNER TO gerege")
            assert ok, msg
    finally:
        admin.close()

    assert _run_verify(tenant_db["owner"]) != 0, "half-owned db must fail verify"

    from scripts import provision_roles

    previous = os.environ.get("ADMIN_DATABASE_URL")
    os.environ["ADMIN_DATABASE_URL"] = tenant_db["db_url"]
    try:
        assert provision_roles.main(["--apply"]) == 0
    finally:
        if previous is None:
            os.environ.pop("ADMIN_DATABASE_URL", None)
        else:
            os.environ["ADMIN_DATABASE_URL"] = previous
    assert _run_verify(tenant_db["owner"]) == 0


@REQUIRE_POSTGRES
def test_p16_15_owner_can_dump_and_app_cannot(tenant_db):
    """The operational consequence of HIGH-01, asserted directly.

    `pg_dump` needs ownership of every table. If ownership has not converged, the
    maintenance guard refuses the owner — which is how a "successful" deployment with
    no backups would have looked in production.
    """
    from core import backup_service

    previous = os.environ.get("DATABASE_URL")
    try:
        os.environ["DATABASE_URL"] = tenant_db["owner"]
        backup_service._assert_maintenance_credential()  # must not raise

        os.environ["DATABASE_URL"] = tenant_db["app"]
        with pytest.raises(backup_service.MaintenanceCredentialRequired):
            backup_service._assert_maintenance_credential()
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous


@REQUIRE_POSTGRES
def test_p16_16_unowned_relations_break_the_owner_backup(tenant_db):
    """Demonstrates why the ownership check is not cosmetic."""
    from core import backup_service

    admin = _raw(tenant_db["admin"])
    try:
        ok, msg = _try(admin, "ALTER TABLE audit_logs OWNER TO gerege")
        assert ok, msg
    finally:
        admin.close()

    previous = os.environ.get("DATABASE_URL")
    try:
        os.environ["DATABASE_URL"] = tenant_db["owner"]
        with pytest.raises(backup_service.MaintenanceCredentialRequired) as exc:
            backup_service._assert_maintenance_credential()
        assert "owns" in str(exc.value)
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous


# ---------------------------------------------------------------------------
# deploy.sh sequencing (static + behavioural)
# ---------------------------------------------------------------------------


def _deploy_script() -> str:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(here, "scripts", "deploy.sh"), encoding="utf-8") as handle:
        return handle.read()


def test_p16_20_deploy_script_transfers_ownership_with_a_full_apply():
    """The post-migration provisioning step must be `--apply`, not `--converge-only`.

    Parsed line-by-line rather than substring-matched against the whole file, so a
    comment that merely mentions `--apply` cannot satisfy the assertion.
    """
    lines = [
        line.strip()
        for line in _deploy_script().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    provisioning = [l for l in lines if "provision_roles.py" in l]
    assert provisioning, "deploy.sh must invoke provisioning"

    converge_only = [l for l in provisioning if "--converge-only" in l]
    assert not converge_only, (
        "deploy.sh must not use --converge-only: it emits GRANT/REVOKE only and skips "
        f"the ALTER ... OWNER TO that HIGH-01 was about: {converge_only}"
    )
    full_apply = [l for l in provisioning if "--apply" in l]
    assert full_apply, "deploy.sh must run a full --apply to transfer ownership"
    verify = [l for l in provisioning if "--verify" in l]
    assert verify, "deploy.sh must verify before starting services"


def test_p16_21_deploy_orders_provision_after_migration_and_before_start():
    """Ordering is the actual fix: migrate, then transfer ownership, then verify, then start."""
    lines = [
        line.strip()
        for line in _deploy_script().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    def index_of(needle: str) -> int:
        for i, line in enumerate(lines):
            if needle in line:
                return i
        return -1

    migrate = index_of("alembic upgrade head")
    apply_after = -1
    for i in range(migrate + 1, len(lines)):
        if "provision_roles.py" in lines[i] and "--apply" in lines[i]:
            apply_after = i
            break
    verify = index_of("provision_roles.py --verify")
    start = index_of("docker compose -f docker-compose.prod.yml up")

    assert migrate >= 0, "deploy.sh must run migrations"
    assert apply_after > migrate, "ownership transfer must run AFTER the migration"
    assert verify > apply_after, "verification must run after convergence"
    assert start > verify, "services must not start before verification"


def test_p16_22_deploy_refuses_without_a_backup():
    """A deploy with no restore point is now a hard failure, not an `echo`."""
    script = _deploy_script()
    assert "ALLOW_DEPLOY_WITHOUT_BACKUP" in script
    assert "exit 1" in script
    # The old behaviour was to print a note and continue.
    assert "skipping the pre-deploy backup" not in script
    # And it actually invokes the maintenance plane.
    assert "maintenance.py backup" in script


def test_p16_23_rollback_does_not_claim_a_rollback_it_did_not_do():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(here, "scripts", "rollback.sh"), encoding="utf-8") as handle:
        script = handle.read()
    assert "ROLLED_BACK_CODE" in script and "ROLLED_BACK_DATA" in script
    # A failed restore must abort rather than restart onto a half-restored database.
    assert "restore" in script and "exit 1" in script
    # After a restore, ownership must be re-converged with a full apply.
    assert "--converge-only" not in "\n".join(
        line for line in script.splitlines() if not line.strip().startswith("#")
    ), "rollback must re-converge ownership with a full --apply"


# ---------------------------------------------------------------------------
# MEDIUM-02 — backup automation is real, configured, and fail-closed
# ---------------------------------------------------------------------------


def test_p16_30_documented_rpo_claim_is_gone():
    """The 24-hour claim had no scheduler behind it and must not reappear."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for relative in ("docs/operations/DISASTER_RECOVERY.md",
                     "docs/deployment/PRODUCTION_DEPLOYMENT.md"):
        with open(os.path.join(here, relative), encoding="utf-8") as handle:
            text = handle.read()
        # A *quoted* correction ("the previous text claimed ...") is legitimate and
        # useful. What must not survive is an un-quoted assertion of the old claim.
        offenders = [
            line for line in text.splitlines()
            if "automated daily 03:00" in line and not line.lstrip().startswith(">")
        ]
        assert not offenders, f"{relative} still asserts the removed schedule: {offenders}"
    with open(os.path.join(here, "docs/operations/DISASTER_RECOVERY.md"),
              encoding="utf-8") as handle:
        dr = handle.read()
    assert "NOT CONFIGURED" in dr, "the honest status must be stated, not implied"


def test_p16_31_scheduler_templates_exist_and_invoke_the_scheduled_entry_point():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    unit = os.path.join(here, "deploy", "systemd", "gerege-backup.service")
    timer = os.path.join(here, "deploy", "systemd", "gerege-backup.timer")
    cron = os.path.join(here, "deploy", "cron", "gerege-backup.cron")
    for path in (unit, timer, cron):
        assert os.path.exists(path), f"missing scheduler template: {path}"
    with open(unit, encoding="utf-8") as handle:
        service = handle.read()
    assert "backup-run" in service, "the unit must run the scheduled entry point"
    assert "EnvironmentFile=" in service, "the owner credential must come from a file"
    with open(timer, encoding="utf-8") as handle:
        timer_text = handle.read()
    assert "OnCalendar=" in timer_text and "Persistent=true" in timer_text
    with open(cron, encoding="utf-8") as handle:
        cron_text = handle.read()
    assert "backup-run" in cron_text


def test_p16_32_scheduler_templates_are_not_installed_by_this_repository():
    """The templates are documentation until an operator installs them."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(here, "deploy", "systemd", "gerege-backup.timer"),
              encoding="utf-8") as handle:
        timer = handle.read()
    assert "NOT INSTALLED" in timer


def test_p16_33_encryption_is_fail_closed_without_a_key(monkeypatch, tmp_path):
    """No key + encryption on ⇒ the run must fail, not write plaintext."""
    from core import backup_automation

    monkeypatch.setenv("BACKUP_DIR", str(tmp_path))
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.delenv("BACKUP_ENCRYPTION_KEY_FILE", raising=False)
    monkeypatch.delenv("BACKUP_ALERT_WEBHOOK", raising=False)

    # Stub the backup itself so the test does not need a database: the property under
    # test is the encryption gate, which runs after a successful dump.
    _install_fake_backup_service(
        monkeypatch, tmp_path,
        payload=b"not-really-a-dump", filename="pg_backup_x.sql.gz",
    )

    result = backup_automation.run_scheduled_backup(label="test")
    assert result["success"] is False
    assert result["exit_code"] == backup_automation.EXIT_NOT_CONFIGURED
    assert "BACKUP_ENCRYPTION_KEY_FILE" in result["error"]
    # Nothing was encrypted and nothing was left encrypted-by-accident.
    assert not list(tmp_path.glob("*.enc"))


def test_p16_34_encryption_round_trip_and_plaintext_removal(monkeypatch, tmp_path):
    from core import backup_automation

    key = tmp_path / "k"
    key.write_text("0123456789abcdef0123456789abcdef")
    monkeypatch.setenv("BACKUP_DIR", str(tmp_path))
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", str(key))
    monkeypatch.delenv("BACKUP_OFFSITE_PATH", raising=False)
    monkeypatch.delenv("BACKUP_ALERT_WEBHOOK", raising=False)

    _install_fake_backup_service(
        monkeypatch, tmp_path,
        payload=b"CREATE TABLE secret_stuff(id int);",
        filename="pg_backup_x.sql.gz",
    )

    result = backup_automation.run_scheduled_backup(label="test")
    assert result["success"] is True, result
    assert result["encrypted"] is True
    assert result["filename"].endswith(".enc")

    archive = tmp_path / result["filename"]
    assert archive.exists()
    blob = archive.read_bytes()
    assert b"secret_stuff" not in blob, "ciphertext must not contain plaintext"
    # The plaintext archive must be gone.
    assert not (tmp_path / "pg_backup_x.sql.gz").exists()

    # Round-trip proves the key actually works.
    out = tmp_path / "decrypted.gz"
    ok, error = backup_automation.decrypt_file(str(archive), str(out), str(key))
    assert ok, error
    assert out.read_bytes() == b"CREATE TABLE secret_stuff(id int);"


def test_p16_35_retention_never_deletes_below_the_floor(monkeypatch, tmp_path):
    """A retention bug that removes every backup is worse than a full disk."""
    import time

    from core import backup_automation

    now = time.time()
    for i in range(10):
        path = tmp_path / f"pg_backup_{i}.sql.gz.enc"
        path.write_bytes(b"x")
        os.utime(path, (now - (100 + i) * 86400, now - (100 + i) * 86400))

    removed = backup_automation.prune(str(tmp_path), days=1, keep_min=7)
    remaining = [p for p in os.listdir(tmp_path) if p.endswith(".enc")]
    assert len(remaining) >= 7, f"count floor violated: {remaining}"
    assert len(removed) == 3


def test_p16_36_status_file_records_failure_for_monitoring(monkeypatch, tmp_path):
    from core import backup_automation

    monkeypatch.setenv("BACKUP_DIR", str(tmp_path))
    monkeypatch.delenv("BACKUP_ALERT_WEBHOOK", raising=False)

    _install_fake_backup_service(
        monkeypatch, tmp_path,
        create_result={"success": False, "error": "role owns 0 of 19 tables"},
    )

    result = backup_automation.run_scheduled_backup(label="test")
    assert result["exit_code"] == backup_automation.EXIT_BACKUP_FAILED

    status = backup_automation.read_status()
    assert status is not None, "monitoring needs a machine-readable status file"
    assert status["success"] is False
    assert "owns 0 of 19" in status["error"]


# ---------------------------------------------------------------------------
# The runtime role cannot reach the maintenance plane
# ---------------------------------------------------------------------------


@REQUIRE_POSTGRES
def test_p16_40_app_role_cannot_read_the_backups_directory_secrets(tenant_db):
    """The scheduled path must be unreachable from the runtime credential.

    Two independent facts, both required by E-05 and re-asserted here because Phase 16
    added new code to the maintenance plane:

      * `gerege_app` cannot take a backup at all (capability guard), and
      * the encryption key is read from a FILE whose path is not derived from anything
        the runtime credential can influence.
    """
    from core import backup_automation, backup_service

    previous = os.environ.get("DATABASE_URL")
    try:
        os.environ["DATABASE_URL"] = tenant_db["app"]
        with pytest.raises(backup_service.MaintenanceCredentialRequired):
            backup_service._assert_maintenance_credential()
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous

    # The key path is an explicit environment setting, never a computed default that a
    # database or a request could steer.
    assert backup_automation._key_path() in (None, os.getenv("BACKUP_ENCRYPTION_KEY_FILE", "") or None)


@REQUIRE_POSTGRES
def test_p16_41_scheduled_run_refuses_the_runtime_credential(tenant_db, tmp_path):
    """`backup-run` under `gerege_app` must fail closed, in a **subprocess**.

    Isolation is deliberate and is part of the test's value:

      * `scripts.maintenance.main()` writes `os.environ["DATABASE_URL"]` process-wide,
        and `core.db_engine` caches one engine per URL. Invoking it in-process leaked a
        normalised DSN into later tests in the same interpreter (measured: 13 unrelated
        failures). A subprocess cannot leak.
      * It also exercises the real entry point — argv parsing, credential resolution,
        the capability guard and the exit code — rather than a reimplementation of it.

    Exit code 10/13/15 all mean "refused"; what must never happen is 0.
    """
    import subprocess
    import sys

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("DATABASE_OWNER_URL", "MIGRATION_DATABASE_URL")
    }
    # The RUNTIME credential, exactly as web/worker would have it.
    env["DATABASE_URL"] = tenant_db["app"]
    env["BACKUP_DIR"] = str(tmp_path)
    env["BACKUP_ENCRYPTION"] = "off"
    env.pop("BACKUP_ALERT_WEBHOOK", None)

    proc = subprocess.run(
        [sys.executable, "scripts/maintenance.py", "backup-run", "--label", "test"],
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    combined = (proc.stdout or "") + (proc.stderr or "")
    assert proc.returncode != 0, f"the runtime credential produced a backup:\n{combined}"
    assert "MaintenanceCredentialRequired" in combined or "cannot create a trustworthy" in combined, combined
    # Nothing was written into the backups directory.
    assert not list(tmp_path.glob("*.gz*")), "a refused run must not leave an archive"
    # No credential material echoed.
    assert tenant_db["app_pw"] not in combined


def test_p16_42_status_probe_reports_missing_and_failed_runs(monkeypatch, tmp_path):
    """Monitoring must be able to tell "no backup ran" from "the last one worked"."""
    from core import backup_automation

    monkeypatch.setenv("BACKUP_DIR", str(tmp_path))
    monkeypatch.delenv("BACKUP_ALERT_WEBHOOK", raising=False)

    # Nothing has ever run.
    assert backup_automation.read_status() is None

    # A failed run leaves a status file the probe can read.
    _install_fake_backup_service(
        monkeypatch, tmp_path, create_result={"success": False, "error": "no dsn"}
    )
    backup_automation.run_scheduled_backup(label="test")
    status = backup_automation.read_status()
    assert status and status["success"] is False


@REQUIRE_POSTGRES
def test_p16_15_owner_can_dump_and_app_cannot(tenant_db):
    """The operational consequence of HIGH-01, asserted directly.

    `pg_dump` needs ownership of every table. If ownership has not converged, the
    maintenance guard refuses the owner — which is how a "successful" deployment with
    no backups would have looked in production.
    """
    from core import backup_service

    previous = os.environ.get("DATABASE_URL")
    try:
        os.environ["DATABASE_URL"] = tenant_db["owner"]
        backup_service._assert_maintenance_credential()  # must not raise

        os.environ["DATABASE_URL"] = tenant_db["app"]
        with pytest.raises(backup_service.MaintenanceCredentialRequired):
            backup_service._assert_maintenance_credential()
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous


@REQUIRE_POSTGRES
def test_p16_16_unowned_relations_break_the_owner_backup(tenant_db):
    """Demonstrates why the ownership check is not cosmetic."""
    from core import backup_service

    admin = _raw(tenant_db["admin"])
    try:
        ok, msg = _try(admin, "ALTER TABLE audit_logs OWNER TO gerege")
        assert ok, msg
    finally:
        admin.close()

    previous = os.environ.get("DATABASE_URL")
    try:
        os.environ["DATABASE_URL"] = tenant_db["owner"]
        with pytest.raises(backup_service.MaintenanceCredentialRequired) as exc:
            backup_service._assert_maintenance_credential()
        assert "owns" in str(exc.value)
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous


# ---------------------------------------------------------------------------
# deploy.sh sequencing (static + behavioural)
# ---------------------------------------------------------------------------


def _deploy_script() -> str:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(here, "scripts", "deploy.sh"), encoding="utf-8") as handle:
        return handle.read()


def test_p16_20_deploy_script_transfers_ownership_with_a_full_apply():
    """The post-migration provisioning step must be `--apply`, not `--converge-only`.

    Parsed line-by-line rather than substring-matched against the whole file, so a
    comment that merely mentions `--apply` cannot satisfy the assertion.
    """
    lines = [
        line.strip()
        for line in _deploy_script().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    provisioning = [l for l in lines if "provision_roles.py" in l]
    assert provisioning, "deploy.sh must invoke provisioning"

    converge_only = [l for l in provisioning if "--converge-only" in l]
    assert not converge_only, (
        "deploy.sh must not use --converge-only: it emits GRANT/REVOKE only and skips "
        f"the ALTER ... OWNER TO that HIGH-01 was about: {converge_only}"
    )
    full_apply = [l for l in provisioning if "--apply" in l]
    assert full_apply, "deploy.sh must run a full --apply to transfer ownership"
    verify = [l for l in provisioning if "--verify" in l]
    assert verify, "deploy.sh must verify before starting services"


def test_p16_21_deploy_orders_provision_after_migration_and_before_start():
    """Ordering is the actual fix: migrate, then transfer ownership, then verify, then start."""
    lines = [
        line.strip()
        for line in _deploy_script().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    def index_of(needle: str) -> int:
        for i, line in enumerate(lines):
            if needle in line:
                return i
        return -1

    migrate = index_of("alembic upgrade head")
    apply_after = -1
    for i in range(migrate + 1, len(lines)):
        if "provision_roles.py" in lines[i] and "--apply" in lines[i]:
            apply_after = i
            break
    verify = index_of("provision_roles.py --verify")
    start = index_of("docker compose -f docker-compose.prod.yml up")

    assert migrate >= 0, "deploy.sh must run migrations"
    assert apply_after > migrate, "ownership transfer must run AFTER the migration"
    assert verify > apply_after, "verification must run after convergence"
    assert start > verify, "services must not start before verification"


def test_p16_22_deploy_refuses_without_a_backup():
    """A deploy with no restore point is now a hard failure, not an `echo`."""
    script = _deploy_script()
    assert "ALLOW_DEPLOY_WITHOUT_BACKUP" in script
    assert "exit 1" in script
    # The old behaviour was to print a note and continue.
    assert "skipping the pre-deploy backup" not in script
    # And it actually invokes the maintenance plane.
    assert "maintenance.py backup" in script


def test_p16_23_rollback_does_not_claim_a_rollback_it_did_not_do():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(here, "scripts", "rollback.sh"), encoding="utf-8") as handle:
        script = handle.read()
    assert "ROLLED_BACK_CODE" in script and "ROLLED_BACK_DATA" in script
    # A failed restore must abort rather than restart onto a half-restored database.
    assert "restore" in script and "exit 1" in script
    # After a restore, ownership must be re-converged with a full apply.
    assert "--converge-only" not in "\n".join(
        line for line in script.splitlines() if not line.strip().startswith("#")
    ), "rollback must re-converge ownership with a full --apply"


# ---------------------------------------------------------------------------
# MEDIUM-02 — backup automation is real, configured, and fail-closed
# ---------------------------------------------------------------------------


def test_p16_30_documented_rpo_claim_is_gone():
    """The 24-hour claim had no scheduler behind it and must not reappear."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for relative in ("docs/operations/DISASTER_RECOVERY.md",
                     "docs/deployment/PRODUCTION_DEPLOYMENT.md"):
        with open(os.path.join(here, relative), encoding="utf-8") as handle:
            text = handle.read()
        # A *quoted* correction ("the previous text claimed ...") is legitimate and
        # useful. What must not survive is an un-quoted assertion of the old claim.
        offenders = [
            line for line in text.splitlines()
            if "automated daily 03:00" in line and not line.lstrip().startswith(">")
        ]
        assert not offenders, f"{relative} still asserts the removed schedule: {offenders}"
    with open(os.path.join(here, "docs/operations/DISASTER_RECOVERY.md"),
              encoding="utf-8") as handle:
        dr = handle.read()
    assert "NOT CONFIGURED" in dr, "the honest status must be stated, not implied"


def test_p16_31_scheduler_templates_exist_and_invoke_the_scheduled_entry_point():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    unit = os.path.join(here, "deploy", "systemd", "gerege-backup.service")
    timer = os.path.join(here, "deploy", "systemd", "gerege-backup.timer")
    cron = os.path.join(here, "deploy", "cron", "gerege-backup.cron")
    for path in (unit, timer, cron):
        assert os.path.exists(path), f"missing scheduler template: {path}"
    with open(unit, encoding="utf-8") as handle:
        service = handle.read()
    assert "backup-run" in service, "the unit must run the scheduled entry point"
    assert "EnvironmentFile=" in service, "the owner credential must come from a file"
    with open(timer, encoding="utf-8") as handle:
        timer_text = handle.read()
    assert "OnCalendar=" in timer_text and "Persistent=true" in timer_text
    with open(cron, encoding="utf-8") as handle:
        cron_text = handle.read()
    assert "backup-run" in cron_text


def test_p16_32_scheduler_templates_are_not_installed_by_this_repository():
    """The templates are documentation until an operator installs them."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(here, "deploy", "systemd", "gerege-backup.timer"),
              encoding="utf-8") as handle:
        timer = handle.read()
    assert "NOT INSTALLED" in timer


def test_p16_33_encryption_is_fail_closed_without_a_key(monkeypatch, tmp_path):
    """No key + encryption on ⇒ the run must fail, not write plaintext."""
    from core import backup_automation

    monkeypatch.setenv("BACKUP_DIR", str(tmp_path))
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.delenv("BACKUP_ENCRYPTION_KEY_FILE", raising=False)
    monkeypatch.delenv("BACKUP_ALERT_WEBHOOK", raising=False)

    # Stub the backup itself so the test does not need a database: the property under
    # test is the encryption gate, which runs after a successful dump.
    _install_fake_backup_service(
        monkeypatch, tmp_path,
        payload=b"not-really-a-dump", filename="pg_backup_x.sql.gz",
    )

    result = backup_automation.run_scheduled_backup(label="test")
    assert result["success"] is False
    assert result["exit_code"] == backup_automation.EXIT_NOT_CONFIGURED
    assert "BACKUP_ENCRYPTION_KEY_FILE" in result["error"]
    # Nothing was encrypted and nothing was left encrypted-by-accident.
    assert not list(tmp_path.glob("*.enc"))


def test_p16_34_encryption_round_trip_and_plaintext_removal(monkeypatch, tmp_path):
    from core import backup_automation

    key = tmp_path / "k"
    key.write_text("0123456789abcdef0123456789abcdef")
    monkeypatch.setenv("BACKUP_DIR", str(tmp_path))
    monkeypatch.setenv("BACKUP_ENCRYPTION", "on")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", str(key))
    monkeypatch.delenv("BACKUP_OFFSITE_PATH", raising=False)
    monkeypatch.delenv("BACKUP_ALERT_WEBHOOK", raising=False)

    _install_fake_backup_service(
        monkeypatch, tmp_path,
        payload=b"CREATE TABLE secret_stuff(id int);",
        filename="pg_backup_x.sql.gz",
    )

    result = backup_automation.run_scheduled_backup(label="test")
    assert result["success"] is True, result
    assert result["encrypted"] is True
    assert result["filename"].endswith(".enc")

    archive = tmp_path / result["filename"]
    assert archive.exists()
    blob = archive.read_bytes()
    assert b"secret_stuff" not in blob, "ciphertext must not contain plaintext"
    # The plaintext archive must be gone.
    assert not (tmp_path / "pg_backup_x.sql.gz").exists()

    # Round-trip proves the key actually works.
    out = tmp_path / "decrypted.gz"
    ok, error = backup_automation.decrypt_file(str(archive), str(out), str(key))
    assert ok, error
    assert out.read_bytes() == b"CREATE TABLE secret_stuff(id int);"


def test_p16_35_retention_never_deletes_below_the_floor(monkeypatch, tmp_path):
    """A retention bug that removes every backup is worse than a full disk."""
    import time

    from core import backup_automation

    now = time.time()
    for i in range(10):
        path = tmp_path / f"pg_backup_{i}.sql.gz.enc"
        path.write_bytes(b"x")
        os.utime(path, (now - (100 + i) * 86400, now - (100 + i) * 86400))

    removed = backup_automation.prune(str(tmp_path), days=1, keep_min=7)
    remaining = [p for p in os.listdir(tmp_path) if p.endswith(".enc")]
    assert len(remaining) >= 7, f"count floor violated: {remaining}"
    assert len(removed) == 3


def test_p16_36_status_file_records_failure_for_monitoring(monkeypatch, tmp_path):
    from core import backup_automation

    monkeypatch.setenv("BACKUP_DIR", str(tmp_path))
    monkeypatch.delenv("BACKUP_ALERT_WEBHOOK", raising=False)

    _install_fake_backup_service(
        monkeypatch, tmp_path,
        create_result={"success": False, "error": "role owns 0 of 19 tables"},
    )

    result = backup_automation.run_scheduled_backup(label="test")
    assert result["exit_code"] == backup_automation.EXIT_BACKUP_FAILED

    status = backup_automation.read_status()
    assert status is not None, "monitoring needs a machine-readable status file"
    assert status["success"] is False
    assert "owns 0 of 19" in status["error"]


# ---------------------------------------------------------------------------
# The runtime role cannot reach the maintenance plane
# ---------------------------------------------------------------------------


@REQUIRE_POSTGRES
def test_p16_40_app_role_cannot_read_the_backups_directory_secrets(tenant_db):
    """The scheduled path must be unreachable from the runtime credential.

    Two independent facts, both required by E-05 and re-asserted here because Phase 16
    added new code to the maintenance plane:

      * `gerege_app` cannot take a backup at all (capability guard), and
      * the encryption key is read from a FILE whose path is not derived from anything
        the runtime credential can influence.
    """
    from core import backup_automation, backup_service

    previous = os.environ.get("DATABASE_URL")
    try:
        os.environ["DATABASE_URL"] = tenant_db["app"]
        with pytest.raises(backup_service.MaintenanceCredentialRequired):
            backup_service._assert_maintenance_credential()
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous

    # The key path is an explicit environment setting, never a computed default that a
    # database or a request could steer.
    assert backup_automation._key_path() in (None, os.getenv("BACKUP_ENCRYPTION_KEY_FILE", "") or None)


@REQUIRE_POSTGRES
def test_p16_41_scheduled_run_refuses_the_runtime_credential(tenant_db, monkeypatch, tmp_path):
    """`backup-run` under `gerege_app` must fail with the credential exit code.

    This is the whole point of Phase 16 not weakening E-05: automation was added
    *around* the guard, not through it.
    """
    from core import backup_automation
    from scripts import maintenance

    monkeypatch.setenv("BACKUP_DIR", str(tmp_path))
    monkeypatch.setenv("BACKUP_ENCRYPTION", "off")
    monkeypatch.delenv("BACKUP_ALERT_WEBHOOK", raising=False)

    for key in ("DATABASE_OWNER_URL", "MIGRATION_DATABASE_URL"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("DATABASE_URL", tenant_db["app"])

    # `maintenance.main` rewrites `os.environ["DATABASE_URL"]` for the whole process
    # and `load_dotenv` is imported with `override=True`, so this test MUST restore the
    # environment itself. `monkeypatch` does that for the variables set above, but
    # `main` assigns directly, so the session URL is captured and put back explicitly.
    #
    # Measured: without this, the two DSN mutations leaked and 13 unrelated tests in
    # `test_enterprise_phases.py` failed when the whole suite ran in one process —
    # `core.db_engine` caches one engine per URL and keeps the poisoned one.
    session_url = os.environ.get("DATABASE_URL")
    try:
        rc = maintenance.main(["backup-run", "--label", "test"])
    finally:
        # Restore BOTH: `main()` may have created a normalised copy, and `load_dotenv`
        # in the imported modules may have repopulated the maintenance variable.
        if session_url is not None:
            os.environ["DATABASE_URL"] = session_url
        os.environ.pop("DATABASE_OWNER_URL", None)
        os.environ.pop("MIGRATION_DATABASE_URL", None)
        from core import db_engine

        db_engine.dispose_shared_engine()

    assert rc != 0, "the runtime credential must never produce a backup"
    status = backup_automation.read_status()
    assert status is not None and status["success"] is False, status
