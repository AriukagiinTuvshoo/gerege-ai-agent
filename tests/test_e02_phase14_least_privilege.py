"""E-05: least-privilege runtime role separation.

These tests answer one question: *if the runtime credential is stolen or the
deployment is misconfigured, can the audit trail still be destroyed?* On the old
single-superuser model the answer was yes — Phase 13 measured `DROP TRIGGER`,
`ALTER TABLE ... DISABLE TRIGGER` and `SET session_replication_role = replica` all
succeeding against the runtime credential, which made the append-only trigger advisory.

Two groups:

* **Role-independent** (run on SQLite and PostgreSQL). The evaluator, the provisioning
  planner, the maintenance-credential guard and the removed endpoints. These encode the
  policy, so they must not be skippable on the default engine.
* **PostgreSQL-only** (skipped on SQLite, which has no roles). Real roles, real grants,
  real attacks — creating `gerege_owner`/`gerege_app` in a throwaway database and
  proving what they can and cannot do.

Everything that needs PostgreSQL is skipped, never silently passed: a green suite on
SQLite must not be readable as "the role split was verified".
"""
from __future__ import annotations

import os
import uuid

import pytest

REQUIRE_POSTGRES = pytest.mark.skipif(
    not os.getenv("DATABASE_URL", "").startswith("postgresql"),
    reason="needs PostgreSQL: SQLite has no roles to separate",
)


def _pg():
    from core.db_engine import is_postgres

    return is_postgres()


def _raw(url: str):
    import psycopg2

    for prefix in ("postgresql+psycopg2://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            url = "postgresql://" + url[len(prefix):]
    conn = psycopg2.connect(url)
    conn.autocommit = True
    return conn


def _try(conn, sql: str):
    """Return (succeeded, message). Never raises."""
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


# ---------------------------------------------------------------------------
# Role-independent: the policy itself
# ---------------------------------------------------------------------------
def test_e05_01_audit_logs_is_the_only_table_narrowed_to_select_insert():
    """The matrix must be restrictive in exactly one place, and deliberately."""
    from core.db_privileges import REQUIRED_TABLE_PRIVILEGES

    narrowed = {
        table: sorted(privs)
        for table, privs in REQUIRED_TABLE_PRIVILEGES.items()
        if set(privs) != {"SELECT", "INSERT", "UPDATE", "DELETE"}
    }
    assert narrowed == {"audit_logs": ["INSERT", "SELECT"]}, narrowed


def test_e05_02_no_table_grants_truncate_references_or_trigger():
    from core.db_privileges import (
        ALWAYS_FORBIDDEN_PRIVILEGES,
        REQUIRED_TABLE_PRIVILEGES,
    )

    for table, privs in REQUIRED_TABLE_PRIVILEGES.items():
        leaked = set(privs) & ALWAYS_FORBIDDEN_PRIVILEGES
        assert not leaked, f"{table} would be granted {leaked}"


def test_e05_03_no_readonly_role_is_created():
    """Decision 2: do not add a role without a consumer.

    Asserted as a property of the provisioning script rather than of a comment, so a
    later edit that starts creating `gerege_readonly` has to delete this test.
    """
    from scripts import provision_roles

    plan_source = provision_roles.__doc__ + provision_roles.build_plan.__doc__
    assert "gerege_readonly" in plan_source, "the 'why not' must stay documented"
    assert not hasattr(provision_roles, "READONLY_ROLE")
    assert provision_roles.RUNTIME_ROLE == "gerege_app"
    assert provision_roles.OWNER_ROLE == "gerege_owner"


def test_e05_04_evaluator_flags_a_superuser():
    from core.db_privileges import evaluate_runtime_privileges

    problems = evaluate_runtime_privileges(
        {
            "role": "postgres",
            "superuser": True,
            "memberships": [],
            "owned_relations": 0,
            "can_become_owner": False,
            "is_database_owner": False,
            "schema_create": True,
            "table_privileges": {},
        }
    )
    joined = " ".join(problems)
    assert "SUPERUSER" in joined
    # A superuser is implicitly a member of every role; that must not be repeated.
    assert "member of" not in joined


def test_e05_05_evaluator_flags_audit_update_and_delete_separately():
    from core.db_privileges import evaluate_runtime_privileges

    problems = evaluate_runtime_privileges(
        {
            "role": "gerege_app",
            "superuser": False,
            "memberships": [],
            "owned_relations": 0,
            "can_become_owner": False,
            "is_database_owner": False,
            "schema_create": False,
            "table_privileges": {"audit_logs": ["SELECT", "INSERT", "UPDATE", "DELETE"]},
            "existing_tables": ["audit_logs"],
        }
    )
    joined = " ".join(problems)
    assert "audit_logs: role holds UPDATE" in joined
    assert "audit_logs: role holds DELETE" in joined


def test_e05_06_evaluator_flags_missing_grants_as_well_as_extra():
    """Under-granting is a failure mode too: it breaks the app at query time."""
    from core.db_privileges import evaluate_runtime_privileges

    problems = evaluate_runtime_privileges(
        {
            "role": "gerege_app",
            "superuser": False,
            "memberships": [],
            "owned_relations": 0,
            "can_become_owner": False,
            "is_database_owner": False,
            "schema_create": False,
            "table_privileges": {"pages": ["SELECT"], "audit_logs": ["SELECT", "INSERT"]},
            "existing_tables": ["pages", "audit_logs"],
        }
    )
    joined = " ".join(problems)
    assert "missing" in joined and "pages" in joined
    assert "audit_logs" not in joined


def test_e05_07_evaluator_is_silent_for_a_correct_role():
    from core.db_privileges import REQUIRED_TABLE_PRIVILEGES, evaluate_runtime_privileges

    report = {
        "role": "gerege_app",
        "superuser": False,
        "memberships": [],
        "owned_relations": 0,
        "can_become_owner": False,
        "is_database_owner": False,
        "schema_create": False,
        "table_privileges": {t: sorted(p) for t, p in REQUIRED_TABLE_PRIVILEGES.items()},
        "existing_tables": sorted(REQUIRED_TABLE_PRIVILEGES),
    }
    assert evaluate_runtime_privileges(report) == []


def test_e05_08_database_ownership_is_a_violation():
    """The PG15+ `pg_database_owner` path: owning the DB implies owning public."""
    from core.db_privileges import evaluate_runtime_privileges

    problems = evaluate_runtime_privileges(
        {
            "role": "gerege_app",
            "superuser": False,
            "memberships": [],
            "owned_relations": 0,
            "can_become_owner": False,
            "is_database_owner": True,
            "database_owner": "gerege_app",
            "schema_create": False,
            "table_privileges": {},
            "existing_tables": [],
        }
    )
    assert any("owns the database" in p for p in problems), problems


def test_e05_09_enforcement_is_off_outside_production_and_tests(monkeypatch):
    """Development and the SQLite default must not be blocked by this check."""
    from core import db_privileges

    monkeypatch.delenv("REQUIRE_LEAST_PRIVILEGE", raising=False)
    monkeypatch.delenv("ENV", raising=False)
    monkeypatch.delenv("STRICT_SECURITY", raising=False)
    assert db_privileges.enforcement_enabled() is False

    monkeypatch.setenv("REQUIRE_LEAST_PRIVILEGE", "1")
    assert db_privileges.enforcement_enabled() is True

    monkeypatch.delenv("REQUIRE_LEAST_PRIVILEGE")
    monkeypatch.setenv("ENV", "production")
    assert db_privileges.enforcement_enabled() is True


def test_e05_10_sqlite_boot_is_a_noop_not_a_failure(tmp_path, monkeypatch):
    """A SQLite database has no roles; the assertion must not fail closed on it."""
    db_path = tmp_path / "e05_sqlite.db"
    monkeypatch.setenv("DB_PATH", str(db_path))
    monkeypatch.delenv("DATABASE_URL", raising=False)

    from core import db_privileges

    report = db_privileges.assert_runtime_is_least_privileged(force=True)
    assert report["dialect"] == "sqlite"
    assert report["violations"] == []


def test_e05_11_backup_refuses_a_non_owner_credential_on_postgres():
    """The guard must exist on the PG path and name the maintenance workflow."""
    from core import backup_service

    source = open(backup_service.__file__, encoding="utf-8").read()
    assert "class MaintenanceCredentialRequired" in source
    # Both entry points are guarded, not just create.
    #
    # Phase 18 split the single guard into two operations because the requirements
    # genuinely differ: a backup must own every existing table (pg_dump locks them all),
    # while a restore into a *destroyed* database has no tables to own and needs schema
    # CREATE instead. The invariant this test protects is unchanged and is now stated
    # more precisely: both entry points call the guard, and it runs before anything is
    # written or replayed.
    assert "_assert_maintenance_credential()" in source, "create_backup must be guarded"
    assert '_assert_maintenance_credential("restore")' in source, "restore_backup must be guarded"
    assert source.index("_assert_maintenance_credential()") < source.index(
        "os.makedirs(BACKUP_DIR"
    ), "the check must run before anything is written"
    guard_at = source.index('def _assert_maintenance_credential')
    restore_call = source.index('_assert_maintenance_credential("restore")')
    assert guard_at < restore_call, "the guard must be defined before it is used"


def test_e05_12_destructive_backup_endpoints_are_gone():
    """Removed, not returning a false success (Decision 1)."""
    from routers import system_router

    paths = {
        (route.path, tuple(sorted(route.methods)))
        for route in system_router.router.routes
        if hasattr(route, "methods")
    }
    assert ("/api/admin/backups/create", ("POST",)) not in paths
    assert ("/api/admin/backups/restore", ("POST",)) not in paths
    # Read-only operations stay.
    assert ("/api/admin/backups", ("GET",)) in paths
    assert ("/api/admin/backups/verify", ("POST",)) in paths


def test_e05_13_worker_no_longer_schedules_a_backup():
    """A nightly pg_dump as the app role could only produce a 0-byte archive."""
    import worker

    source = open(worker.__file__, encoding="utf-8").read()
    assert "backup_service.create_backup" not in source
    assert "daily_db_backup" not in source or "REMOVED" in source


def test_e05_14_provisioning_plan_covers_functions_ownership():
    """Restore failed with 'must be owner of function' until functions moved.

    Regression guard for a defect found by running a real restore, not by review.
    """
    from scripts import provision_roles

    source = open(provision_roles.__file__, encoding="utf-8").read()
    assert "ALTER FUNCTION" in source
    assert "pg_proc" in source


def test_e05_15_provisioning_never_prints_a_password():
    """No path may emit a password literal: not an error, not a dry run."""
    from scripts import provision_roles

    source = open(provision_roles.__file__, encoding="utf-8").read()
    # The failure path reports the position and the server message, never the SQL.
    assert "statement {executed + 1} failed" in source
    assert "logger.info(statement)" not in source
    # `--dry-run` prints the plan, so it must redact the PASSWORD literal.
    assert "PASSWORD '********'" in source
    assert "print(_re.sub(" in source


@REQUIRE_POSTGRES
def test_e05_15b_dry_run_redacts_the_password(provisioned, capsys, monkeypatch):
    """Behavioural check of the line above, against a real plan."""
    from scripts import provision_roles

    monkeypatch.setenv("ADMIN_DATABASE_URL", provisioned["db_url"])
    monkeypatch.setenv("GEREGE_OWNER_PASSWORD", "PLAINTEXT_CANARY_OWNER")
    monkeypatch.setenv("GEREGE_APP_PASSWORD", "PLAINTEXT_CANARY_APP")

    assert provision_roles.main(["--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "PLAINTEXT_CANARY" not in out, "dry run leaked a password"
    assert "PASSWORD '********'" in out


# ---------------------------------------------------------------------------
# PostgreSQL-only: real roles, real attacks
# ---------------------------------------------------------------------------
@pytest.fixture()
def provisioned(tmp_path):
    """A throwaway database with gerege_owner / gerege_app provisioned for real.

    Roles are cluster-wide, so they are created once and dropped in teardown; the
    database is per-test. Grants are reapplied by the script itself, which is the point:
    the test exercises the shipped provisioning path rather than hand-written SQL.
    """
    if not _pg():
        pytest.skip("PostgreSQL required")

    import psycopg2

    import database
    from scripts import provision_roles

    # Build the test DSN with urlparse, not string surgery: the fixture used to split on
    # the last "/" and produced `postgresql+psycopg2://host:5432/db`, which psycopg2 reads
    # as port="ci_pg_password_2026@127.0.0.1:5432".
    import urllib.parse

    admin_url = os.environ["DATABASE_URL"]
    parts = urllib.parse.urlsplit(admin_url)
    host_port = parts.netloc.rsplit("@", 1)[-1]
    # The bootstrap credentials come from the suite's own DATABASE_URL; without them
    # libpq falls back to the OS user ("role \"user\" does not exist").
    bootstrap_userinfo = parts.netloc.rsplit("@", 1)[0] if "@" in parts.netloc else ""

    def dsn(user: str = "", password: str = "", database: str = "postgres") -> str:
        userinfo = f"{user}:{password}" if user else bootstrap_userinfo
        cred = f"{userinfo}@" if userinfo else ""
        return f"postgresql://{cred}{host_port}/{database}"

    db_name = f"e05_t_{uuid.uuid4().hex[:10]}"
    owner_pw = f"ow_{uuid.uuid4().hex[:16]}"
    app_pw = f"ap_{uuid.uuid4().hex[:16]}"

    admin = _raw(dsn(database="postgres"))
    _try(admin, f"DROP DATABASE IF EXISTS {db_name}")
    ok, msg = _try(admin, f"CREATE DATABASE {db_name}")
    assert ok, msg

    db_url = dsn(database=db_name)
    os.environ["ADMIN_DATABASE_URL"] = db_url
    os.environ["GEREGE_OWNER_PASSWORD"] = owner_pw
    os.environ["GEREGE_APP_PASSWORD"] = app_pw

    previous_url = os.environ.get("DATABASE_URL")
    try:
        # Migrate as the bootstrap account, exactly as the `migrate` service does.
        os.environ["DATABASE_URL"] = db_url
        database.init_db()

        assert provision_roles.main(["--apply"]) == 0
        app_url = dsn("gerege_app", app_pw, db_name)
        owner_url = dsn("gerege_owner", owner_pw, db_name)
        yield {"db": db_name, "db_url": db_url, "app": app_url, "owner": owner_url,
               "app_pw": app_pw, "owner_pw": owner_pw, "admin": dsn(database=db_name)}
    finally:
        if previous_url is not None:
            os.environ["DATABASE_URL"] = previous_url
        for key in ("ADMIN_DATABASE_URL", "GEREGE_OWNER_PASSWORD", "GEREGE_APP_PASSWORD"):
            os.environ.pop(key, None)
        try:
            _try(admin, f"DROP DATABASE IF EXISTS {db_name} WITH (FORCE)")
        finally:
            admin.close()


@REQUIRE_POSTGRES
def test_e05_16_app_role_can_do_every_required_operation(provisioned):
    conn = _raw(provisioned["app"])
    try:
        for sql, label in [
            ("SELECT COUNT(*) FROM audit_logs", "read audit"),
            (
                "INSERT INTO audit_logs (page_id, action, details_json) "
                "VALUES ('100799479495809','e05','{}')",
                "write audit",
            ),
            ("SELECT COUNT(*) FROM pages", "read business"),
            ("SELECT nextval('messages_id_seq')", "sequence USAGE"),
            ("SELECT version_num FROM alembic_version", "read alembic_version"),
            ("SELECT pg_advisory_lock(7)", "advisory lock"),
            ("SELECT pg_advisory_unlock(7)", "advisory unlock"),
        ]:
            ok, msg = _try(conn, sql)
            assert ok, f"{label} must work as gerege_app: {msg}"
    finally:
        conn.close()


@REQUIRE_POSTGRES
@pytest.mark.parametrize(
    "sql,label",
    [
        ("UPDATE audit_logs SET action='tampered'", "UPDATE audit_logs"),
        ("DELETE FROM audit_logs", "DELETE audit_logs"),
        ("TRUNCATE audit_logs", "TRUNCATE audit_logs"),
        ("TRUNCATE audit_logs CASCADE", "TRUNCATE audit_logs CASCADE"),
        ("ALTER TABLE audit_logs DISABLE TRIGGER ALL", "DISABLE TRIGGER"),
        ("DROP TRIGGER audit_logs_no_update ON audit_logs", "DROP TRIGGER"),
        ("ALTER TABLE audit_logs OWNER TO gerege_app", "ALTER OWNER"),
        ("ALTER TABLE audit_logs ADD COLUMN tamper TEXT", "ALTER TABLE ADD COLUMN"),
        ("DROP TABLE audit_logs", "DROP TABLE audit_logs"),
        ("SET session_replication_role = replica", "session_replication_role"),
        ("CREATE TABLE e05_evil (x int)", "CREATE TABLE"),
        ("CREATE FUNCTION e05_evil() RETURNS int LANGUAGE sql AS 'SELECT 1'", "CREATE FUNCTION"),
        ("CREATE SCHEMA e05_evil", "CREATE SCHEMA"),
        ("GRANT gerege_owner TO gerege_app", "GRANT owner to self"),
        ("CREATE ROLE e05_evil", "CREATE ROLE"),
        ("SET ROLE gerege_owner", "SET ROLE owner"),
        ("DROP SCHEMA public CASCADE", "DROP SCHEMA"),
    ],
)
@REQUIRE_POSTGRES
def test_e05_17_app_role_cannot_tamper_or_escalate(provisioned, sql, label):
    conn = _raw(provisioned["app"])
    try:
        ok, msg = _try(conn, sql)
        assert not ok, f"{label} SUCCEEDED as gerege_app — it must be refused"
    finally:
        conn.close()


@REQUIRE_POSTGRES
def test_e05_18_self_grant_is_a_noop_not_an_escalation(provisioned):
    """`GRANT UPDATE ... TO self` succeeds as a statement but grants nothing.

    Asserting on the statement's success would record a false positive in either
    direction; the privilege actually held afterwards is the only honest question.
    """
    conn = _raw(provisioned["app"])
    try:
        _try(conn, "GRANT UPDATE ON audit_logs TO gerege_app")
        cur = conn.cursor()
        cur.execute("SELECT has_table_privilege(current_user,'public.audit_logs','UPDATE')")
        assert cur.fetchone()[0] is False
        cur.execute("SELECT has_table_privilege(current_user,'public.audit_logs','DELETE')")
        assert cur.fetchone()[0] is False
        cur.close()
    finally:
        conn.close()


@REQUIRE_POSTGRES
def test_e05_19_tenant_deletion_retains_audit_evidence(provisioned):
    """The ON DELETE SET NULL retention path under the restricted role.

    PostgreSQL performs referential actions as the table owner, so `gerege_app` needs no
    UPDATE on `audit_logs` for this to work. This is the property that made removing
    UPDATE safe; if it ever stops holding, tenant deletion silently loses evidence.
    """
    conn = _raw(provisioned["app"])
    try:
        for sql in [
            "INSERT INTO pages (page_id, name, category, is_active) "
            "VALUES ('e05_del','Probe','x',1)",
            "INSERT INTO audit_logs (page_id, action, resource_type, resource_id) "
            "VALUES ('e05_del','payment.confirmed','invoice','INV-9')",
        ]:
            ok, msg = _try(conn, sql)
            assert ok, msg
        ok, msg = _try(conn, "DELETE FROM pages WHERE page_id='e05_del'")
        assert ok, f"tenant deletion must work as gerege_app: {msg}"

        cur = conn.cursor()
        cur.execute(
            "SELECT page_id, resource_id FROM audit_logs WHERE resource_id='INV-9'"
        )
        row = cur.fetchone()
        cur.close()
        assert row is not None, "audit evidence was destroyed by tenant deletion"
        assert row[0] is None, f"expected page_id NULL after SET NULL, got {row[0]!r}"
        assert row[1] == "INV-9", "resource_id must survive as the retained identifier"
    finally:
        conn.close()


@REQUIRE_POSTGRES
def test_e05_20_owner_role_can_migrate_and_dump(provisioned):
    """gerege_owner must still be able to do maintenance work."""
    conn = _raw(provisioned["owner"])
    try:
        ok, msg = _try(conn, "CREATE TABLE e05_owner_probe (x int)")
        assert ok, f"owner must be able to run DDL: {msg}"
        ok, msg = _try(conn, "DROP TABLE e05_owner_probe")
        assert ok, msg
        # pg_dump cannot run without this; it is why backup moved to the owner.
        ok, msg = _try(conn, "BEGIN; LOCK TABLE registrations IN ACCESS SHARE MODE; COMMIT;")
        assert ok, f"owner must be able to LOCK TABLE for pg_dump: {msg}"
    finally:
        conn.close()


@REQUIRE_POSTGRES
def test_e05_21_backup_refuses_app_and_accepts_owner(provisioned, tmp_path, monkeypatch):
    from core import backup_service

    monkeypatch.setattr(backup_service, "BACKUP_DIR", str(tmp_path / "b"))
    os.makedirs(str(tmp_path / "b"), exist_ok=True)
    previous = os.environ.get("DATABASE_URL")

    try:
        os.environ["DATABASE_URL"] = provisioned["app"].replace(
            "postgresql://", "postgresql+psycopg2://", 1
        )
        with pytest.raises(backup_service.MaintenanceCredentialRequired):
            backup_service.create_backup(label="must_refuse")
        # No 0-byte artifact may be left behind: that is the failure mode this replaces.
        leftovers = [f for f in os.listdir(str(tmp_path / "b")) if f.endswith(".sql.gz")]
        assert leftovers == [], f"a refused backup still wrote {leftovers}"

        os.environ["DATABASE_URL"] = provisioned["owner"].replace(
            "postgresql://", "postgresql+psycopg2://", 1
        )
        result = backup_service.create_backup(label="owner_ok")
        assert result["success"] is True, result
        assert result["size_bytes"] > 0
        assert backup_service.verify_backup(result["filename"])["valid"] is True
    finally:
        if previous is not None:
            os.environ["DATABASE_URL"] = previous


@REQUIRE_POSTGRES
def test_e05_22_startup_refuses_owner_and_superuser_but_accepts_app(provisioned):
    """The fail-closed assertion, against the real catalogue, per role.

    Uses the explicit-connection form of the assertion rather than rewriting
    `DATABASE_URL`. An earlier version of this test repointed the process at three roles
    and reloaded `core.db_engine`, which left a cached engine aimed at a database the
    fixture then dropped — breaking *every later test in the session* with
    "unique index ... is not in force". The connection form tests the same logic with no
    global state at all, which is why the function accepts a connection in the first
    place.
    """
    from core import db_privileges

    for url, must_fail, why in [
        (provisioned["db_url"], True, "bootstrap superuser"),
        (provisioned["owner"], True, "table owner"),
        (provisioned["app"], False, "least-privilege runtime"),
    ]:
        conn = _raw(url)
        try:
            if must_fail:
                with pytest.raises(db_privileges.PrivilegedRuntimeError):
                    db_privileges.assert_runtime_is_least_privileged(conn, force=True)
            else:
                report = db_privileges.assert_runtime_is_least_privileged(conn, force=True)
                assert report["violations"] == [], report["violations"]
                assert report["role"] == "gerege_app"
                assert report["superuser"] is False
                assert report["owned_relations"] == 0
        finally:
            conn.close()


@REQUIRE_POSTGRES
def test_e05_23_out_of_band_grant_is_detected_and_converge_removes_it(provisioned):
    """A grant added by hand must not survive a provisioning run."""
    from scripts import provision_roles

    admin = _raw(provisioned["db_url"])
    try:
        _try(admin, "GRANT UPDATE ON audit_logs TO gerege_app")

        previous = os.environ.get("DATABASE_URL")
        try:
            os.environ["DATABASE_URL"] = provisioned["app"].replace(
                "postgresql://", "postgresql+psycopg2://", 1
            )
            from core import db_privileges

            # Detection first: the live catalogue must show the escalation.
            conn = _raw(provisioned["app"])
            try:
                report = db_privileges.collect_runtime_privileges(conn)
            finally:
                conn.close()
            assert any("audit_logs" in p and "UPDATE" in p
                       for p in db_privileges.evaluate_runtime_privileges(report))
        finally:
            if previous is not None:
                os.environ["DATABASE_URL"] = previous

        # Convergence: `--apply` must remove what someone added by hand.
        os.environ["ADMIN_DATABASE_URL"] = provisioned["db_url"]
        os.environ["GEREGE_OWNER_PASSWORD"] = provisioned["owner_pw"]
        os.environ["GEREGE_APP_PASSWORD"] = provisioned["app_pw"]
        assert provision_roles.main(["--apply"]) == 0

        cur = admin.cursor()
        cur.execute(
            "SELECT privilege_type FROM information_schema.role_table_grants "
            "WHERE table_name='audit_logs' AND grantee='gerege_app' ORDER BY 1"
        )
        assert [r[0] for r in cur.fetchall()] == ["INSERT", "SELECT"]
        cur.close()
    finally:
        admin.close()


@REQUIRE_POSTGRES
def test_e05_23b_backup_guard_asks_what_the_role_can_do(tmp_path, monkeypatch):
    """Regression: the guard must not depend on `gerege_owner` existing by name.

    The first version called `pg_has_role(current_user,'gerege_owner','MEMBER')`, which
    RAISES when that role does not exist. On a cluster where provisioning had not run —
    exactly CI's fresh PostgreSQL, and the Phase 13 gate that runs after it — that turned
    a working `create_backup` into a crash. Caught by CI, not by review.

    The behaviour is pinned two ways, because dropping the role cluster-wide is not
    something a test should do:
      * the source must not name a role to decide the answer, and
      * a role that owns every table (the single-credential deployment) is accepted,
        while a role that owns none (the runtime role) is refused.
    """
    from core import backup_service

    # Text-matching the source is brittle (the explanatory comment quotes the removed
    # call), so drive the real code instead: the guard must decide from what the role
    # owns, and must not care whether a role named `gerege_owner` exists.
    import ast
    import textwrap

    tree = ast.parse(open(backup_service.__file__, encoding="utf-8").read())
    fn = next(
        n for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "_assert_maintenance_credential"
    )
    calls = {
        n.func.id
        for n in ast.walk(fn)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    # It must consult the catalogue about ownership, and it may not make the answer
    # depend on a role existing by name.
    sql_text = " ".join(
        n.value for n in ast.walk(fn)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    )
    assert "relowner" in sql_text, "the guard should judge ownership from the catalogue"
    assert "rolsuper" in sql_text, "a superuser can always dump; the guard should allow it"

    # Behaviour: a single-credential owner (the bootstrap superuser) must be allowed.
    monkeypatch.setattr(backup_service, "BACKUP_DIR", str(tmp_path / "b"))
    os.makedirs(str(tmp_path / "b"), exist_ok=True)
    result = backup_service.create_backup(label="single_credential")
    assert result["success"] is True, result
    assert result["size_bytes"] > 0


@REQUIRE_POSTGRES
def test_e05_24_verify_exits_nonzero_when_the_runtime_role_is_missing(provisioned):
    """`--verify` must not report success on a database with no runtime role."""
    from scripts import provision_roles

    admin = _raw(provisioned["db_url"])
    try:
        _try(admin, "DROP OWNED BY gerege_app")
        _try(admin, "DROP ROLE gerege_app")
        os.environ["ADMIN_DATABASE_URL"] = provisioned["db_url"]
        rc = provision_roles.main(["--verify"])
        assert rc == 1, "--verify reported success without a runtime role"
    finally:
        # put the role back so teardown and other tests are not affected
        os.environ["GEREGE_OWNER_PASSWORD"] = provisioned["owner_pw"]
        os.environ["GEREGE_APP_PASSWORD"] = provisioned["app_pw"]
        provision_roles.main(["--apply"])
        admin.close()
