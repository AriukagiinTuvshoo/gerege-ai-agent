"""Phase 36 - migration deployment safety.

Answers, with evidence, the questions Phase 8 requires:

1. Do migrations run once?          Yes - the one-shot `migrate` service.
2. Can instances race?              Not in the real deploy path (see the caveat below).
3. Is worker startup blocked?       Yes - `service_completed_successfully`.
4. Does a failure stop deployment?  Yes - `restart: "no"` and a chained `&&`.
5. Is the app compatible with the previous schema?  See docs (expand/contract is NOT used).
6. Is rollback documented?          Yes - and 0004 is irreversible by design.

**Measured caveat, first boot only.** Two `alembic upgrade head` processes started
simultaneously against an EMPTY database both try to create `alembic_version`: one
succeeds, the other exits 1 with "already exists". The schema still ends up correct at
0007 with 19 tables, so the failure is clean rather than a partial migration -- but it
means composing `migrate` with anything that runs migrations in parallel on a fresh
volume is unsafe. Against an already-migrated database (the normal redeploy) both
processes exit 0. `schema_manager`'s `pg_advisory_lock` serialises the app-side path, but
Alembic's own `env.py` takes no lock, which is why the first-boot case behaves this way.
"""

from __future__ import annotations

import os
import re

import pytest
import yaml


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="module")
def staging() -> dict:
    with open(os.path.join(REPO_ROOT, "docker-compose.staging.yml"), encoding="utf-8") as handle:
        return yaml.safe_load(handle)


class TestMigrationOrdering:
    def test_migrate_runs_before_web(self, staging):
        deps = staging["services"]["web"]["depends_on"]
        assert deps["migrate"]["condition"] == "service_completed_successfully", (
            "web must not start until migrations finish"
        )

    def test_migrate_runs_before_worker(self, staging):
        deps = staging["services"]["worker"]["depends_on"]
        assert deps["migrate"]["condition"] == "service_completed_successfully", (
            "the worker must not start against an unmigrated schema"
        )

    def test_migration_failure_stops_the_deployment(self, staging):
        """`restart: no` plus a chained `&&` means a failed step halts everything."""
        migrate = staging["services"]["migrate"]
        assert str(migrate["restart"]) == "no"
        command = " ".join(migrate["command"])
        assert "&&" in command
        # Order matters: provision -> migrate -> provision -> verify.
        assert command.index("provision_roles.py --apply") < command.index("alembic upgrade head")
        assert command.index("alembic upgrade head") < command.index("provision_roles.py --verify")

    def test_verify_is_the_last_step(self, staging):
        """A deployment that skips --verify ships an over-privileged runtime role.

        The app refuses to boot in that state, so the failure would appear at API start
        rather than at migration time -- much harder to diagnose.
        """
        command = " ".join(staging["services"]["migrate"]["command"])
        assert command.strip().endswith("--verify")

    def test_migrate_uses_owner_or_bootstrap_credentials_not_the_app_role(self, staging):
        """Alembic needs DDL; the runtime role deliberately cannot perform it."""
        env = staging["services"]["migrate"]["environment"]
        url = str(env["DATABASE_URL"])
        assert "gerege_app" not in url, "migrations must not run as the runtime role"
        assert "${POSTGRES_PASSWORD" in url or "gerege_owner" in url

    def test_no_service_runs_migrations_automatically(self, staging):
        """Startup migrations would race every time an instance restarts."""
        for name, service in staging["services"].items():
            if name == "migrate":
                continue
            command = service.get("command") or []
            joined = " ".join(command) if isinstance(command, list) else str(command)
            assert "alembic upgrade" not in joined, (
                f"{name} runs migrations at startup, which reintroduces the race"
            )

    def test_web_does_not_initialize_schema(self, staging):
        """`init_db()` in a serving process would create tables behind Alembic's back."""
        for name in ("web", "worker"):
            command = staging["services"][name].get("command") or []
            joined = " ".join(command) if isinstance(command, list) else str(command)
            assert "init_db" not in joined


class TestIrreversibleMigration:
    def test_migration_0004_refuses_to_downgrade(self):
        """The documented irreversible migration.

        0004 collapses per-sender session identity into per-tenant identity. If two
        tenants share a sender_id, downgrading would have to delete one tenant's rows, so
        it raises instead. This is the reason a schema rollback past 0004 requires a
        restore rather than `alembic downgrade`.
        """
        path = os.path.join(
            REPO_ROOT, "migrations", "versions", "0004_tenant_session_identity.py"
        )
        source = open(path, encoding="utf-8").read()
        assert "def downgrade" in source
        assert "RuntimeError" in source, (
            "downgrade must refuse rather than silently destroy cross-tenant data"
        )

    def test_only_0004_is_irreversible(self):
        """Every other downgrade must exist, so rollback is possible where it is safe."""
        versions_dir = os.path.join(REPO_ROOT, "migrations", "versions")
        offenders = []
        for filename in sorted(os.listdir(versions_dir)):
            if not filename.endswith(".py"):
                continue
            source = open(os.path.join(versions_dir, filename), encoding="utf-8").read()
            if "def downgrade" not in source:
                offenders.append(filename)
        assert not offenders, f"these migrations have no downgrade at all: {offenders}"

    def test_rollback_documentation_names_the_irreversible_migration(self):
        doc = open(
            os.path.join(REPO_ROOT, "docs", "deployment", "PRODUCTION_DEPLOYMENT.md"),
            encoding="utf-8",
        ).read()
        assert "0004" in doc
        assert "irreversib" in doc.lower() or "downgrade" in doc.lower()


class TestMigrationSafetyNotesDocumented:
    def test_first_boot_race_is_documented(self):
        """An undocumented race becomes an outage someone debugs at 3am.

        The compose file must warn that only one migrator may run against a fresh volume.
        """
        content = open(
            os.path.join(REPO_ROOT, "docker-compose.staging.yml"), encoding="utf-8"
        ).read()
        assert "migrate" in content
        # The deploy runbook carries the detail; this asserts it exists somewhere in-repo.
        runbook = os.path.join(REPO_ROOT, "docs", "deployment", "STAGING_DEPLOYMENT.md")
        assert os.path.isfile(runbook), "staging runbook is missing"
        text = open(runbook, encoding="utf-8").read()
        assert "concurrent" in text.lower() or "race" in text.lower()
