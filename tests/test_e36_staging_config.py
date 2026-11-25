"""Phase 36 - staging isolation and configuration safety.

The failure this guards against is quiet: staging that shares a credential with production
looks fine, passes its smoke test, and then sends a test message to real customers or
writes to the real database. These assertions are cheap; that failure is not.
"""

from __future__ import annotations

import os
import re

import pytest
import yaml


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name: str) -> str:
    with open(os.path.join(REPO_ROOT, name), encoding="utf-8") as handle:
        return handle.read()


@pytest.fixture(scope="module")
def staging_compose() -> dict:
    return yaml.safe_load(_read("docker-compose.staging.yml"))


class TestStagingIsolation:
    def test_uses_a_different_database_name_than_production(self, staging_compose):
        """A shared host with a shared DB name would collide on volumes and schemas."""
        staging_db = staging_compose["services"]["db"]["environment"]["POSTGRES_DB"]
        assert "gerege_staging" in str(staging_db)
        prod = yaml.safe_load(_read("docker-compose.prod.yml"))
        prod_db = str(prod["services"]["db"]["environment"].get("POSTGRES_DB", ""))
        assert "gerege_staging" not in prod_db

    def test_compose_project_name_is_distinct(self, staging_compose):
        """Without a project name, two stacks on one host share container and volume names."""
        assert staging_compose.get("name") == "gerege-staging"

    def test_volumes_are_namespaced_by_the_project(self, staging_compose):
        """Named volumes inherit the project prefix, so staging cannot mount prod's data."""
        for volume in staging_compose.get("volumes", {}):
            assert not volume.startswith("gerege_crm"), (
                f"volume {volume} looks like a production volume name"
            )

    def test_required_secrets_are_mandatory_not_defaulted(self, staging_compose):
        """`:?` rather than `:-` so a blank password stops `compose up`.

        A default here would mean staging silently starts with a known password.
        """
        web_env = staging_compose["services"]["web"]["environment"]
        for key in ("ADMIN_PASSWORD", "E02_ACCOUNT_KEY_SECRET",
                    "ALLOWED_ORIGINS", "TRUSTED_PROXIES"):
            assert ":?" in str(web_env[key]), f"{key} must be required, not defaulted"
        # The database password has no top-level key: it is interpolated into the DSN, so
        # the `:?` guard has to be asserted on the URL itself. Checking for a
        # POSTGRES_APP_PASSWORD key here would pass while the password was optional.
        assert ":?POSTGRES_APP_PASSWORD" in str(web_env["DATABASE_URL"])
        assert ":?POSTGRES_OWNER_PASSWORD" in str(web_env["DATABASE_OWNER_URL"])

    def test_staging_env_template_contains_no_real_looking_secret(self):
        """The template must be placeholders. A committed key is a leaked key."""
        text = _read(".env.staging.example")
        # No long base64/hex blobs after an `=` (those would be generated secrets).
        suspicious = re.findall(r"^[A-Z_]+=([A-Za-z0-9+/=]{32,})$", text, re.MULTILINE)
        assert not suspicious, f"the example file appears to contain real secrets: {suspicious}"
        # No live-looking API keys.
        assert "AIza" not in text
        assert not re.search(r"\d{9,10}:AA[A-Za-z0-9_-]{30,}", text)

    def test_staging_env_points_qpay_at_sandbox(self):
        """A live QPay base URL in a staging file would move real money."""
        text = _read(".env.staging.example")
        assert "sandbox" in text.lower(), "QPay must point at the sandbox in staging"
        for line in text.splitlines():
            if line.startswith("QPAY_BASE_URL="):
                assert "sandbox" in line.lower()

    def test_staging_env_does_not_enable_debug(self):
        text = _read(".env.staging.example")
        # Executable assignments only: the file's own explanation mentions
        # `ENV=development`, and scanning comments would fail on the docs rather than
        # on a real setting.
        assignments = [
            line.strip() for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        assert "ENV=production" in assignments, (
            "staging must run the production code path so fail-closed checks fire"
        )
        for line in assignments:
            assert not line.startswith("DEBUG="), "debug must not be enabled in staging"
            assert line != "ENV=development", "staging must not run the dev path"


class TestStagingExposure:
    def test_only_the_proxy_publishes_ports(self, staging_compose):
        """Database, Redis and the app must be unreachable from outside the host."""
        for name in ("db", "redis", "web", "worker"):
            assert "ports" not in staging_compose["services"][name], (
                f"{name} must not publish a host port in staging"
            )
        assert staging_compose["services"]["proxy"]["ports"]

    def test_proxy_publishes_https(self, staging_compose):
        ports = [str(p) for p in staging_compose["services"]["proxy"]["ports"]]
        assert any("443" in p for p in ports), "the proxy must publish 443"

    def test_app_is_not_root(self, staging_compose):
        assert "user" not in staging_compose["services"]["web"] or str(
            staging_compose["services"]["web"]["user"]
        ) != "root"
        dockerfile = _read("Dockerfile")
        assert "USER gerege" in dockerfile

    def test_trusted_proxies_is_required(self, staging_compose):
        """Missing this silently downgrades generated payment URLs to http:// (F-36-3)."""
        assert "TRUSTED_PROXIES" in staging_compose["services"]["web"]["environment"]
        assert "0.0.0.0/0" not in str(
            staging_compose["services"]["web"]["environment"]["TRUSTED_PROXIES"]
        )


class TestStagingHealthAndBudget:
    def test_healthchecks_use_the_cheap_endpoints(self, staging_compose):
        web_hc = str(staging_compose["services"]["web"]["healthcheck"]["test"])
        assert "/api/ready" in web_hc
        assert "/api/health" not in web_hc

    def test_worker_healthcheck_does_not_need_http(self, staging_compose):
        """The worker has no HTTP surface; its probe must not pretend it does."""
        worker_hc = str(staging_compose["services"]["worker"]["healthcheck"]["test"])
        assert "http" not in worker_hc.lower() or "/api/" not in worker_hc
        assert "worker_heartbeat" in worker_hc or "/tmp/worker_heartbeat" in worker_hc

    def test_connection_budget_is_declared_per_service(self, staging_compose):
        for name in ("web", "worker", "migrate"):
            env = staging_compose["services"][name]["environment"]
            assert env.get("DB_PROCESS_ROLE"), f"{name} must declare DB_PROCESS_ROLE"

    def test_worker_pool_is_small(self, staging_compose):
        env = staging_compose["services"]["worker"]["environment"]
        assert ":2}" in str(env["DB_POOL_SIZE"]) or "2" in str(env["DB_POOL_SIZE"])


class TestDocumentation:
    def test_runbook_exists(self):
        assert os.path.isfile(
            os.path.join(REPO_ROOT, "docs", "deployment", "STAGING_DEPLOYMENT.md")
        )

    def test_runbook_says_it_was_not_executed(self):
        """Honesty requirement: no claim of a deployment that did not happen."""
        text = _read("docs/deployment/STAGING_DEPLOYMENT.md")
        assert "has not been executed" in text or "not been executed" in text

    def test_integration_matrix_exists(self):
        assert os.path.isfile(
            os.path.join(REPO_ROOT, "docs", "deployment", "STAGING_INTEGRATION_MATRIX.md")
        )

    def test_integration_matrix_marks_unverified_integrations(self):
        text = _read("docs/deployment/STAGING_INTEGRATION_MATRIX.md")
        assert "requires real credential" in text
        assert "mock-verified only" in text
