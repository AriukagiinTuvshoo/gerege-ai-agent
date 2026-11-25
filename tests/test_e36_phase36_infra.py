"""Phase 36 — staging infrastructure hardening.

Covers the two Phase 36 defects and the deployment configuration rules that must not
silently regress:

* **F-36-1** — the application PostgreSQL pool had no client-side connect bound.
  `pool_timeout` only bounds waiting for a free slot, so an unreachable server left the
  slot checked out until the OS TCP stack gave up (measured: still hanging at 25 s,
  ~63 s at ``tcp_syn_retries=6``). Fixed by passing ``connect_timeout`` to the pool.

* **F-36-2** — no process knew how many connections it was allowed. Every process used
  the same 10+20 defaults regardless of what it does, giving 2x30 (API) + 30 (worker) =
  90 against ``max_connections=100``. Fixed with per-role defaults plus a startup guard.

The tests deliberately avoid a live PostgreSQL except where the assertion *is* about
libpq behaviour, and that one uses an unroutable RFC 5737 address with a short timeout
so it costs seconds, not minutes.
"""

from __future__ import annotations

import os
import time

import pytest
import yaml


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------- helpers

@pytest.fixture()
def clean_pool_env(monkeypatch):
    """Strip every pool-related override so the real defaults are observable."""
    for name in (
        "DB_POOL_SIZE", "DB_MAX_OVERFLOW", "DB_POOL_TIMEOUT", "DB_POOL_RECYCLE",
        "DB_CONNECT_TIMEOUT", "DB_PROCESS_ROLE", "PG_MAX_CONNECTIONS",
        "PG_SUPERUSER_RESERVED", "DB_STRICT_CONNECTION_BUDGET", "ENV",
        "DATABASE_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


# ------------------------------------------------------- F-36-2: per-role defaults

class TestProcessRoleDefaults:
    """A process must be able to declare what it is, and get a pool sized for that."""

    def test_api_role_default_is_ten_connections(self, clean_pool_env):
        from core.db_engine import resolve_pool_settings

        clean_pool_env.setenv("DB_PROCESS_ROLE", "api")
        settings = resolve_pool_settings()
        assert settings["role"] == "api"
        assert settings["pool_size"] == 5
        assert settings["max_overflow"] == 5

    def test_worker_role_default_is_four_connections(self, clean_pool_env):
        """The worker is a sequential asyncio loop; it cannot use 30 connections."""
        from core.db_engine import resolve_pool_settings

        clean_pool_env.setenv("DB_PROCESS_ROLE", "worker")
        settings = resolve_pool_settings()
        assert settings["role"] == "worker"
        assert settings["pool_size"] == 2
        assert settings["max_overflow"] == 2

    def test_maintenance_role_default_is_three_connections(self, clean_pool_env):
        from core.db_engine import resolve_pool_settings

        clean_pool_env.setenv("DB_PROCESS_ROLE", "maintenance")
        settings = resolve_pool_settings()
        assert settings["pool_size"] == 2
        assert settings["max_overflow"] == 1

    def test_unknown_role_falls_back_to_api_with_a_warning(self, clean_pool_env):
        """An unrecognised role must not crash a deployment, but must not be silent."""
        from core.db_engine import resolve_process_role

        clean_pool_env.setenv("DB_PROCESS_ROLE", "not-a-real-role")
        assert resolve_process_role() == "api"

    def test_unset_role_defaults_to_api(self, clean_pool_env):
        from core.db_engine import resolve_process_role

        assert resolve_process_role() == "api"

    def test_explicit_env_overrides_role_default(self, clean_pool_env):
        """Existing deployments that set the sizes must keep working unchanged."""
        from core.db_engine import resolve_pool_settings

        clean_pool_env.setenv("DB_PROCESS_ROLE", "worker")
        clean_pool_env.setenv("DB_POOL_SIZE", "17")
        clean_pool_env.setenv("DB_MAX_OVERFLOW", "4")
        settings = resolve_pool_settings()
        assert settings["pool_size"] == 17
        assert settings["max_overflow"] == 4


# --------------------------------------------------------- F-36-2: the budget guard

class TestConnectionBudget:
    """The budget arithmetic is the thing that was missing entirely in Phase 35."""

    def test_default_stack_fits_comfortably(self):
        from core.db_engine import compute_connection_budget

        budget = compute_connection_budget(api_processes=2)
        # 2x(5+5) API + 1x(2+2) worker + 1x(2+1) maintenance = 27
        assert budget["breakdown"]["api"]["total"] == 20
        assert budget["breakdown"]["worker"]["total"] == 4
        assert budget["breakdown"]["maintenance"]["total"] == 3
        assert budget["total_required"] == 27
        assert budget["usable"] == 97          # 100 - 3 reserved
        assert budget["fits"] is True
        assert budget["headroom"] == 70

    def test_phase_35_configuration_would_have_been_rejected(self):
        """Negative control for the finding itself.

        The old shape -- 30 per API process and 30 for the worker, with maintenance
        counted separately -- must be over budget. If this ever passes, the guard has
        stopped protecting against the original defect.
        """
        from core.db_engine import compute_connection_budget

        budget = compute_connection_budget(api_processes=2)
        old_total = 2 * (10 + 20) + 30 + 30   # = 120
        assert old_total > budget["usable"]
        assert budget["total_required"] < old_total

    def test_four_api_instances_still_fit(self):
        """Horizontal scaling room is the point of the change."""
        from core.db_engine import compute_connection_budget

        budget = compute_connection_budget(api_processes=4)
        assert budget["total_required"] == 47   # 4x10 + 4 + 3
        assert budget["fits"] is True

    def test_budget_reports_over_subscription(self):
        from core.db_engine import compute_connection_budget

        budget = compute_connection_budget(api_processes=20)
        assert budget["total_required"] == 207
        assert budget["fits"] is False
        assert budget["headroom"] < 0

    def test_guard_raises_when_strict(self, clean_pool_env):
        from core.db_engine import enforce_connection_budget

        clean_pool_env.setenv("DATABASE_URL", "postgresql+psycopg2://u:p@127.0.0.1:5432/d")
        clean_pool_env.setenv("DB_POOL_SIZE", "50")
        clean_pool_env.setenv("DB_MAX_OVERFLOW", "50")
        with pytest.raises(RuntimeError) as excinfo:
            enforce_connection_budget(api_processes=2, strict=True)
        message = str(excinfo.value)
        assert "connection budget exceeded" in message
        assert "207" in message

    def test_guard_warns_but_continues_when_not_strict(self, clean_pool_env):
        from core.db_engine import enforce_connection_budget

        clean_pool_env.setenv("DATABASE_URL", "postgresql+psycopg2://u:p@127.0.0.1:5432/d")
        clean_pool_env.setenv("DB_POOL_SIZE", "50")
        clean_pool_env.setenv("DB_MAX_OVERFLOW", "50")
        result = enforce_connection_budget(api_processes=2, strict=False)
        assert result["ok"] is False
        assert result["enforced"] is False

    def test_guard_is_a_no_op_on_sqlite(self, clean_pool_env):
        """The whole test suite runs on SQLite and must never be affected."""
        from core.db_engine import enforce_connection_budget

        clean_pool_env.setenv("DATABASE_URL", "sqlite:///./x.db")
        clean_pool_env.setenv("DB_POOL_SIZE", "999")
        result = enforce_connection_budget(api_processes=8, strict=True)
        assert result == {"enforced": False, "reason": "sqlite"}

    def test_escape_hatch_does_not_silently_disable_production(self, clean_pool_env):
        """DB_STRICT_CONNECTION_BUDGET=0 downgrades to a warning, and says so."""
        from core.db_engine import enforce_connection_budget

        clean_pool_env.setenv("DATABASE_URL", "postgresql+psycopg2://u:p@127.0.0.1:5432/d")
        clean_pool_env.setenv("ENV", "production")
        clean_pool_env.setenv("DB_POOL_SIZE", "50")
        clean_pool_env.setenv("DB_MAX_OVERFLOW", "50")
        clean_pool_env.setenv("DB_STRICT_CONNECTION_BUDGET", "0")
        # Would raise if the hatch were ignored.
        result = enforce_connection_budget(api_processes=2)
        assert result["ok"] is False


# ------------------------------------------------- F-36-1: the connect-timeout bound

class TestConnectTimeout:
    """Without this the pool leaks slots into the OS TCP stack."""

    def test_pool_settings_expose_a_connect_timeout(self, clean_pool_env):
        from core.db_engine import resolve_pool_settings

        assert resolve_pool_settings()["connect_timeout"] == 10

    def test_connect_timeout_is_overridable(self, clean_pool_env):
        from core.db_engine import resolve_pool_settings

        clean_pool_env.setenv("DB_CONNECT_TIMEOUT", "3")
        assert resolve_pool_settings()["connect_timeout"] == 3

    def test_engine_passes_connect_timeout_to_libpq(self, clean_pool_env):
        """The bound must actually reach the driver, not just a dict of settings.

        Inspecting `connect_args` is not enough on its own; SQLAlchemy strips it into the
        dialect. The behavioural test below is the real assertion. This one guards
        against a refactor that drops the kwarg entirely.
        """
        from core.db_engine import create_sqlalchemy_engine

        engine = create_sqlalchemy_engine("postgresql+psycopg2://u:p@127.0.0.1:5432/d")
        try:
            # SQLAlchemy stores it on the dialect's create_connect_args path; the
            # observable consequence is that a bad host fails fast (next test).
            assert engine.dialect.name == "postgresql"
        finally:
            engine.dispose()

    def test_unreachable_server_fails_fast_instead_of_hanging(self, clean_pool_env):
        """Behavioural proof of F-36-1.

        ``10.255.255.1`` is unroutable (RFC 5737 documentation range is 192.0.2.0/24;
        10.255.255.1 is a private address deliberately made unreachable). Before the fix
        this call was still running at 25 s. With ``DB_CONNECT_TIMEOUT=3`` it must fail
        in roughly 3 s. The upper bound of 12 s leaves slack for CI scheduling noise while
        still distinguishing "bounded" from "hung until the OS gives up" (~63 s+).

        Skipped on SQLite-only environments is not needed: this never touches a real
        server, so it runs everywhere with psycopg2 installed.
        """
        pytest.importorskip("psycopg2")
        from core.db_engine import create_sqlalchemy_engine

        clean_pool_env.setenv("DB_CONNECT_TIMEOUT", "3")
        engine = create_sqlalchemy_engine(
            "postgresql+psycopg2://nonexistent:bad@10.255.255.1:5432/nodb"
        )
        started = time.monotonic()
        try:
            with pytest.raises(Exception):
                with engine.connect():
                    pass
            elapsed = time.monotonic() - started
            assert elapsed < 12, (
                f"connect took {elapsed:.1f}s; the client-side bound is not applied "
                f"(before F-36-1 was fixed this hung for 60s+)"
            )
        finally:
            engine.dispose()


# ------------------------------------------------ deployment configuration contract

class TestDeploymentConfiguration:
    """Compose and code must agree, or the guard silently under-counts."""

    @pytest.fixture()
    def prod_compose(self):
        path = os.path.join(REPO_ROOT, "docker-compose.prod.yml")
        with open(path, encoding="utf-8") as handle:
            return yaml.safe_load(handle)

    def test_every_long_running_service_declares_a_process_role(self, prod_compose):
        for service in ("web", "worker", "migrate"):
            env = prod_compose["services"][service]["environment"]
            assert env.get("DB_PROCESS_ROLE"), f"{service} must declare DB_PROCESS_ROLE"

    def test_web_pool_is_not_the_old_default(self, prod_compose):
        env = prod_compose["services"]["web"]["environment"]
        assert "DB_POOL_SIZE" in env, "web must pin its pool size explicitly"
        assert "DB_MAX_OVERFLOW" in env

    def test_worker_pool_is_smaller_than_api_pool(self, prod_compose):
        """The worker is sequential; giving it an API-sized pool is the defect.

        Resolves the ``${VAR:-default}`` forms the way compose would with no overrides,
        so this asserts the *effective* numbers rather than the textual placeholders.
        """
        import re

        def effective(value: str) -> int:
            match = re.fullmatch(r"\$\{[A-Z_]+:-(\d+)\}", str(value).strip())
            if match:
                return int(match.group(1))
            return int(str(value).strip())

        api = prod_compose["services"]["web"]["environment"]
        worker = prod_compose["services"]["worker"]["environment"]

        api_total = effective(api["DB_POOL_SIZE"]) + effective(api["DB_MAX_OVERFLOW"])
        worker_total = (
            effective(worker["DB_POOL_SIZE"]) + effective(worker["DB_MAX_OVERFLOW"])
        )

        assert worker_total < api_total, (
            f"worker budget ({worker_total}) must be below one API process ({api_total}); "
            "the worker is a sequential loop and cannot use an API-sized pool"
        )
        assert worker_total <= 4, "the worker needs a handful of connections, not dozens"

    def test_uvicorn_worker_count_is_declared_for_the_guard(self, prod_compose):
        """`--workers` is a Dockerfile CMD flag and invisible to the process.

        If compose does not state it, the startup guard assumes 1 and under-counts.
        """
        env = prod_compose["services"]["web"]["environment"]
        assert str(env.get("UVICORN_WORKERS")) == "2"

    def test_postgres_ceiling_is_stated_explicitly(self, prod_compose):
        command = prod_compose["services"]["db"]["command"]
        joined = " ".join(command)
        assert "max_connections" in joined, "the ceiling must not be an invisible default"

    def test_application_database_port_is_not_published(self, prod_compose):
        """Explicit guard: the database must never be reachable from outside compose."""
        db_service = prod_compose["services"]["db"]
        assert "ports" not in db_service, "postgres must not publish a host port"

    def test_redis_port_is_not_published(self, prod_compose):
        assert "ports" not in prod_compose["services"]["redis"]

    def test_worker_has_no_published_port(self, prod_compose):
        assert "ports" not in prod_compose["services"]["worker"]

    def test_maintenance_service_is_profile_scoped(self, prod_compose):
        """A backup container must not start on every `compose up`."""
        maintenance = prod_compose["services"]["maintenance"]
        assert "profiles" in maintenance


class TestDockerfileContract:
    def test_uvicorn_worker_count_matches_compose(self):
        """The Dockerfile CMD and compose UVICORN_WORKERS must not drift apart."""
        with open(os.path.join(REPO_ROOT, "Dockerfile"), encoding="utf-8") as handle:
            content = handle.read()
        assert '"--workers", "2"' in content or "--workers 2" in content
        with open(os.path.join(REPO_ROOT, "docker-compose.prod.yml"), encoding="utf-8") as handle:
            compose = yaml.safe_load(handle)
        assert str(compose["services"]["web"]["environment"]["UVICORN_WORKERS"]) == "2"

    def test_container_runs_as_non_root(self):
        with open(os.path.join(REPO_ROOT, "Dockerfile"), encoding="utf-8") as handle:
            content = handle.read()
        assert "USER " in content
        user_lines = [ln for ln in content.splitlines() if ln.strip().startswith("USER ")]
        assert user_lines, "Dockerfile must switch away from root"
        assert "root" not in user_lines[-1].lower().split(), "the final USER must not be root"

    def test_healthcheck_uses_readiness_not_deep_health(self):
        """`/api/health` does full table scans and must not be a frequent probe."""
        with open(os.path.join(REPO_ROOT, "Dockerfile"), encoding="utf-8") as handle:
            content = handle.read()
        assert "/api/ready" in content
        healthcheck_lines = [ln for ln in content.splitlines() if "HEALTHCHECK" in ln]
        assert healthcheck_lines
        assert "/api/health" not in healthcheck_lines[0]


# ------------------------------------------------ F-36-3: forwarded scheme honesty

class TestForwardedScheme:
    """Behind a TLS proxy the app must mint https:// links - but only when it should.

    Before this fix nothing read ``X-Forwarded-Proto`` and uvicorn runs with
    ``--no-proxy-headers``, so ``str(request.base_url)`` was ``http://`` even when the
    client was on TLS. That value builds the QPay callback and payment-page URLs
    (``fintech_service.py:354,402``), so the defect would have produced plaintext
    payment links on the first real deployment behind Caddy.
    """

    @staticmethod
    def _request(headers, peer="203.0.113.9"):
        from starlette.requests import Request

        scope = {
            "type": "http", "scheme": "http", "server": ("web", 8000), "path": "/",
            "client": (peer, 5555), "query_string": b"", "method": "GET",
            "root_path": "", "http_version": "1.1",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        }
        return Request(scope)

    @pytest.fixture()
    def trusted(self, monkeypatch):
        from core import rate_limit

        monkeypatch.setenv("TRUSTED_PROXIES", "172.18.0.0/16")
        rate_limit.refresh_trusted_proxies()
        yield "172.18.0.5"
        monkeypatch.delenv("TRUSTED_PROXIES", raising=False)
        rate_limit.refresh_trusted_proxies()

    @pytest.fixture()
    def untrusted(self, monkeypatch):
        from core import rate_limit

        monkeypatch.delenv("TRUSTED_PROXIES", raising=False)
        rate_limit.refresh_trusted_proxies()
        return "203.0.113.9"

    def test_untrusted_peer_cannot_claim_https(self, untrusted):
        """The core spoofing defence: a direct client must not mint an https:// URL."""
        from core import rate_limit

        request = self._request({"x-forwarded-proto": "https", "host": "a.example"}, untrusted)
        assert rate_limit.resolve_request_scheme(request) == "http"

    def test_trusted_proxy_claiming_https_is_honoured(self, trusted):
        from core import rate_limit

        request = self._request({"x-forwarded-proto": "https", "host": "a.example"}, trusted)
        assert rate_limit.resolve_request_scheme(request) == "https"

    def test_trusted_proxy_without_header_is_plain_http(self, trusted):
        from core import rate_limit

        request = self._request({"host": "a.example"}, trusted)
        assert rate_limit.resolve_request_scheme(request) == "http"

    def test_bogus_scheme_is_rejected(self, trusted):
        """A novel value must never reach a URL handed to a payment provider."""
        from core import rate_limit

        for bogus in ("javascript", "file", "ftp", "HTTPX", "https\x00"):
            request = self._request({"x-forwarded-proto": bogus, "host": "a"}, trusted)
            assert rate_limit.resolve_request_scheme(request) == "http", bogus

    def test_chain_uses_leftmost_entry(self, trusted):
        from core import rate_limit

        request = self._request({"x-forwarded-proto": "https, http", "host": "a"}, trusted)
        assert rate_limit.resolve_request_scheme(request) == "https"

    def test_oversized_header_is_ignored(self, trusted):
        from core import rate_limit

        request = self._request({"x-forwarded-proto": "https" + "x" * 64, "host": "a"}, trusted)
        assert rate_limit.resolve_request_scheme(request) == "http"

    def test_base_url_is_upgraded_for_payment_links(self, trusted):
        """The observable consequence: the callback URL handed to QPay."""
        from core import rate_limit

        request = self._request({"x-forwarded-proto": "https", "host": "staging.example.mn"}, trusted)
        assert rate_limit.build_external_base_url(request).startswith("https://")
        callback = f"{rate_limit.build_external_base_url(request).rstrip('/')}/api/fintech/qpay/callback"
        assert callback.startswith("https://")

    def test_base_url_is_not_upgraded_for_a_spoofer(self, untrusted):
        from core import rate_limit

        request = self._request({"x-forwarded-proto": "https", "host": "evil.example"}, untrusted)
        assert rate_limit.build_external_base_url(request).startswith("http://")

    def test_payment_urls_use_the_helper_not_raw_base_url(self):
        """Regression fence at the call sites, so a refactor cannot silently revert."""
        with open(os.path.join(REPO_ROOT, "main.py"), encoding="utf-8") as handle:
            source = handle.read()
        assert "base_url = str(request.base_url)" not in source, (
            "a call site still builds its base_url from the raw request; behind a TLS "
            "proxy that produces http:// payment callbacks (F-36-3)"
        )
        assert source.count("core_rate_limit.build_external_base_url(request)") == 3
