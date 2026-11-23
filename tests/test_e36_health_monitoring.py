"""Phase 36 - health and readiness separation.

Phase 35 measured `/api/health` at 28 ms on an empty database rising to 94.6 ms at 10k
rows, because it materialised every registration and every page's sessions on every call.
This file pins the fixed behaviour:

* `/api/live`   -- constant cost, no dependencies, for container/liveness probes
* `/api/ready`  -- bounded dependency check, for load-balancer readiness
* `/api/health` -- counts via COUNT(*), for a human or a low-frequency dashboard

Two properties matter most and are asserted directly:
  1. liveness does not depend on the database (a restart cannot fix a dead database, so
     making liveness depend on it turns an outage into a crash loop);
  2. none of the three leaks a secret, because all three are unauthenticated.
"""

from __future__ import annotations

import os
import re
import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client():
    import main

    with TestClient(main.app, raise_server_exceptions=False) as test_client:
        yield test_client


class TestLiveness:
    def test_live_returns_200(self, client):
        response = client.get("/api/live")
        assert response.status_code == 200
        assert response.json() == {"status": "alive"}

    def test_live_touches_no_database(self, client, monkeypatch):
        """Break the database entirely; liveness must still answer.

        This is the property that stops a database outage from becoming a restart loop.
        """
        import database

        def explode(*args, **kwargs):
            raise RuntimeError("database is down")

        monkeypatch.setattr(database, "get_connection", explode)
        assert client.get("/api/live").status_code == 200

    def test_live_is_cheap(self, client):
        """No query, no aggregation: a few milliseconds at most."""
        client.get("/api/live")
        started = time.perf_counter()
        for _ in range(10):
            client.get("/api/live")
        elapsed_ms = (time.perf_counter() - started) * 100  # ms per call
        assert elapsed_ms < 50, f"liveness averaged {elapsed_ms:.1f} ms; it must be trivial"


class TestReadiness:
    def test_ready_returns_200_when_healthy(self, client):
        response = client.get("/api/ready")
        assert response.status_code == 200
        body = response.json()
        assert body["ready"] is True
        assert body["database"] == "ok"

    def test_ready_reports_failure_as_503(self, client, monkeypatch):
        """A readiness probe must fail *closed* so a balancer stops sending traffic."""
        import database

        def explode(*args, **kwargs):
            raise RuntimeError("database is down")

        monkeypatch.setattr(database, "get_connection", explode)
        response = client.get("/api/ready")
        assert response.status_code == 503
        assert response.json()["ready"] is False
        assert response.json()["database"] == "failed"

    def test_ready_does_not_leak_the_database_url(self, client):
        """The endpoint is unauthenticated; a DSN would disclose host and credentials."""
        text = client.get("/api/ready").text.lower()
        assert "postgresql://" not in text
        assert "postgres://" not in text
        assert "password" not in text
        assert "redis://" not in text

    def test_ready_never_returns_exception_text(self, client, monkeypatch):
        """A driver error can embed a connection string; the response must not."""
        import database

        def explode(*args, **kwargs):
            raise RuntimeError(
                "connection to postgresql://user:secretpw@10.0.0.1:5432/db failed"
            )

        monkeypatch.setattr(database, "get_connection", explode)
        text = client.get("/api/ready").text.lower()
        assert "secretpw" not in text
        assert "10.0.0.1" not in text


class TestDeepHealth:
    def test_health_returns_200(self, client):
        assert client.get("/api/health").status_code == 200

    def test_counts_are_present_and_typed(self, client):
        body = client.get("/api/health").json()
        for key in ("total_pages", "total_leads", "active_sessions"):
            assert key in body, f"{key} missing from the health summary"
            assert body[key] is None or isinstance(body[key], int)
        assert "summary_available" in body

    def test_health_does_not_scan_unbounded_rows(self):
        """The old implementation called get_all_registrations(); it must not come back."""
        import main as main_module

        source = open(main_module.__file__, encoding="utf-8").read()
        health_start = source.index('async def health_check')
        # The whole function, up to the next top-level decorator.
        health_end = source.index('@app.', health_start)
        # Strip comments: the docstring explains what the OLD code did, and a naive scan
        # would match that explanation instead of executable code.
        body = "\n".join(
            line for line in source[health_start:health_end].splitlines()
            if not line.lstrip().startswith("#")
        )
        assert "get_all_registrations()" not in body, (
            "health must count, not materialise every registration"
        )
        assert "COUNT(*)" in body

    def test_health_does_not_leak_secrets(self, client, monkeypatch):
        monkeypatch.setenv("ADMIN_PASSWORD", "super-secret-admin-pw")
        monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyFAKEKEYFORTESTINGONLY1234567890")
        text = client.get("/api/health").text
        assert "super-secret-admin-pw" not in text
        assert "AIzaSyFAKEKEYFORTESTINGONLY1234567890" not in text

    def test_health_reports_missing_counts_rather_than_zero(self, client, monkeypatch):
        """A counting failure must not read as 'you have no customers'."""
        import database

        def explode(*args, **kwargs):
            raise RuntimeError("database is down")

        monkeypatch.setattr(database, "get_connection", explode)
        body = client.get("/api/health").json()
        assert body["summary_available"] is False
        assert body["total_leads"] is None


class TestNoProbeUsesDeepHealth:
    """Deployment files must point probes at the cheap endpoints."""

    def test_dockerfile_healthcheck_uses_ready(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "Dockerfile"), encoding="utf-8") as handle:
            content = handle.read()
        for line in content.splitlines():
            if line.strip().startswith("CMD") and "/api/" in line:
                pass
        healthcheck = [ln for ln in content.splitlines() if "HEALTHCHECK" in ln or "/api/ready" in ln]
        assert healthcheck
        assert any("/api/ready" in ln for ln in healthcheck)

    def test_staging_compose_uses_ready(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "docker-compose.staging.yml"), encoding="utf-8") as handle:
            content = handle.read()
        assert "/api/ready" in content
        executable = "\n".join(
            line for line in content.splitlines() if not line.lstrip().startswith("#")
        )
        assert "/api/health" not in executable, (
            "a probe in staging compose points at the deep health endpoint"
        )

    def test_deploy_script_uses_ready_not_deep_health(self):
        """Phase 35 found deploy.sh gated on /api/health (the O(rows) one)."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "scripts", "deploy.sh"), encoding="utf-8") as handle:
            content = handle.read()
        # Executable lines only: the explanatory comment legitimately names the endpoint
        # it avoids, and scanning it would fail on the documentation rather than the code.
        probe_lines = [
            ln for ln in content.splitlines()
            if not ln.lstrip().startswith("#")
            and ("/api/health" in ln or "/api/ready" in ln)
        ]
        assert probe_lines, "deploy.sh should verify a health endpoint"
        for line in probe_lines:
            assert "/api/health" not in line, (
                f"deploy.sh still probes the O(rows) endpoint: {line.strip()}"
            )
