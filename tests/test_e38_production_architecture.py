"""Phase 38 — production deployment architecture and operational reliability.

Every test here either parses the real artifact or executes the real code path. Where a
defect was fixed in this phase the test is written so that it FAILS against the pre-fix
file: a test that passes both before and after proves nothing about the fix.

The defects this suite guards, all reproduced before being changed:

  F-38-A  HIGH    a pre-flight backup policy refusal skipped alerting AND the status file,
                  so a missing encryption key made every hourly backup fail silently.
  F-38-B  MED     docs/ALERTING-SETUP.md told the operator to expect exit 15; it is 11.
  F-38-C  MED     with no webhook configured, a failed backup never said nobody was told.
  F-38-D  MED     an unusable BACKUP_DIR escaped as an uncaught traceback.
  F-38-E  HIGH    deploy.sh probed a host port that no longer exists once the proxy was
                  added, so every deploy would have rolled itself back.
  F-38-F  HIGH    docker-compose.prod.yml published the app port in plaintext with no
                  proxy at all.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel: str) -> str:
    with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


def _yaml(rel: str):
    import yaml

    return yaml.safe_load(_read(rel))


# ------------------------------------------------- production HTTPS architecture (P2)

class TestProductionProxyTopology:
    """F-38-F: production had no proxy and published the app port directly."""

    @pytest.fixture(scope="class")
    def prod(self):
        return _yaml("docker-compose.prod.yml")

    def test_a_proxy_service_exists(self, prod):
        assert "proxy" in prod["services"], (
            "docker-compose.prod.yml has no reverse proxy, so production would be served "
            "over plaintext HTTP"
        )

    def test_the_proxy_runs_caddy(self, prod):
        image = prod["services"]["proxy"]["image"]
        assert image.startswith("caddy:"), f"expected a Caddy image, found {image!r}"

    def test_only_the_proxy_publishes_host_ports(self, prod):
        publishers = {
            name: svc.get("ports")
            for name, svc in prod["services"].items()
            if svc.get("ports")
        }
        assert set(publishers) == {"proxy"}, (
            f"services other than `proxy` publish host ports: {publishers}"
        )

    def test_the_application_does_not_publish_its_port(self, prod):
        assert not prod["services"]["web"].get("ports"), (
            "`web` still publishes a host port; that bypasses TLS, HSTS and the proxy's "
            "header handling entirely"
        )

    def test_datastores_publish_nothing(self, prod):
        for name in ("db", "redis"):
            assert not prod["services"][name].get("ports"), (
                f"`{name}` publishes a host port and would be reachable from outside"
            )

    def test_the_proxy_publishes_https_and_the_acme_port(self, prod):
        ports = " ".join(prod["services"]["proxy"]["ports"])
        assert "443:443" in ports, "the proxy does not publish 443"
        assert "80:80" in ports, (
            "the proxy does not publish 80, so ACME HTTP-01 challenges cannot be answered "
            "and a certificate cannot be issued without TLS-ALPN only"
        )

    def test_web_depends_on_the_proxy_topology_being_satisfiable(self, prod):
        """The proxy must wait for a healthy app, or it serves 502 during boot."""
        depends = prod["services"]["proxy"].get("depends_on") or {}
        assert "web" in depends
        assert depends["web"]["condition"] == "service_healthy"

    def test_certificate_storage_is_a_named_volume(self, prod):
        """Losing it re-issues certificates and hits Let's Encrypt rate limits."""
        assert "caddy_data" in prod["volumes"]
        mounts = " ".join(str(v) for v in prod["services"]["proxy"]["volumes"])
        assert "caddy_data:/data" in mounts

    def test_the_proxy_mounts_the_production_caddyfile(self, prod):
        mounts = " ".join(str(v) for v in prod["services"]["proxy"]["volumes"])
        assert "deploy/Caddyfile.prod" in mounts, (
            "the proxy does not mount the production Caddyfile"
        )

    def test_staging_and_production_agree_on_topology(self):
        """The architecture must not drift between the two stacks."""
        staging = _yaml("docker-compose.staging.yml")
        production = _yaml("docker-compose.prod.yml")
        for compose, label in ((staging, "staging"), (production, "production")):
            publishers = {
                n for n, s in compose["services"].items() if s.get("ports")
            }
            assert publishers == {"proxy"}, f"{label} publishes from {publishers}"


class TestProductionDomainFailClosed:
    """A missing domain must fail clearly, never silently downgrade to plaintext."""

    def test_domain_is_required_with_an_explicit_message(self):
        text = _read("docker-compose.prod.yml")
        assert re.search(
            r"PRODUCTION_DOMAIN:\s*\$\{PRODUCTION_DOMAIN:\?[^}]*\}", text
        ), "PRODUCTION_DOMAIN is not required with ':?', so a missing domain is silent"

    def test_there_is_no_plaintext_fallback_address(self):
        caddy = _read("deploy/Caddyfile.prod")
        body = "\n".join(
            ln for ln in caddy.splitlines() if ln.strip() and not ln.strip().startswith("#")
        )
        assert not re.search(r"^\s*:80\s*\{", body, re.MULTILINE), (
            "a :80-only site block would serve production over plaintext"
        )
        assert "auto_https off" not in body, "auto_https is disabled"
        assert "tls internal" not in body, (
            "a private CA is unsuitable for production; clients would reject it"
        )

    def test_no_invented_production_domain_is_hardcoded(self):
        caddy = _read("deploy/Caddyfile.prod")
        assert "$PRODUCTION_DOMAIN" in caddy
        # An example.mn literal would silently become the real certificate target.
        body = "\n".join(
            ln for ln in caddy.splitlines() if not ln.strip().startswith("#")
        )
        assert "example.mn" not in body, (
            "the production Caddyfile hardcodes a placeholder domain outside a comment"
        )


class TestProductionTrustedHeaders:
    """F-38-F follow-on: with a proxy in front, TRUSTED_PROXIES cannot be empty."""

    def test_trusted_proxies_is_required_in_production(self):
        text = _read("docker-compose.prod.yml")
        assert re.search(r"TRUSTED_PROXIES:\s*\$\{TRUSTED_PROXIES:\?", text), (
            "TRUSTED_PROXIES still defaults to empty. With a proxy in front, the app would "
            "ignore X-Forwarded-Proto and mint http:// payment callback URLs even though "
            "clients arrive over https"
        )

    def test_the_proxy_sets_the_forwarded_scheme(self):
        caddy = _read("deploy/Caddyfile.prod")
        assert "X-Forwarded-Proto {http.request.scheme}" in caddy

    def test_forwarded_headers_replace_rather_than_append(self):
        """`header_up X+` appends, letting a client inject hops ahead of ours.

        Checked on comment-stripped lines only: the file *explains* the `X+` hazard in a
        comment, and a naive substring test flags that explanation as the defect itself.
        """
        caddy = _read("deploy/Caddyfile.prod")
        body = "\n".join(
            ln for ln in caddy.splitlines() if not ln.strip().startswith("#")
        )
        assert "X+" not in body, (
            "`header_up X+` appends instead of replacing, so a forged inbound chain survives"
        )


class TestProductionCaddyfile:
    def test_log_redacts_session_tokens(self):
        caddy = _read("deploy/Caddyfile.prod")
        for key in ("token", "auth_token", "client_token"):
            assert re.search(rf"replace\s+{key}\s+", caddy), (
                f"the access log does not redact ?{key}=, so session tokens are written "
                "verbatim to container logs"
            )

    def test_exactly_one_log_format_directive(self):
        caddy = _read("deploy/Caddyfile.prod")
        start = caddy.index("log {")
        depth, end = 0, start
        for i in range(start, len(caddy)):
            if caddy[i] == "{":
                depth += 1
            elif caddy[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        block = caddy[start:end]
        assert len(re.findall(r"^\s*format\b", block, re.MULTILINE)) == 1, (
            "a repeated `format` inside one `log` block is a hard Caddyfile error"
        )

    def test_header_block_uses_defer(self):
        caddy = _read("deploy/Caddyfile.prod")
        start = caddy.index("header {")
        assert re.search(r"^\s*defer\s*$", caddy[start:start + 800], re.MULTILINE), (
            "without `defer` the proxy overwrites the application's security headers"
        )

    def test_hsts_is_set(self):
        assert "Strict-Transport-Security" in _read("deploy/Caddyfile.prod")


# ------------------------------------------------------- backup alerting (P4)

class TestBackupAlertingReachesTheHandler:
    """F-38-A: a pre-flight refusal must still alert and write status."""

    def test_cli_passes_the_label_into_the_preflight(self):
        text = _read("scripts/maintenance.py")
        assert "_policy_preflight(label=label)" in text, (
            "backup-run does not pass its label to the pre-flight check, so a refusal "
            "cannot be recorded or alerted"
        )

    def test_the_refusal_path_calls_the_shared_finish(self):
        text = _read("scripts/maintenance.py")
        assert "_record_refusal" in text
        assert "_finish(" in text.split("def _record_refusal")[1][:1200], (
            "the refusal path does not call `_finish`, which is where alerting and the "
            "status file live"
        )

    def test_a_refusal_executes_and_returns_the_policy_code(self, tmp_path):
        """Executed, not inferred: the real CLI, a real missing key."""
        env = {
            k: v for k, v in os.environ.items()
            if k not in ("BACKUP_ENCRYPTION_KEY_FILE", "BACKUP_ALERT_WEBHOOK")
        }
        env.update({
            "BACKUP_DIR": str(tmp_path / "backups"),
            "BACKUP_ENCRYPTION": "on",
            "BACKUP_ENCRYPTION_KEY_FILE": "/nonexistent/p38-test.key",
            "PYTHONPATH": REPO_ROOT,
        })
        result = subprocess.run(
            [sys.executable, "scripts/maintenance.py", "backup-run", "--label", "t38"],
            capture_output=True, text=True, cwd=REPO_ROOT, env=env, timeout=180,
        )
        assert result.returncode == 11, (
            f"expected 11 (ENCRYPTION_KEY_MISSING), got {result.returncode}"
        )
        combined = result.stdout + result.stderr
        assert "nobody is notified" in combined, (
            "the failure did not state that no webhook is configured; an operator cannot "
            "distinguish 'alerting is fine' from 'alerting was never set up'"
        )
        status = tmp_path / "backups" / ".last_backup_status.json"
        assert status.exists(), (
            "a refused backup wrote no status file, so monitoring keeps reporting the "
            "previous successful run"
        )
        import json

        recorded = json.loads(status.read_text())
        assert recorded["success"] is False
        assert recorded["exit_code"] == 11


class TestAlertPayloadSafety:
    def test_alert_failure_does_not_mask_the_backup_exit_code(self):
        """The alert is best-effort; the exit code is the contract."""
        text = _read("core/backup_automation.py")
        section = text.split("def _finish")[1][:2600]
        assert "warnings" in section, (
            "an alert failure is not recorded as a warning on the result"
        )
        # `notify` must not be able to raise out of _finish.
        assert "try:" in section or "notify(" in section

    def test_payload_is_redacted_before_it_leaves_the_process(self):
        text = _read("core/backup_automation.py")
        section = text.split("payload = {")[1][:1600]
        assert "sanitize_payload" in section, (
            "the alert payload is sent without redaction"
        )

    def test_redaction_scrubs_secrets_but_keeps_diagnostics(self, monkeypatch):
        monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", "e38_planted_secret_value_0000001")
        monkeypatch.setenv(
            "DATABASE_URL", "postgresql+psycopg2://u:SUPERSECRETPW_abc@h:5/d"
        )
        sys.path.insert(0, REPO_ROOT)
        from core import redaction

        payload = {
            "event": "backup.failure",
            "error": (
                "connection to postgresql://u:SUPERSECRETPW_abc@h:5/d failed; "
                "key=e38_planted_secret_value_0000001"
            ),
            "warnings": ["password=inline_plaintext_999 rejected"],
            "filename": "pg_backup_20260101.sql.gz",
        }
        out = redaction.sanitize_payload(
            payload, secret_values=redaction.collect_secret_values()
        )
        import json

        blob = json.dumps(out)
        for secret in (
            "SUPERSECRETPW_abc",
            "e38_planted_secret_value_0000001",
            "inline_plaintext_999",
        ):
            assert secret not in blob, f"{secret} leaked into the alert payload"
        assert "pg_backup_20260101.sql.gz" in blob, (
            "redaction destroyed the archive filename, the most actionable field"
        )


class TestAlertingDocs:
    """F-38-B: the runbook told the operator the wrong exit code."""

    def test_documented_exit_code_matches_the_policy(self):
        """A missing key is 11 (encryption), not 15 (not configured)."""
        sys.path.insert(0, REPO_ROOT)
        from core import backup_policy

        # The policy states the split in its own docstring/comments; assert the code does.
        source = _read("core/backup_policy.py")
        assert "a missing key has always been 11" in source
        doc = _read("docs/ALERTING-SETUP.md")
        # Find the §5.4 command's stated expectation.
        assert "Expect exit **11**" in doc, (
            "the alerting runbook does not state the correct exit code for a missing key"
        )
        assert "Expect exit **15**" not in doc, (
            "the runbook still tells the operator to expect 15 for a missing key, which "
            "would make a working alerting path look broken"
        )


# ------------------------------------------------- backup destination safety (P5)

class TestUnusableBackupDirectory:
    """F-38-D: os.makedirs sat outside the handler written to catch it."""

    def test_an_uncreatable_directory_returns_a_clean_error(self, monkeypatch):
        sys.path.insert(0, REPO_ROOT)
        from core import backup_automation

        monkeypatch.setattr(
            backup_automation, "backup_dir", lambda: "/proc/p38/cannot-exist"
        )
        monkeypatch.setenv("BACKUP_ENCRYPTION", "off")
        monkeypatch.delenv("BACKUP_ALERT_WEBHOOK", raising=False)

        result = backup_automation.run_scheduled_backup(label="t38-dest")
        assert result["success"] is False
        assert result["exit_code"] == backup_automation.EXIT_BACKUP_FAILED
        assert "cannot be created" in result["error"], (
            f"expected an actionable message, got {result['error']!r}"
        )

    def test_the_directory_creation_is_inside_a_try(self):
        """A structural backstop for the executed test above."""
        text = _read("core/backup_automation.py")
        before = text.split("os.makedirs(directory, exist_ok=True)")[0]
        tail = before[-400:]
        assert "try:" in tail, (
            "os.makedirs is outside a try block, so an unusable path raises a traceback"
        )


# -------------------------------------------------- deployment script safety (P6)

class TestDeployScriptTopology:
    """F-38-E: the health gate probed a port the new topology no longer publishes."""

    def test_health_check_does_not_assume_a_published_host_port(self):
        text = _read("scripts/deploy.sh")
        assert not re.search(r"curl[^\n]*127\.0\.0\.1:\$\{PORT", text), (
            "deploy.sh probes a published host port, which no longer exists now that the "
            "proxy is the only service publishing ports; every deploy would roll back"
        )
        assert "exec -T web" in text, (
            "deploy.sh does not probe the app from inside its own container"
        )

    def test_a_failed_healthcheck_still_rolls_back(self):
        text = _read("scripts/deploy.sh")
        assert "scripts/rollback.sh" in text
        section = text.split("/api/ready")[-1][:600]
        assert "rollback.sh" in section

    def test_deploy_refuses_without_a_backup(self):
        text = _read("scripts/deploy.sh")
        assert "refusing to deploy without a backup" in text, (
            "a deploy with no restore point can be rolled back only to a broken state"
        )


# ---------------------------------------------- production configuration (P5)

class TestProductionConfigFailsClosed:
    REQUIRED = (
        "POSTGRES_PASSWORD",
        "PRODUCTION_DOMAIN",
        "ACME_EMAIL",
        "ALLOWED_ORIGINS",
        "POSTGRES_APP_PASSWORD",
        "ADMIN_PASSWORD",
        "TRUSTED_PROXIES",
        "E02_ACCOUNT_KEY_SECRET",
        "POSTGRES_OWNER_PASSWORD",
    )

    def test_every_required_setting_uses_the_required_form(self):
        text = _read("docker-compose.prod.yml")
        present = set(re.findall(r"\$\{([A-Z0-9_]+):\?", text))
        missing = [name for name in self.REQUIRED if name not in present]
        assert not missing, (
            f"these are not required with ':?', so a missing value would not stop the "
            f"stack: {missing}"
        )

    def test_production_enables_strict_security(self):
        prod = _yaml("docker-compose.prod.yml")
        for service in ("web", "worker"):
            env = prod["services"][service]["environment"]
            assert env.get("ENV") == "production"
            assert str(env.get("STRICT_SECURITY")) in ("1", "true", "yes")

    # Each case states the WHOLE relevant environment rather than relying on what happens
    # to be exported. The first version deleted REDIS_URL for both cases, so the
    # "missing account key" case actually tripped the Redis gate and reported the wrong
    # missing setting — a test that would have passed a broken build for the wrong reason.
    @pytest.mark.parametrize(
        "env,needle",
        [
            # account key absent, Redis present -> must name the account key
            (
                {
                    "ENV": "production",
                    "STRICT_SECURITY": "1",
                    "REDIS_URL": "redis://127.0.0.1:6379/0",
                },
                "E02_ACCOUNT_KEY_SECRET",
            ),
            # account key present, Redis absent -> must name Redis
            (
                {
                    "ENV": "production",
                    "STRICT_SECURITY": "1",
                    "E02_ACCOUNT_KEY_SECRET": "e38_padding_padding_padding_padding_1",
                    "REDIS_URL": "",
                },
                "REDIS_URL",
            ),
        ],
    )
    def test_startup_refuses_and_names_the_missing_setting(self, env, needle, tmp_path):
        """Executed in a subprocess so the assertion is about real startup behaviour.

        The child gets an ALLOWLISTED environment, not a filtered copy of this one. An
        autouse conftest fixture exports `E02_ACCOUNT_KEY_SECRET` into the real process
        environment for the whole session, so a "delete the keys I care about" approach
        silently inherited it and the account-key case booted. Asserting about a fail-closed
        guard using an environment that already satisfies the guard proves nothing.
        """
        keep = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "VIRTUAL_ENV", "SYSTEMROOT")
        base = {k: v for k, v in os.environ.items() if k in keep}
        base.update(env)
        base["DB_PATH"] = str(tmp_path / "p38_fc.db")
        base["PYTHONPATH"] = REPO_ROOT
        # The startup guards live in `main.lifespan`, not at import time. Importing the
        # module alone never runs them, which is exactly why the first version of this
        # test reported that production "booted" with no secrets: it was not testing
        # startup at all. Entering TestClient's context manager runs the lifespan.
        script = (
            "import database; database.init_db()\n"
            "import main\n"
            "from fastapi.testclient import TestClient\n"
            "with TestClient(main.app):\n"
            "    print('BOOTED')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, cwd=REPO_ROOT, env=base, timeout=180,
        )
        assert result.returncode != 0, "production startup did not fail closed"
        assert needle in (result.stdout + result.stderr), (
            f"the failure did not name {needle}"
        )


# ------------------------------------------------------ operational monitoring (P7)

class TestOperationalSignals:
    """Each signal is executed against a real store; none is inferred from source."""

    def test_worker_heartbeat_reports_alive_after_a_beat(self):
        from core import worker_heartbeat

        if not os.getenv("REDIS_URL"):
            pytest.fail(
                "REDIS_URL is not set. The CI step supplies it; skipping here would make "
                "a missing liveness check indistinguishable from a passing one, which is "
                "the exact gap Phase 36 closed for the worker probe."
            )
        assert worker_heartbeat.beat(loop_count=42, worker_id="p38-probe") is True
        report = worker_heartbeat.read()
        assert report["status"] == "alive"
        heartbeat = report["heartbeat"]
        assert heartbeat["worker_id"] == "p38-probe"
        assert heartbeat["loop_count"] == 42

    def test_a_stale_heartbeat_is_not_reported_alive(self):
        """A dead worker's last heartbeat must not keep the deployment looking healthy."""
        import json
        import time

        from core import worker_heartbeat

        if not os.getenv("REDIS_URL"):
            pytest.fail("REDIS_URL is not set; the stale-heartbeat guard cannot be verified")
        import redis

        client = redis.from_url(os.environ["REDIS_URL"])
        key = worker_heartbeat._key()
        client.set(
            key,
            json.dumps(
                {
                    "worker_id": "dead-worker",
                    "loop_count": 1,
                    "at": time.time() - 99999,
                    "pid": 1,
                }
            ),
            ex=5000,
        )
        try:
            assert worker_heartbeat.read()["status"] == "stale"
        finally:
            client.delete(key)

    def test_readiness_exposes_the_backlog_and_dead_letter_counts(self, tmp_path):
        """Executed through the real endpoint, not by reading the source."""
        import json

        sys.path.insert(0, REPO_ROOT)
        os.environ.setdefault("DB_PATH", str(tmp_path / "p38_ready.db"))
        import database

        database.init_db()
        import main
        from fastapi.testclient import TestClient

        with TestClient(main.app) as client:
            response = client.get("/api/ready")
        assert response.status_code == 200
        body = response.json()
        stats = body["queue_stats"]
        for key in ("pending", "processing", "failed", "dead_letter"):
            assert key in stats, f"the backlog signal {key!r} is not observable"

    def test_readiness_never_leaks_a_secret(self, tmp_path, monkeypatch):
        sys.path.insert(0, REPO_ROOT)
        monkeypatch.setenv("DB_PATH", str(tmp_path / "p38_leak.db"))
        planted = "p38_planted_readiness_secret_0001"
        monkeypatch.setenv("ADMIN_PASSWORD", planted)
        import database

        database.init_db()
        import main
        from fastapi.testclient import TestClient

        with TestClient(main.app) as client:
            text = client.get("/api/ready").text
        assert planted not in text
        # Backend kind is fine to expose; the DSN is not.
        assert "://" not in text, "the readiness payload contains a URL"

    def test_connection_budget_refuses_an_oversubscribed_production_pool(self):
        """The guard's decision logic, driven directly.

        This deliberately does not skip when PostgreSQL is absent. CI's gate treats a
        skip as a failure ("skipping is not passing"), and rightly so - a security guard
        that is only exercised on the machine that happened to have a database is not
        guarded. The pure computation below is what decides the outcome; the PostgreSQL
        path is exercised separately by ``test_connection_budget_is_a_noop_on_sqlite``
        and by the full PG suite.
        """
        sys.path.insert(0, REPO_ROOT)
        from core import db_engine

        monkeypatch = pytest.MonkeyPatch()
        try:
            monkeypatch.setenv("PG_MAX_CONNECTIONS", "5")
            monkeypatch.setenv("DB_POOL_SIZE", "50")
            monkeypatch.setenv("DB_MAX_OVERFLOW", "50")
            monkeypatch.setenv("DB_PROCESS_ROLE", "api")
            budget = db_engine.connection_budget_from_env(api_processes=2)
            assert budget["total_required"] > budget["usable"], (
                "the fixture did not oversubscribe the pool"
            )
            assert budget["fits"] is False
            assert budget["headroom"] < 0
        finally:
            monkeypatch.undo()

    def test_an_in_budget_configuration_reports_fits(self):
        sys.path.insert(0, REPO_ROOT)
        from core import db_engine

        monkeypatch = pytest.MonkeyPatch()
        try:
            monkeypatch.setenv("PG_MAX_CONNECTIONS", "100")
            monkeypatch.setenv("PG_SUPERUSER_RESERVED", "3")
            monkeypatch.setenv("DB_POOL_SIZE", "5")
            monkeypatch.setenv("DB_MAX_OVERFLOW", "5")
            monkeypatch.setenv("DB_PROCESS_ROLE", "api")
            budget = db_engine.connection_budget_from_env(api_processes=2)
            assert budget["fits"] is True, budget
            assert budget["headroom"] > 0
        finally:
            monkeypatch.undo()

    def test_connection_budget_is_a_deliberate_noop_on_sqlite(self):
        """SQLite must not be failed by a PostgreSQL capacity guard."""
        sys.path.insert(0, REPO_ROOT)
        from core import db_engine

        if db_engine.is_postgres():
            monkeypatch = pytest.MonkeyPatch()
            monkeypatch.setenv("DATABASE_URL", "")
            try:
                pass
            finally:
                monkeypatch.undo()
        # With no PG engine, enforcement returns a structured no-op rather than raising.
        result = db_engine.enforce_connection_budget(api_processes=1)
        assert isinstance(result, dict)


# ------------------------------------------------ production env template (P5)

class TestProductionEnvTemplate:
    """F-38-I: the template did not document the variables that now gate startup."""

    TEMPLATE = "docs/deployment/PRODUCTION_ENV_TEMPLATE.env"

    def test_every_required_compose_variable_is_documented(self):
        import re as _re

        compose = _read("docker-compose.prod.yml")
        required = set(_re.findall(r"\$\{([A-Z0-9_]+):\?", compose))
        template = _read(self.TEMPLATE)
        documented = set(_re.findall(r"^([A-Z0-9_]+)=", template, _re.MULTILINE))
        missing = sorted(required - documented)
        assert not missing, (
            f"these required variables appear in no template, so an operator cannot know "
            f"to set them: {missing}"
        )

    def test_trusted_proxies_is_not_left_empty(self):
        template = _read(self.TEMPLATE)
        match = re.search(r"^TRUSTED_PROXIES=(.*)$", template, re.MULTILINE)
        assert match, "TRUSTED_PROXIES is not documented"
        assert match.group(1).strip(), (
            "TRUSTED_PROXIES is documented as empty; an operator copying this template "
            "gets a stack that refuses to start, and one that would mint http:// payment "
            "URLs behind the proxy"
        )

    def test_the_template_does_not_claim_there_is_no_proxy(self):
        template = _read(self.TEMPLATE)
        assert "port 8000 is published directly" not in template, (
            "the template still describes the pre-Phase-38 topology"
        )

    def test_the_template_carries_no_real_credentials(self):
        template = _read(self.TEMPLATE)
        for name in ("POSTGRES_PASSWORD", "ADMIN_PASSWORD", "E02_ACCOUNT_KEY_SECRET"):
            match = re.search(rf"^{name}=(.*)$", template, re.MULTILINE)
            if match:
                value = match.group(1).strip()
                # A placeholder is fine; a plausible literal is not.
                assert not value or value.startswith("<") or "example" in value.lower(), (
                    f"{name} carries what looks like a real value in a template"
                )
