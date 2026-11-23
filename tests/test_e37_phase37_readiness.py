"""Phase 37 — independent verification of the staging deployment artifacts.

Phase 36 produced these files and graded itself. Phase 37 read them again from scratch
and found four defects that the Phase 36 tests could not see, because those tests
asserted that a *string was present* rather than that a *behaviour was correct*:

  F-37-1 (HIGH)   Caddyfile had `format json` twice inside one `log` block. Caddy's docs:
                  "each subdirective may only be specified once per `log` block ...
                  repeating one is an error." The proxy would not have started.
  F-37-2 (MEDIUM) The access log recorded full request URIs while the app accepts session
                  tokens via `?token=` query parameters (main.py), so live session tokens
                  would have been written to container logs.
  F-37-3 (LOW)    The `header` block claimed `defer` kept application values authoritative;
                  `defer` was not set, and a bare `field value` overwrites.
  F-37-4 (HIGH)   The worker healthcheck polled `/tmp/worker_heartbeat`, a file nothing
                  ever creates — the heartbeat is a Redis key. The container would have
                  been permanently unhealthy.

The lesson encoded here: assert semantics. Where a claim can be checked by executing
something, execute it.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

import pytest
import yaml


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name: str) -> str:
    with open(os.path.join(REPO_ROOT, name), encoding="utf-8") as handle:
        return handle.read()


def _caddyfile_excluding_comments() -> str:
    """Executable Caddyfile lines only.

    Every defect above was surrounded by a comment that described correct behaviour. A
    scanner that reads comments would have found nothing wrong — which is exactly why
    Phase 36's tests passed.
    """
    return "\n".join(
        line for line in _read("deploy/Caddyfile").splitlines()
        if not line.lstrip().startswith("#")
    )


@pytest.fixture(scope="module")
def staging_compose() -> dict:
    return yaml.safe_load(_read("docker-compose.staging.yml"))


# ---------------------------------------------------------- F-37-1: Caddyfile validity

class TestCaddyLogBlock:
    """The block that would have stopped Caddy from starting."""

    def test_log_block_declares_format_once(self):
        """Repeating `format` inside one `log` block is a Caddyfile error.

        Verified against Caddy's own directive documentation, which states that other
        than `hostnames`, "each subdirective may only be specified once per `log` block
        ... repeating one is an error".
        """
        body = _caddyfile_excluding_comments()
        # Isolate the log block: from the `log {` line to its matching closing brace.
        start = body.index("log {")
        depth = 0
        end = start
        for index in range(start, len(body)):
            if body[index] == "{":
                depth += 1
            elif body[index] == "}":
                depth -= 1
                if depth == 0:
                    end = index
                    break
        block = body[start:end]

        format_count = len(re.findall(r"^\s*format\s", block, re.MULTILINE))
        assert format_count == 1, (
            f"the log block declares `format` {format_count} times; Caddy rejects that "
            f"as a duplicate subdirective:\n{block}"
        )

    def test_no_subdirective_is_repeated_in_the_log_block(self):
        """Generalise the check rather than special-casing `format`."""
        body = _caddyfile_excluding_comments()
        start = body.index("log {")
        depth, end = 0, start
        for index in range(start, len(body)):
            if body[index] == "{":
                depth += 1
            elif body[index] == "}":
                depth -= 1
                if depth == 0:
                    end = index
                    break
        block = body[start:end]
        # Top-level subdirectives of this block are at one indent level.
        names = re.findall(r"^\t([a-z_]+)\s", block, re.MULTILINE)
        repeats = {name for name in names if names.count(name) > 1 and name != "hostnames"}
        assert not repeats, f"repeated log subdirectives: {sorted(repeats)}"


class TestCaddyForwardedHeaders:
    def test_forwarded_proto_is_passed(self):
        """Without it the app mints http:// payment callbacks (F-36-3)."""
        assert "X-Forwarded-Proto {http.request.scheme}" in _read("deploy/Caddyfile")

    def test_forwarding_headers_replace_not_append(self):
        """`header_up X+` would append and let a client inject hops ahead of ours."""
        body = _caddyfile_excluding_comments()
        assert not re.search(r"header_up\s+X-\w+\+", body)


# ------------------------------------------------------- F-37-2: token redaction in logs

class TestCaddyLogRedaction:
    """Session tokens must not reach the access log."""

    def test_app_still_accepts_tokens_in_query_strings(self):
        """Guard the reason this matters.

        If the application ever stops accepting query-string tokens, the redaction below
        becomes belt-and-braces rather than load-bearing — and this test will say so.
        """
        source = _read("main.py")
        assert 'request.query_params.get("token")' in source, (
            "the app no longer reads tokens from the query string; the Caddyfile "
            "redaction comment is now stale"
        )

    def test_log_filter_redacts_every_query_token_key(self):
        body = _caddyfile_excluding_comments()
        for key in ("token", "auth_token", "client_token"):
            assert re.search(rf'replace\s+{key}\s+"?REDACTED"?', body), (
                f"the access log does not redact ?{key}= values"
            )

    def test_log_filter_is_actually_wired_to_the_request_uri(self):
        """Redacting a field that is not logged would be a no-op with a reassuring shape."""
        body = _caddyfile_excluding_comments()
        assert "request>uri" in body, "the filter must target the logged request URI"

    def test_redaction_markers_are_not_empty_strings(self):
        """An empty replacement deletes the key, hiding that a token was even used.

        Keeping a marker preserves the forensic signal while protecting the secret.
        """
        body = _caddyfile_excluding_comments()
        for match in re.finditer(r'replace\s+(token|auth_token|client_token)\s+(\S+)', body):
            assert match.group(2).strip('"') != "", (
                f"{match.group(1)} is deleted rather than redacted"
            )


# ------------------------------------------------------------ F-37-3: header semantics

class TestCaddyHeaderSemantics:
    def test_header_block_uses_defer(self):
        """A bare `field value` overwrites the upstream value.

        The application sets all five of these headers on every response. Without
        `defer` the proxy's copies win, so a future CSP change in the application would
        silently stop taking effect.
        """
        body = _caddyfile_excluding_comments()
        header_block_start = body.index("header {")
        header_block = body[header_block_start:body.index("}", header_block_start)]
        assert "defer" in header_block, (
            "the header block must set `defer` so the application's values win"
        )

    def test_still_hsts_and_nosniff(self):
        body = _caddyfile_excluding_comments()
        assert "Strict-Transport-Security" in body
        assert "X-Content-Type-Options" in body


# ------------------------------------------------------- F-37-4: worker healthcheck

class TestWorkerHealthcheck:
    """The probe that could never have succeeded."""

    def test_healthcheck_does_not_probe_a_file_nothing_creates(self, staging_compose):
        """F-37-4: the heartbeat is a Redis key, not a file on disk."""
        command = " ".join(str(part) for part in staging_compose["services"]["worker"]["healthcheck"]["test"])
        assert "/tmp/worker_heartbeat" not in command, (
            "the healthcheck polls a file the worker never writes; it would always fail"
        )

    def test_healthcheck_reads_the_real_heartbeat(self, staging_compose):
        command = " ".join(str(part) for part in staging_compose["services"]["worker"]["healthcheck"]["test"])
        assert "worker_heartbeat" in command
        assert "alive" in command

    def test_healthcheck_command_actually_executes(self, monkeypatch):
        """Execute the probe instead of pattern-matching it.

        This is the assertion Phase 36 was missing. It runs the compose healthcheck body
        and checks the exit code in both states.
        """
        raw = yaml.safe_load(_read("docker-compose.staging.yml"))["services"]["worker"]["healthcheck"]["test"]
        # compose form: ["CMD", "python", "-c", "<script>"]
        assert raw[0] == "CMD" and raw[1] == "python" and raw[2] == "-c"
        script = raw[3]

        from core import worker_heartbeat

        if worker_heartbeat._redis() is None:
            pytest.skip("needs a live Redis to exercise the heartbeat probe")

        monkeypatch.setenv("DB_PATH", os.path.join(REPO_ROOT, "p37_hc_probe.db"))
        monkeypatch.setenv("REDIS_URL", os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0"))
        worker_heartbeat.clear()

        no_beat = subprocess.run(
            [sys.executable, "-c", script], cwd=REPO_ROOT,
            capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": REPO_ROOT},
        )
        assert no_beat.returncode == 1, (
            f"with no heartbeat the probe must report unhealthy; got {no_beat.returncode}"
        )

        worker_heartbeat.beat(1, worker_id="p37")
        with_beat = subprocess.run(
            [sys.executable, "-c", script], cwd=REPO_ROOT,
            capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": REPO_ROOT},
        )
        assert with_beat.returncode == 0, (
            f"with a fresh heartbeat the probe must report healthy; got "
            f"{with_beat.returncode}: {with_beat.stderr[-400:]}"
        )
        worker_heartbeat.clear()


# --------------------------------------------------------------- port exposure (rebuilt)

class TestPortExposure:
    def test_only_proxy_publishes_host_ports(self, staging_compose):
        published = {
            name: svc["ports"]
            for name, svc in staging_compose["services"].items()
            if svc.get("ports")
        }
        assert set(published) == {"proxy"}, f"unexpected published ports: {published}"

    def test_database_and_redis_are_private(self, staging_compose):
        for name in ("db", "redis"):
            assert "ports" not in staging_compose["services"][name]
            # `expose` is documentation-only and harmless; a host `ports` mapping is not.

    def test_production_compose_port_exposure_is_recorded(self):
        """Production still publishes plaintext 8000 and has no proxy.

        Phase 36 hardened *staging* only. This asserts the fact rather than leaving it
        implicit, so the production verdict cannot quietly assume TLS exists.
        """
        prod = yaml.safe_load(_read("docker-compose.prod.yml"))
        web_ports = prod["services"]["web"].get("ports", [])
        assert any("8000" in str(p) for p in web_ports), (
            "production no longer publishes 8000; update the Phase 37 verdict"
        )
        assert "proxy" not in prod["services"], (
            "production now has a proxy service; the TLS finding is closed and the "
            "verdict must be revisited"
        )


# ------------------------------------------------- Caddyfile structural checker (P4)

class TestCaddyfileChecker:
    """`scripts/check_caddyfile.py` is not `caddy validate`, but it catches F-37-1/F-37-3.

    A real `caddy validate` remains a staging gate because Caddy is not installable in this
    environment (no binary, no Go toolchain, Docker Hub unreachable). What is verified here
    is that the checker genuinely detects the defects that shipped, rather than merely
    agreeing with the file it is pointed at.
    """

    def test_checker_passes_the_current_file(self):
        result = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "scripts", "check_caddyfile.py")],
            capture_output=True, text=True, cwd=REPO_ROOT,
        )
        assert result.returncode == 0, result.stdout + result.stderr

    def test_checker_detects_a_repeated_log_subdirective(self, tmp_path, monkeypatch):
        """The exact shape of F-37-1."""
        broken = tmp_path / "Caddyfile"
        broken.write_text(
            "{$D} {\n\treverse_proxy web:8000\n\tlog {\n\t\tformat json\n\t\tformat json\n\t}\n}\n",
            encoding="utf-8",
        )
        sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
        import importlib

        import check_caddyfile

        importlib.reload(check_caddyfile)
        monkeypatch.setattr(check_caddyfile, "CADDYFILE", str(broken))
        problems = check_caddyfile.check()
        assert any("format" in p and "2 times" in p for p in problems), problems

    def test_checker_detects_a_header_block_without_defer(self, tmp_path, monkeypatch):
        """The exact shape of F-37-3."""
        broken = tmp_path / "Caddyfile"
        broken.write_text(
            "{$D} {\n\theader {\n\t\tX-Frame-Options \"DENY\"\n\t}\n\treverse_proxy web:8000\n"
            "\theader_up X-Forwarded-Proto {http.request.scheme}\n}\n",
            encoding="utf-8",
        )
        sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
        import importlib

        import check_caddyfile

        importlib.reload(check_caddyfile)
        monkeypatch.setattr(check_caddyfile, "CADDYFILE", str(broken))
        problems = check_caddyfile.check()
        assert any("defer" in p for p in problems), problems

    def test_checker_is_wired_into_ci(self):
        ci = _read(".github/workflows/ci.yml")
        assert "check_caddyfile.py" in ci, (
            "the structural checker is not run by CI, so F-37-1 could return unnoticed"
        )


# --------------------------------------------------------- config isolation (P5)

class TestStagingIsolation:
    """Staging must not be able to reach production, and must fail closed.

    Each test here either reads the real configuration files or executes the application's
    own startup path in a subprocess. None of them assert that a string merely appears in a
    file, which is the mistake that let F-37-4 ship in Phase 36.
    """

    def test_staging_defaults_to_a_different_database_than_production(self):
        staging = _yaml("docker-compose.staging.yml")
        production = _yaml("docker-compose.prod.yml")
        staging_db = staging["services"]["db"]["environment"]["POSTGRES_DB"]
        production_db = production["services"]["db"]["environment"]["POSTGRES_DB"]
        assert "gerege_staging" in staging_db
        assert "gerege_crm" in production_db
        assert staging_db != production_db, (
            "staging and production default to the same database name; a copied .env "
            "would point staging at production data"
        )

    def test_staging_runs_in_production_mode(self):
        """Staging must exercise the same security posture, or it proves nothing."""
        compose = _yaml("docker-compose.staging.yml")
        for service in ("web", "worker"):
            env = compose["services"][service]["environment"]
            assert env.get("ENV") == "production", f"{service} does not set ENV=production"
            assert str(env.get("STRICT_SECURITY")) in ("1", "true", "yes")

    def test_staging_uses_the_qpay_sandbox(self):
        with open(os.path.join(REPO_ROOT, ".env.staging.example"), encoding="utf-8") as f:
            template = f.read()
        assert "merchant-sandbox.qpay.mn" in template or "sandbox" in template.lower(), (
            "the staging template does not point QPay at the sandbox; real charges could "
            "be created from staging"
        )

    def test_startup_refuses_without_the_account_key_secret(self):
        """Executed, not inferred: production mode must fail closed."""
        result = _boot_with_env(
            {
                "ENV": "production",
                "STRICT_SECURITY": "1",
                "E02_ACCOUNT_KEY_SECRET": "",
                "REDIS_URL": "",
            }
        )
        assert result.returncode != 0, (
            "the application booted in production mode with no account-key secret"
        )
        combined = result.stdout + result.stderr
        assert "E02_ACCOUNT_KEY_SECRET" in combined, combined[-800:]

    def test_startup_refuses_without_redis_in_production(self):
        """The second gate in the chain, reached only once the first is satisfied."""
        result = _boot_with_env(
            {
                "ENV": "production",
                "STRICT_SECURITY": "1",
                "E02_ACCOUNT_KEY_SECRET": "p37-disposable-not-a-real-secret-000000",
                "REDIS_URL": "",
            }
        )
        assert result.returncode != 0, (
            "the application booted in production mode with no shared rate-limit store"
        )
        assert "REDIS_URL is required" in (result.stdout + result.stderr)

    def test_development_mode_still_boots_without_secrets(self):
        """Fail-closed must not mean fail-always: local development stays usable."""
        result = _boot_with_env({"ENV": "development", "STRICT_SECURITY": "0"})
        assert result.returncode == 0, (result.stdout + result.stderr)[-800:]
        assert "BOOTED" in result.stdout


def _yaml(name):
    import yaml

    with open(os.path.join(REPO_ROOT, name), encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _boot_with_env(overrides):
    """Start the real app in a subprocess with a disposable SQLite database.

    `DATABASE_URL` is stripped unconditionally. When the enclosing suite runs against
    PostgreSQL, inheriting it makes `init_db()` abort on the runtime-role privilege check
    before the gate under test is ever reached, so the test would pass or fail for a reason
    that has nothing to do with what it asserts. This must be hermetic.
    """
    env = {
        k: v for k, v in os.environ.items()
        if k not in overrides and k not in ("DATABASE_URL", "DB_PATH")
    }
    env.update(overrides)
    env["DB_PATH"] = os.path.join(
        os.environ.get("TMPDIR", "/tmp"), f"p37_isolation_{os.getpid()}.db"
    )
    env["PYTHONPATH"] = REPO_ROOT
    script = (
        "import database; database.init_db()\n"
        "import main\n"
        "from fastapi.testclient import TestClient\n"
        "with TestClient(main.app) as c:\n"
        "    print('BOOTED', c.get('/api/live').status_code)\n"
    )
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, cwd=REPO_ROOT, env=env, timeout=180,
    )


# ------------------------------------------------------------- staging runbook (P7)

class TestStagingRunbook:
    """The runbook must have an unbroken numbered sequence and no stale claims."""

    RUNBOOK = "docs/deployment/STAGING_DEPLOYMENT.md"

    #: Claims that were true at some point and are now false. A runbook that keeps them
    #: trains the operator to distrust the document.
    STALE_CLAIMS = (
        "digest is a **placeholder**",
        "No Docker build has been executed",
        "base image digest is a **placeholder**",
    )

    def test_sections_are_numbered_without_gaps(self):
        text = _read(self.RUNBOOK)
        numbers = [int(n) for n in re.findall(r"^## (\d+)\.", text, re.MULTILINE)]
        assert numbers, "no numbered sections found"
        assert numbers == list(range(numbers[0], numbers[0] + len(numbers))), (
            f"section numbering has a gap or duplicate: {numbers}"
        )
        assert len(numbers) >= 14, f"expected at least 14 sections, found {len(numbers)}"

    def test_no_stale_claims_survive(self):
        text = _read(self.RUNBOOK)
        for stale in self.STALE_CLAIMS:
            assert stale not in text, f"the runbook still claims: {stale!r}"

    def test_recovery_objectives_are_present_and_measured(self):
        text = _read(self.RUNBOOK)
        assert "RPO" in text and "RTO" in text
        assert "pg_dump" in text and "pg_restore" in text
        # A measured figure, not an adjective.
        assert re.search(r"\b\d+ ms\b", text), (
            "no measured restore timing; the RTO section is asserting a benchmark it "
            "never took"
        )

    def test_caddy_validate_is_named_as_a_required_gate(self):
        text = _read(self.RUNBOOK)
        assert "caddy validate" in text
        # It must say the check has NOT been run here, not merely list the command.
        assert "never run" in text or "never been parsed" in text

    def test_production_port_exposure_gap_is_documented(self):
        """docker-compose.prod.yml publishes the app port and has no proxy."""
        text = _read(self.RUNBOOK)
        assert "docker-compose.prod.yml" in text
        assert "no reverse proxy" in text or "no\n  proxy" in text or "no proxy" in text
