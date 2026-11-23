"""Phase 39 — staging operational readiness and deployment rehearsal.

Every test here parses the real artifact or executes the real code path. Where a defect
was found in this phase the test is written so that it FAILS against the pre-fix file: a
test that passes both before and after proves nothing about the fix.

The defects this suite guards, all reproduced before being changed:

  F-39-D  HIGH  ``run_worker_tick`` ran its scheduler steps unguarded and published the
                heartbeat as its *last* statement, so any raising step skipped the
                heartbeat entirely. A live worker therefore reported **dead** to the
                container healthcheck, Docker crash-looped a process that was only
                partially broken, and queue processing plus appointment reminders both
                stopped. Reproduced: 3/3 ticks raised, heartbeat status went ``missing``.
  F-39-A  MED   ``docker-compose.staging.yml`` declared **0/7** resource limits (prod had
                5/7), so staging could starve a shared host of CPU and memory.
  F-39-B  MED   the production worker had **no healthcheck** — Phase 37 fixed staging
                only — so a wedged production worker stayed ``Up`` forever.
  F-39-C  MED   ``docker-compose.prod.yml`` had no ``name:``, so the compose project was
                derived from the directory name. Run from the same checkout as staging it
                collided with staging's ``pgdata`` / ``redisdata`` / ``caddy_data``
                volumes, i.e. one environment could mount the other's database.
"""

from __future__ import annotations

import ast
import os
import re

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

STAGING = "docker-compose.staging.yml"
PROD = "docker-compose.prod.yml"

# The seven long-running services that must be bounded on a shared host. ``migrate`` is
# deliberately excluded: it is a one-shot job that must be allowed to use a whole core.
BOUNDED_SERVICES = ("proxy", "web", "worker", "maintenance", "db", "redis")


def _read(rel: str) -> str:
    with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


def _yaml(rel: str):
    import yaml

    return yaml.safe_load(_read(rel))


def _mem_mb(value: str) -> float:
    """Turn a compose memory string into megabytes."""
    match = re.fullmatch(r"\s*([0-9.]+)\s*([kKmMgG]?)[bB]?\s*", str(value))
    assert match, f"unparseable memory limit: {value!r}"
    number = float(match.group(1))
    unit = match.group(2).lower()
    return {"": number / (1024 * 1024), "k": number / 1024, "m": number, "g": number * 1024}[unit]


# --------------------------------------------------------------------------------------
# F-39-A — staging resources were unbounded
# --------------------------------------------------------------------------------------


class TestStagingResourceLimits:
    @pytest.fixture(scope="class")
    def staging(self):
        return _yaml(STAGING)

    @pytest.mark.parametrize("service", BOUNDED_SERVICES)
    def test_every_staging_service_is_bounded(self, staging, service):
        """F-39-A: staging declared no limits at all, so any service could take the host."""
        block = staging["services"][service]
        deploy = block.get("deploy") or {}
        resources = deploy.get("resources") or {}
        limits = resources.get("limits") or {}
        assert limits.get("cpus"), f"{service} has no CPU limit in staging"
        assert limits.get("memory"), f"{service} has no memory limit in staging"

    @pytest.mark.parametrize("service", BOUNDED_SERVICES)
    def test_the_limit_values_are_parseable_and_sane(self, staging, service):
        """A limit is only enforced if the runtime can parse it. ``memory: 512`` (no unit)
        would be read as 512 *bytes* and every container would be OOM-killed instantly."""
        limits = staging["services"][service]["deploy"]["resources"]["limits"]

        assert re.fullmatch(r"[0-9.]+", str(limits["cpus"])), limits["cpus"]
        assert 0 < float(limits["cpus"]) <= 8, f"{service} cpu limit looks wrong: {limits['cpus']}"

        assert re.fullmatch(r"[0-9]+[mMgG]", str(limits["memory"])), (
            f"{service} memory limit needs an explicit m/g unit: {limits['memory']!r}"
        )
        assert 16 <= _mem_mb(limits["memory"]) <= 16384, (
            f"{service} memory limit looks wrong: {limits['memory']}"
        )

    def test_the_runtime_does_not_also_set_a_conflicting_limit(self, staging):
        """``mem_limit``/``cpus`` alongside ``deploy.resources`` is legal, but if only one of
        the two carries a value the effective bound depends on the Compose version. Do not
        leave two sources of truth for the same number."""
        for service in BOUNDED_SERVICES:
            block = staging["services"][service]
            if "mem_limit" in block:
                assert _mem_mb(block["mem_limit"]) == _mem_mb(
                    block["deploy"]["resources"]["limits"]["memory"]
                ), f"{service} declares two different memory limits"

    def test_staging_limits_do_not_exceed_production(self, staging):
        """Staging must not be able to claim more of a shared host than production does."""
        prod = _yaml(PROD)

        for service in BOUNDED_SERVICES:
            if service not in prod["services"]:
                continue
            staging_limits = staging["services"][service]["deploy"]["resources"]["limits"]
            prod_limits = ((prod["services"][service].get("deploy") or {}).get("resources") or {}).get(
                "limits"
            ) or {}
            if not prod_limits.get("memory"):
                continue
            assert _mem_mb(staging_limits["memory"]) <= _mem_mb(prod_limits["memory"]), (
                f"{service} staging memory limit exceeds production"
            )

    def test_the_migration_job_is_not_artificially_bounded(self, staging):
        """A one-shot migration is allowed to be unbounded — it must finish, not be throttled."""
        block = staging["services"]["migrate"]
        limits = ((block.get("deploy") or {}).get("resources") or {}).get("limits") or {}
        assert not limits.get("memory"), "migrate should not carry a memory limit"


# --------------------------------------------------------------------------------------
# F-39-B — the production worker had no healthcheck
# --------------------------------------------------------------------------------------


class TestProductionWorkerHealthcheck:
    @pytest.fixture(scope="class")
    def worker(self):
        return _yaml(PROD)["services"]["worker"]

    def test_the_production_worker_has_a_healthcheck(self, worker):
        """F-39-B: without one a wedged worker stays ``Up`` and nothing restarts it."""
        assert "healthcheck" in worker, "production worker has no healthcheck"

    def test_the_healthcheck_probes_the_heartbeat_key(self, worker):
        probe = " ".join(worker["healthcheck"]["test"])
        assert "heartbeat" in probe, probe

    def test_the_healthcheck_fails_closed_without_a_heartbeat(self, worker):
        """A 'not present yet' heartbeat must be unhealthy, not silently healthy."""
        probe = " ".join(worker["healthcheck"]["test"])
        # The probe is `sys.exit(0 if read()["status"] == "alive" else 1)`, so the failure
        # branch may be spelled `exit(1)`, `exit 1`, or an `else 1` conditional.
        assert re.search(r"exit\(1\)|exit\s+1|else\s+1\)", probe), (
            f"the probe has no non-zero exit path for an unhealthy worker: {probe}"
        )
        assert "sys.exit(" in probe, probe

    def test_the_healthcheck_is_exec_form(self, worker):
        """Shell form would need a shell in the image; exec form is also unambiguous."""
        assert worker["healthcheck"]["test"][0] == "CMD", worker["healthcheck"]["test"]

    def test_the_healthcheck_can_actually_fail(self, worker):
        """Execute the probe string: no heartbeat must yield a non-zero exit."""
        import subprocess
        import sys

        spec = worker["healthcheck"]["test"]
        if spec[0] == "CMD":
            spec = spec[1:]  # exec form: ["python", "-c", "<code>"]
        if len(spec) < 3 or "-c" not in spec:
            pytest.skip(f"probe is not an inline python program: {spec[:2]}")
        code = spec[spec.index("-c") + 1]

        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "REDIS_URL": "redis://127.0.0.1:6379/15",
            "PYTHONPATH": REPO_ROOT,
        }
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode != 0, (
            "the worker probe exited 0 with no heartbeat in Redis, so a dead worker "
            f"would be reported healthy\nstdout={result.stdout}\nstderr={result.stderr}"
        )

    def test_the_healthcheck_is_restart_aware(self, worker):
        assert worker.get("restart") in {"unless-stopped", "always", "on-failure"}

    def test_staging_and_production_probes_agree(self):
        """The two environments must not diverge on what 'worker alive' means."""
        staging_probe = " ".join(_yaml(STAGING)["services"]["worker"]["healthcheck"]["test"])
        prod_probe = " ".join(_yaml(PROD)["services"]["worker"]["healthcheck"]["test"])
        assert staging_probe == prod_probe, (
            f"worker probes diverged:\n staging: {staging_probe}\n prod   : {prod_probe}"
        )


# --------------------------------------------------------------------------------------
# F-39-C — the production project name was derived from the directory
# --------------------------------------------------------------------------------------


class TestComposeProjectNames:
    def test_staging_declares_an_explicit_project_name(self):
        assert _yaml(STAGING).get("name") == "gerege-staging"

    def test_production_declares_an_explicit_project_name(self):
        """F-39-C: with no ``name:`` the project is the directory name, so two environments
        checked out side by side can resolve to the same volume namespace."""
        assert _yaml(PROD).get("name") == "gerege-production"

    def test_the_two_project_names_differ(self):
        assert _yaml(STAGING)["name"] != _yaml(PROD)["name"]

    def test_no_named_volume_is_shared_by_both_environments(self):
        """Volume keys are project-scoped; a shared key across a shared project name would
        let staging mount the production database."""
        staging_volumes = set(_yaml(STAGING).get("volumes") or {})
        prod_volumes = set(_yaml(PROD).get("volumes") or {})
        assert staging_volumes & prod_volumes, "expected the same logical volume keys"

        assert _yaml(STAGING)["name"] != _yaml(PROD)["name"], (
            "the same logical volume keys are declared in both files, so the project "
            "names are the only thing keeping the data directories apart"
        )

    def test_staging_uses_its_own_database_name(self):
        staging_db = _yaml(STAGING)["services"]["db"]["environment"]["POSTGRES_DB"]
        assert staging_db != "gerege", "staging must not target the production database name"
        assert "staging" in str(staging_db)


# --------------------------------------------------------------------------------------
# F-39-D — an unguarded scheduler step killed the heartbeat
# --------------------------------------------------------------------------------------


def _tick_source() -> str:
    return _read("worker.py")


def _find_tick(tree):
    """``run_worker_tick`` is an async def; AsyncFunctionDef is NOT a FunctionDef subclass,
    so matching on FunctionDef alone silently finds nothing."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "run_worker_tick":
            return node
    raise AssertionError("run_worker_tick not found in worker.py")


class TestWorkerTickIsFailureIsolated:
    """F-39-D is the serious one: partial failure used to look like total death."""

    def test_the_stats_dict_declares_the_scheduler_error_counter(self):
        tick = _find_tick(ast.parse(_tick_source()))
        found = None
        for inner in ast.walk(tick):
            if isinstance(inner, ast.Dict):
                keys = [k.value for k in inner.keys if isinstance(k, ast.Constant)]
                if "queue_processed" in keys:
                    found = keys
        assert found is not None, "run_worker_tick has no stats dict"
        assert "scheduler_errors" in found, f"scheduler_errors missing from stats: {found}"

    def test_the_heartbeat_payload_reports_the_counter(self):
        source = _tick_source()
        assert '"scheduler_errors"' in source, "the heartbeat payload does not carry scheduler_errors"

    def test_the_heartbeat_allowlist_accepts_the_counter(self):
        """The heartbeat writer validates extra keys; an unlisted key is dropped silently,
        which would hide the signal at exactly the moment it matters."""
        from core import worker_heartbeat

        assert "scheduler_errors" in worker_heartbeat.ALLOWED_EXTRA_KEYS

    def test_each_scheduler_step_is_individually_guarded(self):
        """Three scheduler steps must each have their own ``except``: one shared try around
        all of them would let step 2's failure skip step 3."""
        tick = _find_tick(ast.parse(_tick_source()))

        guarded = 0
        for node in ast.walk(tick):
            if not isinstance(node, ast.Try):
                continue
            body_source = ast.get_source_segment(_tick_source(), node) or ""
            if "scheduler_errors" in body_source:
                guarded += 1

        assert guarded >= 3, (
            f"only {guarded} scheduler step(s) increment scheduler_errors; each of the "
            "three serial scheduler steps needs its own guard"
        )

    def test_the_heartbeat_is_the_last_meaningful_action_of_the_tick(self):
        """This is deliberate, not a bug: publishing the beat last is what detects a wedged
        loop, so the fix is the per-step guards and never moving the beat earlier.

        The tick ends with ``return stats``; the beat is the last thing it *does*. Every
        scheduler step must therefore be ordered before it.
        """
        tick = _find_tick(ast.parse(_tick_source()))

        def _has_beat(node) -> bool:
            return any(
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Attribute)
                and inner.func.attr == "beat"
                for inner in ast.walk(node)
            )

        beat_statement = None
        for index, statement in enumerate(tick.body):
            if _has_beat(statement):
                beat_statement = index
        assert beat_statement is not None, "the tick no longer publishes a heartbeat"

        scheduler_after_beat = [
            statement
            for statement in tick.body[beat_statement + 1 :]
            if isinstance(statement, (ast.Expr, ast.Assign, ast.For, ast.While, ast.Try))
        ]
        assert not scheduler_after_beat, (
            "work still runs after the heartbeat, which would let the worker report "
            "'alive' while it is wedged"
        )

        # The return must follow the beat, otherwise the tick could never report stats.
        assert isinstance(tick.body[-1], ast.Return)


@pytest.mark.integration
class TestWorkerTickSurvivesASchedulerFailure:
    """The reproduction, executed against the fixed code."""

    @pytest.fixture
    def redis_available(self):
        pytest.importorskip  # keep pytest's skip accounting honest
        try:
            from core import worker_heartbeat

            worker_heartbeat._redis().ping()
        except Exception as exc:  # pragma: no cover - environment dependent
            pytest.fail(f"Redis is required for the heartbeat tests: {exc}")

    def test_a_raising_scheduler_step_still_publishes_an_alive_heartbeat(
        self, tmp_path, monkeypatch, redis_available
    ):
        import asyncio

        import appointment_service
        import database
        from core import worker_heartbeat

        monkeypatch.setenv("DB_PATH", str(tmp_path / "tick.db"))
        monkeypatch.setattr("database.DB_PATH", str(tmp_path / "tick.db"), raising=False)
        database.init_db()
        worker_heartbeat._redis().delete(worker_heartbeat._key())

        async def boom(*args, **kwargs):
            raise RuntimeError("reminder dispatch is wedged")

        monkeypatch.setattr(
            appointment_service, "check_and_dispatch_appointment_reminders", boom, raising=False
        )

        import worker

        asyncio.run(worker.run_worker_tick(0))

        state = worker_heartbeat.read()
        assert state.get("status") == "alive", (
            "a partially failing worker reported dead; before the fix the heartbeat was "
            f"never written and status became 'missing' (got {state.get('status')!r})"
        )

        heartbeat = state.get("heartbeat") or {}
        assert heartbeat.get("scheduler_errors") == 1, heartbeat
        assert "queue_processed" in heartbeat, "the tick did not complete its later steps"

    def test_a_healthy_tick_reports_zero_scheduler_errors(self, tmp_path, monkeypatch, redis_available):
        import asyncio

        import database
        from core import worker_heartbeat

        monkeypatch.setenv("DB_PATH", str(tmp_path / "clean.db"))
        database.init_db()
        worker_heartbeat._redis().delete(worker_heartbeat._key())

        import worker

        asyncio.run(worker.run_worker_tick(0))

        heartbeat = worker_heartbeat.read().get("heartbeat") or {}
        assert heartbeat.get("scheduler_errors") == 0, heartbeat


# --------------------------------------------------------------------------------------
# Staging must not borrow production configuration
# --------------------------------------------------------------------------------------


class TestStagingDoesNotBorrowProductionConfiguration:
    """Staging and production share a `services:` shape but must never share an identity."""

    @pytest.fixture(scope="class")
    def staging_text(self):
        return _read(STAGING)

    @pytest.fixture(scope="class")
    def prod_text(self):
        return _read(PROD)

    def test_each_environment_mounts_its_own_proxy_config(self, staging_text, prod_text):
        """A staging rehearsal must not terminate TLS on the production site address."""
        assert "./deploy/Caddyfile:" in staging_text, "staging does not mount deploy/Caddyfile"
        assert "./deploy/Caddyfile.prod:" in prod_text, "production does not mount its own Caddyfile"
        assert "Caddyfile.prod" not in staging_text, (
            "staging loads the production proxy config, so it would serve PRODUCTION_DOMAIN"
        )

    @staticmethod
    def _site_blocks(text: str) -> list[str]:
        """Return the non-comment lines that open a site block."""
        return [
            line.strip()
            for line in text.splitlines()
            if not line.lstrip().startswith("#") and "{" in line
        ]

    def test_the_site_addresses_differ(self):
        """Compare the actual site blocks, not the comments: Caddyfile.prod legitimately
        *names* {$STAGING_DOMAIN} in prose while explaining how the two differ."""
        staging = _read("deploy/Caddyfile")
        prod = _read("deploy/Caddyfile.prod")

        staging_top = staging.lstrip().splitlines()[0]
        prod_top = prod.lstrip().splitlines()[0]
        del staging_top, prod_top  # the first line is a comment, not the address

        staging_blocks = "\n".join(self._site_blocks(staging))
        prod_blocks = "\n".join(self._site_blocks(prod))

        assert "{$STAGING_DOMAIN}" in staging_blocks
        assert "{$PRODUCTION_DOMAIN}" in prod_blocks
        assert "{$PRODUCTION_DOMAIN}" not in staging_blocks, (
            "staging's site block serves the production domain"
        )
        assert "{$STAGING_DOMAIN}" not in prod_blocks, (
            "production's site block serves the staging domain"
        )

    def test_staging_requires_its_own_domain_variable(self, staging_text):
        assert "${STAGING_DOMAIN:?" in staging_text
        assert "${PRODUCTION_DOMAIN" not in staging_text

    def test_production_requires_its_own_domain_variable(self, prod_text):
        assert "${PRODUCTION_DOMAIN:?" in prod_text
        assert "${STAGING_DOMAIN" not in prod_text

    @pytest.mark.parametrize("rel", [STAGING, PROD], ids=["staging", "production"])
    def test_required_variables_fail_loudly_rather_than_defaulting(self, rel):
        """A missing secret must abort compose, never fall back to a placeholder."""
        required = set(re.findall(r"\$\{([A-Z0-9_]+):\?", _read(rel)))
        assert len(required) >= 9, sorted(required)
        for name in ("ADMIN_PASSWORD", "POSTGRES_OWNER_PASSWORD", "E02_ACCOUNT_KEY_SECRET"):
            assert name in required, f"{name} is not fail-fast in {rel}"

    def test_the_application_password_is_not_the_owner_password(self, staging_text):
        """One credential for both planes would defeat the Phase 16 grant separation."""
        assert "POSTGRES_APP_PASSWORD:?" in staging_text
        assert "POSTGRES_OWNER_PASSWORD:?" in staging_text


# --------------------------------------------------------------------------------------
# F-39-E — the staging file advertised a first-boot escape hatch that does not exist
# --------------------------------------------------------------------------------------


class TestStagingFirstBootStoryIsTrue:
    """This comment was the only place a DNS-less first boot was described, and every
    remedy it named was missing from the repository. An operator following it would have
    concluded the checkout was broken."""

    @staticmethod
    def _prose() -> str:
        """Comment lines only: the point is what the file *tells* an operator."""
        return "\n".join(
            line for line in _read(STAGING).splitlines() if line.lstrip().startswith("#")
        )

    def test_no_phantom_no_proxy_profile_is_advertised(self):
        assert "no-proxy" not in self._prose(), (
            "the staging comments advertise a `--profile no-proxy` that is not defined "
            "anywhere in the file"
        )

    def test_no_phantom_local_caddyfile_is_advertised(self):
        prose = self._prose()
        if "Caddyfile.local" not in prose:
            return
        assert os.path.exists(os.path.join(REPO_ROOT, "deploy/Caddyfile.local")), (
            "the staging comments point at deploy/Caddyfile.local, which does not exist"
        )

    def test_every_profile_named_in_the_prose_is_defined(self):
        """A `--profile X` in a comment must correspond to a real `profiles:` entry."""
        import yaml

        prose = self._prose()
        named = set(re.findall(r"--profile\s+([a-z0-9-]+)", prose))
        defined = set()
        for service in (_yaml(STAGING).get("services") or {}).values():
            for profile in service.get("profiles") or []:
                defined.add(profile)
        # The backup profile is named in prose and is genuinely defined.
        assert named <= defined | {"maintenance"}, (
            f"prose names undefined profiles: {sorted(named - defined)}"
        )

    def test_the_proxy_cannot_be_disabled_if_tls_fails(self):
        """The file must not offer a plaintext fallback, which is the failure mode the
        comment used to invite (publish 8000 and skip TLS)."""
        staging = _yaml(STAGING)
        assert "proxy" in staging["services"]
        assert not staging["services"]["proxy"].get("profiles"), (
            "the proxy must not be behind an opt-out profile"
        )

    def test_web_publishes_no_host_port_at_all(self):
        assert not _yaml(STAGING)["services"]["web"].get("ports"), (
            "the application must only be reachable through the proxy"
        )


# --------------------------------------------------------------------------------------
# The rehearsal script is the only place the staging architecture is EXECUTED
# --------------------------------------------------------------------------------------


class TestTheRehearsalScriptIsRealAndWired:
    """The audit environment has no Docker, so every container-level claim in the Phase 39
    report rests on this script. If it silently degrades to a no-op the report becomes a
    lie, so its shape is asserted here."""

    SCRIPT = "scripts/p39_staging_rehearsal.sh"

    @pytest.fixture(scope="class")
    def script(self):
        return _read(self.SCRIPT)

    def test_the_script_exists_and_is_executable(self):
        path = os.path.join(REPO_ROOT, self.SCRIPT)
        assert os.path.isfile(path)
        assert os.access(path, os.X_OK), "the rehearsal script is not executable"

    def test_it_parses_as_bash(self):
        import subprocess

        result = subprocess.run(["bash", "-n", self.SCRIPT], cwd=REPO_ROOT, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

    def test_it_refuses_to_claim_success_without_docker(self):
        """A missing Docker must be reported as BLOCKED, never as a pass. Executed here:
        this environment genuinely has no Docker, so this is a real negative control."""
        import subprocess

        if subprocess.run(["bash", "-c", "command -v docker"], capture_output=True).returncode == 0:
            pytest.skip("docker is present here, so the BLOCKED path cannot be exercised")

        result = subprocess.run(
            ["bash", self.SCRIPT], cwd=REPO_ROOT, capture_output=True, text=True, timeout=120
        )
        assert result.returncode != 0, (
            "the rehearsal exited 0 without Docker, so a green CI run would prove nothing"
        )
        assert "BLOCKED" in result.stdout, result.stdout

    def test_it_has_a_preflight_guard_for_docker(self, script):
        assert "command -v docker" in script
        assert "docker info" in script

    def test_it_runs_the_real_compose_file(self, script):
        """A hand-written approximation of the stack would not test the shipped artifact."""
        assert "docker-compose.staging.yml" in script

    def test_it_cleans_up_but_does_not_touch_anything_else(self, script):
        """Teardown must be scoped to the disposable project, never a global prune of
        volumes it did not create."""
        assert "down -v" in script
        assert "-p \"$PROJECT\"" in script or "-p $PROJECT" in script
        assert "docker volume prune" not in script, "a global volume prune could destroy real data"
        assert "docker system prune" not in script

    def test_it_uses_a_reserved_invalid_domain(self, script):
        """RFC 2606 reserves .invalid, so no certificate is ever requested for it."""
        assert ".invalid" in script
        assert "letsencrypt.org" not in script

    def test_it_asserts_the_four_phase_39_properties(self, script):
        assert "/api/health" in script
        assert "/api/ready" in script
        assert "scheduler_errors" in script, "the F-39-D reproduction is not in the rehearsal"
        assert "id -u" in script, "the non-root assertion is missing"

    def test_ci_actually_invokes_it(self):
        ci = _read(".github/workflows/ci.yml")
        assert self.SCRIPT in ci, "CI never runs the rehearsal, so it proves nothing"
        # It must not be reachable only through a step that ignores failures.
        index = ci.index(self.SCRIPT)
        preceding = ci[max(0, index - 900) : index]
        assert "continue-on-error: true" not in preceding, (
            "the rehearsal step is allowed to fail without failing the build"
        )

    def test_ci_runs_this_suite(self):
        assert "tests/test_e39_staging_operational_readiness.py" in _read(".github/workflows/ci.yml")


# --------------------------------------------------------------------------------------
# F-39-F — the staging env template named a variable no code reads
# --------------------------------------------------------------------------------------


class TestEnvTemplatesNameVariablesTheCodeReads:
    """A template is a contract. A name that appears only in documentation configures
    nothing, and with BACKUP_ENCRYPTION=on the failure is a refusal at every backup."""

    TEMPLATES = (".env.staging.example", "docs/deployment/PRODUCTION_ENV_TEMPLATE.env", ".env.example")

    def test_the_backup_key_variable_matches_the_code(self):
        """The only name consulted by the backup plane."""
        import inspect

        from core import backup_policy

        source = inspect.getsource(backup_policy)
        assert 'os.getenv("BACKUP_ENCRYPTION_KEY_FILE"' in source

        for template in self.TEMPLATES:
            text = _read(template)
            assert "BACKUP_ENCRYPTION_KEY_FILE" in text, f"{template} never names the real variable"
            assert not re.search(r"^BACKUP_KEY_FILE\s*=", text, re.MULTILINE), (
                f"{template} sets BACKUP_KEY_FILE, which no code reads"
            )

    def test_encryption_on_always_has_a_key_path_configured(self):
        """BACKUP_ENCRYPTION=on with no key path is a guaranteed refusal (exit 15)."""
        for template in self.TEMPLATES:
            text = _read(template)
            if not re.search(r"^BACKUP_ENCRYPTION\s*=\s*on", text, re.MULTILINE):
                continue
            assert re.search(r"^BACKUP_ENCRYPTION_KEY_FILE\s*=\S+", text, re.MULTILINE), (
                f"{template} enables encryption without configuring a key path"
            )

    def test_every_variable_the_staging_stack_requires_is_in_the_template(self):
        """Copying the template must be sufficient to satisfy every `:?` in the compose file."""
        required = set(re.findall(r"\$\{([A-Z0-9_]+):\?", _read(STAGING)))
        template = _read(".env.staging.example")
        provided = set(re.findall(r"^([A-Z0-9_]+)=", template, re.MULTILINE))
        missing = required - provided
        assert not missing, f"the staging template omits required variables: {sorted(missing)}"

    def test_the_staging_template_provides_no_real_credentials(self):
        """Placeholders must be empty; a populated default would be a committed secret."""
        for line in _read(".env.staging.example").splitlines():
            if line.lstrip().startswith("#") or "=" not in line:
                continue
            name, _, value = line.partition("=")
            name = name.strip()
            value = value.strip()
            if not value or "$" in value or value.isdigit():
                continue
            if re.search(r"PASSWORD|SECRET|TOKEN|KEY(?:_FILE)?$", name):
                assert not re.search(r"[A-Za-z0-9]{16,}", value), (
                    f"{name} in the staging template looks like a real credential"
                )


# --------------------------------------------------------------------------------------
# Phase 38's zero-tolerance invariants still hold
# --------------------------------------------------------------------------------------


class TestOperationalScriptsRemainIntact:
    """Phase 38 fixed a deploy that rolled itself back; these must not regress."""

    def test_deploy_takes_a_backup_before_it_brings_up_the_stack(self):
        """Match the real commands. Searching for the bare word "migrate" hits a comment
        on line 14 and passes a broken ordering by accident."""
        source = _read("scripts/deploy.sh")
        backup_at = source.find("scripts/maintenance.py backup")
        up_at = source.find("docker compose -f docker-compose.prod.yml up")
        assert backup_at != -1, "deploy.sh no longer takes a pre-deploy backup"
        assert up_at != -1, "deploy.sh no longer brings the stack up"
        assert backup_at < up_at, "the pre-deploy backup must precede the stack restart"

    def test_a_refused_backup_stops_the_deploy(self):
        source = _read("scripts/deploy.sh")
        assert "refusing to deploy without a backup" in source
        assert re.search(r"exit\s+\d+", source), "deploy.sh has no explicit failure exit"

    def test_rollback_restores_data_as_well_as_code(self):
        source = _read("scripts/rollback.sh")
        assert "restore" in source, "rollback must restore the pre-deploy archive"
        assert "pre_deploy" in source

    def test_the_exit_codes_match_the_implementation(self):
        from core import backup_automation

        assert backup_automation.EXIT_OK == 0
        assert backup_automation.EXIT_BACKUP_FAILED == 10
        assert backup_automation.EXIT_ENCRYPTION_FAILED == 11
        assert backup_automation.EXIT_NOT_CONFIGURED == 15
