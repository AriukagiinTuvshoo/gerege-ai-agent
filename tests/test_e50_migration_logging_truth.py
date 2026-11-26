"""Phase 50 — F-50-4: running the migrations must not silence the application.

`migrations/env.py` called `logging.config.fileConfig(alembic.ini)`, which defaults to
`disable_existing_loggers=True`, and `alembic.ini` sets `[logger_root] level = WARN`.
`main.py` imports — and therefore creates the loggers of — `agent`, `database`,
`core.security`, `core.secret_guard`, `core.ai_router`, `core.monitoring`, `core.task_queue`,
`core.rate_limit` and `fintech_service` *before* `database.init_db()` reaches that file.

Measured on a first boot (empty database, so the migrations do run), before the fix:

    agent                          True        core.security              True
    database                       True        core.redaction             False
    core.task_queue                True        core.account_keys          False
    core.rate_limit                True        fintech_service            True
    core.secret_guard              True        gerege.worker              False
    core.ai_readiness              True        core.backup_automation     False
    core.monitoring                True        core.ai_router             True

    DISABLED: 10 of 15
    an agent error logged after first boot reaches a handler: False

So a freshly deployed instance — or any release that ships a new migration, which is every
schema change — ran with its AI errors, its security log, its "secrets are not
production-ready" warning and its structured monitoring all silently dropped, for the
lifetime of the process, while looking completely healthy. This is the mechanism behind the
`caplog` hazard Phase 49 recorded without being able to explain it: on an already-migrated
database `core.schema_manager.ensure_schema()` returns before invoking Alembic, so nothing
is disabled and capture works — which is why the same assertion passed on a warm database
and captured nothing on a cold one.

The fix has two guards, both pinned here: `core.schema_manager._alembic_config()` tells
`env.py` to skip logging configuration entirely when Alembic runs as a library, and
`env.py` passes `disable_existing_loggers=False` so that even a CLI `alembic upgrade head`
run next to a live process cannot silence it. Alembic's own output is unaffected on the CLI
path, which is what that configuration exists for.

Every assertion about the application boot runs in a **child process**: logger state is
process-global, so a test that migrated the schema earlier in the session would otherwise
decide the answer for the tests that follow.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: The loggers an operator depends on during an incident. Chosen before the measurement, not
#: after: these are the modules that log AI failures, security decisions, secret-guard
#: warnings, queue and limiter state, payments and structured monitoring.
WATCHED_LOGGERS = (
    "agent",
    "database",
    "ai_agent_app",
    "core.task_queue",
    "core.rate_limit",
    "core.secret_guard",
    "core.ai_readiness",
    "core.security",
    "core.redaction",
    "core.account_keys",
    "core.ai_router",
    "core.monitoring",
    "core.backup_automation",
    "fintech_service",
    "gerege.worker",
)

#: What the same measurement returned before the fix. Kept so the test says what regressing
#: would look like, instead of just "something changed".
DISABLED_BEFORE_THE_FIX = {
    "agent",
    "database",
    "core.task_queue",
    "core.rate_limit",
    "core.secret_guard",
    "core.ai_readiness",
    "core.security",
    "core.monitoring",
    "core.ai_router",
    "fintech_service",
}

_BOOT_SCRIPT = r"""
import json
import logging
import sys
import types

# `.env` must not decide this measurement: `core/db_engine.py` calls
# `load_dotenv(override=True)` at import, which would override DB_PATH and point the child at
# a real database (F-48A-2). Stubbing dotenv keeps the probe on the disposable database the
# parent asked for, whether or not the developer has a .env in the repository root.
_stub = types.ModuleType("dotenv")
_stub.load_dotenv = lambda *a, **k: None
_stub.find_dotenv = lambda *a, **k: ""
sys.modules["dotenv"] = _stub

root = logging.getLogger()
before = {
    "root_level": root.level,
    "root_handlers": [type(h).__name__ for h in root.handlers],
}

# The production entrypoint: importing it runs database.init_db(), which runs the migrations
# on an empty database and therefore executes migrations/env.py.
import main  # noqa: E402

after = {
    "root_level": logging.getLogger().level,
    "root_handlers": [type(h).__name__ for h in logging.getLogger().handlers],
    "disabled": {name: bool(logging.getLogger(name).disabled) for name in json.loads(sys.argv[1])},
}

# The consequence an operator would actually feel: can a message still be logged?
captured = {}
for name in ("agent", "core.ai_readiness", "core.security", "core.secret_guard"):
    seen = []

    class Probe(logging.Handler):
        def emit(self, record, _seen=seen):
            _seen.append(record.getMessage())

    logger = logging.getLogger(name)
    handler = Probe()
    logger.addHandler(handler)
    logger.error("e50-probe-message-for-%s" % name)
    logger.removeHandler(handler)
    captured[name] = bool(seen)

# And through the module that Phase 50 added, which logs once per failed generation call.
from core import ai_readiness  # noqa: E402

seen = []


class Probe2(logging.Handler):
    def emit(self, record, _seen=seen):
        _seen.append(record.getMessage())


probe_logger = logging.getLogger("core.ai_readiness")
handler = Probe2()
probe_logger.addHandler(handler)
ai_readiness.record_failure(RuntimeError("403 PERMISSION_DENIED"), model="e50-model")
probe_logger.removeHandler(handler)
captured["ai_readiness.record_failure"] = bool(seen)

print(json.dumps({"before": before, "after": after, "captured": captured}))
"""


@pytest.fixture(scope="module")
def first_boot():
    """One real first boot of the application against an empty database, in a child process."""
    import tempfile

    workdir = tempfile.mkdtemp(prefix="e50-boot-")
    script = os.path.join(workdir, "boot_probe.py")
    with open(script, "w", encoding="utf-8") as handle:
        handle.write(_BOOT_SCRIPT)

    env = dict(os.environ)
    env["DB_PATH"] = os.path.join(workdir, "first_boot.db")
    env["CSV_PATH"] = os.path.join(workdir, "first_boot.csv")
    env["BACKUP_DIR"] = os.path.join(workdir, "backups")
    env["PYTHONPATH"] = REPO_ROOT
    env.pop("DATABASE_URL", None)
    env.pop("REDIS_URL", None)
    env.pop("GEMINI_API_KEY", None)
    # Deterministic: with no META_APP_SECRET the guard must warn in development, which is the
    # warning an operator needs on a fresh deployment.
    env.pop("META_APP_SECRET", None)
    env["ENV"] = "development"

    completed = subprocess.run(
        [sys.executable, script, json.dumps(list(WATCHED_LOGGERS))],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert completed.returncode == 0, f"first boot failed:\n{completed.stderr[-3000:]}"

    payload = json.loads(completed.stdout.strip().splitlines()[-1])
    payload["stderr"] = completed.stderr
    # The migrations must actually have run, or the test would be measuring nothing.
    assert "Running upgrade" in completed.stderr, (
        "the child did not run any migration, so it did not exercise migrations/env.py"
    )
    return payload


class TestAFirstBootDoesNotSilenceTheApplication:
    def test_no_application_logger_is_left_disabled(self, first_boot):
        disabled = [n for n, flag in first_boot["after"]["disabled"].items() if flag]
        assert disabled == [], f"these loggers were silenced by the migration run: {disabled}"

    def test_the_measurement_is_about_the_loggers_that_used_to_be_silenced(self, first_boot):
        """Guard against the test passing because it stopped looking at the right loggers."""
        watched = set(first_boot["after"]["disabled"])
        assert set(WATCHED_LOGGERS) == watched
        assert DISABLED_BEFORE_THE_FIX <= watched, (
            "the loggers this finding was measured on must stay in the watched set"
        )

    def test_an_ai_error_can_still_be_logged_after_a_first_boot(self, first_boot):
        assert first_boot["captured"]["agent"] is True
        assert first_boot["captured"]["ai_readiness.record_failure"] is True

    def test_a_security_log_can_still_be_written_after_a_first_boot(self, first_boot):
        """`core.security` logs webhook refusals and admin events; losing those is losing
        the audit trail an incident review reads."""
        assert first_boot["captured"]["core.security"] is True

    def test_the_applications_own_logging_configuration_survives(self, first_boot):
        """`main.py` calls `logging.basicConfig(level=INFO)`. `alembic.ini` sets root to WARN
        and installs its own formatter, which would have dropped every INFO line the
        application emits — so what must survive is the *application's* configuration, not
        whatever the process happened to have before importing."""
        import logging as _logging

        assert first_boot["after"]["root_level"] == _logging.INFO, (
            "root was left at alembic.ini's WARN, so application INFO logs are dropped"
        )
        assert first_boot["after"]["root_handlers"] == ["StreamHandler"]

    def test_the_applications_log_format_is_the_one_still_in_use(self, first_boot):
        """The two configurations are distinguishable only by their formatter:
        `basicConfig` writes `LEVEL:name:message`, alembic.ini writes `LEVEL [name] message`."""
        stderr = first_boot["stderr"]
        assert "INFO:database:Schema ready" in stderr, "the application's formatter is gone"
        assert "INFO  [alembic" not in stderr, (
            "alembic.ini's formatter replaced the application's during the migration run"
        )

    def test_the_migration_output_is_still_visible_in_the_application_log(self, first_boot):
        """Skipping Alembic's logging config must not hide what the migration did."""
        stderr = first_boot["stderr"]
        assert "Running upgrade" in stderr
        assert "Schema ready: upgraded" in stderr

    def test_the_secret_guard_can_still_speak_after_a_first_boot(self, first_boot):
        """`core.secret_guard` produces the warning an operator most needs on a fresh
        deployment ("secrets are not production-ready"). Its logger is created before the
        migrations run, so before the fix that warning was among the ones silently dropped.

        The guard itself only speaks during the lifespan, which a bare import never runs, so
        this asserts the property that was actually broken: the logger can still emit.
        """
        assert first_boot["after"]["disabled"]["core.secret_guard"] is False
        assert first_boot["captured"]["core.secret_guard"] is True


class TestTheCliPathIsUnaffected:
    """`env.py` still configures logging for a human running Alembic from a shell."""

    def test_cli_upgrade_still_works_and_uses_alembics_own_formatter(self, tmp_path):
        env = dict(os.environ)
        # `alembic.ini` pins `sqlalchemy.url = sqlite:///leads.db`, and `migrations/env.py`
        # lets that pin win over DB_PATH unless DATABASE_URL is set. Pointing DATABASE_URL at
        # a disposable file is what keeps this test from migrating a file in the repository.
        target = tmp_path / "cli.db"
        env["DATABASE_URL"] = f"sqlite:///{target}"
        env["DB_PATH"] = str(target)
        env["CSV_PATH"] = str(tmp_path / "cli.csv")
        env["PYTHONPATH"] = REPO_ROOT

        completed = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", "alembic.ini", "upgrade", "head"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
        )
        assert completed.returncode == 0, completed.stderr[-2000:]
        combined = completed.stdout + completed.stderr
        assert target.exists(), "the CLI run must have used the disposable database"
        # alembic.ini's formatter is "%(levelname)-5.5s [%(name)s] %(message)s"; the
        # application's basicConfig formatter is "LEVEL:name:message". The CLI must still
        # produce the former, which only happens if fileConfig ran.
        assert "INFO  [alembic.runtime.migration]" in combined

    def test_the_skip_is_requested_only_by_the_programmatic_caller(self):
        from core.schema_manager import _alembic_config

        assert _alembic_config().attributes.get("skip_logging_config") is True

        source = open(
            os.path.join(REPO_ROOT, "core", "schema_manager.py"), encoding="utf-8"
        ).read()
        assert source.count('cfg.attributes["skip_logging_config"] = True') == 1


class TestTheGuardsAreInTheSource:
    def test_env_py_never_disables_existing_loggers(self):
        source = open(os.path.join(REPO_ROOT, "migrations", "env.py"), encoding="utf-8").read()
        assert "disable_existing_loggers=False" in source
        assert "fileConfig(config.config_file_name)\n" not in source, (
            "an unguarded fileConfig() call came back"
        )

    def test_env_py_honours_the_skip_attribute(self):
        source = open(os.path.join(REPO_ROOT, "migrations", "env.py"), encoding="utf-8").read()
        assert 'config.attributes.get("skip_logging_config")' in source

    def test_the_two_guards_are_documented_where_they_live(self):
        """A one-line default with no comment gets reverted by the next person who tidies up."""
        env_source = open(os.path.join(REPO_ROOT, "migrations", "env.py"), encoding="utf-8").read()
        manager_source = open(
            os.path.join(REPO_ROOT, "core", "schema_manager.py"), encoding="utf-8"
        ).read()
        assert "F-50-4" in env_source
        assert "F-50-4" in manager_source

    def test_alembic_ini_still_sets_a_root_level(self):
        """The skip must stay necessary: if alembic.ini ever stopped configuring root, the
        programmatic guard would be dead code nobody notices has rotted."""
        ini = open(os.path.join(REPO_ROOT, "alembic.ini"), encoding="utf-8").read()
        assert "[logger_root]" in ini
