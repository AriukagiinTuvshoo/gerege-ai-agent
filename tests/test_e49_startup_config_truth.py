"""Phase 49 — configuration and status that report what IS, not what was asked for.

Four separate places in this codebase answered a question with a constant instead of an
observation. Each was found by running the system locally (Phase 48/48A) and reading what
came back rather than what the documentation promised:

F-48A-3 `/api/admin/worker/health` returned a hardcoded scheduler note claiming "the API
        runs with DISABLE_INLINE_SCHEDULER=1". The Phase 48A run had it set to `0` and the
        log said `Executive Daily Briefing & Retention scheduler loop started`, so the one
        endpoint an operator consults told them the opposite of the truth — and hid a real
        problem (two schedulers, duplicate daily reports).

F-48A-5 `core/worker_heartbeat.py` read its three tuning variables at import. The module
        does not load `.env` itself, so *import order* decided whether the operator's
        configuration existed yet. Measured in Phase 48A with `.env` setting
        `WORKER_HEARTBEAT_BEAT_SECONDS=7.5`: a process importing this module directly saw
        10.0, a process importing `database` first saw 7.5. A non-numeric value raised
        during import and surfaced as an unrelated ImportError.

F-48A-1 `database.CSV_PATH` was pinned next to the module while the database was
        redirectable through `DB_PATH`, so a throwaway database silently overwrote the
        repository's `leads.csv`. Fixed in Phase 48A; this file is the regression guard,
        because zero tests referenced `CSV_PATH` when it shipped.

F-49-2  `dashboard.html` rendered `value="agent_verify_secret_token_123"` — a string
        published in this repository — in a field with a "copy" button next to the Meta
        callback URL, and a permanently green "Бэлэн" (Ready) badge. Following that panel
        pasted a public string into Meta, whose handshake production refuses with 403.

Also covered: the Windows launchers. They cannot be *executed* on this Linux CI runner, so
what is asserted here is exactly what can be checked statically — that they start the
documented command, and that none of them prints a credential or weakens a security
setting. Anything requiring a real `cmd.exe` remains NOT VERIFIED and is reported as such.
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PUBLISHED = "agent_verify_secret_token_123"
LAUNCHERS = ("start.bat", "start_agency.bat", "tunnel.bat")


@pytest.fixture(autouse=True, scope="module")
def _schema_ready():
    import database

    database.init_db()
    yield


@pytest.fixture()
def admin_client(monkeypatch):
    import main

    password = "e49-admin-pw"
    monkeypatch.setenv("ADMIN_PASSWORD", password)
    with TestClient(main.app, raise_server_exceptions=False) as client:
        client.cookies.clear()
        response = client.post("/api/auth/login", json={"password": password})
        assert response.status_code == 200, f"admin login failed: {response.status_code}"
        yield client
        client.cookies.clear()


def _read(name: str) -> str:
    return (REPO_ROOT / name).read_text(encoding="utf-8", errors="replace")


# ===========================================================================
# F-48A-3 — the scheduler topology is reported, not asserted
# ===========================================================================


class TestSchedulerTopologyIsObserved:
    def test_what_the_process_did_beats_what_the_variable_says(self, monkeypatch):
        """The core of the fix: `main.py` re-reads `.env` at runtime (F-48A-4), so the
        variable can disagree with the running scheduler. The record wins."""
        import main
        from routers import system_router

        monkeypatch.setenv("DISABLE_INLINE_SCHEDULER", "0")  # variable: it should be running
        monkeypatch.setattr(main, "INLINE_SCHEDULER_STARTED", False, raising=False)
        assert system_router._inline_scheduler_running_in_api() is False

        monkeypatch.setenv("DISABLE_INLINE_SCHEDULER", "1")  # variable: it should be off
        monkeypatch.setattr(main, "INLINE_SCHEDULER_STARTED", True, raising=False)
        assert system_router._inline_scheduler_running_in_api() is True

    def test_the_variable_is_the_fallback_when_the_lifespan_never_ran(self, monkeypatch):
        import main
        from routers import system_router

        monkeypatch.setattr(main, "INLINE_SCHEDULER_STARTED", None, raising=False)
        monkeypatch.setenv("DISABLE_INLINE_SCHEDULER", "1")
        assert system_router._inline_scheduler_running_in_api() is False
        monkeypatch.setenv("DISABLE_INLINE_SCHEDULER", "0")
        assert system_router._inline_scheduler_running_in_api() is True

    def test_the_lifespan_records_the_decision_it_made(self, monkeypatch):
        import main

        monkeypatch.setattr(main, "INLINE_SCHEDULER_STARTED", None, raising=False)
        monkeypatch.setenv("DISABLE_INLINE_SCHEDULER", "1")
        with TestClient(main.app, raise_server_exceptions=False) as client:
            assert client.get("/api/live").status_code == 200
            assert main.INLINE_SCHEDULER_STARTED is False

        monkeypatch.setattr(main, "INLINE_SCHEDULER_STARTED", None, raising=False)
        monkeypatch.setenv("DISABLE_INLINE_SCHEDULER", "0")
        with TestClient(main.app, raise_server_exceptions=False) as client:
            assert client.get("/api/live").status_code == 200
            assert main.INLINE_SCHEDULER_STARTED is True

    def test_the_note_describes_the_duplicate_scheduler_case(self, admin_client, monkeypatch):
        import main

        monkeypatch.setattr(main, "INLINE_SCHEDULER_STARTED", True, raising=False)
        body = admin_client.get("/api/admin/worker/health").json()
        scheduler = body["scheduler"]

        assert scheduler["inline_scheduler_in_api"] is True
        assert "DISABLE_INLINE_SCHEDULER=0" in scheduler["note"]
        assert "twice" in scheduler["note"], "the note must say what the risk actually is"
        # The old constant text asserted the opposite configuration.
        assert "DISABLE_INLINE_SCHEDULER=1, so a stopped worker" not in scheduler["note"]
        # The Phase 36 contract is unchanged.
        assert scheduler["location"] == "worker"
        assert "DISABLE_INLINE_SCHEDULER" in scheduler["note"]

    def test_the_note_describes_the_worker_owns_it_case(self, admin_client, monkeypatch):
        import main

        monkeypatch.setattr(main, "INLINE_SCHEDULER_STARTED", False, raising=False)
        scheduler = admin_client.get("/api/admin/worker/health").json()["scheduler"]

        assert scheduler["inline_scheduler_in_api"] is False
        assert "DISABLE_INLINE_SCHEDULER=1" in scheduler["note"]
        assert "a stopped worker" in scheduler["note"]

    def test_the_response_still_leaks_nothing(self, admin_client, monkeypatch):
        """The note grew longer; the Phase 36 non-disclosure property must survive that."""
        import main

        for started in (True, False):
            monkeypatch.setattr(main, "INLINE_SCHEDULER_STARTED", started, raising=False)
            response = admin_client.get("/api/admin/worker/health")
            text = response.text.lower()
            assert "redis://" not in text
            assert "password" not in text
            assert PUBLISHED not in text


# ===========================================================================
# F-48A-5 — heartbeat configuration is read when it is used
# ===========================================================================


class TestHeartbeatConfigurationIsLateBound:
    @pytest.fixture(autouse=True)
    def _clean_env(self, monkeypatch):
        from core import worker_heartbeat as hb

        for name in (hb.FRESH_WINDOW_ENV, hb.KEY_TTL_ENV, hb.BEAT_INTERVAL_ENV):
            monkeypatch.delenv(name, raising=False)
        yield

    def test_the_documented_defaults_are_the_phase_41_numbers(self):
        from core import worker_heartbeat as hb

        assert hb.fresh_window_seconds() == 30
        assert hb.key_ttl_seconds() == 90
        assert hb.beat_interval_seconds() == 10.0
        # Phase 41's invariant: two missed beats must not stale a healthy worker.
        assert hb.beat_interval_seconds() * 2 <= hb.fresh_window_seconds()

    def test_the_values_follow_the_environment_without_a_reimport(self, monkeypatch):
        """The whole point: no import order can bypass them."""
        from core import worker_heartbeat as hb

        monkeypatch.setenv(hb.FRESH_WINDOW_ENV, "45")
        assert hb.fresh_window_seconds() == 45
        monkeypatch.setenv(hb.FRESH_WINDOW_ENV, "12")
        assert hb.fresh_window_seconds() == 12

    def test_a_standalone_import_sees_the_configuration(self):
        """The Phase 48A measurement, as a regression test.

        A child process imports ONLY this module — nothing loads `.env` first — and must
        still see the configured numbers.
        """
        from core import worker_heartbeat as hb

        code = (
            "import sys;"
            "sys.path.insert(0, %r);"
            "from core import worker_heartbeat as hb;"
            "print(hb.FRESH_WINDOW_SECONDS, hb.BEAT_INTERVAL_SECONDS, hb.DEFAULT_TTL_SECONDS)"
        ) % str(REPO_ROOT)
        env = {
            **os.environ,
            hb.FRESH_WINDOW_ENV: "17",
            hb.BEAT_INTERVAL_ENV: "2.5",
            hb.KEY_TTL_ENV: "400",
        }
        result = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=120
        )
        assert result.returncode == 0, result.stderr[-600:]
        assert result.stdout.strip() == "17 2.5 400"

    def test_the_historical_module_attributes_still_resolve(self):
        from core import worker_heartbeat as hb

        assert hb.FRESH_WINDOW_SECONDS == hb.fresh_window_seconds()
        assert hb.DEFAULT_TTL_SECONDS == hb.key_ttl_seconds()
        assert hb.BEAT_INTERVAL_SECONDS == hb.beat_interval_seconds()
        assert isinstance(hb.FRESH_WINDOW_SECONDS, int)
        assert isinstance(hb.DEFAULT_TTL_SECONDS, int)
        assert isinstance(hb.BEAT_INTERVAL_SECONDS, float)

    def test_a_typo_still_raises(self):
        """PEP 562 must not turn every missing attribute into a silent default."""
        from core import worker_heartbeat as hb

        with pytest.raises(AttributeError):
            hb.DEFINITELY_NOT_A_SETTING

    def test_monkeypatching_the_module_attribute_still_wins(self, monkeypatch):
        """Test isolation has to survive the change: an assignment creates a real attribute."""
        from core import worker_heartbeat as hb

        monkeypatch.setattr(hb, "DEFAULT_TTL_SECONDS", 5)
        assert hb.DEFAULT_TTL_SECONDS == 5

    @pytest.mark.parametrize("garbage", ["not-a-number", "", "  ", "12s", "0", "-30"])
    def test_a_bad_value_falls_back_instead_of_raising(self, monkeypatch, garbage):
        """Import used to raise `ValueError`, which surfaced as an unrelated ImportError."""
        from core import worker_heartbeat as hb

        monkeypatch.setenv(hb.FRESH_WINDOW_ENV, garbage)
        assert hb.fresh_window_seconds() == hb.DEFAULT_FRESH_WINDOW_SECONDS

    def test_the_ttl_is_kept_wide_enough_for_the_stale_band(self, monkeypatch):
        """`stale` means wedged, `missing` means gone. A TTL inside the fresh window
        collapses them into one state, and nothing enforced that before."""
        from core import worker_heartbeat as hb

        monkeypatch.setenv(hb.FRESH_WINDOW_ENV, "120")
        monkeypatch.setenv(hb.KEY_TTL_ENV, "90")
        ttl = hb.key_ttl_seconds()
        assert ttl > hb.fresh_window_seconds()
        assert ttl == 360

    def test_a_sane_ttl_is_left_alone(self, monkeypatch):
        from core import worker_heartbeat as hb

        monkeypatch.setenv(hb.FRESH_WINDOW_ENV, "30")
        monkeypatch.setenv(hb.KEY_TTL_ENV, "600")
        assert hb.key_ttl_seconds() == 600

    def test_read_reports_the_numbers_it_actually_used(self, monkeypatch):
        """The payload is the operator's evidence; it must not quote defaults."""
        from core import worker_heartbeat as hb

        monkeypatch.setenv(hb.FRESH_WINDOW_ENV, "17")
        monkeypatch.setenv(hb.KEY_TTL_ENV, "400")
        state = hb.read()
        assert state["fresh_window_seconds"] == 17
        assert state["ttl_seconds"] == 400
        assert state["status"] in ("alive", "stale", "missing", "unknown")

    def test_a_warning_is_logged_once_per_problem(self, monkeypatch):
        from core import worker_heartbeat as hb

        hb._config_warnings.clear()
        monkeypatch.setenv(hb.FRESH_WINDOW_ENV, "nonsense")
        for _ in range(5):
            hb.fresh_window_seconds()
        assert len(hb._config_warnings) == 1
        # The message names the variable and the default, never the value.
        assert "nonsense" not in "".join(hb._config_warnings)
        hb._config_warnings.clear()


# ===========================================================================
# F-48A-1 — the CSV mirror follows the database, not the source tree
# ===========================================================================


def _csv_path_in_child(extra_env: dict, tmp_path: pathlib.Path) -> str:
    """Resolve `database.CSV_PATH` in a child process that never loads `.env`.

    `.env` is stubbed out rather than moved: `core/db_engine.py` calls
    `load_dotenv(override=True)` at import, which would otherwise override whatever the
    child was given (F-48A-2). `DB_PATH` points into the test's tmp dir so the probe cannot
    touch a repository file.
    """
    code = (
        "import sys, types;"
        "stub = types.ModuleType('dotenv');"
        "stub.load_dotenv = lambda *a, **k: False;"
        "stub.find_dotenv = lambda *a, **k: '';"
        "stub.set_key = lambda *a, **k: None;"
        "sys.modules['dotenv'] = stub;"
        "sys.path.insert(0, %r);"
        "import database;"
        "print(database.CSV_PATH)"
    ) % str(REPO_ROOT)
    env = {
        **os.environ,
        "DB_PATH": str(tmp_path / "probe.db"),
        "CSV_PATH": "",
        **extra_env,
    }
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(tmp_path),
        timeout=180,
    )
    assert result.returncode == 0, result.stderr[-800:]
    return result.stdout.strip().splitlines()[-1]


class TestCsvMirrorIsRedirectable:
    def test_the_environment_decides_where_the_mirror_is_written(self, tmp_path):
        target = tmp_path / "throwaway-mirror.csv"
        got = _csv_path_in_child({"CSV_PATH": str(target)}, tmp_path)
        assert got == str(target)

    def test_the_default_is_unchanged_for_every_existing_install(self, tmp_path):
        """Backward compatibility, asserted rather than assumed: `docker-compose.yml` bind
        mounts `./leads.csv`, so the default has to keep resolving to the repository root."""
        got = _csv_path_in_child({}, tmp_path)
        assert got == str(REPO_ROOT / "leads.csv")

    def test_the_source_still_reads_the_variable(self):
        """Guards the fix itself against a future 'simplification' back to a constant."""
        source = _read("database.py")
        assignment = next(
            line for line in source.splitlines() if line.strip().startswith("CSV_PATH =")
        )
        assert 'os.getenv("CSV_PATH"' in assignment
        assert "leads.csv" in assignment
        assert "__file__" in assignment

    def test_env_example_documents_it_next_to_the_database(self):
        text = _read(".env.example")
        assert "CSV_PATH=" in text
        assert text.index("DB_PATH=") < text.index("CSV_PATH=") < text.index("REDIS_URL=")


# ===========================================================================
# F-49-2 — the dashboard does not hand out a published secret
# ===========================================================================


def _rendered_dashboard() -> str:
    """`dashboard.html` without its HTML comments.

    The file documents the removed value in a comment on purpose, the way `main.py`'s
    docstrings quote the expression they removed; what must be true is that nothing
    *rendered* carries it.
    """
    return re.sub(r"<!--.*?-->", "", _read("dashboard.html"), flags=re.DOTALL)


class TestDashboardDoesNotPublishThePlaceholder:
    def test_the_published_string_is_not_rendered_anywhere(self):
        assert PUBLISHED not in _rendered_dashboard()

    def test_the_verify_token_field_starts_empty(self):
        match = re.search(r'<input id="settings-webhook-verify-token"[^>]*>', _read("dashboard.html"))
        assert match, "the verify-token input disappeared from the settings panel"
        assert f'value="{PUBLISHED}"' not in match.group(0)
        assert 'value=""' in match.group(0)

    def test_the_field_is_filled_from_the_page_record(self):
        text = _read("dashboard.html")
        assert "p.verify_token" in text
        assert "verify_token_is_placeholder" in text, (
            "the frontend must ask the server whether a value is public, not know the string"
        )
        assert "settings-webhook-verify-token-note" in text

    def test_the_readiness_badge_is_no_longer_a_constant_claim(self):
        text = _read("dashboard.html")
        assert 'id="settings-webhook-status-badge"' in text
        assert "meta_token_configured" in text
        assert "/api/health" in text
        badge = re.search(r'<span id="settings-webhook-status-badge"[^>]*>([^<]*)</span>', text)
        assert badge, "the badge lost its id"
        assert badge.group(1).strip() != "Бэлэн", "the badge still claims readiness unconditionally"

    def test_the_field_says_which_endpoint_it_authenticates(self):
        """`/webhook` compares META_VERIFY_TOKEN; `/api/manychat` compares the page token.
        Conflating them is what made the old panel actively misleading."""
        label = re.search(r"<label[^>]*>Verify Token[^<]*<code[^>]*>([^<]+)</code>", _read("dashboard.html"))
        assert label, "the verify-token label no longer names its endpoint"
        assert label.group(1) == "/api/manychat"

    def test_copying_nothing_says_so(self):
        text = _read("dashboard.html")
        index = text.index("function copyWebhookVerifyToken")
        body = text[index : index + 900]
        assert "el.value.trim()" in body, "the copy handler no longer checks for an empty field"
        assert "Хуулах утга алга" in body


# ===========================================================================
# The Windows launchers — everything that can be checked without Windows
# ===========================================================================


class TestLaunchers:
    @pytest.mark.parametrize("name", LAUNCHERS)
    def test_the_launcher_is_still_there(self, name):
        assert (REPO_ROOT / name).is_file(), f"{name} went missing"

    @pytest.mark.parametrize("name", LAUNCHERS)
    def test_no_launcher_prints_a_credential(self, name):
        """Phase 48A removed `echo Админ нууц үг: ADMIN2026` from a launcher that also opens
        a public tunnel. This keeps it removed, in every launcher."""
        text = _read(name)
        lowered = text.lower()
        assert "admin2026" not in lowered
        assert "password123!" not in lowered
        assert "%admin_password%" not in lowered, "a launcher must not expand the secret"
        assert "echo %meta_" not in lowered
        assert "type .env" not in lowered, "a launcher must not dump .env to the console"

    @pytest.mark.parametrize("name", LAUNCHERS)
    def test_no_launcher_weakens_a_security_setting(self, name):
        """`start_agency.bat` publishes the machine through a Cloudflare tunnel, so it above
        all must not turn a guard off on the way past."""
        for line in _read(name).splitlines():
            stripped = line.strip().lower()
            if not stripped.startswith("set "):
                continue
            for forbidden in (
                "env=production",
                "strict_security=0",
                "webhook_fail_closed=0",
                "disallow_query_token=0",
            ):
                assert forbidden not in stripped, f"{name} sets {forbidden}"

    def test_the_launchers_start_the_documented_command(self):
        assert "python main.py" in _read("start.bat")
        assert "python main.py" in _read("start_agency.bat")
        readme = _read("README.md")
        assert "python main.py" in readme, "README and the launchers disagree on how to start"

    def test_the_launchers_point_at_the_documented_port(self):
        for name in ("start.bat", "start_agency.bat", "tunnel.bat"):
            assert "http://localhost:8000" in _read(name)
        assert "8000" in _read("README.md")

    def test_the_agency_launcher_tells_the_operator_where_the_password_is(self):
        """The replacement for the removed echo: a pointer, not a value."""
        text = _read("start_agency.bat")
        assert "ADMIN_PASSWORD" in text
        assert ".env" in text
        assert "дэлгэцэнд хэвлэгдэхгүй" in text, "the launcher no longer says the value is not printed"

    def test_every_python_file_a_launcher_names_exists(self):
        for name in LAUNCHERS:
            for referenced in set(re.findall(r"([A-Za-z0-9_\-]+\.py)\b", _read(name))):
                assert (REPO_ROOT / referenced).is_file(), f"{name} runs {referenced}, which is not in the repository"


# ===========================================================================
# Documentation agrees with the code
# ===========================================================================


class TestDocumentationAgrees:
    def test_the_readme_documents_the_manychat_rule(self):
        text = _read("README.md")
        assert "/api/manychat" in text
        assert "MANYCHAT_WEBHOOK_SECRET" in text
        assert "403" in text

    def test_the_readme_documents_the_upsert_rule(self):
        text = _read("README.md")
        assert "POST /api/pages" in text
        assert "upsert" in text.lower()
        assert "monthly_token_limit" in text

    def test_no_document_offers_the_published_placeholder(self):
        """Phase 48A removed the instruction; Phase 49 keeps the value out of the docs too.
        Naming a published secret in a setup guide is how it ends up in a Meta dashboard."""
        for name in ("README.md", ".env.example", ".env.staging.example"):
            assert PUBLISHED not in _read(name), f"{name} prints the published placeholder"

    def test_the_env_example_explains_why_a_placeholder_is_refused(self):
        text = _read(".env.example")
        assert "MANYCHAT_WEBHOOK_SECRET=" in text
        assert "F-49-1" in text
        assert "secrets.token_urlsafe" in text, "the file must say how to generate one"
