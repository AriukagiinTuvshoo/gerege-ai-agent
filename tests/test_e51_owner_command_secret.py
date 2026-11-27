"""Phase 51 — F-51-5: a string published in this repository was the Telegram owner secret.

`executive_bot_service.handle_owner_command` decided who owns the business with

    expected_secret = os.getenv("VERIFY_TOKEN", "GEREGE_VERIFY_2026").strip()
    ...
    if not existing_mgr_id or str(existing_mgr_id) == str(chat_id) or provided_secret == expected_secret:
        os.environ["TELEGRAM_MANAGER_CHAT_ID"] = str(chat_id)
        database.update_page_telegram_settings(..., manager_chat_id=str(chat_id))

`VERIFY_TOKEN` was documented nowhere: not in `.env.example`, not in `.env`, not in
`docker-compose.prod.yml`, not in `docker-compose.staging.yml`, not in `docs/`. A repository
wide `grep -rn GEREGE_VERIFY_2026` matched exactly one line — the default itself. So the
published literal *was* the credential of every deployment that switched Telegram on, and a
Telegram bot is public by username: a stranger who messaged it `/start GEREGE_VERIFY_2026`
became the owner, received the daily executive report (revenue, invoices, cargo, customers),
could pull `/today`, `/report`, `/qpay` and `/cargo` on demand, and locked the real owner out
through the very guard that protects a registered manager. With `VERIFY_TOKEN` set but empty
the hole was wider: `provided_secret == expected_secret` became `"" == ""`, so a bare `/start`
from anybody took ownership.

This is the third instance of one defect in this codebase — a value published in the
repository being accepted as a credential. F-44-B closed it for `META_VERIFY_TOKEN`, F-49-1
for the ManyChat webhook. Both were found by following a published default to the comparison
that used it; this one was found from the other direction, by listing every environment
variable the code reads that no template mentions (that listing is now a test:
`TestEveryEnvironmentVariableTheCodeReadsIsDocumented`).

Each behavioural test below was run against the pre-fix handler and failed; the predicate
tests could not run at all because `owner_command_secret_is_usable` did not exist. Nothing
here weakens an existing assertion — `handle_owner_command` had no test coverage of any kind
before this file (only `scratch/test_executive_e2e.py`, which is not collected and which
asserts nothing about ownership).
"""

import asyncio
import io
import os
import re
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import database  # noqa: E402
import executive_bot_service  # noqa: E402
from core import secret_guard, security  # noqa: E402

#: Taken from the one place that owns the rule, never retyped: a test that hardcodes the
#: published literal would keep passing if the literal changed.
PUBLISHED = security.PUBLIC_OWNER_COMMAND_SECRET

OWNER = "111111"          # the chat id already registered as the report recipient
STRANGER = "999999"       # anybody else who finds the bot
STRONG = "e51-generated-owner-secret-4c8f1a9d"


def _run(coro):
    """Drive the async handler from a synchronous test."""
    return asyncio.run(coro)


@pytest.fixture()
def registered_owner(monkeypatch):
    """A page whose report recipient is already OWNER, recording every write.

    `handle_owner_command` reads the manager id from the page row first and from
    `TELEGRAM_MANAGER_CHAT_ID` second, so the page is the authority under test. Both the read
    and the write are stubbed: this test must not depend on a database, and it must be able
    to assert that *nothing was written*.
    """
    writes = []
    page = {"page_id": "p51", "telegram_manager_chat_id": OWNER, "telegram_bot_token": ""}
    monkeypatch.setattr(database, "get_page", lambda _page_id: dict(page))
    monkeypatch.setattr(
        database,
        "update_page_telegram_settings",
        lambda **kwargs: writes.append(kwargs) or None,
    )
    monkeypatch.delenv("TELEGRAM_MANAGER_CHAT_ID", raising=False)
    return {"page": page, "writes": writes}


@pytest.fixture()
def unregistered(monkeypatch):
    """The same page with nobody registered yet — the onboarding case."""
    writes = []
    page = {"page_id": "p51", "telegram_manager_chat_id": "", "telegram_bot_token": ""}
    monkeypatch.setattr(database, "get_page", lambda _page_id: dict(page))
    monkeypatch.setattr(
        database,
        "update_page_telegram_settings",
        lambda **kwargs: writes.append(kwargs) or None,
    )
    monkeypatch.delenv("TELEGRAM_MANAGER_CHAT_ID", raising=False)
    return {"page": page, "writes": writes}


def _start(chat_id, text, page_id="p51"):
    return _run(
        executive_bot_service.handle_owner_command(
            chat_id=str(chat_id), text=text, page_id=page_id
        )
    )


# --------------------------------------------------------------------------------------
# 1. The rule itself: a published value is not a secret, in any environment
# --------------------------------------------------------------------------------------


class TestThePublishedLiteralIsNotASecret:
    """`owner_command_secret_is_usable` — the point-of-use guard (F-51-5)."""

    @pytest.mark.parametrize(
        "value",
        [
            PUBLISHED,
            PUBLISHED.lower(),
            PUBLISHED.upper(),
            f"  {PUBLISHED}  ",          # trimmed, so padding is not a bypass
            f"{PUBLISHED}\n",
            "",
            "   ",
            None,
            "changeme",
            "change_me",
            "<generate: openssl rand -base64 32>",
            "your-secret-here",
            security.PUBLIC_VERIFY_TOKEN_PLACEHOLDER,   # the *other* published literal
        ],
    )
    def test_refused(self, value):
        assert security.owner_command_secret_is_usable(value) is False

    def test_a_generated_value_is_accepted(self):
        assert security.owner_command_secret_is_usable(STRONG) is True

    @pytest.mark.parametrize("env", ["development", "production"])
    def test_refused_in_every_environment(self, monkeypatch, env):
        """Unlike the Meta handshake this is not permissive in development.

        `meta_verify_token_is_usable` accepts the published default outside production
        because sixteen suites authenticate with it and nothing is exposed there. Nothing
        depends on this one — no test and no template ever named it — and development
        permissiveness is how a published literal reaches production unnoticed.
        """
        monkeypatch.setenv("ENV", env)
        monkeypatch.delenv("STRICT_SECURITY", raising=False)
        assert security.owner_command_secret_is_usable(PUBLISHED) is False
        assert security.owner_command_secret_is_usable(STRONG) is True

    def test_it_never_returns_the_value(self):
        """A predicate, not an accessor: the caller compares, it does not receive."""
        assert security.owner_command_secret_is_usable(STRONG) is True
        assert isinstance(security.owner_command_secret_is_usable(STRONG), bool)

    def test_the_published_literal_is_on_the_authoritative_list(self):
        """`core.secret_guard` keeps one list of values this repository publishes."""
        assert PUBLISHED.lower() in secret_guard.PUBLISHED_OR_PLACEHOLDER_VALUES
        issue = secret_guard.classify_secret("VERIFY_TOKEN", PUBLISHED)
        assert issue is not None and issue.reason == "placeholder"
        assert PUBLISHED not in issue.detail, "the detail must not carry the value"

    def test_verify_token_is_not_a_startup_requirement(self):
        """Deliberate: after the fix, an unset VERIFY_TOKEN is the *safer* configuration.

        No secret means no secret-based re-registration at all. Forcing operators to invent
        one would be the mistake `core/secret_guard.py` already documents for
        `META_APP_SECRET` — measured to fail unrelated suites while removing no risk.
        """
        env = {
            "ENV": "production",
            "META_APP_SECRET": "9f2a1c7e5b8d4036a1e9c4f7b2d8e5a3",
            "E02_ACCOUNT_KEY_SECRET": "9f2a1c7e5b8d4036a1e9c4f7b2d8e5a3",
            "ADMIN_PASSWORD": "9f2a1c7e5b8d4036a1e9c4f7b2d8e5a3",
            "TELEGRAM_BOT_TOKEN": "123456:ABC-DEF",
            "TELEGRAM_WEBHOOK_SECRET": "9f2a1c7e5b8d4036a1e9c4f7b2d8e5a3",
        }
        assert secret_guard.validate_production_secrets(env) == []
        assert "VERIFY_TOKEN" not in secret_guard.REQUIRED_PRODUCTION_SECRETS
        assert "VERIFY_TOKEN" not in secret_guard.CONDITIONAL_SECRETS


# --------------------------------------------------------------------------------------
# 2. The attack, closed
# --------------------------------------------------------------------------------------


class TestTheOwnerCommandRefusesATakeover:
    @pytest.mark.parametrize(
        "text",
        [
            f"/start {PUBLISHED}",
            f"/start {PUBLISHED.lower()}",
            f"/start    {PUBLISHED}",
            f"/start {PUBLISHED} ",
        ],
    )
    def test_a_stranger_cannot_claim_ownership_with_the_published_secret(
        self, monkeypatch, registered_owner, text
    ):
        monkeypatch.delenv("VERIFY_TOKEN", raising=False)
        assert _start(STRANGER, text) is None, "a stranger must get no reply at all"
        assert registered_owner["writes"] == [], "and must not be written into the page row"
        assert os.environ.get("TELEGRAM_MANAGER_CHAT_ID") != str(STRANGER)

    def test_the_real_owner_is_not_displaced(self, monkeypatch, registered_owner):
        """The takeover also locked the legitimate owner out — both halves must be closed.

        The report formatter is stubbed: this test is about who is allowed to ask, not about
        the database it would read, and a stub keeps the assertion true on a machine with no
        schema at all.
        """
        monkeypatch.delenv("VERIFY_TOKEN", raising=False)
        monkeypatch.setattr(
            executive_bot_service, "format_executive_report", lambda **kwargs: "REPORT-SENTINEL"
        )
        assert _start(STRANGER, f"/start {PUBLISHED}") is None
        assert registered_owner["page"]["telegram_manager_chat_id"] == OWNER
        assert _start(OWNER, "/today") == "REPORT-SENTINEL", (
            "the registered owner must still receive their report"
        )

    def test_an_explicitly_configured_published_value_is_refused(
        self, monkeypatch, registered_owner
    ):
        """Setting VERIFY_TOKEN to the published literal must not resurrect the hole."""
        monkeypatch.setenv("VERIFY_TOKEN", PUBLISHED)
        assert _start(STRANGER, f"/start {PUBLISHED}") is None
        assert registered_owner["writes"] == []

    def test_an_empty_verify_token_does_not_make_a_bare_start_a_takeover(
        self, monkeypatch, registered_owner
    ):
        """The second shape of the defect: `provided == expected` was `"" == ""`."""
        monkeypatch.setenv("VERIFY_TOKEN", "")
        assert _start(STRANGER, "/start") is None
        assert registered_owner["writes"] == []

    def test_a_placeholder_secret_is_refused(self, monkeypatch, registered_owner):
        monkeypatch.setenv("VERIFY_TOKEN", "changeme")
        assert _start(STRANGER, "/start changeme") is None
        assert registered_owner["writes"] == []

    def test_a_wrong_secret_is_refused(self, monkeypatch, registered_owner):
        monkeypatch.setenv("VERIFY_TOKEN", STRONG)
        assert _start(STRANGER, f"/start not-the-configured-secret") is None
        assert registered_owner["writes"] == []

    def test_the_other_published_literal_is_refused_too(self, monkeypatch, registered_owner):
        """An operator who copied the Meta default into VERIFY_TOKEN gets no hole either."""
        monkeypatch.setenv("VERIFY_TOKEN", security.PUBLIC_VERIFY_TOKEN_PLACEHOLDER)
        assert _start(STRANGER, f"/start {security.PUBLIC_VERIFY_TOKEN_PLACEHOLDER}") is None
        assert registered_owner["writes"] == []

    def test_a_refused_secret_is_reported_without_its_value(
        self, monkeypatch, registered_owner, caplog
    ):
        """An operator who configured a placeholder needs to be told, not silently ignored.

        The log names the variable and the reason. It must not contain the value: the whole
        point is that the value is not a secret, and echoing credentials into logs is what
        F-50-2 was about.
        """
        import logging

        monkeypatch.setenv("VERIFY_TOKEN", "changeme")
        with caplog.at_level(logging.WARNING, logger="executive_bot"):
            assert _start(STRANGER, "/start changeme") is None
        messages = "\n".join(r.getMessage() for r in caplog.records)
        assert "VERIFY_TOKEN" in messages
        assert "changeme" not in messages

    def test_no_secret_value_reaches_the_reply(self, monkeypatch, registered_owner):
        """The greeting is sent back into a Telegram chat; it must not carry the secret."""
        monkeypatch.setenv("VERIFY_TOKEN", STRONG)
        reply = _start(OWNER, f"/start {STRONG}") or ""
        assert STRONG not in reply


# --------------------------------------------------------------------------------------
# 3. What must keep working
# --------------------------------------------------------------------------------------


class TestTheLegitimateFlowsStillWork:
    def test_the_registered_owner_is_unaffected(self, monkeypatch, registered_owner):
        monkeypatch.delenv("VERIFY_TOKEN", raising=False)
        reply = _start(OWNER, "/start")
        assert reply and "Сайн байна уу" in reply
        assert registered_owner["page"]["telegram_manager_chat_id"] == OWNER

    def test_a_configured_secret_still_re_registers_the_owner(
        self, monkeypatch, registered_owner
    ):
        """The documented recovery path: a lost phone, a new chat id, a real secret."""
        monkeypatch.setenv("VERIFY_TOKEN", STRONG)
        reply = _start(STRANGER, f"/start {STRONG}")
        assert reply, "a holder of the configured secret may still re-register"
        assert registered_owner["writes"], "and the page row must record the new recipient"
        assert str(registered_owner["writes"][-1].get("manager_chat_id")) == str(STRANGER)
        assert os.environ.get("TELEGRAM_MANAGER_CHAT_ID") == str(STRANGER)

    def test_a_first_start_still_claims_an_unregistered_slot(self, monkeypatch, unregistered):
        """Onboarding is unchanged: with nobody registered, `/start` claims the slot.

        Deliberately preserved. It is the documented first-run flow, it cannot displace
        anybody, and closing it would break every new installation — the defect was that a
        *published string* could displace a registered owner, not that a first claim exists.
        """
        monkeypatch.delenv("VERIFY_TOKEN", raising=False)
        reply = _start(STRANGER, "/start")
        assert reply and "Сайн байна уу" in reply
        assert unregistered["writes"]
        assert str(unregistered["writes"][-1].get("manager_chat_id")) == str(STRANGER)

    def test_the_environment_fallback_still_names_the_owner(self, monkeypatch):
        """No page row, but TELEGRAM_MANAGER_CHAT_ID set: same protection applies."""
        writes = []
        monkeypatch.setattr(database, "get_page", lambda _page_id: {})
        monkeypatch.setattr(
            database,
            "update_page_telegram_settings",
            lambda **kwargs: writes.append(kwargs) or None,
        )
        monkeypatch.setenv("TELEGRAM_MANAGER_CHAT_ID", OWNER)
        monkeypatch.delenv("VERIFY_TOKEN", raising=False)
        assert _start(STRANGER, f"/start {PUBLISHED}") is None
        assert os.environ.get("TELEGRAM_MANAGER_CHAT_ID") == OWNER
        assert _start(OWNER, "/help"), "the owner named by the environment still works"

    def test_owner_only_commands_stay_owner_only(self, monkeypatch, registered_owner):
        monkeypatch.delenv("VERIFY_TOKEN", raising=False)
        for command in ("/today", "/report", "/qpay", "/cargo"):
            assert _start(STRANGER, command) is None, f"{command} answered to a stranger"


# --------------------------------------------------------------------------------------
# 4. The HTTP boundary: a forged update must not move the owner
# --------------------------------------------------------------------------------------


class TestTheWebhookCannotBeUsedToTakeOver:
    """End to end through `POST /telegram/webhook`.

    In development with no `TELEGRAM_WEBHOOK_SECRET`, the webhook's own fail-closed check
    accepts a request (that permissiveness is documented and deliberate), so this is the
    shortest path from the internet to `handle_owner_command`. Whatever the transport check
    does, a forged update must not be able to move the report recipient.
    """

    @pytest.fixture()
    def client(self, monkeypatch, registered_owner):
        import main
        from starlette.testclient import TestClient

        monkeypatch.setenv("ENV", "development")
        monkeypatch.setenv("WEBHOOK_FAIL_CLOSED", "0")
        monkeypatch.delenv("TELEGRAM_WEBHOOK_SECRET", raising=False)
        monkeypatch.delenv("VERIFY_TOKEN", raising=False)

        sent = []

        async def _no_send(*args, **kwargs):
            sent.append((args, kwargs))

        monkeypatch.setattr(main, "send_telegram_message", _no_send)
        # The handler returns None, so the route falls through to the AI chat path; that is
        # not what this test is about and it must not reach a provider or a database.
        import agent as agent_module

        monkeypatch.setattr(
            agent_module, "process_message", lambda **kwargs: {"reply": "", "registered": False}
        )
        with TestClient(main.app, raise_server_exceptions=False) as test_client:
            test_client.sent = sent
            yield test_client

    def _update(self, chat_id, text):
        return {"message": {"chat": {"id": int(chat_id)}, "text": text}}

    def test_a_forged_update_carrying_the_published_secret_changes_nothing(
        self, client, registered_owner
    ):
        response = client.post("/telegram/webhook", json=self._update(STRANGER, f"/start {PUBLISHED}"))
        assert response.status_code == 200, response.text
        assert response.json().get("mode") != "owner_command"
        assert registered_owner["writes"] == []
        assert registered_owner["page"]["telegram_manager_chat_id"] == OWNER
        assert os.environ.get("TELEGRAM_MANAGER_CHAT_ID") != str(STRANGER)

    def test_a_forged_bare_start_changes_nothing(self, client, registered_owner):
        response = client.post("/telegram/webhook", json=self._update(STRANGER, "/start"))
        assert response.status_code == 200, response.text
        assert registered_owner["writes"] == []
        assert registered_owner["page"]["telegram_manager_chat_id"] == OWNER


# --------------------------------------------------------------------------------------
# 5. Source contract
# --------------------------------------------------------------------------------------


class TestTheSourceContract:
    def _read(self, *names):
        return "\n".join(
            io.open(os.path.join(REPO_ROOT, n), encoding="utf-8").read() for n in names
        )

    def test_the_handler_has_no_published_fallback(self):
        """The exact expression that made the literal a credential must not come back.

        Comment lines are excluded first, on purpose: the fix's own comment quotes the old
        expression while explaining it, so a whole-file substring assertion would fail on the
        documentation of the fix. What must be true is that no *executable* line names it.
        """
        body = self._read("executive_bot_service.py")
        code = "\n".join(l for l in body.splitlines() if not l.strip().startswith("#"))
        assert "GEREGE_VERIFY_2026" not in code, (
            "the published literal is back in executable code"
        )
        assert 'os.getenv("VERIFY_TOKEN", "GEREGE_VERIFY_2026")' not in code
        offenders = [
            line.strip()
            for line in code.splitlines()
            if "GEREGE_VERIFY_2026" in line and "PUBLIC_OWNER_COMMAND_SECRET" not in line
        ]
        assert not offenders, f"the published literal is back in code: {offenders}"
        # A docstring may quote the old expression too (this fix's does), so the "named once"
        # property is asserted on the constant's definition, in the test below, not by
        # counting occurrences of the string.

    def test_the_secret_is_compared_in_constant_time(self):
        """`==` on a secret short-circuits on the first differing byte.

        Only executable lines count: the fix's own comment quotes the old expression while
        explaining it, which is exactly the shape that made a naive string assertion misfire
        in Phase 43 (see `test_main_has_no_published_fallback` in test_e45_final_hardening.py).
        """
        body = "\n".join(
            line
            for line in self._read("executive_bot_service.py").splitlines()
            if not line.strip().startswith("#")
        )
        assert "hmac.compare_digest" in body, (
            "the owner secret is compared with `==`, which short-circuits on the first "
            "differing byte"
        )
        assert not re.search(r"provided_secret\s*==\s*expected_secret", body)
        assert not re.search(r"provided_secret\s*!=\s*expected_secret", body)

    def test_the_decision_goes_through_the_point_of_use_guard(self):
        body = self._read("executive_bot_service.py")
        assert "owner_command_secret_is_usable" in body

    def test_the_literal_lives_in_one_place(self):
        """Named once, in `core/security.py`, next to the other published value."""
        security_body = self._read("core/security.py")
        assert security_body.count('PUBLIC_OWNER_COMMAND_SECRET = "GEREGE_VERIFY_2026"') == 1


# --------------------------------------------------------------------------------------
# 6. How this was found, pinned so the next one is found the same way
# --------------------------------------------------------------------------------------


class TestEveryEnvironmentVariableTheCodeReadsIsDocumented:
    """F-51-2. `VERIFY_TOKEN` was invisible because nothing listed what the code reads.

    The mirror image of F-40-B, which pinned "the template must not name a variable no code
    reads". This pins the other direction: a variable the code reads that no template
    mentions is a variable nobody knows to configure — which is exactly how a published
    default became a production credential.

    Deliberately a contract with an exemption list rather than a demand that all ~80 names
    appear: pool tunables, CLI-only flags and compose-internal plumbing have no business in
    an operator's `.env`, and each exemption states why. A *new* name forces a decision.
    """

    #: name -> why it is not in `.env.example`. Every entry is a reason, not a shrug.
    EXEMPT = {
        # --- compose/deploy plumbing: set by the compose file, never by an operator's .env
        "GEREGE_APP_PASSWORD": "internal: docker-compose passes POSTGRES_APP_PASSWORD to the provisioning job under this name",
        "GEREGE_OWNER_PASSWORD": "internal: docker-compose passes POSTGRES_OWNER_PASSWORD to the provisioning job under this name",
        "GEREGE_RUNTIME_ROLE": "internal: provisioning job argument, defaults to core.db_privileges.RUNTIME_ROLE",
        "POSTGRES_ADMIN_PASSWORD": "bootstrap superuser, consumed by the postgres image in docker-compose only",
        "POSTGRES_ADMIN_USER": "bootstrap superuser, consumed by the postgres image in docker-compose only",
        "POSTGRES_DB": "postgres image bootstrap; the application reads DATABASE_URL",
        "POSTGRES_HOST": "postgres image/compose networking; the application reads DATABASE_URL",
        "POSTGRES_PASSWORD": "postgres image bootstrap; the application reads DATABASE_URL",
        "POSTGRES_PORT": "compose port mapping; the application reads DATABASE_URL",
        "POSTGRES_URL": "CLI convenience for scripts/migrate_sqlite_to_postgres.py (--postgres-url)",
        "POSTGRES_USER": "postgres image bootstrap; the application reads DATABASE_URL",
        # --- CLI/tool arguments with a flag equivalent
        "WORKER_ID": "worker identity, derived from the hostname when unset; a CLI concern",
        # --- connection-pool and timeout tunables, sized by DB_PROCESS_ROLE
        "DB_CONNECT_TIMEOUT": "pool tunable, documented in docs/ with DB_PROCESS_ROLE",
        "DB_IDLE_IN_TRANSACTION_TIMEOUT_MS": "session bound applied by core.db_engine",
        "DB_LOCK_TIMEOUT_MS": "session bound applied by core.db_engine",
        "DB_MAX_OVERFLOW": "pool tunable derived from DB_PROCESS_ROLE",
        "DB_POOL_RECYCLE": "pool tunable derived from DB_PROCESS_ROLE",
        "DB_POOL_SIZE": "pool tunable derived from DB_PROCESS_ROLE",
        "DB_POOL_TIMEOUT": "pool tunable derived from DB_PROCESS_ROLE",
        "DB_STATEMENT_TIMEOUT_MS": "session bound applied by core.db_engine, not an operator setting",
        "DB_STRICT_CONNECTION_BUDGET": "adversarial switch used by the budget test suite",
        "PG_MAX_CONNECTIONS": "server ceiling read for budget arithmetic, not a setting to change",
        "PG_SUPERUSER_RESERVED": "server reserve read for budget arithmetic, not a setting to change",
        # --- adversarial/test switches that must not be discoverable as operator settings
        "REQUIRE_LEAST_PRIVILEGE": "adversarial switch: forces the E-05 guard on outside production",
        # --- backup alert tuning with safe defaults
        "BACKUP_ALERT_BACKOFF_S": "alert retry tuning, defaults in core.backup_automation",
        "BACKUP_ALERT_RETRIES": "alert retry tuning, defaults in core.backup_automation",
        "BACKUP_OFFSITE_MAX_PAGES": "offsite pagination tuning, defaults in core.backup_offsite",
        # --- not a real variable
        "SOMETHING": "appears only inside a comment in scripts/check_pytest_log.py",
    }

    #: Names that must be documented, whatever the exemption list says. Each one changed
    #: behaviour an operator has to know about, or was the subject of a finding.
    MUST_BE_DOCUMENTED = (
        "VERIFY_TOKEN",               # F-51-5: the owner-command secret
        "ALLOW_ENV_FILE_WRITE",       # F-51-3: gates writing credentials into .env
        "DISABLE_DEFAULT_ADMIN_PASSWORD",
        "HOST",                       # without it the app binds 127.0.0.1 only
        "TELEGRAM_MANAGER_CHAT_ID",   # where the executive report is sent
        "BACKUP_DIR",
        "AI_PROVIDER",
        "AI_FALLBACK_ENABLED",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_MODEL",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_MODEL",
        "QPAY_BASE_URL",
        "DB_PROCESS_ROLE",
        "UVICORN_WORKERS",
        "RELOAD",
    )

    GLOBS = ("*.py", "core/*.py", "scripts/*.py", "routers/*.py")

    def _names_read_by_code(self):
        import glob

        pattern = re.compile(r'os\.(?:getenv|environ\.get)\(\s*"([A-Z0-9_]+)"')
        names = set()
        for relative in self.GLOBS:
            for path in glob.glob(os.path.join(REPO_ROOT, relative)):
                try:
                    names |= set(
                        pattern.findall(io.open(path, encoding="utf-8").read())
                    )
                except (OSError, UnicodeDecodeError):  # pragma: no cover
                    continue
        return names

    def _template(self):
        return io.open(os.path.join(REPO_ROOT, ".env.example"), encoding="utf-8").read()

    def test_no_undocumented_variable_is_left(self):
        template = self._template()
        undocumented = sorted(
            name
            for name in self._names_read_by_code()
            if name not in template and name not in self.EXEMPT
        )
        assert not undocumented, (
            f".env.example never mentions variable(s) the code reads: {undocumented}. "
            "An operator cannot configure what they have never heard of — that is how "
            "VERIFY_TOKEN kept its published default (F-51-5). Document the variable, or "
            "add it to EXEMPT with a reason."
        )

    def test_the_exemption_list_holds_nothing_that_is_documented(self):
        """An exemption that is also documented is stale weight and hides drift."""
        template = self._template()
        stale = sorted(n for n in self.EXEMPT if n in template)
        assert not stale, f"exempt but documented, remove from EXEMPT: {stale}"

    def test_every_exempt_name_is_still_read_by_the_code(self):
        """The mirror of F-40-B: an exemption for a name nothing reads is a dead entry."""
        read = self._names_read_by_code()
        dead = sorted(n for n in self.EXEMPT if n not in read)
        assert not dead, f"exempt but no longer read by any code: {dead}"

    @pytest.mark.parametrize("name", MUST_BE_DOCUMENTED)
    def test_the_operator_relevant_names_are_present(self, name):
        assert name in self._template(), f"{name} must be documented in .env.example"

    def test_every_assigned_key_is_named_in_a_comment_above_it(self):
        """F-51-2. Measured before the fix: 27 of the 40 assigned keys appeared in no
        comment anywhere in the file — a reader who grepped the key name found the
        assignment and nothing else. A template is a contract; an unnamed key is one an
        operator has to read the source to understand.
        """
        lines = self._template().split("\n")
        assigned = []
        for index, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            assigned.append((index, stripped.split("=", 1)[0].strip()))

        unnamed = []
        for index, name in assigned:
            above = "\n".join(
                l for l in lines[:index] if l.strip().startswith("#")
            )
            if name not in above:
                unnamed.append(name)
        assert not unnamed, (
            f"assigned in .env.example but never named in a comment above it: {unnamed}"
        )
