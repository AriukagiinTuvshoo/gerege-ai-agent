"""Phase 49 — a published placeholder that worked as a webhook credential, and the upsert
that kept installing it.

Phase 48A left one observation open (O2): `pages.verify_token` still defaults to a string
printed in this repository. It was recorded as "schema-defined, and production already
refuses it at the Meta handshake". Following it one level further showed that was only half
true — there is a *second* consumer of that column, and it was not guarded at all.

F-49-1  `core.security.verify_manychat_webhook_secret` accepted any non-empty
        `pages.verify_token` as the expected secret for `POST /api/manychat`, an endpoint
        that runs `agent.process_message` and therefore writes registrations, messages and
        leads. Measured on a running instance (development, `WEBHOOK_FAIL_CLOSED=0`, no
        `MANYCHAT_WEBHOOK_SECRET` configured):

            X-ManyChat-Secret: agent_verify_secret_token_123  -> 200
            X-ManyChat-Secret: definitely-not-the-token       -> 403
            (no header)                                       -> 403

        Production was not protected either: the fail-closed branch only ran when the
        expected value was **empty**, and a placeholder default is not empty, so the
        comparison against the published string simply succeeded.

F-49-4  `POST /api/pages` is an upsert, but it read every column with a literal default, so
        a payload that merely omitted a column *reset* it. The dashboard's "Тохиргоо
        хадгалах" button posts `{page_id, name, page_access_token, knowledge_json}`.
        Measured on a running instance, one click:

            verify_token        'real-49-verify-token-do-not-lose' -> 'agent_verify_secret_token_123'
            monthly_token_limit 5000                               -> 100000

        i.e. it replaced the page's webhook secret with the published one — which F-49-1
        then accepted as a credential — and multiplied the tenant's token quota twenty
        times over. `category` and `is_active` were reset the same way; the latter silently
        re-enabled a tenant somebody had disabled.

The two fixes are deliberately the same shape as F-44-B (Phase 45): a published or
placeholder value is not a secret, and in production/`STRICT_SECURITY`/fail-closed it is
refused rather than compared. Development keeps its previous behaviour, because the suite
and local runs depend on it and nothing is exposed there. "Omitted" now means "unchanged"
on the upsert, which is what an upsert that a UI calls has to mean.

Nothing here prints a secret value: the tests assert on decisions (`True`/`False`), on the
stored row, and on the *absence* of a value from logs.
"""

from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

import database
from core import security

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: The published default. Taken from the one place that owns the rule, never retyped.
PUBLISHED = security.PUBLIC_VERIFY_TOKEN_PLACEHOLDER

#: A generated value, i.e. what an operator is told to produce. Not a secret.
REAL_TOKEN = "e49-generated-page-verify-token-7c1f2a"

PAGE_REAL = "p49_real_token"
PAGE_PUBLISHED = "p49_published_token"
PAGE_UPSERT = "p49_upsert_probe"
ABSENT_PAGE = "p49_no_such_page"


@pytest.fixture(autouse=True, scope="module")
def _schema_ready():
    """Bring the schema up before any fixture writes a row.

    `import main` calls `database.init_db()` at module level, so suites that build a
    TestClient first never notice; these fixtures write pages *before* main is imported.
    Idempotent — a second call reports "already at head" and changes nothing.
    """
    database.init_db()
    yield


def _request(headers=None, method: str = "POST", path: str = "/api/manychat"):
    """A Starlette request carrying only headers, which is all the check reads."""
    from starlette.requests import Request

    raw = [
        (str(k).lower().encode("latin-1"), str(v).encode("latin-1"))
        for k, v in (headers or {}).items()
    ]
    return Request(
        {"type": "http", "method": method, "path": path, "headers": raw, "query_string": b""}
    )


@pytest.fixture()
def page_with_real_token():
    database.save_page(
        page_id=PAGE_REAL, name="P49 Real Token", category="general", verify_token=REAL_TOKEN
    )
    try:
        yield PAGE_REAL
    finally:
        database.delete_page(PAGE_REAL)


@pytest.fixture()
def page_with_published_token():
    database.save_page(
        page_id=PAGE_PUBLISHED,
        name="P49 Published Token",
        category="general",
        verify_token=PUBLISHED,
    )
    try:
        yield PAGE_PUBLISHED
    finally:
        database.delete_page(PAGE_PUBLISHED)


@pytest.fixture()
def admin_client(monkeypatch):
    """An authenticated admin session.

    `monkeypatch.setenv` rather than `os.environ.setdefault`: the Phase 36 suite documents
    what a leaked ADMIN_PASSWORD did to five unrelated suites.
    """
    import main

    password = "e49-admin-pw"
    monkeypatch.setenv("ADMIN_PASSWORD", password)
    with TestClient(main.app, raise_server_exceptions=False) as client:
        client.cookies.clear()
        response = client.post("/api/auth/login", json={"password": password})
        assert response.status_code == 200, f"admin login failed: {response.status_code} {response.text[:200]}"
        yield client
        client.cookies.clear()


def _development(monkeypatch):
    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("STRICT_SECURITY", raising=False)
    monkeypatch.delenv("WEBHOOK_FAIL_CLOSED", raising=False)


# ===========================================================================
# The predicate itself
# ===========================================================================


class TestUsableWebhookSecret:
    def test_empty_is_never_a_secret(self):
        assert security.usable_webhook_secret("") == ""
        assert security.usable_webhook_secret(None) == ""
        assert security.usable_webhook_secret("   \t ") == ""

    def test_a_generated_value_is_returned_unchanged(self):
        assert security.usable_webhook_secret(REAL_TOKEN) == REAL_TOKEN

    def test_production_refuses_the_published_placeholder(self, monkeypatch):
        """The exact value that used to authenticate a webhook in production."""
        monkeypatch.setenv("ENV", "production")
        assert security.usable_webhook_secret(PUBLISHED) == ""

    def test_strict_security_refuses_it_too(self, monkeypatch):
        """Case-insensitive, because that is what an operator pastes."""
        monkeypatch.setenv("STRICT_SECURITY", "1")
        assert security.usable_webhook_secret(PUBLISHED.upper()) == ""

    @pytest.mark.parametrize(
        "placeholder",
        ["changeme", "change_me", "your-token-here", "<generate: openssl rand -hex 16>", "TODO"],
    )
    def test_production_refuses_template_leftovers(self, monkeypatch, placeholder):
        monkeypatch.setenv("ENV", "production")
        assert security.usable_webhook_secret(placeholder) == ""

    def test_production_accepts_a_generated_value(self, monkeypatch):
        """Not "refuse everything": the fix must leave a working configuration possible."""
        monkeypatch.setenv("ENV", "production")
        assert security.usable_webhook_secret(REAL_TOKEN) == REAL_TOKEN

    def test_development_keeps_its_previous_behaviour(self, monkeypatch):
        """Stated on purpose: local runs and this suite rely on the dev posture."""
        _development(monkeypatch)
        assert security.usable_webhook_secret(PUBLISHED) == PUBLISHED

    def test_it_never_hands_back_a_value_it_refused(self, monkeypatch):
        monkeypatch.setenv("ENV", "production")
        assert PUBLISHED not in security.usable_webhook_secret(PUBLISHED)


# ===========================================================================
# F-49-1 — the ManyChat webhook
# ===========================================================================


class TestManyChatWebhookSecret:
    def test_production_refuses_the_published_page_token_even_when_the_header_matches(
        self, monkeypatch, page_with_published_token
    ):
        """The vulnerability: a matching header and a public expected value."""
        monkeypatch.setenv("ENV", "production")
        monkeypatch.delenv("MANYCHAT_WEBHOOK_SECRET", raising=False)
        request = _request({"X-ManyChat-Secret": PUBLISHED})
        assert security.verify_manychat_webhook_secret(request, page_id=page_with_published_token) is False

    def test_production_accepts_a_generated_page_token(self, monkeypatch, page_with_real_token):
        monkeypatch.setenv("ENV", "production")
        monkeypatch.delenv("MANYCHAT_WEBHOOK_SECRET", raising=False)
        request = _request({"X-ManyChat-Secret": REAL_TOKEN})
        assert security.verify_manychat_webhook_secret(request, page_id=page_with_real_token) is True

    def test_production_refuses_a_wrong_header(self, monkeypatch, page_with_real_token):
        monkeypatch.setenv("ENV", "production")
        monkeypatch.delenv("MANYCHAT_WEBHOOK_SECRET", raising=False)
        request = _request({"X-ManyChat-Secret": "not-the-token"})
        assert security.verify_manychat_webhook_secret(request, page_id=page_with_real_token) is False

    def test_production_refuses_a_published_env_secret(
        self, monkeypatch, page_with_published_token
    ):
        """Both sources refused: the environment AND the page row."""
        monkeypatch.setenv("ENV", "production")
        monkeypatch.setenv("MANYCHAT_WEBHOOK_SECRET", PUBLISHED)
        request = _request({"X-ManyChat-Secret": PUBLISHED})
        assert security.verify_manychat_webhook_secret(request, page_id=page_with_published_token) is False

    def test_a_generated_env_secret_wins_over_the_page_row(self, monkeypatch, page_with_real_token):
        """Precedence is unchanged: the deployment-wide secret is the one that counts."""
        monkeypatch.setenv("ENV", "production")
        monkeypatch.setenv("MANYCHAT_WEBHOOK_SECRET", "e49-deployment-wide-secret-4b7d")
        assert security.verify_manychat_webhook_secret(
            _request({"X-ManyChat-Secret": "e49-deployment-wide-secret-4b7d"}), page_id=page_with_real_token
        ) is True
        assert security.verify_manychat_webhook_secret(
            _request({"X-ManyChat-Secret": REAL_TOKEN}), page_id=page_with_real_token
        ) is False

    def test_fail_closed_with_nothing_configured(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_FAIL_CLOSED", "1")
        monkeypatch.delenv("MANYCHAT_WEBHOOK_SECRET", raising=False)
        request = _request({"X-ManyChat-Secret": "anything"})
        assert security.verify_manychat_webhook_secret(request, page_id=ABSENT_PAGE) is False

    def test_development_without_a_secret_is_permissive(self, monkeypatch):
        """The documented dev posture, identical to `verify_telegram_webhook_secret`."""
        _development(monkeypatch)
        monkeypatch.delenv("MANYCHAT_WEBHOOK_SECRET", raising=False)
        assert security.verify_manychat_webhook_secret(_request({}), page_id=ABSENT_PAGE) is True

    def test_development_still_accepts_the_published_page_token(
        self, monkeypatch, page_with_published_token
    ):
        """Unchanged on purpose — the fix is scoped to production/fail-closed."""
        _development(monkeypatch)
        monkeypatch.delenv("MANYCHAT_WEBHOOK_SECRET", raising=False)
        request = _request({"X-ManyChat-Secret": PUBLISHED})
        assert security.verify_manychat_webhook_secret(request, page_id=page_with_published_token) is True

    def test_a_missing_header_never_matches_a_configured_secret(self, monkeypatch, page_with_real_token):
        monkeypatch.setenv("ENV", "production")
        monkeypatch.delenv("MANYCHAT_WEBHOOK_SECRET", raising=False)
        assert security.verify_manychat_webhook_secret(_request({}), page_id=page_with_real_token) is False

    def test_the_bearer_form_is_still_accepted(self, monkeypatch, page_with_real_token):
        monkeypatch.setenv("ENV", "production")
        monkeypatch.delenv("MANYCHAT_WEBHOOK_SECRET", raising=False)
        request = _request({"Authorization": f"Bearer {REAL_TOKEN}"})
        assert security.verify_manychat_webhook_secret(request, page_id=page_with_real_token) is True

    def test_the_refusal_names_the_cause_without_naming_the_value(
        self, monkeypatch, page_with_published_token
    ):
        """An operator has to be able to tell 'unset' from 'set to a published value'.

        Asserted through a stub logger rather than `caplog` on purpose. Measured while
        writing this file: with a schema that had to be created inside the same pytest
        session, `caplog.text` came back **empty** for this record while the same assertion
        passed against an already-migrated database — i.e. capture depended on whether the
        module-scoped `init_db()` had run migrations, not on the code under test. An
        `assert "secret" not in caplog.text` that captures nothing is a free pass, so this
        test does not depend on the global logging configuration at all. The stub records
        what the module actually emitted; the assertions are unchanged.

        The mechanism was identified in Phase 50 and is fixed at its source (F-50-4):
        `migrations/env.py` called `logging.config.fileConfig(alembic.ini)`, which defaults to
        `disable_existing_loggers=True`, so any migration run disabled every logger created
        before it — `core.security` among them. On an already-migrated database
        `core.schema_manager.ensure_schema()` returns before invoking Alembic, which is
        exactly why the warm-database run captured and the cold one did not. See
        tests/test_e50_migration_logging_truth.py. This test keeps the stub logger: being
        independent of global logging state is a property worth keeping even now.
        """
        emitted = []

        class _RecordingLogger:
            def error(self, message, *args, **kwargs):
                emitted.append(str(message))

            def warning(self, message, *args, **kwargs):
                emitted.append(str(message))

        monkeypatch.setattr(security, "logger", _RecordingLogger())
        monkeypatch.setenv("ENV", "production")
        monkeypatch.delenv("MANYCHAT_WEBHOOK_SECRET", raising=False)

        refused = security.verify_manychat_webhook_secret(
            _request({"X-ManyChat-Secret": PUBLISHED}), page_id=page_with_published_token
        )
        assert refused is False

        text = "\n".join(emitted)
        assert text, "the refusal was silent: nothing told the operator what to fix"
        assert "MANYCHAT_WEBHOOK_SECRET" in text
        assert "placeholder" in text
        assert PUBLISHED not in text, "the log must never carry the value it refused"

    def test_an_unset_secret_is_diagnosed_differently_from_a_published_one(self, monkeypatch):
        """The two operator errors must not collapse into one message.

        Precedent for caring: `main.py`'s startup guards were deliberately ordered so a broad
        secret sweep could not mask the specific "REDIS_URL is required" diagnosis.
        """
        emitted = []

        class _RecordingLogger:
            def error(self, message, *args, **kwargs):
                emitted.append(str(message))

        monkeypatch.setattr(security, "logger", _RecordingLogger())
        monkeypatch.setenv("ENV", "production")
        monkeypatch.delenv("MANYCHAT_WEBHOOK_SECRET", raising=False)

        assert security.verify_manychat_webhook_secret(_request({}), page_id=ABSENT_PAGE) is False
        unset_text = "\n".join(emitted)
        assert "is not configured" in unset_text
        assert "placeholder" not in unset_text

    def test_a_missing_page_row_does_not_raise(self, monkeypatch):
        monkeypatch.setenv("ENV", "production")
        monkeypatch.delenv("MANYCHAT_WEBHOOK_SECRET", raising=False)
        assert security.verify_manychat_webhook_secret(_request({}), page_id=None) is False


class TestManyChatEndpoint:
    """End-to-end, through the route that actually writes into the CRM."""

    def test_the_published_token_no_longer_reaches_the_agent(self, page_with_real_token):
        import main

        with TestClient(main.app, raise_server_exceptions=False) as client:
            refused = client.post(
                "/api/manychat",
                json={"page_id": page_with_real_token, "user_id": "p49-attacker", "message": ""},
                headers={"X-ManyChat-Secret": PUBLISHED},
            )
            accepted = client.post(
                "/api/manychat",
                json={"page_id": page_with_real_token, "user_id": "p49-operator", "message": ""},
                headers={"X-ManyChat-Secret": REAL_TOKEN},
            )
        assert refused.status_code == 403, refused.text
        assert accepted.status_code == 200, accepted.text


# ===========================================================================
# F-49-4 — the upsert
# ===========================================================================


class TestPageUpsertPreservesWhatThePayloadOmitted:
    @pytest.fixture()
    def provisioned_page(self):
        database.save_page(
            page_id=PAGE_UPSERT,
            name="P49 Probe",
            category="cargo",
            page_access_token="EAAQ-p49-page-token",
            verify_token=REAL_TOKEN,
            knowledge_json=json.dumps({"greeting": "P49 knowledge that must survive"}),
            monthly_token_limit=5000,
        )
        try:
            yield PAGE_UPSERT
        finally:
            database.delete_page(PAGE_UPSERT)

    def test_the_dashboard_request_no_longer_resets_the_webhook_secret(
        self, admin_client, provisioned_page
    ):
        """Exactly the body `dashboard.saveCurrentPageSettings()` sends."""
        response = admin_client.post(
            "/api/pages",
            json={
                "page_id": provisioned_page,
                "name": "P49 Probe",
                "page_access_token": "EAAQ-p49-page-token",
                "knowledge_json": json.dumps({"greeting": "P49 knowledge that must survive"}),
            },
        )
        assert response.status_code == 200, response.text

        row = database.get_page(provisioned_page)
        assert row["verify_token"] == REAL_TOKEN, (
            "the page's webhook secret was replaced by the published default again"
        )
        assert row["monthly_token_limit"] == 5000, "the tenant's quota was reset"
        assert row["category"] == "cargo", "the category was reset to 'general'"
        assert "must survive" in (row["knowledge_json"] or "")

    def test_an_explicit_value_still_wins(self, admin_client, provisioned_page):
        """"Omitted means unchanged" must not become "the payload is ignored"."""
        response = admin_client.post(
            "/api/pages",
            json={
                "page_id": provisioned_page,
                "name": "P49 Renamed",
                "verify_token": "e49-rotated-token-8d2b",
                "monthly_token_limit": 7777,
                "category": "salon",
            },
        )
        assert response.status_code == 200, response.text
        row = database.get_page(provisioned_page)
        assert row["name"] == "P49 Renamed"
        assert row["verify_token"] == "e49-rotated-token-8d2b"
        assert row["monthly_token_limit"] == 7777
        assert row["category"] == "salon"

    def test_a_disabled_tenant_stays_disabled(self, admin_client, provisioned_page):
        """`save_page`'s `is_active` default is 1: a settings save used to re-enable a tenant."""
        database.save_page(
            page_id=provisioned_page,
            name="P49 Probe",
            category="cargo",
            verify_token=REAL_TOKEN,
            is_active=0,
        )
        assert database.get_page(provisioned_page)["is_active"] == 0

        response = admin_client.post(
            "/api/pages", json={"page_id": provisioned_page, "name": "P49 Probe"}
        )
        assert response.status_code == 200, response.text
        assert database.get_page(provisioned_page)["is_active"] == 0, (
            "an unrelated settings save re-enabled a tenant that had been disabled"
        )

    def test_an_explicit_disable_is_honoured_and_audited(self, admin_client, provisioned_page):
        response = admin_client.post(
            "/api/pages", json={"page_id": provisioned_page, "name": "P49 Probe", "is_active": False}
        )
        assert response.status_code == 200, response.text
        assert database.get_page(provisioned_page)["is_active"] == 0

        details = _latest_audit_details(provisioned_page)
        assert details is not None, "the upsert wrote no audit row"
        assert details.get("is_active") is False, (
            "the audit row asserted a state the request never wrote (it was a hardcoded True)"
        )
        # The audit row still carries no secret.
        assert REAL_TOKEN not in json.dumps(details)

    def test_a_masked_token_echoed_back_is_not_stored(self, admin_client, provisioned_page):
        """Clients that render masked values must not be able to write the mask."""
        response = admin_client.post(
            "/api/pages",
            json={"page_id": provisioned_page, "name": "P49 Probe", "verify_token": "ab••••yz"},
        )
        assert response.status_code == 200, response.text
        row = database.get_page(provisioned_page)
        assert row["verify_token"] == REAL_TOKEN
        assert "•" not in (row["verify_token"] or "")

    def test_validation_still_comes_first(self, admin_client):
        """The 400 path must not be reached by way of a database read."""
        response = admin_client.post("/api/pages", json={"page_id": "", "name": ""})
        assert response.status_code == 400
        assert "Page ID" in response.text


def _latest_audit_details(page_id: str):
    conn = database.get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT details_json FROM audit_logs "
            "WHERE action = 'page.upsert' AND page_id = ? ORDER BY id DESC",
            (page_id,),
        )
        rows = cursor.fetchall()
    finally:
        conn.close()
    if not rows:
        return None
    raw = rows[0][0] if not isinstance(rows[0], dict) else rows[0].get("details_json")
    try:
        return json.loads(raw or "{}")
    except Exception:
        return None


# ===========================================================================
# The client-side flag that makes the dashboard honest (F-49-2)
# ===========================================================================


class TestMaskedPagePayloadSaysWhetherTheTokenIsPublic:
    def test_the_flag_is_true_for_the_published_default(self, page_with_published_token):
        masked = database.get_page(page_with_published_token, mask_secrets=True)
        assert masked["verify_token_is_placeholder"] is True

    def test_the_flag_is_false_for_a_generated_token(self, page_with_real_token):
        masked = database.get_page(page_with_real_token, mask_secrets=True)
        assert masked["verify_token_is_placeholder"] is False

    def test_the_flag_is_true_when_nothing_is_configured(self, monkeypatch):
        page_id = "p49_no_token"
        database.save_page(page_id=page_id, name="P49 No Token", category="general", verify_token="")
        try:
            masked = database.get_page(page_id, mask_secrets=True)
            assert masked["verify_token_is_placeholder"] is True
        finally:
            database.delete_page(page_id)

    def test_the_flag_is_environment_independent(self, monkeypatch, page_with_published_token):
        """A published value is published in development too, so the answer must not move."""
        _development(monkeypatch)
        assert database.get_page(page_with_published_token, mask_secrets=True)[
            "verify_token_is_placeholder"
        ] is True
        monkeypatch.setenv("ENV", "production")
        assert database.get_page(page_with_published_token, mask_secrets=True)[
            "verify_token_is_placeholder"
        ] is True

    def test_the_unmasked_read_is_unchanged(self, page_with_real_token):
        """Server-side callers need the value; the flag belongs to the masked projection."""
        row = database.get_page(page_with_real_token)
        assert row["verify_token"] == REAL_TOKEN
        assert "verify_token_is_placeholder" not in row

    def test_the_api_carries_the_flag_to_the_dashboard(self, admin_client, page_with_real_token):
        response = admin_client.get("/api/pages")
        assert response.status_code == 200, response.text
        rows = {row["page_id"]: row for row in response.json()["data"]}
        assert page_with_real_token in rows
        assert rows[page_with_real_token]["verify_token_is_placeholder"] is False
