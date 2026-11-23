"""
Phase 33 — audit findings closure.

Every test here corresponds to a finding raised in Phase 32 and closed (or proven) in
Phase 33. They are written to fail against HEAD `5758fbd`:

    E-33-1  A Telegram non-200 response (403 "bot was blocked", 429, 500) returned
            `True` from `retention_service.dispatch_channel_message`, so a broadcast
            counted an undelivered message as delivered and persisted a "bot" row the
            customer never received. Same class for the retention auto-checks, which
            then recorded `sent_followups` for a message that was never sent.

    E-33-2  `DATABASE_URL=sqlite:///...` was honoured by `get_database_url()` /
            Alembic but **ignored** by `get_db_connection()`, which read only `DB_PATH`
            and fell back to the repository `leads.db`. A caller that set a SQLite URL
            to isolate itself kept writing to the repository database while migrations
            targeted the URL's file: two databases, silent divergence.

Design notes
------------
* External providers are always mocked. No test here performs network I/O, and the
  mocks are installed at the `httpx.AsyncClient` boundary — the same seam production
  code uses — so the real dispatch logic runs.
* Assertions are on **returned values and database side effects**, never on an HTTP
  status alone. A test that only asserted `200` would have passed against the bug.
* Database isolation uses `DB_PATH` (the documented override) and, for E-33-2, a
  SQLite `DATABASE_URL` — which is precisely what that finding is about.
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database
import retention_service
from core import db_engine


# --------------------------------------------------------------------------- helpers
class _FakeResponse:
    def __init__(self, status_code: int, text: str = "", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload or {}

    def json(self):
        return self._payload


class _FakeAsyncClient:
    """Stand-in for `httpx.AsyncClient` that records calls and replays one response."""

    def __init__(self, response: _FakeResponse, calls: list):
        self._response = response
        self._calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def post(self, url, **kwargs):
        self._calls.append({"url": url, **kwargs})
        return self._response


@pytest.fixture()
def fake_provider(monkeypatch):
    """Install a fake `httpx` at the module seam used by retention_service.

    Returns a setter: `fake_provider(status_code, text="")` -> list of captured calls.
    """
    calls: list = []
    holder = {"response": _FakeResponse(200)}

    class _Shim:
        @staticmethod
        def AsyncClient(*_args, **_kwargs):
            return _FakeAsyncClient(holder["response"], calls)

    monkeypatch.setattr(retention_service, "httpx", type("FakeHttpx", (), {"AsyncClient": _Shim.AsyncClient}))

    def _set(status_code: int, text: str = ""):
        holder["response"] = _FakeResponse(status_code, text)
        return calls

    return _set


@pytest.fixture()
def tenant(tmp_path, monkeypatch):
    """A disposable SQLite database with one tenant that has a Telegram bot token.

    Isolation is enforced by **rebinding `database.DB_PATH`**, not merely by exporting
    `DB_PATH`. The environment variable is only read when the module is first imported,
    so a later `monkeypatch.setenv` would silently leave the repositories pointing at the
    repository `leads.db` — exactly the E-33-2 trap. Rebinding the module global is the
    documented override (`resolved_sqlite_path()` honours it) and is what makes these
    tests immune to being run against pre-fix source, where a negative control would
    otherwise pollute the developer's database.
    """
    db_file = tmp_path / "e33.db"
    monkeypatch.setenv("DB_PATH", str(db_file))
    monkeypatch.setattr(database, "DB_PATH", str(db_file), raising=False)
    database.init_db()

    pid = "e33_tenant"
    database.save_page(page_id=pid, name="E33 Tenant")
    database.update_page_telegram_settings(pid, "111:TESTTOKEN", "999")

    yield pid

    # Leave no rows behind in this file even though it is disposable, so a future test
    # pointed at the same path cannot read another test's data.
    conn = database.get_connection()
    try:
        for table in ("messages", "session_states", "marketing_campaigns"):
            try:
                conn.execute(f"DELETE FROM {table} WHERE page_id = ?", (pid,))
            except Exception:
                pass
        conn.commit()
    finally:
        conn.close()


def _bot_rows(sender_id: str, page_id: str) -> list:
    return [
        m
        for m in database.get_conversation_history(sender_id, limit=50, page_id=page_id)
        if m.get("sender_type") == "bot"
    ]


# ------------------------------------------------------- E-33-1 delivery truthfulness
@pytest.mark.parametrize("status_code", [403, 429, 500, 400])
def test_e33_1_telegram_failure_is_reported_as_not_delivered(tenant, fake_provider, status_code):
    """A failed Telegram send must return False and must not persist a "bot" message.

    Before the fix the 200-branch was the only `return True`, there was no `return False`
    for a non-200, and execution fell through to the generic fallback, which persists the
    message and returns True. The message was then counted as delivered.
    """
    fake_provider(status_code, '{"ok":false,"description":"Forbidden: bot was blocked by the user"}')
    sender = f"tg_{status_code}"

    delivered = asyncio.run(
        retention_service.dispatch_channel_message(tenant, sender, "telegram", "Төлбөр төлөх сануулга")
    )

    assert delivered is False, f"Telegram HTTP {status_code} must not be reported as delivered"
    assert _bot_rows(sender, tenant) == [], "a failed send must not be persisted as a delivered message"


def test_e33_1_telegram_success_still_persists_and_reports_delivered(tenant, fake_provider):
    """The happy path must keep working: 200 -> True, and exactly one persisted message."""
    calls = fake_provider(200)
    sender = "tg_ok"

    delivered = asyncio.run(
        retention_service.dispatch_channel_message(tenant, sender, "telegram", "Сайн байна уу")
    )

    assert delivered is True
    rows = _bot_rows(sender, tenant)
    assert len(rows) == 1
    assert rows[0]["content"] == "Сайн байна уу"
    # The payload actually carries the chat id, so a 200 is attributable to this recipient.
    assert calls and calls[0]["json"]["chat_id"] == "ok"


def test_e33_1_missing_credentials_fails_closed_without_calling_the_provider(tenant, fake_provider, monkeypatch):
    """No bot token -> False, no outbound call, nothing persisted."""
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    database.update_page_telegram_settings(tenant, "", "999")
    calls = fake_provider(200)

    delivered = asyncio.run(
        retention_service.dispatch_channel_message(tenant, "tg_notoken", "telegram", "hi")
    )

    assert delivered is False
    assert calls == [], "no token means the provider must never be contacted"
    assert _bot_rows("tg_notoken", tenant) == []


def test_e33_1_broadcast_sent_count_matches_actual_deliveries(tenant, fake_provider):
    """The campaign counter is the user-visible number: it must not include failures.

    This is the end-to-end form of the finding. Two contacts, one Telegram (fails) and
    one web (always succeeds locally), so an honest count is 1 and a buggy count is 2.
    """
    from core import models  # noqa: F401  (ensures tables exist before seeding)

    for sid, channel in (("tg_777", "telegram"), ("web_888", "web")):
        database.save_chat_message(
            page_id=tenant, sender_id=sid, channel=channel, sender_type="user", content="hi"
        )

    fake_provider(403, '{"ok":false,"description":"Forbidden: bot was blocked by the user"}')

    result = asyncio.run(
        retention_service.send_broadcast(
            page_id=tenant, title="Promo", message="SALE", target_segment="all", channel="all"
        )
    )

    assert result["success"] is True
    assert result["sent_count"] == 1, "the blocked Telegram recipient must not be counted as delivered"
    assert result["campaign"]["sent_count"] == 1, "the stored campaign must record the same number"
    assert _bot_rows("tg_777", tenant) == [], "no delivered message may be persisted for the blocked user"
    assert len(_bot_rows("web_888", tenant)) == 1, "the web recipient is served locally and must be recorded"


def test_e33_1_meta_failure_is_still_reported_as_not_delivered(tenant, fake_provider):
    """Regression guard: the Meta branch already returned False. Keep it that way."""
    conn = database.get_connection()
    try:
        conn.execute("UPDATE pages SET page_access_token = ? WHERE page_id = ?", ("METATOK", tenant))
        conn.commit()
    finally:
        conn.close()

    fake_provider(400, '{"error":{"message":"Invalid token"}}')
    delivered = asyncio.run(
        retention_service.dispatch_channel_message(tenant, "meta_555", "meta", "hi")
    )

    assert delivered is False
    assert _bot_rows("meta_555", tenant) == []


def test_e33_1_web_channel_never_contacts_a_provider(tenant, fake_provider):
    """A web recipient is served from our own database; it must not hit httpx at all."""
    calls = fake_provider(200)

    delivered = asyncio.run(
        retention_service.dispatch_channel_message(tenant, "web_1", "web", "welcome")
    )

    assert delivered is True
    assert calls == [], "the web channel must not make an outbound HTTP call"
    assert len(_bot_rows("web_1", tenant)) == 1


# ------------------------------------------------- E-33-2 database URL resolution
def _resolve(monkeypatch, url: str | None, db_path: str | None):
    for key in ("DATABASE_URL", "DB_PATH"):
        monkeypatch.delenv(key, raising=False)
    if url:
        monkeypatch.setenv("DATABASE_URL", url)
    if db_path:
        monkeypatch.setenv("DB_PATH", db_path)
    return db_engine.get_sqlite_db_path()


@pytest.mark.parametrize(
    "url,expected",
    [
        ("sqlite:////tmp/e33_abs.db", "/tmp/e33_abs.db"),
        ("sqlite:///rel_e33.db", "rel_e33.db"),
    ],
)
def test_e33_2_sqlite_database_url_selects_the_connection_file(monkeypatch, url, expected):
    """A SQLite DATABASE_URL must steer `get_db_connection()`, not just Alembic.

    Before the fix this returned the repository's `leads.db` while `get_database_url()`
    returned the URL, so migrations and queries used different files.
    """
    assert _resolve(monkeypatch, url, None) == expected


def test_e33_2_db_path_still_wins_over_a_sqlite_url(monkeypatch):
    """`DB_PATH` is the documented SQLite override and keeps precedence (compatibility)."""
    assert _resolve(monkeypatch, "sqlite:////tmp/e33_url.db", "/tmp/e33_path.db") == "/tmp/e33_path.db"


def test_e33_2_explicit_argument_still_wins_over_both(monkeypatch):
    """`database.resolved_sqlite_path()` passes an argument; that must remain authoritative."""
    monkeypatch.setenv("DB_PATH", "/tmp/e33_path.db")
    monkeypatch.setenv("DATABASE_URL", "sqlite:////tmp/e33_url.db")
    assert db_engine.get_sqlite_db_path("/tmp/e33_explicit.db") == "/tmp/e33_explicit.db"


def test_e33_2_neither_variable_falls_back_to_the_repository_database(monkeypatch):
    """Unchanged default: with no configuration the app uses `leads.db` in the repo root."""
    resolved = _resolve(monkeypatch, None, None)
    assert os.path.basename(resolved) == "leads.db"
    assert resolved == os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(db_engine.__file__))), "leads.db"
    )


@pytest.mark.parametrize("url", ["postgresql://u:p@127.0.0.1:5432/d", "postgresql+psycopg2://u:p@h/d"])
def test_e33_2_postgres_url_does_not_produce_a_sqlite_path(monkeypatch, url):
    """PostgreSQL behaviour must be untouched: no SQLite path is derived from a PG URL."""
    assert db_engine._sqlite_path_from_url(url) is None


@pytest.mark.parametrize("url", ["sqlite://", "sqlite:///:memory:", "sqlite:////:memory:"])
def test_e33_2_in_memory_urls_are_not_treated_as_files(monkeypatch, url):
    """An in-memory URL has no file; resolving it must not fabricate a path."""
    assert db_engine._sqlite_path_from_url(url) is None


def test_e33_2_connection_and_migration_layers_agree(tmp_path, monkeypatch):
    """The actual split-brain: both layers must name the same file.

    The pair that must agree is the **resolver the repositories use**
    (`database.resolved_sqlite_path()`, which `get_connection()` passes to
    `get_db_connection`) and the one Alembic uses (`schema_manager`). Comparing the
    no-argument `db_engine.get_sqlite_db_path()` would be the wrong assertion: that is a
    lower-level helper, not the value the application connects with.
    """
    from core import schema_manager

    target = str(tmp_path / "agreed.db")
    monkeypatch.delenv("DB_PATH", raising=False)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{target}")
    # Neutralise any rebinding another module performed earlier in the session so this
    # test observes environment resolution, which is what the finding is about.
    monkeypatch.setattr(database, "DB_PATH", database._DEFAULT_DB_PATH, raising=False)

    repository_path = database.resolved_sqlite_path()
    migration_path = schema_manager._resolved_sqlite_path()

    assert repository_path == target
    assert migration_path == target, (
        "Alembic must migrate the file the repositories use; "
        f"repository={repository_path!r} migration={migration_path!r}"
    )


def test_e33_2_an_explicit_rebinding_still_wins_over_the_url(tmp_path, monkeypatch):
    """`database.DB_PATH` rebinding stays authoritative — `api/index.py` relies on it.

    The Vercel bootstrap copies the database into a private runtime directory and assigns
    `database.DB_PATH` directly. A SQLite `DATABASE_URL` must not override that, or the
    serverless entry point would write to the wrong file.
    """
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'url.db'}")
    rebound = str(tmp_path / "runtime" / "leads.db")
    monkeypatch.setattr(database, "DB_PATH", rebound, raising=False)

    assert database.resolved_sqlite_path() == rebound


def test_e33_2_a_sqlite_url_actually_isolates_writes(tmp_path, monkeypatch):
    """End to end: init_db() and repository writes land in the URL's file, not `leads.db`.

    Before the fix this test wrote to the repository database — the exact accident that
    made four pre-existing SQL-injection tests non-isolating.
    """
    import importlib

    target = tmp_path / "isolated.db"
    monkeypatch.delenv("DB_PATH", raising=False)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{target}")

    importlib.reload(database)
    try:
        database.init_db()
        database.save_page(page_id="e33_iso", name="Iso")

        conn = database.get_connection()
        try:
            actual = conn.execute("PRAGMA database_list").fetchone()[2]
        finally:
            conn.close()

        assert os.path.abspath(actual) == os.path.abspath(str(target))
        assert target.exists()
    finally:
        # Restore the module-level global so later tests do not inherit this URL.
        monkeypatch.undo()
        importlib.reload(database)


def test_e33_2_postgres_url_leaves_sqlite_resolution_alone(monkeypatch):
    """With a PostgreSQL URL, `schema_manager` must not claim a SQLite file."""
    from core import schema_manager

    monkeypatch.delenv("DB_PATH", raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg2://u:p@127.0.0.1:5432/d")

    assert schema_manager._resolved_sqlite_path() is None
