"""
Stage E — E-01 regression tests: cross-tenant session / PII disclosure (P0).

Written **before** the fix so the leak is provable. Every test drives the application through
its public HTTP surface with real tenant session tokens. No test writes rows with hand-written
SQL to manufacture the leak — a fixture that edits the database can make any system look
broken, and an audit that relies on one proves nothing.

Root cause being pinned
-----------------------
`session_states` was keyed on `sender_id` alone:

    PRIMARY KEY (sender_id)          -- not (page_id, sender_id)

`log_message()` and `save_registration()` upsert on that key with
`page_id = COALESCE(?, session_states.page_id)`, which always takes the *new* value, so a
session row is reassigned to whichever tenant spoke last. In addition:

* `get_active_sessions()` computed `last_message` / `last_sender_type` / `message_count`
  with subqueries filtered on `sender_id` only.
* `get_conversation_history()`, `is_session_human_takeover()` and `set_human_takeover()`
  filtered on `sender_id` only.
* The takeover/send ownership guard authorised against `msgs[0]` — the *oldest* row across
  all tenants — instead of the caller's tenant.

The scenario throughout: **one person (one sender ID) who contacts two different businesses.**
That is ordinary traffic, not an attack, and it is what makes the leak a P0.
"""
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402

ACME = "ACME_TENANT"
GLOBEX = "GLOBEX_TENANT"
CUSTOMER = "PSID_CUSTOMER_1"
ACME_PHONE = "88001234"
ACME_NAME = "Бат"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db = tmp_path / "e01.db"
    monkeypatch.setenv("DB_PATH", str(db))
    monkeypatch.setattr(database, "DB_PATH", str(db))
    database.init_db()
    database.save_page(page_id=ACME, name="Acme", category="general")
    database.save_page(page_id=GLOBEX, name="Globex", category="general")
    import main

    return TestClient(main.app, raise_server_exceptions=False)


def _tenant_token(page_id: str) -> dict:
    """A real session token for a client user of that tenant."""
    token = database.create_session(role="client", page_id=page_id, ip_address="10.0.0.1")
    return {"Authorization": f"Bearer {token}"}


def _sessions(client, page_id: str):
    r = client.get("/api/sessions", headers=_tenant_token(page_id))
    assert r.status_code == 200, r.text
    return r.json().get("data", [])


def _chat(client, message: str, page_id: str):
    r = client.post(
        "/api/chat",
        json={"message": message, "sender_id": CUSTOMER, "page_id": page_id},
    )
    assert r.status_code == 200, r.text
    return r


# ---------------------------------------------------------------------------
# 1-3: the ordinary sequence that triggers the leak
# ---------------------------------------------------------------------------
def test_acme_customer_gives_their_phone_and_globex_never_sees_it(client):
    """
    Tests 1-5. Acme's customer chats and the agent records their phone. The same person then
    messages Globex. Globex must not be shown Acme's customer name or phone.
    """
    _chat(client, f"намайг {ACME_NAME} гэдэг, утас {ACME_PHONE}", ACME)

    _chat(client, "hello, do you deliver?", GLOBEX)

    globex_rows = _sessions(client, GLOBEX)
    assert globex_rows, "Globex should see its own conversation"
    for row in globex_rows:
        assert row["page_id"] == GLOBEX
        assert row["customer_phone"] != ACME_PHONE, (
            "E-01: Globex was shown the phone number Acme collected"
        )
        assert row["customer_name"] != ACME_NAME, (
            "E-01: Globex was shown the customer name Acme collected"
        )


def test_each_tenant_keeps_its_own_conversation_row(client):
    """Test 6 + 12: the conversation must not migrate away from the tenant that owns it."""
    _chat(client, "hi from acme", ACME)
    _chat(client, "hi from globex", GLOBEX)

    assert _sessions(client, ACME), "Acme lost its own conversation"
    assert _sessions(client, GLOBEX), "Globex lost its own conversation"
    assert {r["page_id"] for r in _sessions(client, ACME)} == {ACME}
    assert {r["page_id"] for r in _sessions(client, GLOBEX)} == {GLOBEX}


def test_message_count_and_last_message_are_per_tenant(client):
    """Tests 7-8: counts and last-message must come from the caller's tenant only."""
    _chat(client, "acme one", ACME)
    _chat(client, "acme two", ACME)
    _chat(client, "globex one", GLOBEX)

    acme = _sessions(client, ACME)[0]
    globex = _sessions(client, GLOBEX)[0]

    # Each conversation has: the user message(s) + the assistant reply per exchange.
    assert acme["message_count"] != globex["message_count"], (
        "both tenants report the same message count, so the count is not tenant-scoped"
    )
    assert globex["last_message"] != "acme two", (
        "Globex's last_message is Acme's message"
    )


def test_human_takeover_is_per_tenant(client):
    """Test 9: takeover state must not leak between tenants."""
    _chat(client, "хүнтэй ярихыг хүсэж байна", ACME)  # escalation keyword -> takeover
    # Globex must have its own conversation for this assertion to mean anything; otherwise
    # an empty list would make it pass without proving isolation.
    _chat(client, "globex, шинэ яриа", GLOBEX)

    globex = _sessions(client, GLOBEX)
    assert globex, "Globex must see its own conversation"
    for row in globex:
        assert not row["is_human_takeover"], (
            "E-01: Globex inherited Acme's human-takeover state"
        )


# ---------------------------------------------------------------------------
# 10-11: authorisation
# ---------------------------------------------------------------------------
def test_globex_cannot_toggle_takeover_on_acmes_session(client):
    """
    Test 10: a tenant with no session for that sender must be refused.

    Two separate properties, because "403" alone is not isolation:
      * a tenant that never spoke to this customer gets 403/404 (no cross-tenant write);
      * Acme's own takeover state is never altered by that attempt.
    """
    _chat(client, "acme conversation", ACME)
    acme_id = _sessions(client, ACME)[0]["sender_id"]

    r = client.post(
        f"/api/sessions/{acme_id}/takeover",
        json={"takeover": True},
        headers=_tenant_token(GLOBEX),
    )
    assert r.status_code in (403, 404), (
        f"Globex was allowed to toggle takeover on Acme's session (status {r.status_code})"
    )

    acme = {row["sender_id"]: row for row in _sessions(client, ACME)}[acme_id]
    assert not acme["is_human_takeover"], (
        "E-01: Acme's takeover state changed because another tenant asked for it"
    )


def test_globex_cannot_send_into_acmes_session(client):
    """
    Test 11: sending into another tenant's session must be refused and must not appear
    in Acme's transcript.
    """
    _chat(client, "acme conversation", ACME)
    acme_id = _sessions(client, ACME)[0]["sender_id"]
    before = len(client.get(
        f"/api/sessions/{acme_id}/messages", headers=_tenant_token(ACME)
    ).json()["messages"])

    r = client.post(
        f"/api/sessions/{acme_id}/send",
        json={"message": "injected by globex", "page_id": ACME},
        headers=_tenant_token(GLOBEX),
    )
    assert r.status_code in (403, 404), (
        f"Globex was allowed to send into Acme's session (status {r.status_code})"
    )

    after = client.get(
        f"/api/sessions/{acme_id}/messages", headers=_tenant_token(ACME)
    ).json()["messages"]
    assert len(after) == before, "E-01: a foreign tenant injected a message into Acme's transcript"
    assert all("injected by globex" not in (m.get("content") or "") for m in after), (
        "E-01: the injected message is visible in Acme's transcript"
    )


def test_shared_sender_writes_only_touch_the_calling_tenants_row(client):
    """
    Test 12: the ordinary case — one person talks to two businesses.

    Both tenants legitimately own a session for that sender, so both may act on THEIR OWN
    row. What must never happen is one tenant's action changing the other's state. The old
    code authorised against `msgs[0]` (the oldest message across all tenants) and then wrote
    to a single globally-keyed row, so whichever tenant spoke last owned both.
    """
    # Acme's message is written FIRST, so `msgs[0]` is Acme's row. Under the old
    # oldest-message rule this made Globex's own session unusable and, once Globex's
    # traffic reassigned the shared row, made Acme's state writable by Globex.
    _chat(client, "acme first", ACME)
    _chat(client, "globex second", GLOBEX)
    assert _sessions(client, GLOBEX), "precondition: Globex must have its own session"

    r = client.post(
        f"/api/sessions/{CUSTOMER}/takeover",
        json={"takeover": True},
        headers=_tenant_token(GLOBEX),
    )
    assert r.status_code == 200, (
        f"Globex must be able to toggle takeover on its OWN session, got {r.status_code}: {r.text}"
    )

    acme = {row["sender_id"]: row for row in _sessions(client, ACME)}[CUSTOMER]
    globex = {row["sender_id"]: row for row in _sessions(client, GLOBEX)}[CUSTOMER]
    # SQLite stores booleans as 0/1, so compare by truthiness rather than identity.
    assert bool(globex["is_human_takeover"]), "Globex's own takeover did not take effect"
    assert not acme["is_human_takeover"], (
        "E-01: Globex's takeover write changed Acme's session state"
    )


# ---------------------------------------------------------------------------
# Schema-level: the database itself must enforce the identity
# ---------------------------------------------------------------------------
def test_session_identity_is_tenant_scoped_in_the_schema(client):
    """
    The fix must not be query-only. The database has to reject a duplicate
    (page_id, sender_id) so a future query cannot reintroduce the leak.
    """
    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO session_states (sender_id, page_id, channel) VALUES (?,?,?)",
            (CUSTOMER, ACME, "web"),
        )
        conn.commit()
        # A second row for the SAME tenant must be rejected (it is the same identity).
        with pytest.raises(Exception):
            cur.execute(
                "INSERT INTO session_states (sender_id, page_id, channel) VALUES (?,?,?)",
                (CUSTOMER, ACME, "web"),
            )
            conn.commit()
        conn.rollback()
        # A row for a DIFFERENT tenant must be accepted.
        cur.execute(
            "INSERT INTO session_states (sender_id, page_id, channel) VALUES (?,?,?)",
            (CUSTOMER, GLOBEX, "web"),
        )
        conn.commit()
        cur.execute(
            "SELECT COUNT(*) FROM session_states WHERE sender_id = ?", (CUSTOMER,)
        )
        assert cur.fetchone()[0] == 2, "two tenants could not both keep their own session"
    finally:
        conn.close()
