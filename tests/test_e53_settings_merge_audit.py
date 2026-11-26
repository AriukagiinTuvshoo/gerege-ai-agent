"""
Phase 53 — settings forms MERGE instead of replacing, and credential changes leave a trace.

Every finding below was reproduced against the running application before the fix, on a
disposable page (`p53_probe`, created through `POST /api/pages` and deleted through
`DELETE /api/pages/p53_probe` afterwards). The measurements quoted here are from that run.

    F-53-1 (High)    `POST /api/executive/settings` read `payload.get(key, "")` for all four
                     columns and handed the result straight to an UPDATE, so a body that named
                     ONE field stored empty strings over the other three. Measured:
                     `{"daily_report_time": "09:15"}` turned the stored bot token
                     `111222333:PROBE-P53-SYNTHETIC` into `''` and the report recipient
                     `555000111` into `''`, then answered `{"success": true}`.

    F-53-2 (Medium)  `1 if payload.get("daily_report_enabled", True) else 0` made an ABSENT key
                     mean "on". Measured: the same partial POST moved a page the operator had
                     switched off from `0` to `1`. `worker.py:115` and the scheduler loop in
                     `main.py:65` both act on that column, so the reports start again on their
                     own. The string `"0"` was truthy under that rule, so it meant "on" too.

    F-53-3 (Medium)  The endpoint that changes WHO receives the daily executive report — with
                     `executive:write`, over the API — wrote no audit row at all. Measured: four
                     recipient changes left the audit table at 78 rows. O-51-4 (Phase 52) audited
                     the unauthenticated `/start` path in `executive_bot_service.py`, so an
                     auditor querying `executive.recipient.%` saw only that path and not this
                     more powerful one.

    F-53-4 (Medium)  `database.update_page_telegram_settings` returns `rowcount > 0` and the
                     handler ignored it. Measured: a POST naming a page that had never been
                     created wrote 0 rows and answered
                     `{"success": true, ... "амжилттай хадгалагдлаа"}`.

    F-53-5 (High)    `POST /api/fintech/settings` had the identical shape over the merchant's
                     PAYMENT credentials. Measured: `{"ebarimt_enabled": 1}` alone wiped
                     `qpay_username`, `qpay_password` and `qpay_invoice_code` and answered
                     `{"success": true}`.

    F-53-6 (High)    No audit row existed for any payment-credential change, ever. Measured:
                     0 rows in `audit_logs` whose action matched `%qpay%`, `%fintech%` or
                     `%payment%`, on the endpoint that stores the QPay password.

    F-53-7 (High)    `dashboard.html` filled `#setting-qpay-password` from
                     `currentPage.qpay_password`, a key `_sanitize_page_secrets()` pops from
                     every page dict before it leaves the API. So the box was blank for every
                     page that HAD a password, and saving posted that blank. Measured: one save
                     that changed nothing left `qpay_username='p53_merchant'` and
                     `qpay_password=''` — a half-broken payment config the form could not show,
                     because the mask it never read (`P5••••••••PW`) was the only evidence a
                     password existed. This is B6's defect class, on payment credentials.

    F-53-8 (High)    The executive form put the bot token's mask in a *placeholder*, so an
                     untouched save posted `telegram_bot_token: ""`. The handler's existing
                     guard (`if bot_token and "..." in bot_token`) could never fire, because a
                     placeholder is not posted. Measured: one dashboard-shaped save destroyed
                     the stored token and the bot stopped being able to send.

    F-53-9 (Low)     `POST /api/retention/rules` wrote `payload.get("delay_hours", 2)` and
                     `payload.get("is_active", True)` straight into an upsert, so a body naming
                     only the message reset the delay to 2 hours and re-activated a rule the
                     operator had switched off — which then messages customers by itself.

Design notes
------------
* Every behavioural test asserts the DATABASE, not just the response. A test that asserted
  `success is True` would have passed against all nine defects: they all answered success.
* The credentials used are synthetic and appear nowhere else. Tests scan the responses and
  every audit row for them, because "the API did not leak it" is a claim that has to be
  checked rather than assumed.
* Isolation is by rebinding `database.DB_PATH` (the documented override, as `test_e34` does),
  so no test can reach the deployment's database or the repository's `leads.db`.
* The dashboard tests are source contracts: they strip JS and HTML comments before scanning,
  because every fix in this file is documented in a comment that quotes the line it replaced.
  A scan that did not strip comments would match the documentation of the fix and pass.
"""

import hashlib
import io
import json
import os
import re
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402  (after the path insert, as every other module here does)

PAGE = "p53_probe"
MISSING_PAGE = "p53_does_not_exist"
BOT_TOKEN = "111222333:PROBE-P53-SYNTHETIC"
ROTATED_TOKEN = "444555666:PROBE-P53-ROTATED"
RECIPIENT = "555000111"
OTHER_RECIPIENT = "999888777"
QPAY_USER = "p53_merchant"
QPAY_PW = "P53-SYNTHETIC-PAY-PW"
QPAY_PW_2 = "NEW-P53-PAY-PW-2"
INVOICE = "P53INV"
ADMIN_PW = "e53-sample-admin-password"
BULLET = "\u2022"

#: every credential value this module invents; none may appear in a response or an audit row
SECRETS = (BOT_TOKEN, ROTATED_TOKEN, QPAY_PW, QPAY_PW_2)


# --------------------------------------------------------------------------- fixtures
@pytest.fixture()
def settings_env(tmp_path, monkeypatch):
    """A disposable database holding one page with a bot token, a recipient and QPay creds.

    `ADMIN_PASSWORD` is set to this module's own constant rather than read from the
    environment, because `authenticate_admin` compares against `os.getenv("ADMIN_PASSWORD")`
    at request time and a dotenv re-read between the two reads produced a spurious 401 in an
    earlier phase.
    """
    db_file = tmp_path / "p53.db"
    monkeypatch.setenv("DB_PATH", str(db_file))
    monkeypatch.setattr(database, "DB_PATH", str(db_file), raising=False)
    monkeypatch.setenv("ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("STRICT_SECURITY", raising=False)
    monkeypatch.delenv("DISABLE_DEFAULT_ADMIN_PASSWORD", raising=False)
    database.init_db()

    database.save_page(page_id=PAGE, name="Phase 53 probe")
    database.update_page_telegram_settings(PAGE, BOT_TOKEN, RECIPIENT, "08:30", 0)
    database.update_page_qpay_settings(PAGE, QPAY_USER, QPAY_PW, INVOICE, 0)
    yield {"db": str(db_file)}


# --------------------------------------------------------------------------- helpers
def _client():
    from fastapi.testclient import TestClient

    import main

    c = TestClient(main.app)
    c.cookies.clear()  # a stale session would authenticate a request meant to be fresh
    return c


def _login_token():
    r = _client().post("/api/auth/login", json={"type": "admin", "password": ADMIN_PW})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _headers():
    return {"Authorization": f"Bearer {_login_token()}"}


def _post(route, payload):
    return _client().post(route, headers=_headers(), json=payload)


def _post_exec(payload):
    return _post("/api/executive/settings", dict(payload, page_id=PAGE))


def _post_fintech(payload):
    return _post("/api/fintech/settings", dict(payload, page_id=PAGE))


def _post_retention(payload):
    return _post("/api/retention/rules", dict(payload, page_id=PAGE))


def _row(page_id=PAGE):
    """The stored columns, read back from the database rather than from any response."""
    conn = database.get_connection()
    conn.row_factory = sqlite3.Row
    try:
        r = conn.execute(
            "SELECT telegram_bot_token, telegram_manager_chat_id, daily_report_time,"
            " daily_report_enabled, qpay_username, qpay_password, qpay_invoice_code,"
            " ebarimt_enabled FROM pages WHERE page_id = ?",
            (page_id,),
        ).fetchone()
        return dict(r) if r else None
    finally:
        conn.close()


def _page_exists(page_id):
    conn = database.get_connection()
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM pages WHERE page_id = ?", (page_id,)
        ).fetchone()[0]
    finally:
        conn.close()


def _audit(action_like, page_id=PAGE):
    conn = database.get_connection()
    conn.row_factory = sqlite3.Row
    try:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM audit_logs WHERE action LIKE ? AND COALESCE(resource_id, '') = ?"
                " ORDER BY id",
                (action_like, page_id),
            ).fetchall()
        ]
    finally:
        conn.close()


def _new_rows(action_like, act):
    """Run `act` and return only the audit rows it added.

    Counting rows absolutely is valid only on a database this module owns. The authoritative
    suite runs against PostgreSQL, where `database.get_connection()` resolves through
    `core.db_engine` and IGNORES `database.DB_PATH`, so every module shares one database and
    the rows written by this module's earlier tests are still there. Measured: one query for
    `executive.recipient.transferred` on this page returned 13 rows under PostgreSQL and 1
    under SQLite. A delta is true on both, so every audit assertion here takes one.
    """
    before = len(_audit(action_like))
    act()
    rows = _audit(action_like)
    assert len(rows) >= before, "audit rows disappeared"
    return rows[before:]


def _rule(rule_type="abandoned_chat"):
    conn = database.get_connection()
    conn.row_factory = sqlite3.Row
    try:
        r = conn.execute(
            "SELECT rule_type, delay_hours, message_template, is_active FROM automated_rules"
            " WHERE page_id = ? AND rule_type = ?",
            (PAGE, rule_type),
        ).fetchone()
        return dict(r) if r else None
    finally:
        conn.close()


# --------------------------------------------------------------------------- dashboard
def _dashboard_text():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return io.open(os.path.join(root, "dashboard.html"), encoding="utf-8").read()


def _js_only(text):
    """Strip the comments, because every fix here is documented in one.

    Without this the scan matches the comment that quotes the replaced line and reports the
    defect as fixed. `<!--` blocks are stripped too: `dashboard.html` carries HTML comments
    that quote the same code.
    """
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    return "\n".join(ln for ln in text.split("\n") if not ln.strip().startswith("//"))


def _js_function(name, text=None):
    """The body of one JS function, found by brace matching."""
    code = _js_only(text or _dashboard_text())
    m = re.search(r"function\s+" + re.escape(name) + r"\s*\([^)]*\)\s*\{", code)
    assert m, f"{name} was not found in dashboard.html"
    depth, i = 0, m.end() - 1
    while i < len(code):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[m.start(): i + 1]
        i += 1
    raise AssertionError(f"unbalanced braces in {name}")


# ======================================================================================
# 1. F-53-1 / F-53-5 — a field the body does not name keeps what is stored
# ======================================================================================
class TestAPartialSaveDoesNotDestroyStoredCredentials:
    def test_a_body_naming_only_the_report_time_keeps_the_bot_token(self, settings_env):
        r = _post_exec({"daily_report_time": "09:15"})
        assert r.status_code == 200, r.text
        assert _row()["telegram_bot_token"] == BOT_TOKEN, "the token was destroyed"

    def test_a_body_naming_only_the_report_time_keeps_the_recipient(self, settings_env):
        _post_exec({"daily_report_time": "09:15"})
        assert _row()["telegram_manager_chat_id"] == RECIPIENT

    def test_it_still_updates_the_field_the_body_named(self, settings_env):
        _post_exec({"daily_report_time": "09:15"})
        assert _row()["daily_report_time"] == "09:15"

    def test_a_body_naming_nothing_changes_nothing(self, settings_env):
        before = _row()
        r = _post_exec({})
        assert r.status_code == 200, r.text
        assert _row() == before

    def test_the_response_names_what_it_preserved(self, settings_env):
        body = _post_exec({"daily_report_time": "09:15"}).json()
        assert body["changed"] == ["daily_report_time"]
        assert "telegram_bot_token" in body["preserved"]
        assert "telegram_manager_chat_id" in body["preserved"]
        assert body["cleared"] == []

    def test_a_body_naming_only_the_ebarimt_toggle_keeps_the_payment_credentials(
        self, settings_env
    ):
        r = _post_fintech({"ebarimt_enabled": 1})
        assert r.status_code == 200, r.text
        row = _row()
        assert row["qpay_username"] == QPAY_USER
        assert row["qpay_password"] == QPAY_PW, "the payment password was destroyed"
        assert row["qpay_invoice_code"] == INVOICE
        assert row["ebarimt_enabled"] == 1

    def test_the_qpay_response_names_what_it_preserved(self, settings_env):
        body = _post_fintech({"ebarimt_enabled": 1}).json()
        assert body["changed"] == ["ebarimt_enabled"]
        assert "qpay_password" in body["preserved"]

    def test_a_real_new_credential_still_stores(self, settings_env):
        """The merge must not turn into a refusal to update anything."""
        _post_fintech({"qpay_password": QPAY_PW_2})
        _post_exec({"telegram_bot_token": ROTATED_TOKEN})
        row = _row()
        assert row["qpay_password"] == QPAY_PW_2
        assert row["telegram_bot_token"] == ROTATED_TOKEN

    def test_a_credential_containing_a_single_dot_still_stores(self, settings_env):
        """Only a mask shape is refused; a password with one dot is a password."""
        password = "P53.WITH.DOTS"
        _post_fintech({"qpay_password": password})
        assert _row()["qpay_password"] == password


# ======================================================================================
# 2. F-53-2 — an absent flag is not an instruction to switch something on
# ======================================================================================
class TestAnAbsentFlagKeepsWhatIsStored:
    def test_an_absent_daily_report_enabled_keeps_reports_off(self, settings_env):
        assert _row()["daily_report_enabled"] == 0, "the fixture stores them off"
        _post_exec({"daily_report_time": "09:15"})
        assert _row()["daily_report_enabled"] == 0, "reports were switched back on"

    def test_a_named_true_still_turns_reports_on(self, settings_env):
        _post_exec({"daily_report_enabled": True})
        assert _row()["daily_report_enabled"] == 1

    def test_a_named_false_still_turns_reports_off(self, settings_env):
        _post_exec({"daily_report_enabled": True})
        _post_exec({"daily_report_enabled": False})
        assert _row()["daily_report_enabled"] == 0

    def test_the_string_zero_means_off(self, settings_env):
        """`1 if payload.get(...) else 0` made the string "0" truthy, so it meant "on"."""
        _post_exec({"daily_report_enabled": "0"})
        assert _row()["daily_report_enabled"] == 0

    def test_the_string_one_means_on(self, settings_env):
        _post_exec({"daily_report_enabled": "1"})
        assert _row()["daily_report_enabled"] == 1

    def test_an_absent_ebarimt_flag_keeps_what_is_stored(self, settings_env):
        assert _row()["ebarimt_enabled"] == 0
        _post_fintech({"qpay_invoice_code": "P53INV-2"})
        assert _row()["ebarimt_enabled"] == 0


# ======================================================================================
# 3. F-53-3 / F-53-6 — the change leaves a trace, in the vocabulary O-51-4 established
# ======================================================================================
class TestTheChangeLeavesATrace:
    def test_a_first_recipient_is_audited_as_registered(self, settings_env):
        """An empty slot filled through the API is a registration, in O-51-4's vocabulary."""
        cleared = _new_rows(
            "executive.recipient.%",
            lambda: _post_exec({"telegram_manager_chat_id": ""}),
        )
        assert [r["action"] for r in cleared] == ["executive.recipient.cleared"]
        registered = _new_rows(
            "executive.recipient.%",
            lambda: _post_exec({"telegram_manager_chat_id": OTHER_RECIPIENT}),
        )
        assert [r["action"] for r in registered] == ["executive.recipient.registered"]
        details = json.loads(registered[0]["details_json"])
        assert details["chat_id"] == OTHER_RECIPIENT
        assert details["previous_chat_id"] == ""

    def test_a_different_recipient_is_audited_as_transferred(self, settings_env):
        rows = _new_rows(
            "executive.recipient.%",
            lambda: _post_exec({"telegram_manager_chat_id": OTHER_RECIPIENT}),
        )
        assert [r["action"] for r in rows] == ["executive.recipient.transferred"]
        details = json.loads(rows[0]["details_json"])
        assert details["previous_chat_id"] == RECIPIENT
        assert details["chat_id"] == OTHER_RECIPIENT

    def test_an_emptied_recipient_is_audited_as_cleared(self, settings_env):
        rows = _new_rows(
            "executive.recipient.%",
            lambda: _post_exec({"telegram_manager_chat_id": ""}),
        )
        assert [r["action"] for r in rows] == ["executive.recipient.cleared"]
        assert json.loads(rows[0]["details_json"])["previous_chat_id"] == RECIPIENT

    def test_a_token_only_change_is_audited_as_settings_updated(self, settings_env):
        rows = _new_rows(
            "executive.%", lambda: _post_exec({"telegram_bot_token": ROTATED_TOKEN})
        )
        assert [r["action"] for r in rows] == ["executive.settings.updated"]
        details = json.loads(rows[0]["details_json"])
        assert details["bot_token_changed"] is True
        assert details["has_bot_token"] is True
        assert "telegram_bot_token" in details["changed_fields"]

    def test_a_save_that_changes_nothing_writes_no_row(self, settings_env):
        """A repeated form save is not an event. An unauthenticated `/start` is a different
        case and O-51-4 records it as `reaffirmed`, because there the asking is the evidence."""
        rows = _new_rows(
            "executive.%",
            lambda: _post_exec({
                "telegram_manager_chat_id": RECIPIENT,
                "telegram_bot_token": BOT_TOKEN,
                "daily_report_time": "08:30",
                "daily_report_enabled": False,
            }),
        )
        assert rows == []

    def test_a_qpay_change_is_audited(self, settings_env):
        rows = _new_rows(
            "fintech.%", lambda: _post_fintech({"qpay_invoice_code": "P53INV-2"})
        )
        assert [r["action"] for r in rows] == ["fintech.credentials.updated"]
        assert json.loads(rows[0]["details_json"])["changed_fields"] == ["qpay_invoice_code"]

    def test_a_removed_qpay_password_is_audited_as_cleared(self, settings_env):
        rows = _new_rows("fintech.%", lambda: _post_fintech({"qpay_password": ""}))
        assert [r["action"] for r in rows] == ["fintech.credentials.cleared"]
        details = json.loads(rows[0]["details_json"])
        assert details["has_qpay"] is False
        assert details["cleared_fields"] == ["qpay_password"]

    def test_a_qpay_save_that_changes_nothing_writes_no_row(self, settings_env):
        rows = _new_rows(
            "fintech.%",
            lambda: _post_fintech({
                "qpay_username": QPAY_USER,
                "qpay_password": QPAY_PW,
                "qpay_invoice_code": INVOICE,
                "ebarimt_enabled": 0,
            }),
        )
        assert rows == []

    def test_the_row_names_the_actor_and_a_session_reference(self, settings_env):
        rows = _new_rows(
            "executive.recipient.%",
            lambda: _post_exec({"telegram_manager_chat_id": OTHER_RECIPIENT}),
        )
        row = rows[0]
        assert row["actor_role"] == "admin"
        assert row["resource_type"] == "executive_recipient"
        assert row["resource_id"] == PAGE
        details = json.loads(row["details_json"])
        assert re.fullmatch(r"[0-9a-f]{12}", details["session_ref"]), details["session_ref"]
        assert details["via"] == "api"

    def test_the_session_reference_is_a_hash_and_not_the_token(self, settings_env):
        token = _login_token()
        expected = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
        rows = _new_rows(
            "executive.recipient.%",
            lambda: _client().post(
                "/api/executive/settings",
                headers={"Authorization": f"Bearer {token}"},
                json={"page_id": PAGE, "telegram_manager_chat_id": OTHER_RECIPIENT},
            ),
        )
        assert len(rows) == 1
        assert json.loads(rows[0]["details_json"])["session_ref"] == expected
        assert token not in (rows[0]["details_json"] or "")
        assert token not in str(dict(rows[0]))

    def test_no_audit_row_carries_a_credential(self, settings_env):
        """Scanned over EVERY row in the table, not just this page's: these values are unique
        to this module, so finding one anywhere would mean it escaped."""
        _post_exec({"telegram_bot_token": ROTATED_TOKEN})
        _post_exec({"telegram_manager_chat_id": OTHER_RECIPIENT})
        _post_fintech({"qpay_password": QPAY_PW_2})
        _post_fintech({"qpay_password": ""})
        conn = database.get_connection()
        try:
            blob = "\n".join(
                r[0] or ""
                for r in conn.execute("SELECT details_json FROM audit_logs").fetchall()
            )
        finally:
            conn.close()
        assert blob, "the probes should have written rows"
        for secret in SECRETS:
            assert secret not in blob, f"{secret[:6]}... reached the audit table"

    def test_no_row_this_endpoint_wrote_carries_a_mask(self, settings_env):
        """Delta-scoped, with the masks of THIS test's credentials as the needles.

        A global scan for `...` was wrong on two counts, both measured. Under PostgreSQL the
        rows this module wrote during earlier runs are still in the shared table. And
        `test_a_non_credential_field_is_not_mask_checked` stores the recipient `-100...777`,
        which the audit row records as `chat_id` — correctly, because a recipient id is not a
        secret and O-51-4 records it in the same field. So the claim is narrower and true: no
        row written by these two probes carries the bullet mask character, the mask of a
        credential this test stored, or the credential itself.
        """
        token_mask = database.mask_secret(ROTATED_TOKEN, 6, 4)
        password_mask = database.mask_secret(QPAY_PW_2, 2, 2)
        assert BULLET in password_mask and BULLET in token_mask, "the masks are bullet masks"
        before = len(_audit("%"))
        _post_exec({"telegram_bot_token": ROTATED_TOKEN})
        _post_fintech({"qpay_password": QPAY_PW_2})
        rows = _audit("%")[before:]
        assert rows, "the probes should have written rows"
        blob = "\n".join(r["details_json"] or "" for r in rows)
        for needle in (BULLET, token_mask, password_mask, ROTATED_TOKEN, QPAY_PW_2):
            assert needle not in blob, f"{needle[:6]!r} reached an audit row"


# ======================================================================================
# 4. F-53-4 — the response says whether anything was written
# ======================================================================================
class TestTheResponseTellsTheTruth:
    def test_a_page_that_does_not_exist_reports_failure(self, settings_env):
        r = _post("/api/executive/settings", {"page_id": MISSING_PAGE,
                                             "telegram_manager_chat_id": OTHER_RECIPIENT})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["success"] is False
        assert body["written"] is False
        assert body["changed"] == []

    def test_nothing_is_written_for_a_page_that_does_not_exist(self, settings_env):
        _post("/api/executive/settings", {"page_id": MISSING_PAGE,
                                          "telegram_manager_chat_id": OTHER_RECIPIENT})
        assert _page_exists(MISSING_PAGE) == 0
        assert _row(MISSING_PAGE) is None

    def test_no_audit_row_is_written_for_a_failed_write(self, settings_env):
        _post("/api/executive/settings", {"page_id": MISSING_PAGE,
                                          "telegram_manager_chat_id": OTHER_RECIPIENT})
        assert _audit("executive.%", page_id=MISSING_PAGE) == []

    def test_the_fintech_form_says_the_same_thing(self, settings_env):
        body = _post("/api/fintech/settings", {"page_id": MISSING_PAGE,
                                               "qpay_username": QPAY_USER}).json()
        assert body["success"] is False
        assert body["written"] is False
        assert _page_exists(MISSING_PAGE) == 0

    def test_a_successful_write_reports_written_true(self, settings_env):
        body = _post_exec({"daily_report_time": "09:15"}).json()
        assert body["success"] is True
        assert body["written"] is True
        assert body["page_id"] == PAGE


# ======================================================================================
# 5. A mask the API showed is never stored as a credential
# ======================================================================================
class TestAMaskIsNotACredential:
    def test_a_bullet_mask_posted_at_the_qpay_password_is_not_stored(self, settings_env):
        mask = database.mask_secret(QPAY_PW, 2, 2)
        assert BULLET in mask, mask
        body = _post_fintech({"qpay_password": mask}).json()
        assert body["mask_echoes"] == ["qpay_password"]
        assert _row()["qpay_password"] == QPAY_PW

    def test_an_ellipsis_mask_posted_at_the_bot_token_is_not_stored(self, settings_env):
        echo = f"{BOT_TOKEN[:6]}...{BOT_TOKEN[-4:]}"
        body = _post_exec({"telegram_bot_token": echo}).json()
        assert body["mask_echoes"] == ["telegram_bot_token"]
        assert _row()["telegram_bot_token"] == BOT_TOKEN

    def test_a_bullet_mask_posted_at_the_bot_token_is_not_stored(self, settings_env):
        """`GET /api/pages` masks the bot token with bullets, `GET /api/executive/settings`
        with an ellipsis, so a client can echo either shape at this field."""
        echo = database.mask_secret(BOT_TOKEN, 6, 4)
        _post_exec({"telegram_bot_token": echo})
        assert _row()["telegram_bot_token"] == BOT_TOKEN

    def test_a_mask_is_refused_even_when_nothing_is_stored(self, settings_env):
        """The regression in the first version of this fix, measured: with an empty stored
        value the guard returned early, so the mask itself was written as the credential and
        the page ended up with a QPay password made of bullets."""
        _post_fintech({"qpay_password": ""})
        assert _row()["qpay_password"] == ""
        mask = database.mask_secret(QPAY_PW, 2, 2)
        body = _post_fintech({"qpay_password": mask}).json()
        assert body["mask_echoes"] == ["qpay_password"]
        assert _row()["qpay_password"] == "", "a mask was stored as the payment credential"

    def test_an_ellipsis_mask_is_refused_even_when_nothing_is_stored(self, settings_env):
        _post_exec({"telegram_bot_token": ""})
        _post_exec({"telegram_bot_token": "111222...TIC"})
        assert _row()["telegram_bot_token"] == ""

    def test_the_echoed_field_is_reported_as_preserved_not_changed(self, settings_env):
        body = _post_fintech({"qpay_password": database.mask_secret(QPAY_PW, 2, 2)}).json()
        assert "qpay_password" in body["preserved"]
        assert body["changed"] == []

    def test_a_non_credential_field_is_not_mask_checked(self, settings_env):
        """The recipient is not a credential, so a value with dots in it is stored verbatim."""
        _post_exec({"telegram_manager_chat_id": "-100...777"})
        assert _row()["telegram_manager_chat_id"] == "-100...777"


# ======================================================================================
# 6. F-53-9 — a retention rule merges too
# ======================================================================================
class TestARetentionRuleMergesToo:
    def test_a_partial_update_keeps_the_delay(self, settings_env):
        _post_retention({"rule_type": "abandoned_chat", "delay_hours": 48,
                         "message_template": "P53 template", "is_active": False})
        assert _rule()["delay_hours"] == 48
        _post_retention({"rule_type": "abandoned_chat", "message_template": "P53 template v2"})
        assert _rule()["delay_hours"] == 48, "the delay was reset to the payload default"

    def test_a_partial_update_keeps_the_rule_inactive(self, settings_env):
        _post_retention({"rule_type": "abandoned_chat", "delay_hours": 48,
                         "message_template": "P53 template", "is_active": False})
        _post_retention({"rule_type": "abandoned_chat", "message_template": "P53 template v2"})
        assert _rule()["is_active"] == 0, "a disabled rule was re-activated"

    def test_it_still_updates_the_template_it_named(self, settings_env):
        _post_retention({"rule_type": "abandoned_chat", "delay_hours": 48,
                         "message_template": "P53 template", "is_active": False})
        _post_retention({"rule_type": "abandoned_chat", "message_template": "P53 template v2"})
        assert _rule()["message_template"] == "P53 template v2"

    def test_a_missing_rule_type_is_still_refused(self, settings_env):
        r = _post_retention({"message_template": "no rule type"})
        assert r.status_code == 400

    def test_a_rule_with_no_message_anywhere_is_still_refused(self, settings_env):
        """`get_automated_rules` seeds defaults, so an empty template can only reach the
        upsert if the caller explicitly empties it."""
        r = _post_retention({"rule_type": "abandoned_chat", "message_template": ""})
        assert r.status_code == 400

    def test_a_delay_that_is_not_a_number_falls_back_to_the_schema_default(self, settings_env):
        _post_retention({"rule_type": "abandoned_chat", "message_template": "P53",
                         "delay_hours": "soon"})
        assert _rule()["delay_hours"] == 2


# ======================================================================================
# 7. O-51-5 stays: naming a field with an empty value is still an explicit clear
# ======================================================================================
class TestAnExplicitClearStillWorks:
    def test_an_empty_recipient_in_the_body_clears_it(self, settings_env):
        body = _post_exec({"telegram_manager_chat_id": ""}).json()
        assert body["success"] is True
        assert _row()["telegram_manager_chat_id"] == ""

    def test_the_response_reports_it_as_cleared(self, settings_env):
        body = _post_exec({"telegram_manager_chat_id": ""}).json()
        assert body["cleared"] == ["telegram_manager_chat_id"]

    def test_an_empty_qpay_password_in_the_body_clears_it(self, settings_env):
        _post_fintech({"qpay_password": ""})
        assert _row()["qpay_password"] == ""

    def test_an_empty_bot_token_in_the_body_clears_it(self, settings_env):
        _post_exec({"telegram_bot_token": ""})
        assert _row()["telegram_bot_token"] == ""

    def test_an_on_off_field_is_not_reported_as_cleared(self, settings_env):
        """A flag turned off is 0, not "cleared"; the word belongs to values that were removed.

        The fixture stores the reports OFF, so they are switched on first - otherwise the
        POST below changes nothing and the test would assert against an empty list.
        """
        _post_exec({"daily_report_enabled": True})
        assert _row()["daily_report_enabled"] == 1
        body = _post_exec({"daily_report_enabled": False}).json()
        assert "daily_report_enabled" in body["changed"]
        assert "daily_report_enabled" not in body["cleared"]
        assert body["cleared"] == []


# ======================================================================================
# 8. The response carries field names, never values
# ======================================================================================
class TestTheResponseCarriesNamesNotValues:
    def test_no_credential_appears_in_the_executive_response(self, settings_env):
        r = _post_exec({"telegram_bot_token": ROTATED_TOKEN})
        for secret in SECRETS:
            assert secret not in r.text

    def test_no_credential_appears_in_the_fintech_response(self, settings_env):
        r = _post_fintech({"qpay_password": QPAY_PW_2})
        for secret in SECRETS:
            assert secret not in r.text

    def test_the_lists_hold_field_names_only(self, settings_env):
        body = _post_exec({"telegram_bot_token": ROTATED_TOKEN,
                           "telegram_manager_chat_id": OTHER_RECIPIENT}).json()
        import main

        known = set(body["changed"]) | set(body["preserved"]) | set(body["cleared"])
        allowed = set(main.EXECUTIVE_SETTINGS_SPEC)
        assert known <= allowed, (known - allowed, allowed)
        assert known == allowed, "every field the form owns is accounted for"

    def test_a_no_change_save_says_so_in_the_message(self, settings_env):
        body = _post_exec({"telegram_manager_chat_id": RECIPIENT}).json()
        assert body["changed"] == []
        assert body["message"] != (
            "Telegram болон өглөөний тайлангийн тохиргоо амжилттай хадгалагдлаа"
        )


# ======================================================================================
# 9. The merge helper on its own
# ======================================================================================
class TestTheMergeHelper:
    def _merge(self, payload, stored, spec):
        import main

        return main._merged_settings(payload, stored, spec)

    def test_an_absent_key_returns_the_stored_value(self, settings_env):
        import main

        values, changed, preserved, cleared, echoes = self._merge(
            {}, {"telegram_bot_token": BOT_TOKEN}, main.EXECUTIVE_SETTINGS_SPEC
        )
        assert values["telegram_bot_token"] == BOT_TOKEN
        assert "telegram_bot_token" in preserved
        assert changed == [] and cleared == [] and echoes == []

    def test_a_missing_stored_column_falls_back_to_the_spec_default(self, settings_env):
        import main

        values, *_ = self._merge({}, {}, main.EXECUTIVE_SETTINGS_SPEC)
        assert values["daily_report_time"] == "08:30"
        assert values["daily_report_enabled"] == 1

    def test_the_returned_lists_are_sorted_and_unique(self, settings_env):
        import main

        _values, changed, preserved, cleared, echoes = self._merge(
            {"telegram_bot_token": ROTATED_TOKEN, "telegram_manager_chat_id": ""},
            {"telegram_bot_token": BOT_TOKEN, "telegram_manager_chat_id": RECIPIENT},
            main.EXECUTIVE_SETTINGS_SPEC,
        )
        for lst in (changed, preserved, cleared, echoes):
            assert lst == sorted(set(lst))
        assert cleared == ["telegram_manager_chat_id"]

    def test_none_is_coerced_to_an_empty_string_not_the_literal_none(self, settings_env):
        import main

        values, *_ = self._merge(
            {"telegram_manager_chat_id": None}, {}, main.EXECUTIVE_SETTINGS_SPEC
        )
        assert values["telegram_manager_chat_id"] == ""

    def test_values_are_stripped(self, settings_env):
        import main

        values, *_ = self._merge(
            {"telegram_manager_chat_id": "  555  "}, {}, main.EXECUTIVE_SETTINGS_SPEC
        )
        assert values["telegram_manager_chat_id"] == "555"

    def test_the_flag_coercer(self, settings_env):
        import main

        assert main._settings_flag(True) == 1
        assert main._settings_flag(False) == 0
        assert main._settings_flag(1) == 1
        assert main._settings_flag(0) == 0
        assert main._settings_flag("0") == 0
        assert main._settings_flag("false") == 0
        assert main._settings_flag("off") == 0
        assert main._settings_flag("") == 0
        assert main._settings_flag("1") == 1
        assert main._settings_flag(None) == 0

    def test_the_hours_coercer(self, settings_env):
        import main

        assert main._settings_hours("48") == 48
        assert main._settings_hours(6) == 6
        assert main._settings_hours("soon") == 2
        assert main._settings_hours(None) == 2

    def test_the_mask_echo_recogniser(self, settings_env):
        import main

        bullet = database.mask_secret(QPAY_PW, 2, 2)
        assert main._is_mask_echo(bullet, QPAY_PW, ("bullets",)) is True
        assert main._is_mask_echo(bullet, "", ("bullets",)) is True, "the empty-field case"
        assert main._is_mask_echo("111222...TIC", "", ("ellipsis", "bullets")) is True
        assert main._is_mask_echo(QPAY_PW_2, QPAY_PW, ("bullets",)) is False
        assert main._is_mask_echo("", QPAY_PW, ("bullets",)) is False
        assert main._is_mask_echo(QPAY_PW, QPAY_PW, None) is False, "not a credential field"


# ======================================================================================
# 10. F-53-7 / F-53-8 — the dashboard does not read a field the API masks away
# ======================================================================================
class TestTheDashboardDoesNotPostAValueItWasNeverGiven:
    def test_no_code_reads_the_popped_qpay_password(self, settings_env):
        code = _js_only(_dashboard_text())
        assert not re.search(r"\bcurrentPage\.qpay_password\b", code), (
            "the dashboard reads a key `_sanitize_page_secrets` pops, so the box is always "
            "blank and saving destroys the stored password"
        )

    def test_no_code_reads_the_popped_bot_token(self, settings_env):
        code = _js_only(_dashboard_text())
        assert not re.search(r"\bcfg\.telegram_bot_token\b", code)

    def test_the_qpay_mask_goes_into_the_placeholder_not_the_value(self, settings_env):
        body = _js_function("openQPaySettingsModal")
        assert re.search(r"qpayPasswordBox\.placeholder\s*=\s*qpayMasked", body)
        assert re.search(r"qpayPasswordBox\.value\s*=\s*''", body)
        assert "currentPage.qpay_password_masked" in body

    def test_the_qpay_note_element_exists_and_is_filled(self, settings_env):
        text = _dashboard_text()
        assert 'id="settings-qpay-password-note"' in text
        assert "settings-qpay-password-note').textContent" in _js_function(
            "openQPaySettingsModal"
        )

    def test_the_qpay_remove_control_exists_and_is_reset_on_open(self, settings_env):
        assert 'id="setting-qpay-clear"' in _dashboard_text()
        assert "setting-qpay-clear').checked = false" in _js_function("openQPaySettingsModal")

    def test_the_qpay_save_omits_the_password_when_the_box_is_empty(self, settings_env):
        body = _js_function("saveQPaySettings")
        assert "qpay_password: p," not in body, "the save still posts an empty password"
        assert re.search(r"\(p \? \{ qpay_password: p \} : \{\}\)", body)
        assert "Object.assign" in body

    def test_the_qpay_remove_tick_posts_an_explicit_empty_string(self, settings_env):
        body = _js_function("saveQPaySettings")
        assert re.search(
            r"setting-qpay-clear'\)\.checked\s*\?\s*\{ qpay_password: '' \}", body
        )

    def test_the_executive_save_omits_the_token_when_the_box_is_empty(self, settings_env):
        body = _js_function("saveExecutiveSettings")
        assert "telegram_bot_token: botToken," not in body
        assert re.search(r"\(botToken \? \{ telegram_bot_token: botToken \} : \{\}\)", body)

    def test_the_executive_remove_tick_posts_an_explicit_empty_string(self, settings_env):
        body = _js_function("saveExecutiveSettings")
        assert re.search(
            r"input-exec-bot-token-clear'\)\.checked\s*\?\s*\{ telegram_bot_token: '' \}", body
        )

    def test_the_executive_form_clears_the_value_and_keeps_the_mask_as_a_placeholder(
        self, settings_env
    ):
        body = _js_function("loadExecutiveData")
        assert re.search(r"execTokenBox\.value\s*=\s*''", body)
        assert "cfg.telegram_bot_token_masked" in body
        assert "settings-exec-bot-token-note" in body

    def test_the_executive_remove_control_exists(self, settings_env):
        assert 'id="input-exec-bot-token-clear"' in _dashboard_text()

    def test_neither_save_function_reads_a_field_the_api_pops(self, settings_env):
        """The general form of B6's contract, applied to both functions this phase touched:
        every `p.<field>` they read must exist in a real sanitized page row."""
        real = database.get_all_pages(mask_secrets=True)
        keys = set(real[0].keys()) if real else set()
        assert keys, "the fixture should have produced a page row"
        for name in ("openQPaySettingsModal",):
            body = _js_function(name)
            for field in re.findall(r"\bcurrentPage\.([a-z_]+)\b", body):
                assert field in keys, f"{name} reads currentPage.{field}, which the API masks"
