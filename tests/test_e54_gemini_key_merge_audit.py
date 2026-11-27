"""
Phase 54 — the per-tenant Gemini key and the sheet URL MERGE instead of replacing.

Both findings were reproduced against the running application before the fix, on disposable
pages created through `POST /api/pages` and deleted through `DELETE /api/pages/{page_id}`. The
measurements quoted here are from those runs.

    F-54-1 (High)    `POST /api/pages/{page_id}/gemini_key` read
                     `payload.get("gemini_api_key", "")` and handed it straight to an UPDATE,
                     so a body that named only the quota stored an empty string over the
                     tenant's API key. Measured live:

                         stored:                        key = 35 chars, limit = 5000
                         POST {"monthly_token_limit": 7000}
                         response: {"status":"success","message":"...амжилттай шинэчлэгдлээ!"}
                         stored:                        key = 0 chars,  limit = 7000
                         audit rows written:            0

                     That exact partial body is what the product's own dashboard posts from the
                     Client Access modal (`dashboard.html`: `body: JSON.stringify({page_id,
                     monthly_token_limit: parseInt(limit)})`, with no `gemini_api_key` key), so
                     ONE Save click on a quota destroyed a tenant's personal API key and moved
                     them onto the operator's paid quota, while the UI showed a success toast.
                     This is the same shape as F-53-1/F-53-5, on a credential.

    F-54-2 (Medium)  `POST /api/pages/{page_id}/google_sheets` had the identical shape over the
                     column that says where the tenant's knowledge comes from. Measured live on
                     the pre-fix tree, with a URL that passes the SSRF validator:

                         stored:  https://docs.google.com/spreadsheets/d/P54BEFORESHEET/edit#gid=0
                         POST {"page_id": "..."}            (no google_sheets_url)
                         response: {"success":true,...,"google_sheets_url":""}
                         stored:  ''

                     An earlier probe of this endpoint reported nothing because the URL it used
                     (`https://example.invalid/...`) was rejected with 400 by
                     `sheets_service.normalize_sheet_csv_url`, so nothing was stored to wipe.
                     The precondition is part of the measurement.

    F-54-3 (Medium)  `database.update_page_gemini_key` and `database.update_page_google_sheets`
                     both ended in an unconditional `return True`, so neither handler could tell
                     a write from a no-op. Measured live: a POST naming `p54_never_created`
                     wrote 0 rows and answered `{"status":"success"}`; the sheets endpoint
                     answered `{"success":true}` for a page that had never existed either.

Design notes
------------
* Every behavioural test asserts the DATABASE, not just the response. All three defects
  answered success, so a test that asserted the status would have passed against every one.
* Audit assertions are DELTAS, never absolute counts. The authoritative suite runs against
  PostgreSQL, where `database.get_connection()` resolves through `core.db_engine` and ignores a
  rebound `database.DB_PATH`, so rows written by this module's earlier tests — and by earlier
  runs — are still in the table. A delta is true on both dialects. (This is the trap that made
  `test_e02_phase13_audit_append_only.py:378` order-dependent; see F-53-10.)
* The credentials used are synthetic and appear nowhere else. Responses and audit rows are
  scanned for them, because "the API did not leak it" has to be checked, not assumed.
* Names allowed in `changed`/`preserved`/`cleared` are derived from `main.GEMINI_SETTINGS_SPEC`
  rather than restated, so renaming a field breaks the test that should break.
"""

import io
import os
import re
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402  (after the path insert, as every other module here does)

PAGE = "p54_probe"
MISSING_PAGE = "p54_does_not_exist"
GEMINI_KEY = "AIzaSYNTHETICP54KEYdonotuse0000000"
GEMINI_KEY_2 = "AIzaROTATEDP54KEYdonotuse000000"
QUOTA = 5000
OTHER_QUOTA = 7000
SHEET_URL = "https://docs.google.com/spreadsheets/d/P54TESTSHEET123/edit#gid=0"
SHEET_URL_2 = "https://docs.google.com/spreadsheets/d/P54OTHERSHEET456/edit#gid=0"
SSRF_URL = "http://169.254.169.254/latest/meta-data/"
ADMIN_PW = "e54-sample-admin-password"
BULLET = "\u2022"

#: every credential value this module invents; none may appear in a response or an audit row
SECRETS = (GEMINI_KEY, GEMINI_KEY_2)


# --------------------------------------------------------------------------- fixtures
@pytest.fixture()
def key_env(tmp_path, monkeypatch):
    """A disposable database holding one page with a Gemini key, a quota and a sheet URL.

    `ADMIN_PASSWORD` is this module's own constant rather than a value read from the
    environment, because `authenticate_admin` compares against `os.getenv("ADMIN_PASSWORD")`
    at request time and a dotenv re-read between the two reads produced a spurious 401 in an
    earlier phase.
    """
    db_file = tmp_path / "p54.db"
    monkeypatch.setenv("DB_PATH", str(db_file))
    monkeypatch.setattr(database, "DB_PATH", str(db_file), raising=False)
    monkeypatch.setenv("ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("STRICT_SECURITY", raising=False)
    monkeypatch.delenv("DISABLE_DEFAULT_ADMIN_PASSWORD", raising=False)
    database.init_db()

    database.save_page(page_id=PAGE, name="Phase 54 probe")
    database.update_page_gemini_key(PAGE, GEMINI_KEY, QUOTA)
    database.update_page_google_sheets(PAGE, SHEET_URL)
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


def _post_key(payload, route=None):
    """POST to the per-page gemini_key route unless another route is named."""
    return _post(route or f"/api/pages/{PAGE}/gemini_key", dict(payload, page_id=PAGE))


def _post_sheets(payload):
    return _post(f"/api/pages/{PAGE}/google_sheets", dict(payload, page_id=PAGE))


def _row(page_id=PAGE):
    """The stored columns, read back from the database rather than from any response."""
    conn = database.get_connection()
    conn.row_factory = sqlite3.Row
    try:
        r = conn.execute(
            "SELECT gemini_api_key, monthly_token_limit, google_sheets_url"
            " FROM pages WHERE page_id = ?",
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
    """Run `act` and return only the audit rows it added."""
    before = len(_audit(action_like))
    act()
    rows = _audit(action_like)
    assert len(rows) >= before, "audit rows disappeared"
    return rows[before:]


def _details(row):
    import json

    raw = row.get("details_json") or row.get("details") or "{}"
    try:
        return json.loads(raw) if isinstance(raw, str) else dict(raw)
    except Exception:
        return {}


def _mask_of(value, start=4, end=4):
    return database.mask_secret(value, start, end)


def _allowed_names():
    import main

    return set(main.GEMINI_SETTINGS_SPEC) | set(main.SHEETS_SETTINGS_SPEC)


def _dashboard_source():
    """`dashboard.html` with every comment stripped.

    Each fix in this repository is documented in a comment that quotes the line it replaced, so
    a scan that did not strip comments would match the documentation of the fix and pass.
    """
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard.html")
    text = io.open(path, encoding="utf-8").read()
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    return "\n".join(ln for ln in text.split("\n") if not ln.strip().startswith("//"))


# =========================================================================== F-54-1
class TestAPartialSaveDoesNotDestroyTheTenantsKey:
    """The defect: a body naming only the quota stored '' over the tenant's API key."""

    def test_the_key_survives_a_quota_only_save(self, key_env):
        _post_key({"monthly_token_limit": OTHER_QUOTA})
        row = _row()
        assert row["gemini_api_key"] == GEMINI_KEY
        assert row["monthly_token_limit"] == OTHER_QUOTA

    def test_the_quota_survives_a_key_only_save(self, key_env):
        _post_key({"gemini_api_key": GEMINI_KEY_2})
        row = _row()
        assert row["gemini_api_key"] == GEMINI_KEY_2
        assert row["monthly_token_limit"] == QUOTA

    def test_an_empty_body_changes_nothing(self, key_env):
        _post_key({})
        row = _row()
        assert row["gemini_api_key"] == GEMINI_KEY
        assert row["monthly_token_limit"] == QUOTA

    def test_a_real_new_key_is_still_stored(self, key_env):
        """The merge must not become a refusal to update."""
        r = _post_key({"gemini_api_key": GEMINI_KEY_2, "monthly_token_limit": OTHER_QUOTA})
        assert r.status_code == 200, r.text
        row = _row()
        assert row["gemini_api_key"] == GEMINI_KEY_2
        assert row["monthly_token_limit"] == OTHER_QUOTA

    def test_the_key_is_stripped_not_padded(self, key_env):
        _post_key({"gemini_api_key": f"  {GEMINI_KEY_2}  "})
        assert _row()["gemini_api_key"] == GEMINI_KEY_2

    def test_the_route_without_a_page_id_merges_too(self, key_env):
        """`@app.post("/api/pages/gemini_key")` shares the handler; it must behave identically."""
        _post_key({"monthly_token_limit": OTHER_QUOTA}, route="/api/pages/gemini_key")
        row = _row()
        assert row["gemini_api_key"] == GEMINI_KEY
        assert row["monthly_token_limit"] == OTHER_QUOTA

    def test_the_response_names_what_was_preserved(self, key_env):
        body = _post_key({"monthly_token_limit": OTHER_QUOTA}).json()
        assert "gemini_api_key" in body["preserved"]
        assert "monthly_token_limit" in body["changed"]
        assert body["cleared"] == []


class TestTheDashboardShapedSaveIsSafe:
    """The partial body `dashboard.html` really posts from the Client Access modal."""

    def test_the_exact_dashboard_body_preserves_the_key(self, key_env):
        # dashboard.html: body: JSON.stringify({page_id: activePageId,
        #                                       monthly_token_limit: parseInt(limit)})
        r = _post("/api/pages/gemini_key", {"page_id": PAGE, "monthly_token_limit": 200000})
        assert r.status_code == 200, r.text
        row = _row()
        assert row["gemini_api_key"] == GEMINI_KEY, "one Save click destroyed the tenant's key"
        assert row["monthly_token_limit"] == 200000

    def test_the_modal_still_posts_no_key_field(self, key_env):
        """The dashboard was NOT changed for this fix; the server merge is what makes it safe.

        Pinning that keeps the two from drifting: if someone later makes the modal post a
        `gemini_api_key` it read from somewhere, this test says the assumption changed.
        """
        src = _dashboard_source()
        block = src[src.index("'/api/pages/gemini_key'"):]
        block = block[: block.index("});")]
        assert "monthly_token_limit" in block
        assert "gemini_api_key" not in block

    def test_the_dedicated_key_form_still_refuses_an_empty_key(self, key_env):
        src = _dashboard_source()
        block = src[src.index("async function saveClientCustomGeminiKey"):]
        block = block[: block.index("\n      }")]
        assert "if (!key)" in block, "the empty-key guard was removed from the key form"


# =========================================================================== F-54-3
class TestTheResponseTellsTheTruth:
    """`return True` unconditionally meant a failed write was reported as a success."""

    def test_a_missing_page_reports_not_written(self, key_env):
        r = _post(f"/api/pages/{MISSING_PAGE}/gemini_key",
                  {"page_id": MISSING_PAGE, "gemini_api_key": GEMINI_KEY_2})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["success"] is False
        assert body["written"] is False
        assert body["status"] == "error"

    def test_a_missing_page_creates_nothing(self, key_env):
        _post(f"/api/pages/{MISSING_PAGE}/gemini_key",
              {"page_id": MISSING_PAGE, "gemini_api_key": GEMINI_KEY_2})
        assert _page_exists(MISSING_PAGE) == 0

    def test_a_missing_page_writes_no_audit_row(self, key_env):
        """Scoped to the page id the failed write named, not to this module's page.

        Filtering by `PAGE` here would have passed no matter what the endpoint did, because a
        row for `MISSING_PAGE` carries that id as its `resource_id`.
        """
        before = len(_audit("%", MISSING_PAGE))
        _post(f"/api/pages/{MISSING_PAGE}/gemini_key",
              {"page_id": MISSING_PAGE, "gemini_api_key": GEMINI_KEY_2})
        rows = _audit("%", MISSING_PAGE)
        assert len(rows) == before, [r["action"] for r in rows[before:]]

    def test_a_real_write_reports_written(self, key_env):
        body = _post_key({"monthly_token_limit": OTHER_QUOTA}).json()
        assert body["success"] is True
        assert body["written"] is True
        assert body["status"] == "success"

    def test_the_database_function_itself_reports_rowcount(self, key_env):
        assert database.update_page_gemini_key(PAGE, GEMINI_KEY_2, QUOTA) is True
        assert database.update_page_gemini_key(MISSING_PAGE, GEMINI_KEY_2, QUOTA) is False

    def test_the_sheets_database_function_reports_rowcount(self, key_env):
        assert database.update_page_google_sheets(PAGE, SHEET_URL_2) is True
        assert database.update_page_google_sheets(MISSING_PAGE, SHEET_URL_2) is False

    def test_the_sheets_endpoint_reports_a_missing_page(self, key_env):
        r = _post(f"/api/pages/{MISSING_PAGE}/google_sheets",
                  {"page_id": MISSING_PAGE, "google_sheets_url": SHEET_URL})
        body = r.json()
        assert body["success"] is False
        assert body["written"] is False
        assert _page_exists(MISSING_PAGE) == 0

    def test_the_dashboard_contract_still_holds(self, key_env):
        """`saveClientCustomGeminiKey` branches on `data.status === 'success'`."""
        ok = _post_key({"gemini_api_key": GEMINI_KEY_2}).json()
        assert ok["status"] == "success"
        bad = _post(f"/api/pages/{MISSING_PAGE}/gemini_key",
                    {"page_id": MISSING_PAGE, "gemini_api_key": GEMINI_KEY_2}).json()
        assert bad["status"] != "success"
        assert bad.get("error"), "the failure branch must carry a message the UI can show"


# =========================================================================== audit
class TestTheChangeLeavesATrace:
    """This endpoint wrote no audit row at all, and the database function contains none."""

    def test_a_quota_change_is_audited(self, key_env):
        rows = _new_rows("page.gemini_key.%",
                         lambda: _post_key({"monthly_token_limit": OTHER_QUOTA}))
        assert len(rows) == 1
        assert rows[0]["action"] == "page.gemini_key.updated"

    def test_a_key_change_is_audited(self, key_env):
        rows = _new_rows("page.gemini_key.%",
                         lambda: _post_key({"gemini_api_key": GEMINI_KEY_2}))
        assert len(rows) == 1
        d = _details(rows[0])
        assert d["gemini_key_changed"] is True
        assert "gemini_api_key" in d["changed_fields"]

    def test_removing_the_key_is_audited_as_cleared(self, key_env):
        rows = _new_rows("page.gemini_key.%", lambda: _post_key({"gemini_api_key": ""}))
        assert len(rows) == 1
        assert rows[0]["action"] == "page.gemini_key.cleared"
        assert _details(rows[0])["has_gemini_key"] is False

    def test_a_save_that_changes_nothing_writes_no_row(self, key_env):
        rows = _new_rows("page.gemini_key.%",
                         lambda: _post_key({"gemini_api_key": GEMINI_KEY,
                                            "monthly_token_limit": QUOTA}))
        assert rows == []

    def test_a_mask_echo_writes_no_row(self, key_env):
        rows = _new_rows("page.gemini_key.%",
                         lambda: _post_key({"gemini_api_key": _mask_of(GEMINI_KEY)}))
        assert rows == []

    def test_the_row_names_the_actor_and_the_resource(self, key_env):
        rows = _new_rows("page.gemini_key.%",
                         lambda: _post_key({"monthly_token_limit": OTHER_QUOTA}))
        row = rows[0]
        assert row["actor_role"] == "admin"
        assert row["resource_id"] == PAGE
        assert row["resource_type"] == "page_gemini_key"

    def test_the_row_carries_the_quota_but_not_the_key(self, key_env):
        rows = _new_rows("page.gemini_key.%",
                         lambda: _post_key({"gemini_api_key": GEMINI_KEY_2,
                                            "monthly_token_limit": OTHER_QUOTA}))
        d = _details(rows[0])
        assert d["monthly_token_limit"] == OTHER_QUOTA
        assert d["has_gemini_key"] is True
        assert d["via"] == "api"

    def test_the_session_is_a_hash_prefix_not_a_token(self, key_env):
        rows = _new_rows("page.gemini_key.%",
                         lambda: _post_key({"monthly_token_limit": OTHER_QUOTA}))
        ref = _details(rows[0])["session_ref"]
        assert re.fullmatch(r"[0-9a-f]{12}", ref), "session_ref must be a 12-hex prefix"

    def test_two_saves_by_one_login_share_a_session_ref(self, key_env):
        """One token reused for both requests — `_post_key` logs in afresh each call, which is
        why this test drives the client directly."""
        headers = _headers()
        c = _client()
        before = len(_audit("page.gemini_key.%"))
        c.post(f"/api/pages/{PAGE}/gemini_key", headers=headers,
               json={"page_id": PAGE, "monthly_token_limit": OTHER_QUOTA})
        c.post(f"/api/pages/{PAGE}/gemini_key", headers=headers,
               json={"page_id": PAGE, "monthly_token_limit": QUOTA})
        rows = _audit("page.gemini_key.%")
        assert len(rows) == before + 2, "both saves changed something, so both are audited"
        refs = {_details(r)["session_ref"] for r in rows[before:]}
        assert len(refs) == 1, "one login must tie its rows together"

    def test_two_logins_produce_different_session_refs(self, key_env):
        """The other half of the property: the reference must actually distinguish logins."""
        first = _new_rows("page.gemini_key.%",
                          lambda: _post_key({"monthly_token_limit": OTHER_QUOTA}))
        second = _new_rows("page.gemini_key.%",
                           lambda: _post_key({"monthly_token_limit": QUOTA}))
        assert _details(first[0])["session_ref"] != _details(second[0])["session_ref"]

    def test_the_sheets_endpoint_is_deliberately_not_audited(self, key_env):
        """Recorded so the omission is a decision, not an oversight.

        A sheet URL is a knowledge source, not a credential and not an authorisation fact —
        the line Phase 53 drew for retention rules.
        """
        rows = _new_rows("%", lambda: _post_sheets({"google_sheets_url": SHEET_URL_2}))
        assert rows == []


# =========================================================================== masks
class TestAMaskIsNotAKey:
    """`gemini_api_key_masked = mask_secret(key, 4, 4)` — an echo must not be stored."""

    def test_a_bullet_mask_is_refused(self, key_env):
        _post_key({"gemini_api_key": _mask_of(GEMINI_KEY)})
        assert _row()["gemini_api_key"] == GEMINI_KEY

    def test_the_mask_is_named_in_the_response(self, key_env):
        body = _post_key({"gemini_api_key": _mask_of(GEMINI_KEY)}).json()
        assert body["mask_echoes"] == ["gemini_api_key"]
        assert body["changed"] == []

    def test_a_short_keys_mask_is_refused(self, key_env):
        """`mask_secret` returns eight asterisks when the value is too short to split."""
        database.update_page_gemini_key(PAGE, "SHORTKEY", QUOTA)
        assert _mask_of("SHORTKEY") == "*" * 8
        _post_key({"gemini_api_key": "*" * 8})
        assert _row()["gemini_api_key"] == "SHORTKEY"

    def test_a_mask_is_refused_even_when_nothing_is_stored(self, key_env):
        """The hole my own Phase 53 first fix shipped; pinned here from the start.

        The shape rules must not depend on a stored value existing, or clearing the field first
        lets a mask be stored as the credential.
        """
        database.update_page_gemini_key(PAGE, "", QUOTA)
        _post_key({"gemini_api_key": f"AIza{BULLET * 8}9999"})
        assert _row()["gemini_api_key"] == ""

    def test_a_key_containing_single_dots_is_still_stored(self, key_env):
        """Only the shapes this API actually shows are refused."""
        odd = "AIzaodd.key.with.dots.000000000"
        _post_key({"gemini_api_key": odd})
        assert _row()["gemini_api_key"] == odd

    def test_the_quota_is_not_mask_checked(self, key_env):
        body = _post_key({"monthly_token_limit": OTHER_QUOTA}).json()
        assert body["mask_echoes"] == []


# =========================================================================== quota
class TestTheQuotaIsNotSilentlyZeroed:
    """An unparseable or non-positive quota must not become a quota that blocks the tenant."""

    def test_an_unparseable_quota_keeps_the_stored_one(self, key_env):
        body = _post_key({"monthly_token_limit": "not-a-number"}).json()
        assert _row()["monthly_token_limit"] == QUOTA
        assert "monthly_token_limit" in body["ignored_fields"]

    def test_a_zero_quota_keeps_the_stored_one(self, key_env):
        _post_key({"monthly_token_limit": 0})
        assert _row()["monthly_token_limit"] == QUOTA

    def test_a_negative_quota_keeps_the_stored_one(self, key_env):
        _post_key({"monthly_token_limit": -500})
        assert _row()["monthly_token_limit"] == QUOTA

    def test_a_valid_quota_is_stored(self, key_env):
        body = _post_key({"monthly_token_limit": OTHER_QUOTA}).json()
        assert _row()["monthly_token_limit"] == OTHER_QUOTA
        assert body["ignored_fields"] == []

    def test_a_quota_sent_as_a_numeric_string_is_stored(self, key_env):
        _post_key({"monthly_token_limit": str(OTHER_QUOTA)})
        assert _row()["monthly_token_limit"] == OTHER_QUOTA

    def test_an_ignored_quota_writes_no_audit_row(self, key_env):
        rows = _new_rows("page.gemini_key.%",
                         lambda: _post_key({"monthly_token_limit": "garbage"}))
        assert rows == []


# =========================================================================== F-54-2
class TestTheSheetsUrlMergesToo:
    """An absent `google_sheets_url` cleared the tenant's knowledge source."""

    def test_an_absent_url_preserves_the_stored_one(self, key_env):
        r = _post_sheets({})
        assert r.status_code == 200, r.text
        assert _row()["google_sheets_url"] == SHEET_URL

    def test_a_body_naming_only_the_page_preserves_the_url(self, key_env):
        """The exact body measured to wipe the URL on the pre-fix tree."""
        _post_sheets({"page_id": PAGE})
        assert _row()["google_sheets_url"] == SHEET_URL

    def test_a_named_url_is_stored(self, key_env):
        _post_sheets({"google_sheets_url": SHEET_URL_2})
        assert _row()["google_sheets_url"] == SHEET_URL_2

    def test_an_explicit_empty_url_clears_it(self, key_env):
        body = _post_sheets({"google_sheets_url": ""}).json()
        assert _row()["google_sheets_url"] == ""
        assert "google_sheets_url" in body["cleared"]

    def test_the_ssrf_block_survives_the_merge(self, key_env):
        """`test_phase1_google_sheets_ssrf_blocked` pins a 400; the merge must not weaken it."""
        r = _post_sheets({"google_sheets_url": SSRF_URL})
        assert r.status_code == 400, r.text
        assert _row()["google_sheets_url"] == SHEET_URL, "a refused URL must not be stored"

    def test_a_non_google_host_is_still_refused(self, key_env):
        r = _post_sheets({"google_sheets_url": "https://example.invalid/sheet"})
        assert r.status_code == 400, r.text
        assert _row()["google_sheets_url"] == SHEET_URL

    def test_the_response_reports_the_stored_url(self, key_env):
        body = _post_sheets({}).json()
        assert body["success"] is True
        assert body["written"] is True
        assert body["google_sheets_url"] == SHEET_URL
        assert body["preserved"] == ["google_sheets_url"]


# =========================================================================== side effects
class TestSessionsAreResetOnlyWhenSomethingMoved:
    """A no-op save used to throw away every in-flight conversation for the tenant."""

    def test_a_changed_key_resets_sessions(self, key_env, monkeypatch):
        import main

        calls = []
        monkeypatch.setattr(main.agent, "reset_sessions", lambda *a, **k: calls.append(a))
        _post_key({"gemini_api_key": GEMINI_KEY_2})
        assert len(calls) == 1

    def test_a_no_op_save_does_not_reset_sessions(self, key_env, monkeypatch):
        import main

        calls = []
        monkeypatch.setattr(main.agent, "reset_sessions", lambda *a, **k: calls.append(a))
        _post_key({"gemini_api_key": GEMINI_KEY, "monthly_token_limit": QUOTA})
        assert calls == []

    def test_a_mask_echo_does_not_reset_sessions(self, key_env, monkeypatch):
        import main

        calls = []
        monkeypatch.setattr(main.agent, "reset_sessions", lambda *a, **k: calls.append(a))
        _post_key({"gemini_api_key": _mask_of(GEMINI_KEY)})
        assert calls == []

    def test_a_changed_sheet_url_resets_sessions(self, key_env, monkeypatch):
        import main

        calls = []
        monkeypatch.setattr(main.agent, "reset_sessions", lambda *a, **k: calls.append(a))
        _post_sheets({"google_sheets_url": SHEET_URL_2})
        assert len(calls) == 1


# =========================================================================== auth unchanged
class TestTheAuthorisationGateIsUnchanged:
    """Rewriting a handler is a chance to weaken its gate; these pin that it was not."""

    def test_an_unauthenticated_key_write_is_refused(self, key_env):
        r = _client().post(f"/api/pages/{PAGE}/gemini_key",
                           json={"page_id": PAGE, "gemini_api_key": GEMINI_KEY_2})
        assert r.status_code == 401, r.text
        assert _row()["gemini_api_key"] == GEMINI_KEY

    def test_an_unauthenticated_sheets_write_is_refused(self, key_env):
        r = _client().post(f"/api/pages/{PAGE}/google_sheets",
                           json={"page_id": PAGE, "google_sheets_url": SHEET_URL_2})
        assert r.status_code == 401, r.text
        assert _row()["google_sheets_url"] == SHEET_URL

    def test_a_missing_page_id_is_a_400(self, key_env):
        r = _post("/api/pages/gemini_key", {"gemini_api_key": GEMINI_KEY_2})
        assert r.status_code == 400, r.text


# =========================================================================== leaks
class TestNoSecretIsLeaked:
    """A claim that has to be checked, not assumed."""

    def test_no_response_carries_the_key(self, key_env):
        for payload in ({"gemini_api_key": GEMINI_KEY_2},
                        {"monthly_token_limit": OTHER_QUOTA},
                        {"gemini_api_key": ""},
                        {}):
            text = _post_key(payload).text
            for secret in SECRETS:
                assert secret not in text, payload

    def test_no_audit_row_carries_the_key_or_its_mask(self, key_env):
        _new_rows("page.gemini_key.%", lambda: _post_key({"gemini_api_key": GEMINI_KEY_2}))
        _new_rows("page.gemini_key.%", lambda: _post_key({"gemini_api_key": ""}))
        needles = list(SECRETS) + [_mask_of(s) for s in SECRETS] + [BULLET]
        for row in _audit("page.gemini_key.%"):
            blob = str(row.get("details_json") or row.get("details") or "")
            for needle in needles:
                assert needle not in blob, row["action"]

    def test_the_detail_endpoint_still_masks_the_key(self, key_env):
        r = _client().get(f"/api/pages/detail?page_id={PAGE}", headers=_headers())
        assert r.status_code == 200, r.text
        assert GEMINI_KEY not in r.text
        assert "gemini_api_key_masked" in r.json()

    def test_the_response_reports_names_not_values(self, key_env):
        import json

        body = _post_key({"gemini_api_key": GEMINI_KEY_2, "monthly_token_limit": OTHER_QUOTA}).json()
        for field in ("changed", "preserved", "cleared", "mask_echoes", "ignored_fields"):
            for name in body[field]:
                assert name in _allowed_names(), name
        assert GEMINI_KEY_2 not in json.dumps(body)


# =========================================================================== spec
class TestTheSpecIsWellFormed:
    """The spec is the contract; a malformed entry silently changes what merge means."""

    def test_every_spec_column_exists_on_the_row(self, key_env):
        import main

        row = _row()
        for spec in (main.GEMINI_SETTINGS_SPEC, main.SHEETS_SETTINGS_SPEC):
            for key, (column, default, coerce, mask_styles) in spec.items():
                assert column in row, f"{key} -> {column} is not a column of pages"
                assert callable(coerce), key

    def test_only_the_credential_carries_mask_styles(self, key_env):
        import main

        assert main.GEMINI_SETTINGS_SPEC["gemini_api_key"][3] == ("bullets",)
        assert main.GEMINI_SETTINGS_SPEC["monthly_token_limit"][3] is None
        assert main.SHEETS_SETTINGS_SPEC["google_sheets_url"][3] is None

    def test_the_quota_coercer_floors_at_zero(self, key_env):
        import main

        assert main._settings_quota(5000) == 5000
        assert main._settings_quota("5000") == 5000
        assert main._settings_quota(-1) == 0
        assert main._settings_quota("garbage") == 0
        assert main._settings_quota(None) == 0

    def test_the_specs_do_not_overlap_the_phase_53_ones(self, key_env):
        import main

        for spec in (main.GEMINI_SETTINGS_SPEC, main.SHEETS_SETTINGS_SPEC):
            for other in (main.EXECUTIVE_SETTINGS_SPEC, main.FINTECH_SETTINGS_SPEC,
                          main.RETENTION_RULE_SPEC):
                assert not (set(spec) & set(other)), "one payload key must map to one column"
