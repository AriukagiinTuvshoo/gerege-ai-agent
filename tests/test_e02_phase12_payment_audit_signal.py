"""
Stage E — E-03 Phase 2: the payment audit signal must reach a caller (finding F-B).

Phase 11 made a failed `payment.confirmed` audit write loud *inside*
`fintech_service`: it logs `AUDIT LOSS` with `exc_info=True` and returns
`audit_recorded`. Phase 12 found that nothing ever read that field —

    grep -rn "audit_recorded" --include=*.py .   ->  ONE hit, the producer

— and that both callers discarded the return value entirely. The QPay webhook did:

    await fintech_service.process_successful_payment(...)   # result discarded
    return Response("SUCCESS")

so the only trace of a settled-but-unaudited payment was a log line nobody was
watching, on a path that answered 200 either way.

These tests pin three separate things, because "F-B is fixed" is ambiguous:

  1. SHAPE    — `audit_recorded` is present on every return path, so a caller can
                never mistake a missing key for a good outcome.
  3. MEANING  — True / False / None are distinguishable and mean what they say.
  2. WIRING   — both callers actually read it and report the loss.

The payment semantics themselves are NOT changed and are asserted to be unchanged:
money that has moved stays moved, the HTTP answer stays 200, and an audit failure
never turns a successful payment into a failed one. That is a deliberate constraint
of this phase, not an oversight.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402
from core import account_keys  # noqa: E402

TEST_SECRET = "e03-phase2-test-secret-0123456789abcdef0123"


@pytest.fixture()
def db(tmp_path, monkeypatch):
    db_url = (os.getenv("DATABASE_URL") or "").strip()
    require_pg = (os.getenv("R10_REQUIRE_POSTGRES") or "").strip() == "1"

    if db_url:
        monkeypatch.setenv("DATABASE_URL", db_url)
    else:
        if require_pg:
            pytest.fail("R10_REQUIRE_POSTGRES=1 but DATABASE_URL is unset")
        monkeypatch.delenv("DATABASE_URL", raising=False)
        path = tmp_path / "e03p2.db"
        monkeypatch.setenv("DB_PATH", str(path))
        monkeypatch.setattr(database, "DB_PATH", str(path))

    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()
    database.init_db()

    conn = database.get_connection()
    try:
        # Phase 13: append-only table; clear through the test-only helper.
        from conftest import clear_audit_logs_for_test

        clear_audit_logs_for_test(conn)
    finally:
        conn.close()
    return database


@pytest.fixture()
def client(db, monkeypatch):
    """An admin client that is allowed to reach the payment simulator."""
    from fastapi.testclient import TestClient

    import main

    monkeypatch.setenv("ENV", "test")
    monkeypatch.setenv("ENABLE_PAYMENT_SIMULATOR", "1")

    test_client = TestClient(main.app, raise_server_exceptions=False)
    token = database.create_session(role="admin", page_id=database.DEFAULT_PAGE_ID)
    test_client.headers.update({"Authorization": f"Bearer {token}"})
    return test_client


@pytest.fixture()
def audit_loss_reports():
    """Capture the AUDIT LOSS lines the caller-side reporter emits.

    Deliberately not built on `monkeypatch`: `monkeypatch` unwinds in LIFO order
    relative to other fixtures, and an earlier version of this fixture restored the
    logger's level *after* the next test had already installed its own handler, which
    made unrelated tests in this file fail when run together but pass alone. An
    explicit try/finally has no ordering dependency.
    """
    import logging

    captured = []

    class Handler(logging.Handler):
        def emit(self, record):
            captured.append(record.getMessage())

    logger = logging.getLogger("fintech_service")
    handler = Handler()
    previous_level = logger.level
    previous_propagate = logger.propagate
    # `migrations/env.py` calls `logging.config.fileConfig(...)`, which defaults to
    # `disable_existing_loggers=True`. Every `init_db()` therefore disables any logger
    # that already exists, so a test that captures this logger must re-enable it or
    # it silently captures nothing depending on which test ran first. See the audit
    # record for this phase: the same hazard applies to production if the import order
    # in `main.py` is ever changed.
    #
    # Phase 50 measured that production case and fixed it at the source (F-50-4): a first
    # boot left 10 of 15 application loggers disabled, `agent` among them. `env.py` now
    # skips logging configuration for programmatic callers and never disables existing
    # loggers; see tests/test_e50_migration_logging_truth.py. This fixture keeps the
    # defensive re-enable, so it stays correct whichever way the global state lands.
    previous_disabled = logger.disabled
    logger.addHandler(handler)
    logger.setLevel(logging.ERROR)
    logger.propagate = False
    logger.disabled = False
    try:
        yield captured
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
        logger.propagate = previous_propagate
        logger.disabled = previous_disabled


def _invoice(page_id=None):
    page_id = page_id or database.DEFAULT_PAGE_ID
    return database.create_invoice(
        page_id=page_id, amount=1000, description="E-03", sender_id="e03_user"
    )["invoice_id"]


def _fail_audit(monkeypatch):
    def boom(*args, **kwargs):
        raise database.AuditLogWriteError(
            args[0] if args else "payment.confirmed", RuntimeError("audit store down")
        )

    monkeypatch.setattr(database, "record_audit_log", boom)


# ===========================================================================
# 1. SHAPE — every return path carries the field
# ===========================================================================


def test_2001_every_return_path_carries_audit_recorded(client, db, audit_loss_reports):
    """
    Pre-fix: only the full-success return had the key. A caller checking
    `result["audit_recorded"]` would raise KeyError on the two replay paths and on
    the not-found path — so the "signal" was unusable exactly where it mattered.
    """
    settled = _invoice()
    first = client.post(f"/api/fintech/invoices/{settled}/simulate-pay").json()
    assert "audit_recorded" in first

    replay = client.post(f"/api/fintech/invoices/{settled}/simulate-pay").json()
    assert "audit_recorded" in replay, "the already-PAID path must carry the field too"

    locked = _invoice()
    database.claim_notification_lock(
        f"qpay_paid:{locked}", page_id=database.DEFAULT_PAGE_ID, channel="qpay"
    )
    guard = client.post(f"/api/fintech/invoices/{locked}/simulate-pay").json()
    assert "audit_recorded" in guard, "the replay-guard path must carry the field too"


def test_2002_not_found_path_carries_audit_recorded(db):
    """
    The `success: False` path must also be explicit: `None`, never a missing key.

    Asserted at the *service* boundary, because the simulator endpoint checks the
    invoice itself and answers 404 before the service is ever called. That early
    return is the correct behaviour (no money, no audit) and is pinned separately.
    """
    import asyncio

    import fintech_service

    body = asyncio.run(
        fintech_service.process_successful_payment("INV-DOES-NOT-EXIST", provider_payment_id="X")
    )
    assert body.get("success") is False
    assert "audit_recorded" in body
    assert body["audit_recorded"] is None


def test_2003_the_endpoint_rejects_an_unknown_invoice_before_the_service_runs(client, db):
    """The 404 happens upstream of the service, so no audit is attempted at all."""
    body = client.post("/api/fintech/invoices/INV-DOES-NOT-EXIST/simulate-pay").json()
    assert body.get("success") is False
    assert body.get("error"), "the admin gets a reason, not a fabricated audit field"

    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM audit_logs WHERE action = 'payment.confirmed'")
        assert int(cur.fetchone()[0]) == 0
    finally:
        conn.close()


# ===========================================================================
# 2. MEANING — the three states mean what they say
# ===========================================================================


def test_2011_settling_call_reports_true_when_the_audit_row_was_written(client, db):
    inv = _invoice()
    body = client.post(f"/api/fintech/invoices/{inv}/simulate-pay").json()

    assert body["success"] is True
    assert body["audit_recorded"] is True, "a written audit must report True, not None"

    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM audit_logs WHERE action = 'payment.confirmed'")
        assert int(cur.fetchone()[0]) == 1
    finally:
        conn.close()


def test_2012_settling_call_reports_false_when_the_audit_row_was_not_written(
    client, db, monkeypatch, audit_loss_reports
):
    """
    The case F-B is about. Pre-fix the payment still succeeded — correctly — but the
    information died inside the service. Post-fix it is returned AND reported.
    """
    inv = _invoice()
    _fail_audit(monkeypatch)

    body = client.post(f"/api/fintech/invoices/{inv}/simulate-pay").json()

    assert body["success"] is True, "a lost audit must never turn a paid invoice into a failure"
    assert body["audit_recorded"] is False
    assert db.get_invoice(inv)["status"] == "PAID", "money moved; the invoice stays PAID"
    assert any("AUDIT LOSS" in m for m in audit_loss_reports), (
        "the caller must report the loss, not just the service"
    )


def test_2013_replay_paths_report_none_because_no_audit_was_expected(client, db, audit_loss_reports):
    """
    `None` is not a failure and must not be alarmed on. Writing `payment.confirmed`
    on a replay would fabricate a second confirmation for one payment, which is worse
    than not writing it — so the correct signal is "nothing to record", not False.
    """
    inv = _invoice()
    client.post(f"/api/fintech/invoices/{inv}/simulate-pay")
    audit_loss_reports.clear()

    replay = client.post(f"/api/fintech/invoices/{inv}/simulate-pay").json()

    assert replay["success"] is True
    assert replay["audit_recorded"] is None, (
        "a replay recorded nothing, but that is not an audit LOSS"
    )
    assert not any("AUDIT LOSS" in m for m in audit_loss_reports), (
        "reporting an audit loss for a replay would train operators to ignore the alarm"
    )


def test_2014_replay_does_not_double_write_the_audit_row(client, db):
    """The policy on the replay path has a second half: no second row."""
    inv = _invoice()
    client.post(f"/api/fintech/invoices/{inv}/simulate-pay")
    client.post(f"/api/fintech/invoices/{inv}/simulate-pay")

    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM audit_logs WHERE action = 'payment.confirmed'")
        assert int(cur.fetchone()[0]) == 1, "one payment, one confirmation record"
    finally:
        conn.close()


# ===========================================================================
# 3. WIRING — the callers read it
# ===========================================================================


def test_2021_report_audit_outcome_is_true_for_recorded_and_not_expected():
    import fintech_service

    assert fintech_service.report_audit_outcome({"audit_recorded": True}, caller="t") is True
    assert fintech_service.report_audit_outcome({"audit_recorded": None}, caller="t") is True


def test_2022_report_audit_outcome_is_false_and_logs_for_a_lost_audit(audit_loss_reports):
    import fintech_service

    result = fintech_service.report_audit_outcome(
        {"audit_recorded": False, "invoice": {"invoice_id": "INV-X"}}, caller="unit"
    )
    assert result is False
    messages = [m for m in audit_loss_reports if "AUDIT LOSS" in m]
    assert messages, "a False audit outcome must always be reported"
    assert "INV-X" in messages[0], "the report must name the invoice an operator has to reconcile"
    assert "unit" in messages[0], "the report must name which caller lost it"


def test_2023_qpay_callback_does_not_answer_non_200_when_the_audit_is_lost(db, monkeypatch):
    """
    The webhook contract: QPay retries anything that is not 200. A retry cannot make
    the audit store accept a row it refused, and re-driving a settled payment is
    strictly worse than recording the gap. So the answer stays SUCCESS/200 and the
    reconciliation burden lands where an operator can act on it.
    """
    import asyncio

    import fintech_service

    inv = _invoice()
    _fail_audit(monkeypatch)

    result = asyncio.run(
        fintech_service.process_successful_payment(inv, provider_payment_id="X", callback_verified=0)
    )
    # The service reports the gap and still reports the payment as settled...
    assert result["success"] is True
    assert result["audit_recorded"] is False
    # ...and the caller-side reporter is what decides the operator-facing outcome.
    assert fintech_service.report_audit_outcome(result, caller="qpay_callback") is False
    assert db.get_invoice(inv)["status"] == "PAID"


def test_2024_reporting_never_masks_a_payment_that_actually_failed(audit_loss_reports):
    """Negative control: a failed payment must not be reported as an audit loss.

    A missing invoice means no money moved and no audit was expected, so the reporter
    must stay silent. Alarming here would make the real alarm indistinguishable from
    routine noise — the failure mode that made F-B invisible in the first place.
    """
    import fintech_service

    result = {"success": False, "message": "not found", "audit_recorded": None}
    assert fintech_service.report_audit_outcome(result, caller="unit") is True
    assert not [m for m in audit_loss_reports if "AUDIT LOSS" in m]
