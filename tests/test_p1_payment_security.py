"""
P1 Payment Security Regression Tests:
1. P1-SEC-01: simulate-pay fail-closed & server-authoritative admin access control
2. P1-SEC-03: QPay callback fail-closed provider verification & idempotency
3. P1-SEC-05: Public invoice status PII leak prevention & allowlist schema
"""
import os
import sys
import time
import uuid
import unittest.mock

try:
    import pytest
except ImportError:  # script mode
    pytest = None
from typing import Dict, Any

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main
import database
import fintech_service
from core import security as core_security

client = TestClient(main.app)


def _setup_test_environment():
    database.init_db()
    # Create test pages
    database.save_page(page_id="p1_tenant_a", name="Tenant A Payments")
    database.save_page(page_id="p1_tenant_b", name="Tenant B Payments")
    database.set_client_credentials(
        page_id="p1_tenant_a",
        username="p1_client_a",
        password="Password123!",
    )
    database.set_client_credentials(
        page_id="p1_tenant_b",
        username="p1_client_b",
        password="Password123!",
    )


if pytest is not None:
    @pytest.fixture(autouse=True, scope="session")
    def _pytest_environment():
        """
        TD-03 (B-08): `_setup_test_environment()` used to run only inside the
        `if __name__ == "__main__":` block, so under pytest the tenant pages
        p1_tenant_a / p1_client_a never existed and 5 tests failed with a 401 that
        had nothing to do with payment security.

        Session-scoped and idempotent: CI runs this file both standalone and as part
        of the full `pytest tests/` invocation, and in PostgreSQL mode the rows may
        already be present.
        """
        _setup_test_environment()


def _get_admin_token() -> str:
    admin_pw = os.getenv("ADMIN_PASSWORD", database.DEFAULT_ADMIN_PASSWORD)
    resp = client.post("/api/auth/login", json={"type": "admin", "password": admin_pw})
    assert resp.status_code == 200, f"Admin login failed: {resp.text}"
    return resp.json()["token"]


def _get_client_token(username: str = "p1_client_a") -> str:
    resp = client.post("/api/auth/login", json={"type": "client", "identifier": username, "password": "Password123!"})
    assert resp.status_code == 200, f"Client login failed: {resp.text}"
    return resp.json()["token"]


# =========================================================================
# 1. P1-SEC-01: SIMULATE-PAY ACCESS CONTROL & FAIL-CLOSED TESTS
# =========================================================================

def test_simulate_pay_anonymous_denied():
    """Anonymous unauthenticated user must be denied (401)."""
    client.cookies.clear()
    inv = database.create_invoice(
        page_id="p1_tenant_a",
        amount=50000,
        description="Anon Sim Test",
        sender_id="anon_user",
    )
    inv_id = inv["invoice_id"]

    # In dev/test mode without auth
    os.environ["ENV"] = "test"
    os.environ["ENABLE_PAYMENT_SIMULATOR"] = "1"
    try:
        resp = client.post(f"/api/fintech/invoices/{inv_id}/simulate-pay")
        assert resp.status_code == 401, f"Expected 401 Unauthorized, got {resp.status_code}"
        # Assert invoice status was not modified
        fresh_inv = database.get_invoice(inv_id)
        assert fresh_inv["status"] == "PENDING"
    finally:
        os.environ.pop("ENV", None)
        os.environ.pop("ENABLE_PAYMENT_SIMULATOR", None)


def test_simulate_pay_client_user_denied():
    """Client authenticated user must be denied (403 Forbidden)."""
    inv = database.create_invoice(
        page_id="p1_tenant_a",
        amount=25000,
        description="Client Sim Test",
        sender_id="client_user",
    )
    inv_id = inv["invoice_id"]
    client_token = _get_client_token("p1_client_a")

    os.environ["ENV"] = "test"
    os.environ["ENABLE_PAYMENT_SIMULATOR"] = "1"
    try:
        resp = client.post(
            f"/api/fintech/invoices/{inv_id}/simulate-pay",
            headers={"Authorization": f"Bearer {client_token}"},
        )
        assert resp.status_code == 403, f"Expected 403 Forbidden for client, got {resp.status_code}"
        fresh_inv = database.get_invoice(inv_id)
        assert fresh_inv["status"] == "PENDING"
    finally:
        os.environ.pop("ENV", None)
        os.environ.pop("ENABLE_PAYMENT_SIMULATOR", None)


def test_simulate_pay_production_always_denied():
    """In production mode, simulator is strictly denied even for Admin with flag set."""
    inv = database.create_invoice(
        page_id="p1_tenant_a",
        amount=100000,
        description="Prod Sim Test",
        sender_id="prod_user",
    )
    inv_id = inv["invoice_id"]
    admin_token = _get_admin_token()

    os.environ["ENV"] = "production"
    os.environ["ENABLE_PAYMENT_SIMULATOR"] = "1"
    try:
        resp = client.post(
            f"/api/fintech/invoices/{inv_id}/simulate-pay",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 403, f"Expected 403 in production, got {resp.status_code}"
        assert "Production орчинд" in resp.json().get("error", "")
        fresh_inv = database.get_invoice(inv_id)
        assert fresh_inv["status"] == "PENDING"
    finally:
        os.environ.pop("ENV", None)
        os.environ.pop("ENABLE_PAYMENT_SIMULATOR", None)


def test_simulate_pay_default_deny_when_flag_missing():
    """Default state is DENY when flag is not set and ENV is not dev/test."""
    inv = database.create_invoice(
        page_id="p1_tenant_a",
        amount=30000,
        description="Flag Missing Test",
        sender_id="flag_user",
    )
    inv_id = inv["invoice_id"]
    admin_token = _get_admin_token()

    os.environ.pop("ENV", None)
    os.environ.pop("ENABLE_PAYMENT_SIMULATOR", None)

    resp = client.post(
        f"/api/fintech/invoices/{inv_id}/simulate-pay",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 403, f"Expected 403 Default Deny, got {resp.status_code}"
    fresh_inv = database.get_invoice(inv_id)
    assert fresh_inv["status"] == "PENDING"


def test_simulate_pay_cross_tenant_denied():
    """Admin/manager with tenant scope page_id=p1_tenant_b cannot simulate invoice of p1_tenant_a."""
    inv = database.create_invoice(
        page_id="p1_tenant_a",
        amount=40000,
        description="Cross Tenant Test",
        sender_id="cross_user",
    )
    inv_id = inv["invoice_id"]

    # Create scoped admin token for tenant B
    token_b = database.create_session(role="admin", page_id="p1_tenant_b")

    os.environ["ENV"] = "test"
    os.environ["ENABLE_PAYMENT_SIMULATOR"] = "1"
    try:
        resp = client.post(
            f"/api/fintech/invoices/{inv_id}/simulate-pay",
            headers={"Authorization": f"Bearer {token_b}"},
        )
        assert resp.status_code == 403, f"Expected 403 Cross-Tenant Denied, got {resp.status_code}"
        fresh_inv = database.get_invoice(inv_id)
        assert fresh_inv["status"] == "PENDING"
    finally:
        os.environ.pop("ENV", None)
        os.environ.pop("ENABLE_PAYMENT_SIMULATOR", None)


def test_simulate_pay_allowed_for_global_admin_in_dev_mode():
    """Global admin in dev/test mode with ENABLE_PAYMENT_SIMULATOR=1 can simulate payment."""
    inv = database.create_invoice(
        page_id="p1_tenant_a",
        amount=45000,
        description="Valid Sim Test",
        sender_id="valid_sim_user",
    )
    inv_id = inv["invoice_id"]
    admin_token = _get_admin_token()

    os.environ["ENV"] = "test"
    os.environ["ENABLE_PAYMENT_SIMULATOR"] = "1"
    try:
        resp = client.post(
            f"/api/fintech/invoices/{inv_id}/simulate-pay",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert data["success"] is True
        fresh_inv = database.get_invoice(inv_id)
        assert fresh_inv["status"] == "PAID"
    finally:
        os.environ.pop("ENV", None)
        os.environ.pop("ENABLE_PAYMENT_SIMULATOR", None)


# =========================================================================
# 2. P1-SEC-03: QPAY CALLBACK FAIL-CLOSED VERIFICATION & IDEMPOTENCY TESTS
# =========================================================================

def test_qpay_callback_missing_credentials_fails_closed():
    """When merchant has no QPay credentials configured, callback fails closed (400) and invoice remains PENDING."""
    database.save_page(page_id="p1_tenant_no_qpay", name="Tenant Without QPay")
    database.update_page_qpay_settings(
        page_id="p1_tenant_no_qpay",
        username="",
        password="",
        invoice_code="",
    )
    inv = database.create_invoice(
        page_id="p1_tenant_no_qpay",
        amount=70000,
        description="Missing Cred Callback Test",
        sender_id="cred_user",
    )
    inv_id = inv["invoice_id"]

    # Clear environment credentials and mock allowance
    os.environ.pop("QPAY_USERNAME", None)
    os.environ.pop("QPAY_PASSWORD", None)
    os.environ.pop("ALLOW_MOCK_QPAY_CALLBACK", None)

    resp = client.post(
        "/api/fintech/qpay/callback",
        json={"invoice_id": inv_id, "object_id": "test_obj_123"},
    )
    assert resp.status_code == 400, f"Expected 400 for missing credentials, got {resp.status_code}: {resp.text}"
    assert "PROVIDER_VERIFICATION_REQUIRED" in resp.text

    # Database assertion: invoice must NOT be paid
    fresh_inv = database.get_invoice(inv_id)
    assert fresh_inv["status"] == "PENDING"


def test_qpay_callback_provider_auth_failure_preserves_pending():
    """If provider OAuth token endpoint fails, callback fails closed and invoice remains PENDING."""
    inv = database.create_invoice(
        page_id="p1_tenant_a",
        amount=80000,
        description="Auth Fail Callback Test",
        sender_id="auth_user",
    )
    inv_id = inv["invoice_id"]

    # Configure credentials on page
    database.update_page_qpay_settings(
        page_id="p1_tenant_a",
        username="qpay_test_merchant",
        password="qpay_test_password",
        invoice_code="TEST_INVOICE_CODE",
    )

    # Mock get_qpay_token returning None (auth failure)
    with unittest.mock.patch("fintech_service.get_qpay_token", return_value=None):
        resp = client.post(
            "/api/fintech/qpay/callback",
            json={"invoice_id": inv_id, "object_id": "obj_auth_fail"},
        )
        assert resp.status_code == 400
        assert "PROVIDER_AUTH_FAILED" in resp.text
        fresh_inv = database.get_invoice(inv_id)
        assert fresh_inv["status"] == "PENDING"


def test_qpay_callback_provider_verification_failure_preserves_pending():
    """If provider check returns verified=False, callback rejects and invoice remains PENDING."""
    inv = database.create_invoice(
        page_id="p1_tenant_a",
        amount=90000,
        description="Verification Fail Callback Test",
        sender_id="ver_user",
    )
    inv_id = inv["invoice_id"]

    database.update_page_qpay_settings(
        page_id="p1_tenant_a",
        username="qpay_test_merchant",
        password="qpay_test_password",
        invoice_code="TEST_INVOICE_CODE",
    )

    with unittest.mock.patch("fintech_service.get_qpay_token", return_value="mock_access_token_123"), \
         unittest.mock.patch("fintech_service.check_qpay_payment_live_detailed", return_value={"verified": False}):
        resp = client.post(
            "/api/fintech/qpay/callback",
            json={"invoice_id": inv_id, "object_id": "obj_ver_fail"},
        )
        assert resp.status_code == 400
        assert "FAILED_VERIFICATION" in resp.text
        fresh_inv = database.get_invoice(inv_id)
        assert fresh_inv["status"] == "PENDING"


def test_qpay_callback_amount_mismatch_preserves_pending():
    """If provider check reports an amount less than invoice amount, verification fails and status is PENDING."""
    inv = database.create_invoice(
        page_id="p1_tenant_a",
        amount=100000,
        description="Amount Mismatch Test",
        sender_id="amt_user",
    )
    inv_id = inv["invoice_id"]

    database.update_page_qpay_settings(
        page_id="p1_tenant_a",
        username="qpay_test_merchant",
        password="qpay_test_password",
        invoice_code="TEST_INVOICE_CODE",
    )

    # Provider reports only 50000 paid for a 100000 invoice
    with unittest.mock.patch("fintech_service.get_qpay_token", return_value="mock_access_token_123"), \
         unittest.mock.patch("fintech_service.check_qpay_payment_live_detailed", return_value={"verified": False, "paid_amount": 50000}):
        resp = client.post(
            "/api/fintech/qpay/callback",
            json={"invoice_id": inv_id, "object_id": "obj_amt_mismatch"},
        )
        assert resp.status_code == 400
        assert "FAILED_VERIFICATION" in resp.text
        fresh_inv = database.get_invoice(inv_id)
        assert fresh_inv["status"] == "PENDING"


def test_qpay_callback_verified_success_and_idempotent_duplicate():
    """When provider verification succeeds, marks invoice PAID. Subsequent duplicate returns 200 SUCCESS idempotently."""
    inv = database.create_invoice(
        page_id="p1_tenant_a",
        amount=60000,
        description="Verified Success Test",
        sender_id="succ_user",
    )
    inv_id = inv["invoice_id"]

    database.update_page_qpay_settings(
        page_id="p1_tenant_a",
        username="qpay_test_merchant",
        password="qpay_test_password",
        invoice_code="TEST_INVOICE_CODE",
    )

    mock_check_result = {
        "verified": True,
        "provider_payment_id": "QPAY_TX_998877",
        "paid_amount": 60000,
        "currency": "MNT",
    }

    with unittest.mock.patch("fintech_service.get_qpay_token", return_value="mock_access_token_123"), \
         unittest.mock.patch("fintech_service.check_qpay_payment_live_detailed", return_value=mock_check_result):

        # First callback: genuinely confirms payment
        resp1 = client.post(
            "/api/fintech/qpay/callback",
            json={"invoice_id": inv_id, "object_id": "obj_succ_1"},
        )
        assert resp1.status_code == 200
        assert resp1.text == "SUCCESS"

        fresh_inv = database.get_invoice(inv_id)
        assert fresh_inv["status"] == "PAID"
        assert fresh_inv["provider_payment_id"] == "QPAY_TX_998877"
        assert fresh_inv["callback_verified"] == 1
        initial_paid_at = fresh_inv["paid_at"]

        # Duplicate callback: must return 200 SUCCESS idempotently without duplicate side-effects
        resp2 = client.post(
            "/api/fintech/qpay/callback",
            json={"invoice_id": inv_id, "object_id": "obj_succ_1"},
        )
        assert resp2.status_code == 200
        assert resp2.text == "SUCCESS"

        fresh_inv_2 = database.get_invoice(inv_id)
        assert fresh_inv_2["status"] == "PAID"
        assert fresh_inv_2["paid_at"] == initial_paid_at


# =========================================================================
# 3. P1-SEC-05: PUBLIC INVOICE STATUS PII PROTECTION TESTS
# =========================================================================

def test_public_invoice_status_filters_pii():
    """Public /api/fintech/invoices/{id}/status response must NEVER leak sender_id, customer phone, or internal notes."""
    client.cookies.clear()
    inv = database.create_invoice(
        page_id="p1_tenant_a",
        amount=120000,
        description="Confidential Medical Service",
        sender_id="sensitive_fb_user_99887766",
        channel="facebook",
    )
    inv_id = inv["invoice_id"]

    # Public unauthenticated request
    resp = client.get(f"/api/fintech/invoices/{inv_id}/status")
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "PENDING"
    inv_data = data["invoice"]

    # Public fields MUST be present
    assert inv_data["invoice_id"] == inv_id
    assert inv_data["amount"] == 120000
    assert inv_data["currency"] == "MNT"
    assert inv_data["description"] == "Confidential Medical Service"
    assert "status" in inv_data
    assert "ebarimt_lottery" in inv_data
    assert "ebarimt_qr" in inv_data

    # PII and private fields MUST NOT be present in public view
    assert "sender_id" not in inv_data, "PII Leak: sender_id must not be exposed in public response!"
    assert "customer_phone" not in inv_data
    assert "phone" not in inv_data
    assert "raw_payload" not in inv_data
    assert "metadata" not in inv_data


def test_authorized_admin_invoice_status_retains_full_details():
    """Authorized admin or tenant manager retains access to full operational invoice data."""
    inv = database.create_invoice(
        page_id="p1_tenant_a",
        amount=150000,
        description="Internal Service",
        sender_id="internal_client_uuid_12345",
        channel="web",
    )
    inv_id = inv["invoice_id"]
    admin_token = _get_admin_token()

    resp = client.get(
        f"/api/fintech/invoices/{inv_id}/status",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    inv_data = data["invoice"]

    # Authorized admin CAN view full operational sender_id
    assert inv_data["sender_id"] == "internal_client_uuid_12345"
    assert inv_data["amount"] == 150000


def test_payment_page_html_renders_without_breaking():
    """Ensure GET /pay/{invoice_id} renders cleanly with updated sanitized structure."""
    inv = database.create_invoice(
        page_id="p1_tenant_a",
        amount=85000,
        description="Dental Examination",
        sender_id="pat_123",
    )
    inv_id = inv["invoice_id"]

    resp = client.get(f"/pay/{inv_id}")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert inv_id in resp.text
    assert "Dental Examination" in resp.text
    assert "85,000" in resp.text or "85000" in resp.text


# =========================================================================
# MAIN TEST RUNNER
# =========================================================================

if __name__ == "__main__":
    print("=== RUNNING P1 PAYMENT SECURITY REGRESSION TESTS ===")
    _setup_test_environment()

    print("\n--- 1. P1-SEC-01 Simulate-Pay Tests ---")
    test_simulate_pay_anonymous_denied()
    print("[PASS] test_simulate_pay_anonymous_denied")
    test_simulate_pay_client_user_denied()
    print("[PASS] test_simulate_pay_client_user_denied")
    test_simulate_pay_production_always_denied()
    print("[PASS] test_simulate_pay_production_always_denied")
    test_simulate_pay_default_deny_when_flag_missing()
    print("[PASS] test_simulate_pay_default_deny_when_flag_missing")
    test_simulate_pay_cross_tenant_denied()
    print("[PASS] test_simulate_pay_cross_tenant_denied")
    test_simulate_pay_allowed_for_global_admin_in_dev_mode()
    print("[PASS] test_simulate_pay_allowed_for_global_admin_in_dev_mode")

    print("\n--- 2. P1-SEC-03 QPay Callback Tests ---")
    test_qpay_callback_missing_credentials_fails_closed()
    print("[PASS] test_qpay_callback_missing_credentials_fails_closed")
    test_qpay_callback_provider_auth_failure_preserves_pending()
    print("[PASS] test_qpay_callback_provider_auth_failure_preserves_pending")
    test_qpay_callback_provider_verification_failure_preserves_pending()
    print("[PASS] test_qpay_callback_provider_verification_failure_preserves_pending")
    test_qpay_callback_amount_mismatch_preserves_pending()
    print("[PASS] test_qpay_callback_amount_mismatch_preserves_pending")
    test_qpay_callback_verified_success_and_idempotent_duplicate()
    print("[PASS] test_qpay_callback_verified_success_and_idempotent_duplicate")

    print("\n--- 3. P1-SEC-05 Public Invoice Status PII Tests ---")
    test_public_invoice_status_filters_pii()
    print("[PASS] test_public_invoice_status_filters_pii")
    test_authorized_admin_invoice_status_retains_full_details()
    print("[PASS] test_authorized_admin_invoice_status_retains_full_details")
    test_payment_page_html_renders_without_breaking()
    print("[PASS] test_payment_page_html_renders_without_breaking")

    print("\n=== ALL 14 P1 PAYMENT SECURITY TESTS PASSED 100% ===")
