"""
P0-1 Security Remediation Tests: Client Role Privilege Escalation Prevention.
Verifies that client logins cannot define or escalate roles via request payloads,
magic links remain strictly client-scoped, admin logins work properly,
and tenant isolation is strictly enforced against cross-tenant data access.
"""
import os
import sys
try:
    import pytest
except ImportError:
    pytest = None
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main
import database
from core import security as core_security

client = TestClient(main.app)


def _setup_tenants_and_credentials():
    database.init_db()
    # Setup Tenant A
    database.save_page(
        page_id="p0_tenant_a",
        name="Tenant A Corp",
        category="retail",
    )
    database.set_client_credentials(
        page_id="p0_tenant_a",
        username="tenant_a_user",
        password="Password123!",
    )

    # Setup Tenant B
    database.save_page(
        page_id="p0_tenant_b",
        name="Tenant B Corp",
        category="cargo",
    )
    database.set_client_credentials(
        page_id="p0_tenant_b",
        username="tenant_b_user",
        password="Password123!",
    )


if pytest is not None:
    @pytest.fixture(autouse=True)
    def setup_tenants_and_credentials():
        _setup_tenants_and_credentials()


def test_client_cannot_escalate_role_via_login_payload():
    """Client attempting to pass 'role: manager' in payload must still receive 'client' role."""
    resp = client.post(
        "/api/auth/login",
        json={
            "type": "client",
            "identifier": "tenant_a_user",
            "password": "Password123!",
            "role": "manager",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["role"] == "client", "Client payload must NEVER escalate to manager"

    token = data["token"]
    session = database.get_session(token)
    assert session is not None
    assert session["role"] == "client"

    # Verify session token cannot perform manager-only action if restricted
    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["role"] == "client"


def test_client_login_defaults_to_client_role():
    """Client login without role specification defaults to 'client'."""
    resp = client.post(
        "/api/auth/login",
        json={
            "type": "client",
            "identifier": "tenant_a_user",
            "password": "Password123!",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["role"] == "client"


def test_manager_role_requires_server_side_authorization():
    """Attempting to request roles like 'super_admin', 'admin', 'manager', 'warehouse_staff' fails to escalate."""
    for illicit_role in ["super_admin", "admin", "manager", "warehouse_staff", "agent"]:
        resp = client.post(
            "/api/auth/login",
            json={
                "type": "client",
                "identifier": "tenant_a_user",
                "password": "Password123!",
                "role": illicit_role,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["role"] == "client", f"Role '{illicit_role}' must not be granted via client login payload"


def test_admin_login_remains_unchanged():
    """Admin login with valid password creates an admin session."""
    orig_pw = database.DEFAULT_ADMIN_PASSWORD
    resp = client.post(
        "/api/auth/login",
        json={
            "type": "admin",
            "password": orig_pw,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["role"] == "admin"
    assert data["page_id"] is None


def test_magic_token_remains_client_scoped():
    """Magic link token authentication always produces a 'client' role session."""
    page_a = database.get_page("p0_tenant_a")
    magic_token = page_a["client_magic_token"]
    assert magic_token

    resp = client.post(
        "/api/auth/login",
        json={
            "type": "magic",
            "token": magic_token,
            "role": "manager",  # Trying to escalate via magic link
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["role"] == "client", "Magic token must always be scoped to 'client'"


def test_tenant_a_cannot_access_tenant_b_data():
    """Cross-tenant data access integration test: Tenant A user cannot read or write Tenant B leads."""
    # Login as Tenant A
    login_a = client.post(
        "/api/auth/login",
        json={
            "type": "client",
            "identifier": "tenant_a_user",
            "password": "Password123!",
        },
    )
    assert login_a.status_code == 200
    token_a = login_a.json()["token"]

    # Create lead in Tenant B
    database.save_registration(
        page_id="p0_tenant_b",
        name="Confidential Customer B",
        phone="99887766",
        service="Cargo Import",
        sender_id="user_b_1",
    )

    # Tenant A attempts to fetch Tenant B leads via query parameter
    resp_cross = client.get(
        "/api/leads?page_id=p0_tenant_b",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert resp_cross.status_code == 403, "Cross-tenant access must return 403 Forbidden"
    assert "Cross-tenant access denied" in resp_cross.json().get("detail", "")

    # Tenant A fetching own leads succeeds
    resp_own = client.get(
        "/api/leads?page_id=p0_tenant_a",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert resp_own.status_code == 200
    res_data = resp_own.json()
    leads_list = res_data.get("data", res_data if isinstance(res_data, list) else [])
    assert isinstance(leads_list, list)
    for lead in leads_list:
        assert lead.get("page_id") == "p0_tenant_a"


if __name__ == "__main__":
    print("=== RUNNING P0-1 SECURITY ROLE ESCALATION TESTS ===")
    _setup_tenants_and_credentials()
    test_client_cannot_escalate_role_via_login_payload()
    print("[PASS] test_client_cannot_escalate_role_via_login_payload")
    test_client_login_defaults_to_client_role()
    print("[PASS] test_client_login_defaults_to_client_role")
    test_manager_role_requires_server_side_authorization()
    print("[PASS] test_manager_role_requires_server_side_authorization")
    test_admin_login_remains_unchanged()
    print("[PASS] test_admin_login_remains_unchanged")
    test_magic_token_remains_client_scoped()
    print("[PASS] test_magic_token_remains_client_scoped")
    test_tenant_a_cannot_access_tenant_b_data()
    print("[PASS] test_tenant_a_cannot_access_tenant_b_data")
    print("=== ALL P0-1 TESTS PASSED 100% ===")
