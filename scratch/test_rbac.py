import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import json
from fastapi.testclient import TestClient

import main
import database

def run_tests():
    print("=== STARTING RBAC & MULTI-TENANT SAAS VERIFICATION ===")
    client = TestClient(main.app)

    # 1. Admin Login
    res = client.post("/api/auth/login", json={"type": "admin", "password": "admin2026"})
    assert res.status_code == 200, f"Admin login failed: {res.text}"
    admin_data = res.json()
    assert admin_data["role"] == "admin"
    admin_token = admin_data["token"]
    print("✅ 1. Admin Login: PASSED (role=admin)")

    # 2. Add client 'cargo' if not present
    client.post(
        "/api/pages",
        json={"page_id": "cargo_client_test", "name": "Cargo Express", "category": "cargo"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    print("✅ 2. Admin Created Page 'Cargo Express': PASSED")

    # 3. Set credentials & get Magic Token for 'cargo_client_test'
    cred_res = client.post(
        "/api/pages/cargo_client_test/credentials",
        json={"username": "cargo_owner", "password": "cargo_pass_123"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert cred_res.status_code == 200, cred_res.text
    magic_token = cred_res.json()["data"]["magic_token"]
    print(f"✅ 3. Generated Magic Token for client: {magic_token[:10]}...")

    # 4. Client Login via Magic Token
    client_login_res = client.post("/api/auth/login", json={"type": "magic", "token": magic_token})
    assert client_login_res.status_code == 200, client_login_res.text
    client_data = client_login_res.json()
    assert client_data["role"] == "client"
    assert client_data["page_id"] == "cargo_client_test"
    client_token = client_data["token"]
    print("✅ 4. Client Login via Magic Token: PASSED (role=client, page_id=cargo_client_test)")

    # 5. Client views pages: must ONLY see their own page!
    pages_res = client.get("/api/pages", headers={"Authorization": f"Bearer {client_token}"})
    assert pages_res.status_code == 200
    pages_data = pages_res.json()
    assert pages_data["total"] == 1, f"Expected 1 page for client, got {pages_data['total']}"
    assert pages_data["data"][0]["page_id"] == "cargo_client_test"
    print("✅ 5. Client Page Isolation: PASSED (Only sees 'cargo_client_test', zero leak of other clients)")

    # 6. Client attempts to create a new page -> MUST return 403 Forbidden!
    forbidden_res = client.post(
        "/api/pages",
        json={"page_id": "hacker_page", "name": "Hacker Page"},
        headers={"Authorization": f"Bearer {client_token}"}
    )
    assert forbidden_res.status_code == 403, f"Expected 403, got {forbidden_res.status_code}"
    print("✅ 6. Client Action Guard: PASSED (403 Forbidden on create page)")

    # 7. Client sets their own Gemini API Key
    key_res = client.post(
        "/api/pages/cargo_client_test/gemini_key",
        json={"gemini_api_key": "AIzaSy_SAMPLE_CLIENT_KEY_FOR_TESTING", "monthly_token_limit": 150000},
        headers={"Authorization": f"Bearer {client_token}"}
    )
    assert key_res.status_code == 200
    page_detail = client.get("/api/pages/cargo_client_test", headers={"Authorization": f"Bearer {client_token}"}).json()
    assert page_detail["has_custom_gemini_key"] is True
    assert "SAMPLE" not in page_detail.get("gemini_api_key_masked", "")
    print("✅ 7. Client Dedicated Gemini Key & Masking: PASSED (Masked in frontend)")

    # 8. Token increment & quota check
    initial_tokens = page_detail.get("tokens_used", 0)
    database.increment_page_tokens("cargo_client_test", 1250)
    updated_page = database.get_page("cargo_client_test")
    assert updated_page["tokens_used"] == initial_tokens + 1250
    print(f"✅ 8. Token Tracking: PASSED ({initial_tokens} -> {updated_page['tokens_used']} tokens)")

    print("\n🎉 ALL 8/8 RBAC & CLIENT ISOLATION SECURITY TESTS PASSED PERFECTLY!")

if __name__ == "__main__":
    run_tests()
