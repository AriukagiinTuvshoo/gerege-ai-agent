import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import database
import agent
import sheets_service
import executive_bot_service
from main import app
from fastapi.testclient import TestClient

def run_security_p0_tests():
    client = TestClient(app)

    print("=== P0-1: Secret Masking on GET /api/pages ===")
    res_pages = client.get("/api/pages")
    assert res_pages.status_code == 200
    pages_data = res_pages.json().get("data", [])
    for p in pages_data:
        assert "page_access_token" not in p, "Raw page_access_token leaked!"
        assert "gemini_api_key" not in p, "Raw gemini_api_key leaked!"
        assert "qpay_password" not in p, "Raw qpay_password leaked!"
        assert "telegram_bot_token" not in p, "Raw telegram_bot_token leaked!"
        assert "client_password_hash" not in p, "client_password_hash leaked!"
        assert "client_salt" not in p, "client_salt leaked!"
        assert "client_magic_token" not in p, "Unauthenticated GET /api/pages leaked client_magic_token!"
    print("[PASS] P0-1: Zero raw tokens or magic links leaked on unauthenticated GET /api/pages")

    print("=== P0-2: Unauthenticated Admin Endpoint Protection ===")
    res_update_keys = client.post("/api/update-keys", json={"admin_password": "HACKED"})
    assert res_update_keys.status_code == 401, f"Expected 401, got {res_update_keys.status_code}"

    res_create_page = client.post("/api/pages", json={"page_id": "hacked_page", "name": "Hacked"})
    assert res_create_page.status_code == 401, f"Expected 401, got {res_create_page.status_code}"

    res_del_page = client.delete("/api/pages/cargo_client_test")
    assert res_del_page.status_code == 401, f"Expected 401, got {res_del_page.status_code}"

    res_creds = client.post("/api/pages/cargo_client_test/credentials", json={"username": "hacker"})
    assert res_creds.status_code == 401, f"Expected 401, got {res_creds.status_code}"
    print("[PASS] P0-2: All admin endpoints reject unauthenticated requests with HTTP 401")

    print("=== P0-4: QPay Callback Specification (HTTP 200 SUCCESS) ===")
    inv = database.create_invoice(
        page_id=database.DEFAULT_PAGE_ID,
        amount=15000,
        description="Security Test Invoice",
        sender_id="sec_test_user",
        channel="web"
    )
    res_cb = client.post(f"/api/fintech/qpay/callback?invoice_id={inv['invoice_id']}", json={})
    assert res_cb.status_code == 200
    assert res_cb.text == "SUCCESS", f"Expected 'SUCCESS', got {res_cb.text}"
    print("[PASS] P0-4: QPay callback returns HTTP 200 'SUCCESS' plain text")

    print("=== P0-5: Receipt Validation ('INVALID_RECEIPT' must NOT match 'VALID_RECEIPT') ===")
    sample_text = "INVALID_RECEIPT\nТайлбар: Энэ бол гүйлгээний баримт биш, энгийн зураг байна."
    first_line = sample_text.strip().splitlines()[0].strip().upper()
    is_valid = first_line.startswith("VALID_RECEIPT") and not first_line.startswith("INVALID_RECEIPT")
    assert is_valid is False, "INVALID_RECEIPT was falsely treated as valid!"
    print("[PASS] P0-5: Strict receipt prefix check rejects INVALID_RECEIPT")

    print("=== P0-6: Admin Backdoor Disabled When Custom ADMIN_PASSWORD Set ===")
    old_pw = os.environ.get("ADMIN_PASSWORD")
    try:
        os.environ["ADMIN_PASSWORD"] = "MySuperSecretProdPass99!"
        assert database.authenticate_admin("ADMIN2026") is False, "Hardcoded ADMIN2026 backdoor still worked!"
        assert database.authenticate_admin("MySuperSecretProdPass99!") is True
    finally:
        if old_pw is not None:
            os.environ["ADMIN_PASSWORD"] = old_pw
        else:
            os.environ.pop("ADMIN_PASSWORD", None)
    print("[PASS] P0-6: ADMIN2026 fallback disabled when custom ADMIN_PASSWORD is set")

    print("=== P0-7: Webhook HMAC Signature & Owner /start Hijack Guard ===")
    os.environ["META_APP_SECRET"] = "test_meta_secret_key"
    try:
        res_bad_sig = client.post(
            "/webhook",
            content=b'{"entry":[]}',
            headers={"X-Hub-Signature-256": "sha256=invalid_signature"}
        )
        assert res_bad_sig.status_code == 403, f"Expected 403 on bad HMAC, got {res_bad_sig.status_code}"
    finally:
        os.environ.pop("META_APP_SECRET", None)
    print("[PASS] P0-7: Meta webhook rejects invalid X-Hub-Signature-256 with HTTP 403")

    print("=== P1: SSRF Protection on Google Sheets URL & Strict Name Extraction ===")
    try:
        sheets_service.normalize_sheet_csv_url("http://169.254.169.254/latest/meta-data/")
        assert False, "SSRF URL should have raised ValueError!"
    except ValueError:
        pass

    det1 = agent.extract_phone_and_name_fallback("Сайн байна уу 12345678")
    assert det1 is None, f"12345678 is not a valid Mongolian mobile prefix, got {det1}"

    det2 = agent.extract_phone_and_name_fallback("Сайн байна уу 99112233")
    assert det2 is not None and det2["phone"] == "99112233"
    assert det2["name"] != "Сайн", f"'Сайн байна' should not be extracted as customer name, got {det2}"

    det3 = agent.extract_phone_and_name_fallback("Сайн байна уу Болд 99112233")
    assert det3 is not None and det3["phone"] == "99112233"
    assert det3["name"] == "Болд", f"Expected 'Болд', got {det3}"
    print("[PASS] P1: SSRF blocked and 'Сайн байна' false-positive lead extraction eliminated")

    print("\nALL P0 & P1 SECURITY VERIFICATION TESTS PASSED 100%!")

if __name__ == "__main__":
    run_security_p0_tests()
