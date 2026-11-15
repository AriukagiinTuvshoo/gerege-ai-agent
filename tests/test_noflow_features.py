"""
Regression & Integration Tests for noflow-inspired features:
1. Comment-to-DM Automation CRUD & 1-Click ON/OFF Toggle + Multi-Tenant Isolation
2. Meta Webhook Comment-to-DM Engine (Facebook feed + Instagram comments + Idempotency + Self-reply guard)
3. Tracked Short Links (/r/{code}) + Atomic CTR Increment + Open-Redirect Guard
4. Saved Hours & ROI Analytics (/api/analytics/roi)
"""
import hashlib
import hmac
import json
import os
import sys
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database
import main

client = TestClient(main.app)


def _setup_test_environment():
    database.init_db()
    database.save_page(page_id="nf_tenant_a", name="NoFlow Tenant A", page_access_token="tok_nf_a")
    database.save_page(page_id="nf_tenant_b", name="NoFlow Tenant B", page_access_token="tok_nf_b")
    database.set_client_credentials(page_id="nf_tenant_a", username="nf_client_a", password="Password123!")
    database.set_client_credentials(page_id="nf_tenant_b", username="nf_client_b", password="Password123!")


def _get_client_token(username: str) -> str:
    resp = client.post("/api/auth/login", json={"type": "client", "identifier": username, "password": "Password123!"})
    assert resp.status_code == 200, f"Client login failed: {resp.text}"
    return resp.json()["token"]


def _sign_meta_payload(raw_body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def test_comment_automation_crud_toggle_and_tenant_isolation():
    _setup_test_environment()
    tok_a = _get_client_token("nf_client_a")
    tok_b = _get_client_token("nf_client_b")

    # Unauthenticated rejected (fresh client without cookies)
    unauth = TestClient(main.app).get("/api/automations/comments")
    assert unauth.status_code in (401, 403)

    # Tenant A creates an automation
    create_resp = client.post(
        "/api/automations/comments",
        headers={"Authorization": f"Bearer {tok_a}"},
        json={
            "name": "Үнийн мэдээлэл DM",
            "keyword_pattern": "үнэ, хэд вэ",
            "post_id": "*",
            "public_reply_text": "Чат руу үнэ илгээлээ!",
            "dm_message_text": "Сайн байна уу? Манай үнэ 49,000₮.",
            "cta_button_text": "Захиалах",
            "cta_url": "https://example.com/order",
        },
    )
    assert create_resp.status_code == 200, create_resp.text
    auto = create_resp.json()["automation"]
    auto_id = auto["id"]
    assert auto["page_id"] == "nf_tenant_a"
    assert auto["is_active"] == 1

    # Tenant B cannot see Tenant A's automation
    list_b = client.get("/api/automations/comments", headers={"Authorization": f"Bearer {tok_b}"})
    assert list_b.status_code == 200
    assert all(item["id"] != auto_id for item in list_b.json()["automations"])

    # Tenant B cannot toggle or delete Tenant A's automation (403)
    toggle_b = client.post(f"/api/automations/comments/{auto_id}/toggle", headers={"Authorization": f"Bearer {tok_b}"})
    assert toggle_b.status_code == 403
    del_b = client.delete(f"/api/automations/comments/{auto_id}", headers={"Authorization": f"Bearer {tok_b}"})
    assert del_b.status_code == 403

    # Tenant A 1-click toggle OFF then ON
    t_off = client.post(f"/api/automations/comments/{auto_id}/toggle", headers={"Authorization": f"Bearer {tok_a}"})
    assert t_off.status_code == 200
    assert t_off.json()["automation"]["is_active"] == 0

    t_on = client.post(f"/api/automations/comments/{auto_id}/toggle", headers={"Authorization": f"Bearer {tok_a}"})
    assert t_on.status_code == 200
    assert t_on.json()["automation"]["is_active"] == 1

    # Tenant A deletes
    del_a = client.delete(f"/api/automations/comments/{auto_id}", headers={"Authorization": f"Bearer {tok_a}"})
    assert del_a.status_code == 200


def test_meta_webhook_comment_to_dm_and_idempotency():
    _setup_test_environment()
    tok_a = _get_client_token("nf_client_a")

    rule_resp = client.post(
        "/api/automations/comments",
        headers={"Authorization": f"Bearer {tok_a}"},
        json={
            "name": "FB/IG Comment Rule",
            "keyword_pattern": "үнэ, price",
            "post_id": "*",
            "public_reply_text": "Чат шалгана уу ✅",
            "dm_message_text": "Үнийн мэдээллийг илгээлээ!",
            "cta_button_text": "Дэлгэрэнгүй",
            "cta_url": "https://example.com/catalog",
        },
    )
    assert rule_resp.status_code == 200
    rule_id = rule_resp.json()["automation"]["id"]

    fb_comment_id = f"fb_c_{uuid.uuid4().hex[:8]}"
    fb_payload = {
        "object": "page",
        "entry": [
            {
                "id": "nf_tenant_a",
                "changes": [
                    {
                        "field": "feed",
                        "value": {
                            "item": "comment",
                            "verb": "add",
                            "comment_id": fb_comment_id,
                            "post_id": "post_123",
                            "message": "Энэ хэд вэ? Үнэ хэлээч",
                            "from": {"id": "user_999"},
                        },
                    }
                ],
            }
        ],
    }
    raw_fb = json.dumps(fb_payload).encode("utf-8")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_post = AsyncMock(return_value=mock_resp)

    with patch.dict(os.environ, {"META_APP_SECRET": "test_meta_secret"}), patch("httpx.AsyncClient.post", mock_post):
        sig = _sign_meta_payload(raw_fb, "test_meta_secret")
        res1 = client.post("/webhook", content=raw_fb, headers={"X-Hub-Signature-256": sig})
        assert res1.status_code == 200
        # Duplicate webhook with same comment_id must be deduplicated
        res2 = client.post("/webhook", content=raw_fb, headers={"X-Hub-Signature-256": sig})
        assert res2.status_code == 200

    # 1 public reply + 1 private DM = 2 outbound Graph API calls total (not 4)
    assert mock_post.call_count == 2
    updated_rule = database.get_comment_automation(rule_id)
    assert updated_rule is not None
    assert updated_rule["trigger_count"] == 1

    # Self-comment (from.id == page_id) must be ignored
    self_payload = {
        "object": "instagram",
        "entry": [
            {
                "id": "nf_tenant_a",
                "changes": [
                    {
                        "field": "comments",
                        "value": {
                            "id": f"ig_self_{uuid.uuid4().hex[:6]}",
                            "text": "үнэ",
                            "media": {"id": "ig_media_1"},
                            "from": {"id": "nf_tenant_a"},
                        },
                    }
                ],
            }
        ],
    }
    raw_self = json.dumps(self_payload).encode("utf-8")
    with patch.dict(os.environ, {"META_APP_SECRET": "test_meta_secret"}), patch("httpx.AsyncClient.post", mock_post):
        sig_self = _sign_meta_payload(raw_self, "test_meta_secret")
        res_self = client.post("/webhook", content=raw_self, headers={"X-Hub-Signature-256": sig_self})
        assert res_self.status_code == 200
    assert mock_post.call_count == 2


def test_tracked_links_and_open_redirect_guard():
    _setup_test_environment()
    tok_a = _get_client_token("nf_client_a")

    # Reject dangerous URLs
    bad_js = client.post(
        "/api/automations/links",
        headers={"Authorization": f"Bearer {tok_a}"},
        json={"title": "XSS", "target_url": "javascript:alert(1)"},
    )
    assert bad_js.status_code == 400

    bad_proto = client.post(
        "/api/automations/links",
        headers={"Authorization": f"Bearer {tok_a}"},
        json={"title": "OpenRedirect", "target_url": "//evil.com"},
    )
    assert bad_proto.status_code == 400

    # Create valid link
    code = f"c{uuid.uuid4().hex[:6]}"
    ok_resp = client.post(
        "/api/automations/links",
        headers={"Authorization": f"Bearer {tok_a}"},
        json={"title": "Catalog", "target_url": "https://example.com/shop", "code": code},
    )
    assert ok_resp.status_code == 200, ok_resp.text
    assert ok_resp.json()["link"]["code"] == code

    # Hit /r/{code} twice without following external redirect
    r1 = client.get(f"/r/{code}", follow_redirects=False)
    assert r1.status_code == 307
    assert r1.headers["location"] == "https://example.com/shop"

    r2 = client.get(f"/r/{code}", follow_redirects=False)
    assert r2.status_code == 307

    links = client.get("/api/automations/links", headers={"Authorization": f"Bearer {tok_a}"}).json()["links"]
    matched = [l for l in links if l["code"] == code]
    assert len(matched) == 1
    assert matched[0]["clicks_count"] == 2


def test_roi_analytics_saved_hours():
    _setup_test_environment()
    tok_a = _get_client_token("nf_client_a")

    roi_resp = client.get("/api/analytics/roi", headers={"Authorization": f"Bearer {tok_a}"})
    assert roi_resp.status_code == 200, roi_resp.text
    roi = roi_resp.json()
    assert roi["page_id"] == "nf_tenant_a"
    assert roi["link_clicks"] >= 2
    assert roi["comment_replies"] >= 1
    assert roi["total_interactions"] >= 1
    assert roi["estimated_hours_saved"] >= 0.0
    assert roi["estimated_cost_saved_mnt"] >= 0


if __name__ == "__main__":
    test_comment_automation_crud_toggle_and_tenant_isolation()
    print("[PASS] test_comment_automation_crud_toggle_and_tenant_isolation")
    test_meta_webhook_comment_to_dm_and_idempotency()
    print("[PASS] test_meta_webhook_comment_to_dm_and_idempotency")
    test_tracked_links_and_open_redirect_guard()
    print("[PASS] test_tracked_links_and_open_redirect_guard")
    test_roi_analytics_saved_hours()
    print("[PASS] test_roi_analytics_saved_hours")
    print("ALL NOFLOW FEATURE TESTS PASSED!")
