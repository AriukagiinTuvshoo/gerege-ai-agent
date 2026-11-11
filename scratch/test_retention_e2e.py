import os
import sys

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
from datetime import datetime
from fastapi.testclient import TestClient

import database
import retention_service
from main import app

def run_retention_e2e():
    print("==================================================")
    print("   MODULE 4: SMART RETENTION & 1-CLICK BROADCAST E2E")
    print("==================================================")

    pid = database.DEFAULT_PAGE_ID

    # 1. Test Database Rules
    print("\n--- 1. Testing Retention Rules in DB ---")
    rules = database.get_automated_rules(pid)
    assert len(rules) >= 3, f"Expected at least 3 rules, got {len(rules)}"
    print(f"Found {len(rules)} automated rules:")
    for r in rules:
        print(f"  • {r['rule_type']}: {r['delay_hours']}h delay, active={r['is_active']}")

    # Update a rule
    database.update_automated_rule(
        page_id=pid,
        rule_type="abandoned_chat",
        delay_hours=3,
        message_template="Туршилтын хаягдсан чат сэргээх зурвас",
        is_active=True
    )
    updated_rules = {r["rule_type"]: r for r in database.get_automated_rules(pid)}
    assert updated_rules["abandoned_chat"]["delay_hours"] == 3
    print("✅ Rule update successfully verified!")

    # 2. Test Sent Follow-up & Deduplication
    print("\n--- 2. Testing Follow-up Deduplication ---")
    test_sender = f"test_user_abandoned_{int(datetime.now().timestamp())}"
    assert database.is_followup_sent(pid, "abandoned_chat", test_sender) is False
    database.record_sent_followup(pid, "abandoned_chat", test_sender, "web")
    assert database.is_followup_sent(pid, "abandoned_chat", test_sender) is True
    print("✅ Follow-up recording and duplicate prevention verified!")

    # 3. Test Audience Segmentation
    print("\n--- 3. Testing Audience Segmentation ---")
    all_aud = database.get_broadcast_audience(pid, "all")
    leads_aud = database.get_broadcast_audience(pid, "leads_only")
    unreg_aud = database.get_broadcast_audience(pid, "unregistered")
    print(f"Audience counts -> All: {len(all_aud)}, Leads: {len(leads_aud)}, Unregistered: {len(unreg_aud)}")
    assert isinstance(all_aud, list)
    print("✅ Audience queries passed!")

    # 4. Test Broadcast Dispatch Service
    print("\n--- 4. Testing 1-Click Broadcast Dispatch ---")
    # Insert a dummy web message to ensure there is audience
    database.save_chat_message(pid, "sim_test_user_broadcast", "web", "user", "Үнэ хэд вэ?")
    b_res = asyncio.run(retention_service.send_broadcast(
        page_id=pid,
        title="Шинэ жилийн урамшуулал 20%",
        message="Эрхэм харилцагч танд 20%-ийн хөнгөлөлт үзүүлж байна!",
        target_segment="all",
        channel="web"
    ))
    print("Broadcast result:", b_res)
    assert b_res["success"] is True
    assert b_res["sent_count"] >= 1
    print("✅ Broadcast service verified!")

    # 5. Test REST API Endpoints with TestClient
    print("\n--- 5. Testing REST API Endpoints ---")
    client = TestClient(app)

    # 5.1 GET /api/retention/rules
    res_rules = client.get("/api/retention/rules")
    assert res_rules.status_code == 200
    assert len(res_rules.json()["rules"]) >= 3
    print("✅ GET /api/retention/rules OK")

    # 5.2 POST /api/retention/rules
    res_up_rule = client.post("/api/retention/rules", json={
        "rule_type": "abandoned_chat",
        "delay_hours": 2,
        "message_template": "Сайн байна уу? Сонголт хийхэд тусламж хэрэгтэй юу?",
        "is_active": True
    })
    assert res_up_rule.status_code == 200
    assert res_up_rule.json()["success"] is True
    print("✅ POST /api/retention/rules OK")

    # 5.3 GET /api/retention/summary
    res_sum = client.get("/api/retention/summary")
    assert res_sum.status_code == 200
    summary = res_sum.json()
    assert summary["total_campaigns"] >= 1
    print(f"✅ GET /api/retention/summary OK: {summary}")

    # 5.4 POST /api/retention/broadcast
    res_bc = client.post("/api/retention/broadcast", json={
        "title": "API Тест Broadcast",
        "message": "Энэ бол туршилтын зарлал юм.",
        "target_segment": "all",
        "channel": "web"
    })
    assert res_bc.status_code == 200
    assert res_bc.json()["success"] is True
    print("✅ POST /api/retention/broadcast OK")

    # 5.5 GET /api/retention/campaigns
    res_camps = client.get("/api/retention/campaigns")
    assert res_camps.status_code == 200
    camps = res_camps.json()
    assert len(camps) >= 2
    print(f"✅ GET /api/retention/campaigns OK (Found {len(camps)} campaigns)")

    # 5.6 POST /api/retention/trigger-checks
    res_trig = client.post("/api/retention/trigger-checks")
    assert res_trig.status_code == 200
    print(f"✅ POST /api/retention/trigger-checks OK: {res_trig.json()}")

    print("\n==================================================")
    print("   ALL MODULE 4 E2E TESTS PASSED 100% SUCCESFULLY! 🎉")
    print("==================================================")

if __name__ == "__main__":
    run_retention_e2e()
