import os
import sys

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
import json
import httpx
from datetime import datetime
from fastapi.testclient import TestClient

import database
import executive_bot_service
from main import app

def run_e2e_tests():
    print("==================================================")
    print("   MODULE 3: EXECUTIVE BRIEFING & TELEGRAM BOT E2E")
    print("==================================================")

    # 1. Test Report Formatting
    print("\n--- 1. Testing format_executive_report ---")
    today_str = datetime.now().strftime("%Y-%m-%d")
    report = executive_bot_service.format_executive_report(page_id=database.DEFAULT_PAGE_ID, target_date=today_str)
    print("Sample Generated Report:")
    print(report)
    assert "ӨГЛӨӨНИЙ ЭЗНИЙ ТАЙЛАН" in report or today_str in report
    assert "Байгууллага" in report
    assert "Шинэ харилцагчийн чат" in report
    assert "Баталгаажсан QPay" in report
    print("✅ format_executive_report passed!")

    # 2. Test Owner Interactive Commands
    print("\n--- 2. Testing Owner Interactive Commands ---")
    test_chat_id = "9988776655"

    # 2.1 /start
    res_start = asyncio.run(executive_bot_service.handle_owner_command(test_chat_id, "/start", page_id=database.DEFAULT_PAGE_ID))
    print(f"[/start response]:\n{res_start}\n")
    assert "Гэрэгэ Эзний Туслах" in res_start
    assert "/today" in res_start

    # Check that settings were updated in DB
    page = database.get_page(database.DEFAULT_PAGE_ID)
    assert page.get("telegram_manager_chat_id") == test_chat_id
    print("✅ /start command & manager chat ID auto-save verified!")

    # 2.2 /today
    res_today = asyncio.run(executive_bot_service.handle_owner_command(test_chat_id, "/today", page_id=database.DEFAULT_PAGE_ID))
    print(f"[/today response]:\n{res_today[:120]}...\n")
    assert "ШУУРХАЙ ТАЙЛАН" in res_today
    print("✅ /today command verified!")

    # 2.3 /qpay
    res_qpay = asyncio.run(executive_bot_service.handle_owner_command(test_chat_id, "/qpay", page_id=database.DEFAULT_PAGE_ID))
    print(f"[/qpay response]:\n{res_qpay}\n")
    assert "QPay" in res_qpay
    print("✅ /qpay command verified!")

    # 2.4 /cargo
    res_cargo = asyncio.run(executive_bot_service.handle_owner_command(test_chat_id, "/cargo", page_id=database.DEFAULT_PAGE_ID))
    print(f"[/cargo response]:\n{res_cargo}\n")
    assert "Агуулах & Каргоны Төлөв" in res_cargo
    assert "Нийт бүртгэлтэй ачаа" in res_cargo
    print("✅ /cargo command verified!")

    # 2.5 /help
    res_help = asyncio.run(executive_bot_service.handle_owner_command(test_chat_id, "/help", page_id=database.DEFAULT_PAGE_ID))
    assert "/today" in res_help and "/cargo" in res_help
    print("✅ /help command verified!")

    # 3. Test REST API Endpoints with TestClient
    print("\n--- 3. Testing Executive REST API Endpoints ---")
    client = TestClient(app)

    # 3.1 GET /api/executive/preview
    prev_res = client.get("/api/executive/preview")
    assert prev_res.status_code == 200, f"Preview failed: {prev_res.text}"
    prev_data = prev_res.json()
    assert "report_text" in prev_data
    assert "metrics" in prev_data
    print(f"✅ GET /api/executive/preview successful (metrics keys: {list(prev_data['metrics'].keys())})")

    # 3.2 POST /api/executive/settings
    settings_payload = {
        "telegram_bot_token": "7112233445:AAH_test_fake_token_for_verification",
        "telegram_manager_chat_id": test_chat_id,
        "daily_report_time": "08:30",
        "daily_report_enabled": True
    }
    set_res = client.post("/api/executive/settings", json=settings_payload)
    assert set_res.status_code == 200
    assert set_res.json()["success"] is True
    print("✅ POST /api/executive/settings successful!")

    # 3.3 GET /api/executive/settings
    get_set_res = client.get("/api/executive/settings")
    assert get_set_res.status_code == 200
    cfg = get_set_res.json()
    assert cfg["has_bot_token"] is True
    assert "..." in cfg["telegram_bot_token_masked"]  # masked for security!
    assert cfg["telegram_manager_chat_id"] == test_chat_id
    assert cfg["daily_report_time"] == "08:30"
    print(f"✅ GET /api/executive/settings successful: {cfg}")

    # 3.4 POST /telegram/webhook with owner command
    webhook_payload = {
        "update_id": 999111,
        "message": {
            "message_id": 1,
            "chat": {"id": int(test_chat_id)},
            "text": "/today"
        }
    }
    hook_res = client.post("/telegram/webhook", json=webhook_payload)
    assert hook_res.status_code == 200
    assert hook_res.json().get("mode") == "owner_command"
    print("✅ Telegram Webhook successfully recognized and routed owner command!")

    # 3.5 POST /api/executive/send-report (mock attempt - gracefully handles Telegram HTTP status without crashing)
    send_res = client.post("/api/executive/send-report", json={"chat_id": test_chat_id})
    assert send_res.status_code == 200
    print(f"✅ POST /api/executive/send-report response handled gracefully: {send_res.json()}")

    print("\n==================================================")
    print("   ALL MODULE 3 E2E TESTS PASSED 100% SUCCESFULLY! 🎉")
    print("==================================================")

if __name__ == "__main__":
    run_e2e_tests()
