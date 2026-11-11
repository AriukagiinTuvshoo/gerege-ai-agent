import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncio
import database
import cargo_service
import agent
from main import app
from fastapi.testclient import TestClient

def run_tests():
    print("=== 1. Testing Warehouse Barcode Scan API ===")
    client = TestClient(app)

    # 1. Barcode scan simulation
    scan_res = client.post("/api/cargo/scan", json={
        "page_id": "100799479495809",
        "tracking_code": "MGL-9988",
        "location": "УБ БЗД 13-р хороолол салбар",
        "weight_kg": 3.5,
        "price_amount": 12500
    })
    print(f"Scan API status: {scan_res.status_code}")
    assert scan_res.status_code == 200
    data = scan_res.json()
    assert data["success"] is True
    pkg = data["package"]
    print(f"Scanned package: {pkg['tracking_code']}, status: {pkg['status']}, invoice_id: {data['invoice_id']}")
    assert pkg["status"] == "ARRIVED_UB"
    assert data["invoice_id"] is not None
    assert "/pay/" in data["pay_url"]

    # 2. Scanner HTML Page rendering
    res_scanner_page = client.get("/scanner")
    print(f"GET /scanner status: {res_scanner_page.status_code}")
    assert res_scanner_page.status_code == 200
    assert "html5-qrcode" in res_scanner_page.text

    # 3. Cargo Summary API
    res_sum = client.get("/api/cargo/summary")
    print(f"Cargo summary: {res_sum.json()}")
    assert res_sum.json()["arrived_packages"] >= 1

    # 4. AI Chatbot Real-time Cargo Query
    print("\n=== 2. Testing AI Chatbot Cargo Inquiry ===")
    chat_res = agent.agent.process_message(
        text="Сайн байна уу, миний MGL-9988 кодтой ачаа ирсэн болов уу?",
        sender_id="test_cargo_user",
        channel="web"
    )
    print("Agent Reply:\n", chat_res["reply"])
    assert "MGL-9988" in chat_res["reply"]
    assert "12,500" in chat_res["reply"] or "12500" in chat_res["reply"]
    assert any(w in chat_res["reply"] for w in ["ирж", "ирсэн", "бэлэн"])

    # 5. Mark Delivered
    print("\n=== 3. Testing Mark Cargo Delivered ===")
    deliv_res = client.post("/api/cargo/MGL-9988/deliver?page_id=100799479495809")
    assert deliv_res.json()["success"] is True
    assert deliv_res.json()["package"]["status"] == "DELIVERED"
    print("Package status marked DELIVERED successfully!")

    print("\n=== ALL CARGO SUPERPOWER TESTS PASSED 100%! ===")

if __name__ == "__main__":
    run_tests()
