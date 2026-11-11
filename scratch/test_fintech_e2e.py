import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncio
import database
import fintech_service
import agent
from main import app
from fastapi.testclient import TestClient

def run_tests():
    print("=== 1. Testing Invoice Creation ===")
    order = asyncio.run(fintech_service.create_payment_order(
        page_id="100799479495809",
        amount=25000,
        description="VIP Багц Төлбөр",
        sender_id="test_user_fintech",
        channel="web"
    ))
    inv_id = order["invoice_id"]
    print(f"Generated invoice: {inv_id}, amount: {order['amount']}, banks: {len(order['deep_links'])}")
    assert inv_id.startswith("QP-")
    assert len(order["deep_links"]) >= 6

    print("\n=== 2. Testing TestClient HTTP Endpoints ===")
    client = TestClient(app)

    # Pay page
    res_page = client.get(f"/pay/{inv_id}")
    print(f"GET /pay/{inv_id} status: {res_page.status_code}")
    assert res_page.status_code == 200
    assert "QPay v2" in res_page.text
    assert "25,000" in res_page.text

    # Status check before payment
    res_status = client.get(f"/api/fintech/invoices/{inv_id}/status")
    print(f"GET /api/fintech/invoices/{inv_id}/status: {res_status.json()['status']}")
    assert res_status.json()["status"] == "PENDING"

    # Simulate 1-second auto confirmation
    res_sim = client.post(f"/api/fintech/invoices/{inv_id}/simulate-pay")
    sim_data = res_sim.json()
    print(f"POST /api/fintech/invoices/{inv_id}/simulate-pay: success={sim_data['success']}")
    assert sim_data["success"] is True
    assert "ebarimt" in sim_data
    lottery = sim_data["ebarimt"]["lottery"]
    print(f"E-Barimt Lottery: {lottery}, QR fiscal: {sim_data['ebarimt']['qr_data'][:16]}...")

    # Status check after payment
    res_status2 = client.get(f"/api/fintech/invoices/{inv_id}/status")
    print(f"GET status after pay: {res_status2.json()['status']}")
    assert res_status2.json()["status"] == "PAID"

    # Verify summary
    summary = database.get_fintech_summary("100799479495809")
    print(f"Fintech Summary: total_revenue={summary['total_revenue']}₮, paid_count={summary['paid_count']}")
    assert summary["paid_count"] >= 1

    # Verify registration in CRM
    leads = database.get_all_registrations("100799479495809")
    matched_lead = [l for l in leads if lottery in str(l.get("notes", "")) or lottery in str(l.get("name", ""))]
    print(f"Matched CRM lead count: {len(matched_lead)}")
    assert len(matched_lead) > 0

    print("\n=== ALL FINTECH E2E TESTS PASSED 100%! ===")

if __name__ == "__main__":
    run_tests()
