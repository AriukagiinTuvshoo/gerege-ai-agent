import asyncio
import os
import sys
from datetime import datetime, timedelta
import io

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import database
import appointment_service
import agent
from main import app
from httpx import AsyncClient, ASGITransport

async def run_e2e_tests():
    print("======================================================================")
    print("🚀 STARTING E2E VERIFICATION: APPOINTMENT BOOKING & VOICE ASSISTANT")
    print("======================================================================")

    unique_suffix = int(datetime.now().timestamp())
    test_page_id = f"test_page_e2e_appt_{unique_suffix}"
    today_str = datetime.now().strftime("%Y-%m-%d")
    tomorrow_str = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")

    # -------------------------------------------------------------
    # 1. Test Date & Time Normalization
    # -------------------------------------------------------------
    print("\n[TEST 1] Testing Date & Time Normalization...")
    norm_today = appointment_service.normalize_appointment_date("өнөөдөр")
    assert norm_today == today_str, f"Expected {today_str}, got {norm_today}"

    norm_tomorrow = appointment_service.normalize_appointment_date("маргааш")
    assert norm_tomorrow == tomorrow_str, f"Expected {tomorrow_str}, got {norm_tomorrow}"

    norm_explicit = appointment_service.normalize_appointment_date("2026-11-20")
    assert norm_explicit == "2026-11-20"

    norm_time_1 = appointment_service.normalize_appointment_time("15:30")
    assert norm_time_1 == "15:30"

    norm_time_2 = appointment_service.normalize_appointment_time("14 цаг")
    assert norm_time_2 == "14:00"

    norm_time_3 = appointment_service.normalize_appointment_time("өдрийн 2 цагт")
    assert norm_time_3 == "14:00"
    print("✅ Date & Time Normalization passed 100%!")

    # -------------------------------------------------------------
    # 2. Test Booking via appointment_service and Slot Clash Prevention
    # -------------------------------------------------------------
    print("\n[TEST 2] Testing Slot Booking & Conflict Clash Prevention...")
    customer_phone = f"99{unique_suffix % 1000000:06d}"
    
    # Check availability
    is_free = database.is_slot_available(test_page_id, tomorrow_str, "14:00", "Үс засалт")
    assert is_free is True, "Slot should be initially free"

    # Book slot
    res1 = appointment_service.book_appointment_from_ai(
        page_id=test_page_id,
        customer_name="Тэргэл",
        customer_phone=customer_phone,
        service_name="Үс засалт",
        appointment_date=tomorrow_str,
        appointment_time="14:00",
        sender_id=f"sender_{unique_suffix}",
        channel="telegram",
        notes="Мастер үсчин дээр"
    )
    assert res1["success"] is True, f"Booking should succeed: {res1}"
    appt_id = res1["appointment"]["id"]
    print(f"✅ Slot successfully booked (Appt ID: {appt_id})")

    # Double-booking attempt on the EXACT SAME SLOT must fail
    res2 = appointment_service.book_appointment_from_ai(
        page_id=test_page_id,
        customer_name="Бат-Эрдэнэ",
        customer_phone="99887766",
        service_name="Үс засалт",
        appointment_date=tomorrow_str,
        appointment_time="14:00",
        sender_id="sender_rival",
        channel="web"
    )
    assert res2["success"] is False, "Double-booking should be blocked by conflict check!"
    assert "захиалга" in res2["message"] or "боломжгүй" in res2["message"]
    print("✅ Double-booking attempt was correctly blocked!")

    # -------------------------------------------------------------
    # 3. Test Dual Lead Registration
    # -------------------------------------------------------------
    print("\n[TEST 3] Testing Dual Lead Sync to Registrations...")
    regs = database.get_all_registrations(test_page_id)
    matched_leads = [r for r in regs if r.get("phone") == customer_phone]
    assert len(matched_leads) > 0, "Lead should be dual-saved to registrations table"
    print(f"✅ Dual lead sync verified for {matched_leads[0]['name']} ({matched_leads[0]['phone']})")

    # -------------------------------------------------------------
    # 4. Test 2-Hour Auto-Reminder Simulation
    # -------------------------------------------------------------
    print("\n[TEST 4] Testing 2-Hour Reminder Dispatch Logic...")
    # Create an appointment that is exactly 1.5 hours in the future
    near_time = (datetime.now() + timedelta(minutes=90)).strftime("%H:%M")
    res_near = appointment_service.book_appointment_from_ai(
        page_id=test_page_id,
        customer_name="Саруул",
        customer_phone="88112233",
        service_name="Арьс арчилгаа",
        appointment_date=today_str,
        appointment_time=near_time,
        sender_id=f"sender_near_{unique_suffix}",
        channel="web"
    )
    assert res_near["success"] is True

    # Check pending reminders
    reminders = database.get_pending_appointment_reminders(hours_ahead=2)
    matching_reminders = [r for r in reminders if r["id"] == res_near["appointment"]["id"]]
    assert len(matching_reminders) == 1, "Appointment ~1.5h away must be identified as pending reminder"
    print(f"✅ Pending reminder identified for appt #{matching_reminders[0]['id']}")

    # Dispatch reminder check
    dispatched = await appointment_service.check_and_dispatch_appointment_reminders()
    print(f"✅ check_and_dispatch_appointment_reminders executed: {dispatched} reminders sent")
    
    # Verify reminder_sent is marked
    updated_appt = database.get_appointment(res_near["appointment"]["id"])
    assert updated_appt["reminder_sent"] == 1, "reminder_sent must be marked 1"
    print("✅ reminder_sent flag confirmed in DB!")

    # -------------------------------------------------------------
    # 5. Test REST APIs via AsyncClient
    # -------------------------------------------------------------
    print("\n[TEST 5] Testing REST API Endpoints...")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # GET /api/appointments/summary
        sum_res = await client.get(f"/api/appointments/summary?page_id={test_page_id}")
        assert sum_res.status_code == 200
        summary_json = sum_res.json()
        assert summary_json["total_all"] >= 2
        print(f"✅ /api/appointments/summary returned valid metrics: {summary_json}")

        # GET /api/appointments
        list_res = await client.get(f"/api/appointments?page_id={test_page_id}")
        assert list_res.status_code == 200
        list_json = list_res.json()
        assert list_json["count"] >= 2
        print(f"✅ /api/appointments returned {list_json['count']} appointments")

        # POST /api/appointments (manual creation)
        new_phone = f"85{unique_suffix % 1000000:06d}"
        create_res = await client.post("/api/appointments", json={
            "page_id": test_page_id,
            "customer_name": "Хулан",
            "customer_phone": new_phone,
            "service_name": "Нүүрний массаж",
            "appointment_date": tomorrow_str,
            "appointment_time": "16:00",
            "notes": "VIP өрөө",
            "channel": "web"
        })
        assert create_res.status_code == 200
        create_json = create_res.json()
        assert create_json["success"] is True
        new_id = create_json["appointment"]["id"]
        print(f"✅ POST /api/appointments successfully created appointment #{new_id}")

        # POST /api/appointments/{id}/status -> COMPLETED
        status_res = await client.post(f"/api/appointments/{new_id}/status", json={"status": "COMPLETED"})
        assert status_res.status_code == 200
        assert status_res.json()["success"] is True
        check_completed = database.get_appointment(new_id)
        assert check_completed["status"] == "COMPLETED"
        print(f"✅ POST /api/appointments/{new_id}/status updated status to COMPLETED")

        # POST /api/chat/voice (Multimodal audio upload)
        print("\n[TEST 6] Testing POST /api/chat/voice Multimodal Audio Endpoint...")
        # Create a mock audio stream (e.g. sample WAV header bytes)
        sample_audio = b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\x44\xac\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00data\x00\x00\x00\x00"
        files = {
            "audio_file": ("test_voice.wav", io.BytesIO(sample_audio), "audio/wav")
        }
        data = {
            "page_id": test_page_id,
            "sender_id": f"voice_user_{unique_suffix}",
            "text": "Маргааш 11 цагт цаг захиалъя"
        }
        voice_res = await client.post("/api/chat/voice", files=files, data=data)
        assert voice_res.status_code == 200, f"Voice API returned {voice_res.status_code}: {voice_res.text}"
        voice_json = voice_res.json()
        assert "reply" in voice_json
        print(f"✅ /api/chat/voice responded cleanly with: {voice_json['reply'][:100]}...")

    print("\n======================================================================")
    print("🎉 ALL MODULE 5 & 6 E2E VERIFICATIONS PASSED WITH 100% SUCCESS!")
    print("======================================================================")

if __name__ == "__main__":
    asyncio.run(run_e2e_tests())
