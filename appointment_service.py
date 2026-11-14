import os
import re
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

import database
import retention_service

logger = logging.getLogger("appointment_service")

# -------------------------------------------------------------
# 1. ОГНОО БА ЦАГИЙН ХӨРВҮҮЛЭГЧ ТУСЛАХУУД
# -------------------------------------------------------------
def normalize_appointment_date(date_str: str) -> str:
    """Огноог YYYY-MM-DD формат руу хөрвүүлэх (жишээ: 'маргааш', 'өнөөдөр', '2026-11-15')"""
    date_str = (date_str or "").strip().lower()
    now = datetime.now()

    if "өнөөдөр" in date_str or "today" in date_str:
        return now.strftime("%Y-%m-%d")
    elif "маргааш" in date_str or "tomorrow" in date_str:
        return (now + timedelta(days=1)).strftime("%Y-%m-%d")
    elif "нөгөөдөр" in date_str:
        return (now + timedelta(days=2)).strftime("%Y-%m-%d")

    # YYYY-MM-DD эсвэл MM-DD эсвэл YYYY.MM.DD
    match = re.search(r'(\d{4})[-./](\d{1,2})[-./](\d{1,2})', date_str)
    if match:
        y, m, d = match.groups()
        return f"{int(y):04d}-{int(m):02d}-{int(d):02d}"

    match_short = re.search(r'(\d{1,2})[-./](\d{1,2})', date_str)
    if match_short:
        m, d = match_short.groups()
        return f"{now.year:04d}-{int(m):02d}-{int(d):02d}"

    return now.strftime("%Y-%m-%d")

def normalize_appointment_time(time_str: str) -> str:
    """Цагийг HH:MM формат руу хөрвүүлэх (жишээ: '14:00', '14 цаг', '14:30', 'өдрийн 2 цаг')"""
    time_str = (time_str or "").strip().lower()
    
    # Үдээс хойш, орой, pm илэрхийлэл байгаа эсэх
    is_pm = any(w in time_str for w in ["pm", "өдөр", "орой", "үдээс хойш"])

    match = re.search(r'(\d{1,2})[:.](\d{2})', time_str)
    if match:
        h, m = int(match.group(1)), int(match.group(2))
        if is_pm and h < 12:
            h += 12
        return f"{h:02d}:{m:02d}"
    
    match_hour = re.search(r'(\d{1,2})\s*(цаг|h|pm)?', time_str)
    if match_hour:
        h = int(match_hour.group(1))
        if is_pm and h < 12:
            h += 12
        elif h <= 6:  # Бизнес үйлчилгээнд 1-6 цаг нь ихэвчлэн 13:00-18:00
            h += 12
        return f"{h:02d}:00"

    return "14:00"

# -------------------------------------------------------------
# 2. ЦАГ ЗАХИАЛГА ҮҮСГЭХ ХӨДӨЛГҮҮР
# -------------------------------------------------------------
def book_appointment_from_ai(
    page_id: str,
    customer_name: str,
    customer_phone: str,
    service_name: str,
    appointment_date: str,
    appointment_time: str,
    sender_id: Optional[str] = None,
    channel: str = "web",
    notes: str = ""
) -> Dict[str, Any]:
    """Хиймэл оюун ухаанаас дуудагдах цаг захиалгын хэрэгсэл"""
    clean_date = normalize_appointment_date(appointment_date)
    clean_time = normalize_appointment_time(appointment_time)

    # Утасны дугаар цэвэрлэх
    phone_digits = re.sub(r'\D', '', customer_phone or '')
    if len(phone_digits) >= 8:
        clean_phone = phone_digits[-8:]
    else:
        clean_phone = customer_phone or "-"

    # Сул цаг шалгах
    if not database.is_slot_available(page_id, clean_date, clean_time, service_name):
        return {
            "success": False,
            "message": f"Уучлаарай, {clean_date}-ны {clean_time} цагт өөр захиалга аль хэдийн товлогдсон байна. Та өөр цаг сонгоно уу (жишээ нь: өмнөх эсвэл дараагийн цаг)."
        }

    appt = database.create_appointment(
        page_id=page_id,
        customer_name=customer_name or "Харилцагч",
        customer_phone=clean_phone,
        service_name=service_name or "Үйлчилгээ",
        appointment_date=clean_date,
        appointment_time=clean_time,
        sender_id=sender_id,
        channel=channel,
        notes=notes
    )

    if appt:
        return {
            "success": True,
            "appointment": appt,
            "message": f"Таны {clean_date}-ны {clean_time} цагт товлосон '{service_name}' үйлчилгээний цаг амжилттай баталгаажлаа! (Захиалга #{appt['id']}). Бид цаг эхлэхээс 2 цагийн өмнө танд сануулга илгээх болно."
        }
    else:
        return {
            "success": False,
            "message": "Цаг захиалахад алдаа гарлаа. Та дахин оролдоно уу."
        }

# -------------------------------------------------------------
# 3. 2 ЦАГИЙН ӨМНӨХ АВТОМАТ САНУУЛГА ИЛГЭЭХ
# -------------------------------------------------------------
async def check_and_dispatch_appointment_reminders() -> int:
    """2 цагийн өмнөх сануулгыг автоматаар илгээх цикл"""
    reminders = database.get_pending_appointment_reminders(hours_ahead=2)
    sent_count = 0

    for a in reminders:
        sid = a.get("sender_id")
        chn = a.get("channel", "web")
        pid = a.get("page_id")
        cust_name = a.get("customer_name", "Харилцагч")
        srv_name = a.get("service_name", "үйлчилгээ")
        time_str = a.get("appointment_time", "")

        msg = (
            f"Сайн байна уу, {cust_name}? ✨\n"
            f"Таны өнөөдөр {time_str} цагт товлогдсон '{srv_name}' үйлчилгээний цаг 2 цагийн дараа эхэлнэ.\n"
            f"Та цагтаа амжиж ирэх боломжтой юу? Хэрэв цагаа цуцлах эсвэл хойшлуулах бол энэ чатаар шууд мэдэгдээрэй 😊"
        )

        if sid:
            try:
                lock_key = f"appt_reminder:{a['id']}"
                if not database.claim_notification_lock(lock_key, channel=chn):
                    continue
                success = await retention_service.dispatch_channel_message(pid, sid, chn, msg)
                if success:
                    database.mark_appointment_reminder_sent(a["id"])
                    sent_count += 1
                    logger.info(f"Appointment reminder #{a['id']} sent to {sid} ({chn})")
            except Exception as e:
                logger.error(f"Error sending appointment reminder #{a['id']}: {e}")

    return sent_count
