import os
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
import httpx
from dotenv import load_dotenv

import database

load_dotenv(override=True)
logger = logging.getLogger("retention_service")

# -------------------------------------------------------------
# 1. СУВГУУД РУУ МЕССЕЖ ИЛГЭЭГЧ ТУСЛАХУУД
# -------------------------------------------------------------
async def dispatch_channel_message(
    page_id: str,
    sender_id: str,
    channel: str,
    message_text: str
) -> bool:
    """Сувгийн онцлогоос хамааран харилцагч руу мессеж илгээх"""
    page = database.get_page(page_id) or {}
    
    # 1. Вэб эсвэл симулятор
    if channel == "web" or sender_id.startswith("sim_") or sender_id.startswith("web_"):
        database.save_chat_message(
            page_id=page_id,
            sender_id=sender_id,
            channel="web",
            sender_type="bot",
            content=message_text
        )
        return True

    # 2. Telegram
    if channel == "telegram" or sender_id.startswith("tg_"):
        raw_chat_id = sender_id.replace("tg_", "")
        bot_token = page.get("telegram_bot_token") or os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        if not bot_token:
            return False
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        try:
            async with httpx.AsyncClient() as client:
                res = await client.post(url, json={"chat_id": raw_chat_id, "text": message_text}, timeout=10.0)
                if res.status_code == 200:
                    database.save_chat_message(page_id, sender_id, "telegram", "bot", message_text)
                    return True
        except Exception as e:
            logger.error(f"Telegram dispatch error to {sender_id}: {e}")
            return False

    # 3. Facebook Messenger / Instagram Direct
    if channel in ["facebook", "meta", "instagram", "facebook/instagram", "manychat/instagram"] or sender_id.startswith("meta_"):
        raw_meta_id = sender_id.replace("meta_", "")
        token = page.get("page_access_token") or os.getenv("META_PAGE_ACCESS_TOKEN", "").strip()
        if not token:
            return False
        graph_ver = os.getenv("META_GRAPH_API_VERSION", "v22.0")
        url = f"https://graph.facebook.com/{graph_ver}/me/messages?access_token={token}"
        payload = {
            "recipient": {"id": raw_meta_id},
            "messaging_type": "RESPONSE",
            "message": {"text": message_text}
        }
        try:
            async with httpx.AsyncClient() as client:
                res = await client.post(url, json=payload, timeout=10.0)
                if res.status_code == 200:
                    database.save_chat_message(page_id, sender_id, channel, "bot", message_text)
                    return True
                else:
                    logger.warning(f"Meta dispatch non-200 [{res.status_code}] to {sender_id}: {res.text}")
                    return False
        except Exception as e:
            logger.error(f"Meta dispatch error to {sender_id}: {e}")
            return False

    # Default fallback: save to DB
    database.save_chat_message(page_id, sender_id, channel, "bot", message_text)
    return True

# -------------------------------------------------------------
# 2. АВТОМАТ СЭРГЭЭХ ДҮРМҮҮДИЙГ АЖИЛЛУУЛАХ (CRON / LOOP)
# -------------------------------------------------------------
async def run_automated_retention_checks(base_url: str = "http://localhost:8000") -> Dict[str, Any]:
    """Бүх хуудсын хувьд идэвхтэй дүрмүүдийг шалгаж, харилцагчид руу авто-сануулга илгээх"""
    pages = database.get_all_pages()
    stats = {
        "abandoned_sent": 0,
        "cargo_pickup_sent": 0,
        "retention_sent": 0
    }

    for p in pages:
        pid = p.get("page_id")
        if not pid:
            continue

        rules = {r["rule_type"]: r for r in database.get_automated_rules(pid) if r.get("is_active")}

        # 1. Хаягдсан чат (Abandoned Chat)
        if "abandoned_chat" in rules:
            r = rules["abandoned_chat"]
            delay = r.get("delay_hours", 2)
            msg = r.get("message_template", "")
            candidates = database.get_abandoned_chat_candidates(pid, delay_hours=delay)
            for c in candidates:
                sid = c["sender_id"]
                chn = c.get("channel", "web")
                success = await dispatch_channel_message(pid, sid, chn, msg)
                if success:
                    database.record_sent_followup(pid, "abandoned_chat", sid, chn)
                    stats["abandoned_sent"] += 1

        # 2. Карго ачаагаа аваагүй байгаа сануулга (Cargo Pickup Reminder)
        if "cargo_pickup" in rules:
            r = rules["cargo_pickup"]
            delay = r.get("delay_hours", 48)
            msg_tmpl = r.get("message_template", "")
            candidates = database.get_cargo_pickup_candidates(pid, delay_hours=delay)
            for c in candidates:
                sid = c.get("sender_id")
                if not sid:
                    continue
                chn = c.get("channel", "web")
                code = c.get("tracking_code", "")
                custom_msg = f"{msg_tmpl}\n(Карго код: {code})"
                if c.get("invoice_id"):
                    custom_msg += f"\n👉 QPay төлбөр төлөх холбоос: {base_url}/pay/{c['invoice_id']}"
                success = await dispatch_channel_message(pid, sid, chn, custom_msg)
                if success:
                    database.record_sent_followup(pid, "cargo_pickup", sid, chn)
                    stats["cargo_pickup_sent"] += 1

        # 3. 25+ хоногийн дараах давтан сэрээгч (Retention Re-engagement)
        if "retention_followup" in rules:
            r = rules["retention_followup"]
            delay_days = int(r.get("delay_hours", 600) / 24) or 25
            msg = r.get("message_template", "")
            candidates = database.get_retention_candidates(pid, delay_days=delay_days)
            for c in candidates:
                sid = c.get("sender_id")
                if not sid:
                    continue
                chn = c.get("channel", "web")
                success = await dispatch_channel_message(pid, sid, chn, msg)
                if success:
                    database.record_sent_followup(pid, "retention_followup", sid, chn)
                    stats["retention_sent"] += 1

    return stats

# -------------------------------------------------------------
# 3. 1-CLICK BROADCAST (ОЛОН ХҮНД ЗЭРЭГ ИЛГЭЭХ)
# -------------------------------------------------------------
async def send_broadcast(
    page_id: str,
    title: str,
    message: str,
    target_segment: str = "all",
    channel: str = "all"
) -> Dict[str, Any]:
    """1-Click Broadcast илгээх үндсэн хөдөлгүүр"""
    audience = database.get_broadcast_audience(page_id, segment=target_segment)
    sent_count = 0

    for member in audience:
        sid = member.get("sender_id")
        chn = member.get("channel", "web")
        if not sid:
            continue

        if channel != "all" and chn != channel:
            continue

        success = await dispatch_channel_message(page_id, sid, chn, message)
        if success:
            sent_count += 1
            # Throttling to prevent provider rate limiting
            await asyncio.sleep(0.05)

    camp = database.create_marketing_campaign(
        page_id=page_id,
        title=title,
        message=message,
        target_segment=target_segment,
        channel=channel,
        sent_count=sent_count
    )

    return {
        "success": True,
        "message": f"Broadcast амжилттай илгээгдлээ. Нийт {sent_count} харилцагчид хүргэгдэв.",
        "campaign": camp,
        "sent_count": sent_count
    }
