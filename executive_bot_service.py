import os
import hmac
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import httpx
from dotenv import load_dotenv

import database
from core import security as core_security

load_dotenv(override=True)
logger = logging.getLogger("executive_bot")

# -------------------------------------------------------------
# 1. ӨГЛӨӨНИЙ ЭЗНИЙ ТАЙЛАН БЭЛТГЭХ
# -------------------------------------------------------------
def format_executive_report(page_id: Optional[str] = None, target_date: Optional[str] = None) -> str:
    """Бизнес эрхлэгчид зориулсан өдрийн нэгдсэн тайлангийн найруулга (Markdown)"""
    page = database.get_page(page_id) if page_id else {}
    comp_name = page.get("name") if page else "Гэрэгэ Бизнес Үйлдлийн Систем"
    
    if not target_date:
        # Анхдагчаар өчигдрийн тайлан
        target_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        
    metrics = database.get_daily_executive_metrics(page_id=page_id, date_str=target_date)

    report = (
        f"☀️ *ӨГЛӨӨНИЙ ЭЗНИЙ ТАЙЛАН* — {metrics['date']}\n"
        f"🏢 *Байгууллага:* {comp_name}\n"
        f"━━━━━━━━━━━━━━━━━━━\n\n"
        f"📊 *Өдрийн гол үзүүлэлтүүд:*\n"
        f"• 💬 *Шинэ харилцагчийн чат:* {metrics['chats_count']} хүн\n"
        f"• 👥 *Бүртгэгдсэн сэжим (Leads):* {metrics['leads_count']} хүн\n"
        f"• 📦 *Агуулахад буусан ачаа:* {metrics['cargo_arrived']} хайрцаг\n"
        f"• 💳 *Баталгаажсан QPay:* {metrics['paid_count']} ширхэг\n"
        f"• 💰 *Нийт төлөгдсөн орлого:* {metrics['paid_amount']:,.0f} ₮\n"
        f"• 🧾 *Олгосон И-Баримт:* {metrics['paid_count']} баримт\n\n"
        f"⚠️ *Анхаарах төлөвүүд:*\n"
    )

    if metrics['pending_cargo_count'] > 0:
        report += f"• ⏳ Төлбөр хүлээгдэж буй ачаа: {metrics['pending_cargo_count']} ширхэг ({metrics['pending_cargo_amount']:,.0f} ₮)\n"
    else:
        report += "• ✅ Төлбөр хүлээгдэж буй ачаа байхгүй\n"

    if metrics['escalated_count'] > 0:
        report += f"• 👤 Хүнтэй ярих хүсэлт гаргасан: {metrics['escalated_count']} харилцагч\n"
    else:
        report += "• 🤖 Бүх чат AI туслахаар 100% автомат хариулагдсан\n"

    report += (
        f"\n━━━━━━━━━━━━━━━━━━━\n"
        f"🚀 *Амжилттай өдрийг хүсье! Систем хэвийн ажиллаж байна.*"
    )
    return report

# -------------------------------------------------------------
# 2. МЕНЕЖЕРТ TELEGRAM-ААР ТАЙЛАН ИЛГЭЭХ
# -------------------------------------------------------------
async def send_executive_report(
    chat_id: Optional[str] = None,
    page_id: Optional[str] = None,
    target_date: Optional[str] = None
) -> Dict[str, Any]:
    """Тайланг тухайн эзний Telegram чат руу илгээх"""
    page = database.get_page(page_id) if page_id else {}
    bot_token = (page.get("telegram_bot_token") if page else None) or os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    target_chat_id = chat_id or (page.get("telegram_manager_chat_id") if page else None) or os.getenv("TELEGRAM_MANAGER_CHAT_ID", "").strip()

    if not bot_token:
        return {"success": False, "message": "Telegram Bot Token тохируулаагүй байна"}
    if not target_chat_id:
        return {"success": False, "message": "Менежерийн Telegram Chat ID тохируулаагүй байна"}

    text = format_executive_report(page_id=page_id, target_date=target_date)
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": target_chat_id,
        "text": text,
        "parse_mode": "Markdown"
    }

    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(url, json=payload, timeout=12.0)
            if res.status_code == 200:
                logger.info(f"Executive report successfully sent to {target_chat_id}")
                return {"success": True, "message": "Тайлан амжилттай илгээгдлээ", "chat_id": target_chat_id}
            else:
                # F-34-3: the response body is NOT returned to the caller. Telegram echoes the
                # request URL in some error payloads, and that URL contains the bot token.
                logger.error(f"Telegram API Error [{res.status_code}]: {res.text}")
                return {
                    "success": False,
                    "message": f"Telegram алдаа [{res.status_code}]. Bot токен болон chat ID-г шалгана уу.",
                }
    except Exception as e:
        # F-34-3: previously `str(e)` was returned to the API client. httpx embeds the
        # request URL in its exception text, and the URL is
        # `https://api.telegram.org/bot<TOKEN>/sendMessage`, so any transport error
        # disclosed the tenant's bot token to whoever called this endpoint. The detail
        # stays in the server log; the client gets a stable message with no secret.
        logger.error(f"Error sending executive report: {type(e).__name__}: {e}")
        return {
            "success": False,
            "message": "Telegram-т холбогдоход алдаа гарлаа. Сүлжээ болон Bot Token-оо шалгана уу.",
        }

# -------------------------------------------------------------
# 3. ЭЗНИЙ ИНТЕРАКТИВ КОМАНД ХҮЛЭЭН АВАХ (/start, /today, /qpay)
# -------------------------------------------------------------
async def handle_owner_command(chat_id: str, text: str, page_id: Optional[str] = None) -> Optional[str]:
    """
    Эзэн боттойгоо Telegram-аар харилцах командууд:
    /start -> Эзнийг таньж баталгаажуулах
    /today -> Өнөөдрийн шуурхай тайлан
    /report -> Өчигдрийн бүтэн тайлан
    /qpay -> Сүүлийн төлбөрүүд
    /cargo -> Агуулахын ачааны төлөв
    /help -> Тусламж
    """
    cmd = text.strip().lower()
    page = database.get_page(page_id) if page_id else {}
    page = page or {}
    existing_mgr_id = (page.get("telegram_manager_chat_id") or os.getenv("TELEGRAM_MANAGER_CHAT_ID", "")).strip()

    if cmd.startswith("/start"):
        parts = text.strip().split()
        provided_secret = parts[1] if len(parts) > 1 else ""
        # F-51-5: this line used to read
        #     expected_secret = os.getenv("VERIFY_TOKEN", "GEREGE_VERIFY_2026").strip()
        # which made a string published in this repository — and documented in no template,
        # no compose file and no doc — the credential that decides WHO receives the executive
        # reports. A Telegram bot is public by username, so any stranger who sent
        # `/start GEREGE_VERIFY_2026` became the owner: the daily report (revenue, invoices,
        # cargo, customers) went to their chat, the on-demand commands answered to them, and
        # the real owner was locked out by the P0-7 guard just below. With VERIFY_TOKEN set
        # but empty the hole was wider still: `provided_secret == expected_secret` was
        # `"" == ""`, so a bare `/start` from anybody took ownership.
        #
        # The expected value is now accepted only if it is a secret at all, and the comparison
        # is constant-time. With no usable secret the flow degrades to the safe one: a
        # registered owner keeps working, a stranger is refused, and a first `/start` still
        # claims an empty slot (the documented onboarding flow, unchanged).
        expected_secret = os.getenv("VERIFY_TOKEN", "").strip()
        secret_is_usable = core_security.owner_command_secret_is_usable(expected_secret)
        if expected_secret and not secret_is_usable:
            # Named, never valued: the operator must learn their setting was refused, and the
            # point of the finding is that this value travels no further than this line.
            logger.error(
                "VERIFY_TOKEN is set to a published or placeholder value, so it is refused as "
                "the owner-command secret (F-51-5): no /start secret can re-register the report "
                "recipient until it is replaced, e.g. "
                'python -c "import secrets; print(secrets.token_urlsafe(32))"'
            )
        secret_matches = bool(secret_is_usable) and hmac.compare_digest(
            provided_secret.strip(), expected_secret
        )

        # Хэрэв өмнө нь эзэн бүртгэгдсэн бол өөр хүн /start бичихэд эзний эрхийг булаахгүй байх хамгаалалт (P0-7)
        if existing_mgr_id and str(existing_mgr_id) != str(chat_id) and not secret_matches:
            return None

        # Эзний Chat ID-г хадгалах (анх удаа холбож буй эсвэл нууц кодоор баталгаажсан үед)
        if not existing_mgr_id or str(existing_mgr_id) == str(chat_id) or secret_matches:
            os.environ["TELEGRAM_MANAGER_CHAT_ID"] = str(chat_id)
            if page_id:
                database.update_page_telegram_settings(
                    page_id=page_id,
                    bot_token=page.get("telegram_bot_token") or os.getenv("TELEGRAM_BOT_TOKEN", ""),
                    manager_chat_id=str(chat_id)
                )

        return (
            "Сайн байна уу, захирал аа! 🤝\n\n"
            "Таны хувийн бизнесийн *Гэрэгэ Эзний Туслах* амжилттай холбогдлоо.\n"
            "Би танд өглөө бүрийн *08:30-д* өчигдрийн борлуулалт, карго болон харилцагчийн нэгдсэн тайланг автоматаар хүргэх болно.\n\n"
            "Та хүссэн үедээ дараах коммандуудыг бичиж мэдээллээ бодит цагт аваарай:\n"
            "• `/today` — Өнөөдрийн шуурхай үзүүлэлт\n"
            "• `/report` — Өчигдрийн дэлгэрэнгүй тайлан\n"
            "• `/qpay` — Сүүлийн QPay төлбөрүүд\n"
            "• `/cargo` — Агуулахын үлдэгдэл ба ирсэн ачаа\n"
            "• `/help` — Тусламж"
        )

    # Бусад удирдлагын командуудыг зөвхөн бүртгэлтэй эзэн дуудах эрхтэй
    if existing_mgr_id and str(existing_mgr_id) != str(chat_id):
        return None

    elif cmd in ["/today", "өнөөдөр"]:
        today_str = datetime.now().strftime("%Y-%m-%d")
        return format_executive_report(page_id=page_id, target_date=today_str).replace("ӨГЛӨӨНИЙ ЭЗНИЙ ТАЙЛАН", "ӨНӨӨДРИЙН ШУУРХАЙ ТАЙЛАН")

    elif cmd in ["/report", "/yesterday", "өчигдөр", "тайлан"]:
        yesterday_str = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        return format_executive_report(page_id=page_id, target_date=yesterday_str)

    elif cmd in ["/qpay", "төлбөр", "орлого"]:
        invoices = database.list_invoices(page_id=page_id, limit=5, status="PAID")
        summary = database.get_fintech_summary(page_id)
        if not invoices:
            return f"💳 *QPay Төлбөрийн Мэдээлэл:*\nӨнөөдрийн нийт орлого: {summary['today_revenue']:,} ₮\nОдоогоор төлбөр хийгдээгүй байна."
        lines = [f"💳 *Сүүлийн QPay Төлбөрүүд (Өнөөдөр: {summary['today_revenue']:,} ₮):*"]
        for inv in invoices:
            time_str = (inv.get("paid_at") or "").split(" ")[-1][:5]
            lines.append(f"• {time_str} | *{inv['amount']:,} ₮* | {inv['description'][:20]}... | Сугалаа: `{inv.get('ebarimt_lottery') or '-'}`")
        return "\n".join(lines)

    elif cmd in ["/cargo", "ачаа", "агуулах"]:
        summary = database.get_cargo_summary(page_id or database.DEFAULT_PAGE_ID)
        return (
            f"📦 *Агуулах & Каргоны Төлөв:*\n"
            f"• Нийт бүртгэлтэй ачаа: *{summary['total_packages']}*\n"
            f"• 🟢 УБ-т ирсэн (Олгоход бэлэн): *{summary['arrived_packages']}*\n"
            f"• 📦 Хүлээлгэн өгсөн: *{summary['delivered_packages']}*\n"
            f"• ⏳ Төлбөр хүлээгдэж буй: *{summary['pending_payment_count']} ачаа ({summary['pending_payment_amount']:,} ₮)*"
        )

    elif cmd in ["/help", "тусламж"]:
        return (
            "🛠 *Эзний Удирдлагын Туслах:*\n\n"
            "• `/today` — Өнөөдрийн шуурхай орлого, чат, ачааны мэдээ\n"
            "• `/report` — Өчигдрийн нэгдсэн тайлан\n"
            "• `/qpay` — Сүүлийн QPay төлбөрүүд ба И-Баримт\n"
            "• `/cargo` — Агуулахын төлөв байдал\n"
            "• `/start` — Холболтыг шинэчлэх"
        )

    return None
