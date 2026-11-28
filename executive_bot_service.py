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
def _audit_recipient_event(
    action: str,
    chat_id: str,
    page_id: Optional[str],
    page_exists: bool,
    previous: str = "",
    **details: Any,
) -> None:
    """Write one audit row for a change to (or a refused change to) the report recipient.

    O-51-4 (Phase 52). ``database.record_audit_log`` appeared **zero** times in this module —
    measured with ``grep -c record_audit_log executive_bot_service.py`` — while this is the
    module that decides WHO receives the daily executive report (revenue, invoices, cargo,
    customers) and answers `/today`, `/report`, `/qpay` and `/cargo`. Every other path that
    changes an authorisation-relevant fact in this codebase writes an audit row: logins
    (`auth.login.success`/`.failed`), key changes (`system.keys.updated`), prompt-injection
    blocks (`ai.prompt_injection.blocked`), data deletion (`user.data.deleted`). An ownership
    change reached from a **public Telegram webhook** was the one that left no trace, so after
    F-51-5 was fixed there was still no way to answer "who took ownership of the reports, when,
    and was a secret presented?" from the record.

    Two properties are deliberate:

    * It never raises. `record_audit_log` raises `AuditLogWriteError` by contract so a caller
      can tell an audit failure from any other, and this caller's job is to answer a Telegram
      message: an unwritable audit table must not turn a working `/start` into a 500 that the
      bot answers with nothing. The failure is logged as an error instead, naming the action,
      so the gap is at least visible in the log the operator reads.
    * It records identifiers and reasons, never the secret. The `/start <secret>` value does
      not reach this function at all; ``via_secret`` is a boolean, which is what an auditor
      needs and is the only form that cannot leak the credential into the audit table.

    ``page_exists`` decides whether ``page_id`` is passed on. `audit_logs.page_id` is a foreign
    key to `pages`, so naming a page that does not exist would fail on PostgreSQL (where
    enforcement is on) and the row would be lost; `page` was already fetched by the caller, so
    this costs no query.
    """
    try:
        database.record_audit_log(
            action,
            page_id=page_id if page_exists else None,
            actor_role="telegram",
            actor_id=str(chat_id),
            resource_type="executive_recipient",
            resource_id=str(page_id) if page_exists else "process",
            details={
                "chat_id": str(chat_id),
                "previous_chat_id": str(previous or ""),
                **details,
            },
        )
    except Exception as exc:  # noqa: BLE001 - see the docstring: never break the reply
        logger.error(
            "could not write the audit row for %s (chat_id %s): %s",
            action, chat_id, type(exc).__name__,
        )


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
        slot_is_empty = not existing_mgr_id
        is_registered_owner = str(existing_mgr_id) == str(chat_id)
        if existing_mgr_id and not is_registered_owner and not secret_matches:
            # O-51-4: a refused takeover attempt is exactly what an audit trail is for. The
            # guard already worked; it was silent.
            _audit_recipient_event(
                "executive.recipient.change_refused",
                chat_id=chat_id,
                page_id=page_id,
                page_exists=bool(page),
                previous=existing_mgr_id,
                reason="registered_owner_exists",
                via_secret=False,
            )
            return None

        # O-51-1 (Phase 52). The claim below still lets a first `/start` take an EMPTY slot,
        # which is the documented onboarding flow and stays exactly that in development, where
        # nobody outside the operator can reach the bot. In production it is a hole with the
        # same shape as F-51-5: a Telegram bot is public by username, so whoever messages it
        # first becomes the recipient of the daily executive report, and the P0-7 guard above
        # then locks the real owner out of the slot the stranger took. With no usable
        # VERIFY_TOKEN there is nothing that distinguishes the operator from anybody else, so
        # production requires one. Two registration paths remain open to an operator there:
        # `/start <secret>` with a generated VERIFY_TOKEN, and the admin API
        # POST /api/executive/settings, which is authenticated and already audited.
        if slot_is_empty and not secret_matches and core_security.is_production_mode():
            logger.error(
                "Refusing an unauthenticated /start that would claim the executive-report "
                "recipient in production (O-51-1): no owner is registered and VERIFY_TOKEN is "
                "not a usable secret. Set VERIFY_TOKEN to a generated value "
                '(python -c "import secrets; print(secrets.token_urlsafe(32))") and send '
                '"/start <that value>", or register the recipient through the admin API '
                "POST /api/executive/settings."
            )
            _audit_recipient_event(
                "executive.recipient.claim_refused",
                chat_id=chat_id,
                page_id=page_id,
                page_exists=bool(page),
                previous="",
                reason="empty_slot_requires_secret_in_production",
                via_secret=False,
            )
            return None

        # Эзний Chat ID-г хадгалах (анх удаа холбож буй эсвэл нууц кодоор баталгаажсан үед)
        if slot_is_empty or is_registered_owner or secret_matches:
            if page_id:
                database.update_page_telegram_settings(
                    page_id=page_id,
                    bot_token=page.get("telegram_bot_token") or os.getenv("TELEGRAM_BOT_TOKEN", ""),
                    manager_chat_id=str(chat_id)
                )
            # O-51-4: which of the three branches ran is the fact worth recording, and the
            # three have very different meanings - a first registration, the owner re-announcing
            # themselves, and a transfer authorised by the secret.
            _audit_recipient_event(
                "executive.recipient.registered" if slot_is_empty
                else ("executive.recipient.reaffirmed" if is_registered_owner
                      else "executive.recipient.transferred"),
                chat_id=chat_id,
                page_id=page_id,
                page_exists=bool(page),
                previous=existing_mgr_id,
                reason="first_registration" if slot_is_empty
                else ("same_chat_id" if is_registered_owner else "secret_verified"),
                via_secret=bool(secret_matches and not slot_is_empty and not is_registered_owner),
                stored_in_page=bool(page_id),
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

    # Бусад удирдлагын командуудыг зөвхөн бүртгэлтэй эзэн дуудах эрхтэй (хоосон үед ч хаана)
    if not existing_mgr_id or str(existing_mgr_id) != str(chat_id):
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
