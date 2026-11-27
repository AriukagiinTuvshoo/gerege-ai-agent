import os
import io
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

import database
import fintech_service

logger = logging.getLogger("cargo_service")

# -------------------------------------------------------------
# 1. АЧАА БАРКОДООР СКАЙНДАХ БА АВТО МЭДЭГДЭЛ ИЛГЭЭХ
# -------------------------------------------------------------
async def scan_and_notify_package(
    page_id: str,
    tracking_code: str,
    location: str = "УБ Агуулах",
    weight_kg: Optional[float] = None,
    price_amount: Optional[int] = None,
    base_url: str = ""
) -> Dict[str, Any]:
    """
    Агуулахын ажилтан баркод уншуулахад:
    1. Баазад ачааны төлөвийг 'ARRIVED_UB' болгон бүртгэх
    2. Төлбөр тооцоологдсон бол QPay нэхэмжлэх автоматаар үүсгэх
    3. Ачааны эзний Facebook / Telegram / утас руу 'Ачаа ирлээ' мэдэгдлийг QPay линктэй нь шууд илгээх
    """
    tracking_clean = tracking_code.strip().upper()
    existing_pkg = database.get_cargo_package(page_id, tracking_clean)

    # Тооцоолсон жин ба үнэ
    w = float(weight_kg) if weight_kg is not None else (existing_pkg.get("weight_kg", 0.0) if existing_pkg else 0.0)
    p = int(price_amount) if price_amount is not None else (existing_pkg.get("price_amount", 0) if existing_pkg else 0)

    # 1. Төлбөр байгаа бөгөөд нэхэмжлэх үүсээгүй бол QPay нэхэмжлэх үүсгэх
    invoice_id = existing_pkg.get("invoice_id") if existing_pkg else None
    pay_url = ""
    invoice_data = None

    if p > 0:
        if not invoice_id:
            try:
                inv_res = await fintech_service.create_payment_order(
                    page_id=page_id,
                    amount=p,
                    description=f"Карго тээвэр: {tracking_clean} ({w}кг)",
                    sender_id=existing_pkg.get("sender_id") if existing_pkg else None,
                    channel=existing_pkg.get("channel", "web") if existing_pkg else "web",
                    base_url=base_url
                )
                invoice_id = inv_res.get("invoice_id")
                pay_url = inv_res.get("pay_url", "")
                invoice_data = inv_res
            except Exception as e:
                logger.error(f"Error creating QPay invoice for cargo {tracking_clean}: {e}")
        else:
            pay_url = f"{base_url.rstrip('/')}/pay/{invoice_id}" if base_url else f"/pay/{invoice_id}"

    # 2. Агуулахад ирсэн төлөвт оруулах
    updated_pkg = database.scan_arrive_package(
        page_id=page_id,
        tracking_code=tracking_clean,
        location=location,
        weight_kg=w,
        price_amount=p,
        invoice_id=invoice_id
    )

    # 3. Мэдэгдэл бэлтгэх ба илгээх
    customer_name = updated_pkg.get("customer_name") or "Эрхэм харилцагч"
    sender_id = updated_pkg.get("sender_id")
    channel = updated_pkg.get("channel", "web")

    notification_sent = False
    notify_text = (
        f"Сайн байна уу, {customer_name}-ээ! 🎉\n\n"
        f"Таны **{tracking_clean}** карго кодтой ачаа Улаанбаатар салбар дээр ирж олгоход бэлэн боллоо.\n\n"
        f"📍 **Хүлээн авах цэг:** {location}\n"
        f"⚖️ **Ачааны жин:** {w} кг\n"
        f"💰 **Тээврийн хөлс:** {p:,.0f} ₮\n"
    )

    if pay_url:
        notify_text += (
            f"\n⚡ **QPay Төлбөрийн Шууд Линк:**\n"
            f"👉 {pay_url}\n\n"
            f"*(Утсан дээрээ линкээр орж Хаан, Голомт, М банкны апп-аараа 1 товшилтоор төлөхөд 1 секундэд баталгаажиж, И-Баримт очих болно!)*"
        )
    else:
        notify_text += "\nИрж авахдаа карго кодоо шалгуулан авна уу. Баярлалаа! ✨"

    page = database.get_page(page_id) or {}
    page_token = page.get("page_access_token")

    try:
        if (channel in ("meta", "facebook", "instagram", "facebook/instagram") or (sender_id and sender_id.startswith("meta_"))) and sender_id:
            from main import send_meta_message
            await send_meta_message(sender_id.replace("meta_", ""), notify_text, page_token=page_token)
            notification_sent = True
        elif (channel == "telegram" or (sender_id and sender_id.startswith("tg_"))) and sender_id:
            from main import send_telegram_message
            await send_telegram_message(sender_id.replace("tg_", ""), notify_text)
            notification_sent = True
    except Exception as notify_err:
        logger.warning(f"Cargo notification delivery skipped: {notify_err}")

    # Менежерт мэдэгдэх
    try:
        from main import notify_manager_telegram
        await notify_manager_telegram({
            "id": updated_pkg.get("id"),
            "service": f"Карго Ачаа Ирсэн: {tracking_clean}",
            "name": customer_name,
            "phone": updated_pkg.get("customer_phone", "Бүртгэлгүй"),
            "channel": channel,
            "created_at": datetime.now().strftime("%H:%M:%S")
        })
    except Exception:
        pass

    return {
        "success": True,
        "message": f"Ачаа {tracking_clean} амжилттай бүртгэгдэж ирсэн төлөвт орлоо",
        "package": updated_pkg,
        "invoice_id": invoice_id,
        "pay_url": pay_url,
        "notification_sent": notification_sent
    }

# -------------------------------------------------------------
# 2. ХАРИЛЦАГЧИЙН АЧААГ ХАЙХ (AI ЧАТБОТ ДУУДАХ ХЭРЭГСЭЛ)
# -------------------------------------------------------------
def lookup_customer_cargo(page_id: str, query: str, base_url: str = "") -> str:
    """Хэрэглэгчийн карго код эсвэл утсаар ачааны мэдээллийг товч бөгөөд тодорхой гаргаж өгөх"""
    packages = database.find_cargo_by_phone_or_code(page_id, query)
    if not packages:
        return ""

    lines = []
    for p in packages:
        status_mn = {
            "REGISTERED": "Бүртгэгдсэн (Агуулах руу замд гарсан)",
            "IN_TRANSIT": "Замдаа тээвэрлэгдэж байгаа",
            "ARRIVED_UB": "🟢 Улаанбаатар салбар дээр ирсэн (Олгоход бэлэн)",
            "PAID": "✅ Төлбөр төлөгдсөн (Олгоход бэлэн)",
            "DELIVERED": "📦 Хэрэглэгч хүлээн авсан (Олгогдсон)"
        }.get(p.get("status", ""), p.get("status", ""))

        tracking = p.get("tracking_code", "")
        weight = p.get("weight_kg", 0)
        price = p.get("price_amount", 0)
        loc = p.get("warehouse_location", "УБ Агуулах")
        inv_id = p.get("invoice_id")

        item = f"• **Карго код:** {tracking} | **Төлөв:** {status_mn}\n  **Жин:** {weight}кг | **Тээврийн хөлс:** {price:,.0f}₮ | **Байршил:** {loc}"
        if inv_id and p.get("status") == "ARRIVED_UB":
            p_url = f"{base_url.rstrip('/')}/pay/{inv_id}" if base_url else f"/pay/{inv_id}"
            item += f"\n  👉 **Төлбөр төлөх QPay холбоос:** {p_url}"
        lines.append(item)

    return "\n\n".join(lines)

# -------------------------------------------------------------
# 3. EXCEL / CSV МАНИФЕСТ ОРУУЛАХ (BATCH IMPORT)
# -------------------------------------------------------------
def import_manifest_from_excel_bytes(page_id: str, file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Excel файлаас карго ачаануудын жагсаалтыг олноор нь баазад оруулах
    Багана: Код (Tracking), Утас (Phone), Нэр (Name), Жин (Weight), Үнэ (Price)
    """
    import openpyxl

    # Phase 56 (F-56-5). Two defects in this function, both measured live:
    #
    #   POST /api/cargo/import-manifest?page_id=p56_never_created   (a valid one-row .xlsx)
    #     -> HTTP 200 {"success":false,"message":"Excel уншихад алдаа гарлаа: FOREIGN KEY
    #        constraint failed"}
    #
    # The Excel file parsed correctly; the database refused the write, because `cargo_packages`
    # has a foreign key to `pages` (`migrations/versions/0003_foreign_keys.py`). One `try` wrapped
    # both the parse and the write loop and named every failure "Excel уншихад алдаа гарлаа", so
    # an operator was sent to look for a broken spreadsheet. The second defect: the rows that had
    # already been committed before the failure were counted in `inserted_count` and then
    # discarded, so a partially imported manifest was indistinguishable from a total failure.
    #
    # The page is checked up front, and the two stages are reported separately with the count of
    # rows that did land. `upsert_cargo_package` is an idempotent upsert on
    # `(page_id, tracking_code)`, so re-uploading the same file after a partial import is safe -
    # which is why the loop is reported honestly rather than restructured into one transaction.
    if not database.get_page(page_id):
        return {
            "success": False,
            "stage": "page",
            "written": 0,
            "count": 0,
            "message": f"'{page_id}' хуудас олдсонгүй - ямар ч ачаа бүртгэсэнгүй.",
        }

    stage = "read"
    written = 0
    try:
        wb = openpyxl.load_workbook(io.BytesIO(file_bytes), data_only=True)
        sheet = wb.active
        rows = list(sheet.iter_rows(values_only=True))
        if not rows:
            return {"success": False, "message": "Файл хоосон байна"}

        header = [str(c).strip().lower() if c else "" for c in rows[0]]
        
        # Багана тодорхойлох
        col_tracking = -1
        col_phone = -1
        col_name = -1
        col_weight = -1
        col_price = -1

        for idx, h in enumerate(header):
            if any(k in h for k in ["код", "tracking", "barcode", "ачаа"]):
                col_tracking = idx
            elif any(k in h for k in ["утас", "phone", "mobile"]):
                col_phone = idx
            elif any(k in h for k in ["нэр", "name", "хэрэглэгч"]):
                col_name = idx
            elif any(k in h for k in ["жин", "weight", "кг", "kg"]):
                col_weight = idx
            elif any(k in h for k in ["үнэ", "price", "төлбөр", "хөлс", "төг"]):
                col_price = idx

        if col_tracking == -1:
            # 1-р баганыг шууд tracking гэж үзэх
            col_tracking = 0

        stage = "write"
        inserted_count = 0
        for r in rows[1:]:
            if not r or len(r) <= col_tracking or not r[col_tracking]:
                continue
            code = str(r[col_tracking]).strip()
            if not code or len(code) < 3:
                continue

            phone = str(r[col_phone]).strip() if col_phone != -1 and len(r) > col_phone and r[col_phone] else ""
            name = str(r[col_name]).strip() if col_name != -1 and len(r) > col_name and r[col_name] else "Харилцагч"
            
            weight = 0.0
            if col_weight != -1 and len(r) > col_weight and r[col_weight]:
                try:
                    weight = float(str(r[col_weight]).replace("kg", "").replace("кг", "").strip())
                except Exception:
                    weight = 0.0

            price = 0
            if col_price != -1 and len(r) > col_price and r[col_price]:
                try:
                    price = int(float(str(r[col_price]).replace("₮", "").replace(",", "").strip()))
                except Exception:
                    price = 0

            database.upsert_cargo_package(
                page_id=page_id,
                tracking_code=code,
                customer_name=name,
                customer_phone=phone,
                weight_kg=weight,
                price_amount=price,
                status="IN_TRANSIT"
            )
            inserted_count += 1
            written = inserted_count

        return {
            "success": True,
            "message": f"Нийт {inserted_count} ачааг амжилттай импортлон бүртгэлээ",
            "count": inserted_count
        }
    except Exception as e:
        if stage == "read":
            logger.error(f"Error reading cargo manifest {filename}: {e}", exc_info=e)
            return {
                "success": False,
                "stage": "read",
                "written": 0,
                "count": 0,
                "message": f"Excel файл уншигдсангүй ({type(e).__name__}): {e}",
            }
        # Phase 56 (F-55-3's rule applied here: the exception type is named, its traceback goes to
        # the log, and the caller is told how much of the import actually landed.)
        logger.error(
            f"Error writing cargo manifest {filename} after {written} row(s): {e}", exc_info=e
        )
        return {
            "success": False,
            "stage": "write",
            "written": written,
            "count": written,
            "message": (
                f"{written} ачааг бүртгэсний дараа өгөгдлийн сангийн алдаа гарлаа "
                f"({type(e).__name__}): үлдсэн мөрүүд импортлогдоогүй. "
                f"Файлыг дахин илгээхэд өмнө бүртгэгдсэн ачаанууд давхардахгүй."
            ),
        }
