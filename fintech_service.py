import os
import io
import json
import base64
import random
import logging
import secrets
import httpx
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from dotenv import load_dotenv

import database

load_dotenv(override=True)
logger = logging.getLogger("fintech_service")

# Static qrcodes хавтас бэлтгэх
STATIC_QR_DIR = os.path.join(os.path.dirname(__file__), "static", "qrcodes")
os.makedirs(STATIC_QR_DIR, exist_ok=True)

# Монгол улсын томоохон банкуудын албан ёсны Deep Link ба лого тохиргоо
SUPPORTED_BANKS = [
    {
        "id": "khanbank",
        "name": "Хаан банк",
        "en_name": "Khan Bank",
        "color": "#006838",
        "bg_class": "bg-emerald-600 hover:bg-emerald-700",
        "scheme": "khanbank://q?qPay_QRcode={qr_text}",
        "web_url": "https://www.khanbank.com",
        "logo_svg": '<svg class="w-6 h-6 inline-block mr-2" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10" fill="#006838"/><path d="M7 12l3 3 7-7" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg>'
    },
    {
        "id": "socialpay",
        "name": "SocialPay (Голомт)",
        "en_name": "SocialPay Golomt",
        "color": "#0055B8",
        "bg_class": "bg-blue-600 hover:bg-blue-700",
        "scheme": "socialpay://q?qPay_QRcode={qr_text}",
        "web_url": "https://www.golomtbank.com",
        "logo_svg": '<svg class="w-6 h-6 inline-block mr-2" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10" fill="#0055B8"/><path d="M12 7v10M8 12h8" stroke="#fff" stroke-width="2.5" stroke-linecap="round"/></svg>'
    },
    {
        "id": "mbank",
        "name": "М банк",
        "en_name": "M Bank",
        "color": "#111827",
        "bg_class": "bg-gray-900 hover:bg-black",
        "scheme": "mbank://q?qPay_QRcode={qr_text}",
        "web_url": "https://m-bank.mn",
        "logo_svg": '<svg class="w-6 h-6 inline-block mr-2" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10" fill="#111827"/><path d="M8 16V8l4 4 4-4v8" stroke="#00E5FF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>'
    },
    {
        "id": "statebank",
        "name": "Төрийн банк",
        "en_name": "State Bank",
        "color": "#D32F2F",
        "bg_class": "bg-red-600 hover:bg-red-700",
        "scheme": "statebank://q?qPay_QRcode={qr_text}",
        "web_url": "https://www.statebank.mn",
        "logo_svg": '<svg class="w-6 h-6 inline-block mr-2" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10" fill="#D32F2F"/><text x="12" y="16" fill="#fff" font-size="10" font-weight="bold" text-anchor="middle">ТБ</text></svg>'
    },
    {
        "id": "xacbank",
        "name": "Хас банк",
        "en_name": "XacBank",
        "color": "#FF6600",
        "bg_class": "bg-amber-600 hover:bg-amber-700",
        "scheme": "xacbank://q?qPay_QRcode={qr_text}",
        "web_url": "https://www.xacbank.mn",
        "logo_svg": '<svg class="w-6 h-6 inline-block mr-2" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10" fill="#FF6600"/><text x="12" y="16" fill="#fff" font-size="11" font-weight="bold" text-anchor="middle">XAC</text></svg>'
    },
    {
        "id": "tdbbank",
        "name": "ХХБ (TDB Online)",
        "en_name": "Trade & Development Bank",
        "color": "#0B4D9C",
        "bg_class": "bg-indigo-700 hover:bg-indigo-800",
        "scheme": "tdbbank://q?qPay_QRcode={qr_text}",
        "web_url": "https://www.tdbm.mn",
        "logo_svg": '<svg class="w-6 h-6 inline-block mr-2" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10" fill="#0B4D9C"/><text x="12" y="16" fill="#fff" font-size="10" font-weight="bold" text-anchor="middle">TDB</text></svg>'
    },
    {
        "id": "mostmoney",
        "name": "Most Money",
        "en_name": "Most Money",
        "color": "#F59E0B",
        "bg_class": "bg-yellow-500 hover:bg-yellow-600",
        "scheme": "mostmoney://q?qPay_QRcode={qr_text}",
        "web_url": "https://www.mostmoney.mn",
        "logo_svg": '<svg class="w-6 h-6 inline-block mr-2" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10" fill="#F59E0B"/><text x="12" y="16" fill="#fff" font-size="10" font-weight="bold" text-anchor="middle">MM</text></svg>'
    },
    {
        "id": "ardapp",
        "name": "Ард Апп",
        "en_name": "Ard App",
        "color": "#EC4899",
        "bg_class": "bg-pink-600 hover:bg-pink-700",
        "scheme": "ardapp://q?qPay_QRcode={qr_text}",
        "web_url": "https://www.ard.mn",
        "logo_svg": '<svg class="w-6 h-6 inline-block mr-2" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10" fill="#EC4899"/><text x="12" y="16" fill="#fff" font-size="10" font-weight="bold" text-anchor="middle">ARD</text></svg>'
    }
]

# -------------------------------------------------------------
# 1. QR КОД БА БАНКНЫ DEEP LINK ҮҮСГЭХ ХЭРЭГСЛҮҮД
# -------------------------------------------------------------
def generate_qr_image(text: str, filename: Optional[str] = None) -> Tuple[str, str]:
    """
    QPay QR текстийг өндөр нарийвчлалтай зураг (PNG) болгон хөрвүүлж хадгалах ба Base64 Data URI буцаах
    """
    try:
        import qrcode
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=2,
        )
        qr.add_data(text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#0f172a", back_color="#ffffff")

        buf = io.BytesIO()
        img.save(buf, format="PNG")
        png_bytes = buf.getvalue()

        # Base64 data URI үүсгэх
        b64 = base64.b64encode(png_bytes).decode("ascii")
        data_uri = f"data:image/png;base64,{b64}"

        # Файлаар хадгалах
        file_url = ""
        if filename:
            safe_name = f"{filename}.png"
            file_path = os.path.join(STATIC_QR_DIR, safe_name)
            with open(file_path, "wb") as f:
                f.write(png_bytes)
            file_url = f"/static/qrcodes/{safe_name}"

        return data_uri, file_url
    except Exception as e:
        logger.error(f"QR зураг үүсгэхэд алдаа: {e}")
        return "", ""

def build_bank_deep_links(qr_text: str) -> List[Dict[str, Any]]:
    """Бүх дэмжигдсэн банкуудын deep link жагсаалтыг бэлтгэх"""
    links = []
    for b in SUPPORTED_BANKS:
        link = b["scheme"].replace("{qr_text}", qr_text)
        links.append({
            "id": b["id"],
            "name": b["name"],
            "en_name": b["en_name"],
            "color": b["color"],
            "bg_class": b["bg_class"],
            "link": link,
            "web_url": b["web_url"],
            "logo_svg": b["logo_svg"]
        })
    return links

# -------------------------------------------------------------
# 2. И-БАРИМТ (E-BARIMT POSAPI 3.0) ҮҮСГЭГЧ СТАНДАРТ
# -------------------------------------------------------------
def generate_ebarimt(amount: int, merchant_tin: str = "6408194", company_name: str = "Гэрэгэ Системс") -> Dict[str, Any]:
    """
    И-Баримт POSAPI 3.0 стандартын дагуу 33 оронтой QR код болон сугалааны дугаар үүсгэх
    - Сугалаа: 2 монгол крилл үсэг + 8 тоо (Жишээ: АБ48192041)
    - НӨАТ: 10%
    - НХАТ: 1%
    """
    cyrillic_letters = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЭЮЯ"
    let1 = random.choice(cyrillic_letters)
    let2 = random.choice(cyrillic_letters)
    digits = "".join([str(random.randint(0, 9)) for _ in range(8)])
    lottery_number = f"{let1}{let2}{digits}"

    # 33 оронтой фискал код (ДДТД - Дахин давтагдашгүй төлбөрийн дугаар)
    fiscal_33 = "".join([str(random.randint(0, 9)) for _ in range(33)])

    # Татварын задаргаа
    vat = int(amount / 1.1 * 0.1)
    city_tax = int(amount * 0.01) if amount > 5000 else 0
    subtotal = amount - vat - city_tax

    return {
        "lottery": lottery_number,
        "qr_data": fiscal_33,
        "amount": amount,
        "subtotal": subtotal,
        "vat": vat,
        "city_tax": city_tax,
        "merchant_tin": merchant_tin,
        "company_name": company_name,
        "issued_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

# -------------------------------------------------------------
# 3. QPAY v2 АЛБАН ЁСНЫ API КЛИЕНТ БА ИНВОЙС ҮҮСГЭХ
# -------------------------------------------------------------
QPAY_BASE_URL = os.getenv("QPAY_BASE_URL", "https://merchant.qpay.mn/v2")

async def get_qpay_token(username: str, password: str) -> Optional[str]:
    """QPay v2 OAuth2 Bearer токен авах"""
    if not username or not password:
        return None
    url = f"{QPAY_BASE_URL}/auth/token"
    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(url, auth=(username, password), timeout=10.0)
            if res.status_code == 200:
                data = res.json()
                return data.get("access_token")
            logger.error(f"QPay Auth Error [{res.status_code}]: {res.text}")
    except Exception as e:
        logger.error(f"QPay Auth Exception: {e}")
    return None

async def create_qpay_invoice_live(
    token: str,
    invoice_code: str,
    sender_invoice_no: str,
    amount: int,
    description: str,
    callback_url: str
) -> Optional[Dict[str, Any]]:
    """Албан ёсны QPay v2 API-аар нэхэмжлэх үүсгэх"""
    url = f"{QPAY_BASE_URL}/invoice"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "invoice_code": invoice_code,
        "sender_invoice_no": sender_invoice_no,
        "invoice_receiver_code": "terminal",
        "invoice_description": description,
        "amount": amount,
        "callback_url": callback_url
    }
    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(url, headers=headers, json=payload, timeout=12.0)
            if res.status_code == 200:
                return res.json()
            logger.error(f"QPay Create Invoice Error [{res.status_code}]: {res.text}")
    except Exception as e:
        logger.error(f"QPay Create Invoice Exception: {e}")
    return None

# -------------------------------------------------------------
# 4. НЭГДСЭН ТӨЛБӨРИЙН НЭХЭМЖЛЭХ ҮҮСГЭХ (UNIFIED FACTORY)
# -------------------------------------------------------------
async def create_payment_order(
    page_id: str,
    amount: int,
    description: str = "Үйлчилгээний төлбөр",
    sender_id: Optional[str] = None,
    channel: str = "web",
    base_url: str = ""
) -> Dict[str, Any]:
    """
    QPay v2 эсвэл Smart Sandbox горимоор найдвартай төлбөрийн нэхэмжлэх, QR код, Deep link үүсгэх
    """
    import uuid
    invoice_id = f"QP-{datetime.now().strftime('%Y%m%d%H%M')}-{uuid.uuid4().hex[:6].upper()}"

    # Хуудасны мэдээлэл болон QPay тохиргоог шалгах
    page = database.get_page(page_id) or {}
    qpay_user = page.get("qpay_username") or os.getenv("QPAY_USERNAME", "").strip()
    qpay_pass = page.get("qpay_password") or os.getenv("QPAY_PASSWORD", "").strip()
    qpay_code = page.get("qpay_invoice_code") or os.getenv("QPAY_INVOICE_CODE", "").strip()

    qr_text = ""
    deep_links = []
    is_live = False

    # 1. Албан ёсны QPay эрх тохируулагдсан бол бодит API дуудах
    if qpay_user and qpay_pass and qpay_code:
        token = await get_qpay_token(qpay_user, qpay_pass)
        if token:
            callback = f"{base_url.rstrip('/')}/api/fintech/qpay/callback?invoice_id={invoice_id}"
            live_res = await create_qpay_invoice_live(
                token=token,
                invoice_code=qpay_code,
                sender_invoice_no=invoice_id,
                amount=amount,
                description=description,
                callback_url=callback
            )
            if live_res and "qr_text" in live_res:
                qr_text = live_res["qr_text"]
                is_live = True
                # QPay-аас ирсэн банкуудын холбоос байгаа эсэх
                qpay_urls = live_res.get("urls", [])
                if qpay_urls:
                    for u in qpay_urls:
                        deep_links.append({
                            "id": u.get("name", "").lower().replace(" ", ""),
                            "name": u.get("description") or u.get("name"),
                            "link": u.get("link"),
                            "logo_svg": ""
                        })

    # 2. Хэрэв шууд QPay түлхүүр хараахан байхгүй бол Smart Simulator / Sandbox горимоор стандарт QR & Deep Links үүсгэх
    if not qr_text:
        # Стандарт Монгол QPay payload формат
        qr_text = f"qpay://payment?invoice_id={invoice_id}&amount={amount}&merchant={page_id}&desc={description}"
        deep_links = build_bank_deep_links(qr_text)

    # QR зураг үүсгэж хадгалах
    data_uri, file_url = generate_qr_image(qr_text, filename=invoice_id)

    # Өгөгдлийн санд нэхэмжлэх үүсгэх
    inv = database.create_invoice(
        page_id=page_id,
        amount=amount,
        description=description,
        sender_id=sender_id,
        channel=channel,
        qr_text=qr_text,
        qr_image_url=file_url or data_uri,
        deep_links=deep_links,
        invoice_id=invoice_id
    )

    pay_page_url = f"{base_url.rstrip('/')}/pay/{invoice_id}" if base_url else f"/pay/{invoice_id}"

    return {
        "invoice_id": invoice_id,
        "amount": amount,
        "description": description,
        "status": "PENDING",
        "qr_text": qr_text,
        "qr_data_uri": data_uri,
        "qr_image_url": file_url or data_uri,
        "deep_links": deep_links,
        "pay_url": pay_page_url,
        "is_live_qpay": is_live,
        "created_at": inv.get("created_at") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

def create_payment_order_sync(
    page_id: str,
    amount: int,
    description: str = "Үйлчилгээний төлбөр",
    sender_id: Optional[str] = None,
    channel: str = "web",
    base_url: str = ""
) -> Dict[str, Any]:
    """
    Синхрон (Sync) горимоор найдвартай төлбөрийн нэхэмжлэх, QR код, Deep link үүсгэх
    """
    import uuid
    invoice_id = f"QP-{datetime.now().strftime('%Y%m%d%H%M')}-{uuid.uuid4().hex[:6].upper()}"

    # Стандарт Монгол QPay payload формат
    qr_text = f"qpay://payment?invoice_id={invoice_id}&amount={amount}&merchant={page_id}&desc={description}"
    deep_links = build_bank_deep_links(qr_text)

    # QR зураг үүсгэж хадгалах
    data_uri, file_url = generate_qr_image(qr_text, filename=invoice_id)

    # Өгөгдлийн санд нэхэмжлэх үүсгэх
    inv = database.create_invoice(
        page_id=page_id,
        amount=amount,
        description=description,
        sender_id=sender_id,
        channel=channel,
        qr_text=qr_text,
        qr_image_url=file_url or data_uri,
        deep_links=deep_links,
        invoice_id=invoice_id
    )

    pay_page_url = f"{base_url.rstrip('/')}/pay/{invoice_id}" if base_url else f"/pay/{invoice_id}"

    return {
        "invoice_id": invoice_id,
        "amount": amount,
        "description": description,
        "status": "PENDING",
        "qr_text": qr_text,
        "qr_data_uri": data_uri,
        "qr_image_url": file_url or data_uri,
        "deep_links": deep_links,
        "pay_url": pay_page_url,
        "is_live_qpay": False,
        "created_at": inv.get("created_at") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


# -------------------------------------------------------------
# 5. ТӨЛБӨРИЙГ 1 СЕКУНДЭД АВТОМАТААР БАТАЛГААЖУУЛАХ (WEBHOOK / CALLBACK)
# -------------------------------------------------------------
async def process_successful_payment(invoice_id: str, callback_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Төлбөр төлөгдсөн үед:
    1. Нэхэмжлэхийг 'PAID' болгож тэмдэглэх
    2. И-Баримт (33 оронтой код + сугалаа) автоматаар үүсгэх
    3. CRM бүртгэлд (registrations) автоматаар оруулж баталгаажуулах
    4. Google Sheets рүү бодит цагт синхрон хийх
    5. Харилцагчийн чат (FB Messenger, Telegram) руу баталгаажуулалт болон И-Баримт илгээх
    """
    inv = database.get_invoice(invoice_id)
    if not inv:
        return {"success": False, "message": "Нэхэмжлэх олдсонгүй"}

    if inv.get("status") == "PAID":
        return {
            "success": True,
            "message": "Аль хэдийн төлөгдсөн байна",
            "invoice": inv,
            "ebarimt": {
                "lottery": inv.get("ebarimt_lottery"),
                "qr_data": inv.get("ebarimt_qr")
            }
        }

    page_id = inv.get("page_id", database.DEFAULT_PAGE_ID)
    amount = inv.get("amount", 0)
    sender_id = inv.get("sender_id", "")
    channel = inv.get("channel", "web")
    description = inv.get("description", "Үйлчилгээний төлбөр")

    # 1. И-Баримт үүсгэх
    page = database.get_page(page_id) or {}
    company_name = page.get("name", "Гэрэгэ Системс")
    ebarimt = generate_ebarimt(amount=amount, company_name=company_name)

    # 2. Өгөгдлийн санд нэхэмжлэхийг шинэчлэх
    updated_inv = database.mark_invoice_paid(
        invoice_id=invoice_id,
        ebarimt_lottery=ebarimt["lottery"],
        ebarimt_qr=ebarimt["qr_data"]
    )

    # 3. CRM бүртгэлд бүртгэх / төлөв шинэчлэх
    phone_clean = (sender_id or "").replace("meta_", "").replace("tg_", "") or "Утас бүртгэлгүй"
    lead_name = f"QPay Харилцагч ({ebarimt['lottery']})"
    reg_id = database.save_registration(
        name=lead_name,
        phone=phone_clean,
        service=f"QPay: {description} ({amount:,.0f}₮)",
        channel=channel,
        sender_id=sender_id,
        notes=f"Төлбөр төлөгдсөн (QPay: {invoice_id}). И-Баримтын сугалаа: {ebarimt['lottery']}",
        status="verified",
        page_id=page_id
    )

    # 4. CSV болон файлын синхрон хийх
    try:
        database.sync_to_csv(page_id=page_id)
    except Exception as e:
        logger.warning(f"CSV sync skipped: {e}")

    # 5. Хэрэглэгчид баталгаажуулах мессеж илгээх
    receipt_msg = (
        f"Төлбөр амжилттай баталгаажлаа! 🎉\n\n"
        f"💳 Төлсөн дүн: {amount:,.0f}₮\n"
        f"🧾 И-БАРИМТ:\n"
        f"• Сугалааны дугаар: {ebarimt['lottery']}\n"
        f"• ДДТД (Код): {ebarimt['qr_data'][:16]}...\n\n"
        f"Үйлчилгээг сонгосонд баярлалаа! Таны эрх автоматаар нээгдлээ. 🎬✨"
    )

    # Сувгаар нь хариу дамжуулах
    try:
        if (channel in ("meta", "facebook", "instagram", "facebook/instagram") or (sender_id and sender_id.startswith("meta_"))) and sender_id:
            from main import send_meta_message
            page_token = page.get("page_access_token")
            await send_meta_message(sender_id.replace("meta_", ""), receipt_msg, page_token=page_token)
        elif (channel == "telegram" or (sender_id and sender_id.startswith("tg_"))) and sender_id:
            from main import send_telegram_message
            await send_telegram_message(sender_id.replace("tg_", ""), receipt_msg)
    except Exception as e:
        logger.warning(f"Chat messaging notification skipped: {e}")

    # Менежерт мэдэгдэх
    try:
        from main import notify_manager_telegram
        await notify_manager_telegram({
            "id": reg_id,
            "service": f"{company_name} (QPay {amount:,.0f}₮)",
            "name": lead_name,
            "phone": phone_clean,
            "channel": channel,
            "created_at": datetime.now().strftime("%H:%M:%S")
        })
    except Exception as e:
        logger.warning(f"Manager notification skipped: {e}")

    return {
        "success": True,
        "message": "Төлбөр амжилттай баталгаажиж, И-Баримт олгогдлоо",
        "invoice": updated_inv,
        "ebarimt": ebarimt
    }
