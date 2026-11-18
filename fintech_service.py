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


async def check_qpay_payment_live_detailed(
    token: str,
    object_id: str,
    expected_amount: int = 0,
    expected_currency: str = "MNT",
) -> Dict[str, Any]:
    """
    QPay v2 API (/v2/payment/check) дуудаж тухайн нэхэмжлэх бодитоор төлөгдсөн эсэх,
    мөнгөн дүн, валют болон provider_payment_id-г нарийвчлан шалгах (Phase 1.4 P0).
    """
    result = {
        "verified": False,
        "provider_payment_id": None,
        "paid_amount": 0,
        "currency": expected_currency,
    }
    if not token or not object_id:
        return result
    url = f"{QPAY_BASE_URL}/payment/check"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "object_type": "INVOICE",
        "object_id": object_id,
        "offset": {"page_number": 1, "page_limit": 10},
    }
    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(url, headers=headers, json=payload, timeout=10.0)
            if res.status_code == 200:
                data = res.json()
                rows = data.get("rows") or []
                paid_amt = int(float(data.get("paid_amount") or 0))
                result["paid_amount"] = paid_amt
                for r in rows:
                    status_str = str(r.get("payment_status", "")).upper()
                    row_currency = str(r.get("payment_currency") or expected_currency).upper()
                    row_amt = int(float(r.get("payment_amount") or 0))
                    if status_str == "PAID":
                        if expected_currency and row_currency != expected_currency.upper():
                            continue
                        if expected_amount <= 0 or paid_amt >= expected_amount or row_amt >= expected_amount:
                            result["verified"] = True
                            result["provider_payment_id"] = str(r.get("payment_id") or r.get("id") or "")
                            result["paid_amount"] = max(paid_amt, row_amt)
                            result["currency"] = row_currency
                            return result
                if paid_amt > 0 and (expected_amount <= 0 or paid_amt >= expected_amount):
                    result["verified"] = True
                    return result
    except Exception as e:
        logger.error(f"QPay Payment Check Exception: {e}")
    return result


async def check_qpay_payment_live(
    token: str,
    object_id: str,
    expected_amount: int = 0,
    expected_currency: str = "MNT",
) -> bool:
    """
    QPay v2 API (/v2/payment/check) дуудаж тухайн нэхэмжлэх бодитоор төлөгдсөн эсэхийг баталгаажуулах (Phase 1 P0).
    """
    detail = await check_qpay_payment_live_detailed(
        token=token,
        object_id=object_id,
        expected_amount=expected_amount,
        expected_currency=expected_currency,
    )
    return bool(detail.get("verified"))

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
    qpay_invoice_id = None

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
                qpay_invoice_id = live_res.get("invoice_id")
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
        invoice_id=invoice_id,
        currency="MNT",
        qpay_invoice_id=qpay_invoice_id,
    )

    pay_page_url = f"{base_url.rstrip('/')}/pay/{invoice_id}" if base_url else f"/pay/{invoice_id}"

    return {
        "invoice_id": invoice_id,
        "qpay_invoice_id": qpay_invoice_id,
        "amount": amount,
        "currency": "MNT",
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

    page = database.get_page(page_id) or {}
    qpay_user = page.get("qpay_username") or os.getenv("QPAY_USERNAME", "").strip()
    qpay_pass = page.get("qpay_password") or os.getenv("QPAY_PASSWORD", "").strip()
    qpay_code = page.get("qpay_invoice_code") or os.getenv("QPAY_INVOICE_CODE", "").strip()

    qr_text = ""
    deep_links = []
    is_live = False
    qpay_invoice_id = None

    if qpay_user and qpay_pass and qpay_code:
        try:
            with httpx.Client(timeout=10.0) as client:
                tok_res = client.post(f"{QPAY_BASE_URL}/auth/token", auth=(qpay_user, qpay_pass))
                if tok_res.status_code == 200:
                    token = tok_res.json().get("access_token")
                    if token:
                        callback = f"{base_url.rstrip('/')}/api/fintech/qpay/callback?invoice_id={invoice_id}"
                        inv_res = client.post(
                            f"{QPAY_BASE_URL}/invoice",
                            headers={"Authorization": f"Bearer {token}"},
                            json={
                                "invoice_code": qpay_code,
                                "sender_invoice_no": invoice_id,
                                "invoice_receiver_code": "terminal",
                                "invoice_description": description,
                                "amount": amount,
                                "callback_url": callback,
                            },
                        )
                        if inv_res.status_code == 200:
                            live_res = inv_res.json()
                            if live_res and "qr_text" in live_res:
                                qr_text = live_res["qr_text"]
                                qpay_invoice_id = live_res.get("invoice_id")
                                is_live = True
                                for u in live_res.get("urls", []):
                                    deep_links.append({
                                        "id": u.get("name", "").lower().replace(" ", ""),
                                        "name": u.get("description") or u.get("name"),
                                        "link": u.get("link"),
                                        "logo_svg": "",
                                    })
        except Exception as e:
            logger.error(f"QPay Sync Invoice Exception: {e}")

    if not qr_text:
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
        invoice_id=invoice_id,
        currency="MNT",
        qpay_invoice_id=qpay_invoice_id,
    )

    pay_page_url = f"{base_url.rstrip('/')}/pay/{invoice_id}" if base_url else f"/pay/{invoice_id}"

    return {
        "invoice_id": invoice_id,
        "qpay_invoice_id": qpay_invoice_id,
        "amount": amount,
        "currency": "MNT",
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


# -------------------------------------------------------------
# 5. ТӨЛБӨРИЙГ 1 СЕКУНДЭД АВТОМАТААР БАТАЛГААЖУУЛАХ (WEBHOOK / CALLBACK)
# -------------------------------------------------------------
def report_audit_outcome(result: Dict[str, Any], *, caller: str) -> bool:
    """Mount the payment result's audit outcome on the surface a monitor can see.

    E-03 (Phase 12 finding F-B). `process_successful_payment()` has always returned
    `audit_recorded`, but until now nothing read it: the only trace of a lost
    `payment.confirmed` row was a log line written inside the function. A log line
    that no alert watches is not a signal.

    This turns the field into an explicit, greppable, one-line event per payment so
    that "money moved, audit row did not" is visible at the point the response is
    built, with the caller and the invoice in the same record.

    Returns True when the caller should treat the payment as fully accounted for
    (nothing to report, or the audit was recorded), False when an audit loss was
    reported. It NEVER decides whether the payment succeeded — the money has already
    moved by the time any of this runs, and refusing or retrying the payment because
    a log write failed would be a worse outcome than recording it late.

    `audit_recorded is None` means no audit was expected on that path (replay or
    already-settled), so there is nothing to report and nothing to alarm on.
    """
    recorded = result.get("audit_recorded")
    if recorded is None or recorded is True:
        return True

    logger.error(
        "AUDIT LOSS (unreported to caller): payment %r settled successfully via %s "
        "but its payment.confirmed audit row was NOT written. The invoice is PAID. "
        "Reconstruct the audit from the provider callback.",
        result.get("invoice", {}).get("invoice_id") if isinstance(result.get("invoice"), dict) else None,
        caller,
    )
    return False


async def process_successful_payment(
    invoice_id: str,
    callback_data: Optional[Dict[str, Any]] = None,
    provider_payment_id: Optional[str] = None,
    callback_verified: int = 0,
) -> Dict[str, Any]:
    """
    Төлбөр төлөгдсөн үед (Idempotent & Replay-Protected):
    1. Нэхэмжлэхийг 'PAID' болгож тэмдэглэх
    2. И-Баримт (33 оронтой код + сугалаа) автоматаар үүсгэх
    3. CRM бүртгэлд (registrations) автоматаар оруулж баталгаажуулах
    4. Google Sheets рүү бодит цагт синхрон хийх
    5. Харилцагчийн чат (FB Messenger, Telegram) руу баталгаажуулалт болон И-Баримт илгээх
    """
    inv = database.get_invoice(invoice_id)
    if not inv:
        return {"success": False, "message": "Нэхэмжлэх олдсонгүй", "audit_recorded": None}

    if inv.get("status") == "PAID":
        # E-03 (Phase 12 finding F-B). `audit_recorded` is returned on EVERY path, so a
        # caller never has to guess whether a missing key means "audited fine" or "we
        # forgot". The three states are:
        #
        #   True  -> this call wrote its audit row
        #   False -> this call tried and FAILED to write it (payment still succeeded)
        #   None  -> no audit was expected: the payment was already settled and audited
        #            by the call that settled it
        #
        # Here the invoice was already PAID before this call did anything, so there is
        # nothing new to record and writing `payment.confirmed` again would fabricate a
        # second confirmation for one payment.
        return {
            "success": True,
            "message": "Аль хэдийн төлөгдсөн байна",
            "invoice": inv,
            "ebarimt": {
                "lottery": inv.get("ebarimt_lottery"),
                "qr_data": inv.get("ebarimt_qr")
            },
            "audit_recorded": None,
        }

    page_id = inv.get("page_id", database.DEFAULT_PAGE_ID)

    # Idempotency & Replay Lock: concurrent callback-ууд давхар баримт олгохоос хамгаална
    if not database.claim_notification_lock(
        f"qpay_paid:{invoice_id}",
        page_id=page_id,
        channel="qpay",
    ):
        fresh_inv = database.get_invoice(invoice_id) or inv
        # Same `None` policy as the already-PAID branch above, and for the same reason:
        # the lock is held by the call that is doing the work, so this one settled
        # nothing and must not claim an audit it did not write. Any other choice would
        # make a duplicate provider callback look like a fresh confirmation.
        return {
            "success": True,
            "message": "Аль хэдийн боловсруулагдсан байна (Idempotent Replay Guard)",
            "invoice": fresh_inv,
            "ebarimt": {
                "lottery": fresh_inv.get("ebarimt_lottery"),
                "qr_data": fresh_inv.get("ebarimt_qr"),
            },
            "audit_recorded": None,
        }

    amount = inv.get("amount", 0)
    sender_id = inv.get("sender_id", "")
    channel = inv.get("channel", "web")
    description = inv.get("description", "Үйлчилгээний төлбөр")

    if not provider_payment_id and isinstance(callback_data, dict):
        provider_payment_id = str(
            callback_data.get("provider_payment_id")
            or callback_data.get("payment_id")
            or callback_data.get("qpay_payment_id")
            or ""
        ).strip() or None

    # 1. И-Баримт үүсгэх
    page = database.get_page(page_id) or {}
    company_name = page.get("name", "Гэрэгэ Системс")
    ebarimt = generate_ebarimt(amount=amount, company_name=company_name)

    # 2. Өгөгдлийн санд нэхэмжлэхийг шинэчлэх
    updated_inv = database.mark_invoice_paid(
        invoice_id=invoice_id,
        ebarimt_lottery=ebarimt["lottery"],
        ebarimt_qr=ebarimt["qr_data"],
        provider_payment_id=provider_payment_id,
        callback_verified=callback_verified,
    )

    # E-02 Phase 11 (R17). This block used to be `except Exception: pass`, which turned a
    # caller-side TypeError into SILENT loss: every payment confirmation went unaudited
    # with no error, no log line and no failing test. It was the worst instance of R17 and
    # the one nobody could see.
    #
    # The audit is still not allowed to fail the payment — the money has already moved, and
    # refusing to record a completed payment would be a worse outcome than recording it
    # late. So it stays non-fatal, but it is now LOUD: a structured error log carrying the
    # invoice id, plus the flag this function returns so a caller can surface it.
    audit_ok = True
    try:
        database.record_audit_log(
            action="payment.confirmed",
            page_id=page_id,
            actor_role="system",
            actor_id=sender_id or "qpay_callback",
            resource_type="invoice",
            resource_id=invoice_id,
            details={
                "amount": amount,
                "provider_payment_id": provider_payment_id,
                "callback_verified": callback_verified,
                "ebarimt_lottery": ebarimt["lottery"],
            },
        )
    except Exception:
        audit_ok = False
        logger.error(
            "AUDIT LOSS: payment.confirmed for invoice %r (page %r) was NOT recorded; "
            "the payment itself succeeded. Reconstruct from the provider callback.",
            invoice_id, page_id, exc_info=True,
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
        "ebarimt": ebarimt,
        # E-02 Phase 11 (R17): False means the payment succeeded but its
        # `payment.confirmed` audit row was NOT written. Surfaced rather than
        # hidden, so a caller or monitor can act on it.
        "audit_recorded": audit_ok,
    }
