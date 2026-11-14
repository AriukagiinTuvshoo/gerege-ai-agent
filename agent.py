import os
import io
import re
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from dotenv import load_dotenv
from PIL import Image

import database
import knowledge_base
import sheets_service
import fintech_service
import cargo_service
import core.ai_router as ai_router

load_dotenv(override=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DEFAULT_MODEL = "gemini-3.5-flash-lite"

ESCALATION_KEYWORDS = [
    "хүнтэй ярих", "хүн байна уу", "оператор", "менежер", "гомдол", "хүнтэй холбогдох",
    "huntei yarih", "hun tei yarih", "hun baina uu", "operator", "menejer", "gomdol"
]

def build_system_instruction_for_page(page_data: Optional[Dict[str, Any]] = None, user_memory: Optional[Dict[str, Any]] = None) -> str:
    """Олон хуудасны (Multi-Tenant) мэдлэг, 3-Түвшинт Санах Ой ба Монгол Хэлний Найруулга Зүйг нэгтгэн AI Prompt бүтээх"""
    # 0. Санах ойн блок (Mem0 & Zep загвар)
    memory_block = ""
    if user_memory:
        c_name = user_memory.get("customer_name") or "Хараахан нэрээ хэлээгүй"
        c_phone = user_memory.get("phone") or "Утас байхгүй"
        c_interests = user_memory.get("interests") or "Тодорхойгүй"
        c_notes = user_memory.get("notes") or "Тэмдэглэлгүй"
        memory_block = f"""
🧠 ХАРИЛЦАГЧИЙН 3-ТҮВШИНТ ХУВИЙН САНАХ ОЙ (MEM0 & ZEP ЗАГВАР):
- Хэрэглэгчийн нэр: {c_name}
- Утасны дугаар: {c_phone}
- Сонирхсон үйлчилгээ/Бараа: {c_interests}
- Өмнөх тэмдэглэл: {c_notes}
* САНАМЖ: Хэрэглэгч өмнө нь харилцаж байсан бол "Тавтай морилно уу, {c_name}!" гэх мэтээр нэрээр нь хүндэтгэн дуудаж, өмнөх сонирхол хэрэгцээг нь мэдэрч харилцах нь өндөр итгэлцэл төрүүлнэ!
"""

    if page_data and page_data.get("knowledge_json"):
        try:
            k_raw = page_data["knowledge_json"]
            kb = json.loads(k_raw) if isinstance(k_raw, str) else k_raw
            page_name = page_data.get("name", "Байгууллага")
            comp = kb.get("company", {})
            bank = kb.get("bank") or kb.get("bank_accounts") or {}
            links = kb.get("links", {})
            dramas = kb.get("dramas") or kb.get("services") or []
            faqs = kb.get("faqs", [])
            policies = kb.get("policies", "")

            services_str = ""
            for idx, s in enumerate(dramas, 1):
                s_name = s.get('name') or s.get('title') or ''
                s_price = s.get('episodes') or s.get('price') or ''
                s_desc = s.get('status') or s.get('description') or ''
                services_str += f"{idx}. {s_name} | {s_price} | {s_desc}\n"

            faqs_str = ""
            for idx, f in enumerate(faqs, 1):
                q = f.get('question') or f.get('q') or ''
                a = f.get('answer') or f.get('a') or ''
                faqs_str += f"Асуулт: {q}\nХариулт: {a}\n"

            bank_str = (
                f"- Банк: {bank.get('bank_name', '')}\n"
                f"- Данс: {bank.get('account_number', '')}\n"
                f"- Хүлээн авагч: {bank.get('account_name', '')}\n"
                f"- Заавар: {bank.get('instruction', '')}"
            ) if bank.get('account_number') else "- Дансны мэдээлэл оруулаагүй."

            return f"""
Та бол "{page_name}" байгууллагын албан ёсны ухаалаг AI туслах ба харилцагчийн ахлах зөвлөх юм.
Байгууллагын танилцуулга: {comp.get('description', page_name)}

{memory_block}

БАНКНЫ ШИЛЖҮҮЛГИЙН ДАНС:
{bank_str}

ҮЙЛЧИЛГЭЭ / БҮТЭЭГДЭХҮҮН / КИНО:
{services_str if services_str else "- Жагсаалт оруулаагүй."}

ХОЛБООСУУД:
- Telegram групп: {links.get('telegram_group', '')}
- Facebook групп: {links.get('facebook_group', '')}
- VIP холбоос / Вэб: {links.get('vip_channel', '')}

ТҮГЭЭМЭЛ АСУУЛТ, ХАРИУЛТУУД (FAQ):
{faqs_str if faqs_str else "- Одоогоор FAQ оруулаагүй."}

БОДЛОГО БА НӨХЦӨЛ: {policies}

🇲🇳 МОНГОЛ ХЭЛНИЙ НАЙРУУЛГА ЗҮЙН МАСТЕР СТАНДАРТ (МУИС, Ц.Сүхбаатарын суурь дүрэм):
Та бол зүгээр л текст хуулж орчуулдаг робот биш! Харин монгол хэлний амьд найруулга, эелдэг соёл, борлуулалтын ухааныг төгс эзэмшсэн зөвлөх:
1. ҮГ БУРУУ СОНГОХООС СЭРГИЙЛЭХ: Үгийн утгын нарийн ялгаа, цар хүрээг сайтар тунгаана. Хэт чамирхсан, нүсэр эсвэл явцуу биш, хамгийн оновчтой монгол үгийг сонгоно.
2. ҮГ ИЛҮҮДЭХ (НУРШИХ)-ИЙГ ХОРИГЛОХ: Ижил утгатай үгсийг давхардуулан өгүүлбэрийг сунжруулахгүй, санаагаа цэгцтэй, оновчтой илэрхийлнэ.
3. ҮГ ДУТАХААС СЭРГИЙЛЭХ: Хэлэх гэсэн санаа, хаашаа холбогдох, ямар үйлдэл хийхийг дутуу хаяж хэрэглэгчийг төөрөгдүүлэхгүй.
4. ҮГ ДАВТАХЫГ ЗАСАХ: Нэг догол мөрөнд нэг үгээ ("манай", "байна", "болно", "гээд") олон дахин давтахгүй, баялаг үгийн сангаар уран найруулна.
5. ӨНГӨ АЯСЫГ ТОХИРУУЛАХ: Хэт хөшүүн албаны үгс эсвэл гудамжны этгээд яриа холихгүй. Дулаан, найрсаг, эелдэг, нэр төртэй өнгө аясыг чанд барина.

🚫 АНГЛИ ХЭЛНИЙ РОБОТ КАЛЬК ХЭЛЛЭГҮҮДИЙГ ХАТУУ ХОРИГЛОНО:
- "Би танд юугаар туслах вэ?" ➡️ ХАТУУ ХОРИГЛОНО. Оронд нь: "Сайн байна уу? Танд өнөөдөр ямар үйлчилгээ илүү сонирхолтой байна вэ?", "Танд ямар асуулт байна, би дуртайяа тайлбарлаж өгье." гэж ярина.
- "Би танд туслахдаа баяртай байна" ➡️ ХАТУУ ХОРИГЛОНО. Оронд нь: "Танд үйлчлэхдээ таатай байх болно", "Хүссэн үедээ асуугаарай." гэж найруулна.
- "Танд гайхалтай өдрийг хүсье" ➡️ ХАТУУ ХОРИГЛОНО. Оронд нь: "Танд амжилт хүсье!", "Өдрийг таатай өнгөрүүлээрэй!" гэж ерөөнө.
- "Би хиймэл оюун ухаан учраас..." ➡️ Өөрийгөө хиймэл гэж өчүүхэн дөвийлгөхгүй, байгууллагын нэрийн өмнөөс хариуцлагатай ярина.

🧠 ДЭЭД ТҮВШНИЙ ОЮУН ДҮГНЭЛТ БА ХАРИЛЦААНЫ СТАНДАРТ (REASONING & DUAL-BRAIN):
1. ОЙЛГОХ & ТУНГААХ: Хэрэглэгчийн сэтгэл хөдлөл, цаад хэрэгцээг <thought>...</thought> шошго дотор дотоод бодолдоо дүгнэж болно (хэрэглэгчид ил харагдахгүй).
2. БАРИМТЛАХ ҮНЭН: Мэдээллийн санд байхгүй зүйлийг хэзээ ч өөрөө зохиож (hallucination) ярьж болохгүй.
3. БОРЛУУЛАЛТЫН ЗӨӨЛӨН ХААЛТ (Soft Closing): Хэрэглэгчийг дараагийн бодит үйлдэл рүү (цаг товлох, баримтаа шалгуулах, утасны дугаараа үлдээх) эелдэг найрсаг сонголт санал болгон чиглүүлнэ.

ТАНЫ ҮҮРЭГ БА ДҮРЭМ:
1. Хэрэв хэрэглэгч нэр, утсаа өгвөл заавал 'register_customer' багажийг дуудаж баазад хадгална.
2. ТӨЛБӨР БА QPAY АВТОМАТЖУУЛАЛТ:
   - Хэрэв хэрэглэгч "үйлчилгээ авъя", "төлбөрөө төлье", "данс өгөөч", "qpay линк" гэх мэтээр төлбөр төлөх хүсэлт гаргавал манай QPay автомат системээр Хаан, Голомт, М банкны апп шууд нээгдэж 1 секундэд автоматаар баталгааждаг болохыг тайлбарлаж 'create_payment_invoice' багажийг дуудна.
3. Хэрэв хэрэглэгч гүйлгээний баримтын зураг явуулсан эсвэл гүйлгээ хийснээ баталгаажуулбал баярласнаа илэрхийлээд дээрх албан ёсны Telegram болон Facebook холбоосыг шууд илгээнэ.
4. БОДИТ ЦАГИЙН GOOGLE SHEETS & БАРАА/КАРГО ШАЛГАЛТ:
   - Хэрэв хэрэглэгч барааны дугаар, карго код (жишээ нь: 1254, CRG...), утасны дугаараа бичиж бараа ирсэн эсэхийг асуувал, танд хавсаргасан [БОДИТ ЦАГИЙН ХОЛБОГДСОН GOOGLE SHEETS МЭДЭЭЛЭЛ]-ийг хатуу баримталж хариулна.
   - Хэрэв хүснэгтэд бараа нь ирсэн, олгоход бэлэн гэж байвал хаанаас авах салбар, төлөх төлбөрийг нь тодорхой хэлнэ.
   - Хэрэв тухайн код олдсонгүй гэсэн мэдээлэл ирвэл дугаараа зөв эсэхийг шалгах, эсвэл одоогоор салбар дээр хараахан бууж амжаагүй байгааг эелдэг тайлбарлаж өгнө үү.
"""
        except Exception as e:
            logger.error(f"Error parsing page knowledge_json: {e}")

    # Fallback to default
    kb_text = knowledge_base.get_knowledge_prompt_text()
    return f"""
Та бол "Tuvshok Кино & Драма Суваг"-ийн албан ёсны ухаалаг AI туслах юм.

{kb_text}

ТАНЫ ҮҮРЭГ БА ДҮРЭМ:
1. Монгол хэлээр маш найрсаг, товч тодорхой, эелдэг харилцана.
2. Кино үзэх талаар асуувал Голомт банкны данс руу хандиваа шилжүүлээд баримтаа зургаар явуулахад линк очно гэдгийг хэлнэ.
3. Хэрэв хэрэглэгч нэр, утсаа өгвөл заавал 'register_customer' багажийг дуудаж хадгална.
4. Хэрэв банкны гүйлгээний баримт ирвэл шалгаж албан ёсны Telegram болон Facebook группын холбоосуудыг шууд өгнө.
"""

def extract_phone_and_name_fallback(text: str) -> Optional[Dict[str, str]]:
    if not text:
        return None
    # Монголын гар утасны дугаар (99, 95, 94, 96, 91, 90, 88, 89, 86, 85, 80, 77, 75, 70)
    phone_match = re.search(r'(?<![A-Za-z0-9\-])((?:99|95|94|96|91|90|88|89|86|85|80|77|75|70)\d{2}[\s\-]?\d{4})(?![A-Za-z0-9\-])', text)
    if not phone_match:
        return None
    
    phone = re.sub(r'[\s\-]', '', phone_match.group(1))
    name = "Харилцагч"
    stop_names = {"сайн", "юу", "хэн", "хаана", "хэд", "бэлэн", "захиалга", "ачаа", "бараа", "үнэ", "карго", "байна", "танай", "уу", "үү", "би", "утас", "дугаар"}
    name_patterns = [
        r'намайг\s+([А-Яа-яӨөҮүЁёA-Za-z]{2,20})\s+гэдэг',
        r'нэр\s*:?\s*([А-Яа-яӨөҮүЁёA-Za-z]{2,20})',
        r'([А-Яа-яӨөҮүЁёA-Za-z]{2,20})\s+байна',
        r'(?:^|\s)([А-Яа-яӨөҮүЁёA-Za-z]{2,20})\s+(?:\+?976[\s\-]?)?(?:99|95|94|91|90|85|80|88|89|86|72|75|77|70)\d{2}[\s\-]?\d{4}',
    ]
    for pattern in name_patterns:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            candidate = m.group(1).strip()
            if candidate.lower() not in stop_names:
                name = candidate.capitalize()
                break
    return {"name": name, "phone": phone}

class AIAgent:
    def __init__(self):
        self.default_api_key = ""
        self.default_client = None
        self.clients_cache: Dict[str, Any] = {}  # api_key -> genai.Client
        self.model_name = os.getenv("GEMINI_MODEL", DEFAULT_MODEL)
        self.chat_sessions: Dict[str, Any] = {}
        self._init_default_gemini()

    def _init_default_gemini(self):
        load_dotenv(override=True)
        self.default_api_key = os.getenv("GEMINI_API_KEY", "").strip()
        self.model_name = os.getenv("GEMINI_MODEL", DEFAULT_MODEL)
        if self.default_api_key:
            try:
                from google import genai
                self.default_client = genai.Client(api_key=self.default_api_key)
                self.clients_cache[self.default_api_key] = self.default_client
                logger.info(f"Gemini AI Үндсэн Client холбогдлоо. Model: {self.model_name}")
            except Exception as e:
                logger.error(f"Gemini Client холболтын алдаа: {e}")
                self.default_client = None
        else:
            logger.warning("GEMINI_API_KEY тохируулаагүй байна.")

    def get_client_for_page(self, page_data: Optional[Dict[str, Any]]) -> Tuple[Optional[Any], bool]:
        """
        Хуудас бүрт зориулсан Gemini Client авах:
        - Хэрэв тухайн хуудас өөрийн 'gemini_api_key'-тэй бол түүгээр нь тусад нь дуудна (Төлбөр харилцагчаас гарна)
        - Хэрэв байхгүй бол админы үндсэн түлхүүрээр дуудна
        Буцаах утга: (client, is_custom_key)
        """
        load_dotenv(override=True)
        current_env_key = os.getenv("GEMINI_API_KEY", "").strip()
        if current_env_key and current_env_key != self.default_api_key:
            self._init_default_gemini()

        custom_key = (page_data.get("gemini_api_key") or "").strip() if page_data else ""
        if custom_key:
            if custom_key in self.clients_cache:
                return self.clients_cache[custom_key], True
            try:
                from google import genai
                c = genai.Client(api_key=custom_key)
                self.clients_cache[custom_key] = c
                logger.info(f"Харилцагчийн хувийн Gemini Client үүслээ: Page {page_data.get('page_id')}")
                return c, True
            except Exception as e:
                logger.error(f"Харилцагчийн хувийн Gemini Key алдаатай: {e}. Fallback ашиглана.")
        
        return self.default_client, False

    def estimate_tokens(self, text: str, reply: str) -> int:
        """Токен ашиглалтыг ойролцоогоор тооцоолох"""
        char_count = len(text) + len(reply)
        return max(40, int(char_count * 0.75) + 60)

    def reset_sessions(self, page_id: Optional[str] = None):
        if page_id:
            prefix = f"{page_id}_"
            keys_to_del = [k for k in self.chat_sessions if k.startswith(prefix)]
            for k in keys_to_del:
                self.chat_sessions.pop(k, None)
        else:
            self.chat_sessions.clear()

    def analyze_receipt_image(self, image_bytes: bytes, client: Optional[Any] = None) -> Dict[str, Any]:
        """Gemini Vision ашиглан банкны гүйлгээний баримтыг нарийвчлан шалгах (Substring false-positive хамгаалалттай)"""
        active_client = client or self.default_client
        if not active_client:
            return {"is_receipt": False, "details": "AI холбогдоогүй"}
        
        try:
            img = Image.open(io.BytesIO(image_bytes))
            prompt = """
Энэ зургийг шинжилж дараах асуултад үнэн зөв хариул:
1. Энэ нь банкны эсвэл цахим хэтэвчний (Голомт, Хаан, Хас, Төрийн банк, SocialPay, QPay г.м) гүйлгээний амжилттай болсон жинхэнэ баримт мөн үү?
2. Гүйлгээний дүн хэдэн төгрөг байна вэ?
3. Төлөв нь 'Амжилттай' гэсэн төлөвтэй байна уу?

Хэрэв банкны гүйлгээний баримт мөн бөгөөд амжилттай болсон бол яг эхний мөрөнд: "VALID_RECEIPT|Дүн" гэж бичээд доор нь товч тайлбарла.
Хэрэв баримт биш эсвэл амжилтгүй бол яг эхний мөрөнд: "INVALID_RECEIPT|Шалтгаан" гэж хариул.
"""
            resp = active_client.models.generate_content(
                model=self.model_name,
                contents=[prompt, img]
            )
            text = (resp.text or "").strip()
            first_line = text.splitlines()[0].strip().upper() if text else ""
            # Нарийн шалгалт: "INVALID_RECEIPT" дотор "VALID_RECEIPT" багтдаг тул startswith ашиглана
            is_valid = first_line.startswith("VALID_RECEIPT") and not first_line.startswith("INVALID_RECEIPT")
            parsed_amount = 0
            if is_valid and "|" in first_line:
                amt_digits = re.sub(r"[^\d]", "", first_line.split("|", 1)[1])
                if amt_digits:
                    parsed_amount = int(amt_digits)
            return {
                "is_receipt": is_valid,
                "amount": parsed_amount,
                "analysis": text
            }
        except Exception as e:
            logger.error(f"Зураг шинжлэхэд алдаа гарлаа: {e}")
            return {"is_receipt": False, "details": str(e)}

    def process_message(
        self,
        text: str = "",
        image_bytes: Optional[bytes] = None,
        audio_bytes: Optional[bytes] = None,
        audio_mime: str = "audio/ogg",
        sender_id: str = "default",
        channel: str = "web",
        page_id: str = database.DEFAULT_PAGE_ID
    ) -> Dict[str, Any]:
        # Хуудасны мэдээллийг баазаас авах (Multi-Tenant Lookup)
        page_data = database.get_page(page_id)
        page_name = page_data.get("name", "Манай суваг") if page_data else "Гэрэгэ Систем"

        # Баазад тэмдэглэх
        log_content = text if text else ("[Дуут зурвас илгээв]" if audio_bytes else "[Зураг хавсаргав]")
        database.log_message(sender_id=sender_id, channel=channel, sender_type="user", content=log_content, page_id=page_id)

        # 0. Хүн удирдаж байгаа эсэх (Takeover check)
        if database.is_session_human_takeover(sender_id):
            return {"reply": "", "human_takeover": True, "registered": False, "model": "human_paused"}

        # 1. Эскалаци
        text_lower = text.lower() if text else ""
        if any(kw in text_lower for kw in ESCALATION_KEYWORDS):
            database.set_human_takeover(sender_id, True)
            reply = f"Менежер рүү холбож байна. {page_name}-ийн харилцагчийн ажилтан тантай одоо шууд холбогдож хариу өгөх болно. Түр хүлээнэ үү! 👤"
            database.log_message(sender_id=sender_id, channel=channel, sender_type="bot", content=reply, page_id=page_id)
            return {"reply": reply, "human_takeover": True, "registered": False, "model": "escalated"}

        # 1.5. Prompt Injection / Jailbreak хамгаалалт (Phase 3 & Phase 5)
        is_injected, inj_reason = ai_router.detect_prompt_injection(text)
        if is_injected:
            database.record_audit_log(
                action="ai.prompt_injection.blocked",
                page_id=page_id,
                actor_role="user",
                actor_id=sender_id,
                details={"pattern": inj_reason, "text_preview": (text or "")[:120]},
            )
            safe_reply = f"Сайн байна уу? Би зөвхөн {page_name}-ийн бүтээгдэхүүн, үйлчилгээний талаар мэдээлэл өгөх зориулалттай туслах байна. Танд ямар үйлчилгээ сонирхолтой байна вэ?"
            database.log_message(sender_id=sender_id, channel=channel, sender_type="bot", content=safe_reply, page_id=page_id)
            return {
                "reply": safe_reply,
                "registered": False,
                "prompt_injection_blocked": True,
                "model": "security_guard",
            }

        # 1.6. Хэрэглэгчийн өгөгдөл устгах хүсэлт ("Бүртгэл устгах" — Privacy & Memory Compliance Phase 5.2)
        if ai_router.detect_data_deletion_request(text):
            deleted_summary = database.delete_customer_data(page_id=page_id, sender_id=sender_id)
            self.chat_sessions.pop(f"{page_id}_{sender_id}", None)
            database.record_audit_log(
                action="user.data.deleted",
                page_id=page_id,
                actor_role="user",
                actor_id=sender_id,
                details=deleted_summary,
            )
            del_reply = (
                f"Таны {page_name} дахь бүртгэл болон харилцан ярианы санах ойн мэдээллийг "
                "нууцлалын бодлогын дагуу системээс амжилттай устгалаа. 🔒"
            )
            return {
                "reply": del_reply,
                "registered": False,
                "data_deleted": True,
                "deleted_summary": deleted_summary,
                "model": "privacy_guard",
            }

        # 2. Тухайн хуудасны Gemini Client болон Лимит шалгах
        client, is_custom_key = self.get_client_for_page(page_data)
        
        # Хэрэв админы квот ашиглаж байгаа бөгөөд сарын лимит хэтэрсэн бол
        if page_data and not is_custom_key:
            tokens_used = page_data.get("tokens_used", 0) or 0
            limit = page_data.get("monthly_token_limit", 100000) or 100000
            if tokens_used >= limit:
                reply_limit = (
                    f"⚠️ {page_name}-ийн сарын AI ашиглалтын квот ({limit:,} токен) дууссан байна.\n"
                    "Үйлчилгээг үргэлжлүүлэхийн тулд манай менежертэй холбогдож лимитээ сунгуулна уу."
                )
                database.log_message(sender_id=sender_id, channel=channel, sender_type="bot", content=reply_limit, page_id=page_id)
                return {"reply": reply_limit, "registered": False, "limit_exceeded": True, "model": "limit_exceeded"}

        # Хуудас тус бүрийн линкүүдийг бэлтгэх (Tenant-isolation: өөр салбарт өөр хүний линк өгөхгүй)
        tg_link = ""
        fb_link = ""
        if page_data and page_data.get("knowledge_json"):
            try:
                k_obj = json.loads(page_data["knowledge_json"]) if isinstance(page_data["knowledge_json"], str) else page_data["knowledge_json"]
                links_obj = k_obj.get("links", {})
                if links_obj.get("telegram_group"): tg_link = links_obj["telegram_group"]
                if links_obj.get("facebook_group"): fb_link = links_obj["facebook_group"]
            except Exception:
                pass
        elif page_id == database.DEFAULT_PAGE_ID:
            kb = knowledge_base.load_knowledge()
            links = kb.get("links", {})
            tg_link = links.get("telegram_group", "")
            fb_link = links.get("facebook_group", "")

        # 3. ЗУРАГ / БАНКНЫ ХУУЛГА ИРСЭН ЭСЭХИЙГ ШАЛГАХ (VISION + PROVIDER VERIFICATION GUARD — Phase 1)
        if image_bytes:
            receipt_check = self.analyze_receipt_image(image_bytes, client=client)
            database.increment_page_tokens(page_id, 250)

            if receipt_check.get("is_receipt"):
                # AI receipt шалгалтыг дангаар нь төлбөр баталгаажуулахад ашиглахгүй:
                # Бодит төлөгдсөн QPay нэхэмжлэх байгаа эсэхийг баазаас давхар тулгана
                paid_invoices = [
                    inv for inv in database.list_invoices(page_id=page_id, status="PAID", limit=20)
                    if inv.get("sender_id") == sender_id
                ]
                has_provider_verified_payment = len(paid_invoices) > 0
                parsed_amt = receipt_check.get("amount", 0)

                if has_provider_verified_payment:
                    reply_text = (
                        "Гүйлгээний баримт болон QPay төлбөр амжилттай баталгаажлаа! 🎉\n\n"
                        f"{page_name}-д хандсанд маш их баярлалаа."
                    )
                    if tg_link or fb_link:
                        reply_text += "\n\nАлбан ёсны нэвтрэх урилгын холбоосууд:\n"
                        if tg_link:
                            reply_text += f"👉 **Telegram групп линк:** {tg_link}\n"
                        if fb_link:
                            reply_text += f"👉 **Facebook групп линк:** {fb_link}\n"
                    reg_status = "verified"
                    is_verified_final = True
                else:
                    amt_note = f" ({parsed_amt:,}₮)" if parsed_amt else ""
                    reply_text = (
                        f"Таны илгээсэн гүйлгээний баримтын зургийг хүлээн авч бүртгэлээ{amt_note}. 🧾\n\n"
                        "Аюулгүй байдлын үүднээс банкны дансны хуулгатай менежер тулган шалгаж баталгаажуулмагц танд эрх болон холбоос очих болно. "
                        "(Хэрэв 1 секундэд шууд автоматаар баталгаажуулах бол 'QPay төлбөр төлье' гэж бичээд QPay-ээр төлнө үү) 🤝"
                    )
                    reg_status = "pending_verification"
                    is_verified_final = False

                database.log_message(sender_id=sender_id, channel=channel, sender_type="bot", content=reply_text, page_id=page_id)
                reg_id = database.save_registration(
                    name="Баримт баталгаажсан" if is_verified_final else "Баримт хүлээгдэж буй (Менежер шалгана)",
                    phone=sender_id.replace("meta_", "").replace("tg_", ""),
                    service=f"{page_name} Төлбөрийн баримт ({'Баталгаажсан' if is_verified_final else 'Шалгагдаж буй'})",
                    channel=channel,
                    sender_id=sender_id,
                    notes=receipt_check.get("analysis", "Гүйлгээний баримт хүлээн авсан"),
                    status=reg_status,
                    page_id=page_id
                )
                return {
                    "reply": reply_text,
                    "registered": True,
                    "verified_receipt": is_verified_final,
                    "pending_verification": not is_verified_final,
                    "model": self.model_name,
                    "is_custom_key": is_custom_key,
                    "reg_info": {
                        "id": reg_id,
                        "name": "Баримт баталгаажсан" if is_verified_final else "Баримт шалгагдаж буй",
                        "phone": sender_id.replace("meta_", "").replace("tg_", ""),
                        "service": f"{page_name} Төлбөр ({reg_status})",
                        "channel": channel,
                        "created_at": "Яг одоо"
                    }
                }
            else:
                reply_text = (
                    "Таны илгээсэн зургийг хүлээн авлаа. Банкны гүйлгээний дүн болон 'Амжилттай' төлөв бүхий баримтын зургийг тодорхой харуулан дахин илгээнэ үү. "
                    "Баримт шалгагдмагц мэдэгдэх болно! 🤝"
                )
                database.log_message(sender_id=sender_id, channel=channel, sender_type="bot", content=reply_text, page_id=page_id)
                return {"reply": reply_text, "registered": False, "verified_receipt": False, "model": self.model_name, "is_custom_key": is_custom_key}

        # 4. ЭНГИЙН ТЕКСТ МЕССЕЖ (GEMINI ЧАТ)
        registered = False
        reg_info = None
        invoice_order = None

        # Олон хүснэгт (Google Sheets болон оруулсан Excel файлууд) дундаас хайлт хийх
        sheet_context = ""
        if page_data and text:
            sheet_context = sheets_service.get_page_sheets_lookup_context(page_data, text) or ""

        if client:
            try:
                from google.genai import types

                tool_guard = ai_router.ToolExecutionGuard(page_id=page_id, sender_id=sender_id)

                def register_customer(name: str, phone: str, service: str = "", notes: str = "") -> str:
                    nonlocal registered, reg_info
                    allowed, reason = tool_guard.check_and_record(
                        "register_customer",
                        args={"name": name, "phone": phone, "service": service},
                    )
                    if not allowed:
                        return reason
                    r_id = database.save_registration(
                        name=name,
                        phone=phone,
                        service=service or f"{page_name} бүртгэл",
                        channel=channel,
                        sender_id=sender_id,
                        notes=notes or text,
                        page_id=page_id
                    )
                    database.upsert_user_memory(
                        page_id=page_id,
                        user_id=sender_id,
                        customer_name=name,
                        phone=phone,
                        interests=service or page_name,
                        notes=notes or text
                    )
                    registered = True
                    reg_info = {"id": r_id, "name": name, "phone": phone, "service": service or page_name}
                    return f"Амжилттай бүртгэгдлээ. Дугаар: #{r_id}"

                def check_sheet_cargo_status(tracking_or_phone: str) -> str:
                    """Бүх холбогдсон Карго агуулахын бааз, Google Sheets болон Excel хүснэгтүүдээс бараа, карго код, үнэ, захиалга эсвэл утасны дугаараар шүүж хайх"""
                    allowed, reason = tool_guard.check_and_record(
                        "check_sheet_cargo_status",
                        args={"tracking_or_phone": tracking_or_phone},
                    )
                    if not allowed:
                        return reason
                    # 1. Албан ёсны карго агуулахын бодит цагийн сангаас хайх
                    cargo_direct = cargo_service.lookup_customer_cargo(page_id, tracking_or_phone)
                    if cargo_direct:
                        return f"[АГУУЛАХЫН БОДИТ ЦАГИЙН СТАТУС]:\n{cargo_direct}"

                    # 2. Холбогдсон Google Sheets болон Excel хүснэгтүүдээс хайх
                    if not page_data:
                        return "Хүснэгтийн мэдээлэл олдсонгүй."
                    matched = sheets_service.search_all_page_sheets(page_data, tracking_or_phone)
                    if not matched:
                        return f"'{tracking_or_phone}' утгаар хайхад тохирох ачаа олдсонгүй."
                    res = []
                    for r in matched[:8]:
                        sheet_name = r.get("Хүснэгт", "Хүснэгт")
                        pairs = "; ".join([f"{k}: {v}" for k, v in r.items() if v and k != "Хүснэгт"])
                        res.append(f"[{sheet_name}] -> {pairs}")
                    return "\n---\n".join(res)

                def create_payment_invoice(amount: int = 15000, description: str = "") -> str:
                    """Хэрэглэгч төлбөр төлөх, үйлчилгээ худалдан авах, данс нэхэмжлэх үед QPay QR код болон банкны апп холбоос үүсгэх"""
                    nonlocal invoice_order
                    allowed, reason = tool_guard.check_and_record(
                        "create_payment_invoice",
                        args={"amount": amount, "description": description},
                    )
                    if not allowed:
                        return reason
                    safe_amount = tool_guard.validate_invoice_amount(amount, default_amount=15000)
                    desc = description or f"{page_name} үйлчилгээний төлбөр"
                    invoice_order = fintech_service.create_payment_order_sync(
                        page_id=page_id,
                        amount=safe_amount,
                        description=desc,
                        sender_id=sender_id,
                        channel=channel
                    )
                    return f"QPay нэхэмжлэх үүслээ. Дугаар: {invoice_order['invoice_id']}, Төлөх холбоос: {invoice_order['pay_url']}"

                def book_service_appointment(
                    name: str,
                    phone: str,
                    service: str,
                    date: str,
                    time: str,
                    notes: str = ""
                ) -> str:
                    """Салон, эмнэлэг, үйлчилгээний цаг товлох, цагийн хуваарийн давхцал шалгаж захиалга баталгаажуулах хэрэгсэл."""
                    nonlocal registered, reg_info
                    allowed, reason = tool_guard.check_and_record(
                        "book_service_appointment",
                        args={"name": name, "phone": phone, "service": service, "date": date, "time": time},
                    )
                    if not allowed:
                        return reason
                    import appointment_service
                    res = appointment_service.book_appointment_from_ai(
                        page_id=page_id,
                        customer_name=name,
                        customer_phone=phone,
                        service_name=service or page_name,
                        appointment_date=date,
                        appointment_time=time,
                        sender_id=sender_id,
                        channel=channel,
                        notes=notes or text
                    )
                    if res.get("success"):
                        registered = True
                        reg_info = {"id": res["appointment"]["id"], "name": name, "phone": phone, "service": service}
                    return res.get("message", "Цаг захиалгын мэдээлэл шалгагдлаа.")

                # Хэрэглэгчийн санах ой ба Persistent Conversation History татах (Phase 3)
                user_memory = database.get_user_memory(page_id, sender_id)
                persistent_history = ai_router.format_persistent_conversation_context(sender_id, limit=8)
                sys_instruction = build_system_instruction_for_page(page_data, user_memory=user_memory) + persistent_history

                agent_tools = [register_customer, check_sheet_cargo_status, create_payment_invoice, book_service_appointment]

                session_key = f"{page_id}_{sender_id}"
                if session_key not in self.chat_sessions:
                    config = types.GenerateContentConfig(
                        system_instruction=sys_instruction,
                        tools=agent_tools,
                        temperature=0.7,
                    )
                    self.chat_sessions[session_key] = client.chats.create(
                        model=self.model_name,
                        config=config
                    )

                chat = self.chat_sessions[session_key]
                
                if audio_bytes:
                    audio_part = types.Part.from_bytes(data=audio_bytes, mime_type=audio_mime)
                    prompt_txt = text if text else "Энэ дуут зурвасыг сонсоод монгол хэлээр бүрэн ойлгож, найрсаг хариулж, хэрэгтэй үйлдлийг гүйцэтгэнэ үү."
                    if sheet_context:
                        prompt_txt += f"\n\n{sheet_context}"
                    message_payload = [prompt_txt, audio_part]
                else:
                    wrapped_text = ai_router.wrap_untrusted_user_input(text)
                    message_payload = wrapped_text
                    if sheet_context:
                        message_payload = f"{wrapped_text}\n\n{sheet_context}"

                try:
                    response = ai_router.execute_with_retry(lambda: chat.send_message(message_payload), max_retries=1)
                    reply_text = response.text or ""
                except Exception as send_err:
                    logger.warning(f"Chat session send_message error, refreshing session: {send_err}")
                    self.chat_sessions.pop(session_key, None)
                    config = types.GenerateContentConfig(
                        system_instruction=sys_instruction,
                        tools=agent_tools,
                        temperature=0.7,
                    )
                    new_chat = client.chats.create(
                        model=self.model_name,
                        config=config
                    )
                    self.chat_sessions[session_key] = new_chat
                    response = ai_router.execute_with_retry(lambda: new_chat.send_message(message_payload), max_retries=1)
                    reply_text = response.text or ""

                # AI Response Evaluation (Phase 3)
                eval_res = ai_router.evaluate_ai_response(reply_text, page_id=page_id)
                reply_text = eval_res["cleaned_reply"]
                if not reply_text:
                    reply_text = f"Сайн байна уу? {page_name}-д тавтай морилно уу! Танд ямар мэдээлэл хэрэгтэй байна вэ?"

                # 5. ТӨЛБӨРИЙН ХҮСЭЛТ ШАЛГАХ (QPAY EXPLICIT INTENT FALLBACK)
                payment_keywords = ["төлбөр төлье", "төлбөрөө төлье", "qpay линк", "qpay-ээр төлье", "нэхэмжлэх авъя", "хандив өгье"]
                is_payment_intent = any(pk in text.lower() for pk in payment_keywords)

                if is_payment_intent and not invoice_order:
                    default_amount = 15000
                    if "хандив" in text.lower() or "кино" in text.lower():
                        default_amount = 10000
                    amount_match = re.search(r'(\d+)[kк]', text.lower())
                    if amount_match:
                        default_amount = int(amount_match.group(1)) * 1000

                    invoice_order = fintech_service.create_payment_order_sync(
                        page_id=page_id,
                        amount=default_amount,
                        description=f"{page_name} төлбөр",
                        sender_id=sender_id,
                        channel=channel
                    )

                if invoice_order and invoice_order.get("pay_url"):
                    reply_text += (
                        f"\n\n⚡ **QPay Төлбөрийн Шууд Холбоос:**\n"
                        f"👉 **[ЭНД ДАРЖ ТӨЛӨХ]({invoice_order['pay_url']})**\n\n"
                        f"*(Утсан дээрээ дээрх линк дээр дармагц Хаан, Голомт SocialPay, М банк гэх мэт банкны апп шууд нээгдэнэ. Төлбөр хийгдсэн секундын дотор 100% автоматаар баталгаажин И-Баримт очих болно! 🎉)*"
                    )

                # Токен тоолох ба хуудасны баазад нэмэх (usage_metadata бодит тоо байвал ашиглах)
                usage_meta = getattr(response, "usage_metadata", None)
                real_tokens = getattr(usage_meta, "total_token_count", None) if usage_meta else None
                tokens_spent = int(real_tokens) if real_tokens else self.estimate_tokens(text, reply_text)
                database.increment_page_tokens(page_id, tokens_spent)

                if not registered:
                    detected = extract_phone_and_name_fallback(text)
                    if detected:
                        r_id = database.save_registration(
                            name=detected["name"],
                            phone=detected["phone"],
                            service=f"{page_name} бүртгэл",
                            channel=channel,
                            sender_id=sender_id,
                            notes=text,
                            page_id=page_id
                        )
                        database.upsert_user_memory(
                            page_id=page_id,
                            user_id=sender_id,
                            customer_name=detected["name"],
                            phone=detected["phone"],
                            notes=text
                        )
                        registered = True
                        reg_info = {"id": r_id, "name": detected["name"], "phone": detected["phone"]}

                database.log_message(sender_id=sender_id, channel=channel, sender_type="bot", content=reply_text, page_id=page_id)
                return {
                    "reply": reply_text,
                    "registered": registered,
                    "reg_info": reg_info,
                    "invoice_order": invoice_order,
                    "model": self.model_name,
                    "is_custom_key": is_custom_key,
                    "tokens_spent": tokens_spent
                }
            except Exception as e:
                logger.error(f"Gemini API алдаа: {e}")

        # 4.5. Олон төрлийн AI Provider Fallback (OpenAI / DeepSeek / Anthropic — Phase 3)
        if text:
            try:
                user_memory = database.get_user_memory(page_id, sender_id)
                sys_inst = build_system_instruction_for_page(page_data, user_memory=user_memory)
                hist = database.get_conversation_history(sender_id=sender_id, limit=8)
                alt_reply = ai_router.call_openai_compatible_fallback(sys_inst, text, hist) or ai_router.call_anthropic_fallback(sys_inst, text, hist)
                if alt_reply:
                    eval_alt = ai_router.evaluate_ai_response(alt_reply, page_id=page_id)
                    clean_alt = eval_alt["cleaned_reply"]
                    if clean_alt:
                        database.log_message(sender_id=sender_id, channel=channel, sender_type="bot", content=clean_alt, page_id=page_id)
                        return {
                            "reply": clean_alt,
                            "registered": registered,
                            "reg_info": reg_info,
                            "model": os.getenv("AI_PROVIDER", "multi_provider_fallback"),
                            "is_custom_key": False,
                        }
            except Exception as alt_err:
                logger.warning(f"Alternative AI provider fallback error: {alt_err}")

        # 5. Нөөц хариу (Deterministic fallback when external AI providers are unconfigured or unreachable)
        detected = extract_phone_and_name_fallback(text)
        if detected:
            r_id = database.save_registration(
                name=detected["name"],
                phone=detected["phone"],
                service=f"{page_name} бүртгэл",
                channel=channel,
                sender_id=sender_id,
                notes=text,
                page_id=page_id
            )
            database.upsert_user_memory(
                page_id=page_id,
                user_id=sender_id,
                customer_name=detected["name"],
                phone=detected["phone"],
                notes=text
            )
            registered = True
            reg_info = {"id": r_id, "name": detected["name"], "phone": detected["phone"]}
            reply_text = f"Баярлалаа, {detected['name']}! Таны мэдээллийг хүлээн авлаа. Манай менежер тантай удахгүй холбогдох болно! 🤝"
        else:
            reply_text = f"Сайн байна уу? {page_name}-д тавтай морилно уу! Танд ямар мэдээлэл хэрэгтэй байна вэ?"

        # Deterministic QPay payment intent fallback
        invoice_order = None
        if text:
            payment_keywords = ["төлбөр төлье", "төлбөрөө төлье", "qpay линк", "qpay-ээр төлье", "нэхэмжлэх авъя", "хандив өгье"]
            is_payment_intent = any(pk in text.lower() for pk in payment_keywords)
            if is_payment_intent:
                default_amount = 15000
                if "хандив" in text.lower() or "кино" in text.lower():
                    default_amount = 10000
                amount_match = re.search(r'(\d+)[kк]', text.lower())
                if amount_match:
                    default_amount = int(amount_match.group(1)) * 1000
                invoice_order = fintech_service.create_payment_order_sync(
                    page_id=page_id,
                    amount=default_amount,
                    description=f"{page_name} төлбөр",
                    sender_id=sender_id,
                    channel=channel
                )
                if invoice_order and invoice_order.get("pay_url"):
                    reply_text += (
                        f"\n\n⚡ **QPay Төлбөрийн Шууд Холбоос:**\n"
                        f"👉 **[ЭНД ДАРЖ ТӨЛӨХ]({invoice_order['pay_url']})**"
                    )

        database.log_message(sender_id=sender_id, channel=channel, sender_type="bot", content=reply_text, page_id=page_id)
        return {
            "reply": reply_text,
            "registered": registered,
            "reg_info": reg_info,
            "invoice_order": invoice_order,
            "model": "fallback",
            "is_custom_key": False,
        }

agent = AIAgent()

def reset_sessions(page_id: Optional[str] = None):
    agent.reset_sessions(page_id=page_id)

def process_message(*args, **kwargs):
    return agent.process_message(*args, **kwargs)

def _init_default_gemini():
    agent._init_default_gemini()

# Module-level accessors
def is_gemini_ready() -> bool:
    return bool(agent.default_client)

def get_model_name() -> str:
    return agent.model_name

