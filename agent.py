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

load_dotenv(override=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DEFAULT_MODEL = "gemini-3.5-flash-lite"

ESCALATION_KEYWORDS = [
    "хүнтэй ярих", "хүн байна уу", "оператор", "менежер", "гомдол", "хүнтэй холбогдох"
]

def build_system_instruction_for_page(page_data: Optional[Dict[str, Any]] = None) -> str:
    """Олон хуудасны (Multi-Tenant) мэдлэг ба өгөгдлийг AI Prompt болгон бүтээх"""
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
Та бол "{page_name}" байгууллагын албан ёсны ухаалаг AI туслах юм.
Байгууллагын танилцуулга: {comp.get('description', page_name)}

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

ТАНЫ ҮҮРЭГ БА ДҮРЭМ:
1. Монгол хэлээр маш найрсаг, товч тодорхой, эелдэг харилцана.
2. Хэрэглэгчийн асуусан асуултад дээрх байгууллагын мэдлэгийн сангийн хүрээнд үнэн зөв хариулна.
3. Хэрэв хэрэглэгч нэр, утсаа өгвөл заавал 'register_customer' багажийг дуудаж баазад хадгална.
4. Хэрэв хэрэглэгч гүйлгээний баримтын зураг явуулсан эсвэл гүйлгээ хийснээ баталгаажуулбал баярласнаа илэрхийлээд дээрх албан ёсны Telegram болон Facebook холбоосыг шууд илгээнэ.
5. БОДИТ ЦАГИЙН GOOGLE SHEETS & БАРАА/КАРГО ШАЛГАЛТ:
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
    phone_match = re.search(r'\b([8976]\d{7})\b', text.replace("-", "").replace(" ", ""))
    if not phone_match:
        phone_match = re.search(r'\b(\d{8})\b', text)
    
    if phone_match:
        phone = phone_match.group(1)
        name = "Харилцагч"
        name_patterns = [
            r'намайг\s+([А-Яа-яA-Za-z]+)\s+гэдэг',
            r'нэр\s*:?\s*([А-Яа-яA-Za-z]+)',
            r'([А-Яа-яA-Za-z]+)\s+байна',
            r'^([А-Яа-яA-Za-z]+)\s+\d{8}',
        ]
        for pattern in name_patterns:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                name = m.group(1).capitalize()
                break
        return {"name": name, "phone": phone}
    return None

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

    def reset_sessions(self):
        self.chat_sessions.clear()

    def analyze_receipt_image(self, image_bytes: bytes, client: Optional[Any] = None) -> Dict[str, Any]:
        """Gemini Vision ашиглан банкны гүйлгээний баримтыг таних"""
        active_client = client or self.default_client
        if not active_client:
            return {"is_receipt": False, "details": "AI холбогдоогүй"}
        
        try:
            img = Image.open(io.BytesIO(image_bytes))
            prompt = """
Энэ зургийг шинжилж дараах асуултад үнэн зөв хариул:
1. Энэ нь банкны эсвэл цахим хэтэвчний (Голомт, Хаан, Хас, Төрийн банк, SocialPay, QPay г.м) гүйлгээний амжилттай болсон баримт мөн үү?
2. Гүйлгээний дүн хэдэн төгрөг байна вэ?
3. Төлөв нь 'Амжилттай' гэсэн төлөвтэй байна уу?

Хэрэв банкны гүйлгээний баримт мөн бөгөөд амжилттай болсон бол эхний мөрөнд: "VALID_RECEIPT|Дүн" гэж бичээд доор нь товч тайлбарла.
Хэрэв биш бол: "INVALID_RECEIPT|Шалтгаан" гэж хариул.
"""
            resp = active_client.models.generate_content(
                model=self.model_name,
                contents=[prompt, img]
            )
            text = resp.text or ""
            is_valid = "VALID_RECEIPT" in text or "Амжилттай" in text or any(c in text for c in ["5,000", "10,000", "20,000", "төгрөг", "₮", "MNT"])
            return {
                "is_receipt": is_valid,
                "analysis": text
            }
        except Exception as e:
            logger.error(f"Зураг шинжлэхэд алдаа гарлаа: {e}")
            return {"is_receipt": False, "details": str(e)}

    def process_message(
        self,
        text: str = "",
        image_bytes: Optional[bytes] = None,
        sender_id: str = "default",
        channel: str = "web",
        page_id: str = database.DEFAULT_PAGE_ID
    ) -> Dict[str, Any]:
        # Хуудасны мэдээллийг баазаас авах (Multi-Tenant Lookup)
        page_data = database.get_page(page_id)
        page_name = page_data.get("name", "Манай суваг") if page_data else "Tuvshok Кино Суваг"

        # Баазад тэмдэглэх
        log_content = text if text else "[Зураг хавсаргав]"
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

        # Хуудас тус бүрийн линкүүдийг бэлтгэх
        tg_link = "https://t.me/+9tgSTfrXiUs2ODk1"
        fb_link = "https://www.facebook.com/groups/2991030297929100/"
        if page_data and page_data.get("knowledge_json"):
            try:
                k_obj = json.loads(page_data["knowledge_json"]) if isinstance(page_data["knowledge_json"], str) else page_data["knowledge_json"]
                links_obj = k_obj.get("links", {})
                if links_obj.get("telegram_group"): tg_link = links_obj["telegram_group"]
                if links_obj.get("facebook_group"): fb_link = links_obj["facebook_group"]
            except Exception:
                pass
        else:
            kb = knowledge_base.load_knowledge()
            links = kb.get("links", {})
            tg_link = links.get("telegram_group", tg_link)
            fb_link = links.get("facebook_group", fb_link)

        # 3. ЗУРАГ / БАНКНЫ ХУУЛГА ИРСЭН ЭСЭХИЙГ ШАЛГАХ (VISION)
        if image_bytes:
            receipt_check = self.analyze_receipt_image(image_bytes, client=client)
            # Зураг уншихад ойролцоогоор 250 токен зарцуулна
            database.increment_page_tokens(page_id, 250)
            
            if receipt_check.get("is_receipt"):
                reply_text = (
                    "Гүйлгээний баримтыг амжилттай шалгаж баталгаажууллаа! 🎉\n\n"
                    f"{page_name}-д хандсанд маш их баярлалаа. Албан ёсны нэвтрэх урилгын холбоосууд:\n\n"
                    f"👉 **Telegram групп линк:** {tg_link}\n"
                    f"👉 **Facebook групп линк:** {fb_link}\n\n"
                    "Холбоосоор орж тухлан үзээрэй! 🎬 Асуух зүйл гарвал хэзээд бичээрэй."
                )
                database.log_message(sender_id=sender_id, channel=channel, sender_type="bot", content=reply_text, page_id=page_id)
                reg_id = database.save_registration(
                    name="Баримт баталгаажсан",
                    phone=sender_id.replace("meta_", "").replace("tg_", ""),
                    service=f"{page_name} Хандив/Төлбөр (Баталгаажсан)",
                    channel=channel,
                    sender_id=sender_id,
                    notes=receipt_check.get("analysis", "Гүйлгээний баримт амжилттай"),
                    status="verified",
                    page_id=page_id
                )
                return {
                    "reply": reply_text,
                    "registered": True,
                    "verified_receipt": True,
                    "model": self.model_name,
                    "is_custom_key": is_custom_key,
                    "reg_info": {
                        "id": reg_id,
                        "name": "Баримт баталгаажсан",
                        "phone": sender_id.replace("meta_", "").replace("tg_", ""),
                        "service": f"{page_name} Төлбөр (Баталгаажсан)",
                        "channel": channel,
                        "created_at": "Яг одоо"
                    }
                }
            else:
                reply_text = (
                    "Таны илгээсэн зургийг хүлээн авлаа. Банкны гүйлгээний дүн болон 'Амжилттай' төлөв бүхий баримтын зургийг тодорхой харуулан дахин илгээнэ үү. "
                    "Баримт шалгагдмагц холбоос автоматаар очно шүү! 🤝"
                )
                database.log_message(sender_id=sender_id, channel=channel, sender_type="bot", content=reply_text, page_id=page_id)
                return {"reply": reply_text, "registered": False, "model": self.model_name, "is_custom_key": is_custom_key}

        # 4. ЭНГИЙН ТЕКСТ МЕССЕЖ (GEMINI ЧАТ)
        registered = False
        reg_info = None

        # Google Sheets холболт шалгах ба бараа/карго хайлт хийх
        sheets_url = page_data.get("google_sheets_url") if page_data else None
        sheet_context = ""
        if sheets_url and text:
            sheet_context = sheets_service.get_sheet_lookup_context(sheets_url, text) or ""

        if client:
            try:
                from google.genai import types

                def register_customer(name: str, phone: str, service: str = "", notes: str = "") -> str:
                    nonlocal registered, reg_info
                    r_id = database.save_registration(
                        name=name,
                        phone=phone,
                        service=service or f"{page_name} бүртгэл",
                        channel=channel,
                        sender_id=sender_id,
                        notes=notes or text,
                        page_id=page_id
                    )
                    registered = True
                    reg_info = {"id": r_id, "name": name, "phone": phone, "service": service or page_name}
                    return f"Амжилттай бүртгэгдлээ. Дугаар: #{r_id}"

                def check_sheet_cargo_status(tracking_or_phone: str) -> str:
                    """Google Sheets-ээс барааны төлөв хайх"""
                    if not sheets_url:
                        return "Google Sheets холбогдоогүй байна."
                    matched = sheets_service.search_sheet_records(sheets_url, tracking_or_phone)
                    if not matched:
                        return f"'{tracking_or_phone}' дугаартай барааны мэдээлэл олдсонгүй."
                    res = []
                    for r in matched[:3]:
                        res.append("; ".join([f"{k}: {v}" for k, v in r.items() if v]))
                    return "\n---\n".join(res)

                session_key = f"{page_id}_{sender_id}"
                if session_key not in self.chat_sessions:
                    config = types.GenerateContentConfig(
                        system_instruction=build_system_instruction_for_page(page_data),
                        tools=[register_customer, check_sheet_cargo_status],
                        temperature=0.7,
                    )
                    self.chat_sessions[session_key] = client.chats.create(
                        model=self.model_name,
                        config=config
                    )

                chat = self.chat_sessions[session_key]
                message_payload = text
                if sheet_context:
                    message_payload = f"{text}\n\n{sheet_context}"

                response = chat.send_message(message_payload)
                reply_text = response.text or ""

                # Токен тоолох ба хуудасны баазад нэмэх
                tokens_spent = self.estimate_tokens(text, reply_text)
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
                        registered = True
                        reg_info = {"id": r_id, "name": detected["name"], "phone": detected["phone"]}

                database.log_message(sender_id=sender_id, channel=channel, sender_type="bot", content=reply_text, page_id=page_id)
                return {
                    "reply": reply_text,
                    "registered": registered,
                    "reg_info": reg_info,
                    "model": self.model_name,
                    "is_custom_key": is_custom_key,
                    "tokens_spent": tokens_spent
                }
            except Exception as e:
                logger.error(f"Gemini API алдаа: {e}")

        # 5. Нөөц хариу
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
            registered = True
            reg_info = {"id": r_id, "name": detected["name"], "phone": detected["phone"]}
            reply_text = f"Баярлалаа, {detected['name']}! Таны мэдээллийг хүлээн авлаа. Манай менежер тантай удахгүй холбогдох болно! 🤝"
        else:
            reply_text = f"Сайн байна уу? {page_name}-д тавтай морилно уу! Танд ямар мэдээлэл хэрэгтэй байна вэ?"

        database.log_message(sender_id=sender_id, channel=channel, sender_type="bot", content=reply_text, page_id=page_id)
        return {"reply": reply_text, "registered": registered, "reg_info": reg_info, "model": "fallback", "is_custom_key": False}

agent = AIAgent()

def reset_sessions():
    agent.reset_sessions()

def process_message(*args, **kwargs):
    return agent.process_message(*args, **kwargs)

def _init_default_gemini():
    agent._init_default_gemini()

# Module-level accessors
def is_gemini_ready() -> bool:
    return bool(agent.default_client)

def get_model_name() -> str:
    return agent.model_name

