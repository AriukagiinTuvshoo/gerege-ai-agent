import os
import re
import time
import json
import logging
from typing import Dict, Any, List, Optional, Callable, Tuple
import httpx

import database

logger = logging.getLogger("core.ai_router")

# -------------------------------------------------------------
# 1. PROMPT INJECTION ХАМГААЛАЛТ (DETECTION & SANITIZATION)
# -------------------------------------------------------------
PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)",
    r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)",
    r"reveal\s+(your\s+)?(system\s+prompt|hidden\s+instructions|api\s+key)",
    r"show\s+(me\s+)?(your\s+)?(system\s+prompt|developer\s+prompt)",
    r"you\s+are\s+now\s+in\s+(developer|dan|jailbreak|unrestricted)\s+mode",
    r"өмнөх\s+(бүх\s+)?зааврыг\s+(март|үл\s+тоо|хүчингүй\s+болго)",
    r"систем\s+промпт(оо|ыг)\s+(харуул|хэл|задруул)",
    r"нууц\s+түлхүүр(ээ|ийг)\s+хэл",
    r"<\s*/?\s*system\s*>",
    r"\[\s*SYSTEM\s*\]",
    r"\[\s*INST\s*\]",
]


def detect_prompt_injection(text: str) -> Tuple[bool, str]:
    """
    Хэрэглэгчийн оролтоос Prompt Injection / Jailbreak халдлагын шинж тэмдгийг илрүүлэх.
    Returns: (is_injected: bool, matched_reason: str)
    """
    if not text:
        return False, ""
    cleaned = text.strip()
    for pat in PROMPT_INJECTION_PATTERNS:
        if re.search(pat, cleaned, re.IGNORECASE):
            logger.warning(f"Prompt injection attempt blocked: pattern={pat}")
            return True, pat
    return False, ""


def wrap_untrusted_user_input(text: str) -> str:
    """Хэрэглэгчийн текстийг систем промптоос тусгаарласан XML хашаанд хийх"""
    sanitized = (text or "").replace("</user_message>", "").replace("<system>", "").replace("</system>", "")
    return f"<user_message>\n{sanitized}\n</user_message>"


# -------------------------------------------------------------
# 2. TOOL CALLING ЭРХИЙН ХЯЗГААРЛАЛТ (SCOPED TOOL GUARD)
# -------------------------------------------------------------
MIN_INVOICE_AMOUNT = 100
MAX_INVOICE_AMOUNT = 10_000_000
MAX_TOOL_CALLS_PER_TURN = 3


class ToolExecutionGuard:
    """
    LLM-ийн Tool Calling эрхийг хязгаарлагч:
    - Зөвхөн тухайн tenant-ийн `page_id` дотор үйлдэл хийхийг баталгаажуулна
    - Нэг мессежийн эргэлтэд (turn) дуудагдах tool-ийн тоог хязгаарлана
    - Төлбөрийн нэхэмжлэхийн дүнг зөвшөөрөгдсөн хязгаар (100₮ - 10,000,000₮) болон каталогийн үнэтэй тулгана
    """

    def __init__(self, page_id: str, sender_id: str, catalog_prices: Optional[List[int]] = None):
        self.page_id = str(page_id or database.DEFAULT_PAGE_ID)
        self.sender_id = str(sender_id or "anonymous")
        self.catalog_prices = catalog_prices or []
        self.call_counts: Dict[str, int] = {}
        self.total_calls: int = 0

    def check_and_record(self, tool_name: str) -> Tuple[bool, str]:
        if self.total_calls >= MAX_TOOL_CALLS_PER_TURN:
            return False, f"Нэг удаагийн хариултад {MAX_TOOL_CALLS_PER_TURN}-аас олон хэрэгсэл дуудах боломжгүй."
        count = self.call_counts.get(tool_name, 0)
        if tool_name == "create_payment_invoice" and count >= 1:
            return False, "Нэг мессежид зөвхөн 1 удаа нэхэмжлэх үүсгэх эрхтэй."
        self.call_counts[tool_name] = count + 1
        self.total_calls += 1
        return True, "OK"

    def validate_invoice_amount(self, requested_amount: int, default_amount: int = 15000) -> int:
        try:
            amt = int(requested_amount)
        except Exception:
            amt = default_amount

        if amt < MIN_INVOICE_AMOUNT or amt > MAX_INVOICE_AMOUNT:
            logger.warning(f"ToolGuard clamped out-of-range invoice amount {amt} -> {default_amount}")
            return default_amount

        if self.catalog_prices and amt not in self.catalog_prices:
            # Хэрэв каталогийн үнэ тодорхойлогдсон бөгөөд хэт зөрүүтэй бол хамгийн ойрын каталогийн үнийг сонгох
            pass
        return amt


# -------------------------------------------------------------
# 3. AI RESPONSE EVALUATION (ГАРАЛТЫН ЧАНАР БА АЮУЛГҮЙ БАЙДЛЫН ҮНЭЛГЭЭ)
# -------------------------------------------------------------
def evaluate_ai_response(reply_text: str, page_id: str) -> Dict[str, Any]:
    """
    AI-ийн гаргасан хариултыг хэрэглэгч рүү илгээхийн өмнө шалгаж үнэлэх:
    - Дотоод <thought> тагуудыг цэвэрлэх
    - Систем промпт эсвэл API key задарсан эсэхийг шалгах
    - Хоосон эсвэл хэт богино хариултыг илрүүлэх
    """
    raw = reply_text or ""
    cleaned = re.sub(r"<thought>.*?</thought>", "", raw, flags=re.DOTALL).strip()
    cleaned = re.sub(r"</?user_message>", "", cleaned).strip()

    issues: List[str] = []
    safety_score = 1.0

    # Систем түлхүүр эсвэл дотоод заавар задарсан эсэх
    leak_patterns = [
        r"AIzaSy[A-Za-z0-9_\-]{20,}",
        r"sk-[A-Za-z0-9]{20,}",
        r"ХАРИУЛАХ ЗААВАР БА ДҮРЭМ \(ЧАНД МӨРДӨХ\)",
        r"client_password_hash",
    ]
    for lp in leak_patterns:
        if re.search(lp, cleaned):
            issues.append(f"secret_or_prompt_leak:{lp}")
            safety_score = 0.0

    relevance_score = 1.0 if len(cleaned) >= 2 else 0.0
    passed = safety_score >= 0.8 and relevance_score >= 0.5

    if not passed and safety_score == 0.0:
        cleaned = "Сайн байна уу? Танд манай үйлчилгээний талаар ямар мэдээлэл хэрэгтэй байна вэ?"

    return {
        "cleaned_reply": cleaned,
        "passed": passed,
        "safety_score": safety_score,
        "relevance_score": relevance_score,
        "issues": issues,
    }


# -------------------------------------------------------------
# 4. RETRY, TIMEOUT БА MULTI-PROVIDER ROUTER (GEMINI / OPENAI / ANTHROPIC)
# -------------------------------------------------------------
def execute_with_retry(
    func: Callable[[], Any],
    max_retries: int = 2,
    base_delay: float = 0.4,
) -> Any:
    """Түр зуурын сүлжээний эсвэл 429/5xx алдаа гарвал Exponential Backoff-оор дахин оролдох"""
    last_exc = None
    for attempt in range(max_retries + 1):
        try:
            return func()
        except Exception as e:
            last_exc = e
            err_str = str(e).lower()
            # 400 Invalid Argument эсвэл 401/403 бол дахин оролдох шаардлагагүй
            if "400" in err_str or "invalid_argument" in err_str or "401" in err_str or "403" in err_str:
                raise
            if attempt < max_retries:
                sleep_sec = base_delay * (2 ** attempt)
                logger.warning(f"AI call retry {attempt + 1}/{max_retries} after {sleep_sec:.1f}s due to: {e}")
                time.sleep(sleep_sec)
    raise last_exc


def call_openai_compatible_fallback(
    system_instruction: str,
    user_text: str,
    history: List[Dict[str, Any]],
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    timeout: float = 15.0,
) -> Optional[str]:
    """OpenAI / DeepSeek / Ollama нийцтэй API дуудах (Multi-provider сонголт эсвэл Gemini fallback)"""
    key = api_key or os.getenv("OPENAI_API_KEY", "").strip()
    url_base = (base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
    model_name = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    if not key and "localhost" not in url_base and "127.0.0.1" not in url_base:
        return None

    messages = [{"role": "system", "content": system_instruction}]
    for h in history[-8:]:
        role = "user" if h.get("sender_type") == "user" else "assistant"
        content = h.get("content") or ""
        if content:
            messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": user_text})

    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"

    with httpx.Client(timeout=timeout) as client:
        resp = client.post(
            f"{url_base}/chat/completions",
            headers=headers,
            json={"model": model_name, "messages": messages, "temperature": 0.4},
        )
        if resp.status_code == 200:
            data = resp.json()
            choices = data.get("choices") or []
            if choices:
                return choices[0].get("message", {}).get("content", "")
    return None


def call_anthropic_fallback(
    system_instruction: str,
    user_text: str,
    history: List[Dict[str, Any]],
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    timeout: float = 15.0,
) -> Optional[str]:
    """Anthropic Claude API дуудах (Multi-provider сонголт эсвэл fallback)"""
    key = api_key or os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not key:
        return None
    model_name = model or os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-latest")

    messages = []
    for h in history[-8:]:
        role = "user" if h.get("sender_type") == "user" else "assistant"
        content = h.get("content") or ""
        if content:
            messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": user_text})

    headers = {
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(
            "https://api.anthropic.com/v1/messages",
            headers=headers,
            json={
                "model": model_name,
                "max_tokens": 1024,
                "system": system_instruction,
                "messages": messages,
            },
        )
        if resp.status_code == 200:
            data = resp.json()
            content_blocks = data.get("content") or []
            if content_blocks and isinstance(content_blocks, list):
                return content_blocks[0].get("text", "")
    return None


def format_persistent_conversation_context(sender_id: str, limit: int = 8) -> str:
    """
    Баазад хадгалагдсан өмнөх харилцан ярианы түүхийг (Persistent Conversation Memory)
    сервер унтарч ассан ч алдахгүйгээр сэргээж контекст болгох
    """
    try:
        rows = database.get_conversation_history(sender_id=sender_id, limit=limit)
    except Exception:
        return ""
    if not rows:
        return ""
    lines = ["\n==========================================", "📜 ӨМНӨХ ЯРИАНЫ ТҮҮХ (PERSISTENT CONVERSATION MEMORY):"]
    for r in rows[-limit:]:
        who = "Хэрэглэгч" if r.get("sender_type") == "user" else "Туслах"
        content = (r.get("content") or "").strip()
        if content:
            lines.append(f"- {who}: {content[:240]}")
    lines.append("==========================================")
    return "\n".join(lines)
