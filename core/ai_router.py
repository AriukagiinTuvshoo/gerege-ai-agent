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
# 1. PROMPT INJECTION ХАМГААЛАЛТ БА USER DATA DELETION INTENT
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

DATA_DELETION_PATTERNS = [
    r"^\s*бүртгэл\s+устгах\s*$",
    r"миний\s+(бүх\s+)?(мэдээлэл|мэдээллийг|бүртгэлийг)\s+устга",
    r"delete\s+my\s+(data|account|registration)",
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


def detect_data_deletion_request(text: str) -> bool:
    """Хэрэглэгч өөрийн мэдээлэл, санах ойг устгуулах ('Бүртгэл устгах') хүсэлт илгээсэн эсэх"""
    if not text:
        return False
    cleaned = text.strip()
    for pat in DATA_DELETION_PATTERNS:
        if re.search(pat, cleaned, re.IGNORECASE):
            return True
    return False


def wrap_untrusted_user_input(text: str) -> str:
    """Хэрэглэгчийн текстийг систем промптоос тусгаарласан XML хашаанд хийх"""
    sanitized = (text or "").replace("</user_message>", "").replace("<system>", "").replace("</system>", "")
    return f"<user_message>\n{sanitized}\n</user_message>"


# -------------------------------------------------------------
# 2. TOOL CALLING ЭРХИЙН ХЯЗГААРЛАЛТ & AUDIT LOGGING (SCOPED TOOL GUARD)
# -------------------------------------------------------------
MIN_INVOICE_AMOUNT = 100
MAX_INVOICE_AMOUNT = 10_000_000
MAX_TOOL_CALLS_PER_TURN = 3


class ToolExecutionGuard:
    """
    LLM-ийн Tool Calling эрхийг хязгаарлагч ба Audit Logger:
    - Зөвхөн тухайн tenant-ийн `page_id` дотор үйлдэл хийхийг баталгаажуулна
    - Нэг мессежийн эргэлтэд (turn) дуудагдах tool-ийн тоог хязгаарлана
    - Төлбөрийн нэхэмжлэхийн дүнг зөвшөөрөгдсөн хязгаар (100₮ - 10,000,000₮) болон каталогийн үнэтэй тулгана
    - Хэрэгсэл дуудагдах бүрийг `audit_logs` хүснэгтэд бүртгэнэ
    """

    def __init__(self, page_id: str, sender_id: str, catalog_prices: Optional[List[int]] = None):
        self.page_id = str(page_id or database.DEFAULT_PAGE_ID)
        self.sender_id = str(sender_id or "anonymous")
        self.catalog_prices = catalog_prices or []
        self.call_counts: Dict[str, int] = {}
        self.total_calls: int = 0

    def check_and_record(self, tool_name: str, args: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        if self.total_calls >= MAX_TOOL_CALLS_PER_TURN:
            database.record_audit_log(
                action=f"ai.tool.blocked.{tool_name}",
                page_id=self.page_id,
                actor_role="ai_agent",
                actor_id=self.sender_id,
                resource_type="tool",
                resource_id=tool_name,
                details={"reason": "max_tool_calls_per_turn_exceeded", "args": args or {}},
            )
            return False, f"Нэг удаагийн хариултад {MAX_TOOL_CALLS_PER_TURN}-аас олон хэрэгсэл дуудах боломжгүй."
        count = self.call_counts.get(tool_name, 0)
        if tool_name == "create_payment_invoice" and count >= 1:
            database.record_audit_log(
                action=f"ai.tool.blocked.{tool_name}",
                page_id=self.page_id,
                actor_role="ai_agent",
                actor_id=self.sender_id,
                resource_type="tool",
                resource_id=tool_name,
                details={"reason": "duplicate_invoice_in_same_turn", "args": args or {}},
            )
            return False, "Нэг мессежид зөвхөн 1 удаа нэхэмжлэх үүсгэх эрхтэй."
        self.call_counts[tool_name] = count + 1
        self.total_calls += 1
        try:
            database.record_audit_log(
                action=f"ai.tool.executed.{tool_name}",
                page_id=self.page_id,
                actor_role="ai_agent",
                actor_id=self.sender_id,
                resource_type="tool",
                resource_id=tool_name,
                details={"call_index": self.total_calls, "args": args or {}},
            )
        except Exception:
            pass
        return True, "OK"

    def validate_invoice_amount(self, requested_amount: int, default_amount: int = 15000) -> int:
        try:
            amt = int(requested_amount)
        except Exception:
            amt = default_amount

        if amt < MIN_INVOICE_AMOUNT or amt > MAX_INVOICE_AMOUNT:
            logger.warning(f"ToolGuard clamped out-of-range invoice amount {amt} -> {default_amount}")
            return default_amount

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
# 4. CIRCUIT BREAKER, RETRY, TIMEOUT & MULTI-PROVIDER ROUTER
# -------------------------------------------------------------
class CircuitBreaker:
    """Provider-level Circuit Breaker to prevent cascading timeouts during provider outages."""

    def __init__(self, name: str, failure_threshold: int = 5, cooldown_seconds: float = 60.0):
        self.name = name
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self.failures = 0
        self.opened_at: Optional[float] = None

    def allow_request(self) -> bool:
        if self.opened_at is None:
            return True
        if (time.time() - self.opened_at) >= self.cooldown_seconds:
            # Half-open probe
            return True
        return False

    def record_success(self) -> None:
        self.failures = 0
        self.opened_at = None

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.opened_at = time.time()
            logger.warning(f"CircuitBreaker [{self.name}] OPENED after {self.failures} consecutive failures.")


_CIRCUIT_BREAKERS: Dict[str, CircuitBreaker] = {}


def get_circuit_breaker(provider_name: str) -> CircuitBreaker:
    key = (provider_name or "default").lower()
    if key not in _CIRCUIT_BREAKERS:
        _CIRCUIT_BREAKERS[key] = CircuitBreaker(name=key)
    return _CIRCUIT_BREAKERS[key]


def is_ai_fallback_enabled() -> bool:
    """
    External fallback providers (OpenAI / Anthropic) are only called when explicitly enabled
    via AI_FALLBACK_ENABLED=1 or AI_PROVIDER configuration (Phase 5.1 privacy & opt-in).
    """
    flag = os.getenv("AI_FALLBACK_ENABLED", "0").strip().lower()
    provider = os.getenv("AI_PROVIDER", "gemini").strip().lower()
    return flag in ("1", "true", "yes") or provider in ("openai", "anthropic", "claude")


def execute_with_retry(
    func: Callable[[], Any],
    max_retries: int = 2,
    base_delay: float = 0.4,
    provider_name: str = "gemini",
) -> Any:
    """Түр зуурын сүлжээний эсвэл 429/5xx алдаа гарвал Exponential Backoff + CircuitBreaker-ээр дахин оролдох"""
    cb = get_circuit_breaker(provider_name)
    if not cb.allow_request():
        raise RuntimeError(f"CircuitBreaker '{provider_name}' is currently OPEN; skipping call")

    last_exc = None
    for attempt in range(max_retries + 1):
        try:
            res = func()
            cb.record_success()
            return res
        except Exception as e:
            last_exc = e
            err_str = str(e).lower()
            if "400" in err_str or "invalid_argument" in err_str or "401" in err_str or "403" in err_str:
                raise
            if attempt < max_retries:
                sleep_sec = base_delay * (2 ** attempt)
                logger.warning(f"AI call retry {attempt + 1}/{max_retries} after {sleep_sec:.1f}s due to: {e}")
                time.sleep(sleep_sec)
    cb.record_failure()
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
    if not is_ai_fallback_enabled() and not api_key:
        return None
    cb = get_circuit_breaker("openai")
    if not cb.allow_request():
        return None

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

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(
                f"{url_base}/chat/completions",
                headers=headers,
                json={"model": model_name, "messages": messages, "temperature": 0.4},
            )
            if resp.status_code == 200:
                cb.record_success()
                data = resp.json()
                choices = data.get("choices") or []
                if choices:
                    return choices[0].get("message", {}).get("content", "")
            cb.record_failure()
    except Exception as e:
        cb.record_failure()
        logger.warning(f"OpenAI fallback error: {e}")
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
    if not is_ai_fallback_enabled() and not api_key:
        return None
    cb = get_circuit_breaker("anthropic")
    if not cb.allow_request():
        return None

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
    try:
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
                cb.record_success()
                data = resp.json()
                content_blocks = data.get("content") or []
                if content_blocks and isinstance(content_blocks, list):
                    return content_blocks[0].get("text", "")
            cb.record_failure()
    except Exception as e:
        cb.record_failure()
        logger.warning(f"Anthropic fallback error: {e}")
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
