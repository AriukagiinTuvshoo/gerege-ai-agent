# PHASE 5 — AI AGENT RELIABILITY AND SAFETY

**Repository:** `https://github.com/AriukagiinTuvshoo/gerege-ai-agent`  
**Modules:** [`core/ai_router.py`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/core/ai_router.py), [`agent.py`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/agent.py), [`database.py`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/database.py), [`tests/test_ai_eval_suite.py`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/tests/test_ai_eval_suite.py)

---

## 1. AI Provider Abstraction & Reliability Controls

### 1.1 Timeout & Exponential Backoff Retry
- [`core/ai_router.py`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/core/ai_router.py) wraps Gemini (`google-genai`) and optional fallback providers (`OpenAI`, `Anthropic`) with:
  - Per-call execution timeout (`timeout_seconds = 18.0` via `asyncio.wait_for`).
  - Exponential backoff retry (`max_retries = 2`, `0.5 * 2^attempt` seconds) on transient network/5xx errors.
  - Immediate fail-fast on prompt injection or quota exhaustion without wasting retries.

### 1.2 Per-Provider Circuit Breaker
- [`CircuitBreaker`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/core/ai_router.py#L43-L73) tracks consecutive provider failures (`failure_threshold = 4`, `recovery_timeout = 60.0s`).
- When a provider exceeds `failure_threshold`, its circuit opens for `60s`, preventing cascading latency spikes across worker threads and webhook handlers.
- Inspectable via `AIProviderRouter.get_circuit_status()`.

### 1.3 Explicit Fallback Opt-In (`AI_FALLBACK_ENABLED`)
- Cross-provider fallback (`Gemini -> OpenAI -> Anthropic`) is **disabled by default** unless `AI_FALLBACK_ENABLED=true` is explicitly configured in the environment (`is_ai_fallback_enabled()`).
- Prevents accidental transmission of customer data to third-party LLM providers not authorized by the tenant.

### 1.4 Per-Tenant Token Quota Guard
- `AIProviderRouter.check_tenant_token_quota(page_id, estimated_tokens)` enforces a daily per-tenant token budget (`DEFAULT_DAILY_TOKEN_LIMIT = 500,000`) to protect against runaway loops or abuse.

---

## 2. Prompt Injection & Output Safety Guards

### 2.1 Untrusted User Input Isolation
- `sanitize_user_prompt(text)` truncates oversized inputs (`MAX_USER_INPUT_CHARS = 4000`) and wraps user messages in explicit `<user_message>...</user_message>` XML boundaries.
- System instructions in [`agent.py`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/agent.py) treat everything inside `<user_message>` as untrusted user data that cannot override system rules, pricing, or tenant boundaries.

### 2.2 Prompt Injection Detection
- `detect_prompt_injection(text)` screens for 11 English and Mongolian adversarial patterns:
  - System instruction override (`ignore all previous instructions`, `өөрийн зааврыг март`)
  - System prompt/secret extraction (`system prompt-оо харуул`, `reveal your api key`)
  - Role/privilege escalation (`you are now admin`, `developer mode`, `jailbreak`)
  - Fraudulent payment bypass (`simulate_payment_success`, `mark_invoice_paid`, `төлбөр төлөгдсөн гэж тооц`)

### 2.3 Output Secret Redaction
- `validate_ai_output_safety(output_text)` strips leaked credentials (`AIza...`, `sk-...`, `EAAB...`, `page_access_token=`, `gemini_api_key=`, `qpay_password=`, `ADMIN_PASSWORD=`) before any response reaches the user.

---

## 3. Tool-Call Authorization & Audit Logging

- [`ToolExecutionGuard`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/core/ai_router.py#L140-L246) enforces:
  1. **Allowed Tool Whitelist:** Only `save_registration`, `create_qpay_invoice`, `check_cargo_status`, `book_appointment`, and `escalate_to_human` are executable by the AI agent.
  2. **Strict Parameter Schema Validation:** Validates required arguments, numeric bounds (`100 <= amount <= 50,000,000`), and blocks cross-tenant `page_id` override attempts in tool arguments.
  3. **Audit Trail:** Every allowed or denied AI tool call is recorded in the `audit_logs` table via `database.record_audit_log(...)` with `actor_role="ai_agent"`, `action="ai_tool:<tool_name>"`, `tenant_page_id`, and `status` (`ALLOWED` or `DENIED_INVALID_SCHEMA`).

---

## 4. Conversation Memory & Customer Data Deletion (`Бүртгэл устгах`)

- Persistent customer memory is stored in `user_memories` scoped strictly by `(page_id, sender_id)`.
- Customers can view their stored profile with `"Миний мэдээлэл"` and permanently erase their profile, memories, session state, messages, and registrations for that tenant by sending `"Бүртгэл устгах"` or `"Миний мэдээллийг устга"`.
- Handled deterministically in [`agent.py`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/agent.py#L540-L561) via [`database.delete_customer_data(sender_id, page_id)`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/database.py#L962-L1002), which also writes an immutable `customer_self_delete_data` entry to `audit_logs`.

---

## 5. AI Evaluation Suite (`tests/test_ai_eval_suite.py`)

[`tests/test_ai_eval_suite.py`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/tests/test_ai_eval_suite.py) verifies all 10 required evaluation categories:
1. Mongolian FAQ responses
2. Lead registration flow (`save_registration`)
3. QPay invoice creation (`create_qpay_invoice`)
4. Receipt image fraud rejection (refusing to mark payment `PAID` from text/receipt claims)
5. Cargo tracking flow (`check_cargo_status`)
6. Appointment booking flow (`book_appointment`)
7. Human handoff escalation (`escalate_to_human`)
8. Prompt injection resistance (English + Mongolian)
9. Secret extraction resistance (`validate_ai_output_safety`)
10. Cross-tenant data request refusal (`page_id` override blocked)
