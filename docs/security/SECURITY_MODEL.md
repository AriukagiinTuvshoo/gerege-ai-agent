# Security Model & Multi-Tenant Isolation — Gerege AI Agent

## 1. 7-Role RBAC Matrix (`core/security.py`)

| Role | Scope | Key Permissions |
|---|---|---|
| `super_admin` / `admin` | Global (`*`) | Full administrative access (`*`), tenant management, backups, queue & telemetry, key rotation. |
| `tenant_admin` / `client` | Single Tenant (`page_id`) | Full tenant CRM, knowledge base, sheets, cargo, fintech, retention, appointments (`pages:read`, `leads:*`, `chats:*`, `cargo:*`, `fintech:*`, `appointments:*`). |
| `manager` | Single Tenant (`page_id`) | Operational management (`leads:*`, `chats:*`, `cargo:*`, `fintech:read`, `appointments:*`, `retention:*`, `executive:read`). |
| `support_agent` | Single Tenant (`page_id`) | Customer support & human takeover (`leads:read`, `leads:write`, `chats:read`, `chats:write`, `appointments:read`, `appointments:write`). |
| `cargo_operator` | Single Tenant (`page_id`) | Warehouse operations (`cargo:read`, `cargo:write`, `leads:read`). |
| `finance_reviewer` | Single Tenant (`page_id`) | Financial reconciliation (`fintech:read`, `fintech:write`, `leads:read`, `leads:export`). |
| `viewer` | Single Tenant (`page_id`) | Read-only dashboard access (`pages:read`, `leads:read`, `chats:read`, `cargo:read`, `fintech:read`, `appointments:read`). |

## 2. Defense-in-Depth Controls

1. **Tenant Isolation (Zero Cross-Tenant IDOR)**:
   - `enforce_tenant_scope()` and `verify_resource_tenant_ownership()` verify that non-admin sessions can only read or mutate resources belonging to their own `page_id`. Cross-tenant requests return HTTP `403 Forbidden`.
2. **Fail-Closed Webhook Verification**:
   - Meta `/webhook` requires `X-Hub-Signature-256` HMAC-SHA256 verification against `META_APP_SECRET`.
   - Telegram `/telegram/webhook` requires `X-Telegram-Bot-Api-Secret-Token` constant-time match against `TELEGRAM_WEBHOOK_SECRET`.
3. **Strict Payment Verification**:
   - QPay callbacks verify payment status, exact amount (`paid_amount >= expected_amount`), and currency (`MNT`) directly with the QPay v2 API before marking any invoice `PAID`.
   - AI Vision receipt uploads (`analyze_receipt_image`) never mark an invoice `PAID` without provider verification (`verified_receipt=False, pending_verification=True`).
4. **AI Security & Prompt Injection Guard (`core/ai_router.py`)**:
   - Blocks Mongolian and English prompt-injection/jailbreak patterns before LLM invocation and logs attempts to `audit_logs`.
   - Wraps user input in `<user_message>` boundaries, strips `<thought>` tags, and redacts any accidental secret leaks in responses and logs.
5. **HTTP Security Headers & Upload Limits**:
   - Every response includes `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and `X-Request-ID`.
   - Multipart uploads exceeding `10 MB` are rejected with HTTP `413 Payload Too Large`.
