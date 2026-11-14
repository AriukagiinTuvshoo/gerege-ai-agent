# Phase 1 — Security Hardening Implementation (`SECURITY_IMPLEMENTATION.md`)

**Status:** Completed (P0)  
**Primary Modules:** [`core/security.py`](../../core/security.py), [`database.py`](../../database.py), [`fintech_service.py`](../../fintech_service.py), [`main.py`](../../main.py), [`dashboard.html`](../../dashboard.html)

---

## 1. Centralized Authentication (`core/security.py` & `database.py`)

### 1.1 No Default Admin Password Backdoor in Production
- `database.authenticate_admin()` enforces fail-closed authentication when `ENV=production` or `STRICT_SECURITY=1` or `DISABLE_DEFAULT_ADMIN_PASSWORD=1`: if `ADMIN_PASSWORD` is unset or equals `ADMIN2026`, login is rejected (`False`).
- Constant-time comparison (`hmac.compare_digest` / `core_security.constant_time_equal`) is used for all admin password, webhook secret, and challenge token checks.
- Removed the hardcoded `quickAdminLogin()` (`ADMIN2026`) auto-login from `dashboard.html` so unauthenticated browser visitors always see the login modal.

### 1.2 Session Lifecycle, Revocation & Cookie Hardening
- `sessions` table now stores `revoked` (`INTEGER DEFAULT 0`), `revoked_at`, `ip_address`, and `expires_at`.
- `database.get_session()` rejects expired (`expires_at < now`) and revoked (`revoked = 1`) tokens immediately.
- `database.set_client_credentials()` automatically calls `database.revoke_all_page_sessions(page_id)` so password/credential rotation invalidates all existing tenant sessions.
- `/api/auth/login` sets `HttpOnly`, `SameSite=Lax`, and `Secure=core_security.is_production_mode()` on `session_token` cookies.
- Query-string tokens (`?token=...`) are rejected automatically when `is_production_mode()` is active unless explicitly overridden with `ALLOW_QUERY_TOKEN=1`.
- Brute-force rate limiting on `/api/auth/login` limits failed attempts per IP to 10/minute (`HTTP 429`) and records structured audit events (`auth.login.success`, `auth.login.failed`) in `audit_logs`.

---

## 2. Centralized Role-Based Access Control (RBAC)

`core/security.py` defines 7 explicit roles and their granular permission matrix (`ROLE_PERMISSIONS`):

| Role | Scope | Permissions |
|---|---|---|
| `super_admin` | Global | All system, tenant, CRM, inbox, fintech, cargo, retention, appointments, executive permissions |
| `admin` | Global | All system, tenant, CRM, inbox, fintech, cargo, retention, appointments, executive permissions |
| `manager` | Tenant (`page_id`) | `pages:read`, `leads:*`, `sessions:*`, `knowledge:*`, `fintech:*`, `cargo:*`, `retention:*`, `appointments:*`, `executive:*` |
| `client` | Tenant (`page_id`) | `pages:read`, `leads:*`, `sessions:*`, `knowledge:*`, `fintech:*`, `cargo:*`, `retention:*`, `appointments:*`, `executive:*` |
| `agent` | Tenant (`page_id`) | `pages:read`, `leads:read/write`, `sessions:read/write`, `knowledge:read`, `fintech:read/write`, `cargo:read`, `appointments:read/write` |
| `warehouse_staff` | Tenant (`page_id`) | `pages:read`, `cargo:read/write`, `leads:read` |
| `read_only` | Tenant (`page_id`) | `*:read` only (cannot mutate leads, invoices, cargo, knowledge, or settings) |

---

## 3. Mandatory Multi-Tenant Isolation & IDOR Prevention

- `core_security.enforce_tenant_scope(request, requested_page_id, require_auth=True, allow_admin_all=..., permission=...)` is now enforced across all protected endpoints:
  - `/api/pages`, `/api/pages/{page_id}`, `/api/pages/{page_id}/gemini_key`, `/api/pages/{page_id}/credentials`, `/api/pages/{page_id}/google_sheets`, `/api/pages/{page_id}/sheets*`
  - `/api/sessions`, `/api/sessions/{sender_id}/messages`, `/api/sessions/{sender_id}/takeover`, `/api/sessions/{sender_id}/send`
  - `/api/leads`, `/api/registrations`, `/api/leads/{lead_id}/status`, `/api/export/csv`, `/api/export/excel`
  - `/api/knowledge` (GET/POST)
  - `/api/fintech/summary`, `/api/fintech/invoices`, `/api/fintech/settings`, `/api/fintech/create-invoice`
  - `/api/cargo/scan`, `/api/cargo/{tracking_code}/deliver`, `/api/cargo/packages`, `/api/cargo/summary`, `/api/cargo/import-manifest`
  - `/api/executive/preview`, `/api/executive/send-report`, `/api/executive/settings`
  - `/api/retention/rules`, `/api/retention/broadcast`, `/api/retention/campaigns`, `/api/retention/summary`, `/api/retention/trigger-checks`
  - `/api/appointments`, `/api/appointments/{appointment_id}/status`, `/api/appointments/summary`
- **No Silent Default Tenant Fallback:** Unauthenticated requests to protected endpoints receive `401 Unauthorized` rather than falling back to `DEFAULT_PAGE_ID`.
- **Cross-Tenant IDOR Prevention:** Tenant-scoped roles passing another tenant's `page_id` or accessing another tenant's lead/session/appointment ID receive `403 Forbidden`.

---

## 4. Webhook & Payment Security (`fintech_service.py` & `main.py`)

### 4.1 Fail-Closed Webhook Verification
- **Meta Messenger / Instagram (`POST /webhook` & `GET /webhook`):**
  - Verifies `X-Hub-Signature-256` using HMAC-SHA256 over raw request bytes (`verify_meta_webhook_signature`).
  - Verifies `hub.verify_token` using constant-time digest comparison (`constant_time_equal`).
- **Telegram (`POST /telegram/webhook`):**
  - Verifies `X-Telegram-Bot-Api-Secret-Token` using `hmac.compare_digest` (`verify_telegram_webhook_secret`).
- **ManyChat (`POST /api/manychat`):**
  - Verifies `X-ManyChat-Secret` / `X-Webhook-Secret` / `Bearer` token against `MANYCHAT_WEBHOOK_SECRET` or tenant `verify_token` (`verify_manychat_webhook_secret`).

### 4.2 QPay v2 Live Verification & Replay Protection
- `fintech_service.check_qpay_payment_live_detailed()` calls QPay `/v2/payment/check` and validates:
  1. `payment_status == "PAID"`
  2. `paid_amount >= expected_amount` (invoice amount)
  3. `payment_currency == expected_currency` (`MNT`)
  4. Extracts `provider_payment_id`
- `fintech_service.process_successful_payment()` uses `database.claim_notification_lock("qpay_paid:{invoice_id}")` for atomic replay/idempotency protection, stores `provider_payment_id` and `callback_verified=1`, and writes an immutable `payment.confirmed` audit log.
- Payment simulation (`POST /api/fintech/invoices/{invoice_id}/simulate-pay`) is blocked for non-admins when `is_production_mode()` or `DISABLE_PAYMENT_SIMULATOR=1`.
- Receipt screenshot analysis in `agent.py` creates `pending_verification` leads for manager review and never marks a QPay invoice as `PAID`.

---

## 5. API & Upload Hardening

- **Upload Size Limits:** Enforced `MAX_UPLOAD_BYTES = 10 MB` (`HTTP 413`) on `/api/upload-receipt`, `/api/pages/{page_id}/sheets/upload`, `/api/cargo/import-manifest`, and `/api/chat/voice`.
- **SSRF Protection:** `sheets_service.normalize_sheet_csv_url()` strictly enforces `https://docs.google.com/spreadsheets/d/<id>` and is validated on both `/api/pages/{page_id}/google_sheets` and `/api/pages/{page_id}/sheets/add`.
- **Environment File Safety:** `/api/update-keys` never writes plaintext `.env` in production mode.
