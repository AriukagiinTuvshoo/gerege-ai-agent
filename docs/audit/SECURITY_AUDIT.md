# SECURITY AUDIT — OWASP ASVS / Top-10 aligned

Scope: `48e9c6f`. Severity: **P0** = exploitable now, blocks production · **P1** = high · **P2** = medium ·
**P3** = low/hardening. Every finding has a reproducible check.

---

## SEC-01 · P0 · CORS reflects any origin with credentials

| Field | Value |
|---|---|
| **File** | `main.py:135-140` |
| **Code** | `CORSMiddleware(allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])` |
| **OWASP** | A05:2021 Security Misconfiguration / ASVS V14.5 |

**Current behaviour (verified).** A pre-flight from `https://evil-attacker.example` is answered
`200` with `access-control-allow-origin: https://evil-attacker.example` and
`access-control-allow-credentials: true`.

```
EXP preflight status: 200
EXP AC-Allow-Origin: https://evil-attacker.example
EXP AC-Allow-Credentials: true
EXP AC-Allow-Headers: authorization,content-type
```

**Root cause.** `allow_origins=["*"]` combined with `allow_credentials=True`. Starlette cannot emit a
literal `*` when credentials are enabled, so it *reflects* the request `Origin` — which converts a
misconfiguration into a full credentialed cross-origin bypass.

**Exploit scenario (cross-tenant data theft + authenticated action forgery).**

1. Browsers attach the `session_token` cookie (`samesite="lax"`, `httponly`) to **same-site** requests.
   Because the API reflects any `Origin`, a page on `https://evil.example` can issue
   `fetch('https://app.gerege.mn/api/leads', {credentials:'include'})`.
2. Pre-flight passes (verified above). The response carries `ACAO: https://evil.example` +
   `ACAC: true`, so the browser hands the body to the attacker's JS.
3. The attacker reads every lead/registration, conversation, invoice and page configuration for the
   victim's tenant — and can replay state-changing POSTs.
4. Verified with a real victim session: after login the cookie is set, and a request carrying
   `Origin: https://evil-attacker.example` is answered with `ACAO: https://evil-attacker.example`,
   `ACAC: true`.

**User impact.** Complete cross-tenant confidentiality and integrity loss from a single phishing link.
**Fix.** Replace `["*"]` with an explicit allowlist from `ALLOWED_ORIGINS` (env), validate it at boot,
reject unknown origins. Never combine `*` with `allow_credentials=True`.
**Required tests.** `test_cors_rejects_unknown_origin`, `test_cors_allows_configured_origin_with_credentials`,
`test_cors_no_wildcard_when_credentials_enabled`.
**Related.** `P2-04` (missing CSP/HSTS amplifies impact).

---

## SEC-02 · P1 · Cross-tenant invoice read (BOLA/IDOR)

| Field | Value |
|---|---|
| **File** | `main.py:1500-1545` |
| **OWASP** | A01:2021 Broken Access Control / ASVS V4 |

**Current behaviour (verified).** Tenant **B** authenticates normally and requests
`GET /api/fintech/invoices/{invoice_of_tenant_A}/status`:

```
CONF status: 200
CONF returned keys: ['amount','created_at','currency','description','ebarimt_lottery','ebarimt_qr','invoice_id','page_id','paid_at','status']
CONF leaked page_id of other tenant: iso_a | amount: 777777 | desc: A-secret-desc
```

The other tenant's `page_id`, amount, description, payment status and e-Barimt QR/lottery are disclosed.

**Root cause.** The handler computes `is_authorized` but uses it only to choose between the *full* record and
a "PII-safe" projection. The projection still contains `page_id`, `amount`, `description`, `paid_at`,
`ebarimt_*`. There is no `404`/`403` for a caller outside the invoice's tenant.

**Exploit scenario.** Invoice IDs are guessable in structure
(`INV-YYYYMMDD-XXXXXXXX`, 8 hex chars ⇒ ~4.3 × 10⁹, and `QP-YYYYMMDDHHMM-XXXXXX`). A tenant enumerating
IDs harvests competitors' revenue, descriptions and customer counts. Combined with `SEC-01` the attacker
needs no credentials at all.

**User impact.** Business-confidential financial data of other tenants.
**Fix.** If `user.page_id != inv.page_id` and not admin → `404`. Keep a genuinely public *tokenised* view
for the payment page only (`/pay/{id}` with an unguessable token), not the numeric-looking ID.
**Required tests.** `test_cross_tenant_invoice_status_404`, `test_admin_can_read_any_invoice`,
`test_public_invoice_projection_has_no_page_id`.
**Related.** `SEC-01`.

---

## SEC-03 · P2 · Missing Content-Security-Policy and HSTS

| Field | Value |
|---|---|
| **File** | `main.py:105-115` (middleware sets only `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`) |
| **OWASP** | A05:2021 |

**Verified.** `grep -n "Content-Security-Policy\|Strict-Transport-Security"` → **no matches** in
`main.py`, `core/*.py`, `routers/*.py`.

**Impact.** `dashboard.html` renders tenant data and loads four third-party origins
(`cdn.tailwindcss.com`, `cdnjs.cloudflare.com`, `fonts.googleapis.com`, `fonts.gstatic.com`) with no CSP.
A compromised CDN, or any stored-XSS in a lead name / message body, executes with the operator's session.
`dashboard.html` also embeds user content via template strings — CSP is the backstop.

**Fix.** Add `Content-Security-Policy` (`default-src 'self'`; explicit `script-src`/`style-src`/`font-src`
for the CDNs, or self-host them) and `Strict-Transport-Security: max-age=31536000; includeSubDomains`
when `is_production_mode()`. Consider `X-Frame-Options: DENY` already present — keep.
**Required tests.** `test_security_headers_present_in_production`, `test_hsts_absent_on_http_dev`.

---

## SEC-04 · P2 · Webhook deduplication is per-process and unbounded in intent

| Field | Value |
|---|---|
| **File** | `main.py:149` (`_PROCESSED_MIDS: List[str] = []`), `main.py:427-431` |
| **OWASP** | A04:2021 Insecure Design |

**Verified.** Dedup compares `mid` against a Python list; `del _PROCESSED_MIDS[:500]` when > 2 000.

**Impact.** `Dockerfile` runs `--workers 2` and `docker-compose.prod.yml` runs a separate `worker`. A Meta
retry can land on the other worker ⇒ **duplicate reply sent to the customer**. Conversely, after 2 000
messages the list evicts the oldest, so a delayed retry is re-processed. `list` membership is O(n).

**Fix.** Use the existing `notification_locks` table (already has `idempotency_key PRIMARY KEY` and expiry)
via `claim_notification_lock()`, or a Redis `SET NX EX`. Both are already implemented — the webhook simply
does not use them.
**Required tests.** `test_duplicate_webhook_same_mid_processed_once_across_workers`,
`test_webhook_dedup_survives_process_restart`, `test_expired_lock_allows_replay`.

---

## SEC-05 · P2 · Unhandled exceptions are fully masked (no traceback, no correlation)

| Field | Value |
|---|---|
| **File** | `main.py:103-127` |
| **OWASP** | A09:2021 Security Logging & Monitoring Failures |

**Verified.** The middleware catches `Exception`, records `error_detail=str(exc)` in an in-memory counter,
and returns a generic body. `traceback` is never logged. Discovering `SEC-06` (`TypeError: Object of type
datetime is not JSON serializable`) required instrumenting the route directly.

**Impact.** Two-fold — (a) operators cannot diagnose production 500s; (b) genuine attack attempts
(e.g. malformed payloads probing for crashes) leave only a one-line string. This is an availability and
forensics risk, and it is *why* `P0-01` shipped.
**Fix.** Log `logger.exception(...)` with `request_id`, `path`, `method`, and a redacted stack; keep the
generic response body.
**Required tests.** `test_500_logs_traceback_with_request_id`, `test_500_body_does_not_leak_internals`.

---

## Positive controls verified (do not regress)

| Control | Evidence |
|---|---|
| Meta signature fail-closed | `verify_meta_webhook_signature` returns `False` when `META_APP_SECRET` missing **and** fail-closed mode is on; `hmac.compare_digest` used |
| Telegram secret fail-closed | `verify_telegram_webhook_secret`, same pattern |
| ManyChat secret | env secret or per-page `verify_token`, `compare_digest` |
| Password hashing | PBKDF2-HMAC-SHA256, 100 000 iterations, per-user 16-byte salt (`database.py:29-44`) |
| Password compare | `secrets.compare_digest` (timing-safe) |
| Role escalation blocked | `resolve_tenant_login_role` ignores payload `role`; 6/6 tests pass |
| Default admin password | `ADMIN2026` is **fail-closed** when `ENV=production` or `STRICT_SECURITY=1` (`database.py:528-543`) and compose sets both |
| Payment simulator | Denies in production, requires admin, tenant-scoped (`main.py:1626-1670`) |
| QPay callback | Fail-closed: 400 `PROVIDER_VERIFICATION_REQUIRED` unless provider-verified or explicit mock flag |
| Tenant isolation (leads/sessions/comments) | cross-tenant probes → `403` / empty list |
| Secrets in git | none; only synthetic fixtures |
| Docker | non-root `gerege` user, `PYTHONDONTWRITEBYTECODE`, no secrets baked in |
| SQL injection surface | parameterised `?` placeholders throughout; `f"SELECT … {p_cond}"` uses only literal column/pipe fragments, not user data — **no injection found**, but see `TD-05` |

---

## Dependency vulnerabilities (verified with `pip-audit`)

```
Found 78 known vulnerabilities in 2 packages
  pillow 11.3.0 → 76 findings, all fixed in 13.0.0
  pytest 8.4.2  → PYSEC-2026-1845, fixed in 9.0.3
```

`requirements.txt` pins `pillow>=10.4.0,<12.0.0` and `pytest>=8.0.0,<9.0.0` — **the fixes are excluded by
the upper bounds**. Pillow is reachable from untrusted input: `agent.py:246` `Image.open(BytesIO(image_bytes))`
on an image fetched from a webhook attachment URL (`main.py`, attachment handler). That is attacker-influenced
image decoding in-process.
**Fix.** `pillow>=13.0.0,<14.0.0`, `pytest>=9.0.3,<10.0.0`; add `pip-audit -r requirements.txt` to CI as a gate.
**Required tests.** CI job `dependency-audit` fails the build on any new advisory.

---

## Attack-surface inventory

| Surface | Auth | Notes |
|---|---|---|
| `GET /webhook` | token query | verify handshake |
| `POST /webhook` | HMAC-256 | fail-closed |
| `POST /telegram/webhook` | secret token | fail-closed |
| `POST /api/manychat` | shared secret | fail-closed |
| `GET/POST /api/fintech/qpay/callback` | fail-closed provider check | |
| `GET /pay/{invoice_id}` | **public** | renders amount/description — see `SEC-02` |
| `POST /api/chat` | public (widget) | rate limiting? see below |
| `POST /api/upload-receipt` | public? | image upload → Pillow |
| `GET /r/{code}` | public | tracked-link redirect |
| `/api/auth/*` | — | 10 attempts / 60 s per IP **in memory** |
| 60+ `/api/*` | session + RBAC | |

**Gaps found in this inventory**

- Rate limiting is **in-memory** (`_LOGIN_ATTEMPTS`). With `--workers 2` the effective limit is doubled,
  and it resets on deploy. No limiting at all on `POST /api/chat`, `/api/upload-receipt`, or `/r/{code}`.
- `/pay/{invoice_id}` is public *and* the ID is partly guessable (`INV-date-hex8`); the amount and
  description of any invoice can be enumerated.
**Fix.** Redis-backed counters keyed by IP + route; Redis `SET NX` for dedup; tokenised payment links.
**Required tests.** `test_login_rate_limit_is_shared_across_workers`,
`test_chat_endpoint_rate_limited`, `test_pay_route_requires_token`.

---

## Findings index

| ID | Sev | Title | Status |
|---|---|---|---|
| SEC-01 | **P0** | CORS wildcard + credentials | Open |
| SEC-02 | P1 | Cross-tenant invoice read | Open |
| SEC-03 | P2 | Missing CSP / HSTS | Open |
| SEC-04 | P2 | Per-process webhook dedup | Open |
| SEC-05 | P2 | Masked exceptions / no tracebacks | Open |
| SEC-06 | P1 | 76 Pillow CVEs unfixable due to pin | Open |
| SEC-07 | P2 | In-memory rate limiting, unthrottled public endpoints | Open |
| SEC-08 | P2 | Public guessable invoice IDs reveal amount/description | Open |

`P0` count = **2** (`SEC-01`, plus data-integrity `P0-01` in `BASELINE_AUDIT.md`). **Production is blocked.**
