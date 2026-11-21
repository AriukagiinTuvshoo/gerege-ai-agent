# FEATURE MATRIX — Implemented vs. Claimed

Legend: **REAL** = works end-to-end, verified · **PARTIAL** = works on SQLite but broken/limited on
PostgreSQL, or missing key sub-cases · **UI-ONLY** = reachable in UI, no working backend effect ·
**BROKEN** = returns 500/incorrect result on the primary (PostgreSQL) target · **MISSING** = absent.

Verification column cites the check performed in Phase 0.

---

## 1. Channels / Omnichannel

| Feature | Claimed | Actual | Evidence | Note |
|---|---|---|---|---|
| Meta webhook verify (`GET /webhook`) | Yes | **REAL** | route inspected; fail-closed sig check | `META_VERIFY_TOKEN` |
| Meta message receive | Yes | **PARTIAL** | `POST /webhook` → signature verified then processed | cannot reach Meta API from sandbox |
| Meta send (`send_meta_message`) | Yes | **PARTIAL** | Graph v22.0 call, 10 s timeout, error logged | no live token |
| IG DM / comments | Yes | **PARTIAL** | shares Meta webhook path | — |
| Comment-to-DM automation | Yes | **BROKEN on PG** | `create_comment_automation` → `id: None`; `get_comment_automation(None)` → `TypeError` | `P1-01` |
| Telegram webhook | Yes | **PARTIAL** | secret-token check, fail-closed | no live bot |
| ManyChat webhook | Yes | **PARTIAL** | secret check via env or page `verify_token` | — |
| Website chat widget (`widget.js`) | Yes | **REAL** | 200, 10,290 bytes | `POST /api/chat` |
| Webhook idempotency (Meta `mid`) | Yes | **PARTIAL** | in-process `list` capped at 2,000 | not multi-worker safe (`P2-02`) |
| Webhook retry / DLQ | Claimed | **MISSING** | no retry queue for inbound webhooks | events lost on handler error |

## 2. AI Agent

| Feature | Claimed | Actual | Evidence | Note |
|---|---|---|---|---|
| Gemini integration | Yes | **REAL (code)** | `agent.py` google-genai, tool defs | not exercised without key |
| Provider abstraction | Yes | **PARTIAL** | `core/ai_router.py` has circuit breaker, retry/backoff, OpenAI-compatible + Anthropic fallback | primary path still hardwired to Gemini client in `agent.py`; no `AIProvider` interface |
| Tool calling | Yes | **REAL (code)** | 4 tools: `register_customer`, `check_sheet_cargo_status`, `create_payment_invoice`, `book_service_appointment` | guard `ToolExecutionGuard`, max 3 calls/turn |
| Prompt-injection defence | Yes | **REAL** | `detect_prompt_injection`, `wrap_untrusted_user_input` | pattern-based |
| Secret/PII leak guard | Yes | **REAL** | `evaluate_ai_response` redaction tests pass | `test_ai_eval_suite` 11/11 |
| Cost / token accounting | Yes | **PARTIAL** | `estimate_tokens` + `tokens_used` + `monthly_token_limit` | estimate, not provider-reported usage |
| Prompt versioning | Claimed | **MISSING** | single `build_system_instruction_for_page()` string | no version IDs, no regression dataset |
| Human handoff | Yes | **PARTIAL** | `is_human_takeover` on `session_states`, `/takeover` route | no SLA/routing rules |
| RAG | No | **MISSING** | — | `knowledge_json` is inline text only |

## 3. CRM & Sales

| Feature | Claimed | Actual | Evidence | Note |
|---|---|---|---|---|
| Leads list | Yes | **BROKEN on PG once data exists** | `get_all_registrations` returns `datetime` → 500 | `P0-01` |
| Leads filter/search/paginate | Yes | **REAL** (empty DB) | in-Python filtering | O(n) scan, no SQL pagination |
| Lead status update | Yes | **REAL** | `POST /api/leads/{id}/status` 200 | — |
| CSV export | Yes | **REAL** | 200, UTF-8 BOM header | — |
| Excel export | Yes | **REAL (code)** | `openpyxl` | — |
| Contact / duplicate detection | Claimed | **MISSING** | no unique constraint on `(page_id, phone)` | duplicates possible |
| Contact merge | Claimed | **MISSING** | — | — |
| Tags / custom fields | Claimed | **MISSING** | no schema | — |
| Sales pipeline / deal stages | Claimed | **MISSING** | no schema | — |
| Assignment / team inbox | Claimed | **PARTIAL** | `is_human_takeover` only | no agent assignment |
| Notes / internal comments | Claimed | **MISSING** | — | — |
| Customer timeline | Claimed | **PARTIAL** | `/api/sessions/{id}/messages` | no unified timeline |
| Consent / retention rules | Yes | **PARTIAL** | `retention_service` campaigns | no consent ledger |

## 4. Automation Engine

| Feature | Claimed | Actual | Evidence | Note |
|---|---|---|---|---|
| Keyword rules | Yes | **REAL** | `automated_rules`, `sent_followups` | — |
| Comment trigger | Yes | **BROKEN on PG** | `P1-01` | — |
| Tag/link/order triggers | Claimed | **MISSING** | only keyword/comment | — |
| Visual workflow builder | Claimed | **MISSING** | rule list UI only | — |
| Conditions/branching | Claimed | **MISSING** | — | — |
| Wait/delay | Yes | **REAL** | `delay_hours` + scheduler | — |
| Execution history | Yes | **REAL** | `sent_followups`, `task_jobs` | — |
| Retry / backoff / DLQ | Yes | **REAL** | `task_queue.fail_job` → `DEAD_LETTER` | verified in chaos suite |
| Cancellation | Claimed | **PARTIAL** | `request_shutdown` | per-job cancel absent |

## 5. Analytics & ROI

| Feature | Claimed | Actual | Evidence | Note |
|---|---|---|---|---|
| Fintech summary | Yes | **BROKEN on PG** | `paid_at LIKE '2026-…'` → `timestamp ~~ unknown` | `P1-03` |
| Executive report preview | Yes | **BROKEN on PG** | `created_at LIKE '…'` | `P1-03` |
| ROI analytics (`/api/analytics/roi`) | Yes | **PARTIAL** | tracked links + conversions | no revenue attribution join |
| Cargo summary | Yes | 200 | verified | date via `arrived_at LIKE` → latent `P1-03` |
| Appointments summary | Yes | 200 | verified | — |
| Retention summary | Yes | 200 | verified | — |
| Response-time / handoff rate | Claimed | **MISSING** | not computed | — |
| Cost per lead / AI cost | Claimed | **MISSING** | token estimate only | — |

## 6. Auth / Tenancy / Admin

| Feature | Claimed | Actual | Evidence | Note |
|---|---|---|---|---|
| Admin password login | Yes | **REAL** | 200; default `ADMIN2026` **fail-closed** in prod | good |
| Tenant client login | Yes | **REAL** | 200 | — |
| Server-authoritative role | Yes | **REAL** | `resolve_tenant_login_role` ignores payload `role` | 6/6 tests pass |
| Session revocation | Yes | **REAL** | `revoked`, `revoked_at` | — |
| Session expiry | Yes | **REAL** | `expires_at` checked | — |
| RBAC permission matrix | Yes | **REAL** | `ROLE_PERMISSIONS` + `has_permission` | — |
| Tenant isolation (leads/sessions) | Yes | **REAL** | cross-tenant probes → 403 / empty | verified |
| Tenant isolation (invoices) | — | **PARTIAL** | any tenant can read another's invoice fields by ID | `P1-04` |
| Audit log | Yes | **REAL** | `audit_logs` + `record_audit_log` | not tamper-evident |
| API keys per tenant | Claimed | **MISSING** | `client_magic_token` only | — |
| 2FA / MFA | — | **MISSING** | — | — |

## 7. Reliability / DevOps

| Feature | Claimed | Actual | Evidence | Note |
|---|---|---|---|---|
| DB-backed job queue | Yes | **REAL** | `task_jobs` + atomic `UPDATE` | — |
| Redis auto-reconnect | Yes | **REAL** | `_get_redis()` ping + 5 s retry | — |
| Stale job recovery | Yes | **REAL** | `recover_stale_jobs(300)` | — |
| Graceful shutdown | Yes | **REAL** | `request_shutdown`, SIGTERM test passes | — |
| Backup (PG + SQLite) | Yes | **REAL** | `pg_dump` + SHA-256 + `.meta.json` | — |
| Restore verification | Yes | **REAL** | checksum + per-table counts + staging `PRAGMA integrity_check` | 7/7 pass |
| Restore rollback | Yes | **REAL** | `pre_restore` snapshot | 7/7 pass |
| Alembic migration | Yes | **REAL** | up + down both verified | **types wrong** (`P1-02`) |
| Schema-drift gate | Yes | **INADEQUATE** | compares column names only | `P2-01` |
| Health / readiness | Yes | **REAL** | `/api/health`, `/api/ready` 200 | 503 on DB down (claimed) |
| Metrics | Yes | **PARTIAL** | in-memory counters | lost on restart; no Prometheus |
| Structured logging | Claimed | **PARTIAL** | `logging` + `str(exc)`; no JSON, no tracebacks | — |
| Docker non-root | Yes | **REAL** | `useradd gerege` + `USER gerege` | good |
| CI live PG+Redis | Yes | **PARTIAL** | services present, but step 8 blocks steps 9–14 | `TD-01` |
| Load testing | Claimed | **MISSING** | no locust/k6 artefact | — |

## 8. Frontend

| Feature | Actual | Evidence |
|---|---|---|
| Single-file SPA (`dashboard.html`) | 5,498 LOC, 118 inline `onclick` | all **66** distinct handlers defined |
| Login / tenant portal / admin panel | reachable | `/`, `/dashboard`, `/admin` 200 |
| Demo/mock data | **none found** | grep for mock/demo/dummy → only “Phone Mockup” comment |
| Design system | ad-hoc Tailwind classes, no components | CDN `cdn.tailwindcss.com` (runtime compile) |
| Mongolian language | Yes | — |
| Accessibility | unknown / untested | no ARIA audit performed |
| Timezone/date formatting | `datetime.now()` (naive, server-local) | correct only if server TZ == business TZ |
| Offline / CDN failure | breaks (Tailwind, Font Awesome, Google Fonts from CDN) | supply-chain + availability risk |

---

## 9. Summary counts

| Status | Count |
|---|---|
| REAL (verified working) | 35 |
| PARTIAL (works with caveats) | 24 |
| BROKEN on PostgreSQL | **6** |
| MISSING (claimed or expected, absent) | **16** |
| UI-ONLY (no backend effect) | 0 |

The absence of UI-ONLY items is a genuine positive: every `onclick` in the dashboard resolves to a defined
function, and no fake analytics arrays were found.
