# ROADMAP — Prioritised, with Effort & Dependencies

Derived from the Phase 0 audit of `48e9c6f`. Effort is engineering days for one senior engineer.
"Verified by" lists the proof required before an item may be marked **PASS** — a claim without a command
and its output does not count.

---

## Stage A — Baseline audit ✅ **PASS**

Delivered: `BASELINE_AUDIT.md`, `ARCHITECTURE_MAP.md`, `FEATURE_MATRIX.md`, `SECURITY_AUDIT.md`,
`TECHNICAL_DEBT.md`, `PRODUCTION_READINESS.md`, this file. Read-only on product code.

---

## Stage B — P0/P1 security & data integrity  ← **START HERE**

| ID | Task | Fixes | Depends | Effort | Verified by |
|---|---|---|---|---|---|
| B-01 | Central `jsonable()` response serialiser (`datetime`, `date`, `Decimal`, `bytes`); apply at every route returning DB rows | P0-01 | — | 0.5 d | `test_leads_with_data_returns_200_on_postgres`, `test_auth_me_client_returns_200_on_postgres` |
| B-02 | CORS: `ALLOWED_ORIGINS` allowlist, boot-time validation, never `*` + credentials | SEC-01 | — | 0.25 d | `test_cors_rejects_unknown_origin`, `test_cors_allows_configured_origin` |
| B-03 | Derive id-table list from `information_schema` (or `RETURNING *`), not a hand-maintained set | P1-01 | — | 0.25 d | `test_comment_automation_create_returns_id_on_postgres`, `test_tracked_links_create_returns_id` |
| B-04 | Date predicates: `col >= ? AND col < ?` instead of `LIKE ?%` | P1-03 | — | 0.5 d | `test_fintech_summary_on_postgres`, `test_executive_preview_on_postgres` |
| B-05 | Invoice status: non-owner tenant → `404`; public payment page uses unguessable token | P1-04 | B-01 | 0.5 d | `test_cross_tenant_invoice_status_404`, `test_public_pay_token_required` |
| B-06 | Bump `pillow>=13.0.0`, `pytest>=9.0.3`; add `pip-audit` CI gate | SEC-06 | — | 0.25 d | `pip-audit` reports 0 vulnerabilities |
| B-07 | CI: `if: ${{ !cancelled() }}` on migration steps; order migration **before** live suites | TD-01 | — | 0.25 d | CI run shows all stages executed |
| B-08 | `@pytest.fixture(autouse=True, scope="module")` in `test_p1_payment_security.py` | TD-03 | — | 0.25 d | suite green **in isolation** |
| B-09 | Redis-backed login rate limit | SEC-07 | — | 0.5 d | `test_rate_limit_shared_across_workers` |
| B-10 | CSP + HSTS in production | SEC-03 | — | 0.5 d | `test_security_headers_present_in_production` |
| B-11 | Structured error logging with `request_id` + traceback | SEC-05 | — | 0.25 d | `test_500_logs_traceback_with_request_id` |

**Stage B exit gate (all must hold):**
1. `pytest tests/` → **0 failed** in SQLite mode **and** PG16+Redis mode.
2. Endpoint sweep (21 GETs × admin+client) → **0 × 500**.
3. `pip-audit` → 0 known vulnerabilities.
4. CI green on the stage PR, with no skipped verification steps.

Estimated: **4 days**.

---

## Stage C — Database, migration, backup/restore

| ID | Task | Fixes | Depends | Effort |
|---|---|---|---|---|
| C-01 | `core/models.py` becomes the only metadata; regenerate `0001` with real `DateTime`/`Text`/`String` types | TD-02 | B | 1 d |
| C-02 | `compare_metadata()` gate in CI against live PG (types included) | P2-01 | C-01 | 0.5 d |
| C-03 | `0002` migration: `varchar(64) → timestamptz` with `USING` cast, backup + rollback script, row checksum before/after | TD-02 | C-01 | 1.5 d |
| C-04 | Remove `init_db()` DDL; boot asserts `alembic current == head` | TD-02 | C-03 | 1 d |
| C-05 | FK constraints on tenant columns + `UNIQUE(page_id, phone)` for lead dedupe | TD-02, CRM | C-04 | 1 d |
| C-06 | SQL-side pagination/filtering for `/api/leads`, `/api/sessions` | TD-08 | — | 1 d |
| C-07 | Restore drill script + measured RTO/RPO documented | — | — | 0.5 d |

**Exit gate:** fresh `alembic upgrade head` + boot → `compare_metadata` diff = ∅; existing-data migration
verified by row count + per-table SHA-256; `alembic downgrade` verified on a copy.
Estimated: **6.5 days**.

---

## Stage D — Backend architecture & reliability

| ID | Task | Fixes | Effort |
|---|---|---|---|
| D-01 | Single auth dependency; delete duplicate token extractors | TD-04 | 1 d |
| D-02 | Split `database.py` → `repositories/*` + `core/crypto.py` + `domain/*` (shim first) | TD-05 | 3 d |
| D-03 | `integrations/messaging/*`; remove `from main import …` in services & worker | TD-06 | 1 d |
| D-04 | Redis state: dedup, rate limit, circuit breaker | TD-07 | 1.5 d |
| D-05 | Inbound webhook retry + DLQ (persist raw event, then process) | TD | 1.5 d |
| D-06 | Prometheus metrics; flush in-memory telemetry periodically | Observability | 1 d |
| D-07 | Layering test (`test_layering.py`) — no `services → app` imports | TD-06 | 0.25 d |

**Exit gate:** no `main` import in service modules; webhook duplicate across 2 workers processed once;
metrics endpoint scraped by a local Prometheus.
Estimated: **9.25 days**.

---

## Stage E — Omnichannel integrations

| ID | Task | Effort |
|---|---|---|
| E-01 | `MessagingProvider` interface + `MetaProvider`, `TelegramProvider`, `WebChatProvider` | 2 d |
| E-02 | Attachment validation (MIME allowlist, size cap, re-encode) before Pillow | 1 d |
| E-03 | Per-page token lifecycle: expiry detection, refresh reminder, 403 surfacing | 1.5 d |
| E-04 | Delivery status + retry on 429/5xx with jittered backoff | 1.5 d |
| E-05 | Identity linking: never auto-merge users across channels (explicit verified link only) | 1 d |
| E-06 | Sandbox-credential integration tests (Meta test app, TG test bot) — marked `BLOCKED` until creds exist | 2 d |

**Exit gate:** adapter contract tests pass against recorded fixtures; live smoke test documented but only
claimed when credentials exist.

---

## Stage F — AI Agent engine

| ID | Task | Effort |
|---|---|---|
| F-01 | `AIProvider` protocol: `generate()`, `stream()`, `tool_call()`, `usage()`; Gemini + OpenAI-compatible impls | 2 d |
| F-02 | Provider-agnostic tool schema (currently Gemini-shaped) | 1 d |
| F-03 | Prompt versioning: `prompts/v{n}.md` + `PROMPT_VERSION` env + eval binding | 1 d |
| F-04 | Eval dataset (≥ 50 conversations) + scoring (groundedness, no-hallucination, leak, handoff) in CI | 2 d |
| F-05 | Use provider-reported token usage; cost per tenant per day | 1 d |
| F-06 | Human handoff policy (confidence threshold, keyword, SLA) | 1 d |
| F-07 | RAG over `knowledge_json` with citations (only if knowledge exceeds prompt budget) | 3 d (optional) |

---

## Stage G — CRM & sales

`tags`, `custom_fields` (JSONB + validation), duplicate detection + `merge_contacts` (transactional,
audited), pipeline `deal_stages` + `deals`, assignment + team inbox, notes, unified timeline, consent ledger.
Effort ≈ **8 days.** Each action must call `enforce_tenant_scope` + `has_permission` and be covered by a
cross-tenant test.

## Stage H — Automation

Visual model (`nodes`/`edges` JSONB) with validation, versioning, execution history, conditions/branching,
per-run timeout, concurrency lock per contact, cancellation. Effort ≈ **10 days.**
Idempotency: every action keyed by `(run_id, node_id)` through `notification_locks`.

## Stage I — Analytics & ROI

Document each metric's definition + source table + SQL. Implement: response time, AI vs human reply rate,
handoff rate, conversion, link clicks, revenue attribution, cost per lead, AI cost. Effort ≈ **6 days.**
No metric may be displayed unless its query returns real rows.

## Stage J — Frontend & UX

Extract modules, remove inline handlers, self-host assets, add CSP-compatible build, component library,
loading/empty/error states, keyboard nav, a11y audit, date/number formatting via `Intl` with tenant TZ.
Effort ≈ **10 days.**

## Stage K — Performance & scalability

Author load harness (k6/locust) → **baseline first**, then optimise, then re-measure. Targets:
p95 < 400 ms at 100 concurrent users; webhook throughput ≥ 200/s; DB pool saturation alerts.
Effort ≈ **6 days** (measurement is mandatory before any claim).

## Stage L — Testing & CI/CD

Coverage gate (line ≥ 70 %, but only for newly-touched modules), dependency audit, Playwright e2e for 5
critical journeys, Postgres service matrix, flaky-test quarantine policy. Effort ≈ **5 days.**

## Stage M — Deployment & observability

Metrics + alerting (5xx rate, p95, queue depth, DLQ > 0, backup age), log aggregation, deploy runbook
dry-run, restore drill on staging, rollback rehearsal. Effort ≈ **4 days.**

## Stage N — Release

Version, changelog, commit SHA, CI run link, test summary, known limitations, rollback instructions.
Close-out requires: all P0/P1 closed, tenant isolation suite green, restore drill passed, prod build passed.

---

## Sequencing summary

```
A ✅ ──► B (4 d) ──► C (6.5 d) ──► D (9.25 d) ──► E ──► F ──► G ──► H ──► I ──► J ──► K ──► L ──► M ──► N
                       │
                       └─ C-01/C-02 may run parallel with D-01/D-07 (different files)
```

**Rule enforced:** no two workstreams touch the same file, schema, or API contract concurrently.
`C-01..C-05` own the schema; `D-02` owns `database.py`. They must be serialised.
