# PRODUCTION READINESS — Verdict & Scored Assessment

Audit commit: `48e9c6f`. All measurements reproducible (see `BASELINE_AUDIT.md` §2).

---

## 1. Verdict

> ### ⛔ NOT PRODUCTION READY — release blocked
>
> Two **P0** issues are open. Per the rules of this engagement, a P0 keeps the verdict at
> "do not ship" regardless of the aggregate score.
>
> A PostgreSQL deployment at this commit is **functionally unusable for tenants**
> (dashboard bootstrap returns 500) and **CORS-exploitable** by any website.

**Target environment for the blockers:** PostgreSQL 16 (the documented production target in
`docker-compose.prod.yml` and `docs/database/POSTGRESQL_MIGRATION.md`). SQLite is the only currently
*working* mode, and SQLite is not a viable multi-tenant production store here.

---

## 2. Production blockers

| # | Blocker | Consequence if shipped | Fix effort |
|---|---|---|---|
| B1 | `P0-01` datetime serialisation | Tenant dashboard stuck at auth modal; `/api/leads` 500 once one lead exists; `/api/pages` 500 for admin | **S** (1 serialiser + regression tests) |
| B2 | `SEC-01` CORS wildcard + credentials | Any website steals any tenant's data | **S** (allowlist + tests) |
| B3 | `P1-02` schema drift (251 type diffs) | Migrated DB and runtime DB disagree; date filters throw | **L** (see TD-02 plan) |
| B4 | `P1-01` `lastrowid` None for 2 tables | Comment-to-DM automation silently creates broken rows | **S** (2 entries + test) |
| B5 | `P1-03` `LIKE` date filters on PG | Fintech & executive reports 500 | **S** (range predicates) |
| B6 | `P1-04` cross-tenant invoice read | Competitor revenue disclosure | **S** (tenant check → 404) |
| B7 | `SEC-06` Pillow CVEs | Attacker-influenced image decoding | **S** (bump pin; verify API compat) |
| B8 | `TD-01` CI skips migration verification | Regressions merge unseen | **S** (add `if: !cancelled()`) |
| B9 | `TD-03` pytest fixture absent | 5 permanent false failures training green-blindness | **S** (fixture) |
| B10 | `P1-06` zero foreign keys | Orphaned tenant rows; no referential integrity | **M** (FKs + backfill check) |

`S` ≈ < 1 day, `L` ≈ 3–5 days. **Total to clear blocks: ~2–3 focused days**, of which schema rework (B3)
is the long pole.

---

## 3. Scores

Weights are those specified for this engagement. Every score is tied to evidence; unmeasured areas are
capped rather than guessed.

| Dimension | Max | Score | Evidence / why not higher |
|---|---|---|---|
| Architecture | 10 | **4.0** | Clear separation exists (`core/`, `routers/`, services) and the compat layer is a thoughtful bridge. But: dual schema authority, 2.5 k-LOC `database.py`, services importing the app, 3 token extractors. |
| Security | 15 | **6.5** | Strong: PBKDF2, timing-safe compares, fail-closed webhook sigs, server-authoritative roles, 6/6 escalation tests, prod admin fail-closed, payment simulator locked. Deductions: CORS P0, cross-tenant invoice read, no CSP/HSTS, in-memory rate limits, 76 CVEs. |
| Database & Integrity | 10 | **3.0** | Alembic up/down works; backups have SHA-256 + per-table counts; restore rollback verified 7/7. But 251 type diffs, `LIKE` date filters, `lastrowid` gaps, drift checker blind to types, no FK constraints on tenant columns. |
| Backend Reliability | 10 | **6.0** | DB-backed queue with atomic claim + visibility recovery + DLQ + graceful shutdown (all tested). Deductions: per-process dedup/limits/circuit-breakers, no inbound webhook retry/DLQ, 4 endpoints 500. |
| AI Quality | 10 | **5.5** | Injection detection, secret-leak evaluation, circuit breaker, retry/backoff, tool guard (max 3 calls), deterministic CI fallback. Deductions: no provider interface (Gemini-welded), no prompt versioning/regression dataset, token counts are estimates, no RAG. |
| Omnichannel Integration | 10 | **4.5** | Meta/IG/Telegram/ManyChat/web widget all wired with fail-closed secret checks. Deductions: **zero live provider round-trips verified** (no credentials), comment-to-DM broken on PG, no per-channel adapter interface, no attachment validation. |
| CRM & Automation | 10 | **5.0** | Leads, status, CSV/Excel, keyword rules, comment rules, delays, execution history, DLQ. Deductions: no tags/custom fields/pipeline/merge/dedup/assignment/notes; no visual builder; leads 500 on PG. |
| Frontend & UX | 8 | **4.0** | All 66 handlers wired, no fake data, Mongolian, responsive Tailwind. Deductions: 5.5 k-LOC single file, 118 inline handlers, CDN runtime compile (CSP-hostile, outage-coupled), no a11y audit, no loading/empty/error-state audit. |
| Performance & Scalability | 7 | **2.0** | **No load test exists and none was run** (see §4). List endpoints do in-Python filtering over up to 2,000 rows; unbounded `get_all_registrations`. Score capped because it is unmeasured. |
| Testing & CI/CD | 5 | **3.0** | 93 real tests, 86 pass; live PG+Redis service containers; migration & restore suites genuinely exercise PG. Deductions: HEAD CI **red**, step-8 blocks migration steps, pytest fixture missing, no coverage gate, no load/e2e-browser tests. |
| DevOps & Observability | 3 | **1.5** | Non-root Docker, healthchecks, compose limits, backup/restore, deploy+rollback scripts. Deductions: no Prometheus/metrics export, in-memory telemetry, no structured logging/tracebacks, no alerting. |
| Documentation | 2 | **0.5** | Volume is high (7 doc areas), but `FINAL_PRODUCTION_READINESS.md` states "Zero Schema Drift" and "20/20 passed" — both falsified in this audit. Self-reported PASS is unsupported. |
| **Total** | **100** | **45.5** | |

### Tier

| Band | Meaning | This project |
|---|---|---|
| 95–100 | Production-ready | |
| 90–94 | High quality, low risk | |
| 80–89 | Good, possible blockers | |
| 70–79 | Major improvements needed | |
| **0–69** | **Do not ship** | **45.5 ⇒ do not ship** |

This is an internal engineering assessment, not an external certification.

---

## 4. What was **not** verified (explicit)

Honesty requirement — these are `NOT TESTED` / `BLOCKED`, not passes:

| Area | Status | Reason |
|---|---|---|
| Live Meta Graph API send/receive | `BLOCKED` | no page token / app secret |
| Live Instagram DM & comment events | `BLOCKED` | same |
| Live Telegram bot round-trip | `BLOCKED` | no bot token |
| Live QPay v2 payment | `BLOCKED` | no merchant credentials |
| Live Gemini inference | `BLOCKED` | no API key (CI deliberately runs keyless) |
| Browser rendering / responsive / a11y | `NOT TESTED` | no browser in sandbox |
| Load test @10/50/100 users | `NOT TESTED` | no load harness in repo; would need k6/locust authored first |
| Redis outage mid-flight (real) | `PARTIAL` | chaos suite simulates; no real Redis kill |
| Cross-tenant isolation on **every** endpoint | `PARTIAL` | probed leads/sessions/messages/comments/invoices; **not** exhaustive across 79 routes |
| Kubernetes/cloud deployment | `NOT TESTED` | compose only |

---

## 5. Roadmap (effort-estimated, dependency-ordered)

### Stage B — Stop the bleeding (2–3 days) → unblocks production *eligibility*
| # | Task | Depends on | Effort |
|---|---|---|---|
| B1 | API-boundary JSON serialiser for `datetime`/`Decimal`; regression test on **live PG with ≥1 row** | — | 0.5 d |
| B2 | CORS allowlist from `ALLOWED_ORIGINS`; boot validation; 3 tests | — | 0.25 d |
| B3 | `RETURNING` for **all** id tables (derive from `information_schema`, not a hand list) | — | 0.25 d |
| B4 | Replace `LIKE 'date%'` with `>= AND <` range predicates | — | 0.5 d |
| B5 | Invoice tenant check → `404`; tokenised public payment view | B1 | 0.5 d |
| B6 | Bump `pillow>=13`, `pytest>=9.0.3`; `pip-audit` CI gate | — | 0.25 d |
| B7 | CI: `if: !cancelled()` on steps 9–14; reorder so migration precedes live suites | — | 0.25 d |
| B8 | `pytest` fixture for `test_p1_payment_security.py` | — | 0.25 d |

**Exit gate:** `pytest tests/` green in **both** SQLite and PG+Redis modes; CI green on a PR;
endpoint sweep shows **0 × 500**; CORS test suite green.

### Stage C — Schema single-source (3–5 days)
`core/models.py` → Alembic generation; `compare_metadata()` gate; `0002` type migration with data cast +
rollback + checksum verification; drop `init_db()` DDL; boot asserts head revision.

### Stage D — Backend hardening (4–6 days)
Redis-backed dedup/rate-limit/circuit-breaker; structured logging with tracebacks + `request_id`;
repository split for `database.py`; unified auth dependency; inbound webhook retry/DLQ.

### Stage E–H — Integrations, AI, CRM, Automation (2–3 weeks)
Per-channel adapters behind `MessagingProvider`; `AIProvider` interface + prompt versioning + eval dataset;
CRM gaps (tags, dedupe, merge, pipeline, assignment); visual workflow with conditions/branching.

### Stage I–K — Analytics, Frontend, Performance (2–3 weeks)
SQL-side pagination; ROI definitions documented with source tables; frontend build + component extraction +
CSP; **load tests authored and run** before any perf claim.

### Stage L–M — CI/CD & Ops (1 week)
Coverage gate, dependency audit, e2e (Playwright), Postgres service matrix, Prometheus metrics, alerting,
deploy runbook dry-run, restore drill.

### Stage N — Release (2 days)
Close P0/P1, changelog + version + SHA + CI run + known limitations + rollback instructions.

**Realistic path to 90+:** Stages B + C + D (≈ 10–14 focused days) plus Redis-backed state — those three
move Security, Database and Reliability to ~80 % of their weight. Frontend/performance scores cannot rise
without measured load tests.

---

## 6. Dependency map of blockers

```
TD-02 (dual schema authority)
├── causes P0-01 (datetime → 500)          [B1 fixes symptom; TD-02 fixes cause]
├── causes P1-03 (LIKE on varchar/timestamp)[B4 fixes symptom]
└── enables P2-01 (drift checker blind)

SEC-01 (CORS)  ──amplifies──►  P1-04 (invoice leak)   [B2, B5]
SEC-03 (no CSP) ──amplifies──►  any stored XSS in dashboard.html

P1-01 (lastrowid)  ──blocks──►  CRM/Automation features (comment-to-DM)
TD-01 (CI skips)   ──hid──►     P1-02 for N commits
TD-03 (no fixture) ──hid──►     payment-security regressions
```

Fix order must respect this: **TD-02 before any further schema work**, **B1 before B5**, **B2 together with B5**.
