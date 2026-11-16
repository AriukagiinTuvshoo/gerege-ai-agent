# STAGE B — P0/P1 SECURITY & DATA INTEGRITY · COMPLETION GATE

- **Branch:** `arena/d78ebf88-gerege-ai-agent`
- **Audit base:** `48e9c6f` → audit commit `ac5cffe`
- **Environment:** PostgreSQL **16.2** (TCP, UTF8/C.utf8), Redis **6.2.14**, Python 3.11,
  `pg_dump`/`psql` 16.2 on `PATH`. CI-parity.
- **Status: `PASS`**

---

## 1. Defects closed in this stage

| ID | Sev | Finding | Fix | Proof |
|---|---|---|---|---|
| **P0-01** | P0 | `datetime` not JSON-serialisable → `/api/auth/me`, `/api/leads`, `/api/pages` 500 on PostgreSQL | `core/serialization.py::jsonable` + `SafeJSONResponse`, aliased as `JSONResponse` so all 50+ call sites normalise | 4 endpoint tests + boundary test |
| **SEC-01** | P0 | CORS reflected any origin with `allow_credentials=True` | `core.security.resolve_allowed_origins()` allowlist; no wildcard ever; fail-closed in production | 3 CORS tests + behaviour matrix |
| **P1-01** | P1 | `lastrowid` `None` on PG for `comment_automations` / `tracked_links` | `_has_serial_id_column()` resolves from `information_schema` (cached), replacing the hand-maintained set | 3 tests incl. API-level id |
| **P1-03** | P1 | `LIKE 'date%'` → `timestamp ~~ unknown` on PG | `day_range_bounds()` + `>= ? AND < ?` range predicates | 4 tests (fintech ×2, daily metrics, executive) |
| **P1-04** | P1 | Cross-tenant invoice read (BOLA) | Non-owner authenticated caller → **404** (not 403, to avoid confirming existence) | 3 tests (cross-tenant 404, owner 200, admin 200) |
| **SEC-06** | P1 | 76 Pillow + 2 pytest CVEs excluded by `requirements.txt` bounds | `pillow>=13.0.0,<14.0.0`, `pytest>=9.0.3,<10.0.0`; `pip-audit` gate added to CI | `pip-audit` → **No known vulnerabilities found** |
| **TD-01** | P2 | CI step-8 failure skipped migration/verification steps 9–14 | `if: ${{ !cancelled() }}` on all 18 post-compile steps; dependency-audit + Stage B live-PG suites added | 26 steps parsed, YAML valid, only 4 intentional pre-gates unguarded |
| **TD-03** | P1 | `test_p1_payment_security.py` fixture never ran under pytest | session-scoped `autouse` pytest fixture | suite green **in isolation**: 14/14 (was 5 failed / 9 passed) |
| **P1-07** | P1 | *(found during this stage)* `GROUP BY m.sender_id` selects bare columns → `GroupingError` on PG; abandoned-chat detection threw on **every worker tick** | latest-message-per-sender via `NOT EXISTS` correlated aggregate (portable, no window functions) | chaos suite 20/20 ×3 fresh DBs; tick returns clean stats |

**P1-07 detail.** This was not in the Phase 0 ledger. It surfaced because Stage B's
`scenario_20` run became order-dependent (10.9 s = the test's `wait_for(timeout=10)`).
Re-runs on the **original** code reproduced it 3/3: `run_worker_tick` raised
`GroupingError: column "m.channel" must appear in the GROUP BY clause`. SQLite tolerates the
bare columns; PostgreSQL does not. Because `worker_main_loop` catches and logs the exception,
production would have silently skipped retention reminders and appointment dispatch on every
tick — a **silent functional outage**, invisible in SQLite CI.

---

## 2. Before / after

| Measurement | Before (`48e9c6f`) | After | 
|---|---|---|
| `pytest tests/` — SQLite | **5 failed**, 88 passed | **0 failed, 112 passed**, 1 skipped |
| `pytest tests/` — PG16+Redis | **7 failed**, 86 passed | **0 failed, 112 passed**, 1 skipped |
| Endpoint sweep (42 requests) | **4 × 500** | **0 × 500** (2 expected 403/404) |
| `pip-audit` | **78 vulnerabilities / 2 packages** | **0** |
| Chaos suite, fresh PG DB | 1 failed / 19 passed, 10.9 s (original code) | **20 passed**, ~0.95 s |
| `test_p1_payment_security` isolated | 5 failed / 9 passed | **14 passed** |
| Schema-drift gate (CI step 7) | pass | pass |
| Clean env from `requirements.txt` | — | boot + **112 passed** in both modes |

---

## 3. Commands actually executed

```bash
# schema + data
alembic upgrade head                       # PG16, 18 tables
python -c "import database; database.init_db()"   # runtime DDL path

# suites, both modes
env -u DATABASE_URL pytest tests/ -q
DATABASE_URL=... REDIS_URL=... pytest tests/ -q
pytest tests/test_stage_b_regressions.py -q            # 20 passed (3 schemas)
pytest tests/test_p1_payment_security.py -q            # 14 passed (isolation)

# CI steps reproduced individually
python scripts/migrate_sqlite_to_postgres.py --dry-run      # DRY_RUN_OK
python -c "from core.db_engine import create_sqlalchemy_engine; ..."  # PG_ENGINE_OK
python -m py_compile <21 modules>                           # PASS
pip-audit -r requirements.txt                                # 0 vulnerabilities

# clean-environment validation (mirrors Dockerfile)
python3 -m venv /tmp/dsim && /tmp/dsim/bin/pip install -r requirements.txt
/tmp/dsim/bin/python -c "import database; database.init_db()"   # INIT_DB OK
/tmp/dsim/bin/python -m pytest tests/ -q                        # 112 passed
```

---

## 4. Files changed

| File | Change |
|---|---|
| `core/serialization.py` | **new** — `jsonable()` + `SafeJSONResponse` |
| `core/security.py` | `resolve_allowed_origins()` CORS allowlist; `List` import |
| `core/db_engine.py` | `_has_serial_id_column()` catalog lookup + cache; `threading` import; 2 tables added to bootstrap set |
| `database.py` | `day_range_bounds()`; range predicates in `get_fintech_summary` (1 site) and `get_daily_executive_metrics` (4 sites); abandoned-chat query rewrite |
| `main.py` | `SafeJSONResponse` alias for `JSONResponse`; `default_response_class`; CORS allowlist wiring; invoice status rewritten (tenant 404 / admin full / public allowlist) |
| `requirements.txt` | `pillow>=13.0.0,<14.0.0`, `pytest>=9.0.3,<10.0.0` |
| `.github/workflows/ci.yml` | 18 guarded steps, dependency-audit gate, Stage B live-PG suite, `ALLOWED_ORIGINS` env |
| `tests/test_stage_b_regressions.py` | **new** — 20 regression tests |
| `tests/test_p1_payment_security.py` | pytest `autouse` fixture (TD-03) |
| `.env.example` | full env reference incl. `ALLOWED_ORIGINS`, `META_APP_SECRET`, `TELEGRAM_WEBHOOK_SECRET` |
| `docker-compose.prod.yml` | `ALLOWED_ORIGINS` required in production |

No user `.env`, database file, upload, or API key was deleted or rewritten.
No test was deleted, skipped, or weakened: `test_public_invoice_status_filters_pii` **caught a
real over-narrowing** in my first invoice fix and the production contract was restored rather
than the test changed.

---

## 5. Design decisions worth review

1. **Serialisation lives at one boundary, not in repositories.** `database.py` keeps returning
   real `datetime` objects (correct domain type). This avoids touching 60+ repository functions
   and keeps the fix idempotent; when Stage C moves to typed `timestamptz` columns, nothing here
   needs to change.
2. **`JSONResponse` is aliased, not replaced call-site-by-call-site.** 50+ explicit
   `JSONResponse(...)` constructions bypass FastAPI's `jsonable_encoder`; `default_response_class`
   alone does not help. The alias is one line and cannot be forgotten by a future handler.
3. **`lastrowid` is derived from the catalog, not a list.** A list always rots; the cache is
   populated from `information_schema` so adding a table can never silently reintroduce `id: None`.
4. **Cross-tenant invoice access returns 404, not 403.** 403 confirms the invoice exists,
   enabling IDOR enumeration. 404 is indistinguishable from "not found".
5. **The public invoice projection was restored, not narrowed.** It is an existing tested
   contract required by the payment page; it already excludes `sender_id` and phone. The BOLA
   fix targets *authenticated* cross-tenant reads.

---

## 6. Residual risk & not-done

| Item | Status | Note |
|---|---|---|
| `P1-02` 251 column type diffs (dual schema authority) | **OPEN** | Deliberately deferred to **Stage C** — needs a data-cast migration + rollback, not a hotfix |
| `P1-06` zero foreign keys | **OPEN** | Stage C |
| `P2-01` drift checker blind to types | **OPEN** | Stage C (`compare_metadata`) |
| `SEC-03` CSP / HSTS | **OPEN** | Stage B-10, intentionally after CORS lands |
| `SEC-04` per-process webhook dedup | **OPEN** | Stage D (Redis) |
| `SEC-07` in-memory rate limiting | **OPEN** | Stage D (Redis) |
| Docker image build | **NOT TESTED** | no Docker in sandbox; validated by replicating Dockerfile steps in a clean venv |
| Live Meta/Telegram/QPay/Gemini calls | **BLOCKED** | no credentials |
| Browser/a11y/load tests | **NOT TESTED** | no browser/load harness |

**Production remains blocked** on `P1-02` (Stage C): a PostgreSQL deployment still has a schema
whose column types differ between the Alembic migration and the runtime DDL. The *symptoms*
(500s) are gone because serialisation and range predicates are now type-agnostic, but the
*root cause* is untouched by design — fixing it requires a reversible data migration.

---

## 7. Gate report

1. **Checked** — all 5 Stage B defects + 3 harness defects; both DB modes; 3 schema variants; clean env.
2. **Found** — the 8 planned items plus **1 new P1** (`P1-07`, PostgreSQL-only silent worker outage).
3. **Root causes** — untyped JSON boundary; credentialed wildcard CORS; hand-maintained serial-table
   list; string-formatted dates assumed `TEXT`; authz computed but not enforced; dependency upper
   bounds below fix versions; test fixtures outside pytest lifecycle; SQLite-only `GROUP BY`.
4. **Files changed** — 11 (§4).
5. **Tests added** — 20 regression tests, all failing before their fix.
6. **Commands** — §3, all re-runnable.
7. **Results** — 112 passed / 0 failed in both modes; 0 × 500; 0 CVEs.
8. **Not checked** — Docker build, live providers, browser, load.
9. **Residual risk** — schema divergence (`P1-02`) and missing FKs (`P1-06`); production blocked.
10. **Next** — **Stage C**: single schema authority, typed columns, FK constraints, drift gate.

**STAGE B STATUS: `PASS`** (blockers B1–B9 closed). Overall production readiness remains
**blocked** until Stage C.
