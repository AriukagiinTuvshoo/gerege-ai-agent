# TECHNICAL DEBT REGISTER

Each item: location, current state, root cause, impact, fix, required test. Ordered by leverage.

---

## TD-01 · P2 · CI step-8 failure silently skips the migration & schema verification steps

**File:** `.github/workflows/ci.yml:70-104`

**Current state.** Steps 9–14 (`SQLite→PG dry-run`, driver check, PG engine, `alembic upgrade head`,
data migration, cursor regression) have **no** `if:` condition. Step 8 (pytest) failed in run `43720772489`,
so all six were **skipped**, and every later live-PG suite ran against a **schema-less** database.
Steps 15+ do carry `if: ${{ !cancelled() }}`.

**Root cause.** Only the *later* steps were hardened with `!cancelled()`; the migration block was not.

**Impact.** CI reports failures that are artefacts of a missing schema (masking true signal) **and** skips
the only check that would have caught `P1-02`. The "0 failures → green" property is not trustworthy.

**Fix.** Add `if: ${{ !cancelled() }}` to steps 9–14 *and* split the job: `lint+unit` → `integration`
(needs a migrated DB, created by an explicit `alembic upgrade head` step that must pass) → `e2e`.
Add a final `fail-fast-summary` step that fails the job if any step was skipped-by-cancellation.
**Required test.** A CI self-test: deliberately break one unit test and assert the integration stages still
execute and still report their own status.

---

## TD-02 · P1 · Dual schema authority: `init_db()` DDL vs Alembic, no type enforcement

**Files:** `database.py:62-360` (runtime DDL), `migrations/versions/0001_initial_enterprise_schema.py`
(Alembic), `core/models.py` (declarative), `core/db_engine.py:389-448` (`verify_schema_drift`)

**Current state.**
- `main.py:36` executes `database.init_db()` at **import time** → the process creates/alters the schema.
- Alembic `0001` re-declares the same 17 tables independently.
- **251 column type differences** between the two DDLs on PostgreSQL 16:

| Column | Alembic | runtime `init_db()` |
|---|---|---|
| `pages.created_at` | `character varying` | `timestamp without time zone` |
| `registrations.created_at` | `character varying` | `timestamp` |
| `messages.created_at` | `character varying` | `timestamp` |
| `sessions.created_at` | `character varying` | `timestamp` |
| `invoices.paid_at` | `character varying` | `text` (STRING) |
| all `*_id` / `*_name` | `character varying(n)` | `text` |

- The migration compensates with `_ts_default() = CAST(CURRENT_TIMESTAMP AS VARCHAR)` and
  `sa.Column("created_at", sa.String(64))` — i.e. it deliberately models timestamps as strings.
- `verify_schema_drift()` parses **column names only** by AST and returns `has_drift: False`.
- **Neither schema declares a single foreign key.** Verified on both live databases:
  `SELECT count(*) … constraint_type='FOREIGN KEY'` → `gerege_crm_test: 0`, `gerege_prod: 0`.
  Multi-tenant relations (`messages.page_id → pages.page_id`, `invoices.page_id → pages.page_id`,
  `task_jobs.page_id → pages.page_id`, …) are enforced **only by application code**.
  This is `P1-06`: deleting a tenant leaves orphaned bills, messages and jobs; there is no
  `ON DELETE` policy and no DB-level guard against writing a row for a non-existent tenant.

**Root cause.** `init_db()` predates the PostgreSQL work and was never removed; Alembic was written to
*match column names* (to make the CI drift check green) rather than to match types. The drift checker
compares the two source files, never the live database, and never types.

**Impact.** Three distinct failures, all verified:
1. `P0-01` — on the runtime schema, psycopg2 returns `datetime` and `JSONResponse` raises `TypeError`.
2. Any SQL written for the Alembic schema (`LIKE '2026-…'` on a varchar) fails on the runtime schema
   (`timestamp ~~ unknown`) — `P1-03`.
3. `alembic upgrade head` then boot produces a *third*, hybrid schema.

**Fix (ordered, see `ARCHITECTURE_MAP.md#migration-path`).**
1. Delete the timestamp-as-string modelling; make `core/models.py` the single metadata source and generate
   `0001` from it.
2. Add `alembic.autogenerate.compare_metadata()` against a live PG as a **failing** CI gate.
3. Migrate existing data with an explicit `ALTER TABLE … TYPE timestamptz USING created_at::timestamptz`
   (with a backup + rollback script), not a `DROP`.
4. Remove `init_db()` from `main.py` import path; replace with an `alembic current == head` assertion at boot.
**Required tests.** `test_alembic_metadata_matches_live_postgres` (zero diff incl. types),
`test_app_boot_requires_head_revision`, `test_migration_0002_preserves_rows_and_checksums`.

---

## TD-03 · P1 · `test_p1_payment_security.py` fixture never runs under pytest

**File:** `tests/test_p1_payment_security.py:26` (`_setup_test_environment`), `:488` (`if __name__ == "__main__":`)

**Current state.** `_setup_test_environment()` is invoked **only** in the `__main__` block. Under pytest no
`@pytest.fixture(autouse=True)` exists, so `p1_tenant_a` / `p1_client_a` are never created. 5 tests fail
with `401 … салбар олдсонгүй`.

**Root cause.** The suite was authored to run as a script (`python tests/test_p1_payment_security.py`) and
pytest collection was added later without a fixture. The CI runs it under **both** modes, which is why
step 8 (pytest) fails while the script path passes.

**Impact.** 5 false failures per CI run; the real payment-security assertions are never exercised in
pytest mode; contributors learn to ignore red.
**Fix.** Convert to `@pytest.fixture(autouse=True, scope="module")` and delete the `__main__` duplicate
(keep one entry point). Same pattern should be checked in every `tests/*.py` that has a `__main__` runner.
**Required test.** `pytest tests/test_p1_payment_security.py` green **in isolation** (proven baseline for
this fix: run alone currently gives `5 failed, 9 passed`).

---

## TD-04 · P2 · Three parallel token-extraction implementations

**Files:** `main.py:217` (`get_current_user`), `core/security.py:228` (`extract_token_from_request`),
`core/security.py:272` (`resolve_current_user`)

**Current state.** Each reads header → cookie → query param, with slightly different precedence and
different query-param names (`token`, `auth_token`, `client_token`, `client_token`).
**Root cause.** Incremental hardening without consolidation.
**Impact.** A future change to precedence (e.g. dropping query tokens) must be made in three places; a
missed one is an auth bypass.
**Fix.** One `get_current_user(request)` dependency; delete the others; make query-token support a single
explicit setting.
**Required test.** Parametrised precedence table test (header wins over cookie wins over query; revoked token
rejected in all three transports).

---

## TD-05 · P2 · `database.py` mixes DDL, I/O, domain rules, and crypto

**File:** `database.py` (2,532 LOC, 60+ functions)

**Current state.** Contains: table DDL + ad-hoc `ALTER TABLE ADD COLUMN` migrations (lines 360-400),
connection plumbing, password hashing (`hash_password`, `verify_password`, `hmac_equal`), secret masking,
CSV/Excel export, ROI math, notification locks, comment automations, tracked links.
**Root cause.** No repository/domain boundary; `main.py` calls it directly.
**Impact.** Untestable in isolation; every schema change risks breaking money/queue/lock logic; the module
is the single biggest merge-conflict magnet.
**Fix.** Split into `core/crypto.py`, `repositories/{leads,messages,invoices,cargo,automations,jobs}.py`,
`domain/{roi,lead_status}.py`. Do it **one aggregate at a time**, keeping `database.py` as a thin
re-export shim until each call site is migrated.
**Required test.** Per-repository integration tests against live PG; a "no imports from `app`" architectural
test (`test_layering.py`).

---

## TD-06 · P2 · Services import the application module

**Files:** `fintech_service.py:650,654,661`; `cargo_service.py:99,103,111`; `worker.py:30`
(`from main import send_meta_message, send_telegram_message, notify_manager_telegram`)

**Current state.** Deferred imports inside functions, so no import cycle at load; but the dependency arrow
points domain ← app.
**Impact.** `worker.py` cannot run without importing the whole FastAPI app (and therefore opening DB schema
at import). Unit-testing a service pulls in the app. Reverses the stated architecture.
**Fix.** Extract `integrations/messaging/{meta,telegram}.py`; inject a `Notifier` into services.
**Required test.** `test_worker_imports_do_not_load_fastapi_app`.

---

## TD-07 · P2 · Cache/limit state in process memory

**Files:** `main.py:149` `_PROCESSED_MIDS`, `main.py:150` `_LOGIN_ATTEMPTS`, `core/monitoring.py`
(in-memory counters), `core/ai_router.py:221` `_CIRCUIT_BREAKERS`, `agent.py` session cache

**Current state.** All per-process. `Dockerfile` uses `--workers 2`; compose runs a separate `worker`.
**Impact.** Rate limits double per replica; webhook dedup breaks across workers; metrics vanish on restart;
one worker's open circuit breaker does not protect the other.
**Fix.** Redis for `_PROCESSED_MIDS` (via `notification_locks`), `_LOGIN_ATTEMPTS` (Redis `INCR`+`EXPIRE`),
and circuit-breaker state. Metrics → Prometheus registry or periodic DB flush.
**Required test.** `test_rate_limit_shared_across_two_workers`, `test_circuit_breaker_shared_state`.

---

## TD-08 · P2 · N+1 / full-table scans in list endpoints

**Files:** `main.py:1018` onward (`get_all_registrations` then Python-side filter/slice), ROI/summary helpers

**Current state.** `/api/leads` loads **all** registrations for a tenant (`limit=500`, max 2,000) and filters
in Python; totals are computed over the full list.
**Impact.** Linear memory and latency growth per tenant; a tenant with 200 k leads will time out.
**Fix.** Push `status`/`search`/`limit`/`offset` into SQL with a covering index on `(page_id, created_at)`
(already present) plus `(page_id, status)`.
**Required test.** `test_leads_pagination_is_sql_side` (assert `LIMIT/OFFSET` in the executed SQL) and a
seed-100k latency budget test.

---

## TD-09 · P2 · Frontend is a single 5,498-line file with CDN runtime compilation

**File:** `dashboard.html`; CDN deps: `cdn.tailwindcss.com`, `cdnjs.cloudflare.com`, Google Fonts

**Current state.** Inline `<script>`, 118 `onclick` attributes, no modules, no build. Tailwind is compiled
in the browser on every page load.
**Impact.** No tree-shaking (large payload), no caching strategy, flash-of-unstyled-content, CSP-hostile
(inline handlers require `'unsafe-inline'`), and any CDN incident takes the dashboard down.
**Fix.** Extract `static/js/*.js` modules + a real build; self-host fonts/icons; add CSP without
`'unsafe-inline'`. Keep Mongolian copy.
**Required test.** Lighthouse/perf budget in CI; `test_dashboard_has_no_inline_event_handlers`.

---

## TD-10 · P3 · Naive datetimes everywhere

**Files:** `database.py` (`datetime.now()`, `datetime.utcnow()`), `core/task_queue.py`,
`agent.py`, `fintech_service.py`

**Current state.** Mix of `datetime.now()` and `datetime.utcnow()`; values stored as local-format strings
(`"%Y-%m-%d %H:%M:%S"`); no timezone column.
**Impact.** Correctness depends on server TZ; DST-free Mongolia hides it locally but any deployment with a
different TZ computes the wrong "today", wrong follow-up windows, wrong ROI.
**Fix.** `datetime.now(timezone.utc)` + `timestamptz` columns (couples to `TD-02`); format at the edge.
**Required test.** `test_today_boundary_uses_utc_and_tenant_tz`.

---

## TD-11 · P3 · `scratch/` is untracked-by-CI ad-hoc test code

**Files:** `scratch/*.py` (8 scripts, ~900 LOC)

**Current state.** `scratch/test_*_e2e.py` resemble tests but are not collected (not under `tests/`, and the
CI command enumerates files explicitly). They contain synthetic tokens.
**Impact.** False sense of coverage; confusing to contributors.
**Fix.** Move the still-valuable ones into `tests/`, delete the rest.
**Required test.** `pytest tests/` is the single entry point and collects everything that matters.

---

## Debt summary

| Priority | Count | Items |
|---|---|---|
| P1 | 2 | TD-02 (schema authority), TD-03 (pytest fixture) |
| P2 | 7 | TD-01, TD-04, TD-05, TD-06, TD-07, TD-08, TD-09 |
| P3 | 2 | TD-10, TD-11 |

`TD-02` is the single highest-leverage item: it is the root cause of `P0-01` and `P1-03`, and it is the
reason the documented "Zero Schema Drift" claim is false.
