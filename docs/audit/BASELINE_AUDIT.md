# PHASE 0 — BASELINE AUDIT (Evidence-Backed)

- **Repository:** `AriukagiinTuvshoo/gerege-ai-agent`
- **Branch audited:** `arena/d78ebf88-gerege-ai-agent`
- **Base commit:** `48e9c6f7392729bc87d0c810553ff459a919dbfb`
- **Base commit subject:** `feat: P0/P1 security hardening and noflow-inspired Comment-to-DM, tracked links, & ROI analytics`
- **Base commit date:** 2026-11-15 22:46:41 +0900
- **Audit date:** 2026-11-16
- **Working tree at audit start:** clean, 0 untracked, 0 modified, 93 tracked files
- **Commit count in history:** **1** (squashed history — `git rev-list --count HEAD` = 1)

> **Methodology.** Every claim below is reproduced locally. The audit environment was rebuilt to mirror
> CI exactly: **PostgreSQL 16.2** on TCP `127.0.0.1:5432` (database `gerege_crm_test`, user `gerege`,
> UTF8/C.utf8), **Redis 6.2.14** on `127.0.0.1:6379`, Python 3.11 + all `requirements.txt` pins, and
> `pg_dump`/`psql` 16.2 on `PATH`. Claims that fail in this sandbox because of *sandbox* limitations are
> explicitly marked as such and are **not** reported as repository defects.

---

## 1. Repository State vs. GitHub `main`

| Check | Result |
|---|---|
| Local `main` == `origin/main` == HEAD | Yes (`0` ahead / `0` behind) |
| Local branch vs base commit | Identical; no local edits at audit start |
| Untracked / ignored artefacts present | None at audit start |
| Secrets committed to git | **No** real secrets. Matches for `AIza…` are synthetic test fixtures (`AIzaSy_SAMPLE_CLIENT_KEY_FOR_TESTING`, `AIzaSyD9876…`) |
| `.env` present in repo | No (only `.env.example`, values blank) |

### 1.1 GitHub Actions — actual results (do not trust the docs)

`gh run list` for `main`:

| Run | Conclusion | Headline |
|---|---|---|
| `43720772489` | **failure** | `feat: P0/P1 security hardening and noflow-inspired…` (**current HEAD**) |
| `43689993618` | success | `fix: handle pg_dump 17 transaction_timeout…` |
| `43689812772` … `43687234288` (13 runs) | **failure** | CI iteration churn, all within ~1 hour before the last success |

**The commit this branch is based on has a red CI run.** Step-level results of run `43720772489`
(retrieved via `gh api .../actions/runs/43720772489/jobs`; raw logs had expired server-side, so the
failure was **reproduced locally** instead of guessed):

| # | Step | Status |
|---|---|---|
| 7 | Initialize SQLite schema & verify zero schema drift | success |
| **8** | **Run Pytest Regression… (SQLite mode)** | **failure** |
| 9–14 | SQLite→PG dry-run, drivers, PG engine, Alembic, data migration, cursor regression | **skipped** (blocked by step 8) |
| **18** | **P0-1 Security Role Escalation Suite (live PG)** | **failure** |
| **21** | **P1 Payment Security Suite (live PG)** | **failure** |
| **22** | **NoFlow Features Suite (live PG)** | **failure** |
| **23** | **Enterprise Phases Suite (live PG + Redis)** | **failure** |
| **25** | **Failure Scenarios Suite** | **failure** |
| 15,16,17,19,20,24,26 | Restore good/bad, P0-2, P0-3, AI Eval, Docker build | success |

**Consequence:** steps 9–14 are the schema-migration and live-PostgreSQL verification steps. They were
**skipped, not passed**. Because step 8 aborted the job, `alembic upgrade head` never ran in that run, so
the live-PG suites that *did* execute against a **schema-less** database. This is a CI harness defect that
masks real signal — see `TECHNICAL_DEBT.md#TD-01`.

---

## 2. Reproduced Baseline (independent of CI)

### 2.1 Test suite — two modes

| Mode | Command | Result |
|---|---|---|
| SQLite (no `DATABASE_URL`) | `pytest tests/` | **5 failed, 88 passed** (3.55 s) |
| PostgreSQL 16 + Redis 7 | `pytest tests/` with `DATABASE_URL`+`REDIS_URL` | **7 failed, 86 passed** (5.73 s) |

Failures in PostgreSQL mode (all reproduced, root causes verified):

| # | Test | Verified root cause | Owner |
|---|---|---|---|
| 1–5 | `tests/test_p1_payment_security.py` (5 tests) | `_setup_test_environment()` is **never called under pytest** — it is only invoked inside `if __name__ == "__main__":` at line 488. Under pytest the fixture pages `p1_tenant_a/b` do not exist, so client login returns 401. | Test harness (`TD-03`) |
| 6–7 | `tests/test_noflow_features.py` (2 tests) | `create_comment_automation()` returns `id: None` on PostgreSQL, then `get_comment_automation(None)` raises `TypeError`. Caused by `comment_automations` missing from `_SERIAL_ID_TABLES`. | Product (`P1-01`) |

> **Correction of an earlier assumption:** the 5 `test_p1_payment_security` failures are *not* a payment
> security regression. They are a test-isolation defect. Isolated proof: the same five tests pass when
> fixture state is created first, and the observed error is `401 … "p1_client_a' нэртэй харилцагчийн салбар
> олдсонгүй"` — a missing fixture, not a missing authorization check.

### 2.2 Failures caused by the audit sandbox — **NOT** repository defects

These were initially observed failing and were then re-run after fixing the *environment*:

| Symptom | Cause | Resolution |
|---|---|---|
| `alembic upgrade head` → `UnicodeEncodeError: 'ascii' codec` | `initdb` created `SQL_ASCII` DB | Re-created cluster with `--encoding=UTF8 --locale=C.utf8` → migrates cleanly |
| `create_backup()` → `[Errno 2] No such file or directory: 'pg_dump'` | `pg_dump` absent from sandbox `PATH` | Added PG 16.2 bin to `PATH` → all 43 restore/failure/enterprise tests pass |
| Live-PG suites failing with empty tables | CI blocked `alembic upgrade head` (step 8) | Ran `alembic upgrade head` manually |

After environment parity: **43/43** of `test_postgres_restore_real_rollback.py`,
`test_failure_scenarios.py`, `test_enterprise_phases.py` pass.

---

## 3. What actually runs (verified)

| Capability | Verified evidence |
|---|---|
| App boots on PostgreSQL | `import main` → `init_db()` creates 17 tables (types differ from Alembic — see `P1-02`) |
| Alembic upgrade/downgrade | `upgrade head` → 18 tables incl. `alembic_version`; `downgrade base` → only `alembic_version` remains |
| Admin login | 200 |
| Tenant client login | 200 |
| Tenant dashboard bootstrap | **500** on PostgreSQL (`P0-01`) |
| Comment-to-DM automation | create returns `id: null` on PG (`P1-01`) |
| Backup/restore on live PG | PASS with `pg_dump` 16 |
| Queue atomic claim | DB-backed `UPDATE … WHERE status='PENDING'` (single-statement atomic; see `P2-02`) |
| Webhook signatures | Fail-closed; `hmac.compare_digest` (correct) |
| Static UI | `/`, `/dashboard`, `/admin`, `/privacy`, `/terms`, `/widget.js` all 200 |

### 3.1 Endpoint sweep on real PostgreSQL (admin + client sessions, 21 GETs each)

```
admin  : 200 ×19, 500 /api/pages, 500 /api/fintech/summary, 500 /api/executive/preview, 404 /api/pages/detail
client : 200 ×17, 500 /api/auth/me, 500 /api/pages, 500 /api/fintech/summary, 500 /api/executive/preview, 403 /api/pages/detail
```

**Four endpoints return HTTP 500 for a tenant user on PostgreSQL.**

---

## 4. Severity Ledger (summary)

| ID | Sev | Title | File | Status |
|---|---|---|---|---|
| P0-01 | **P0** | `datetime` not JSON-serialisable → tenant dashboard, `/api/leads`, `/api/pages` 500 on PostgreSQL | `main.py:372`, `database.py` DDL | Open |
| P0-02 | **P0** | CORS reflects any origin **with** `allow_credentials=True` | `main.py:135-140` | Open |
| P1-01 | **P1** | `lastrowid` is `None` for `comment_automations` & `tracked_links` on PostgreSQL | `core/db_engine.py:147` | Open |
| P1-02 | **P1** | Alembic schema ≠ runtime schema: **251 column type differences** | `migrations/versions/0001…py` | Open |
| P1-03 | **P1** | `LIKE`-based date filtering breaks on PostgreSQL (`timestamp ~~ unknown`) | `database.py:1434,1686-1698` | Open |
| P1-04 | **P1** | Cross-tenant invoice read: any tenant reads another tenant's invoice by ID | `main.py:1523` | Open |
| P1-05 | **P1** | `requirements.txt` pins `pillow<12.0.0` but 76 CVEs need `13.0.0` | `requirements.txt:5` | Open |
| P1-06 | **P1** | **Zero foreign-key constraints** in either schema; tenant relations unenforced at DB level | `database.py:62-360`, `migrations/versions/0001…py` | Open |
| P2-01 | **P2** | Schema-drift checker only compares **column names**, never types, never live DB | `core/db_engine.py:389-448` | Open |
| P2-02 | **P2** | Webhook dedup is in-process `list` (`_PROCESSED_MIDS`) — not multi-worker safe | `main.py:149,427` | Open |
| P2-03 | **P2** | Services import `main` (layering inversion) | `fintech_service.py:650`, `cargo_service.py:99`, `worker.py:30` | Open |
| P2-04 | **P2** | Missing security headers: CSP, HSTS | `main.py:105-115` | Open |
| TD-01 | **P2** | CI: step 8 failure skips migration/verification steps 9–14 (no `if: !cancelled()`) | `.github/workflows/ci.yml:70-104` | Open |
| TD-03 | **P1** | `test_p1_payment_security.py` fixture never runs under pytest | `tests/test_p1_payment_security.py:26,488` | Open |

Full detail, root cause and required tests: `SECURITY_AUDIT.md`, `TECHNICAL_DEBT.md`.

---

## 5. Documentation accuracy

`docs/audit/FINAL_PRODUCTION_READINESS.md` claims:

> “**Zero Schema Drift** … 100 % alignment across all 15 tables”
> “20/20 failure and chaos scenarios PASSED”

Both are **contradicted by measured evidence**:

- `verify_schema_drift()` returns `has_drift: False` **because it only compares column *names***. The live
  PostgreSQL schema created by Alembic differs from the runtime `init_db()` schema in **251**
  column definitions (`information_schema.columns` diff).
- The chaos suite does not pass on a live PG+Redis environment at HEAD (7 failures reproduced).
- `PROGRESS.md` lists Phases 1–11 as `COMPLETED`. Phase 1 explicitly claims “PostgreSQL Engine, Pool,
  SAVEPOINT & Zero Schema Drift … COMPLETED” — this is inaccurate per the two points above.

This is a **documentation-integrity finding**, not a cosmetic one: it caused readiness to be reported at a
level the code does not support.

---

## 6. Phase 0 Gate Report

1. **What was checked** — git state vs GitHub `main`; real GitHub Actions conclusions + step matrix;
   full test suite in SQLite and PG16+Redis modes; Alembic up/down; live endpoint sweep; CORS,
   auth, RBAC, tenant isolation, webhook signatures; backup/restore; queue claim logic; dependency CVEs;
   frontend handler wiring; documentation claims.
2. **What was found** — 2 × P0, 7 × P1, 4 × P2, plus 1 test-harness defect. HEAD CI is red.
3. **Root causes** — (a) dual schema source-of-truth (raw `init_db()` DDL vs Alembic) with no type
   enforcement; (b) tests assert `status_code` but never body serialisation on PostgreSQL; (c) CORS
   configured with wildcard + credentials; (d) `_SERIAL_ID_TABLES` list not derived from schema.
4. **Files changed** — this phase is **read-only**; only `docs/audit/*` added.
5. **Tests added** — none yet (audit phase).
6. **Commands run** — see §2; `pytest tests/`, `alembic upgrade/downgrade`, `pip-audit`,
   `gh run view`, `gh api …/jobs`, `psql information_schema` diffs.
7. **Results** — 5 fail (SQLite), 7 fail (PG+Redis), 4 endpoints 500 on PG.
8. **Not checked** — real Meta/Instagram/Telegram/QPay network round-trips (no credentials); browser
   rendering/responsiveness (no browser in sandbox); 100-user load test.
9. **Residual risk** — P0-01 and P0-02 mean a PostgreSQL production deployment is **not usable** and is
   **CORS-exploitable**.
10. **Next phase** — Stage B: close P0-01, P0-02, then P1-01/02/03/04, with regression tests written
    *before* the fix.

**PHASE 0 STATUS: `PASS`** (audit completed with reproducible evidence) — the *product* is **not**
production-ready.
