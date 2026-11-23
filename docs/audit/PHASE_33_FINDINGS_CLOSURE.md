# PHASE 33 — Audit Findings Closure & Verification Hardening

Baseline: branch `arena/d78ebf88-gerege-ai-agent`, HEAD `5758fbd`, `main` `48e9c6f`,
PR #1 open/unmerged, CI `45040355154` 64/64. All verified before any change.

This phase closed two findings, corrected one stale document, and established a
canonical route inventory. It did **not** add product features.

---

## 1. F-33-1 — route inventory was measured with a broken method

Phase 32 reported 84 routes for the inventory and 81 for test coverage. Neither number
came from a working enumeration.

**Root cause.** `app.routes` does not contain the included routers' routes in this
FastAPI version. `include_router()` stores a lazy `fastapi.routing._IncludedRouter`
wrapper instead of flattening the child router's routes into the parent list:

```
Counter({'APIRoute': 79, 'Route': 4, '_IncludedRouter': 2, 'Mount': 1})
```

Any audit that walks `app.routes` therefore sees 79 `APIRoute` objects and **silently
misses all 14 routes** contributed by `routers/system_router.py` and
`routers/automation_router.py`. Both Phase 32 figures were artifacts of that gap; the
"81" happened to be a path count that coincided with the real path total.

**Canonical inventory** (from `app.openapi()`, which resolves included routers):

| Measure | Count |
|---|---|
| Unique paths | **81** |
| Method-level operations | **93** (GET 48, POST 41, DELETE 4) |
| Contributed by included routers | 14 |
| Plain Starlette routes (docs, `/static`, `/widget.js`) | 6 |
| Paths with **zero** test-file reference | **42** |

The 42 is a *reference* count, not a coverage claim: a grep hit is not evidence that a
route's behaviour is asserted. Phase 32's "41" was off by one for the same reason.

**Lesson recorded:** enumerate routes through `app.openapi()`, never `app.routes`.

---

## 2. F-33-2 — a failed Telegram send was reported as delivered

**Severity: High. Silent data-integrity failure with customer-visible consequences.**

`retention_service.dispatch_channel_message()` handled a Telegram non-200 response by
falling out of the `if channel == "telegram"` branch into the generic default fallback,
which persists the message and returns `True`. There was no `return False` on the
non-200 path.

**Reproduced (PostgreSQL-free, mocked `httpx`):** Telegram returned
`403 Forbidden: bot was blocked by the user`; `dispatch_channel_message` returned
`True`, wrote the message to `messages` as a `bot` row, and the broadcast endpoint
answered:

```json
{"success": true, "sent_count": 2, "campaign": {"sent_count": 2}}
```

for an audience of two where exactly one recipient could receive anything. The customer
received nothing; the operator was told it was delivered.

Two consumers were affected: `POST /api/retention/broadcast` (the `sent_count` shown in
the UI) and `run_automated_retention_checks` (which then writes `sent_followups`, so the
retention cadence believes the customer was contacted).

**Fix:** return `False` on the non-200 path and log the status and body. The Meta branch
already did this; only Telegram was missing it. Verified across 400/403/429/500 → `False`
with no row persisted, and 200 → `True` with exactly one row.

**Regression tests:** `tests/test_e33_phase33_findings.py` — 6 cases including the
end-to-end `sent_count` assertion. Negative control against `5758fbd`: **failed**.

---

## 3. F-33-3 — `DATABASE_URL=sqlite://…` was honoured for migrations, ignored for queries

**Severity: High (developer/CI isolation and data-integrity risk).**

`get_database_url()` returned the `DATABASE_URL`, and Alembic used it. `get_db_connection()`
called `get_sqlite_db_path()`, which read **only** `DB_PATH` and otherwise fell back to
the repository `leads.db`. A SQLite `DATABASE_URL` therefore produced two databases:

```
DATABASE_URL      = sqlite:////tmp/p33_sb_a.db
Alembic target    = /tmp/p33_sb_a.db        (created)
actual connection = /home/user/.../leads.db (all reads and writes)
```

`core/schema_manager._resolved_sqlite_path()` compounded it by returning `None` for *any*
set `DATABASE_URL`, so the migration layer declined to name a file while the repository
layer named a different one.

**Blast radius in the existing suite.** Four pre-existing tests set
`DATABASE_URL=sqlite://…` and reload `database`; all four were quietly operating on the
repository `leads.db` instead of their `tmp_path`, including
`tests/test_e07_phase26_sql_injection.py`. They passed, so the non-isolation was
invisible. This is precisely the failure mode
`docs/audit/STAGE_C_COMPLETION.md §3b` fixed once for `DB_PATH`; the same defect remained
for `DATABASE_URL`.

**Decision: Option A — support a SQLite `DATABASE_URL`.** Rejected alternatives:
rejecting it would break the four existing tests, `scripts/verify_migration_0002.py`, the
migration docs, and any deployment that sets it; a warning-only option leaves the
silent divergence in place. Option A is the only one that removes the split-brain.

**Changes:**

| File | Change |
|---|---|
| `core/db_engine.py` | New `_sqlite_path_from_url()`; `get_sqlite_db_path()` precedence is now `default_path` → `DB_PATH` → SQLite `DATABASE_URL` → repository `leads.db` |
| `core/schema_manager.py` | Only a **non-SQLite** URL suppresses SQLite resolution, matching the connection layer |
| `database.py` | `resolved_sqlite_path()` re-reads the live environment; an explicit runtime rebind of `database.DB_PATH` still wins (the Vercel bootstrap in `api/index.py` depends on that) |
| `.env.example` | Documents `DB_PATH` (previously absent entirely) and the new precedence |

PostgreSQL behaviour is unchanged: a `postgresql://` URL still selects PostgreSQL and
yields no SQLite path.

**Regression tests:** 10 cases in `tests/test_e33_phase33_findings.py`, including
`_sqlite_path_from_url` edge cases (`sqlite://`, `sqlite:///:memory:`, relative vs
absolute) and an end-to-end isolation test that asserts the connection's
`PRAGMA database_list` path. Negative control against `5758fbd`: **failed**.

**Side effect verified:** the four affected test files no longer touch `leads.db`
(mtime unchanged across a run).

---

## 4. Feature matrix reconciliation (Phase 4)

Re-verified on a **real PostgreSQL 16 database** (`p33_matrix`, `alembic upgrade head`):

| ID | Original claim | Reproduced against `5758fbd`? | Current result | Status |
|---|---|---|---|---|
| P0-01 | `get_all_registrations` returns `datetime` → HTTP 500 | Yes (per Phase 0 audit) | Row with `created_at: datetime` encodes cleanly via `core.serialization`; no 500 | **FIXED** |
| P1-01 | `create_comment_automation` → `id: None` → `TypeError` | Yes | Returns `{'id': 1, …}`; `_SERIAL_ID_TABLES` covers the table | **FIXED** |
| P1-03 | `paid_at LIKE '2026-…'` → `timestamp ~~ unknown` | Yes | `get_fintech_summary` returns correct aggregates; no `LIKE` on timestamps remains | **FIXED** |

`docs/audit/FEATURE_MATRIX.md` rows are annotated `FIXED` with the evidence and the
guarding test; the original wording is preserved for the audit trail. **No unresolved
finding was removed.**

---

## 5. Test-quality review of the new tests (Phase 6)

| Check | Result |
|---|---|
| Mocks at the correct boundary | `httpx.AsyncClient` only — the seam production code uses. Route/handler logic runs for real. |
| Real route handlers executed | Yes — tests call `retention_service.dispatch_channel_message` / `send_broadcast`, and `database.init_db()` builds the schema |
| Assertions meaningful | Return values and row counts; **no test asserts on HTTP status alone** |
| Fixtures isolated | `database.DB_PATH` rebound per test (not just `DB_PATH` env, see below) |
| Can a broken implementation pass? | Negative control: **14 of 23 failed** against `5758fbd` |
| Order-independent | Verified by running the file twice and adjacent to the polluter file |
| External side effects prevented | Zero network I/O; `leads.db` residue checked after every run |

**A flaw found in my own test during this review.** `test_e33_2_connection_and_migration_layers_agree`
initially compared `db_engine.get_sqlite_db_path()` against the Alembic resolver. That is
the wrong pair: the value the repositories *connect with* is
`database.resolved_sqlite_path()`. The test failed only when run after
`tests/test_e07_phase28_ssrf_and_tempfiles.py`, which `exec`s `api/index.py` and leaves
`database.DB_PATH` rebound to `/tmp/gerege-runtime-*/leads.db` for the rest of the
session. Fixed by comparing the correct pair and neutralising the rebind with
`monkeypatch`. A second flaw — the `tenant` fixture relied on the `DB_PATH` environment
variable, which a pre-fix `database.py` ignores — was fixed by rebinding the module
global, so a negative-control run cannot write to the developer's database.

Both flaws were caught by the negative control, not by the green run.

---

## 6. Full regression

Fresh disposable PostgreSQL database (`p33_v2`, `alembic upgrade head`), environment
configured as documented in Phase 32:

```
1313 passed, 36 skipped, 0 failed in 318.28 s
```

| | Phase 32 | Phase 33 |
|---|---|---|
| Passed | 1290 | **1313** (+23) |
| Skipped | 36 | 36 |
| Failed | 0 | **0** |

Skips are the pre-existing env/PG/Windows guards, unchanged.

Scanners:

| Check | Result |
|---|---|
| `scripts/validate_workflows.py` | OK |
| Bandit (CI scope) | 0 HIGH, 19 MEDIUM — unchanged baseline (B608 ×17 documented SQL fragments, B310, B314) |
| pip-audit | 21 advisories, all in `pip` and `setuptools` (build tooling); **no application dependency affected** |
| Secret scan of the diff | No credential-like strings |

---

## 7. Remaining untested routes (42)

Classified by whether a defect could cause harm that is not immediately visible.
A "reference" count of zero does not mean untested behaviour: several routes are
exercised indirectly through the dashboard paths that the suite does cover.

| Risk | Routes | Why |
|---|---|---|
| **High** | `/api/sessions/{sender_id}/send`, `/api/sessions/{sender_id}/takeover`, `/api/retention/trigger-checks`, `/api/executive/send-report`, `/api/pages/{page_id}/sheets/upload` | Outbound message dispatch, cross-operator state change, background job trigger, file ingestion. E-33-1 lived in exactly this category and had no test. |
| **Medium** | `/api/update-keys`, `/api/pages/{page_id}/credentials`, `/api/pages/{page_id}/gemini_key`, `/api/pages/gemini_key`, `/api/fintech/settings`, `/api/executive/settings`, `/api/fintech/invoices/{invoice_id}/simulate-pay` | Credential mutation. Authorisation was verified by hand in Phase 32 (401 unauthenticated); persistence and masking are not under test. |
| **Medium** | `/api/export/csv`, `/api/export/excel`, `/api/cargo/import-manifest`, `/api/cargo/{tracking_code}/deliver`, `/api/registrations`, `/api/pages/detail`, `/api/pages/{page_id}` | Data egress and bulk mutation; response shape unverified by tests. |
| **Low** | `/api/automations/comments/{automation_id}`, `…/toggle`, `/api/cargo/summary`, `/api/retention/campaigns`, `/api/retention/summary`, `/api/appointments/summary`, `/api/appointments/{id}/status`, `/api/pages/{page_id}/sheets*`, `/api/manychat` | Read-mostly or low-blast-radius; several verified by hand in Phase 32. |
| **Low (pages)** | `/dashboard`, `/privacy`, `/terms`, `/widget.js`, `/b/{branch_slug}`, `/{branch_slug}` | Static or public pages; asset serving verified in Phase 32. |

`/api/sessions/{sender_id}/send` is the highest-value next test: it dispatches outbound
messages on the same provider seam as F-33-2 and has no regression test.

---

## 8. Reference

- Canonical route count: 81 paths / 93 operations, from `app.openapi()`.
- New tests: `tests/test_e33_phase33_findings.py` (23).
- CI: dedicated Phase 33 step, enforced by `tests/test_e29_ci_integrity.py`.
