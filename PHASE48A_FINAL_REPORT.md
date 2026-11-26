# PHASE 48A — LOCAL STARTUP FIX & SAFE LIVE TEST

**Date:** 2026-11-25 (UTC), 15:29–16:03Z
**Repository:** `AriukagiinTuvshoo/gerege-ai-agent`
**Code under test:** merged `main` @ `debefb417f6d92685cddff257723bb469636596a`
**Work branch:** `arena/d78ebf88-gerege-ai-agent` → commit `b84969aebdfec8087e707b8027e65075fc0b4bfc`
**Outcome:** pushed (fast-forward), PR #2 opened, CI **success** on the exact SHA, merged
into `main` as `aedeca46c473dad10ad250c6187aadce1f461225` under explicit authorisation — see §12.

> Arena tracks this session on `arena/d78ebf88-gerege-ai-agent`, so a different branch
> could not be created or checked out. That branch **is** a feature branch (not `main`),
> which satisfies the requirement "make changes on a separate feature branch, never push
> directly to main". `main` and `origin/main` stayed at `debefb4` throughout.

---

## 1. Baseline — PASS

| Item | Value | Match |
|---|---|---|
| `git fetch origin` | clean | ✅ |
| Current branch | `arena/d78ebf88-gerege-ai-agent` | ✅ |
| HEAD (before this phase) | `5402ab9174264b2b42620468ba197bb83732946d` | ✅ |
| `main` | `debefb417f6d92685cddff257723bb469636596a` | ✅ expected |
| `origin/main` | `debefb417f6d92685cddff257723bb469636596a` | ✅ synced |
| Content identity | `git diff debefb4 HEAD` → **empty** (the feature tip is `debefb4`'s second parent) | ✅ |
| PR #1 | MERGED (2026-11-25T14:22:05Z); no open PRs | ✅ |
| Working tree | only untracked `PHASE4*_REPORT.md`; zero tracked modifications | ✅ |

No mismatch → no STOP. Nothing was overwritten; the untracked reports were left in place.

---

## 2. Startup configuration audit — PASS

### 2.1 Does `load_dotenv()` have to run before the imports in `main.py`?

**No — and this was proved, not assumed.** `main.py:41` calls `load_dotenv(override=True)`
*after* `import database` (line 24), which looks wrong, but the import graph already
covers it:

```
core/db_engine.py:9    load_dotenv(override=True)   ← runs at IMPORT time
database.py:11         from core.db_engine import … ← so dotenv is loaded BEFORE
database.py:26         DEFAULT_ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", …)
core/task_queue.py:12  import database              ← and before its own singleton (line 550)
core/backup_service.py:13 import database
```

**Empirical proof** — fresh venv, fresh process, `env -i` (process env verified free of
every app variable), nothing exported, `.env` as the only source:

| # | Check | Result |
|---|---|---|
| 1 | `database.DEFAULT_ADMIN_PASSWORD` came from `.env` | **True** |
| 2 | `database.DB_PATH` came from `.env` | **True** (`/tmp/p48a/p48a_smoke.db`) |
| 3 | `is_production_mode()` honours `.env` `ENV=development` | **True** |
| 4 | `is_webhook_fail_closed()` honours `.env` `WEBHOOK_FAIL_CLOSED=0` | **True** |
| 5 | `META_VERIFY_TOKEN` usable in dev | **True** |
| 6 | published placeholder verify token rejected under `ENV=production` | **True** (Phase 45 F-44-B live) |
| 7 | `authenticate_admin(<.env password>)` | **True** |
| 8 | `authenticate_admin("ADMIN2026")` (published default) | **False** — rejected even in dev once `.env` sets `ADMIN_PASSWORD` |
| 9 | `REDIS_URL` empty → queue backend | `db` (documented fallback) |
| 10 | `core.secret_guard.validate_production_secrets()` in dev | warns, does **not** raise (1 issue: `META_APP_SECRET`) |
| 11 | `core.rate_limit` startup validators in dev | no raise; `is_shared()=False` (memory fallback) |
| 12 | `core.backup_service.BACKUP_DIR` from `.env` | **True** |

### 2.2 `DB_PATH` / `DATABASE_URL` precedence — PASS

Documented order `DB_PATH` > `sqlite:///` URL > `./leads.db`, verified case by case in
isolated processes:

| Case | Input | Resolved |
|---|---|---|
| A | `DB_PATH=/tmp/p48a/a.db` + `DATABASE_URL=sqlite:///rel_b.db` | `/tmp/p48a/a.db` (DB_PATH wins) |
| B | only `DATABASE_URL=sqlite:///rel_b.db` | `rel_b.db` |
| C | only `DATABASE_URL=sqlite:////tmp/p48a/c.db` | `/tmp/p48a/c.db` |
| D | neither set | `<repo>/leads.db` |
| E | `DATABASE_URL=postgresql+psycopg2://…` | `<repo>/leads.db` (unused: the engine is PostgreSQL) |

### 2.3 `DEFAULT_ADMIN_PASSWORD` — PASS (with one hazard recorded)

`database.py:26` binds it at import time, but `authenticate_admin()` re-reads
`os.getenv("ADMIN_PASSWORD")` **at call time** and compares only against that when it is
set. Verified live over HTTP: the `.env` password → **200**, `ADMIN2026` → **401**,
wrong password → **401**. In production/strict mode with `ADMIN_PASSWORD` unset,
`authenticate_admin()` returns `False` (fail-closed) — asserted by
`tests/test_enterprise_phases.py`.

### 2.4 Redis fallback and startup checks — PASS

| Condition | Observed |
|---|---|
| `REDIS_URL` empty (dev) | `rate_limit_store=memory`, `rate_limit_store_required=false`, `queue_backend=db`; app starts and serves |
| Job round-trip with **no Redis** | enqueue → `PENDING` → claim → `PROCESSING` → handler → `ack=True` → `completed=1` on the **db** backend |
| `REDIS_URL` set (local Redis) | `TaskQueue connected to Redis backend`, `rate_limit_store=redis`, `shared=True`, `queue=redis+db`, worker heartbeat `alive` |
| Production | `validate_store_for_startup()` requires a reachable Redis and raises `RateLimitStoreUnavailable` (R11) — not exercised here (dev) |

### 2.5 Secret guard development behaviour — PASS

Development: logs `secrets are not production-ready (META_APP_SECRET: missing …).
Development continues; production would refuse to start.` and returns the issue list.
Production/`STRICT_SECURITY=1`: raises `InsecureSecretError` naming **names and reasons
only**. Observed live in every startup of this phase; no secret value was ever logged.

### 2.6 One fragility found (not a live defect) — OBSERVATION F-48A-5

`core/worker_heartbeat.py` reads `WORKER_HEARTBEAT_*` at import time and imports neither
`database` nor `core.db_engine`, so **imported alone** it does not see `.env`:

| Import order | `BEAT_INTERVAL_SECONDS` (`.env` says 7.5) |
|---|---|
| `from core import worker_heartbeat` alone | **10.0** (code default — `.env` missed) |
| `import database` first (what `main.py`/`worker.py` do) | **7.5** (`.env` honoured) |

Every real entrypoint (`main.py`, `worker.py`, `scripts/*`) imports `database` first, so
no application path is affected. **No code was changed for this**: adding a second
`load_dotenv(override=True)` would risk the audited suites that `monkeypatch.setenv` and
then reload modules. Recorded so the implicit dependency is known.

### 2.7 `.env` overrides exported environment variables — OBSERVATION F-48A-2

`load_dotenv(override=True)` **mutates `os.environ`**. Proven: with a repo-root `.env`
present, a process started with `ENV=production DB_PATH=/tmp/should-be-ignored.db` ended
up with `is_production_mode() == False` and `DB_PATH` replaced by the `.env` value.

Consequences, both acted on in this phase:
1. The test suite **must** run without a local `.env` in the repo root, or the recipe's
   `DATABASE_URL`/`REDIS_URL` are silently replaced. `.env` was therefore moved to
   `/tmp/p48a/env.live` for the suite run and restored afterwards.
2. An operator who exports `ENV=production` in the shell while a stale development `.env`
   sits in the working directory runs in **development** mode. This is inherent to
   `override=True`; the README now tells the operator to create `.env` deliberately and
   the production path uses compose/Docker env instead.

---

## 3. README and launcher fixes — DONE

### 3.1 `README.md` (51 → 273 lines)

Removed / replaced:

- ❌ The instruction to paste the repository's **published webhook verify token** into
  Meta's *Verify Token* field. That string is public in this repo; `core/security.py`
  classifies it as a placeholder and `meta_verify_token_is_usable()` **refuses it under
  `ENV=production` / `STRICT_SECURITY=1`** (Phase 45 F-44-B, asserted by
  `tests/test_e45_final_hardening.py:250`). The README now says to generate a random
  token and put it in `META_VERIFY_TOKEN`, and states that published/example values are
  rejected in production. The literal value no longer appears anywhere in the file.
- ❌ "Сервер одоо шууд ажиллаж байна" + SQLite-only description.

Added: requirements table (Python 3.12 for the lock, 3.11+ locally; PostgreSQL + Redis
required only in production), venv creation for Windows and macOS/Linux,
`requirements.txt` vs `requirements-dev.txt` vs hash-locked `requirements.lock`, creating
`.env` **without overwriting** an existing one (`if not exist .env copy …` / `cp -n`),
secret generation commands, the "never use published example values" warning, `DB_PATH`
precedence, PostgreSQL + `scripts/provision_roles.py --apply/--check`, migration
verification (`alembic current` / `alembic heads`), the Redis requirement and R11
fail-closed startup, `python main.py` (loopback, B104) vs the container's
`uvicorn main:app`, compose files, the separate `python worker.py` process and
`DISABLE_INLINE_SCHEDULER`, the four health endpoints, graceful shutdown, Gemini,
Meta/Instagram (with `META_APP_SECRET` signature verification and 403 fail-closed),
Telegram (`TELEGRAM_WEBHOOK_SECRET` → `X-Telegram-Bot-Api-Secret-Token`), a document
index (17 verified paths), and a production pre-flight checklist.

Verified: no `agent_verify_secret_token_123`, no `ADMIN2026`, no `Password123!`
(the only README assertion any test makes — `tests/test_e07_phase25_aidolab_critical.py`);
all **30** repository paths named in the file exist; `README.md` is not in
`test_e11_documentation_verification.py`'s controlled document set.

### 3.2 `start_agency.bat` — credential echo removed

It printed `echo   - Админ нууц үг: ADMIN2026` on every launch — a published default
credential displayed on screen, while `docs/security/SECURITY_IMPLEMENTATION.md` records
that the hardcoded `ADMIN2026` auto-login was removed from `dashboard.html` for exactly
this reason. Replaced with a pointer to `ADMIN_PASSWORD` in `.env` plus the generation
command. No test references any `.bat` file, so nothing was affected.

### 3.3 Correction to the Phase 48 report

`PHASE48_FINAL_REPORT.md` §9-O1 claimed `start.bat` "does not exist in the repo".
**That was wrong and has been withdrawn in that file**: `start.bat`, `start_agency.bat`
and `tunnel.bat` all exist and are tracked; `start.bat` runs `python main.py`, so the old
README's launch advice was valid. The error came from reading a truncated 40-entry `ls`.

---

## 4. Local environment — PASS

| Step | Result |
|---|---|
| Virtual environment | `python3 -m venv /home/user/p48a-venv` → **Python 3.11.2** |
| `pip install -r requirements.txt` | **rc=0**, 54 packages (fastapi 0.165.0, uvicorn 0.54.0, starlette 1.10.0, sqlalchemy 2.1.9, alembic 1.20.1, redis 5.3.1, psycopg2-binary 2.9.13, google-genai 1.75.0, cryptography 50.0.2, pillow 13.0.0, openpyxl 3.1.5, pytest 9.2.0, PyYAML 6.0.4) |
| `requirements.lock` note | the lock is hash-pinned to **CPython 3.12** manylinux wheels, so a 3.11 venv installs from `requirements.txt`; on Windows use 3.12 to match the lock/Docker image |
| `.env` | created with `cp -n .env.example .env` (no `.env` existed → **nothing overwritten**), mode `0600`, git-ignored (`.gitignore:2`), never staged or committed |
| Database | **disposable SQLite** `/tmp/p48a/p48a_smoke.db` via `DB_PATH` — outside the repo |
| CSV mirror | `/tmp/p48a/leads.csv` via the new `CSV_PATH` |
| Backups | `BACKUP_DIR=/tmp/p48a/backups` so the repo's `backups/` was not written |
| Admin password | locally generated `secrets.token_urlsafe(24)`, kept in `/tmp/p48a/sentinels.txt` (mode `0600`, outside the repo); value printed nowhere in this report |
| Production/staging credentials | **none used** — no PostgreSQL staging host, no AWS/S3, no vendor tokens |
| Gemini key | absent → AI integration **BLOCKED** (see §5.5) |
| Existing data deleted | **none** (see §6) |

---

## 5. Start and test — results

Started exactly as documented: `python main.py` from the fresh venv, `.env` as the only
configuration source, nothing exported.

Startup log: `Applying schema migrations <empty> -> 0008_tenant_not_null` (8 migrations,
`SQLiteImpl`) → `Uvicorn running on http://127.0.0.1:8000` → `Application startup
complete`. Loopback binding and the `StatReload` watcher are the documented dev defaults
(B104).

| # | Area | Verdict | Evidence |
|---|---|---|---|
| 5.1 | Application opens | **PASS** | `/` 200, `/admin` 200, `/api/live` 200 (`{"status":"alive"}`) |
| 5.2 | Health endpoints | **PASS** | `/api/ready` 200 `ready=true database=ok engine=sqlite rate_limit_store=memory(required=false) queue_backend=db`; `/api/health` 200 `status=healthy gemini_ready=false telegram_configured=false meta_token_configured=false` |
| 5.3 | Login / session | **PASS** | `.env` password → 200 `success=true role=admin`; `ADMIN2026` → **401**; wrong → **401**; `/api/leads` unauthenticated → **401**; forged cookie → **401**; authenticated → 200 |
| 5.4 | Dashboard | **PASS** | `/` and `/admin` serve the dashboard HTML (200) |
| 5.5 | **AI / chat integration** | **BLOCKED** | `GEMINI_API_KEY` unset. `POST /api/chat` → 200 with an explicit **`"model":"fallback"`** reply (honest degradation, no crash, no fabricated AI answer); empty message → `"Та мессежээ бичнэ үү."`; `/api/health` reports `gemini_ready:false` |
| 5.6 | Test customer CRUD | **PASS** | CREATE `save_registration` → id 1, `page_id` NOT NULL enforced; READ `GET /api/leads?search=P48A` → 200 `total=1`; UPDATE `POST /api/leads/1/status` → 200 `{"status":"updated","lead_id":1}` and persisted (`боловсруулсан` / `Phase 48A smoke`); EXPORT csv 200 (contains the test row) + xlsx 200 (5588 bytes, `PK`); DELETE `delete_customer_data` → `{'registrations':1,…}`, row gone |
| 5.7 | Error handling | **PASS** | unknown route 404, malformed JSON 422, empty credentials 401, nonexistent lead 404, `/api/live` 200 afterwards |
| 5.8 | **Restart recovery** | **PASS** | stopped and restarted `python main.py`: `Schema ready: already at head (0008 -> 0008)` (**migrations not re-run**), startup complete, all endpoints 200, marker row `P48A Restart Marker` still present, fresh login 200 |
| 5.9 | Hot reload | **PASS** | editing `database.py` produced `StatReload detected changes in 'database.py'. Reloading...` → clean re-startup at head |
| 5.10 | Worker (`python worker.py`) | **PASS** | started twice and stopped twice, each time `Received SIGTERM` → `worker heartbeat cleared` → `stopped cleanly`; with Redis: heartbeat `status=alive age=0.8–3.8s`, `alive=1 stale=0`, `scheduler.healthy=true`, `scheduler_errors=0` |
| 5.11 | Worker health **without** Redis | **PASS (honest 503)** | `/api/admin/worker/health` → **503** with `worker.status="unknown"`, `reason="redis unavailable; worker liveness cannot be determined"` — it refuses to claim liveness it cannot observe, while `queue.backend=db` still processed a job end-to-end. With `REDIS_URL` set the same endpoint returns **200 alive** |
| 5.12 | Logs | **PASS** | no `ERROR`, no traceback in either process. Only expected WARNINGs: `GEMINI_API_KEY тохируулаагүй`, secret-guard dev warning, `No trusted proxies configured`, and the B104 warning when `HOST=0.0.0.0` was used for the preview |
| 5.13 | Windows launchers | **NOT VERIFIED** | this sandbox is Linux; `start.bat` / `start_agency.bat` / `tunnel.bat` cannot be executed here. `start.bat` is only `python main.py`, which **was** verified; `start_agency.bat` was edited by inspection (its credential echo removed) |

**Application URL:** `http://127.0.0.1:8000` (verified). The final running instance uses
`HOST=0.0.0.0` so the Arena live preview on port 8000 works; `main.py` prints its own
warning that this exposes the reload-enabled dev server, which is why the documented
default stays loopback.

---

## 6. Errors found

### F-48A-1 — `CSV_PATH` ignored `DB_PATH` and overwrote the repository's `leads.csv` (FIXED)

`database.py:24` pinned the CSV mirror next to the module while the database was
redirectable through `DB_PATH`. `save_registration()` and `update_lead_status()` call
`sync_to_csv()` on **every** write, so a run pointed at a disposable database rewrote
`<repo>/leads.csv` with the throwaway rows.

Measured in this phase: after the CRUD smoke test, `leads.db` and `gerege_crm_next.db`
kept their hashes while `leads.csv` had been rewritten (`51ca0568…` → `6ecb484f…`) with
the disposable database's single row.

**Fix:** `CSV_PATH` is now taken from the environment, defaulting to the exact old path:
```python
CSV_PATH = os.getenv("CSV_PATH", "").strip() or os.path.join(os.path.dirname(__file__), "leads.csv")
```
Backward compatible — `docker-compose.yml`'s `./leads.csv` bind mount and every existing
install behave identically unless they opt in. Documented in `.env.example` next to
`DB_PATH`. Zero tests referenced `CSV_PATH` or `leads.csv` before the change.

**Verified live:** with `CSV_PATH=/tmp/p48a/leads.csv` in `.env`, an API `UPDATE` wrote
the disposable mirror (387 bytes) while the repository's `leads.csv` hash stayed
`6ecb484f…`. With `CSV_PATH` unset the default resolves to `<repo>/leads.csv` (proved in
an isolated process).

### Observations (deliberately not changed)

- **F-48A-2** `.env` overrides exported variables (`override=True`) — see §2.7. Inherent
  to the current design; mitigated by documentation and by moving `.env` aside for suite
  runs.
- **F-48A-3** `/api/admin/worker/health` returns a **static** scheduler note claiming
  "the API runs with `DISABLE_INLINE_SCHEDULER=1"`. In this run the API's inline
  scheduler **was** running (`DISABLE_INLINE_SCHEDULER=0`, log: `Executive Daily Briefing
  & Retention scheduler loop started`), so the note stated the opposite of the actual
  configuration. Not changed: `tests/test_e36_worker_health.py` asserts that string, and
  `scheduler.healthy=false` is the conservative direction (it never claims health it
  cannot observe).
- **F-48A-4** `.env` edits are only partly picked up at runtime. `main.py` re-runs
  `load_dotenv(override=True)` inside `/api/health`, which refreshes `os.environ`, but
  already-constructed singletons (rate limiter, queue client, heartbeat client) do not
  re-evaluate: after adding `REDIS_URL`, the running backend still reported
  `memory`/`db` until it was restarted. **A restart is required after changing
  connection-level configuration** — now stated in the README.
- **F-48A-5** `core/worker_heartbeat.py` misses `.env` when imported standalone (§2.6).
- **F-48A-6** Running `tests/test_e45_final_hardening.py::TestMetaVerifyToken` **in
  isolation** fails 2 tests with `core.db_privileges.PrivilegedRuntimeError: refusing to
  start: the database role 'gerege' is more privileged than the application requires`
  (the local `pgserver` role is a superuser that owns 32 relations and the database).
  Those tests boot the app in production mode, where the least-privilege guard is
  enforced; in the full-suite order an earlier test satisfies it. **Attribution proved:**
  with all Phase 48A edits `git stash`ed, the same two tests fail identically on pristine
  `debefb4` content. Pre-existing, environment/ordering dependent, and absent from the
  authoritative full run (§8).
- **O2 (carried from Phase 48)** `pages.verify_token` still defaults to the published
  placeholder in `core/models.py:62`, migration `0001`, `database.save_page()` and the
  request-body default in `main.py`. Not changed: it is schema/migration-defined,
  `tests/test_stage_c_schema.py` asserts the DDL, and `meta_verify_token_is_usable()`
  already rejects it in production. `dashboard.html:1921` also displays it read-only.
- **Benign warning** during the first SQLite migration: `SAWarning: Table
  '_alembic_tmp_session_states' specifies columns 'sender_id' as primary_key=True, not
  matching locally specified columns 'page_id','sender_id'` (migration 0004's SQLite
  table-rebuild path). The migration completed and finished at head `0008`; the same
  warning class appears in the audited suite runs.

---

## 7. Files changed

| File | Change |
|---|---|
| `README.md` | rewritten setup/run/webhook/security documentation; published verify-token instruction removed (+266/−24 lines overall across the commit) |
| `database.py` | `CSV_PATH` honours the environment; default byte-identical to before (F-48A-1) |
| `.env.example` | documented `CSV_PATH` next to `DB_PATH` |
| `start_agency.bat` | removed the plaintext admin-password echo |
| `PHASE48_FINAL_REPORT.md` | O1 correction (untracked report, not committed) |
| `PHASE48A_FINAL_REPORT.md` | this report (untracked, not committed) |

Commit `b84969a` on `arena/d78ebf88-gerege-ai-agent`: 4 files, `+270 / −24`.
Pushed only after explicit authorisation, and never to `main` directly — see §12.

---

## 8. Test results — floor intact

Authoritative full run, `.env` moved aside, dev venv, live PostgreSQL 16 + Redis:

```
DATABASE_URL=postgresql+psycopg2://gerege:****@127.0.0.1:5432/gerege_e05_test
REDIS_URL=redis://127.0.0.1:6379/0
python -m pytest -q --ignore=scratch
→ 1916 passed, 59 skipped, 1 xfailed, 372 warnings in 692.87s (0:11:32)
  window 2026-11-25T15:49:13Z → 16:00:48Z
```

| Metric | Phase 45 baseline | Phase 48A | |
|---|---|---|---|
| passed | 1916 | **1916** | ✅ |
| skipped | 59 | **59** | ✅ |
| xfailed | 1 | **1** | ✅ |
| failed | 0 | **0** | ✅ |

No test was deleted, skipped, weakened or converted; no floor was lowered; no security
check was silenced. Targeted pre-run of the 7 most-affected files gave `2 failed, 319
passed` — the two failures are F-48A-6, reproduced identically on pristine code, and they
do not occur in the full-suite order.

---

## 9. Restrictions compliance

| Rule | Status |
|---|---|
| No production deploy | ✅ none |
| No staging infrastructure change | ✅ none (no DNS/TLS/S3/alert touched) |
| No direct push to `main` | ✅ `main` = `origin/main` = `debefb4` |
| No force push / history rewrite | ✅ none; `5402ab9` remains `b84969a`'s parent |
| No existing database deleted | ✅ nothing dropped; 180+ local PostgreSQL DBs untouched |
| Changes on a feature branch | ✅ `arena/d78ebf88-gerege-ai-agent` (see the branch note at the top) |
| Test floor not lowered | ✅ 1916/59/1 identical to baseline |
| Production/staging credentials unused | ✅ only locally generated secrets |
| No secret printed or committed | ✅ commit diff contains **0** occurrences of the live `ADMIN_PASSWORD`, `E02_ACCOUNT_KEY_SECRET` and `META_VERIFY_TOKEN`; `.env` untracked and absent from the commit; no published placeholder re-added |

### Existing repository data

| File | Outcome |
|---|---|
| `gerege_crm_next.db` | **unchanged** (hash identical, mtime Nov 24) |
| `knowledge.json` | **unchanged** (hash identical, mtime Nov 17) |
| `backups/` | **not written** (`BACKUP_DIR` redirected to `/tmp/p48a/backups`) |
| `leads.db`, `leads.csv` | rewritten at **16:00:38Z by the pytest run**, not by the application. Both are git-ignored and `.gitignore` already labels them "Test-suite artefacts. The suites that rebind DB_PATH leave a database file behind". Evidence: mtime falls inside the suite window (15:49:13→16:00:48); `leads.db` now holds 303 fixture rows (`p0_tenant_b`, `p1_tenant_a`, `rbac_tenant`, …) while this phase's smoke data (1 row, `P48A Restart Marker`) lives only in `/tmp/p48a/p48a_smoke.db`. Before the F-48A-1 fix the application *had* rewritten `leads.csv` once — that is the defect the fix closes. |

---

## 10. Local startup / shutdown instructions (as executed and verified)

### Startup

```bash
# 1. virtual environment (Python 3.12 to match requirements.lock; 3.11 works for requirements.txt)
python3 -m venv .venv                 # Windows: python -m venv .venv
source .venv/bin/activate             # Windows: .venv\Scripts\activate
pip install -r requirements.txt       # + requirements-dev.txt only for tests/CI

# 2. configuration — never overwrite an existing .env
cp -n .env.example .env               # Windows: if not exist .env copy .env.example .env
chmod 600 .env

# 3. generate the secrets (values stay out of git, logs and reports)
python -c "import secrets; print(secrets.token_urlsafe(24))"   # ADMIN_PASSWORD
python -c "import secrets; print(secrets.token_urlsafe(48))"   # E02_ACCOUNT_KEY_SECRET (>=32)
python -c "import secrets; print(secrets.token_urlsafe(32))"   # META_VERIFY_TOKEN etc.

# 4. point the database and its CSV mirror at disposable locations
#    (in .env)  DB_PATH=/tmp/gerege-local/app.db
#               CSV_PATH=/tmp/gerege-local/leads.csv      <- new in this phase
#               BACKUP_DIR=/tmp/gerege-local/backups
#               REDIS_URL=                                <- blank is fine in development
#               ENV=development

# 5. backend — migrations 0001..0008 apply themselves on first start
python main.py                        # → http://127.0.0.1:8000  (Windows: start.bat)

# 6. worker + scheduler (separate process)
python worker.py

# 7. verify
curl -s http://127.0.0.1:8000/api/live    # {"status":"alive"}
curl -s http://127.0.0.1:8000/api/ready   # ready / database / engine / queue
curl -s http://127.0.0.1:8000/api/health  # gemini_ready, rate_limit_backend, totals
```

### Shutdown

```bash
# SIGTERM / Ctrl+C is enough; both processes stop gracefully:
#   worker : "Received SIGTERM" -> "worker heartbeat cleared" -> "stopped cleanly"
#   backend: "Waiting for application shutdown" -> "Application shutdown complete"
kill -TERM <worker_pid> <backend_pid>
```

Restarting re-attaches at head without re-running migrations, and the worker resumes
whatever is still queued. **After changing connection-level settings in `.env`
(`DATABASE_URL`, `REDIS_URL`, `DB_PATH`), restart** — see F-48A-4.

### Running the test suite

```bash
mv .env /tmp/env.hold          # load_dotenv(override=True) would replace the recipe (F-48A-2)
export DATABASE_URL=postgresql+psycopg2://USER:PASS@127.0.0.1:5432/gerege_e05_test
export REDIS_URL=redis://127.0.0.1:6379/0
python -m pytest -q --ignore=scratch      # expect 1916 passed, 59 skipped, 1 xfailed
mv /tmp/env.hold .env
```

---

## 11. Verdicts

| Item | Verdict |
|---|---|
| **Local startup** | **PASS** — `python main.py` boots on a fresh venv from `.env` alone, migrates to head `0008`, serves on `127.0.0.1:8000`, reloads and restarts cleanly |
| **Config loading** | **PASS** — `.env` reaches every module in all real entrypoints (12/12 checks), precedence proven, `load_dotenv` before imports **not** required; two hazards recorded (F-48A-2, F-48A-5) |
| **Database** | **PASS** — disposable SQLite, 8 migrations applied then idempotent at head, data survives restart, no existing database touched or deleted |
| **Login / dashboard** | **PASS** — `.env` password accepted, published default and wrong passwords rejected (401), fail-closed on missing/forged sessions, dashboard renders |
| **CRUD** | **PASS** — create/read/update/delete + CSV & Excel export verified end-to-end |
| **AI integration** | **BLOCKED** — no `GEMINI_API_KEY`; the endpoint degrades honestly (`"model":"fallback"`, `gemini_ready:false`) instead of failing or faking |
| **Worker / scheduler** | **PASS** — graceful start/stop ×2, heartbeat alive with Redis, honest `unknown` + 503 without it, queue round-trip on both `redis+db` and `db` backends |
| **Stability / logs** | **PASS** — no ERROR or traceback; restart recovery and hot reload verified |
| **Test floor** | **PASS** — 1916 / 59 / 1 / 0 failed, identical to the Phase 45 baseline |
| **Windows launchers** | **NOT VERIFIED** — cannot execute `.bat` on this Linux sandbox |
| **Telegram / Meta / QPay** | **BLOCKED** — no vendor credentials (fail-closed behaviour verified in Phase 48) |
| **Staging readiness** | **BLOCKED** — unchanged from Phase 46 |
| **Production readiness** | **NOT READY** — unchanged from Phase 46/47 |

**Conclusion:** local startup is fixed and safe, and the merged code was exercised for
real on a disposable database. One defect was found and fixed (F-48A-1), the README and a
launcher no longer teach or print published credentials, and the test floor is unchanged.
This is **not** a production release: staging remains BLOCKED and production remains NOT
READY. Commit `b84969a` was pushed and merged into `main` as `aedeca4` under explicit
authorisation, with CI green on both the PR head and the merge commit (§12).

---

## 12. Push, PR #2 and merge (executed under explicit authorisation)

### 12.1 Push

Pre-push checks, all green: correct branch; `HEAD == b84969a`; remote branch tip
`5402ab9` **is an ancestor of HEAD** (so a plain fast-forward, never a force push);
`main`/`origin/main` still `debefb4`; working tree clean apart from the untracked phase
reports; `.env` untracked and git-ignored; the outgoing diff re-scanned for the live
`ADMIN_PASSWORD`, `E02_ACCOUNT_KEY_SECRET` and `META_VERIFY_TOKEN` → **0 occurrences**,
and **0** published placeholders re-added.

```
git push origin arena/d78ebf88-gerege-ai-agent
→ 5402ab9..b84969a  (fast-forward)
```

Verified afterwards: `origin/arena/d78ebf88-gerege-ai-agent == b84969a == local HEAD`;
`main` and `origin/main` unchanged at `debefb4`.

**CI did not run on that push.** `.github/workflows/ci.yml` triggers only on
`push: branches: ["main"]` and `pull_request: branches: ["main"]`, so a feature-branch
push with no open PR produces no run (`gh run list` for `b84969a` → 0 at that point).
This was reported rather than glossed over, and is why the PR was opened.

### 12.2 PR #2

`gh pr create --base main --head arena/d78ebf88-gerege-ai-agent` →
**https://github.com/AriukagiinTuvshoo/gerege-ai-agent/pull/2**

| Field | Value |
|---|---|
| State at creation | OPEN, `headOid = b84969a…` (exact audited SHA), base `main` |
| Mergeability | `MERGEABLE`; `mergeStateStatus` `UNSTABLE` → `CLEAN` once checks finished |
| Merge base with main | `5402ab9` — main carried no unrelated work, so no rebase and no rewrite |
| Content difference vs main | exactly the 4 Phase 48A files (`+270 / −24`) |

### 12.3 CI on the PR head

| Field | Value |
|---|---|
| Run | **`45728154558`** |
| Event / SHA | `pull_request` / **`b84969aebdfec8087e707b8027e65075fc0b4bfc`** (identical to the PR head) |
| Result | **success**, job `test-and-security-audit` success, **72 steps, 0 non-success**, 16m13s |
| `gh pr checks 2` | `test-and-security-audit  pass` |

**Limitation, recorded honestly:** the raw CI log text could not be retrieved from this
sandbox — `gh run view --log` downloads from
`results-receiver.actions.githubusercontent.com`, which is outside the sandbox's outbound
host allowlist (`github.com`, `api.github.com`, …). Verification therefore used the API's
run/job/step conclusions, which are authoritative for pass/fail, instead of grepping
pytest summary lines out of the log.

### 12.4 Merge

Pre-merge checks, all green: PR OPEN; `headOid == b84969a`; base `main`; CI conclusion
`success` **on that same SHA**; `origin/main` still `debefb4` (nothing landed in between);
`mergeable = MERGEABLE`, `mergeStateStatus = CLEAN`; still on the feature branch; clean
tree. The workflow was re-inspected for a deployment trigger: it defines a single job
(`test-and-security-audit`) and **no** deploy/release/publish job, so merging could only
run tests — no production deployment path exists to trigger.

```
gh pr merge 2 --merge
```

| Field | Value |
|---|---|
| PR #2 | **MERGED** at `2026-11-26T00:39:35Z` |
| Merge commit | **`aedeca46c473dad10ad250c6187aadce1f461225`** |
| Parents | `debefb417f6d92685cddff257723bb469636596a` (previous main) + `b84969aebdfec8087e707b8027e65075fc0b4bfc` (audited head) |
| `main` before → after | `debefb4` → **`aedeca4`** |
| Merge method | merge commit (`--merge`), consistent with PR #1, preserving the Phase 48A commit as its own history entry |

Ancestry after the merge — append-only, no rewrite, no force push:

* `b84969a` is in `main`'s history ✅
* `debefb4` (previous main) is still an ancestor ✅
* `48e9c6f` (the original base) is still an ancestor ✅
* `origin/main`'s **tree is identical to `b84969a`'s tree** → main's content is exactly
  the audited, CI-verified content ✅

### 12.5 Remote main and local sync

GitHub's merge updated `origin/main` directly, so **no separate push to main was made or
needed** (`git fetch` showed `debefb4..aedeca4  main -> origin/main`). Local `main` was
fast-forwarded with `git fetch origin main:main` — the working branch was **never
switched**; the session stayed on `arena/d78ebf88-gerege-ai-agent` at `b84969a`
throughout, and that branch still exists on the remote.

### 12.6 Post-merge CI on the merge commit

| Field | Value |
|---|---|
| Run | **`45730301251`** |
| Event / SHA | `push` / **`aedeca46c473dad10ad250c6187aadce1f461225`** (the exact merge commit) |
| Result | **success**, job `test-and-security-audit` success, **72 steps, 0 non-success** |

So the merged state of `main` is CI-verified on its own SHA, not only on the PR head.

### 12.7 After the merge

The still-running local instance serves the merged content (main's tree == `b84969a`'s
tree): `/api/live`, `/api/ready`, `/api/health` and `/` all **200**, `engine=sqlite`,
`queue=redis+db`. The repository's `leads.csv` still carries the pytest run's mtime
(`16:00:38Z`) — the live application has not touched it since, which is the F-48A-1 fix
holding in the merged code.

No production deploy was performed, no staging or vendor infrastructure was touched, no
persistent data was deleted, and no test was weakened at any point in this sequence.
**Staging readiness remains BLOCKED and production readiness remains NOT READY.**

| Item | Value |
|---|---|
| PR #2 merged | **YES** (`aedeca4`, 2026-11-26T00:39:35Z) |
| `main` before → after | `debefb4` → `aedeca4` |
| Merge method | merge commit (`gh pr merge 2 --merge`) |
| PR-head CI | `45728154558` — success on `b84969a` |
| Main CI | `45730301251` — success on `aedeca4` |
| `origin/main` updated | **YES** (fast-forward fetch; no force push, no rewrite) |
| Production deploy | **NONE** (the workflow has no deploy job) |
| Staging readiness | **BLOCKED** (unchanged) |
| Production readiness | **NOT READY** (unchanged) |
