# PHASE 48 — LOCAL CONNECTION & LIVE SMOKE TEST

**Date:** 2026-11-25 (UTC), 15:08–15:17Z
**Code under test:** merged `main` @ `debefb417f6d92685cddff257723bb469636596a`
(the working tree of `arena/d78ebf88-gerege-ai-agent` @ `5402ab9` is content-identical
to `debefb4`'s second parent — the merge added no code of its own).

No Git action was taken: no commit, no push, no merge, no branch change, no
production deploy, no destructive migration.

---

## 1. Baseline — PASS

| Item | Value |
|---|---|
| Current branch | `arena/d78ebf88-gerege-ai-agent` |
| HEAD | `5402ab9174264b2b42620468ba197bb83732946d` |
| `main` (local) | `debefb417f6d92685cddff257723bb469636596a` |
| `origin/main` | `debefb417f6d92685cddff257723bb469636596a` (synced) |
| `debefb4` in main history | YES |
| PR #1 | MERGED |
| Working tree | only untracked `PHASE43/44/45/46/47` reports; zero tracked changes |

---

## 2. Environment inspection (read-only) — PASS

| Aspect | Finding |
|---|---|
| Setup instructions | `README.md` (51 lines) — **stale**, see §9-O1 |
| Env template | `.env.example` (documented, Mongolian comments), `.env.staging.example` |
| Compose files | `docker-compose.yml` (single service `agency-hub`, port 8000, SQLite `leads.db`), `docker-compose.staging.yml`, `docker-compose.prod.yml` |
| Database config | `DATABASE_URL` (PostgreSQL or SQLite), `DB_PATH`, `DATABASE_OWNER_URL`, `POSTGRES_*_PASSWORD`; precedence `DB_PATH` > `sqlite:///` URL > `./leads.db` |
| Backend startup | `python main.py` (dev, binds 127.0.0.1, reload on) or `uvicorn main:app` (container path per `Dockerfile`) |
| Frontend | **No separate frontend build.** `dashboard.html` is served by FastAPI at `/`, `/dashboard`, `/admin`, `/{branch_slug}` |
| Worker | `python worker.py` — standalone process, own scheduler + heartbeat |
| Scheduler | Inline loop in backend (`executive_scheduler_loop`) unless `DISABLE_INLINE_SCHEDULER=1`; also runs inside `worker.py` |
| Health endpoints | `/api/live` (liveness), `/api/ready` (readiness: DB + queue), `/api/health` (dashboard summary), `/api/admin/worker/health` (worker + scheduler) |
| Docker | **NOT AVAILABLE** in this sandbox → compose path could not be used; ran the app natively with local PostgreSQL + Redis instead |
| Required env vars | `ENV`, `STRICT_SECURITY`, `DATABASE_URL`, `REDIS_URL`, `ADMIN_PASSWORD`, `E02_ACCOUNT_KEY_SECRET`, `ALLOWED_ORIGINS`, `WEBHOOK_FAIL_CLOSED`, `PORT`/`HOST` |

No secret value was printed at any point — only variable names and set/unset status.

---

## 3. Local setup — PASS

| Step | Result |
|---|---|
| Production environment used | **NO** (`ENV=development`, `STRICT_SECURITY=0`) |
| Production credentials used | **NO** (locally generated random `ADMIN_PASSWORD` and `E02_ACCOUNT_KEY_SECRET`, stored in `/tmp/p48_env.sh`, mode `0600`, outside the repository) |
| Database | **disposable** PostgreSQL DB `p48_smoke` created on the local server (`127.0.0.1:5432`). The 180+ pre-existing local DBs were listed and **left untouched** |
| Docker availability | NOT AVAILABLE — reported, not worked around with anything persistent |
| Dependencies | Python 3.11.2; fastapi 0.163.1, uvicorn, redis, psycopg2, alembic 1.20.1 — all present |
| Migrations | Applied automatically at startup: `<empty> -> 0008_tenant_not_null` (8 migrations, 0001→0008) on real PostgreSQL. `alembic current` = `0008_tenant_not_null (head)` |
| Existing DB/volume/backup deleted | **NONE** |
| `.env` overwritten | **NO** — `.env` does not exist in the repo and was not created |
| Missing configuration | Reported in §9 (Gemini, Telegram, Meta, QPay, offsite backup, alert webhook) |

---

## 4. Services started — PASS

| Service | Command | Status | Health |
|---|---|---|---|
| PostgreSQL | local server (pre-existing) | running | `SELECT 1` → OK |
| Redis | `redis://127.0.0.1:6379/0` | running | `PING` → True |
| Backend (FastAPI) | `uvicorn main:app --host 0.0.0.0 --port 8000` | running, pid 2453000 | `/api/live` 200, `/api/ready` 200, `/api/health` 200 |
| Worker | `python worker.py` | running, pid 2452258 | heartbeat `alive`, age < 6 s |
| Scheduler | inline loop in backend + worker scheduler | running | log: `Executive Daily Briefing & Retention scheduler loop started`; `/api/admin/worker/health` → `scheduler.healthy: true` |
| Frontend | served by backend (`dashboard.html`) | running | `/` 200 (HTML), `/admin` 200, `/scanner` 200 |

`/api/ready` verbatim: `{"ready":true,"status":"ready","database":"ok","engine":"postgresql","rate_limit_store":"redis","rate_limit_store_ok":true,"queue_backend":"redis+db","queue_stats":{...,"redis_connected":true}}`

**Application URL:** `http://localhost:8000` inside the sandbox; bound to
`0.0.0.0:8000`, so it is exposed as the Arena live preview
(`https://8000-<sandboxId>.e2b.app`).

---

## 5. Live smoke test — results

| # | Feature | Verdict | Evidence |
|---|---|---|---|
| 5.1 | Application opens | **PASS** | `/`, `/admin`, `/scanner`, `/api/live` all HTTP 200; dashboard HTML served |
| 5.2 | Login / session | **PASS** | correct password → 200 `success=True role=admin`; wrong password → **401**; `GET /api/leads` unauthenticated → **401** (fail-closed); with session → 200; forged token → **401**; audit rows `auth.login.success` + 2× `auth.login.failed` recorded |
| 5.3 | Dashboard | **PASS** | HTML rendered (Tailwind/FontAwesome dashboard), `total_pages` reported by `/api/health` |
| 5.4 | Core CRUD | **PASS** | CREATE `save_registration` → id 1/2/3; READ `/api/leads` + `get_lead_by_id`; UPDATE `POST /api/leads/1/status` → 200 `{"status":"updated","lead_id":1}`, persisted (`status='боловсруулсан'`); DELETE `delete_customer_data` → `{'registrations':1,...}`, row gone; EXPORT `/api/export/csv` 200 (4 lines, Mongolian header), `/api/export/excel` 200 (5767 bytes, `PK` zip magic) |
| 5.5 | Tenant isolation | **PASS** | tenant_a session sees only `P48 Alpha`; tenant_b only `P48 Bravo`; tenant_a asking `?page_id=p48_tenant_b` → **403** `Cross-tenant access denied`; tenant_b updating tenant_a's lead → **403** `IDOR Forbidden` and the row was unchanged afterwards |
| 5.6 | Telegram integration | **BLOCKED** | `TELEGRAM_BOT_TOKEN` / `TELEGRAM_WEBHOOK_SECRET` unset; `/api/health telegram_configured: false`. Fail-closed behaviour *was* verified: with `WEBHOOK_FAIL_CLOSED=1`, unsigned `POST /telegram/webhook` → **403** + `Telegram webhook fail-closed: TELEGRAM_WEBHOOK_SECRET is not configured`. Real send/receive not testable without credentials |
| 5.7 | Background jobs | **PASS** | full lifecycle on the real Redis queue: enqueue → `PENDING` (`job_ec6910c0d1e14582`) → claim → `PROCESSING` → handler executed → `ack_job` True → `completed: 1`. The dedicated worker also picked a job off Redis and logged `No handler registered for task 'p48_smoke_probe'` (correct: that task type has no registered handler) |
| 5.8 | Worker heartbeat | **PASS** | `/api/admin/worker/health`: `worker_count 1, alive 1, stale 0`, `age_seconds 0.2–5.8`, `fresh_window 30 s`, `ttl 90 s` |
| 5.9 | Scheduler | **PASS** | inline loop started in backend log; `/api/executive/settings` 200 (`daily_report_enabled: true`, `08:30`), `/api/executive/preview` 200 (real report text generated), `/api/retention/rules` 200 (seeded `abandoned_chat` rule), `/api/retention/campaigns` 200 (`[]`); all unauthenticated → **401**; `scheduler.healthy: true`, `scheduler_errors: 0` |
| 5.10 | Error handling | **PASS** | unknown API route → 404; malformed JSON → 422; empty credentials → 401; nonexistent lead id → 404; forged token → 401; server still `/api/live` 200 after the error burst. `GET /nope` → 200 is **by design** (`/{branch_slug}` branch-portal catch-all, which 404s reserved slugs and exposes no admin data) |

Only disposable test data was used (`p48_tenant_a`, `p48_tenant_b`, `P48 Alpha/Bravo/Charlie`, phone numbers `990000xx`).

---

## 6. Stability — PASS

| Check | Result |
|---|---|
| Backend startup | `Application startup complete`, `Uvicorn running on http://0.0.0.0:8000`; connection budget OK (17 required, 97 usable, headroom 80) |
| Backend shutdown | clean stop, no traceback |
| Backend **restart recovery** | restarted → `Schema ready: already at head (0008 -> 0008)` (**migrations not re-run**), startup complete, scheduler loop restarted, all endpoints 200, **data persisted** (`P48 Alpha / боловсруулсан`, `P48 Bravo / шинэ`, 3 pages), fresh admin login succeeded |
| Worker shutdown | graceful: `Received SIGTERM` → `worker heartbeat cleared` → `stopped cleanly` |
| Worker **restart recovery** | new `worker_id`, heartbeat `alive` again, and it **immediately re-consumed the job still pending in Redis** (queue state survived the restart) |
| Probe instance lifecycle | second backend on port 8010 (`WEBHOOK_FAIL_CLOSED=1`) started, used for the fail-closed test, then `Application shutdown complete` |
| Database connection | `SELECT 1` OK; `/api/ready database: ok engine: postgresql` before and after restarts |
| API response | 20/20 requests 200 OK; latency min 0.8 ms / avg 1.1 ms / max 3.5 ms |
| Application logs | no traceback, no unhandled exception. Only expected WARNINGs (see §9) |
| Worker/scheduler errors | `scheduler_errors: 0`; no worker exception in any log |
| Schema drift (live PostgreSQL) | `drift_report()` → `{'has_drift': False, 'count': 0, 'current_revision': '0008_tenant_not_null', 'head_revision': '0008_tenant_not_null'}` |
| Secret hygiene | scanned **819** on-disk log/artifact files for the real `ADMIN_PASSWORD`, `E02_ACCOUNT_KEY_SECRET` and both scoped session tokens → **LEAKS FOUND: none**. `_sanitize_page_secrets` removes `page_access_token`, `gemini_api_key`, `qpay_password`, `telegram_bot_token`, `client_password_hash`, `client_salt` from every API response (verified: no raw key present) |

---

## 7. Git protection — PASS

| Rule | Status |
|---|---|
| No change to `main` | ✅ `main` = `origin/main` = `debefb4` |
| No commit | ✅ none |
| No push | ✅ none |
| No merge | ✅ none |
| No production deploy | ✅ none |
| No destructive migration | ✅ only forward `upgrade head` on a disposable DB |
| Branch unchanged | ✅ still `arena/d78ebf88-gerege-ai-agent` @ `5402ab9` |
| Repo cleanliness | ✅ only untracked `PHASE*_REPORT.md`; no `.env` created; env kept in `/tmp/p48_env.sh` (0600) |

---

## 8. Verdict summary

| Dimension | Verdict |
|---|---|
| Baseline | **PASS** |
| Environment inspection | **PASS** |
| Local setup (disposable, no production) | **PASS** |
| Services started (backend, worker, scheduler, DB, Redis, UI) | **PASS** |
| Application opens / dashboard | **PASS** |
| Login & session (incl. fail-closed + audit) | **PASS** |
| Core CRUD + export | **PASS** |
| Tenant isolation + IDOR defence | **PASS** |
| Background jobs (queue lifecycle) | **PASS** |
| Worker heartbeat | **PASS** |
| Scheduler | **PASS** |
| Error handling | **PASS** |
| Stability (shutdown/restart/recovery/drift/secrets) | **PASS** |
| Telegram integration (real send/receive) | **BLOCKED** (no credentials) |
| Meta (Messenger/Instagram) integration | **BLOCKED** (no credentials) |
| AI / Gemini reply quality | **NOT VERIFIED** (`GEMINI_API_KEY` unset) |
| QPay payment flow (real) | **BLOCKED** (no credentials; simulator flag exists but was not exercised) |
| Offsite backup / alert delivery | **BLOCKED** (unchanged from Phase 46) |
| Staging readiness | **BLOCKED** (unchanged from Phase 46) |
| Production readiness | **NOT READY** (unchanged from Phase 46/47) |

---

## 9. Found errors, warnings and missing configuration

**No functional error was found.** The application started, served, persisted,
recovered and shut down cleanly on real PostgreSQL + Redis.

### Observations (not failures)

- **O1 — `README.md` is stale (docs gap).** It tells the operator the server is
  already running, and describes SQLite `leads.db` as the store with no mention
  of a virtual environment, `requirements.txt`, PostgreSQL, `REDIS_URL` or the
  separate `python worker.py` process. An operator following it would not reach
  a correct install.

  **CORRECTION (Phase 48A):** this report originally also claimed the README
  points at "`start.bat` (a Windows file that does not exist in the repo)".
  That claim was **wrong** and is withdrawn. `start.bat`, `start_agency.bat` and
  `tunnel.bat` all exist and are tracked in git; `start.bat` simply runs
  `python main.py`, so the README's launch advice was valid. The staleness is
  limited to the missing venv/requirements/worker/PostgreSQL/Redis guidance and
  to the published verify-token instruction (fixed in Phase 48A §3). The error
  came from reading a truncated `ls` listing (40 entries) instead of the full
  root; Phase 48A re-listed the root without truncation.
- **O2 — per-page `verify_token` default is a published value (LOW, hygiene).**
  `database.save_page(...)` defaults `verify_token` to
  `agent_verify_secret_token_123`, the same string printed in `README.md`, and
  `_sanitize_page_secrets` does **not** mask `verify_token`. Any page created
  without an explicit token inherits a value that is public in this repository.
  Not exploitable here (`META_VERIFY_TOKEN` is env-driven and Phase 45 made the
  endpoint check fail-closed in production), but a page created through the API
  with no token would carry the published default.
- **O3 — `client_magic_token` is returned unmasked to `pages:read`.** This is
  **by design** (the admin dashboard shows the client's magic link), and every
  vendor secret is stripped; recorded so it is a known, intentional exposure
  rather than an unnoticed one.
- **O4 — least-privilege WARNING (dev only).** Every startup logs
  `Least-privilege check not enforced (not production mode): role 'gerege' has
  26 violation(s) that would stop a production boot`. Correct dev behaviour;
  production requires `scripts/provision_roles.py --apply` to create the split
  `gerege_app` / owner roles.
- **O5 — leftover probe job.** `job_f538b437659149d4` (`p48_smoke_probe`) stays
  `pending` in the disposable queue and the worker re-logs `No handler
  registered` every ~15 s. Harmless, disposable DB only; it will exhaust retries
  into dead-letter.
- **O6 — `GEMINI_API_KEY` not configured**, so AI replies are not exercisable;
  `/api/health` honestly reports `gemini_ready: false`.

### Missing configuration (all optional for local dev, all required for production)

`GEMINI_API_KEY`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET`,
`META_VERIFY_TOKEN`, `META_APP_SECRET`, `META_PAGE_ACCESS_TOKEN`,
`MANYCHAT_WEBHOOK_SECRET`, `QPAY_USERNAME/PASSWORD/INVOICE_CODE`,
`ALLOWED_ORIGINS`, `TRUSTED_PROXIES`, `BACKUP_OFFSITE_PATH`,
`BACKUP_ENCRYPTION_KEY_FILE`, `BACKUP_ALERT_WEBHOOK`, `DATABASE_OWNER_URL`
(real owner credential), `POSTGRES_OWNER_PASSWORD`, `POSTGRES_APP_PASSWORD`.

---

## 10. Startup / shutdown instructions (as actually executed)

### Startup

```bash
# 0. prerequisites: PostgreSQL reachable, Redis reachable, deps installed
#    (python 3.11, fastapi, uvicorn, redis, psycopg2, alembic)

# 1. local-only environment (NEVER commit; keep outside the repo)
umask 077
cat > /tmp/gerege_local.env <<'EOF'
ENV=development
STRICT_SECURITY=0
WEBHOOK_FAIL_CLOSED=0
DATABASE_URL=postgresql+psycopg2://USER:PASS@127.0.0.1:5432/DISPONSABLE_DB
DATABASE_OWNER_URL=postgresql+psycopg2://USER:PASS@127.0.0.1:5432/DISPENSABLE_DB
REDIS_URL=redis://127.0.0.1:6379/0
ADMIN_PASSWORD=<generate: python -c "import secrets;print(secrets.token_urlsafe(24))">
E02_ACCOUNT_KEY_SECRET=<generate: python -c "import secrets;print(secrets.token_urlsafe(48))">
HOST=0.0.0.0
PORT=8000
RELOAD=0
DISABLE_INLINE_SCHEDULER=0
UVICORN_WORKERS=1
EOF
chmod 600 /tmp/gerege_local.env

# 2. create a DISPOSABLE database (never reuse an existing one)
createdb -h 127.0.0.1 -p 5432 -U USER DISPENSABLE_DB

# 3. backend — migrations 0001..0008 apply automatically on first start
source /tmp/gerege_local.env
python -m uvicorn main:app --host "$HOST" --port "$PORT"

# 4. worker (own process; runs the scheduler + heartbeat + queue handlers)
source /tmp/gerege_local.env
DISABLE_INLINE_SCHEDULER=1 python worker.py

# 5. verify
curl -s http://127.0.0.1:8000/api/live      # {"status":"alive"}
curl -s http://127.0.0.1:8000/api/ready     # ready/database/engine/queue
curl -s http://127.0.0.1:8000/api/health    # dashboard summary
# then open http://localhost:8000 and log in with ADMIN_PASSWORD
```

### Shutdown

```bash
# SIGTERM is enough — both processes shut down gracefully:
#   worker:  "Received SIGTERM" -> "worker heartbeat cleared" -> "stopped cleanly"
#   backend: "Waiting for application shutdown" -> "Application shutdown complete"
kill -TERM <worker_pid> <backend_pid>
```

Leave the disposable database in place (do not drop databases that are not
yours). Restarting re-attaches to the same schema at head without re-running
migrations, and the worker resumes any job still pending in Redis.

---

## 11. Conclusion

**The merged code runs.** On a disposable local PostgreSQL + Redis, `main` @
`debefb4` boots, migrates itself to head `0008_tenant_not_null`, serves the
dashboard and API, authenticates fail-closed, isolates tenants (cross-tenant
read **and** write both rejected), performs CRUD + CSV/Excel export, processes
background jobs end-to-end through Redis, keeps a fresh worker heartbeat, runs
its scheduler, handles errors without dying, and survives a full
shutdown/restart cycle with data intact and zero schema drift. No secret value
reached any log, response or report.

**BLOCKED, not passed:** Telegram, Meta, QPay and AI behaviour need real vendor
credentials that do not exist here. Staging readiness remains **BLOCKED** and
production readiness remains **NOT READY**, exactly as recorded in Phase 46/47 —
a green local smoke test on a disposable database is not staging or production
evidence, and this report does not claim it as such.
