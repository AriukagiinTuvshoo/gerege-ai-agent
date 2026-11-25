# PHASE 35 — Deployment Readiness & Infrastructure Audit

Baseline: `arena/d78ebf88-gerege-ai-agent` @ `5afb8fe`, `main` `48e9c6f`, PR #1 open,
CI `45119935392` 66/66, tree clean. Verified before any inspection.

**Scope:** audit and planning only. No deployment, no infrastructure, no credentials.
Every claim is tagged **VERIFIED** (read from code/runtime), **INFERRED** (follows from
verified facts), **UNKNOWN** (no evidence available here), or **BLOCKED** (cannot be
determined from this environment).

---

## 1. Architecture as verified

**Multi-service.** `docker-compose.prod.yml` defines six services; only two serve traffic.

| Service | Role | Verified |
|---|---|---|
| `web` | uvicorn, 2 workers, port 8000 published | Dockerfile:40, compose |
| `worker` | `python worker.py`, no port | compose |
| `migrate` | one-shot: provision roles → alembic → re-provision → verify | compose |
| `maintenance` | profile-scoped one-shot: backup/restore/prune | compose |
| `db` | postgres:16-alpine | compose |
| `redis` | redis:7-alpine, `noeviction`, `maxmemory 400mb` | compose |

### Answers to the Phase 1 questions

| # | Question | Answer | Basis |
|---|---|---|---|
| 1 | Single or multi service? | **Multi** (6 services, 2 long-running) | **VERIFIED** |
| 2 | Can API and worker run independently? | **Yes** — separate processes, separate containers, both connect to the DB/Redis only | **VERIFIED** |
| 3 | Where does the scheduler run? | **Worker only in production.** `DISABLE_INLINE_SCHEDULER=1` stops the API's `executive_scheduler_loop`. In dev the API runs it | `main.py:99-101`, compose | **VERIFIED** |
| 4 | Can multiple API instances run? | **Yes** — no in-process state that would corrupt data. Rate limits are Redis-shared (startup fails closed without Redis) | **VERIFIED** |
| 5 | Are background tasks persisted? | **Yes** — `task_jobs` table; Redis list is a hint, the DB is the queue | `core/task_queue.py:353` | **VERIFIED** |
| 6 | Are scheduled tasks duplicated across instances? | **No** — DB-backed TTL locks. Measured: 2 threads racing one lock → exactly 1 winner | `claim_notification_lock` | **VERIFIED** |
| 7 | What happens on restart? | Jobs survive (DB). In-flight `PROCESSING` jobs are recovered by `recover_stale_jobs()` on the next tick | `worker.py:71` | **VERIFIED** |
| 8 | What happens if a worker crashes? | Same recovery path. Stale jobs re-enter the queue after the visibility timeout | **VERIFIED** (code) / **INFERRED** (timing) |
| 9 | Migrations at startup? | **Not by the API.** Only the `migrate` service, and `web`/`worker` wait on `service_completed_successfully` | compose | **VERIFIED** |
| 10 | Can two instances migrate concurrently? | **Serialised** by `pg_advisory_lock` | `core/schema_manager.py:160` | **VERIFIED** |

### Architecture diagram (verified)

```
Internet
   |  :8000 published directly — NO reverse proxy, NO TLS terminator in this compose
   v
+--------------------+     +---------------------+
| web (uvicorn x2)   |     | worker.py           |
| - REST API         |     | - task queue (25)   |
| - serves SPA       |     | - daily exec report |
| - NO scheduler     |     | - retention (5 min) |
| - rate limit (Redis)|    | - appt reminders    |
+---------+----------+     +----------+----------+
          |                           |
          +-------------+-------------+
                        |
              +---------v----------+      +--------------+
              | PostgreSQL 16      |      | Redis 7      |
              | pool 10+20/process |      | noeviction   |
              | audit append-only  |      | rate limits  |
              +--------------------+      +--------------+
                        ^
              +---------+----------+
              | migrate (one-shot) |
              | maintenance (cron) |
              +--------------------+
```

**Note on the Vercel path.** `vercel.json` + `api/index.py` are a *separate* deployment
mode for serverless. It copies SQLite into a per-process `/tmp` directory — writes are
ephemeral and do not survive the instance. It is documented as requiring managed
PostgreSQL and Redis with the worker on a persistent host
(`docs/deployment/PRODUCTION_DEPLOYMENT.md:208-215`). **It is not a production topology
for this product on SQLite**; treat it as a demo/preview path.

---

## 2. Container & runtime security

| Item | Status | Evidence |
|---|---|---|
| Non-root execution | **VERIFIED GOOD** | `USER gerege` (Dockerfile:24) |
| Healthcheck in image | **VERIFIED GOOD** | uses `/api/ready`, 5 s timeout |
| Graceful shutdown | **VERIFIED GOOD** | SIGINT/SIGTERM handlers in `worker.py:121+`; uvicorn handles its own |
| Secret files in layers | **VERIFIED GOOD** | `.dockerignore` excludes `.env`, `.env.*`, `*.db` |
| Shell/apt in final image | **VERIFIED GOOD** | single-stage, `--no-install-recommends`, apt lists removed |
| Proxy-header spoofing | **VERIFIED GOOD** | `--no-proxy-headers` + `TRUSTED_PROXIES` empty by default |
| Resource limits | **PARTIAL** | `deploy.resources` set, but **`deploy:` is ignored by plain `docker compose`** — it only applies under Swarm or with Compose v2.24+ `--compatibility`/support. **INFERRED RISK** |
| Base image pinning | **WEAK** | `python:3.12-slim`, `postgres:16-alpine`, `redis:7-alpine` — mutable tags, no digest |
| Dependency pinning | **WEAK** | `requirements.txt` uses ranges (`>=x,<y`), **no lockfile, no hashes** |
| Build reproducibility | **NOT VERIFIED** | follows from the two rows above: two builds of the same commit can differ |
| Read-only root filesystem | **NOT IMPLEMENTED** | `/app` is writable by `gerege`; needed for `static/qrcodes` and backups mount |
| Container size | **UNKNOWN** | no image built in this environment |

**Concrete defect (Low/Medium):** `deploy.resources.limits` in `docker-compose.prod.yml`
is inert under non-Swarm `docker compose`. A container can consume the whole host
unbounded. This is a real reliability gap, not a style issue.

---

## 3. Database production readiness — **the most important section**

### 3.1 Connection capacity: a concrete launch blocker

Measured from code and a live PostgreSQL 16:

```
DB_POOL_SIZE      = 10        (core/db_engine.py:111)
DB_MAX_OVERFLOW   = 20        (core/db_engine.py:112)
uvicorn --workers = 2         (Dockerfile:40)
```

| Component | Connections |
|---|---|
| `web` (2 processes × 30) | 60 |
| `worker` (1 process × 30) | 30 |
| **Total steady-state ceiling** | **90** |

PostgreSQL defaults, read from a real instance: `max_connections = 100`,
`superuser_reserved_connections = 3` → **97 usable**. That leaves **7** for `migrate`,
`maintenance`, admin `psql`, and monitoring.

And there is **no guard, warning or validation anywhere** in the codebase that compares
the pool configuration to the server limit (`grep max_connections` → 0 hits).

**Why this blocks launch:** during a deploy, `migrate` needs a connection while `web` and
`worker` hold theirs. If the pool ever reaches 30 per process — which happens under
sustained load because `max_overflow` is *designed* to be used — the 91st connection is
refused by the server, and the failure surfaces as application errors, not as a clear
"pool exhausted" message.

**Minimum fix (planning, not implemented):** either
- set `DB_POOL_SIZE=5, DB_MAX_OVERFLOW=5` (→ 30+15 = 45, comfortable headroom), or
- set PostgreSQL `max_connections=200` and keep the pool, or
- add PgBouncer.

**Recommended:** lower the pool. This workload is low-concurrency (REST + one worker tick
per 45 s); 10 connections per process is not needed.

### 3.2 Other database properties

| Property | Status | Evidence |
|---|---|---|
| Pool pre-ping / recycle | **VERIFIED GOOD** | `pool_pre_ping=True`, `pool_recycle=1800` |
| Session timeouts bounded | **VERIFIED GOOD** | `statement_timeout`, `idle_in_transaction_session_timeout`, `lock_timeout` set per connection |
| Transaction handling | **PARTIAL** | ~53 helpers acquire a connection without `try/finally` (documented in `db_engine` comments); mitigated by the session timeouts |
| Least-privilege roles | **VERIFIED GOOD** | `gerege_app` cannot DDL; `audit_logs` is append-only by trigger; `migrate` is the only owner-credential holder |
| Migration locking | **VERIFIED GOOD** | `pg_advisory_lock` |
| SSL to PostgreSQL | **NOT IMPLEMENTED** | compose uses an internal Docker network, so traffic does not leave the host. **INFERRED acceptable for single-VPS**; **required** if the DB becomes managed/remote — no `sslmode` is configurable today |
| Index health | **NOT VERIFIED** | no `pg_stat_user_indexes` check; schema defines indexes (confirmed by migration drift tests) |

### 3.3 Migration safety

- **While running:** each migration is DDL; additive migrations (0005, 0006, 0007) are safe. **INFERRED**
- **Rolling deploy:** safe *only* if the new code tolerates the old schema. No expand/contract pattern is documented. **UNKNOWN per release**
- **Two instances at once:** safe (advisory lock). **VERIFIED**
- **Rollback:** **`0004_tenant_session_identity` will refuse to downgrade** when two tenants share a `sender_id` — which is the normal state in production. It raises rather than destroying data (`migrations/versions/0004:226-233`). **VERIFIED**

**This is the single most important rollback fact:** a database rollback past 0004 is
**not available**. Recovery must use the backup/restore path, not `alembic downgrade`.

### 3.4 Backup & restore

| Capability | Status |
|---|---|
| Full backup | **VERIFIED** — `maintenance.py backup`, owner credential |
| Encryption | **VERIFIED** — AES-256-GCM, key from a mounted file, **fails closed in production without a key** |
| Offsite | **VERIFIED (code)** — S3-compatible or second mount; **no default mount** (deliberate: a default that was the same disk was previously reported as offsite) |
| Retention | **VERIFIED** — `BACKUP_RETENTION_DAYS=14`, `BACKUP_MIN_KEEP=7`, negatives corrected |
| Integrity verification | **VERIFIED** — SHA-256 + authenticated ciphertext |
| Restore to a fresh database | **VERIFIED** — see below |
| Automated scheduling | **NOT IN CODE** — deliberately removed in E-05 because the runtime role cannot `LOCK TABLE`; a host cron/systemd timer must drive `maintenance.py backup-run` |

**Restore verified for real, in this environment.** `tests/test_postgres_restore_real_rollback.py`
performs an actual `pg_dump` → restore → per-table SHA-256 comparison against live
PostgreSQL 16: **8/8 passed**.

> Caveat found during this audit: the file **fails if run against a database without
> `init_db()`'s seed page**, because one test inserts a registration for
> `DEFAULT_PAGE_ID` and hits the FK. In the full suite the seed exists, so it passes. It
> is a test-ordering dependency, not a product defect — but it means "8/8 passed" only
> holds in a seeded database.

**RPO / RTO are deployment decisions, not code facts:**

| | Value | Basis |
|---|---|---|
| RPO | **24 h** with a daily timer; **as low as 15 min** with a more frequent timer | Backup frequency is set by the host timer; nothing in the app schedules it. **INFERRED** |
| RTO | **Unknown** — depends on archive size and restore method. A 11 MB database restores in seconds; growth is unmeasured | **UNKNOWN** |

---

## 4. Environment & secret management

Full inventory written to **`docs/deployment/PRODUCTION_ENV_TEMPLATE.env`** (placeholders
only). Summary of what the startup contract actually enforces:

| Check | Behaviour | Status |
|---|---|---|
| Missing `E02_ACCOUNT_KEY_SECRET` | **Startup aborts** — verified: `RuntimeError: ... required when running in production` | **VERIFIED GOOD** |
| Missing `REDIS_URL` | **Startup aborts** — verified: `RateLimitStoreUnavailable` | **VERIFIED GOOD** |
| Missing `ALLOWED_ORIGINS` | **Import aborts** — verified in `main.py:161` | **VERIFIED GOOD** |
| Missing `POSTGRES_APP_PASSWORD` / `ADMIN_PASSWORD` / `POSTGRES_OWNER_PASSWORD` | `compose up` fails on `:?` | **VERIFIED GOOD** |
| Weak/default `ADMIN_PASSWORD` in production | guarded by production checks | **PARTIAL** — exact policy not re-audited here |
| Secrets in frontend bundle | **None** — `dashboard.html` contains no embedded keys | **VERIFIED** |
| Secrets in error responses | Mostly redacted (`core/monitoring.py` `redact_secrets`); **one leak found and fixed in Phase 34** | **VERIFIED** |
| `.env` excluded from VCS and image | **Yes** — `.gitignore` + `.dockerignore` | **VERIFIED** |

**Findings:**

1. **`GOOGLE_SHEETS_CREDENTIALS_JSON` is documented but read by nothing.** Verified: 0
   references in code. Sheets integration fetches public CSV exports. An operator
   setting it would debug a variable with no effect. **Fixed in this phase** (removed from
   the template, annotated in `.env.example`).
2. **`STRICT_QPAY_VERIFICATION` is set in compose but read by no application code.** The
   QPay callback is unconditionally fail-closed, so the variable is redundant rather than
   dangerous. **INFERRED safe; should be removed or implemented.**
3. **30 env vars are read in code but absent from `.env.example`** (pool tuning,
   `OPENAI_*`, `QPAY_BASE_URL`, `REQUIRE_LEAST_PRIVILEGE`, …). Now covered by the template.

---

## 5. Network & HTTPS

| Requirement | Current state |
|---|---|
| Reverse proxy | **NONE in the repo** |
| TLS/HTTPS | **NOT TERMINATED** — `web` publishes `:8000` plaintext |
| HSTS header | emitted in production, but only meaningful behind TLS |
| Secure cookies | `secure=is_production_mode()` — correct, **but a Secure cookie over plaintext HTTP will not be stored by the browser** |
| Forwarded-header trust | empty by default — correct for direct exposure |
| CORS | allowlist required, wildcard rejected in production — **VERIFIED GOOD** |
| CSRF | `require_csrf` appears on 0 routes; protection relies on `SameSite=Lax` + bearer tokens | **PARTIAL** |

**Confirmed blocker:** publishing port 8000 directly means **no HTTPS**. Admin login,
session cookies and all tenant data would traverse the network in plaintext, and
`Secure` cookies would not persist. A TLS-terminating proxy is **required**, not
optional.

**Minimum viable network design (INFERRED):**

```
Internet → 443 (TLS, Let's Encrypt) → nginx/Caddy → web:8000 (private network)
                     |                    └→ 80 redirects to 443
                     └→ webhooks (Meta, Telegram, QPay) all arrive here
PostgreSQL/Redis: no published ports, private Docker network only
```

When a proxy is added, `TRUSTED_PROXIES` must be set to the proxy address **and**
`--no-proxy-headers` left in place, or client-IP rate limiting breaks (documented at
`PRODUCTION_DEPLOYMENT.md §1.1`).

---

## 6. Workers & scheduler — horizontal scaling

**Safe to scale horizontally. Verified, not assumed.**

| Question | Answer | Evidence |
|---|---|---|
| Lost on restart? | **No** — `task_jobs` is the queue | `task_queue.py` |
| Execute twice? | **No** — conditional `UPDATE ... WHERE status='PENDING'` + `rowcount` check; measured: second claim returns `None` | **VERIFIED empirically** |
| Two workers, same task? | **No** — same atomic claim | same |
| Scheduled jobs duplicated? | **No** — TTL lock; measured: 2 threads → 1 winner | **VERIFIED empirically** |
| Retries? | **Yes** — exponential backoff `min(3600, 2**attempts)`, `max_retries=3` | `task_queue.py:250` |
| Retry limits? | **Yes** — then `DEAD_LETTER` | same |
| Failed jobs observable? | **Yes** — `GET /api/admin/queue/failed` (admin) | `system_router.py:61` |
| DLQ? | **Yes** — `DEAD_LETTER` status + Redis DLQ key | `task_queue.py:17` |
| Job state persisted? | **Yes** | DB |
| Worker safe to restart? | **Yes** — graceful SIGTERM, stale recovery | `worker.py` |

**Verdict:** the worker/scheduler design is **production-grade for horizontal scaling**.
This is the strongest part of the system.

**Gap:** there is **no worker liveness endpoint**. Queue depth and failures are visible,
but "is the worker process alive?" is not answerable through the API — only through the
container's own restart policy and logs. A dead worker means silent non-delivery until
queues back up.

---

## 7. Third-party integrations

| Integration | Code verified | Mock verified | Live verified | Blockers |
|---|---|---|---|---|
| Telegram (send) | **Yes** | Yes (Phase 33/34) | **No** | Live token; delivery semantics unproven |
| Meta / FB / IG | **Yes** | Partial | **No** | App review + live token |
| QPay | **Yes** — live verification, amount+currency match, idempotent | Yes | **No** | Merchant credentials |
| Google Sheets | **Yes** — public CSV export only | Yes | **No** | Nothing (public sheets) |
| Gemini | **Yes** | Yes (fake client) | **No** | API key; cost behaviour unmeasured |
| ManyChat | **Yes** | Partial | **No** | Live token |
| Webhooks (inbound) | **Yes** — HMAC verify, dedup, fail-closed |Yes | **No** | Real provider signature |

All integrations carry 10–12 s timeouts; AI retries twice with backoff. **No integration
has been exercised against a live provider.** Every "works" claim above is code + mock.

**Must be verified in staging before launch:** Meta webhook signature round-trip,
Telegram delivery (including the 403 path fixed in Phase 34), QPay callback end-to-end
with a real sandbox payment, and Gemini latency/cost under real prompts.

---

## 8. Monitoring & observability

| Capability | Status |
|---|---|
| Liveness (`/api/health`) | **EXISTS, but unbounded** — see below |
| Readiness (`/api/ready`) | **GOOD** — DB + queue probe, 6.6 ms at 10k rows |
| Request IDs | **GOOD** — `X-Request-ID` generated/echoed, on every response |
| Structured logging | **GOOD** — `log_structured_event` with JSON + secret redaction exists |
| Plain logging | `logging.basicConfig(INFO)` also active — output is **mixed forms** |
| Metrics (`/api/admin/metrics`) | **PARTIAL** — in-memory **per process**, lost on restart, not aggregated across 2 workers |
| Worker liveness | **NOT IMPLEMENTED** |
| External alerting | **PARTIAL** — backup failures can POST a webhook (`BACKUP_ALERT_WEBHOOK`); nothing else |
| Uptime monitoring | **NOT IMPLEMENTED** (deployment-side) |
| Provider-failure metrics | **NOT IMPLEMENTED** (logged, not counted) |

**Measured defect — `/api/health` cost grows with data:**

| Data | `/api/health` | `/api/ready` |
|---|---|---|
| Empty | 28.1 ms | — |
| 5,000 registrations + 5,000 messages | **94.6 ms** | 6.6 ms |

`/api/health` runs `get_all_registrations()` and per-page `get_active_sessions()` on
**every call** (`main.py:1764-1768`). At 100k rows this is linear, and the Dockerfile
healthcheck timeout is 5 s. The container healthcheck uses `/api/ready` (correct); but
`deploy.sh:98` uses `/api/health`, and any external monitor pointed at `/api/health`
will add real load.

**Recommendation:** keep monitors on `/api/ready`; treat `/api/health` as a
human-facing detail page, not a probe. A cheap fix would be to stop computing the
counts there, but that is a product change and is **not** made in this phase.

---

## 9. Performance & capacity — measured vs estimated

### Measured in this audit / earlier phases (SQLite, local, `TestClient` — **not** a load test)

| Metric | Value |
|---|---|
| Cold import | 1.57 s |
| `/api/leads?limit=50` @500 rows | 9.7 ms |
| `/api/ready` @10k rows | 6.6 ms |
| `/api/health` @10k rows | 94.6 ms |
| Full test suite | 1,349 tests / 338 s |

### Estimated (clearly labelled — **NOT measured**)

| Deployment | vCPU | RAM | Basis |
|---|---|---|---|
| Small (1 VPS, all 6 services) | 4 | 8 GB | web 1.5 + worker 1.0 + db 1.0 + redis 0.5 = 4.0 CPU from compose limits; ~2.5 GB container limits + OS |
| Medium | 8 | 16 GB | + a second web instance, or managed PG |
| Large | — | — | needs real measurement; do not guess further |

Redis is capped at 400 MB `maxmemory` with `noeviction`; the compose comment states the
container limit is **UNVERIFIED** and warns the margin is thin. Treat 512 MB as a
floor, not a target.

---

## 10. Deployment & rollback

`scripts/deploy.sh` is **verified good**: `set -euo pipefail`, **refuses to deploy
without a backup** (`deploy.sh:40`), records the rollback commit, runs
provision → migrate → restart → `/api/health` check.

`scripts/rollback.sh` rolls back **code and data independently** and prints which
happened. A failed restore is fatal and does not restart services.

**Rollback truth:**

| Question | Answer |
|---|---|
| Code rollback safe? | **Yes** — image tag / commit revert |
| Migration rollback safe? | **NO past 0004** — refuses when tenants share a sender |
| Migrations backward-compatible? | **UNKNOWN per release** — no expand/contract discipline documented |
| Database restore required? | **Yes** for any rollback past 0004 |
| Irreversible migrations | `0004_tenant_session_identity` (data-dependent) |

**Deploy without downtime:** `depends_on: service_completed_successfully` means
`web`/`worker` are *recreated* after migration. On a single VPS this is a short outage,
not zero-downtime. Acceptable for launch; a rolling strategy needs a second host or
an orchestrator.

---

## 11. Cost

Prices are **estimates**; no pricing page was fetched, so treat the numbers as
order-of-magnitude, not quotes. **UNVERIFIED.**

| Option | Composition | Est. monthly |
|---|---|---|
| **A — Lowest cost** | 1 VPS (4 vCPU/8 GB), everything in Docker Compose on it, local disk backups, domain | $25–50 VPS + ~$15 domain/yr |
| **B — Recommended** | 1 VPS for app + separate managed PostgreSQL with automated backups, or a second VPS for backups | $50–120 |
| **C — Scalable** | 2+ app hosts behind a LB, managed PG, managed Redis, object storage, monitoring | $250–500+ |

Excluded: Gemini usage (unmeasured — **UNKNOWN**), Telegram/Meta/QPay (free at this tier),
engineering time.

---

## 12. Readiness matrix

| Category | Status | Evidence | Severity |
|---|---|---|---|
| Application | **VERIFIED** | 1,349 tests, 93 routes, 19 High-risk routes behaviour-tested | — |
| Authentication | **VERIFIED** | Fail-closed startup, RBAC, tenant isolation, revoked-token tests | — |
| Database | **PARTIALLY VERIFIED** | Pool 90 vs limit 100 — no headroom, no guard | **High** |
| Secrets | **PARTIALLY VERIFIED** | Fail-closed startup proven; 2 dead vars found; one leak fixed | Low |
| HTTPS | **NOT IMPLEMENTED** | No proxy, no TLS; port 8000 plaintext | **Blocker** |
| Docker | **PARTIALLY VERIFIED** | Non-root + healthcheck good; mutable tags, no lockfile, limits inert | Medium |
| Worker | **VERIFIED** | Atomic claim + TTL locks measured | — |
| Scheduler | **VERIFIED** | Same; single instance in prod | — |
| Backups | **VERIFIED (logic)** / **NOT IMPLEMENTED (schedule)** | Real restore 8/8; no timer in code | **High** |
| Monitoring | **PARTIALLY VERIFIED** | Health/ready/request-ID good; no worker liveness, per-process metrics | Medium |
| Integrations | **NOT VERIFIED (live)** | Mock only | **High** |
| CI/CD | **VERIFIED** | 66/66 steps, guards against skipped suites | — |
| Rollback | **PARTIALLY VERIFIED** | Code yes; DB no past 0004 | **High** |
| Scaling | **VERIFIED (design)** | Safe to add API/worker instances | — |

---

## 13. Final verdict

### Critical blockers (evidence-backed)

1. **No HTTPS.** The compose file publishes plaintext `:8000`. `Secure` cookies will not
   persist, and admin passwords cross the network in the clear. **Blocker.**
2. **Connection budget exceeds the server.** 90 required against ~97 usable with zero
   headroom and no guard. **Blocker** until the pool is lowered or `max_connections`
   raised.
3. **No scheduled backup.** The code deliberately removed the in-app backup (correctly —
   the runtime role cannot dump), but nothing in the repo replaces it. A deployment that
   skips the documented host timer has **no backups at all**. **Blocker** (process).

### High-risk issues

- No lockfile / no digest pins → non-reproducible builds.
- Rollback past migration 0004 requires a full restore.
- Zero live integration verification.
- No worker liveness signal.
- `deploy.resources` inert under plain Compose.

### Recommended deployment

**Option B, single VPS (4 vCPU / 8 GB) running the provided compose stack, plus:**
- Caddy or nginx terminating TLS on 443 (Caddy for automatic certificates);
- a host `systemd` timer running `maintenance.py backup-run` daily, with an offsite
  target configured;
- `DB_POOL_SIZE=5`, `DB_MAX_OVERFLOW=5` unless `max_connections` is raised;
- uptime monitoring against `/api/ready`, not `/api/health`.

This matches the project's current scale, keeps the least-privilege design the code
already enforces, and needs no architectural change.

### Deployment checklist (ordered)

1. Provision VPS; OS updates; non-root sudo user; SSH keys only.
2. Firewall: allow 22, 80, 443. **Do not allow 8000.**
3. Docker Engine + Compose plugin.
4. Domain → A record.
5. Create `.env` from `PRODUCTION_ENV_TEMPLATE.env`, `chmod 600`.
6. Generate all secrets; never reuse the template placeholders.
7. Install the backup encryption key file; `chmod 400`; mount path matches
   `BACKUP_ENCRYPTION_KEY_FILE`.
8. `docker compose -f docker-compose.prod.yml up -d` (provisions roles, migrates).
9. Verify `provision_roles.py --verify` output.
10. Reverse proxy + TLS; set `TRUSTED_PROXIES` to the proxy address.
11. `/api/ready` returns 200; log in; create a tenant.
12. Install the backup timer; run one manual backup; **perform a restore into a scratch
    database and confirm row counts**.
13. Point uptime monitoring at `/api/ready`.
14. Add the Meta/Telegram/QPay webhook URLs in each provider console.

### Staging requirements before production

Real credentials are mandatory for: Meta webhook signature round-trip; Telegram delivery
including the blocked-bot path; QPay sandbox payment end-to-end; Gemini latency and cost;
a real restore into a fresh database; and a load test at expected peak to replace the
estimates in §9.

### GO / NO-GO

**GO for staging.** The application layer is in genuinely good shape — verified
multi-tenancy, atomic job claiming, fail-closed startup, real restore tests, 1,349
green tests.

**NO-GO for production**, on three evidence-backed grounds: no TLS, no connection
headroom, and no automated backup in the repository. Each has a small, known fix; none
requires redesign. They are deployment work, not code work.

### Next phase

**Phase 36 — Staging Deployment & Live Integration Verification.** Stand up staging
behind TLS, fix the three blockers, and exercise every integration with real sandbox
credentials. Do not begin it without authorization.
