# PHASE 8 — PRODUCTION DEPLOYMENT AND OBSERVABILITY

**Repository:** `https://github.com/AriukagiinTuvshoo/gerege-ai-agent`  
**Modules:** [`Dockerfile`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/Dockerfile), [`docker-compose.prod.yml`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/docker-compose.prod.yml), [`main.py`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/main.py), [`worker.py`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/worker.py), [`core/monitoring.py`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/core/monitoring.py), [`vercel.json`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/vercel.json)

---

## 1. Production Container Topology (`docker-compose.prod.yml`)

Production deployments run 4 isolated services with healthchecks and resource limits:

1. **`db` (`postgres:16-alpine`):**
   - Primary relational store with persistent `pgdata` volume and `pg_isready` healthcheck.
2. **`redis` (`redis:7-alpine`):**
   - Append-only (`--appendonly yes`) broker for `core/task_queue.py` (`gerege:task_queue` and `gerege:task_dlq`).
3. **`web` (`Dockerfile` — non-root user `gerege`):**
   - Runs `uvicorn main:app --host 0.0.0.0 --port 8000 --workers 2 --no-proxy-headers`.
   - Enforces `ENV=production`, `STRICT_SECURITY=1`, `WEBHOOK_FAIL_CLOSED=1`, `STRICT_QPAY_VERIFICATION=1`, and `DISABLE_INLINE_SCHEDULER=1`.
4. **`worker` (`Dockerfile` — non-root user `gerege`):**
   - Runs `python worker.py` in a dedicated container to process background jobs, scheduled follow-ups, daily executive digests, and automated database backups.

### 1.1 Client IP and `TRUSTED_PROXIES` (E-02 Phase 3)

Rate limiting keys on the client IP, so "which IP is the client" is a security decision.

**There is no reverse proxy in this topology.** The `web` service publishes port 8000
directly, so the TCP peer is always the real client and `TRUSTED_PROXIES` stays **empty**.
An empty value means no forwarding header is believed, which is the intended default.

`uvicorn` is started with `--no-proxy-headers`. This is load-bearing: with uvicorn's
default the framework rewrites `scope["client"]` from `X-Forwarded-For` for any peer it
trusts (default `127.0.0.1,::1`), and it does not validate that the value is an IP
address. Disabling it makes `scope["client"]` the actual socket peer, and
`core.rate_limit.resolve_client_ip()` the single authority on forwarding.

| Situation | `TRUSTED_PROXIES` | Client identity |
|---|---|---|
| Direct exposure (this compose file) | *(empty)* | the socket peer |
| Behind a proxy you control | that proxy's address/CIDR | first untrusted hop in `X-Forwarded-For`, walked right-to-left |

Rules enforced in code:

* Empty or unset → trust nothing. A missing configuration is never read as "trust all".
* `*`, `0.0.0.0/0` and `::/0` are rejected, because they disable the policy.
* An unparseable entry is dropped and logged; trust is never widened to compensate.
* `X-Real-IP` and RFC 7239 `Forwarded` are **not** supported. Adding them needs its own
  trust validation and tests; silently falling back to them is how a hardened resolver
  becomes bypassable again.
* Headers over 1 KB or beyond 15 hops are rejected and the socket peer is used.
* Every hop must parse as an IP address; otherwise the walk aborts and the peer is used.
* An empty or whitespace-only entry counts as malformed, exactly like `not-an-ip`. A chain
  such as `", 1.2.3.4"`, `"1.2.3.4, "` or `"1.2.3.4,,10.0.0.1"` is rejected outright and
  the socket peer becomes the identity. Malformed entries are never skipped.

**If you add a proxy, list the proxy's addresses — never the clients'.** Listing clients
would let them rotate their own budget; listing nothing would collapse all users onto the
proxy's address and lock everyone out together.

---

## 2. Liveness & Readiness Probes

| Endpoint | Purpose | Checks Performed | HTTP Status |
|----------|---------|------------------|-------------|
| `GET /api/health` | Liveness Probe | Verifies process event loop responsiveness and reports engine/queue mode + uptime | `200 OK` |
| `GET /api/ready` | Readiness Probe | Executes `SELECT 1` against primary DB (`PostgreSQL`/`SQLite`) and `PING` against Redis when `REDIS_URL` is configured | `200 OK` when ready, `503 Service Unavailable` if DB or required Redis is down |

---

## 3. Vercel Serverless Constraints (`vercel.json` & `api/index.py`)

- When deployed to Vercel Serverless (`api/index.py`), the filesystem is ephemeral (`read-only` outside `/tmp`) and background loops (`worker.py`) do not persist between requests.
- **Required Configuration for Vercel:**
  1. Set `DATABASE_URL` to a managed PostgreSQL instance (e.g., Neon, Supabase, AWS RDS). Never rely on local SQLite on Vercel.
  2. Set `REDIS_URL` to a managed Redis instance (e.g., Upstash) and run `worker.py` on a persistent container host (Railway, Render, Fly.io, or VPS).
  3. Configure all secrets (`ADMIN_PASSWORD`, `GEMINI_API_KEY`, `META_APP_SECRET`, `TELEGRAM_WEBHOOK_SECRET`) via Vercel Environment Variables.

---

## 4. Rollback & Incident Recovery Procedure

1. **Pre-Deploy Snapshot:**
   ```bash
   python -c "from core import backup_service; print(backup_service.create_backup(label='pre_deploy'))"
   ```
2. **Application Rollback:**
   ```bash
   git checkout <previous-known-good-commit>
   docker compose -f docker-compose.prod.yml up -d --build
   ```
3. **Database Rollback (if schema/data regression occurred):**
   ```bash
   python -c "from core import backup_service; print(backup_service.restore_backup('<pre_deploy_backup_filename>'))"
   ```
