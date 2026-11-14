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
   - Runs `uvicorn main:app --host 0.0.0.0 --port 8000 --workers 2`.
   - Enforces `ENV=production`, `STRICT_SECURITY=1`, `WEBHOOK_FAIL_CLOSED=1`, `STRICT_QPAY_VERIFICATION=1`, and `DISABLE_INLINE_SCHEDULER=1`.
4. **`worker` (`Dockerfile` — non-root user `gerege`):**
   - Runs `python worker.py` in a dedicated container to process background jobs, scheduled follow-ups, daily executive digests, and automated database backups.

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
