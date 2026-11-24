# Deployment Runbook — Gerege AI Agent

## 1. Required Environment Variables (Production)

| Variable | Required | Description |
|---|---|---|
| `ENV` | Yes (`production`) | Enables strict production security checks and disables default admin fallback passwords. |
| `ADMIN_PASSWORD` | Yes | Strong Super-Admin password (validated via `secrets.compare_digest`). |
| `DATABASE_URL` | Recommended | `postgresql+psycopg2://user:pass@host:5432/dbname` (defaults to SQLite WAL if unset). |
| `REDIS_URL` | Recommended | `redis://host:6379/0` for low-latency worker notifications (gracefully degrades to DB polling if unreachable). |
| `GEMINI_API_KEY` | Yes (Live AI) | Google Gemini API key (`GEMINI_MODEL` defaults to `gemini-3.5-flash-lite`). |
| `META_APP_SECRET` | Yes (Meta Webhook) | Required for `X-Hub-Signature-256` HMAC-SHA256 verification. |
| `TELEGRAM_WEBHOOK_SECRET` | Yes (TG Webhook) | Required for `X-Telegram-Bot-Api-Secret-Token` verification. |
| `DISABLE_INLINE_SCHEDULER` | Yes (`1` with Worker) | Disables in-process web scheduler when running `python worker.py` as a separate container. |

## 2. Docker Compose Production Deployment

```bash
# 1. Build and start PostgreSQL 16, Redis 7, Web API, and Background Worker
docker compose up -d --build

# 2. Apply Alembic database migrations
docker compose exec web alembic upgrade head

# 3. Verify health and readiness probes
curl -fsS http://localhost:8000/api/health
curl -fsS http://localhost:8000/api/ready
```

## 3. Rollback Procedure

1. Identify the last known-good image tag and pre-deploy backup in `backups/`:
   ```bash
   python -c "from core import backup_service; print(backup_service.list_backups()[:3])"
   ```
2. If a database schema or data rollback is required, restore atomically from the verified backup archive:
   ```bash
   python -c "from core import backup_service; print(backup_service.restore_backup('<backup_filename>'))"
   ```
3. Redeploy the previous container image and verify `/api/ready` returns HTTP `200`.

### 3.1 How long a stop takes (measured)

`docker compose stop` / `docker compose up -d` sends `SIGTERM` and then waits
`stop_grace_period` before `SIGKILL`. Measured in Phase 40 against a disposable
PostgreSQL 16.2 and a live Redis:

| Process | `SIGTERM` behaviour | Measured |
|---|---|---|
| `web` (uvicorn) | in-flight request is completed, then exit | **0.17 s** with a request in flight |
| `worker`, idle | exits on the next event-loop check | **0.00 s** |
| `worker`, mid-batch | finishes the current `process_pending_jobs` batch first | **23.3 s** (25 handlers x 1 s) |

The worker only observes the shutdown event *between* ticks, and one tick awaits a
whole batch of 25 handlers. Docker's default grace is 10 s, so before Phase 40 every
redeploy during a busy batch ended in `SIGKILL`. `docker-compose.prod.yml` and
`docker-compose.staging.yml` now set `stop_grace_period: 60s` on `worker` (Phase 40,
F-40-C). Nothing is lost either way — the queue is at-least-once with a 300 s
visibility timeout — but a batch abandoned half-done is retried work.

If you raise `batch_size` in `worker.py` or add a handler slower than ~2 s, raise
`stop_grace_period` with it: the budget is `batch_size x per-handler time`.
