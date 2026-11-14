# Incident Response Runbook — Gerege AI Agent

## 1. Triage & Diagnostics

1. **Check Liveness & Readiness Probes**:
   - `GET /api/health` — Process liveness and integration configuration flags.
   - `GET /api/ready` — Verifies live Database connectivity (`SELECT 1`) and Task Queue backend status. Returns HTTP `503` if the primary database is unreachable.
2. **Inspect Telemetry & Recent Redacted Errors**:
   - `GET /api/admin/metrics` (Requires Admin Bearer token) — Returns `uptime_seconds`, `total_requests`, `total_errors`, `avg_latency_ms`, `status_counts`, `recent_errors` (with `X-Request-ID` and automatic secret redaction), `db_pool`, `queue`, and `disk_free_mb`.
3. **Inspect Background Queue & Dead-Letter Jobs**:
   - `GET /api/admin/queue/stats` — Counts of `pending`, `processing`, `completed`, `dead_letter`, and `redis_connected`.
   - `GET /api/admin/queue/failed` — Lists `DEAD_LETTER` and `FAILED` jobs with `last_error` and `attempts`.

## 2. Common Incident Playbooks

### Playbook A: Compromised Tenant or Admin Credential
1. Rotate `ADMIN_PASSWORD` / `GEMINI_API_KEY` / `META_APP_SECRET` in environment variables.
2. Revoke all active sessions for the affected tenant or admin:
   ```bash
   python -c "import database; print(database.revoke_all_page_sessions('<page_id>'))"
   ```
3. Review `GET /api/admin/audit-logs?page_id=<page_id>` to trace all actions performed by the session.

### Playbook B: Stuck `PROCESSING` Background Jobs (Worker Crash)
1. `worker.py` automatically runs `task_queue.recover_stale_jobs()` on every tick (default visibility timeout: 300s).
2. To trigger immediate recovery manually:
   ```bash
   python -c "from core.task_queue import task_queue; print('Recovered:', task_queue.recover_stale_jobs(stale_after_seconds=60))"
   ```

### Playbook C: AI Provider Outage (429 / 5xx)
1. `core/ai_router.py` automatically trips the per-provider `CircuitBreaker` after 5 consecutive failures (60s cooldown) and falls back to secondary providers (if `AI_FALLBACK_ENABLED=1`) or deterministic registration/payment handling.
