# System Architecture — Gerege AI Agent & Multi-Tenant CRM

## 1. High-Level Topology

```
[Web Widget / Messenger / Instagram / Telegram / Voice]
                          │
                          ▼
        [FastAPI Web Tier (main.py + routers/)]
         ├─ Auth & 7-Role RBAC (`core/security.py`)
         ├─ Telemetry & Security Headers (`core/monitoring.py`)
         ├─ Multi-Provider AI Router (`agent.py`, `core/ai_router.py`)
         └─ Domain Repositories (`core/repositories.py`)
                          │
        ┌─────────────────┴─────────────────┐
        ▼                                   ▼
[Primary Database]                 [Redis 7 + Task Queue]
 (`core/db_engine.py`,              (`core/task_queue.py`)
  PostgreSQL 16 / SQLite WAL)               │
                                            ▼
                                 [Standalone Worker Process]
                                      (`worker.py`)
                                  ├─ Outbound Meta/Telegram
                                  ├─ Broadcast Campaigns
                                  ├─ 08:30 Executive Reports
                                  ├─ 2h Appointment Reminders
                                  └─ 03:00 Automated Backups
```

## 2. Core Architectural Components

| Layer | Module | Responsibility |
|---|---|---|
| **HTTP API & Webhooks** | `main.py`, `routers/system_router.py` | FastAPI endpoints, request correlation (`X-Request-ID`), security headers, webhook signature verification, rate limiting, and 10MB upload bounds. |
| **Security & RBAC** | `core/security.py` | 7-role RBAC permission matrix, tenant scope enforcement (`enforce_tenant_scope`), fail-closed webhook HMAC verification, SSRF guard, and QPay amount/currency validation. |
| **Database Engine** | `core/db_engine.py`, `core/models.py`, `database.py` | Dual-mode SQLAlchemy engine (`postgresql+psycopg2` connection pool with `SAVEPOINT` statement isolation and `sqlite3` WAL compatibility). Zero drift across all 15 tables. |
| **AI Pipeline** | `agent.py`, `core/ai_router.py` | Gemini primary model + optional OpenAI/Anthropic fallback, prompt injection filter, `ToolExecutionGuard` (max 3 tool calls/turn, invoice amount bounds), `<thought>` tag stripping, secret redaction, and deterministic CI fallback. |
| **Task Queue & Worker** | `core/task_queue.py`, `worker.py` | Durable `task_jobs` table + Redis `LPUSH`/`RPOP` notification channel, auto-reconnect, atomic `locked_by` claiming, visibility timeout recovery (`recover_stale_jobs`), exponential backoff, and Dead-Letter Queue (`DEAD_LETTER`). |
| **Backup & Restore** | `core/backup_service.py` | Gzip-compressed SQLite online backup or PostgreSQL `pg_dump`, `.sha256` checksum, `.meta.json` manifest (`schema_version`, `table_counts`), pre-restore snapshot, and atomic restore (`psql --single-transaction -v ON_ERROR_STOP=1` or staging `PRAGMA integrity_check`). |
