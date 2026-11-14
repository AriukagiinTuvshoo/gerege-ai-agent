# Phase 2 — Database Architecture & PostgreSQL Migration (`POSTGRESQL_MIGRATION.md`)

**Status:** Completed (P0)  
**Primary Modules:** [`core/db_engine.py`](../../core/db_engine.py), [`core/models.py`](../../core/models.py), [`database.py`](../../database.py), [`migrations/versions/0001_initial_enterprise_schema.py`](../../migrations/versions/0001_initial_enterprise_schema.py), [`scripts/migrate_sqlite_to_postgres.py`](../../scripts/migrate_sqlite_to_postgres.py)

---

## 1. Elimination of Split-Brain Database Architecture

Previously, `core/db_engine.py` defined a SQLAlchemy engine while `database.py` and `core/task_queue.py` opened raw `sqlite3.connect(DB_PATH)` connections directly.

### Unified Authoritative Engine (`core/db_engine.py`)
- All 60+ database operations in `database.py` and `core/task_queue.py` now route through `database.get_connection()` -> `core.db_engine.get_db_connection()`.
- **When `DATABASE_URL` points to PostgreSQL (`postgresql://...`):**
  - Uses a pooled SQLAlchemy engine (`pool_size=10`, `max_overflow=20`, `pool_pre_ping=True`, `pool_recycle=1800`).
  - Wraps DBAPI connections in `PostgresCompatConnection` and `PostgresCompatCursor`, which transparently translate SQLite-style `?` placeholders, `INSERT OR IGNORE` (`ON CONFLICT DO NOTHING`), `datetime('now', ...)` intervals, and `cursor.lastrowid` (`RETURNING id`) while returning `CompatRow` objects supporting both dict-key (`row["page_id"]`) and positional (`row[0]`) indexing.
- **When running with SQLite (`sqlite:///...` or local `DB_PATH`):**
  - Enforces `PRAGMA journal_mode=WAL`, `PRAGMA synchronous=NORMAL`, `PRAGMA foreign_keys=ON`, and `timeout=20.0`.

---

## 2. Unified Authoritative Schema (`core/models.py` & `database.py`)

All 15 tables in `core/models.py`, `database.py`, and Alembic migration `0001_initial_enterprise_schema.py` have identical table and column names:

| # | Table Name | Primary Key | Tenant Key | Key Indexes / Unique Constraints |
|---|---|---|---|---|
| 1 | `pages` | `page_id` | `page_id` | `ix_pages_client_username`, `ix_pages_client_magic_token` |
| 2 | `registrations` | `id` | `page_id` | `idx_reg_page (page_id, created_at)` |
| 3 | `messages` | `id` | `page_id` | `idx_msg_sender`, `idx_msg_page` |
| 4 | `session_states` | `sender_id` | `page_id` | `ix_session_states_page_id` |
| 5 | `sessions` | `session_token` | `page_id` | `ix_sessions_page_id` |
| 6 | `user_memories` | `id` | `page_id` | `uq_user_memory_page_user (page_id, user_id)` |
| 7 | `invoices` | `id` | `page_id` | `UNIQUE(invoice_id)`, `idx_inv_page (page_id, status)` |
| 8 | `cargo_packages` | `id` | `page_id` | `uq_cargo_page_code (page_id, tracking_code)` |
| 9 | `automated_rules` | `id` | `page_id` | `uq_rule_page_type (page_id, rule_type)` |
| 10 | `marketing_campaigns` | `id` | `page_id` | `ix_marketing_campaigns_page_id` |
| 11 | `sent_followups` | `id` | `page_id` | `uq_sent_followup (page_id, sender_id, rule_type, reference_id)` |
| 12 | `appointments` | `id` | `page_id` | `idx_appt_page_date`, `idx_appt_reminder` |
| 13 | `notification_locks` | `lock_key` | `page_id` | PK on `lock_key` |
| 14 | `task_jobs` | `job_id` | `page_id` | `idx_task_jobs_status (status, created_at)` |
| 15 | `audit_logs` | `id` | `page_id` | `idx_audit_page_time (page_id, created_at)` |

---

## 3. Alembic Migration Operations

Run migrations against PostgreSQL or SQLite:

```bash
# Upgrade to latest schema
alembic upgrade head

# Check current migration revision
alembic current

# Downgrade one revision (test/staging only)
alembic downgrade -1
```

---

## 4. Safe SQLite-to-PostgreSQL Data Migration (`scripts/migrate_sqlite_to_postgres.py`)

### 4.1 Dry-Run Inspection (Safe Snapshot Verification)
```bash
python scripts/migrate_sqlite_to_postgres.py --sqlite-path registrations.db --dry-run --report backups/migration_dry_run.json
```

### 4.2 Live Migration to PostgreSQL
```bash
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-path registrations.db \
  --postgres-url "postgresql://gerege:STRONG_PASS@localhost:5432/gerege_db" \
  --report backups/migration_report.json
```

### 4.3 Safety Guarantees
1. **Consistent Snapshot:** Uses `sqlite3.backup()` to copy `registrations.db` to an isolated temporary snapshot before reading, avoiding any locks on live traffic.
2. **Idempotent Upserts:** Uses `ON CONFLICT (...) DO NOTHING` and advances PostgreSQL `SERIAL` sequences (`setval(pg_get_serial_sequence(...))`) so re-running never duplicates records.
3. **Automated Verification:** Compares source vs. target row counts across all 15 tables and verifies financial sums (`SUM(amount)` on `invoices`, `SUM(amount) WHERE status='PAID'`, and `SUM(price_amount)` on `cargo_packages`).
