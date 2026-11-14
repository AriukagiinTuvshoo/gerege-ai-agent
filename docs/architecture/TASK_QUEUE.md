# Phase 3 — Production Task Queue & Worker Architecture (`TASK_QUEUE.md`)

**Status:** Completed (P0)  
**Primary Modules:** [`core/task_queue.py`](../../core/task_queue.py), [`worker.py`](../../worker.py), [`routers/system_router.py`](../../routers/system_router.py)

---

## 1. Architecture Overview

`core/task_queue.py` implements a dual-layer persistent task queue (`TaskQueue`):
1. **Durable Database State (`task_jobs` table):** Every enqueued job is persisted via `database.get_connection()` (supporting both PostgreSQL and SQLite WAL) with its `job_id`, `task_type`, `page_id`, `payload_json`, `status`, `attempts`, `max_attempts`, `timeout_seconds`, `next_run_at`, `locked_by`, `locked_at`, and `last_error`.
2. **Real Redis Fast-Path (`REDIS_URL`):** When Redis is configured and reachable, `enqueue()` pushes `{job_id, task_type, page_id}` to `gerege:task_queue` (`LPUSH`), and `process_pending_jobs()` pops ready job IDs from `gerege:task_queue` (`RPOP`) before reconciling with DB-ready jobs. Exhausted jobs are pushed to `gerege:task_dlq` (`DEAD_LETTER`).

---

## 2. Atomic Claiming & Concurrency Safety

To guarantee that multiple worker processes never execute the same job concurrently:
- `_claim_job_atomically(job_id)` runs an atomic conditional update:
  ```sql
  UPDATE task_jobs
  SET status = 'PROCESSING',
      attempts = COALESCE(attempts, 0) + 1,
      locked_by = :worker_id,
      locked_at = :now,
      updated_at = :now
  WHERE job_id = :job_id
    AND status = 'PENDING'
    AND COALESCE(attempts, 0) < COALESCE(max_attempts, 3)
    AND (next_run_at IS NULL OR next_run_at <= :now)
  ```
- Only the worker whose `UPDATE` affects 1 row (`cur.rowcount == 1`) proceeds to execute the task handler.

---

## 3. Retry Policy, Exponential Backoff, Timeouts & Dead-Letter Queue

- **Execution Timeout:** Every task handler runs inside `asyncio.wait_for(handler(payload), timeout=timeout_seconds)` (default `60s`).
- **Exponential Backoff:** On transient failure where `attempts < max_attempts`, the job returns to `PENDING` with `next_run_at = now + min(3600, 2^attempts)` seconds.
- **Dead-Letter Queue (`DEAD_LETTER`):** When `attempts >= max_attempts`, the job transitions to `status = 'DEAD_LETTER'`, its error is recorded in `last_error`, and its metadata is pushed to Redis `gerege:task_dlq`.
- **Stale Job Recovery:** `recover_stale_jobs(stale_after_seconds=300)` automatically detects jobs stuck in `PROCESSING` after a worker crash (`locked_at < now - 300s`) and either requeues them (`PENDING`) or moves them to `DEAD_LETTER`.

---

## 4. Dedicated Worker & Distributed Scheduler Locks (`worker.py`)

- **Separation of Concerns:** The FastAPI web app (`main.py`) only starts the in-process scheduler when `RUN_EMBEDDED_SCHEDULER=1`. In production (`docker-compose.prod.yml`), `worker.py` runs as a dedicated container.
- **Graceful Shutdown:** `worker.py` registers `SIGINT` and `SIGTERM` signal handlers so in-flight `run_worker_tick()` calls complete cleanly before exit.
- **Distributed Locks with TTL:** `database.claim_notification_lock(lock_key, page_id, channel, ttl_seconds=...)` stores `expires_at` in `notification_locks` so expired locks are automatically reclaimed if a worker terminates unexpectedly.
