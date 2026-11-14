import os
import uuid
import json
import socket
import sqlite3
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Callable, Awaitable

import database

logger = logging.getLogger("core.task_queue")

REDIS_QUEUE_KEY = "gerege:task_queue"
REDIS_DLQ_KEY = "gerege:task_dlq"


class TaskQueue:
    """
    Phase 3 (P0): Production Redis & Database Persistent Task Queue.
    - Uses `database.get_connection()` (supports both PostgreSQL and SQLite WAL).
    - When `REDIS_URL` is configured and reachable, pushes job IDs to `gerege:task_queue` (`LPUSH`)
      and consumes via `RPOP`, while persisting durable job state in `task_jobs`.
    - Implements atomic job claiming (`locked_by`, `locked_at`), exponential backoff (`next_run_at`),
      per-task execution timeouts (`asyncio.wait_for`), stale `PROCESSING` recovery, and Dead-Letter Queue (`DEAD_LETTER`).
    """

    def __init__(self, worker_id: Optional[str] = None):
        self.redis_url = os.getenv("REDIS_URL", "").strip()
        self._redis = None
        self.worker_id = worker_id or f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"
        self.handlers: Dict[str, Callable[[Dict[str, Any]], Awaitable[Any]]] = {}
        self._connect_redis()

    def _connect_redis(self) -> None:
        if not self.redis_url:
            self._redis = None
            return
        try:
            import redis  # type: ignore

            self._redis = redis.from_url(self.redis_url, decode_responses=True, socket_timeout=5.0)
            self._redis.ping()
            logger.info("TaskQueue connected to Redis backend.")
        except Exception as e:
            logger.warning(f"Redis unavailable ({e}), using durable DB-backed task_jobs queue.")
            self._redis = None

    def register_handler(self, task_name: str, handler: Callable[[Dict[str, Any]], Awaitable[Any]]) -> None:
        self.handlers[task_name] = handler

    def enqueue(
        self,
        task_name: str,
        payload: Dict[str, Any],
        idempotency_key: Optional[str] = None,
        max_retries: int = 3,
        page_id: Optional[str] = None,
        timeout_seconds: int = 60,
        delay_seconds: int = 0,
    ) -> Dict[str, Any]:
        """Даалгаврыг дараалалд оруулах (Idempotency key давхардвал дахин оруулахгүй)"""
        job_id = str(idempotency_key).strip() if idempotency_key else f"job_{uuid.uuid4().hex[:16]}"
        target_page = str(page_id or (payload or {}).get("page_id") or database.DEFAULT_PAGE_ID)
        now_dt = datetime.now()
        now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")
        next_run_str = (
            (now_dt + timedelta(seconds=max(0, int(delay_seconds)))).strftime("%Y-%m-%d %H:%M:%S")
            if delay_seconds > 0
            else now_str
        )

        conn = database.get_connection()
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        try:
            cur.execute("SELECT idempotency_key, status FROM task_jobs WHERE idempotency_key = ?", (job_id,))
            existing = cur.fetchone()
            if existing:
                conn.close()
                return {
                    "queued": False,
                    "duplicate": True,
                    "job_id": existing["idempotency_key"],
                    "status": existing["status"],
                }

            payload_str = json.dumps(payload or {}, ensure_ascii=False)
            cur.execute(
                """
                INSERT INTO task_jobs (
                    idempotency_key, task_name, payload_json, status,
                    attempts, max_retries, timeout_seconds, next_run_at,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, 'PENDING', 0, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    task_name,
                    payload_str,
                    max(1, int(max_retries)),
                    max(1, int(timeout_seconds)),
                    next_run_str,
                    now_str,
                    now_str,
                ),
            )
            conn.commit()
        except Exception as exc:
            conn.close()
            if "unique" in str(exc).lower() or "duplicate" in str(exc).lower() or isinstance(exc, sqlite3.IntegrityError):
                return {"queued": False, "duplicate": True, "job_id": job_id}
            raise
        conn.close()

        if self._redis and delay_seconds <= 0:
            try:
                self._redis.lpush(
                    REDIS_QUEUE_KEY,
                    json.dumps({"job_id": job_id, "task_name": task_name, "page_id": target_page}),
                )
            except Exception as e:
                logger.warning(f"Redis lpush warning: {e}")

        return {"queued": True, "duplicate": False, "job_id": job_id, "status": "PENDING"}

    def _claim_job_atomically(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Atomically transition a single job from PENDING -> PROCESSING so two workers cannot claim it."""
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = database.get_connection()
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        try:
            cur.execute(
                """
                UPDATE task_jobs
                SET status = 'PROCESSING',
                    attempts = COALESCE(attempts, 0) + 1,
                    locked_by = ?,
                    locked_at = ?,
                    updated_at = ?
                WHERE idempotency_key = ?
                  AND status = 'PENDING'
                  AND COALESCE(attempts, 0) < COALESCE(max_retries, 3)
                  AND (next_run_at IS NULL OR next_run_at <= ?)
                """,
                (self.worker_id, now_str, now_str, job_id, now_str),
            )
            claimed = cur.rowcount
            conn.commit()
            if not claimed or claimed <= 0:
                conn.close()
                return None

            cur.execute("SELECT * FROM task_jobs WHERE idempotency_key = ?", (job_id,))
            row = cur.fetchone()
            conn.close()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Atomic job claim error ({job_id}): {e}")
            conn.close()
            return None

    def recover_stale_jobs(self, stale_after_seconds: int = 300) -> int:
        """
        Recover jobs stuck in PROCESSING state after a worker crash or timeout.
        Jobs with remaining attempts return to PENDING; exhausted jobs move to DEAD_LETTER.
        """
        cutoff = (datetime.now() - timedelta(seconds=max(10, int(stale_after_seconds)))).strftime("%Y-%m-%d %H:%M:%S")
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = database.get_connection()
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """
            SELECT idempotency_key, attempts, max_retries
            FROM task_jobs
            WHERE status = 'PROCESSING' AND locked_at IS NOT NULL AND locked_at < ?
            """,
            (cutoff,),
        )
        stale_rows = [dict(r) for r in cur.fetchall()]
        recovered = 0
        for r in stale_rows:
            jid = r["idempotency_key"]
            att = int(r.get("attempts") or 1)
            max_att = int(r.get("max_retries") or 3)
            new_status = "DEAD_LETTER" if att >= max_att else "PENDING"
            cur.execute(
                """
                UPDATE task_jobs
                SET status = ?,
                    locked_by = NULL,
                    locked_at = NULL,
                    last_error = COALESCE(last_error, '') || ' [Recovered from stale PROCESSING]',
                    updated_at = ?
                WHERE idempotency_key = ? AND status = 'PROCESSING'
                """,
                (new_status, now_str, jid),
            )
            if cur.rowcount and cur.rowcount > 0:
                recovered += 1
        conn.commit()
        conn.close()
        return recovered

    async def process_pending_jobs(self, batch_size: int = 10) -> int:
        """
        Process up to `batch_size` ready jobs.
        1. Recovers stale PROCESSING jobs.
        2. Drains ready job IDs from Redis (`RPOP`) if Redis is connected, plus any DB-ready PENDING jobs.
        3. Claims each job atomically, enforces `timeout_seconds`, and applies exponential backoff or DLQ on failure.
        """
        self.recover_stale_jobs()

        candidate_ids: List[str] = []
        if self._redis:
            try:
                for _ in range(batch_size):
                    raw_item = self._redis.rpop(REDIS_QUEUE_KEY)
                    if not raw_item:
                        break
                    try:
                        parsed = json.loads(raw_item)
                        jid = parsed.get("job_id")
                        if jid and jid not in candidate_ids:
                            candidate_ids.append(str(jid))
                    except Exception:
                        pass
            except Exception as e:
                logger.warning(f"Redis rpop warning: {e}")

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = database.get_connection()
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """
            SELECT idempotency_key FROM task_jobs
            WHERE status = 'PENDING'
              AND idempotency_key IS NOT NULL
              AND COALESCE(attempts, 0) < COALESCE(max_retries, 3)
              AND (next_run_at IS NULL OR next_run_at <= ?)
            ORDER BY created_at ASC
            LIMIT ?
            """,
            (now_str, batch_size),
        )
        for r in cur.fetchall():
            jid = r["idempotency_key"]
            if jid and jid not in candidate_ids:
                candidate_ids.append(jid)
        conn.close()

        processed = 0
        for job_id in candidate_ids[:batch_size]:
            job = self._claim_job_atomically(job_id)
            if not job:
                continue

            task_name = job.get("task_name") or ""
            handler = self.handlers.get(task_name)
            now_done = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if not handler:
                logger.warning(f"No handler registered for task '{task_name}' (job_id={job_id})")
                conn = database.get_connection()
                cur = conn.cursor()
                cur.execute(
                    """
                    UPDATE task_jobs
                    SET status = 'PENDING',
                        attempts = CASE WHEN attempts > 0 THEN attempts - 1 ELSE 0 END,
                        locked_by = NULL,
                        locked_at = NULL,
                        last_error = ?,
                        updated_at = ?
                    WHERE idempotency_key = ?
                    """,
                    (f"No handler registered for {task_name}", now_done, job_id),
                )
                conn.commit()
                conn.close()
                continue

            timeout_sec = max(1, int(job.get("timeout_seconds") or 60))
            try:
                payload = json.loads(job.get("payload_json") or "{}")
                await asyncio.wait_for(handler(payload), timeout=float(timeout_sec))
                conn = database.get_connection()
                cur = conn.cursor()
                cur.execute(
                    """
                    UPDATE task_jobs
                    SET status = 'COMPLETED',
                        locked_by = NULL,
                        locked_at = NULL,
                        updated_at = ?
                    WHERE idempotency_key = ?
                    """,
                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), job_id),
                )
                conn.commit()
                conn.close()
                processed += 1
            except Exception as exc:
                err_msg = f"{type(exc).__name__}: {exc}"
                logger.error(f"Task job {job_id} ({task_name}) failed: {err_msg}")
                attempts = int(job.get("attempts") or 1)
                max_retries = int(job.get("max_retries") or 3)
                is_exhausted = attempts >= max_retries
                new_status = "DEAD_LETTER" if is_exhausted else "PENDING"
                backoff_sec = min(3600, 2 ** attempts)
                next_run = (datetime.now() + timedelta(seconds=backoff_sec)).strftime("%Y-%m-%d %H:%M:%S")

                conn = database.get_connection()
                cur = conn.cursor()
                cur.execute(
                    """
                    UPDATE task_jobs
                    SET status = ?,
                        last_error = ?,
                        next_run_at = ?,
                        locked_by = NULL,
                        locked_at = NULL,
                        updated_at = ?
                    WHERE idempotency_key = ?
                    """,
                    (new_status, err_msg, next_run, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), job_id),
                )
                conn.commit()
                conn.close()

                if is_exhausted and self._redis:
                    try:
                        self._redis.lpush(
                            REDIS_DLQ_KEY,
                            json.dumps({"job_id": job_id, "task_name": task_name, "error": err_msg}),
                        )
                    except Exception:
                        pass

        return processed

    def get_queue_stats(self) -> Dict[str, Any]:
        conn = database.get_connection()
        cur = conn.cursor()
        stats = {
            "backend": "redis+db" if self._redis else "db",
            "redis_connected": bool(self._redis),
            "pending": 0,
            "processing": 0,
            "completed": 0,
            "dead_letter": 0,
            "failed": 0,
        }
        try:
            cur.execute("SELECT status, COUNT(*) FROM task_jobs GROUP BY status")
            for row in cur.fetchall():
                st = str(row[0] or "").upper()
                cnt = int(row[1] or 0)
                if st == "PENDING":
                    stats["pending"] = cnt
                elif st == "PROCESSING":
                    stats["processing"] = cnt
                elif st == "COMPLETED":
                    stats["completed"] = cnt
                elif st == "DEAD_LETTER":
                    stats["dead_letter"] = cnt
                elif st == "FAILED":
                    stats["failed"] = cnt
        except Exception:
            pass
        conn.close()
        return stats

    def list_failed_jobs(self, limit: int = 50) -> List[Dict[str, Any]]:
        conn = database.get_connection()
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """
            SELECT * FROM task_jobs
            WHERE status IN ('DEAD_LETTER', 'FAILED')
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows


task_queue = TaskQueue()


def get_queue_stats() -> Dict[str, Any]:
    return task_queue.get_queue_stats()


def list_failed_jobs(limit: int = 50) -> List[Dict[str, Any]]:
    return task_queue.list_failed_jobs(limit=limit)
