import os
import uuid
import json
import time
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
    Phase 3: Production Redis & Database Persistent Task Queue (At-Least-Once + Idempotent Execution).
    - Uses `database.get_connection()` (supports both PostgreSQL and SQLite WAL).
    - When `REDIS_URL` is configured and reachable, pushes job IDs to `gerege:task_queue` (`LPUSH`)
      and consumes via `RPOP`, while persisting durable job state in `task_jobs`.
    - Automatically reconnects to Redis if Redis restarts, without losing jobs (durable DB backing).
    - Implements atomic job claiming (`locked_by`, `locked_at`), visibility timeout & stale `PROCESSING`
      recovery, explicit job acknowledgment (`ack_job`), exponential backoff (`next_run_at`),
      per-task execution timeouts (`asyncio.wait_for`), and Dead-Letter Queue (`DEAD_LETTER`).
    """

    def __init__(self, worker_id: Optional[str] = None):
        self.redis_url = os.getenv("REDIS_URL", "").strip()
        self._redis = None
        self._last_redis_attempt = 0.0
        self.worker_id = worker_id or f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"
        self.handlers: Dict[str, Callable[[Dict[str, Any]], Awaitable[Any]]] = {}
        self._connect_redis()

    def _connect_redis(self) -> None:
        self.redis_url = os.getenv("REDIS_URL", "").strip()
        if not self.redis_url:
            self._redis = None
            return
        self._last_redis_attempt = time.monotonic()
        try:
            import redis  # type: ignore

            client = redis.from_url(self.redis_url, decode_responses=True, socket_timeout=3.0)
            client.ping()
            self._redis = client
            logger.info("TaskQueue connected to Redis backend.")
        except Exception as e:
            logger.warning(f"Redis unavailable ({e}), using durable DB-backed task_jobs queue.")
            self._redis = None

    def _get_redis(self):
        """Return active Redis client, attempting periodic auto-reconnect if REDIS_URL is configured."""
        if self._redis is not None:
            try:
                self._redis.ping()
                return self._redis
            except Exception as e:
                logger.warning(f"Redis connection lost ({e}), falling back to DB and scheduling reconnect.")
                self._redis = None
        if self.redis_url and (time.monotonic() - self._last_redis_attempt) > 5.0:
            self._connect_redis()
        return self._redis

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

        conn = None
        cur = None
        try:
            conn = database.get_connection()
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT idempotency_key, status FROM task_jobs WHERE idempotency_key = ?", (job_id,))
            existing = cur.fetchone()
            if existing:
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
            if "unique" in str(exc).lower() or "duplicate" in str(exc).lower() or isinstance(exc, sqlite3.IntegrityError):
                return {"queued": False, "duplicate": True, "job_id": job_id}
            raise
        finally:
            if cur is not None:
                try:
                    cur.close()
                except Exception:
                    pass
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

        r_client = self._get_redis()
        if r_client and delay_seconds <= 0:
            try:
                r_client.lpush(
                    REDIS_QUEUE_KEY,
                    json.dumps({"job_id": job_id, "task_name": task_name, "page_id": target_page}),
                )
            except Exception as e:
                logger.warning(f"Redis lpush warning (job persisted in DB): {e}")
                self._redis = None

        return {"queued": True, "duplicate": False, "job_id": job_id, "status": "PENDING"}

    def _claim_job_atomically(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Atomically transition a single job from PENDING -> PROCESSING so two workers cannot claim it."""
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = None
        cur = None
        try:
            conn = database.get_connection()
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
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
                return None

            cur.execute("SELECT * FROM task_jobs WHERE idempotency_key = ?", (job_id,))
            row = cur.fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Atomic job claim error ({job_id}): {e}")
            return None
        finally:
            if cur is not None:
                try:
                    cur.close()
                except Exception:
                    pass
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def ack_job(self, job_id: str) -> bool:
        """Explicitly acknowledge job completion (PROCESSING -> COMPLETED)."""
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = None
        cur = None
        try:
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
                (now_str, job_id),
            )
            changed = (cur.rowcount or 0) > 0
            conn.commit()
            return changed
        finally:
            if cur is not None:
                try:
                    cur.close()
                except Exception:
                    pass
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def fail_job(self, job: Dict[str, Any], err_msg: str) -> str:
        """Record job failure, schedule exponential backoff retry or move to DEAD_LETTER."""
        job_id = str(job.get("idempotency_key") or "")
        task_name = str(job.get("task_name") or "")
        attempts = int(job.get("attempts") or 1)
        max_retries = int(job.get("max_retries") or 3)
        is_exhausted = attempts >= max_retries
        new_status = "DEAD_LETTER" if is_exhausted else "PENDING"
        backoff_sec = min(3600, 2 ** attempts)
        next_run = (datetime.now() + timedelta(seconds=backoff_sec)).strftime("%Y-%m-%d %H:%M:%S")
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = None
        cur = None
        try:
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
                (new_status, err_msg, next_run, now_str, job_id),
            )
            conn.commit()
        finally:
            if cur is not None:
                try:
                    cur.close()
                except Exception:
                    pass
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

        r_client = self._get_redis()
        if is_exhausted and r_client:
            try:
                r_client.lpush(
                    REDIS_DLQ_KEY,
                    json.dumps({"job_id": job_id, "task_name": task_name, "error": err_msg}),
                )
            except Exception:
                self._redis = None

        return new_status

    def recover_stale_jobs(self, stale_after_seconds: int = 300) -> int:
        """
        Recover jobs stuck in PROCESSING state after a worker crash or visibility timeout.
        Jobs with remaining attempts return to PENDING; exhausted jobs move to DEAD_LETTER.
        """
        cutoff = (datetime.now() - timedelta(seconds=max(1, int(stale_after_seconds)))).strftime("%Y-%m-%d %H:%M:%S")
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = None
        cur = None
        recovered = 0
        try:
            conn = database.get_connection()
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                """
                SELECT idempotency_key, attempts, max_retries
                FROM task_jobs
                WHERE status = 'PROCESSING' AND locked_at IS NOT NULL AND locked_at <= ?
                """,
                (cutoff,),
            )
            stale_rows = [dict(r) for r in cur.fetchall()]
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
        finally:
            if cur is not None:
                try:
                    cur.close()
                except Exception:
                    pass
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
        return recovered

    async def process_pending_jobs(self, batch_size: int = 10) -> int:
        """
        Process up to `batch_size` ready jobs.
        1. Recovers stale PROCESSING jobs.
        2. Drains ready job IDs from Redis (`RPOP`) if Redis is connected, plus any DB-ready PENDING jobs.
        3. Claims each job atomically, enforces `timeout_seconds`, and acknowledges or applies backoff/DLQ.
        """
        self.recover_stale_jobs()

        candidate_ids: List[str] = []
        r_client = self._get_redis()
        if r_client:
            try:
                for _ in range(batch_size):
                    raw_item = r_client.rpop(REDIS_QUEUE_KEY)
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
                logger.warning(f"Redis rpop warning (falling back to DB poll): {e}")
                self._redis = None

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = None
        cur = None
        try:
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
        finally:
            if cur is not None:
                try:
                    cur.close()
                except Exception:
                    pass
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

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
                no_h_conn = None
                no_h_cur = None
                try:
                    no_h_conn = database.get_connection()
                    no_h_cur = no_h_conn.cursor()
                    no_h_cur.execute(
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
                    no_h_conn.commit()
                finally:
                    if no_h_cur is not None:
                        try:
                            no_h_cur.close()
                        except Exception:
                            pass
                    if no_h_conn is not None:
                        try:
                            no_h_conn.close()
                        except Exception:
                            pass
                continue

            timeout_sec = max(1, int(job.get("timeout_seconds") or 60))
            try:
                payload = json.loads(job.get("payload_json") or "{}")
                await asyncio.wait_for(handler(payload), timeout=float(timeout_sec))
                self.ack_job(job_id)
                processed += 1
            except Exception as exc:
                err_msg = f"{type(exc).__name__}: {exc}"
                logger.error(f"Task job {job_id} ({task_name}) failed: {err_msg}")
                self.fail_job(job, err_msg)

        return processed

    def get_queue_stats(self) -> Dict[str, Any]:
        r_client = self._get_redis()
        stats = {
            "backend": "redis+db" if r_client else "db",
            "redis_connected": bool(r_client),
            "worker_id": self.worker_id,
            "pending": 0,
            "processing": 0,
            "completed": 0,
            "dead_letter": 0,
            "failed": 0,
        }
        conn = None
        cur = None
        try:
            conn = database.get_connection()
            cur = conn.cursor()
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
        finally:
            if cur is not None:
                try:
                    cur.close()
                except Exception:
                    pass
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
        return stats

    def list_failed_jobs(self, limit: int = 50) -> List[Dict[str, Any]]:
        conn = None
        cur = None
        rows = []
        try:
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
        finally:
            if cur is not None:
                try:
                    cur.close()
                except Exception:
                    pass
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
        return rows


task_queue = TaskQueue()


def get_queue_stats() -> Dict[str, Any]:
    return task_queue.get_queue_stats()


def list_failed_jobs(limit: int = 50) -> List[Dict[str, Any]]:
    return task_queue.list_failed_jobs(limit=limit)
