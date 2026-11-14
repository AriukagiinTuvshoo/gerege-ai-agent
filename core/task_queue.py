import os
import json
import sqlite3
import logging
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional, Callable, Awaitable

import database

logger = logging.getLogger("core.task_queue")


class TaskQueue:
    """
    Phase 4: Redis болон SQLite Persistent Task Queue.
    - REDIS_URL тохируулсан бөгөөд redis сан суусан бол Redis жагсаалт (LPUSH / BRPOP) ашиглана.
    - Бусад үед SQLite `task_jobs` хүснэгт дээр тулгуурласан атомик, idempotency_key хамгаалалттай дараалал ашиглана.
    """

    def __init__(self):
        self.redis_url = os.getenv("REDIS_URL", "").strip()
        self._redis = None
        self.handlers: Dict[str, Callable[[Dict[str, Any]], Awaitable[Any]]] = {}
        if self.redis_url:
            try:
                import redis  # type: ignore

                self._redis = redis.from_url(self.redis_url, decode_responses=True)
                self._redis.ping()
                logger.info("TaskQueue connected to Redis backend.")
            except Exception as e:
                logger.warning(f"Redis unavailable ({e}), falling back to persistent SQLite task_jobs queue.")
                self._redis = None

    def register_handler(self, task_name: str, handler: Callable[[Dict[str, Any]], Awaitable[Any]]) -> None:
        self.handlers[task_name] = handler

    def enqueue(
        self,
        task_name: str,
        payload: Dict[str, Any],
        idempotency_key: Optional[str] = None,
        max_retries: int = 3,
    ) -> Dict[str, Any]:
        """Даалгаврыг дараалалд оруулах (Idempotency key давхардвал дахин оруулахгүй)"""
        if idempotency_key:
            # Idempotency check in notification_locks / task_jobs
            conn = sqlite3.connect(database.DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT id, status FROM task_jobs WHERE idempotency_key = ?", (idempotency_key,))
            existing = cur.fetchone()
            conn.close()
            if existing:
                return {"queued": False, "duplicate": True, "job_id": existing[0], "status": existing[1]}

        payload_str = json.dumps(payload, ensure_ascii=False)
        conn = sqlite3.connect(database.DB_PATH)
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO task_jobs (idempotency_key, task_name, payload_json, status, max_retries)
                VALUES (?, ?, ?, 'PENDING', ?)
                """,
                (idempotency_key, task_name, payload_str, max_retries),
            )
            job_id = cur.lastrowid
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return {"queued": False, "duplicate": True}
        conn.close()

        if self._redis:
            try:
                self._redis.lpush("gerege:task_queue", json.dumps({"job_id": job_id, "task_name": task_name}))
            except Exception as e:
                logger.warning(f"Redis lpush warning: {e}")

        return {"queued": True, "duplicate": False, "job_id": job_id}

    async def process_pending_jobs(self, batch_size: int = 10) -> int:
        """Хүлээгдэж буй даалгавруудыг гүйцэтгэх (Worker циклээс дуудагдана)"""
        conn = sqlite3.connect(database.DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """
            SELECT * FROM task_jobs
            WHERE status = 'PENDING' AND attempts < max_retries
            ORDER BY id ASC LIMIT ?
            """,
            (batch_size,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

        processed = 0
        for job in rows:
            job_id = job["id"]
            task_name = job["task_name"]
            handler = self.handlers.get(task_name)
            if not handler:
                logger.warning(f"No handler registered for task '{task_name}'")
                continue

            conn = sqlite3.connect(database.DB_PATH)
            cur = conn.cursor()
            cur.execute(
                "UPDATE task_jobs SET status = 'PROCESSING', attempts = attempts + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (job_id,),
            )
            conn.commit()
            conn.close()

            try:
                payload = json.loads(job["payload_json"] or "{}")
                await handler(payload)
                conn = sqlite3.connect(database.DB_PATH)
                cur = conn.cursor()
                cur.execute(
                    "UPDATE task_jobs SET status = 'COMPLETED', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (job_id,),
                )
                conn.commit()
                conn.close()
                processed += 1
            except Exception as exc:
                logger.error(f"Task job #{job_id} ({task_name}) error: {exc}")
                new_status = "FAILED" if (job["attempts"] + 1) >= job["max_retries"] else "PENDING"
                conn = sqlite3.connect(database.DB_PATH)
                cur = conn.cursor()
                cur.execute(
                    "UPDATE task_jobs SET status = ?, last_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (new_status, str(exc), job_id),
                )
                conn.commit()
                conn.close()

        return processed


task_queue = TaskQueue()
