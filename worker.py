"""
Phase 3: Standalone Background Worker & Scheduler Process (`python worker.py`).
Runs independently from the FastAPI web server so scaling web workers never duplicates scheduled jobs.
Supports graceful shutdown on SIGINT / SIGTERM and distributed locks with TTL.
"""
import os
import signal
import asyncio
import logging
import time
from datetime import datetime
from typing import Optional
from dotenv import load_dotenv

import database
import executive_bot_service
import retention_service
import appointment_service
from core.task_queue import task_queue

load_dotenv(override=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("gerege.worker")

_SHUTDOWN_EVENT: Optional[asyncio.Event] = None


def register_default_task_handlers() -> None:
    """Task Queue дээр ажиллах стандарт handler-уудыг бүртгэх"""
    from main import send_meta_message, send_telegram_message, notify_manager_telegram

    async def _handle_meta(payload):
        await send_meta_message(
            recipient_id=payload["recipient_id"],
            text=payload["text"],
            page_token=payload.get("page_token"),
        )

    async def _handle_telegram(payload):
        await send_telegram_message(
            chat_id=payload["chat_id"],
            text=payload["text"],
            page_id=payload.get("page_id"),
        )

    async def _handle_manager_notify(payload):
        await notify_manager_telegram(payload)

    async def _handle_broadcast(payload):
        await retention_service.send_broadcast(
            page_id=payload["page_id"],
            title=payload["title"],
            message=payload["message"],
            target_segment=payload.get("target_segment", "all"),
            channel=payload.get("channel", "all"),
        )

    task_queue.register_handler("send_meta_message", _handle_meta)
    task_queue.register_handler("send_telegram_message", _handle_telegram)
    task_queue.register_handler("notify_manager_telegram", _handle_manager_notify)
    task_queue.register_handler("send_broadcast", _handle_broadcast)


async def run_worker_tick(loop_count: int) -> dict:
    """Нэг циклд хийгдэх фоновые ажлууд (Тест болон Worker loop дундаа ашиглана)"""
    now = datetime.now()
    today_str = now.strftime("%Y-%m-%d")
    current_hm = now.strftime("%H:%M")
    stats = {
        "queue_processed": 0,
        "stale_recovered": 0,
        "reports_sent": 0,
        "reminders_sent": 0,
        # Phase 39 (F-39-D): a scheduler step that raised during this tick. Non-zero
        # means something is broken even though the worker itself is alive; before this
        # the only evidence was a log line nobody was watching.
        "scheduler_errors": 0,
    }

    # 0. Гацсан (PROCESSING visibility timeout хэтэрсэн) даалгавруудыг сэргээх
    stats["stale_recovered"] = task_queue.recover_stale_jobs()

    # 1. Task Queue дахь даалгавруудыг гүйцэтгэх
    stats["queue_processed"] = await task_queue.process_pending_jobs(batch_size=25)

    # 2. Өглөөний 08:30 Эзний тайлан (Idempotent lock-оор давхцалаас хамгаалсан)
    # ---------------------------------------------------------------------------
    # Phase 39 (F-39-D): every scheduler step is now isolated.
    #
    # Before this, steps 2-4 ran unguarded in one sequence inside the tick, and the tick
    # is called from a loop that catches everything and continues. The combination meant
    # one broken scheduler call:
    #
    #   * aborted the REST of the tick, so appointment reminders stopped even when due;
    #   * aborted steps 2-4 on every later tick, since the loop just called the same
    #     function again;
    #   * and because `beat()` is deliberately the LAST statement of the tick, the
    #     heartbeat was never written. A LIVE process therefore looked DEAD, the
    #     container went unhealthy, Docker restarted it, and it wedged again.
    #
    # Measured before the fix: three consecutive ticks against a scheduler call that
    # always raises left `worker_heartbeat.read()["status"] == "missing"` while the
    # process was alive and logging errors.
    #
    # Now each step fails independently, the failure is counted, and the tick completes
    # so the heartbeat is written. `scheduler_errors` is exposed through the heartbeat,
    # so a broken step is visible over HTTP instead of only in the log.
    # ---------------------------------------------------------------------------
    try:
        pages = database.get_all_pages()
        for p in pages:
            pid = p.get("page_id")
            if not pid:
                continue
            enabled = p.get("daily_report_enabled", 1)
            target_time = p.get("daily_report_time", "08:30")
            if enabled and current_hm == target_time:
                lock_key = f"daily_exec_report:{pid}:{today_str}"
                if database.claim_notification_lock(lock_key, page_id=pid, channel="telegram", ttl_seconds=86400):
                    logger.info(f"Sending daily executive report for {pid} ({today_str})")
                    await executive_bot_service.send_executive_report(page_id=pid)
                    stats["reports_sent"] += 1
    except Exception as exc:
        stats["scheduler_errors"] += 1
        logger.error(f"daily report step failed: {type(exc).__name__}: {exc}")

    try:
        # 3. 5 минут тутамд автомат сэргээгч (Abandoned chat, Cargo pickup, Retention) - TTL lock-той
        if loop_count % 20 == 0:
            retention_lock = f"scheduler:retention:{now.strftime('%Y-%m-%d %H:%M')}"
            if database.claim_notification_lock(retention_lock, channel="system", ttl_seconds=240):
                await retention_service.run_automated_retention_checks()
    except Exception as exc:
        stats["scheduler_errors"] += 1
        logger.error(f"retention step failed: {type(exc).__name__}: {exc}")

    try:
        # 4. Цаг захиалгын 2 цагийн өмнөх сануулга
        stats["reminders_sent"] = await appointment_service.check_and_dispatch_appointment_reminders()
    except Exception as exc:
        stats["scheduler_errors"] += 1
        logger.error(f"appointment reminder step failed: {type(exc).__name__}: {exc}")

    # 5. Automatic daily backup REMOVED (E-05).
    #
    # The worker runs as `gerege_app`, which owns nothing. `pg_dump` needs
    # `LOCK TABLE ... ACCESS SHARE` on all 18 tables and is refused for a non-owner, so
    # this job could only ever have produced a 0-byte archive reported as a success.
    # A scheduled backup now belongs to the maintenance plane, not the runtime:
    #   docker compose -f docker-compose.prod.yml run --rm maintenance \
    #       python scripts/maintenance.py backup --label daily_auto
    # driven by cron/systemd on the host (docs/operations/BACKUP_RESTORE.md §6).
    # Leaving the call here and letting it raise nightly would train operators to ignore
    # worker errors, so it is gone rather than wrapped in a try/except.

    # Phase 41: this is the PROGRESS record, not the liveness signal.
    #
    # Until Phase 41 this write was the heartbeat, and it sat at the end of the tick for a
    # good reason -- a beat at the start would report "alive" while the loop was wedged in
    # a handler. But it coupled liveness to tick duration: the loop sleeps up to 15 s
    # between ticks and a slow batch measures 23.3 s, so the gap between beats was up to
    # ~38 s and a 30 s freshness window would have false-staled a healthy worker.
    #
    # Liveness is now written by a timer (see `_heartbeat_loop`), and this write exists to
    # say "a tick completed, and here is what it did". Both go to the same per-worker key,
    # so the counters stay on the same record as the age. Best-effort, as before.
    try:
        from core import worker_heartbeat
        worker_heartbeat.beat(loop_count, extra={
            "queue_processed": stats.get("queue_processed", 0),
            "stale_recovered": stats.get("stale_recovered", 0),
            "reports_sent": stats.get("reports_sent", 0),
            "reminders_sent": stats.get("reminders_sent", 0),
            "scheduler_errors": stats.get("scheduler_errors", 0),
            "tick_completed_at": time.time(),
        })
    except Exception as beat_exc:
        # Redis down is survivable: the queue falls back to DB polling.
        logger.warning(f"worker heartbeat skipped: {beat_exc}")

    return stats


def request_shutdown() -> None:
    """Гаднаас болон тестээс worker loop-ийг аюулгүй зогсоох команд."""
    if _SHUTDOWN_EVENT is not None:
        _SHUTDOWN_EVENT.set()


async def worker_main_loop(max_iterations: Optional[int] = None):
    global _SHUTDOWN_EVENT
    _SHUTDOWN_EVENT = asyncio.Event()

    def _signal_handler(sig_name: str):
        logger.info(f"Received {sig_name}; initiating graceful worker shutdown...")
        if _SHUTDOWN_EVENT:
            _SHUTDOWN_EVENT.set()

    loop = asyncio.get_running_loop()
    for s_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, s_name, None)
        if sig is not None:
            try:
                loop.add_signal_handler(sig, _signal_handler, s_name)
            except NotImplementedError:
                # Windows ProactorEventLoop fallback
                signal.signal(sig, lambda *_: _signal_handler(s_name))

    database.init_db()
    register_default_task_handlers()
    # Phase 36: the worker is a sequential asyncio loop, so it is counted once in the
    # connection budget regardless of TASK_QUEUE_BATCH_SIZE. Runs after init_db so a
    # misconfiguration is reported with the schema already known-good.
    try:
        from core.db_engine import enforce_connection_budget
        enforce_connection_budget(api_processes=int(os.getenv("UVICORN_WORKERS", "1")))
    except RuntimeError:
        raise
    except Exception as exc:
        logger.warning(f"connection budget check skipped: {exc}")
    logger.info(f"Gerege Dedicated Background Worker started (worker_id={task_queue.worker_id}).")

    # Phase 41: liveness is its own timer, so a slow batch cannot make a healthy worker
    # look dead and a wedged loop cannot make it look alive. Started before the first tick
    # so the worker is visible immediately rather than one tick later.
    heartbeat_task = asyncio.create_task(_heartbeat_loop())
    try:
        hb_mod = _import_heartbeat()
        if hb_mod is not None:
            hb_mod.beat(0)
    except Exception as exc:  # pragma: no cover - Redis optional in dev
        logger.warning(f"initial heartbeat failed: {exc}")

    loop_count = 0
    try:
        while not _SHUTDOWN_EVENT.is_set():
            try:
                await run_worker_tick(loop_count)
                loop_count += 1
                if max_iterations is not None and loop_count >= max_iterations:
                    _SHUTDOWN_EVENT.set()
                    break
            except Exception as e:
                logger.error(f"Worker loop error: {e}")
            try:
                await asyncio.wait_for(_SHUTDOWN_EVENT.wait(), timeout=15.0)
            except asyncio.TimeoutError:
                pass
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except (asyncio.CancelledError, Exception):
            pass
        # Graceful shutdown removes THIS worker's key, so a restart is visible at once and
        # a stopped worker does not linger as "stale" for the length of its TTL. Other
        # workers' keys are untouched (see clear()).
        try:
            hb_mod = _import_heartbeat()
            if hb_mod is not None:
                hb_mod.clear()
                logger.info("worker heartbeat cleared for this worker")
        except Exception as exc:  # pragma: no cover
            logger.warning(f"heartbeat clear failed: {exc}")

    logger.info("Gerege Background Worker stopped cleanly.")
    return loop_count


def _import_heartbeat():
    try:
        from core import worker_heartbeat

        return worker_heartbeat
    except Exception:
        return None


async def _heartbeat_loop() -> None:
    """Write this worker's liveness every BEAT_INTERVAL_SECONDS until cancelled.

    Separate from the tick on purpose. The tick can take as long as a handler does -- a
    measured 23.3 s mid-batch -- so anything derived from tick timing is a measure of
    throughput, not of liveness. A timer that is independent of the work keeps the two
    questions separate: "is the process running" and "is it getting through the queue".

    Never raises: a Redis outage must not stop the worker, and a failed beat is exactly
    what `status: unknown` is for.
    """
    from core import worker_heartbeat

    interval = worker_heartbeat.BEAT_INTERVAL_SECONDS
    while not _SHUTDOWN_EVENT.is_set():
        try:
            worker_heartbeat.beat()
        except Exception as exc:  # pragma: no cover - Redis optional
            logger.warning(f"heartbeat timer write failed: {exc}")
        try:
            await asyncio.wait_for(_SHUTDOWN_EVENT.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


if __name__ == "__main__":
    asyncio.run(worker_main_loop())
