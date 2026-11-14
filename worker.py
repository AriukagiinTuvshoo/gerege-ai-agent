"""
Phase 4: Standalone Background Worker & Scheduler Process (`python worker.py`).
Runs independently from the FastAPI web server so scaling web workers never duplicates scheduled jobs.
"""
import os
import asyncio
import logging
from datetime import datetime
from dotenv import load_dotenv

import database
import executive_bot_service
import retention_service
import appointment_service
from core.task_queue import task_queue
from core import backup_service

load_dotenv(override=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("gerege.worker")


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
    stats = {"queue_processed": 0, "reports_sent": 0, "reminders_sent": 0}

    # 1. Task Queue дахь даалгавруудыг гүйцэтгэх
    stats["queue_processed"] = await task_queue.process_pending_jobs(batch_size=25)

    # 2. Өглөөний 08:30 Эзний тайлан (Idempotent lock-оор давхцалаас хамгаалсан)
    pages = database.get_all_pages()
    for p in pages:
        pid = p.get("page_id")
        if not pid:
            continue
        enabled = p.get("daily_report_enabled", 1)
        target_time = p.get("daily_report_time", "08:30")
        if enabled and current_hm == target_time:
            lock_key = f"daily_exec_report:{pid}:{today_str}"
            if database.claim_notification_lock(lock_key, channel="telegram"):
                logger.info(f"Sending daily executive report for {pid} ({today_str})")
                await executive_bot_service.send_executive_report(page_id=pid)
                stats["reports_sent"] += 1

    # 3. 15 минут тутамд автомат сэргээгч (Abandoned chat, Cargo pickup, Retention)
    if loop_count % 20 == 0:
        await retention_service.run_automated_retention_checks()

    # 4. Цаг захиалгын 2 цагийн өмнөх сануулга
    stats["reminders_sent"] = await appointment_service.check_and_dispatch_appointment_reminders()

    # 5. Өдөр бүр 03:00 цагт автомат Backup үүсгэх
    if current_hm == "03:00":
        backup_lock = f"daily_db_backup:{today_str}"
        if database.claim_notification_lock(backup_lock, channel="system"):
            backup_service.create_backup(label="daily_auto")

    return stats


async def worker_main_loop():
    database.init_db()
    register_default_task_handlers()
    logger.info("Gerege Dedicated Background Worker & Task Queue processor started.")
    loop_count = 0
    while True:
        try:
            await run_worker_tick(loop_count)
            loop_count += 1
        except Exception as e:
            logger.error(f"Worker loop error: {e}")
        await asyncio.sleep(15)


if __name__ == "__main__":
    asyncio.run(worker_main_loop())
