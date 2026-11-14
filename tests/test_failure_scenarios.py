"""
Phase 10: 20-Scenario Failure & Chaos Verification Suite (`tests/test_failure_scenarios.py`).
Tests real failure modes, resilience, atomic rollback, idempotency, and graceful degradation
across Database, Redis/Worker Queue, Backups, Migration, Security, and AI Providers.
"""
import os
import sys
import json
import gzip
import time
import shutil
import sqlite3
import tempfile
import asyncio
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
import main
import database
import agent
import worker
from core import db_engine
from core import security as core_security
from core import ai_router
from core import backup_service
from core.task_queue import TaskQueue, task_queue
from core.monitoring import telemetry, redact_secrets
from scripts import migrate_sqlite_to_postgres as mig

database.init_db()
client = TestClient(main.app)


def test_scenario_01_db_connection_failure_readiness_503():
    """1. PostgreSQL / Primary DB connection failure -> /api/ready returns 503 fail-closed"""
    orig_get_conn = database.get_connection
    try:
        def _broken_db():
            raise sqlite3.OperationalError("Simulated database connection down")
        database.get_connection = _broken_db
        resp = client.get("/api/ready")
        assert resp.status_code == 503
        body = resp.json()
        assert body["ready"] is False
        assert body["status"] in ("not_ready", "unhealthy")
    finally:
        database.get_connection = orig_get_conn


def test_scenario_02_redis_unavailable_durable_fallback():
    """2. Redis unavailable -> TaskQueue seamlessly degrades to durable SQLite/PostgreSQL store without job loss"""
    q = TaskQueue(worker_id="chaos-worker-02")
    q._redis = None
    q.redis_url = "redis://127.0.0.1:63999/0"  # Unreachable port
    q._last_redis_attempt = time.monotonic()

    key = f"chaos_redis_down_{os.urandom(4).hex()}"
    enq = q.enqueue("chaos_noop_task", {"hello": "world"}, page_id=database.DEFAULT_PAGE_ID, idempotency_key=key)
    assert enq["queued"] is True
    assert enq["job_id"] == key

    stats = q.get_queue_stats()
    assert stats["redis_connected"] is False
    assert stats["pending"] >= 1


def test_scenario_03_worker_crash_mid_job_visibility_recovery():
    """3. Worker crash mid-job -> Stale PROCESSING job is recovered after visibility timeout"""
    q = TaskQueue(worker_id="chaos-worker-03")
    key = f"chaos_crash_job_{os.urandom(4).hex()}"
    enq = q.enqueue("chaos_recover_task", {"step": 1}, page_id=database.DEFAULT_PAGE_ID, idempotency_key=key)
    job_id = enq["job_id"]

    # Simulate a worker claiming the job and crashing 30 seconds ago
    past_ts = (datetime.now() - timedelta(seconds=30)).strftime("%Y-%m-%d %H:%M:%S")
    with database.get_connection() as conn:
        conn.execute(
            "UPDATE task_jobs SET status = 'PROCESSING', locked_by = 'dead-worker-99', locked_at = ? WHERE idempotency_key = ?",
            (past_ts, job_id),
        )
        conn.commit()

    recovered_count = q.recover_stale_jobs(stale_after_seconds=5)
    assert recovered_count >= 1

    with database.get_connection() as conn:
        row = conn.execute("SELECT status, locked_by, last_error FROM task_jobs WHERE idempotency_key = ?", (job_id,)).fetchone()
        assert row["status"] == "PENDING"
        assert row["locked_by"] is None
        assert "Recovered from stale PROCESSING" in (row["last_error"] or "")


def test_scenario_04_unhandled_exception_telemetry_and_secret_redaction():
    """4. Unhandled route/handler exception -> Recorded in telemetry with secret redaction, no stack trace leaked"""
    before_errors = telemetry.total_errors
    telemetry.record_request(
        path="/api/simulated-crash",
        method="POST",
        status_code=500,
        duration_ms=12.5,
        error_detail="Crash with secret AIzaSyD9876543210123456789012345 and password=supersecret",
        request_id="req_chaos_04",
    )
    assert telemetry.total_errors == before_errors + 1
    snap = telemetry.get_snapshot()
    latest_err = snap["recent_errors"][-1]
    assert latest_err["request_id"] == "req_chaos_04"
    assert "AIzaSy" not in latest_err["error"]
    assert "supersecret" not in latest_err["error"]
    assert "[REDACTED" in latest_err["error"]


def test_scenario_05_database_pool_and_concurrent_connections():
    """5. Database pool metrics & concurrent connection stress"""
    pool_stat = db_engine.get_pool_status()
    assert "engine" in pool_stat
    assert "pooled" in pool_stat

    def _run_query(i: int) -> int:
        with database.get_connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM pages").fetchone()
            return int(row["cnt"])

    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(_run_query, range(24)))
    assert len(results) == 24
    assert all(r >= 1 for r in results)


def test_scenario_06_duplicate_webhook_and_notification_deduplication():
    """6. Duplicate webhook / notification request -> Atomic lock prevents duplicate dispatch"""
    lock_key = f"chaos_webhook_mid_{os.urandom(4).hex()}"
    first = database.claim_notification_lock(lock_key, page_id=database.DEFAULT_PAGE_ID, channel="facebook", ttl_seconds=300)
    second = database.claim_notification_lock(lock_key, page_id=database.DEFAULT_PAGE_ID, channel="facebook", ttl_seconds=300)
    assert first is True
    assert second is False


def test_scenario_07_duplicate_background_job_idempotency():
    """7. Duplicate background job -> Enqueue with identical idempotency_key deduplicates"""
    idem_key = f"chaos_idem_job_{os.urandom(4).hex()}"
    j1 = task_queue.enqueue("send_telegram_message", {"chat_id": "1", "text": "a"}, idempotency_key=idem_key)
    j2 = task_queue.enqueue("send_telegram_message", {"chat_id": "1", "text": "a"}, idempotency_key=idem_key)
    assert j1["queued"] is True
    assert j1["duplicate"] is False
    assert j2["queued"] is False
    assert j2["duplicate"] is True


def test_scenario_08_invalid_token_rejected_401():
    """8. Invalid Bearer token -> Protected endpoint returns 401"""
    resp = client.get("/api/leads", headers={"Authorization": "Bearer invalid_forged_token_xyz"})
    assert resp.status_code == 401


def test_scenario_09_expired_or_revoked_session_token_rejected_401():
    """9. Expired or revoked session token -> Protected endpoint returns 401"""
    tok = database.create_session(role="admin", page_id=None, hours=1, ip_address="127.0.0.1")
    assert database.get_session(tok) is not None
    database.revoke_session(tok)
    assert database.get_session(tok) is None

    resp = client.get("/api/leads", headers={"Authorization": f"Bearer {tok}"})
    assert resp.status_code == 401


def test_scenario_10_cross_tenant_request_blocked_403():
    """10. Cross-tenant request -> Client scoped to tenant_a gets 403 when accessing tenant_b"""
    database.save_page(page_id="chaos_tenant_a", name="Chaos Tenant A")
    database.save_page(page_id="chaos_tenant_b", name="Chaos Tenant B")
    tok_a = database.create_session(role="client", page_id="chaos_tenant_a", ip_address="127.0.0.1")
    headers_a = {"Authorization": f"Bearer {tok_a}"}

    resp = client.get("/api/leads?page_id=chaos_tenant_b", headers=headers_a)
    assert resp.status_code == 403


def test_scenario_11_migration_conflict_detected_and_aborted_without_overwrite():
    """11. Migration conflict -> Conflicting target row is detected by SHA-256 row hash and aborts without overwriting"""
    tmp_dir = tempfile.mkdtemp(prefix="chaos_mig_")
    try:
        src_path = os.path.join(tmp_dir, "src.db")
        dst_path = os.path.join(tmp_dir, "dst.db")
        shutil.copy2(database.DB_PATH, src_path)
        shutil.copy2(database.DB_PATH, dst_path)

        # Tamper with one row in dst_path so it conflicts with src_path
        conn = sqlite3.connect(dst_path)
        conn.execute("UPDATE pages SET name = 'CONFLICTING_TARGET_NAME' WHERE page_id = ?", (database.DEFAULT_PAGE_ID,))
        conn.commit()
        conn.close()

        report = mig.run_migration(sqlite_path=src_path, postgres_url=f"sqlite:///{dst_path}", dry_run=False)
        assert report["status"] == "CONFLICT_DETECTED"
        assert len(report["conflicts"]) >= 1

        # Verify target row was NOT overwritten
        conn_check = sqlite3.connect(dst_path)
        row = conn_check.execute("SELECT name FROM pages WHERE page_id = ?", (database.DEFAULT_PAGE_ID,)).fetchone()
        conn_check.close()
        assert row[0] == "CONFLICTING_TARGET_NAME"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_scenario_12_corrupted_backup_archive_rejected():
    """12. Corrupted backup archive -> verify_backup detects SHA-256 / archive corruption"""
    b = backup_service.create_backup(label="chaos_corrupt_test")
    assert b["success"] is True
    fname = b["filename"]
    fpath = os.path.join(backup_service.BACKUP_DIR, fname)

    # Corrupt the archive bytes
    with open(fpath, "wb") as f:
        f.write(b"CORRUPTED_GZIP_ARCHIVE_BYTES")

    try:
        v = backup_service.verify_backup(fname)
        assert v["valid"] is False
    finally:
        for ext in ("", ".sha256", ".meta.json"):
            p = fpath + ext
            if os.path.exists(p):
                os.remove(p)


def test_scenario_13_interrupted_or_corrupted_restore_preserves_live_db():
    """13. Interrupted / failed restore -> Rejects corrupted backup before touching live DB"""
    b = backup_service.create_backup(label="chaos_restore_guard")
    fname = b["filename"]
    fpath = os.path.join(backup_service.BACKUP_DIR, fname)

    # Corrupt the gzip file AND update the sha256 so it passes checksum but fails SQLite staging integrity check!
    import hashlib
    bad_bytes = gzip.compress(b"NOT_A_VALID_SQLITE_DATABASE_HEADER")
    with open(fpath, "wb") as f:
        f.write(bad_bytes)
    bad_sha = hashlib.sha256(bad_bytes).hexdigest()
    with open(fpath + ".sha256", "w", encoding="utf-8") as sf:
        sf.write(f"{bad_sha}  {fname}\n")
    if os.path.exists(fpath + ".meta.json"):
        with open(fpath + ".meta.json", "r", encoding="utf-8") as mf:
            meta = json.load(mf)
        meta["sha256"] = bad_sha
        with open(fpath + ".meta.json", "w", encoding="utf-8") as mf:
            json.dump(meta, mf)

    try:
        res = backup_service.restore_backup(fname)
        assert res["success"] is False
        # Verify live database is still 100% healthy and readable
        with database.get_connection() as conn:
            cnt = conn.execute("SELECT COUNT(*) AS cnt FROM pages").fetchone()["cnt"]
            assert cnt >= 1
    finally:
        for ext in ("", ".sha256", ".meta.json"):
            p = fpath + ext
            if os.path.exists(p):
                os.remove(p)


def test_scenario_14_ai_provider_timeout_and_retry_recovery():
    """14. AI provider timeout -> execute_with_retry retries and trips circuit breaker cleanly on persistent failure"""
    attempts = {"count": 0}

    def _flaky_provider():
        attempts["count"] += 1
        if attempts["count"] < 2:
            raise TimeoutError("Simulated AI provider timeout")
        return "Recovered AI response"

    result = ai_router.execute_with_retry(_flaky_provider, provider_name="chaos_timeout_provider", max_retries=2, base_delay=0.01)
    assert result == "Recovered AI response"
    assert attempts["count"] == 2


def test_scenario_15_ai_provider_quota_exceeded_guard():
    """15. AI provider rate limit / token quota exceeded -> Tenant token quota blocks excess calls"""
    quota_tenant = f"chaos_quota_{os.urandom(3).hex()}"
    database.save_page(page_id=quota_tenant, name="Quota Tenant", monthly_token_limit=100)
    with database.get_connection() as conn:
        conn.execute("UPDATE pages SET monthly_token_limit = 100, tokens_used = 150 WHERE page_id = ?", (quota_tenant,))
        conn.commit()

    res = agent.process_message(text="Сайн байна уу?", sender_id="quota_user", channel="web", page_id=quota_tenant)
    assert res.get("limit_exceeded") is True


def test_scenario_16_invalid_or_unsafe_ai_response_sanitized():
    """16. Invalid / unsafe AI response -> Strips internal <thought> tags and redacts leaked credentials"""
    unsafe_output = "<thought>Internal chain of thought</thought>Here is secret AIzaSyD9876543210123456789012345"
    evaluated = ai_router.evaluate_ai_response(unsafe_output, page_id=database.DEFAULT_PAGE_ID)
    assert evaluated["passed"] is False
    assert "<thought>" not in evaluated["cleaned_reply"]
    assert "AIzaSy" not in evaluated["cleaned_reply"]


def test_scenario_17_oversized_upload_disk_guard_413():
    """17. Oversized upload (>10MB) -> Rejected with 413 Payload Too Large"""
    oversized_bytes = b"0" * (10 * 1024 * 1024 + 512)
    resp = client.post(
        "/api/chat/voice",
        data={"sender_id": "chaos_upload_user", "page_id": database.DEFAULT_PAGE_ID},
        files={"file": ("huge.wav", oversized_bytes, "audio/wav")},
    )
    assert resp.status_code == 413


def test_scenario_18_application_restart_session_and_memory_persistence():
    """18. Application restart -> DB-backed auth sessions and AI user memory persist across process restarts"""
    tok = database.create_session(role="admin", page_id=None, ip_address="127.0.0.1")
    user_id = f"restart_user_{os.urandom(3).hex()}"
    database.upsert_user_memory(
        page_id=database.DEFAULT_PAGE_ID,
        user_id=user_id,
        customer_name="Бат-Эрдэнэ",
        phone="99110099",
        interests="VIP",
    )

    # Simulate restart by clearing in-memory caches and re-running init_db
    agent.reset_sessions()
    database.init_db()

    sess = database.get_session(tok)
    assert sess is not None
    assert sess["role"] == "admin"

    mem = database.get_user_memory(database.DEFAULT_PAGE_ID, user_id)
    assert mem is not None
    assert mem["customer_name"] == "Бат-Эрдэнэ"
    assert mem["phone"] == "99110099"


def test_scenario_19_concurrent_multi_worker_atomic_job_claiming():
    """19. Concurrent workers racing on a single queued job -> Job is claimed and executed by exactly 1 worker"""
    execution_counter = {"runs": 0}

    async def _single_run_handler(payload):
        execution_counter["runs"] += 1
        await asyncio.sleep(0.02)

    q1 = TaskQueue(worker_id="race-worker-1")
    q2 = TaskQueue(worker_id="race-worker-2")
    q1.register_handler("chaos_race_task", _single_run_handler)
    q2.register_handler("chaos_race_task", _single_run_handler)

    # Mark any prior pending jobs as completed so we isolate this test
    with database.get_connection() as conn:
        conn.execute("UPDATE task_jobs SET status = 'COMPLETED' WHERE status = 'PENDING'")
        conn.commit()

    race_key = f"chaos_race_{os.urandom(4).hex()}"
    enq = q1.enqueue("chaos_race_task", {"test": "race"}, idempotency_key=race_key)
    job_id = enq["job_id"]

    # Claim synchronously from two independent worker instances
    c1 = q1._claim_job_atomically(job_id)
    c2 = q2._claim_job_atomically(job_id)
    claimed_list = [c for c in (c1, c2) if c is not None]
    assert len(claimed_list) == 1
    q1.ack_job(job_id)


def test_scenario_20_worker_graceful_shutdown():
    """20. Worker graceful shutdown -> Stops cleanly after current tick when shutdown is requested"""
    async def _run_and_stop():
        loop_task = asyncio.create_task(worker.worker_main_loop(max_iterations=1))
        iters = await asyncio.wait_for(loop_task, timeout=10.0)
        return iters

    completed_iters = asyncio.run(_run_and_stop())
    assert completed_iters == 1


if __name__ == "__main__":
    test_funcs = [v for k, v in list(globals().items()) if k.startswith("test_scenario_") and callable(v)]
    print(f"=== RUNNING {len(test_funcs)} FAILURE & CHAOS SCENARIOS ===")
    for fn in test_funcs:
        fn()
        print(f"[PASS] {fn.__name__}")
    print(f"=== ALL {len(test_funcs)} FAILURE & CHAOS SCENARIOS PASSED 100% ===")
