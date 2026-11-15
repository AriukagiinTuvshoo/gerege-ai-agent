"""
P0-3 Integration Tests: Database Connection Pool Leak Elimination.
Verifies that database connections and cursors are reliably returned to the pool
under all failure conditions (query exceptions, bad queries, early returns),
and that repeated failures never exhaust the SQLAlchemy QueuePool.
"""
import os
import sys
import uuid
import asyncio
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main
import database
from core import db_engine
from core.task_queue import task_queue

client = TestClient(main.app)


def _is_pg():
    return db_engine.is_postgres()


def _get_checkedout_count() -> int:
    if not _is_pg():
        return 0
    engine = db_engine.get_shared_engine()
    return engine.pool.checkedout()


def test_db_connection_returned_to_pool_on_query_exception():
    """Connection is returned to pool even when an invalid query raises an exception."""
    before_checkedout = _get_checkedout_count()
    conn = None
    try:
        conn = database.get_connection()
        cur = conn.cursor()
        try:
            cur.execute("SELECT * FROM non_existent_table_for_leak_test_xyz")
            cur.fetchall()
        except Exception:
            pass
        finally:
            cur.close()
            conn.close()
    except Exception:
        pass

    after_checkedout = _get_checkedout_count()
    assert after_checkedout == before_checkedout, (
        f"Connection leak detected! checkedout before={before_checkedout}, after={after_checkedout}"
    )


def test_task_ack_returns_connection_on_failure():
    """task_queue.ack_job safely returns connection even on invalid job ID or statement failure."""
    before_checkedout = _get_checkedout_count()
    task_queue.ack_job("non_existent_job_xyz_123")
    after_checkedout = _get_checkedout_count()
    assert after_checkedout == before_checkedout, "ack_job leaked connection!"


def test_task_fail_returns_connection_on_failure():
    """task_queue.fail_job safely returns connection to pool."""
    before_checkedout = _get_checkedout_count()
    dummy_job = {
        "idempotency_key": f"fail_job_{uuid.uuid4().hex[:8]}",
        "task_name": "test_leak",
        "attempts": 1,
        "max_retries": 3,
    }
    task_queue.fail_job(dummy_job, "simulated error")
    after_checkedout = _get_checkedout_count()
    assert after_checkedout == before_checkedout, "fail_job leaked connection!"


def test_queue_stats_returns_connection_on_failure():
    """task_queue.get_queue_stats safely closes connection even when called repeatedly."""
    before_checkedout = _get_checkedout_count()
    for _ in range(10):
        stats = task_queue.get_queue_stats()
        assert isinstance(stats, dict)
    after_checkedout = _get_checkedout_count()
    assert after_checkedout == before_checkedout, "get_queue_stats leaked connection!"


def test_readiness_returns_connection_on_query_failure():
    """GET /api/ready probe never leaks connections even when queries fail or succeed."""
    before_checkedout = _get_checkedout_count()
    for _ in range(10):
        resp = client.get("/api/ready")
        assert resp.status_code in (200, 503)
    after_checkedout = _get_checkedout_count()
    assert after_checkedout == before_checkedout, "Readiness probe leaked connections!"


def test_transaction_exception_returns_connection_to_pool():
    """Transaction exception and rollback reliably returns connection to pool."""
    before_checkedout = _get_checkedout_count()
    for _ in range(20):
        try:
            with database.get_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT 1")
                raise RuntimeError("Simulated transaction crash")
        except RuntimeError:
            pass

    after_checkedout = _get_checkedout_count()
    assert after_checkedout == before_checkedout, (
        f"Transaction crash leaked connection! before={before_checkedout}, after={after_checkedout}"
    )


def test_connection_and_cursor_idempotent_close():
    """Calling close() multiple times on connection or cursor never raises error or leaks."""
    before_checkedout = _get_checkedout_count()
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1")
    cur.close()
    cur.close()  # idempotent second close
    conn.close()
    conn.close()  # idempotent second close
    after_checkedout = _get_checkedout_count()
    assert after_checkedout == before_checkedout, "Idempotent close altered pool state!"


def test_connection_pool_does_not_exhaust_after_repeated_failures():
    """Repeatedly executing failing queries never exhausts QueuePool."""
    before_checkedout = _get_checkedout_count()
    for i in range(50):
        conn = None
        cur = None
        try:
            conn = database.get_connection()
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM non_existent_leak_tbl")
        except Exception:
            pass
        finally:
            if cur is not None:
                cur.close()
            if conn is not None:
                conn.close()

    after_checkedout = _get_checkedout_count()
    assert after_checkedout == before_checkedout, (
        f"Pool exhausted or leaked! before={before_checkedout}, after={after_checkedout}"
    )

    # Prove pool can still acquire a healthy connection immediately
    healthy_conn = database.get_connection()
    healthy_cur = healthy_conn.cursor()
    healthy_cur.execute("SELECT 1")
    row = healthy_cur.fetchone()
    assert row is not None
    healthy_cur.close()
    healthy_conn.close()


if __name__ == "__main__":
    print("=== RUNNING P0-3 CONNECTION POOL LEAK REMEDIATION TESTS ===")
    test_db_connection_returned_to_pool_on_query_exception()
    print("[PASS] test_db_connection_returned_to_pool_on_query_exception")
    test_task_ack_returns_connection_on_failure()
    print("[PASS] test_task_ack_returns_connection_on_failure")
    test_task_fail_returns_connection_on_failure()
    print("[PASS] test_task_fail_returns_connection_on_failure")
    test_queue_stats_returns_connection_on_failure()
    print("[PASS] test_queue_stats_returns_connection_on_failure")
    test_readiness_returns_connection_on_query_failure()
    print("[PASS] test_readiness_returns_connection_on_query_failure")
    test_transaction_exception_returns_connection_to_pool()
    print("[PASS] test_transaction_exception_returns_connection_to_pool")
    test_connection_and_cursor_idempotent_close()
    print("[PASS] test_connection_and_cursor_idempotent_close")
    test_connection_pool_does_not_exhaust_after_repeated_failures()
    print("[PASS] test_connection_pool_does_not_exhaust_after_repeated_failures")
    print("=== ALL P0-3 TESTS PASSED 100% ===")
