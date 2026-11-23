"""Phase 36 - worker liveness and observability.

Phase 35's finding: no worker liveness endpoint existed, so a worker that died while the
queue was empty was invisible over HTTP. This file covers the heartbeat added to close
that gap, including the properties that make it trustworthy:

  * a **stale** heartbeat is not reported as healthy (the whole point);
  * a **missing** heartbeat is distinguishable from an **unknown** one;
  * no task payload or tenant data can reach the response;
  * the endpoint is admin-only.

The heartbeat is a short-TTL Redis key rather than a new table, because `database.py` is
held byte-identical and a new table would need a migration. Redis is already a hard
production dependency.
"""

from __future__ import annotations

import json
import os
import time

import pytest
from fastapi.testclient import TestClient


# --------------------------------------------------------------- pure unit behaviour

class TestHeartbeatStates:
    """The four states must be distinguishable, and 'stale' must never read as 'alive'."""

    @pytest.fixture()
    def hb(self):
        from core import worker_heartbeat

        return worker_heartbeat

    @pytest.fixture()
    def redis_client(self, hb):
        client = hb._redis()
        if client is None:
            pytest.skip("needs a live Redis")
        client.delete(hb._key())
        yield client
        try:
            client.delete(hb._key())
        except Exception:
            pass

    def test_missing_when_nothing_written(self, hb, redis_client):
        state = hb.read()
        assert state["status"] == "missing"
        assert state["heartbeat"] is None

    def test_alive_after_a_beat(self, hb, redis_client):
        assert hb.beat(42, worker_id="w-1") is True
        state = hb.read()
        assert state["status"] == "alive"
        assert state["heartbeat"]["loop_count"] == 42
        assert state["heartbeat"]["worker_id"] == "w-1"

    def test_stale_heartbeat_is_not_alive(self, hb, redis_client):
        """The critical property: a dead worker's last beat must not look healthy."""
        redis_client.set(
            hb._key(),
            json.dumps({"worker_id": "w-1", "loop_count": 3, "at": time.time() - 1000, "pid": 1}),
            ex=hb.DEFAULT_TTL_SECONDS,
        )
        state = hb.read()
        assert state["status"] == "stale"
        assert state["status"] != "alive"
        assert "reason" in state

    def test_expired_key_reports_missing_not_stale(self, hb, redis_client):
        """TTL expiry is what stops a dead worker leaving a permanent healthy flag."""
        redis_client.set(
            hb._key(),
            json.dumps({"worker_id": "w", "loop_count": 1, "at": time.time(), "pid": 1}),
            ex=1,
        )
        time.sleep(1.2)
        assert hb.read()["status"] == "missing"

    def test_unknown_when_payload_is_corrupt(self, hb, redis_client):
        redis_client.set(hb._key(), "not-json", ex=60)
        state = hb.read()
        assert state["status"] == "unknown"
        assert "reason" in state

    def test_unknown_when_redis_is_unreachable(self, hb, monkeypatch):
        """No Redis means no claim either way -- never a fabricated 'alive'."""
        monkeypatch.setattr(hb, "_redis", lambda: None)
        assert hb.read()["status"] == "unknown"

    def test_beat_is_best_effort_without_redis(self, hb, monkeypatch):
        """Monitoring must never kill the process it monitors."""
        monkeypatch.setattr(hb, "_redis", lambda: None)
        assert hb.beat(1) is False  # no exception


class TestHeartbeatPayloadSafety:
    """The payload is returned over HTTP, so its contents must be constrained."""

    @pytest.fixture()
    def redis_client(self):
        from core import worker_heartbeat as hb

        client = hb._redis()
        if client is None:
            pytest.skip("needs a live Redis")
        client.delete(hb._key())
        yield client
        client.delete(hb._key())

    def test_secret_keys_are_rejected(self, redis_client):
        """Regression: an open `extra` dict put a token verbatim into the response."""
        from core import worker_heartbeat as hb

        hb.beat(1, worker_id="w", extra={"secret_token": "SHOULD_NOT_APPEAR"})
        state = hb.read()
        assert "secret_token" not in state["heartbeat"]
        assert "SHOULD_NOT_APPEAR" not in json.dumps(state)

    def test_string_values_are_rejected_even_when_allowlisted(self, redis_client):
        """A string is a scalar too, and a scalar can be a secret."""
        from core import worker_heartbeat as hb

        hb.beat(1, worker_id="w", extra={"reports_sent": "leaked-string"})
        assert "reports_sent" not in hb.read()["heartbeat"]

    def test_allowlisted_counters_survive(self, redis_client):
        from core import worker_heartbeat as hb

        hb.beat(1, worker_id="w", extra={"queue_processed": 7, "reminders_sent": 0})
        heartbeat = hb.read()["heartbeat"]
        assert heartbeat["queue_processed"] == 7
        assert heartbeat["reminders_sent"] == 0

    def test_payload_carries_no_task_or_tenant_data(self, redis_client):
        from core import worker_heartbeat as hb

        hb.beat(1, worker_id="w")
        keys = set(hb.read()["heartbeat"])
        assert keys <= {"worker_id", "loop_count", "pid", "age_seconds"} | set(
            hb.ALLOWED_EXTRA_KEYS
        )


# ------------------------------------------------------------------ endpoint behaviour

@pytest.fixture()
def admin_client(monkeypatch):
    """An authenticated admin client.

    **Test-isolation defect found during Phase 36 and fixed here.** An earlier version of
    this fixture called `os.environ.setdefault("ADMIN_PASSWORD", ...)`, which writes to the
    real process environment and is never undone. Every test that ran afterwards inherited
    the wrong admin password, and five unrelated suites failed with "admin password
    incorrect" when the whole suite was run together -- while passing in isolation. It also
    would have masked a genuine regression behind a misleading error.

    `monkeypatch.setenv` is scoped to the test and restored automatically.
    """
    import main

    password = "e36-admin-pw"
    monkeypatch.setenv("ADMIN_PASSWORD", password)
    with TestClient(main.app, raise_server_exceptions=False) as client:
        client.cookies.clear()
        response = client.post("/api/auth/login", json={"password": password})
        if response.status_code != 200:
            pytest.skip(f"admin login unavailable: {response.status_code}")
        yield client
        client.cookies.clear()


class TestWorkerHealthEndpoint:
    def test_anonymous_is_rejected(self):
        """Deployment internals must not be readable without authentication."""
        import main

        with TestClient(main.app, raise_server_exceptions=False) as client:
            assert client.get("/api/admin/worker/health").status_code == 401

    def test_admin_gets_a_report(self, admin_client):
        response = admin_client.get("/api/admin/worker/health")
        assert response.status_code in (200, 503), response.text
        body = response.json()
        assert set(body) >= {"worker", "scheduler", "queue", "alerts"}
        assert body["worker"]["status"] in ("alive", "stale", "missing", "unknown")

    def test_status_code_follows_liveness(self, admin_client):
        """503 when the worker is not alive, so a monitor notices without parsing JSON."""
        from core import worker_heartbeat as hb

        response = admin_client.get("/api/admin/worker/health")
        expected = 200 if response.json()["worker"]["status"] == "alive" else 503
        assert response.status_code == expected

    def test_reports_that_the_scheduler_lives_in_the_worker(self, admin_client):
        """A dead worker is also a dead scheduler; the response must say so plainly."""
        body = admin_client.get("/api/admin/worker/health").json()
        assert body["scheduler"]["location"] == "worker"
        assert "DISABLE_INLINE_SCHEDULER" in body["scheduler"]["note"]

    def test_includes_queue_backlog_and_dead_letter(self, admin_client):
        body = admin_client.get("/api/admin/worker/health").json()
        queue = body["queue"]
        for key in ("pending", "processing", "completed", "dead_letter", "failed"):
            assert key in queue
        assert "dead_letter_jobs" in body["alerts"]

    def test_does_not_disclose_redis_url(self, admin_client):
        text = admin_client.get("/api/admin/worker/health").text.lower()
        assert "redis://" not in text
        assert "password" not in text


# ------------------------------------------------------------------ worker wiring

class TestWorkerLoopWiring:
    def test_tick_writes_a_heartbeat(self):
        """The beat must be at the END of the tick, after work is done.

        A heartbeat written at the start would keep reporting 'alive' while the loop was
        wedged inside a handler -- exactly the failure this is meant to detect.
        """
        import worker

        source = open(worker.__file__, encoding="utf-8").read()
        tick_start = source.index("async def run_worker_tick")
        tick_end = source.index("def request_shutdown")
        body = source[tick_start:tick_end]
        assert "worker_heartbeat.beat(" in body
        # The beat must come after the queue processing, not before it.
        assert body.index("process_pending_jobs") < body.index("worker_heartbeat.beat(")

    def test_heartbeat_failure_does_not_break_the_tick(self):
        source = open(__import__("worker").__file__, encoding="utf-8").read()
        tick_start = source.index("async def run_worker_tick")
        tick_end = source.index("def request_shutdown")
        body = source[tick_start:tick_end]
        beat_at = body.index("worker_heartbeat.beat(")
        # There must be a try/except around the call.
        preceding = body[:beat_at]
        assert "try:" in preceding[-400:], "the beat call must be wrapped in try/except"
