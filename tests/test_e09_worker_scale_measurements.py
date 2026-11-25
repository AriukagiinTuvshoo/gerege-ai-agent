"""Phase 9 measurement gaps — what two workers, and a killed worker, actually do.

Phase 9 built the observability surface: `/api/ready`, the pool/queue metrics, the disk
figure. What it left unmeasured was the behaviour of the thing being observed. Three
questions had no answer backed by a number:

  1. **Two worker processes.** The heartbeat is one Redis key per deployment. Does a
     second worker coexist with the first, or replace it?
  2. **`kill -9`.** A worker that is SIGKILLed writes no final heartbeat and gets no
     chance to clean up. How long does the endpoint keep calling it alive?
  3. **Cross-process scheduler overlap.** Every scheduler step claims a lock first. Two
     processes reaching the same minute: one claim, or two?

Each was measured before it was asserted, against the real code paths: `worker.py`'s own
loop for (1) and (2), `database.claim_notification_lock` in two OS processes for (3).

The answers were not all comfortable. At the time (1) showed the second worker REPLACING
the first's heartbeat, so the endpoint reported one worker when two were running, and (2)
showed a killed worker reading `alive` for 150 s. Both were recorded as they were, and
both **were fixed in Phase 41** - which is why these tests now assert the fixed behaviour.

Keeping the history matters here: a reader who finds `test_two_workers_each_keep_a_
heartbeat` should be able to see that this was measured as broken first. The pre-fix
behaviour is reproduced by `git show 4e9acf8:core/worker_heartbeat.py`, and the numbers
are in `docs/audit/PHASE_9_MEASUREMENTS.md` (§1, §2) and
`docs/audit/PHASE_41_WORKER_RELIABILITY.md` §3.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _redis_or_skip(heartbeat):
    """The heartbeat is Redis-backed by design; without Redis there is nothing to measure."""
    client = heartbeat._redis()
    if client is None:
        pytest.skip("no Redis: the worker heartbeat is Redis-backed and cannot be measured")
    return client


# ----------------------------------------------------- one heartbeat key, two workers


class TestTwoWorkersShareOneHeartbeatKey:
    """Measured: the second worker's beat replaces the first's. One key, one payload."""

    def test_the_key_is_per_deployment_not_per_worker(self, monkeypatch):
        """This is WHY the measurement below comes out the way it does."""
        from core import worker_heartbeat

        monkeypatch.delenv("WORKER_HEARTBEAT_KEY", raising=False)
        assert worker_heartbeat._key() == "gerege:worker:heartbeat"
        # A worker id changes the payload, never the key.
        monkeypatch.setenv("WORKER_ID", "worker-A")
        first = worker_heartbeat._key()
        monkeypatch.setenv("WORKER_ID", "worker-B")
        assert worker_heartbeat._key() == first

    def test_two_workers_each_keep_their_own_heartbeat(self, monkeypatch):
        """Phase 9 measured this as broken; Phase 41 fixed it, and this asserts the fix.

        Before: two beats, one key, and the endpoint named only whichever beat last. The
        first worker was not stale, not missing, not reported at all. After: two keys, two
        entries, and neither can overwrite the other.
        """
        from core import worker_heartbeat

        client = _redis_or_skip(worker_heartbeat)
        for key in client.keys(worker_heartbeat._prefix() + "*"):
            client.delete(key)
        try:
            monkeypatch.setenv("WORKER_ID", "worker-A")
            assert worker_heartbeat.beat(loop_count=7) is True
            monkeypatch.setenv("WORKER_ID", "worker-B")
            assert worker_heartbeat.beat(loop_count=3) is True

            first = json.loads(client.get(worker_heartbeat._key("worker-A")))
            second = json.loads(client.get(worker_heartbeat._key("worker-B")))
            assert first["loop_count"] == 7, "worker B overwrote worker A's heartbeat"
            assert second["loop_count"] == 3

            report = worker_heartbeat.read()
            assert report["worker_count"] == 2
            assert report["alive_count"] == 2
            assert {w["worker_id"] for w in report["workers"]} == {"worker-A", "worker-B"}
            # With two workers there is no single "the worker" to name, so the compat
            # field is None rather than an arbitrary pick.
            assert report["heartbeat"] is None
            assert report["heartbeat_summary"] is None
        finally:
            for key in client.keys(worker_heartbeat._prefix() + "*"):
                client.delete(key)


# ------------------------------------------------------------- a worker that is SIGKILLed


class TestAKilledWorkerStopsLookingAliveWithinTheWindow:
    """Phase 9 measured 150 s; Phase 41 lowered the window to 30 s and measured 27–30 s.

    A SIGKILLed process cannot clear its key or stop beating, so its state is a function of
    the age of its last beat. That is the same mechanism as before - the change is the
    constant, and the measurement that the constant holds in a real process
    (`docs/audit/PHASE_41_WORKER_RELIABILITY.md` §3: stale at +30.0 s from a live SIGKILL).
    """

    @pytest.mark.parametrize(
        ("age_seconds", "expected"),
        [
            (0.0, "alive"),  # the moment of the kill
            (29.0, "alive"),  # one second inside the fresh window
            (31.0, "stale"),  # past it: reported stale, not alive
            (89.0, "stale"),  # still present, still stale
        ],
    )
    def test_the_reported_state_for_a_heartbeat_of_a_given_age(
        self, age_seconds, expected
    ):
        """The state the endpoint returns is a function of age alone."""
        from core import worker_heartbeat

        client = _redis_or_skip(worker_heartbeat)
        for key in client.keys(worker_heartbeat._prefix() + "*"):
            client.delete(key)
        try:
            payload = {
                "worker_id": "worker-kill9",
                "loop_count": 1,
                "at": time.time() - age_seconds,
                "pid": 12345,
            }
            client.set(
                worker_heartbeat._key("worker-kill9"),
                json.dumps(payload),
                ex=worker_heartbeat.DEFAULT_TTL_SECONDS,
            )
            state = worker_heartbeat.read("worker-kill9")
            assert state["status"] == expected
        finally:
            for key in client.keys(worker_heartbeat._prefix() + "*"):
                client.delete(key)

    def test_the_detection_window_is_bounded_by_the_fresh_window(self):
        """The number in the report is the number in the code, not a value copied twice."""
        from core import worker_heartbeat

        assert worker_heartbeat.FRESH_WINDOW_SECONDS == 30, (
            "the window moved; re-measure detection before changing this assertion"
        )
        assert worker_heartbeat.DEFAULT_TTL_SECONDS == 90
        assert worker_heartbeat.BEAT_INTERVAL_SECONDS < worker_heartbeat.FRESH_WINDOW_SECONDS
        # Two consecutive missed beats must not stale a healthy worker.
        assert worker_heartbeat.BEAT_INTERVAL_SECONDS * 2 <= worker_heartbeat.FRESH_WINDOW_SECONDS

    def test_a_real_sigkill_leaves_the_key_intact(self, tmp_path):
        """Verified by killing a process rather than by reasoning about it.

        A short-lived child writes one heartbeat and blocks; SIGKILL gives it no chance to
        clean up, which is the point. If the key vanished on kill, detecting the crash
        would be "working" for the wrong reason - the worker would look like it never
        started rather than like it died.
        """
        from core import worker_heartbeat

        client = _redis_or_skip(worker_heartbeat)
        for key in client.keys(worker_heartbeat._prefix() + "*"):
            client.delete(key)
        code = (
            "import os,sys,time;"
            "sys.path.insert(0, %r);"
            "os.environ['REDIS_URL']=%r;"
            "from core import worker_heartbeat;"
            "worker_heartbeat.beat(loop_count=1, worker_id='worker-sigkill');"
            "time.sleep(60)"
        ) % (REPO_ROOT, os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0"))
        proc = subprocess.Popen([sys.executable, "-c", code], cwd=str(tmp_path))
        try:
            for _ in range(100):
                if client.exists(worker_heartbeat._key("worker-sigkill")):
                    break
                time.sleep(0.1)
            assert client.exists(worker_heartbeat._key("worker-sigkill")), (
                "the child never wrote a heartbeat"
            )
            assert worker_heartbeat.read("worker-sigkill")["status"] == "alive"

            proc.kill()
            proc.wait(timeout=30)
            assert proc.returncode not in (0, None)

            assert client.exists(worker_heartbeat._key("worker-sigkill")), (
                "the heartbeat key vanished when the process was SIGKILLed; a killed "
                "worker would then be reported as never having started"
            )
            assert worker_heartbeat.read("worker-sigkill")["status"] == "alive", (
                "SIGKILL should leave a fresh heartbeat behind - the process had no chance "
                "to clear it or to stop beating"
            )
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)
            for key in client.keys(worker_heartbeat._prefix() + "*"):
                client.delete(key)


# ------------------------------------------------- cross-process scheduler exclusion


class TestTwoProcessesCannotRunTheSameScheduledStep:
    """Measured: one winner, one loser, across two OS processes and one lock key."""

    def test_exactly_one_of_two_processes_claims_the_lock(self):
        """The scheduler steps are guarded by `claim_notification_lock`, a PK insert.

        That it is atomic within one process is not the question - a single asyncio loop
        cannot race itself. The question is whether it still excludes when the two callers
        are separate processes with separate database connections, because that is the
        shape a second worker creates.
        """
        script = tmp_path_script = None
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as handle:
            handle.write(
                "import sys;sys.path.insert(0, %r)\n"
                "import database\n"
                "database.init_db()\n"
                "key, tag = sys.argv[1], sys.argv[2]\n"
                "print(tag, database.claim_notification_lock(key, channel='system', ttl_seconds=240))\n"
                % REPO_ROOT
            )
            script = handle.name
        tmp_path_script = script

        lock_key = f"p9_cross_process:{int(time.time())}"
        env = {**os.environ}
        try:
            procs = [
                subprocess.Popen(
                    [sys.executable, tmp_path_script, lock_key, tag],
                    cwd=REPO_ROOT,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for tag in ("A", "B")
            ]
            outputs = [proc.communicate(timeout=120)[0] for proc in procs]
        finally:
            os.unlink(tmp_path_script)

        claims = [line.strip() for output in outputs for line in output.splitlines() if line.strip()]
        granted = [line for line in claims if line.endswith("True")]
        refused = [line for line in claims if line.endswith("False")]
        assert len(granted) == 1, f"expected exactly one process to win, got: {claims}"
        assert len(refused) == 1, f"expected exactly one process to lose, got: {claims}"
