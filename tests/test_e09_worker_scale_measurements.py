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

The answers are not all comfortable. (1) shows the second worker REPLACES the first's
heartbeat, so the endpoint reports one worker when two are running; (2) shows a killed
worker reads `alive` for up to FRESH_WINDOW_SECONDS. Both are recorded as they are - the
tests pin the current behaviour so a change is visible, and the ones that describe a
limitation say so in their own name.
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

    def test_the_second_worker_replaces_the_first_and_the_report_names_only_one(
        self, monkeypatch
    ):
        """Measurement, not intention: two beats, one surviving payload.

        A deployment running two worker processes is therefore reported as running one,
        and the id it reports is whichever beat last. The queue counters have the same
        problem: `loop_count` and the tick totals are per process, so the endpoint shows
        one process's numbers as though they were the deployment's.

        This is pinned rather than fixed because the production topology is a single
        worker process (see the comment on `_key`). The test exists so that turning the
        worker into a pool is a decision someone makes with this number in front of them,
        not a discovery made from a graph that silently halved.
        """
        from core import worker_heartbeat

        client = _redis_or_skip(worker_heartbeat)
        client.delete(worker_heartbeat._key())
        try:
            monkeypatch.setenv("WORKER_ID", "worker-A")
            assert worker_heartbeat.beat(loop_count=7) is True
            first = json.loads(client.get(worker_heartbeat._key()))
            assert first["worker_id"] == "worker-A"

            monkeypatch.setenv("WORKER_ID", "worker-B")
            assert worker_heartbeat.beat(loop_count=3) is True
            stored = json.loads(client.get(worker_heartbeat._key()))

            # One key. One payload. The first worker is no longer represented at all.
            assert stored["worker_id"] == "worker-B", "the last beat wins the single key"
            assert stored["loop_count"] == 3
            assert client.exists(worker_heartbeat._key())
            report = worker_heartbeat.read()
            assert report["status"] == "alive"
            assert report["heartbeat"]["worker_id"] == "worker-B"
        finally:
            client.delete(worker_heartbeat._key())


# ------------------------------------------------------------- a worker that is SIGKILLed


class TestAKilledWorkerStillReadsAlive:
    """Measured: `kill -9`, then `alive` for 150 s and `missing` after the 180 s TTL."""

    @pytest.mark.parametrize(
        ("age_seconds", "expected"),
        [
            (0.0, "alive"),  # the moment of the kill
            (30.0, "alive"),  # still called alive half a minute later
            (149.0, "alive"),  # one second inside the fresh window
            (151.0, "stale"),  # past it: reported stale, not dead
        ],
    )
    def test_the_reported_state_for_a_heartbeat_of_a_given_age(
        self, monkeypatch, age_seconds, expected
    ):
        """The state the endpoint returns is a function of age alone.

        A SIGKILLed process cannot clear its key, so this is exactly the sequence an
        operator sees: nothing distinguishes "working" from "killed" until the heartbeat
        ages out of the fresh window.
        """
        from core import worker_heartbeat

        client = _redis_or_skip(worker_heartbeat)
        client.delete(worker_heartbeat._key())
        try:
            payload = {
                "worker_id": "worker-kill9",
                "loop_count": 1,
                "at": time.time() - age_seconds,
                "pid": 12345,
            }
            client.set(worker_heartbeat._key(), json.dumps(payload), ex=180)
            assert worker_heartbeat.read()["status"] == expected
        finally:
            client.delete(worker_heartbeat._key())

    def test_the_measured_window_is_the_configured_fresh_window(self):
        """The number in the report is the number in the code, not a value copied twice."""
        from core import worker_heartbeat

        assert worker_heartbeat.FRESH_WINDOW_SECONDS == 150
        assert worker_heartbeat.DEFAULT_TTL_SECONDS == 180
        assert worker_heartbeat.FRESH_WINDOW_SECONDS < worker_heartbeat.DEFAULT_TTL_SECONDS

    def test_a_real_sigkill_leaves_the_key_intact(self, tmp_path):
        """The claim above, verified by killing a process rather than by reasoning about it.

        A short-lived child writes one heartbeat and blocks; SIGKILL gives it no chance to
        clean up, which is the point. If the key is gone afterwards the window above is
        fiction, and a worker crash would be reported correctly for the wrong reason.
        """
        from core import worker_heartbeat

        client = _redis_or_skip(worker_heartbeat)
        client.delete(worker_heartbeat._key())
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
                if client.exists(worker_heartbeat._key()):
                    break
                time.sleep(0.1)
            assert client.exists(worker_heartbeat._key()), "the child never wrote a heartbeat"
            assert worker_heartbeat.read()["status"] == "alive"

            proc.kill()
            proc.wait(timeout=30)
            assert proc.returncode not in (0, None)

            # The key survives the kill, and still reads alive.
            assert client.exists(worker_heartbeat._key()), (
                "the heartbeat key vanished when the process was SIGKILLed; a killed "
                "worker would then be reported as never having started"
            )
            assert worker_heartbeat.read()["status"] == "alive", (
                "SIGKILL should leave a fresh heartbeat behind - the process had no chance "
                "to clear it or to stop beating"
            )
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)
            client.delete(worker_heartbeat._key())


# ------------------------------------------------------- the report records the numbers

class TestTheMeasurementsAreWrittenDown:
    """A measurement that lives only in a commit message is lost by the next release."""

    REPORT = "docs/audit/PHASE_9_MEASUREMENTS.md"

    def test_the_report_exists_and_states_each_answer(self):
        with open(os.path.join(REPO_ROOT, self.REPORT), encoding="utf-8") as handle:
            text = handle.read()
        # §1: the second worker replaces the first.
        assert "last beat wins" in text or "second worker's beat replaces" in text
        # §2: the window, stated as a number and tied to the constant it comes from.
        from core import worker_heartbeat

        assert f"{worker_heartbeat.FRESH_WINDOW_SECONDS}` second window" in text or (
            f"{worker_heartbeat.FRESH_WINDOW_SECONDS} second" in text
        ), f"the report does not state the measured {worker_heartbeat.FRESH_WINDOW_SECONDS} s window"
        # §3: cross-process exclusion works.
        assert "exactly one" in text.lower()

    def test_the_report_does_not_promise_more_than_was_measured(self):
        """It records a limitation and a budget, not a fix for either."""
        with open(os.path.join(REPO_ROOT, self.REPORT), encoding="utf-8") as handle:
            text = handle.read()
        assert "limitation, not defect" in text.lower(), (
            "the two-worker finding is a limitation; calling it fixed would be untrue"
        )
        assert "budget" in text.lower()


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
