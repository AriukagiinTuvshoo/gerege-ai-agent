"""Phase 41 — per-worker heartbeat isolation, crash detection, and multi-worker reliability.

Phase 9 measured three defects and wrote them down as limitations:

  * two worker processes shared one Redis key, so the last beat won and the other worker
    was not stale, not missing, not reported at all;
  * `worker_id` defaulted to the literal string `"worker-1"`, so even the surviving name
    was not an identity;
  * a SIGKILLed worker read `alive` for 150 s.

This file is the behavioural evidence that all three are fixed, and that the fixes did not
cost anything the old design provided. Every number asserted here was measured first; the
measurements are in `docs/audit/PHASE_41_WORKER_RELIABILITY.md`.

Two rules these tests follow, both learned the hard way in this repository:

  * **no source-string assertions where behaviour can be exercised.** "The code contains
    `_key(worker_id)`" proves nothing about whether two workers collide; two beats and two
    GETs do.
  * **every critical fix gets a negative control.** The pre-fix module is available at
    `git show 4e9acf8:core/worker_heartbeat.py`; the controls in
    `TestNegativeControlsAgainstThePreFixModule` load it and show these properties failing
    there, so the tests are known to be capable of failing.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
import uuid

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: The Phase 40 final commit - i.e. the code before this phase's fix.
PRE_FIX_COMMIT = "4e9acf8"


def _plain(value):
    """Redis may hand back bytes or str depending on decode_responses; normalise."""
    if isinstance(value, bytes):
        return value.decode()
    return str(value)


@pytest.fixture()
def hb():
    from core import worker_heartbeat

    return worker_heartbeat


@pytest.fixture()
def redis_client(hb):
    """A live Redis with no worker heartbeats in it, before and after."""
    client = hb._redis()
    if client is None:
        pytest.skip("needs a live Redis: the heartbeat is Redis-backed by design")

    def wipe():
        for key in client.keys(hb._prefix() + "*"):
            client.delete(key)

    wipe()
    yield client
    wipe()


# --------------------------------------------------------------- unique heartbeat keys


class TestEveryWorkerGetsItsOwnKey:
    def test_two_workers_write_two_keys(self, hb, redis_client):
        hb.beat(1, worker_id="alpha")
        hb.beat(2, worker_id="beta")
        keys = sorted(_plain(k).rsplit(":", 1)[-1] for k in redis_client.keys(hb._prefix() + "*"))
        assert keys == ["alpha", "beta"]

    def test_one_worker_cannot_overwrite_another(self, hb, redis_client):
        """The Phase 9 defect, as an assertion.

        Before: the second beat replaced the first and `read()` named only the second.
        """
        hb.beat(loop_count=7, worker_id="alpha")
        hb.beat(loop_count=3, worker_id="beta")
        alpha = json.loads(redis_client.get(hb._key("alpha")))
        beta = json.loads(redis_client.get(hb._key("beta")))
        assert alpha["loop_count"] == 7
        assert beta["loop_count"] == 3

    def test_the_default_identity_is_not_a_constant(self, hb, monkeypatch):
        """`"worker-1"` could not distinguish two processes; that was defect 2."""
        monkeypatch.delenv("WORKER_ID", raising=False)
        first = hb.current_worker_id()
        assert first != "worker-1", "the fallback identity is a constant again"
        assert str(os.getpid()) in first, "the identity does not name this process"

    def test_the_identity_matches_what_the_job_table_records(self, hb, monkeypatch):
        """The heartbeat and `task_jobs.locked_by` must name a worker the same way.

        Two names for one process is how a dashboard and a database end up disagreeing
        about which worker is which.
        """
        from core.task_queue import task_queue

        monkeypatch.delenv("WORKER_ID", raising=False)
        assert hb.current_worker_id() == task_queue.worker_id

    def test_an_explicit_worker_id_wins(self, hb, monkeypatch):
        monkeypatch.setenv("WORKER_ID", "stable-name-for-this-host")
        assert hb.current_worker_id() == "stable-name-for-this-host"


# --------------------------------------------------------------- two and three workers


class TestTwoWorkers:
    def test_both_stay_visible(self, hb, redis_client):
        hb.beat(worker_id="w-a")
        hb.beat(worker_id="w-b")
        pool = hb.read()
        assert pool["worker_count"] == 2
        assert pool["alive_count"] == 2
        assert {w["worker_id"] for w in pool["workers"]} == {"w-a", "w-b"}

    def test_one_dying_does_not_hide_the_other(self, hb, redis_client):
        """A crashed worker must not remove a healthy one from the report.

        This is the property a single key could not have: writing the survivor's beat
        would have overwritten the corpse, and the pool would read as perfectly healthy.
        """
        hb.beat(worker_id="w-a")
        hb.beat(worker_id="w-b")
        # a's last beat is old enough to be stale; b keeps beating.
        redis_client.set(
            hb._key("w-a"),
            json.dumps({"worker_id": "w-a", "loop_count": 1, "at": time.time() - 100, "pid": 1}),
            ex=hb.DEFAULT_TTL_SECONDS,
        )
        hb.beat(worker_id="w-b")
        pool = hb.read()
        assert pool["status"] == "alive", "the pool must still be usable with one worker up"
        assert pool["alive_count"] == 1
        assert pool["stale_count"] == 1
        states = {w["worker_id"]: w["status"] for w in pool["workers"]}
        assert states == {"w-a": "stale", "w-b": "alive"}

    def test_the_pool_is_degraded_when_only_some_workers_are_stale(self, hb, redis_client):
        hb.beat(worker_id="w-a")
        hb.beat(worker_id="w-b")
        redis_client.set(
            hb._key("w-a"),
            json.dumps({"worker_id": "w-a", "loop_count": 1, "at": time.time() - 100, "pid": 1}),
            ex=hb.DEFAULT_TTL_SECONDS,
        )
        pool = hb.read()
        assert pool["stale_count"] == 1
        # The aggregate stays "alive" (the service is up) but the count says degraded.
        # A single boolean could not express "1 of 2" - which is why the pool counts exist.
        assert pool["status"] == "alive"
        assert "1 of 2" in pool.get("reason", "")


class TestThreeWorkers:
    def test_three_stay_visible_and_independent(self, hb, redis_client):
        for index, name in enumerate(("w-1", "w-2", "w-3")):
            hb.beat(loop_count=index, worker_id=name)
        pool = hb.read()
        assert pool["worker_count"] == 3
        assert pool["alive_count"] == 3
        counts = {w["worker_id"]: w["loop_count"] for w in pool["workers"]}
        assert counts == {"w-1": 0, "w-2": 1, "w-3": 2}

    def test_losing_two_of_three_is_reported_as_a_degraded_pool(self, hb, redis_client):
        for name in ("w-1", "w-2", "w-3"):
            hb.beat(worker_id=name)
        for name in ("w-2", "w-3"):
            redis_client.set(
                hb._key(name),
                json.dumps({"worker_id": name, "loop_count": 1,
                            "at": time.time() - 100, "pid": 1}),
                ex=hb.DEFAULT_TTL_SECONDS,
            )
        pool = hb.read()
        assert pool["status"] == "alive"
        assert pool["alive_count"] == 1
        assert pool["stale_count"] == 2
        assert "1 of 3" in pool.get("reason", "")


# --------------------------------------------------------------- detection and restarts


class TestDeadWorkerDetection:
    def test_a_crashed_worker_goes_stale_within_the_window(self, hb, redis_client):
        """The detection target, as arithmetic on the age of the last beat."""
        hb.beat(worker_id="w-doomed")
        # Simulate the process stopping dead: its key stays, its age grows.
        redis_client.set(
            hb._key("w-doomed"),
            json.dumps({"worker_id": "w-doomed", "loop_count": 1,
                        "at": time.time() - (hb.FRESH_WINDOW_SECONDS + 1), "pid": 1}),
            ex=hb.DEFAULT_TTL_SECONDS,
        )
        state = hb.read("w-doomed")
        assert state["status"] == "stale"
        assert state["status"] != "alive"

    def test_a_worker_is_not_stale_at_the_boundary(self, hb, redis_client):
        """One second inside the window must still read alive, or the target is a lie."""
        redis_client.set(
            hb._key("w-ok"),
            json.dumps({"worker_id": "w-ok", "loop_count": 1,
                        "at": time.time() - (hb.FRESH_WINDOW_SECONDS - 1), "pid": 1}),
            ex=hb.DEFAULT_TTL_SECONDS,
        )
        assert hb.read("w-ok")["status"] == "alive"

    def test_two_consecutive_missed_beats_do_not_stale_a_healthy_worker(self, hb):
        """The allowance that makes a 30 s window safe rather than jittery."""
        assert hb.BEAT_INTERVAL_SECONDS * 2 <= hb.FRESH_WINDOW_SECONDS

    def test_graceful_shutdown_removes_only_that_worker(self, hb, redis_client, monkeypatch):
        """`clear()` used to delete the single shared key, which would kill the pool view.

        It must now remove this worker's key and leave its siblings alone - and it must
        actually be called on shutdown, which the pre-fix worker never did (defect 3).
        """
        hb.beat(worker_id="w-a")
        hb.beat(worker_id="w-b")
        monkeypatch.setenv("WORKER_ID", "w-a")
        hb.clear()
        assert not redis_client.exists(hb._key("w-a"))
        assert redis_client.exists(hb._key("w-b"))
        assert hb.read()["worker_count"] == 1

    def test_a_restart_with_the_same_id_reuses_one_key(self, hb, redis_client):
        """A restart must not leave a corpse behind for a new process to compete with."""
        hb.beat(loop_count=1, worker_id="w-restart")
        hb.clear(worker_id="w-restart")  # graceful stop
        hb.beat(loop_count=1, worker_id="w-restart")  # start again
        keys = redis_client.keys(hb._key("w-restart") + "*")
        assert len(keys) == 1
        assert hb.read("w-restart")["status"] == "alive"

    def test_a_restart_with_a_new_id_leaves_the_old_one_visible_until_it_expires(
        self, hb, redis_client
    ):
        """The honest behaviour: a crashed worker's key is not deleted by its successor.

        It cannot be - the successor has no way to know the key is a corpse rather than a
        live sibling. It ages out via the TTL, which is why the TTL is bounded.
        """
        hb.beat(worker_id="w-old")
        # The old process dies without clearing.
        hb.beat(worker_id="w-new")
        assert hb.read()["worker_count"] == 2
        ttl = redis_client.ttl(hb._key("w-old"))
        assert 0 < ttl <= hb.DEFAULT_TTL_SECONDS, (
            "a dead worker's key must expire on its own; without a bounded TTL the pool "
            "accumulates corpses and every count becomes meaningless"
        )

    def test_expired_keys_are_cleaned_by_redis_not_by_the_application(self, hb, redis_client):
        redis_client.set(
            hb._key("w-gone"),
            json.dumps({"worker_id": "w-gone", "loop_count": 1, "at": time.time(), "pid": 1}),
            ex=1,
        )
        assert hb.read()["worker_count"] == 1
        time.sleep(1.3)
        pool = hb.read()
        assert pool["worker_count"] == 0
        assert pool["status"] == "missing"


# ---------------------------------------------------------------------- Redis behaviour


class TestRedisOutage:
    def test_an_unreachable_redis_reports_unknown_not_dead(self, hb, monkeypatch):
        """The dependency failing is not the workers failing, and the answer must say so."""
        monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:6399/0")
        from core.task_queue import task_queue

        saved_url, saved_client = task_queue.redis_url, task_queue._redis
        task_queue.redis_url = "redis://127.0.0.1:6399/0"
        task_queue._redis = None
        task_queue._last_redis_attempt = 0.0
        try:
            state = hb.read()
            assert state["status"] == "unknown"
            assert "redis" in state.get("reason", "").lower(), (
                "an unknown state must name Redis as the cause, or an operator will read it "
                "as a worker problem"
            )
            assert state["status"] not in ("missing", "stale", "alive")
        finally:
            task_queue.redis_url = saved_url
            task_queue._redis = saved_client

    def test_beat_does_not_raise_when_redis_is_down(self, hb, monkeypatch):
        """A monitoring write must never stop the process it monitors.

        "Down" is simulated with a client whose every operation raises, which is what a
        refused connection looks like to this module. Pointing REDIS_URL at a dead port is
        NOT enough: `task_queue._get_redis()` keeps the connection pool it already has, so
        the call succeeds against the old server and the test would prove nothing. That
        was measured here before the test was rewritten.
        """
        class Refusing:
            def set(self, *args, **kwargs):
                raise ConnectionError("Connection refused")

            def get(self, *args, **kwargs):
                raise ConnectionError("Connection refused")

            def keys(self, *args, **kwargs):
                raise ConnectionError("Connection refused")

            def delete(self, *args, **kwargs):
                raise ConnectionError("Connection refused")

        monkeypatch.setattr(hb, "_redis", lambda: Refusing())
        assert hb.beat(1, worker_id="w-x") is False, "beat() must report failure, not raise"
        assert hb.read()["status"] == "unknown"
        hb.clear(worker_id="w-x")  # must not raise either


# ------------------------------------------------------------------------- key safety


class TestWorkerIdentityCannotEscapeTheKey:
    """A worker id is caller-supplied and becomes part of a Redis key."""

    @pytest.mark.parametrize(
        "bad",
        [
            "evil:key",           # a namespace separator
            "a\nFLUSHALL",        # a line break into a pipeline
            "with space",
            "x" * 200,            # unbounded
            "",
            "../../etc/passwd",
            "ключ",               # non-ASCII, which some key encoders mangle
        ],
    )
    def test_unsafe_ids_are_rejected(self, hb, bad):
        with pytest.raises(ValueError):
            hb.validate_worker_id(bad)

    def test_beat_refuses_an_unsafe_id_before_touching_redis(self, hb):
        with pytest.raises(ValueError):
            hb.beat(1, worker_id="bad:id")
        with pytest.raises(ValueError):
            hb.read("bad:id")

    def test_a_normal_generated_id_is_accepted(self, hb):
        hb.validate_worker_id(hb.current_worker_id())  # must not raise


class TestThePayloadCarriesNoSecrets:
    def test_unlisted_keys_never_reach_redis(self, hb, redis_client):
        hb.beat(1, worker_id="w", extra={"secret_token": "SHOULD_NOT_APPEAR"})
        stored = _plain(redis_client.get(hb._key("w")))
        assert "SHOULD_NOT_APPEAR" not in stored
        assert "secret_token" not in stored

    def test_no_redis_url_or_password_is_stored(self, hb, redis_client):
        hb.beat(1, worker_id="w")
        stored = _plain(redis_client.get(hb._key("w")))
        assert "redis://" not in stored
        assert "password" not in stored.lower()


# ------------------------------------------------------------------------- pool health


class TestPoolHealthIsDerivedFromIndividualWorkers:
    def test_an_empty_pool_is_missing_not_unknown(self, hb, redis_client):
        assert hb.read()["status"] == "missing"

    def test_one_alive_makes_the_pool_alive(self, hb, redis_client):
        hb.beat(worker_id="w-a")
        assert hb.read()["status"] == "alive"

    def test_all_stale_makes_the_pool_stale(self, hb, redis_client):
        for name in ("w-a", "w-b"):
            redis_client.set(
                hb._key(name),
                json.dumps({"worker_id": name, "loop_count": 1,
                            "at": time.time() - 100, "pid": 1}),
                ex=hb.DEFAULT_TTL_SECONDS,
            )
        assert hb.read()["status"] == "stale"

    def test_the_compat_field_names_a_worker_only_when_there_is_exactly_one(
        self, hb, redis_client
    ):
        """The old `read()["heartbeat"]` shape survives, but only where it is unambiguous."""
        hb.beat(loop_count=5, worker_id="w-only")
        assert hb.read()["heartbeat"]["worker_id"] == "w-only"
        hb.beat(worker_id="w-second")
        assert hb.read()["heartbeat"] is None, (
            "with two workers there is no single 'the worker'; picking one is the bug "
            "this phase fixed"
        )


# ------------------------------------------------------------- negative controls (RED)


class TestNegativeControlsAgainstThePreFixModule:
    """Load the pre-fix module and show these properties are FALSE there.

    A test that has never failed is not evidence. Each control below exercises the same
    scenario against `core/worker_heartbeat.py` as it existed at Phase 40's final commit
    and asserts the DEFECT, so the pair (control fails / current test passes) is what makes
    the fix observable.
    """

    @pytest.fixture()
    def pre_fix(self):
        source = subprocess.run(
            ["git", "show", f"{PRE_FIX_COMMIT}:core/worker_heartbeat.py"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if source.returncode != 0:
            pytest.skip(f"cannot read {PRE_FIX_COMMIT} from this checkout")
        path = os.path.join(REPO_ROOT, f".pre_fix_heartbeat_{os.getpid()}.py")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(source.stdout)
        spec = importlib.util.spec_from_file_location("pre_fix_heartbeat", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        yield module
        os.unlink(path)

    def test_control_the_pre_fix_module_shared_one_key(self, hb, pre_fix, redis_client):
        # The same call on the two modules, to show they really do differ.
        redis_client.delete(pre_fix._key())
        pre_fix.beat(1, worker_id="alpha")
        pre_fix.beat(2, worker_id="beta")
        pre_fix_keys = redis_client.keys("gerege:worker:heartbeat*")
        assert len(pre_fix_keys) == 1, "the pre-fix module was supposed to collide"
        assert pre_fix.read()["heartbeat"]["worker_id"] == "beta"

        for key in redis_client.keys(hb._prefix() + "*"):
            redis_client.delete(key)
        hb.beat(1, worker_id="alpha")
        hb.beat(2, worker_id="beta")
        assert len(redis_client.keys(hb._prefix() + "*")) == 2

    def test_control_the_pre_fix_window_was_150_seconds(self, pre_fix, hb):
        assert pre_fix.FRESH_WINDOW_SECONDS == 150
        assert hb.FRESH_WINDOW_SECONDS == 30
        assert hb.FRESH_WINDOW_SECONDS < pre_fix.FRESH_WINDOW_SECONDS

    def test_control_the_pre_fix_default_identity_was_a_constant(self, pre_fix):
        """The pre-fix module had no per-process identity to fall back to at all."""
        assert not hasattr(pre_fix, "current_worker_id"), (
            "if the pre-fix module gained this attribute the control is comparing the "
            "wrong code"
        )

    def test_control_the_pre_fix_module_had_no_key_validation(self, pre_fix):
        assert not hasattr(pre_fix, "validate_worker_id")
        # And it wrote whatever it was given straight into a key:
        assert pre_fix._key() == "gerege:worker:heartbeat"


class TestAPreviousReleaseWorkerIsStillVisible:
    """Phase 41 finding, found by this phase's own pool view.

    Before Phase 41 there was exactly one heartbeat key: the bare prefix. A worker still
    running the previous release writes that key and nothing else. The first version of the
    pool view scanned only `<prefix>:*`, so during a rolling deploy it reported `missing`
    while the old worker was alive and processing jobs - a liveness signal that is wrong in
    the most dangerous direction, because it invites a restart of something that is working.

    These use a dedicated prefix so they cannot be confused by, or confuse, other keys.
    """

    @pytest.fixture
    def client(self, monkeypatch):
        from core import worker_heartbeat

        if not os.getenv("REDIS_URL"):
            pytest.fail("REDIS_URL is not set; the legacy-key path cannot be verified")
        prefix = f"gerege:test:p41legacy:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        monkeypatch.setenv("WORKER_HEARTBEAT_KEY", prefix)
        redis_client = worker_heartbeat._redis()
        for key in redis_client.keys(prefix + "*"):
            redis_client.delete(key)
        yield redis_client
        for key in redis_client.keys(prefix + "*"):
            redis_client.delete(key)

    def test_an_old_worker_writing_the_bare_key_is_reported_alive(self, client):
        import json
        import time

        from core import worker_heartbeat

        client.set(
            worker_heartbeat._key(),
            json.dumps({"worker_id": "old-worker", "loop_count": 7, "at": time.time(), "pid": 1}),
            ex=5000,
        )
        report = worker_heartbeat.read()
        assert report["status"] == "alive", report
        assert report["worker_count"] == 1, report
        assert report["workers"][0]["worker_id"] == "old-worker", report["workers"]

    def test_an_old_worker_mixed_with_a_new_one_is_reported_as_two(self, client):
        """The deploy actually in flight: both layouts live at once."""
        import json
        import time

        from core import worker_heartbeat

        client.set(
            worker_heartbeat._key(),
            json.dumps({"worker_id": "old-worker", "loop_count": 7, "at": time.time(), "pid": 1}),
            ex=5000,
        )
        worker_heartbeat.beat(1, worker_id="new-worker")
        report = worker_heartbeat.read()
        assert report["worker_count"] == 2, report
        assert {w["worker_id"] for w in report["workers"]} == {"old-worker", "new-worker"}
        assert report["status"] == "alive"
        # And the compatibility name is withheld, because two workers exist.
        assert report["heartbeat"] is None

    def test_a_stale_old_worker_is_not_reported_alive(self, client):
        """The same rule as for a new worker: age decides, not the layout of the key."""
        import json
        import time

        from core import worker_heartbeat

        client.set(
            worker_heartbeat._key(),
            json.dumps(
                {"worker_id": "old-worker", "loop_count": 7, "at": time.time() - 99999, "pid": 1}
            ),
            ex=5000,
        )
        report = worker_heartbeat.read()
        assert report["status"] == "stale", report

    def test_negative_control_a_prefix_glob_alone_misses_the_bare_key(self, client):
        """The mechanism, isolated: `<prefix>:*` does not match `<prefix>`.

        This is how the defect arises, and it is worth asserting directly because it is a
        property of Redis globbing rather than of any version of this module. If the glob
        ever matched the bare key, the extra `client.get(legacy_key)` in `read()` would be
        unnecessary - and the reverse is what the bug was.
        """
        import json
        import time

        from core import worker_heartbeat

        client.set(
            worker_heartbeat._key(),
            json.dumps({"worker_id": "old-worker", "loop_count": 7, "at": time.time(), "pid": 1}),
            ex=5000,
        )
        globbed = client.keys(worker_heartbeat._prefix() + ":*")
        assert not globbed, (
            f"the prefix glob matched {globbed!r}; the defect being fixed is that it does not "
            "match the bare key, so this control is no longer measuring anything"
        )
        # ...while the key itself is plainly present.
        assert client.get(worker_heartbeat._key())
        # And `read()` accounts for it anyway.
        assert worker_heartbeat.read()["worker_count"] == 1
