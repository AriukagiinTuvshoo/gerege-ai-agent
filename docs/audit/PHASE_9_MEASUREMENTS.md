# Phase 9 — the measurements Phase 9 left out

Phase 9 built the observability surface and said so in `PROGRESS.md`. What it did not do
is measure the behaviour of the thing being observed. Three questions had no number
behind them, and this file records what they are, how they were measured, and what the
answers mean.

Everything below was measured on this checkout against the real code paths — `worker.py`'s
own loop, `core/worker_heartbeat.py`, and `database.claim_notification_lock` — not reasoned
about from reading them. The measurements are pinned by
`tests/test_e09_worker_scale_measurements.py` (9 cases, gated in CI).

---

## 1. Two worker processes on one heartbeat key

**Question:** the heartbeat is one Redis key per deployment (`gerege:worker:heartbeat`),
and its payload names one `worker_id`. What happens when two worker processes run?

**Measured:** the second worker's beat replaces the first's, entirely.

```
STORED: {"worker_id": "worker-B", "loop_count": 0, "pid": 1877894, ...}
READ:   {"status": "alive", "heartbeat": {"worker_id": "worker-B", ...}}
```

`worker-A` is not represented in what the endpoint returns, and no second payload exists
to compare against. `loop_count` and `queue_processed` are per process, so what the
endpoint shows for them is one process's numbers presented as the deployment's.

**What this means.** A deployment running two worker processes is reported as running one,
and the id it reports is whichever process beat last. Nothing here is broken for the
current topology — production runs a single worker process, and `_key` says so:

> The production topology is a single worker process; if that ever becomes a pool, the
> endpoint below already reports per-worker ids from the stored payload and this can be
> extended to a hash without changing the response shape.

That comment is half right. The response shape does carry a `worker_id`, so reading it is
already possible, but *storing* more than one requires the key to become a hash or to be
per-worker. Scaling the worker out before doing that halves the reported queue throughput
and hides a worker's death, and both would look like a quiet period.

**Verdict:** limitation, not defect. Recorded so that scaling out is a decision made with
this number in hand.

---

## 2. How long a `kill -9`ed worker reads `alive`

**Question:** a SIGKILLed worker writes no final heartbeat and gets no chance to clear its
key. How long does `/api/admin/worker` keep saying it is fine?

**Measured** by killing a real worker with SIGKILL and polling `read()`:

| After the kill | `status` | key present | heartbeat age |
|---|---|---|---|
| immediately | `alive` | yes | 0.2 s |
| +1 s | `alive` | yes | 1.2 s |
| +30 s | `alive` | yes | 30.2 s |
| +120 s | `alive` | yes | 120.2 s |
| +190 s | `missing` | no | — |

So there is a **150 second window in which a dead worker is reported as alive**, then a
30 second band reported as `stale`, then `missing` once the 180 s TTL expires. The
boundary is `FRESH_WINDOW_SECONDS` exactly: at 149 s the state is `alive`, at 151 s it is
`stale`.

**What this means.** This is the cost of a TTL-key design and it is the right trade (no
schema change, the key cleans itself up), but the number matters operationally: the
alerting rule for "worker died" cannot be `status != alive` if the response is meant to be
acted on inside two and a half minutes. Anything faster needs an active probe — the queue
consumer's own clock, not the process's last confession.

The window is not a bug to fix so much as a budget to state. It is stated here.

---

## 3. Two processes and one scheduled step

**Question:** every scheduler step claims a lock before it runs
(`database.claim_notification_lock`, a primary-key insert). That is atomic within one
process trivially — a single asyncio loop cannot race itself. Does it still exclude when
the two callers are separate OS processes with separate database connections?

**Measured:** yes. Two processes started concurrently against the same lock key:

```
A True
B False
```

Exactly one winner, one loser, no wait-and-both-succeed, no duplicate step. The same was
measured for the actual production shape of the lock: the retention step's
`scheduler:retention:<minute>` key and the daily report's
`daily_exec_report:<page>:<date>` key are both claimed this way.

**What this means.** Scaling the worker out does not double-send the daily report or
double-run retention. This is the one of the three questions where the answer is
unambiguously good, and it means the heartbeat limitation in §1 is a visibility problem
rather than a correctness one.

---

## Summary

| Question | Answer | Kind |
|---|---|---|
| Two workers, one heartbeat key | last beat wins; the others are invisible | limitation (§1) |
| `kill -9`, then `/api/admin/worker` | `alive` for 150 s, `stale` for 30 s, then `missing` | budget (§2) |
| Two processes, one scheduled step | exactly one runs it | correct (§3) |

None of these required a code change. Two of them are constraints an operator needs to
know and now can look up; the third confirms that the lock design survives the topology
change it was never explicitly tested against.
