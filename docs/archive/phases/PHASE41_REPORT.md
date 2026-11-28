# Phase 41 — Worker Reliability, Heartbeat Isolation & S3 CI Coverage

**Branch** `arena/d78ebf88-gerege-ai-agent` · **Final HEAD** `814afb6be107f014c572781ca4c4bb11f8442885`
**CI** run `45419076024` — `completed / success` on that exact SHA
**PR #1** — OPEN, unmerged, head = `814afb6`

---

## Verdicts

| Area | Verdict | Basis |
|---|---|---|
| Worker reliability | **PASS** | 40/40 jobs drained by 2 workers, 0 duplicates |
| Heartbeat accuracy | **PASS** | per-worker keys; alive 0.36 s after start |
| Crash detection | **PASS** | `kill -9` → stale 29.6 s, missing 89.7 s |
| Multi-worker | **PASS** | 2/2 and 3/3 alive, distinct ids, isolated staleness |
| S3 CI coverage | **PASS** | 46 skips eliminated; 258 passed / 1 skipped / 259 collected |
| Backup / restore | **PASS** | 17/17 integrity + 11/11 integration on moto |
| Security | **PASS** | no real-AWS reachable; production refuses plaintext |
| CI reliability | **PASS** | first run found 2 real defects; second run green |
| PR merge readiness | **READY — not merged** | await authorization |

---

## Findings

Each was found by this phase's own work, not by restating a Phase 40 item.

### F-41-A — Shared heartbeat key: last writer wins, dead workers look alive (VERIFIED)
- **Severity** High
- **Root cause** Every worker wrote `gerege:worker:heartbeat`; `read()` returned that one payload and its `status` was computed from whoever beat last.
- **Repro** Two real processes → `KEYS gerege:worker:heartbeat*` returns **1** key; both report as `worker-1`.
- **Fix** One key per worker (`<prefix>:<id>`), id validated against `^[A-Za-z0-9._-]{1,128}$`, pool view reporting each worker separately.
- **Test** `tests/test_e41_worker_heartbeat_isolation.py` 42 passed; negative control loads `4e9acf8:core/worker_heartbeat.py` via `git show` and reproduces the collision.

### F-41-B — A previous-release worker is invisible to the pool view (VERIFIED — introduced by this phase, caught by this phase)
- **Severity** High
- **Root cause** My first pool implementation scanned only `<prefix>:*`. The pre-Phase-41 worker writes the bare `<prefix>`, which that glob does not match.
- **Repro** Bare key present and fresh → `read()` returned `worker_count=0`, `status=missing` while the worker was working. During a rolling deploy this would report "no workers" with live work in flight.
- **Fix** `read()` also reads the bare key and attributes it to the `worker_id` its payload carries.
- **Test** `TestAPreviousReleaseWorkerIsStillVisible` — 4 cases, including a control asserting `<prefix>:*` genuinely does **not** match `<prefix>` (so the fix is not redundant), and a mixed old+new case reporting 2 workers.

### F-41-C — Tick-driven heartbeat cannot support a 30 s window (VERIFIED)
- **Severity** High (would have caused false "dead worker" alerts)
- **Root cause** Liveness was written at the end of a tick; the loop sleeps 15 s and a slow batch measures 23.3 s, so the beat gap reached ~38 s.
- **Fix** A timer task beats every 10 s independently of the tick; the tick-completion write is kept only to publish counters.
- **Measured** `BEAT_INTERVAL*2 (20 s) ≤ FRESH_WINDOW (30 s)`; asserted in `test_e09`.

### F-41-D — 46 S3 cases skipped in CI and were excused by four `--allow-skip-file` entries (VERIFIED)
- **Severity** High (the offsite code never ran in CI)
- **Repro** Without an endpoint: **14 passed, 46 skipped, 4 failed**. With moto: **64 passed**.
- **Fix** CI starts `moto.server` on 127.0.0.1:5062; the four exceptions are removed; gate floor 257 passes / 259 collected; only the SQLite WAL skip remains permitted.
- **Test** `test_e41_s3_ci_coverage.py` (24) + `test_e41_s3_execution.py` (7).

### F-41-E — `moto[s3]` does not include the standalone server (VERIFIED in CI, fixed)
- **Severity** Medium (CI-only, but it blocked the phase's main deliverable)
- **Repro** First CI run: `ModuleNotFoundError: No module named 'moto.server'`. The step's guard **failed the run** rather than letting 46 cases skip — the guard did its job.
- **Root cause** The server entry point lives in the separate `server` extra (flask, flask-cors, …).
- **Fix** `pip install "moto[s3,server]==5.2.5"`.

### F-41-F — Staging rehearsal F-39-D check read an ambiguous name (VERIFIED in CI, fixed)
- **Severity** Medium
- **Root cause** The check runs `docker compose exec worker python` inside a container whose worker is already beating, then read `read()["heartbeat"]`. With per-worker keys there are two records, and `read()` deliberately names a worker only when exactly one exists.
- **Repro** Second worker present → `heartbeat=None`, check failed, while the tick's own record was `alive` with `scheduler_errors=1`.
- **Fix** The check now asks its real question — "did **my** tick leave **my** record alive and counted it" — via `read(current_worker_id())`. The e39 test covering the same property is tightened identically, and its cleanup, which deleted the bare prefix, now clears per-worker keys (it had become a no-op).

### F-41-G — Tests shared one heartbeat namespace with the whole run (VERIFIED)
- **Severity** Medium (test-integrity)
- **Root cause** `e38`/`e39` asserted single-worker liveness while every other suite used the same Redis DB. They passed before only because one key meant last-writer-wins.
- **Fix** Per-test prefix via the documented `WORKER_HEARTBEAT_KEY` override; nothing bypassed.

---

## Measurements

**Heartbeat / crash detection** (real processes, Redis :6380, TTL 90 s / window 30 s)

| Scenario | Result |
|---|---|
| Worker visible after start | **0.36 s** |
| `kill -9` → alive | +0–29.6 s |
| `kill -9` → stale | **29.6 s** |
| `kill -9` → missing (TTL) | **89.7 s** |
| Graceful SIGTERM | exit 0 → **0 keys**, `missing` |
| 2 workers / 3 workers | **2/2** · **3/3** alive, distinct ids |
| 4 workers, one staled | aggregate `alive`, **3 alive / 1 stale**, that worker alone `stale` |
| Redis unavailable | `unknown`, `beat()` → False, no exception |
| Unsafe worker id | rejected before Redis |

**Multi-worker end-to-end** (PG `p41_multi`, two real worker processes)

| Metric | Result |
|---|---|
| Jobs enqueued / completed | 40 / **40** |
| Failed / dead-letter | 0 / 0 |
| **Duplicates** | **0** (40 handled, 40 distinct) |
| Per-worker split | 25 / 15 (both did work) |
| Pool during run | `alive 2/2`, ids `split-alpha`/`split-bravo` |
| After graceful SIGTERM | **0 keys**, `missing` |

**S3 execution count** (the headline)

| Environment | Result |
|---|---|
| Phase 40 shape (no endpoint) | 14 passed, **46 skipped**, 4 failed |
| Phase 41 (moto :5062) | **64 passed, 0 skipped** |
| Backup step total, CI | **258 passed, 1 skipped, 259 collected** (was 181/47/228) |

**Test suites**

| Suite | Count |
|---|---|
| e41 heartbeat isolation | 42 |
| e41 S3 CI coverage | 24 |
| e41 S3 execution | 7 |
| e09 worker scale | 9 |
| e36 worker health | 19 |
| e38 / e39 / e40 | 89 total, green |
| **Full suite (local)** | **1882 passed, 0 failed, 4 skipped, 1 xfailed** |

**Skip breakdown (4, all legitimate and engine-gated — none S3)**
`test_e02_phase10_login_identity` (SQLite locking), `test_e02_phase41_hardening` (case folding), `test_e07_phase22_wal_copy_safety` (WAL on PG), `test_stage_b_regressions` (ALLOWED_ORIGINS unset).

---

## Force-push / history audit

- `origin/main` **is an ancestor** of HEAD; **0** commits on main are missing from HEAD.
- **182** commits on branch, **0 merge commits**, **0** `forced-update` entries in the reflog.
- The push to `814afb6` was a normal fast-forward (`ccde0e5..814afb6`).
- `git fsck --unreachable`: 55 dangling commits still present in the object DB.
- **Result: PASS — no history was rewritten, nothing was lost.**

---

## Security

- No credentials in the diff (`AKIA`/secret/token/private-key scan clean).
- `BACKUP_OFFSITE_TEST_ENDPOINT` is **test-only** — no production module reads it.
- `AWS_ACCESS_KEY_ID` is deliberately **not** set in CI: the suite skips if present (measured — setting it turned a pass into a skip).
- Plain-http offsite requires all three: explicit opt-in, loopback host, and non-production. Verified refused for prod+loopback and staging+public.
- Worker id validated before any Redis call.

## Limitations / residual risk

1. **CI logs were not downloadable** (`results-receiver` returned EOF). CI verdicts come from the runs/steps API and annotations; per-step log text could not be quoted.
2. **Phase 39 ran in CI only** — no Docker locally, so the rehearsal cannot be reproduced here.
3. Motos is an S3 *simulation*: it does not reproduce real AWS IAM, region, or throttling behaviour. Real-AWS tests remain explicitly external.
4. The legacy-key fix reads one extra key per `read()`; on a large pool this is a single `GET`, not a scan.
5. `p41_multi` ownership is `gerege`; connecting as `gerege_owner` fails with `InsufficientPrivilege` (a local artifact of the role split, not a product defect).

## Guardrail compliance

No `main` modification · no force-push · no history rewrite · no production deploy or credentials · no real AWS · no databases deleted · PR #1 **not merged** · disposable DBs only · floors derived from measurement, never lowered.

**Stopped here awaiting authorization.**
