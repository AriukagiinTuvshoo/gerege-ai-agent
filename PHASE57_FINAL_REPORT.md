# PHASE 57 — FINAL REPORT

**Theme:** *A swallowed failure must still leave a trace.*

Phases 54–56 established that **what the caller is told** has to match **what was
actually written** (a 200 that writes nothing is a defect wearing a smile). Phase 57
is the mirror image of the same principle: places where the control flow was already
correct — the code fell back, retried, closed, or returned a default — but **said
nothing at all**, so the defect was invisible to the operator, to the log, and to the
caller who had to act on it.

Branch: `arena/d78ebf88-gerege-ai-agent` · base commit: `a6b441d` (Phase 56) ·
`origin/main` at the time of writing: `c809654` (unchanged, no merge performed).

---

## 1. Result summary

| id | site | defect class | BEFORE (measured) | AFTER (measured) | verdict |
|---|---|---|---|---|---|
| **F-57-1** | `dashboard.html` `handleManagerSend` | client discards the reply, clears the input first | reply of `POST /api/sessions/{id}/send` never read; server answers **404/403/400** live | reply assigned to `sendRes`, `!ok \|\| error` restores the text and shows the server's own wording; input cleared only after | **FIXED** |
| **F-57-2** | `dashboard.html` `handleSaveClientCredentials` | client discards the reply, then toasts success | `parseInt(limit)` → `NaN` → `null`; endpoint answers **200** `changed:[] preserved:[…,monthly_token_limit]`, stored limit stays **100000**; unconditional success toast | radix-10 parse, `Number.isFinite`/`>0` guard, `limitRes.ok` + `success===false` + `ignored_fields` checked, every failure branch `alert()`s and `return`s before the toast | **FIXED** |
| **F-57-3** | `dashboard.html` `handleLogout` | client discards the reply, reloads regardless | `window.location.reload()` ran whatever the server said; a refused logout was indistinguishable from a real one | reply read, `data.success === false` alerts that the session may still be valid, reload kept (it is what reveals the true state) | **FIXED** |
| **F-57-4** | `main.get_knowledge` | silent substitution of data | corrupt `knowledge_json` → **200** with the *deployment default* KB, **0** WARNING/ERROR lines, corrupt row left in place | same response shape (consumers read arbitrary KB keys) **plus** a WARNING naming the page id, the exception class and the parse message; stored value untouched | **FIXED** |
| **F-57-5** | `core/ai_router.ToolExecutionGuard.check_and_record` | swallowed audit write | audit row for `ai.tool.executed.<tool>` lost, call still returned `(True,"OK")`, nothing recorded the loss | still `(True,"OK")` (refusing a customer message because an audit row failed is worse) **plus** a WARNING naming the tool, tenant and call index | **FIXED** |
| **F-57-6** | `core/db_bounds._apply_session_bounds` | swallowed commit of a safety setting | commit failure silent ⇒ `idle_in_transaction_session_timeout` lost at the first rollback. Measured on PostgreSQL: **`1min` with the commit vs `0` without** | WARNING stating the consequence; module got its own `core.db_bounds` logger (it had none) | **FIXED** |
| **F-57-7** | `core/db_engine.get_db_connection` | one `except: pass` covering three independent settings | read-only DB: `journal_mode=WAL` fails ⇒ **`foreign_keys=0`**, **`busy_timeout=15000`**; with enforcement off an FK-violating `INSERT` naming `p57_never_created` **succeeded (1 row)** | one try per pragma: same DB ⇒ **`foreign_keys=1`**, **`busy_timeout=5000`**, WAL failure logged with the path and the driver's reason | **FIXED** |
| **F-57-8** | `core/task_queue.get_queue_stats` | swallowed read reported as data | counts returned as the zeros they were initialised to ⇒ `/api/health` reported a healthy empty queue; the caller's own `Readiness queue stats fallback` never fired | zeros kept (the health contract's shape is unchanged) **plus** a WARNING naming `task_jobs` | **FIXED** |

**8 findings, 8 fixed, 0 open.**

Test suite: **2691 → 2739 passed / 0 failed** (floor 2471; Phase 56 delivered 2691,
so this phase adds exactly its 48). New module
`tests/test_e57_silent_failure_truth.py`: **48 tests**, 14 classes, all passing under
SQLite (`.env` parked, `-u DATABASE_URL`) and under PostgreSQL, twice.

---

## 2. Why F-57-7 is the most consequential of the eight

`PRAGMA foreign_keys=ON` is not a nicety in this repository. It is the mechanism that
makes every Phase 55/56 guarantee true — "a write naming a page that does not exist is
refused by the driver, at the boundary, with a message that names the page". Three
PRAGMAs shared one `try/except Exception: pass`, so whichever failed first discarded
the rest.

Measured on a database file the process cannot write to (WAL cannot be enabled there):

```
BEFORE   journal_mode=delete   foreign_keys=0   busy_timeout=15000
AFTER    journal_mode=delete   foreign_keys=1   busy_timeout=5000
         WARNING core.db_engine: PRAGMA journal_mode=WAL could not be applied to
         file:/tmp/p57_ro3/fk.db?mode=ro (OperationalError: attempt to write a readonly database)
```

And separately, why `foreign_keys=0` is not academic:

```
PRAGMA foreign_keys=OFF
INSERT INTO invoices (page_id) VALUES ('p57_never_created')   -> committed, 1 row
PRAGMA foreign_keys=ON
INSERT INTO invoices (page_id) VALUES ('p57_never_created')   -> IntegrityError: FOREIGN KEY constraint failed
```

`busy_timeout` also matters: `15000` is the `connect(timeout=15.0)` default, not the
intended `5000`; the two are close enough that the difference is easy to miss and
awkward enough (a 15 s stall on a locked database instead of 5 s) that it should not be
left to chance.

---

## 3. Candidates examined and deliberately left alone

Every one of these was read in full and classified. They are recorded here so a later
phase does not mistake them for oversights, and three of them are now **pinned by test**
so that they cannot drift.

| candidate | why it passes |
|---|---|
| `main.auth_login` → `database.create_session(...)` (sweep D's only hit) | the page id is read out of a **stored row**: `page_id = client_page["page_id"]` (`main.py:460`) before `create_session(role=resolved_role, page_id=page_id, …)` (`:467`). The operator login path passes `page_id=None` explicitly. No request value reaches the FK. Pinned by `test_auth_login_writes_a_stored_page_id_not_a_request_value`, which traces the local back to its assignment. |
| `core/db_privileges._fetch_safe` | a probe that must never raise: it runs inside `SAVEPOINT`/`ROLLBACK TO SAVEPOINT`, returns `[]` on failure, and closes the cursor in `finally`. Swallowing is the contract. |
| `core/schema_manager.ensure_schema` | the swallowed statement is `pg_advisory_unlock` + `commit` in a `finally`. The advisory lock is released when the session ends either way, and a migration that succeeded must not be reported as failed because unlocking threw. |
| `main.readiness_check` (×2) | `finally: cur.close()` / `conn.close()` — releasing a resource that is already unusable. The DB failure itself **is** logged (`Readiness DB check failed`) and the queue-stats fallback **is** logged (`Readiness queue stats fallback`). |
| `main.get_knowledge`'s JSON fallback **shape** | kept intentionally: consumers read arbitrary knowledge-base keys, so wrapping the reply in `{"status": …}` would break them. The trace went into the log, not the response. Pinned by `test_the_response_shape_is_unchanged_for_consumers`. |
| `core/task_queue.get_queue_stats`'s zeros | kept intentionally: `/api/health` has a fixed key contract, and a missing key is a worse failure than a zero plus a warning. Pinned by `test_a_failed_count_query_logs_and_still_returns_the_shape`. |
| 137 remaining `except → pass` (from 142) | the sweep is reported as a *countable inventory*, not as 137 findings. The refined sweep — silent `pass` inside a **route handler** or swallowing a **database write** — went **3 → 2** and **6 → 2**; the four survivors are the ones above, and the pair is pinned by `test_the_remaining_silent_write_swallows_are_the_two_documented_ones`. |
| `main.send_executive_report_api` (`pid or database.DEFAULT_PAGE_ID`, `:3135`) | a coerced default, i.e. Phase 56's class rather than Phase 57's. Recorded as a **Phase 58 candidate** — not touched here, because changing it would alter a scheduled report's target tenant, which needs its own measurement and its own refusal contract. |
| `dashboard.html:4667`-era `handleLogout` reload | kept: the reload is what reveals the true session state. Only the *silence* was the defect. |

---

## 4. Verification

### 4.1 New tests

`tests/test_e57_silent_failure_truth.py` — **1101 lines, 14 classes, 48 tests**.

```
SQLite (.env parked, -u DATABASE_URL)          48 passed / 0 failed in 1.85s
PostgreSQL (gerege_e05_test), run 1            48 passed / 0 failed in 1.84s
PostgreSQL (gerege_e05_test), run 2            48 passed / 0 failed in 1.78s
E50 + E55 + E56 + E57 together (SQLite)       372 passed / 0 failed in 59.05s
```

Coverage by finding: F-57-1 → 6 tests, F-57-2 → 6, F-57-3 → 4, F-57-4 → 6, F-57-5 → 5,
F-57-6 → 5, F-57-7 → 6, F-57-8 → 3, sweeps/pins → 7.

Behavioural tests were preferred over source scans wherever a real object could be
constructed: the pragma isolation test drives the real `get_db_connection` with a
failing connection; the read-only test drives it with a real `0o444` database file and
asserts the two guarantees that matter (`foreign_keys=1`, `busy_timeout=5000`) — those
hold whether or not the process is root, so the test needs no skip.

### 4.2 Revert harness — `CAUGHT=11 / MISSED=0 / ANCHOR=0`

`/tmp/p57_revert.py` restores the pre-fix files from `/tmp/p57_pristine`, then reverts
**one diff hunk at a time** (`patch -R`) from the delivered state in `/tmp/p57_patched`,
runs the module, and requires a named test to fail:

```
BASELINE (all fixes in place)                        passed=48 failed=0
CAUGHT  F-57-1 handleManagerSend reply discarded     failed=7
CAUGHT  F-57-3 handleLogout reply discarded          failed=5
CAUGHT  F-57-2 token limit reply discarded           failed=6
CAUGHT  F-57-4 knowledge fallback silent             failed=3
CAUGHT  F-57-5 audit loss silent                     failed=2
CAUGHT  F-57-6a db_bounds logger infra               failed=2
CAUGHT  F-57-6b db_bounds commit swallowed           failed=2
CAUGHT  F-57-7 pragma isolation                      failed=5
CAUGHT  F-57-8 queue stats swallowed                 failed=3
CAUGHT  CALIB-1 db_engine docstring only             failed=0   (control: nothing load-bearing)
CAUGHT  CALIB-2 task_queue comment only              failed=0   (control: nothing load-bearing)
sha restoration: all 6 files verified identical
```

The two calibration cases are the point of the exercise in the other direction: they
prove the harness reports **zero** when a change carries no weight, so the nine
non-zero results are evidence and not noise.

### 4.3 Negative control — `CAUGHT=11 / MISSED=0`

`/tmp/p57_negctl.py` introduces **new** defects (not reverts) and requires the suite to
catch each:

```
NC-1  a NEW except:pass inside a route handler            caught (3 failures)
NC-2  allow_admin_all=False -> True in manager_send_message caught (1)
NC-3  foreign_keys=ON removed from the pragma list        caught (4)
NC-4  a NEW unread `await fetch` in the dashboard         caught (1)
NC-5  ignored_fields removed from the gemini_key reply    caught (1)
NC-6  task_queue warning -> pass                          caught (3)
NC-7  db_bounds commit warning -> pass                    caught (2)
NC-8  ai_router audit warning -> pass                     caught (2)
NC-9  knowledge fallback warning -> pass                  caught (3)
NC-10 reload moved before the logout reply is read        caught (2)
NC-11 "quota" removed from ERROR_CLASSES                  caught (1)
```

NC-11 is the standing security pin from Phase 50: after the run, `core/ai_readiness.py`
was restored and verified byte-identical to `HEAD` (sha `ae8a15fda0700b00`), and
`tests/test_e50_ai_readiness_truth.py:833`'s exact `ERROR_CLASSES` tuple is untouched.
**No test was removed, skipped, weakened or converted in this phase.**

### 4.4 Live measurement (running application, disposable SQLite app DB)

BEFORE (`/tmp/p57_probe1.sh`, app pid 3847764):

```
GET  /api/knowledge?page_id=p57_probe   valid JSON -> 200 {"bank_accounts":{"khaan":"P57 valid"}}
GET  /api/knowledge?page_id=p57_probe   corrupt    -> 200 (the deployment default KB)
                                        new WARNING/ERROR lines mentioning knowledge: 0
                                        corrupt row still in the database, unchanged
POST /api/sessions/p57_no_such_session/send        -> 404 "Сесс олдсонгүй! (Session not found in this tenant)"
POST /api/pages/p57_probe/gemini_key  limit:null   -> 200 changed:[] preserved:[…,monthly_token_limit]
                                        stored limit afterwards: 100000
POST /api/auth/logout                              -> 200 {"success":true,"message":"Амжилттай гарлаа"}
500s: 0    unhandled exceptions: 0
```

AFTER (`/tmp/p57_probe2.sh`) — **OK=9 / FAIL=0**:

```
valid JSON (positive control)      200, new WARNING lines: 0
corrupt JSON                       200, new WARNING lines: 1
    WARNING:ai_agent_app:knowledge_json for page 'p57_probe' is not valid JSON
    (JSONDecodeError: Expecting property name enclosed in double quotes: line 1 column 43
    (char 42)); serving the default knowledge base instead. The stored value was left untouched.
restored JSON                      200, the page's own KB is served again
server contracts for F-57-1/2/3    404 / 200 (preserved) / 200 / 200 — unchanged
500s: 0    unhandled exceptions: 0
```

The client-side fixes (F-57-1/2/3) are verified statically — `node --check` on both
extracted inline `<script>` blocks passes, and a brace-walk scan confirms all four
fetches in the three handlers are assigned and each has an error branch — because no
browser is available in this environment. **Browser-level behaviour is NOT VERIFIED.**

### 4.5 Regressions (all previous phases, live and static)

```
P51  /tmp/p55_regr_p51.sh        37 PASS / 0 FAIL   (baseline 37/0)
P52  /tmp/p54_regr_p52.sh        34 PASS / 0 FAIL   (baseline 34/0)
P53  /tmp/p54_regr_p53.sh        46 PASS / 0 FAIL   (baseline 46/0)
P54  /tmp/p54_checks54.sh        45 PASS / 0 FAIL   (baseline 45/0)
P55  /tmp/p55_checks55.sh        91 PASS / 0 FAIL   (baseline 91/0)
P55 negative control             88 PASS / 3 FAIL   (baseline 88/3 — the 3 are intentional)
P56  /tmp/p56_probe3.sh          27 OK   / 1 FAIL   (baseline 27/1 — the 1 is a known wrong
                                                     harness expectation: `sender_id:5` is
                                                     coerced to the text "5" and accepted,
                                                     as pinned by test_e55…:778)
```

One harness line had to be corrected before P56 could be re-run: `wantrow 2 "comments:
эерэг хяналт мөр бичсэн (BEFORE 1 + энэ)"` assumed the row written by Phase 56's BEFORE
probe was still present. Phase 56's cleanup deleted `p56_probe`, and its comment
automations went with it (FK `ON DELETE CASCADE`), so the correct expectation is 1 —
proved by the row's own timestamp: the single `comment_automations` row for the page was
created at `2026-11-27 07:06:33`, the same second as the freshly created page. This is a
stale baseline in a disposable harness, not a regression in the product.

### 4.6 Blast radius

Every test module that references any of the six changed files, by import or by
the names they expose (`get_db_connection`, `get_queue_stats`,
`_apply_session_bounds`, `knowledge_json`, `record_audit_log`,
`update_page_gemini_key`, `manager_send_message`, `auth_logout`, `PRAGMA`,
`foreign_keys`, `idle_in_transaction_session_timeout`, `dashboard.html`, …):
**65 modules**, listed in `/tmp/p57_blast_list.txt`.

```
PostgreSQL (gerege_e05_test), .env parked:
    2011 passed, 53 skipped, 0 failed in 319.64s (0:05:19)
    ENV_SHA_BEFORE = ENV_SHA_AFTER = 2c90cc39177b2402
```

Phase 56's equivalent run was 45 modules → 1603 passed / 22 skipped / 0 failed in
349.49 s; the module list grew because Phase 57 touched `core/db_engine.py`, which
nearly every database-facing module references.

This run is what moved `leads.db` (sha `2e2e6608bf4b4145` → `94d92f958d67d684`)
and grew `backups/` by 11 files — both are O-55-1's known mechanism, not new
defects, and both are declared in §5.

### 4.7 Full suite

Every module under `tests/`, PostgreSQL (`gerege_e05_test`), `.env` parked with a
`trap`, no `DB_PATH` override — the same recipe as Phase 56:

```
2739 passed, 74 skipped, 1 xfailed, 390 warnings in 699.33s (0:11:39)      exit code 0
ENV_SHA_AFTER = ENV_SHA_BEFORE = 2c90cc39177b2402
LEADS_BEFORE  = 94d92f958d67d684      LEADS_AFTER = 5bc354703892f3d4
BACKUPS_BEFORE = 3799 files           BACKUPS_AFTER = 3822 files
```

Phase 56 was 2691 passed / 74 skipped / 1 xfailed in 710.43 s. The delta is
exactly the 48 new tests: **no test was removed, skipped, weakened or converted**,
the skip count is unchanged, and the single `xfailed` is the same pre-existing one.

**Two things happened during this run that are declared rather than glossed over.**

1. *The 56% stall.* Progress sat at 56% and, unlike Phase 56's stall, consumed
   **zero CPU and produced zero log growth for a full 60 s sample**
   (`wchan=do_poll`, `syscall=7`, five worker threads in `inet_csk_accept`, four
   established sockets to PostgreSQL and Redis). That is a real wait, not slow
   work — the region is `tests/test_e38_production_architecture.py` /
   `test_e39_staging_operational_readiness.py`, which start local listeners and
   wait on subprocesses with their own timeouts. It resumed by itself and went
   56% → 97% in the next 120 s (log +1316 bytes, CPU +39 s), finishing at exit
   code 0. The refinement to Phase 56's lesson: *zero CPU plus zero log growth
   means "waiting", not "hung" — check `wchan`/`syscall` and whether the wait has
   a timeout before killing anything.*
2. *`.env` was briefly un-parked mid-run.* While diagnosing that stall I ran
   `pytest --collect-only` to identify the test at the 56% mark. Its wrapper
   moved `.env` aside and back, and because the suite had already parked the file
   the "move aside" no-opped while the "move back" restored it into the
   repository for roughly one to two seconds. Nothing in the suite read it in
   that window in a way that changed the outcome — `ENV_SHA_AFTER` equals
   `ENV_SHA_BEFORE`, the run exited 0, and the totals are exactly Phase 56's plus
   48 — but the state was mine to keep clean and it was not, so it is recorded
   here. The file was re-parked immediately and the suite's own `trap` restored
   it at the end (verified: `.env` present, sha `2c90cc39177b2402`, mode `600`,
   no copy left in `/tmp/p48a/env.live`).

`.env` sha `2c90cc39177b2402` before and after every run in this phase; the file was
parked in `/tmp/p48a/env.live` with a `trap` for each run and restored each time.

---

## 5. Residue declared

| artefact | before Phase 57 | after | note |
|---|---|---|---|
| app DB pages (`/tmp/p48a/p48a_smoke.db`) | 4 (`100799479495809`, `p49_dev_default`, `p49_final`, `p49_upsert_probe`) | **4, identical** | `p57_probe`, `p56_probe` and `p51_live` created for probing and deleted (HTTP 200 each); children CASCADEd to 0 (invoices, comment_automations, tracked_links, cargo_packages) |
| app DB `audit_logs` (`/tmp/p48a/p48a_smoke.db`) | 420 rows / 386 NULL page_id | **492 rows / 453 NULL** | append-only by design; +72/+67 from this phase's probes and the P51–P56 regression re-runs. `page_id LIKE 'p57%'` rows: **0** |
| `leads.db` | sha `2e2e6608bf4b4145`, 1618 audit / 1429 sessions / 1708 invoices / 30 pages | sha **`5bc354703892f3d4`**, 1654 audit / 1455 sessions / 1734 invoices / 31 pages | moved twice, both by test runs and neither by product code: the blast-radius run took it to `94d92f958d67d684`, the full suite to `5bc354703892f3d4` (+36/+26/+26/+1 overall). This is O-55-1's known mechanism — two test modules have no `DB_PATH`/`tmp_path` fixture — and the file is git-ignored. `page_id LIKE 'p57%'` rows: **0**; `e57%` rows: **0** |
| PostgreSQL `gerege_e05_test` | 22 pages / 360 audit | **22 pages / 360 audit — unchanged** | `pages LIKE 'p57%'` or `'e57%'`: **0**; `audit_logs` rows referencing `p57%`/`e57%`: **0** |
| Redis `gerege:test:*` | 0 | 0 | |
| `backups/` | 3788 files | **3822 files (+34)** | never deleted. +11 from the blast-radius run, +23 from the full suite; the growth comes from backup-automation tests, and parking `.env` unsets `BACKUP_DIR` so they land here |
| `/tmp/p57_*` | — | 39 files | probe scripts, logs, pristine/patched copies, harnesses — all outside the repository, none committed |

Nothing was added to Git except the six source files and the one new test module.
`.env`, `leads.db`, `gerege_crm_next.db`, `leads.csv`, `backups/` and `__pycache__`
remain git-ignored and untracked.

---

## 6. Standing constraints honoured

* **No test removed, skipped, weakened or converted.** The new module contains no
  `skipif` and no `xfail`; the 74 pre-existing skips are unchanged.
* **No security check silenced.** `ERROR_CLASSES` verified byte-identical; the
  `allow_admin_all=False` on `manager_send_message` is now pinned by a test that fails
  when it is flipped (NC-2).
* **Every item classified** PASS / FAIL / FIXED / NOT VERIFIED with before-and-after
  measurements; where a candidate passes, §3 records why.
* **Test floor:** 2471 passed / 0 failed required — delivered **2739 passed / 0 failed** (floor 2471).
* **Push authorisation** covers `arena/d78ebf88-gerege-ai-agent` only. No push to
  `main`, no force push, no history rewrite.
* **No secret value** was committed, logged or echoed. The one secret-scan hit pattern
  from Phase 56 (`gemini_api_key=` on a de-indented line) was re-checked against the
  staged diff and printed masked only.

---

## 7. Open items — the operator's, not the agent's

| id | item | why it is not mine |
|---|---|---|
| **O-51-3** | `TELEGRAM_WEBHOOK_SECRET` is unset and `WEBHOOK_FAIL_CLOSED=0` | setting a webhook secret and deciding to fail closed is a deployment decision; the code path is implemented and tested |
| **O-55-1** | `tests/test_stage_b_regressions.py` and `tests/test_p1_payment_security.py` do not set `DB_PATH`/`tmp_path`, so a run without `.env` writes the git-ignored `leads.db` | changing those two modules' fixture strategy alters tests that predate this work and are pinned by earlier phases; needs its own authorised pass |
| — | `GEMINI_API_KEY` rotation (the key is exposed on public `main`) | rotation is a credential operation |
| — | merge / PR / deploy | each needs fresh, separate authorisation |

**NOT VERIFIED (environment limits):** browser-level dashboard behaviour for F-57-1/2/3
(no browser); AI answer quality, Telegram, Meta and QPay round-trips (no egress — HTTP
000 / curl exit 35 to Google); the Windows launcher.

---

## 8. Carried forward for Phase 58

1. `main.py:3135` `send_executive_report_api` — `pid or database.DEFAULT_PAGE_ID`, the
   coerced-default class Phase 56 attacked elsewhere. Needs a measurement of what a
   scheduled executive report should do when its tenant cannot be resolved.
2. The remaining 137 `except → pass` outside the two refined classes. A worthwhile next
   slice is the 30 in `database.py` and the 20 in `core/task_queue.py`: not all are
   defects, but none of them has been read in full the way the nine in this phase were.
3. `handleManagerSend` now restores the operator's text on failure; the same pattern
   (clear-then-send) may exist in other composer paths.
4. `core/db_bounds.py` has a logger now; the module's other swallowed paths (four
   remain) can be revisited with the same doctrine it already states in its docstring:
   *"A blocked query must fail, not look like zero rows."*

---

*The commit that carries this report is recorded in a follow-up commit, because a
commit cannot contain its own sha.*

