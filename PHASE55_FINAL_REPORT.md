# PHASE 55 — FINAL REPORT

**Branch** `arena/d78ebf88-gerege-ai-agent` · **base** `37dc970` (Phase 54) · **commit** `6f28c74`, pushed to `arena/d78ebf88-gerege-ai-agent` only (`37dc970..6f28c74`). `origin/main` untouched at `c809654`; **0** pull requests opened, merged or deployed. The sha is written by the follow-up commit, because a commit cannot contain its own.
**Instruction being executed:** *"odoo zasah saijruulah bolomjtoi zuilsee hiijil bai"* — proceed
autonomously with what can be fixed and improved. Read as authority to work, not to merge, open a
pull request, push to `main`, rotate a key, or deploy.

---

## 0. Verdict

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| F-55-1 | A failed write leaked its connection **and its transaction**, stalling the next writer | High | **FIXED** |
| F-55-2 | `POST /api/retention/rules` answered 500 for a page that does not exist | High | **FIXED** |
| F-55-3 | A 500 was returned and **logged nowhere** — zero tracebacks in the backend log | High | **FIXED** |
| F-55-4 | `POST /api/pages/{id}/credentials` answered 500 whose text claimed the rotation *had* happened | High | **FIXED** |
| F-55-5 | `dashboard.html` announced success for two calls whose responses it never read | Medium | **FIXED** |
| F-55-6 | The same foreign key 500'd two more endpoints (`appointments`, `retention/broadcast`) | Medium | **FIXED** |
| F-55-7 | 13 request fields were `.strip()`ed unguarded; a number or an object crashed the request | Medium | **FIXED** |
| F-55-8 | Two status endpoints stored any value; one **nulled a lead's stage** and one freed a booked slot | High | **FIXED** |
| F-55-9 | *Self-inflicted, caught by the suite:* the F-55-1 fix broke two connection-type detectors | High | **FIXED** |
| F-54-4 | `delete_page` reported a deletion that deleted nothing, and audited it | Medium | **CLOSED** (carried from Phase 54) |

Ten items: ten fixed or closed, **0 left open**. Nothing in this phase was skipped, weakened or
declared-and-dropped; three of my own earlier claims were wrong and are corrected in §6.

---

## 1. How the phase started

Phase 54 closed with `delete_page`'s unconditional `return True` measured and deliberately not
fixed. Sweeping that *class* rather than that symptom — "a `database.py` writer that can raise
between `get_connection()` and `conn.close()`" — produced something worse than the item that
prompted the sweep: a leaked connection holding a write lock.

Class size, measured from the source:

| Measurement | Before | After |
|---|---|---|
| functions in `database.py` that call `get_connection()` | 78 | 78 |
| …with a `try/finally` around the connection | **19** | **78** |
| …of those, writing to one of the 14 tables whose `page_id` is a foreign key to `pages` | 18 | 18 (all guarded) |
| `close()` calls in `authenticate_client_detailed` | 6 hand-written | 1, in a `finally` |

The 14 foreign keys are `migrations/versions/0003_foreign_keys.py`: appointments, audit_logs,
automated_rules, cargo_packages, comment_automations, invoices, marketing_campaigns, messages,
registrations, sent_followups, session_states, sessions, tracked_links, user_memories.

Highest-reach writers that were unguarded, by number of call sites in application code:
`log_message` (11, including `agent.py:338/349` — the core AI reply path), `create_session` (4),
`upsert_user_memory` (3), `set_human_takeover` (2), `create_invoice` (2), `update_lead_status` (2).

---

## 2. F-55-1 — the leak, and the second half of it that the first fix did not solve

### 2.1 Before

`database.update_automated_rule()` had no `try/finally`. `automated_rules.page_id` carries a
foreign key to `pages`, so a request naming a page that does not exist raised out of the writer
and never reached `conn.close()`. Measured in-process on a disposable SQLite database:

```
database.update_automated_rule("p55_never", …)  -> IntegrityError: FOREIGN KEY constraint failed
database.save_page(…)                           -> 5.00s, then OperationalError: database is locked
database.delete_page(…)                         -> OperationalError: database is locked
                                                  (traceback at database.py:1228)
gc.collect()                                    -> lock released in 0.00s
```

5.00 s is `PRAGMA busy_timeout=5000`, set in `core/db_engine.get_db_connection`. Under PostgreSQL
the same leak costs a pool slot (`DB_POOL_SIZE` + `DB_MAX_OVERFLOW`, `DB_POOL_TIMEOUT=30`) instead
of a file lock.

### 2.2 The part I first got wrong, and then measured properly

My first reading was "one bad request stalls **every** write for five seconds". That is too
strong, and the live measurement says so: after two 500s on the running application, the next
write returned **HTTP 200 in 0.00 s** on all 18 attempts over 18 seconds. The reason is that the
leaked connection has no strong referent once the traceback that holds it is gone, so the garbage
collector drops it and the lock ends. The deterministic 5.00 s stall is the in-process one above,
where the traceback object keeps the frame — and the cursor, and the lock — alive.

That distinction turned out to be the whole finding. `finally: conn.close()` alone is **not
sufficient**, and the proof is four runs of the same sequence:

| Run | What holds the exception | Next write |
|---|---|---|
| A | nothing (exception object discarded) | OK, 0.00 s |
| **B** | **traceback retained** (`pytest.raises(...) as excinfo`) | **`OperationalError: database is locked`** |
| C | retained, then `gc.collect()` | OK, 0.00 s |
| D | retained, then an explicit `rollback()` | OK, 0.00 s |

B is the production shape, not a test artefact: the error middleware keeps the exception for
`telemetry.record_request(..., error_detail=str(exc))`, and since F-55-3 it keeps it for the log
record's `exc_info` as well. So a 500 on a write path held the write lock for as long as the
request's own error handling held the exception.

### 2.3 After

Two layers, both needed:

1. **Every connection is released in a `finally`** — all 78 functions in `database.py`. The
   transform was mechanical and guarded: each function was required to have exactly one
   `conn = get_connection()` and one `conn.close()`, no use of `conn`/`cursor` after the close, no
   `try`/`except` already inside the span, and every body line indented at function level. Two
   functions did not fit and were done by hand: `authenticate_client_detailed` (six hand-written
   closes on four refusal branches, the last of which was the only statement in an `else:`) and
   `init_db` (a `try/except` inside the span). Phase 54's two credential writers were also done by
   hand, because they read `cursor.rowcount` **after** `conn.close()`; they now read it before.
2. **`close()` ends the transaction** — `core.db_engine.RollbackOnCloseConnection`, a
   `sqlite3.Connection` subclass whose `close()` rolls back when `in_transaction` is true. One
   change, and it covers every caller, including the 78 above. `PostgresCompatConnection.close()`
   has rolled back first since Phase 20, on the stated assumption that this "matches
   `sqlite3.Connection.close()`"; measured, it did not.

A rollback after a successful `commit()` is a no-op and a pure reader has no transaction open, so
the happy path is unchanged — pinned by
`TestCloseEndsTheTransaction::test_a_committed_write_survives_close`.

After both layers, run B above passes: **OK, 0.00 s** with the traceback still referenced.

---

## 3. F-55-2 / F-55-4 / F-55-6 — "that page does not exist" was a 500

`enforce_tenant_scope` hands an admin back the page id they asked for **without an existence
check**, and every one of these endpoints then wrote to a table whose `page_id` is a foreign key.
All four were measured live on the running application before the fix:

| Endpoint | Request | Before | After |
|---|---|---|---|
| `POST /api/retention/rules` | `{"page_id": "p55_never_exists", …}` | **500** `{"detail":"Internal server error","request_id":"fd59ddb15c147c70"}`, 0 rows | **200** `success:false, written:false, changed:[]`, message names the missing page, 0 rows |
| `POST /api/pages/{id}/credentials` | `{"page_id": "p55_never_d", "username": …}` | **500** `{"error":"Хуудас (p55_never_d) нэвтрэх эрх шинэчлэх хийгдсэн боловч …"}`, 0 rows | **404** `{"error":"…олдсонгүй…","written":false}`, 0 rows, no audit row |
| `POST /api/appointments` | `{"page_id": "p55_never_f", …}` | **500** `request_id=68d855587b22a185` | **200** `success:false, written:false`, 0 rows |
| `POST /api/retention/broadcast` | `{"page_id": "p55_never_f", …}` | **500** `request_id=58f275caf3d373a5` | **200** `success:false, written:false, sent:0`, 0 rows |

F-55-4 is the worst of the four, because the 500's own text asserted the opposite of the truth.
The backend log recorded the real sequence:

```
ERROR:ai_agent_app:audit write failed for page.credentials.updated after Хуудас (p55_never_d)
  нэвтрэх эрх шинэчлэх had already committed: audit event 'page.credentials.updated' could not
  be recorded: IntegrityError: FOREIGN KEY constraint failed
```

`set_client_credentials` updated 0 rows, and the audit INSERT then hit `audit_logs.page_id`'s
foreign key. The caller was told a rotation "had already committed" that had not happened.

Three of the four answer **HTTP 200 with `success:false`** rather than a 4xx, because that is what
their own clients read: `dashboard.html` branches on `data.success` and alerts `data.message` for
retention rules, appointments and broadcast. An `HTTPException` would have delivered `detail`
instead, and the appointments client would have alerted its slot-conflict fallback — a wrong
diagnosis shown to an operator. The credentials endpoint answers **404 with `error`** because its
client branches on `!credRes.ok || credData.error`, and both of its routes
(`/api/pages/credentials` and `/api/pages/{page_id}/credentials`) share one handler.

Four endpoints that were already correct are recorded here so the sweep is auditable, not
selective: `POST /api/leads/{id}/status` → 404, `POST /api/sessions/{sender}/takeover` → 404,
`POST /api/cargo/{code}/deliver` → 200 `success:false`, `POST /api/appointments/{id}/status` → 404.

---

## 4. F-55-3 — a 500 that logged nothing

The middleware recorded `str(exc)` into telemetry and returned a generic 500. **Across every 500
measured on a running instance, the backend log held zero tracebacks.** The 500s from §3 appear in
the log only as uvicorn's access line:

```
INFO:     127.0.0.1:46940 - "POST /api/retention/rules HTTP/1.1" 500 Internal Server Error
```

The handler now logs `logger.error("unhandled exception on %s %s (request_id=%s): %s", …,
exc_info=exc)`. Same five 500s, after the fix:

```
ERROR:ai_agent_app:unhandled exception on POST /api/appointments (request_id=68d855587b22a185): IntegrityError
Traceback (most recent call last): …
ERROR:ai_agent_app:unhandled exception on POST /api/retention/broadcast (request_id=58f275caf3d373a5): IntegrityError
ERROR:ai_agent_app:unhandled exception on POST /api/appointments (request_id=34fe1582bc4039de): AttributeError
ERROR:ai_agent_app:unhandled exception on POST /api/pages/p55_probe/credentials (request_id=9590439d02b5fd94): AttributeError
ERROR:ai_agent_app:unhandled exception on POST /api/retention/broadcast (request_id=b9df114824206db3): ProgrammingError
```

The client response stays generic — a traceback is not for the caller — and the log names the
exception **type**, not its message, because a message can carry a credential. Pinned by
`test_the_log_does_not_leak_a_credential_from_the_body`.

This fix is also what made the rest of the phase measurable: F-55-6, F-55-7 and F-55-8 were all
found by reading the tracebacks it produced.

---

## 5. F-55-7 / F-55-8 — the request body was assumed to be well-typed

### 5.1 F-55-7: unguarded `.strip()` on request fields

**18 `_payload_text` call sites across 9 handlers, covering 23 request fields** (measured by walking
the AST for `_payload_text(` calls). Measured live, before:

```
POST /api/appointments        {"notes": 12345}              -> 500 AttributeError: 'int' object has no attribute 'strip'
POST /api/pages/{id}/credentials {"password": 12345}        -> 500 AttributeError, inside database.set_client_credentials
POST /api/retention/broadcast {"target_segment": {"a": 1}}  -> 500 ProgrammingError: the dict reached a SQL parameter
```

Found in two sweeps. The first was a source scan for `payload.get(key, default).strip()` and its
loop form, which named **13** sites. The second swept by *class* rather than by literal key — "what
happens if the field is a number or a container" — and named **5** more that no key-literal scan
would have found. All 18 call sites now read through one helper:

| Handler | Fields | Call sites |
|---|---|---|
| `create_appointment_manual_api` | customer_name, customer_phone, service_name, appointment_date, appointment_time, notes | 6 |
| `update_keys` | gemini_key, meta_token, meta_verify, tg_token, tg_manager_id, admin_password | 1 (loop) |
| `send_broadcast_api` | title, message, target_segment, channel | 4 |
| `set_page_credentials_endpoint` | username, password | 2 |
| `web_chat_endpoint` | message | 1 |
| `manager_send_message` | message | 1 |
| `update_lead` | notes | 1 |
| `test_page_google_sheet_endpoint` | google_sheets_url | 1 |
| `scan_cargo_package_api` | tracking_code | 1 |
| **total** | **23 fields** | **18 sites / 9 handlers** |

They now go through `_payload_text(payload, key, default)`: a number becomes its text form (that
is what the stored column wants), a container is refused with **400 naming the field**, because
`str({"a": 1})` would write Python syntax into a marketing row. `database.set_client_credentials`
coerces `username`, `page_id` and `password` itself, since `repositories/tenant_repo.py:26`
reaches it without going through the HTTP boundary.

**Correction:** `update_keys` is *not* reachable this way over HTTP. It declares
`payload: Dict[str, str]`, so FastAPI answers **422** before the handler body runs (measured:
`{"detail":[{"type":"string_type","loc":["body","gemini_key"],…}]}`). Its guard is defence in
depth for a future annotation change, not the fix for a live 500. The other 17 sites are all
`Dict[str, Any]` and were reachable.

After: `notes: 12345` → 200 and the row holds `"12345"`; `target_segment: {"a":1}` → 400
`"target_segment must be a string"`; `channel: [1,2]` → 400; `password: 12345` → 200.
**Zero new 500s** across all eight type-confusion probes.

### 5.2 F-55-8: two status endpoints stored anything

```
POST /api/appointments/1/status {"status": {"a": 1}}  -> 500 ProgrammingError
POST /api/appointments/1/status {"status": 12345}     -> 200, and the row then held status '12345'
POST /api/leads/1/status        {"status": {"a": 1}}  -> 500 ProgrammingError
POST /api/leads/1/status        {"status": null}      -> 200 {"status":"updated"}, and the lead's
                                                         stored status became NULL
```

`appointments.status` is a closed set — `is_slot_available` and `get_upcoming_appointments` both
filter on `status = 'CONFIRMED'`, and the dashboard renders exactly three values. Storing `'12345'`
therefore did not merely look wrong: **the booked slot stopped matching the availability check and
became bookable again for somebody else.** It is now validated against
`APPOINTMENT_STATUSES = ("CONFIRMED", "COMPLETED", "CANCELLED")`, and both refusals — a value of
the wrong type and a value outside the enum — carry the same `{success:false, written:false,
message}` body, because the client alerts `json.message` on that branch whatever the status code.

The lead vocabulary is free-form Mongolian text (`"шинэ"` is only the default), so no enum is
imposed; but an explicit `null` is refused rather than written. `payload.get("status", "шинэ")`
returns the default only for an **absent** key, so a body saying `"status": null` wrote NULL and
answered `{"status":"updated"}`. **This deployment's lead 1 was corrupted that way by my own
probe** (`P48A Restart Marker`, stage `p49-verified` → NULL) and was restored through the fixed
endpoint, verified by reading the row back: `('p49-verified',)`.

---

## 6. F-55-5 — the dashboard announced success it had not checked

Two functions discarded the response and toasted success unconditionally:

| Function | Before | After |
|---|---|---|
| `handleDeleteCurrentPage` | `await fetch(…); showToast('Хуудас устгагдлаа.')` | reads `data.status !== 'deleted'`, toasts `data.message \|\| data.error \|\| 'Хуудас устгагдсангүй.'` |
| `changeLeadStatus` | `await fetch(…); showToast('Төлөв амжилттай шинэчлэгдлээ!')` | reads `data.status !== 'updated'`, toasts `'Төлөв шинэчлэгдсэнгүй.'` on refusal |

This is the same defect Phase 54 recorded as evidence for F-54-4 and left open. Both endpoints can
now refuse, so both toasts could lie. Pinned by source assertions in
`TestTheDashboardReadsTheResponse` and by byte-level assertions on the **served** dashboard in the
live checks.

---

## 7. F-54-4 closed — `delete_page` tells the truth

Phase 54 measured this and deliberately did not fix it, because the handler's only failure branch
answered 400 `"Үндсэн хуудсыг устгах боломжгүй"`, so a bare `rowcount > 0` would have blamed the
default page for every missing-page delete. The two reasons are now separated:

```
database.delete_page("p55_never_a")  -> False   (was True)
DELETE /api/pages/p55_never_e        -> 200 {"status":"not_found","deleted":false,…}
                                        (was 200 {"status":"deleted","page_id":"p55_never_e"})
DELETE /api/pages/100799479495809    -> 400 {"error":"Үндсэн хуудсыг устгах боломжгүй"}   (unchanged)
DELETE /api/pages/<real page>        -> 200 {"status":"deleted","deleted":true,…} + 1 audit row
```

No `page.delete` audit row and no `agent.reset_sessions` call for a deletion that deleted nothing.
HTTP 200 with the truth in the body matches this endpoint's existing `{"status": …}` contract and
Phase 53/54's convention, and the dashboard reads the body rather than the status code. The five
tests in `tests/test_e02_phase11_audit_contract.py` that pin the surrounding contract all create
the page first, and still pass; so do `test_p1_06_foreign_keys.py:182`
(`delete_page("tp") is True` for a page it created) and `:196` (`DEFAULT_PAGE_ID` → False).

---

## 8. F-55-9 — the fix broke two detectors, and the suite caught it

The first full-suite run of this phase came back **2 failed, 2580 passed, 74 skipped, 1 xfailed,
4 errors**. All six problems were in `test_e02_phase41_hardening.py` and
`test_e02_phase42_admission_ownership.py`, on both dialects, and all said the same thing:

```
AssertionError: legacy_duplicates_allowed() failed to restore uq_pages_client_username_norm:
                the suite would continue without the R10 uniqueness invariant in force
```

Bisecting by file (revert one, re-run) named `core/db_engine.py`. Instrumenting the real test named
the mechanism:

```
with the fix:     [DIAG] create_index_sql: OK      [DIAG] describe=''       -> index_is_correct False
without the fix:  [DIAG] create_index_sql: OK      [DIAG] describe='CREATE UNIQUE INDEX uq_pages_client_username_norm ON pages (LOWER(TRIM(client_username))) WHERE clie…'
```

The CREATE succeeded; the *read* could not see it. `core.username_uniqueness._dialect_of(conn)`
identifies a connection by asking whether the string `type(conn).__module__` contains `"sqlite"`.
`RollbackOnCloseConnection` is defined in `core.db_engine`, so it does not. The `core.db_engine`
fallback further down was not reached either, because it sits inside `if inner is not None:` and a
`sqlite3.Connection` subclass has no `_conn` attribute. The answer was `"unknown"`,
`_INDEX_DEFINITION_QUERIES` has no `"unknown"` entry, and `describe_index` returned `None`.

Both detectors now ask the type hierarchy first — `isinstance(conn, sqlite3.Connection)` — and keep
the name test for wrappers that are not subclasses:

* `core/username_uniqueness.py::_dialect_of`
* `core/db_bounds.py::_is_sqlite_connection` (this one had been reaching the weaker
  "fall back to the configured engine" branch, which its own docstring says must not happen:
  *"the connection object itself is the authority on what it is, and this must not depend on the
  process environment"*)

After: **77 passed, 1 skipped, 0 failed, 0 errors** on both dialects. Five tests in the new module
pin it, including the exact assertion that broke
(`test_the_username_unique_index_is_readable_through_the_app_connection`) and one that monkeypatches
`is_postgres()` to `True` to prove `_is_sqlite_connection` no longer consults the environment.

This is recorded as a finding rather than folded silently into F-55-1 because it is the more
transferable lesson: **a latent fragility (identifying a type by its module's file name) becomes a
live defect the moment someone adds a subclass.**

---

## 9. What changed

| File | Lines | What |
|---|---|---|
| `database.py` | 2948 → `3313` | 78 functions release their connection in a `finally`; `delete_page` returns `rowcount > 0`; Phase 54's two credential writers read `rowcount` before the close; `set_client_credentials` coerces `username`/`page_id`/`password` |
| `core/db_engine.py` | 840 → `869` | `RollbackOnCloseConnection`, and `sqlite3.connect(..., factory=…)` |
| `core/username_uniqueness.py` | 385 → `400` | `_dialect_of` identifies by type hierarchy first (F-55-9) |
| `core/db_bounds.py` | 349 → `356` | `_is_sqlite_connection` identifies by type hierarchy first (F-55-9) |
| `main.py` | 3713 → `3920` | 500 logging; existence checks on 4 endpoints; `_payload_text` (18 sites / 23 fields); `APPOINTMENT_STATUSES` validation; lead-status validation; delete handler's `not_found` branch |
| `dashboard.html` | 5663 → `5679` | two toasts read their responses |
| `tests/test_e55_write_path_truth.py` | new, `1279` | `134` tests, `11 test classes plus one connection spy` classes, 0 skipped, 0 xfailed |

---

## 10. Verification

| Check | Result |
|---|---|
| New module, SQLite | `**134 passed** in 59.78 s` |
| New module, PostgreSQL | `**134 passed** in 7.60 s` |
| New module, PostgreSQL again | `**134 passed** in 6.70 s` |
| Revert proofs (span-scoped, restore sha-verified) | `**21 CAUGHT / 0 MISSED of 21** (see §10.1 — the first run was 20/1, and the MISS was fixed, not accepted)` |
| Sensitive modules — connection/db/WAL/backup bounds, foreign keys, schema, tenant isolation | `**37 modules, 1185 passed, 91 skipped, 0 failed** in 334.66 s (SQLite). The set is every test module that mentions `db_engine`, `db_bounds` or `username_uniqueness` — i.e. the blast radius of F-55-1 and F-55-9, not a hand-picked list.` |
| Full suite, PostgreSQL | `**2590 passed, 74 skipped, 1 xfailed, 0 failed, 0 errors** in 717.07 s (PostgreSQL). Floor is 2471 passed / 0 failed. The first run of the same suite on this phase's code returned `2 failed, 2580 passed, 74 skipped, 1 xfailed, 4 errors` — that is what exposed F-55-9 (§8); the intermediate run after fixing it returned 2587 passed / 0 failed, and the final run above adds the 3 tests §10.1 introduced.` |
| Live checks, Phase 55 | `**91 PASS / 0 FAIL**` |
| Regression, Phase 54 live set | `**45 PASS / 0 FAIL**` |
| Regression, Phase 53 live set | `**46 PASS / 0 FAIL**` |
| Regression, Phase 52 live set | `**34 PASS / 0 FAIL** (first attempt 32/2 — see §10.2)` |
| Regression, Phase 51 live set | `**37 PASS / 0 FAIL**` |
| Negative control (corrupted expectations must FAIL) | `**88 PASS / 3 FAIL** — exactly the three corrupted expectations, so 91/0 is not vacuous` |
| `tests/test_e50_ai_readiness_truth.py:833` `ERROR_CLASSES` | `**unchanged, byte for byte.** `tests/test_e50_ai_readiness_truth.py` is byte-identical to its previous revision (sha256 `4f96a9c04a3e95fb…` on both sides), and lines 820-860 `cmp` clean. In fact **0** tracked test files were modified in this phase: the only change under `tests/` is the new module.` |
| Credential scan of the staged diff, per file | `**0** matches. Every value in the deployment's `.env` of 8 or more characters was compared against every added line of the staged diff (values never printed): 0 hits. Pattern scan of the same diff: `sk-…` 0, `ghp_`/`github_pat_` 0, `AKIA…` 0, PostgreSQL DSN with an embedded password 0. The only `AIza…`-shaped strings are **3**, all in `tests/test_e55_write_path_truth.py` and all deliberately synthetic (`AIzaSYNTHETICP55…`), used to prove a key is written masked and never echoed.` |

Tests removed, skipped, weakened or converted in this phase: **0**.

### 10.1 The revert proof caught a gap in the module, and it was closed rather than accepted

The first revert run came back **20 CAUGHT / 1 MISSED**. The miss was
`database: gemini writer reads rowcount after close`: moving `written = cursor.rowcount > 0` out of
the `try` to after the `finally: conn.close()` left all 131 tests passing. sqlite3 keeps a closed
cursor's `rowcount` readable, so on SQLite the reverted shape is behaviourally identical — and these
cases run on SQLite, deliberately, because the lock behaviour F-55-1 fixes is a SQLite WAL property.

The underlying claim is about *other* drivers, so it is now pinned on the shape of the code:
`TestTheRowCountIsReadBeforeTheConnectionIsClosed` walks `database.py`'s AST and requires every
function that reads `cursor.rowcount` to read it before its `conn.close()` and inside a
`try/finally`. It found **12** such functions. One of its three tests asserts that
`update_page_gemini_key`, `delete_page` and `update_appointment_status` are still among them, so the
invariant test cannot silently lose the code it was written against and start proving nothing.

The module went 131 → **134** tests; the re-run of all 21 revert cases gave **21 CAUGHT / 0 MISSED**,
with that case now failing `1 failed, 132 passed`. The full suite was then re-run on the final code.

### 10.2 Two regression FAILs that were the harness's run order, not a regression

The Phase 52 regression script's first run under this phase reported **32 PASS / 2 FAIL**:

```
FAIL  at least 5 generation failures recorded (breaker threshold)  expected=yes actual=no(2)
FAIL  the breaker state that used to report 'other'                expected=breaker_open actual=not_yet
```

Both read `/api/health`'s `gemini_attempts`, which is **cumulative per process**. I had run P52
before P51, and P51 is the script that provokes the Gemini network failures (this sandbox has no
egress to Google hosts: `TLS/SSL connection has been closed (EOF)`). Running P51 first took
`gemini_attempts` to **10** with `gemini_error_class: network`, and re-running P52 unchanged gave
**34 PASS / 0 FAIL**. No code was touched between the two runs, so the first result measured the run
order, not the fix. These two scripts are order-dependent by construction and must be run
P51 → P52; that is recorded here rather than papered over by editing a previous phase's expectation.

---

## 11. Residual and open

* **F-54-4's contract choice is now made, not open** — HTTP 200 with `status:"not_found"`. If the
  operator prefers a 404, that is a one-line change in `delete_page_endpoint`; the tests name the
  assertion that would have to move.
* `update_keys` remains protected by its `Dict[str, str]` annotation rather than by its own guard.
  Changing that annotation to `Dict[str, Any]` would make the guard load-bearing; the test asserts
  "refused, and `.env` untouched" for either status code so that it does not silently rot.
* **O-55-1 (new, open, pre-existing — not Phase 55's, and not fixed here).** The suite can only be
  run with `.env` moved aside, because `core/db_engine.py:9` calls `load_dotenv(override=True)` and
  the live file's `DATABASE_URL` would otherwise point every test at this deployment's own database.
  With `.env` gone, `DB_PATH` is unset and `get_sqlite_db_path` falls back to the **repository's own
  `leads.db`**. Two test modules do not isolate that: `tests/test_stage_b_regressions.py` and
  `tests/test_p1_payment_security.py` (both `DB_PATH=0, tmp_path=0`; every other writing module sets
  one). Measured on `leads.db`, sha `1edf74f7404c31e9` → `f3e2a9fa38f118f1`: **+46 `audit_logs`
  rows** (37 `auth.login.success`, 5 `page.upsert`, 4 `payment.confirmed`), **+39 `sessions`**,
  **+38 `invoices`**, for tenants `stageb_tenant_a/b`, `p1_tenant_a/b` and `p1_tenant_no_qpay`.
  Page count unchanged at 28, and that file contains **0** rows with a `p55_*`/`e55_*` page id —
  this module's `write_env` fixture sets `DB_PATH` to a `tmp_path` file, so none of it is Phase 55's.
  Left open deliberately: fixing it means editing two modules' fixtures at the end of a phase whose
  suite is green, for a defect that predates the phase. `leads.db` is git-ignored, so no test data
  reached the commit; the rows are declared here instead of being deleted, because `audit_logs` is
  append-only by design (`migrations/versions/0007_audit_append_only.py`).
* `O-51-3` is unchanged: `TELEGRAM_WEBHOOK_SECRET` unset and `WEBHOOK_FAIL_CLOSED=0` in this
  deployment. Production refuses to start without it. Not mine to close.
* The `GEMINI_API_KEY` published on `origin/main:.env.example` is **0 % resolved**. It is in history
  since `c809654` and CI run `45773782793` passed it. Only rotation closes it; the operator chose
  `rotate_only`, so no repository change is made for it here.
* Production readiness remains 0/4 and operator-only remediation 1/6, both unchanged by this phase.
* Whether any real tenant's data was already corrupted by F-55-8's `{"status": null}` path, or had
  a slot double-booked through a garbage `appointments.status`, **cannot be determined from here**:
  nothing recorded either value before this phase. Lead 1 in this deployment was corrupted by my own
  probe and restored; no other row was found with a NULL stage or a non-enum appointment status
  (`SELECT DISTINCT status FROM appointments` on the application database returned `('12345',)` —
  my own probe row — and is now `CONFIRMED`).

---

## 12. Data, artefacts and cleanup

**Application database** `/tmp/p48a/p48a_smoke.db` (this deployment's own, `DB_PATH` from `.env`):

| Item | State after cleanup |
|---|---|
| pages | **4**: `100799479495809` (the real tenant), `p49_dev_default`, `p49_final`, `p49_upsert_probe`. Every probe page is gone: `p55_probe`, `p55_live`, and `p51_live`/`p52_live`/`p53_live`/`p54_live` recreated by the regression re-runs. |
| appointments with a `p5%` page id | **0**. Appointment id 1 — which carried this phase's `notes='12345'` probe residue — belonged to `p55_probe` and cascade-deleted with it, so that residue is gone rather than declared. |
| registrations with a `p5%` page id | **0**; lead 1 is `('100799479495809', 'p49-verified')`, the value restored after F-55-8's probe nulled it. |
| `automated_rules` with a `p5%` page id | **0** (the 3 rows `get_automated_rules` seeded on `p55_probe` went with it). |
| `gemini_api_key` matching a probe key | **0**. The synthetic key the live checks wrote was on `p55_live`, deleted by the script's own cleanup section, which also asserts this. |
| **`audit_logs`** | **337 rows remain and none was deleted** — the table is append-only (`migrations/versions/0007_audit_append_only.py`). 308 of them now carry `page_id IS NULL` because `audit_logs.page_id` is `ON DELETE SET NULL` (`0003_foreign_keys.py:101`), so deleting a probe page nulls the reference and keeps the record. Rows this phase added: `p55_probe` create/delete, `p55_live` create/delete ×2 (checks + negative control), `p54_live`/`p53_live`/`p52_live`/`p51_live` re-created and deleted by the regression re-runs, the appointments/leads/credentials/retention probes, and 2 `page.delete` rows from the cleanup. Today's 331 rows break down as `auth.login.success` 65, `page.upsert` 57, `page.delete` 50, `executive.settings.updated` 31, `page.gemini_key.updated` 25, `system.keys.updated` 23, `executive.recipient.registered` 17, `fintech.credentials.updated` 16, `executive.recipient.change_refused` 15, and 7 further classes ≤ 6 each. |

**Elsewhere:**

* `backups/` grew **3668 → 3714** files (+46). Isolated runs move `.env` aside, which unsets
  `BACKUP_DIR`, so maintenance tests write into the repository's own `backups/`. Nothing was
  deleted there, by standing instruction.
* The repository's `leads.db` changed sha `1edf74f7404c31e9` → `f3e2a9fa38f118f1` — **not by this
  phase's code**; see O-55-1 in §11 for the measured row delta. Page count still 28. Git-ignored,
  so none of it reached the commit.
* `gerege_crm_next.db` sha `4ccd2b197c82fd8a` unchanged (the Phase 51 regression asserts this).
* PostgreSQL test database `gerege_e05_test`: **0** rows with a `p55%`/`e55%` page id in `pages`,
  `registrations`, `appointments`, `session_states` or `audit_logs` — the new module cleans up after
  itself on both dialects. It still holds 22 pages and 360 audit rows accumulated by earlier phases'
  fixtures, and it is a disposable database, not this deployment's.
* Redis: **0** keys matching `gerege:test:*` at the end of the phase.
* The application and its worker were stopped; port 8000 has no listener. Their logs
  (`/tmp/p55_backend3.log`, `/tmp/p55_worker3.log`) are mode 600 and contain **no** credential: the
  6 `ERROR` lines in the backend log are the Gemini network failures and circuit-breaker
  short-circuits the Phase 51 regression provokes on purpose, and there are **0** lines containing
  `500 Internal Server Error`, `unhandled exception` or `Traceback`.
* Evidence and harnesses kept under `/tmp`, none of it in the repository: `p55_full_suite.log`
  (the run that exposed F-55-9), `p55_full_suite2.log`, `p55_full_suite3.log` (the final run),
  `p55_revert_run.log` (20/1), `p55_revert_run2.log` (21/0), `p55_checks55.sh` + `p55_checks55_out.txt`
  / `_out2.txt`, `p55_negctl55.sh` + `p55_negctl55_out.txt`, `p55_regr_p51.sh` (the P51 script with
  its log paths repointed at this run) and `p55_regr_p5{1,2,3,4}_out*.txt`, `p55_backend2.log` (the
  recorded 500s), `p55_bisect/` and `p55_bisect2/` (sha-verified copies of the working tree, used to
  bisect F-55-9 and to restore after the revert proofs), `p55_uus_pristine.py`. Throwaway databases
  under `/tmp/pytest-of-user/pytest-*` are pytest's own and expire with it.
