# PHASE 56 — FINAL REPORT

**Branch:** `arena/d78ebf88-gerege-ai-agent` · **base:** `5f12a98` (Phase 55) · **code + report commit:** `b49c19c` · **`origin/main`:** untouched
**Date:** 2026-11-27 · **ids opened:** F-56-1 … F-56-9 (9) · **ids closed:** 9 · **open at the end:** 0
**Tests added:** 101 in `tests/test_e56_page_identity_truth.py` (87 `def test_`, 10 classes) · removed/skipped/weakened: **0**

---

## 0. Verdict

| # | Site | Defect | Before (measured live) | After (measured live) | Class |
|---|------|--------|------------------------|-----------------------|-------|
| F-56-1 | `routers/automation_router.py:96` `create_comment_automation` | writes with a page id nobody checked | **500** `IntegrityError`, log `unhandled exception`, 0 rows | **404** `'p56_never_created' хуудас олдсонгүй - ямар ч дүрэм үүсгэсэнгүй.`, 0 rows | CLOSED |
| F-56-2 | `routers/automation_router.py` `create_tracked_link` | same | **500** `IntegrityError`, 0 rows | **404** `… ямар ч холбоос үүсгэсэнгүй.`, 0 rows | CLOSED |
| F-56-3 | `main.py` `create_invoice_manual_api` | missing page + five body shapes | **500** × 6 (1 `IntegrityError`, 1 `ValueError`, 2 `TypeError`, 2 `ProgrammingError`), 0 invoices | **404** for the missing page, **400** naming the field for the five shapes | CLOSED |
| F-56-4 | `main.py` `update_knowledge` | `if page_obj:` skipped the write, the success return did not | **200** `{"status":"success", … амжилттай шинэчлэгдлээ!"}`, 0 rows | **200** `{"status":"error","written":false,… шинэчлэгдсэнгүй."}`, 0 rows | CLOSED |
| F-56-5 | `cargo_service.py` `import_manifest_from_excel_bytes` | one `try` for parse + write; driver text quoted; committed rows discarded | **200** `{"success":false,"message":"Excel уншихад алдаа гарлаа: FOREIGN KEY constraint failed"}` | **200** `{"success":false,"stage":"page"｜"read"｜"write","written":N,"count":N,…}` | CLOSED |
| F-56-6 | `dashboard.html` × 4 (`submitManualInvoice`, `saveCurrentPageSettings`, `handleSaveLinks`, `handleSaveKnowledge`) | response awaited, never read; success toast unconditional | toast fired on 400/404/500 alike | each reads `res.ok` + the body and reports the refusal | CLOSED |
| F-56-7 | `dashboard.html` × 2 (`toggleCommentAutomationRule`, `deleteCommentAutomationRule`) | `if (res.ok)` with no `else` | a refused toggle/delete produced **no reaction at all** | both have an `else` that reports `err.detail ‖ err.error ‖ err.message` | CLOSED |
| F-56-8 | `scripts/migrate_sqlite_to_postgres.py:240` `inspect_sqlite_snapshot` | `conn.close()` was the second-to-last line of a ~50-statement body | any error in between leaked the snapshot connection | split into an owner + a body helper; close is in a `finally` | CLOSED |
| F-56-9 | `scripts/migrate_sqlite_to_postgres.py:220` `create_sqlite_snapshot` | **two** connections, one on the live database, closed after `src.backup(dst)` | a failed backup leaked both, and left a partial snapshot file | both closed in nested `finally`; the partial file is unlinked | CLOSED |

Backend log across the whole AFTER round (live probes + negative control + five regression suites):
**0 × `500 Internal Server Error`, 0 × `unhandled exception`, 0 × `IntegrityError`.**
The BEFORE round had **8 and 8**.

---

## 1. How the phase started

The standing instruction is *"odoo zasah saijruulah bolomjtoi zuilsee hiijil bai"* — keep finding and
fixing what can be fixed now, without per-item approval. The operator-side list stays the user's own
work and was not touched: `GEMINI_API_KEY` rotation, `TELEGRAM_WEBHOOK_SECRET` / `WEBHOOK_FAIL_CLOSED`
(O-51-3), deploy, merge to `main`, PR creation. Nothing in this phase required any of them.

Phase 55 closed ten ids of one class: a write path that answered a 500, or claimed success, for a
`page_id` that does not exist. Phase 55 swept `main.py`. This phase re-ran the same question against
the rest of the repository, and the first lesson was about the sweep rather than the code:

> **Phase 55 swept for a literal. Phase 56 swept for a class.**
> Phase 55 looked for `payload.get(key, "").strip()` and closed 18 sites. Three lines below one of
> them sat `int(payload.get("amount", 10000))` — the same assumption, a different call — and it
> produced five live 500s in this phase. Sweeping by coercion type (`int`/`float` over any
> `.get()` of a request body, inside a route handler) finds all of them at once. That sweep is now a
> test, pinned at zero, and it covers `routers/` and `scripts/` too.

---

## 2. Root cause: `enforce_tenant_scope` returns a page *id*, not a page

`core.security.enforce_tenant_scope` answers an administrator with the page id they asked for. That
is correct for its own job — tenancy, not existence — and it is not changed here. Fourteen tables
carry a foreign key to `pages` (`migrations/versions/0003_foreign_keys.py`, thirteen of them
`CASCADE`, `audit_logs` `SET NULL`). So a write that names a page nobody created is refused by the
**driver**, at the last possible moment, with the least useful possible message.

Four consequences, all measured:

1. An `INSERT` becomes an unhandled `IntegrityError` → 500 with no explanation (F-56-1/2/3).
2. A handler that reads `database.get_page(page_id) or {}` cannot distinguish *no such page* from
   *a page with no settings*, so it writes and lets the FK refuse (F-56-3).
3. A handler that guards with `if page_obj:` and then falls through to a success return tells the
   operator the write happened (F-56-4) — the worst of the four, because nothing downstream errors.
4. A handler with one `try` around *parse* and *write* blames the wrong artifact (F-56-5).

The fix is always at the HTTP boundary, never in the service: `fintech_service.create_payment_order`
still does `database.get_page(page_id) or {}`, because its other four callers (`agent.py:591`,
`:738`, `:865`, `cargo_service.py:45`) take the page from a stored row rather than from a body.
Changing the service contract would have touched all of them to fix one caller. A test pins that
decision so it is not "cleaned up" later.

---

## 3. F-56-1 / F-56-2 — the router Phase 55 never swept

```
POST /api/automations/comments  {"page_id":"p56_never_created","name":"p56 probe","dm_message_text":"p56 dm"}
    -> HTTP 500 {"detail":"Internal server error","request_id":"25429644f4999e19"}
    -> log: unhandled exception … IntegrityError
    -> comment_automations rows written: 0
POST /api/automations/links     {"page_id":"p56_never_created","title":"p56","target_url":"https://example.com/p56"}
    -> HTTP 500 (request_id e99762e418e3979b), tracked_links rows written: 0
```

Positive controls, same bodies against `p56_probe`: **200**, one row each (`automation.id` 1,
`code RyZ39nA5`). So the payload was fine and the page was the problem.

Both writers ended in `page_id=scoped_page_id or database.DEFAULT_PAGE_ID`. One resolver now stands
in front of both:

```python
def _resolve_existing_page(scoped_page_id: Optional[str], refusal: str) -> str:
    target = str(scoped_page_id or database.DEFAULT_PAGE_ID)
    if not database.get_page(target):
        raise HTTPException(status_code=404, detail=f"'{target}' хуудас олдсонгүй - {refusal}.")
    return target
```

A **404** rather than a 200 with a flag, because this router's own refusals are already
`HTTPException(404, "Автоматжуулалт олдсонгүй")` and because both dashboard consumers branch on
`res.ok` — until F-56-7 they said nothing at all on the failure path, so a 4xx is what actually
reaches the operator.

The two id-lookup endpoints were **left alone on purpose**: `toggle` and `delete` resolve by
automation id and already 404 (measured: `DELETE /api/automations/comments/99999999` → 404,
`POST …/99999999/toggle` → 404). A test asserts the resolver did not creep into them, so the change
stays as narrow as the defect.

After: **404** for both, 0 rows; positive controls **200** with a row each.

---

## 4. F-56-3 — the money endpoint: five body shapes and a missing page

Six live 500s on `POST /api/fintech/create-invoice`, each with its request_id:

| body | exception | request_id |
|------|-----------|-----------|
| `{"page_id":"p56_never_created","amount":1200}` | `IntegrityError` | `d443b6c6cbc4aa47` |
| `{"amount":"abc"}` | `ValueError` | `c562394d1e30f977` |
| `{"amount":null}` | `TypeError` | `bbe3073d879e584f` |
| `{"amount":{"a":1}}` | `TypeError` | `27017758da8851e0` |
| `{"description":{"a":1}}` | `ProgrammingError` (dict reached a SQL parameter) | `9005767c2736ac74` |
| `{"sender_id":{"a":1}}` | `ProgrammingError` | `a865c94c2f4b7148` |

Invoices written by all six: **0**. Positive control: **200** `invoice_id QP-202611270431-9A7CCB`.
`{"amount":-5}` already answered **400** `Мөнгөн дүн 0-ээс их байх ёстой` — that rule is pinned to
survive, and its position (coercion → business rule → page guard) is asserted by AST ordering.

Two new guards:

* `_payload_int(payload, key, default)` — Phase 55's `_payload_text` for numbers. An **absent** key
  takes the default (as `payload.get` always did); a **present** `null` is refused, because quietly
  invoicing the default 10000₮ for an empty field is worse than a 400; a numeric string is accepted
  (that is what an HTML form posts); `bool` is refused explicitly even though it is an `int`
  subclass, so `{"amount": true}` cannot become a 1₮ invoice.
* a 404 page check immediately before `create_payment_order`.

After: 404 for the missing page, **400** naming the field (`amount must be a number`,
`description must be a string`, `sender_id must be a string`) for all five shapes, 0 invoices, and
the positive control still returns an `invoice_id`.

One measurement in this phase corrected **me**, not the code: `{"sender_id": 5}` answers **200** and
stores the text `'5'`. My first harness expected 400. The authority is Phase 55's pinned test
`test_payload_text_coerces_a_number_to_its_text_form` — `sender_id` is a Telegram user id on the
paths that matter, so a numeric sender is not a malformed body. The expectation was wrong; the
behaviour is right and is now documented in the test that covers it.

---

## 5. F-56-4 — a 200 that claimed success and wrote nothing

```
POST /api/knowledge?page_id=p56_never_created  {"bank_accounts":{"khaan":"P56 never"}}
    -> HTTP 200 {"status":"success","message":"p56_never_created хуудасны мэдлэгийн сан амжилттай шинэчлэгдлээ!"}
    -> rows written: 0
```

`if page_obj:` wrapped the `save_page(...)` call; the `return {"status": "success", …}` was outside
it, so the missing page fell straight through to the success message. The positive control (a page
that exists) returned a **byte-identical** message and did write — the two were indistinguishable to
the caller. And both dashboard knowledge saves discarded the response entirely (F-56-6), which is
how an operator came to be told that new bank-account details were saved while the agent kept
answering from the stored ones.

The guard now returns before the write, keeps the endpoint's own vocabulary, and skips
`agent.reset_sessions` (there is no page to reset):

```python
if not page_obj:
    return JSONResponse({"status": "error", "written": False, "page_id": target_id,
                         "message": f"'{target_id}' хуудас олдсонгүй - мэдлэгийн сан шинэчлэгдсэнгүй."})
```

**200, not 4xx** — the consumer reads `data.status`, and the endpoint's success shape is
`{"status": "success"}`, so `status: "error"` is the honest sibling. Phase 49's F-49-4 rules are
pinned to survive: the stored `gemini_api_key`, `verify_token`, `monthly_token_limit` and
`is_active` are still carried through, so a knowledge edit cannot blank a secret or re-enable a
disabled tenant.

After: `{"status":"error","written":false}` for the missing page, 0 rows, `reset_sessions` not
called; `{"status":"success"}` and one row for the real page.

---

## 6. F-56-5 — the cargo manifest: which stage failed, and how many rows landed

```
POST /api/cargo/import-manifest?page_id=p56_never_created   (a valid one-row .xlsx)
    -> HTTP 200 {"success":false,"message":"Excel уншихад алдаа гарлаа: FOREIGN KEY constraint failed"}
```

The Excel file parsed correctly; the **database** refused the write. One `try` wrapped the parse and
the write loop and named every failure "Excel уншихад алдаа гарлаа", so the operator was sent to
look for a broken spreadsheet, and the message quoted the driver verbatim. A second defect sat
underneath: `upsert_cargo_package` commits per row, so a manifest of 500 that fails on row 3 has
written 2 packages — `inserted_count` held that number and the `except` branch threw it away, making
a partial import indistinguishable from a total failure.

Now: the page is checked **before** the file is opened, and the two stages report separately.

```python
if not database.get_page(page_id):
    return {"success": False, "stage": "page", "written": 0, "count": 0,
            "message": f"'{page_id}' хуудас олдсонгүй - ямар ч ачаа бүртгэсэнгүй."}
…
except Exception as e:
    if stage == "read":   # parse
        logger.error(f"Error reading cargo manifest {filename}: {e}", exc_info=e)
        return {"success": False, "stage": "read", "written": 0, "count": 0,
                "message": f"Excel файл уншигдсангүй ({type(e).__name__}): {e}"}
    logger.error(f"Error writing cargo manifest {filename} after {written} row(s): {e}", exc_info=e)
    return {"success": False, "stage": "write", "written": written, "count": written,
            "message": f"{written} ачааг бүртгэсний дараа өгөгдлийн сангийн алдаа гарлаа "
                       f"({type(e).__name__}): үлдсэн мөрүүд импортлогдоогүй. "
                       f"Файлыг дахин илгээхэд өмнө бүртгэгдсэн ачаанууд давхардахгүй."}
```

The write branch **names the exception type and never quotes the driver text**: a test injects
`IntegrityError("FOREIGN KEY constraint failed")` on row 3 of 5 and asserts the response says
`written: 2` and does *not* contain the driver string, while the log does. The promise that a
re-upload is safe is not taken on faith either — `database.upsert_cargo_package` is
`ON CONFLICT(page_id, tracking_code) DO UPDATE`, pinned by source and by a real SQLite test that
upserts the same code twice and finds one row.

`{"success": true, "count": N}` for a good import and `{"message": "Файл хоосон байна"}` for an
empty workbook are unchanged. **200 kept**, because the consumer already branches on `data.success`
and alerts `data.message` (that consumer was one of the false positives in §9).

After: `stage:"page"` for a missing page (proved to run before parsing by sending bytes that are not
a spreadsheet at all — the answer is still `page`, not `read`), `stage:"read"` with `(BadZipFile)`
for a corrupt file, `stage:"write"` with the honest count for a mid-import failure.

---

## 7. F-56-6 / F-56-7 — the dashboard said nothing, or said the wrong thing

Six consumers awaited a response and never read it, each followed by an unconditional success toast:

| function | endpoint | before |
|---|---|---|
| `submitManualInvoice` | `POST /api/fintech/create-invoice` | `const inv = await res.json()` then a success toast; `inv.pay_url` undefined on any refusal, so no payment window opened either |
| `saveCurrentPageSettings` | `POST /api/pages` | the "Тохиргоо хадгалах" button; 400 `{"error":"Page ID болон Нэр шаардлагатай"}` (measured) toasted as saved |
| `handleSaveLinks` | `POST /api/knowledge` | bank-account details; toasted as saved even for F-56-4's silent no-op |
| `handleSaveKnowledge` | `POST /api/knowledge` | the knowledge base itself; same |

Each now reads `res.ok` **and** the body, and reports the refusal in the same Mongolian voice as the
rest of the dashboard. The invoice one is an `alert`, not a toast, because it is the money path; it
reads `detail ‖ error ‖ message` because this phase's own fixes answer with `detail` while older
endpoints answer with `error`.

F-56-7 is the narrower, quieter defect: two `if (res.ok) { … }` blocks with no `else` at all, so a
404 or 403 on a toggle or a delete produced **no reaction whatsoever** — a failed click and a slow
click looked identical.

The metric, measured with a calibrated scanner rather than a regex:

| | `if (X.ok)` blocks | with `else` | toast success with no `else` |
|---|---|---|---|
| before | 18 | 2 (lines 5621, 5664) | **2** (toggle 5634, delete 5642) |
| after | 18 | **4** (5662, 5675, 5690, 5716) | **0** |

The 14 remaining else-less blocks read data or re-render; they claim nothing to the operator. The
four that now have an `else` are exactly the four automation write paths, and a test asserts that by
walking up from each block to its owning function.

### 7.1 A SyntaxError I introduced, and the check that caught it

The first version of the knowledge patches wrote `const res = await fetch(…)` inside
`handleSaveLinks` and `handleSaveKnowledge` — both of which **already** declare `const res` for the
GET that loads the current knowledge. Two `const`s in one scope is a `SyntaxError`, and a
`SyntaxError` in an inline `<script>` takes down the **whole block**, not the one save: the browser
would have run none of the dashboard's JavaScript.

`node --check` on the extracted block reported it (`Identifier 'res' has already been declared`).
The declarations are now `saveRes`, and the check is a permanent test: both inline blocks must parse.
The revert harness proves the test can fail — a case injects exactly that duplicate and the test
catches it. This is worth recording because it is the second time in two phases that a fix broke a
detector (F-55-9) and the suite, not the author, noticed.

---

## 8. F-56-8 / F-56-9 — the migration script's connections

Found by the AST sweep, not by reading: *"every `sqlite3.connect` in this repository is closed in a
`finally`"*. `migrations/` is out of scope (Alembic owns those connections); `scripts/` was not, and
both hits were in one file.

**F-56-8** `inspect_sqlite_snapshot(snap_path)` opened a connection and closed it on the
second-to-last line of a body of roughly fifty statements — a snapshot missing a column, a checksum
over a corrupt page, a `None` where a total was expected, and the file stayed open for the rest of
the migration. The function now owns the connection and closes it in a `finally`; the body moved
verbatim into `_inspect_sqlite_snapshot(conn)`, which owns nothing and closes nothing (asserted).

**F-56-9** `create_sqlite_snapshot` was worse and was only found after the sweep was widened: it
opened **two** connections — `dst` on the fresh snapshot and `src` on the **live SQLite database
being migrated** — and closed both on the last two lines, after `with dst: src.backup(dst)`. That
backup is precisely the statement that can fail (locked database, full disk, corrupt page);
`with dst:` commits or rolls back but does **not** close. Both connections leaked, and the partial
snapshot file stayed in `/tmp` with its path unknown to any caller. Now: nested `finally` for both
connections, and the snapshot is unlinked when the backup did not complete — with the `return`
inside the `try`, so a success never unlinks its own result (asserted by ordering).

The sweep was widened during this phase, because the first version had a hole the revert harness
found: it only flagged a function that *has* a `close()` outside a `finally`, so reverting F-56-8 —
which leaves the body with no close at all — sailed through. The sweep now flags an owned connection
that is neither closed in a `finally` nor returned to the caller (`core/db_engine.get_db_connection`
returns its connection, and a `with sqlite3.connect(…)` block produces no ownership at all). Three
calibration tests pin the widened rule in both directions. Repo-wide result: **0**.

---

## 9. What PASSed by measurement — the false positives

A sweep is only as good as the things it clears. These looked like the same defect and are not; each
is measured, and the ones that could drift are pinned by a test.

| Suspect | Why it is not a defect |
|---|---|
| `POST /api/pages` with `name: ""` | **400** `{"error":"Page ID болон Нэр шаардлагатай"}` — refuses before writing |
| `POST /api/pages/{id}/gemini_key` with `monthly_token_limit` = `"abc"`, `{"a":1}`, `null`, `[1,2]`, `"5000"`, `5000` | **all 200**; bad values reported as `changed: []`, `preserved: ["gemini_api_key","monthly_token_limit"]`, `ignored_fields: ["monthly_token_limit"]`; stored limit stays 5000 (Phase 54's merge rule) |
| `core/backup_crypto.py:311` `int(header.get("_container_version", FORMAT_VERSION))` outside a `try` | unreachable failure: `read_header()` (:257) validates magic/version/truncation and **overwrites** `_container_version` with the struct-unpacked int |
| `core/pinned_http.py` | flagged by the opener sweep; it is a socket, not a DB-API connection |
| `database.save_page` / `update_automated_rule` bare `return True` | measured on a throwaway DB: SQLite `ON CONFLICT DO UPDATE` reports rowcount 1, so `True` is the truth |
| `routers/automation_router.py` toggle / delete | resolve by id first → **404** (measured) |
| `dashboard.html` `submitCargoManifest` (:3492) | already correct: `if (data.success) {…} else { alert(data.message ‖ 'Импортлоход алдаа гарлаа') }`, a `catch` for a non-JSON answer, and a `finally` that re-enables the button |
| `dashboard.html` :4468, :4589, :4611, :4948, :4992, :5227, :5279 | flagged by a 13-line window heuristic; each checks `data.success` with an `else` |
| `main.py:1299/1320/1370` gemini `monthly_token_limit` coercion | inside a `try`, and the endpoint answers 200 with `ignored_fields` |
| `main.py:2706` `qpay_webhook` `inv.get("amount")` | `inv` is a stored row, not a request body |
| 55 of 57 hits in the numeric-coercion sweep | they coerce values from the DB, Redis or a `struct` — not from a request body. The sweep is therefore restricted to route handlers |

---

## 10. Three defects in my own harness, found by measurement

Recorded because each one would otherwise have become a false claim in this report.

1. **The first AFTER harness reported `OK=3 FAIL=25` while every response body showed the fix
   working.** Three separate bugs in the script: expected codes copied from the BEFORE table (a
   column that meant "500 before" was read as "200 expected"), substring checks written with spaces
   (`'"status": "success"'`) against a body that has none (`{"status":"success"}`), and an invented
   column name (`amount_mnt` for `amount`). The bodies and the log were the evidence; the script was
   rewritten around a `run`/`want`/`wantrow` split and produced 28/28.
2. **The `.ok`-block scanner was wrong twice.** Starting the brace count on the line *after* the
   `if` never counts the opening brace; and looking for `else` only where depth returns to 0 finds
   nothing, because `} else {` nets to zero braces — the `else` sits on the line that closes the
   if-*body*. Both versions reported "18 blocks, 0 with an else", which contradicted two blocks I
   had read by eye. The calibrated version reproduces the hand reading exactly (2 before, 4 after)
   and is now a tested helper with three calibration cases of its own.
3. **The P53 regression FAIL was my choice of script, not a regression.** `p53_checks53.sh` counts
   `audit_logs WHERE resource_id='p53_never_created'` **absolutely**, and one such row exists from a
   Phase 53-era manual `DELETE` at 2026-11-26 12:09:57 (id 143). Phase 54 and Phase 55 both ran the
   *corrected* script `p54_regr_p53.sh`, whose check is scoped to `action like 'executive.%' or
   'fintech.%'` and labelled "no SETTINGS audit row". Running that one gives **46/0**. No previous
   phase's expectation was edited; the row predates this phase by sixteen hours.

---

## 11. What changed

| file | lines | change |
|---|---|---|
| `main.py` | 3920 → 4004 (+84) | `_payload_int`; invoice handler typed + 404 guard; knowledge guard and de-indented write; `_payload_text` docstring count corrected to the AST's truth (20 sites / 10 handlers) |
| `routers/automation_router.py` | 201 → 231 (+30) | `_resolve_existing_page`, used by both writers |
| `cargo_service.py` | 249 → 303 (+54) | page guard before the parse; `stage`/`written` reporting; driver text to the log only |
| `scripts/migrate_sqlite_to_postgres.py` | 702 → 741 (+39) | `inspect_sqlite_snapshot` owner/helper split; `create_sqlite_snapshot` nested `finally` + unlink |
| `dashboard.html` | 5679 → 5731 (+52) | four consumers read the response; two `else` branches added |
| `tests/test_e56_page_identity_truth.py` | new, 1610 lines | 101 tests, 10 classes |

`git diff --stat`: **293 insertions, 34 deletions** across the five source files, plus the new test
module. No file outside that set was touched.

---

## 12. Verification

| check | result |
|---|---|
| new module `tests/test_e56_page_identity_truth.py` | **101 passed / 0 failed** (3.8 s) |
| revert harness `/tmp/p56_revert.py`, 17 cases | **17 CAUGHT / 0 MISSED / 0 ANCHOR**; all five files restored to their pristine sha256 after every case |
| live AFTER `/tmp/p56_probe3.sh` | **28 / 28** (27 in the run + `sender_id:5` re-measured against Phase 55's pinned contract in `/tmp/p56_probe4.sh`) |
| live negative control `/tmp/p56_negctl.sh` | 6 expectations corrupted → **17 FAIL / 11 OK**, so the harness is not passing vacuously |
| backend log, AFTER round | **0** × 500, **0** × `unhandled exception`, **0** × `IntegrityError` (BEFORE: 8 and 8) |
| blast radius (45 modules that reference the changed code) | **1603 passed / 22 skipped / 0 failed** in 349.49 s |
| regression P51 | **37 / 0** |
| regression P52 | **34 / 0** |
| regression P53 | **46 / 0** (with the corrected script — see §10.3) |
| regression P54 | **45 / 0** |
| regression P55 | **91 / 0** |
| P55 negative control | **88 / 3** (the three deliberate failures, unchanged) |
| sweeps: numeric coercion at the HTTP boundary | **0** |
| sweeps: writer taking an unchecked default page | **0** |
| sweeps: connection opened and not released in a `finally` | **0** |
| `node --check` on both inline `<script>` blocks | **2 / 2** parse |
| full suite, PostgreSQL | **2691 passed / 74 skipped / 1 xfailed / 0 failed** in 710.43 s (`/tmp/p56_full_suite.log`) — 2590 at the end of Phase 55 plus the 101 added here |
| tests removed / skipped / weakened / converted | **0** |
| `tests/test_e50_ai_readiness_truth.py` | untouched; `ERROR_CLASSES == ("auth","quota","model","network","bad_request","server","other")` asserted from the module itself |
| test floor | 2471 passed / 0 failed required; **2691 passed / 0 failed** delivered |

The revert cases, one per fix, with the tests that caught each:

| case | caught |
|---|---|
| F-56-1 comments writer | 4/4 |
| F-56-2 links writer | 3/3 |
| F-56-3a `int(payload.get("amount"))` restored | 2/2 |
| F-56-3b invoice page guard removed | 3/3 |
| F-56-3c `description … .strip()` restored | 2/2 — including **Phase 55's** `test_no_unguarded_payload_strip_sites_remain`, i.e. the older phase's own sweep catches the newer phase's regression |
| F-56-4 knowledge guard removed, `if page_obj:` restored | 2/2 |
| F-56-5a cargo page guard removed | 3/3 |
| F-56-5b cargo stage reporting reverted | 3/3 |
| F-56-6a–d four dashboard consumers reverted | 1/1, 1/1, 2/2, 2/2 |
| F-56-7a/b two `else` branches removed | 3/3 each |
| F-56-8 inspect snapshot reverted | 4/4 |
| F-56-9 create snapshot reverted | 3/3 |
| calibration: duplicate `const res` injected | 1/1 (`node --check`) |

Two absolute-count assertions in the live harness are run-order dependent by nature: re-running
`p56_probe3.sh` increments `comment_automations` for `p56_probe` and adds a second 1300₮ invoice, so
a second run reports 3 and 2 where the authoritative run reported 2 and 1. The negative control
showed exactly this. The authoritative AFTER numbers are the first run's, and the page was deleted
during cleanup, so nothing persists.

---

## 13. Residual and open

**Open, and the user's own work — not touched:**

| id | what | why it is still open |
|---|---|---|
| O-51-3 | `TELEGRAM_WEBHOOK_SECRET` unset, `WEBHOOK_FAIL_CLOSED=0` | operator-side secret + deploy decision |
| O-55-1 | `tests/test_stage_b_regressions.py` and `tests/test_p1_payment_security.py` have no `DB_PATH`/`tmp_path`, so a suite run without `.env` writes into the repo's git-ignored `leads.db` | fixing it means editing two earlier phases' fixtures; recorded rather than rushed. Growth this phase, measured around the two runs that touch it: sha `f3e2a9fa38f118f1` → `e542a09c5db42f92` (blast radius, 1601 audit / 1413 sessions / 1689 invoices / 30 pages) → `2e2e6608bf4b4145` (full suite, 1618 / 1429 / 1708 / 30) — **+17 audit, +16 sessions, +19 invoices** in the suite run alone, and still **0** `p56%`/`e56%`/`p55%`/`e55%` rows, i.e. none of it is this phase's probe data. It happens even with `DATABASE_URL` set, because those two modules reach `core.db_engine.get_sqlite_db_path` with no `DB_PATH` and `.env` parked, and that falls back to the repo's `leads.db` |
| — | the exposed `GEMINI_API_KEY` on public `main` | only rotation closes it; **0 %** resolved |
| — | production readiness 0/4, operator-only 1/7 | unchanged, by design |

**Countable lists:**

* `F-*` ids: 40 closed before this phase + 9 here = **49 / 49 = 100 %**
* `O-*` ids: **5 / 7 closed = 71 %** (O-51-3, O-55-1 open)
* B1–B7: **7 / 7 = 100 %**
* Phase 56 defects found → closed: **9 / 9 = 100 %**
* revert cases caught: **17 / 17 = 100 %**
* live AFTER checks: **28 / 28 = 100 %**
* dashboard `.ok` blocks that toast with no failure branch: **2 → 0 = 100 % closed**
* repo-wide sweeps at zero: **3 / 3**
* tests removed, skipped, weakened or converted: **0**
* push authorisation used outside `arena/d78ebf88-gerege-ai-agent`: **0**

**Not verified, and not claimed:** Gemini key validity (no egress to Google hosts — HTTP 000 / curl
exit 35), AI reply quality, Telegram, Meta, QPay end-to-end, the Windows launcher, and dashboard
toasts at browser level (the JS is checked by `node --check` and by source assertions, not by a
browser).

---

## 14. Data, artefacts and cleanup

Probe data was created in the deployment's own throwaway DB (`/tmp/p48a/p48a_smoke.db`) and removed
through the API:

| | before cleanup | after |
|---|---|---|
| pages | 6 | **4** (`100799479495809`, `p49_dev_default`, `p49_final`, `p49_upsert_probe`) |
| `p56_probe` children | comments 3, links 4, invoices 7, cargo 1 | **0 / 0 / 0 / 0** (cascade) |
| pages matching `p5%` | 2 (`p56_probe`, `p51_live`) | **0** |
| `audit_logs` | 416 | **420** |

`DELETE /api/pages/p56_probe` → 200 `{"status":"deleted","deleted":true}`. `p51_live` was left behind
by the P51 regression script and was deleted the same way (Phase 55 did the same). `p56_never_created`
was never created at all — verified 0 page rows, 0 children.

**Declared, not hidden:** `audit_logs` is append-only, so the probes' residue stays. It grew from the
pre-phase baseline of **337 rows / 308 with NULL `page_id`** to **420 / 386** — **+83 rows, +78
NULL-page rows**, all from this phase's live measurements and the five regression suites. The
PostgreSQL test DB `gerege_e05_test` holds 22 pages / 360 audit rows with **0** `p56%`/`p55%`/`e55%`
residue. Redis `gerege:test:*` → 0. `backups/` was never deleted from: **3714 → 3788 files (+74)**, written by the suite's own
backup/restore tests. Declared, not cleaned.

Synthetic values only: page ids `p56_probe` / `p56_never_created`, cargo code `P56CARGO0001`,
phones `99990000`–`99990010`, bank text `P56 after real`, amounts 1200/1300/1400₮. No secret value
was printed, logged or committed; cookie jars (`/tmp/p56_ck*.txt`) were deleted after each round.

Artefacts kept in `/tmp` for audit: `p56_probe1.sh` (BEFORE), `p56_probe3.sh` + `p56_probe4.sh`
(AFTER), `p56_negctl.sh`, `p56_revert.py` + `p56_revert_run2.log`, `p56_sweeps.py`, `p56_okscan.py`,
`p56_blast_list.txt` + `p56_blast.log`, `p56_full_suite.log`, `p56_backend_after.log`,
`p56_regr_p5{1,2,3,4,5}.out`, `p56_negctl55.out`, `p56_leads_before.txt`, `p56_pristine/` (the five
pre-patch sources the revert harness restores from), `p56_manifest.xlsx`, `p56_bad.xlsx`.

---

## 15. The boundary respected

Work is committed to `arena/d78ebf88-gerege-ai-agent` only. `origin/main` is untouched, no force
push, no history rewrite, **no PR opened, nothing merged, nothing deployed, no key rotated**. The
pre-existing `git merge-tree` conflict on `.env.example` (from B3) is unchanged, so a merge would
still need a human decision.
