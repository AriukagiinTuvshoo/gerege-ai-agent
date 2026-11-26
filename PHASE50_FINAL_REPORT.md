# PHASE 50 — CONNECTING THE GEMINI KEY, AND WHAT THAT EXPOSED

**Repository:** `AriukagiinTuvshoo/gerege-ai-agent`
**Branch:** `arena/d78ebf88-gerege-ai-agent`
**Started from:** `1a3bcbd` (Phase 49 pushed), `main` @ `aedeca4`
**Instructions:** *"GEMINI API KEY HOLBOH ASUUDALIIG … ENE KEYIIG HOLBOOD OGOOROI"* (connect this
key), then *"DARAAGIIN AJILAA HIIGEEREI"* (proceed with the next work).
**Window:** 2026-11-26T05:4x → 06:5x UTC

**Outcome:** the key is connected in the only place it belongs (the git-ignored local `.env`)
and could not be exercised, because this sandbox has no route to Google. Connecting it exposed
**four defects**, one of them severe and long-standing: running the migrations at first boot
**silently disabled 10 of 15 application loggers**, including the AI error log, the security
log and the secret-guard warning — the process looked healthy and ran blind. That also
explains, at last, the `caplog` hazard Phase 49 recorded without being able to identify.

Full suite: **2106 passed, 59 skipped, 1 xfailed, 0 failed** in 675.34 s — floor raised from
2003 by exactly the 103 tests added here. Nothing removed, skipped, weakened or converted.

---

## 1. The key itself

| Question | Answer |
|---|---|
| Where is it stored? | `.env` line 9, `GEMINI_API_KEY=…`, mode `600`, git-ignored (`.gitignore:2`) |
| Written how? | Atomic rewrite (`tempfile` + `os.replace`), all **42** keys and **170** lines preserved, no other secret touched |
| Committed or pushed? | **No.** `git grep` for the literal value: 0 hits in tracked files; 0 hits in the last commits; `.env` is not tracked |
| Logged anywhere? | **No.** 0 occurrences in the backend log, the worker log, or any file in the repository except `.env` (verified by grepping for the literal value) |
| Accepted by the app? | Yes — `INFO:agent:Gemini AI Үндсэн Client холбогдлоо. Model: gemini-3.5-flash-lite`, and the previous `GEMINI_API_KEY тохируулаагүй байна` warning is gone |
| Proven to work? | **NO — cannot be proven here.** See §2 |
| Still needs doing | **Rotate it.** It was pasted into a chat, so it must be treated as exposed |

Two mechanical facts worth knowing:

* The app **hot-reloads this one variable**: `agent.get_client_for_page()` re-runs
  `load_dotenv(override=True)` and re-initialises when the key differs, so `/api/health`
  flipped to `gemini_configured: true` on the *already running* process before any restart.
  That is a narrow exception to F-48A-4 (which is about connection-level settings), not a
  general one — Redis, `DATABASE_URL`, `DB_PATH` and the limiter still need a restart.
* `google-genai` 1.75.0 sends the key in the **`x-goog-api-key` header** (`_api_client.py:784`)
  and never as a `?key=` query parameter. That is why no URL in any error message can carry
  it — a structural guarantee, not luck.

---

## 2. Why the AI still cannot be verified here

This sandbox's egress allowlist is `github.com`, `api.github.com`, `pypi.org`,
`registry.npmjs.org`, `files.pythonhosted.org`. Measured:

```
github.com                             HTTP 200
generativelanguage.googleapis.com      HTTP 000   BLOCKED (TLS closed immediately)
aiplatform.googleapis.com              HTTP 000   BLOCKED
oauth2.googleapis.com                  HTTP 000   BLOCKED
```

The application's own log shows the attempt and the graceful degradation:

```
WARNING:core.ai_router: AI call retry 1/1 after 0.4s due to: TLS/SSL connection has been closed (EOF)
WARNING:agent: Chat session send_message error, refreshing session: …
ERROR:agent: Gemini API алдаа: …
INFO: 127.0.0.1 - "POST /api/chat HTTP/1.1" 200 OK        ← fell back, did not break
```

`/api/chat` returns **200** with `"model":"fallback"` and the deterministic Mongolian reply.
So: **AI reply quality = NOT VERIFIED (egress blocked)** — not "the key is bad", and not
"the AI works". The key's *validity* is equally unverifiable from here.

One shape observation, offered only as something to check: the key is **53 characters,
`AQ.Ab…O3-Q`**, not the classic AI Studio shape (`AIza…`, 39 characters, which is also what
this repository's own fake-key test fixture uses). That is not evidence of a problem — but if
a live call returns `400 API_KEY_INVALID`, the key is the thing to re-issue, and if it returns
`404`, the key is fine and `GEMINI_MODEL=gemini-3.5-flash-lite` in `.env` is the thing to
change. §11 has the exact commands to tell those apart in under a minute.

---

## 3. F-50-1 — `gemini_ready` reported a key that had never worked (MEDIUM, misleading signal)

`agent.is_gemini_ready()` is `bool(agent.default_client)`, and building that client
(`genai.Client(api_key=…)`) performs **no network I/O**. `/api/health` published the result as
`gemini_ready`, next to two honestly named neighbours — `meta_token_configured` and
`telegram_configured` — which claim only configuration. Measured live, before the fix:

```
/api/health -> {"gemini_ready": true,  ...}      ← while every generation attempt failed
/api/chat   -> 200 {"model": "fallback"}
```

An operator reading `gemini_ready: true` during an incident concludes the AI works. This is
the same class of defect as F-48A-3 (the worker-health endpoint asserting a scheduler topology
it had never observed), and it was fixed the same way: **report what was observed**.

### What was added

`core/ai_readiness.py` (new, 330 lines, stdlib only) records the outcome of real generation
calls and publishes them:

| Field | Meaning |
|---|---|
| `gemini_ready` | **unchanged value**, kept so nothing that already reads it changes behaviour |
| `gemini_configured` | what `gemini_ready` always actually meant, now named plainly |
| `gemini_verified` | `null` = never attempted since startup; `true`/`false` = the last real call's outcome |
| `gemini_error_class` | one of a **closed enum**: `auth`, `quota`, `model`, `network`, `bad_request`, `server`, `other` |
| `gemini_attempts` | generation calls observed since startup |
| `gemini_note` | one static sentence saying what is and is not known |

Measured live after the fix (same instance, same key, same blocked network):

```
fresh process   : gemini_configured=True  gemini_verified=None   gemini_attempts=0
                  note: "GEMINI_API_KEY is set and a client was built, but no generation call has
                         been attempted since startup, so the key is NOT proven to work: building
                         the client makes no network call. Send one message to find out."
after /api/chat : gemini_configured=True  gemini_verified=False  gemini_error_class="network"
                  gemini_attempts=2
                  note: "the most recent generation call FAILED (class: network); replies are
                         falling back to the deterministic answer. A configured key is not a
                         working key."
```

`gemini_attempts=2` for one user message is truthful, not a bug: `ai_router.execute_with_retry`
retried once, and the session-refresh path tried again. Counting calls rather than conversations
is what makes the retry visible.

### Design decisions, and why

* **`null` is not `false`.** A freshly started process has not failed anything; reporting
  "not verified" as `false` would send an operator chasing a working key.
* **No exception text in `/api/health`.** It is unauthenticated, and `/api/ready` already
  states that rule in its own comment (*"Backend kind, never the URL, and no exception text"*).
  `health_fields()` therefore publishes a closed enum and counters only; the redacted excerpt
  is kept in `snapshot()` for logs, tests and admin surfaces.
* **The classification is a closed enum, matched on the provider's own vocabulary.** A first
  version matched bare digits as HTTP statuses; that made `the report was 429 pages long` a
  quota failure and `_ssl.c:992` a source of false matches. Digits are now honoured only where
  a provider demonstrably puts one — on the exception's `status_code`/`code` attribute, or in
  the wrappers SDKs actually emit (`<HttpError 403 when requesting …>`, `Error code: 429 - …`,
  `status_code=503`). Reason phrases are tried first, because they are more reliable.
  `Permission denied` on a *filesystem* path deliberately does **not** classify as `auth`.
  All 26 pinned cases pass.
* **Outcomes are recorded per key scope.** A tenant's own `pages.gemini_api_key` proving itself
  says nothing about the platform key, so `scope="page"` observations never move the default
  verdict — otherwise one paying tenant would hide a broken platform credential.
* **Only the network call is recorded.** `Image.open()` failing on a corrupt upload is bad
  input, not a broken key; recording it would let one user's malformed JPEG mark the platform
  AI as down. Both `send_message` attempts go through one closure (`_send_generation`) so a
  retry cannot be mistaken for a first attempt.
* **Rotating the key discards the old verdict.** `_init_default_gemini()` keeps a 16-char
  sha256 fingerprint (never the value) and resets the default scope when it changes, because a
  success observed with the previous credential says nothing about the new one. Re-initialising
  with the *same* key keeps the verdict — which matters, since `get_client_for_page()` calls it
  on request paths.
* **The diagnostic cannot break anything it is reported through.** Every recorder swallows its
  own errors, `gemini_status()` falls back to configuration-only if reporting raises, and a
  test proves `/api/health` still answers 200 with the diagnostic deliberately broken.

---

## 4. F-50-2 — raw exception text was logged, and returned to an API caller

Four AI error paths interpolated the exception straight into a log message, and one returned it
in a response body:

```python
logger.error(f"Gemini API алдаа: {e}")
logger.warning(f"Chat session send_message error, refreshing session: {send_err}")
logger.error(f"Зураг шинжлэхэд алдаа гарлаа: {e}")
return {"is_receipt": False, "details": str(e)}          # ← to the caller
logger.warning(f"Alternative AI provider fallback error: {alt_err}")
logger.error(f"Gemini Client холболтын алдаа: {e}")
```

The repository already owns the right tool (`core/redaction.py`, which lists
`GEMINI_API_KEY` among `SECRET_ENV_VARS` and collapses newlines so a caller cannot forge a
second log record) and already uses it on the backup-alert path — but not here. A provider or
SDK message can quote the request it was building, and the OpenAI-compatible fallback takes a
`base_url` that an operator may have written with a key in it.

All six sites now go through `ai_readiness.redacted()`: redacted against every secret in the
environment, ANSI and control characters stripped, collapsed to one line, bounded to 200
characters, and — if the redactor itself fails — reduced to the exception's class name rather
than passing the text through. Verified live: the key appears **0** times in either process log,
while the diagnostic survives intact:

```
WARNING:core.ai_readiness:AI generation failed (scope=default class=network): ConnectError: TLS/SSL connection has been closed (EOF) (_ssl.c:992)
```

---

## 5. F-50-3 — removing the key did not stop using it

`_init_default_gemini()` had an `else` branch that logged "no key configured" but left
`self.default_client` pointing at the previously built client:

```python
else:
    logger.warning("GEMINI_API_KEY тохируулаагүй байна.")   # client left in place
```

So an operator who deleted or revoked a key at runtime kept calling — and **billing** — the
credential they had just removed, while `/api/health` reported it as configured. Found by a
test, not by inspection: `test_clearing_the_key_discards_the_verdict` failed with
`assert True is False` and the cause was this branch. Now the client is dropped, with a distinct
log line when something was actually removed:

```python
if self.default_client is not None:
    logger.warning("GEMINI_API_KEY устгагдсан тул Gemini client-г зогсоов.")
else:
    logger.warning("GEMINI_API_KEY тохируулаагүй байна.")
self.default_client = None
```

---

## 6. F-50-4 — the first boot silenced the application (HIGH)

This is the significant one, and it was found because a *test fixture* captured nothing.

`migrations/env.py` called `logging.config.fileConfig(alembic.ini)`. That function defaults to
**`disable_existing_loggers=True`**, and `alembic.ini` sets `[logger_root] level = WARN`.
`main.py` imports — and therefore creates the loggers of — `agent`, `database`, `core.security`,
`core.secret_guard`, `core.ai_router`, `core.monitoring`, `core.task_queue`, `core.rate_limit`
and `fintech_service` **before** `database.init_db()` reaches that file.

`core.schema_manager.ensure_schema()` only invokes Alembic when the database is *not* already at
head. So the damage lands on exactly two occasions: **a first deployment**, and **any release
that ships a new migration** — which is every schema change.

Measured with a child process booting `main.py` against an empty database, before the fix:

```
agent              True      core.security          True       fintech_service   True
database           True      core.redaction         False      gerege.worker     False
core.task_queue    True      core.account_keys      False      core.backup_automation False
core.rate_limit    True      core.ai_router         True       ai_agent_app      False
core.secret_guard  True      core.monitoring        True
core.ai_readiness  True

DISABLED: 10 of 15
an agent error logged after first boot reaches a handler: False
an AI-readiness failure reaches a handler             : False
```

Consequences on a freshly deployed instance, all silent and all with a healthy-looking process:
no AI error log, no `core.security` log (which is where webhook refusals and admin events are
recorded), no `core.secret_guard` "secrets are not production-ready" warning — the one warning
an operator most needs on a first deployment — no structured monitoring, and root dropped to
WARN so every application INFO line disappeared too. Nothing crashes; the logs simply stop.

### This also explains the Phase 49 `caplog` mystery

Phase 49 recorded that a `caplog` assertion captured **zero** records on a fresh `DB_PATH` but
passed against an already-migrated database, and reported the mechanism as *not identified*.
It is this: on a warm database `ensure_schema()` returns before invoking Alembic, so nothing is
disabled and capture works; on a cold one the migration run disables the module logger and
`caplog` sees nothing. An `assert "secret" not in caplog.text` that captures nothing is a free
pass — which is why Phase 49 moved those assertions onto stub loggers. That decision stays
correct even now; the comment in `tests/test_e49_page_secret_hygiene.py` has been updated to
name the mechanism, as has the older workaround comment in
`tests/test_e02_phase12_payment_audit_signal.py`, which had already warned that *"the same
hazard applies to production if the import order in `main.py` is ever changed"*. The import
order never changed; production was already exposed.

### The fix — two guards

```python
# migrations/env.py
if config.config_file_name is not None and not config.attributes.get("skip_logging_config"):
    fileConfig(config.config_file_name, disable_existing_loggers=False)
```

```python
# core/schema_manager._alembic_config()
cfg.attributes["skip_logging_config"] = True
```

1. **A library call must not reconfigure its caller's logging.** The application has already
   configured logging (`main.py`: `logging.basicConfig(level=INFO)`; `worker.py`: a timestamped
   format), so when `core.schema_manager` runs Alembic programmatically, `env.py` now skips
   logging configuration entirely.
2. **Even a CLI run cannot silence a live process.** `disable_existing_loggers=False` is kept
   for the human path (`alembic upgrade head` from a shell), which still configures Alembic's
   own loggers exactly as before — verified: the CLI still works (exit 0) and still emits
   Alembic's own formatter (`INFO  [alembic.runtime.migration] …`), while the application boot
   now emits the application's (`INFO:database:Schema ready: …`).

Measured after the fix, same child-process boot against an empty database:

```
DISABLED after a first-boot migration run: 0 -> []
an agent error logged after first boot reaches a handler: True
an AI-readiness failure reaches a handler             : True
root level after boot: INFO (was WARN)   root handlers: ['StreamHandler']
the application's formatter is still the one in use: True
Alembic's migration output still visible in the app log: True (14 lines)
core.secret_guard still able to speak: True
```

---

## 7. Files changed

| File | Change |
|---|---|
| `core/ai_readiness.py` | **new** — observed AI-readiness state: closed error-class enum, per-scope counters, redaction helper, `health_fields()` for unauthenticated surfaces, `snapshot()` for logs/admin, thread-safe and non-throwing (F-50-1, F-50-2) |
| `agent.py` | records the outcome of every generation call through one closure; key-fingerprint reset on rotation; drops the client when the key is removed (F-50-3); six error sites redacted; new accessors `is_gemini_configured()`, `gemini_status()`, `gemini_observation()`; `is_gemini_ready()` keeps its value and gains a docstring saying what it really means |
| `main.py` | `/api/health` publishes `agent.gemini_status()` instead of the bare flag (F-50-1) |
| `migrations/env.py` | `fileConfig(..., disable_existing_loggers=False)`, skipped for programmatic callers (F-50-4) |
| `core/schema_manager.py` | `_alembic_config()` sets `skip_logging_config` (F-50-4) |
| `tests/test_e50_ai_readiness_truth.py` | **new** — 89 tests (F-50-1, F-50-2, F-50-3) |
| `tests/test_e50_migration_logging_truth.py` | **new** — 14 tests (F-50-4), each application-boot assertion in a child process because logger state is process-global |
| `tests/test_e49_page_secret_hygiene.py` | comment only — names the mechanism behind the Phase 49 `caplog` observation |
| `tests/test_e02_phase12_payment_audit_signal.py` | comment only — records that the hazard its fixture works around is now fixed at the source |

No schema, migration-script or model change. `.env` is not tracked and was not committed.

---

## 8. Live verification after the fix

Instance restarted with the key in `.env`, disposable SQLite (`/tmp/p48a/p48a_smoke.db`),
Redis 6379, worker running separately. **18 scripted checks, 18 PASS / 0 FAIL.**

| # | Check | Result |
|---|---|---|
| 1 | `/api/health` on a fresh process | `gemini_configured=true`, `gemini_verified=null`, `gemini_attempts=0`, note says the key is NOT proven |
| 2 | `/api/chat` then `/api/health` | 200 `"model":"fallback"`; then `gemini_verified=false`, `gemini_error_class="network"`, `gemini_attempts=2` |
| 3 | `gemini_ready` compatibility | still `true` (means configured), unchanged for existing consumers |
| 4 | Secret in the unauthenticated payload | **0** occurrences of the key; **0** occurrences of `TLS`/`EOF`/`_ssl.c`; payload 543 bytes |
| 5 | Secret in either process log | **0** occurrences in the backend log and **0** in the worker log |
| 6 | Failure classified once, in the log | `WARNING:core.ai_readiness:AI generation failed (scope=default class=network): ConnectError: …` |
| 7 | Login with the `.env` password | 200 |
| 8 | ManyChat published placeholder | **403** (Phase 49's F-49-1 still holds) |
| 9 | ManyChat real page token | **200** |
| 10 | Dashboard-shaped upsert | 200, `verify_token` preserved (F-49-4 still holds) |
| 11 | Worker health | `alive`, `location=worker`, `inline_scheduler_in_api=true` (F-48A-3 still holds) |
| 12 | `leads.csv`, `gerege_crm_next.db`, `knowledge.json` | byte-identical |
| 13 | Startup logging after the fix | `INFO:agent:Gemini AI Үндсэн Client холбогдлоо`, `WARNING:core.secret_guard:secrets are not production-ready …`, `INFO:ai_agent_app:… scheduler loop started` — all visible |
| 14 | Schema | `already at head (0008→0008)` |

---

## 9. Test results — floor raised again

Authoritative run, same conditions as the Phase 49 baseline (`.env` moved aside for the whole
run, dev venv, live PostgreSQL 16 + Redis, both application processes stopped):

```
CSV_PATH=/tmp/p50_suite_leads.csv
REDIS_URL=redis://127.0.0.1:6379/0
DATABASE_URL=postgresql+psycopg2://gerege:****@127.0.0.1:5432/gerege_e05_test
python -m pytest -q -p no:cacheprovider --ignore=scratch
→ 2106 passed, 59 skipped, 1 xfailed, 372 warnings in 675.34s (0:11:15)
  window 2026-11-26T06:27:30Z → 06:39:10Z   log: /tmp/p50_full_suite2.log
```

| Metric | Phase 48A | Phase 49 | **Phase 50** | |
|---|---|---|---|---|
| passed | 1916 | 2003 | **2106** | ✅ **+103** (89 + 14, all new assertions) |
| skipped | 59 | 59 | **59** | ✅ unchanged |
| xfailed | 1 | 1 | **1** | ✅ unchanged |
| failed | 0 | 0 | **0** | ✅ |
| warnings | 372 | 372 | **372** | ✅ unchanged |

Targeted runs before the full suite: the two new modules **103 passed**; the seven
most-affected existing modules (`e36_health_monitoring`, `ai_eval_suite`,
`e36_migration_safety`, `stage_c_schema`, `e02_phase12_payment_audit_signal`,
`enterprise_phases`, `e49_page_secret_hygiene`) **121 passed, 0 failed**.

### 9.1 The first full-suite attempt produced 12 false failures — declared, diagnosed, re-run

The first attempt added `DB_PATH=/tmp/p50_suite.db` and `BACKUP_DIR=/tmp/p50_suite_backups` to
the environment, intending to keep the suite away from repository files. It finished
`12 failed, 2094 passed`. All 12 were caused by that change, not by the code:

```
E  FileNotFoundError: SQLite database not found: /tmp/p50_suite.db
   tests/test_e07_phase26_sql_injection.py           (8)
   tests/test_migration_and_restore_verification.py  (2)
   tests/test_failure_scenarios.py                   (1)
   tests/test_enterprise_phases.py                   (1)
```

With `DATABASE_URL` pointing at PostgreSQL, no SQLite file is ever created at `DB_PATH` — but
these tests call `copy_sqlite_database(database.DB_PATH, …)`, which requires `database.DB_PATH`
to be a real, existing SQLite database. Pointing it at a path that cannot exist breaks them.
The Phase 49 recipe had no `DB_PATH` override for exactly this reason; that was not recorded,
and this is the record. The re-run above uses the Phase 49 configuration verbatim.

**Recipe correction:** when the authoritative suite runs against PostgreSQL, do **not** set
`DB_PATH` to a nonexistent file. Leave it unset so `database.DB_PATH` resolves to the
repository's git-ignored `leads.db`, which those tests read as a SQLite source.

That same attempt also had `.env` restored for about a minute while the suite was still running
(the tool call was interrupted and the follow-up call restored it before I noticed). Any test
that called `load_dotenv(override=True)` in that window would have seen the live `.env`. It is
not possible to attribute individual failures to that, which is precisely why the whole run was
discarded and repeated cleanly rather than argued about. The re-run had `.env` moved aside for
its entire 675 s and never touched.

### 9.2 Side effects of the verification runs (declared)

| Path | What happened | Assessment |
|---|---|---|
| `backups/` (repo root, git-ignored) | **+23 files** this run (3455 → 3478); +31 during Phase 50's first attempt | the suite moves `.env` aside, so `BACKUP_DIR` is unset and the backup tests use the default directory. No existing file modified or deleted; not deleted afterwards — the standing rule is never to delete backups |
| `leads.db` (repo root, git-ignored) | **rewritten** (`92a383303f7b1650` → `44095d958e9e8aee`) | unavoidable in the authoritative configuration (§9.1): SQLite-path tests use it as their source database. Pre-existing suite behaviour — Phase 48A recorded the same rewrite |
| `leads.csv` (repo root, git-ignored) | **untouched** (`5e9a18e8e03e1de4`) | `CSV_PATH` redirect (F-48A-1) holding for a second consecutive run |
| `gerege_crm_next.db`, `knowledge.json` | **untouched** (`4ccd2b197c82fd8a`, `3f0c6cac3907bd29`) | real data safe |
| PostgreSQL `gerege_e05_test`, Redis 6379 | written by the suite | disposable instances |
| `/tmp/p48a/p48a_smoke.db` | 1 chat message logged, page settings re-saved | disposable live-smoke database |
| `/tmp/p50*` | probe databases, logs, cookie jars, JSON captures | disposable |

---

## 10. Restrictions compliance

| Restriction | Status |
|---|---|
| No production deployment, no staging change | ✅ none |
| No direct push to `main`, no force push, no history rewrite | ✅ §12 |
| No deleting databases, volumes or backups | ✅ nothing deleted (§9.2) |
| Never overwrite `.env` | ✅ edited in place, atomically, all 42 keys preserved; moved aside for suite runs and always restored |
| Never lower the test floor / remove or skip tests | ✅ floor raised 2003 → 2106; two existing test files touched **comment-only** |
| Never silence a security check | ✅ the opposite: §6 restores ten silenced loggers, §4 redacts six leak paths |
| No secrets in logs, commits or reports | ✅ §1 and §8: 0 occurrences of the key outside `.env`; this report never prints it |
| Disposable data only | ✅ probe pages, one probe sender, `/tmp/p50*` |

---

## 11. What the operator should do next

**1. Rotate this key.** It was pasted into a chat. Re-issue it in Google AI Studio, put the new
value in `.env`, restart both processes — and note that Phase 50 now discards the previous
verification when the key changes, so `/api/health` will honestly report `gemini_verified: null`
until the next message.

**2. Verify it where there is internet** (this sandbox cannot):

```bash
export GEMINI_API_KEY='…'
curl -s -H "x-goog-api-key: $GEMINI_API_KEY" \
  https://generativelanguage.googleapis.com/v1beta/models | head -c 300
curl -s -H "x-goog-api-key: $GEMINI_API_KEY" -H 'Content-Type: application/json' \
  -X POST "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent" \
  -d '{"contents":[{"parts":[{"text":"Сайн байна уу"}]}]}' | head -c 400
```

The header form keeps the key out of shell history and out of any URL.

**3. Read the new fields, not the old one.** `gemini_configured` says a key exists;
`gemini_verified` says whether the last real call worked; `gemini_error_class` says which kind
of problem it was — `auth` → rotate the key, `quota` → billing or backoff, `model` → check
`GEMINI_MODEL`, `network` → egress, proxy or firewall, `server` → retry later.

**4. Do not use `POST /api/update-keys` to set a key while `ALLOW_ENV_FILE_WRITE=1`.** In
non-production that endpoint rewrites `.env` down to **8 keys**, silently dropping `DB_PATH`,
`CSV_PATH`, `REDIS_URL`, `BACKUP_DIR`, `MANYCHAT_WEBHOOK_SECRET`, `STRICT_SECURITY`,
`WEBHOOK_FAIL_CLOSED` and the rest. It is `0` in this deployment, so there is no exposure today;
recorded as an observation, not fixed (§13).

---

## 12. Git record

### 12.1 Pre-push verification

| Check | Value |
|---|---|
| Branch | `arena/d78ebf88-gerege-ai-agent` (the session's pinned branch; not renamed, not switched) |
| HEAD before | `1a3bcbd` (Phase 49) |
| Remote branch tip before | `1a3bcbd` — in sync, so the push is a fast-forward |
| `origin/main` before **and** after | `aedeca46c473dad10ad250c6187aadce1f461225` — **unchanged** |
| Ancestry | remote tip is an ancestor of HEAD → fast-forward, **no** `--force` |
| Change set | 11 files, 2301 insertions, 17 deletions (1 new module, 2 new test modules, 1 new report) |
| `.env` tracked by git | **No** — `git ls-files --error-unmatch .env` fails; `.gitignore:2` |
| The Gemini key in any tracked file | **0** files (`git grep` for the literal value) |
| Live secrets in the two reports | **0** occurrences of `ADMIN_PASSWORD`, `E02_ACCOUNT_KEY_SECRET`, `META_VERIFY_TOKEN`, or the Gemini key. The key's sha256 fingerprint (`5c83e611e4ce565a…`) is quoted so a leak could be recognised without publishing the value |
| Test values used instead | obviously fake and prefixed: `e50-fake-gemini-key-4a7c9e2b`, `e50-distinctive-diagnostic-marker-7731`, `e50-a-different-fake-key-1111` |
| Open PRs at push time | **0** — nothing merged into `main` |

### 12.2 Commit and push

```
commit  fca3ddc4e8d02345443b29f3605bd129ca2da985   (arena/d78ebf88-gerege-ai-agent)
parent  1a3bcbd365e33bd4e768d3d120b11887760a2ffa   (Phase 49)
date    2026-11-26T06:43:34Z
stats   11 files, +2301 / -17
push    1a3bcbd..fca3ddc  arena/d78ebf88-gerege-ai-agent -> arena/d78ebf88-gerege-ai-agent
        (fast-forward, exit code 0)
```

Post-push verification: `git ls-remote origin arena/d78ebf88-gerege-ai-agent` → `fca3ddc…`;
local HEAD == remote tip; `origin/main` still `aedeca4…`;
`gh api …/commits/fca3ddc` confirms the SHA, the parent and the stats above. The commit diff was
grepped for the literal Gemini key: **0 occurrences**.

**Follow-up commit.** This section cannot describe its own push record, so it was completed by
one documentation-only commit *after* `fca3ddc` was pushed. That commit changes
`PHASE50_FINAL_REPORT.md` and nothing else — no code, no test, no configuration — so **the change
set under review is `fca3ddc`**, and `git diff fca3ddc..HEAD -- . ':!PHASE50_FINAL_REPORT.md'`
is empty.

### 12.3 CI

`.github/workflows/ci.yml` triggers only on `push: branches: ["main"]` and
`pull_request: branches: ["main"]`. This is a feature-branch push with no open PR, so **no CI
run is triggered** — the same situation as Phase 49 §10.3, and for the same reason. Verification
of this change set is local and complete: the full suite at **2106 passed / 59 skipped /
1 xfailed / 0 failed** (§9) plus the 18 live checks (§8), both against the code being pushed.
The workflow still contains a single `test-and-security-audit` job and no deploy/release/publish
job, so even a merge to `main` cannot start a production deployment from CI.

### 12.4 Not done, and needing authorisation

| Action | Status |
|---|---|
| Push to `main` | **NOT DONE** — not authorised |
| Pull request for this change set | **NOT OPENED** — the instruction was to do the work; opening a PR would trigger CI and is a separate decision |
| Merge into `main` | **NOT DONE** — requires fresh authorisation |
| Force push / history rewrite | **NOT DONE** |
| Production deployment / staging change | **NOT DONE** |
| Rotating the exposed Gemini key | **CANNOT BE DONE HERE** — no route to Google; the operator must do it (§11.1) |

---

## 13. Observations recorded, not fixed

* **`alembic.ini` pins `sqlalchemy.url = sqlite:///leads.db`**, and `migrations/env.py` lets that
  pin win over `DB_PATH` unless `DATABASE_URL` is set. A CLI `alembic upgrade head` run from the
  repository root therefore targets the repository's `leads.db` even when the operator set
  `DB_PATH` to a disposable file. It is a no-op when that file is already at head (which is why
  nothing was damaged here — `leads.db` kept its 02:51 mtime through a CLI probe), but it is a
  footgun. Safe recipe: `DATABASE_URL=sqlite:///path/to/disposable.db alembic upgrade head`.
  The precedence itself is deliberate and documented in `env.py`, so it was not changed.
* **`except Exception as e: logger.error("Gemini API алдаа: …")`** wraps the whole AI block, so
  a database or tool error inside it is reported as a Gemini API error. The message is now
  redacted but still mis-attributes. Left alone: re-labelling it would change operator-facing
  log text that people may grep for, and the readiness verdict is recorded against the call
  itself, so the misleading label no longer drives any signal.
* **`POST /api/update-keys` truncates `.env` to 8 keys** when `ALLOW_ENV_FILE_WRITE=1` (§11.4).
  Not reachable in this deployment and not part of the instruction; fixing it means deciding
  whether that endpoint should write `.env` at all.
* **`GEMINI_MODEL=gemini-3.5-flash-lite`** could not be validated against the provider's model
  list (no egress). If a live call returns 404, this is the value to change.
* **F-48A-6** (two `TestMetaVerifyToken` tests fail when run in isolation against a superuser
  PostgreSQL role) is unchanged: environmental, 0 failures in the authoritative run, remedy is
  `scripts/provision_roles.py --apply`. Not attempted — it would reconfigure the shared local
  cluster other suites depend on, and the privilege guard must not be weakened.
* **AI reply quality** remains NOT VERIFIED for a new reason: the credential now exists, but the
  network path does not. Everything else in Phase 48A/49's BLOCKED list is unchanged
  (Telegram, Meta, QPay, staging, production).

---

## 14. Verdicts

| Item | Verdict |
|---|---|
| Gemini key connected locally | **PASS** — in `.env` only, 600, untracked, unlogged, all 42 keys preserved |
| Key accepted by the application | **PASS** — client built, `gemini_configured=true`, old warning gone |
| Key proven valid | **NOT VERIFIED** — no route to Google from this sandbox |
| AI reply quality | **BLOCKED** (network), degrades gracefully with `"model":"fallback"` |
| F-50-1 configured ≠ verified | **FIXED** — measured live: `null` → `false`/`network`, 89 tests |
| F-50-2 unredacted AI error text | **FIXED** — 6 sites redacted; 0 key occurrences in any log |
| F-50-3 key removal left a live client | **FIXED** — client dropped, distinct log line |
| F-50-4 first boot silenced 10/15 loggers | **FIXED** — 0 disabled after the fix, both guards pinned; also explains and closes the Phase 49 `caplog` observation |
| Test floor | **PASS** — 2106 / 59 / 1 / 0 |
| Phase 49 fixes still holding | **PASS** — ManyChat 403/200, upsert preservation, truthful scheduler note |
| Telegram / Meta / QPay real traffic | **BLOCKED** — no vendor credentials |
| Windows launcher execution | **NOT VERIFIED** — no `cmd.exe` here |
| Staging readiness | **BLOCKED** — unchanged |
| Production readiness | **NOT READY** — unchanged |

**This is not a production release.** Four defects were closed in code and measured locally, but
no AI call has ever succeeded from this environment, no staging system exists here, and the
production checklist in `README.md` is still unmet. The key must be rotated before it is used
anywhere real.
