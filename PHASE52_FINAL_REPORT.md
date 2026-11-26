# Phase 52 — the deferred backlog closed: B1, B5, B6 and observations O-51-1, O-51-2, O-51-4, O-51-6

Operator instruction: *"buh ajilaa 100 ni huvi boltol ni hiigeerei"* — finish all the remaining
work. Phase 51 delivered four of the seven backlog items (B2, B3, B4, B7) and recorded six
observations; the operator had at that time deferred B1, B5 and B6. This phase does the rest.

Everything here is measured on this instance, before and after. Where a fix could not be
verified from this sandbox it is marked **NOT VERIFIED** or **BLOCKED** with the reason, rather
than reported as done.

---

## 1. Verdicts

| Item | What it was | Verdict | Before → after |
|---|---|---|---|
| **B1** | `agent_verify_secret_token_123` — a string printed in this repository — was an executable default on four independent paths, including the schema itself | **PASS** | 4 executable paths → 0; `pages.verify_token` DDL default `'agent_verify_secret_token_123'` → none; an INSERT omitting the column minted the published value → mints nothing |
| **B5** | `alembic.ini` pinned `sqlite:///leads.db`, and `env.py` let that pin win, so a shell `alembic upgrade head` migrated the checkout's own database | **PASS** | pin present, targetless run succeeded → pin removed, targetless run refuses with rc=1 and names the two variables to set |
| **B6** | `dashboard.html` filled the Meta token field from `p.page_access_token`, a key the API pops, so it rendered empty for every page including configured ones | **PASS** | field blank and silent → masked value as placeholder, plus a note stating whether a token exists and what leaving the box empty does |
| **O-51-1** | an *empty* report-recipient slot could be claimed by an unauthenticated `/start` in production | **PASS** | stranger's bare `/start` claimed the slot → refused in production, audited, environment untouched; development onboarding unchanged |
| **O-51-2** | an open circuit breaker classified as `other`, hiding the cause that opened it | **PASS** | `gemini_error_class=other` after the breaker opened → `network`, with the breaker open (`attempts=6`) |
| **O-51-4** | `record_audit_log` appeared **0** times in `executive_bot_service.py` | **PASS** | 0 call sites → 4 events (`registered`, `reaffirmed`, `transferred`, `change_refused`, `claim_refused`); 10 rows written live during verification |
| **O-51-6** | `POST /api/update-keys` answered "saved successfully" for a change no file recorded and the worker never saw | **PASS** | unconditional success message → `persisted`/`process_only`/`warning`, and the split-brain measured live: API `'888777666'` vs database row `''` |

Not attempted, because they are not agent-doable from this sandbox and were never on this list:
**O-51-3** (`TELEGRAM_WEBHOOK_SECRET` unset with `WEBHOOK_FAIL_CLOSED=0` — an operator
credential) and **O-51-5** (`POST /api/executive/settings` clears the recipient when given an
empty id — that is the documented way to unregister, and Phase 51's live checks rely on it to
restore state). Both are restated in §11.

---

## 2. B1 — the schema must not hand out a published credential

### 2.1 What was measured before

The literal appeared on **four executable paths**, only one of which any previous phase had
touched:

| Path | Line before | Effect |
|---|---|---|
| `core/models.py` | `verify_token = Column(String(255), default="agent_verify_secret_token_123")` | every `create_all`-built database |
| `database.py` `init_db()` | the first-boot INSERT for `DEFAULT_PAGE_ID` | the default page of every fresh install |
| `database.py` `save_page()` | `verify_token: str = "agent_verify_secret_token_123"` | every caller that did not name one (~12 test files, and any future caller) |
| `migrations/versions/0001_…py` | `server_default="agent_verify_secret_token_123"` | **every already-deployed database** |

The fourth is the one that cannot be fixed by editing Python. Measured on the repository's
`leads.db` and on the live application database, both at revision `0008`:

```
PRAGMA table_info(pages) -> verify_token | VARCHAR(255) | dflt_value = "'agent_verify_secret_token_123'"
```

Phase 45 (F-44-B) closed the *read* side — `meta_verify_token_is_usable()` refuses the value in
production and `GET /webhook` fails closed. Phase 49 (F-49-1/-2/-4) closed the *spread* side —
the dashboard no longer renders it, `save_page` preserves a stored token instead of
overwriting it, and a masked echo is cleared rather than stored. What remained was the *write*
side: a column default is not documentation, it is a value the schema supplies to any row that
does not name one. An INSERT that omitted the column — a support script, a data-fix run, a
future caller, `sqlite3` by hand — silently minted a page whose webhook token is public
knowledge, and reported success while doing it.

### 2.2 What changed

The three application paths now default to `""`. Empty is the only default that cannot be a
secret somebody else also has, and it fails closed in every environment:
`meta_verify_token_is_usable("")` is `False`, `usable_webhook_secret("")` is `""`.

Revision **`0009_verify_token_default`** removes the fourth. `0001` is left exactly as written —
it is applied history, and editing a released migration desynchronises every database that ran
it from every database that runs it fresh, which is a worse defect than the one being fixed.

The literal survives in the source in exactly two executable places, both of which are the rule
that *recognises* it: `core/security.py` `PUBLIC_VERIFY_TOKEN_PLACEHOLDER` and
`core/secret_guard.py` `PUBLISHED_OR_PLACEHOLDER_VALUES`. Removing a default must not remove the
predicate, or an operator who typed the value by hand — or a database created before `0009` —
would stop being refused. Every other remaining occurrence is a docstring or comment recording
what was fixed.

### 2.3 Two defects found while writing `0009`, both measured

**(a) The obvious SQLite rebuild fails, and it fails because of an unrelated security fix.**

```
CREATE TABLE pages__p52 (…); INSERT …; DROP TABLE pages; ALTER TABLE pages__p52 RENAME TO pages
-> sqlite3.OperationalError: error in trigger audit_logs_no_update: no such table: main.pages
```

`ALTER TABLE … RENAME TO` re-parses every trigger body in the schema so it can rewrite
references to the renamed table. Revision `0007`'s append-only guard `audit_logs_no_update`
carries `SELECT COUNT(*) FROM pages …` in its `WHEN` clause, and during the rename `pages` does
not exist — it was just dropped and the replacement still has its temporary name. **The
audit-integrity guard from Phase 13 broke a migration written in Phase 52.** The guard is right
and stays; the rename runs under `PRAGMA legacy_alter_table=ON`, which skips that fix-up pass.
Nothing needed rewriting: the triggers reference `pages` by name and the rebuilt table keeps
that name.

The first diagnosis was wrong and is recorded because it was plausible: `PRAGMA
foreign_keys=OFF` is a no-op inside a transaction, so the assumption was that `DROP TABLE pages`
cascaded into `audit_logs` (`ON DELETE SET NULL`) and tripped the guard. Measured: Python's
`sqlite3` leaves enforcement off by default here (`PRAGMA foreign_keys` → `0` before any
`BEGIN`), so no cascade occurred and the step-by-step run put the failure on the `RENAME`, not
the `DROP`.

**(b) Rebuilding from `PRAGMA table_info` silently loses a constraint.**

`0008` reconstructs a table from `PRAGMA table_info`, and its own comment records that a first
version lost NOT NULL flags and a server default. For `pages` the same approach loses something
`table_info` cannot report at all: an inline `UNIQUE`, whose `sqlite_autoindex_pages_1` is
invisible to it. So `0009` does not reconstruct the schema — it takes the table's own DDL text
from `sqlite_master` and removes exactly one clause from it, parsing the body on top-level
commas (paren- and quote-aware, because `DECIMAL(10,2)` and quoted strings both contain commas).
Type, nullability, every inline `UNIQUE`/`CHECK`, column order and the primary key survive
because they are never rewritten.

### 2.4 Verification

Round trip on a **copy of the repository's real 28-page database**, `.env` moved aside so the
shell environment decides the target:

| | before `0009` | after | after downgrade | after re-upgrade |
|---|---|---|---|---|
| `alembic_version` | `0008_tenant_not_null` | `0009_verify_token_default` | `0008_tenant_not_null` | `0009_verify_token_default` |
| `verify_token` default | `'agent_verify_secret_token_123'` | none | the literal again | none |
| `pages` rows | 28 | 28 | 28 | 28 |
| `messages` / `audit_logs` rows | 211 / 1445 | 211 / 1445 | — | 211 / 1445 |
| tables referencing `pages` | 14 | 14 | — | 14 |
| indexes + triggers on `pages` | 5 | 5 | — | 5 |
| `foreign_key_check` / `integrity_check` | — | empty / `ok` | — | empty / `ok` |

The migration asserts all of that itself and raises rather than report success — row count,
child-reference count, `foreign_key_check`, `integrity_check`, every captured index and trigger
present again, and a per-column shape comparison that must show `verify_token`'s default as the
*only* difference.

Behavioural proof, which is the only measurement that matters:

```
INSERT INTO pages (page_id, name) VALUES (…)   -> before: 'agent_verify_secret_token_123'
                                                  after:  NULL
```

The live application database was migrated by this work and re-verified: 5 pages, 15 child
references, all indexes and triggers, `integrity_check ok`, backend answering `200` afterwards
and logging `Schema ready: already at head (0009_verify_token_default -> 0009_verify_token_default)`.

### 2.5 What `0009` deliberately does not do

It does **not** blank rows that already hold the published literal. Measured after the
migration, the live default page still holds it. That is intentional: clearing a credential in
use breaks a working ManyChat/Meta integration silently, from a change whose stated purpose was
to stop *new* rows inheriting the value. It is `0008`'s reasoning in the opposite direction —
there, refusing to backfill was right because assigning a NULL tenant would move data between
tenants; here, refusing to rewrite is right because an operator's decision is required. The
codebase already surfaces the decision: `_sanitize_page_secrets()` ships
`verify_token_is_placeholder`, the dashboard warns on it, `meta_verify_token_is_usable()`
refuses it in production, and F-49-1's `usable_webhook_secret()` means it cannot authenticate a
webhook there either.

---

## 3. B5 — a targetless migration run must refuse, not guess

### 3.1 Before

`alembic.ini:5` read `sqlalchemy.url = sqlite:///leads.db`, and `migrations/env.py` preferred
that pin over `DB_PATH` unless `DATABASE_URL` was set. `.env` is git-ignored, so **every fresh
clone** is the case where nothing else names a target. Measured in a sandbox copy with the pin
restored: `returncode 0`, `leads.db` created — a shell `alembic upgrade head` migrated the
repository's own database and reported success. This is not theoretical: the repository's
`leads.db` is a real file with a real schema, and Phase 51's own notes track its sha
(`c7c5359ae6d1f22b`) precisely because test runs are expected to change it.

### 3.2 After

`alembic.ini` keeps the key, empty, with a comment explaining why it must stay empty — so the
next reader does not helpfully fill it in. `env.py` resolves the target from three places and
refuses when none named one:

1. `DATABASE_URL` in the environment,
2. `DB_PATH` in the environment (via `get_database_url()`'s SQLite fallback),
3. a URL pinned by the caller — `core/schema_manager._alembic_config()`, which is how the
   application's own first-boot migration runs.

```
RuntimeError: Alembic was invoked without a target database. Set DATABASE_URL (or DB_PATH for a
SQLite file) and re-run; refusing to fall back to the repository's own leads.db. Programmatic
runs through core.schema_manager pin the URL and never reach this.
```

Measured: fresh-clone shape (no `.env`, no variables) → `rc=1` with that message, `leads.db`
sha unchanged at `c7c5359ae6d1f22b`; with `DB_PATH` named → `rc=0`, a 266 KB database created
and migrated to head. The three existing tests that invoke the Alembic CLI stayed green
(`test_e02_phase13_audit_append_only.py:567`, `test_e07_phase22_recovery_safety.py:162`,
`test_e50_migration_logging_truth.py:276`) — all three name a target, which is the point.

### 3.3 Two environment traps this exposed, both worth recording

**`core/db_engine.py:9` calls `load_dotenv(override=True)` at import.** A shell `alembic` run
inside the repository therefore reads `.env` and *overrides* variables exported on the command
line. Measured: three `alembic` invocations that exported `DB_PATH=/tmp/p52_rt/rt.db` migrated
`/tmp/p48a/p48a_smoke.db` — the live application database — because `.env` names it. The copy
was never touched (its version stayed `0008`), which is how the mistake was caught. Every
migration measurement in this phase was re-run with `.env` moved aside.

**`python -m alembic` puts the current directory on `sys.path[0]`.** The first live B5 check ran
from the repository root against a sandbox `alembic.ini`, so it imported the *repository's*
`core/`, read the real `.env`, found `DB_PATH`, and the guard correctly did not fire — the check
passed vacuously. It now runs from inside the sandbox, as the unit test does. The guard's real
reach is therefore precise and worth stating: **it fires only when nothing names a target.** A
deployment whose `.env` sets `DB_PATH` has named one, and is unaffected.

---

## 4. B6 — the dashboard must not read a field the API removes

`updatePageUI()` did:

```js
document.getElementById('settings-meta-token').value = p.page_access_token || '';
```

`p.page_access_token` does not exist. `database._sanitize_page_secrets()` pops the real value
out of every page dict before it leaves the API (Phase 49, F-49-2) and ships
`page_access_token_masked` plus `has_page_token` instead. So the field was blank for **every**
page, including the ones with a token stored — and an empty password box reads as "no token
configured", a statement about the system the client was not in a position to make and got
wrong for every configured tenant.

The masked value now goes to `placeholder`, never to `value`, and a note states the truth in
both directions. A placeholder is not submitted, so `saveCurrentPageSettings()` still posts an
empty string and `save_page`'s `COALESCE(NULLIF(excluded.page_access_token,''), pages.page_access_token)`
preserves the stored token. Putting the masked text in `value` would post it back; `save_page`
clears a `•`/`****` echo to `""` rather than storing it, but relying on that guard to undo a
mistake the UI should never make is not a design.

Live, against the running instance: `GET /api/pages` returned 6 rows, **0** carrying
`page_access_token`, **6** carrying the mask and the flag; the served dashboard contains the note
element and **0** reads of the popped field.

The test that would have caught this originally is now in the suite, generalised: every
`p.<field>` referenced by `updatePageUI()` and `saveCurrentPageSettings()` must be a key the API
actually ships. Comparing the two sets keeps them from drifting apart again in silence, which is
how this one hid — nothing errored, the field was simply always empty.

---

## 5. O-51-1 — an empty slot is not free for the taking in production

F-51-5 removed the published owner secret. What it left, and documented as an observation, is
that a **first** `/start` still claims an *empty* slot. In development that is the onboarding
flow and it is unchanged. In production it is a hole with the same shape as the finding that
preceded it: a Telegram bot is public by username, so whoever messages it first becomes the
recipient of the daily executive report (revenue, invoices, cargo, customers) and can pull
`/today`, `/report`, `/qpay` and `/cargo` — and the P0-7 guard then locks the real owner out of
the slot the stranger took. With no usable `VERIFY_TOKEN` there is nothing distinguishing the
operator from anybody else, so production now requires one.

Two registration paths remain open to an operator there, and the refusal names both:
`/start <secret>` with a generated `VERIFY_TOKEN`, and `POST /api/executive/settings`, which is
authenticated and audited. `STRICT_SECURITY=1` is treated as production, matching
`is_production_mode()` everywhere else.

Live, against the real module and the real database: a stranger's bare `/start` on an empty slot
was refused, the slot stayed empty, `os.environ` was not mutated, and the refusal was audited.
Development onboarding still works, and so does production onboarding *with* a generated secret —
the fix must not lock the operator out of their own bot, and that is tested in both directions.

---

## 6. O-51-2 — an open breaker now says why it opened

The error was:

```
RuntimeError: CircuitBreaker 'gemini' is currently OPEN; skipping call
```

`ai_readiness._CLASSIFIERS` has no needle for it, so it classified `other`. Measured on this
instance, where egress to Google is closed: the first five failures classified `network`, the
breaker opened, and every call after that reported `other` — so `/api/health` said
"unclassified" for exactly the condition that had a known, operator-actionable cause. An
operator reading `other` has nothing to act on; the same operator reading `network` checks
egress.

The cause is now carried two ways:

* **in the text** — `CircuitBreaker 'gemini' is currently OPEN after 6 consecutive network failure(s); skipping call` — because a human reads the log line and the excerpt `snapshot()` keeps;
* **as an attribute** — `gerege_error_class`, which `classify_error()` honours *after validating it against `ERROR_CLASSES`*.

The attribute matters because text is a poor channel for a fact the raiser already knows, and
the proof is that `auth` appears in no needle of the `auth` class: a breaker opened by 401s
classifies as `auth` only through the attribute. Failures are classified when they happen, while
the exception still carries its type, status attribute and text; the failure that opened the
breaker is not necessarily the last one before a later call is refused, and the refused call has
no cause of its own.

`ERROR_CLASSES` is **unchanged**, byte for byte. Extending the vocabulary would have meant
editing the exact-tuple assertion at `test_e50_ai_readiness_truth.py:833` — a security test, and
not something a classification fix should need to touch. The new module pins the tuple a second
time so the choice is recorded in both places, and pins that a bogus `gerege_error_class` cannot
add to the vocabulary.

Two related gaps closed on the way: the fallback paths called `record_failure()` with no argument
after a non-2xx answer, throwing the reason away at the moment it was known — `_ProviderStatus`
now carries the status code, which `classify_error` reads before any text (429 → `quota`,
401 → `auth`, 503 → `server`); and an open `openai`/`anthropic` breaker returned `None`
silently, indistinguishable from a fallback that was never configured, so it now logs why.

Live: `attempts=6` (past the threshold of 5, so the breaker is open) with
`gemini_error_class=network`. Before this phase the same state reported `other`, and Phase 51's
live-check script had to accept *both* values with a comment explaining the breaker; that branch
is now unreachable and says so.

---

## 7. O-51-4 — ownership of the executive reports is now auditable

`grep -c record_audit_log executive_bot_service.py` returned **0**, in the module that decides
who receives the business's daily report. Every other path that changes an
authorisation-relevant fact in this codebase writes a row: `auth.login.success`/`.failed`,
`system.keys.updated`, `ai.prompt_injection.blocked`, `user.data.deleted`. An ownership change
reachable from a **public Telegram webhook** was the one that left no trace, so even after
F-51-5 there was no way to answer "who took ownership, when, and was a secret presented?" from
the record.

Five events are now written, following the existing dotted-lowercase convention:
`executive.recipient.registered`, `.reaffirmed`, `.transferred`, `.change_refused`,
`.claim_refused`. Distinguishing the three successful cases is the point: a first registration,
the owner re-announcing themselves, and a transfer authorised by the secret have very different
meanings and previously looked identical — all three were one `if` with three `or` branches.

Two properties are deliberate. The helper **never raises**: `record_audit_log` raises
`AuditLogWriteError` by contract so a caller can tell an audit failure from any other, and this
caller's job is to answer a Telegram message, so an unwritable audit table must not turn a
working `/start` into silence — the gap is logged as an error naming the action instead. And it
records **identifiers and reasons, never the secret**: the `/start <secret>` value does not reach
the function at all, `via_secret` is a boolean, which is what an auditor needs and the only form
that cannot leak a credential into the audit table.

`page_id` is passed only when the page row actually exists (the caller has already fetched it, so
this costs no query): `audit_logs.page_id` is a foreign key to `pages`, so naming a page that
does not exist would lose the row on PostgreSQL, where enforcement is on.

Live: 10 recipient rows in the application database, including `change_refused` rows written
during the Phase 51 check run — a refused takeover attempt now leaves a trace, which is exactly
what an audit trail is for and which the guard never did before. The `/start` secret appears in
none of them.

---

## 8. O-51-6 — "saved successfully" for a change nothing recorded

`POST /api/update-keys` mutated `os.environ` unconditionally, then wrote `.env` **only** with the
gate open (`not production and ALLOW_ENV_FILE_WRITE=1`), and answered
`{"status": "success", "message": "Тохиргоо амжилттай хадгалагдлаа!"}` either way.

The consequence was not cosmetic. `TELEGRAM_MANAGER_CHAT_ID` in `os.environ` is one of the two
sources `handle_owner_command` reads to decide who owns the executive reports, so an admin call
with the gate closed produced a process that believed a different owner was registered from the
one in the database — and from the one the **worker** believed, the worker being a separate
process that never sees the assignment and is what actually sends the 08:30 report. Nothing
reconciled the two except a restart, and nothing told the operator a restart was needed.

**Measured live, on the running instance, during this phase's verification:**

```
GET /api/executive/settings -> telegram_manager_chat_id = '888777666'
database row                -> telegram_manager_chat_id = ''
```

The response now carries `persisted`, `process_only` (environment variable *names*, never
values) and `warning`, and the message says which of the two happened. For the recipient
specifically the warning names the split and the durable path:

> Applied to this process only, not written to .env (ALLOW_ENV_FILE_WRITE is not 1); a restart
> reverts it and no other process ever saw it: TELEGRAM_MANAGER_CHAT_ID. This one is worse than
> the others: the executive-report recipient is per page in the database, and the worker — a
> separate process, and the one that actually sends the 08:30 report — reads that row. This
> process and the worker now disagree about who owns the reports. Register it with POST
> /api/executive/settings, or persist .env and restart, to make it durable.

The in-process update itself is **kept**. `tests/test_e51_env_write_merge.py` documents it as
intended behaviour ("the in-process update still succeeds"), an admin rotating a key mid-run
should not have to restart to use it, and a test in the new module pins that it still happens.
What changed is that the state of the system can now be read instead of inferred.

Verification ran that probe against the live backend and then restarted it, because leaving a
process-only value behind in the running instance is precisely the defect being reported.

---

## 9. Tests

**New module: `tests/test_e52_backlog_closure.py` — 67 tests**, covering all seven items:
source contracts (so a revert is caught even where behaviour is hard to reach), behavioural
tests against real databases and the real modules, and the migration round trip in a sandbox
copy of the migration tree.

The sandbox exists because of §3.3's first trap: `core/db_engine.py` calls
`load_dotenv(override=True)` at import, and `find_dotenv()` walks up from that file, so a
subprocess run against the repository reads the developer's real `.env` and overrides every
variable the test set. A copy with an **empty** `.env` at its root stops the walk there, so the
subprocess environment decides the target in every environment — including one with a real
`.env` holding a live credential.

**Revert proofs: 10 of 10 CAUGHT.** Each fix was reverted in place, the relevant tests run, and
the file restored byte-identically (sha compared before and after):

| Reverted | Result |
|---|---|
| `core/models.py` column default → the literal | 2 failed, 7 passed |
| `database.save_page` default → the literal | 2 failed |
| `init_db()` first-boot INSERT → the literal | 2 failed |
| `alembic.ini` pin restored | 5 failed, 2 passed |
| `env.py` refusal removed | 2 failed |
| dashboard reads `p.page_access_token` again | 3 failed, 2 passed |
| O-51-1 production refusal removed | 5 failed, 3 passed |
| O-51-2 declared-class hook removed | 1 failed, 9 passed |
| O-51-4 audit writes removed | 9 failed, 2 passed |
| O-51-6 truthful response removed | 7 failed, 2 passed |

**One existing assertion changed shape, and was strengthened.**
`test_e51_env_write_merge.py::test_the_gate_is_unchanged` pinned the write gate as a literal
`if not core_security.is_production_mode() and os.getenv("ALLOW_ENV_FILE_WRITE", "0") == "1":`
line. O-51-6 lifted the same two conditions into a named `write_gate_open` so the response can
report which side of it a request landed on. The test now pins the *conditions* (normalised, so
reformatting cannot hide a change) and additionally requires the single `merge_env_file(updates)`
call to sit **inside** the gate's block — a stronger property than the punctuation it replaced.
No test was removed, skipped, weakened or converted anywhere in this phase.

**Blast radius:** the 16 modules that touch anything changed here — e45, e49 ×2, e50 ×2, e51 ×4,
e52, stage_c_schema, e02, e34, ai_eval_suite, enterprise_phases, failure_scenarios — run
**595 passed, 0 failed**.

---

## 10. Live verification

Two scripts, both against the running instance (backend + worker on revision `0009`):

* `/tmp/p52_live_checks.sh` — Phase 51's 37 checks, repointed at this phase's logs, re-run
  against the Phase 52 build: **37 PASS / 0 FAIL**. Its O-51-2 branch that accepted `other` as
  truthful is now unreachable and annotated as such.
* `/tmp/p52_new_checks.sh` — 34 new checks for this phase: **34 PASS / 0 FAIL**.

**71 PASS / 0 FAIL** in total. Three harness defects were found and fixed before that result was
accepted, and are recorded because two of them produced a green-looking wrong answer:

1. A check expected `NULL` where the API stores `""` — the fix was correct, the expectation was not.
2. The B5 check ran from the repository root, so `python -m alembic` put the repository on
   `sys.path[0]`, imported the repo's `core/`, read the real `.env`, and the guard correctly did
   not fire: **a vacuous pass**.
3. The O-51-1 check set `ENV=production` *before* importing `executive_bot_service`, whose
   module-level `load_dotenv(override=True)` reset it from `.env`. The stranger claimed the slot,
   which is correct development behaviour and looked like a failed fix.

The first run of the new script reported 21 PASS / 13 FAIL. Every one of the 13 was a harness
defect, not a code defect — but that is only knowable because each was diagnosed rather than
adjusted until green.

State after verification: the probe page `p52_live` was created and deleted through the API (row
count 0), the repository's `leads.db` is unchanged at `c7c5359ae6d1f22b`, `.env` is unchanged at
sha `2c90cc39177b2402` / 170 lines / mode 600, and the backend was restarted to clear the
process-only value the O-51-6 probe set. Disposable artefacts left behind and declared: 10
`executive.recipient.*` rows in the application database's `audit_logs`.

---

## 11. Full suite

Run on the delivered tree: `.env` moved aside, **no `DB_PATH` exported** (pointing it at a
nonexistent file makes four modules' `copy_sqlite_database(database.DB_PATH, …)` fail with
`FileNotFoundError`), `DATABASE_URL` aimed at the local PostgreSQL test database, pgserver's
binaries on `PATH`, `--ignore=scratch`, backend and worker stopped first, and launched with
`start_process` because the run outlasts a shell timeout.

```
2334 passed, 59 skipped, 1 xfailed, 390 warnings in 701.71s (0:11:41)
```

**0 FAILED, 0 ERROR.** Log: `/tmp/p52_full_suite.log`, mode 600.

Reconciliation against the Phase 51 floor of 2266 — **+68, every one accounted for**:

| | tests |
|---|---|
| Phase 51 floor (authoritative run 3) | 2266 |
| `tests/test_e52_backlog_closure.py` (new) | +67 |
| one schema-manager pin split into a SQLite case and a PostgreSQL case (§3.3's first trap made the single version assert something false under PostgreSQL) | +1 |
| **Phase 52** | **2334** |

Skips 59 and the single xfail are unchanged across every run since Phase 48A. Nothing was
removed, skipped, deselected or converted to reach this number, and no `skipif` was added
anywhere in this phase.

Side effects, measured before and after, declared and not reverted:

| | before | after |
|---|---|---|
| `leads.db` (git-ignored, `.gitignore:19`) | `c7c5359ae6d1f22b`, at `0008` | `330d1f4834af4ed6`, at **`0009`** |
| `backups/` (git-ignored, `.gitignore:25`) | 3574 files | 3597 files |
| `leads.csv` | `5e9a18e8e03e1de4` | unchanged |
| `knowledge.json` | `3f0c6cac3907bd29` | unchanged |
| `gerege_crm_next.db` | `4ccd2b197c82fd8a` | unchanged |
| `.env` | `2c90cc39177b2402`, 170 lines, mode 600 | unchanged |

`leads.db` moved because the suite ran the new revision against it: a real 28-page database,
migrated from `0008` to `0009` unattended, still holding all 28 pages with the published default
gone. That is `0009`'s fourth successful run against a real database (the repository's, the live
application's, and two sandbox copies first). `backups/` grows because the backup tests write
real files into the configured directory; it is git-ignored and is never deleted.

---

## 12. What this phase does not change

* **Production readiness: 0 of 4 items verifiable from here.** No Google egress
  (`generativelanguage.googleapis.com` → HTTP 000, curl exit 35, DNS IPv6-only), no Windows, no
  Docker, no live Telegram/Meta/QPay credentials. The Gemini key remains **connected** and
  **accepted by the app**, **NOT VERIFIED** as valid, and AI reply quality remains **BLOCKED**.
* **`O-51-3`** — `TELEGRAM_WEBHOOK_SECRET` unset with `WEBHOOK_FAIL_CLOSED=0` lets a forged
  webhook consume AI quota. Operator credential; unchanged.
* **`O-51-5`** — `POST /api/executive/settings` clears the recipient when given an empty id. That
  is the documented way to unregister, and Phase 51's live checks depend on it to restore state;
  changing it would remove a capability rather than fix a defect. Unchanged, still recorded.
* **The exposed `GEMINI_API_KEY` on public `main` is still 0% resolved.** `origin/main:.env.example`
  line 9 carries a value byte-identical to the live key in this deployment's `.env`, in a public
  repository, in history since `c809654`. CI run `45773782793` passed it. The operator chose
  `rotate_only`: **only rotation closes it**, deleting the line leaves it readable in history,
  and no repository change was authorised for the exposure. Nothing in this phase touches it, and
  it cannot be tested or revoked from here because Google is unreachable.
* Operator-only list still at **1 of 6** (PR #3 merged; pending: rotate the key, validate the key,
  real Telegram/Meta/QPay credentials, staging + production deployment, Windows launchers).

---

## 13. Files changed

| File | Change |
|---|---|
| `core/models.py` | B1: column default `""`, with the reason recorded at the column |
| `database.py` | B1: first-boot INSERT and `save_page`'s parameter default |
| `migrations/versions/0009_verify_token_default_cleared.py` | **new** — B1: drops the default on both dialects, verifies the rebuild, reversible |
| `alembic.ini` | B5: `sqlalchemy.url` emptied, with the reason in place |
| `migrations/env.py` | B5: refuses when no target is named |
| `dashboard.html` | B6: masked value as placeholder, note element, no read of a popped field |
| `executive_bot_service.py` | O-51-1 production refusal; O-51-4 five audited events and the helper |
| `core/ai_router.py` | O-51-2: `last_failure_class`, `_ProviderStatus`, `_circuit_open_error`, five call sites |
| `core/ai_readiness.py` | O-51-2: honours a validated `gerege_error_class` |
| `main.py` | O-51-6: named gate, `persisted`/`process_only`/`warning`, truthful message |
| `tests/test_e52_backlog_closure.py` | **new** — 67 tests |
| `tests/test_e51_env_write_merge.py` | the gate assertion reshaped to the new form and strengthened |

No migration other than `0009` was added or edited. `0001` is untouched. No secret value appears
in any file changed here, in any log quoted, or in this report.

---

## 14. Git record

### 14.1 State before this phase

Branch `arena/d78ebf88-gerege-ai-agent`, HEAD `e89c230` == `origin/arena/d78ebf88-gerege-ai-agent`,
working tree clean, 4 commits ahead of `origin/main` (`c809654`), 0 open pull requests. The Arena
context line reporting `pr_open` against base `48e9c6f7` is stale: PRs #1, #2 and #3 are all
merged and Phase 51 opened none, by the operator's `no_pr` decision.

### 14.2 What is committed

13 files — 3 new (`PHASE52_FINAL_REPORT.md`,
`migrations/versions/0009_verify_token_default_cleared.py`,
`tests/test_e52_backlog_closure.py`) and 10 modified. Staged diff: **2740 lines**.

Credential scan of the staged diff before committing, computed rather than eyeballed:

| Scanned for | Occurrences |
|---|---|
| the live `GEMINI_API_KEY` value from `.env` | **0** |
| the first 12 characters of that key | **0** |
| the live `ADMIN_PASSWORD` value | **0** |
| any `AIza[0-9A-Za-z_-]{20,}`-shaped token | **0** |

`.env` is git-ignored and was never staged; it is unchanged at sha `2c90cc39177b2402`, 170 lines,
mode 600. The only credential-shaped literal this phase *added* to the repository is
`agent_verify_secret_token_123` inside `0009` — the published value it removes as a default and
has to be able to restore on a downgrade. It was already in the repository in four places, is
already refused by two predicates, and is not a secret.

### 14.3 Commits

<<COMMITS>>

### 14.4 Authorisation

Push authorisation covers `arena/d78ebf88-gerege-ai-agent` only. No push to `main`, no force
push, no history rewrite, no rebase. Fresh separate authorisation is still required for: opening
or merging a pull request, pushing to `main`, deploying, and rotating any credential.

Note for whoever merges this: `git merge-tree --write-tree origin/main HEAD` reported
`CONFLICT (content): .env.example` at the end of Phase 51, because `main` carries the exposed key
on line 9 of that file while B3 restructured the same block. This phase changes no template, so
the conflict is unchanged and still has to be resolved by hand — by keeping B3's structure and
**not** keeping the key. `check-runs` on feature-branch commits returns 0 because
`.github/workflows/ci.yml` triggers only on `push: branches: ["main"]` and on `pull_request`;
opening a PR would run CI.
