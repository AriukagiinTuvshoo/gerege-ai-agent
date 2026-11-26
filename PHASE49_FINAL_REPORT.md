# PHASE 49 — CLOSED OUT THE OPEN FINDINGS

**Repository:** `AriukagiinTuvshoo/gerege-ai-agent`
**Branch:** `arena/d78ebf88-gerege-ai-agent` (branched from `main` @ `48e9c6f`)
**Started from:** `main` @ `aedeca46c473dad10ad250c6187aadce1f461225` (Phase 48A merged), branch @ `b84969a`
**Instruction:** *"odoo dutuu bgaa heseguudee duusgaad push hiigeerei"* — finish the parts that were still
incomplete, then push.
**Window:** 2026-11-26T02:0x → 02:5x UTC (sandbox clock)

**Outcome:** the open items that could be closed **without vendor credentials, a staging
environment or a Windows machine** are closed and measured; four previously unreported
defects were found while closing them, one of them a **production authentication bypass**.
Full suite **2003 passed / 59 skipped / 1 xfailed / 0 failed** (floor *raised* by 87 tests,
nothing removed, skipped or weakened). Change set committed and pushed to the feature
branch. No production deployment, no staging change, no `main` push, no force push, no
history rewrite, no deleted data.

---

## 1. What "incomplete" meant, and what was addressable

Phase 48A left these items open. Each is classified by whether it could be finished here:

| Open item from Phase 48A | Addressable in this sandbox? | Result |
|---|---|---|
| **F-48A-3** worker-health `scheduler.note` stated the opposite of the real configuration | **YES** — code + tests | **FIXED** (§3.1) |
| **F-48A-5** `core/worker_heartbeat.py` config decided by import order | **YES** — code + tests | **FIXED** (§3.2) |
| **F-48A-1** `CSV_PATH` fix had **zero** test coverage when it merged | **YES** — tests | **GUARDED** (§3.3) |
| **O2** the published `verify_token` default is still consumed somewhere | **PARTLY** — followed it to the consumers | **2 real defects found and fixed** (§3.4, §3.5); the schema default itself is deliberately unchanged (§6) |
| Windows launchers **NOT VERIFIED** | **PARTLY** — cannot run `.bat` on Linux | **Statically verified** for everything checkable (§3.6); execution still NOT VERIFIED |
| **F-48A-2** `.env` overrides exported variables | inherent to the design | documented, unchanged (§6) |
| **F-48A-4** connection-level `.env` changes need a restart | inherent | documented; one false signal removed by §3.1 (§6) |
| **F-48A-6** 2 tests fail in isolation on a superuser PostgreSQL role | environment, not code | **still open**, remedy documented (§6) |
| AI integration **BLOCKED** (no `GEMINI_API_KEY`) | no | **BLOCKED**, honest degradation re-verified (§5.9) |
| Telegram / Meta / QPay **BLOCKED** (no vendor credentials) | no | **BLOCKED** |
| Staging readiness **BLOCKED**, production **NOT READY** | no | unchanged (§8) |

---

## 2. New defects found while closing the old ones

Following Phase 48A's observation O2 ("`pages.verify_token` still defaults to the published
placeholder") to its **consumers** rather than to its schema turned up four defects that no
previous phase had reported. All four were measured on a running instance before being
fixed, and re-measured after.

| ID | Severity | Defect |
|---|---|---|
| **F-49-1** | **HIGH** (production auth bypass) | `/api/manychat` accepted the *published* `pages.verify_token` default as a valid webhook secret, in every environment including production |
| **F-49-4** | **HIGH** (data + security) | `POST /api/pages` reset every column the payload omitted — one dashboard click replaced a page's webhook secret with the published string and set its token quota to 100000 |
| **F-49-2** | MEDIUM (misinformation + secret hygiene) | `dashboard.html` rendered the published string in a copy-to-clipboard "Verify Token" field next to the Meta callback URL, under a permanently green "Бэлэн" (Ready) badge |
| **F-49-5** | LOW (test isolation) | `tests/test_e37_phase37_readiness.py` could not set up "no heartbeat" on a shared Redis, so it reported a failure unrelated to the code under test whenever a local worker was running |

---

## 3. Fixes, with the measurements that justify them

### 3.1 F-48A-3 — the worker-health note now reports the topology instead of asserting one

`routers/system_router.py` returned a **constant**:

```python
"note": ("the API runs with DISABLE_INLINE_SCHEDULER=1, so a stopped worker "
         "also stops scheduled reports and retention"),
```

Phase 48A measured the API running with `DISABLE_INLINE_SCHEDULER=0` and its own loop
started (`Executive Daily Briefing & Retention scheduler loop started`), so the endpoint an
operator consults during an outage asserted the opposite of reality — and hid a genuine
problem: with the inline loop on, the API **and** the worker each run a scheduler, so
scheduled reports can fire twice.

**Fix.** `main.py`'s lifespan records what it actually did:

```python
INLINE_SCHEDULER_STARTED: Optional[bool] = None          # module level
...
INLINE_SCHEDULER_STARTED = os.getenv("DISABLE_INLINE_SCHEDULER", "0") != "1"
if INLINE_SCHEDULER_STARTED:
    scheduler_task = asyncio.create_task(executive_scheduler_loop())
```

`routers/system_router._inline_scheduler_running_in_api()` reads that record, falling back
to the variable only when the lifespan never ran (a router mounted in a test app). It reads
the *record* rather than the variable on purpose: `main.py` re-runs `load_dotenv(override=True)`
inside `/api/health`, so the environment of a long-running process can change after startup
while the scheduler task does not (F-48A-4). The response also gained
`scheduler.inline_scheduler_in_api`, and both note variants name
`DISABLE_INLINE_SCHEDULER`, so the Phase 36 contract asserted by
`tests/test_e36_worker_health.py:220` is unchanged.

**Measured after the fix, live:**

```
scheduler.location          : worker
scheduler.inline_scheduler_in_api : True
scheduler.note              : the API runs with DISABLE_INLINE_SCHEDULER=0, so it ALSO runs
                              its own inline scheduler while the worker runs one too:
                              scheduled reports and retention can fire twice. ...
```

### 3.2 F-48A-5 — heartbeat configuration is read when it is used, not when the module is imported

`core/worker_heartbeat.py` read its three tuning variables at import time, and the module
does not load `.env` itself (`core/db_engine.py` does, on behalf of `database.py`). Import
order therefore decided whether an operator's configuration existed yet. Phase 48A measured
it with `.env` setting `WORKER_HEARTBEAT_BEAT_SECONDS=7.5`: a process importing this module
directly saw **10.0**, a process importing `database` first saw **7.5**. A non-numeric value
was worse — `int()` raised during import and surfaced as an ImportError from an unrelated
module.

**Fix.** `fresh_window_seconds()`, `beat_interval_seconds()` and `key_ttl_seconds()` read the
environment on each call; the historical module attributes still resolve through PEP 562
`__getattr__`, so `worker_heartbeat.DEFAULT_TTL_SECONDS`, `worker.py` and every existing
suite keep working — they now get the *current* value instead of an import-time snapshot.
Garbage falls back to the documented default with one warning per problem (never repeating
the value); a typo'd attribute still raises `AttributeError`; `monkeypatch.setattr` still
wins, so test isolation is unaffected.

One invariant that nothing enforced is now enforced: the key TTL must exceed the fresh
window, or the key expires before it can ever be judged `stale` and the two states this
module exists to distinguish ("wedged" vs "gone") collapse into one.
`WORKER_HEARTBEAT_FRESH_SECONDS=120` with the default 90 s TTL used to do exactly that
silently; the TTL is now widened (to 3× the window) and the reason is logged. Liveness
reporting is a diagnostic, so it widens and warns rather than refusing to start.

**Measured:**

```
defaults                    : 30 / 90 / 10.0
env set to 120 / (default)  : fresh=120 ttl=360 (widened, warned once) beat=7.5
env garbage for the TTL     : falls back, warns once, no exception
child process importing ONLY this module with FRESH=17 BEAT=2.5 TTL=400 -> "17 2.5 400"
```

The last line is the original fragility as a regression test
(`test_a_standalone_import_sees_the_configuration`).

### 3.3 F-48A-1 — the merged `CSV_PATH` fix now has a regression guard

Phase 48A shipped `CSV_PATH` with **zero** tests referencing it. Added:

* the environment decides where the mirror is written (functional, in a child process whose
  `dotenv` is stubbed out so `.env` cannot override the probe — F-48A-2);
* the **default is unchanged**: it still resolves to `<repo>/leads.csv`, which
  `docker-compose.yml` bind-mounts, so every existing install behaves identically;
* the source still reads the variable (guards against a future "simplification" back to a
  constant);
* `.env.example` still documents it between `DB_PATH` and `REDIS_URL`.

**Measured live after the restart** (`CSV_PATH=/tmp/p48a/leads.csv` in `.env`):

```
POST /api/leads/1/status -> 200 {"status":"updated","lead_id":1}
repository leads.csv : 5e9a18e8e03e1de4 -> 5e9a18e8e03e1de4   (byte-identical)
/tmp/p48a/leads.csv  : ec29f43f5f698175 -> 754ef37ec975e710   (took the write)
```

The authoritative suite run also used `CSV_PATH=/tmp/p49_suite_leads.csv`, so this run did
**not** rewrite the repository's `leads.csv` at all — the first suite run in this project
that left it untouched, which is the fix doing its job.

### 3.4 F-49-1 — the published placeholder was a working credential for `/api/manychat` (HIGH)

`core.security.verify_manychat_webhook_secret` took any non-empty value as the expected
secret:

```python
expected = os.getenv("MANYCHAT_WEBHOOK_SECRET", "").strip()
if not expected and page_id:
    page_cfg = database.get_page(page_id)
    if page_cfg and page_cfg.get("verify_token"):
        expected = str(page_cfg.get("verify_token")).strip()
```

`pages.verify_token` defaults to a string printed in this repository (migration `0001`,
`core/models.py`, `database.save_page`, `dashboard.html`). The endpoint then runs
`agent.process_message`, which writes registrations, messages and leads.

**Measured before the fix** (development, `WEBHOOK_FAIL_CLOSED=0`, no `MANYCHAT_WEBHOOK_SECRET`):

```
POST /api/manychat  X-ManyChat-Secret: agent_verify_secret_token_123  -> 200
POST /api/manychat  X-ManyChat-Secret: definitely-not-the-token       -> 403
POST /api/manychat  (no header)                                       -> 403
```

Production was **not** protected: the fail-closed branch only ran when `expected` was
*empty*, and a placeholder default is not empty, so `hmac.compare_digest` against the
published string simply succeeded. Phase 45's `meta_verify_token_is_usable()` guard had been
applied to the Meta handshake (`GET /webhook`, which reads `META_VERIFY_TOKEN` from the
environment) but not to this second consumer, which reads the *page* column.

**Fix.** One predicate, both sources:

```python
def usable_webhook_secret(value): ...          # "" unless meta_verify_token_is_usable(value)
expected = usable_webhook_secret(os.getenv("MANYCHAT_WEBHOOK_SECRET", ""))
if not expected and page_id:
    expected = usable_webhook_secret(str((page_cfg or {}).get("verify_token") or ""))
```

A refused candidate is treated as *not configured*, which routes to the existing fail-closed
branch instead of to a comparison against a public value. The diagnosis distinguishes the two
operator errors ("not configured" vs "configured, but published/placeholder") and never
carries the value — following `main.py`'s existing rule that a broad guard must not mask a
more specific diagnosis.

**Measured after the fix, live** (page holding a generated token):

```
X-ManyChat-Secret: agent_verify_secret_token_123  -> 403   (was 200)
X-ManyChat-Secret: final-real-token-9a3c          -> 200
X-ManyChat-Secret: nope                           -> 403
```

**Behaviour change stated explicitly:** in *development*, a page with no usable secret now
falls through to the dev-permissive branch (as `verify_telegram_webhook_secret` already did)
instead of requiring the published string. In production and under `WEBHOOK_FAIL_CLOSED=1`
the result is a refusal either way — strictly safer than before. Development is unchanged for
a page that still carries the published default (the seeded default page), which is what the
suite and local runs rely on.

### 3.5 F-49-4 — one click in the dashboard replaced a webhook secret with the published one (HIGH)

`POST /api/pages` is an upsert, but every column was read with a literal default, so a
payload that merely *omitted* a column reset it. The dashboard's "Тохиргоо хадгалах" button
posts `{page_id, name, page_access_token, knowledge_json}`.

**Measured before the fix, live:**

```
create : verify_token='real-49-verify-token-do-not-lose' monthly_token_limit=5000 category='cargo'
upsert : verify_token='agent_verify_secret_token_123'    monthly_token_limit=100000
         category reset to 'general', is_active forced to 1, knowledge_json survived (it was sent)
```

So saving a page's settings silently installed the published webhook secret — which F-49-1
then accepted as a credential — and multiplied the tenant's token quota twenty times over.
`is_active` was forced back to 1 by `save_page`'s default, i.e. any settings save re-enabled
a tenant somebody had disabled. `page_access_token` and `gemini_api_key` were *not* affected:
they already used `COALESCE(NULLIF(excluded.x, ''), pages.x)`.

**Fix, in three layers:**

1. `database.save_page` — `verify_token` now preserves like the neighbouring secrets
   (`COALESCE(NULLIF(excluded.verify_token, ''), pages.verify_token)`), and a masked value
   echoed back by a client is cleared to `""` (preserve) instead of being stored literally,
   matching the existing guards for the two tokens.
2. `main.py:create_or_update_page` — omitted means **unchanged**: the stored row supplies
   `category`, `verify_token`, `monthly_token_limit`, `is_active` and `knowledge_json`; an
   explicit value in the payload still wins. The published literal is gone from this
   endpoint, and the 400 validation now runs *before* the database read.
3. `main.py:_save_page_sheets_list` / `update_knowledge` — the two remaining
   `page_obj.get("verify_token", "<published>")` fallbacks became `or ""` (preserve), and
   both now carry `is_active` through instead of re-enabling the tenant.

The audit row was also asserting a state the request never set (`"is_active": True`,
hardcoded); it now records what was written.

**Measured after the fix, live (fresh restart, merged code):**

```
create : verify_token='final-real-token-9a3c' category='salon' monthly_token_limit=4242
dashboard-shaped upsert -> 200
stored : {'verify_token': 'final-real-token-9a3c', 'category': 'salon',
          'monthly_token_limit': 4242, 'is_active': 1}          -> all preserved
explicit values still win: name/verify_token/quota/category all updated when sent
masked value echoed back ("ab••••yz") -> original preserved, no "•" stored
```

### 3.6 F-49-2 — the dashboard no longer hands out a published secret or claims a readiness it does not have

`dashboard.html` rendered

```html
<input id="settings-webhook-verify-token" readonly value="agent_verify_secret_token_123" ...>
<button onclick="copyWebhookVerifyToken()">Хуулах</button>
<span class="...text-emerald-400...">Бэлэн</span>
```

next to `Callback URL: <origin>/webhook`. Three problems, all measured:

* the value was **never** populated from the server — it was a constant, so the copy button
  put a string from this repository on the operator's clipboard with the toast
  *"Verify Token хуулагдлаа!"*;
* it conflated two different secrets. `/webhook` compares `hub.verify_token` against
  `META_VERIFY_TOKEN` from `.env` (Phase 45), while the page's own `verify_token` is what
  `/api/manychat` compares against (F-49-1). Pasting the panel's value into Meta produced a
  handshake that production refuses with **403**;
* the badge was a hardcoded "Бэлэн" on an instance where `/api/health` reported
  `meta_token_configured: false`.

**Fix.** The input starts empty; `updatePageUI()` fills it from the page record and writes an
explicit note for each of the three states (a real token, a published one, none). The badge
is set from `/api/health`'s `meta_token_configured` — a boolean; the endpoint never returns
the value. `copyWebhookVerifyToken()` refuses to "copy" an empty field and says which setting
produces one. The label now names the endpoint the token authenticates
(`Verify Token (ManyChat /api/manychat)`).

To keep the published string in exactly one place (`core/security.py`), the *judgement* is
made server-side: `database._sanitize_page_secrets()` adds
`verify_token_is_placeholder`, computed by `meta_verify_token_is_placeholder()` and therefore
environment-independent. The frontend never learns the literal.

`verify_token` itself is deliberately **not** masked in that projection: it is the value an
operator must paste into ManyChat, and masking it would make the copy button useless. The
other four secrets stay masked and popped as before (see §6 for the residual this leaves).

**Measured, live, on the served page:**

```
served bytes            : 298109
placeholder in raw file : True   (only inside the explanatory HTML comment)
placeholder rendered    : False  (comments stripped)
badge is dynamic        : True   (id present, set from meta_token_configured)
note element present    : True
```

### 3.7 F-49-5 — a test that could not set up its own precondition

`tests/test_e37_phase37_readiness.py::TestWorkerHealthcheck::test_healthcheck_command_actually_executes`
calls `worker_heartbeat.clear()` to establish "no heartbeat", but since Phase 41 `clear()`
removes only *this process's* key. On the default prefix, any other worker beating on the
same Redis — a developer's `python worker.py`, which is exactly how this was found — leaves an
`alive` heartbeat behind, so the compose healthcheck probe exited **0** where the test
requires **1**:

```
FAILED ... AssertionError: with no heartbeat the probe must report unhealthy; got 0
  child script: import sys; from core.worker_heartbeat import read;
                sys.exit(0 if read()["status"] == "alive" else 1)
```

Reproduced twice with the Phase 49 worker running; passed every time with it stopped (which
is why the Phase 48A suite did not show it).

**Fix.** The test now uses the documented `WORKER_HEARTBEAT_KEY` override — the child
inherits the environment, so parent and probe share an isolated namespace — wipes that prefix
(a key from an interrupted run would answer the question being asked), and wipes it again at
the end instead of leaving the `p37` beat on a shared Redis. **Both original assertions are
unchanged**; the test became hermetic, not weaker. Verified: `34 passed` with the live worker
beating.

---

## 4. Files changed

| File | Change |
|---|---|
| `core/security.py` | `usable_webhook_secret()`; `verify_manychat_webhook_secret()` refuses a published/placeholder secret from either source and names the cause without the value (F-49-1) |
| `database.py` | `save_page()` preserves a stored `verify_token` on an empty one and clears masked values; `_sanitize_page_secrets()` adds `verify_token_is_placeholder` (F-49-4, F-49-2) |
| `main.py` | `INLINE_SCHEDULER_STARTED` recorded by the lifespan; `POST /api/pages` treats omitted columns as unchanged; the two remaining published-placeholder fallbacks removed; `is_active` carried through; audit detail made truthful (F-48A-3, F-49-4) |
| `routers/system_router.py` | `_inline_scheduler_running_in_api()`; dynamic, truthful scheduler note + `inline_scheduler_in_api` (F-48A-3) |
| `core/worker_heartbeat.py` | tuning values late-bound with safe fallbacks; TTL/fresh-window invariant enforced; PEP 562 `__getattr__` keeps the historical names (F-48A-5) |
| `dashboard.html` | published value removed from the rendered page; field populated from the page record with an explicit note; readiness badge driven by `/api/health`; copy guard; label names its endpoint (F-49-2) |
| `.env.example` | `MANYCHAT_WEBHOOK_SECRET` now explains the fail-closed rule and how to generate a value |
| `README.md` | new "ManyChat / External Request bridge" and "Салбарын тохиргоог хадгалах (`POST /api/pages`)" sections; dashboard panel behaviour documented |
| `tests/test_e37_phase37_readiness.py` | healthcheck-probe test isolated on its own heartbeat prefix (F-49-5) |
| `tests/test_e49_page_secret_hygiene.py` | **new** — 38 tests (F-49-1, F-49-4, F-49-2) |
| `tests/test_e49_startup_config_truth.py` | **new** — 49 tests (F-48A-3, F-48A-5, F-48A-1 guard, launchers, docs) |

Diffstat: `9 files changed, 493 insertions(+), 46 deletions(-)` plus two new test files.

No schema, migration or model change. No test deleted, skipped, weakened or converted; no
security check silenced; no assertion relaxed.

---

## 5. Live verification after the fixes (restarted app, merged code paths)

Instance: `HOST=0.0.0.0 python main.py` + `python worker.py`, `.env` with
`ENV=development`, disposable SQLite at `DB_PATH=/tmp/p48a/p48a_smoke.db`,
`CSV_PATH=/tmp/p48a/leads.csv`, Redis at `127.0.0.1:6379`.

| # | Check | Result |
|---|---|---|
| 5.1 | `/api/live`, `/api/ready`, `/api/health`, `/`, `/admin` | **PASS** — all 200; `engine=sqlite`, `rate_limit_store=redis`, `queue_backend=redis+db` |
| 5.2 | Login with the `.env` password | **PASS** — 200 |
| 5.3 | Login with `ADMIN2026` | **PASS** — 401 (published default still refused) |
| 5.4 | `GET /api/leads` unauthenticated | **PASS** — 401 |
| 5.5 | Worker health + truthful scheduler note | **PASS** — 200, `worker.status=alive`, `alive_count=1`, `stale_count=0`, `inline_scheduler_in_api=true`, note says `DISABLE_INLINE_SCHEDULER=0 … ALSO runs its own inline scheduler … can fire twice`, `location=worker` |
| 5.6 | Page upsert preservation | **PASS** — verify_token / category / quota / is_active all preserved; explicit values still win |
| 5.7 | ManyChat secret check | **PASS** — published placeholder 403, real page token 200, wrong token 403 |
| 5.8 | `/api/pages` placeholder flag | **PASS** — `true` for the seeded default page and for a page with no token, `false` for pages with generated tokens |
| 5.9 | AI / chat integration | **BLOCKED** (unchanged) — no `GEMINI_API_KEY`; `/api/chat` 200 with `"model":"fallback"`, `gemini_ready:false`. Honest degradation, no fabricated AI answer |
| 5.10 | Served dashboard | **PASS** — published string not rendered, badge dynamic, note element present |
| 5.11 | CSV mirror redirection (F-48A-1) | **PASS** — write went to `/tmp/p48a/leads.csv`; repository `leads.csv` byte-identical |
| 5.12 | Schema state after restart | **PASS** — `Schema ready: already at head (0008→0008)` |
| 5.13 | Graceful stop of both processes | **PASS** — `Received SIGTERM` → `worker heartbeat cleared` → `stopped cleanly`; `Application shutdown complete` |

`13 PASS / 0 FAIL` on the scripted checks, plus the four in-script assertions
(truthful note, upsert preservation, no rendered placeholder, CSV mirror) all PASS.

---

## 6. Deliberately NOT changed

* **The `pages.verify_token` schema default itself** (migration `0001`, `core/models.py:62`,
  `database.save_page`'s signature default, the default-page seed at `database.py:181`).
  Migrations are applied artifacts and `tests/test_stage_c_schema.py` asserts the DDL; a new
  migration to change a column default would touch every existing install for a value that
  **no production consumer accepts any more** — `GET /webhook` refuses it (Phase 45) and
  `/api/manychat` refuses it (F-49-1). What remains is a development convenience, and both
  production paths fail closed. Recorded instead of changed.
* **`verify_token` is not masked in the `GET /api/pages` projection**, unlike the four
  neighbouring secrets. It is the value an operator has to paste into ManyChat, and the
  endpoint is admin/tenant-scoped. Masking it would break the dashboard's copy button and
  change an API contract without an instruction to. The new
  `verify_token_is_placeholder` boolean gives the client the judgement it needs without the
  frontend learning the literal.
* **F-48A-2** — `.env` overrides exported variables (`load_dotenv(override=True)`). Inherent
  to the current design; documented in the README, and worked around in the suite by moving
  `.env` aside (and, in the new CSV probe, by stubbing `dotenv` in the child).
* **F-48A-4** — connection-level `.env` changes need a restart. Documented; §3.1 removed one
  false signal (the health note no longer quotes an environment that may have changed since
  startup). Re-initialising Redis/limiter singletons at runtime is a design change, not a fix.
* **F-48A-6** — `tests/test_e45_final_hardening.py::TestMetaVerifyToken` still fails when run
  **in isolation** against the local `pgserver` cluster, because the local role `gerege` is a
  superuser that owns the database and `core/db_privileges.py` refuses to run production mode
  that way. This is environment, not code, and it does not occur in the full-suite order
  (confirmed again: the authoritative run has 0 failures). Remedy, unchanged and **not
  attempted here** because it would reconfigure the shared local cluster other suites depend
  on: `python scripts/provision_roles.py --apply` with `DATABASE_OWNER_URL`, then point
  `DATABASE_URL` at `gerege_app`. Do not skip, monkeypatch or relax `core/db_privileges.py`.
* **`settings-meta-token` (Facebook Page Access Token) renders empty.** `GET /api/pages`
  pops `page_access_token` and returns `page_access_token_masked`, so `p.page_access_token`
  is undefined in the UI. It is a cosmetic wart, not a defect: `save_page` preserves the
  stored token on an empty one, so saving does not wipe it. Displaying the masked value
  instead was left alone — a masked string posted back is only safe because of the `•`/`****`
  guards, and that round trip is not worth the risk without an instruction to change it.
* **Windows launcher execution** — cannot be done on this Linux runner. §7 states exactly what
  was verified instead.

---

## 7. Windows launchers — what is now verified, and what is not

`start.bat`, `start_agency.bat` and `tunnel.bat` cannot be executed here, so execution
remains **NOT VERIFIED**. What *is* now asserted by tests (previously nothing — no test in the
repository referenced a `.bat` file):

* all three still exist;
* none of them prints a credential: no `ADMIN2026`, no `Password123!`, no `%ADMIN_PASSWORD%`
  expansion, no `type .env`;
* none of them weakens a security setting (`ENV=production`, `STRICT_SECURITY=0`,
  `WEBHOOK_FAIL_CLOSED=0`, `DISALLOW_QUERY_TOKEN=0`) — which matters most for
  `start_agency.bat`, since it publishes the machine through a Cloudflare tunnel;
* they start the command the README documents (`python main.py`) and point at the port the
  README documents (`http://localhost:8000`);
* every `.py` file a launcher names exists in the repository;
* `start_agency.bat` still tells the operator where the admin password lives (`.env` →
  `ADMIN_PASSWORD`) and that it is not printed — the Phase 48A replacement for the removed echo.

---

## 8. Test results — floor raised

Authoritative full run, `.env` moved aside, dev venv, live PostgreSQL 16 + Redis, both
application processes stopped (same conditions as the Phase 48A baseline):

```
DATABASE_URL=postgresql+psycopg2://gerege:****@127.0.0.1:5432/gerege_e05_test
REDIS_URL=redis://127.0.0.1:6379/0
CSV_PATH=/tmp/p49_suite_leads.csv
python -m pytest -q -p no:cacheprovider --ignore=scratch
→ 2003 passed, 59 skipped, 1 xfailed, 372 warnings in 668.50s (0:11:08)
  window 2026-11-26T02:40:22Z → 02:51:33Z
```

| Metric | Phase 45 baseline | Phase 48A | **Phase 49** | |
|---|---|---|---|---|
| passed | 1916 | 1916 | **2003** | ✅ **+87** (38 + 49 new tests, all of them new assertions) |
| skipped | 59 | 59 | **59** | ✅ unchanged — no new skips, none converted |
| xfailed | 1 | 1 | **1** | ✅ unchanged |
| failed | 0 | 0 | **0** | ✅ |
| warnings | 372 | 372 | **372** | ✅ unchanged |

Targeted pre-run of the 14 most-affected suites gave `1 failed, 446 passed`; the single
failure was F-49-5 (the shared-Redis heartbeat test), diagnosed, fixed in §3.7 and re-verified
(`34 passed` with a live worker beating). Both new files also pass on PostgreSQL 16 and on a
fresh SQLite schema, and pass on a second run against an already-migrated database — the
caplog hazard described below was made irrelevant rather than worked around.

**Test-infrastructure hazard recorded, not root-caused.** While writing the F-49-1 tests, a
`caplog` assertion captured **nothing** when the schema had to be created inside the same
pytest session, and passed against an already-migrated database. The assertion was therefore
moved onto a stub logger injected with `monkeypatch.setattr(security, "logger", …)`, which
does not depend on the global logging configuration at all; the assertions themselves are
unchanged (the diagnosis must name the cause, and must not contain the value). This matters
beyond this file: an `assert "secret" not in caplog.text` that captures nothing is a free
pass, so any future log assertion written in a session that also creates a schema should be
treated as unproven until it is shown to capture. A standalone probe showed `init_db()`
neither removes root handlers nor disables the `core.security` logger, so the mechanism is
**not** identified; it is reported as observed rather than explained.

---

## 9. Restrictions compliance

| Restriction | Status |
|---|---|
| No production deployment | ✅ none — nothing here deploys; `.github/workflows/ci.yml` has a single `test-and-security-audit` job and no deploy/release/publish job |
| No staging infrastructure change | ✅ none — `docker-compose.staging.yml` / `.prod.yml` untouched (only *read*, by the F-49-5 test) |
| No direct push to `main`, no force push, no history rewrite | ✅ see §10 |
| No deleting existing databases, volumes or backups | ✅ `gerege_crm_next.db` and `knowledge.json` untouched; `BACKUP_DIR` still redirected to `/tmp/p48a/backups` (never written); only disposable probe databases in `/tmp` were created and removed |
| Never overwrite `.env` | ✅ moved aside for suite runs and moved back; never rewritten |
| Never lower the test floor / remove or skip tests to pass | ✅ floor raised (§8); one existing test made hermetic with both assertions intact (§3.7) |
| Never silence a security check | ✅ the opposite: two consumers of a published value now fail closed |
| No secrets in logs, commits or reports | ✅ §10 scan: 0 occurrences of any live secret; all new test values are obviously fake (`e49-…`); no document offers the published placeholder any more |
| Disposable data only | ✅ probe pages (`p49_*`), one marker lead, and `/tmp/p49*` databases |

---

## 10. Git record

*(filled in after the push — see §10.1)*

### 10.1 Push

---

## 11. Verdicts

| Item | Verdict |
|---|---|
| F-48A-3 scheduler note | **FIXED** — measured live, both variants tested |
| F-48A-5 heartbeat config | **FIXED** — measured live + in a standalone child process |
| F-48A-1 regression guard | **DONE** — 4 tests, default proven unchanged |
| F-49-1 ManyChat published credential | **FIXED** — 403/200/403 measured live; production refusal covered by tests |
| F-49-4 upsert reset | **FIXED** — preservation measured live on SQLite and PostgreSQL |
| F-49-2 dashboard placeholder + false "Ready" | **FIXED** — served page verified |
| F-49-5 test isolation | **FIXED** — passes with a live worker beating |
| Windows launcher execution | **NOT VERIFIED** — no `cmd.exe` here; static properties now tested (§7) |
| AI / chat integration | **BLOCKED** — no `GEMINI_API_KEY`; degrades honestly |
| Telegram / Meta / QPay real traffic | **BLOCKED** — no vendor credentials |
| F-48A-6 isolated-run privilege failures | **OPEN** — environment, remedy documented, 0 failures in the authoritative run |
| Test floor | **PASS** — 2003 / 59 / 1 / 0 |
| Staging readiness | **BLOCKED** — unchanged |
| Production readiness | **NOT READY** — unchanged |

**This is not a production release.** Two HIGH findings were closed in code, but no
staging environment or vendor credential exists here, so none of the integration paths were
exercised against a real third party, and the production checklist in `README.md` is still
unmet.

---

## 12. Startup / shutdown (unchanged from Phase 48A §10)

```bash
cd <repo>
python -m venv .venv && . .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp -n .env.example .env                                # never overwrite an existing .env
#   then in .env:  ADMIN_PASSWORD / E02_ACCOUNT_KEY_SECRET / META_VERIFY_TOKEN = generated
#                  DB_PATH, CSV_PATH, BACKUP_DIR  -> disposable locations
#                  REDIS_URL=                           (blank is fine in development)
#                  ENV=development
python main.py                                         # backend on :8000
python worker.py                                       # worker + scheduler, separate process
curl -s localhost:8000/api/live  /api/ready  /api/health
# SIGTERM / Ctrl+C stops both gracefully
```

Two additions worth knowing after this phase:

* **`MANYCHAT_WEBHOOK_SECRET`** must be a generated value in production if `/api/manychat` is
  exposed — a page whose `verify_token` is still the published default is now refused rather
  than accepted.
* **Saving a page's settings no longer resets it.** Anything that called `POST /api/pages`
  with a partial payload and *relied* on the reset (nothing in this repository did) would now
  see the stored values preserved.
