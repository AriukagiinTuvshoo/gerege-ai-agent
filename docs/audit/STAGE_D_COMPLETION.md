# Stage D — Referential integrity and cross-process security

**Branch** `arena/d78ebf88-gerege-ai-agent` · **Base** `48e9c6f` (main) · **Status** complete, CI green

Stage C made `core/models.py` the single schema authority. Stage D closes the four findings
that still blocked a production verdict: `P1-06` (no foreign keys) and the three
cross-process security gaps `SEC-03`, `SEC-04`, `SEC-07`.

The through-line: **three of the four were only visible because the database is now the
authority.** A schema-drift gate that did not exist a week ago is what caught the restore
rollback bug in §2, and foreign keys are what exposed the webhook writing rows for
unregistered tenants in §3.

---

## 1. P1-06 — the schema had zero foreign keys

**Finding.** `SELECT count(*) … constraint_type='FOREIGN KEY'` returned **0** on both live
databases. Every tenant relation was enforced only by application code.

**Impact, verified rather than assumed.** `database.delete_page()` deleted from a
hand-maintained list of twelve table names. The list had already drifted from the schema:

| Table | Deleted with the tenant before | After |
|---|---|---|
| `registrations`, `messages`, `sessions`, `session_states`, `user_memories`, `invoices`, `cargo_packages`, `automated_rules`, `marketing_campaigns`, `sent_followups`, `appointments` | yes | yes |
| **`comment_automations`** | **no** | yes |
| **`tracked_links`** | **no** | yes |
| **`audit_logs`** | **no** | no — *deliberately* |
| **`task_jobs`** | **no** | yes |

Deleting a tenant left automation, link and job rows stranded permanently: unreachable by
any tenant-scoped query, and impossible to clean up because the page they referenced was
gone.

**Fix.** `migrations/versions/0003_foreign_keys.py` adds **16** constraints, declared in
`models.py`:

* **14 × `ON DELETE CASCADE`** on the tenant columns.
* **`audit_logs.page_id → ON DELETE SET NULL`** — the audit trail must outlive the tenant.
  Cascading it would let anyone erase their own audit history by deleting a page.
* **`cargo_packages.invoice_id`** and **`tracked_links.automation_id` → `SET NULL`** —
  optional links. Clearing the reference must not destroy the cargo record or the link's
  click history, which is revenue data.

**Safety.** A foreign key cannot be added over orphan rows. The migration probes for them
*before* any DDL and aborts with a named, actionable message:

```
Cannot add foreign keys: orphan rows would violate them.
  - table 'invoices' has 2 row(s) whose page_id has no matching pages.page_id
Delete or re-parent these rows, then re-run `alembic upgrade head`.
They are not removed automatically because that would be silent data loss.
```

This was not hypothetical: an existing Stage C test seeded invoices for a tenant that was
never created, and the probe caught it. The test fixture was corrected — the *guard* was
right.

**`delete_page()`** now issues a single `DELETE FROM pages WHERE page_id = ?` and lets the
database cascade, so the table list that caused the drift no longer exists.

**Verified on both dialects:** 16 FKs present; round trip `16 → 0 → 16`; cascade confirmed;
`audit_logs` row survives with `page_id NULL`; invalid insert rejected; SQLite timestamps
untouched by the table rebuild (`2026-11-16 04:05:06` → `2026-11-16 04:05:06`, `typeof` still
`text` — the batch-mode truncation trap from Stage C did not recur).

---

## 2. A real bug the drift gate found: the restore rollback was not atomic

**Not on the original list.** While adding foreign keys, the new PostgreSQL drift gate
failed with:

```
diff_count: 1
diffs: [('remove_table', Table('_dummy_temp_tbl', ...))]
```

**Root cause.** On a failed restore, `core/backup_service.py` replayed the pre-restore
snapshot with `pg_dump --clean`. Such a dump emits `DROP TABLE IF EXISTS` only for the
tables *it contains* — so any table created by the rejected restore survived. The API
returned `rolled_back: True, atomic_rollback: True` while the database had silently
diverged from `models.py`.

**This also explains a pre-existing mystery.** Four migration/restore tests failed on the
first run against a *freshly created* PostgreSQL database and passed on the second. They
reproduced at the Stage B baseline (`7676442`), which is why they were recorded as
pre-existing in `STAGE_C_COMPLETION.md` rather than blamed on Stage C. They were caused by
this leak, and they are gone.

**Fix.** Drop and recreate the `public` schema before replaying the snapshot, so the replay
is authoritative. A regression test asserts that a table created by a failed restore is
gone after rollback.

**Verified.** Full suite on a **virgin** PostgreSQL database: **165 passed / 1 skipped**
(previously 4 failures on first run).

---

## 3. SEC-04 — webhook deduplication was per process

**Finding.** `_PROCESSED_MIDS: List[str]` in `main.py`. `Dockerfile` runs `--workers 2` and
`docker-compose.prod.yml` runs a separate worker, so a Meta retry landing on another process
was processed twice and **the customer received a duplicate reply**. The list also evicted
its oldest 500 entries past 2 000, so a delayed retry could be re-processed.

**Fix.** Claim a row in `notification_locks` — an atomic `INSERT` against a primary key that
every worker shares and that survives restarts. TTL is 14 days (Meta retries for ~7).

**Verified across two real interpreter processes:** exactly one lock, one reply.

**A second bug surfaced here.** With the new foreign keys, the webhook wrote messages for
pages that did not exist — a 500, which Meta would retry for days. Unknown pages are now
dropped with a warning. They are deliberately **not** created implicitly: the page access
token is unverified at that point, so letting an arbitrary sender conjure a tenant row would
be a tenant-isolation hole.

**Hardened along the way.** `claim_notification_lock()` caught *every* exception and
returned `False`, making a genuine store failure indistinguishable from "already claimed" —
it would have silently dropped notifications. It now returns `False` only for a duplicate
key (`sqlite3.IntegrityError` **or** `psycopg2.errors.UniqueViolation` — different classes,
verified by probing both) and re-raises everything else.

---

## 4. SEC-07 — rate limits were per process, and three endpoints had none

**Finding.** The only limit was `_LOGIN_ATTEMPTS: Dict[str, List[float]]`, a Python dict.
Effective login limit: **10 × (number of processes) per minute**, reset on every deploy.
Separately, `POST /api/chat` (public widget), `POST /api/upload-receipt` (drives Pillow,
i.e. attacker-controlled CPU) and `GET /r/{code}` had **no limit at all**.

**Fix.** `core/rate_limit.py` counts per `(scope, identity)` using an atomic Redis `INCR`
when `REDIS_URL` is set, with a bounded in-process fallback.

The fallback is an availability choice, and it is **not presented as equivalent**: a
process-local counter is strictly weaker. So the app logs the backend at startup and
`/api/health` exposes `rate_limit_backend` and `rate_limits_shared_across_workers` — a
deployment that believes it is protected can be checked. Failing closed would turn a Redis
outage into a total login outage.

**Verified across two real interpreter processes.** Process 1 spends the 10 login attempts
(`401 × 10`); a **fresh** process is immediately `429`. An in-process test cannot fail for
this bug, because the bug was that state lived inside one process — so the test uses real
subprocesses.

**Two implementation notes.**

* `EXPIRE … NX` requires Redis ≥ 7.0 and this sandbox runs 6.2, where it raises. The TTL is
  now asserted only when the counter is created, which is equivalent for a fixed window and
  works on every supported version. Found by running it — the fail-open path surfaced the
  error instead of silently not limiting.
* `tests/conftest.py` resets counters per test. With a shared store, every test request
  comes from the same address, so one suite's logins would `429` every later suite. That is
  correct behaviour for a shared limiter; the fix belongs in the fixture.

---

## 5. SEC-03 — no CSP, no HSTS

**Finding.** The middleware set only `X-Content-Type-Options`, `X-Frame-Options` and
`Referrer-Policy`. No `Content-Security-Policy`, no `Strict-Transport-Security`.

**Fix.** `core/security.build_security_headers()` — one source of truth, used by both the
success and the 500 path, which are written separately and are where security headers are
usually dropped.

**Honest scope — this is a partial mitigation, and the documentation says so.**
`dashboard.html` is a single 310 kB file with **118 inline `onclick=` handlers** and four
inline `<script>` blocks, and `cdn.tailwindcss.com` compiles CSS in the browser (which needs
`eval`). A policy without `'unsafe-inline'`/`'unsafe-eval'` would break the dashboard, so
they are present and documented rather than shipped as if the job were complete.

What the policy *does* buy: script can only load from named origins (no attacker-controlled
host), and `object-src`, `base-uri`, `form-action` and `frame-ancestors` are locked down —
which is where most injected-markup attacks start. `frame-src` is `'none'` because nothing
is embedded (`docs.google.com` / `sheets.new` are navigation links, which CSP does not
govern). Dropping `'unsafe-inline'` requires removing the inline handlers first; that is
frontend work and is **not** claimed here.

HSTS is production-only on purpose: sending it from a local HTTP dev server pins `localhost`
to HTTPS in the developer's browser for a year.

---

## 6. Verification

| Suite | SQLite | PostgreSQL 16 |
|---|---|---|
| Full `tests/` with Redis 7 | **165 passed, 1 skipped** | **165 passed, 1 skipped** |
| Full `tests/` without Redis | **163 passed, 3 skipped** | n/a |
| Stage C schema authority | 19 passed | 19 passed |
| P1-06 foreign keys | 6 passed | 6 passed |
| SEC-04 webhook dedup | 6 passed | 6 passed |
| SEC-03 security headers | 7 passed | 7 passed |
| SEC-07 rate limits | 12 passed, 2 skipped (no Redis) / 14 passed (Redis) | same |

The 3 skips without Redis are the shared-store tests, which is the correct signal: they
cannot assert cross-process behaviour without a shared store.

**CI.** Every new gate is in `.github/workflows/ci.yml` and green:

| Step | Result |
|---|---|
| Initialize SQLite schema & verify zero schema drift | success |
| Migration integrity (0001 → 0002 → 0001 → 0002) | success |
| Stage C schema authority suite (SQLite) | success |
| **Verify rate limits are shared across workers (SEC-07, live Redis)** | success |
| Verify zero schema drift on Live PostgreSQL 16 | success |
| **Verify foreign keys exist (Live PostgreSQL 16) — P1-06** | success |
| Stage C schema authority suite (Live PostgreSQL 16) | success |
| Build Production Docker Image | success |

Stage D also raised the schema to **revision `0003_foreign_keys`**; `alembic upgrade head`
on any existing deployment applies it, and `downgrade()` removes exactly the constraints
this revision added.

---

## 7. What this does *not* fix

Stated plainly, because the verdict depends on it:

* **Live provider round-trips remain unverified** — no Meta, Telegram, QPay or Gemini
  credentials in this environment. The omnichannel score stays capped for that reason.
* **No load test exists and none was run.** Performance remains unmeasured rather than
  assumed.
* **No browser, accessibility or visual audit** was performed.
* **The CSP is partial** (§5) — inline handlers are still executable.
* **Circuit breakers remain per process**, and `SEC-05` (masked exceptions, no tracebacks)
  and `SEC-08` (guessable invoice IDs) are still open. They were not in this stage's scope
  and are not claimed.
* **`docs/audit/` scores are self-assessed.** The total is now arithmetically correct
  (63.0 = the sum of its rows; the previous 57.5 was not), which is a documentation fix, not
  evidence of quality.

The verdict therefore remains **do not ship**, for the reasons above rather than for the
four findings this stage closed.
