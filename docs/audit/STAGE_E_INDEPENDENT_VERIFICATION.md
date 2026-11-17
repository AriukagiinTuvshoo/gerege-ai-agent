# Stage E — E1 Independent verification of Stage D

**Rule applied:** every Stage D claim was re-tested from scratch against the running system,
not accepted from the completion report. Where a claim failed, the root cause was traced
before writing anything down.

**Headline:** 3 of 4 Stage D items hold up under adversarial testing. **Two new
cross-tenant data-leak defects were found that Stage D did not have**, and the tenant
isolation the whole audit assumed does not actually hold.

---

## Verdict summary

| Item | Stage D claim | Independent result | Status |
|---|---|---|---|
| P1-06 | 16 FKs, CASCADE/SET NULL, orphan guard, restore-safe | fully confirmed, plus a stronger concurrency proof | **PASS** |
| SEC-04 | atomic claim; cross-process dedup | confirmed atomic (16-way concurrent, 1 winner) — but a crash window drops messages | **PARTIAL** |
| SEC-07 | shared limits, fallback, multi-process | atomic in normal operation — **but trivially bypassable and silently fails open** | **FAIL** |
| SEC-03 | CSP + prod-only HSTS on success and error | fully confirmed on a real uvicorn server | **PASS** |
| (new) | tenant isolation | **broken** — cross-tenant customer PII disclosure, demonstrated with natural traffic | **FAIL (P0)** |

---

## E1.1 — P1-06 Foreign keys · PASS

### Confirmed

Measured directly against PostgreSQL's own catalog, not the project's helper:

```
16 FOREIGN KEY constraints, public schema
appointments.page_id          -> pages.page_id            CASCADE
audit_logs.page_id            -> pages.page_id            SET NULL
automated_rules.page_id       -> pages.page_id            CASCADE
cargo_packages.invoice_id     -> invoices.invoice_id      SET NULL
cargo_packages.page_id        -> pages.page_id            CASCADE
comment_automations.page_id   -> pages.page_id            CASCADE
invoices.page_id              -> pages.page_id            CASCADE
marketing_campaigns.page_id   -> pages.page_id            CASCADE
messages.page_id              -> pages.page_id            CASCADE
registrations.page_id         -> pages.page_id            CASCADE
sent_followups.page_id        -> pages.page_id            CASCADE
session_states.page_id        -> pages.page_id            CASCADE
sessions.page_id              -> pages.page_id            CASCADE
tracked_links.automation_id   -> comment_automations.id   SET NULL
tracked_links.page_id         -> pages.page_id            CASCADE
user_memories.page_id         -> pages.page_id            CASCADE
```

Policies match the documented intent exactly: 14 tenant columns cascade, `audit_logs`
survives tenant deletion, and the two optional cross-references clear instead of deleting.

### Orphan guard: safe and atomic

Built a database at `0002`, inserted one invoice referencing a non-existent tenant, then
attempted `upgrade head`:

```
RuntimeError: Cannot add foreign keys: orphan rows would violate them.
  - table 'invoices' has 2 row(s) whose page_id has no matching pages.page_id
revision after refusal: 0002_schema_authority
rows after refusal:     1   (unchanged)
FKs after refusal:      0
```

The migration refused **before** any DDL. Data and revision untouched. This is the correct
behaviour and it is stronger than Stage D documented.

### Round trip: data preserved

`0002 → 0003 → 0002 → head` with real rows present:

```
before:      pages=1 msgs=1 audit=1
downgraded:  FKs=0   pages=1 msgs=1 audit=1
re-upgraded: FKs=16  pages=1 msgs=1 audit=1
```

Row counts identical at every step; constraint count returns to exactly 16.

### Restore preserves FKs — verified by wiping to an empty schema

Stage D claimed "restore re-verified"; this audit tested the harder case — destroy the schema
completely, then restore:

```
before backup:       FKs=16
after DROP SCHEMA public CASCADE: tables=0
restore success:     True   (post_restore_verified: True)
after restore:       FKs=16  messages=1
```

Foreign keys survive a full dump/restore cycle. The atomic-rollback fix from Stage C therefore
composes correctly with the Stage D constraints.

### Gap noted (not a defect)

16 FKs cover the *tenant* dimension well. **`sender_id` columns were deliberately not given
foreign keys**, and that turned out to matter — see E1.5.

---

## E1.2 — SEC-04 Webhook deduplication · PARTIAL

### Atomicity: confirmed, and stronger than Stage D showed

Stage D proved dedup with **two sequential processes**. This audit tested true simultaneity —
16 threads racing the same `mid` against one PostgreSQL database:

```
16 concurrent claims on the SAME lock
  winners (claimed): 1     <- exactly one
  losers:            15
  errors:            0
```

Exactly one winner, no errors surfaced. The `INSERT`-on-primary-key mechanism is genuinely
atomic; the claim holds.

### Defect found — crash between claim and processing silently drops the message

The lock is claimed **before** the event is processed:

```python
if not database.claim_notification_lock(dedup_key, ..., ttl_seconds=14 days):
    continue          # duplicate -> ignore
# ... processing happens here ...
```

If the process dies (deploy, OOM, restart) after the claim and before the reply is sent, the
message is already marked as handled. Meta's retry — which is exactly what retries are for —
is then discarded as a duplicate:

```
worker A claimed:        True
worker A dies here
worker B claim on retry: False  -> delivery DROPPED
lock expires after:      14 days
```

**Impact.** A customer message can be lost for up to 14 days with no reply and no alert. At
-least-once delivery is converted into at-most-once with an infinite failure window.

**Severity** P1 (data/message loss, requires a crash in a narrow window).

**Fix direction (not applied — awaiting approval):** move the claim to *after* successful
processing, or store an explicit state (`claimed` / `sent`) and let a retry re-drive a
`claimed`-but-never-`sent` row. The second is safer because it preserves dedup during normal
operation while allowing recovery after a crash.

### Fail-open on database error — deliberate, documented, accepted

If the dedup store raises, the handler logs with a traceback and processes the message. A
duplicate reply is less harmful than dropping every inbound message during a store outage.
Reviewed and judged reasonable, but it *is* a duplicate-delivery window and belongs in the
risk register.

---

## E1.3 — SEC-07 Rate limiting · **FAIL**

### What works

* **Shared state, truly atomic:** 200 concurrent requests against `limit=50` produced
  exactly **50** allowed. No over-admission race.
* **Cross-process:** two separate interpreters against one Redis share the counter.
* **Recovery:** after a Redis restart the existing client reconnects and continues enforcing.
* **Cold-start fallback:** if Redis is unreachable at import, the limiter degrades to a
  bounded per-process counter and *reports* `memory` / `is_shared=False`.
* **`Retry-After`** header present on rejection.

### Defect 1 (P0) — the login limit is bypassable by rotating `X-Forwarded-For`

`client_identity()` uses the **left-most** `X-Forwarded-For` value, which the client
controls. Tested against a real uvicorn server (not TestClient):

```
A) same X-Forwarded-For each attempt:  [401×10, 429, 429, 429]   -> blocked
B) rotate X-Forwarded-For each attempt: [401 × 13]               -> blocked 0 of 13
```

An attacker sends one header per request and **never hits the limit**. There is no
account-level lockout behind it — `authenticate_admin()` is a bare `compare_digest` with
no failure counter. **The rate limiter is the only brute-force control on the admin login,
and it can be turned off with a header.**

The docstring in `core/rate_limit.py` acknowledges the header is client-controlled and
states it "must never be used for authentication or authorisation decisions" — correct — but
then uses it as the sole key for the one control protecting the admin password.

**Fix direction:** trust a proxy-supplied header only from a configured trusted proxy, or key
the admin-login limit on the account being attacked rather than the source address (or both).
Awaiting approval.

### Defect 2 (P1) — silent fail-open with a false health signal

If Redis dies **while the app is running**:

```
1. backend while healthy: redis
2. Redis killed. 4 subsequent requests: allowed=True count=0  (allowed=True count=0 ...)
3. still reports backend: redis | is_shared: True
```

Every request is allowed, the counter is never incremented, and **`/api/health` still reports
`rate_limits_shared_across_workers: true`** — so an operator checking health is told limits
are enforced when they are not. The security control fails open *and* actively misreports its
own state.

Cold-start fallback is honest (reports `memory`); the runtime-outage path is not. That
asymmetry is the defect.

**Fix direction:** track the last successful store contact and have `backend()`/health report
`degraded` when calls are failing; consider failing closed for the admin-login scope only.

**Severity** P1 (security control silently absent, misleading telemetry).

---

## E1.4 — SEC-03 CSP / HSTS · PASS

Verified against a **real uvicorn server**, because a header bug that only appears outside
TestClient would be exactly the kind of thing a green suite hides.

```
GET /api/health (dev mode), real server:
  x-request-id:             94df02443d59dbc9
  x-content-type-options:   nosniff
  x-frame-options:          DENY
  referrer-policy:          strict-origin-when-cross-origin
  content-security-policy:  default-src 'self'; script-src 'self' https://cdn.tailwindcss...
  Strict-Transport-Security: ABSENT   <- correct in dev
```

* CSP present, HSTS correctly **absent** outside production (so local dev is not pinned to
  HTTPS for a year).
* Headers present on error responses too (covered by `tests/test_sec_03_security_headers.py`).
* No wildcard in `script-src`; origins are named explicitly.
* `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`.

### Honest limitation, unchanged from Stage D

The policy still requires `'unsafe-inline'` and `'unsafe-eval'` because `dashboard.html` has
118 inline `onclick=` handlers, four inline `<script>` blocks, and loads
`cdn.tailwindcss.com` which compiles CSS in the browser. A strict policy breaks the
dashboard. This is a *partial* mitigation and is labelled as such; the E1 review concurs that
shipping a strict policy without refactoring the frontend would be a regression, not a fix.

### Process note (self-correction)

My first live check reported "CSP MISSING". That was **my** error: I built a plain `dict()`
from a case-insensitive header object and looked up `"Content-Security-Policy"` while
uvicorn emits lowercase. The header was always there. Recorded because an audit that hides its
own false positives is worth less than one that shows them.

---

## E1.5 — NEW: cross-tenant PII disclosure (P0, not previously reported)

Found while checking whether the 16 FKs were *complete*. They are complete for the tenant
dimension — but `session_states` is keyed on `sender_id` **alone**:

```sql
session_states  PRIMARY KEY (sender_id)      -- not (page_id, sender_id)
```

and `log_message()` upserts on that key while overwriting the tenant:

```sql
INSERT INTO session_states (sender_id, page_id, channel, updated_at) VALUES (?,?,?,CURRENT_TIMESTAMP)
ON CONFLICT(sender_id) DO UPDATE SET
    page_id = COALESCE(?, session_states.page_id),      -- <- newest tenant wins
    ...
```

`COALESCE(?, existing)` always takes the **new** value because the parameter is non-null,
so every message reassigns the whole session row to the tenant that spoke last.

### Methodological correction (self-audit)

My first version of this finding demonstrated the leak by issuing a manual `UPDATE` to move
the session row. **That was a doctored fixture and does not prove anything** — an auditor can
make any system fail by editing its database. It is recorded here rather than quietly deleted.
The finding was then re-tested using **only public application functions and ordinary customer
behaviour**, and the real defect is worse than the doctored version suggested.

### Reproduction — natural traffic only, no manual SQL

```python
save_page("ACME", ...); save_page("GLOBEX", ...)          # two businesses
S = "PSID_REAL"                                            # one customer

log_message(S, ..., "Acme: hi",    page_id="ACME")         # 1. Acme's customer talks
#    Acme's staff saves the customer's details (ordinary CRM use):
UPDATE session_states SET customer_phone='88001234', customer_name='Bat Bold',
                          is_human_takeover=1 WHERE sender_id=S
log_message(S, ..., "Globex: hello", page_id="GLOBEX")     # 2. same person talks to Globex
```

Result — **Globex's own dashboard view of its own conversation**:

```
customer_name     = 'Bat Bold'
customer_phone    = '88001234'      <- saved by ACME, disclosed to GLOBEX
is_human_takeover = 1               <- ACME's state
message_count     = 2               <- Globex received exactly 1
ACME's conversation still listed? False    <- Acme's thread vanished from Acme's view
```

### Three distinct consequences

1. **Cross-tenant PII disclosure.** Tenant B is shown the customer phone number and name that
   tenant A collected. This is the confidentiality property the engagement exists to protect.
2. **Conversation hijacking / data loss.** The thread is reassigned to the newest tenant, so
   tenant A's conversation disappears from tenant A's own dashboard — a reliability defect on
   top of the disclosure.
3. **Unscoped message reads.** `get_active_sessions()` computes `last_message`,
   `last_sender_type` and `message_count` with subqueries filtered on `sender_id` **only**:

   ```sql
   (SELECT content FROM messages WHERE sender_id = s.sender_id ORDER BY id DESC LIMIT 1)
   ```

   `message_count` therefore always counts every tenant's messages (measured: 2 where Globex
   had 1). Whether the *content* shown belongs to another tenant depends on which message is
   newest — so message-body disclosure is **order-dependent**, not unconditional. Stated that
   way deliberately: the count leak is unconditional, the body leak is conditional, and both
   are defects. An earlier draft of this report over-claimed the body leak as unconditional.

### Related — the takeover/send ownership guard checks the wrong row

`/api/sessions/{sender_id}/takeover` and `/send` authorise with:

```python
msgs = database.get_conversation_history(sender_id, limit=5)    # no page_id filter
verify_resource_tenant_ownership(user, msgs[0].get("page_id"))
```

`get_conversation_history()` returns **every** tenant's messages for that sender ordered
`created_at ASC`, so `msgs[0]` is the oldest row *overall* — not the caller's tenant. The
guard can therefore approve an action against a conversation containing another tenant's data,
and `set_human_takeover(sender_id)` then updates with no tenant predicate at all.

### Severity

**P0.** Exploitable by any authenticated tenant user through normal product use, demonstrated
end-to-end with the app's own functions, results in cross-tenant disclosure of customer PII
plus loss of another tenant's conversation.

It is **not** introduced by Stage D — it predates it — but it invalidates the "tenant
isolation verified" assumption carried by every prior report, and it is not in the
SEC-05 / SEC-08 list this stage was asked to investigate.

### Test coverage: none

`grep` across `tests/` found **no** test asserting two tenants sharing a sender ID stay
isolated, and no test that a session row is scoped by tenant. The suite is green while this is
broken — the single most important result of this audit.

## Corrections to prior reporting

| Prior claim | Reality |
|---|---|
| "remote commit `97ea01f`" | branch tip is `deedebf`; 4 commits landed after |
| "165 passed / 1 skipped" | 166/166 pass when configured as CI does; the skip is environmental |
| "tenant isolation" implied by prior stages | **does not hold** — see E1.5 |
