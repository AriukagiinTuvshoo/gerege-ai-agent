# E-01 — Tenant Isolation of Session State, Messages and PII (P0)

**Status:** FIXED — verified on SQLite and PostgreSQL 16, regression suite green.
**Severity:** P0 (cross-tenant disclosure of customer name, phone number and message counts).
**Commit:** `dfeaef3` on `arena/d78ebf88-gerege-ai-agent`.
**Engineer roles:** Principal Security Engineer, Senior Backend, DB Architect, QA.

---

## 1. Root cause

The defect was in the **database schema**, not only in the queries.

`session_states` — the table that holds "who is this customer, what is their phone
number, is a human driving this conversation" — was keyed on the sender alone:

```sql
CREATE TABLE session_states (
    sender_id VARCHAR(255) NOT NULL,
    page_id   VARCHAR(128) DEFAULT '100799479495809',
    ...
    PRIMARY KEY (sender_id)          -- one row per person, GLOBALLY
);
```

`page_id` was an ordinary column. Two consequences followed, and the second is what made
this a P0 rather than a nuisance:

1. **Writes reassigned ownership.** Both write paths upserted on the sender-only key and
   set the tenant from the incoming request:

   ```sql
   ON CONFLICT(sender_id) DO UPDATE SET
       page_id = COALESCE(?, session_states.page_id),   -- parameter is always non-null
       ...
   ```

   `COALESCE(?, existing)` looks defensive, but the bound parameter came from the current
   webhook/request and was never null. The row therefore moved to **whichever tenant spoke
   last**, and carried its `customer_name` / `customer_phone` with it.

2. **Reads were unscoped.** `get_conversation_history()`, `is_session_human_takeover()`
   and `set_human_takeover()` filtered on `sender_id` only. `get_active_sessions()`
   scoped its outer query by `page_id` but computed `last_message`, `last_sender_type`
   and `message_count` in correlated subqueries that filtered on `sender_id` alone, so
   even a correctly scoped list row leaked another tenant's content and volume.

3. **Authorization was derived from the data it was meant to protect.** The takeover and
   send endpoints decided ownership from `msgs[0]` — the **oldest** message returned by
   an unscoped, `ORDER BY created_at ASC` query. Without the `page_id` filter, `msgs[0]`
   is the oldest row across *all* tenants, so the guard authorised against an arbitrary
   tenant's message.

The trigger is not an attack. It is **one person contacting two businesses** through the
same channel identity (a shared Facebook PSID, a reused Telegram id, a shared link).

## 2. Before / after

Proof obtained by natural traffic only — the public `/api/chat` endpoint followed by each
tenant's own authenticated `/api/sessions`. No `UPDATE`, no hand-written fixture rows.

Scenario: sender `PSID_PII_1` gives Acme their name and phone, then messages Globex.

### Before (`fdd4acc`)

| Caller | customer_name | customer_phone | message_count |
|---|---|---|---|
| Acme   | *(no rows — Acme's conversation is gone)* | — | — |
| Globex | `Бат` | `88001234` | 4 |

Globex was served Acme's customer's name and phone number from Globex's own
authenticated session list. Acme lost access to its own conversation at the same time.

### After (`dfeaef3`)

| Caller | customer_name | customer_phone | message_count | last_message |
|---|---|---|---|---|
| Acme   | `Бат` | `88001234` | 2 | Acme's own reply |
| Globex | `None` | `None` | 2 | Globex's own reply |

Message bodies are likewise separated: Acme receives only its two messages, Globex only
its own two. Neither response contains the other tenant's text.

## 3. Modified files

| File | Change |
|---|---|
| `core/models.py` | `SessionStateModel` PK → `(page_id, sender_id)`. |
| `migrations/versions/0004_tenant_session_identity.py` | **New.** Data-preserving upgrade + guarded downgrade. |
| `database.py` | Scoped `log_message`, `save_registration`, `get_conversation_history`, `get_active_sessions` (outer query **and** all three subqueries), `set_human_takeover`, `is_session_human_takeover`; added `session_belongs_to_page`; page_id-sanitisation now warns instead of silently orphaning rows. |
| `main.py` | `/api/sessions/{sender_id}/messages`, `/takeover`, `/send` derive the tenant from the auth context via `enforce_tenant_scope`; `/api/health` aggregates per tenant. |
| `agent.py` | Takeover check/set and history read pass `page_id`. |
| `core/ai_router.py` | `format_persistent_conversation_context` takes `page_id`. |
| `repositories/crm_repo.py` | `get_messages` requires `page_id`. |
| `scripts/migrate_sqlite_to_postgres.py` | ETL `pk_cols` for `session_states` → `["page_id", "sender_id"]`. |
| `tests/test_e01_tenant_isolation.py` | **New.** 8 regression tests over real HTTP with real tenant tokens. |

### Fail-closed contract

The scoped functions raise `ValueError` when `page_id` is absent rather than returning
unfiltered rows. A caller that forgets the tenant now fails loudly in tests instead of
quietly serving another tenant's data. Every in-repo caller was updated.

## 4. Migration `0004_tenant_session_identity`

Design constraints: data-preserving, no guessed ownership, stoppable, reversible.

**Upgrade**
1. Backfill legacy `page_id IS NULL` rows (permitted by `0001`) to the default page.
2. For each sender whose stored owner disagrees with its messages: if **all** messages
   agree on one tenant, correct the owner; if messages span **more than one** tenant,
   raise `RuntimeError` naming the sender and abort. The original single-tenant row never
   held the other tenants' data, so their `customer_name`/`customer_phone` cannot be
   reconstructed — the migration reports instead of inventing an owner.
3. Assert no duplicate `(page_id, sender_id)` would be created.
4. Rebuild the table with `PRIMARY KEY (page_id, sender_id)`, `page_id NOT NULL`.

**Downgrade** refuses while two tenants hold a row for the same sender, because collapsing
them to a sender-only key would destroy one tenant's row.

The primary key name is read from the catalog rather than assumed. `0001` created the
SQLite table with an inline `PRIMARY KEY (sender_id)` and no `CONSTRAINT` clause, so the
inspector reports `name: None`; hard-coding `pk_session_states` raised
`ValueError: No such constraint` on the first execution attempt.

**Verified behaviour**

| Check | SQLite | PostgreSQL 16 |
|---|---|---|
| Upgrade on populated DB (rows + timestamps preserved) | PASS | PASS |
| `page_id` becomes `NOT NULL` | PASS | PASS |
| Same sender can exist for two tenants | PASS | PASS |
| Duplicate `(page_id, sender_id)` rejected | PASS | PASS |
| Ambiguous sender stops the upgrade, DB left at `0003` | PASS | PASS |
| Downgrade refuses on tenant collision | PASS | PASS |
| Downgrade → upgrade round trip | PASS | PASS |
| `drift_report()`: `has_drift=False` at head `0004` | PASS | — |

## 5. Authorization

Before: ownership taken from `msgs[0]`, the oldest message across all tenants.
After: three independent rules.

* The tenant comes from `enforce_tenant_scope(request, ...)`, i.e. from the authenticated
  session. `payload["page_id"]` and `?page_id=` are no longer trusted; a non-admin caller
  that asks for another tenant is refused by the existing guard.
* The caller's tenant must actually own the session — either a `session_states` row or
  history for that `(page_id, sender_id)`. Otherwise **404**, never a silent write.
* All reads and writes are filtered by that resolved `page_id`, so acting on your own row
  cannot touch another tenant's state.

Demonstrated on live HTTP:

| Attempt | Result |
|---|---|
| Globex toggles takeover on a sender only Acme knows | `404` |
| Globex sends into a sender only Acme knows | `404` |
| Globex reads a sender only Acme knows | `200`, `messages: []` (no existence disclosure) |
| Globex toggles takeover on **its own** row for a shared sender | `200`; Acme's `is_human_takeover` stays `0` |
| Acme reads its own history afterwards | `200`, unchanged |

## 6. Tests

`tests/test_e01_tenant_isolation.py` — 12 tests, all driven through FastAPI's HTTP surface
with real `database.create_session(...)` bearer tokens. No test writes rows with SQL to
manufacture a leak.

1. Acme's customer gives a phone number; Globex never sees it.
2. Each tenant keeps its own conversation row (Acme does not lose its conversation).
3. `message_count` and `last_message` are per tenant.
4. Human takeover is per tenant.
5. Globex cannot toggle takeover on Acme's session; Acme's state is unchanged.
6. Globex cannot send into Acme's session; nothing appears in Acme's transcript.
7. A shared sender's takeover write only touches the calling tenant's row.
8. The schema itself rejects a duplicate `(page_id, sender_id)`.
9. No message **body** crosses tenants (tests 2-3 check counts; this checks content).
10. The admin all-branch view still works, and a client asking for another branch is 403.
11. Four threads × ten writes from two tenants: no collision, no overwritten PII.
12. `0003 → 0004 → 0003 → 0004`, twice: every row and timestamp identical afterwards.

Tests 5 and 6 were **strengthened after the first fix attempt**. They originally asserted
only that Globex received non-200, which passed for the wrong reason: once rows are
per-tenant, Globex legitimately owns a row for a shared sender, so `200` is correct
behaviour and the refusal must be tested on a sender Globex does not own. Their
preconditions were also vacuous before — they asserted against an empty list.

**Before the fix:** 5 failed, 2 passed (the 2 were anti-regression guards for the
pre-existing 403 check, kept deliberately).
**After the fix:** 12/12 on both engines.

## 7. Results

| Suite | SQLite | PostgreSQL 16 |
|---|---|---|
| `tests/test_e01_tenant_isolation.py` | **12 passed** | **12 passed** |
| Full suite `tests/` | **175 passed, 3 skipped** | **175 passed, 3 skipped** |

The 3 skips are pre-existing and environment-gated, not E-01: two require `REDIS_URL` for
a shared limiter, one requires an explicit `ALLOWED_ORIGINS`. They are not counted as
passes.

### CI evidence

* Run: [`43991938565`](https://github.com/AriukagiinTuvshoo/gerege-ai-agent/actions/runs/43991938565)
* Commit: `dfeaef3c7cf628149d1922a442a373cb92693b50`
* Conclusion: **success**
* Steps, all `success`: dependency vulnerability audit · Pytest regression, enterprise,
  AI-eval and failure suites (SQLite mode) · Postgres connectivity and drivers · SQLAlchemy
  Postgres engine connection · production Docker image build.

A latent bug in the downgrade path (`batch.alter_column("session_states", "page_id", …)`
— an extra positional argument) was caught by the pre-existing
`test_migration_round_trip_is_reversible_and_lossless` and fixed before commit.

## 8. Remaining risks

* **Historic reassigned rows are reported, not repaired.** Where a sender's messages span
  several tenants, migration 0004 stops and names the sender. Their historical PII cannot
  be restored from the database. Operational decision required per case.
* **Default-page backfill assumes single-tenant legacy.** NULL `page_id` rows are assigned
  to `100799479495809`. Correct for this deployment's history, but it is an assumption and
  should be confirmed against production data before running on a real copy.
* **`sender_id` is not globally unique across channels.** Two different people could share
  a sender id on different channels of the same page; that stays a single session row, as
  before. Not a cross-tenant issue, out of scope here.
* **Other tables were not re-audited for the same pattern.** `user_memories`, `appointments`
  and `registrations` already carry `page_id` and were probed with tenant tokens during
  verification, but E-01's schema change is limited to `session_states`.
* **No production run.** Verified against local SQLite and a local PG16 instance only.

## 9. Rollback

1. `alembic downgrade 0003_foreign_keys` — reverts the PK to `(sender_id)` and restores
   `page_id` nullability. It **refuses** if two tenants share a sender; remove or merge
   those rows deliberately first.
2. `git revert dfeaef3` — restores the previous query and endpoint behaviour.
3. Restore the pre-migration backup (`core/backup_service.py` covers `session_states`).

Order matters: revert the code first if the rollback is due to an application fault, and
only downgrade the schema after the code no longer expects the composite key.
