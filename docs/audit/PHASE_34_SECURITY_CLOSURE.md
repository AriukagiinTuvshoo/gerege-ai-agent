# PHASE 34 — High-Risk Route & Credential Security Closure

Baseline: branch `arena/d78ebf88-gerege-ai-agent`, HEAD `c18a818`, `main` `48e9c6f`,
PR #1 open/unmerged, CI `45115895309` 65/65. Verified before any change.

Three defects were confirmed by reproduction and fixed. The route ledger was extended from
reference-counting to behavioural status for all 93 operations.

---

## 1. F-34-1 — cross-tenant report recipient (High)

**Route:** `POST /api/executive/send-report`

`payload["chat_id"]` was forwarded verbatim to `send_executive_report`, whose `chat_id`
argument overrides the tenant's configured `telegram_manager_chat_id`.

**Reproduction.** Admin scoped to tenant A, caller supplies tenant B's chat id:

```
request  {"page_id": "tenantA", "chat_id": "chatB"}
result   {"success": true, "chat_id": "chatB"}
dispatched URL   https://api.telegram.org/bot111:AAA_TOKEN_A/sendMessage
dispatched body  {"chat_id": "chatB", ...}
```

Tenant A's report — which contains that tenant's revenue figures — was delivered to a
chat tenant A does not control, using tenant A's bot. Any caller holding
`executive:write` could do this; `enforce_tenant_scope` only constrains `page_id`.

**Fix.** `chat_id` is no longer accepted from the body. The recipient is always the scoped
tenant's own `telegram_manager_chat_id`. An explicit value is **rejected with 400** rather
than silently ignored, so a caller cannot believe an override took effect. The dashboard
never sent `chat_id` (`dashboard.html:3456-3459` posts only `date_str`), so no working
flow changes.

**Remaining risk.** An admin can still name any `page_id` they are authorised for; that is
intended admin reach, not a cross-tenant escalation. Constrained further only if the
product gains per-tenant admin roles.

---

## 2. F-34-2 — cross-tenant side effects from a tenant-scoped caller (High)

**Route:** `POST /api/retention/trigger-checks`

The handler called `require_permission(request, "retention:write")` and then ran
`run_automated_retention_checks()`, which iterates **every page in the database**. No
tenant scope was applied anywhere. `has_permission("client", "retention:write")` is `True`,
so a tenant `client` could trigger the scheduler's all-tenants sweep over HTTP.

**Reproduction.** Tenant A client; abandoned-chat candidates seeded on B and C only:

```
POST /api/retention/trigger-checks          (client token)
200 {"stats": {"abandoned_sent": 2, ...}}
tenants actually dispatched to: ['tB', 'tC']
```

Two follow-up messages were sent into two other tenants. This is a *sending* action —
customer-visible and irreversible.

**Fix.** The endpoint resolves scope through `enforce_tenant_scope` and passes it to
`run_automated_retention_checks(..., page_id=scoped)`, which now filters the page list.
Verified: same scenario dispatches to `[]`; naming another tenant returns **403**.

**Deliberately unchanged.** `main.py:77` (inline scheduler) and `worker.py:95` call
`run_automated_retention_checks()` with no `page_id`, so the background sweep still covers
every tenant. `page_id` defaults to `None` = all pages, which preserves scheduler
behaviour exactly. The dashboard (`dashboard.html:5125`) sends no `page_id`, so it scopes
to the logged-in tenant — the intended semantics for a manual trigger.

---

## 3. F-34-3 — bot token disclosed through the error path (Medium)

**Routes:** `POST /api/executive/send-report` (and any caller of
`send_executive_report`)

Two leaks in the same function:

```python
except Exception as e:
    return {"success": False, "message": str(e)}          # leak 1
...
return {"success": False, "message": f"...: {res.text}"}  # leak 2
```

httpx embeds the request URL in its exception text, and the URL is
`https://api.telegram.org/bot<TOKEN>/sendMessage`. Telegram error bodies can echo the
same. **Reproduction:** a transport error returned
`"connection to api.telegram.org/bot111:SECRET_BOT_TOKEN_XYZ failed"` to the HTTP client —
the tenant's live bot token, in a 200 response body.

**Fix.** The client receives a stable message with no secret; status code and detail stay
in the server log. Provider bodies are no longer echoed. `success` remains `False`, so the
failure is still reported honestly.

**Remaining risk.** The token still appears in server logs at `logger.error`, deliberately:
operators need the cause, and logs are a controlled surface. Log aggregation must itself
be access-controlled (unchanged posture, documented not fixed).

---

## 4. Route ledger

`docs/audit/PHASE_34_ROUTE_LEDGER.json` — all 93 operations, generated from runtime
introspection (`APIRoute` objects from `app.routes` plus the `_IncludedRouter` wrappers,
which this FastAPI version does not flatten).

| Measure | Value |
|---|---|
| Operations | **93** |
| Unique paths | **81** |
| From included routers | **14** |
| Auth required | 65 |
| Admin-only (`require_admin`) | 13 |
| Tenant-scoped (`enforce_tenant_scope`) | 49 |
| Mutating DB calls | 25 |
| Outbound dispatch | 6 |

Reconciliation with Phase 33: 93 operations / 81 paths / 14 router operations confirmed
independently. Phase 33's "39 uncovered paths" was a *reference* count; this ledger
classifies by whether a test issues the verb against the path (an `EXERCISED` marker),
which is still weaker than proving behaviour.

**Status after Phase 34:**

| Status | Count |
|---|---|
| VERIFIED (Phase 34 behavioural test) | 10 |
| VERIFIED (Phase 33) | 1 |
| EXERCISED (existing test issues the verb) | 48 |
| NOT_VERIFIED | 34 (Low 26, Medium 8, **High 0**) |

All 19 High-risk operations are now behaviourally verified. The 34 remaining are Low
(summaries, static pages, sheet sub-routes) and Medium (8 settings/knowledge POSTs).

---

## 5. Credential and secret management audit

Checked, all against synthetic values:

| Check | Result |
|---|---|
| `/api/update-keys` requires admin, not mere auth | **PASS** — tenant client 403; `ADMIN_PASSWORD` unchanged after a refused write |
| `/api/pages/{id}/credentials` requires admin | **PASS** (`require_admin`) |
| Cross-tenant credential **write** (`gemini_key`) | **PASS** — tenant client → another tenant 403 |
| Cross-tenant page read | **PASS** — 403 |
| Plaintext secrets in GET responses | **PASS** — `/api/pages/{id}`, `/api/pages/detail`, `/api/executive/settings` return masked/absent values |
| Secrets in audit logs | **PASS** — `/api/update-keys` records only `updated_fields` names |
| Secrets in error responses | **FAIL → fixed** (F-34-3) |
| Anonymous credential writes | **PASS** — 401 |

**One residual design note, not a defect:** `/api/update-keys` writes process-global
`os.environ` rather than persisting per-tenant configuration, and it accepts
`admin_password`. It is admin-only and audited, and the tenant-scoped credential endpoints
are the supported path; but a process-local admin password change does not survive a
restart and does not propagate across the worker container. Recorded as debt (P3), not
changed here — persisting credentials is a feature, and this phase does not add features.

---

## 6. Tests added

`tests/test_e34_phase34_security.py` — **36 tests**:

| Group | Count |
|---|---|
| F-34-1 report recipient (refusal, happy path, unauth) | 3 |
| F-34-2 retention scoping (client, widen attempt, admin scope, unauth) | 4 |
| F-34-3 secret non-disclosure (transport error, provider body, honest failure) | 3 |
| Admin plane (5 GETs × anonymous + tenant client, positive control, mutating, page delete) | 14 |
| Backup verify path traversal (5 hostile names), auth, missing archive | 7 |
| Credential/masking surface | 5 |

Providers are mocked at the `httpx.AsyncClient` seam. Every test asserts response
semantics **and** database or dispatch state.

**Two flaws found in my own tests during Phase 4 review:**

1. `test_a_tenant_client_cannot_delete_a_page` sent `page_id` in the JSON body, but the
   handler reads it from the **query string**. That produced `400 page_id missing` *before*
   `require_admin` ran — a test that passed while proving nothing about authorization.
   Fixed to use `params=`, with a positive control that an admin delete succeeds.
2. An earlier probe reported sheet upload returning `200` unauthenticated. That was a
   `TestClient` cookie-retention artifact: a prior login in the same client object. With
   cookies cleared it is **401** and nothing is persisted. No defect.

**Negative control (validity-checked).** Source restored to `c18a818` with
`git show c18a818:<file> > <file>`, verified byte-identical (`git diff --stat c18a818` →
empty) before running: **6 of 36 fail** — exactly the three findings, both directions for
F-34-1 and F-34-3. The 30 passing tests guard protections that already existed, which is
the expected result for a suite that mixes new regressions with standing guards. Source
restored, residue checked: `leads.db` row counts unchanged.

---

## 7. Verification

Fresh disposable PostgreSQL (`p34_full`, `alembic upgrade head`):

```
1349 passed, 36 skipped, 0 failed in 338.02 s
```

| | Phase 33 | Phase 34 |
|---|---|---|
| Passed | 1,313 | **1,349** (+36) |
| Skipped | 36 | 36 |
| Failed | 0 | **0** |

`leads.db` page count: 25 before, 25 after. Zero `p34%` rows in any table.

| Check | Result |
|---|---|
| `scripts/validate_workflows.py` | OK |
| Bandit (CI scope) | 0 HIGH, 19 MEDIUM — unchanged (B608 ×17, B310, B314) |
| pip-audit | 21 advisories, all in `pip`/`setuptools` |
| Secret scan (diff + new files) | 0 |
| e29 CI-integrity guard | 20 passed, now requires the Phase 34 suite |
