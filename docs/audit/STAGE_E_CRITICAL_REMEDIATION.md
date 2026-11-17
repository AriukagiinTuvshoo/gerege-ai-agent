# Stage E — Critical Security Remediation

**Branch:** `arena/d78ebf88-gerege-ai-agent` · **Base:** `main` @ `48e9c6f`
**Baseline commit:** `fdd4acc` (Stage E independent verification)
**Gate rule:** a Step's acceptance criteria must be met before the next Step begins. No
Step is marked complete on "skip", "partially", or "looks fine" — only on evidence.

---

## Scope and order

Strictly sequential. Parallelising these would make each failure ambiguous.

| Step | Priority | Subject | Status |
|---|---|---|---|
| **E-01** | P0 | Tenant isolation of session state, messages and PII | **FIXED — verified** |
| **E-02** | P0 | Login rate limit, trusted proxy, account-level lockout | **Phase 3 done** · Phase 4 not started |
| **E-03** | P1 | Redis outage truthfulness in health; per-endpoint fail policy | Not started |
| **E-04** | P1 | Durable webhook processing: lease, retry, idempotency | Not started |

Reports: [`E01_TENANT_ISOLATION.md`](E01_TENANT_ISOLATION.md) ·
[`E02_LOGIN_RATE_LIMIT.md`](E02_LOGIN_RATE_LIMIT.md) (Phase 3 of 4).

`E03_REDIS_RESILIENCE.md` and `E04_WEBHOOK_RELIABILITY.md` are deliberately **not written
yet** — they are authored only once their Step is actually remediated.

---

## E-01 — Tenant isolation (P0) · `dfeaef3` + `d96d3cb`

### What was wrong

`session_states` was keyed on `sender_id` alone. Both write paths upserted on that key
with `page_id = COALESCE(?, existing)`, and the bound parameter was never null, so the
session row — including the customer's name and phone number — moved to whichever tenant
spoke **last**. All session reads were additionally unscoped on `sender_id`, and the
takeover/send ownership guard authorised against `msgs[0]`, the *oldest* message across
all tenants.

The trigger is ordinary traffic: one person contacting two businesses.

### Evidence, natural traffic only

Sender `PSID_PII_1` gives Acme their name and phone, then messages Globex.

| | Before `fdd4acc` | After `dfeaef3` |
|---|---|---|
| Globex sees | `customer_name='Бат'`, `customer_phone='88001234'`, `message_count=4` | `customer_name=None`, `customer_phone=None`, `message_count=2` |
| Acme sees | **no rows** — its conversation was reassigned away | `'Бат'` / `'88001234'`, `message_count=2`, its own messages |
| Cross-tenant write | allowed (ownership read from the oldest message) | `404` for a tenant with no session; own-row writes cannot touch the other tenant |

### Acceptance criteria

| Criterion | Result | Evidence |
|---|---|---|
| 0 cross-tenant PII disclosure | **PASS** | Globex `customer_name`/`customer_phone` are `None`; bodies contain only its own messages |
| 0 message-count leak | **PASS** | `message_count` is 2/2, not 4 for both |
| 0 identity collision | **PASS** | PK `(page_id, sender_id)`; duplicate insert rejected; migration asserts pre-conditions |
| 403/equivalent on unauthorised takeover | **PASS** | `404` (fail closed, no existence disclosure) |
| 403/equivalent on unauthorised send | **PASS** | `404`; Acme's transcript unchanged |
| Schema-enforced, not query-only | **PASS** | `core/models.py` PK + migration `0004` |
| Data-preserving migration | **PASS** | Rows and timestamps preserved; ambiguous senders stop and are named |
| Downgrade path | **PASS** | Round trip verified; refuses on tenant collision |
| SQLite PASS | **PASS** | 171 passed, 3 skipped |
| PostgreSQL PASS | **PASS** | 171 passed, 3 skipped |
| Migration verified on both engines | **PASS** | Upgrade, downgrade, refusal, round trip |
| Real-HTTP regression tests, no manual-SQL fixtures | **PASS** | 8 tests, bearer tokens, `/api/chat` + `/api/sessions` |
| CI PASS | **PASS** | [`43992507126`](https://github.com/AriukagiinTuvshoo/gerege-ai-agent/actions/runs/43992507126) on `d96d3cb` — all steps green incl. Docker build; earlier [`43991938565`](https://github.com/AriukagiinTuvshoo/gerege-ai-agent/actions/runs/43991938565) on `dfeaef3` also green |
| 12 mandated regression tests | **PASS — 12 of 12 implemented** | `tests/test_e01_tenant_isolation.py` |

### The 12 regression tests

All 12 are implemented in `tests/test_e01_tenant_isolation.py` and pass on SQLite and PG16.

| # | Test | Asserts |
|---|---|---|
| 1 | `test_acme_customer_gives_their_phone_and_globex_never_sees_it` | No cross-tenant PII |
| 2 | `test_each_tenant_keeps_its_own_conversation_row` | No tenant loses its own row |
| 3 | `test_message_count_and_last_message_are_per_tenant` | No count/last-message leak |
| 4 | `test_human_takeover_is_per_tenant` | Takeover state isolated |
| 5 | `test_globex_cannot_toggle_takeover_on_acmes_session` | Refusal **and** Acme's state unchanged |
| 6 | `test_globex_cannot_send_into_acmes_session` | Refusal **and** nothing in Acme's transcript |
| 7 | `test_shared_sender_writes_only_touch_the_calling_tenants_row` | Own-row write succeeds, other row untouched |
| 8 | `test_session_identity_is_tenant_scoped_in_the_schema` | DB rejects duplicate `(page_id, sender_id)` |
| 9 | `test_message_bodies_are_not_mixed_between_tenants` | No message **body** crosses tenants |
| 10 | `test_admin_cross_tenant_view_is_explicit_and_client_scope_still_denied` | Admin all-branch view works; client scope still 403 |
| 11 | `test_concurrent_writes_from_two_tenants_do_not_collide` | 4 threads × 10 writes: no collision, no overwrite |
| 12 | `test_migration_replay_preserves_rows` | `0003→0004→0003→0004` twice, rows identical |

Tests 5 and 6 were **strengthened after the first fix attempt**: they originally asserted
only a non-200, which passed for the wrong reason because a tenant legitimately owns its
own row for a shared sender — the refusal must be tested against a sender the caller does
not own. Their preconditions were also vacuous before (asserted against an empty list).

Test 10 caught a **regression I introduced**: making `get_active_sessions` fail closed on a
missing `page_id` broke the admin "all branches" view with a 500. That path is now an
explicit per-tenant aggregate.

### Rollback

`alembic downgrade 0003_foreign_keys` (refuses on tenant collision), then
`git revert dfeaef3`, or restore the pre-migration backup. Full detail in the E-01 report.

---

## E-02 Phase 3 — trusted-proxy client IP (P0, partial)

### What was wrong

`client_identity()` returned the left-most `X-Forwarded-For` with no trust check. Worse,
`request.client.host` was **not** the TCP peer: uvicorn's default
`forwarded_allow_ips="127.0.0.1,::1"` rewrote `scope["client"]` from the same header,
taking the right-most entry without validating it. Two parsers, two answers, both
attacker-influenced.

### What was fixed

`--no-proxy-headers` on the production command, so `scope["client"]` is the real socket
peer; and `resolve_client_ip()` as the single authority, driven by `TRUSTED_PROXIES`
(empty = trust nothing, `*` and `0.0.0.0/0` rejected, IPv4/IPv6/CIDR, bounded hops and
bytes, junk aborts to the peer).

### Acceptance criteria — Phase 3 only

| Criterion | Result |
|---|---|
| Environment-variable configuration only | **PASS** |
| Default trusts nothing | **PASS** |
| Direct XFF / X-Real-IP / Forwarded spoofing cannot change identity | **PASS** |
| Trusted chain resolved correctly, incl. multi-hop and spoofed prefix | **PASS** |
| uvicorn and app follow one policy | **PASS** |
| IPv4 / IPv6 | **PASS** |
| Malformed headers | **PASS** |
| Real uvicorn HTTP | **PASS** with Redis; **FAIL** without (R1, E-03) |
| SQLite / PostgreSQL regression | **PASS** |
| E-01 regression | **PASS** 12/12 |
| CI | **PASS** — [`44000307785`](https://github.com/AriukagiinTuvshoo/gerege-ai-agent/actions/runs/44000307785) on `d39fac6`, all steps green incl. Docker build (step conclusions only; log text unreachable) |
| Account-level protection | **NOT IMPLEMENTED** — Phase 4 |

**E-02 is NOT complete and SEC-07 remains FAIL.**

### Corrected test count

The Phase 2 report said "20 tests". The file defines **21** test functions (mandated case 11
was split into `test_11` and `test_11b`). Both environment totals — SQLite 15+4+2,
PostgreSQL 16+5 — equal 21 and were correct. Full per-test table in the E-02 report.

`test_20` passes pre-fix because Redis already shares whatever is counted; it is left
passing deliberately. After Phase 4 it keeps its green result but asserts that the
*account* counter survives a restart rather than an arbitrary key.

## Outstanding across Stage E

* E-02: 0/13 rotating-`X-Forwarded-For` bypasses still succeed on a real uvicorn; no
  account-level lockout (SEC-07 is **FAIL**, not fixed by E-01).
* E-03: Redis failure still fails open, and `/api/health` still reports
  `rate_limits_shared_across_workers: true` when it is not.
* E-04: webhook processing still claims before processing, with a 14-day swallow window.
* Integrations remain `NOT TESTED` without credentials — which blocks any production
  approval regardless of the score.
* Score remains **63.0/100**; E-01 does not change the rubric until the remaining Steps
  land and are re-scored.
