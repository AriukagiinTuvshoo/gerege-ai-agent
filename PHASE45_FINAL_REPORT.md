# PHASE 45 — FINAL HARDENING, STAGING VALIDATION & SIGN-OFF

**Date:** 2026-11-25 (UTC)
**Branch:** `arena/d78ebf88-gerege-ai-agent`
**PR:** #1 (OPEN, unmerged, base `main`)

---

## 1. Initial and final SHAs

| Item | SHA |
|---|---|
| Initial HEAD (Phase 45 baseline) | `f65a4609b4acf48f33a39feefd33272447ff08aa` |
| Final HEAD (Phase 45A commit, pushed) | `5402ab9174264b2b42620468ba197bb83732946d` |
| `main` (unchanged throughout) | `48e9c6f7392729bc87d0c810553ff459a919dbfb` |
| Remote branch tip after push | `5402ab9174264b2b42620468ba197bb83732946d` (== local HEAD) |

One commit was added on the feature branch (`5402ab9`, 8 files, +1269/−23). No force
push, no history rewrite: the previous remote tip `f65a460` is a direct ancestor of
`5402ab9` (fast-forward). `main` was never modified; PR #1 was never merged.

---

## 2. F-44-A/B/C/F resolution evidence

### F-44-A — IDOR guard bypass via `None`/empty resource page ID → **RESOLVED**

- `core/security.py::verify_resource_tenant_ownership` now fails closed on `None`,
  empty, whitespace-only, and malformed resource page IDs instead of silently
  bypassing tenant ownership. All callers were inspected (lead and appointment
  paths in `main.py:1488` and `main.py:2757`); both pass the looked-up record's
  `page_id`, so a nullable record now yields 403 rather than an unguarded read.
- `registrations.page_id` is now `NOT NULL` at the model layer
  (`core/models.py`) and in the database via migration
  `0008_registration_tenant_not_null` (PostgreSQL `ALTER TABLE`; SQLite table
  rebuild that preserves every column's type/NOT NULL/default/PK, all indexes,
  triggers, and foreign keys).
- Public widget behaviour is unchanged (the guard is only applied to
  authenticated resource access).
- Verified: fresh PostgreSQL database → provision roles → `alembic upgrade head`
  (8 migrations) → downgrade to `0007` → re-upgrade → `registrations.page_id`
  `is_nullable=NO`; SQLite drift report `has_drift=False, count=0`.

### F-44-B — Meta `hub.verify_token` public fallback → **RESOLVED**

- The public/default fallback token was removed from the production path.
  `core/security.py::meta_verify_token_is_usable` is the single decision point:
  in production an unset, empty, whitespace, or published-placeholder token makes
  GET `/webhook` answer 403 and log the refusal. Comparison is constant-time
  (`hmac.compare_digest`); no token value appears in responses or logs.
- Development/test keeps a usable default only outside production.
- The token is enforced at the endpoint rather than at startup, deliberately: it
  only matters to Meta traffic, so a deployment without the Meta integration still
  starts. This placement is pinned by a test
  (`test_admin_password_is_enforced_elsewhere_not_duplicated` asserts both
  `ADMIN_PASSWORD` and `META_VERIFY_TOKEN` are in `SECRETS_ENFORCED_ELSEWHERE`
  and absent from `REQUIRED_PRODUCTION_SECRETS`).

### F-44-C — `print("[SKIP]"); return` false PASSED → **RESOLVED**

- `tests/test_postgres_restore_real_rollback.py` no longer prints `[SKIP]` and
  returns. It uses `pytest.skip()` with an explicit reason; the skip-gate tests
  assert the skip is reported as *skipped*, never as passed, and that a genuine
  failure remains a failure.
- CI provides a real disposable PostgreSQL 16 target and the suite runs for real
  there (step "Run P0-2 PostgreSQL Real Restore Rollback Suite" — success in run
  `45625942590`).

### F-44-F — Secret enforcement documented but not enforced → **RESOLVED**

- New `core/secret_guard.py`: at startup (as the **last** lifespan guard, so it
  cannot mask more specific diagnoses such as a missing `REDIS_URL`) production
  secrets are validated. Missing, empty, placeholder, or weak values abort
  startup with the variable name and reason only — never the value.
- Required at startup: `E02_ACCOUNT_KEY_SECRET`. Conditional (required only when
  the integration is configured): `META_APP_SECRET` (← `META_VERIFY_TOKEN`),
  `TELEGRAM_WEBHOOK_SECRET` (← `TELEGRAM_BOT_TOKEN`),
  `BACKUP_OFFSITE_SECRET_KEY` (← `BACKUP_OFFSITE_ENDPOINT`).
- Delegated to the point of use and recorded in `SECRETS_ENFORCED_ELSEWHERE`:
  `ADMIN_PASSWORD` (`database.authenticate_admin` refuses the default in
  production) and `META_VERIFY_TOKEN` (F-44-B endpoint check). Duplicating these
  in the startup sweep was measured to break unrelated suites while adding no
  protection.

---

## 3. Regression test results

`tests/test_e45_final_hardening.py` — **54 tests, all passing**, covering:

- **A1 (IDOR):** valid same-tenant allowed; cross-tenant 403; `None` page ID 403;
  empty/whitespace 403; missing resource 403; nullable DB record 403; public
  widget unchanged.
- **A2 (verify token):** production + missing/empty/whitespace/placeholder token
  → 403 and no challenge echoed; production + valid token → 200 with challenge;
  wrong token → 403; dev/test behaviour usable; no accidental public fallback.
- **A3 (skip honesty):** missing PostgreSQL → skipped with reason, never passed;
  required CI execution cannot silently skip; genuine failure stays failure.
- **A4 (secrets):** missing/empty/placeholder/weak production secrets abort
  startup naming the variable and reason; a strong generated value passes; the
  error message never contains the secret value.

**Negative controls** (run against reverted vulnerable code, then restored):
reverting the IDOR guard → 4 failed/6 passed; restoring the public fallback
token → fallback test failed; restoring `print("[SKIP]"); return` → 3 failed;
deleting the startup hook line → `test_startup_hook_is_wired` failed. All four
controls fired; final state 54/54.

---

## 4. Full suite results and skip reasons

Local full suite (SQLite mode, `--ignore=scratch`, live Redis, PostgreSQL
available):

```
1916 passed, 59 skipped, 1 xfailed, 0 failed   (671s)
```

Focused suites: skip-gate + CI-integrity + e45 → **109 passed**.
`pip-audit -r requirements.txt` → **No known vulnerabilities found**.
`scripts/validate_workflows.py` → OK (1 file). `alembic heads` → single head
`0008_tenant_not_null`. Schema drift (SQLite and PostgreSQL) → zero.

The 59 skips are pre-existing, documented, and unchanged by Phase 45 (they are
environment-conditional tests, e.g. requiring live external services); no test
was converted from failure to skip and no test floor was lowered. During the
45A work the full suite was run five times; every intermediate failure was
traced to a Phase 45 edit (migration rebuild, startup-guard ordering, fixture
scope) and fixed — none was a pre-existing defect and none was hidden.

---

## 5. CI run IDs and exact tested SHAs

| Run | SHA tested | Result |
|---|---|---|
| `45594693508` (baseline) | `f65a460` | success |
| **`45625942590`** | **`5402ab9174264b2b42620468ba197bb83732946d`** | **success** |

Run `45625942590` executed on the exact pushed SHA. The single required job
`test-and-security-audit` concluded **success**; all 70+ steps passed, including
Dependency Vulnerability Audit, zero schema drift (SQLite + PostgreSQL 16),
migration integrity, the P0-2 real PostgreSQL restore-rollback suite, Phase 20
backup confidentiality, Phase 39 staging rehearsal (real containers, disposable
stack), and the production Docker image build. Phase 20 and Phase 43
protections remain active (their steps are present and green). No unexpected
skips were reported by the check run.

---

## 6. DNS/TLS/ACME results — **NOT VERIFIED**

Real check performed 2026-11-25:

- The only staging domain referenced anywhere in the codebase,
  `staging.example.mn`, resolves to **NXDOMAIN** (`socket.gethostbyname` →
  `gaierror: Name or service not known`).
- No staging domain, no TLS certificate, no ACME configuration, and no reverse
  proxy deployment exist in this environment. The Caddyfile validation steps in
  CI validate configuration syntax only; they are not evidence of a real
  certificate.

**Classification: NOT VERIFIED.** No real DNS/TLS evidence can be produced
without a provisioned staging domain, which requires explicit authorization to
create external infrastructure.

---

## 7. Real S3 backup and restore results — **BLOCKED**

Real check performed 2026-11-25:

- `BACKUP_OFFSITE_ENDPOINT` — not set.
- `BACKUP_OFFSITE_SECRET_KEY` — not set.
- AWS credentials (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`) — absent.

No staging bucket or staging-only credentials exist. The backup suite's
offsite/S3 coverage runs against Moto mocks in CI, which is not evidence of real
S3 behaviour. No backup was created against, or restored from, any real object
store in Phase 45.

**Classification: BLOCKED** (missing staging bucket + credentials). Nothing was
invented; no existing backup or production object was touched.

---

## 8. Real alert delivery results — **BLOCKED**

Real check performed 2026-11-25:

- `BACKUP_ALERT_WEBHOOK` — not set. No staging-only alert destination or human
  recipient is configured anywhere in the environment.

A successful HTTP response to an empty/mock webhook would not prove human alert
delivery, and no such claim is made.

**Classification: BLOCKED** (no recipient/destination configured).

---

## 9. Staging rehearsal results — **NOT VERIFIED**

No authorized staging environment exists in this environment (no staging
domain, no staging credentials, no staging bucket, no alert destination), so no
staging deployment, health check, authentication/tenant-isolation rehearsal,
worker/scheduler rehearsal, or graceful-restart rehearsal could be performed.
CI's Phase 39 step rehearses a disposable container stack locally; that is
useful engineering evidence but is not a staging environment.

**Classification: NOT VERIFIED.**

---

## 10. Remaining risks and blockers

1. **No staging environment exists.** DNS/TLS/ACME, real S3 backup/restore,
   human alert delivery, and the staging rehearsal are all BLOCKED/NOT VERIFIED
   (F-44-E remains open by necessity, not by oversight).
2. **Provisioning staging requires authorization.** Creating a domain, TLS
   certificate, S3 bucket, or alert destination is external infrastructure
   modification and was not attempted.
3. **Dependency ranges, not exact pins.** `requirements.txt` uses floors with
   upper bounds; `pip-audit` is clean today, but reproducible builds depend on
   the Docker build's locked set. The base image is digest-pinnable via
   `BASE_IMAGE` build-arg and CI reports pinned digests.
4. **Secret sweep scope.** `E02_ACCOUNT_KEY_SECRET` is the only secret whose
   absence aborts startup. `META_VERIFY_TOKEN` and `ADMIN_PASSWORD` are enforced
   at their point of use; if a future endpoint consumes a new secret without a
   point-of-use check, it must be added to `REQUIRED_PRODUCTION_SECRETS` or
   `CONDITIONAL_SECRETS`.
5. **59 pre-existing skips** remain environment-conditional; they are documented
   but mean some coverage only materializes in CI's live-service steps.

---

## 11. Code quality verdict — **PASS**

All four Phase 44 code findings (F-44-A/B/C/F) are closed with regression tests
and negative controls. Full local suite: 1916 passed / 0 failed. CI on the exact
pushed SHA: success, all steps green. Independent re-audit (45C) found no new
critical/high issue: admin authentication fails closed in production, tenant
guard callers are exactly the two authenticated resource paths, webhook
verification is fail-closed in production, no f-string SQL reaches user input
(the five `f"SELECT …"` sites interpolate module-constant table names only),
SSRF pinning and loopback/link-local rejection are in place, backup encryption
is policy-enforced before anything is published, role provisioning revokes and
grants least-privilege, and the CI skip-gate passes (35 tests).

---

## 12. Staging readiness verdict — **NOT VERIFIED**

There is no staging environment to be ready against. Every 45B item is BLOCKED
or NOT VERIFIED for lack of a domain, bucket, credentials, and recipient.

---

## 13. Production readiness verdict — **NOT READY**

The code is in good shape, but production readiness requires real infrastructure
evidence (DNS/TLS, real S3 backup/restore, real alert delivery, staging
rehearsal) that does not exist. Claiming READY on a green CI badge alone would
be exactly the error this phase exists to prevent.

---

## 14. Exact next action required

**Authorize provisioning of a staging environment** (or provide existing
staging-only credentials and a staging domain), then re-run 45B B1–B4 against
it. Concretely, the minimum needed to unblock:

1. A real staging domain under project control (for DNS/TLS/ACME evidence).
2. A dedicated staging S3 bucket + staging-only credentials (for real
   backup/restore evidence).
3. A staging-only alert destination controlled by the project owner (for real
   alert-delivery evidence).

Until then, the correct status is: **code PASS, staging NOT VERIFIED,
production NOT READY**, with PR #1 open and unmerged on `5402ab9`.

---

## Appendix — evidence classification

- **Verified facts:** SHAs, branch/PR state, CI run `45625942590` success on
  `5402ab9`, local suite counts, migration round-trip results, NXDOMAIN and
  unset-variable checks (commands and outputs recorded in §6–§8).
- **Test evidence:** `tests/test_e45_final_hardening.py` (54 tests), negative
  controls, skip-gate/CI-integrity suites, `pip-audit` clean.
- **External infrastructure evidence:** none — explicitly recorded as absent,
  not simulated.
- **Assumptions:** none material. Where a design choice was made (endpoint-layer
  enforcement for `META_VERIFY_TOKEN`, delegation for `ADMIN_PASSWORD`), the
  reasoning is documented in code and pinned by tests.
- **Blocked/unverified:** B1 DNS/TLS/ACME (NOT VERIFIED), B2 real S3 (BLOCKED),
  B3 alert delivery (BLOCKED), B4 staging rehearsal (NOT VERIFIED).
