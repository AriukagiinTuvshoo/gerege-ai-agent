# Phase 44 — Independent Final PR Audit & Release Readiness Assessment

**Repository** `AriukagiinTuvshoo/gerege-ai-agent`
**Audit type** read-only, independent. No code, test, workflow or database was modified.
**Date** 2026-11-16

---

## STEP 0 — Baseline (verified directly, not quoted from earlier reports)

| Item | Value | Expected | Match |
|---|---|---|---|
| Branch | `arena/d78ebf88-gerege-ai-agent` | same | ✅ |
| Local HEAD | `f65a4609b4acf48f33a39feefd33272447ff08aa` | `f65a460` | ✅ |
| Remote branch HEAD | `f65a4609b4acf48f33a39feefd33272447ff08aa` | `f65a460` | ✅ |
| `main` (local + remote) | `48e9c6f7392729bc87d0c810553ff459a919dbfb` | `48e9c6f` | ✅ |
| PR #1 | OPEN, head `f65a460`, base `main`, `mergedAt=null`, `MERGEABLE`/`CLEAN` | OPEN | ✅ |
| Latest CI run | `45594693508`, success, `head_sha=f65a460…`, attempt 1 | `45594693508` | ✅ |
| Working tree | only untracked `PHASE43_REPORT.md` | same | ✅ |
| Force push history | reflog shows three plain `update by push` | none | ✅ |

**No baseline divergence.** This audit was performed against exactly the state Phase 43 reported.

---

## STEP 1 — Full PR change inventory

**186 commits, 224 changed files, +71,710 / −1,066** (`main..HEAD`). 180 added, 44 modified, 0 deleted.

| Area | Files | Notable content |
|---|---|---|
| `tests/` | 82 | 87 test modules total; 76 security/phase suites |
| `docs/` | 61 | deployment, operations, security, audit, testing |
| `core/` | 25 | backup×7, `security.py`, `pinned_http.py`, `rate_limit.py`, `worker_heartbeat.py`, `db_engine.py`, `login_identity.py`, `audit_integrity.py`, `redaction.py` |
| `scripts/` | 15 | `provision_roles.py`, `maintenance.py`, `check_pytest_log.py`, `validate_workflows.py`, `deploy.sh`, `rollback.sh` |
| `migrations/` | 9 | `0002_schema_authority` → `0007_audit_append_only` + `sqlite_compat.py`, `_schema_targets.py` |
| `deploy/` | 5 | Caddyfile ×2, systemd unit + timer, backup cron |
| root | 21 | `main.py`, `database.py`, `agent.py`, `worker.py`, Dockerfiles, compose ×2, `requirements*`, `vercel.json`, phase reports |
| `.github/` | 1 | `ci.yml` (only workflow) |

### Security-sensitive areas inspected

- **Authn / authz** — `core/security.py` (`enforce_tenant_scope`, `verify_resource_tenant_ownership`, webhook verification), `core/login_identity.py`, migration `0006`.
- **Tenant isolation** — `pages.page_id` is the tenant key; 13 tables carry it with FK to `pages` (`0003`), all `ON DELETE CASCADE` except `audit_logs` (`SET NULL`).
- **Database / migrations** — 7 revisions, drift gate via `compare_metadata`.
- **Roles / grants** — `scripts/provision_roles.py`, `core/db_privileges.py`, migration `0007`.
- **Backup / restore** — `core/backup_crypto.py` (AES-256-GCM), `backup_offsite.py`, `backup_archive.py`, `backup_staging.py`, `verify_backup_confidentiality.py`.
- **Workers / schedulers** — `worker_heartbeat.py`, `task_queue.py`, `scheduler_setup.py`, systemd unit/timer.
- **SSRF / egress** — `pinned_http.py`, `outbound_http.py`.
- **CI** — single workflow, 66 steps, 30 count/skip gates.

---

## STEP 2 — Re-audit of historical findings (Phases 32–43)

Each row verified against **current code**, not against a prior report.

| # | Finding | Actual current evidence | Test evidence | Status |
|---|---|---|---|---|
| 1 | **Cross-tenant data leakage (E-01)** | `database.py:1194` session upsert is tenant-scoped; `/api/chat` derives `page_id` from body for anonymous widgets but all reads are filtered by `page_id` | `test_e01_tenant_isolation.py` — 26 cases incl. the Acme→Globex phone-leak sequence | **FIXED** |
| 2 | **Cross-tenant IDOR** | `verify_resource_tenant_ownership` returns 403 on `pageB` for a `pageA` user — measured | `test_enterprise_phases.py::test_phase1_cross_tenant_idor_protection` | **PARTIAL** — see F-44-A |
| 3 | **Telegram token / webhook security** | `verify_telegram_webhook_secret` uses `hmac.compare_digest`; fail-closed on `ENV=production`/`WEBHOOK_FAIL_CLOSED` — measured `False` in prod with no secret | covered by webhook suites | **FIXED** (signature path) |
| 4 | **Meta `hub.verify_token`** | `main.py:507` `os.getenv("META_VERIFY_TOKEN", "agent_verify_secret_token_123")` — a publicly known fallback, **no production guard** | none | **OPEN** — F-44-B |
| 5 | **SSRF / DNS pinning** | `pinned_http.py` dials the pinned IP, refuses proxies, fails closed on unpinned path | `test_e30_ssrf_pinning.py` + `test_e07_phase28` — pass | **FIXED** |
| 6 | **SQL injection / dynamic identifiers** | All `f"…{ident}"` sites are module constants or `int()`-coerced; each carries a `# nosec B608` justification | `test_e07_phase26_sql_injection.py` — pass | **FIXED** |
| 7 | **Worker heartbeat / crash detection** | `read()` returns `unknown` when Redis is down; per-worker keys; `stale` vs `missing` distinct | `test_e41_worker_heartbeat_isolation.py` — 42/42 | **FIXED** |
| 8 | **Duplicate job execution** | `task_queue.py` atomic claim via `locked_by`/`locked_at` + visibility timeout + stale `PROCESSING` reclaim | `test_p0_connection_pool_leak`, e41 | **FIXED** |
| 9 | **Backup confidentiality / restore integrity** | AES-256-GCM, header records `cipher`; plaintext publish blocked at the CLI | `test_e36_backup_operations` + `test_e06_phase18` — 49 passed | **FIXED** |
| 10 | **PostgreSQL role ownership / grants** | Reproduced the full sequence on `p44_audit`: 7 migrations, `verify rc=0`, `tableowner=gerege_owner`; `gerege_app` is non-superuser with **no** UPDATE/DELETE on `audit_logs` but INSERT on `pages` | `test_p0_security_role_escalation` | **FIXED** |
| 11 | **Phase 43 skip gate** | `check_pytest_log.py` requires the name on a `PASSED` line; negative controls reproduce both skip and missing-name rejections (`rc=1`) | `test_e43` + `test_e29` — 55/55 | **FIXED** |
| 12 | **Phase 20 provisioning order** | `ci.yml:1428-1452` = provision → migrate → provision → verify → owner assertion; step ran 7 s and passed in CI | e43 ordering test (fails on the old order: `assert 16 < 15`) | **FIXED** |

---

## STEP 3 — Independent CI integrity audit

Audited `ci.yml` by parsing all 66 steps, not by reading the badge.

### Verified controls

| Requirement | Result | Evidence |
|---|---|---|
| Failures cannot be masked by pipelines | **PASS** | 25 steps use `pytest … \| tee`; **all 25** carry `set -euo pipefail`. The other **15** pytest steps use a bare `pytest` with **no pipe at all** — measured: 0 pytest lines contain a pipe without `pipefail`. |
| No silent `continue-on-error` | **PASS** | exactly 1 occurrence, on the advisory base-image-digest step which ends `exit 0` by design. |
| Required tests must actually PASS | **PASS** | `--require-run` matches a `PASSED` line and is independent of `--no-skip-check`; verified `rc=1` for a missing name. |
| Skip gate cannot be silently disabled | **PASS** | policy locked by `test_e29_ci_integrity.EXPECTED_POLICY` for `p20suite` and `p4`. |
| PostgreSQL tests get a disposable DB | **PASS** | 15 live-PG steps receive an explicit `DATABASE_URL`; on a dead port they **fail** (measured: 8 of 10 fail, 2 error, the 2 that pass do not use the DB). |
| Destructive tests need explicit opt-in | **PASS** | `GEREGE_DESTRUCTIVE_TESTS=1` on the p20 step only; guards now `pytest.skip()`, so absence fails the gate. |
| Env-gated tests reported honestly | **PASS (with a documented gap)** | offsite cases run against **moto** (`127.0.0.1:5062`), not real S3; 34 would skip without it. |
| Thresholds not weakened | **PASS** | p20 floor still **24** (measured run 32); no floor lowered in this PR. |
| Exact head SHA | **PASS with a nuance** | `run.head_sha = f65a460`; check-run attaches to `f65a460`. `main` (`48e9c6f`) is a **direct ancestor**, so the PR merge commit is a fast-forward and its tree is byte-identical to `f65a460`. Review approval does **not** invalidate the run. |

### CI findings

- **F-44-C (MEDIUM).** `tests/test_postgres_restore_real_rollback.py` guards six cases with `print("[SKIP]"); return`. Measured: with `DATABASE_URL` unset the step reports **8 passed** while doing nothing. Not currently exploitable — the step hardcodes a valid `DATABASE_URL` — but a broken service container would silently turn it green. This is the same defect Phase 43 fixed elsewhere; it was left out of scope deliberately.
- **F-44-D (LOW).** 57 of 66 steps use `if: ${{ !cancelled() }}`, so all steps run even after a failure. Correct for coverage, and the job still reports failure — **empirically confirmed** by run `45580262153` (step 31 failed → job `failure`). No aggregate guard exists, which is worth knowing but not a defect.

---

## STEP 4 — Production / staging readiness

### A. Verified locally or in CI

- Full suite on the real stack: **1868 passed, 0 failed, 53 skipped, 1 xfailed** (665 s), reproduced twice.
- Migration chain `0001 → 0007` applies cleanly on PostgreSQL 16 with zero drift; FK set present.
- Role provisioning idempotent and verified; least privilege measured in SQL.
- AES-256-GCM backup/restore round trip; 32/32 Phase 20 cases on a real PostgreSQL database.
- SSRF pinning, SQL-injection refusals, tenant isolation, IDOR 403, worker heartbeat.
- Docker image builds; staging stack rehearsed in **real containers** with a `.invalid` domain.
- Caddyfiles parsed by the real `caddy validate` binary.

### B. Requires external staging verification — **NOT VERIFIED**

| Item | Why it cannot be closed here |
|---|---|
| **DNS** | Rehearsal uses `STAGING_DOMAIN=…​.invalid`; no real zone was ever resolved. |
| **TLS / ACME** | No ACME endpoint contacted by design. Certificate issuance, renewal and the HTTP-01 / TLS-ALPN challenge path are untested. |
| **External staging deploy** | CI rehearses containers locally; no external host, no real ingress, no real DNS propagation. |
| **Real S3 backup/restore drill** | CI uses **moto** (in-memory). `BACKUP_OFFSITE_ENDPOINT` was never pointed at a real bucket; durability, IAM policy, lifecycle rules and cross-region copy are unexercised. |
| **Alert to a real human** | `BACKUP_ALERT_WEBHOOK=""` throughout CI; delivery to a real chat/on-call endpoint never happened. |

### C. Requires real infrastructure or operator confirmation — **NOT VERIFIED**

| Item | Note |
|---|---|
| Secrets & environment | Templates leave every secret blank with a `generate:` hint, and the code enforces the admin password in production — but no real secret store, rotation drill or leak-scan of the deployed environment exists. |
| DB capacity & connection limits | `core/db_engine.py` computes a budget against `PG_MAX_CONNECTIONS`; the real server's value, disk headroom and growth are unknown. |
| Monitoring & incident response | `docs/operations/INCIDENT_RESPONSE.md` and `/api/monitoring` exist; no real pager route, no on-call rotation, no alert-fatigue test. |
| Recovery procedures & ownership | `DISASTER_RECOVERY.md` + `BACKUP_RESTORE.md` exist; nobody has executed them against production-like infrastructure, and no named owner is recorded. |

---

## STEP 5 — Risk assessment

| ID | Finding | Severity | Impact | Likelihood | Evidence | Recommended action |
|---|---|---|---|---|---|---|
| **F-44-A** | `verify_resource_tenant_ownership` **allows** when `resource_page_id` is `None` (measured: `None` → ALLOWED, `''` → ALLOWED). `registrations.page_id` is **nullable** (`is_nullable=YES` measured). | **LOW** (was tentatively HIGH — downgraded, see note) | A lead with a NULL `page_id` would be readable/updatable by any authenticated tenant-scoped user who guesses its integer id. | Very low: every writer passes `page_id`, the column has a non-null default, and IDs are sequential only within a tenant's view. | Direct call: `None`/`''` → no 403. Schema: nullable. | Make the guard fail closed (`if not resource_page_id: 403`) **and** add `NOT NULL` to `registrations.page_id` in a migration. Small, contained change. |
| **F-44-B** | Meta `hub.verify_token` falls back to the public string `agent_verify_secret_token_123` with **no production guard** (measured under `ENV=production`). | **MEDIUM** | An attacker can complete the GET `/webhook` subscription handshake. It does **not** grant event delivery (POST requires `X-Hub-Signature-256`, which *is* fail-closed), so impact is limited to a bogus subscription/DoS surface. | Medium: the string is in this repository and in every default install. | `main.py:187`, `:507`, `:1065`; measured fallback. | Refuse to start (or 403 the handshake) in production when `META_VERIFY_TOKEN` is unset or equals the default, mirroring `_verify_admin_password`'s existing fail-closed pattern. |
| **F-44-C** | `test_postgres_restore_real_rollback.py` uses `print("[SKIP]"); return` ×6. | **MEDIUM** | A broken PG service would render the step **8 passed** while verifying nothing — exactly the F-42-B class of defect. | Low today (hardcoded valid URL) but zero-cost to fix. | Measured: `env -u DATABASE_URL` → 8 passed. | Convert to `pytest.skip()` and add the step to the skip gate with a documented exception list. Same change Phase 43 made for the p20 module. |
| **F-44-D** | No aggregate `always()` guard; 57 steps rely on `!cancelled()`. | **LOW** | Theoretical: a future step added with `continue-on-error` could hide a failure. | Very low: GitHub still fails the job (proven in run `45580262153`). | Step-conclusion audit + that run. | Optional: add a final step asserting every prior step's `outcome == 'success'`. |
| **F-44-E** | Real S3, real DNS/TLS, real alert recipient never exercised. | **HIGH** (for *release*, not for *code*) | Backup durability, certificate issuance and paging are unproven in the environment that will run them. First production incident would be the first test. | Medium: these are the classic "works in CI, fails in prod" areas. | CI uses moto and `.invalid`. | Mandatory staged drill before general availability — see next phase. |
| **F-44-F** | Production secret provisioning rests on documentation, not enforcement (except `ADMIN_PASSWORD`). | **MEDIUM** | A missed line in `PRODUCTION_ENV_TEMPLATE.env` yields a working system with a guessed default (`META_VERIFY_TOKEN`, `verify_token` column). | Medium. | Template comments vs. code defaults. | Extend the existing startup fail-closed checks to every secret that has a public fallback. |

**Not inflated:** items 1, 3, 5, 7, 8, 9, 10, 11, 12 in STEP 2 are genuinely closed, with behavioural evidence in both directions. **Not minimized:** F-44-A was initially rated HIGH and downgraded only after measuring that no code path writes a NULL `page_id`; the guard is still wrong and is trivially reachable if one ever does.

---

## STEP 6 — Final verdicts

### 1. PR code quality: **CONDITIONAL PASS**

The engineering is strong and — unusually — the *evidence* is strong: negative controls in both directions, gates on the gates, a skip gate that catches its own blind spot, and least privilege measured in SQL rather than asserted.

It is not an unconditional PASS because three defects survive in shipped code:

- **F-44-A** — a tenant guard that opens on a NULL/empty value, against a nullable column.
- **F-44-B** — a security-relevant secret with a public fallback and no production guard.
- **F-44-C** — a test module that reports success while doing nothing if its database is absent.

All three are small, well-understood, and individually fixable in a single follow-up commit. None is architectural.

### 2. Production readiness: **NOT READY**

Different question, different answer, and the difference matters:

> **CONDITIONAL PASS** answers *"is this code good enough to merge?"* — yes, with the three fixes above, because everything it claims is verified by tests that would fail if the claim were false.
>
> **NOT READY** answers *"can this carry real traffic tomorrow?"* — no, because the three things that most often break in production are **unverified**: real S3 durability, real DNS/TLS certificate issuance and renewal, and whether an alert actually reaches a human at 03:00. No amount of unit-test quality substitutes for those.

Code quality and deployment readiness are independent axes here. The first is largely earned; the second has no evidence at all. Marking production **READY** would require exactly the external drills listed in STEP 4B, and **none has been run**. Per this phase's own rule — *never mark an external check PASS without evidence* — **NOT READY / NOT VERIFIED** is the only defensible answer.

---

## Remaining blockers before merge (code)

1. **F-44-A** — fail closed on a missing `page_id`; make `registrations.page_id NOT NULL`.
2. **F-44-B** — refuse to serve the Meta handshake with a default/unset `META_VERIFY_TOKEN` in production.
3. **F-44-C** — convert the six `print("[SKIP]"); return` guards to `pytest.skip()`.

## Remaining blockers before production (infrastructure)

4. **F-44-E** — a real-S3 backup + restore drill, including a restore into an empty environment.
5. Real DNS + ACME issuance **and** a renewal cycle.
6. A real alert delivered to a named on-call recipient, with a documented acknowledgement.
7. Confirmation of DB capacity, `max_connections`, disk headroom, and a named operational owner.

---

## Evidence and limitations

**What this audit actually observed**

- Direct `git`/`gh` state, the full `main..HEAD` diff, and a line-by-line parse of all 66 CI steps.
- Live execution: full suite (1868 passed ×2), 213 security-domain cases, role provisioning on a fresh `p44_audit` database, SQL privilege queries, and five targeted negative controls.
- Targeted reproductions of `verify_resource_tenant_ownership(None)`, the Meta verify-token fallback, and the `print("[SKIP]")` module.

**What it could not observe**

- **CI job logs are not retrievable from this sandbox.** `gh api …/logs` and `gh run view --log` both return `EOF` from `results-receiver.actions.githubusercontent.com`, which is outside the egress allowlist. Run `45594693508` is therefore characterised by step conclusions (72/72 success), the exact head SHA, and the absence of any error annotation — **not** by its printed pytest summary. The 32-test p20 figure is a local reproduction of the identical step flow, labelled as such.
- No access to production, staging, DNS, TLS, S3, or any paging system. Everything in STEP 4B/4C is **NOT VERIFIED**, by construction.
- `scratch/` e2e scripts (`test_cargo_lookup.py` and siblings) require external APIs and were excluded from the suite run; they are pre-existing on `main` and untouched by this PR.

---

## Recommended next phase

**Phase 45 — Close the three code findings, then run the first real infrastructure drill.**

Suggested split, smallest first:

1. **Phase 45A (code, ~1 commit)** — F-44-A + F-44-B + F-44-C, each with a regression test that fails before the fix. All three are guard-shaped changes; none touches the schema except adding `NOT NULL`, which needs a backfill check.
2. **Phase 45B (infrastructure, requires credentials the audit environment must not hold)** — real S3 round trip, real DNS/TLS issuance and renewal, one real alert to a human, and a recorded restore drill against a disposable production-shaped database.
3. **Phase 45C** — operator sign-off: named owner for backups and on-call, capacity confirmation, and a re-run of this audit's STEP 4B checklist.

Only after 45B and 45C should production readiness be re-assessed — and it should be re-assessed by evidence, not by elapsed time.

---

## Audit attestation

No merge. No push. No deploy. No code, workflow, test or database modified. `main` untouched at `48e9c6f`. PR #1 still OPEN at `f65a460`. The only file this audit wrote is `PHASE44_REPORT.md`; all temporary databases (`p44_audit`, probes) are disposable and were created solely for measurement.

**PR code quality: CONDITIONAL PASS · Production readiness: NOT READY**
