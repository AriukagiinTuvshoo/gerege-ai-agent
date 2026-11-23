# PHASE 36 — Staging Hardening: Results

Baseline verified before any work: branch `arena/d78ebf88-gerege-ai-agent`, HEAD `c2ebf85`,
`main` `48e9c6f`, PR #1 OPEN, CI `45124631443` 66/66 success, tree clean, 0 unpushed. All
eight checks matched; nothing differed.

**Scope discipline:** no deployment, no external infrastructure, no DNS, no cloud
resources, no production credentials, no production data. Docker is not installed in this
environment and Docker Hub is outside the egress allowlist — that limitation is reported
honestly wherever it affects a result, rather than papered over.

---

## 1. What Phase 35 got right, and what it got wrong

An audit that cannot correct itself is not an audit. Two Phase 35 claims were wrong:

| Phase 35 claim | Reality |
|---|---|
| "No replacement host scheduler exists in the repository." | **Wrong.** `core/scheduler_setup.py` (Phase 24) is a complete, hardened systemd installer with `plan/install/validate/uninstall`, and `docs/SCHEDULER-SETUP.md` documents it. The gap was discoverability. |
| "Migration 0004 is irreversible." | **Too absolute.** It is *data-dependent*. With no cross-tenant `sender_id` collision the downgrade **succeeds** (measured: 0004 → 0003). With a collision it refuses and preserves both rows (measured: 2 rows before, 2 after). |

Both corrections are now documented in the code and the runbooks rather than left in a
report.

---

## 2. Defects found and fixed

### F-36-1 (High) — the application database pool had no connect timeout

`create_engine` for PostgreSQL passed `pool_size`, `max_overflow`, `pool_timeout`,
`pool_pre_ping`, `pool_recycle` — and **no `connect_args`**, so libpq had no
`connect_timeout`. `pool_timeout` only bounds waiting for a free *slot*; once a slot is
checked out, the TCP connect blocks on the OS stack.

Measured with a controlled comparison against an unroutable address:

| Path | Result |
|---|---|
| Backup path (`connect_timeout=10`) | `OperationalError` after **exactly 10.0 s** |
| Application pool (before fix) | **still running at 25 s**, killed by the harness |

`tcp_syn_retries=6` on this host means ~63 s before the OS gives up; a *stuck* slot is never
returned to the pool, so an unreachable database degrades into a stalled pool rather than a
clean error.

**Fixed:** `DB_CONNECT_TIMEOUT` (default 10) is now passed to the pool. Verified
behaviourally — the same probe now fails with `OperationalError` after **5.0 s** at
`DB_CONNECT_TIMEOUT=5`.

### F-36-2 (High) — no process knew its connection budget

Every process inherited the same 10+20 defaults regardless of what it does, and nothing
anywhere compared the total to `max_connections`. The worker was the worst offender: it
runs **one sequential asyncio loop** (`for job_id in candidates: await handler(...)`) and
can never use 30 connections.

| | Before | After |
|---|---|---|
| API (2 × 30) | 60 | 20 (2 × 10) |
| Worker | 30 | 4 (2+2) |
| Maintenance/migrate | 30 | 3 (2+1) |
| **Total required** | **120** | **27** |
| Usable (`max_connections=100` − 3 reserved) | 97 | 97 |
| **Headroom** | **−23** | **+70** |

**Fixed:** `DB_PROCESS_ROLE` (`api` / `worker` / `maintenance`) selects a per-role default;
`enforce_connection_budget()` runs at API and worker startup and **raises in production**
when the configuration cannot fit, warning loudly elsewhere. `PG_MAX_CONNECTIONS` and
`PG_SUPERUSER_RESERVED` make the server ceiling explicit in compose instead of an invisible
image default. Verified live: `connection budget OK: 27 required, 97 usable (headroom 70)`.

Four API instances now need 47 of 97 — real room to scale, which did not exist before.

### F-36-3 (High) — payment URLs would have been plaintext behind TLS

Nothing in the codebase read `X-Forwarded-Proto`, and the container runs uvicorn with
`--no-proxy-headers`. `request.base_url` is used to build the **QPay callback URL** and the
**payment page URL** (`fintech_service.py:354,402`), so the moment a TLS proxy was added
every generated payment link and callback would have been `http://`.

Measured before the fix: with `X-Forwarded-Proto: https` present,
`str(request.base_url)` returned `http://staging.example.mn/`.

**Fixed:** `core/rate_limit.resolve_request_scheme()` / `build_external_base_url()` use the
**same strict trust model as `resolve_client_ip`** — the header is honoured only when the
socket peer is a configured trusted proxy, the value is in `{http, https}`, and it is under
16 bytes. Six security cases verified:

| Case | Result |
|---|---|
| Untrusted peer claims https | `http` (spoof rejected) |
| Trusted proxy claims https | `https` |
| Trusted proxy, no header | `http` |
| `X-Forwarded-Proto: javascript` | `http` (bogus rejected) |
| `https, http` chain | `https` (left-most) |
| Oversized header | `http` (ignored) |

### F-36-4 (Medium) — `/api/health` grew with data; no cheap liveness existed

The endpoint materialised every registration and every page's sessions per call. Phase 35
measured 28 ms empty → 94.6 ms at 10k rows, and `deploy.sh` gated deploys on it.

**Fixed:**
* `/api/live` — constant cost, no dependencies, for container and LB liveness.
* `/api/health` — counts via fixed `COUNT(*)` statements. **Measured 6.5 ms at 5,000
  registrations** with identical counts (`total_leads=5000`), versus 94.6 ms before.
* `scripts/deploy.sh` now gates on `/api/ready` (6.6 ms) instead of the deep endpoint.

Deliberate detail: the count preserves the *previous* number exactly. The old code summed
`len(get_active_sessions(page))`, and that function returns every `session_states` row with
no `is_active` filter despite its name — so the total is simply the table's row count.
Adding a filter would have silently changed a reported figure while looking like a fix.

### F-36-5 (Medium) — a dead worker was invisible

No worker liveness signal existed. Queue depth and failed jobs were admin-readable, but a
worker that died with an empty queue produced no symptom until deliveries stopped.

**Fixed** without a schema change (`database.py` is held byte-identical, and a new table
would need a migration): a short-TTL Redis key, which also gives expiry for free so a dead
worker cannot leave a stale `healthy` flag behind. `GET /api/admin/worker/health` reports
`alive` / `stale` / `missing` / `unknown` and returns **503 unless alive**, so a monitor can
alert on status code alone.

The heartbeat is written at the **end** of each tick, so a loop wedged inside a handler
stops beating — which is the failure worth detecting.

**A flaw found in my own first implementation:** an open `extra` dict meant a caller could
push an arbitrary value — including a token — into a payload returned over HTTP. Demonstrated
with `extra={"secret_token": "..."}` appearing verbatim. Replaced with an allowlist of four
counter names and a numeric-type check (a string is a scalar too, and a scalar can be a
secret).

---

## 3. Test-isolation defect found in my own work

The first full-suite run after my changes showed **5 failures** in unrelated suites with
"admin password incorrect". They passed in isolation.

Cause: my own fixture called `os.environ.setdefault("ADMIN_PASSWORD", ...)`, which writes to
the real process environment and is never undone. Every later test inherited the wrong
password. Fixed with `monkeypatch.setenv`, which is scoped and restored.

This is recorded because it is the exact class of defect Phase 33 warned about: a green
subset proving nothing about the whole. It also would have masked a genuine regression
behind a misleading error message.

---

## 4. Reproducible builds

**Before:** ranges only (`fastapi>=0.115.0,<1.0.0`), no lockfile, mutable base-image tag.

**After:** `requirements.lock` — **46 packages, each with a SHA-256**, generated from the
exact versions that pass CI, resolved as a full transitive closure and downloaded to capture
hashes. **No dependency was upgraded.**

Verified for real, not asserted:

```
python -m venv /tmp/p36_clean
pip install --require-hashes --no-deps -r requirements.lock   →  Successfully installed 46
```

The app then ran on that isolated environment: `main` imported, `init_db()` created the
schema, `/api/ready` returned **200**. Production closure is genuinely sufficient.

`requirements-dev.txt` splits out pytest/bandit/moto so the production image does not ship
test tooling. `pip-audit` against the lock: **46 packages, 0 vulnerabilities.**

**Not done, and why:** the base-image digest is a **documented placeholder**. Docker Hub is
outside the egress allowlist, so the digest could not be resolved, and inventing one
produces an image that cannot pull at all — worse than the tag. The Dockerfile now installs
`--require-hashes` from the lock, and `tests/test_e36_lock.py` **xfails** while the
placeholder is present so it is visible rather than hidden, and turns green by itself once
resolved.

---

## 5. Reverse proxy

`deploy/Caddyfile` + a `proxy` service in `docker-compose.staging.yml`; the app publishes
**no host port** in staging, so 8000 and 5432 are unreachable from outside.

Configured: automatic certificates, HTTP→HTTPS redirect, HSTS, nosniff, `X-Frame-Options`,
request-body cap (25 MB), dial/response/read timeouts, webhook path preserved unmodified,
`X-Forwarded-*` **overwritten** (not appended, which would let a client inject hops).

**Honest limitation:** the Caddyfile has **never been parsed by Caddy**. Caddy and Docker are
both absent here, and release assets are served from a host outside the allowlist. The tests
assert the security *decisions* (forwarded-proto present, no `+` appends, HSTS, body cap,
port exposure) — they cannot catch a syntax error. `caddy validate` is a required step in the
runbook.

---

## 6. Backup and restore — verified end to end

Run against disposable PostgreSQL 16 with real data:

| Step | Result |
|---|---|
| Backup **refused without a key** | `backup REFUSED [ENCRYPTION_KEY_MISSING]` — nothing written |
| Backup with key | 8,715 bytes, `sha256 015be7bc…`, mode 0600 |
| Encryption is real | header `GEREGE-B`, not gzip; `Tenant A`, `Tenant B`, `INSERT INTO`, `CREATE TABLE` **all absent** from the ciphertext |
| Verify | `valid: … sha256 015be7bc…` |
| Restore to fresh DB | `restore OK` |
| **Independent** row-count check | source and destination both 19 tables, 3 pages, identical `page_id` set; 17 FKs; 5 triggers |
| Retention floor | `prune --days 0` pruned **0**; `BACKUP_MIN_KEEP=7` protected the archive |
| Failed backup exit code | `15` (not configured) via `backup`; `10` (failed) via `backup-run` |

**RPO:** the shipped timer is `OnCalendar=hourly` with `Persistent=true` →
**≤ 1 hour, plus catch-up after downtime.** Measured from the unit file, not assumed.

**RTO:** **1.75 s restore** for an 8.8 MB / 19-table database; backup itself takes 1.0 s.
Production-scale RTO is **UNKNOWN** — it depends on archive size and restore method, and no
production-sized dataset exists to measure.

**Correction to Phase 35:** the scheduler installer already existed. Verified by installing
into a scratch directory: units generated with no credential in the body
(`EnvironmentFile=` only), `Persistent=true`, `ProtectSystem=strict`, `NoNewPrivileges`,
`TimeoutStartSec`. The staging variant validates: `configuration is installable`.

---

## 7. Migration safety — measured

| Question | Answer | Evidence |
|---|---|---|
| Run once? | Yes | one-shot `migrate`, `restart: "no"` |
| Can instances race? | Not in the deploy path | see caveat below |
| Is worker blocked until migrated? | Yes | `service_completed_successfully` |
| Does failure stop deployment? | Yes | chained `&&`, `restart: "no"` |
| Rollback documented? | Yes, now | `PRODUCTION_DEPLOYMENT.md` §5.1 (new) |

**First-boot caveat, measured:** two `alembic upgrade head` processes started together against
an **empty** database both create `alembic_version`; one exits **1** with `already exists`.
The schema still ends at `0007` with 19 tables, so the failure is clean rather than a partial
migration — but a deploy script treating non-zero as fatal would roll back a good deployment.
Against an **already-migrated** database both exit **0**. `schema_manager` takes a
`pg_advisory_lock`; Alembic's `env.py` does not. Now documented as §5.2.

**0004 both branches exercised** (see §1).

---

## 8. Local production-mode validation

A true production-mode boot, not a development one:

```
INFO:core.db_engine:connection budget OK: 27 required, 97 usable (headroom 70) - role=api
/api/live → 200   /api/ready → 200 (database ok)   /api/health → 200
pool: {'engine': 'postgresql', 'pooled': True, 'size': 5, 'checkedout': 0}
```

The boot initially **failed** with `PrivilegedRuntimeError` because the local `gerege`
superuser is over-privileged — the least-privilege guard doing its job. After
`provision_roles.py --apply`, verification reported: *"Runtime role 'gerege_app' holds least
privilege. All 32 relation(s) are owned by 'gerege_owner'."*

Worker on the same database: tick executed, heartbeat `alive`, pool `size: 2`.

**Duplicate-scheduler proof:** two concurrent worker ticks racing for the same daily-report
lock produced **1 send**; a subsequent tick produced **0** more.

---

## 9. Test results

| Suite | Result |
|---|---|
| Full suite, fresh PostgreSQL (`p36_v3`) | **1,433 passed / 95 skipped / 1 xfailed / 0 failed** (304 s) |
| Phase 35 comparison | 1,349 passed / 36 skipped / 0 failed |
| New Phase 36 tests | **144** (143 pass + 1 xfail) across 8 files |
| Targeted health/auth/security regression checks | 117 passed, 68 passed |
| `leads.db` isolation | 25 → 25 pages, `git status` clean |
| Workflow validator | `Workflow validation OK (1 file(s))` |
| e29 CI-integrity | 20 passed |

The skip count rose from 36 to 95 because new suites skip Redis-dependent heartbeat cases
where Redis is absent in CI. The heartbeat endpoint still functions: it reports `unknown`
rather than crashing.

### Security scans

| Scan | Result |
|---|---|
| bandit (product code) | **0 HIGH**, 23 MEDIUM, 125 LOW |
| bandit (whole tree) | 4 HIGH — **all in `.scratch/`**, which is untracked and gitignored |
| pip-audit (locked set) | **46 packages, 0 vulnerabilities** (Phase 35: 21, pip/setuptools only, now excluded) |
| Secret scan (26 changed files) | 0 real credentials — 5 matches were `${VAR}` interpolation or deliberate fakes |

**Negative control:** restoring the pre-fix `db_engine.py` and `docker-compose.prod.yml`
produced **23 failed / 7 passed** — the tests genuinely detect both defects, and the source
was restored exactly afterwards.

---

## 10. Cost — estimates, not quotes

Prices are **unverified estimates**; no pricing page was fetched.

| Option | Composition | Est. monthly | Trade-off |
|---|---|---|---|
| **A** | 1 VPS (4 vCPU/8 GB), all services, Caddy, local-disk backups | $25–50 VPS + ~$15/yr domain | Cheapest. Backups share a disk with the database: a host loss takes both. |
| **B** (recommended) | 1 VPS + offsite object storage for backups + optional managed PG | $50–120 | Offsite backup is the single highest-value spend. |
| **C** | Separate API hosts, managed PG + Redis, LB, monitoring | $250–500+ | Not justified at current volume; revisitable when load is measured. |

Excluded: Gemini usage (**UNKNOWN** — no measurement exists), engineering time.

The Phase 36 changes make **A viable at all**: 27 connections of 97 instead of 120 of 97
means the full stack now fits one host.

---

## 11. Remaining blockers

| Blockers | Status |
|---|---|
| ~~No HTTPS~~ | **Closed in config.** Caddyfile + proxy-only staging compose. Unvalidated by Caddy. |
| ~~No connection headroom~~ | **Closed.** 27 of 97, guarded at startup. |
| ~~No automated backup~~ | **Closed.** Existing installer verified; hourly, encrypted, restore-tested. |

| Still open | Severity | Owner action |
|---|---|---|
| Base-image digest is a **placeholder** | **High** | Resolve and paste before any build |
| Caddyfile never parsed by Caddy | Medium | `caddy validate` on the host |
| No Docker build executed | Medium | First build will surface it |
| No integration live-verified | **High** | Requires sandbox credentials + authorisation |
| `deploy.resources` inert under plain compose | Medium | Set cgroup limits or use Swarm |
| Telemetry per-process, lost on restart | Medium | Aggregate externally later |

---

## 12. Verdict

**GO for local staging validation** — done, and it passed. The stack boots in production
mode, fails closed correctly, and the duplicate-dispatch properties hold under concurrency.

**GO for external staging deployment**, conditional on three actions: resolve the base-image
digest, run `caddy validate`, and supply sandbox credentials. Nothing else in the repository
blocks it.

**NO-GO for production.** The infrastructure gaps are closed *in configuration*, but
configuration is not evidence. No image has been built, no certificate issued, no webhook
verified against a real provider, and no load has been measured. Production needs staging to
be stood up and exercised first.

Phase 37 (not started — awaiting authorisation): stand up staging, resolve the digest,
validate the proxy, and execute the integration matrix.
