# Phase 39 — Staging Operational Readiness & Deployment Rehearsal

**Final commit:** `023d5d6aa11b2a340f338c2b758202ad1e4697e6`
**Branch:** `arena/d78ebf88-gerege-ai-agent` (PR #1 open, not merged)
**CI:** run `45308639742` on `023d5d6` — **success, 71 steps, 0 non-success**
**`main`:** `48e9c6f` — unchanged, never modified
**Not deployed. Not merged. No production credentials or data touched.**

---

## 1. What was actually executed (not inferred)

| Validation | How it was executed | Result |
|---|---|---|
| Full test suite | `pytest tests/` on 2026-11-16 | **1589 passed, 114 skipped, 1 xfailed** |
| Phase 36→39 gated suite | CI step "Phase 36 — connection budget, lockfile, health separation, worker heartbeat" | **pass**, 319 collected ≥ floor 315 |
| **Staging stack, real containers** | CI step "Phase 39 — staging deployment rehearsal" | **PASSED — 18 checks, 0 failures** |
| Compose accepts the file | `docker compose config` on a runner | 277 lines, exit 0 |
| Negative control: missing secret | `compose config` with `ADMIN_PASSWORD` unset | exit 1, names the variable |
| Port isolation | parsed `compose config`, negative control re-injected `8000` | proxy only; injection → check fails |
| Migrations | `migrate` container + `information_schema` count | exit 0, **19 tables** |
| API health | `GET /api/health`, `/api/ready` inside the web container | **200, 200** |
| Worker liveness | `worker_heartbeat.read()["status"]` in the worker container | **`alive`** |
| F-39-D under injection | injected a raising scheduler step in the live worker | heartbeat **`alive`**, `scheduler_errors: 1` |
| Non-root container | `id -u` in the web container | **999** |
| Compose health states | `docker compose ps --format json` | no unhealthy service |
| Backup exit codes | `maintenance.py backup` with absent / malformed key | **11** and **11**; unconfigured → **15** |
| Missing prod secret | lifespan startup with `E02_ACCOUNT_KEY_SECRET` unset | **RuntimeError, refused** |
| Redis down | `run_worker_tick` against a dead Redis | degraded to DB queue, **no crash** |
| Trusted proxy | `tests/test_e02_trusted_proxy.py` | **42 passed** |
| Bandit | `core/ scripts/ worker.py main.py` | **0 High**, 19 Medium (all pre-existing B608/B310/B314 in `main`), 93 Low |
| Bandit on changed files | `worker.py`, `core/worker_heartbeat.py` | **1 Low** (B110, pre-existing at `HEAD`) |
| Secret scan | 261 tracked files, credential shapes | 17 hits, **all benign** (`AKIAIOSFODNN7EXAMPLE`, `"test"`, generated RSA keys) |

---

## 2. Defects found and fixed

Every one was reproduced before being changed, and each has a test that fails against the
pre-fix file.

### F-39-I — HIGH — staging created its database roles with no password

`scripts/provision_roles.py` reads `GEREGE_OWNER_PASSWORD` / `GEREGE_APP_PASSWORD`.
Production's `migrate` service mapped them; staging did not. With no password the role is
created as bare `CREATE ROLE ... NOINHERIT LOGIN;`.

**Measured on CI:** migrations applied (19 tables) → every app connection died with
`FATAL: password authentication failed for user "gerege_app"` → worker crash-looped,
heartbeat `missing` → `/api/health` and `/api/ready` connection refused. Staging looked
half-deployed: correct schema, correct topology, unauthenticated application plane.

**Fix:** map both variables in the staging `migrate` service with `:?` (fail fast, never a
passwordless role). **This alone would have blocked a real staging deployment.**

### F-39-D — HIGH — a scheduler error made a live worker report dead

`run_worker_tick` ran its three scheduler steps unguarded and published the heartbeat as
its last action. One raising step aborted the rest of the tick and skipped `beat()`.

**Measured before the fix:** 3/3 ticks raised, `worker_heartbeat.read()["status"]` went
**`missing`** while the process was alive. Docker then restart-loops a partially broken
worker, and queue processing plus appointment reminders stop.

**Fix:** each step individually guarded, failures counted in `stats["scheduler_errors"]`,
the count carried in the heartbeat payload and allowlisted in `core/worker_heartbeat.py`.
`beat()` stays last **on purpose** — publishing it earlier would hide a wedged loop.
Verified in the live container: heartbeat `alive`, `scheduler_errors: 1`.

### F-39-G — HIGH — I broke `docker-compose.staging.yml` myself

An earlier Phase 39 edit left a second `deploy:` key in the `maintenance` service.
**PyYAML merges duplicate keys silently**, so `yaml.safe_load` still reported a complete
limit, all seven resource-limit tests passed, and `docker compose` refused the *entire
file* with `mapping key "deploy" already defined`. The staging stack could not start at
all. Only the container rehearsal found it.

**Fix:** removed the stray block; `maintenance` keeps one coherent `deploy:`. Guarded by
four tests that parse with duplicate keys **rejected** — verified by re-injecting a
duplicate and watching all four fail.

### F-39-A — MEDIUM — staging had 0/7 resource limits

Production had 5/7. Staging could starve a shared host. Now **6/7** (`migrate` is
intentionally unbounded so a one-shot job is never throttled), with parseable units and
staging never exceeding production.

### F-39-B — MEDIUM — the production worker had no healthcheck

Phase 37 fixed staging only, so a wedged production worker stayed `Up` forever. Added the
same Redis-heartbeat probe; **executed** it: no heartbeat → exit 1, after `beat()` → exit 0.

### F-39-C — MEDIUM — production compose had no `name:`

The project was derived from the checkout directory, so running it beside staging collided
with `pgdata` / `redisdata` / `caddy_data` — one environment could mount the other's
database. Now `name: gerege-production`.

### F-39-E — LOW — staging advertised a first-boot path that does not exist

The comment named a `--profile no-proxy` and a `deploy/Caddyfile.local`; neither exists
anywhere in the repo, and that comment was the *only* documented way to start staging
before DNS and TLS are ready. Corrected to state the real, intentional constraint.

### F-39-H — rehearsal harness — `docker compose wait` is not a subcommand

The script's own bug: the failed command substitution aborted the shell silently. Exit
codes are now read with `docker inspect`; every direct `X="$(...)"` is guarded; ERR/EXIT
traps print the failing line.

### Not a defect (retracted)

`.env.staging.example`'s `BACKUP_KEY_FILE` is the **host-side mount source** in
`${BACKUP_KEY_FILE:-./secrets/backup.key}:/run/secrets/backup.key`, while
`BACKUP_ENCRYPTION_KEY_FILE` is the **container** path set by compose. Both names are
correct on their own side. The rename in `f2a2a43` was cosmetic; the commit header
overstates it. The template tests remain valid as guards.

---

## 3. Verdicts

### Repo readiness — **READY**
Green CI on the exact final commit, full suite passing, 0 High bandit issues, no secret
leakage, and the staging architecture proven to run in real containers.

### Local staging rehearsal — **VERIFIED**
18/18 checks on a disposable stack: compose accepted, secret guard fired, migrations
applied (19 tables), API 200/200, worker `alive`, F-39-D injection survived, uid 999.
Torn down with `down -v` scoped to project `p39rehearsal`; a global volume prune is
forbidden by a test.

### External staging deployment — **NOT VERIFIED / BLOCKED**
| Blocker | Severity | Why |
|---|---|---|
| No DNS or host for a real staging domain | **blocker** | Compose requires `STAGING_DOMAIN`; Caddy refuses an empty site address. Needs an authorized host with 80/443 reachable. |
| No ACME reachability test | unknown | Never requested a certificate; the sandbox blocks Docker Hub and ACME. Not exercised by design (`.invalid` domain). |
| No offsite backup target | unknown | `BACKUP_OFFSITE_*` unset. Untested against a real S3. |

### Production deployment — **NOT READY**
| Blocker | Severity | Required action | Authorization |
|---|---|---|---|
| Staging has never run against real DNS/TLS | **high** | Deploy to an authorized staging host first | needs a host + DNS |
| Offsite backup + restore never verified end-to-end | **high** | Configure `BACKUP_OFFSITE_*`, run backup → restore drill | needs bucket credentials |
| Alert delivery never proven to reach a human | **high** | Set `BACKUP_ALERT_WEBHOOK`, induce a failure, confirm receipt | needs a webhook |
| `docker compose` version drift | **medium** | Pin the Compose plugin version in ops docs | none |
| `main` is not this branch | **blocker** | PR #1 review and merge | **explicitly out of scope this phase** |

---

## 4. Unverified assumptions (stated plainly)

- Staging and production share a `services:` shape; I assumed they must not drift, so I
  added a test asserting the role-password mapping matches. That is a policy choice, not a
  measured requirement.
- The non-root check ran as `id -u` → 999. I did not verify the filesystem permissions of
  `/run/secrets/backup.key` inside `maintenance`; that profile was not started.
- The rehearsal used `docker compose` 5.1.3 on the runner. Production's pinned version is
  not verified.
- `scheduler_errors` is per-tick (a transient error clears on the next clean tick). It
  surfaces a *currently broken* step, not a history. No dashboard consumes it, though
  `/api/admin/worker/health` returns it.

---

## 5. Artefact

`tests/test_e39_staging_operational_readiness.py` — **85 tests**, all of which were
checked against the pre-fix state. Seven were demonstrably wrong at first and corrected
only after a negative control failed to fail:

- an AST lookup that missed `async def` (`AsyncFunctionDef` is not `FunctionDef`),
- a "guard precedes compose" assertion that matched a variable *definition*,
- a skip that fired on CI (where Docker exists) and tripped the no-skip gate,
- a paren-matching walk that started one character too late, so it truncated at the first
  inner `)` and never saw the missing `|| true`,
- string matching that hit its own explanatory comments,
- an assertion that `beat()` is the last *statement* (it is the last *action*;
  `return stats` follows),
- a healthcheck probe assumed to be a shell string when it is exec-form.

`scripts/p39_staging_rehearsal.sh` — the only place the staging architecture is executed.
Reports **BLOCKED**, not a pass, when Docker is absent, and a behavioural test proves it.
