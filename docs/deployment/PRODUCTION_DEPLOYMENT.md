# PHASE 8 — PRODUCTION DEPLOYMENT AND OBSERVABILITY

**Repository:** `https://github.com/AriukagiinTuvshoo/gerege-ai-agent`  
**Modules:** [`Dockerfile`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/Dockerfile), [`docker-compose.prod.yml`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/docker-compose.prod.yml), [`main.py`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/main.py), [`worker.py`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/worker.py), [`core/monitoring.py`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/core/monitoring.py), [`vercel.json`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/vercel.json)

---

## 0. Topology (Phase 38)

Production is served **only** through a TLS-terminating proxy. Nothing else publishes a
host port.

```
        :80 / :443                    compose network (no published ports)
internet ────────► proxy (Caddy) ──────────────► web:8000 ──┬──► db:5432   (internal)
                   └ automatic ACME                          └──► redis:6379 (internal)
                     certificates
```

* `proxy` — `caddy:2.8-alpine`, publishes 80/443/443-udp, mounts `deploy/Caddyfile.prod`
  and a persistent `caddy_data` volume. Obtains and renews certificates automatically.
* `web` — FastAPI + static SPA. **No `ports:`.** Reachable only from `proxy`.
* `worker`, `migrate`, `maintenance` — no published ports; `maintenance` is profile-scoped.
* `db`, `redis` — no published ports, ever.

Before Phase 38, `web` published `${PORT:-8000}:8000` directly and there was no proxy at
all, so production would have been served over plaintext: browsers drop `Secure` session
cookies over http://, and every admin password would have crossed the network in the clear.

**Required environment** (see `PRODUCTION_ENV_TEMPLATE.env`). Each is `:?` in the compose
file, so `docker compose up` refuses to start without it:

| Variable | Why it is required |
|---|---|
| `PRODUCTION_DOMAIN` | the hostname Caddy gets a certificate for; no default |
| `ACME_EMAIL` | where certificate-expiry warnings are sent |
| `TRUSTED_PROXIES` | the app only honours `X-Forwarded-Proto` from these peers; empty means http:// payment URLs |
| `ALLOWED_ORIGINS` | CORS allowlist; there is no wildcard fallback in production |
| `POSTGRES_PASSWORD`, `POSTGRES_OWNER_PASSWORD`, `POSTGRES_APP_PASSWORD` | the bootstrap, owner and runtime credentials |
| `ADMIN_PASSWORD`, `E02_ACCOUNT_KEY_SECRET` | admin auth; account-level throttle key (min 32 chars) |

**Design decision: the app still binds `0.0.0.0`.** On a Docker bridge network the proxy
reaches `web` from a different container, so binding `127.0.0.1` would make it unreachable.
The safety comes from *not publishing the port*, not from the bind address. `uvicorn` runs
with `--no-proxy-headers` so `TRUSTED_PROXIES` remains the single authority on forwarded
headers.

**Validate the proxy config before the first start.** A structural checker runs in CI, and
a real `caddy validate` runs there too, but confirm on the actual host:

```bash
docker run --rm -e PRODUCTION_DOMAIN="$PRODUCTION_DOMAIN" -e ACME_EMAIL="$ACME_EMAIL" \
  -v "$PWD/deploy/Caddyfile.prod:/etc/caddy/Caddyfile:ro" \
  caddy:2.8-alpine caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
```


## 1. Production Container Topology (`docker-compose.prod.yml`)

Production deployments run 4 isolated services with healthchecks and resource limits:

1. **`db` (`postgres:16-alpine`):**
   - Primary relational store with persistent `pgdata` volume and `pg_isready` healthcheck.
2. **`redis` (`redis:7-alpine`):**
   - Append-only (`--appendonly yes`) broker for `core/task_queue.py` (`gerege:task_queue` and `gerege:task_dlq`).
3. **`web` (`Dockerfile` — non-root user `gerege`):**
   - Runs `uvicorn main:app --host 0.0.0.0 --port 8000 --workers 2 --no-proxy-headers`.
   - Enforces `ENV=production`, `STRICT_SECURITY=1`, `WEBHOOK_FAIL_CLOSED=1`, `STRICT_QPAY_VERIFICATION=1`, and `DISABLE_INLINE_SCHEDULER=1`.
4. **`worker` (`Dockerfile` — non-root user `gerege`):**
   - Runs `python worker.py` in a dedicated container to process background jobs, scheduled follow-ups and daily executive digests.
   - **Does not run database backups** (corrected in Phase 16, MEDIUM-02). E-05 removed the backup job from `worker.py`: `pg_dump` needs table ownership, and the worker now connects as `gerege_app`, which deliberately has none. Backups run on the owner-credentialed maintenance plane instead — see [BACKUP_AUTOMATION.md](../operations/BACKUP_AUTOMATION.md).
5. **`migrate` (`Dockerfile`, one-shot, `restart: "no"`):**
   - The only service holding the bootstrap and owner credentials. Runs
     `provision_roles --apply` → `alembic upgrade head` → `provision_roles --apply` → `provision_roles --verify`.
   - `web` and `worker` wait on `condition: service_completed_successfully`, so a
     provisioning or verification failure stops the stack instead of serving traffic
     against a database that is not least-privileged.
6. **`maintenance` (`Dockerfile`, profile `maintenance`, `restart: "no"`):**
   - Operator- or timer-invoked only; never started by `up`. Holds `DATABASE_OWNER_URL`
     and nothing else's credential.
   - `python scripts/maintenance.py backup-run --label scheduled` is the single entry
     point for a scheduled run (backup → encrypt → verify → retain → offsite → alert).

> **Backup automation status: NOT CONFIGURED.** No scheduler is installed by this
> repository. `deploy/systemd/` and `deploy/cron/` contain templates; installing one,
> pointing `BACKUP_ALERT_WEBHOOK` at a real destination and measuring a restore are
> operator steps. No RPO can be quoted until they are done.

### 1.1 Client IP and `TRUSTED_PROXIES` (E-02 Phase 3)

Rate limiting keys on the client IP, so "which IP is the client" is a security decision.

**There is no reverse proxy in this topology.** The `web` service publishes port 8000
directly, so the TCP peer is always the real client and `TRUSTED_PROXIES` stays **empty**.
An empty value means no forwarding header is believed, which is the intended default.

`uvicorn` is started with `--no-proxy-headers`. This is load-bearing: with uvicorn's
default the framework rewrites `scope["client"]` from `X-Forwarded-For` for any peer it
trusts (default `127.0.0.1,::1`), and it does not validate that the value is an IP
address. Disabling it makes `scope["client"]` the actual socket peer, and
`core.rate_limit.resolve_client_ip()` the single authority on forwarding.

| Situation | `TRUSTED_PROXIES` | Client identity |
|---|---|---|
| Direct exposure (this compose file) | *(empty)* | the socket peer |
| Behind a proxy you control | that proxy's address/CIDR | first untrusted hop in `X-Forwarded-For`, walked right-to-left |

Rules enforced in code:

* Empty or unset → trust nothing. A missing configuration is never read as "trust all".
* `*`, `0.0.0.0/0` and `::/0` are rejected, because they disable the policy.
* An unparseable entry is dropped and logged; trust is never widened to compensate.
* `X-Real-IP` and RFC 7239 `Forwarded` are **not** supported. Adding them needs its own
  trust validation and tests; silently falling back to them is how a hardened resolver
  becomes bypassable again.
* Headers over 1 KB or beyond 15 hops are rejected and the socket peer is used.
* Every hop must parse as an IP address; otherwise the walk aborts and the peer is used.
* An empty or whitespace-only entry counts as malformed, exactly like `not-an-ip`. A chain
  such as `", 1.2.3.4"`, `"1.2.3.4, "` or `"1.2.3.4,,10.0.0.1"` is rejected outright and
  the socket peer becomes the identity. Malformed entries are never skipped.

**If you add a proxy, list the proxy's addresses — never the clients'.** Listing clients
would let them rotate their own budget; listing nothing would collapse all users onto the
proxy's address and lock everyone out together.

---

### 1.2 Account-level failed-login protection and `E02_ACCOUNT_KEY_SECRET` (E-02 Phase 4)

The IP limit in §1.1 caps how fast **one source** can guess. It cannot cap how many times
**one account** is guessed: an attacker with a proxy pool gets a fresh per-IP budget per
address, so 400 attempts against one login cost 40 addresses and 60 seconds. Phase 4 adds an
independent account-level counter that the source address does not affect.

| Setting | Default | Meaning |
|---|---|---|
| `ACCOUNT_FAILURE_THRESHOLD` | `20` | failed attempts per account per window before throttling |
| `ACCOUNT_FAILURE_WINDOW` | `900` (15 min) | window length; also the maximum `Retry-After` |
| `E02_ACCOUNT_KEY_SECRET` | *(unset)* | keyed-HMAC secret for the counter keys |

Both limits are enforced; neither replaces the other. A request must pass the IP limit
**and** the account limit.

**`E02_ACCOUNT_KEY_SECRET` is REQUIRED in production.** If it is unset, blank, or shorter
than 32 characters, the application **refuses to start**: `main`'s lifespan calls
`core.account_keys.validate_secret_for_startup()`, which raises `RuntimeError` before the app
serves a single request. `docker compose` additionally refuses to bring the `web` service up
at all, because the compose file declares the variable with `:?`.

That combination is deliberate. If the secret were optional, a deployment missing it would
run with account-level throttling *silently disabled* — a security control that is believed to
be present but is not, which is worse than not having it. Development and test mode keep
working without it, and there the throttle degrades to "off" rather than to an unkeyed hash.

Generate one with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

**Provision it as a secret, not as configuration.** Put it in your secret manager (Docker
Swarm secrets, Kubernetes `Secret`, AWS Secrets Manager, Vault) and inject it as an
environment variable at deploy time. Do not commit it, do not put it in `.env` in the
repository, do not bake it into an image layer, and do not paste it into a ticket or a chat.
The application never logs the value, never returns it from any endpoint, and never sends it
to the browser — but it cannot protect a secret that was already copied somewhere else.

Do **not** reuse `META_APP_SECRET`, `TELEGRAM_WEBHOOK_SECRET`, `MANYCHAT_WEBHOOK_SECRET` or
`GEMINI_API_KEY`. The webhook secrets rotate on the vendor's schedule and are shared with a
third party, so a vendor-side rotation would silently reset every account counter; and
widening a vendor secret's blast radius to login identifiers is unnecessary. A dedicated
secret keeps the two lifecycles independent.

Rotating the secret is **safe and self-healing**: existing counters are keyed with the old
secret, so they become unreachable and effectively orphaned. They expire within the window
(15 minutes by default) and are cleaned up by Redis. The practical effect is that every
account's throttle resets — which can only ever *un*-throttle, never lock anyone out.

Rotation takes effect on the next restart of each worker, because the value is read once at
startup. To rotate: deploy the new value and restart. There is no dual-key window; during the
brief period when workers hold different secrets, an account may have two counters (one per
generation). Both expire on their own. A multi-key rotation scheme was considered and rejected
as unnecessary complexity for a control whose worst failure mode is "throttle resets".

What operators see in Redis:

```
ratelimit:auth_account:7d91ec73dbc3af26059b99c7cd2a00e6   TTL 899
```

The suffix is a keyed BLAKE2b digest. **No username or tenant name appears in any key**, so
an operator with Redis access cannot enumerate customers from the keyspace.

Operational notes:

* **This throttles, it does not lock out.** The counter expires on its own after the window,
  and a successful login clears it. There is no permanent lockout to unlock by hand. If you
  must clear an account immediately, delete its `ratelimit:auth_account:*` key.
* **A throttled account refuses all attempts, including the correct password**, until the
  window expires. That is inherent: verifying the password in order to admit the owner would
  verify every guess. The bound is the window (15 min default), which is why the window is
  capped below an hour.
* **A successful login clears the account counter only.** The IP counter deliberately
  survives, so an attacker holding one valid credential cannot launder an abusive address by
  interleaving successful logins.
* **Redis is required for cross-worker enforcement.** With Redis reachable, two workers (and
  any number of replicas) share one counter. If Redis is unreachable the limiter falls back
  to a **per-process** counter, which means the effective limit becomes
  `threshold × number of workers` — it does **not** provide cross-worker protection. The
  fallback is logged loudly. The general fail-open/fail-closed policy for a Redis outage is
  out of scope here (E-03).
* **Responses are uniform.** A wrong password and an unknown account return the same status,
  the same body and comparable timing (an unknown account performs a dummy PBKDF2
  verification so it cannot be distinguished by response time). A throttled account returns
  429 with `Retry-After` and a fixed message, for known and unknown identifiers alike.

### 1.3 Account identity and counter semantics (E-02 Phase 4.1)

**One account has one budget, whatever alias the client uses.** The login form accepts either
the tenant's `client_username` or its `page_id`. The throttle resolves the submitted identifier
against the database (the same `LOWER(TRIM(...))` comparison the login query uses) and keys on
the account's canonical `page_id`. Without this, an attacker alternating between the two
aliases got two independent budgets — measured at 40 attempts against a threshold of 20.

Identifiers that do not resolve to an account are keyed on the database-normalized submitted
value, so unknown accounts stay throttled and the counter does not become an existence oracle.
The digest is always a keyed BLAKE2b; no username or page id is ever written to Redis in
readable form.

**Normalization is the database's, not Python's.** `str.casefold()` is not `LOWER()`: it folds
`ß` to `ss`, which neither SQLite nor PostgreSQL does, and it leaves `Σ`/`Ø` unfolded where
SQLite's ASCII-only `LOWER` also leaves them alone but PostgreSQL folds them. Using it merged
accounts the database keeps distinct and split ones it considers the same. The throttle now
asks the database to evaluate the comparison, so it agrees with the engine on every platform.

**Counter semantics.** Each admitted login consumes one slot atomically. A wrong password keeps
that slot; a successful login refunds exactly the one slot it consumed. Nothing deletes the
counter. This is what makes a failure recorded concurrently with a successful login survive it
— a whole-key reset could not distinguish the two and silently erased it.

Operationally this means **a successful login does not zero the counter**; earlier mistyping
stays recorded until the window expires. A user who has failed a few times and then logs in
correctly still has their remaining budget reduced by those earlier failures, for at most 15
minutes. This is the intended trade: correctness under concurrency over the convenience of an
instant reset.

---

## 2. Liveness & Readiness Probes

| Endpoint | Purpose | Checks Performed | HTTP Status |
|----------|---------|------------------|-------------|
| `GET /api/health` | Liveness Probe | Verifies process event loop responsiveness and reports engine/queue mode + uptime | `200 OK` |
| `GET /api/ready` | Readiness Probe | Executes `SELECT 1` against primary DB (`PostgreSQL`/`SQLite`) and `PING` against Redis when `REDIS_URL` is configured | `200 OK` when ready, `503 Service Unavailable` if DB or required Redis is down |

---

## 3. Vercel Serverless Constraints (`vercel.json` & `api/index.py`)

- When deployed to Vercel Serverless (`api/index.py`), the filesystem is ephemeral (`read-only` outside `/tmp`) and background loops (`worker.py`) do not persist between requests.
- **Required Configuration for Vercel:**
  1. Set `DATABASE_URL` to a managed PostgreSQL instance (e.g., Neon, Supabase, AWS RDS). Never rely on local SQLite on Vercel.
  2. Set `REDIS_URL` to a managed Redis instance (e.g., Upstash) and run `worker.py` on a persistent container host (Railway, Render, Fly.io, or VPS).
  3. Configure all secrets (`ADMIN_PASSWORD`, `GEMINI_API_KEY`, `META_APP_SECRET`, `TELEGRAM_WEBHOOK_SECRET`) via Vercel Environment Variables.

---

## 4. Deployment sequence

`scripts/deploy.sh` performs the same ordered sequence as the `migrate` service, and
stops at the first failure. The ordering matters and is not arbitrary:

| Step | Action | Credential | Why this order |
|---|---|---|---|
| 1 | Pre-deploy backup | owner | A deploy without a restore point cannot be rolled back. **Fatal** unless `ALLOW_DEPLOY_WITHOUT_BACKUP=1`. |
| 2 | `git pull --ff-only` | — | |
| 3 | `provision_roles --apply` | bootstrap | Creates/refreshes the two roles. On a fresh volume there are no tables yet. |
| 4 | `alembic upgrade head` | bootstrap | The migrator **owns what it creates**. |
| 5 | `provision_roles --apply` | bootstrap | **Transfers ownership** of everything the migration just created to `gerege_owner`, then applies grants. Must be a full `--apply`: `--converge-only` emits GRANT/REVOKE only and would skip this — that was finding HIGH-01. |
| 6 | `provision_roles --verify` | any | Fails non-zero on over-privilege, under-provisioning, a missing role, or **any relation not owned by `gerege_owner`**. |
| 7 | `compose up -d --build` | — | `migrate` re-runs steps 3–6 inside the cluster network; `web`/`worker` wait on `service_completed_successfully`. |
| 8 | Healthcheck → auto-rollback | — | |

**Why step 5 cannot be `--converge-only`.** Grants and ownership are independent: a
database can grant `gerege_app` exactly the right privileges while every table is still
owned by the bootstrap superuser. That state passes every privilege check and still
cannot be backed up, because `pg_dump` needs ownership of every table. `--verify` now
checks ownership explicitly, and `--converge-only` is reserved for the post-*restore*
path where ownership already exists.

## 5. Rollback & incident recovery

```bash
bash scripts/rollback.sh
```

The script rolls back code (to `.last_working_commit`) and data (to the newest
`pre_deploy` archive) **independently**, and prints exactly which of the two happened:

```
=== [Gerege Rollback] Completed ===
    code rolled back:     yes
    database rolled back: no
    NOTE: the database still contains the state produced by the failed deploy.
```

A failed restore is **fatal** — the script does not restart services onto a
half-restored database. After a restore it re-runs a full `provision_roles --apply`
(the replayed dump recreates objects that must be re-owned by `gerege_owner`) and then
`--verify`.

> The previous version of this section showed `backup_service.create_backup(...)` and
> `restore_backup(...)` called directly. Both now run the E-05 maintenance-credential
> guard and **refuse** to run under the runtime credential, so those snippets no longer
> work. Use the CLI, which sets the owner credential explicitly.

### 5.1 Schema rollback: what is and is not possible

`scripts/rollback.sh` restores **data**; it does not run `alembic downgrade`. Do not assume
a failed deploy can be undone with one. Phase 36 measured the actual behaviour of every
migration rather than assuming:

| Migration | Downgrade | Notes |
|---|---|---|
| 0001 initial schema | yes | |
| 0002 schema authority | yes | |
| 0003 foreign keys | yes | |
| **0004 tenant session identity** | **conditional** | refuses when tenants collide — see below |
| 0005 username uniqueness | yes | |
| 0006 login identity | yes | |
| 0007 audit append-only | yes | |

**0004 is data-dependent, not unconditionally irreversible.** It collapses
`session_states` from a `(sender_id)` key to `(page_id, sender_id)`. If two tenants hold a
session for the *same* `sender_id`, going back would have to delete one of them, so the
downgrade raises instead of destroying data:

```
RuntimeError: Cannot downgrade to a sender-only primary key: several tenants hold a row
for the same sender, and collapsing them would destroy data.
```

Both branches were exercised against PostgreSQL 16 in Phase 36:

* **No collisions** (fresh or single-tenant database): `alembic downgrade 0003` **succeeds**.
* **Collisions present** (the normal state once two tenants have talked to the same person
  on different pages): the downgrade **refuses**, the revision stays at `0004`, and **both
  rows are still there afterwards**. Verified: 2 rows before, 2 rows after.

Practical consequence: on any database that has served more than one tenant, treat a
schema rollback past 0004 as **unavailable** and recover with a restore instead:

```bash
bash scripts/rollback.sh          # code + data, verified
```

If you genuinely need to go back, resolve the collisions deliberately first — decide which
tenant keeps the session — then downgrade. Never script that.

### 5.2 Do not run two migrators against a fresh volume

Measured on an empty database: two `alembic upgrade head` processes started together both
attempt to create `alembic_version`. One succeeds; the other exits 1 with
`already exists`. The schema still ends at `0007` with 19 tables, so the failure is clean
rather than a partial migration — but it is a non-zero exit, and a deploy script that
treats that as fatal would roll back a perfectly good deployment.

Against an **already-migrated** database (the normal redeploy) both processes exit 0.

Rules:
* Exactly one `migrate` container per deployment. `docker compose up` guarantees this;
  a Kubernetes Job with `parallelism > 1`, or two hosts deploying simultaneously, does not.
* `core/schema_manager.py` takes a `pg_advisory_lock` for the app-side schema path, but
  Alembic's own `env.py` takes no lock — which is why the first-boot case behaves as above.

## 6. Credential rotation

```bash
# App credential: the old password stops working immediately.
python scripts/provision_roles.py --apply --rotate app     # prints the new one ONCE
# update POSTGRES_APP_PASSWORD in the secret store, then:
docker compose -f docker-compose.prod.yml up -d            # restart web + worker

# Owner credential:
python scripts/provision_roles.py --apply --rotate owner
# update POSTGRES_OWNER_PASSWORD and DATABASE_OWNER_URL
```

`--rotate` requires the bootstrap/`CREATEROLE` credential. The generated password is
printed once, never logged, and never written to the backups directory. Rotate both
credentials at any staff change and at least annually.

## 7. Failure recovery

| Symptom | Meaning | Action |
|---|---|---|
| `refusing to start: the database role '…' is more privileged…` | Over-privileged runtime credential | Point `DATABASE_URL` at `gerege_app`; run `provision_roles.py --apply` |
| `VERIFICATION FAILED: … NOT owned by 'gerege_owner'` | Migration ran, ownership transfer did not (HIGH-01) | `provision_roles.py --apply` — full pass, not `--converge-only` |
| `cannot create a trustworthy backup or restore: it owns N of M tables` | Owner credential is not actually the owner | Same repair as above |
| `refusing to deploy without a backup` | `DATABASE_OWNER_URL` unset in `deploy.sh` | Set it, or accept the risk with `ALLOW_DEPLOY_WITHOUT_BACKUP=1` |
| `BACKUP_ENCRYPTION_KEY_FILE is not set but encryption is required` | Scheduled backup has no key | Install the key file (§ backup automation doc) |
| `BACKUP IS STALE` from `maintenance.py status` | The scheduler is not running | Check the timer: `systemctl list-timers gerege-backup.timer` |
