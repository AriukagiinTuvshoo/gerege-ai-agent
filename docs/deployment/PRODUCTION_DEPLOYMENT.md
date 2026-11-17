# PHASE 8 — PRODUCTION DEPLOYMENT AND OBSERVABILITY

**Repository:** `https://github.com/AriukagiinTuvshoo/gerege-ai-agent`  
**Modules:** [`Dockerfile`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/Dockerfile), [`docker-compose.prod.yml`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/docker-compose.prod.yml), [`main.py`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/main.py), [`worker.py`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/worker.py), [`core/monitoring.py`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/core/monitoring.py), [`vercel.json`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/vercel.json)

---

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
   - Runs `python worker.py` in a dedicated container to process background jobs, scheduled follow-ups, daily executive digests, and automated database backups.

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

## 4. Rollback & Incident Recovery Procedure

1. **Pre-Deploy Snapshot:**
   ```bash
   python -c "from core import backup_service; print(backup_service.create_backup(label='pre_deploy'))"
   ```
2. **Application Rollback:**
   ```bash
   git checkout <previous-known-good-commit>
   docker compose -f docker-compose.prod.yml up -d --build
   ```
3. **Database Rollback (if schema/data regression occurred):**
   ```bash
   python -c "from core import backup_service; print(backup_service.restore_backup('<pre_deploy_backup_filename>'))"
   ```
