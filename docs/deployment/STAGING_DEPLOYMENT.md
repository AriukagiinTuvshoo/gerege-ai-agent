# Staging Deployment Runbook

Phase 36. This is the procedure for standing up a **staging** environment that is shaped
like production. It has not been executed against a real host — no external infrastructure
was created during Phase 36. Every step below that requires a server, a domain or a paid
resource is marked **[requires infrastructure]**.

Read `docs/audit/PHASE_36_STAGING_HARDENING.md` first for why each control exists.

---

## 0. What staging is for

Staging exists to answer the questions that mock tests cannot:

* do the webhooks actually verify against real provider signatures?
* does a real QPay sandbox payment settle?
* does the worker deliver anything, and what does a blocked bot look like live?
* what is real Gemini latency and cost per conversation?

If staging shares a credential with production, or runs with `ENV=development`, it answers
none of those questions and is just a second production. Do not start it that way.

---

## 1. Prerequisites  [requires infrastructure]

| Item | Requirement |
|---|---|
| Host | 4 vCPU / 8 GB, Ubuntu 24.04 LTS, Docker Engine + Compose plugin |
| Domain | `staging.example.mn` → A record to the host, **before** first start |
| Ports | 22, 80, 443 only. Never 8000, 5432, 6379 |
| TLS | automatic via Caddy (needs 80 and 443 reachable from the internet) |
| Time | NTP synced — TOTP-style windows and certificate validity both care |

Confirm DNS resolves before starting Caddy. A certificate request against a name that does
not resolve fails, and repeated failures hit Let's Encrypt rate limits.

---

## 2. Secrets

1. Copy `.env.staging.example` to `.env`, `chmod 600`, owner root.
2. Generate every value. Nothing is shared with production:

```bash
openssl rand -base64 24   # POSTGRES_PASSWORD, POSTGRES_OWNER_PASSWORD,
                          # POSTGRES_APP_PASSWORD, ADMIN_PASSWORD
openssl rand -base64 32   # E02_ACCOUNT_KEY_SECRET
openssl rand -hex 32      # TELEGRAM_WEBHOOK_SECRET
openssl rand -hex 16      # META_VERIFY_TOKEN
```

3. Backup key — separate from production:

```bash
mkdir -p secrets && chmod 700 secrets
python3 -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())" > secrets/backup.key
chmod 400 secrets/backup.key
```

4. Fill `TRUSTED_PROXIES` after §4 below — it is not knowable before the network exists.

---

## 3. First start  [requires infrastructure]

```bash
docker compose -f docker-compose.staging.yml up -d db redis
docker compose -f docker-compose.staging.yml run --rm migrate
docker compose -f docker-compose.staging.yml up -d web worker proxy
```

**Run `migrate` exactly once.** Two migrators against a *fresh* volume race on
`alembic_version`; one exits non-zero even though the schema ends up correct
(measured — see `PRODUCTION_DEPLOYMENT.md` §5.2). Against an already-migrated database both
exit 0, so a restart is harmless.

Watch the migration chain: `provision_roles --apply` → `alembic upgrade head` →
`provision_roles --apply` → `provision_roles --verify`. The final `--verify` is what stops
an over-privileged runtime role reaching the API, where it would fail at boot with a much
less obvious error.

---

## 4. Set TRUSTED_PROXIES

The application honours `X-Forwarded-Proto` **only** from a configured trusted peer. If this
is wrong, generated QPay callbacks and payment links come out as `http://` (F-36-3).

```bash
docker network inspect gerege-staging_default \
  --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'
```

Put that subnet in `TRUSTED_PROXIES`, then `docker compose -f docker-compose.staging.yml up -d web`.
Do not use `0.0.0.0/0`: that lets any client claim to be on HTTPS and have the app mint an
`https://` payment URL it does not control.

---

## 5. Verify the stack came up correctly

```bash
# TLS and certificate
curl -sS -o /dev/null -w '%{http_code}\n' https://staging.example.mn/api/live     # 200
curl -sSI http://staging.example.mn/api/live | head -1                            # 308 -> https

# readiness (DB + Redis + limiter), not the deep health endpoint
curl -sS https://staging.example.mn/api/ready | python3 -m json.tool

# forwarded scheme is honoured: the payment callback must come out https://
curl -sS https://staging.example.mn/api/health | python3 -m json.tool
```

Expected: `/api/ready` → `{"ready": true, "database": "ok", ...}` and
`rate_limit_store` = `redis`, `rate_limit_store_required` = true.

If `rate_limit_store` says `memory` in staging, `REDIS_URL` is not reaching the app and
staging is not exercising the production path.

Then log in at `https://staging.example.mn/` with `ADMIN_PASSWORD`. **If login fails while
`/api/ready` is green, suspect TLS or the cookie**: `Secure` cookies are silently dropped
over plaintext HTTP, which is what happened before the proxy existed.

---

## 6. Worker and scheduler

The scheduler runs **inside the worker** in this topology (`web` sets
`DISABLE_INLINE_SCHEDULER=1`). Verify it is alive:

```bash
curl -sS https://staging.example.mn/api/admin/worker/health \
  -H "Cookie: session=<admin session>" | python3 -m json.tool
```

Expected `worker.status` = `alive`, with `heartbeat.age_seconds` under ~150 s, roughly
matching the 45 s tick. Statuses and what they mean:

| status | meaning | action |
|---|---|---|
| `alive` | a tick completed recently | none |
| `stale` | key present but old — the loop is wedged | inspect worker logs; a handler may be hanging |
| `missing` | no key — never started or TTL lapsed | check the container is running |
| `unknown` | Redis unreadable | check Redis; this is not a claim of health |

The endpoint returns **503** unless the worker is `alive`, so a monitor can alert on status
code alone.

---

## 7. Backups

Install the timer on the host (see `docs/SCHEDULER-SETUP.md`), pointed at the staging
compose file:

```bash
python scripts/maintenance.py scheduler install --yes \
  --working-dir /opt/gerege-staging \
  --env-file /opt/gerege-staging/.env \
  --exec-start '/usr/bin/docker compose -f docker-compose.staging.yml --profile maintenance run --rm --no-deps maintenance python scripts/maintenance.py backup-run --label scheduled'
sudo systemctl daemon-reload && sudo systemctl enable --now gerege-backup.timer
```

Then **prove it works** rather than assuming:

```bash
docker compose -f docker-compose.staging.yml --profile maintenance \
  run --rm --no-deps maintenance python scripts/maintenance.py backup-run --label first
docker compose -f docker-compose.staging.yml --profile maintenance \
  run --rm --no-deps maintenance python scripts/maintenance.py status
```

A backup that has never been restored is a file, not a backup. Restore into a scratch
database and compare row counts before trusting it:

```bash
# on the host, with an owner DSN pointing at a NEW empty database
python scripts/maintenance.py restore <archive> --yes
```

---

## 8. Integrations

Use sandbox credentials only. See `docs/deployment/STAGING_INTEGRATION_MATRIX.md` for the
per-provider test plan. Two hard rules:

* **never** point staging's Telegram bot at the production bot — a test message reaches real
  customers;
* **never** put live QPay merchant credentials in a staging file.

---

## 9. Rollback

```bash
bash scripts/rollback.sh
```

Code and data roll back independently and the script says which happened. Schema rollback
is a separate matter: past migration **0004** it is only possible when no two tenants share
a `sender_id`, and it refuses rather than destroying data. On a multi-tenant database,
treat it as unavailable and restore instead. Detail: `PRODUCTION_DEPLOYMENT.md` §5.1.

---

## 10. Teardown

```bash
docker compose -f docker-compose.staging.yml down            # keep volumes
docker compose -f docker-compose.staging.yml down -v         # DESTROY staging data
```

`-v` deletes `pgdata`, `backups` and `caddy_data`. Losing `caddy_data` means re-issuing
certificates on next start, which is rate-limited. Take a backup first if any of the staging
data is worth keeping.

---

## 11. What is still not verified

Being explicit so nobody mistakes a green staging for a green production:

* The Caddyfile has **never been parsed by Caddy** in this repository's test suite. Run
  `caddy validate --config deploy/Caddyfile --adapter caddyfile` on the host before first start.
* The base image digest is a **placeholder**; resolve it before building (§ audit report).
* No Docker build has been executed — Docker is unavailable in the audit environment.
* No integration has been exercised against a live provider.
