#!/usr/bin/env bash
# Deploy the application with least-privilege role separation converged.
#
# Phase 16 (HIGH-01). The previous version migrated as the bootstrap account and then
# ran `provision_roles.py --apply --converge-only`. `--converge-only` emits GRANT and
# REVOKE statements only — it contains no `ALTER ... OWNER TO` — so on a fresh database
# every table stayed owned by the bootstrap superuser. That state passes every privilege
# check (the runtime grants are correct) but cannot be backed up: `pg_dump` needs
# ownership, so the maintenance guard refuses `gerege_owner`. The deployment reported
# success and left the cluster unable to take a backup.
#
# The sequence below is the same one `docker-compose.prod.yml` uses:
#
#   provision (create roles)  ->  migrate  ->  provision (transfer ownership + grants)
#                              ->  verify   ->  start services
#
# Ownership transfer must come *after* the migration, because the migration creates the
# tables as the bootstrap account. It must be a full `--apply`, because only the full
# plan contains the ownership statements. Every step is idempotent, so an interrupted
# run is repaired by re-running the script.
set -euo pipefail

ADMIN_URL="${ADMIN_DATABASE_URL:-}"
OWNER_URL="${DATABASE_OWNER_URL:-}"

echo "=== [Gerege Deploy] 1. Pre-deploy database backup ==="
# The backup runs on the maintenance plane with the owner credential. `gerege_app`
# cannot `pg_dump` (no ownership, so no LOCK TABLE), and the old in-app path could
# record a 0-byte archive as a success.
#
# Phase 16: a missing backup used to be an `echo` and the deploy continued. A deploy
# without a restore point is a decision an operator has to make deliberately, so it now
# requires an explicit, loud override.
if [ -z "$OWNER_URL" ]; then
  if [ "${ALLOW_DEPLOY_WITHOUT_BACKUP:-0}" = "1" ]; then
    echo "WARNING: DATABASE_OWNER_URL is not set and ALLOW_DEPLOY_WITHOUT_BACKUP=1."
    echo "WARNING: deploying with NO restore point. A failed deploy cannot be rolled back."
  else
    cat >&2 <<'MSG'
ERROR: refusing to deploy without a backup.

DATABASE_OWNER_URL is not set, so no pre-deploy snapshot can be taken. A deployment
with no restore point cannot be rolled back, and the rollback path would have to
restore nothing and then restart the services anyway.

Set DATABASE_OWNER_URL to the gerege_owner DSN, or — if you have accepted the risk —
re-run with ALLOW_DEPLOY_WITHOUT_BACKUP=1.
MSG
    exit 1
  fi
else
  python scripts/maintenance.py backup --label pre_deploy
fi

PREV_COMMIT=$(git rev-parse HEAD)
echo "$PREV_COMMIT" > .last_working_commit
echo "Recorded rollback target commit: $PREV_COMMIT"

echo "=== [Gerege Deploy] 2. Pulling latest code ==="
git pull --ff-only origin main

echo "=== [Gerege Deploy] 3. Provisioning roles (create/refresh) ==="
# Pass 1: on a fresh volume there are no tables yet; this only creates the two roles.
python scripts/provision_roles.py --apply

echo "=== [Gerege Deploy] 4. Running migrations as the bootstrap account ==="
# The bootstrap account owns what it creates, which is why the next step exists.
alembic upgrade head || python -c "import database; database.init_db()"

echo "=== [Gerege Deploy] 5. Converging ownership and grants ==="
# Pass 2, full plan: `ALTER TABLE/SEQUENCE/FUNCTION ... OWNER TO gerege_owner` followed
# by the grant plan. This is the step that makes backup possible. `--converge-only`
# would run the grants but skip the ownership transfer, which is HIGH-01.
#
# Requires a credential that is a member of `gerege_owner` (the bootstrap superuser is).
if [ -z "$ADMIN_URL" ]; then
  echo "ERROR: ADMIN_DATABASE_URL is required to transfer ownership to gerege_owner." >&2
  exit 1
fi
python scripts/provision_roles.py --apply

echo "=== [Gerege Deploy] 6. Verifying the deployed state ==="
# Exits non-zero if the runtime role is over-privileged, under-provisioned, missing, or
# if any relation is not owned by gerege_owner. Nothing starts if this fails.
python scripts/provision_roles.py --verify

echo "=== [Gerege Deploy] 7. Restarting production services ==="
# `compose up` re-runs the `migrate` service first, which repeats the same
# provision -> migrate -> provision -> verify sequence inside the cluster network, and
# `web`/`worker` wait on `service_completed_successfully`. The host-side sequence above
# exists so a failure surfaces here, before any container is replaced.
if command -v docker >/dev/null 2>&1 && [ -f docker-compose.prod.yml ]; then
  docker compose -f docker-compose.prod.yml up -d --build
fi

echo "=== [Gerege Deploy] 8. Post-deploy healthcheck ==="
sleep 3
# Phase 36: gate on /api/ready, not /api/health.
#
# /api/health used to materialise every registration and every page's sessions, so its
# cost grew with the tenant's data (measured 28 ms empty -> 94.6 ms at 10k rows) and this
# gate could fail a deploy on a large-but-healthy database. /api/ready performs one
# `SELECT 1` plus the queue and limiter checks (~6 ms) and is what the container
# healthcheck and the load balancer already use, so the deploy now verifies the same
# readiness signal the runtime does.
# Phase 38: probe from INSIDE the web container, not from the host on a published port.
#
# `docker-compose.prod.yml` no longer publishes 8000 — the API is reachable only through
# the `proxy` service — so a host-side `curl http://127.0.0.1:8000/api/ready` can never
# connect. Left unchanged, every production deploy would have failed this gate and
# triggered an automatic rollback of a perfectly healthy release. That is the exact class
# of breakage a topology change causes in a script that assumed the old topology.
#
# `docker compose exec` runs inside the container's network namespace, so this checks the
# same endpoint the container healthcheck uses, without exposing a port.
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"
if ! docker compose -f "$COMPOSE_FILE" exec -T web \
      python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/ready', timeout=5)" \
      >/dev/null 2>&1; then
  echo "Healthcheck FAILED (/api/ready)! Triggering automatic rollback..." >&2
  bash scripts/rollback.sh
  exit 1
fi

echo "=== [Gerege Deploy] SUCCESS ==="
