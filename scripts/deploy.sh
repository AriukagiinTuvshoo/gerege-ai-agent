#!/usr/bin/env bash
set -euo pipefail

echo "=== [Gerege Deploy] 1. Creating pre-deploy DB backup ==="
# E-05: backup runs on the maintenance plane, not as the runtime role. `gerege_app`
# cannot pg_dump (no LOCK TABLE rights), and the old form would have produced a 0-byte
# archive reported as success. This uses the owner credential from DATABASE_OWNER_URL.
if [ -n "${DATABASE_OWNER_URL:-}" ]; then
  python scripts/maintenance.py backup --label pre_deploy
else
  echo "DATABASE_OWNER_URL is not set: skipping the pre-deploy backup."
  echo "Set it (or run the maintenance container) so a rollback has a restore point."
fi

PREV_COMMIT=$(git rev-parse HEAD)
echo "$PREV_COMMIT" > .last_working_commit
echo "Recorded rollback target commit: $PREV_COMMIT"

echo "=== [Gerege Deploy] 2. Pulling latest code & running migrations ==="
git pull --ff-only origin main
# E-05: migrations, ownership transfer and the grant plan are one provisioning pass.
# Running bare `alembic upgrade head` as an unprivileged account leaves new tables
# unowned and ungranted; `--apply` leaves the database in the state the app requires.
python scripts/provision_roles.py --apply
alembic upgrade head || python -c "import database; database.init_db()"
python scripts/provision_roles.py --apply --converge-only
python scripts/provision_roles.py --verify

echo "=== [Gerege Deploy] 3. Restarting production services ==="
if command -v docker >/dev/null 2>&1 && [ -f docker-compose.prod.yml ]; then
  docker compose -f docker-compose.prod.yml up -d --build
fi

echo "=== [Gerege Deploy] 4. Running post-deploy healthcheck ==="
sleep 3
if ! curl -fsS "http://127.0.0.1:${PORT:-8000}/api/health" >/dev/null; then
  echo "Healthcheck FAILED! Triggering automatic rollback..."
  bash scripts/rollback.sh
  exit 1
fi

echo "=== [Gerege Deploy] SUCCESS! ==="
