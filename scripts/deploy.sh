#!/usr/bin/env bash
set -euo pipefail

echo "=== [Gerege Deploy] 1. Creating pre-deploy DB backup ==="
python -c "from core import backup_service; res = backup_service.create_backup('pre_deploy'); print(res)"

PREV_COMMIT=$(git rev-parse HEAD)
echo "$PREV_COMMIT" > .last_working_commit
echo "Recorded rollback target commit: $PREV_COMMIT"

echo "=== [Gerege Deploy] 2. Pulling latest code & running migrations ==="
git pull --ff-only origin main
alembic upgrade head || python -c "import database; database.init_db()"

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
