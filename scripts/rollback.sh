#!/usr/bin/env bash
set -euo pipefail

echo "=== [Gerege Rollback] Initiating emergency rollback ==="

if [ -f .last_working_commit ]; then
  TARGET_COMMIT=$(cat .last_working_commit)
  echo "Rolling back git working tree to $TARGET_COMMIT ..."
  git checkout "$TARGET_COMMIT"
fi

echo "Restoring latest pre_deploy database backup if available..."
# E-05: restore is owner-credentialed maintenance, never the runtime role.
if [ -n "${DATABASE_OWNER_URL:-}" ]; then
  PRE=$(python scripts/maintenance.py list | grep pre_deploy | head -1 | awk '{print $1}')
  if [ -n "${PRE:-}" ]; then
    python scripts/maintenance.py restore "$PRE" --yes
    # A restore recreates tables, so re-apply the grants before the app restarts.
    python scripts/provision_roles.py --apply --converge-only
    python scripts/provision_roles.py --verify
  else
    echo "No pre_deploy backup found, keeping current database state."
  fi
else
  echo "DATABASE_OWNER_URL is not set: cannot restore. Keeping current database state."
fi

if command -v docker >/dev/null 2>&1 && [ -f docker-compose.prod.yml ]; then
  docker compose -f docker-compose.prod.yml up -d --build
fi

echo "=== [Gerege Rollback] Completed ==="
