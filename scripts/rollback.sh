#!/usr/bin/env bash
set -euo pipefail

echo "=== [Gerege Rollback] Initiating emergency rollback ==="

if [ -f .last_working_commit ]; then
  TARGET_COMMIT=$(cat .last_working_commit)
  echo "Rolling back git working tree to $TARGET_COMMIT ..."
  git checkout "$TARGET_COMMIT"
fi

echo "Restoring latest pre_deploy database backup if available..."
python - <<'PY'
from core import backup_service
backups = backup_service.list_backups()
pre = [b for b in backups if "pre_deploy" in b["filename"]]
if pre:
    res = backup_service.restore_backup(pre[0]["filename"])
    print("Database restore result:", res)
else:
    print("No pre_deploy backup found, keeping current database state.")
PY

if command -v docker >/dev/null 2>&1 && [ -f docker-compose.prod.yml ]; then
  docker compose -f docker-compose.prod.yml up -d --build
fi

echo "=== [Gerege Rollback] Completed ==="
