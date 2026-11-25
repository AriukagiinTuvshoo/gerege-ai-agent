#!/usr/bin/env bash
# Emergency rollback to the last recorded working commit and its pre-deploy snapshot.
#
# Phase 16: two defects fixed here.
#
#  1. The restore path re-applied grants with `--converge-only`, which is correct for a
#     *restored* database (the dump is replayed with `--no-owner`, so ownership has to be
#     transferred first — `maintenance.py restore` does that). But if the restore itself
#     did not happen, the script still restarted the services and printed "Completed",
#     reporting a rollback that had not occurred. Every branch now states plainly what it
#     did and did not do, and a failed restore is fatal.
#
#  2. Nothing verified ownership afterwards. `--verify` now covers it.
set -euo pipefail

echo "=== [Gerege Rollback] Initiating emergency rollback ==="

ROLLED_BACK_CODE=no
ROLLED_BACK_DATA=no

if [ -f .last_working_commit ]; then
  TARGET_COMMIT=$(cat .last_working_commit)
  echo "Rolling back git working tree to $TARGET_COMMIT ..."
  git checkout "$TARGET_COMMIT"
  ROLLED_BACK_CODE=yes
else
  echo "No .last_working_commit: code is NOT being rolled back."
fi

echo "Restoring latest pre_deploy database backup if available..."
if [ -n "${DATABASE_OWNER_URL:-}" ]; then
  # `maintenance.py list` prints one archive per line; the label filter keeps the newest
  # pre_deploy snapshot only.
  # Phase 18: this used to grep `maintenance.py list` for a `pre_deploy` archive and
  # silently skip the restore when the result was empty. Since the deploy path encrypts
  # the snapshot, `list` could not see it, so PRE was always empty and every rollback
  # recovered code while leaving the database from the failed deploy in place -- while
  # still printing "Completed". `list` now reports encrypted archives, and an empty
  # result here is a hard failure rather than a quiet no-op.
  PRE=$(python scripts/maintenance.py list | grep pre_deploy | head -1 | awk '{print $1}') || PRE=""
  if [ -n "${PRE:-}" ]; then
    # A restore recreates tables, so ownership and grants are re-converged afterwards.
    # `restore` fails closed (non-zero) rather than leaving a half-restored database.
    if ! python scripts/maintenance.py restore "$PRE" --yes; then
      echo "ERROR: restore of '$PRE' failed. The database may be in an intermediate" >&2
      echo "state. Do not start the application; investigate before continuing." >&2
      exit 1
    fi
    ROLLED_BACK_DATA=yes
    # Full `--apply`, not `--converge-only`: the replayed dump recreates objects that
    # must be re-owned by gerege_owner before the grants mean anything, and before the
    # maintenance guard will allow the next backup (HIGH-01).
    python scripts/provision_roles.py --apply || {
      echo "ERROR: could not re-converge ownership/grants after restore." >&2
      echo "Run: python scripts/provision_roles.py --apply --admin-url <owner-or-admin-dsn>" >&2
      exit 1
    }
    python scripts/provision_roles.py --verify
  else
    echo "ERROR: no pre_deploy snapshot was found, so the database has NOT been rolled" >&2
    echo "       back. The schema and data still come from the failed deploy. Starting the" >&2
    echo "       previous release against it may fail or corrupt data." >&2
    echo "       Inspect: python scripts/maintenance.py list" >&2
    echo "       Then restore a known-good archive by hand before restarting anything." >&2
    exit 1
  fi
else
  echo "WARNING: DATABASE_OWNER_URL is not set, so the database is NOT being rolled back." >&2
  echo "         Only application code was reverted; the data still comes from the failed" >&2
  echo "         deploy. Set DATABASE_OWNER_URL and re-run to restore a snapshot." >&2
  exit 1
fi

if command -v docker >/dev/null 2>&1 && [ -f docker-compose.prod.yml ]; then
  docker compose -f docker-compose.prod.yml up -d --build
fi

echo "=== [Gerege Rollback] Completed ==="
echo "    code rolled back:     $ROLLED_BACK_CODE"
echo "    database rolled back: $ROLLED_BACK_DATA"
if [ "$ROLLED_BACK_DATA" = "no" ]; then
  echo "    NOTE: the database still contains the state produced by the failed deploy." >&2
  echo "    If the previous release is not schema-compatible, this will fail at runtime." >&2
fi
