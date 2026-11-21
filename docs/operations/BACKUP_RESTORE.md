# Backup & Atomic Restore Runbook

## 1. Backup Architecture (`core/backup_service.py`)

Every backup operation generates three artifacts inside `backups/`:
1. **Compressed Archive**: `gerege_<engine>_<label>_<timestamp>.db.gz` (SQLite online backup) or `.sql.gz` (`pg_dump --clean --if-exists --no-owner --no-privileges`).
2. **SHA-256 Checksum File**: `<filename>.sha256` containing the hex digest of the compressed archive.
3. **Metadata Manifest**: `<filename>.meta.json` recording `engine`, `schema_version`, `size_bytes`, `sha256`, `table_counts`, and `total_rows`.

## 2. Operational Commands

> **Changed in E-05.** Backup and restore are owner-credentialed maintenance operations.
> They are no longer reachable over HTTP and no longer run inside the worker. See
> [LEAST_PRIVILEGE_ROLES.md](LEAST_PRIVILEGE_ROLES.md) for why.

### Create a Backup
```bash
# Host, with the owner DSN in the environment:
DATABASE_OWNER_URL="postgresql://gerege_owner:@db:5432/gerege_crm" \
  python scripts/maintenance.py backup --label pre_release

# Or through the one-shot container (no local Python needed):
docker compose -f docker-compose.prod.yml run --rm maintenance \
  python scripts/maintenance.py backup --label pre_release
```

### Verify Backup Integrity (Checksum + Archive Structure + Manifest)
```bash
python scripts/maintenance.py verify <filename>
```

### Atomic Restore (With Automatic `pre_restore` Safety Snapshot)
```bash
python scripts/maintenance.py restore <filename>          # interactive confirmation
python scripts/maintenance.py restore <filename> --yes    # non-interactive (cron/CI)
```
Restore refuses to run non-interactively without `--yes`, verifies the archive *before*
taking the pre-restore snapshot, and re-applies the runtime grants afterwards (a dump
taken with `--no-owner --no-privileges` recreates tables, and the schema default
privileges would otherwise re-widen `gerege_app` to full CRUD on `audit_logs`).

### Scheduled Backups
The worker's 03:00 job was removed: it ran as `gerege_app`, which cannot `pg_dump`.
Schedule it on the host instead:

```cron
0 3 * * * cd /srv/gerege && docker compose -f docker-compose.prod.yml run --rm \
  maintenance python scripts/maintenance.py backup --label daily_auto \
  && docker compose -f docker-compose.prod.yml run --rm \
  maintenance python scripts/maintenance.py prune --days 14
```

### API surface after E-05

| Endpoint | Status |
|---|---|
| `GET  /api/admin/backups` | kept — reads the backups directory |
| `POST /api/admin/backups/verify` | kept — checksum/structural check |
| `POST /api/admin/backups/create` | **removed** — cannot work as `gerege_app` |
| `POST /api/admin/backups/restore` | **removed** — needs ownership |

## 3. Restore Safety Guarantees

- **Pre-Check**: `restore_backup()` runs `verify_backup()` before touching the live database. If the SHA-256 checksum or gzip header is invalid, restore aborts immediately.
- **Pre-Restore Snapshot**: Before overwriting any data, `create_backup(label="pre_restore")` snapshots the current database state.
- **SQLite Staging Verification**: Decompresses into a temporary `.restore_staging` file and runs `PRAGMA integrity_check` before atomically swapping onto the live database file.
- **PostgreSQL Single-Transaction Restore**: Executes `psql --single-transaction -v ON_ERROR_STOP=1` so any SQL error rolls back the entire restore without leaving partial state.
