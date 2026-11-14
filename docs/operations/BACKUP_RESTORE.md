# Backup & Atomic Restore Runbook

## 1. Backup Architecture (`core/backup_service.py`)

Every backup operation generates three artifacts inside `backups/`:
1. **Compressed Archive**: `gerege_<engine>_<label>_<timestamp>.db.gz` (SQLite online backup) or `.sql.gz` (`pg_dump --clean --if-exists --no-owner --no-privileges`).
2. **SHA-256 Checksum File**: `<filename>.sha256` containing the hex digest of the compressed archive.
3. **Metadata Manifest**: `<filename>.meta.json` recording `engine`, `schema_version`, `size_bytes`, `sha256`, `table_counts`, and `total_rows`.

## 2. Operational Commands

### Create a Backup
```bash
python -c "from core import backup_service; print(backup_service.create_backup(label='pre_release'))"
```

### Verify Backup Integrity (Checksum + Archive Structure + Manifest)
```bash
python -c "from core import backup_service; print(backup_service.verify_backup('<filename>'))"
```

### Atomic Restore (With Automatic `pre_restore` Safety Snapshot)
```bash
python -c "from core import backup_service; print(backup_service.restore_backup('<filename>'))"
```

## 3. Restore Safety Guarantees

- **Pre-Check**: `restore_backup()` runs `verify_backup()` before touching the live database. If the SHA-256 checksum or gzip header is invalid, restore aborts immediately.
- **Pre-Restore Snapshot**: Before overwriting any data, `create_backup(label="pre_restore")` snapshots the current database state.
- **SQLite Staging Verification**: Decompresses into a temporary `.restore_staging` file and runs `PRAGMA integrity_check` before atomically swapping onto the live database file.
- **PostgreSQL Single-Transaction Restore**: Executes `psql --single-transaction -v ON_ERROR_STOP=1` so any SQL error rolls back the entire restore without leaving partial state.
