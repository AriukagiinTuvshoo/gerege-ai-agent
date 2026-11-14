# SQLite-to-PostgreSQL Migration Guide

## 1. Overview (`scripts/migrate_sqlite_to_postgres.py`)

The migration pipeline transfers all 15 tables from SQLite (`leads.db`) to PostgreSQL 16 (or a target SQLite database) with deterministic row-level and table-level verification:
- **Safe Online Snapshot**: Creates a temporary consistent snapshot via `sqlite3.Connection.backup()` before reading.
- **Batch Processing**: Streams rows ordered by primary key in configurable batches (`--batch-size 500`).
- **Deterministic Row & Table Checksums**: Computes canonical JSON SHA-256 hashes (`compute_canonical_row_hash`, `compute_table_checksum`) across all columns for every table.
- **Strict Conflict Policy (Never Overwrites Silently)**:
  - If a primary key already exists in the target database with an **identical** canonical row hash, it is safely skipped (`identical_skipped`) so re-running the migration is 100% idempotent.
  - If a primary key exists in the target database with **different** column values, the migration immediately records the exact column diff in `report["conflicts"]`, rolls back the transaction, and exits with `status = "CONFLICT_DETECTED"` without overwriting target data.

## 2. Step-by-Step Execution

### Step 1: Dry-Run Inspection & Source Checksums
```bash
python scripts/migrate_sqlite_to_postgres.py --dry-run
```

### Step 2: Apply Alembic Schema on Target PostgreSQL Database
```bash
export DATABASE_URL="postgresql+psycopg2://gerege:password@localhost:5432/gerege_crm"
alembic upgrade head
```

### Step 3: Execute Migration & Post-Migration Verification
```bash
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-path leads.db \
  --postgres-url "$DATABASE_URL" \
  --batch-size 500 \
  --report-path backups/migration_report.json
```

## 3. Verification Criteria (`status == "MIGRATED_AND_VERIFIED"`)

The script only returns exit code `0` when all of the following hold:
1. `conflicts == []` (zero conflicting rows).
2. `source_count == target_count` for all 15 tables.
3. `source_checksum == target_checksum` (SHA-256 canonical table hash) for all 15 tables.
4. `paid_revenue_match == True` and `pending_revenue_match == True` (exact financial MNT equality).
