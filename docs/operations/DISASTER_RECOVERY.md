# Phase 4 — Backup & Disaster Recovery Runbook (`DISASTER_RECOVERY.md`)

**Status:** Completed (P1)  
**Primary Module:** [`core/backup_service.py`](../../core/backup_service.py), [`routers/system_router.py`](../../routers/system_router.py)

---

## 1. Recovery Objectives (RPO & RTO)

- **Recovery Point Objective (RPO):** <= 24 hours via automated daily 03:00 AM snapshots (`worker.py`), or 0 minutes before any manual migration/restore (`pre_restore` automatic snapshot).
- **Recovery Time Objective (RTO):** <= 5 minutes via `scripts/maintenance.py restore` (E-05: the restore HTTP endpoint was removed; restore requires the owner credential).
- **Retention Policy:** 14 days rolling retention (`backup_service.prune_old_backups(keep_days=14)`).

---

## 2. Backup Creation & Integrity Verification

### 2.1 PostgreSQL (`pg_dump` + Gzip + SHA-256)
- When `DATABASE_URL` is PostgreSQL (`postgresql://...`), `backup_service.create_backup()` executes:
  ```bash
  pg_dump --no-owner --no-privileges "$DATABASE_URL" | gzip > backups/pg_backup_<label>_<timestamp>.sql.gz
  ```
- Computes SHA-256 and writes `backups/pg_backup_<label>_<timestamp>.sql.gz.sha256`.
- `backup_service.verify_backup()` validates:
  1. SHA-256 digest matches `.sha256` manifest.
  2. Full gzip stream decompresses without corruption.
  3. SQL dump contains valid PostgreSQL DDL/DML headers (`PostgreSQL database dump`, `CREATE TABLE`, `SET`, `COPY`, `INSERT INTO`).

### 2.2 SQLite (`sqlite3.backup` + Gzip + SHA-256 + Isolated Integrity Check)
- When using SQLite, `backup_service.create_backup()` uses the online SQLite backup API (`src_conn.backup(dst_conn)`) into a temporary file, compresses to `.db.gz`, and writes `.sha256`.
- `backup_service.verify_backup()` decompresses `.db.gz` into an isolated temporary SQLite database, executes `PRAGMA integrity_check`, and verifies that core tables (`pages`, `registrations`, `invoices`) are present and readable.

---

## 3. Restore Runbook

### 3.1 Via the Maintenance CLI (E-05: owner credential, explicit operator action)
```bash
# 1. List available backups (read-only; this one is also available over HTTP)
python scripts/maintenance.py list
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:8000/api/admin/backups

# 2. Verify backup integrity before restore
python scripts/maintenance.py verify <filename>

# 3. Restore (verifies the archive, then creates a pre_restore snapshot)
docker compose -f docker-compose.prod.yml run --rm maintenance \
  python scripts/maintenance.py restore <filename>

# 4. Confirm the runtime role is still least-privileged, then start the app
python scripts/provision_roles.py --verify
```

Restore requires the owner credential (`DATABASE_OWNER_URL`, or the `maintenance`
service). It cannot be done as `gerege_app`: replaying a dump drops and recreates the
schema, which needs ownership. The old `POST /api/admin/backups/restore` endpoint was
removed for that reason — see [LEAST_PRIVILEGE_ROLES.md](LEAST_PRIVILEGE_ROLES.md).

### 3.2 Via CLI into an Isolated Target Database (Restore Drill)
```python
from core import backup_service

# 1. Create a fresh backup
bk = backup_service.create_backup(label="drill")
assert bk["success"] is True

# 2. Verify SHA-256 and structural integrity
ver = backup_service.verify_backup(bk["filename"])
assert ver["valid"] is True

# 3. Restore (for PostgreSQL, pass target_db_url to test on a throwaway database)
res = backup_service.restore_backup(bk["filename"])
assert res["success"] is True
```
