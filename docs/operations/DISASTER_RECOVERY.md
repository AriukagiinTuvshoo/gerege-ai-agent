# Phase 4 — Backup & Disaster Recovery Runbook (`DISASTER_RECOVERY.md`)

**Status:** Completed (P1)  
**Primary Module:** [`core/backup_service.py`](../../core/backup_service.py), [`routers/system_router.py`](../../routers/system_router.py)

---

## 1. Recovery Objectives (RPO & RTO)

> **Corrected in Phase 16 (MEDIUM-02).** The previous text claimed "RPO ≤ 24 hours via
> automated daily 03:00 AM snapshots (`worker.py`)". **That scheduler no longer exists.**
> E-05 removed backup execution from `worker.py`, because `pg_dump` requires table
> ownership and the restricted runtime role deliberately does not have it. No
> replacement timer is installed by this repository, so *no RPO can be quoted*.

- **Recovery Point Objective (RPO):** **NOT CONFIGURED / undefined.** The RPO equals the
  interval of whatever external scheduler is installed around
  `scripts/maintenance.py backup-run` (see
  [BACKUP_AUTOMATION.md](BACKUP_AUTOMATION.md)). `deploy/systemd/gerege-backup.timer`
  and `deploy/cron/gerege-backup.cron` are templates in this repository; **neither is
  installed on any host by this repository**. Until one is installed and verified with
  `systemctl list-timers`, the only backup is one an operator takes by hand.
- **Manual backup:** `python scripts/maintenance.py backup --label manual` (owner
  credential). A pre-deploy snapshot is taken by `scripts/deploy.sh`, which now
  **refuses to deploy without one** unless explicitly overridden.
- **Recovery Time Objective (RTO):** **UNMEASURED.** Restore is
  `scripts/maintenance.py restore` with the owner credential (E-05 removed the restore
  HTTP endpoint). The only defensible RTO figure is one measured in a restore drill on
  the real dataset — see §3.2. The previous "≤ 5 minutes" was never measured.
- **Retention Policy:** age-based (`BACKUP_RETENTION_DAYS`, default 14) with a hard
  count floor (`BACKUP_MIN_KEEP`, default 7), so a retention bug cannot delete every
  archive. Enforced by `maintenance.py backup-run` and available manually via
  `maintenance.py prune --days N`.

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

> **Corrected in Phase 16.** The previous snippet called
> `backup_service.create_backup()` and `restore_backup()` directly. Both now run the
> E-05 maintenance-credential guard, so they only work from a process whose
> `DATABASE_URL` is the **owner** credential — `create_backup()` from an interactive
> Python shell using the runtime DSN is refused by design. Use the CLI, which sets the
> credential explicitly and cannot be pointed at the wrong role by accident.

A backup that has never been restored is a hypothesis. Run this **at least quarterly**,
against an isolated database — never production:

```bash
# 1. Decrypt the newest archive (skip if BACKUP_ENCRYPTION=off).
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
    -in backups/<archive>.sql.gz.enc -out /tmp/drill.sql.gz \
    -pass file:/etc/gerege/backup.key
gunzip -t /tmp/drill.sql.gz && echo "gzip OK"

# 2. Restore into a THROWAWAY database. Requires the owner credential.
DATABASE_OWNER_URL=postgresql://gerege_owner:...@host:5432/gerege_drill \
    python scripts/maintenance.py restore <archive> --yes

# 3. Prove the restored copy is complete AND correctly owned. `--verify` now checks
#    ownership as well as privileges (Phase 16, HIGH-01).
DATABASE_URL=postgresql://gerege_owner:...@host:5432/gerege_drill \
    python scripts/provision_roles.py --verify

# 4. Record the wall-clock time of step 2. That measurement is the RTO.
#    Record the archive timestamp vs. now. That interval is the RPO you actually have.
```

Delete the drill database afterwards. A drill that is never recorded did not happen:
write the measured RTO and the date into the operations log.
