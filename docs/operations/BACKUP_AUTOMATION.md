# Backup automation — architecture decision and configuration

**Status:** repository-level infrastructure implemented; **external scheduler NOT CONFIGURED**
**Applies to:** E-05 / Phase 16 (MEDIUM-02)

---

## 1. Why this decision exists

E-05 removed backup execution from the web process, because `pg_dump` needs table
ownership and the runtime role deliberately no longer has it. That was correct. What
was not done was replacing the removed schedule: Phase 15 found **no cron, systemd
timer, Kubernetes CronJob or in-process scheduler anywhere in the repository**, while
`PRODUCTION_DEPLOYMENT.md` and `DISASTER_RECOVERY.md` still promised an automated
daily backup and a 24-hour RPO.

A feature that removes a schedule is not complete until the replacement is specified.
This document records the options considered, the choice, and exactly what remains
outside this repository.

## 2. Options considered

| | Option | Owner credential exposure | Failure visibility | Fits this repo? |
|---|---|---|---|---|
| **A** | Host cron or systemd timer calling `maintenance.py backup-run` | Key lives in a root-readable env file; only the timer process sees it | Timer unit can report exit status; needs `OnFailure=` or a wrapper | **Yes** — smallest moving part, no new long-running process |
| **B** | Dedicated Compose "scheduler" service (looping container) | Same secret, but it becomes a permanently-running container holding the owner DSN | Needs its own healthcheck; a crashed loop looks like a healthy container unless monitored | Possible, but it adds a long-lived process whose only job is `sleep` |
| **C** | External infrastructure scheduler (cloud cron, K8s CronJob, managed backup) | Depends on the platform's secret handling | Usually the best: native retry/alerting | **Best long-term**, but it is infrastructure, and nothing in this repo can configure or verify it |
| **D** | GitHub Actions scheduled workflow | Owner DSN must become a CI secret reachable from GitHub-hosted runners | GitHub run notifications | **Rejected** — it requires network-reachable production database credentials to live in a third-party CI system, contradicting the E-05 boundary that owner credentials stay on the maintenance plane |

## 3. Decision

**A is the implemented path; C is the recommended production target.**

Rationale: the repository already ships everything option A needs — `postgresql-client`
in the image, `scripts/maintenance.py`, and `docker-compose.prod.yml` with a
`maintenance` service that is `restart: "no"` and profile-scoped. Option A adds no
long-running process and keeps the owner credential on the host that already holds it.
Option D was rejected on security grounds, not convenience. Option C remains the
recommendation for any real estate: a managed cron with managed secrets and native
alerting is strictly better than a host timer, and nothing here prevents it.

Both options invoke the **same** command, so switching later changes only the trigger:

```bash
docker compose -f docker-compose.prod.yml run --rm maintenance \
    python scripts/maintenance.py backup-run --label scheduled
```

## 4. What a scheduled run does

`scripts/maintenance.py backup-run` → `core/backup_automation.run_scheduled_backup()`:

1. **Backup** via `backup_service.create_backup()` — which still runs the E-05
   capability guard first, so a credential that cannot dump fails *before* a process is
   spawned rather than producing a 0-byte archive.
2. **Verify** the archive with `backup_service.verify_backup()` (gzip stream, SQL
   structure, SHA-256). An unverifiable archive is treated as a failed backup.
3. **Encrypt** with **AES-256-GCM** (authenticated). Phase 18 replaced the Phase 16
   `openssl enc -aes-256-cbc` call, which had no MAC: a modified archive decrypted
   cleanly and nothing could tell a genuine archive from a forged one. `openssl enc`
   cannot do AEAD at all in OpenSSL 3.0, so the primitive comes from the `cryptography`
   package. The key is read from a **file**, never `argv`. See
   [BACKUP_ENCRYPTION.md](BACKUP_ENCRYPTION.md) for the container format.
4. **Round-trip check** — the ciphertext is decrypted and authenticated once before it is
   published, so an archive that was written wrong is never recorded as a backup.
5. **Offsite upload** through a provider interface: S3-compatible over HTTPS with SigV4,
   or an explicitly-labelled local directory. With nothing configured the run reports
   `NOT CONFIGURED` rather than treating a same-disk copy as offsite.
6. **Retention** by age (`BACKUP_RETENTION_DAYS`, default 14) with a hard count floor
   (`BACKUP_MIN_KEEP`, default 7, clamped to >= 1) so a retention bug can never delete
   every backup. Sidecars are removed with their archive.

   Retention deletes only what it can classify as a superseded restore point. It
   **never deletes a plaintext archive**, whatever its age, and it **never deletes a file
   it cannot classify** — an `.enc` whose header this build does not recognise may come
   from a newer format or a different key, and deleting it to satisfy an age rule is not a
   decision retention is allowed to make. Both were wrong before Phase 22: an aged
   plaintext dump was deleted while an encrypted archive was kept, and an unclassifiable
   `.enc` was swept.

   Plaintext leftovers are reported by `maintenance.py legacy` (exit 17) and removed only
   by `maintenance.py legacy --quarantine <dir> --yes`, which **moves** them and never
   deletes. That command is the single path by which plaintext leaves `BACKUP_DIR`.
7. **Status file** `<BACKUP_DIR>/.last_backup_status.json` and an optional
   `BACKUP_ALERT_WEBHOOK` POST.

The whole run holds an exclusive `flock` on `<BACKUP_DIR>/.backup.lock`, so two timers,
or a backup and a prune, cannot overlap. The kernel releases the lock on process death
(including `SIGKILL`), so a crash cannot wedge the backup system.

**In production, nothing plaintext ever enters `BACKUP_DIR`.** The dump is written into a
private 0700 `.staging-*` directory inside the same filesystem and only the ciphertext is
published by an atomic rename; the staging directory is destroyed on success, on exception,
on `SIGTERM` and at interpreter exit, and a directory left by a `SIGKILL` is swept at the
start of the next run. Production cannot disable encryption at all
(`core/backup_policy.py`), so the plaintext file never leaves staging.

Outside production, `BACKUP_ENCRYPTION=off` is still available for local development. In
that mode the dump **is** published to `BACKUP_DIR` as a plaintext `.sql.gz` at mode 0600,
flagged `encryption_format="none"` and carrying a warning. The earlier wording of this
paragraph claimed plaintext never enters `BACKUP_DIR` without that qualification, which was
true of the production path only.

Exit codes are distinct per failure class so a timer unit or alerting rule can
distinguish them:

| Code | Meaning |
|---|---|
| `0` | ok |
| `10` | backup failed |
| `11` | encryption failed (a key is configured but unusable) |
| `12` | integrity failed (the archive did not authenticate or did not verify) |
| `13` | credential invalid (the role cannot perform the operation) |
| `14` | offsite failed |
| `15` | not configured (no key, encryption refused, configuration refused) |
| `16` | another backup/prune/restore holds the lock |
| `17` | **plaintext archives present** (`maintenance.py legacy`: action needed) |
| `18` | **a configured bound was exceeded** — database or `pg_dump` timed out |

`17` and `18` were the same number until Phase 22: timeouts returned `17`, which
`maintenance.py legacy` already used for "plaintext is on disk". A monitor could not tell an
unresolved plaintext exposure from a slow database. Timeouts are now `18` throughout. Every
timeout carries `"timeout": true` in the result as well, so a caller does not have to parse
the code.

## 5. Configuration

| Variable | Required | Meaning |
|---|---|---|
| `DATABASE_OWNER_URL` | **yes** | `gerege_owner` DSN. Never set on `web`/`worker`. |
| `BACKUP_ENCRYPTION` | no (default `on`) | `off` only for development. In production, leaving it on with no key fails the run. |
| `BACKUP_ENCRYPTION_KEY_FILE` | **yes when encryption is on** | Path to a 32-byte key file, mode `0400`, owned by the maintenance user. **Back this up separately** — without it every archive is unreadable. |
| `BACKUP_OFFSITE_PATH` | one of these | Independent mount/volume. A path on the same disk as `BACKUP_DIR` provides no independent failure protection. |
| `BACKUP_OFFSITE_URL` | one of these | S3-compatible URL, `https://<endpoint>/<bucket>/<prefix>`. Must be `https`; plain `http` is refused (see the loopback exception below). |
| `BACKUP_OFFSITE_ACCESS_KEY` / `BACKUP_OFFSITE_SECRET_KEY` | with `_URL` | Credentials for the bucket. Use a role limited to `PutObject`/`GetObject`/`DeleteObject` on that prefix. |
| `BACKUP_OFFSITE_REGION` | with `_URL` | Signing region; defaults to `us-east-1`. |
| `BACKUP_OFFSITE_ALLOW_INSECURE_LOOPBACK` | test only | `1` permits a plain-`http` **loopback** endpoint, so offsite can be verified against a local S3-compatible server. Refused when `ENV=production`, ignored for any non-loopback host, and requires exactly `1`. |
| `BACKUP_RETENTION_DAYS` | no (14) | Age-based pruning. |
| `BACKUP_MIN_KEEP` | no (7) | Count floor that overrides the age rule. |
| `BACKUP_ALERT_WEBHOOK` | recommended | JSON POST on success/failure. |
| `BACKUP_MAX_AGE_HOURS` | no (36) | Staleness threshold used by `maintenance.py status`. |

Generate the key once, on the maintenance host, and store a copy in the secret manager:

```bash
head -c 32 /dev/urandom | base64 > /etc/gerege/backup.key
chmod 0400 /etc/gerege/backup.key
```

## 6. Operator requirements — NOT CONFIGURED in this repository

Everything in this section is infrastructure and **none of it is configured here**. Do
not mark backups as operational until each line is true in the target environment.

- [ ] **Scheduler installed and enabled** — `deploy/systemd/gerege-backup.timer`
      (hourly `OnCalendar`) or `deploy/cron/gerege-backup.cron`. Present in the repo as
      a template; **not installed on any host by this repository**.
- [ ] **Failure notification endpoint** — `BACKUP_ALERT_WEBHOOK` pointed at a real
      destination. Without it, failures are recorded in the status file and in the
      journal, and **nobody is told**.
- [ ] **Independent storage** — `BACKUP_OFFSITE_PATH` on a different device, or
      `BACKUP_OFFSITE_URL` pointed at an object store. Offsite status distinguishes
      `OFFSITE_NOT_CONFIGURED`, `OFFSITE_CONFIGURED`, `OFFSITE_VERIFIED` and
      `OFFSITE_FAILED`; **configured is not verified.** `VERIFIED` is only claimed after an
      upload is downloaded back and its SHA-256 matched against the locally recorded digest,
      and it is never claimed against a provider this repository has not actually run
      against. As shipped, offsite is **NOT VERIFIED**.
- [ ] **Key stored off-host** — a copy of `backup.key` in the secret manager. Losing it
      loses every backup.
- [ ] **Monitoring wired to the probe** — schedule `maintenance.py status` (exit 1 =
      failed or stale) in the existing monitoring system.

## 7. Restore drill

Backups that have never been restored are a hypothesis. Run at least quarterly:

```bash
# 1. Restore the encrypted archive directly. Phase 18 made this a supported operation:
#    `restore` authenticates and decrypts the archive itself, so there is no manual
#    step and no way to decrypt to a file the restore path cannot see.
export BACKUP_ENCRYPTION_KEY_FILE=/etc/gerege/backup.key
python scripts/maintenance.py list            # encrypted archives are listed
python scripts/maintenance.py verify <archive>

# 2. Restore into an ISOLATED database (never production).
#    restore requires the owner credential, by design.
DATABASE_OWNER_URL=postgresql://gerege_owner:...@host:5432/gerege_drill \
    python scripts/maintenance.py restore <archive> --yes

# 3. Prove the restored database is usable and correctly owned.
DATABASE_URL=postgresql://gerege_owner:...@host:5432/gerege_drill \
    python scripts/provision_roles.py --verify
```

Record the wall-clock time of step 2 — that measurement, not an aspiration, is the RTO.

## 8. RPO / RTO

Both are **properties of the configured schedule, not of this code**:

* **RPO** = the schedule interval, plus detection and re-run time. With an hourly timer
  the RPO is ≤1 hour; with a daily timer, ≤24 hours. **No value can be quoted until a
  timer is installed, because none is.**
* **RTO** = restore time measured in a drill, plus the operator's decision time.

The previous documentation quoted "RPO ≤ 24 hours via automated daily 03:00
snapshots". That claim had no schedule behind it and has been removed.
