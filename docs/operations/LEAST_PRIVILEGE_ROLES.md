# Least-Privilege Roles (E-05)

Two database roles, two planes:

| Role | Used by | Owns | Can do |
|---|---|---|---|
| `gerege_owner` | `migrate`, `maintenance` services; repair scripts | the schema, 19 tables, 13 sequences, 2 trigger functions | DDL, `pg_dump`, restore, `REPAIR` |
| `gerege_app` | `web`, `worker` | nothing | `SELECT/INSERT/UPDATE/DELETE` on 17 business tables, `SELECT/INSERT` on `audit_logs`, `USAGE` on sequences, `SELECT` on `alembic_version` |

The bootstrap superuser (`POSTGRES_USER`) creates its own cluster and provisions these
roles. It is **not** a runtime credential.

## Why this exists

Phase 13 made `audit_logs` append-only with triggers, and measured the limit of that
control honestly: the runtime credential was a superuser, so `DROP TRIGGER`,
`ALTER TABLE … DISABLE TRIGGER` and `SET session_replication_role = replica` all worked
against it. The trigger only protects against a role that cannot remove it.

What the split actually buys, stated without rounding up:

- **A stolen `DATABASE_URL` (the `gerege_app` password) can no longer alter audit
  history.** Measured: UPDATE, DELETE, TRUNCATE, `DISABLE TRIGGER`, `DROP TRIGGER`,
  `ALTER TABLE … OWNER`, `session_replication_role`, `CREATE TABLE/FUNCTION/SCHEMA`,
  `GRANT` to self and `SET ROLE gerege_owner` are all refused.
- **A stolen `gerege_owner` credential still can.** Ownership is what `DROP TRIGGER`
  requires, and no in-database design removes that. This is *not* tamper evidence; it is
  a reduction in the number of credentials that can destroy the trail from "the one the
  app runs as" to "the one used a few times a day for maintenance".
- **A database superuser still can.** Unchanged from Phase 13.

## Day-to-day

Nothing changes for developers: SQLite has no roles and `DB_PATH`/`DATABASE_URL` behave
as before. The assertion is a no-op on SQLite and only enforced in production mode
(`ENV=production|prod` or `STRICT_SECURITY=1`) or when `REQUIRE_LEAST_PRIVILEGE=1`.

### Provisioning

```bash
python scripts/provision_roles.py --check      # read-only report
python scripts/provision_roles.py --dry-run    # the SQL, passwords redacted
python scripts/provision_roles.py --apply      # converge (idempotent)
python scripts/provision_roles.py --verify     # exit 1 unless least-privileged
```

Passwords come from `GEREGE_OWNER_PASSWORD` / `GEREGE_APP_PASSWORD`. If unset during
`--apply`, a strong password is generated and printed **once**. It is not stored, not
logged, and redacted from `--dry-run`.

`--apply` needs an account that can `CREATE ROLE` (`ADMIN_DATABASE_URL`). The grant and
ownership portion needs only ownership, which is why the `migrate` container holds the
bootstrap credential and neither `web` nor `worker` does.

### Compose

`migrate` is a one-shot service that runs before `web` and `worker`, and both wait for it
to complete successfully:

```
provision_roles --apply          # create/refresh roles
alembic upgrade head             # as the bootstrap account
provision_roles --apply          # transfer ownership of what the migration created
provision_roles --verify         # fail the container if the end state is wrong
```

`maintenance` is profile-scoped and never starts on `up`:

```bash
docker compose -f docker-compose.prod.yml run --rm maintenance python scripts/maintenance.py backup
```

## Backup and restore moved

`pg_dump` needs `LOCK TABLE … ACCESS SHARE` on every table; restore needs
`DROP`/`CREATE` on the schema. `gerege_app` has neither, by design. Measured on
PostgreSQL 16 as a non-owner: `pg_dump` exits 1 with
`permission denied for table registrations`. The old API wrapper captured that stdout
and gzipped it, so `POST /api/admin/backups/create` returned **`success: true` for a
0-byte archive**.

So:

- `POST /api/admin/backups/create` and `POST /api/admin/backups/restore` are **removed**.
- `GET /api/admin/backups` and `POST /api/admin/backups/verify` remain (read-only).
- The worker's nightly 03:00 backup is removed from the runtime.
- `core.backup_service` refuses a non-owner credential with
  `MaintenanceCredentialRequired` rather than producing an empty archive.

Use `scripts/maintenance.py` (see [BACKUP_RESTORE.md](BACKUP_RESTORE.md)).

## Credential rotation

Each role rotates independently; no downtime and no schema change.

```bash
# 1. Generate and apply the new password for one role.
GEREGE_APP_PASSWORD="$(openssl rand -base64 24)" \
  python scripts/provision_roles.py --apply --rotate app
#    -> prints the password ONCE; store it in the secret manager.

# 2. Update the deployment secret.
#      POSTGRES_APP_PASSWORD=<new>   (web + worker)
#      POSTGRES_OWNER_PASSWORD=<new> (migrate + maintenance)

# 3. Restart the consumers of that credential.
docker compose -f docker-compose.prod.yml up -d --force-recreate web worker
```

The old password stops working at step 1, so rotate during a window when a brief
reconnect is acceptable — existing pool connections are **not** terminated by
`ALTER ROLE … PASSWORD`; they keep working until they reconnect, then fail if the
client still has the old secret. Restart the consumers in the same change.

To rotate without `--rotate` (e.g. already generated), set the env var and run
`--apply`; it will `ALTER ROLE … PASSWORD` because the role exists.

## Order of a first rollout on an existing deployment

The order matters: nothing is removed until the new path is proven.

1. **Provision.** `provision_roles.py --apply`. Roles exist; `gerege_app` can read and
   write; `gerege_owner` owns everything. The app still runs as before, as the bootstrap
   user, so this step is invisible.
2. **Verify.** `provision_roles.py --verify` → exit 0.
3. **Back up** with the *old* path while it still works
   (`maintenance.py backup` as the bootstrap account works too — it owns everything).
4. **Point `web` and `worker` at `gerege_app`.** Set `POSTGRES_APP_PASSWORD`, update the
   DSNs, restart. Watch `/api/ready` and the logs: a missing grant appears as
   `permission denied for table …` on the first query that needs it.
5. **Confirm the assertion is live.** Boot with `REQUIRE_LEAST_PRIVILEGE=1` and check the
   log line `Runtime role 'gerege_app' holds least privilege`.
6. **Move the backup cron** from anything running in the app to
   `docker compose run --rm maintenance`.
7. **Only now remove the old runtime credential** from the environment. Do not leave it
   mounted "just in case".

Rollback at any step: point `DATABASE_URL` back at the bootstrap user and restart. That
restores availability immediately. It is **not** an acceptable permanent state — it is
the emergency path, and step 6 exists to make sure nobody forgets to finish.

## Restore and grants

A restore replays a `pg_dump` taken with `--no-owner --no-privileges`. The tables are
recreated, and the schema's **default privileges** then grant `gerege_app` full CRUD —
including `UPDATE`/`DELETE` on `audit_logs`. Measured: one restore silently re-widened
the runtime role, and the startup assertion then (correctly) refused to boot.

`restore_backup` now re-converges the grant plan itself after the dump is applied, and
reports `grant_note` in the result. The startup assertion is the backstop if that ever
fails.

## Failure modes and what they look like

| Symptom | Cause | Fix |
|---|---|---|
| Startup: `refusing to start: the database role 'X' is more privileged…` | `DATABASE_URL` still points at the owner/superuser | point it at `gerege_app`; this is the check working |
| Startup: `… role is missing ['SELECT', …]` | grants lost (restore, manual revoke) | `provision_roles.py --apply` |
| Runtime: `permission denied for table pages` | same | same |
| `MaintenanceCredentialRequired` from a backup call | backup attempted as `gerege_app` | use `maintenance.py` / the `maintenance` service |
| `must be owner of function` during restore | a function left owned by another role | `provision_roles.py --apply` |

## Residual risk

- `gerege_owner` compromise defeats the audit guard. Documented above, not mitigated.
- The assertion runs at startup, not continuously. A grant added while the app is running
  is detected at the next restart, not immediately. `--verify` in cron narrows that gap;
  it is not a substitute for not granting things.
- A role that is a member of `gerege_owner` is treated as an owner. `gerege_app` is
  created `NOINHERIT` and is a member of nothing, and the assertion already reports any
  membership as a violation.
- SQLite deployments get none of this. They keep the Phase 13 triggers only.
