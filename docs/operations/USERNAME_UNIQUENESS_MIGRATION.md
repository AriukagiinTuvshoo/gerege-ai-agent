# Username uniqueness migration and collision remediation

**Finding:** R10 — concurrent cross-tenant username claim
**Revision:** `0005_username_uniqueness` (down-revision `0004_tenant_session_identity`)
**Invariant:** `uq_pages_client_username_norm`

---

## 1. What the invariant is

```sql
-- PostgreSQL (as created)
CREATE UNIQUE INDEX uq_pages_client_username_norm
    ON public.pages USING btree (lower(TRIM(BOTH FROM client_username)))
    WHERE ((client_username IS NOT NULL) AND (TRIM(BOTH FROM client_username) <> ''::text));

-- SQLite (as created)
CREATE UNIQUE INDEX uq_pages_client_username_norm
    ON pages (LOWER(TRIM(client_username)))
    WHERE client_username IS NOT NULL AND TRIM(client_username) <> '';
```

The expression is deliberately identical to the one used by login, by the failed-login
throttle, and by `resolve_canonical_account`. If the index and the lookup ever used
different normalizations, the index would protect a name nobody queries.

It is **partial**. Rows with `NULL`, `''`, or whitespace-only usernames are outside the
predicate, so any number of credential-less pages can coexist. Blank usernames are not
identities, and treating them as one shared identity would be a denial of service against
every page that has no login yet.

### The second invariant: cross-column login identity (revision `0006`, R16)

The unique index above covers **one column**. Login resolves an identifier with
`LOWER(TRIM(client_username)) = ? OR LOWER(TRIM(page_id)) = ?`, so an identifier can also be
claimed through `page_id`. The index cannot see:

* a `client_username` that equals **another row's `page_id`**, in either direction;
* two `page_id`s differing only by **case or surrounding whitespace** — these are distinct
  primary keys and one login identifier.

Revision `0006` adds a projection whose primary key *is* the normalized identifier:

```sql
CREATE TABLE page_login_namespace (
    normalized_identifier VARCHAR(255) PRIMARY KEY NOT NULL,
    page_id               VARCHAR(128) NOT NULL REFERENCES pages(page_id) ON DELETE CASCADE
);
```

It is maintained by triggers on `pages` (`INSERT`, `UPDATE`, `DELETE`). Because the
identifier is a primary key, the database serialises concurrent claimants: this is an
invariant, not a check. Application code must never write to this table — a manual `INSERT`
desynchronises the projection from `pages`, and the startup guard will then refuse to boot.
That refusal is the intended behaviour, not a bug.

### What it prevents

Before this index, `set_client_credentials` checked-and-then-wrote. Two tenants could pass
the check concurrently and both commit. Phase 1 reproduced that **12/12 times on both
PostgreSQL 16.2 and SQLite 3.40.1**, with two, three, or four winners for a single name.

The consequences were not merely cosmetic:

* login identity became ambiguous — the resolver's `ORDER BY page_id LIMIT 1` silently
  chose one tenant, so one of them could never log in;
* the two tenants **shared one failed-login budget**, so an attacker grinding against one
  account could lock out the other;
* a `username` equal to another tenant's `page_id` could hijack `set_client_credentials`.

The index makes the anomaly unrepresentable. `database.set_client_credentials` now maps the
resulting `IntegrityError`/`UniqueViolation` to `CredentialConflictError`, which the API
returns as `409`. **Only** that specific violation is mapped (matcher in
`database._is_username_uniqueness_violation`); foreign-key, NOT NULL, and unrelated unique
violations still propagate as errors rather than masquerading as a username conflict.

---

## 2. Before you migrate: run the preflight

The preflight is **read-only**. It never writes, never picks a winner, never deletes.

```bash
# what does the database actually contain?
python scripts/repair_username_uniqueness.py --check

# or, from Python
python -c "
import database
from core import username_uniqueness as u
c = database.get_connection()
print(u.duplicate_report_text(u.find_duplicate_usernames(c)))
"
```

If it prints `OK`, the invariant is already in force and there is nothing to do.

If it prints collisions, **stop**. The migration will refuse to run, by design.

### What a collision looks like

```
1. username 'mlopez' is claimed by 2 tenants: 'page-7f2a', 'page-c010'
2. username 'Tuvshoo' is claimed by 3 tenants: 'page-11', 'page-4b', 'page-90'
```

Grouping is on `LOWER(TRIM(...))`, so `Tuvshoo`, `  tuvshoo  `, and `TUVSHOO` are one
collision, not three distinct names. This mirrors exactly what the engine will reject.

---

## 3. Resolving a collision — a human decision

**This is the part that cannot be automated, and must not be.** Two tenants have each been
logging in with the same name. Which of them keeps it is a business decision that requires
talking to the tenant owners. Any script that "resolved" this by keeping the lower
`page_id`, the newer row, or the most recent login would silently lock a real user out of
their account.

For each group, decide with the owners, then apply **one** of:

| Situation | Action |
|---|---|
| Tenants are genuinely distinct people | Give each a distinct username; tell both owners. |
| One is an abandoned duplicate page | Clear that page's credentials (below). |
| Same person, two pages | Merge deliberately — a separate, audited operation. |

Clearing one side's credentials (the only action this project will script for you, and even
then as an explicit human-run statement rather than an automatic step):

```sql
-- Inspect first. Never run the UPDATE without having run this SELECT.
SELECT page_id, client_username, created_at
  FROM pages
 WHERE LOWER(TRIM(client_username)) = 'mlopez'
 ORDER BY page_id;

-- Then clear the ONE row you decided to retire. This removes access for that page.
UPDATE pages
   SET client_username = NULL, client_password_hash = NULL, client_salt = NULL
 WHERE page_id = 'page-c010';
```

> **Never** `DELETE FROM pages` to resolve a collision. The page owns data beyond its
> credentials; deleting it destroys tenant content to fix a login problem.

Re-run the preflight. When it reports zero collisions, install the index.

---

## 4. Installing the index

### Normal path (database is below `0005`)

```bash
python scripts/migrate.py --check     # what would change?
python scripts/migrate.py             # apply, takes a backup first
```

`scripts/migrate.py` wraps Alembic with a pre-migration backup and a post-migration
verification, which is required in this project for operations that rewrite tables.

### Repair path (database claims to be at head but the index is missing)

**`alembic upgrade head` does not fix this, and reports success while doing nothing.**
Alembic compares the version stamped in `alembic_version` against the script directory. If
the stamp says `0005` and the index was dropped afterwards — a manual `DROP INDEX`, a
partial restore, a crashed upgrade, or the pre-Phase-8 `_sync_indexes()` impostor — there is
no revision to run. Verified during Phase 8 migration validation.

Use the repair tool, which is revision-independent and idempotent:

```bash
python scripts/repair_username_uniqueness.py --check   # exit 1 if the invariant is absent
python scripts/repair_username_uniqueness.py           # re-create it if that is safe
python scripts/repair_username_uniqueness.py --dry-run # print the SQL, change nothing
```

It refuses (exit 1) if any collision exists, and it removes an impostor index of the same
name first, because `CREATE INDEX IF NOT EXISTS` would otherwise silently keep a non-unique
look-alike.

### Interrupted migration

If a crash left the database stamped at `0005` with no index, startup refuses to serve.
That is intentional: serving without the invariant is the bug. Run the repair tool above.
Re-running the revision (`downgrade 0004` then `upgrade head`) also works but is a heavier
operation and should use `scripts/migrate.py`.

---

## 5. Verifying

```bash
python scripts/repair_username_uniqueness.py --check   # exit 0 = in force
```

```sql
-- PostgreSQL
SELECT indexdef FROM pg_indexes WHERE indexname = 'uq_pages_client_username_norm';
-- SQLite
SELECT sql FROM sqlite_master WHERE type='index' AND name='uq_pages_client_username_norm';
```

Do not verify by name alone. `index_is_correct()` requires, in the engine's own definition
text, all four properties: **unique**, the **`lower`** expression, the **`trim`**
expression, and the **`where`** predicate. A name-only check is how the pre-Phase-8
impostor survived: a non-unique index on the raw column carried the same name and enforced
nothing. `core/schema_manager.assert_security_invariants` runs this check on **every**
startup, including the already-at-head fast path, and refuses to boot if it fails.

---

## 6. Locking and downtime

The index is created **transactionally**, not with `CONCURRENTLY`:
`migrations/env.py` runs everything inside `context.begin_transaction()`, and
`CREATE INDEX CONCURRENTLY` cannot run inside a transaction block.

Consequences to plan for:

* PostgreSQL takes a `SHARE` lock on `pages` for the duration. Reads continue; writes to
  `pages` (new page creation, credential changes) block until it finishes.
* For a table of this project's size the build is short. For a large installation, run it in
  a maintenance window and measure first on a copy.
* SQLite locks the database file for the duration; stop writers first.

If you need a truly concurrent build on PostgreSQL, create the index by hand with
`CONCURRENTLY` and then run `alembic stamp 0005_username_uniqueness`. Verify the shape
afterwards with `--check`. This is an advanced path: a `CONCURRENTLY` build that fails
leaves an **invalid** index behind, which satisfies a name check but enforces nothing.

---

## 7. Rolling back

```bash
python scripts/migrate.py    # inspect available downgrade options
alembic downgrade 0004_tenant_session_identity
```

**Rolling back to `0004` removes the uniqueness guarantee. It is a security downgrade, not
a neutral schema change.** Verified during Phase 8: after downgrading, two rows with
`'rollback_dupe'` and `'ROLLBACK_DUPE'` coexist again, which re-opens R10 in full.

The downgrade logs a warning and does not attempt to delete data. Roll back only to escape a
broken forward migration, re-apply as soon as the cause is fixed, and treat the window as an
incident: during it, concurrent claims are possible again.

---

## 8. What this migration will never do

* Never chooses a winner among colliding tenants.
* Never merges accounts.
* Never clears or rewrites a username, password hash, or salt.
* Never deletes a row.
* Never leaves the database in a state where the version says "applied" but the index is
  not actually in force — the revision verifies the index **shape** after creating it and
  raises if it is wrong, rather than reporting success.

If it cannot install the invariant safely, it stops and says why. That is the intended
behaviour.

---

## 8b. Recovering the cross-column invariant (revision `0006`)

`alembic upgrade head` is a **silent no-op** on a database already stamped at `0006`. If the
projection or the triggers are missing there, it prints success and changes nothing. Use the
dedicated tool.

```bash
python scripts/repair_login_identity.py --check    # read-only; exit 1 if not in force
python scripts/repair_login_identity.py            # rebuild if it is safe
python scripts/repair_login_identity.py --dry-run  # print the SQL only
```

What it does, by state (all verified on SQLite and PostgreSQL 16):

| state | `--check` | repair |
| --- | --- | --- |
| healthy | exit 0 | no-op |
| triggers dropped, table intact | exit 1 | re-creates triggers |
| stale table (rows written while triggers were gone) | exit 1 | re-derives it from `pages` |
| table and triggers both gone | exit 1 | rebuilds both |
| collision present | exit 1 | **refuses**, exit 1, changes nothing |
| no `pages` table (un-migrated database) | exit 2 | tells you to run `alembic upgrade head` |

It never chooses a winner, merges accounts, clears a username, rewrites a `page_id`, or
deletes a row. Resolve collisions in section 3 first; the rules are identical.

### Maintenance fallback (when the tool cannot be run)

Approved as a documented last resort, and verified by hand. On a database with the
projection and triggers removed, this restores the invariant:

```sql
-- 1. remove any remaining triggers (PostgreSQL: also DROP FUNCTION ...)
DROP TRIGGER IF EXISTS trg_page_login_ns_ai ON pages;
DROP TRIGGER IF EXISTS trg_page_login_ns_au ON pages;
DROP TRIGGER IF EXISTS trg_page_login_ns_ad ON pages;

-- 2. discard the projection; `pages` is the only source of truth
DROP TABLE IF EXISTS page_login_namespace;

-- 3. re-create it (the FK matters: see tests/test_p1_06_foreign_keys.py)
CREATE TABLE page_login_namespace (
    normalized_identifier VARCHAR(255) PRIMARY KEY NOT NULL,
    page_id               VARCHAR(128) NOT NULL REFERENCES pages(page_id) ON DELETE CASCADE
);

-- 4. re-derive. INSERT ... ON CONFLICT DO NOTHING is NOT acceptable here: a collision must
--    abort loudly, not be silently dropped.
INSERT INTO page_login_namespace (normalized_identifier, page_id)
SELECT k, p FROM (
    SELECT LOWER(TRIM(page_id)) AS k, page_id AS p FROM pages WHERE TRIM(page_id) <> ''
    UNION
    SELECT LOWER(TRIM(client_username)) AS k, page_id AS p FROM pages
     WHERE client_username IS NOT NULL AND TRIM(client_username) <> ''
) AS keys ORDER BY k;

-- 5. re-create the triggers. Copy the exact definitions from
--    core/login_identity.py:create_triggers_sql() -- do not retype them from memory.
```

Then re-run `--check` and start the application: the startup guard is the verification.

**One behaviour to expect.** On PostgreSQL, dropping only the table leaves the triggers
attached to `pages`, so the next write fails loudly with `UndefinedTable`. That is correct —
loud, never silent — and the repair tool handles that state.

## 9. Checklist

```
[ ] Back up the database (scripts/migrate.py does this automatically)
[ ] Run the preflight: python scripts/repair_username_uniqueness.py --check
[ ] If collisions: resolve each with the tenant owners; re-run the preflight
[ ] Apply: python scripts/migrate.py    (or the repair tool if already stamped at head)
[ ] Verify: --check exits 0
[ ] Start the application; confirm it boots (the startup guard would refuse otherwise)
[ ] Confirm a second concurrent claim now returns 409, not a duplicate row
[ ] Confirm revision 0006 is applied: python scripts/repair_login_identity.py --check
[ ] Confirm a page_id equal to another tenant's username is refused (409 identifier_conflict)
[ ] Confirm two page_ids differing only by case cannot both exist
```
