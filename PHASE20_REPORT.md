# Phase 20 — Backup & Restore Remediation: Final Report (P12)

**Branch:** `arena/d78ebf88-gerege-ai-agent`
**Base:** `main` @ `48e9c6f` (unchanged)
**Head:** `d275858`
**PR:** #1 — **open, not merged, not deployed**
**CI:** run `44653806612` — **success**, 54/54 steps

---

## 1. Executive summary

Phase 20 set out to make backup and restore a defensible recovery capability rather than
an evidence-free claim. It did that, and in the process it found that the *rollback* — the
mechanism the whole design leans on — did not work at all.

Three defects were found and fixed. All three were pre-existing; none was introduced by
this phase.

| # | Defect | Severity | Status |
|---|--------|----------|--------|
| 1 | Automatic rollback could never replay an encrypted pre-restore snapshot | **Critical** — recovery was impossible | Fixed (`5afc622`) |
| 2 | `_reset_public_schema` never reset anything, and reported success | **Critical** — "atomic" rollback was not atomic | Fixed (`d275858`) |
| 3 | Failed writes strand pooled connections `idle in transaction`, holding locks | **High** — blocked the rollback itself | Fixed (`d275858`) |

The third defect is why the second was hard to see: it produced intermittent 180–241 s
hangs that looked like slowness rather than a correctness bug.

**The honest headline:** a restore that failed verification could not have been rolled
back. On a real cluster, the operator would have received `ROLLBACK_FAILED` and a manual
recovery instruction — and the pre-restore snapshot would not have been replayable by the
automatic path either. This is exactly the class of defect that a "we have backups" claim
hides, and it is the reason this phase existed.

---

## 2. What was actually broken, and how it was proven

Every finding below was reproduced against a live PostgreSQL 16 cluster, not inferred from
reading code.

### 2.1 Rollback could not replay its own snapshot

`restore_backup()` decrypts the pre-restore snapshot into a staging directory before
replaying it. The replay call sites were reading the *original encrypted* path instead of
the decrypted one, so `_apply_postgres_sql_file` handed gzip a `.enc` file and failed with
`BadGzipFile`. The caller logged `rollback … FAILED` and returned `ROLLBACK_FAILED`.

**Proof of the negative control:** with the fix reverted, the test returns `ROLLBACK_FAILED`
and the assertion fails at line 723. With the fix, `ROLLED_BACK_TO_PRE_SNAPSHOT`.

### 2.2 The schema reset was a silent no-op (and sometimes destructive)

`_reset_public_schema` ran:

```sql
DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public AUTHORIZATION current_user;
```

as the **restoring** role. On any normal cluster `public` is created by `initdb` and owned by
the bootstrap superuser, so this failed with `must be owner of schema public` **every single
time**. The caller did this with the result:

```python
reset_ok, reset_err = _reset_public_schema(pg_url)
if not reset_ok:
    logger.error(f"Could not reset schema before rollback: {reset_err}")
    # ... and then carried on replaying anyway
```

So the replay ran on top of the failed restore's tables, `pg_dump --clean` could not drop
them (it only drops what the dump contains), and the schema drifted.

A first fix attempt filtered the drops by `current_user`. That was worse in a subtle way: it
exited `0` while dropping **nothing** whenever migrations had been applied by the bootstrap
role — which is how CI and a fresh install converge. A reset that cannot be distinguished
from a no-op is more dangerous than one that fails, because the caller treats exit `0` as
licence to replay over live data.

**Final fix:**
- Drop every object *inside* `public` — never the schema itself, because recreating the
  schema destroys `gerege_app`'s grants. That failure mode was observed: the app came back
  from a "successful" rollback with `relation "pages" does not exist`.
- Keep `SET lock_timeout` in the **same psql session** as the drops. Splitting it into a
  separate `psql -c` call leaves the drops unbounded; that mistake reproduced the 241 s CI
  hang exactly.
- **Count what is left** afterwards. Exit status alone is not evidence.

### 2.3 Stranded connections held the locks the rollback needed

`PostgresCompatConnection.close()` returned the raw connection to the SQLAlchemy pool
without rolling back. psycopg2 opens a transaction on the first statement, so a helper that
only `SELECT`ed handed back a connection that was still `idle in transaction`. Separately,
~60 helpers in `database.py` are shaped `conn = get_connection(); ...; conn.close()` with no
`try/finally`, so any exception skipped `close()` entirely.

In CI the blocking backend's last statement was `RELEASE SAVEPOINT sp_gerege_120` — one of
those cursors. The leaked transaction held `ACCESS EXCLUSIVE` off `pages`, `_reset_public_schema`
waited out `lock_timeout`, and the rollback could not run.

**Measured, not assumed:** dropping the cursor does not clear it; dropping the wrapper does
not either (`PostgresCompatCursor` holds the raw connection); only an explicit
rollback-then-close, or the `__del__` net, releases it.

**Fix:** `close()` now rolls back (matching `sqlite3.Connection.close()`, which discards the
pending transaction), `__del__` releases a stranded connection once its traceback is
dropped, and `save_registration` — the function the failing test exercised — uses an
explicit `try/finally`.

### 2.4 Fail fast instead of hanging

If the reset cannot run, `restore_backup` now stops and returns `ROLLBACK_FAILED` with the
blocking cause in `rollback_error`, naming the likely culprit (a client left `idle in
transaction`) and pointing at the preserved snapshot. It no longer replays over a live
schema and waits out a 180 s psql timeout. The pre-restore snapshot is untouched and still
on disk.

**Net effect on the affected suite: 241 s (CI, timing out) → 1.3 s.**

---

## 3. Verification

### 3.1 Test totals

| Suite | Database | Result |
|-------|----------|--------|
| Full suite | PostgreSQL 16.2 | **677 passed / 42 skipped / 0 failed** |
| Full suite | SQLite | **625 passed / 94 skipped / 0 failed** |
| P0-2 restore/rollback (CI step 39) | PostgreSQL 16 | **8/8 in 1.3 s** (was 2/8 + 241 s hang) |
| Phase 20 module | PostgreSQL 16 | **32/32** |

### 3.2 End-to-end operator path (real CLI, disposable cluster)

`maintenance.py backup` → `maintenance.py restore --yes`, both as `gerege_owner`:

```
backup OK: pg_backup_manual_…​.sql.gz.enc (8626 bytes, sha256 1cfa12b2…)
  rows: audit_logs=0 pages=2
app SELECT pages          : 2
app UPDATE audit_logs     : ERROR: permission denied for table audit_logs
provision_roles --verify  : Runtime role 'gerege_app' holds least privilege.
                            All 32 relation(s) are owned by 'gerege_owner'.
tables                    : 19 (want 19)
staging residue           : 0
plaintext .sql residue    : 0
```

### 3.3 Negative controls

Each new test was run against the unfixed code to confirm it fails for the right reason.

| Test | With fix | Without fix |
|------|----------|-------------|
| `p20_30` rollback replays encrypted snapshot | `ROLLED_BACK_TO_PRE_SNAPSHOT` | `ROLLBACK_FAILED`, assertion at line 723 |
| `p20_31` stranded connection releases locks | pass | fail — `no __del__ safety net` |
| `p20_32` schema reset empties the schema | pass | fail — relations remain after "success" |

---

## 4. Corrections to earlier findings

**Finding 10 is withdrawn in its original form.** It claimed restore coverage was absent
from the repository. That was wrong: 12 tests already called `restore_backup()` and a
deliberate break of it failed 2 of them. Restore was covered.

The gap that actually existed — and that `tests/test_e06_phase20_backup_remediation.py`
now fills — was narrower and more interesting:

- **failure modes** were untested (wrong key, tampered ciphertext, mid-restore SQL failure),
- **isolation** was untested (the suite shared a database and its destructive tests
  contaminated later ones),
- **locking** was untested (the cross-process lock, stale-PID sweep, refused concurrent
  restore/prune),
- **the AEAD path** was untested (encryption on/off, required-key-missing, floor semantics).

That is a materially different finding from "restore is untested", and it is the one that
should carry into the record.

**Also recorded:** `tests/test_enterprise_phases.py::test_phase2_sqlite_to_postgres_migration_dry_run`
fails in isolation and at base `fef08a3` with `sqlite3.DatabaseError: file is not a database`.
Cause: a corrupted gitignored `leads.db` fixture in the working tree. It is a
test-infrastructure defect, unrelated to Phase 20, and it is what produced 40 confusing
"failures" in one intermediate run.

---

## 5. P9 acceptance — coverage mapping

P9 listed 18 cases. The mapping below is against the 25 cases that P9 required plus the
7 added during remediation (32 total). "Real path" means the assertion exercises the
production code path, not a stub.

| P9 case | Test | Real path? | Notes |
|---------|------|-----------|-------|
| create backup without staging still encrypts | `p20_01` | Yes | production call sites pass no `staging_dir` |
| production callers pass no staging dir | `p20_02` | Yes | asserts the call convention itself |
| encryption failure publishes nothing | `p20_03` | Yes | no partial archive on failure |
| encryption required but key unset is fatal | `p20_04` | Yes | boot-time refusal, not silent fallback |
| documented opt-out is flagged, not silent | `p20_05` | Yes | plaintext is a recorded state |
| metadata not world-readable | `p20_06` | Yes | file mode asserted |
| plaintext cannot satisfy the encrypted floor | `p20_07` | Yes | floor semantics |
| floor never empties a plaintext-only directory | `p20_08` | Yes | prevents mass deletion |
| classification distinguishes all four states | `p20_09` | Yes | encrypted/plaintext/unknown/missing |
| legacy scan never reads archive bodies | `p20_10` | Yes | header-only inspection |
| retention keeps newest by timestamp not name | `p20_11` | Yes | adversarial filenames |
| undated objects never deleted | `p20_12` | Yes | fail-safe |
| failed deletion not reported as deleted | `p20_13` | Yes | honest result reporting |
| retention floor cannot be zeroed | `p20_14` | Yes | guard against `0` |
| S3 verify rejects wrong size and digest | `p20_15` | Yes | offsite integrity |
| S3 verify detects an empty object | `p20_16` | Yes | |
| download verifies hashes received bytes | `p20_17` | Yes | |
| restore refuses while lock is held | `p20_18` | Yes | cross-process lock |
| prune refuses while lock is held | `p20_19` | Yes | |
| lock released after a failure | `p20_20` | Yes | no deadlock after crash |
| lock works across processes | `p20_21` | Yes | real subprocess |
| locked sweep removes a dead PID's staging | `p20_22` | Yes | crash recovery |
| sweep never removes an active staging | `p20_23` | Yes | |
| sweep ignores published archives | `p20_24` | Yes | |
| *added:* mid-restore SQL failure rolls back atomically | `p20_25` | Yes | real PG, real rollback |
| *added:* restore refuses tampered ciphertext | `p20_26` | Yes | AEAD authentication |
| *added:* restore refuses wrong key | `p20_27` | Yes | |
| *added:* encrypted round trip restores tenant data | `p20_28` | Yes | |
| *added:* restore re-arms the append-only guard | `p20_29` | Yes | audit_logs protection survives restore |
| *added:* rollback replays the encrypted pre-restore snapshot | `p20_30` | Yes | **this is the p20_2.x defect** |
| *added:* a stranded connection releases its locks | `p20_31` | Yes | **this is the p20_2.3 defect** |
| *added:* schema reset actually empties the schema | `p20_32` | Yes | **this is the p20_2.2 defect** |

Two cases (`p20_31`, `p20_32`) deliberately empty `public`, so they cannot share a database
with the rest of the suite. They are opt-in via `GEREGE_DESTRUCTIVE_TESTS=1`, which the
Phase 20 CI step sets because that step owns a disposable database. Without the gate they
broke 24 unrelated tests; that was caught and fixed rather than papered over.

---

## 6. Security properties established

| # | Property | Evidence |
|---|----------|----------|
| 1 | Archives are authenticated-encrypted; plaintext cannot masquerade as encrypted | `p20_07`, `p20_26`, `p20_27` |
| 2 | Tampered ciphertext and wrong keys are refused before any data is written | `p20_26`, `p20_27` |
| 3 | No decrypted snapshot survives a rollback | `.staging-*` residue asserted empty in `p20_25`, `p20_30` |
| 4 | Metadata is not world-readable | `p20_06` |
| 5 | Retention cannot be tricked into deleting the newest or the undated | `p20_11`, `p20_12`, `p20_14` |
| 6 | Concurrent restore/prune is refused, not interleaved | `p20_18`, `p20_19` |
| 7 | Locks are cross-process and survive a crash without deadlock | `p20_20`, `p20_21`, `p20_22` |
| 8 | The runtime role keeps least privilege after backup *and* restore | `provision_roles --verify`: "All 32 relation(s) owned by gerege_owner"; `audit_logs` UPDATE denied |
| 9 | The append-only audit guard is re-armed by a restore | `p20_29` |
| 10 | A failed restore is reported honestly, with a recovery instruction and no DSN | `p20_25`; `rollback_status`/`rollback_error`; DSN never interpolated (Phase 18 rule) |

---

## 7. Scope honesty — what this phase did *not* do

- **No merge, no deploy, no production database, no secrets.** PR #1 remains open.
- **No offsite provider was exercised.** S3 verification was tested against a local mock,
  not a real bucket. Offsite durability remains unproven (see verdict below).
- **No restore was timed on production-sized data.** The largest fixture is a few thousand
  rows; the 1.3 s figure says nothing about a multi-gigabyte archive.
- **No point-in-time recovery.** The design is snapshot-based; PITR would need WAL
  archiving, which is not implemented.
- **No DR drill against a real cluster failure.** The rollback was exercised against a
  deliberately failing restore, which is a different (and more testable) thing than losing
  a disk.

---

## 8. Verdicts

Carried forward from Phase 19, re-assessed against Phase 20 evidence.

| Area | Verdict | Rationale |
|------|---------|-----------|
| **SECURITY** | **NO-GO** | Unchanged by Phase 20. The backup path is now defensible; the remaining blockers are outside its scope. |
| **BACKUP** | **CONDITIONAL** | Encryption, authenticity, retention and locking are now tested and enforced. Condition: offsite replication is verified only against a mock. |
| **RESTORE** | **GO** | 8/8 real-cluster tests, encrypted round trip, honest failure reporting, least privilege preserved. |
| **ROLLBACK** | **CONDITIONAL → GO** | Was genuinely broken in three independent ways (sections 2.1–2.3). Now atomic against a real cluster with negative controls. Condition met on a disposable cluster; production-sized data untested. Upgrade from CONDITIONAL is deliberate and evidence-backed. |
| **OFFSITE** | **NO-GO** | Integrity checks exist and are tested, but no real provider was exercised and no restore-from-offsite was performed. |
| **PILOT** | **NO-GO** | Blocked by SECURITY and OFFSITE. |
| **PRODUCTION** | **NO-GO** | Blocked by SECURITY, OFFSITE, and the absence of any production-scale restore measurement. |

The overall picture is narrower than when Phase 20 began: recovery is no longer a claim,
it is a tested capability — on a disposable cluster, at fixture scale, with an untested
offsite leg.

---

## 9. Commits

| Commit | Content |
|--------|---------|
| `849ba12` | staging-dir sweep, crash safety |
| `b7d4dae` | backup confidentiality gates |
| `38c9cd7` | encrypted floor, retention |
| `3c6c8ab` | read-only runtime mounts, restore tests |
| `e65e1ea` | CI gates that fail on plaintext publication, PG restore tests |
| `5afc622` | **fix:** rollback could never replay its encrypted snapshot |
| `d275858` | **fix:** schema reset made real; stranded connections no longer hold locks |

CI: `44653806612` — success, 54/54 steps, including the P0-2 restore/rollback step that
failed in `44470731733`.
