# Phase 23 — Final State Verification & Operational Readiness

Independent audit of Phase 22. Every claim in `docs/PHASE22-REMEDIATION-REPORT.md` was
re-checked against the repository, the Actions API, and live behaviour. **The Phase 22 report
was not assumed accurate, and was not.**

Two real code defects and five documentation errors were found. The defects are fixed here;
the documentation errors are corrected in place.

---

## 1. Repository state at audit start

| Item | Value |
|---|---|
| Branch | `arena/d78ebf88-gerege-ai-agent` |
| HEAD at start | `50c47d3a2848fef2bcc1c2bbafd24b1a075eeba1` |
| Working tree | **clean** — no staged, unstaged or untracked changes |
| `main` | `48e9c6f7392729bc87d0c810553ff459a919dbfb` (unchanged) |
| PR #1 | **OPEN**, `mergedAt: null`, mergeable, head → `main` |
| Base | `main` @ `48e9c6f` |

No stop-and-report condition. Nothing was overwritten or discarded.

---

## 2. Reconciling the Phase 22 report's commit and CI claims

The report cited `50c47d3`, `e6fd261`, `81a628a`, `10227a2` and run `44870665596`. These do
**not** all refer to what the report said.

### The run ID does not exist

`gh api repos/…/actions/runs/44870665596` → **404**. The report's "Final CI" was not a real
run. The real runs are:

| SHA | Run | Result |
|---|---|---|
| `10227a2` | `44870188807` | success, 54/54 |
| `50c47d3` | `44870697565` | success, 54/54 |

### `b9c4f28` was a failure, not a success

The report listed it among "all success". Run `44868935540` **failed at step 29, exit 11** —
the N-14 key-length regression, introduced by Phase 22 itself.

### Six commits never ran in CI at all

For `56ab3cb`, `fbcf933`, `57493b7`, `973af66`, `433d26d`, `fc83a1c` the Actions API reports
`total_count = 0`. There is no run, on any branch. These include **P21-01 (production
encryption enforcement)** and **P21-10 (DB bounds)** — the two highest-severity fixes in the
phase. Their correctness rested entirely on local test evidence. Section 3 re-verifies them
independently.

### The step-17 failure count

The report said "the four commits before `e6fd261`". Six runs failed on step 17:
`a1db789`, `15287a3`, `18e73f9`, `715480c`, `f2b3aeb`, `88c1adc`.

### Commit count

Report said 19. Actual: **21** `31de90e..50c47d3` (20 through `10227a2`).

### The authoritative history

| Commit | Run | Result |
|---|---|---|
| `56ab3cb` … `fc83a1c` (6) | — | **no run** |
| `a1db789` | `44762160502` | failure — step 17 |
| `15287a3` | `44766838374` | failure — step 17 |
| `18e73f9` | `44769999587` | failure — step 17 |
| `715480c` | `44863835098` | failure — step 17 |
| `f2b3aeb` | `44864441744` | failure — step 17 |
| `88c1adc` | `44864968615` | failure — step 17 |
| `e6fd261` | `44866192167` | **success** |
| `81a628a` | `44867084989` | success |
| `f78533c` | `44867720999` | success |
| `6291da3` | `44867816666` | success |
| `4a88af3` | `44867924898` | success |
| `b9c4f28` | `44868935540` | **failure — step 29, exit 11** |
| `cf19bea` | `44869060836` | failure — step 29, exit 11 |
| `10227a2` | `44870188807` | **success** |
| `50c47d3` | `44870697565` | **success** |

---

## 3. Independent verification

Each item was checked in source **and** exercised. "Documented" means I could only confirm the
code says it; "verified" means I observed the behaviour.

| # | Item | File / function | Actual behaviour | Tests | Independent evidence | Limitation |
|---|---|---|---|---|---|---|
| 1 | SQLite WAL-safe snapshots | `tests/conftest.py::copy_sqlite_database` | uses `sqlite3.Connection.backup()`, reads through the WAL | `test_e07_phase22_wal_copy_safety.py` (6) | **verified** — reproduced the empty-schema copy, confirmed the helper returns full schema | the one remaining `shutil.copy2` (`test_migration_and_restore_verification.py:97`) copies a *test-owned, already-checkpointed* file, correctly commented |
| 2 | Production encryption enforcement | `core/backup_policy.py::evaluate` | `ENCRYPTION_DISABLED_IN_PRODUCTION` → 15, before any DB read | `test_e07_phase22_backup_policy.py` (44) | **verified** — prod+off → 15, 0 archives; prod+no key → 15 | production flag is env-derived (`ENV`/`APP_ENV`); a host mislabelling itself is not production |
| 3 | Key validation via the real loader | `core/backup_policy.py` | delegates to `backup_crypto.load_key`; no duplicated rules | `test_e07_phase22_backup_policy.py` | **verified** — 45-byte base64 (the documented generator), raw 32B, newline form all accepted; 5-byte → 11; hex → 11 | hex is deliberately not a form |
| 4 | Backup exit-code propagation | `scripts/maintenance.py::cmd_backup` | returns `result["exit_code"]` | `test_e07_phase22_db_bounds.py`, `test_e07_phase23_exit_codes.py` | **verified** — 0/11/15/18 observed through the CLI | — |
| 5 | Timeout code uniqueness | `core/backup_service.py`, `core/backup_automation.py::EXIT_TIMEOUT` | 18 = bound exceeded, 17 = plaintext present | `test_e07_phase23_exit_codes.py` (5) | **verified** — `backup` → 18; `backup-run` → **18 after D-7** (was 10) | see D-7 |
| 6 | PostgreSQL connection timeouts | `core/db_engine.py::_set_pg_session_bounds` | `1min` / `5min` / `30s` on every pooled connection | `test_e07_phase22_connection_bounds.py` (6) | **verified** — `SHOW` against a live pool returned all three | bounds the symptom; the 53 unguarded helpers remain |
| 7 | Alert retry & failure semantics | `core/backup_automation.py::notify` | 3 attempts, 1 s backoff, 10 s cap, 4xx not retried, never raises | `test_e07_phase22_alerting.py` (11), `test_e07_phase23_alert_redaction.py` (5) | **verified** — local sink returned 503/503/200 → delivered on attempt 3; unreachable → `notification failed`, no raise | no alert destination is configured anywhere |
| 8 | S3 pagination & integrity | `core/backup_offsite.py` | full pagination; SHA-256 of the download vs caller-supplied digest | `test_e07_phase22_offsite_pagination.py` (23), `…_offsite_integrity.py` (17) | **verified** — same-size corruption caught (`downloaded digest does not match`) | local S3-compatible server only |
| 9 | AEAD chunk ordering | `core/backup_crypto.py::_chunk_aad` | AAD binds version + index + length + header digest; v1 readable | `test_e07_phase22_aead_binding.py` (22) | **verified** — reorder/truncate/replay/downgrade all rejected | v1 archives remain readable by design |
| 10 | Schema drift against the real target | `core/backup_service.py::_rollback_invariants` | engine passed **explicitly**, not from ambient `DATABASE_URL` | `test_e07_phase22_recovery_safety.py` (13) | **verified** — source comment records the NC that returned "no drift" while comparing SQLite | — |
| 11 | Encrypted manifest & restore verification | `core/backup_service.py` | manifest published, names the ciphertext, carries row counts | `test_e07_phase23_restore_verification.py` (5) | **verified** — real `.meta.json` produced with 17 table counts and `encrypted: true` | **D-6** — manifest absence used to pass vacuously; now fixed |
| 12 | Plaintext retention & pruning | `core/backup_service.py::prune_old_backups` | never deletes plaintext or unclassifiable archives | `test_e07_phase22_retention_plaintext.py` (13) | **verified** — unknown-header `.enc` retained; plaintext excluded | — |

### Two defects the audit found

**D-6 — a restore with no manifest claimed a verification it never performed.**
Both verifiers loop over `_REQUIRED_RESTORE_TABLES` and compare only `if t in
expected_counts`. Empty manifest ⇒ nothing compared ⇒ `verified: True`. Reproduced by deleting
`*.meta.json` from a real encrypted archive and restoring: `post_restore_verified: True`, no
table examined. This is precisely the consequence Phase 22's N-2 claimed to have removed — N-2
made the manifest *exist*, it did not make it *required*. Pre-existing in `main`
(`git log -S` pins it to `48e9c6f`).

Fixed by **narrowing the claim, not blocking the restore**: `post_restore_verified` is now
`False` when nothing was compared, `row_counts_checked` says which, and `verification_note`
explains. The restore still succeeds — failing it would make disaster recovery impossible for
any pre-manifest archive and, because `cmd_restore` gates on `success`, would roll back over an
intact database.

**D-7 — the scheduled path flattened every exit code to 10.**
`run_scheduled_backup()` set `exit_code=EXIT_BACKUP_FAILED` unconditionally, the same bug
Phase 22 fixed in `create_backup`. Reproduced under an `ACCESS EXCLUSIVE` lock on `pages`:

```
maintenance.py backup      -> exit 18   (correct)
maintenance.py backup-run  -> exit 10   (reported a lock timeout as a generic failure)
```

`backup-run` is what a systemd timer invokes, and the unit templates document 18 as "a
configured bound was exceeded". Now preserved, and 18 is named `EXIT_TIMEOUT` in the module
that builds the alert payload — previously a bare literal in `backup_service.py` that
alerting had no constant for.

---

## 4. Test integrity

### Commands

```bash
# Full suite
DATABASE_URL="postgresql+psycopg2://gerege:ci_pg_password_2026@127.0.0.1:5432/p22_e06" \
BACKUP_OFFSITE_TEST_ENDPOINT=http://127.0.0.1:5062 REDIS_URL=redis://127.0.0.1:6379/0 \
python -m pytest tests/ -q -p no:randomly

# CI step 17, extracted from ci.yml
bash /tmp/p22/step17_v2.sh
```

### Results

| Run | Result |
|---|---|
| Full suite (before fixes) | 906 passed, 0 failed, 4 skipped |
| Full suite (after fixes) | **921 passed, 0 failed, 4 skipped** (351 s) |
| CI step 17 exact | **148 passed, 3 skipped, exit 0** |
| Existing restore/rollback suites after D-6 | 45 passed |

### The 4 skips

| Suite | Reason |
|---|---|
| `test_e02_phase10_login_identity` | SQLite-only locking property; PostgreSQL does not behave that way |
| `test_e02_phase41_hardening` | this engine does not fold Ø/ø, so there is no variant to test |
| `test_stage_b_regressions` | `ALLOWED_ORIGINS` not explicitly configured in this run |
| `test_e07_phase22_backup_policy` (2) | needs a live `pg_dump` on PATH |

Step 17's own 3 skips are the environment-conditional ones above; they are not new.

### Negative controls

All run in **isolated copies** (`/tmp/p23_nc*`); the working tree was never modified for a
control.

| Control | Change | Result |
|---|---|---|
| NC-23a | `post_restore_verified` widened back to `True` | **1 failed** |
| NC-23b | row-count mismatch detection disabled | **1 failed** |
| NC-23c | scheduled path overwrites with `EXIT_BACKUP_FAILED` | **2 failed** |
| NC-23d | `EXIT_TIMEOUT` constant removed | **3 failed** |

Each restored: all pass. The Phase 22 controls (NC-1…NC-20) were not re-run individually;
their fixes are re-covered by the suites above, all green.

---

## 5. Operational gaps — not solved by repository code

### Offsite — **NOT VERIFIED**

Verified behaviour:

| Case | Result |
|---|---|
| `http://` to a real remote host | refused |
| `http://` remote + loopback opt-in | refused (opt-in is loopback-only) |
| `http://` `10.0.0.5` + opt-in | refused |
| `http://` loopback + opt-in + `ENV=production` | refused |
| `https://` real host | configured |
| local S3-compatible server via loopback opt-in | full upload → verify → corruption detected |

**HTTPS is mandatory for any real remote provider.** The loopback opt-in cannot be widened:
it requires the literal `1`, a loopback host, and a non-production `ENV`.

**Evidence required before a real provider may be called VERIFIED** (none of this exists
today):

1. `BACKUP_OFFSITE_URL` set to a real `https://` endpoint with a bucket-scoped credential
   limited to `PutObject`/`GetObject`/`DeleteObject` on that prefix.
2. One real backup run completing with `offsite` reported as uploaded.
3. `verify_against_record()` succeeding against that object — i.e. the object downloaded back
   and its SHA-256 matched the locally recorded digest.
4. A deliberate same-size corruption detected against the same provider.
5. The status file recording the run, and the operator capturing all four outputs.

Status as of this audit: `OFFSITE_CONFIGURED` only against a **local** S3-compatible server.

### Scheduler — **NOT CONFIGURED**

- Templates exist: `deploy/systemd/gerege-backup.{service,timer}`, `deploy/cron/gerege-backup.cron`.
- **Nothing is installed.** Neither `/etc/systemd/system/gerege-backup.*` nor
  `/etc/cron.d/gerege-backup` exists on this host.
- `maintenance.py status` correctly reports `scheduler installed on this host: NO` and
  `state: NEVER_EXECUTED`.
- There is **no installer**: no `--install`, `--uninstall`, `--dry-run`, or overlap-control
  subcommand. The earlier "safe installer/uninstaller/dry-run" requirement in the mandate is
  therefore **not met by the repository** — installation is a documented manual procedure, and
  it was **not tested here** (no install was attempted, per the constraint not to touch a real
  host).
- Exit-code mapping in the unit comment matches the implemented set (10/11/12/13/14/15/16/18),
  and `17` is correctly reserved for plaintext detection. Verified by test.

### Alerting — **NOT CONFIGURED**

- Retry verified: 503/503/200 delivered on attempt 3; a 4xx is not retried.
- Payload is an allowlist of 9 fields; it cannot carry a DSN or key path (tested).
- **There is no redactor and the `error` string is not scrubbed.** The risk was assessed
  rather than assumed: `pg_dump`/libpq and SQLAlchemy both report host and port but never the
  password, including on auth failure and DNS failure. A test pins that, so a driver regression
  fails the suite.
- **No destination is configured** anywhere — not in this environment, not in CI.
- Activation requires: a real webhook URL in `BACKUP_ALERT_WEBHOOK`, a receiver that returns
  2xx, and one deliberately failed run confirming the alert arrives. Until then failures are
  recorded in the status file and **nobody is told**.

### Recovery — **CONDITIONAL GO**

Measured on disposable databases only (timings are observed, not estimated):

| Operation | Observed |
|---|---|
| Lock-blocked backup preflight → exit 18 | ~5–6 s (statement 30 s / lock 5 s bounds) |
| Encrypted backup of the fixture DB | ~1 s |
| Restore + post-restore verification | ~1 s |
| Rollback invariant checks (drift/ownership/grants) | sub-second on the fixture |

**No RPO or RTO is stated.** These are single-database fixture timings on a local cluster and
say nothing about a production dataset; inventing a number from them would be dishonest.

---

## 6. Documentation audit

| Defect | Claim | Reality | Action |
|---|---|---|---|
| D-1 | CI run `44870665596` | **404 — does not exist** | corrected in §1 and §11 |
| D-2 | `b9c4f28` was a success | failed step 29, exit 11 | corrected; §11 now a full table |
| D-3 | "Commits (19)" | 21 (20 through `10227a2`) | corrected |
| D-4 | "the four commits before `e6fd261`" | six failed step 17; **six earlier commits never ran CI at all** | corrected, with the gap called out |
| D-5 | "Final HEAD `10227a2`" | branch HEAD is `50c47d3` | clarified |
| D-6 | RESTORE/RECOVERY **GO** | verification could pass vacuously | code fixed; verdicts → CONDITIONAL GO |

Exit-code tables were checked against observed CLI behaviour and now match (0/11/15/18
observed; 10/12/13/14/16/17 documented and unchanged). Every skip is explained in §4. No
wording was found that implies production readiness after these corrections — the Phase 22
verdict table already carried PRODUCTION **NO-GO**.

---

## 7. Changes made

Two code fixes and their tests, plus the documentation corrections above. Nothing unrelated.

```
core/backup_service.py        D-6: row_counts_checked; narrowed post_restore_verified
scripts/maintenance.py        D-6: CLI warns when counts were not compared
core/backup_automation.py     D-7: EXIT_TIMEOUT named; scheduled path preserves the code
tests/test_e07_phase23_restore_verification.py   new (5)
tests/test_e07_phase23_exit_codes.py             new (5)
tests/test_e07_phase23_alert_redaction.py        new (5)
docs/PHASE22-REMEDIATION-REPORT.md               D-1…D-6 corrections
docs/PHASE23-FINAL-VERIFICATION.md               this report
```

Deliberately **not** changed: restore was not made to fail on a missing manifest (it would
break recovery); no installer was invented; no offsite or alert destination was configured;
no `main`, no deployment, no force-push.
