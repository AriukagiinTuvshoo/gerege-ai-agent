# Phase 43 — CI Skip-Gate Hardening & Exact-HEAD CI Verification

**Branch** `arena/d78ebf88-gerege-ai-agent`
**Starting HEAD** `20ddb1ad64440c385224d40d1386c51ba187331d` (matches Phase 42 exactly)
**Final HEAD** `f65a4609b4acf48f33a39feefd33272447ff08aa` — **pushed, CI GREEN**
**Main** `48e9c6f` (unmodified), **PR #1** OPEN, unmerged

**Verdict: PASS** — CI is green on the exact final commit, and the fix is proven in both
directions (fails without it, passes with it).

---

## 1. Original root cause

Phase 42 reported **F-42-B**: `/tmp/p20suite.log` is gated with `--no-skip-check`, so
`check_pytest_log.py` switches its skip check off wholesale.

That was **accurate but incomplete**. Removing the flag is necessary and **not
sufficient**, and I measured that before writing any fix.

Two cases carried this guard:

```python
if os.getenv("GEREGE_DESTRUCTIVE_TESTS") != "1":
    print("[SKIP] set GEREGE_DESTRUCTIVE_TESTS=1 to run (uses the live database)")
    return
```

`return` is not a skip. pytest records **PASSED**. Measured on a clean PostgreSQL
database with the variable unset:

```
test_p20_31_a_stranded_connection_releases_its_locks    PASSED [ 96%]
test_p20_32_schema_reset_actually_empties_the_schema    PASSED [100%]
[SKIP] set GEREGE_DESTRUCTIVE_TESTS=1 to run (uses the live database)
[SKIP] set GEREGE_DESTRUCTIVE_TESTS=1 to run (drops every object in public)
============================== 2 passed in 0.28s ===============================
```

The `[SKIP]` notices go to pytest's **captured-output trap**, so CI's `-v` log does not
contain them at all.

**The decisive measurement:** I ran both the current gate *and* the gate Phase 42
proposed (drop `--no-skip-check`) against that log. **Both returned 0.**

```
GATE with --no-skip-check      -> EXIT 0
GATE without --no-skip-check   -> EXIT 0
```

A count floor cannot catch it either: the cases *do* run; they just do nothing.

So the real defect has three layers:

| Layer | Mechanism | Detectable by a log gate? |
|---|---|---|
| L1 | `--no-skip-check` disables the check | only if removed |
| L2 | `print(); return` records PASSED | **no** — nothing to find |
| L3 | stdout captured, so even the notice is absent | **no** |

---

## 2. Files changed

| File | Change |
|---|---|
| `scripts/check_pytest_log.py` | new `--require-run NAME`; +63 lines |
| `.github/workflows/ci.yml` | p20 gate: drop `--no-skip-check`, add two `--require-run`, +17 lines |
| `tests/test_e06_phase20_backup_remediation.py` | 2 guards: `print+return` → `pytest.skip()` |
| `tests/test_e29_ci_integrity.py` | policy map: `/tmp/p20suite.log` now `(True, [])` |
| `tests/test_e43_skip_gate_hardening.py` | **new**, 35 tests |

Across the phase: `dec359a` (98 insertions, 11 deletions, 4 files + new suite),
`b7e9927` (the p20 step's database and its first 4 guard tests), `f65a460`
(+73/−1 — the provisioning order and 2 more guard tests).

---

## 3. Exact fix

**Three parts, each covering a shape the others cannot. Part (d) was added only after CI
proved parts (a)–(c) were not enough on their own.**

**(a) Source — the skip becomes real.** Both guards now call
`pytest.skip("GEREGE_DESTRUCTIVE_TESTS=1 is required (...)")`. pytest writes a
`SKIPPED` line with the reason, so the failure is *legible*, not merely detectable.

**(b) Gate — the skip check is on.** `--no-skip-check` removed from the p20 line.

**(c) Gate — `--require-run` requires PASSED.** The named case must appear on a line
containing `PASSED`. This **stands on its own**: it does not depend on the skip check, so
a future re-added `--no-skip-check` cannot reopen the hole.

`--require-run` matches `PASSED` specifically, **not the bare name**. My first version
tested `name in text` — and measured: a *skipped* case's name is in the log, so that
version passed a log where both destructive cases had skipped. That mistake is now
pinned by `test_a_skipped_destructive_case_is_rejected_even_with_the_skip_check_off`.

**(d) A real database, provisioned in the right order.** Turning the skip check on made
the step fail with `8 case(s) SKIPPED` — because the step had never set a `DATABASE_URL`
at all, so `db_engine.is_postgres()` was `False` and the module ran against SQLite. The
step now owns a disposable database and builds it the way the Phase 24 DR step does:

```
provision_roles.py --apply     # GRANT USAGE, CREATE ON SCHEMA public TO gerege_owner
alembic upgrade head           # 7 revisions, as gerege_owner
provision_roles.py --apply     # converge grants over the new tables
provision_roles.py --verify
assert tableowner = gerege_owner
```

The order is load-bearing and I got it wrong first time. Migrating before provisioning
dies immediately — `permission denied for schema public` — because since PostgreSQL 15
`CREATE DATABASE` leaves `public` grantable only to `pg_database_owner` (the superuser).

**Policy preserved:** the destructive opt-in `GEREGE_DESTRUCTIVE_TESTS=1` is still set in
CI. It remains what makes the destructive work *safe*; the gate is what makes its absence
*fail*. The pass floor stays at **24** — **not lowered**, and not raised to 32 either,
because it is a floor and the measured run is 32.

---

## 4. Before-fix reproduction

| Step | Command | Result |
|---|---|---|
| Old gate, opt-in missing | `check_pytest_log.py log --min-passed 24 --require-summary --no-skip-check` | **exit 0** ← the defect |
| Phase 42's proposed fix | same without `--no-skip-check` | **exit 0** ← still broken |
| Log contents | `grep -c SKIPPED` | **0** |

---

## 5. After-fix reproduction

Disposable databases, both directions, full CI command.

**Case A — opt-in present:**

```
32 passed, 2 warnings in 3.20s
  required case passed: test_p20_31_a_stranded_connection_releases_its_locks
  required case passed: test_p20_32_schema_reset_actually_empties_the_schema
  log: 32 passed, 0 failed
GATE EXIT=0
```

**Case B — opt-in missing:**

```
30 passed, 2 skipped, 1 warning in 2.36s
::error:: 2 case(s) SKIPPED in file(s) with no documented exception:
   tests/test_e06_phase20_backup_remediation.py 2
   test_p20_31_a_stranded_connection_releases_its_locks SKIPPED [ 96%]
   test_p20_32_schema_reset_actually_empties_the_schema SKIPPED [100%]
GATE EXIT=1
```

The step now fails, names both cases, and states the requirement.

**Case C — the provisioning order, on a fresh database (the run-2 failure):**

```
CREATE DATABASE gerege_p20_test                      -- as superuser, so owner = gerege
alembic upgrade head        (BEFORE provision)  ->  psycopg2.errors.InsufficientPrivilege:
                                                     permission denied for schema public
                                                     0 tables created
alembic upgrade head        (AFTER provision)   ->  7 revisions applied
provision_roles.py --apply / --verify           ->  rc 0 / rc 0
tableowner                                      ->  gerege_owner
```


---

## 6. Negative-control results

**The strongest evidence: 9 of the new tests fail against the pre-fix code and all 35
pass after it.** Measured by stashing the fix and re-running:

```
9 failed, 17 passed        (pre-fix, 26 tests existed then)
35 passed                  (post-fix)
```

**A second negative control was added for run 2**, which the first four guard tests could
not have caught. Restoring the exact failing order (`alembic` before `provision`) makes
the ordering test fail and nothing else:

```
assert 16 < 15
FAILED TestTheStepProvidesARealDatabase::test_provisioning_comes_before_the_migration
1 failed, 34 passed
```

Restoring the correct order: **35 passed.** So the test that now guards the run-2 defect
is itself proven to fail on that defect.

All 10 required negative controls, each behavioural (real logs, real subprocess):

| # | Requirement | Test | Status |
|---|---|---|---|
| 1 | Normal opt-in: cases execute | `TestCaseANormalCiConfiguration` (2) | PASS |
| 2 | Missing opt-in: gate fails | `test_the_gate_fails_when_neither_case_ran` | PASS |
| 3 | Six unexpected skips: gate fails | `test_six_unexpected_skips_fail` | PASS |
| 4 | One documented skip: allowed | `test_a_documented_allowed_skip_still_passes` | PASS |
| 5 | Unparseable skip output: fail closed | `test_unparseable_skip_output_fails_closed` | PASS |
| 6 | Missing log: fail | `test_a_missing_log_fails` | PASS |
| 7 | Empty log: fail | `test_an_empty_log_fails_when_execution_was_expected` | PASS |
| 8 | Failed pytest: propagates | `test_a_failed_case_propagates` | PASS |
| 9 | Below floor: fail | `test_a_count_below_the_floor_fails` | PASS |
| 10 | Injected skip cannot exit 0 | `TestAnInjectedSkipCannotPass` (3) | PASS |

Plus `test_removing_no_skip_check_alone_does_NOT_fix_it`, which encodes the Phase 42
premise so it cannot be "simplified" back to the one-line fix later.

**Not source-string assertions:** every control builds a real log file and runs the real
`scripts/check_pytest_log.py` as a subprocess.

---

## 7. Full test results

| Metric | Count |
|---|---|
| **Passed** | **1868** |
| **Failed** | **0** |
| **Skipped** | **53** (env-gated) |
| **Xfailed** | **1** |
| **Collected** | **1922** |

Sum check: 1868 + 53 + 1 = 1922 ✅

This run reflects the final tree (`f65a460`). The skip count is higher than the 6 measured
earlier in the phase **because this sandbox had to be rebuilt mid-phase**, and the
rebuilt one exposes neither `P24_DR_DATABASE_URL` nor `BACKUP_OFFSITE_TEST_ENDPOINT`, so
the DR and offsite suites skip instead of running. That was verified rather than assumed:
the 53 skips resolve into exactly those two env-gated families (11 DR, 32 offsite, plus
the pre-existing 6 and 4 from `test_e41_s3_execution.py`). **No skip is caused by the
changes in this phase** — CI sets both variables, which is why CI's step count is 72/72.
`scratch/test_cargo_lookup.py` (pre-existing on `main`, an external-API e2e script) fails
on this sandbox's lack of egress and is excluded from the 1868.

**Skip breakdown (6) — up from 4 in Phase 42, and that increase is the fix working:**

| # | Test | Reason | New? |
|---|---|---|---|
| 1 | `e02_phase10_login_identity:669` | SQLite locking property | pre-existing |
| 2 | `e02_phase41_hardening:852` | engine does not fold Ø/ø | pre-existing |
| 3 | **`e06_phase20_backup_remediation:789`** | **`GEREGE_DESTRUCTIVE_TESTS=1` required** | **NEW — was a false pass** |
| 4 | **`e06_phase20_backup_remediation:872`** | **`GEREGE_DESTRUCTIVE_TESTS=1` required** | **NEW — was a false pass** |
| 5 | `e07_phase22_wal_copy_safety:159` | WAL does not apply to PG | pre-existing |
| 6 | `stage_b_regressions:172` | `ALLOWED_ORIGINS` unset | pre-existing |

Skips 3 and 4 are **not regressions.** They are two tests that previously reported
`PASSED` while verifying nothing. Reporting them honestly is the point of this phase.

**Focused suites:** `test_e43_skip_gate_hardening.py` **35 passed** ·
`test_e29_ci_integrity.py` **20 passed** · combined **55 passed**.

**Phase 20 suite, run with the step's own sequence and env:** **32 passed, 0 skipped**,
gate `check_pytest_log.py … --min-passed 24 --require-summary --require-run ×2` **exit 0**.

**Workflow validation:** `validate_workflows.py` OK. Both changed files compile.

---

## 8. CI runs and exact SHAs

Three runs, and the last one is the only evidence that counts.

| # | Commit | Run | Result | What it proved |
|---|---|---|---|---|
| 1 | `dec359a` | [`45575674150`](https://github.com/AriukagiinTuvshoo/gerege-ai-agent/actions/runs/45575674150) | **failure** | The new skip gate fired: `8 case(s) SKIPPED` in the p20 module. The step had never set `DATABASE_URL`. |
| 2 | `b7e9927` | [`45580262153`](https://github.com/AriukagiinTuvshoo/gerege-ai-agent/actions/runs/45580262153) | **failure** | The first fix migrated before provisioning: `permission denied for schema public`, in zero seconds. |
| 3 | **`f65a460`** | **[`45594693508`](https://github.com/AriukagiinTuvshoo/gerege-ai-agent/actions/runs/45594693508)** | **success** | **72/72 steps pass. Step 31 green after 7 s — it had failed in 1 s and 0 s.** |

### Run 3, on exactly `f65a4609b4acf48f33a39feefd33272447ff08aa`

| Field | Value |
|---|---|
| Run ID | `45594693508` |
| Head SHA | `f65a4609b4acf48f33a39feefd33272447ff08aa` (exact match) |
| Workflow | `Gerege Enterprise CI & Security Gate`, event `pull_request`, attempt 1 |
| Job | `139137570097` `test-and-security-audit` — **success** |
| Steps | **72 total, 72 success, 0 failed, 0 skipped** |
| Annotations | Node 20 deprecation warning + 4 image digest notices. **No skip-gate complaint, no error.** |
| Step 31 | "Phase 20 — backup confidentiality, offsite integrity, locking" — **success**, 10:29:22Z → 10:29:29Z |

The step-31 duration is the tell: 1 s (run 1) and 0 s (run 2) were failures *before pytest
started*; 7 s is the provisioning → migration → provisioning → verify sequence plus a
32-test suite actually running.

### Runs 1 and 2 failed for different reasons, and both were real

They are worth keeping in the record because each was a defect the previous phase's
evidence could not have caught:

1. **`dec359a`** — the p20 step set no `DATABASE_URL`, so `db_engine.is_postgres()` was
   `False` and the module ran against SQLite. Six `@pytestmark_pg` cases and the two
   destructive ones skipped; `--no-skip-check` had been hiding that for the step's whole
   life. Removing the flag converted a hidden pass into an honest failure.
2. **`b7e9927`** — fixing (1) by adding a database exposed a second defect in my own fix:
   `alembic upgrade head` ran before `provision_roles.py --apply`. Since PostgreSQL 15 the
   `public` schema grants CREATE only to `pg_database_owner`, i.e. the superuser, so the
   migration could not create `alembic_version`. Reproduced locally; the corrected order
   is the one the Phase 24 DR step already uses.

**Logs were not retrievable** for any of the three runs: `gh api …/logs` and
`gh run view --log` both return `EOF` from `results-receiver.actions.githubusercontent.com`,
which this sandbox cannot reach. Run 3's evidence is therefore the step-level
conclusions, the 72/72 count and the absence of an error annotation — **plus** the local
reproduction of the identical step flow, which is recorded in §11. Where the logs would
have given the pytest summary line directly, that number is reproduced locally instead and
labelled as such.

---

## 9. Remaining limitations

1. **CI logs are not downloadable from this sandbox.** The runs themselves are verified
   from the API (step conclusions, 72/72, annotations), but the pytest summary line for
   step 31 is reproduced locally rather than read from the CI log. If a future failure
   needs the log text, it has to be read in the GitHub UI or from an environment that can
   reach `results-receiver.actions.githubusercontent.com`.
2. **`--require-run` requires `-v`.** Without `-v` pytest writes no per-case `PASSED`
   lines and the check fails closed. CI passes `-v`, so this is correct but worth knowing:
   the option is not usable on a `-q` step.
3. **Only the two p20 guards were converted.** Other modules use the same
   `print("[SKIP]"); return` pattern — `tests/test_postgres_restore_real_rollback.py` has
   at least five. They are **out of scope** for this phase (guardrail: no unrelated
   modifications) and none is on a `--no-skip-check` gate. **Recommended as a follow-up.**
4. **Phase 42's "6 skipped" figure was misdiagnosed by me.** It came from the SQLite
   fallback path (`@pytestmark_pg`), not from the opt-in. The opt-in defect was real and
   worse, but the number in the Phase 42 report was not its symptom. Corrected here.
5. The p20 floor stays 24 while a green run is 32; it is a floor, not an equality check,
   and I did not tighten it.

---

## 10. Is F-42-B resolved?

**YES — VERIFIED end to end, on the exact commit CI tested.**

| Sub-claim | Status |
|---|---|
| `--no-skip-check` removed from the p20 gate | **VERIFIED** |
| Gate fails when the destructive suite does not run | **VERIFIED** (exit 1, both cases named) |
| Gate passes on a normal run | **VERIFIED** (exit 0, 32 passed) |
| Cannot be reopened by re-adding `--no-skip-check` | **VERIFIED** (`--require-run` is independent) |
| Fails closed on missing / empty / unparseable / below-floor | **VERIFIED** (behavioural tests) |
| Negative controls meaningful | **VERIFIED** (9 fail pre-fix, 35 pass post-fix) |
| Test floors not lowered | **VERIFIED** (floor still 24) |
| Existing skip exceptions still work | **VERIFIED** |
| No regression in the full suite | **VERIFIED** (1868 passed, 0 failed locally) |
| **CI green on the final SHA** | **VERIFIED** — run `45594693508`, `f65a460`, 72/72 steps |

### What the fix actually turned out to be

F-42-B was reported as "the gate is switched off with `--no-skip-check`". That was true
and it was the *smaller* half. Turning the gate on exposed that the Phase 20 module had
**never run against PostgreSQL in CI at all** — it ran against a SQLite stand-in, whose
silent skips the disabled gate had been covering. Fixing the gate without fixing the
database would have made the step green while it still verified nothing, which is why the
fix could not be an exception for the skips.

The final shape of the fix, in three parts:

1. **Gate honesty** — `--no-skip-check` off, two `--require-run` assertions on, because
   the two destructive cases `return` rather than `skip()` and no skip gate can see that.
2. **A real database** — the step owns a disposable PostgreSQL database and provisions it
   in the order the DR step uses: `provision --apply` → `alembic upgrade head` → `provision
   --apply` → `verify`, then asserts `tableowner = gerege_owner`.
3. **Guards on the guards** — four tests that the step names a PostgreSQL URL, creates and
   migrates its own database and seeds the row the round-trip case protects; **two more**
   that pin the provisioning *order* and the ownership assertion, added after run 2 proved
   the first four could not catch an ordering defect.

### Phase verdict: **PASS**

The original weakness is fixed, the fix is proven in both directions by negative controls,
and CI is green on the exact commit that contains it. Two attempts were required; both
failures were diagnosed to root cause and neither was worked around by weakening a gate,
lowering a floor, deleting a test or hiding a skip.

**Nothing was merged, deployed, forced, or rewritten. `main` untouched at `48e9c6f`.
PR #1 is OPEN, `MERGEABLE`/`CLEAN`, head `f65a460`, base `main`.** Per the phase
instructions the merge decision is not mine to make — the branch is ready to review.
