# Phase 10, 11 and 12 — what "COMPLETED" was standing on

`docs/audit/PROGRESS.md` records three phases as finished:

| Phase | Recorded outcome |
|---|---|
| Phase 10 | 20-scenario failure & chaos suite — "all 20 executed and passed (`exit code 0`)" |
| Phase 11 | Complete production documentation — "9 files authored **and verified**" |
| Phase 12 | (no entry in the log at all) |

Each claim was checked. Two of the three did not survive contact with the artefact, and
the third was never recorded. The defects below are the ones a reader cannot see, because
they are about links, numbers and diagrams rather than about behaviour.

---

## Phase 10 — the suite passes; nothing checked that it ran

**What the log says:** all 20 scenarios executed and passed, exit code 0.

**What was measured:** 20 tests, 20 passing, and — running the file directly — a true
`exit code 0`. The claim itself is accurate. What was wrong is the machinery around it.

The CI step was:

```yaml
- name: Run Failure Scenarios Suite (Live PostgreSQL 16 & Redis 7)
  run: |
    pytest tests/test_failure_scenarios.py -v --tb=short
```

Ten words with no log written and no guard. Two consequences, both of which this repository
has already been bitten by elsewhere:

* **a scenario that SKIPS reports exactly what one that passes reports.** A skipped chaos
  test is indistinguishable from a passing one in this step, and `exit code 0` is what you
  get either way. This is the same shape as the Phase 22/23/24 step, which spent months
  green while 23 cases skipped on every run.
* **`exit code 0` is not evidence of 20 passes.** It is evidence that pytest did not fail,
  which a collection error, a skip and an empty selection all also produce.

**Fixed:** the step now writes a log and asserts `--min-passed 20 --require-summary`. The
scenario count is asserted against the file, so adding or losing a scenario is visible.

---

## Phase 11 — "authored and verified", with 22 links that only work on one machine

**What the log says:** the documents are authored and verified.

**What was measured**, by reading them:

### 1. Twenty-two links pointed at the author's Windows disk

Three documents contained links of this shape:

```
[`main.py`](file:///c:/Users/enhtv/Documents/ai-agent-person-fixed/ai-agent-person/main.py)
```

`file:///c:/Users/...` resolves on exactly one machine on earth, and it publishes that
machine's directory layout — including the author's account name — to every reader. Eleven
in `docs/ai/AI_RELIABILITY_AND_SECURITY.md`, five in `docs/ci/CI_CD_AND_TESTING.md`, six in
`docs/deployment/PRODUCTION_DEPLOYMENT.md`. All 22 now resolve inside the repository
(`../../main.py`).

A document whose "verified" status was never tested for its own links is a document whose
links were not verified.

### 2. The architecture diagram drew a module that does not exist

`docs/architecture/SYSTEM_ARCHITECTURE.md` put a `Domain Repositories (core/repositories.py)`
layer in the middle of the topology. There is no `core/repositories.py` in this repository
and there never was: data access goes through `database.py`, and domain logic lives in the
`*_service.py` modules at the repository root. Anyone orienting themselves from the diagram
would have gone looking for a layer that is not there.

Now `Domain Services (*_service.py, data access via database.py)` — which is what the code
does.

### 3. The table count was three migrations out of date

Three documents said **15 tables**. `core/models.py` defines **18**, a fresh database
creates 18, and `MIGRATION_TABLES` in the migration tool copies **17** — the difference being
`page_login_namespace`, added by migration 0006, which holds no source rows to transfer.

Both numbers are now stated correctly, and the difference is explained where it appears
rather than left for a reader to reconcile.

---

## Phase 12 — the phase the log does not mention

`PROGRESS.md` runs Phase 11, then stops. There is no Phase 12 row, no document named after
it, and no test that refers to it. Whatever Phase 12 was meant to be, the record does not
say, and nothing in the repository depends on it.

This report does not invent one. It records the absence: an audit log that skips a phase
number cannot be used to establish that the work happened, and a reader should not have to
guess whether it was merged, dropped, or renumbered.

---

## What now prevents this

`tests/test_e11_documentation_verification.py` — 68 cases, gated in CI — defines "verified"
as something a machine checks:

| Check | What it catches |
|---|---|
| every document exists and is longer than a stub | a claimed document that was never written |
| every relative link resolves | the 22 `file:///c:/` links |
| no document contains an absolute local path | the same leak, in any future form |
| every repo path in backticks exists | the `core/repositories.py` layer |
| table counts match `models.py` and `MIGRATION_TABLES` | the stale `15 tables` |
| the counts are explained where they differ | a reader reconciling 17 vs 18 alone |
| the Phase 10 step writes a log and asserts 20 passes | a chaos scenario that skips |

Four negative controls were run against these tests before they were committed: restoring
the `core/repositories.py` line, restoring a `file:///c:/` link, restoring `15 tables`, and
stripping the Phase 10 gate. Each fails the test that exists for it.

The third needed a second attempt. The first version asserted `"17 tables" in body or
"all 17 tables" in body.lower()`, which passed with the document saying 15 in one place and
17 in another — one correct number hiding three wrong ones. It now checks every count the
document states, not whether the right one appears somewhere.

---

## Verdict

| Phase | Claim | Verdict |
|---|---|---|
| 10 | 20 scenarios pass | **True**, and now gated rather than assumed |
| 11 | 9 documents authored and verified | **Half true** — authored, yes; verified, no. Fixed |
| 12 | — | **Not recorded**, and not reconstructable from the repository |

The pattern across all three is the one this phase keeps meeting: a status line was trusted
where an artefact could have been read. Thirty seconds of reading found 22 dead links, a
module that does not exist and a number three migrations stale.
