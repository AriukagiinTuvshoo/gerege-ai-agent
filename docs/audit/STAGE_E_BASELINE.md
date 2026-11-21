# Stage E — E0 Baseline: remote and environment truth

**Date** 2026-11-17 · **Auditor** Stage E independent pass · **Rule** nothing trusted from prior
reports without re-measurement.

This document records what the repository and CI *actually* were before any Stage E change.
No code was modified during E0/E1.

---

## 1. Repository state (measured, not quoted)

| Fact | Value | How measured |
|---|---|---|
| Local HEAD | `deedebf85fcb8b7815a31733ca44fff8d9d9ded6` | `git rev-parse HEAD` |
| Remote branch tip | `deedebf85fcb8b7815a31733ca44fff8d9d9ded6` | `git ls-remote origin` |
| Local vs remote | **0 ahead / 0 behind** | `git rev-list --left-right --count` |
| `origin/main` | `48e9c6f7392729bc87d0c810553ff459a919dbfb` | `git ls-remote origin` |
| Merge-base with main | `48e9c6f` (= main, unchanged) | `git merge-base` |
| Working tree | clean | `git status --short` |
| Current branch | `arena/d78ebf88-gerege-ai-agent` | `git branch --show-current` |
| `main` touched directly? | **No** | main is still at the base commit |

**Correction to the Stage D hand-off.** The Stage D message cited remote commit `97ea01f`.
That was accurate when written but is **not** the branch tip: four commits landed after it.

```
97ea01f  docs(stage-c): record P1-05 fix, ...     <- cited in the Stage D hand-off
38c00a9  feat(P1-06): add foreign keys
0bec434  fix(SEC-04): dedupe Meta webhooks
e52e84d  fix(SEC-03): CSP + production-only HSTS
f892265  fix(SEC-07): shared-store rate limiting
deedebf  docs(stage-d): completion report        <- actual tip
```

No divergence between local and remote; nothing needed restoring.

---

## 2. Pull request

| Field | Value |
|---|---|
| PR | **#1 — OPEN** |
| Base / head | `main` / `arena/d78ebf88-gerege-ai-agent` |
| Mergeable / state | `MERGEABLE` / `CLEAN` |
| Size | +7048 / −547 across 41 files |
| Commits | 15 |
| URL | https://github.com/AriukagiinTuvshoo/gerege-ai-agent/pull/1 |

---

## 3. CI (verified from GitHub, not from a report)

Latest run on the branch tip: **`43988038959`** on `deedebf` — **success**, and every prior
run on every commit of the branch is also success:

```
43988038959  deedebf  completed/success
43987573358  f892265  completed/success
43986566347  e52e84d  completed/success
43985857467  0bec434  completed/success
43985064523  38c00a9  completed/success
43909114273  97ea01f  completed/success
```

`PR #1 statusCheckRollup` → `SUCCESS test-and-security-audit`.

**Step-level evidence** (run `43988038959`, job `133721180378`): 34 substantive steps, all
`success`, including Docker build and the live PostgreSQL/Redis suites.

**Is CI hiding anything?** Checked explicitly:

| Check | Result |
|---|---|
| `continue-on-error` | **none** in the workflow |
| `\|\| true` / `; true` / `exit 0` in run blocks | **none** |
| Steps guarded by `if: !cancelled()` | 23 of 32 |

The `if: !cancelled()` guards are deliberate: they let later diagnostic steps run even after
an earlier failure, but a failing step still fails the job, so a red build cannot look green.
This is the opposite of masking.

---

## 4. Test suite — measured

`166` test functions across 16 files.

| Configuration | Result |
|---|---|
| SQLite, `REDIS_URL` set, `ALLOWED_ORIGINS` set (as CI runs it) | **166 passed** |
| SQLite, no `ALLOWED_ORIGINS` | 165 passed, **1 skipped** |
| SQLite, no `REDIS_URL` | 163 passed, **3 skipped** |

**The "1 skipped" in the Stage D figures is environmental, not a hidden failure.** It is
`tests/test_stage_b_regressions.py:172` — `SKIPPED: ALLOWED_ORIGINS not configured
explicitly`. CI sets `ALLOWED_ORIGINS`, so CI executes it and the count there is 166
passing, 0 skipped. Reported honestly rather than rounded to "165 passed" everywhere.

---

## 5. Schema state

| Item | Value |
|---|---|
| Migration head | `0003_foreign_keys` |
| Foreign keys (PostgreSQL, measured via `pg_constraint`) | **16** |
| Drift vs `core/models.py` | 0 |

Verified with an independent SQL query rather than the project's own helper.

---

## 6. Environment used for this audit

| Component | Version / config |
|---|---|
| Python | 3.11.2, SQLAlchemy 2.1.9, Alembic 1.20.1 |
| PostgreSQL | 16.2, local cluster, `--encoding=UTF8 --locale=C.utf8` |
| Redis | 6.2.14, `127.0.0.1:6379` |
| Test databases | disposable `e1_*` databases created per test, never production |

All destructive tests (restore, wipe-and-recover) ran only against throw-away databases
created for this audit.
