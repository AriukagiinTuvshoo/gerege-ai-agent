# Alerting setup — pointing failure notifications at a real destination

> **Status: implemented and tested against a local HTTP sink. NOT CONFIGURED anywhere.** No
> destination exists in this repository, in its CI, or in the development environment used to
> build it. Until `BACKUP_ALERT_WEBHOOK` is set to a real endpoint and one deliberately failed
> run is observed arriving, **failures are recorded in the status file and nobody is told.**

---

## 1. How it works

`backup-run` posts a small JSON document to `BACKUP_ALERT_WEBHOOK` on success and on failure.
The two properties that matter:

1. **Alerting cannot change what a run means.** A delivery failure is appended to
   `result["warnings"]` and never alters `success`, `exit_code` or the original `error`.
   Tested both ways: a failed alert during a good backup leaves it successful; a failed alert
   during a bad backup leaves the original error intact.
2. **It cannot crash the run.** `notify()` never raises, including on a malformed webhook. A
   typo in the URL produces a warning, not a traceback — that was a real defect until Phase 24.

## 2. Configuration

| Variable | Default | Meaning |
|---|---|---|
| `BACKUP_ALERT_WEBHOOK` | unset | Full URL. Unset means **nobody is notified**, and the run says so in its warnings. |
| `BACKUP_ALERT_RETRIES` | 3 | Total attempts, clamped to 1–10. |
| `BACKUP_ALERT_BACKOFF_S` | 1 | Delay between attempts, clamped to 0–10 s. |

Worst-case added latency is `attempts × 10 s + backoff`, i.e. under a minute at defaults.

## 3. Retry policy

| Response | Retried? | Why |
|---|---|---|
| 2xx | no (success) | — |
| 5xx | **yes** | transient server fault |
| 429 | **yes** | a throttle is not a malformed request; sending again is what the receiver asked for |
| 400, 401, 403, 404, 422 | **no** | the request is wrong; retrying cannot fix it |
| connection refused / DNS failure / timeout | **yes** | transient by nature |

The last failure is reported as `notification failed: … (after N attempts)`. A test asserts
that a permanently broken receiver is contacted exactly `BACKUP_ALERT_RETRIES` times and not
more.

## 4. What is sent

An allowlist of nine fields — never a dump of the result dict:

```
event, label, filename, encrypted, offsite, exit_code, error, warnings, finished_at
```

No DSN, no key path, no environment dump. A test asserts the set exactly, so a future field
cannot be added without the test being updated deliberately.

### Redaction

`core/redaction.py` runs at the single chokepoint before the payload leaves the process:

- URL/DSN userinfo (`scheme://user:password@host` → `scheme://user:[REDACTED]@host`)
- `password=`/`secret=`/`token=`/`api_key=`/`client_secret=`-style pairs
- AWS access key ids, bearer tokens, JWTs
- base64 blobs containing `+` or `/` (narrowed deliberately — see below)
- literal values of known secret environment variables, longest first
- control characters and ANSI escapes stripped; line breaks collapsed to one line
- length bounded at 1000 characters with an explicit truncation marker

**Why this exists, honestly.** No leak was observed. libpq, `pg_dump`, SQLAlchemy and the
offsite module were each tested and none echo a credential. The payload does forward `error`
and `warnings` verbatim, and one site interpolates a raw exception, so the only thing standing
between a driver change and a credential in a third-party chat service is other libraries'
discretion. This is defence in depth, not a fixed exploit.

**Over-redaction is treated as a real failure mode.** The first draft's base64 rule destroyed
sha256 digests and archive filenames — the entire actionable content of a restore alert. Tests
assert that real diagnostics (lock timeouts, digest mismatches, "No space left on device",
archive filenames, sha256 values) pass through **unchanged**, and that a credential does not.

Prefer a redaction rule that fires too rarely to one that hides the reason a backup failed.

## 5. Activating it safely

1. Create a receiver you control — a chat webhook, or an internal endpoint. Do not point this
   at a shared or third-party destination until you have read §4.
2. `export BACKUP_ALERT_WEBHOOK=https://…` in `/etc/gerege/backup.env`, mode 0600.
3. Send a test without touching a backup:
   ```bash
   python - <<'EOF'
   from core import backup_automation as ba
   print(ba.notify("https://your-endpoint", {"event": "backup.test", "label": "manual-test"}))
   EOF
   ```
   Expect `(True, 'http 200')`. If it returns `http 4xx`, the payload is wrong — do not
   retry harder.
4. Cause one real failure and confirm it arrives:
   ```bash
   BACKUP_ENCRYPTION_KEY_FILE=/nonexistent python scripts/maintenance.py backup-run --label alert-test
   ```
   Expect exit **11** (`ENCRYPTION_KEY_MISSING`) and an alert whose `event` is
   `backup.failure` and whose `exit_code` is **11**.

   > **Corrected in Phase 38.** This step used to say "expect exit 15". A missing key has
   > always been **11** — `core/backup_policy.py` states the split explicitly ("the
   > documented codes are 11 (encryption failed) and 15 (not configured), and a missing key
   > has always been 11"). The wrong number mattered: an operator following this page would
   > have seen 11, concluded the alerting path was broken, and "fixed" a working system.
   >
   > Phase 38 also found that this command delivered **no alert at all** before the fix
   > (F-38-A): the CLI's pre-flight refusal returned before the alerting code ran. If you
   > are reading this on a commit before `f38`, this step cannot pass.

4b. Confirm the *silent* path is also loud — with no webhook configured, a failure must say
   so:
   ```bash
   BACKUP_ALERT_WEBHOOK= BACKUP_ENCRYPTION_KEY_FILE=/nonexistent \
     python scripts/maintenance.py backup-run --label no-hook-test
   ```
   Expect exit 11 **and** `warning: BACKUP_ALERT_WEBHOOK is not configured: nobody is
   notified of a failure`. Without that line an operator has no way to tell "alerting is
   fine" from "alerting was never configured".

## 6. Evidence required before calling alerting "configured"

- [ ] `BACKUP_ALERT_WEBHOOK` set in the environment file, mode 0600
- [ ] The test payload in §5.3 delivered (2xx)
- [ ] The failure in §5.4 delivered, with the right `event` and `exit_code`
- [ ] A deliberate typo confirmed to produce a *warning*, not a crash
- [ ] `maintenance.py status` still reporting the run correctly

Until all five are true on the target host, alerting is **NOT CONFIGURED**, and a failed
backup will be silent apart from the status file and the journal.
