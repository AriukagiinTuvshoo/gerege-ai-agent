# Scheduler setup — installing the backup timer

How to install, verify, and remove the hourly backup timer. Read §1 first: it is the part that
determines whether any of this applies to your host.

> **Status: implemented and tested against disposable directories. NOT installed or verified
> on a real host, and not verified by this project's CI.** `systemctl` has never been invoked
> successfully by the test suite — the build environment has systemd as PID 1 but no D-Bus
> bus, and runs as a non-root user. Every claim below about `install`/`uninstall` refers to
> filesystem behaviour and to an injected `systemctl`, not to a live systemd.

---

## 1. What "installed" means, and why it is three questions

The status command answers three separate questions. They are not interchangeable, and
conflating them is how a host ends up with a timer nobody knows is disabled.

| Question | Command | Meaning |
|---|---|---|
| Are the unit files on disk? | `scheduler status` → `installed` | The files exist and this tool wrote them |
| Will the timer fire after reboot? | `scheduler status` → `enabled` | `systemctl is-enabled gerege-backup.timer` |
| Is it firing now? | `scheduler status` → `active` | `systemctl is-active gerege-backup.timer` |

`enabled` and `active` are reported as **unknown** when no systemd bus is reachable. The tool
never infers them from file presence.

---

## 2. Prerequisites

1. **`/etc/gerege/backup.env`, mode 0600, owned by root.** It holds
   `DATABASE_OWNER_URL` and `BACKUP_ENCRYPTION_KEY_FILE`. The installer will not create it —
   it contains a credential — but it *will* refuse to install if the file is world- or
   group-readable. See [BACKUP_AUTOMATION.md](operations/BACKUP_AUTOMATION.md) §5.
2. **The maintenance image works.** The unit runs:
   ```
   /usr/bin/docker compose -f docker-compose.prod.yml run --rm --no-deps maintenance \
       python scripts/maintenance.py backup-run --label scheduled
   ```
   Run that command by hand once before installing a timer around it. A timer that fails
   hourly is worse than no timer, because it looks configured.
3. **`BACKUP_DIR` is writable inside the service's sandbox.** The rendered unit sets
   `ProtectSystem=strict`, which makes everything read-only except `/opt/gerege` and
   `/var/log`. If `BACKUP_DIR` is elsewhere, add it to `ReadWritePaths` — the installer will
   not do this for you, because guessing a path is worse than saying so.

---

## 3. Preview before touching anything

`dry-run` computes the identical plan `install` executes — one function backs both, so the
preview cannot drift. It writes no file, creates no directory, enables no unit.

```bash
python scripts/maintenance.py scheduler dry-run
```

It prints one line per file:

```
  create    /etc/systemd/system/gerege-backup.service (0o644) - does not exist
  create    /etc/systemd/system/gerege-backup.timer (0o644) - does not exist
```

`validate` checks configuration only, and exits non-zero on a problem:

```bash
python scripts/maintenance.py scheduler validate
python scripts/maintenance.py scheduler validate --on-calendar ""   # PROBLEM: would never fire
```

Refused configurations include: an `ExecStart` that does not invoke `maintenance.py`, a
relative path, a zero or >24h timeout, a `RandomizedDelaySec` above one hour, a randomised
delay that could push a run past its interval, and any unit that embeds a credential (it would
appear in `systemctl cat` for any local user).

---

## 4. Install

```bash
sudo python scripts/maintenance.py scheduler install
```

Requirements enforced at this point:

- **Refuses to overwrite.** If a unit exists with different content, the install stops and
  names the file. Re-run with `--force` to replace it — your version is kept as `.bak`.
- **Refuses without confirmation.** Interactive by default; `--yes` is required when stdin is
  not a TTY, so a script cannot install a timer by accident.
- **Rolls back on failure.** A write that fails part-way restores the file it had already
  replaced and removes the one it had created. There is no half-installed state.
- **Fails safely without systemd.** Files are written, `enabled` is reported `NO`, and the
  command exits **1**. It does not claim a timer that will fire.

Useful flags: `--unit-dir`, `--env-file`, `--on-calendar`, `--timeout`, `--no-enable`,
`--no-persistent`, `--exec-start`, `--working-dir`. `--unit-dir` exists so the whole lifecycle
can be exercised somewhere harmless:

```bash
python scripts/maintenance.py scheduler install --unit-dir /tmp/units --env-file /tmp/backup.env --yes
```

---

## 5. Verify it actually fires

Installing files is not the goal. Before you call this operational:

```bash
systemctl list-timers gerege-backup.timer     # must show a NEXT and a LAST
systemctl status gerege-backup.timer
journalctl -u gerege-backup.service -n 50     # the last run's output, and its exit code
python scripts/maintenance.py status          # reads the status file the run wrote
```

`maintenance.py status` exits **1** when the last run failed or is older than
`BACKUP_MAX_AGE_HOURS`, which is what a monitoring system should alert on.

### Exit codes the timer will produce

| Code | Meaning | What to do |
|---|---|---|
| 0 | success | — |
| 10 | backup failed | read the journal |
| 11 | encryption failed (key configured but unusable) | check the key file, not the database |
| 12 | integrity failed (archive did not authenticate) | do not trust the archive; investigate disk |
| 13 | credential invalid | wrong role |
| 14 | offsite failed | local archive is still good |
| 15 | not configured (no key, or policy refused) | configuration error, not a runtime one |
| 16 | another backup/restore holds the lock | normal if a long restore is running |
| 17 | reserved: `maintenance.py legacy` found plaintext on disk | an exposure, not a schedule problem |
| 18 | a configured bound was exceeded (database or `pg_dump` timed out) | the database is slow or blocked |

`Type=oneshot` with no `SuccessExitStatus=` means systemd reports these unchanged, so an
`OnFailure=` handler can distinguish them. A test pins that `SuccessExitStatus` is never
added — it would make a failed backup look successful.

---

## 6. Overlap

The timer can, in principle, start a run while a previous one is still going. Two things
prevent a collision:

- `RandomizedDelaySec=300` spreads the hourly start.
- The run itself takes an exclusive `flock` on `<BACKUP_DIR>/.backup.lock`. A second
  concurrent run exits **16** immediately rather than interleaving. Verified: holding the lock
  and starting a run produced exit 16.

`flock` is released by the kernel on process death, so a `SIGKILL` cannot wedge the scheduler.

---

## 7. Uninstall

```bash
python scripts/maintenance.py scheduler uninstall --dry-run   # show only
sudo python scripts/maintenance.py scheduler uninstall
```

It removes **only** the two unit files, and only if they carry this installer's header. A
hand-written `gerege-backup.*` is left in place and named in the output.

It will **not**:
- touch anything in `BACKUP_DIR` — it never reads that directory;
- delete `/etc/gerege/backup.env` — that holds the owner credential and belongs to you;
- remove a unit it did not write, even with `--force`.

It disables and stops the timer first when systemd is reachable, then deletes the files. If
systemd is unreachable it says so and still removes the files.

---

## 8. What is not verified

Being explicit, because the difference matters:

| Claim | Status |
|---|---|
| Plan/dry-run/install/uninstall logic | **Tested** — 36 tests against disposable directories |
| Refuses to overwrite; `--force` keeps `.bak` | **Tested** |
| Rolls back a partial install | **Tested** with injected write failures |
| Uninstall leaves foreign units, archives, env file | **Tested** |
| Reports `enabled: NO` when systemd is absent | **Tested** |
| `systemctl enable` actually enables a timer | **Not verified on a real host** |
| The timer fires hourly in production | **Not verified** — requires a real host |
| `ReadWritePaths` is correct for your `BACKUP_DIR` | **Your responsibility** |

Do not describe the scheduler as operational until §5 has been run on the target host and
`systemctl list-timers` shows a NEXT run.
