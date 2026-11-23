#!/usr/bin/env python3
"""Owner-credentialed maintenance operations (finding E-05).

Backup and restore moved here from the application runtime because they cannot be done
correctly by ``gerege_app``:

* ``pg_dump`` needs ``LOCK TABLE ... ACCESS SHARE`` on every table. Measured on
  PostgreSQL 16: as a non-owner it fails with ``permission denied for table
  registrations`` and writes an **empty** archive.
* restore replays a dump that drops and recreates the schema, which requires ownership.

Giving the runtime those rights would undo the role split, so these operations now run
under ``gerege_owner`` from an operator-triggered process. The application keeps the
read-only listing endpoint (it only reads the backups directory) and no longer exposes
create/restore over HTTP.

Usage
-----
::

    python scripts/maintenance.py backup          # create a labelled backup
    python scripts/maintenance.py list            # what exists
    python scripts/maintenance.py verify <file>   # checksum + structural check
    python scripts/maintenance.py restore <file>  # EXPLICIT; pre-backup + verify
    python scripts/maintenance.py prune --days 14

The connection comes from ``DATABASE_OWNER_URL`` (preferred) or
``MIGRATION_DATABASE_URL``, falling back to ``DATABASE_URL`` **only** when that URL is
already owner-capable. It is never printed. If the credential is not the owner the
process exits non-zero with an explanation rather than producing a useless archive.

Restore is required to be deliberate: it takes a fresh pre-restore snapshot first,
verifies both the chosen archive and the result, and refuses to run without ``--yes``
in a non-interactive context.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Optional, Sequence

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _owner_url() -> Optional[str]:
    """Resolve the maintenance DSN without ever logging it.

    ``DATABASE_URL`` is the runtime credential in a split deployment; using it here
    would guarantee the guard in ``backup_service`` rejects the operation. It is kept as
    the last fallback only for single-credential setups (development, SQLite), where the
    one role *is* the owner — and the guard still decides whether it is good enough.
    """
    for name in ("DATABASE_OWNER_URL", "MIGRATION_DATABASE_URL", "DATABASE_URL"):
        value = os.getenv(name, "").strip()
        if value:
            if name == "DATABASE_URL":
                print(
                    "note: DATABASE_OWNER_URL is unset; falling back to DATABASE_URL. "
                    "This is only correct if that URL already belongs to the owner role.",
                    file=sys.stderr,
                )
            return value
    return None


def _describe_connection(service) -> None:
    """Print who we are, to prove the credential is the maintenance one."""
    from core.db_engine import is_postgres

    if not is_postgres():
        print(f"engine: sqlite ({os.getenv('DB_PATH', 'default path')})")
        return
    from core.db_engine import get_db_connection

    # Phase 24 (D-8): this banner is diagnostic only, but it opened a connection with no
    # handler. An unreachable database therefore produced a raw psycopg2 traceback from
    # `raw_connection()` before the backup had even started - the operator got 20 frames of
    # SQLAlchemy internals instead of "I cannot reach the database". The banner must never
    # be able to abort the command; whatever it cannot determine is simply not printed.
    try:
        conn = get_db_connection()
    except Exception as exc:  # noqa: BLE001
        print(f"engine: postgresql   (cannot describe connection: {type(exc).__name__})")
        return
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT current_user, "
            "(SELECT COUNT(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            " WHERE n.nspname='public' AND c.relkind='r' AND pg_get_userbyid(c.relowner)=current_user)"
        )
        user, owned = cur.fetchone()
        cur.close()
    except Exception as exc:  # noqa: BLE001
        print(f"engine: postgresql   (cannot read role: {type(exc).__name__})")
        return
    finally:
        try:
            conn.close()
        except Exception:
            pass
    print(f"engine: postgresql   role: {user}   tables owned: {owned}")


def _policy_preflight(label: Optional[str] = None) -> Optional[int]:
    """Refuse an unsatisfiable backup policy before anything touches the database.

    Phase 22 (P21-01). ``create_backup()`` already refuses, but by then the CLI has
    opened a connection to print its identity banner. "No tenant data was read" is part
    of the security claim, so the check has to come first: this returns an exit code
    when the run must not start, and None when it may proceed. ``evaluate()`` is a pure
    function of the environment, so this costs nothing and cannot fail for I/O reasons.

    Phase 38 (F-38-A) — this used to return the exit code and stop, which made a policy
    refusal **completely silent**:

      * no alert was sent. Alerting lives in ``backup_automation._finish()``, which only
        the scheduled-run path calls, and the refusal happened *before* that path was
        entered. So the single most likely production misconfiguration — a missing or
        unreadable encryption key — disabled alerting at exactly the moment alerting
        exists for. The runbook told the operator to expect an alert here; there was none.
      * the status file was not written, so ``maintenance.py status`` and any monitor
        reading ``.last_backup_status.json`` kept reporting the previous **successful**
        run while every hourly backup failed.

    Reproduced before changing it: with ``BACKUP_ENCRYPTION_KEY_FILE=/nonexistent`` and a
    live webhook, ``backup-run`` exited 11 and delivered zero requests, while calling
    ``run_scheduled_backup()`` directly delivered a correct ``backup.failure`` payload.
    The divergence was the CLI, not the library.

    When ``label`` is given the refusal is recorded through the same path a scheduled run
    uses, so alerting and the status file behave identically. When it is not (the manual
    ``backup`` command), this stays a pure environment check with no side effects.
    """
    from core import backup_policy

    policy = backup_policy.evaluate()
    if policy.allowed:
        return None
    print(f"backup REFUSED [{policy.code}]: {policy.error}", file=sys.stderr)
    if label is not None:
        _record_refusal(policy, label)
    return policy.exit_code


def _record_refusal(policy, label: str) -> None:
    """Make a pre-flight refusal visible to alerting and to monitoring.

    Deliberately contains no I/O that can raise: this runs on the failure path, and a
    refusal that crashed would report the wrong reason. If the status write fails, the
    alert is still attempted, and vice versa.

    Phase 38 (F-38-C). Whatever ``_finish`` appends to ``warnings`` is printed. The
    important one is "BACKUP_ALERT_WEBHOOK is not configured: nobody is notified of a
    failure" — without printing it, an operator who forgot to configure the webhook got a
    failure line, an exit code, and no statement that no human would ever hear about it.
    A missing alert configuration must be loud, and it must not be inferred from silence.
    """
    from core import backup_automation

    result = {
        "label": label,
        "encrypted": False,
        "offsite": False,
        "pruned": [],
        "warnings": [],
        "exit_code": policy.exit_code,
        "success": False,
        "error": policy.error,
        "encryption_policy": policy.code,
        "policy_refused": True,
    }
    try:
        backup_automation._finish(result, backup_automation.backup_dir())
    except Exception as exc:  # noqa: BLE001 - never mask the refusal itself
        print(
            f"  warning: could not record the refusal ({type(exc).__name__}); "
            "the exit code below is still authoritative",
            file=sys.stderr,
        )
        return
    for warning in result.get("warnings") or []:
        print(f"  warning: {warning}", file=sys.stderr)


def cmd_backup(label: str) -> int:
    from core import backup_service

    refused = _policy_preflight()
    if refused is not None:
        return refused
    _describe_connection(backup_service)
    result = backup_service.create_backup(label=label)
    if not result.get("success"):
        print(f"backup FAILED: {result.get('error')}", file=sys.stderr)
        # Phase 22: propagate the code the service computed instead of a blanket 1.
        #
        # The scheduled path (`backup-run`) has always returned `result["exit_code"]`, so
        # the documented code table - 11 crypto, 12 integrity, 15 not configured, 18
        # timeout - described one entry point and not the other. A timer or alerting rule
        # watching a manual backup could not distinguish a timeout from a missing key from
        # a disk-full, and the codes were effectively decorative for this command.
        code = result.get("exit_code")
        return int(code) if code else 1
    print(
        f"backup OK: {result['filename']} "
        f"({result['size_bytes']} bytes, sha256 {result['sha256'][:16]}…)"
    )
    counts = result.get("table_counts") or {}
    print(f"  rows: audit_logs={counts.get('audit_logs')} pages={counts.get('pages')}")
    return 0


def cmd_backup_run(label: str) -> int:
    """One complete scheduled run (Phase 16): backup, encrypt, verify, retain, alert.

    This is what a timer invokes. It prints only non-secret facts and exits with a
    code that distinguishes the failure classes (see core/backup_automation.py).
    """
    from core import backup_automation

    refused = _policy_preflight(label=label)
    if refused is not None:
        return refused
    _describe_connection(None)  # service arg is unused; identity only
    result = backup_automation.run_scheduled_backup(label=label)
    if not result.get("success"):
        print(f"SCHEDULED BACKUP FAILED: {result.get('error')}", file=sys.stderr)
        for warning in result.get("warnings") or []:
            print(f"  warning: {warning}", file=sys.stderr)
        return int(result.get("exit_code") or backup_automation.EXIT_BACKUP_FAILED)
    print(
        f"scheduled backup OK: {result.get('filename')} "
        f"({result.get('size_bytes')} bytes, encrypted={result.get('encrypted')}, "
        f"offsite={result.get('offsite')})"
    )
    pruned = result.get("pruned") or []
    print(f"  retention: kept last {result.get('retention_days')} day(s); pruned {len(pruned)}")
    for warning in result.get("warnings") or []:
        print(f"  warning: {warning}")
    return int(result.get("exit_code") or 0)


def cmd_status() -> int:
    """Monitoring probe: distinguishes never-ran, in-progress, failed, stale and ok.

    Phase 18: a single exit code could not tell an operator whether to read the last
    error, wait, or go and install a scheduler that was never installed. The state is now
    explicit, and "no scheduler is installed on this host" is reported as a fact rather
    than inferred.
    """
    from core import backup_automation, backup_policy

    # Phase 22 (P21-01): report the resolved security policy alongside run health. An
    # operator asking "is this host able to back up at all?" should get an answer before
    # the first failed run, and a misconfigured policy is a configuration fact, not a run
    # outcome. Only names and reasons are printed - never key material or a DSN.
    policy = backup_policy.describe()
    print(
        f"encryption policy: {policy['code']} "
        f"(production={policy['production']}, mode={policy['mode']}, "
        f"key_configured={policy['key_configured']})"
    )
    if not policy["allowed"]:
        print(f"  POLICY REFUSES BACKUPS: {policy['error']}", file=sys.stderr)
    elif policy["warning"]:
        print(f"  warning: {policy['warning']}")

    info = backup_automation.operational_state()
    state = info["state"]
    installed = info.get("scheduler_installed")

    if state == backup_automation.STATE_NEVER_EXECUTED:
        print("NO BACKUP STATUS: no scheduled run has been recorded on this host")
    elif state == backup_automation.STATE_IN_PROGRESS:
        print(f"BACKUP IN PROGRESS: {info.get('detail')}")
    elif state == backup_automation.STATE_FAILED:
        print(f"BACKUP FAILED: exit_code={info.get('exit_code')} {info.get('error') or ''}".strip())
    elif state == backup_automation.STATE_STALE:
        print(f"BACKUP IS STALE: age {info.get('age_hours')}h (max {info.get('max_age_hours')}h)")
    else:
        print(f"BACKUP OK: last successful run {info.get('age_hours')}h ago "
              f"(max {info.get('max_age_hours')}h)")

    print(f"  state: {state}")
    print(f"  scheduler installed on this host: {'yes' if installed else 'NO'}")
    if not installed:
        print(
            "  WARNING: no gerege-backup.timer or /etc/cron.d/gerege-backup exists here.",
            file=sys.stderr,
        )
        print(
            "  The repository ships templates in deploy/systemd and deploy/cron; they are",
            file=sys.stderr,
        )
        print(
            "  NOT installed. Until they are, backups only happen when someone runs them.",
            file=sys.stderr,
        )

    detail = backup_automation.read_status() or {}
    if detail.get("offsite_state"):
        print(f"  offsite: {detail.get('offsite_state')}"
              + (f" (provider {detail.get('offsite_provider')})" if detail.get("offsite_provider") else ""))
    if detail.get("warnings"):
        for warning in detail["warnings"]:
            print(f"  warning: {warning}")

    return 0 if state == backup_automation.STATE_SUCCESS else 1


def cmd_list() -> int:
    from core import backup_service

    items = backup_service.list_backups()
    if not items:
        print("no backups")
        return 0
    from core import backup_automation, backup_service as _bs

    # Phase 20: show the security class next to each archive. Before this, a plaintext
    # leftover and a verified encrypted archive printed identically, so an operator
    # reading `list` had no way to tell which lines were safe restore points.
    print(f"{'filename':<52} {'size':>12}  {'class':<16} created")
    unauthenticated = 0
    for item in items[:50]:
        path = os.path.join(_bs.BACKUP_DIR, item["filename"])
        klass = backup_automation.classify_archive(path)
        if klass != "authenticated":
            unauthenticated += 1
        print(f"{item['filename']:<52} {item['size_bytes']:>12}  {klass:<16} {item['modified_at']}")
    if unauthenticated:
        print(
            f"\nWARNING: {unauthenticated} archive(s) are not authenticated encrypted backups; "
            "run `maintenance.py legacy` for a detailed report."
        )
    return 0


def cmd_verify(filename: str) -> int:
    from core import backup_service

    result = backup_service.verify_backup(filename)
    if result.get("valid"):
        print(f"valid: {filename} sha256 {result.get('sha256', '')[:16]}…")
        return 0
    print(f"INVALID: {result.get('error')}", file=sys.stderr)
    return 1


def cmd_restore(filename: str, assume_yes: bool) -> int:
    from core import backup_service

    _describe_connection(backup_service)

    # Verify BEFORE creating the pre-restore snapshot: a corrupt archive must not push a
    # good snapshot out of the retention window, and must not touch a live database.
    check = backup_service.verify_backup(filename)
    if not check.get("valid"):
        print(f"refusing to restore: {check.get('error')}", file=sys.stderr)
        return 1

    if not assume_yes:
        if not sys.stdin.isatty():
            print(
                "refusing to restore non-interactively without --yes. Restore replaces "
                "the live schema; run it as an explicit operator action.",
                file=sys.stderr,
            )
            return 2
        print(
            f"About to restore {filename} over the live database.\n"
            "A pre-restore snapshot is taken first, and the result is verified; if "
            "verification fails the process replays that snapshot.\n"
            "Type the word 'restore' to continue: ",
            end="",
            flush=True,
        )
        if sys.stdin.readline().strip().lower() != "restore":
            print("aborted; nothing was changed.")
            return 2

    print("creating pre-restore snapshot…")
    result = backup_service.restore_backup(filename)
    if result.get("success"):
        print(
            f"restore OK from {result.get('restored_from')}; "
            f"pre-restore snapshot {result.get('pre_restore_snapshot')}"
        )
        counts = result.get("restored_table_counts") or {}
        print(f"  rows: audit_logs={counts.get('audit_logs')} pages={counts.get('pages')}")
        # Phase 23: do not let "restore OK" imply the contents were checked when the
        # archive carried no manifest. The restore is still correct to keep; the claim
        # about it is what has to shrink.
        if not result.get("row_counts_checked", True):
            print(
                "\n  WARNING: row counts were NOT verified. " + str(result.get("verification_note") or ""),
                file=sys.stderr,
            )
            print(
                "  Inspect the restored data before restarting the application.",
                file=sys.stderr,
            )
        note = result.get("grant_note")
        if note:
            print(f"\ngrants: {note}")
        print(
            "\nVerify before restarting the application:\n"
            "  python scripts/provision_roles.py --verify   (exit 0 = least privilege)\n"
            "  python scripts/maintenance.py verify         (archive integrity)\n"
            "The app refuses to boot on an over-privileged runtime role, so a clean\n"
            "--verify is the precondition for `docker compose up`."
        )
        return 0

    print(f"restore FAILED: {result.get('error')}", file=sys.stderr)
    print(f"  rollback_status: {result.get('rollback_status')}", file=sys.stderr)
    if result.get("recovery_instruction"):
        print(f"  {result['recovery_instruction']}", file=sys.stderr)
    return 1


def cmd_legacy(quarantine: Optional[str] = None, confirmed: bool = False) -> int:
    """Report plaintext/legacy archives in the backup directory. Read-only by default.

    Phase 19 found that ``maintenance.py backup``, ``migrate.py`` and ``deploy.sh``
    published plaintext dumps into ``BACKUP_DIR``. Those files may still exist on a
    deployed host, and they are the most sensitive artifacts the product produces.

    Deliberately conservative:

    * never reads archive **contents** — only enough of the file header to classify it, so
      running it cannot spill tenant data into a terminal or a log;
    * never deletes anything; ``--quarantine`` *moves* files, and requires ``--yes``;
    * refuses a quarantine directory inside the backup directory, which would defeat it.

    Exit codes: 0 = no plaintext found, 17 = plaintext present (action needed).
    """
    import shutil

    from core import backup_automation, backup_service

    directory = backup_service.BACKUP_DIR
    if not os.path.isdir(directory):
        print(f"no backup directory at {directory}")
        return 0

    classified = [
        (name, backup_automation.classify_archive(os.path.join(directory, name)))
        for name, _st in backup_automation._archives(directory)
    ]
    # Use the shared inventory rather than re-deriving it here. It was written for this
    # purpose and had no caller (P21-03); two independent definitions of "plaintext" is how
    # `prune` and `legacy` came to disagree about whether these files may be deleted.
    plaintext = [n for n, _st in backup_automation.legacy_plaintext_archives(directory)]
    assert set(plaintext) <= {n for n, c in classified if c == "plaintext"}
    legacy_ossl = [n for n, c in classified if c == "legacy-openssl"]
    unknown = [n for n, c in classified if c == "unknown"]
    encrypted = [n for n, c in classified if c == "authenticated"]

    print(f"backup directory: {directory}")
    print(f"  authenticated (AEAD) : {len(encrypted)}")
    print(f"  legacy openssl (.enc): {len(legacy_ossl)}  (restorable, NOT authenticated)")
    print(f"  plaintext            : {len(plaintext)}  (tenant data in the clear)")
    print(f"  unknown              : {len(unknown)}  (not restorable; never counted)")

    if plaintext:
        print()
        print("PLAINTEXT ARCHIVES PRESENT — readable without the encryption key:")
        for name in plaintext:
            print(f"  {name}")

    if quarantine:
        if not confirmed:
            print("\nrefusing to move archives: pass --yes with --quarantine")
            return 17
        if os.path.abspath(quarantine) == os.path.abspath(directory):
            print("\nrefusing: quarantine directory is the backup directory itself")
            return 17
        os.makedirs(quarantine, mode=0o700, exist_ok=True)
        try:
            os.chmod(quarantine, 0o700)
        except OSError:
            pass
        moved = 0
        for name in plaintext + legacy_ossl:
            src = os.path.join(directory, name)
            dst = os.path.join(quarantine, name)
            try:
                shutil.move(src, dst)
            except OSError as exc:
                print(f"  could not move {name}: {type(exc).__name__}")
                continue
            # Sidecars describe a file that is no longer in this directory.
            for suffix in (".sha256", ".meta.json"):
                sidecar = src + suffix
                if os.path.exists(sidecar):
                    try:
                        shutil.move(sidecar, dst + suffix)
                    except OSError:
                        pass
            moved += 1
        print(f"\nmoved {moved} archive(s) to {quarantine} (nothing was deleted)")
        if moved:
            # The list above was computed before the move. Exit status has to describe the
            # directory as it stands now: a quarantine that moved every plaintext archive
            # has resolved the condition, and returning 17 anyway made a successful
            # remediation indistinguishable from "still exposed" to an operator or a
            # monitor. P21-03 follow-up.
            return 17 if (len(plaintext) + len(legacy_ossl) - moved) > 0 else 0

    return 17 if plaintext else 0


def cmd_prune(days: int) -> int:
    from core import backup_service

    result = backup_service.prune_old_backups(keep_days=days)
    # Phase 20: a locked-out prune used to print "pruned 0 backup(s)" and exit 0, which
    # reads exactly like a successful retention pass that found nothing to do. It is a
    # *refusal*, and an operator tuning retention needs to know the difference.
    if result.get("locked"):
        print(f"SKIPPED: {result.get('error', 'backup directory is locked')}")
        return 16
    print(f"pruned {result['pruned_count']} backup(s) older than {days} day(s)")
    for name in result["pruned_files"]:
        print(f"  {name}")
    return 0


def cmd_scheduler(args) -> int:
    """Scheduler lifecycle (Phase 24): status / validate / dry-run / install / uninstall.

    Writes only the systemd unit files this installer owns, and only when asked. `--dry-run`
    computes the identical plan and prints it without touching anything.
    """
    from core import scheduler_setup as sched

    unit_dir = args.unit_dir or sched.DEFAULT_UNIT_DIR
    env_file = args.env_file or sched.DEFAULT_ENV_FILE
    emit = lambda message: print(f"  {message}")

    if args.action == "status":
        state = sched.status(unit_dir=unit_dir, env_file=env_file)
        print(f"unit directory: {state['unit_dir']}")
        print(f"  service installed: {'yes' if state['service']['installed'] else 'NO'}"
              f" ({'ours' if state['service']['is_ours'] else 'not ours' if state['service']['installed'] else '-'})")
        print(f"  timer installed:   {'yes' if state['timer']['installed'] else 'NO'}"
              f" ({'ours' if state['timer']['is_ours'] else 'not ours' if state['timer']['installed'] else '-'})")
        print(f"  env file:          {'present' if state['env_file_present'] else 'MISSING'}"
              f"{' mode ' + state['env_file_mode'] if state['env_file_mode'] else ''}")
        print(f"  systemd available: {'yes' if state['systemd_available'] else 'NO'}")
        # Three separate facts. "installed" does not imply "enabled" or "active".
        print(f"  installed:         {'yes' if state['installed'] else 'NO'}")
        print(f"  enabled:           {'yes' if state['enabled'] else 'NO' if state['systemd_available'] else 'unknown (no systemd)'}")
        print(f"  active:            {'yes' if state['active'] else 'NO' if state['systemd_available'] else 'unknown (no systemd)'}")
        if state["systemd_detail"]:
            print(f"  systemd:           {state['systemd_detail']}")
        if not state["installed"]:
            print("\n  The scheduler is NOT installed on this host. Backups only happen when",
                  file=sys.stderr)
            print("  someone runs them. See docs/SCHEDULER-SETUP.md.", file=sys.stderr)
            return 1
        return 0

    if args.action == "validate":
        problems = sched.validate_config(
            exec_start=args.exec_start, working_dir=args.working_dir, env_file=env_file,
            timeout_s=args.timeout, on_calendar=args.on_calendar,
            randomized_delay_s=args.randomized_delay, unit_dir=unit_dir,
        )
        if problems:
            for problem in problems:
                print(f"  PROBLEM: {problem}", file=sys.stderr)
            return 1
        print("  configuration is installable")
        return 0

    if args.action in ("dry-run", "install"):
        plan = sched.plan_install(
            exec_start=args.exec_start, working_dir=args.working_dir, env_file=env_file,
            timeout_s=args.timeout, on_calendar=args.on_calendar,
            randomized_delay_s=args.randomized_delay, persistent=not args.no_persistent,
            unit_dir=unit_dir, force=args.force,
        )
        if not plan.ok:
            print("  cannot install: the plan has problems", file=sys.stderr)
            for problem in plan.problems:
                print(f"  PROBLEM: {problem}", file=sys.stderr)
            return 1
        for note in plan.notes:
            print(f"  note: {note}")
        for item in plan.files:
            print(f"  {item.action:9s} {item.path} ({oct(item.mode)}) - {item.reason}")

        if args.action == "dry-run":
            print("\n  dry-run: nothing was written, no unit was enabled, no service started.")
            return 0

        if not args.yes:
            if not sys.stdin.isatty():
                print("  refusing to install without confirmation: pass --yes", file=sys.stderr)
                return 2
            answer = input("Install these files? [y/N] ").strip().lower()
            if answer not in ("y", "yes"):
                print("  aborted; nothing was changed.")
                return 2

        result = sched.install(plan, enable=not args.no_enable, assume_yes=args.yes, log=emit)
        if not result.get("success"):
            print(f"  install FAILED: {result.get('error')}", file=sys.stderr)
            return 1
        print(f"  installed: {len(result['written'])} file(s)")
        print(f"  enabled:   {'yes' if result['enabled'] else 'NO'}")
        print(f"  detail:    {result['enable_detail']}")
        if not result["enabled"]:
            print("\n  Files are installed but the timer is NOT enabled. Run:",
                  file=sys.stderr)
            print(f"    sudo systemctl daemon-reload && sudo systemctl enable --now {sched.UNIT_TIMER}",
                  file=sys.stderr)
            return 1
        return 0

    if args.action == "uninstall":
        result = sched.uninstall(unit_dir=unit_dir, env_file=env_file,
                                 force=args.force, dry_run=args.dry_run, log=emit)
        action = "would remove" if result["dry_run"] else "removed"
        targets = result.get("would_remove") if result["dry_run"] else result.get("removed")
        print(f"  {action}: {len(targets)} file(s)")
        for note in result.get("notes", []):
            print(f"  note: {note}")
        return 0

    print(f"  unknown action {args.action}", file=sys.stderr)
    return 2


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Owner-credentialed maintenance (E-05).")
    sub = parser.add_subparsers(dest="command", required=True)

    p_backup = sub.add_parser("backup", help="create a backup")
    p_backup.add_argument("--label", default="manual")

    sub.add_parser("list", help="list existing backups")

    p_verify = sub.add_parser("verify", help="verify one archive")
    p_verify.add_argument("filename")

    p_restore = sub.add_parser("restore", help="restore (explicit, verifies both ways)")
    p_restore.add_argument("filename")
    p_restore.add_argument("--yes", action="store_true", help="skip the interactive confirmation")

    p_prune = sub.add_parser("prune", help="delete old archives")
    p_prune.add_argument("--days", type=int, default=14)

    # Phase 20: safe detection of plaintext archives left by the pre-fix manual path.
    p_legacy = sub.add_parser(
        "legacy",
        help="report plaintext/unauthenticated archives in the backup directory (read-only)",
    )
    p_legacy.add_argument(
        "--quarantine",
        metavar="DIR",
        help="move plaintext archives to DIR (a private 0700 directory) after reporting",
    )
    p_legacy.add_argument(
        "--yes",
        action="store_true",
        help="required with --quarantine; no archive is ever deleted automatically",
    )

    # Phase 16: the scheduled entry point, and the monitoring probe that reads it.
    p_run = sub.add_parser(
        "backup-run", help="scheduled run: backup + encrypt + verify + retain + alert"
    )
    p_run.add_argument("--label", default="scheduled")
    sub.add_parser("status", help="report the last scheduled run (monitoring probe)")

    # Phase 24: scheduler lifecycle. Paths are injectable so the whole lifecycle can be
    # exercised without touching a real systemd installation.
    p_sched = sub.add_parser("scheduler", help="install/validate/remove the backup timer")
    p_sched.add_argument(
        "action",
        choices=("status", "validate", "dry-run", "install", "uninstall"),
    )
    p_sched.add_argument("--unit-dir", help=f"systemd unit directory (default {('%(default)s')})")
    p_sched.add_argument("--env-file", help="environment file the unit reads")
    p_sched.add_argument(
        "--exec-start",
        default=(
            "/usr/bin/docker compose -f docker-compose.prod.yml run --rm --no-deps "
            "maintenance python scripts/maintenance.py backup-run --label scheduled"
        ),
        help="command the unit runs",
    )
    p_sched.add_argument("--working-dir", default="/opt/gerege")
    p_sched.add_argument("--timeout", type=int, default=2 * 3600, help="TimeoutStartSec")
    p_sched.add_argument("--on-calendar", default="hourly")
    p_sched.add_argument("--randomized-delay", type=int, default=300)
    p_sched.add_argument("--no-persistent", action="store_true")
    p_sched.add_argument("--no-enable", action="store_true", help="write files, do not enable")
    p_sched.add_argument("--force", action="store_true", help="replace a differing existing unit")
    p_sched.add_argument("--dry-run", action="store_true", help="for uninstall: show only")
    p_sched.add_argument("--yes", action="store_true", help="required for noninteractive install")

    args = parser.parse_args(argv)

    url = _owner_url()
    if url:
        # Point the whole process at the maintenance credential. `load_dotenv` inside the
        # modules uses `override=True`, so this must be set before they are imported —
        # every command imports `core.backup_service` lazily for exactly that reason.
        #
        # Phase 16: the normalisation used to rewrite `os.environ` in place, so a caller
        # that invoked `main()` in-process (a test, or any future embedder) had its own
        # `DATABASE_URL` silently rewritten from `postgresql+psycopg2://` to
        # `postgresql://`. `core.db_engine` caches one engine per URL, so the mutated
        # value poisoned every later test in the same process. The env var is now
        # restored by `main()`'s caller-visible contract: see `_restore_env` below.
        normalised = url
        if normalised.startswith("postgres://"):
            normalised = normalised.replace("postgres://", "postgresql+psycopg2://", 1)
        elif normalised.startswith("postgresql://"):
            normalised = normalised.replace("postgresql://", "postgresql+psycopg2://", 1)
        os.environ["DATABASE_URL"] = normalised

    if args.command == "backup":
        return cmd_backup(args.label)
    if args.command == "list":
        return cmd_list()
    if args.command == "verify":
        return cmd_verify(args.filename)
    if args.command == "restore":
        return cmd_restore(args.filename, args.yes)
    if args.command == "prune":
        return cmd_prune(args.days)
    if args.command == "legacy":
        return cmd_legacy(args.quarantine, args.yes)
    if args.command == "backup-run":
        return cmd_backup_run(args.label)
    if args.command == "scheduler":
        return cmd_scheduler(args)
    if args.command == "status":
        return cmd_status()
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    # Phase 24 (D-8): `MaintenanceCredentialRequired` is a deliberate precondition, not a
    # crash - it names the wrong role, the empty schema, or an unreachable database. Letting
    # it escape produced a 20-frame psycopg2/SQLAlchemy traceback that buries the one line
    # an operator needs. It is reported, with exit 15 ("not configured"), which is the code
    # the table already assigns to a run that cannot be performed correctly.
    #
    # Every other exception is left alone: an unexpected failure of unknown shape should
    # keep its traceback, because that is what a bug report needs.
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001
        from core.backup_service import MaintenanceCredentialRequired

        if isinstance(exc, MaintenanceCredentialRequired):
            print(f"cannot run: {exc}", file=sys.stderr)
            sys.exit(15)
        raise
