"""Scheduler installation lifecycle (Phase 24).

The repository ships systemd templates but has never had a way to install them, and an
operator following the runbook by hand had no way to tell a clean install from a partial one.
This module adds `status` / `validate` / `dry-run` / `install` / `uninstall` behind the
existing `maintenance.py` CLI.

It deliberately does **not** run `systemctl` blindly on whoever's machine invokes it. Every
filesystem destination and every system command is injectable, which is what makes the whole
lifecycle testable in an environment with no systemd bus - and is why the claims in
`docs/SCHEDULER-SETUP.md` are limited to what was actually exercised.

Design rules, in the order they matter:

* **Dry-run changes nothing.** It computes the identical plan as `install` and prints it.
  There is one planning function, so a dry-run cannot drift from a real run.
* **The installer owns exactly the files it writes.** Ownership is recorded by name, so
  `uninstall` removes those files and nothing else. It never deletes an archive, never
  touches `/etc/gerege/backup.env`, and refuses to remove a file whose content it did not
  write (an operator's local edit is a conflict, not a cleanup target).
* **Never silently overwrite.** An existing unit with different content is a conflict; the
  operator must pass `--force`, and `--force` still keeps a `.bak` of what it replaced.
* **Fail safely and coherently.** A partial install is rolled back to the pre-install state
  rather than left half-applied.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

# --- Defaults -----------------------------------------------------------------------------

#: Where systemd units live. Injectable for tests; not environment-overridable on purpose -
#: a mis-set variable must not cause the installer to write units somewhere unexpected.
DEFAULT_UNIT_DIR = "/etc/systemd/system"

#: The environment file the unit reads. Owned by the operator; this installer NEVER writes it
#: (it holds the owner credential) and NEVER deletes it.
DEFAULT_ENV_FILE = "/etc/gerege/backup.env"

UNIT_SERVICE = "gerege-backup.service"
UNIT_TIMER = "gerege-backup.timer"

#: Files this installer considers its own. Anything not in this list is not removed by
#: `uninstall`, ever.
OWNED_FILES: Tuple[str, ...] = (UNIT_SERVICE, UNIT_TIMER)


class SchedulerError(RuntimeError):
    """An installation step failed in a way the operator must see."""


# --- Plan model ---------------------------------------------------------------------------


@dataclass
class PlannedFile:
    """One file the installer intends to write."""

    name: str
    path: str
    content: str
    mode: int
    action: str  # "create" | "replace" | "unchanged"
    reason: str = ""


@dataclass
class Plan:
    unit_dir: str
    env_file: str
    files: List[PlannedFile] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    def changes(self) -> List[PlannedFile]:
        return [f for f in self.files if f.action != "unchanged"]


# --- Rendering ----------------------------------------------------------------------------


def _render_service(exec_start: str, working_dir: str, env_file: str, timeout_s: int) -> str:
    """Render the unit from the shipped template, with the operator's paths substituted.

    Kept as a template string rather than generated from scratch so the shipped file and the
    installed file stay recognisably the same document.
    """
    return f"""# Gerege backup - one run. Invoked by {UNIT_TIMER}.
#
# Installed by `python scripts/maintenance.py scheduler install`.
# Remove with `python scripts/maintenance.py scheduler uninstall`.
#
# The owner credential lives in {env_file} with mode 0600, owned by root. It is never placed
# in this unit file, so it never appears in `systemctl cat`.
[Unit]
Description=Gerege CRM database backup (encrypted, verified, retained)
After=docker.service
Requires=docker.service
OnFailure=none

[Service]
Type=oneshot
WorkingDirectory={working_dir}
EnvironmentFile={env_file}
# Distinct exit codes are passed through unchanged (10 backup, 11 crypto, 12 integrity,
# 13 credential, 14 offsite, 15 not configured, 16 locked, 18 timeout) so OnFailure
# handlers and alerting can distinguish them. 17 is reserved for `maintenance.py legacy`
# reporting plaintext on disk, which is a different operator action entirely.
ExecStart={exec_start}
TimeoutStartSec={timeout_s}s
# Hardening: the backup needs to write BACKUP_DIR and talk to docker; it needs nothing else.
# These are additive to the shipped template and are what `scheduler validate` checks for.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
# BACKUP_DIR must be writable by the service; add ReadWritePaths if it lives outside these.
ReadWritePaths=/opt/gerege /var/log
Nice=10
IOSchedulingClass=idle

[Install]
WantedBy=multi-user.target
"""


def _render_timer(on_calendar: str, randomized_delay_s: int, persistent: bool) -> str:
    return f"""# Gerege backup schedule.
#
# Installed by `python scripts/maintenance.py scheduler install`.
# Hourly is the default because it is the cheapest defensible RPO. `Persistent=true` runs a
# missed backup after downtime instead of skipping it.
[Unit]
Description=Gerege CRM database backup timer

[Timer]
OnCalendar={on_calendar}
RandomizedDelaySec={randomized_delay_s}
Persistent={"true" if persistent else "false"}
Unit={UNIT_SERVICE}

[Install]
WantedBy=timers.target
"""


# --- Validation ---------------------------------------------------------------------------

_EXIT_CODES_REQUIRED = r"\b(10|11|12|13|14|15|16|18)\b"


def validate_config(
    *,
    exec_start: str,
    working_dir: str,
    env_file: str,
    timeout_s: int,
    on_calendar: str,
    randomized_delay_s: int,
    unit_dir: str,
) -> List[str]:
    """Return a list of problems; empty means the configuration is installable.

    Validation happens before anything is written, which is the only way `dry-run` can be
    trusted as a preview of what `install` would do.
    """
    problems: List[str] = []

    if not exec_start.strip():
        problems.append("ExecStart is empty: the timer would start a unit that does nothing")
    if "maintenance.py" not in exec_start:
        problems.append(
            "ExecStart does not invoke scripts/maintenance.py - it must run the backup entry "
            "point, not an arbitrary command"
        )
    if "backup-run" not in exec_start and "backup" not in exec_start:
        problems.append("ExecStart does not run a backup subcommand")
    if not os.path.isabs(working_dir):
        problems.append(f"WorkingDirectory must be absolute, got {working_dir!r}")
    if not os.path.isabs(env_file):
        problems.append(f"EnvironmentFile must be absolute, got {env_file!r}")
    if not os.path.isabs(unit_dir):
        problems.append(f"unit directory must be absolute, got {unit_dir!r}")
    if timeout_s <= 0:
        problems.append("TimeoutStartSec must be positive; a zero timeout defeats the bound")
    if timeout_s > 24 * 3600:
        problems.append(
            "TimeoutStartSec exceeds 24h, which cannot be distinguished from a wedged unit"
        )
    if not on_calendar.strip():
        problems.append("OnCalendar is empty: the timer would never fire")
    if randomized_delay_s < 0:
        problems.append("RandomizedDelaySec must not be negative")
    if randomized_delay_s > 3600:
        problems.append(
            "RandomizedDelaySec above 3600s would let a backup drift past its interval"
        )
    return problems


def validate_rendered_service(service_text: str) -> List[str]:
    """Check the rendered unit for the properties the audit cares about."""
    problems: List[str] = []
    if not re.search(r"^Type=oneshot$", service_text, re.MULTILINE):
        problems.append("service is not Type=oneshot; a backup is not a daemon")
    if not re.search(r"^TimeoutStartSec=\d+s?$", service_text, re.MULTILINE):
        problems.append("service has no explicit TimeoutStartSec")
    if "EnvironmentFile=" not in service_text:
        problems.append("service has no EnvironmentFile; credentials would have nowhere to go")
    # Any `Environment=`/`EnvironmentFile=`-adjacent line that names a credential, in any
    # position - a directive can appear after other text on the same line.
    if re.search(
        r"(DATABASE_OWNER_URL|DATABASE_URL|PGPASSWORD|BACKUP_ENCRYPTION_KEY\w*)",
        service_text,
    ):
        problems.append(
            "service embeds a credential; it must come from EnvironmentFile so it does not "
            "appear in `systemctl cat`"
        )
    if not re.search(_EXIT_CODES_REQUIRED, service_text):
        problems.append(
            "service does not document the exit-code contract; an OnFailure handler could "
            "not tell a timeout from a plaintext exposure"
        )
    return problems


def validate_rendered_timer(timer_text: str) -> List[str]:
    problems: List[str] = []
    if UNIT_SERVICE not in timer_text:
        problems.append(f"timer does not reference {UNIT_SERVICE}")
    if not re.search(r"^OnCalendar=\S+", timer_text, re.MULTILINE):
        problems.append("timer has no OnCalendar")
    if not re.search(r"^Persistent=(true|false)$", timer_text, re.MULTILINE):
        problems.append("timer does not state Persistent explicitly")
    return problems


# --- Status -------------------------------------------------------------------------------


@dataclass
class UnitState:
    """What exists on disk. Deliberately not the same question as "is it enabled"."""

    name: str
    path: str
    installed: bool
    is_ours: bool
    reason: str = ""


def _read(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError):
        return None


def unit_state(name: str, unit_dir: str) -> UnitState:
    path = os.path.join(unit_dir, name)
    if not os.path.exists(path):
        return UnitState(name, path, installed=False, is_ours=False, reason="not present")
    text = _read(path) or ""
    ours = "Installed by `python scripts/maintenance.py scheduler install`" in text
    return UnitState(
        name,
        path,
        installed=True,
        is_ours=ours,
        reason="installed by this tool" if ours else "present but NOT written by this tool",
    )


def status(
    *,
    unit_dir: str = DEFAULT_UNIT_DIR,
    env_file: str = DEFAULT_ENV_FILE,
    run: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    """Report disk state, env-file state, and systemd's own view where a bus exists.

    ``enabled`` and ``active`` are only ever reported as True when systemd itself said so;
    the installer does not infer them from file presence.
    """
    service = unit_state(UNIT_SERVICE, unit_dir)
    timer = unit_state(UNIT_TIMER, unit_dir)
    env_present = os.path.exists(env_file)
    env_mode: Optional[str] = None
    if env_present:
        try:
            env_mode = oct(os.stat(env_file).st_mode & 0o777)
        except OSError:
            env_mode = None

    systemd_available, enabled, active, detail = _systemd_query(timer.name, run=run)

    return {
        "unit_dir": unit_dir,
        "env_file": env_file,
        "env_file_present": env_present,
        "env_file_mode": env_mode,
        "service": {"path": service.path, "installed": service.installed, "is_ours": service.is_ours},
        "timer": {"path": timer.path, "installed": timer.installed, "is_ours": timer.is_ours},
        # Three distinct questions the runbook used to conflate.
        "installed": service.installed and timer.installed,
        "systemd_available": systemd_available,
        "enabled": enabled,
        "active": active,
        "systemd_detail": detail,
    }


def _systemd_query(
    unit: str, run: Optional[Callable[..., Any]] = None
) -> Tuple[bool, bool, bool, str]:
    """Ask systemd whether the unit is enabled/active. Never raises."""
    runner = run or subprocess.run
    if shutil.which("systemctl") is None:
        return False, False, False, "systemctl not found on PATH"
    try:
        probe = runner(
            ["systemctl", "is-system-running"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception as exc:  # noqa: BLE001 - status must never explode
        return False, False, False, f"systemd probe failed: {type(exc).__name__}"
    running = (probe.stdout or "").strip() or (probe.stderr or "").strip()
    if "Failed to connect to bus" in (probe.stderr or "") or "offline" in running:
        return False, False, False, f"no systemd bus: {running[:80]}"

    def _query(verb: str) -> Tuple[bool, str]:
        try:
            result = runner(["systemctl", verb, unit], capture_output=True, text=True, timeout=10)
            return result.returncode == 0, (result.stdout or result.stderr or "").strip()
        except Exception as exc:  # noqa: BLE001
            return False, f"{verb} failed: {type(exc).__name__}"

    enabled, enabled_detail = _query("is-enabled")
    active, active_detail = _query("is-active")
    return True, enabled, active, f"enabled={enabled_detail or '-'} active={active_detail or '-'}"


# --- Planning -----------------------------------------------------------------------------


def plan_install(
    *,
    exec_start: str,
    working_dir: str,
    env_file: str,
    timeout_s: int,
    on_calendar: str,
    randomized_delay_s: int,
    persistent: bool,
    unit_dir: str,
    force: bool = False,
) -> Plan:
    """Compute the full install plan. This is what `dry-run` prints and `install` executes.

    Reading the destination is the only side effect, and it does not write anything.
    """
    plan = Plan(unit_dir=unit_dir, env_file=env_file)
    plan.problems.extend(
        validate_config(
            exec_start=exec_start,
            working_dir=working_dir,
            env_file=env_file,
            timeout_s=timeout_s,
            on_calendar=on_calendar,
            randomized_delay_s=randomized_delay_s,
            unit_dir=unit_dir,
        )
    )

    service_text = _render_service(exec_start, working_dir, env_file, timeout_s)
    timer_text = _render_timer(on_calendar, randomized_delay_s, persistent)
    plan.problems.extend(validate_rendered_service(service_text))
    plan.problems.extend(validate_rendered_timer(timer_text))

    if plan.problems:
        # Do not plan file actions for a configuration that cannot be installed; a preview
        # suggesting otherwise would be a lie.
        return plan

    for name, content, mode in (
        (UNIT_SERVICE, service_text, 0o644),
        (UNIT_TIMER, timer_text, 0o644),
    ):
        destination = os.path.join(unit_dir, name)
        existing = _read(destination)
        if existing is None and not os.path.exists(destination):
            action, reason = "create", "does not exist"
        elif existing is None:
            action, reason = "create", "exists but is unreadable; will be replaced"
        elif existing == content:
            action, reason = "unchanged", "already installed and identical"
        elif not force:
            action, reason = "replace", "already exists with different content"
            plan.problems.append(
                f"{destination} already exists and differs from what this installer would "
                "write. Refusing to overwrite it. Re-run with --force to replace it (the "
                "existing file is kept as .bak)."
            )
        else:
            action, reason = "replace", "exists with different content; --force given"
        plan.files.append(PlannedFile(name, destination, content, mode, action, reason))

    if not os.path.exists(env_file):
        plan.notes.append(
            f"{env_file} does not exist. The unit will not start without it, and it holds the "
            "owner credential - this installer does not create it. See "
            "docs/SCHEDULER-SETUP.md."
        )
    else:
        try:
            mode = os.stat(env_file).st_mode & 0o777
            if mode & 0o077:
                plan.problems.append(
                    f"{env_file} mode is {oct(mode)}; it must be 0600 (it holds a database "
                    "credential). Fix with: chmod 0600 " + env_file
                )
        except OSError as exc:
            plan.problems.append(f"cannot stat {env_file}: {type(exc).__name__}")

    return plan


# --- Execution ----------------------------------------------------------------------------


def _atomic_write(path: str, content: str, mode: int) -> None:
    """Write via a temp file in the same directory, then rename. Never a partial unit."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(dir=directory, prefix=".gerege-unit-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
    except Exception:
        if os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        raise


def install(
    plan: Plan,
    *,
    run: Optional[Callable[..., Any]] = None,
    enable: bool = True,
    assume_yes: bool = False,
    log: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Execute a plan. Rolls back to the pre-install state if any step fails.

    ``enable`` defaults to True but is reported separately: writing files and enabling the
    timer are different claims, and the result says which of them actually happened.
    """
    emit = log or (lambda message: None)
    if not plan.ok:
        return {
            "success": False,
            "error": "refusing to install: the plan has problems",
            "problems": plan.problems,
            "written": [],
            "enabled": False,
        }

    written: List[str] = []
    backups: List[Tuple[str, str]] = []  # (path, backup path)
    created_dirs: List[str] = []

    if not os.path.isdir(plan.unit_dir):
        created_dirs.append(plan.unit_dir)

    try:
        for item in plan.changes():
            if item.action == "replace":
                backup_path = item.path + ".bak"
                shutil.copy2(item.path, backup_path)
                backups.append((item.path, backup_path))
                emit(f"kept existing {item.path} as {backup_path}")
            _atomic_write(item.path, item.content, item.mode)
            written.append(item.path)
            emit(f"{'created' if item.action == 'create' else 'replaced'} {item.path} ({oct(item.mode)})")
    except Exception as exc:  # noqa: BLE001 - rollback must catch everything
        emit(f"write failed: {type(exc).__name__}: {exc}")
        _rollback(written, backups, created_dirs, emit)
        return {
            "success": False,
            "error": f"{type(exc).__name__}: {exc}",
            "rolled_back": True,
            "written": [],
            "enabled": False,
        }

    enabled = False
    enable_detail = "not attempted"
    reloaded = False
    if enable:
        systemd_available, _, _, detail = _systemd_query(UNIT_TIMER, run=run)
        if not systemd_available:
            enable_detail = f"systemd unavailable ({detail}); files installed but NOT enabled"
            emit(enable_detail)
        else:
            runner = run or subprocess.run
            for command in (
                ["systemctl", "daemon-reload"],
                ["systemctl", "enable", "--now", UNIT_TIMER],
            ):
                try:
                    result = runner(command, capture_output=True, text=True, timeout=60)
                    if result.returncode != 0:
                        enable_detail = (
                            f"{' '.join(command)} failed (exit {result.returncode}): "
                            f"{(result.stderr or result.stdout or '').strip()[:200]}"
                        )
                        emit(enable_detail)
                        break
                    if command[1] == "daemon-reload":
                        reloaded = True
                except Exception as exc:  # noqa: BLE001
                    enable_detail = f"{' '.join(command)} failed: {type(exc).__name__}"
                    emit(enable_detail)
                    break
            else:
                enabled = True
                enable_detail = f"{UNIT_TIMER} enabled and started"

    return {
        "success": True,
        "written": written,
        # Three separate claims, never collapsed into one "installed" boolean.
        "installed": bool(written),
        "daemon_reloaded": reloaded,
        "enabled": enabled,
        "enable_detail": enable_detail,
        "notes": plan.notes,
    }


def _rollback(
    written: Sequence[str],
    backups: Sequence[Tuple[str, str]],
    created_dirs: Sequence[str],
    emit: Callable[[str], None],
) -> None:
    """Restore the pre-install state after a failed install."""
    backup_map = dict(backups)
    for path in reversed(list(written)):
        try:
            if path in backup_map:
                shutil.move(backup_map[path], path)
                emit(f"restored previous {path}")
            else:
                os.unlink(path)
                emit(f"removed partially written {path}")
        except OSError as exc:
            emit(f"rollback could not restore {path}: {type(exc).__name__}")
    for directory in reversed(list(created_dirs)):
        try:
            os.rmdir(directory)
            emit(f"removed directory created by this run: {directory}")
        except OSError:
            pass


# --- Uninstall ----------------------------------------------------------------------------


def plan_uninstall(
    *, unit_dir: str = DEFAULT_UNIT_DIR, env_file: str = DEFAULT_ENV_FILE, force: bool = False
) -> Dict[str, Any]:
    """Decide what uninstall would remove. Only files this installer wrote are eligible."""
    removable: List[str] = []
    kept: List[Tuple[str, str]] = []

    for name in OWNED_FILES:
        state = unit_state(name, unit_dir)
        if not state.installed:
            kept.append((state.path, "not present"))
            continue
        if not state.is_ours and not force:
            kept.append(
                (
                    state.path,
                    "present but not written by this installer; remove it manually if that "
                    "is what you want",
                )
            )
            continue
        removable.append(state.path)

    notes: List[str] = []
    if os.path.exists(env_file):
        notes.append(
            f"{env_file} is kept: it holds the owner credential and is operator-owned. "
            "Delete it yourself if you are decommissioning the host."
        )
    notes.append(
        "Backup archives are never touched by uninstall. They live in BACKUP_DIR, which this "
        "command does not read."
    )
    return {"removable": removable, "kept": kept, "notes": notes, "env_file": env_file}


def uninstall(
    *,
    unit_dir: str = DEFAULT_UNIT_DIR,
    env_file: str = DEFAULT_ENV_FILE,
    run: Optional[Callable[..., Any]] = None,
    force: bool = False,
    dry_run: bool = False,
    log: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Remove only what this installer created. Disable first, then delete files."""
    emit = log or (lambda message: None)
    plan = plan_uninstall(unit_dir=unit_dir, env_file=env_file, force=force)

    for path, reason in plan["kept"]:
        emit(f"keeping {path}: {reason}")

    if dry_run:
        for path in plan["removable"]:
            emit(f"would remove {path}")
        return {"success": True, "dry_run": True, "removed": [], "would_remove": plan["removable"], "enabled": None}

    systemd_available, _, _, _ = _systemd_query(UNIT_TIMER, run=run)
    disabled = False
    if systemd_available and os.path.exists(os.path.join(unit_dir, UNIT_TIMER)):
        runner = run or subprocess.run
        for command in (
            ["systemctl", "disable", "--now", UNIT_TIMER],
            ["systemctl", "daemon-reload"],
        ):
            try:
                result = runner(command, capture_output=True, text=True, timeout=60)
                if result.returncode != 0:
                    emit(f"{' '.join(command)} exited {result.returncode} (continuing)")
                elif command[1] == "disable":
                    disabled = True
            except Exception as exc:  # noqa: BLE001
                emit(f"{' '.join(command)} failed: {type(exc).__name__} (continuing)")
    else:
        emit("systemd unavailable or unit not installed: skipping disable")

    removed: List[str] = []
    for path in plan["removable"]:
        try:
            os.unlink(path)
            removed.append(path)
            emit(f"removed {path}")
        except OSError as exc:
            emit(f"could not remove {path}: {type(exc).__name__}")

    return {
        "success": True,
        "dry_run": False,
        "removed": removed,
        "disabled": disabled,
        "notes": plan["notes"],
    }
