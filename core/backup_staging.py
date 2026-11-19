"""Secure staging + advisory locking for backup operations (Phase 18).

Two Phase 17 findings live here.

**Plaintext leak (CRITICAL-2).** ``create_backup`` wrote the dump straight into
``BACKUP_DIR``. When encryption then failed, the run exited 11 correctly but left a
world-readable ``.sql.gz`` full of tenant data behind, because the only code that
removed the plaintext sat *after* the encryption call on the success path. The fix is
structural rather than a ``try/finally`` bolted onto one branch: the dump is written
into a private staging directory (mode 0700) **inside the same filesystem** so that
publishing it is an atomic ``rename``, and the staging directory is destroyed by an
``atexit`` handler, a signal handler, and an explicit context manager. Any plaintext
that exists at any moment is therefore outside ``BACKUP_DIR``, inside a 0700 directory,
with mode 0600 files — and it is removed on every exit path, including ``SIGTERM``.

A crash that skips all of those (``SIGKILL``, power loss) can still leave a staging
directory behind. That is handled by :func:`sweep_stale_staging`, which runs at the
start of every backup and removes staging directories that are not owned by a live
process.

**Concurrency (MEDIUM-4).** Two runs of ``backup-run`` could overlap: cron fires every
hour, systemd ``Type=oneshot`` only serialises one unit, and nothing prevented a prune
from deleting an archive that another process was still writing. :func:`backup_lock`
takes an exclusive, non-blocking ``flock`` on ``<BACKUP_DIR>/.backup.lock``. ``flock``
is tied to the open file description, so the kernel releases it when the process dies —
there is no stale-lock state to recover from, which is the failure mode of a
lockfile-plus-PID design.
"""

from __future__ import annotations

import atexit
import errno
import os
import shutil
import signal
import secrets
import time
from types import FrameType
from typing import Optional

STAGING_PREFIX = ".staging-"
LOCK_NAME = ".backup.lock"
_SECURE_MODE = 0o700
_FILE_MODE = 0o600


class LockUnavailable(RuntimeError):
    """Another backup/prune/restore already holds the lock."""


def _harden_dir(path: str) -> None:
    try:
        os.chmod(path, _SECURE_MODE)
    except OSError:
        pass


class StagingDir:
    """A private working directory that guarantees its plaintext contents are destroyed.

    Usage::

        with StagingDir(backup_dir) as staging:
            dump_path = staging.path("payload.sql.gz")
            ...
            staging.publish(dump_path, os.path.join(backup_dir, "final.sql.gz"))

    The context manager removes the whole directory on exit, whether the body raised,
    returned, or was interrupted by a catchable signal.
    """

    def __init__(self, parent: str, prefix: str = STAGING_PREFIX) -> None:
        self.parent = os.path.abspath(parent)
        self.prefix = prefix
        self.path_dir: Optional[str] = None
        self._signal_handlers: dict = {}
        self._prev_handlers: dict = {}
        self._registered_atexit = False

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self) -> "StagingDir":
        os.makedirs(self.parent, exist_ok=True)
        while True:
            candidate = os.path.join(self.parent, f"{self.prefix}{os.getpid()}-{secrets.token_hex(4)}")
            try:
                os.makedirs(candidate, mode=_SECURE_MODE)
                break
            except FileExistsError:  # pragma: no cover - vanishingly unlikely
                continue
        _harden_dir(candidate)
        self.path_dir = candidate
        self._install_signal_guards()
        atexit.register(self.cleanup)
        self._registered_atexit = True
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.cleanup()
        return False

    def _install_signal_guards(self) -> None:
        """Best-effort cleanup on SIGTERM/SIGINT.

        The previous handler is restored immediately after cleaning up, then re-raised,
        so the process still dies with the right status. Only the main thread can
        install handlers; a background thread simply relies on ``atexit`` and the
        explicit context manager.
        """

        def _handler(signum: int, frame: Optional[FrameType]) -> None:  # pragma: no cover - signal path
            self.cleanup()
            previous = self._prev_handlers.get(signum)
            if callable(previous):
                previous(signum, frame)
            else:
                signal.signal(signum, signal.SIG_DFL)
                os.kill(os.getpid(), signum)

        for signame in ("SIGTERM", "SIGINT"):
            signum = getattr(signal, signame, None)
            if signum is None:
                continue
            self._signal_handlers[signum] = _handler
            try:
                self._prev_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, _handler)
            except (ValueError, OSError):  # not the main thread
                self._signal_handlers.pop(signum, None)

    # -- helpers -----------------------------------------------------------
    def path(self, name: str) -> str:
        if not self.path_dir:
            raise RuntimeError("staging directory used outside its context manager")
        full = os.path.join(self.path_dir, os.path.basename(name))
        return full

    def create_private(self, name: str) -> str:
        """Create an empty file with 0600 permissions from the first byte."""
        full = self.path(name)
        fd = os.open(full, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, _FILE_MODE)
        os.close(fd)
        os.chmod(full, _FILE_MODE)
        return full

    def publish(self, src: str, dest: str) -> None:
        """Atomically move a finished artifact into its final location.

        ``rename`` only succeeds atomically within one filesystem, which is why the
        staging directory is created inside the backup directory's parent.
        """
        os.chmod(src, _FILE_MODE)
        os.replace(src, dest)

    # -- teardown ----------------------------------------------------------
    def cleanup(self) -> None:
        if not self.path_dir:
            return
        directory, self.path_dir = self.path_dir, None
        if self._registered_atexit:
            try:
                atexit.unregister(self.cleanup)
            except Exception:  # pragma: no cover
                pass
            self._registered_atexit = False
        for signum, previous in self._prev_handlers.items():
            try:
                signal.signal(signum, previous if callable(previous) else signal.SIG_DFL)
            except (ValueError, OSError):  # pragma: no cover
                pass
        self._prev_handlers.clear()
        self._signal_handlers.clear()
        _destroy_tree(directory)


def _destroy_tree(path: str) -> None:
    """Remove a directory and its contents, overwriting nothing but unlinking everything."""
    if not path or not os.path.isdir(path):
        return
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            try:
                os.unlink(os.path.join(root, name))
            except OSError:
                pass
        for name in dirs:
            try:
                os.rmdir(os.path.join(root, name))
            except OSError:
                pass
    try:
        os.rmdir(path)
    except OSError:
        shutil.rmtree(path, ignore_errors=True)


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError as exc:
        return exc.errno == errno.EPERM
    return True


def sweep_stale_staging(parent: str, max_age: float = 6 * 3600) -> list:
    """Remove staging directories left by a process that died without cleanup.

    A staging directory is only removed when the process that created it is gone *and*
    it is older than ``max_age``. The age check protects a long-running backup on a
    shared filesystem where PID namespaces may collide.
    """
    removed = []
    if not os.path.isdir(parent):
        return removed
    now = time.time()
    for name in os.listdir(parent):
        if not name.startswith(STAGING_PREFIX):
            continue
        full = os.path.join(parent, name)
        if not os.path.isdir(full):
            continue
        try:
            pid = int(name[len(STAGING_PREFIX):].split("-", 1)[0])
        except (ValueError, IndexError):
            pid = -1
        try:
            age = now - os.stat(full).st_mtime
        except OSError:
            continue
        if _pid_alive(pid) or age < max_age:
            continue
        _destroy_tree(full)
        removed.append(name)
    return removed


class BackupLock:
    """Exclusive advisory lock shared by backup, prune and restore.

    ``flock`` is released by the kernel when the file descriptor closes — including on
    ``SIGKILL`` — so a crashed process can never wedge the backup system.
    """

    def __init__(self, directory: str, name: str = LOCK_NAME) -> None:
        self.path = os.path.join(directory, name)
        self._fd: Optional[int] = None

    def __enter__(self) -> "BackupLock":
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        try:
            import fcntl
        except ImportError:  # pragma: no cover - POSIX only project
            return self
        self._fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self._fd)
            self._fd = None
            raise LockUnavailable(
                f"another backup, prune or restore is already running (lock: {os.path.basename(self.path)})"
            )
        os.write(self._fd, f"{os.getpid()}\n".encode())
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self._fd is not None:
            try:
                import fcntl

                fcntl.flock(self._fd, fcntl.LOCK_UN)
            except Exception:  # pragma: no cover
                pass
            try:
                os.close(self._fd)
            except OSError:  # pragma: no cover
                pass
            self._fd = None
        return False


def backup_lock(directory: Optional[str] = None) -> BackupLock:
    """Lock the backup directory (or the configured one when ``directory`` is None)."""
    if directory is None:
        directory = os.getenv("BACKUP_DIR", "backups")
    return BackupLock(directory)
