import os
import shutil
import sqlite3

# Vercel serverless орчинд writable зам нь зөвхөн /tmp байна
#
# Phase 27 (B108): the path used to be the literal "/tmp/leads.db" - a fixed, predictable
# name in a directory shared by everything on the host. `os.path.exists()` follows symlinks,
# so a link planted at that path made the existence check succeed and skipped the copy,
# while `sqlite3.connect()` then opened *through* the link and wrote the schema and rows
# into whatever it pointed at. Reproduced: a symlink to another application's valid SQLite
# file caused this process to create a `pages` table inside that database.
#
# Now: a private per-process directory created with `mkdtemp` (mode 0700, unpredictable
# name), and the database opened with `O_NOFOLLOW` so a link is refused rather than
# followed even if one appears inside it.
if os.getenv("VERCEL"):
    import atexit
    import tempfile

    #: Phase 28: every runtime directory this module creates, so cleanup can be restricted
    #: to exactly those and can never be pointed at anything else.
    _RUNTIME_DIRS = []
    _RUNTIME_PREFIX = "gerege-runtime-"

    def _make_runtime_dir():
        """Create a private runtime directory and register it for cleanup."""
        path = tempfile.mkdtemp(prefix=_RUNTIME_PREFIX)
        _RUNTIME_DIRS.append(path)
        return path

    def _cleanup_runtime_dirs():
        """Remove the runtime directories this process created. Never raises.

        Scope, deliberately narrow: a directory is removed only if its name still starts
        with the prefix AND its parent is the temp root. That combination cannot match a
        path outside the temp directory, so a corrupted or tampered registry entry cannot
        turn cleanup into an arbitrary delete. A symlinked entry is unlinked, never
        descended into, so cleanup cannot be redirected at the file it points to.

        What this must NOT do: `orig_db` (the checked-in leads.db) is the application's
        source data and is never in this list - only the copies live here.
        """
        temp_root = os.path.realpath(tempfile.gettempdir())
        for path in reversed(_RUNTIME_DIRS):
            try:
                # Guard on where the *entry* lives, not on where it points. Realpath-ing the
                # entry first would resolve a symlink and then judge the target, which both
                # makes the islink branch unreachable and lets the decision depend on a
                # location the entry's creator chose.
                entry = os.path.abspath(path)
                if os.path.realpath(os.path.dirname(entry)) != temp_root:
                    continue
                if not os.path.basename(entry).startswith(_RUNTIME_PREFIX):
                    continue
                if os.path.islink(entry):
                    # Unlink the link itself. Descending through it would delete the
                    # target's contents, turning temp cleanup into a cross-directory delete.
                    os.unlink(entry)
                elif os.path.isdir(entry):
                    # rmtree does not follow symlinks for entries inside the tree, so a link
                    # planted in the directory is removed rather than traversed.
                    shutil.rmtree(entry, ignore_errors=True)
            except Exception:
                # Cleanup failure must never convert a request into a 500, and never mask
                # the original exception on the way out.
                pass
        _RUNTIME_DIRS.clear()

    # Registered here rather than after the database is ready: an exception between the
    # two points would otherwise leak the directory it had just created.
    #
    # Honest limitation: a serverless platform may tear the process down without running
    # atexit handlers at all (SIGKILL, container reclaim), so this reduces accumulation on
    # a warm instance and on an ordinary exit. It cannot guarantee prompt cleanup, and it
    # is why the directory name stays unpredictable rather than becoming a fixed path that
    # would have to be trusted.
    atexit.register(_cleanup_runtime_dirs)

    orig_db = os.path.join(os.path.dirname(os.path.dirname(__file__)), "leads.db")
    # mkdtemp is atomic and 0700: no window in which another user could create the entry.
    _runtime_dir = _make_runtime_dir()
    tmp_db = os.path.join(_runtime_dir, "leads.db")
    if os.path.exists(orig_db):
        try:
            shutil.copy(orig_db, tmp_db)
        except Exception:
            pass
    # Refuse to follow a symlink at the database path. `O_NOFOLLOW` fails with ELOOP on a
    # link instead of resolving it. The descriptor is closed immediately; sqlite3 reopens
    # the path, and because the directory is 0700 and owned by this process, nothing else
    # can have created an entry there in between.
    try:
        _fd = os.open(tmp_db, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(_fd)
    except OSError:
        # A symlink here means the runtime directory was tampered with. Fall back to a
        # brand-new name rather than opening the link.
        tmp_db = os.path.join(_make_runtime_dir(), "leads.db")
        _fd = os.open(tmp_db, os.O_RDWR | os.O_CREAT, 0o600)
        os.close(_fd)
    # Narrow the file mode too. Inside a 0700 directory it is already unreachable by
    # another user, but a mode set explicitly survives the directory being loosened later.
    try:
        os.chmod(tmp_db, 0o600)
    except OSError:
        pass
    import database
    database.DB_PATH = tmp_db
    database.init_db()

from main import app
