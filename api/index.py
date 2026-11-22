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
    import tempfile

    orig_db = os.path.join(os.path.dirname(os.path.dirname(__file__)), "leads.db")
    # mkdtemp is atomic and 0700: no window in which another user could create the entry.
    _runtime_dir = tempfile.mkdtemp(prefix="gerege-runtime-")
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
        tmp_db = os.path.join(tempfile.mkdtemp(prefix="gerege-runtime-"), "leads.db")
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
