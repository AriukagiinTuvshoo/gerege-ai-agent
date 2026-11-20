"""Bounded database operations for backup and maintenance work.

Phase 22 (P21-10). Phase 21 found that a single lock on one table made a backup hang
indefinitely:

    $ maintenance.py backup --label lockrepro        # another session holds ACCESS EXCLUSIVE
    ...no output for 398s, killed by the harness, exit 124

The cause was not the dump. ``_create_backup_dump`` ran ``_collect_db_table_counts()``
first - seventeen ``SELECT COUNT(*)`` statements on the plain application connection with
``statement_timeout = 0`` - and the first one blocked forever on the lock. The dump's own
``subprocess.run(timeout=120)`` was never reached, so the configured bound did not apply,
nothing was logged, and no alert fired.

Three separate lessons, each encoded here:

1. **A timeout must apply to every statement, not to one call site.** Setting
   ``statement_timeout`` per operation is unenforceable by review: the next query someone
   adds is unbounded again. Every connection opened for maintenance work goes through
   this module, where the timeouts are set once, on the session.
2. **A blocked query must fail, not look like zero rows.** The old code caught every
   exception and recorded ``counts[tbl] = 0``, so a lock-blocked backup reported a healthy
   "rows: pages=0" line. For a *measurement* that is merely wrong; for a *precondition* it
   is dangerous. :func:`run_scalar` never absorbs an error into a plausible-looking value.
3. **A deadline is not a sum of timeouts.** Seventeen statements with a 10 s statement
   timeout each is 170 s of hang. :class:`Deadline` makes the *operation* bounded, and each
   statement's effective budget is whatever remains.

What is deliberately not here: a retry loop. A backup that cannot get a lock at the first
attempt is a fact the operator needs to see (another backup is running, or a migration is
holding the table), not something to paper over by retrying for longer than the deadline.
"""

from __future__ import annotations

import contextlib
import os
import time
from dataclasses import dataclass
from typing import Any, Iterable, Optional


class BoundedOperationTimeout(RuntimeError):
    """A database operation exceeded its deadline or was cancelled by a server timeout.

    The message is operator-facing and must say *what* timed out; a backup that fails with
    "canceling statement due to statement timeout" and nothing else sends the reader to the
    PostgreSQL logs to find out which step died.
    """


class BoundedOperationCancelled(RuntimeError):
    """The caller's cancellation event fired (SIGTERM, shutdown, test fail-fast)."""


def _env_float(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, "").strip() or default)
    except ValueError:
        return default
    return value if value > 0 else default


#: Server-side bounds, in seconds, applied to every maintenance session.
STATEMENT_TIMEOUT_S = _env_float("BACKUP_DB_STATEMENT_TIMEOUT", 30.0)
LOCK_TIMEOUT_S = _env_float("BACKUP_DB_LOCK_TIMEOUT", 5.0)
#: Client-side connect bound. libpq also honours this via ``connect_timeout`` in the DSN.
CONNECT_TIMEOUT_S = _env_float("BACKUP_DB_CONNECT_TIMEOUT", 10.0)
#: Whole-operation deadline. Defaults above Phase 21's observed 398 s hang by a wide margin
#: while staying inside a typical systemd ``TimeoutStartSec``.
OPERATION_DEADLINE_S = _env_float("BACKUP_DB_OPERATION_DEADLINE", 120.0)


@dataclass
class Deadline:
    """A wall-clock budget for a group of operations.

    ``remaining()`` is what each statement should be allowed; a statement started with
    little budget left gets a short ``statement_timeout`` rather than the session default,
    so the *operation* is bounded even if it issues many statements.
    """

    total_s: float
    label: str = "operation"
    _start: float = 0.0

    def __post_init__(self) -> None:
        self._start = time.monotonic()

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start

    def remaining(self) -> float:
        return max(0.0, self.total_s - self.elapsed)

    def expired(self) -> bool:
        return self.remaining() <= 0.0

    def check(self) -> None:
        if self.expired():
            raise BoundedOperationTimeout(
                f"{self.label} exceeded its {self.total_s:.0f}s deadline after "
                f"{self.elapsed:.1f}s"
            )

    def budget(self, cap: float) -> float:
        """The statement budget: the smaller of `cap` and what is left."""
        left = self.remaining()
        if left <= 0:
            self.check()
        return min(cap, left)


def _ms(seconds: float) -> int:
    """PostgreSQL timeouts are milliseconds; never round a positive budget down to 0."""
    return max(1, int(round(seconds * 1000)))


#: SQLSTATEs that mean "your bound fired", not "the server is broken".
#: 55P03 lock_not_available, 57014 query_canceled, 08006/08003 connection gone.
_TIMEOUT_SQLSTATES = {
    "55P03": "a lock could not be acquired within lock_timeout",
    "57014": "the statement exceeded statement_timeout",
    "08006": "the connection was lost",
    "08003": "the connection was closed",
}


def translate_driver_error(exc: BaseException, label: str) -> BaseException:
    """Map a driver timeout into a bounded-operation error with an operator message.

    A raw ``psycopg2.errors.LockNotAvailable`` traceback tells an operator nothing about
    which step of the backup died or how long it waited, and a traceback in the CLI output
    is itself an information leak (paths, SQL text with the table layout). The original
    exception stays chained so a debugger keeps the detail.
    """
    sqlstate = getattr(exc, "pgcode", None) or getattr(exc, "sqlstate", None)
    described = _TIMEOUT_SQLSTATES.get(str(sqlstate or ""), None)
    if described is None:
        return exc
    return BoundedOperationTimeout(
        f"{label}: {described}. This is a configured bound, not a server failure - "
        f"statement_timeout={STATEMENT_TIMEOUT_S:g}s, lock_timeout={LOCK_TIMEOUT_S:g}s. "
        f"Another session is probably holding a lock; the operation was abandoned."
    )


@contextlib.contextmanager
def bounded_session(
    *,
    label: str,
    deadline: Optional[Deadline] = None,
    statement_timeout: Optional[float] = None,
    lock_timeout: Optional[float] = None,
    cancel_event: Any = None,
):
    """Open a connection whose every statement is bounded, and close it on all exits.

    Yields ``(conn, deadline)``. The connection has ``statement_timeout``,
    ``lock_timeout`` and ``idle_in_transaction_session_timeout`` set, so a lock waits for
    ``lock_timeout`` and then raises instead of hanging, and a transaction abandoned by an
    exception cannot sit idle holding locks - the Phase 21 audit observed
    ``idle_in_transaction_session_timeout = 0`` on the application path.

    Raises :class:`BoundedOperationCancelled` if ``cancel_event`` is set, before and after
    the work, so a SIGTERM does not have to wait for the server timeout to take effect.
    """
    from database import get_connection

    if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
        raise BoundedOperationCancelled(f"{label} cancelled before it started")

    deadline = deadline or Deadline(OPERATION_DEADLINE_S, label=label)
    stmt = statement_timeout if statement_timeout is not None else STATEMENT_TIMEOUT_S
    lock = lock_timeout if lock_timeout is not None else LOCK_TIMEOUT_S

    conn = None
    try:
        try:
            conn = get_connection()
        except Exception as exc:
            # An unreachable database must read as a bound failure too: the connect
            # timeout is what protects the operator from a silent multi-minute hang.
            raise translate_driver_error(exc, f"{label}: could not connect") from exc
        _apply_session_bounds(conn, statement_timeout=deadline.budget(stmt), lock_timeout=lock)
        try:
            yield conn, deadline
        except Exception as exc:
            translated = translate_driver_error(exc, label)
            if translated is exc:
                raise
            raise translated from exc
        if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
            raise BoundedOperationCancelled(f"{label} cancelled")
        deadline.check()
    finally:
        # Roll back before closing: a connection returned to a pool mid-transaction is the
        # "lock held by a failed transaction" failure Phase 21 found on the app path. The
        # pool recycle guard is a second line of defence, not a substitute.
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass


def _apply_session_bounds(conn, *, statement_timeout: float, lock_timeout: float) -> None:
    """SET the session timeouts. Failure here is fatal: an unbounded session is the bug."""
    budget_ms = _ms(statement_timeout)
    lock_ms = _ms(lock_timeout)
    cur = conn.cursor()
    try:
        cur.execute(f"SET statement_timeout = {budget_ms}")
        cur.execute(f"SET lock_timeout = {lock_ms}")
        # Not a timeout but the same class of defect: an abandoned transaction must not
        # hold locks until someone notices.
        cur.execute("SET idle_in_transaction_session_timeout = 60000")
    finally:
        try:
            cur.close()
        except Exception:
            pass
    # `SET` is transactional and autocommit is off on these connections; commit so the
    # bounds survive the first rollback.
    try:
        conn.commit()
    except Exception:
        pass


def run_scalar(
    sql: str,
    params: Iterable[Any] = (),
    *,
    label: str,
    deadline: Optional[Deadline] = None,
    cancel_event: Any = None,
) -> Any:
    """Run one scalar query under the session bounds, and never invent a value.

    Unlike the Phase 21 preflight, a failure raises. The caller decides whether a missing
    count is fatal (for a backup precondition it is) or merely reduces what it can report.
    """
    with bounded_session(label=label, deadline=deadline, cancel_event=cancel_event) as (conn, dl):
        cur = conn.cursor()
        try:
            cur.execute(sql, tuple(params))
            row = cur.fetchone()
            return None if row is None else row[0]
        finally:
            try:
                cur.close()
            except Exception:
                pass
            dl.check()


def measure_statement_budget() -> dict:
    """Operator/status view of the configured bounds. No secrets, no DSN."""
    return {
        "statement_timeout_s": STATEMENT_TIMEOUT_S,
        "lock_timeout_s": LOCK_TIMEOUT_S,
        "connect_timeout_s": CONNECT_TIMEOUT_S,
        "operation_deadline_s": OPERATION_DEADLINE_S,
    }


def bound_sqlalchemy_connection(conn, *, statement_timeout: Optional[float] = None,
                                lock_timeout: Optional[float] = None) -> None:
    """Apply the session bounds to a SQLAlchemy ``Connection``.

    The restore verifiers build their own ``create_engine`` rather than going through
    :func:`bounded_session`, because they connect to the *restored* database by URL rather
    than to the application's. That is a good reason for a different connection, not for an
    unbounded one: the same lock that hangs a preflight hangs a post-restore verification,
    and a verification that hangs is indistinguishable to an operator from a restore that
    hangs.
    """
    from sqlalchemy import text

    stmt_ms = _ms(statement_timeout if statement_timeout is not None else STATEMENT_TIMEOUT_S)
    lock_ms = _ms(lock_timeout if lock_timeout is not None else LOCK_TIMEOUT_S)
    conn.execute(text(f"SET statement_timeout = {stmt_ms}"))
    conn.execute(text(f"SET lock_timeout = {lock_ms}"))
    conn.execute(text("SET idle_in_transaction_session_timeout = 60000"))


def bound_dbapi_connection(conn, *, statement_timeout: Optional[float] = None,
                           lock_timeout: Optional[float] = None) -> None:
    """Apply the session bounds to a raw DB-API connection (psycopg2)."""
    _apply_session_bounds(
        conn,
        statement_timeout=statement_timeout if statement_timeout is not None else STATEMENT_TIMEOUT_S,
        lock_timeout=lock_timeout if lock_timeout is not None else LOCK_TIMEOUT_S,
    )
