"""Phase 57 — E57: a failure that is swallowed must still leave a trace.

Phases 54-56 established that *what the caller is told* has to match *what was
actually written*. This phase is the mirror image: places where the code did the
right thing about control flow but said nothing at all, so the defect was
invisible to the operator, to the log, and to the caller.

Eight findings, each measured before the fix:

``F-57-1`` ``dashboard.html handleManagerSend``
    The reply of ``POST /api/sessions/{id}/send`` was discarded and the input box
    was cleared *before* the request. Measured live: that endpoint answers ``404
    Сесс олдсонгүй! (Session not found in this tenant)`` for an unknown session,
    ``403`` when the tenant cannot be resolved and ``400`` for an empty message.
    All three looked identical to a delivered reply, and the manager's text was
    already gone.

``F-57-2`` ``dashboard.html handleSaveClientCredentials``
    ``parseInt(limit)`` is ``NaN`` for a non-numeric field, ``JSON.stringify``
    turns ``NaN`` into ``null``, and ``POST /api/pages/gemini_key`` answers ``200``
    with ``changed: []`` / ``preserved: ["gemini_api_key","monthly_token_limit"]``
    while the stored limit keeps its old value (``100000`` in the probe). This
    function threw that reply away and then told the operator the whole
    "хандалтын тохиргоо" had been saved — a billing guard reported as set when
    nothing changed.

``F-57-3`` ``dashboard.html handleLogout``
    ``window.location.reload()`` ran whatever the server said, so a refused
    logout was indistinguishable from a successful one while the session cookie
    may still have been valid.

``F-57-4`` ``main.get_knowledge``
    A page whose stored ``knowledge_json`` is not valid JSON was served the
    deployment's **default** knowledge base with ``200`` and no log line. Measured
    live: ``GET /api/knowledge?page_id=p57_probe`` with a corrupt row returned the
    default company knowledge and produced ``0`` WARNING/ERROR lines mentioning
    knowledge, while the corrupt row stayed in the database.

``F-57-5`` ``core.ai_router.ToolExecutionGuard.check_and_record``
    The audit row for an executed AI tool call was swallowed; the call still
    returned ``(True, "OK")`` with nothing recording the loss.

``F-57-6`` ``core.db_bounds._apply_session_bounds``
    The commit that makes ``SET idle_in_transaction_session_timeout`` survive the
    first rollback was swallowed. Measured on PostgreSQL: with the commit the
    bound is ``1min`` after a rollback; without it the value is ``0`` — no bound
    at all — which is this module's own documented failure class (F-55-1).

``F-57-7`` ``core.db_engine.get_db_connection``
    Three PRAGMAs shared one ``except Exception: pass``, so the first failure
    silently discarded the other two. ``PRAGMA foreign_keys=ON`` is load-bearing:
    it is what makes Phase 55/56's "the driver refuses a write naming a page that
    does not exist" true. Measured on a read-only database file (where WAL cannot
    be enabled): ``foreign_keys -> 0``, ``busy_timeout -> 15000`` (the connect()
    default), and — with enforcement off — an FK-violating ``INSERT`` naming
    ``p57_never_created`` **succeeded**. After the fix the same file yields
    ``foreign_keys=1`` and ``busy_timeout=5000``, with the WAL failure logged.

``F-57-8`` ``core.task_queue.get_queue_stats``
    The counts came back as the zeros they were initialised to, so ``/api/health``
    reported a healthy empty queue when the query had failed, and the caller's own
    fallback never fired.

Two classes of candidate were examined and left alone deliberately; the tests
below pin *why*, so a later phase cannot mistake them for oversights:

* ``main.auth_login`` writes ``sessions.page_id`` from ``client_page["page_id"]``
  — a stored ``pages`` row, not a request value. Phase 56's class does not apply.
* ``core.db_privileges._fetch_safe`` and ``core.schema_manager.ensure_schema``
  swallow failures by design (a probe that must never raise; an advisory unlock
  that is released when the session ends either way).
"""

from __future__ import annotations

import ast
import io
import logging
import os
import re
import sqlite3

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD = os.path.join(REPO_ROOT, "dashboard.html")

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _read(rel: str) -> str:
    return io.open(os.path.join(REPO_ROOT, rel), encoding="utf-8").read()


def _lines(rel: str) -> list:
    return _read(rel).split("\n")


def _fn_span(rel: str, name: str) -> tuple:
    """(first_line, last_line) of a JS ``function name(...)`` body, brace-walked."""
    lines = _lines(rel)
    pattern = re.compile(r"^\s*(async\s+)?function\s+" + re.escape(name) + r"\s*\(")
    for i, line in enumerate(lines):
        if pattern.match(line):
            depth, started = 0, False
            for j in range(i, min(i + 260, len(lines))):
                for ch in lines[j]:
                    if ch == "{":
                        depth += 1
                        started = True
                    elif ch == "}":
                        depth -= 1
                if started and depth <= 0:
                    return (i + 1, j + 1)
            return (i + 1, min(i + 260, len(lines)))
    raise AssertionError("function %s not found in %s" % (name, rel))


def _fn_body(rel: str, name: str) -> str:
    a, b = _fn_span(rel, name)
    return "\n".join(_lines(rel)[a - 1:b])


def _py_fn(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError("python function %s not found" % name)


def _cleanup_only_pass_handlers(tree) -> set:
    """ids of ``except ...: pass`` handlers that live inside a ``finally`` list."""
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for fin in node.finalbody:            # a list, not a node
                for h in ast.walk(fin):
                    if isinstance(h, ast.ExceptHandler) and all(
                        isinstance(s, ast.Pass) for s in h.body
                    ):
                        out.add(id(h))
    return out


def _route_handlers(tree) -> set:
    out = set()
    verbs = {"get", "post", "put", "delete", "patch", "api_route", "websocket"}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            if (getattr(target, "attr", None) or getattr(target, "id", None)) in verbs:
                out.add(id(node))
    return out


WRITE_CALL = re.compile(
    r"\.(execute|executemany|commit)\(|database\.(create_|save_|update_|insert_|log_|record_|delete_|upsert_)"
)


def _owner(tree, lineno):
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= lineno <= (node.end_lineno or node.lineno):
                best = node
    return best


def _try_of(tree, handler):
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and handler in node.handlers:
            return node
    return None


# ===========================================================================
# F-57-7 — a PRAGMA that cannot be applied must not discard the other two
# ===========================================================================


class _PragmaConn:
    """A connection whose WAL pragma fails, like a read-only database file."""

    def __init__(self, fail_on="journal_mode=WAL"):
        self.fail_on = fail_on
        self.executed = []
        self.closed = False
        self.row_factory = None

    def execute(self, sql, *args, **kwargs):
        if self.fail_on and self.fail_on in sql:
            raise sqlite3.OperationalError("attempt to write a readonly database")
        self.executed.append(sql)
        return self

    def close(self):
        self.closed = True


class TestF577PragmaIsolation:
    def test_each_pragma_runs_even_when_an_earlier_one_fails(self, monkeypatch):
        from core import db_engine

        monkeypatch.setattr(db_engine, "is_postgres", lambda: False)
        conn = _PragmaConn()
        monkeypatch.setattr(db_engine.sqlite3, "connect", lambda *a, **k: conn)

        out = db_engine.get_db_connection("/tmp/p57_does_not_matter.db")

        assert out is conn
        assert "PRAGMA busy_timeout=5000" in conn.executed, (
            "the busy_timeout pragma was discarded because an earlier pragma failed"
        )
        assert "PRAGMA foreign_keys=ON" in conn.executed, (
            "foreign-key enforcement was discarded because an earlier pragma failed"
        )

    def test_the_failed_pragma_is_logged_with_the_path(self, monkeypatch, caplog):
        from core import db_engine

        monkeypatch.setattr(db_engine, "is_postgres", lambda: False)
        conn = _PragmaConn()
        monkeypatch.setattr(db_engine.sqlite3, "connect", lambda *a, **k: conn)

        with caplog.at_level(logging.WARNING, logger="core.db_engine"):
            db_engine.get_db_connection("/tmp/p57_logged_path.db")

        text = caplog.text
        assert "journal_mode=WAL" in text
        assert "p57_logged_path" in text, "the warning must name the database it failed on"
        assert "readonly" in text, "the warning must carry the driver's reason"

    def test_a_successful_pragma_is_not_reported_as_a_failure(self, monkeypatch, caplog):
        from core import db_engine

        monkeypatch.setattr(db_engine, "is_postgres", lambda: False)
        conn = _PragmaConn(fail_on=None)          # nothing fails
        monkeypatch.setattr(db_engine.sqlite3, "connect", lambda *a, **k: conn)

        with caplog.at_level(logging.WARNING, logger="core.db_engine"):
            db_engine.get_db_connection("/tmp/p57_quiet.db")

        assert caplog.text.strip() == "", "a healthy connection must not be noisy"
        assert conn.executed == [
            "PRAGMA journal_mode=WAL",
            "PRAGMA busy_timeout=5000",
            "PRAGMA foreign_keys=ON",
        ]

    def test_a_read_only_database_file_still_enforces_foreign_keys(self, tmp_path, monkeypatch, caplog):
        """The live measurement, repeated as a test.

        A database file the process cannot write to cannot be switched to WAL. Before
        the fix that single failure also switched *off* foreign-key enforcement and
        left ``busy_timeout`` at the ``connect()`` default.
        """
        from core import db_engine

        monkeypatch.setattr(db_engine, "is_postgres", lambda: False)
        db = tmp_path / "p57_ro.db"
        seed = sqlite3.connect(str(db))
        seed.execute("CREATE TABLE pages (page_id TEXT PRIMARY KEY)")
        seed.execute(
            "CREATE TABLE invoices (id INTEGER PRIMARY KEY, "
            "page_id TEXT REFERENCES pages(page_id))"
        )
        seed.commit()
        seed.close()
        os.chmod(str(db), 0o444)

        with caplog.at_level(logging.WARNING, logger="core.db_engine"):
            conn = db_engine.get_db_connection("file:%s?mode=ro" % db)
        try:
            fk = conn.execute("PRAGMA foreign_keys").fetchone()[0]
            busy = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        finally:
            conn.close()
            os.chmod(str(db), 0o644)

        assert fk == 1, "foreign-key enforcement was silently switched off"
        assert busy == 5000, "busy_timeout kept the connect() default instead of 5000"
        # root would not see the WAL failure at all; the guarantee above holds either way.
        if os.geteuid() != 0:
            assert "journal_mode=WAL" in caplog.text

    def test_foreign_key_enforcement_is_what_refuses_a_missing_page(self, tmp_path):
        """Why the pragma matters: with enforcement off the write goes through."""
        db = str(tmp_path / "p57_fk.db")
        seed = sqlite3.connect(db)
        seed.execute("CREATE TABLE pages (page_id TEXT PRIMARY KEY)")
        seed.execute(
            "CREATE TABLE invoices (id INTEGER PRIMARY KEY, "
            "page_id TEXT REFERENCES pages(page_id))"
        )
        seed.commit()

        seed.execute("PRAGMA foreign_keys=OFF")
        seed.execute("INSERT INTO invoices (page_id) VALUES ('p57_never_created')")
        seed.commit()
        off_rows = seed.execute("SELECT COUNT(*) FROM invoices").fetchone()[0]
        seed.execute("DELETE FROM invoices")
        seed.commit()

        seed.execute("PRAGMA foreign_keys=ON")
        with pytest.raises(sqlite3.IntegrityError):
            seed.execute("INSERT INTO invoices (page_id) VALUES ('p57_never_created')")
        seed.close()

        assert off_rows == 1, (
            "with enforcement off a row naming a page that does not exist is accepted"
        )

    def test_the_source_applies_each_pragma_in_its_own_try(self):
        """Shape pin: one attempt per pragma, each in its own try, each failure logged."""
        tree = ast.parse(_read("core/db_engine.py"))
        fn = _py_fn(tree, "get_db_connection")
        pragmas = {"journal_mode=WAL", "busy_timeout=5000", "foreign_keys=ON"}

        loops = [
            n for n in ast.walk(fn)
            if isinstance(n, ast.For)
            and isinstance(n.iter, ast.Tuple)
            and {e.value for e in n.iter.elts if isinstance(e, ast.Constant)} == pragmas
        ]
        assert len(loops) == 1, "the three pragmas must be attempted in one loop over all three"

        loop = loops[0]
        tries = [n for n in ast.walk(loop) if isinstance(n, ast.Try)]
        assert len(tries) == 1, "the loop body must hold exactly one try"
        attempt = tries[0]
        assert len(attempt.body) == 1, "one statement per attempt: that is the whole point"
        assert isinstance(attempt.body[0], ast.Expr)
        assert "PRAGMA" in ast.unparse(attempt.body[0])

        assert len(attempt.handlers) == 1
        handler = attempt.handlers[0]
        assert not all(isinstance(s, ast.Pass) for s in handler.body), (
            "the pragma failure is still swallowed"
        )
        logged = "\n".join(ast.unparse(s) for s in handler.body)
        assert "logger.warning" in logged
        assert not attempt.finalbody

        # and nothing in the function may still swallow a pragma failure
        for node in ast.walk(fn):
            if isinstance(node, ast.ExceptHandler):
                assert not all(isinstance(s, ast.Pass) for s in node.body), (
                    "a pragma failure is still swallowed at line %d"
                    % getattr(node, "lineno", -1)
                )


# ===========================================================================
# F-57-6 — the commit that makes the session bounds survive a rollback
# ===========================================================================


class _BoundsCursor:
    def __init__(self):
        self.executed = []
        self.closed = False

    def execute(self, sql, params=None):
        self.executed.append(sql)
        return self

    def close(self):
        self.closed = True


class _BoundsConn:
    """Not a sqlite3.Connection, so `_is_sqlite_connection` says False."""

    def __init__(self, commit_raises=False):
        self.cursor_obj = _BoundsCursor()
        self.commit_raises = commit_raises
        self.committed = False
        self.rolled_back = False

    def cursor(self):
        return self.cursor_obj

    def commit(self):
        if self.commit_raises:
            raise RuntimeError("server closed the connection unexpectedly")
        self.committed = True

    def rollback(self):
        self.rolled_back = True


class TestF576SessionBoundsCommit:
    def _postgres_branch(self, monkeypatch):
        """Force the PostgreSQL branch.

        `_is_sqlite_connection` identifies a connection positively (isinstance, then the
        type name) and only then falls back to the process environment - and the tests run
        without `DATABASE_URL`, so that fallback says "sqlite" and the function returns
        early. This phase is about the commit on the PostgreSQL branch, so the detection is
        pinned here rather than by the environment (Phase 55 F-55-9 owns the detection).
        """
        from core import db_bounds

        monkeypatch.setattr(db_bounds, "_is_sqlite_connection", lambda conn: False)
        return db_bounds

    def test_a_failed_commit_is_logged_and_does_not_propagate(self, monkeypatch, caplog):
        db_bounds = self._postgres_branch(monkeypatch)

        conn = _BoundsConn(commit_raises=True)
        with caplog.at_level(logging.WARNING, logger="core.db_bounds"):
            db_bounds._apply_session_bounds(conn, statement_timeout=10.0, lock_timeout=5.0)

        assert "commit failed" in caplog.text
        assert "rollback" in caplog.text, (
            "the warning must state the consequence: the bounds will not survive a rollback"
        )

    def test_a_successful_commit_is_silent(self, monkeypatch, caplog):
        db_bounds = self._postgres_branch(monkeypatch)

        conn = _BoundsConn()
        with caplog.at_level(logging.WARNING, logger="core.db_bounds"):
            db_bounds._apply_session_bounds(conn, statement_timeout=10.0, lock_timeout=5.0)

        assert conn.committed is True
        assert caplog.text.strip() == ""

    def test_the_bounds_are_set_before_the_commit(self, monkeypatch):
        db_bounds = self._postgres_branch(monkeypatch)

        conn = _BoundsConn()
        db_bounds._apply_session_bounds(conn, statement_timeout=10.0, lock_timeout=5.0)

        joined = "\n".join(conn.cursor_obj.executed)
        assert "idle_in_transaction_session_timeout" in joined
        assert "statement_timeout" in joined
        assert conn.committed is True, "without the commit the SETs are rolled back with the first transaction"

    def test_sqlite_connections_are_still_a_no_op(self):
        from core import db_bounds

        conn = sqlite3.connect(":memory:")
        db_bounds._apply_session_bounds(conn, statement_timeout=10.0, lock_timeout=5.0)
        conn.close()

    def test_the_module_has_its_own_logger(self):
        src = _read("core/db_bounds.py")
        assert 'logging.getLogger("core.db_bounds")' in src
        assert re.search(r"^import logging$", src, re.M)


# ===========================================================================
# F-57-8 — queue stats must not report zeros as if they were counts
# ===========================================================================


class _QueueCursor:
    def __init__(self, rows=(), raises=False):
        self.rows = rows
        self.raises = raises
        self.executed = []
        self.closed = False

    def execute(self, sql, *args):
        if self.raises:
            raise RuntimeError("no such table: task_jobs")
        self.executed.append(sql)
        return self

    def fetchall(self):
        return self.rows

    def close(self):
        self.closed = True


class _QueueConn:
    def __init__(self, cursor):
        self.cursor_obj = cursor
        self.closed = False

    def cursor(self):
        return self.cursor_obj

    def close(self):
        self.closed = True


class TestF578QueueStatsTruth:
    def _queue(self, monkeypatch, cursor):
        from core import task_queue as tq

        conn = _QueueConn(cursor)
        monkeypatch.setattr(tq.database, "get_connection", lambda *a, **k: conn)
        q = tq.TaskQueue(worker_id="p57-worker")
        monkeypatch.setattr(q, "_get_redis", lambda: None)
        return q, conn

    def test_a_failed_count_query_logs_and_still_returns_the_shape(self, monkeypatch, caplog):
        from core import task_queue as tq

        cursor = _QueueCursor(raises=True)
        q, conn = self._queue(monkeypatch, cursor)

        with caplog.at_level(logging.WARNING, logger="core.task_queue"):
            stats = q.get_queue_stats()

        assert "task_jobs" in caplog.text, "the failed read must be logged"
        assert stats["pending"] == 0 and stats["failed"] == 0
        assert set(stats) >= {
            "backend", "redis_connected", "worker_id",
            "pending", "processing", "completed", "dead_letter", "failed",
        }, "the /api/health contract changed shape"
        assert stats["backend"] == "db"
        assert cursor.closed is True and conn.closed is True

    def test_counts_are_still_reported_when_the_query_works(self, monkeypatch, caplog):
        cursor = _QueueCursor(rows=[("PENDING", 3), ("COMPLETED", 11), ("DEAD_LETTER", 1)])
        q, _ = self._queue(monkeypatch, cursor)

        with caplog.at_level(logging.WARNING, logger="core.task_queue"):
            stats = q.get_queue_stats()

        assert stats["pending"] == 3
        assert stats["completed"] == 11
        assert stats["dead_letter"] == 1
        assert caplog.text.strip() == ""

    def test_the_handler_logs_instead_of_passing(self):
        tree = ast.parse(_read("core/task_queue.py"))
        # `core/task_queue.py` also exposes a module-level `get_queue_stats()` wrapper that
        # just forwards to the singleton; the fix lives in the method.
        candidates = [
            n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name == "get_queue_stats"
        ]
        assert len(candidates) == 2, [c.lineno for c in candidates]
        fn = next(
            c for c in candidates
            if c.args.args and c.args.args[0].arg == "self"
        )
        src = ast.unparse(fn)
        assert "logger.warning" in src
        silent = [
            h for h in ast.walk(fn)
            if isinstance(h, ast.ExceptHandler) and all(isinstance(s, ast.Pass) for s in h.body)
        ]
        # the only remaining `pass` is the cursor/connection close in `finally`
        cleanup = _cleanup_only_pass_handlers(tree)
        assert all(id(h) in cleanup for h in silent), (
            "get_queue_stats still swallows a failure silently"
        )


# ===========================================================================
# F-57-5 — a lost audit row must leave a trace
# ===========================================================================


class TestF575AuditLossIsLogged:
    def test_the_call_still_succeeds_but_the_loss_is_logged(self, monkeypatch, caplog):
        from core import ai_router
        import database

        def boom(**kwargs):
            raise RuntimeError("database is locked")

        monkeypatch.setattr(database, "record_audit_log", boom)
        guard = ai_router.ToolExecutionGuard(page_id="p57_probe", sender_id="p57_sender")

        with caplog.at_level(logging.WARNING, logger="core.ai_router"):
            allowed, message = guard.check_and_record("get_weather", {"city": "UB"})

        assert (allowed, message) == (True, "OK"), (
            "a customer message must not fail because an audit row could not be written"
        )
        assert "ai.tool.executed.get_weather" in caplog.text
        assert "p57_probe" in caplog.text, "the warning must name the tenant"
        assert "call #1" in caplog.text, "the warning must name which call was lost"

    def test_the_call_is_still_counted_when_audit_fails(self, monkeypatch, caplog):
        from core import ai_router
        import database

        monkeypatch.setattr(
            database, "record_audit_log",
            lambda **kwargs: (_ for _ in ()).throw(RuntimeError("locked")),
        )
        guard = ai_router.ToolExecutionGuard(page_id="p57_probe", sender_id="p57_sender")
        with caplog.at_level(logging.WARNING, logger="core.ai_router"):
            guard.check_and_record("get_weather")
            guard.check_and_record("get_weather")

        assert guard.total_calls == 2
        assert guard.call_counts["get_weather"] == 2

    def test_a_successful_audit_write_is_silent(self, monkeypatch, caplog):
        from core import ai_router
        import database

        written = []
        monkeypatch.setattr(database, "record_audit_log", lambda **kw: written.append(kw))
        guard = ai_router.ToolExecutionGuard(page_id="p57_probe", sender_id="p57_sender")

        with caplog.at_level(logging.WARNING, logger="core.ai_router"):
            allowed, _ = guard.check_and_record("create_payment_invoice", {"amount": 1200})

        assert allowed is True
        assert caplog.text.strip() == ""
        assert len(written) == 1
        assert written[0]["action"] == "ai.tool.executed.create_payment_invoice"

    def test_the_blocked_paths_still_write_their_audit_row(self, monkeypatch):
        """F-57-5 must not weaken the fail-closed paths."""
        from core import ai_router
        import database

        written = []
        monkeypatch.setattr(database, "record_audit_log", lambda **kw: written.append(kw))
        guard = ai_router.ToolExecutionGuard(page_id="p57_probe", sender_id="p57_sender")
        guard.total_calls = ai_router.MAX_TOOL_CALLS_PER_TURN

        allowed, message = guard.check_and_record("get_weather")

        assert allowed is False
        assert str(ai_router.MAX_TOOL_CALLS_PER_TURN) in message
        assert written and written[0]["action"] == "ai.tool.blocked.get_weather"

    def test_the_duplicate_invoice_block_is_untouched(self, monkeypatch):
        from core import ai_router
        import database

        written = []
        monkeypatch.setattr(database, "record_audit_log", lambda **kw: written.append(kw))
        guard = ai_router.ToolExecutionGuard(page_id="p57_probe", sender_id="p57_sender")

        first, _ = guard.check_and_record("create_payment_invoice", {"amount": 1200})
        second, message = guard.check_and_record("create_payment_invoice", {"amount": 1200})

        assert first is True and second is False
        assert "1 удаа" in message
        assert [w["action"] for w in written] == [
            "ai.tool.executed.create_payment_invoice",
            "ai.tool.blocked.create_payment_invoice",
        ]


# ===========================================================================
# F-57-4 — a substituted knowledge base must be recorded
# ===========================================================================


class TestF574KnowledgeFallbackIsLogged:
    def _call(self, monkeypatch, stored, caplog):
        import asyncio
        import main
        import knowledge_base

        async def fake_scope(request, **kwargs):
            return "p57_probe"

        monkeypatch.setattr(main.core_security, "enforce_tenant_scope", fake_scope)
        monkeypatch.setattr(
            main.database, "get_page",
            lambda page_id: {"page_id": page_id, "knowledge_json": stored},
        )
        monkeypatch.setattr(
            knowledge_base, "load_knowledge",
            lambda: {"company": {"name": "DEFAULT DEPLOYMENT KB"}},
        )
        with caplog.at_level(logging.WARNING, logger="ai_agent_app"):
            response = asyncio.run(main.get_knowledge(None, page_id="p57_probe"))
        import json
        return json.loads(response.body.decode("utf-8")), caplog.text

    def test_a_corrupt_page_value_serves_the_default_and_says_so(self, monkeypatch, caplog):
        body, text = self._call(
            monkeypatch, '{"bank_accounts": {"khaan": "P57 corrupt",,', caplog)

        assert body == {"company": {"name": "DEFAULT DEPLOYMENT KB"}}
        assert "p57_probe" in text, "the warning must name the page whose knowledge was unusable"
        assert "JSONDecodeError" in text, "the warning must carry the parse failure"
        assert "default knowledge base" in text

    def test_a_valid_page_value_is_returned_without_a_warning(self, monkeypatch, caplog):
        body, text = self._call(
            monkeypatch, '{"bank_accounts":{"khaan":"P57 valid"}}', caplog)

        assert body == {"bank_accounts": {"khaan": "P57 valid"}}
        assert text.strip() == "", "a healthy page must not be noisy"

    def test_an_empty_page_value_is_not_a_warning(self, monkeypatch, caplog):
        """A page that never had knowledge is normal, not a fault."""
        import asyncio
        import json
        import main
        import knowledge_base

        async def fake_scope(request, **kwargs):
            return "p57_probe"

        monkeypatch.setattr(main.core_security, "enforce_tenant_scope", fake_scope)
        monkeypatch.setattr(main.database, "get_page", lambda page_id: {"page_id": page_id})
        monkeypatch.setattr(knowledge_base, "load_knowledge", lambda: {"company": {"name": "D"}})

        with caplog.at_level(logging.WARNING, logger="ai_agent_app"):
            response = asyncio.run(main.get_knowledge(None, page_id="p57_probe"))

        assert json.loads(response.body.decode("utf-8")) == {"company": {"name": "D"}}
        assert caplog.text.strip() == ""

    def test_the_response_shape_is_unchanged_for_consumers(self, monkeypatch, caplog):
        """The fix must not wrap the payload: consumers read arbitrary KB keys."""
        body, _ = self._call(monkeypatch, '{"a": 1', caplog)
        assert set(body) == {"company"}, (
            "no status/error wrapper may be added to /api/knowledge"
        )

    def test_the_stored_value_is_left_untouched(self, monkeypatch, caplog):
        import asyncio
        import main

        touched = []

        async def fake_scope(request, **kwargs):
            return "p57_probe"

        monkeypatch.setattr(main.core_security, "enforce_tenant_scope", fake_scope)
        monkeypatch.setattr(
            main.database, "get_page",
            lambda page_id: {"page_id": page_id, "knowledge_json": "{oops"},
        )
        monkeypatch.setattr(main.knowledge_base, "load_knowledge", lambda: {"company": {}})
        for name in ("save_page", "save_knowledge", "update_page"):
            if hasattr(main.database, name) or hasattr(main.knowledge_base, name):
                target = main.database if hasattr(main.database, name) else main.knowledge_base
                monkeypatch.setattr(
                    target, name,
                    lambda *a, _n=name, **k: touched.append(_n),
                )

        with caplog.at_level(logging.WARNING, logger="ai_agent_app"):
            asyncio.run(main.get_knowledge(None, page_id="p57_probe"))

        assert touched == [], "the corrupt stored value must not be rewritten or repaired"

    def test_the_source_logs_the_page_id(self):
        tree = ast.parse(_read("main.py"))
        fn = _py_fn(tree, "get_knowledge")
        src = ast.unparse(fn)
        assert "logger.warning" in src
        assert "target_id" in src
        assert not re.search(r"except Exception:\s*\n\s*pass", src)


# ===========================================================================
# F-57-1/2/3 — the dashboard must read the reply it asked for
# ===========================================================================


FETCH_ASSIGNED = re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*await fetch\(")


class TestF571ManagerSendReadsTheReply:
    def test_the_reply_is_assigned_and_checked(self):
        body = _fn_body("dashboard.html", "handleManagerSend")
        assert FETCH_ASSIGNED.search(body), "the send reply is still discarded"
        assert ".ok" in body
        assert "showToast" in body

    def test_the_input_is_cleared_only_after_the_reply_is_checked(self):
        lines = _lines("dashboard.html")
        a, b = _fn_span("dashboard.html", "handleManagerSend")
        body = lines[a - 1:b]

        check = next(i for i, x in enumerate(body) if "sendRes.ok" in x or ".ok" in x)
        clears = [i for i, x in enumerate(body) if re.search(r"txtInput\.value\s*=\s*''", x)]
        assert clears, "the input is never cleared"
        assert all(c > check for c in clears), (
            "the manager's text is cleared before the server has answered"
        )

    def test_the_text_is_restored_when_the_send_is_refused(self):
        body = _fn_body("dashboard.html", "handleManagerSend")
        assert "txtInput.value = msg;" in body, (
            "a refused send must give the operator their text back"
        )
        # the restore must live in the failure branch, not after it
        idx_guard = body.index("if (!sendRes.ok")
        idx_restore = body.index("txtInput.value = msg;")
        assert idx_guard < idx_restore < body.index("return;", idx_guard)

    def test_the_server_reason_reaches_the_operator(self):
        body = _fn_body("dashboard.html", "handleManagerSend")
        for key in ("sendData.detail", "sendData.error"):
            assert key in body, "the server's own wording must be shown: %s" % key

    def test_a_json_reply_that_is_not_json_cannot_break_the_handler(self):
        body = _fn_body("dashboard.html", "handleManagerSend")
        assert ".catch(() => ({}))" in body

    def test_the_endpoint_it_still_answers_404_403_400(self):
        """The client fix is only worth anything if the server really refuses."""
        tree = ast.parse(_read("main.py"))
        fn = _py_fn(tree, "manager_send_message")
        src = ast.unparse(fn)
        assert "404" in src and "403" in src and "400" in src
        assert "session_belongs_to_page" in src
        assert "allow_admin_all=False" in src, (
            "this endpoint must not fall back to an admin-wide tenant"
        )


class TestF572TokenLimitClientGuard:
    def test_the_limit_is_parsed_with_a_radix_and_validated(self):
        body = _fn_body("dashboard.html", "handleSaveClientCredentials")
        assert "parseInt(limit, 10)" in body, "parseInt without a radix, and NaN reaches the server"
        assert "Number.isFinite(parsedLimit)" in body
        assert "parsedLimit <= 0" in body

    def test_the_endpoint_reply_is_read(self):
        body = _fn_body("dashboard.html", "handleSaveClientCredentials")
        assigned = FETCH_ASSIGNED.findall(body)
        assert "limitRes" in assigned, "the gemini_key reply is still discarded"
        assert "limitRes.ok" in body

    TOAST = "Харилцагчийн хандалтын тохиргоо амжилттай хадгалагдлаа"

    def test_the_success_toast_comes_after_every_guard(self):
        body = _fn_body("dashboard.html", "handleSaveClientCredentials")
        idx_toast = body.index(self.TOAST)
        for needle in ("credRes.ok", "Number.isFinite(parsedLimit)", "limitRes.ok"):
            assert needle in body, "the guard %r is missing" % needle
            assert body.index(needle) < idx_toast, (
                "the toast still claims success before %s was checked" % needle
            )

    def test_ignored_fields_is_honoured(self):
        """P54's contract: a malformed limit is reported in `ignored_fields`, not in an error."""
        body = _fn_body("dashboard.html", "handleSaveClientCredentials")
        assert "ignored_fields" in body
        assert "'monthly_token_limit'" in body

    def test_a_refused_limit_does_not_claim_the_settings_were_saved(self):
        body = _fn_body("dashboard.html", "handleSaveClientCredentials")
        # every failure branch returns before the toast
        idx_toast = body.index(self.TOAST)
        # only the alerts that *precede* the toast can fall through to it
        failure_branches = [m.start() for m in re.finditer(r"alert\(", body) if m.start() < idx_toast]
        assert len(failure_branches) >= 3, (
            "expected the empty-username, bad-limit and refused-limit alerts, found %d"
            % len(failure_branches)
        )
        for at in failure_branches:
            tail = body[at:idx_toast]
            assert "return;" in tail, "an alert without a return still falls through to the success toast"
        # the catch-block alert sits after the toast and cannot reach it
        assert body.rindex("alert(") > idx_toast

    def test_the_server_side_contract_is_unchanged(self, monkeypatch):
        """P54: 200 with `preserved`/`ignored_fields`, never a silent overwrite.

        The live probe measured exactly this reply for `{"monthly_token_limit": null}`:
        ``{"status":"success","success":true,"written":true,"page_id":"p57_probe",
        "changed":[],"preserved":["gemini_api_key","monthly_token_limit"], ...}`` with the
        stored limit still 100000. The client-side guard added by F-57-2 reads
        `ignored_fields`, so the keys it reads are pinned here too.
        """
        import asyncio
        import json
        import main

        async def fake_scope(request, **kwargs):
            return "p57_probe"

        stored = {"page_id": "p57_probe", "gemini_api_key": "", "monthly_token_limit": 100000}
        monkeypatch.setattr(main.core_security, "enforce_tenant_scope", fake_scope)
        monkeypatch.setattr(main.database, "get_page", lambda page_id: dict(stored))

        monkeypatch.setattr(main.database, "record_audit_log", lambda *a, **k: True)

        def call(written):
            monkeypatch.setattr(main.database, "update_page_gemini_key",
                                lambda *a, **k: written)
            reply = asyncio.run(
                main.update_page_gemini_key_endpoint(
                    {"page_id": "p57_probe", "monthly_token_limit": None}, None))
            return reply if isinstance(reply, dict) else json.loads(reply.body.decode("utf-8"))

        # the write happened: a null limit preserved the stored quota and said so
        ok = call(True)
        assert ok.get("success") is True and ok.get("written") is True
        for key in ("changed", "preserved", "cleared", "ignored_fields", "mask_echoes"):
            assert key in ok, "the client reads %r; the reply no longer carries it" % key
        assert "monthly_token_limit" in ok["preserved"], (
            "P54: a null limit must preserve the stored value"
        )
        assert "monthly_token_limit" in ok["ignored_fields"], (
            "P54: a null limit must be reported as ignored - this is the key F-57-2's client "
            "guard reads, so the toast can no longer claim a limit that was never stored"
        )
        assert ok["changed"] == []

        # the write did not happen (page gone): success/written say so, which is what the
        # client's `limitData.success === false` branch keys on
        refused = call(False)
        assert refused.get("success") is False
        assert refused.get("written") is False
        assert refused.get("page_id") == "p57_probe"
        assert "олдсонгүй" in (refused.get("message") or "")


class TestF573LogoutReportsFailure:
    def test_the_reply_is_read_before_the_reload(self):
        body = _fn_body("dashboard.html", "handleLogout")
        assert FETCH_ASSIGNED.search(body), "the logout reply is still discarded"
        assert body.index(".ok") < body.index("window.location.reload()")

    def test_a_refused_logout_warns_that_the_session_may_be_alive(self):
        body = _fn_body("dashboard.html", "handleLogout")
        assert "data.success === false" in body
        assert "Гарах хүсэлт бүтэлгүйтлээ" in body

    def test_the_reload_still_happens(self):
        """The reload is what reveals the true state; it must not be removed."""
        body = _fn_body("dashboard.html", "handleLogout")
        assert body.rstrip().endswith("}")
        assert body.count("window.location.reload()") == 1
        assert body.index("window.location.reload()") > body.index("alert(")

    def test_the_server_still_reports_success_explicitly(self):
        """`handleLogout` now reads `data.success`; the server must keep sending it."""
        tree = ast.parse(_read("main.py"))
        fn = _py_fn(tree, "auth_logout")
        src = ast.unparse(fn)
        assert "'success'" in src or '"success"' in src


# ===========================================================================
# regression: the sweeps that found these eight must stay at their new level
# ===========================================================================


class TestSweepsStayClosed:
    def test_no_dashboard_fetch_reply_is_discarded(self):
        """Sweep E. BEFORE: 3. AFTER: 0."""
        src = _read("dashboard.html")
        discarded = []
        for i, line in enumerate(src.split("\n"), 1):
            if "await fetch(" not in line:
                continue
            stripped = line.lstrip()
            if not FETCH_ASSIGNED.match(stripped):
                discarded.append(i)
        assert discarded == [], (
            "these dashboard fetches discard the reply: %s" % discarded
        )

    def test_the_three_fixed_handlers_read_their_replies(self):
        for name in ("handleManagerSend", "handleLogout", "handleSaveClientCredentials"):
            body = _fn_body("dashboard.html", name)
            assert FETCH_ASSIGNED.search(body), "%s discards its reply again" % name
            assert ".ok" in body, "%s never checks res.ok" % name

    def test_no_route_handler_swallows_a_failure_outside_cleanup(self):
        """Sweep F, restricted to HTTP handlers. BEFORE: 3. AFTER: 2, both cleanup-only."""
        offenders = []
        for rel in ("main.py",):
            tree = ast.parse(_read(rel))
            cleanup = _cleanup_only_pass_handlers(tree)
            routes = _route_handlers(tree)
            for node in ast.walk(tree):
                if not isinstance(node, ast.ExceptHandler):
                    continue
                if not all(isinstance(s, ast.Pass) for s in node.body):
                    continue
                owner = _owner(tree, node.lineno)
                if owner is None or id(owner) not in routes:
                    continue
                if id(node) in cleanup:
                    continue
                offenders.append("%s:%d %s()" % (rel, node.lineno, owner.name))
        assert offenders == [], (
            "route handlers still swallow failures silently: %s" % offenders
        )

    def test_the_remaining_silent_write_swallows_are_the_two_documented_ones(self):
        """Sweep F, restricted to handlers that swallow a database write.

        BEFORE: 6. AFTER: 2 — and both are intentional, pinned here by name so a
        later phase cannot mistake them for an oversight.
        """
        expected = {
            ("core/db_privileges.py", "_fetch_safe"),
            ("core/schema_manager.py", "ensure_schema"),
        }
        found = set()
        for dp, dirs, files in os.walk(REPO_ROOT):
            dirs[:] = [d for d in dirs if d not in
                       {".git", ".scratch", ".venv", "__pycache__", "backups",
                        "node_modules", "scratch", "migrations", "tests"}
                       and not d.startswith(".")]
            for f in sorted(files):
                if not f.endswith(".py"):
                    continue
                path = os.path.join(dp, f)
                rel = os.path.relpath(path, REPO_ROOT)
                try:
                    tree = ast.parse(_read(rel))
                except SyntaxError:
                    continue
                for node in ast.walk(tree):
                    if not isinstance(node, ast.ExceptHandler):
                        continue
                    if not all(isinstance(s, ast.Pass) for s in node.body):
                        continue
                    attempt = _try_of(tree, node)
                    if attempt is None:
                        continue
                    body = "\n".join(ast.unparse(s) for s in attempt.body)
                    if not WRITE_CALL.search(body):
                        continue
                    owner = _owner(tree, node.lineno)
                    if owner is None:
                        continue
                    found.add((rel, owner.name))
        assert found == expected, (
            "the set of silently-swallowed database writes changed: %s" % sorted(found)
        )

    def test_auth_login_writes_a_stored_page_id_not_a_request_value(self):
        """Sweep D's single hit, pinned as the false positive it is."""
        tree = ast.parse(_read("main.py"))
        fn = _py_fn(tree, "auth_login")
        src = ast.unparse(fn)
        create = [
            n for n in ast.walk(fn)
            if isinstance(n, ast.Call)
            and getattr(n.func, "attr", "") == "create_session"
        ]
        # two login paths: the operator (page_id=None) and the client page
        assert len(create) == 2, [c.lineno for c in create]

        by_line = {c.lineno: c for c in create}
        operator = by_line[min(by_line)]
        client = by_line[max(by_line)]

        op_kw = next((k for k in operator.keywords if k.arg == "page_id"), None)
        assert op_kw is not None and isinstance(op_kw.value, ast.Constant)
        assert op_kw.value.value is None, "the operator session must not name a tenant page"

        kw = next((k for k in client.keywords if k.arg == "page_id"), None)
        assert kw is not None, "create_session is called without a page_id keyword"
        local = kw.value
        assert isinstance(local, ast.Name), ast.unparse(local)

        assignment = None
        for node in ast.walk(fn):
            if (isinstance(node, ast.Assign)
                    and any(isinstance(tg, ast.Name) and tg.id == local.id for tg in node.targets)):
                assignment = node
        assert assignment is not None, "the page id local is never assigned from a stored row"
        value_src = ast.unparse(assignment.value)
        assert "client_page" in value_src, (
            "auth_login must take the page id from the stored client row, not from the request: %s"
            % value_src
        )
        assert "payload" not in value_src and "request" not in value_src

    def test_the_error_classes_tuple_is_untouched(self):
        """Phase 50's security pin must survive this phase value for value.

        `tests/test_e50_ai_readiness_truth.py` pins the literal source text; this copy
        compares the parsed values so a reformat cannot hide a removed class.
        """
        tree = ast.parse(_read("core/ai_readiness.py"))
        found = None
        for node in tree.body:
            if (isinstance(node, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == "ERROR_CLASSES" for t in node.targets)):
                found = node.value
        assert found is not None and isinstance(found, ast.Tuple)
        assert [e.value for e in found.elts] == [
            "auth", "quota", "model", "network", "bad_request", "server", "other",
        ]

    def test_the_dashboard_still_parses(self):
        """`node --check` is run by the phase harness; this is the cheap in-suite twin."""
        src = _read("dashboard.html")
        blocks = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", src, re.S | re.I)
        blocks = [b for b in blocks if b.strip()]
        assert len(blocks) == 2
        for block in blocks:
            assert block.count("{") == block.count("}"), "unbalanced braces in an inline script"
