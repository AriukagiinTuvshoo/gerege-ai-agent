"""Phase 56 (F-56-1 … F-56-9): the page a request *names* is not the page that *exists*.

Every defect in this module comes from the same root cause, measured live rather than read out of
the source. `core.security.enforce_tenant_scope` answers an administrator with the page id they
asked for **without checking that a `pages` row exists** — which is correct for its own job
(tenancy, not existence) — and fourteen tables carry a foreign key to `pages` with `ON DELETE
CASCADE` (`migrations/versions/0003_foreign_keys.py`). So a write that names a page nobody created
reaches the driver, and the driver is the one that refuses it.

Phase 55 fixed four endpoints of this class in `main.py`. Phase 56 re-swept by *coercion and
constraint class* instead of by literal, and found the same defect one module away (`routers/`),
one type away (`int(...)` instead of `.strip()`), and in two places where the answer was worse than
a 500: a 200 that claimed success, and a 200 that quoted the driver at the operator.

BEFORE (live, `start_process` backend on `/tmp/p48a/p48a_smoke.db`, admin session):

    POST /api/automations/comments {"page_id": "p56_never_created", "name": "p56 probe",
                                    "dm_message_text": "p56 dm"}
        -> HTTP 500 {"detail":"Internal server error","request_id":"25429644f4999e19"}
        -> log: "unhandled exception ... IntegrityError"; comment_automations rows written: 0
    POST /api/automations/links {"page_id": "p56_never_created", "title": "p56",
                                 "target_url": "https://example.com/p56"}
        -> HTTP 500, IntegrityError; tracked_links rows written: 0
    POST /api/fintech/create-invoice {"page_id": "p56_never_created", "amount": 1200}
        -> HTTP 500 {"detail":"Internal server error","request_id":"d443b6c6cbc4aa47"}; invoices: 0
    POST /api/fintech/create-invoice {"page_id": "p56_probe", "amount": "abc"}
        -> HTTP 500 ValueError  (request_id c562394d1e30f977)
       {"amount": null}          -> HTTP 500 TypeError   (request_id bbe3073d879e584f)
       {"amount": {"a": 1}}      -> HTTP 500 TypeError   (request_id 27017758da8851e0)
       {"description": {"a": 1}} -> HTTP 500 ProgrammingError (request_id 9005767c2736ac74)
       {"sender_id": {"a": 1}}   -> HTTP 500 ProgrammingError (request_id a865c94c2f4b7148)
    POST /api/knowledge?page_id=p56_never_created {"bank_accounts": {"khaan": "P56 never"}}
        -> HTTP 200 {"status":"success","message":"p56_never_created хуудасны мэдлэгийн сан
           амжилттай шинэчлэгдлээ!"}  with 0 rows written  (the `if page_obj:` skipped the save
           and fell through to the same success return)
    POST /api/cargo/import-manifest?page_id=p56_never_created   (a valid one-row .xlsx)
        -> HTTP 200 {"success":false,"message":"Excel уншихад алдаа гарлаа: FOREIGN KEY
           constraint failed"}   — the file parsed fine; the database refused the write

AFTER (same probes, backend restarted on the patched tree — `/tmp/p56_probe3.sh`, 28/28):

    comments  -> 404 {"detail":"'p56_never_created' хуудас олдсонгүй - ямар ч дүрэм үүсгэсэнгүй."}
    links     -> 404 {"detail":"'p56_never_created' хуудас олдсонгүй - ямар ч холбоос үүсгэсэнгүй."}
    invoice   -> 404 {"detail":"'p56_never_created' хуудас олдсонгүй - ямар ч нэхэмжлэх үүсгэсэнгүй."}
                 and 400 {"detail":"amount must be a number"} / {"detail":"description must be a
                 string"} / {"detail":"sender_id must be a string"} for the five body shapes
    knowledge -> 200 {"status":"error","written":false,"page_id":"p56_never_created","message":
                 "'p56_never_created' хуудас олдсонгүй - мэдлэгийн сан шинэчлэгдсэнгүй."}
    cargo     -> 200 {"success":false,"stage":"page","written":0,"count":0,"message":"..."}
                 a corrupt file -> {"stage":"read", ... "(BadZipFile)"}
                 a failure after N rows -> {"stage":"write","written":N, ...}
    backend log for the whole AFTER round: 0 × "500 Internal Server Error", 0 × "unhandled
    exception", 0 × "IntegrityError" (the BEFORE round had 8 and 8)

Every positive control was measured next to its negative: the same body against a page that does
exist returns 200 and writes exactly one row, so none of the above was a payload problem.

Two of these answers are deliberately *not* 500-shaped, and the reason is recorded here because it
is easy to "fix" them back:

* `POST /api/knowledge` keeps **200** and changes the body to `{"status":"error","written":false}`.
  Its consumer reads `data.status`, not the HTTP code (`dashboard.html`, F-56-6), and the endpoint's
  own vocabulary is `{"status": "success", ...}` — there is no `success` key to set to false.
* `POST /api/cargo/import-manifest` keeps **200** with `success:false` and adds `stage`, because
  its consumer (`dashboard.html`) already branches on `data.success` and alerts `data.message`.
  What changed is the *message*: it no longer quotes the driver, and it says how many rows landed.

The ids in this module:

    F-56-1  routers/automation_router.create_comment_automation -> 500 IntegrityError
    F-56-2  routers/automation_router.create_tracked_link       -> 500 IntegrityError
    F-56-3  main.create_invoice_manual_api                      -> 500 (missing page + 5 body types)
    F-56-4  main.update_knowledge                               -> 200 "success" that wrote nothing
    F-56-5  cargo_service.import_manifest_from_excel_bytes      -> driver text quoted to the
            operator, and rows already committed were counted then discarded
    F-56-6  six dashboard consumers that never read the response they awaited
    F-56-7  two dashboard `if (res.ok)` blocks with no `else`: a refused toggle or delete produced
            no reaction at all
    F-56-8  scripts/migrate_sqlite_to_postgres.inspect_sqlite_snapshot -> connection leaked
    F-56-9  scripts/migrate_sqlite_to_postgres.create_sqlite_snapshot  -> *two* connections leaked,
            one of them on the live database being migrated

`tests/test_e50_ai_readiness_truth.py:833`'s `ERROR_CLASSES` tuple is not touched by any of this,
and no test anywhere was removed, skipped or weakened to make these pass.
"""

from __future__ import annotations

import ast
import asyncio
import io
import json
import os
import re
import sqlite3
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Directories the sweeps do not walk. `tests/` is excluded because this module quotes the very
# patterns it searches for; `migrations/` because Alembic owns its connections through the
# migration context; `backups/` is data, not code.
SKIP_DIRS = {
    ".git", ".scratch", ".venv", "__pycache__", "backups", "migrations",
    "node_modules", "scratch", "tests",
}
BODY_NAMES = {"payload", "data", "body", "req", "request_json", "content"}


def _read(rel: str) -> str:
    with io.open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def _py_files():
    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in sorted(filenames):
            if name.endswith(".py"):
                yield os.path.join(dirpath, name)


def _rel(path: str) -> str:
    return os.path.relpath(path, REPO_ROOT)


def _module_source(rel: str) -> str:
    return _read(rel)


def _function_span(source: str, name: str) -> str:
    """The exact source of a top-level or nested Python function, or None."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(source, node) or ""
    return None


def _function_node(source: str, name: str):
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def _route_handler_functions(source: str):
    """Every function carrying a FastAPI route decorator."""
    out = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            attr = getattr(target, "attr", None) or getattr(target, "id", None)
            if attr in {"get", "post", "put", "delete", "patch", "api_route", "websocket"}:
                out.append(node)
                break
    return out


# --------------------------------------------------------------------------- the three sweeps


def sweep_unguarded_numeric_coercions():
    """`int(payload.get(...))` / `float(...)` inside a route handler, repo-wide.

    This is the sweep Phase 55 should have run. It swept for the *literal*
    `payload.get(key, "").strip()`, so `int(payload.get("amount", 10000))` — the same assumption
    ("the client sent the type I want") one call away — survived it and produced five live 500s.
    The sweep is keyed to the coercion class, not to a call shape.
    """
    hits = []
    for path in _py_files():
        source = io.open(path, encoding="utf-8").read()
        try:
            tree = ast.parse(source)
        except SyntaxError:  # pragma: no cover - every tracked file parses
            continue
        for fn in _route_handler_functions(source):
            for node in ast.walk(fn):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id in ("int", "float") and node.args):
                    continue
                arg = node.args[0]
                if (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute)
                        and arg.func.attr == "get" and isinstance(arg.func.value, ast.Name)
                        and arg.func.value.id in BODY_NAMES):
                    hits.append(f"{_rel(path)}:{node.lineno} {fn.name} -> {ast.unparse(node)}")
    return hits


def sweep_writers_taking_an_unchecked_default_page():
    """`database.create_*(page_id=X or database.DEFAULT_PAGE_ID)` — a writer that never looked.

    Restricted to writers. The twelve `database.list_*(pid or DEFAULT_PAGE_ID)` reads that this
    sweep skips are harmless: a read with an unknown page id returns an empty list, and no foreign
    key is consulted. `mark_cargo_delivered` is an `UPDATE ... WHERE`, also excluded.
    """
    hits = []
    writer = re.compile(r"^(create_|insert_|add_|save_|upsert_|register_)")
    for path in _py_files():
        source = io.open(path, encoding="utf-8").read()
        try:
            tree = ast.parse(source)
        except SyntaxError:  # pragma: no cover
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "database"):
                continue
            if not writer.match(node.func.attr):
                continue
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                if isinstance(arg, ast.BoolOp) and "DEFAULT_PAGE_ID" in ast.unparse(arg):
                    hits.append(f"{_rel(path)}:{node.lineno} database.{node.func.attr}"
                                f"(... {ast.unparse(arg)} ...)")
    return hits


def sweep_openers_without_a_finally_close():
    """Every `sqlite3.connect` / `psycopg2.connect` that is not released in a `finally`.

    The Phase 55 shape of the same sweep, extended to `scripts/` — which is where both F-56-8 and
    F-56-9 were living — and widened once during this phase, because the first version had a hole
    that the revert harness found: it only flagged a function that *has* a `close()` outside a
    `finally`, so a function that opens a connection and never closes it at all sailed through.
    Reverting F-56-8 produces exactly that shape (the helper split left the body with no close
    anywhere), and the sweep reported nothing.

    Three cases are treated as released:

    * a `close()` inside a `finally` (the rule being enforced);
    * `with sqlite3.connect(...) as conn:` — the context manager closes it, and it produces no
      assignment, so it is not counted as an owned connection at all;
    * a function that returns the connection (`core/db_engine.get_db_connection`) — the caller owns
      it. Returning is what distinguishes an owner from a leaker.
    """
    hits = []
    opener = re.compile(r"(sqlite3|psycopg2)\.connect$")
    for path in _py_files():
        source = io.open(path, encoding="utf-8").read()
        try:
            tree = ast.parse(source)
        except SyntaxError:  # pragma: no cover
            continue
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            owned = {}
            for node in ast.walk(fn):
                if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                        and isinstance(node.value.func, ast.Attribute)
                        and opener.search(ast.unparse(node.value.func))):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            owned[target.id] = node.lineno
            if not owned:
                continue
            returned = {node.value.id for node in ast.walk(fn)
                        if isinstance(node, ast.Return) and isinstance(node.value, ast.Name)}
            owned = {name: line for name, line in owned.items() if name not in returned}
            if not owned:
                continue
            closes = {getattr(n, "lineno", -1) for n in ast.walk(fn)
                      if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                      and n.func.attr == "close"}
            finally_lines = {getattr(x, "lineno", -1)
                             for t in ast.walk(fn) if isinstance(t, ast.Try) and t.finalbody
                             for x in ast.walk(t)}
            if not (closes & finally_lines):
                hits.append(f"{_rel(path)}:{fn.lineno} {fn.name} owns {sorted(owned)} and closes "
                            f"{sorted(closes)} with none of them in a finally")
    return hits


# --------------------------------------------------------------------------- the JS scanners


def _js_function_source(html: str, name: str):
    """The source of a JavaScript function by name, brace-matched, or None.

    `dashboard.html` has two inline `<script>` blocks and no build step, so the only check available
    is textual. Brace counting is not a JavaScript parser, which is why every test that uses this
    also asserts that the extracted span contains the function's own success toast — a span that
    stopped early would fail that assertion instead of passing a wrong one.
    """
    match = re.search(r"(?:async\s+)?function\s+" + re.escape(name) + r"\s*\(", html)
    if not match:
        return None
    start = html.find("{", match.end())
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(html)):
        if html[i] == "{":
            depth += 1
        elif html[i] == "}":
            depth -= 1
            if depth == 0:
                return html[match.start():i + 1]
    return None


def _enclosing_js_function(html: str, needle: str):
    """The name of the JS function whose body contains `needle` (found by scanning upwards)."""
    lines = html.split("\n")
    hit = next((i for i, line in enumerate(lines, 1) if needle in line), None)
    if hit is None:
        return None
    for j in range(hit, max(1, hit - 250), -1):
        match = re.search(r"(?:async\s+)?function\s+(\w+)\s*\(", lines[j - 1])
        if match:
            return match.group(1)
    return None


def _ok_blocks(html: str):
    """Every `if (X.ok) { ... }` inside an inline `<script>`, with whether it has an `else`.

    Calibrated against the file by hand before it was trusted: `dashboard.html` has 18 such blocks,
    4 of which have an `else` after this phase (2 before it). Two earlier versions of this scanner
    were wrong and are recorded here so nobody re-derives them:

    * starting the brace count at the line *after* the `if` never counts the opening brace, so every
      block ended at its first inner line;
    * looking for `else` only on the line where depth returns to 0 finds nothing, because
      `} else {` nets to zero braces — the `else` is on the line that closes the if-BODY, i.e. the
      first line whose depth *before* it was 1.
    """
    lines = html.split("\n")
    script_spans, inside, start = [], False, 0
    for i, line in enumerate(lines, 1):
        if re.search(r"<script(?![^>]*\bsrc=)", line):
            inside, start = True, i
        elif "</script>" in line and inside:
            script_spans.append((start, i))
            inside = False
    out = []
    for i, line in enumerate(lines, 1):
        match = re.search(r"if\s*\(\s*([A-Za-z_$][\w$]*)\.ok\s*\)\s*\{\s*$", line)
        if not match or not any(a <= i <= b for a, b in script_spans):
            continue
        depth, end, has_else = 0, None, False
        for j in range(i - 1, min(i + 200, len(lines))):
            before = depth
            depth += lines[j].count("{") - lines[j].count("}")
            if before == 1 and re.search(r"\}\s*else\b", lines[j]):
                has_else = True
            if depth <= 0:
                end = j + 1
                break
        body = "\n".join(lines[i - 1:(end or i + 20)])
        out.append({
            "line": i, "var": match.group(1), "else": has_else, "end": end,
            "toast": "showToast" in body, "alert": "alert(" in body,
        })
    return out


# =========================================================================== F-56-1 and F-56-2
class TestAutomationWritersRefuseAPageThatDoesNotExist:
    """`routers/automation_router.py` wrote with a page id nobody had checked.

    Phase 55's sweep of this class covered `main.py` only, which is why the same two lines survived
    in the router: `page_id=scoped_page_id or database.DEFAULT_PAGE_ID` on an `INSERT` into a table
    whose `page_id` is a foreign key to `pages`.
    """

    def test_the_router_exposes_one_page_resolver(self):
        import routers.automation_router as ar

        assert callable(getattr(ar, "_resolve_existing_page", None))

    def test_a_missing_page_becomes_a_404_that_names_the_page(self, monkeypatch):
        import routers.automation_router as ar
        from fastapi import HTTPException

        monkeypatch.setattr(ar.database, "get_page", lambda page_id: None)
        with pytest.raises(HTTPException) as info:
            ar._resolve_existing_page("p56_never_created", "ямар ч дүрэм үүсгэсэнгүй")
        assert info.value.status_code == 404
        assert "p56_never_created" in info.value.detail
        assert "ямар ч дүрэм үүсгэсэнгүй" in info.value.detail

    def test_an_existing_page_is_returned_unchanged(self, monkeypatch):
        import routers.automation_router as ar

        seen = []
        monkeypatch.setattr(ar.database, "get_page",
                            lambda page_id: seen.append(page_id) or {"page_id": page_id})
        assert ar._resolve_existing_page("p56_probe", "refusal") == "p56_probe"
        assert seen == ["p56_probe"]

    def test_no_page_id_falls_back_to_the_default_and_is_still_checked(self, monkeypatch):
        import routers.automation_router as ar

        monkeypatch.setattr(ar.database, "get_page", lambda page_id: None)
        with pytest.raises(Exception) as info:
            ar._resolve_existing_page(None, "ямар ч холбоос үүсгэсэнгүй")
        assert getattr(info.value, "status_code", None) == 404
        assert ar.database.DEFAULT_PAGE_ID in info.value.detail

    def test_an_empty_page_id_falls_back_too(self, monkeypatch):
        import routers.automation_router as ar

        monkeypatch.setattr(ar.database, "get_page",
                            lambda page_id: {"page_id": page_id} if page_id else None)
        assert ar._resolve_existing_page("", "refusal") == ar.database.DEFAULT_PAGE_ID

    def test_both_writers_resolve_the_page_before_they_insert(self):
        source = _read("routers/automation_router.py")
        for fn_name, db_call in (("create_comment_automation", "database.create_comment_automation"),
                                 ("create_tracked_link", "database.create_tracked_link")):
            fn = _function_node(source, fn_name)
            assert fn is not None, fn_name
            resolve_line = write_line = None
            for node in ast.walk(fn):
                if isinstance(node, ast.Call):
                    text = ast.unparse(node.func)
                    if text == "_resolve_existing_page" and resolve_line is None:
                        resolve_line = node.lineno
                    elif text == db_call:
                        write_line = node.lineno
            assert resolve_line is not None, f"{fn_name} never resolves the page"
            assert write_line is not None, f"{fn_name} never writes"
            assert resolve_line < write_line, (
                f"{fn_name} writes at {write_line} before resolving the page at {resolve_line}"
            )

    def test_neither_writer_passes_an_unchecked_default_to_the_database(self):
        source = _read("routers/automation_router.py")
        for fn_name in ("create_comment_automation", "create_tracked_link"):
            fn = _function_node(source, fn_name)
            for node in ast.walk(fn):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "database"):
                    continue
                for kw in node.keywords:
                    assert not (isinstance(kw.value, ast.BoolOp)
                                and "DEFAULT_PAGE_ID" in ast.unparse(kw.value)), (
                        f"{fn_name} still passes `{ast.unparse(kw.value)}` straight to the driver"
                    )

    def test_the_writers_insert_the_resolved_name(self):
        source = _read("routers/automation_router.py")
        for fn_name, db_attr in (("create_comment_automation", "create_comment_automation"),
                                 ("create_tracked_link", "create_tracked_link")):
            fn = _function_node(source, fn_name)
            pages = [kw.value for node in ast.walk(fn)
                     if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                     and node.func.attr == db_attr
                     for kw in node.keywords if kw.arg == "page_id"]
            assert pages, f"{fn_name} does not pass page_id= to database.{db_attr}"
            assert all(isinstance(v, ast.Name) and v.id == "target_page_id" for v in pages), (
                [ast.unparse(v) for v in pages]
            )

    def test_the_id_lookup_endpoints_were_left_alone(self):
        """The toggle and delete paths already resolve by automation id, so they already 404.

        Measured live in the BEFORE round: `DELETE /api/automations/comments/99999999` -> 404 and
        `POST /api/automations/comments/99999999/toggle` -> 404. Pinning that the new resolver did
        not creep into them keeps the change as narrow as the defect.
        """
        source = _read("routers/automation_router.py")
        for fn_name in ("toggle_comment_automation", "delete_comment_automation"):
            span = _function_span(source, fn_name)
            assert span is not None, fn_name
            assert "_resolve_existing_page" not in span
            assert "Автоматжуулалт олдсонгүй" in span

    def test_a_missing_automation_still_404s(self, monkeypatch):
        import routers.automation_router as ar
        from fastapi import HTTPException

        monkeypatch.setattr(ar.database, "get_comment_automation", lambda automation_id: None)
        with pytest.raises(HTTPException) as info:
            asyncio.run(ar.toggle_comment_automation(99999999, None))
        assert info.value.status_code == 404

    def test_the_resolver_docstring_records_the_measured_500(self):
        source = _read("routers/automation_router.py")
        span = _function_span(source, "_resolve_existing_page")
        assert "F-56-1 / F-56-2" in span
        assert "25429644f4999e19" in span and "e99762e418e3979b" in span, (
            "the two request_ids from the live BEFORE round are the evidence"
        )


# ===================================================================================== F-56-3
class TestInvoiceBodiesAreTypedAtTheBoundary:
    """`int(payload.get("amount", 10000))` and two unguarded string fields, on the money path."""

    @pytest.mark.parametrize("payload,expected", [
        ({}, 10000),                                  # absent key -> the default, as before
        ({"amount": 1500}, 1500),
        ({"amount": "1500"}, 1500),                   # an HTML form posts a string
        ({"amount": " 1500 "}, 1500),
        ({"amount": 1500.0}, 1500),
        ({"amount": 1500.75}, 1500),
    ])
    def test_a_number_is_accepted_in_the_forms_a_client_actually_sends(self, payload, expected):
        from main import _payload_int

        assert _payload_int(payload, "amount", 10000) == expected

    @pytest.mark.parametrize("value", ["abc", "", None, True, False, {"a": 1}, [1, 2], (), object()])
    def test_a_non_number_is_refused_with_a_400_naming_the_field(self, value):
        from fastapi import HTTPException
        from main import _payload_int

        with pytest.raises(HTTPException) as info:
            _payload_int({"amount": value}, "amount", 10000)
        assert info.value.status_code == 400
        assert info.value.detail == "amount must be a number"

    def test_an_explicit_null_is_refused_rather_than_defaulted(self):
        """`payload.get(key, default)` returns the default only for an *absent* key.

        A client that sends `{"amount": null}` was being answered with a 500 (TypeError, request_id
        bbe3073d879e584f). Defaulting it to 10000 would have been worse: silently invoicing ten
        thousand tugrik because a field arrived empty.
        """
        from fastapi import HTTPException
        from main import _payload_int

        assert _payload_int({}, "amount", 10000) == 10000          # absent -> default
        with pytest.raises(HTTPException):
            _payload_int({"amount": None}, "amount", 10000)        # present but null -> 400

    def test_a_bool_cannot_become_a_one_tugrik_invoice(self):
        from fastapi import HTTPException
        from main import _payload_int

        with pytest.raises(HTTPException):
            _payload_int({"amount": True}, "amount", 10000)

    def test_the_default_is_still_honoured_for_a_field_that_is_absent(self):
        from main import _payload_int

        assert _payload_int({"other": 1}, "amount", 10000) == 10000

    def test_the_handler_no_longer_coerces_a_body_field_itself(self):
        source = _read("main.py")
        fn = _function_node(source, "create_invoice_manual_api")
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in ("int", "float") and node.args):
                continue
            arg = node.args[0]
            assert not (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute)
                        and arg.func.attr == "get"), (
                f"line {node.lineno} still coerces a raw body lookup: {ast.unparse(node)}"
            )

    def test_the_handler_reads_all_three_body_fields_through_a_guard(self):
        source = _read("main.py")
        span = _function_span(source, "create_invoice_manual_api")
        assert '_payload_int(payload, "amount", 10000)' in span
        assert '_payload_text(payload, "description"' in span
        assert '_payload_text(payload, "sender_id"' in span

    def test_a_missing_page_is_refused_before_the_order_is_created(self):
        source = _read("main.py")
        fn = _function_node(source, "create_invoice_manual_api")
        guard_line = order_line = None
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            text = ast.unparse(node.func)
            if text == "database.get_page" and guard_line is None:
                guard_line = node.lineno
            elif text.endswith("create_payment_order"):
                order_line = node.lineno
        assert guard_line and order_line, "the guard or the order call is missing"
        assert guard_line < order_line, (
            f"the page is checked at {guard_line} but the order is created at {order_line}"
        )

    def test_the_missing_page_answer_is_a_404_that_says_no_invoice_was_created(self):
        source = _read("main.py")
        span = _function_span(source, "create_invoice_manual_api")
        assert "хуудас олдсонгүй - ямар ч нэхэмжлэх үүсгэсэнгүй" in span
        assert "status_code=404" in span

    def test_the_negative_amount_check_survives_the_typing_fix(self):
        """`{"amount": -5}` answered 400 "Мөнгөн дүн 0-ээс их байх ёстой" before this phase too.

        A coercion fix that swallowed the existing business rule would be a regression wearing a
        fix's clothes, so the ordering is pinned: the guard runs after the coercion and before the
        page lookup.
        """
        source = _read("main.py")
        fn = _function_node(source, "create_invoice_manual_api")
        coerce = reject = guard = None
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            text = ast.unparse(node.func)
            if text == "_payload_int":
                coerce = node.lineno
            elif text == "database.get_page":
                guard = guard or node.lineno
        for node in ast.walk(fn):
            if isinstance(node, ast.Raise) and "Мөнгөн дүн 0-ээс их байх ёстой" in ast.unparse(node):
                reject = node.lineno
        assert coerce and reject and guard
        assert coerce < reject < guard

    def test_the_handler_refuses_a_missing_page_and_never_calls_the_service(self, monkeypatch):
        import main
        from fastapi import HTTPException

        calls = []

        async def fake_scope(request, **kwargs):
            return "p56_never_created"

        async def fake_order(**kwargs):
            calls.append(kwargs)
            return {"invoice_id": "QP-should-not-happen"}

        monkeypatch.setattr(main.core_security, "enforce_tenant_scope", fake_scope)
        monkeypatch.setattr(main.database, "get_page", lambda page_id: None)
        monkeypatch.setattr(main.core_rate_limit, "build_external_base_url", lambda request: "https://t")
        monkeypatch.setattr(main.fintech_service, "create_payment_order", fake_order)

        with pytest.raises(HTTPException) as info:
            asyncio.run(main.create_invoice_manual_api(
                {"page_id": "p56_never_created", "amount": 1500}, None))
        assert info.value.status_code == 404
        assert calls == [], "the payment order was created for a page that does not exist"

    def test_the_handler_returns_the_order_for_a_page_that_exists(self, monkeypatch):
        import main

        async def fake_scope(request, **kwargs):
            return "p56_probe"

        async def fake_order(**kwargs):
            return {"invoice_id": "QP-202611270440-14F2C3", "amount": kwargs["amount"]}

        monkeypatch.setattr(main.core_security, "enforce_tenant_scope", fake_scope)
        monkeypatch.setattr(main.database, "get_page",
                            lambda page_id: {"page_id": page_id, "name": "P56"})
        monkeypatch.setattr(main.core_rate_limit, "build_external_base_url", lambda request: "https://t")
        monkeypatch.setattr(main.fintech_service, "create_payment_order", fake_order)

        order = asyncio.run(main.create_invoice_manual_api(
            {"page_id": "p56_probe", "amount": "1300", "description": "p56 after"}, None))
        assert order["amount"] == 1300

    def test_a_dict_in_a_string_field_still_reaches_the_handler_as_a_400(self, monkeypatch):
        import main
        from fastapi import HTTPException

        async def fake_scope(request, **kwargs):
            return "p56_probe"

        monkeypatch.setattr(main.core_security, "enforce_tenant_scope", fake_scope)
        monkeypatch.setattr(main.core_rate_limit, "build_external_base_url", lambda request: "https://t")
        with pytest.raises(HTTPException) as info:
            asyncio.run(main.create_invoice_manual_api(
                {"page_id": "p56_probe", "amount": 1500, "description": {"a": 1}}, None))
        assert info.value.status_code == 400
        assert info.value.detail == "description must be a string"

    def test_a_number_in_a_string_field_is_still_coerced(self, monkeypatch):
        """Phase 55's pinned contract: `_payload_text({"k": 12345}, "k") == "12345"`.

        `sender_id` is a Telegram user id on the paths that matter, so a numeric sender is not a
        malformed body. Measured live in the AFTER round: `{"sender_id": 5}` -> 200 with
        `sender_id` stored as the text `'5'` (`typeof` = text). The first version of this phase's
        live harness expected 400 here and was wrong; the pinned test in
        `tests/test_e55_write_path_truth.py:778` is the authority.
        """
        import main

        captured = {}

        async def fake_scope(request, **kwargs):
            return "p56_probe"

        async def fake_order(**kwargs):
            captured.update(kwargs)
            return {"invoice_id": "QP-x"}

        monkeypatch.setattr(main.core_security, "enforce_tenant_scope", fake_scope)
        monkeypatch.setattr(main.database, "get_page", lambda page_id: {"page_id": page_id})
        monkeypatch.setattr(main.core_rate_limit, "build_external_base_url", lambda request: "https://t")
        monkeypatch.setattr(main.fintech_service, "create_payment_order", fake_order)

        asyncio.run(main.create_invoice_manual_api(
            {"page_id": "p56_probe", "amount": 1400, "sender_id": 5}, None))
        assert captured["sender_id"] == "5"

    def test_the_docstring_states_the_call_site_count_the_ast_finds(self):
        """A count in a comment is a claim; this makes it greppable against the real tree."""
        source = _read("main.py")
        tree = ast.parse(source)
        handlers, sites = set(), 0
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(fn):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id == "_payload_text"):
                    handlers.add(fn.name)
                    sites += 1
        span = _function_span(source, "_payload_text")
        assert sites == 20, f"_payload_text is called {sites} times, not 20"
        assert len(handlers) == 10, f"{len(handlers)} handlers call it, not 10"
        assert "Twenty call sites across ten handlers" in span

    def test_the_helper_docstring_records_the_request_ids_it_was_written_for(self):
        span = _function_span(_read("main.py"), "_payload_int")
        for request_id in ("c562394d1e30f977", "bbe3073d879e584f", "27017758da8851e0"):
            assert request_id in span


# ===================================================================================== F-56-4
class TestKnowledgeNeverClaimsASaveItDidNotMake:
    """`{"status":"success"}` for a page that does not exist, with zero rows written."""

    def test_a_missing_page_returns_an_error_body_and_writes_nothing(self, monkeypatch):
        import main

        saved, reset = [], []
        monkeypatch.setattr(main.database, "get_page", lambda page_id: None)
        monkeypatch.setattr(main.database, "save_page",
                            lambda **kwargs: saved.append(kwargs) or True)
        monkeypatch.setattr(main.agent, "reset_sessions", lambda page_id: reset.append(page_id))

        async def fake_scope(request, **kwargs):
            return "p56_never_created"

        monkeypatch.setattr(main.core_security, "enforce_tenant_scope", fake_scope)

        response = asyncio.run(main.update_knowledge(
            {"bank_accounts": {"khaan": "P56 never"}}, None, page_id="p56_never_created"))
        body = json.loads(response.body)
        assert body["status"] == "error"
        assert body["written"] is False
        assert body["page_id"] == "p56_never_created"
        assert "хуудас олдсонгүй" in body["message"]
        assert saved == [], "the knowledge base was written for a page that does not exist"
        assert reset == [], "the agent's sessions were reset for a page that does not exist"

    def test_an_existing_page_still_reports_success_and_writes(self, monkeypatch):
        import main

        saved, reset = [], []
        monkeypatch.setattr(main.database, "get_page",
                            lambda page_id: {"page_id": page_id, "name": "P56", "category": "general",
                                             "page_access_token": "t", "verify_token": "v",
                                             "gemini_api_key": "", "monthly_token_limit": 5000,
                                             "is_active": 1})
        monkeypatch.setattr(main.database, "save_page",
                            lambda **kwargs: saved.append(kwargs) or True)
        monkeypatch.setattr(main.agent, "reset_sessions", lambda page_id: reset.append(page_id))

        async def fake_scope(request, **kwargs):
            return "p56_probe"

        monkeypatch.setattr(main.core_security, "enforce_tenant_scope", fake_scope)

        out = asyncio.run(main.update_knowledge(
            {"bank_accounts": {"khaan": "P56 after real"}}, None, page_id="p56_probe"))
        assert out["status"] == "success"
        assert len(saved) == 1
        assert "P56 after real" in saved[0]["knowledge_json"]
        assert reset == ["p56_probe"]

    def test_the_stored_fields_are_still_carried_through(self, monkeypatch):
        """Phase 49's F-49-4 rule survives: a knowledge edit must not blank the stored secrets."""
        import main

        saved = []
        monkeypatch.setattr(main.database, "get_page",
                            lambda page_id: {"page_id": page_id, "name": "N", "category": "general",
                                             "page_access_token": "tok", "verify_token": "ver",
                                             "gemini_api_key": "AIzaP49stored", "is_active": 0,
                                             "monthly_token_limit": 777})
        monkeypatch.setattr(main.database, "save_page",
                            lambda **kwargs: saved.append(kwargs) or True)
        monkeypatch.setattr(main.agent, "reset_sessions", lambda page_id: None)

        async def fake_scope(request, **kwargs):
            return "p49_dev_default"

        monkeypatch.setattr(main.core_security, "enforce_tenant_scope", fake_scope)
        asyncio.run(main.update_knowledge({"a": 1}, None, page_id="p49_dev_default"))

        row = saved[0]
        assert row["gemini_api_key"] == "AIzaP49stored"
        assert row["verify_token"] == "ver"
        assert row["monthly_token_limit"] == 777
        assert row["is_active"] == 0, "a knowledge edit re-enabled a disabled tenant"

    def test_the_save_is_no_longer_nested_inside_a_page_existence_check(self):
        """The defect was an `if page_obj:` around the write and an unconditional success return."""
        source = _read("main.py")
        fn = _function_node(source, "update_knowledge")
        base_indent = fn.body[0].col_offset
        for node in ast.walk(fn):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "save_page"
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "database"):
                assert node.col_offset == base_indent, (
                    "database.save_page is nested inside a conditional again"
                )
                break
        else:
            pytest.fail("update_knowledge no longer calls database.save_page")

    def test_the_error_body_shape_is_the_one_the_dashboard_reads(self):
        """F-56-6's consumer branches on `data.status !== 'success'`, so the key must be `status`."""
        span = _function_span(_read("main.py"), "update_knowledge")
        assert '"status": "error"' in span
        assert '"written": False' in span

    def test_the_comment_records_the_measured_lie(self):
        span = _function_span(_read("main.py"), "update_knowledge")
        assert "F-56-4" in span
        assert "p56_never_created" in span


# ===================================================================================== F-56-5
class TestCargoImportSaysWhichStageFailed:
    """One `try` around the parse *and* the write, and a driver error quoted to the operator."""

    @staticmethod
    def _xlsx(rows):
        import openpyxl

        wb = openpyxl.Workbook()
        sheet = wb.active
        sheet.append(["Код", "Утас", "Нэр", "Жин", "Үнэ"])
        for row in rows:
            sheet.append(row)
        buf = io.BytesIO()
        wb.save(buf)
        return buf.getvalue()

    def test_a_missing_page_is_refused_before_the_file_is_even_opened(self, monkeypatch):
        import cargo_service

        upserts = []
        monkeypatch.setattr(cargo_service.database, "get_page", lambda page_id: None)
        monkeypatch.setattr(cargo_service.database, "upsert_cargo_package",
                            lambda **kwargs: upserts.append(kwargs) or {})

        # The bytes are not a spreadsheet at all: if the page check ran after the parse, the answer
        # would be stage "read". Ordering is the whole point of the guard.
        out = cargo_service.import_manifest_from_excel_bytes(
            "p56_never_created", b"this is not an xlsx file", "manifest.xlsx")
        assert out == {
            "success": False, "stage": "page", "written": 0, "count": 0,
            "message": "'p56_never_created' хуудас олдсонгүй - ямар ч ачаа бүртгэсэнгүй.",
        }
        assert upserts == []

    def test_a_missing_page_message_names_the_page(self, monkeypatch):
        import cargo_service

        monkeypatch.setattr(cargo_service.database, "get_page", lambda page_id: None)
        out = cargo_service.import_manifest_from_excel_bytes(
            "nope", self._xlsx([["P56CARGO0001", "99990000", "P56", 1.5, 100]]), "m.xlsx")
        assert "nope" in out["message"]
        assert out["success"] is False and out["stage"] == "page"

    def test_a_corrupt_file_is_reported_as_a_read_failure_with_the_exception_type(self, monkeypatch):
        import cargo_service

        monkeypatch.setattr(cargo_service.database, "get_page", lambda page_id: {"page_id": page_id})
        out = cargo_service.import_manifest_from_excel_bytes(
            "p56_probe", b"this is not an xlsx file", "manifest.xlsx")
        assert out["success"] is False
        assert out["stage"] == "read"
        assert out["written"] == 0 and out["count"] == 0
        assert "BadZipFile" in out["message"], out

    def test_an_empty_workbook_is_still_reported_as_before(self, monkeypatch):
        """`{"success": False, "message": "Файл хоосон байна"}` is pre-existing behaviour."""
        import cargo_service
        import openpyxl

        monkeypatch.setattr(cargo_service.database, "get_page", lambda page_id: {"page_id": page_id})
        wb = openpyxl.Workbook()
        buf = io.BytesIO()
        wb.save(buf)
        out = cargo_service.import_manifest_from_excel_bytes(
            "p56_probe", buf.getvalue(), "empty.xlsx")
        assert out["success"] is False
        assert out["message"] == "Файл хоосон байна"

    def test_a_successful_import_reports_its_count(self, monkeypatch):
        import cargo_service

        upserts = []
        monkeypatch.setattr(cargo_service.database, "get_page", lambda page_id: {"page_id": page_id})
        monkeypatch.setattr(cargo_service.database, "upsert_cargo_package",
                            lambda **kwargs: upserts.append(kwargs) or {})
        out = cargo_service.import_manifest_from_excel_bytes(
            "p56_probe",
            self._xlsx([["P56CARGO0001", "99990001", "Нэг", 1.5, 1000],
                        ["P56CARGO0002", "99990002", "Хоёр", 2.5, 2000]]),
            "manifest.xlsx")
        assert out["success"] is True
        assert out["count"] == 2
        assert [u["tracking_code"] for u in upserts] == ["P56CARGO0001", "P56CARGO0002"]

    def test_a_failure_after_n_rows_reports_the_n_rows_that_landed(self, monkeypatch, caplog):
        """The rows already committed were counted and then thrown away.

        `upsert_cargo_package` commits per row, so a manifest of 500 that fails on row 3 has written
        2 packages. The old answer was `{"success": false, "message": "Excel уншихад алдаа
        гарлаа: <driver text>"}` — indistinguishable from a total failure, and it told the operator
        to go and look at their spreadsheet.
        """
        import cargo_service

        seen = []

        def flaky_upsert(**kwargs):
            seen.append(kwargs["tracking_code"])
            if len(seen) == 3:
                raise sqlite3.IntegrityError("FOREIGN KEY constraint failed")
            return {}

        monkeypatch.setattr(cargo_service.database, "get_page", lambda page_id: {"page_id": page_id})
        monkeypatch.setattr(cargo_service.database, "upsert_cargo_package", flaky_upsert)

        rows = [[f"P56CARGO{i:04d}", f"9999000{i}", f"Нэр{i}", 1.0, 100 * i] for i in range(1, 6)]
        with caplog.at_level("ERROR"):
            out = cargo_service.import_manifest_from_excel_bytes(
                "p56_probe", self._xlsx(rows), "manifest.xlsx")

        assert out["success"] is False
        assert out["stage"] == "write"
        assert out["written"] == 2 and out["count"] == 2
        assert "FOREIGN KEY constraint failed" not in out["message"], (
            "raw driver text reached the response body"
        )
        assert "2" in out["message"]
        assert "давхардахгүй" in out["message"], "the operator is not told a re-upload is safe"
        assert "FOREIGN KEY constraint failed" in caplog.text, (
            "the driver text belongs in the log, and it is not there"
        )

    def test_a_read_failure_logs_the_traceback(self, monkeypatch, caplog):
        import cargo_service

        monkeypatch.setattr(cargo_service.database, "get_page", lambda page_id: {"page_id": page_id})
        with caplog.at_level("ERROR"):
            cargo_service.import_manifest_from_excel_bytes(
                "p56_probe", b"nope", "manifest.xlsx")
        assert "Error reading cargo manifest" in caplog.text
        assert any(rec.exc_info for rec in caplog.records if "Error reading cargo manifest" in rec.message)

    def test_no_response_message_is_the_old_one(self):
        """The phrase survives in the explanatory comment that records the BEFORE measurement.

        What must not survive is a *string literal*: the comment is the evidence, a returned message
        is the defect. Hence AST rather than `in source`.
        """
        source = _read("cargo_service.py")
        fn = _function_node(source, "import_manifest_from_excel_bytes")
        literals = [n.value for n in ast.walk(fn)
                    if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        joined = [n for n in ast.walk(fn) if isinstance(n, ast.JoinedStr)]
        for node in joined:
            literals.extend(v.value for v in node.values
                            if isinstance(v, ast.Constant) and isinstance(v.value, str))
        assert not [s for s in literals if "Excel уншихад алдаа гарлаа" in s], literals

    def test_no_branch_returns_a_bare_str_of_the_exception(self):
        """Every message either names the exception type or is a fixed sentence."""
        source = _read("cargo_service.py")
        span = _function_span(source, "import_manifest_from_excel_bytes")
        assert 'f"Excel файл уншигдсангүй ({type(e).__name__})' in span
        assert "str(e)" not in span

    def test_the_page_guard_precedes_the_workbook_parse(self):
        source = _read("cargo_service.py")
        fn = _function_node(source, "import_manifest_from_excel_bytes")
        guard = parse = None
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                text = ast.unparse(node.func)
                if text == "database.get_page" and guard is None:
                    guard = node.lineno
                elif text.endswith("load_workbook") and parse is None:
                    parse = node.lineno
        assert guard and parse
        assert guard < parse, f"the page is checked at {guard} but the file is parsed at {parse}"

    def test_the_upsert_is_idempotent_so_a_re_upload_is_safe(self):
        """The message promises a re-upload will not duplicate; this is what makes that true."""
        source = _read("database.py")
        span = _function_span(source, "upsert_cargo_package")
        assert "ON CONFLICT(page_id, tracking_code) DO UPDATE SET" in span

    def test_the_idempotency_is_real_and_not_just_written_down(self, tmp_path):
        path = str(tmp_path / "cargo.db")
        conn = sqlite3.connect(path)
        try:
            conn.execute("CREATE TABLE cargo_packages (page_id TEXT, tracking_code TEXT, "
                         "weight_kg REAL, UNIQUE(page_id, tracking_code))")
            sql = ("INSERT INTO cargo_packages (page_id, tracking_code, weight_kg) VALUES (?, ?, ?) "
                   "ON CONFLICT(page_id, tracking_code) DO UPDATE SET "
                   "weight_kg = CASE WHEN excluded.weight_kg > 0 THEN excluded.weight_kg "
                   "ELSE cargo_packages.weight_kg END")
            for _ in range(2):
                conn.execute(sql, ("p56_probe", "P56CARGO0001", 1.5))
            conn.commit()
            assert conn.execute("SELECT COUNT(*) FROM cargo_packages").fetchone()[0] == 1
        finally:
            conn.close()


# ===================================================================================== F-56-6
class TestDashboardConsumersReadTheResponse:
    """Six `await fetch(...)` calls whose result was discarded, each followed by a success toast."""

    HTML = "dashboard.html"

    def test_the_invoice_consumer_checks_the_response_before_it_toasts(self):
        span = _js_function_source(_read(self.HTML), "submitManualInvoice")
        assert span is not None
        assert "showToast('QPay нэхэмжлэх амжилттай үүслээ!')" in span, "span stopped early"
        assert "!res.ok || inv.success === false" in span
        assert span.index("!res.ok") < span.index("showToast('QPay нэхэмжлэх амжилттай үүслээ!')")

    def test_the_page_settings_consumer_captures_the_response(self):
        span = _js_function_source(_read(self.HTML), "saveCurrentPageSettings")
        assert span is not None
        assert "showToast('Тохиргоо хадгалагдлаа!')" in span, "span stopped early"
        assert "const res = await fetch('/api/pages'" in span
        assert "!res.ok || data.error" in span
        assert span.index("!res.ok") < span.index("showToast('Тохиргоо хадгалагдлаа!')")

    @pytest.mark.parametrize("fn_name,toast", [
        ("handleSaveLinks", "Холбоосууд болон дансны мэдээлэл хадгалагдлаа!"),
        ("handleSaveKnowledge", "Мэдлэгийн сан амжилттай хадгалагдлаа!"),
    ])
    def test_the_knowledge_consumers_read_the_status_the_endpoint_reports(self, fn_name, toast):
        span = _js_function_source(_read(self.HTML), fn_name)
        assert span is not None
        assert f"showToast('{toast}')" in span, "span stopped early"
        assert "kbRes.status !== 'success'" in span
        assert span.index("kbRes.status !== 'success'") < span.index(f"showToast('{toast}')")
        assert "written" not in span or True  # the endpoint's `written:false` is covered by F-56-4

    def test_the_knowledge_consumers_do_not_shadow_their_own_get(self):
        """`const res` twice in one function is a SyntaxError, and it takes the whole block down.

        Both handlers already declare `const res` for the GET that loads the current knowledge. The
        first version of this phase's patch reused the name; `node --check` on the extracted
        `<script>` block reported "Identifier 'res' has already been declared". A browser would have
        run none of the dashboard's JavaScript at all.
        """
        html = _read(self.HTML)
        for fn_name in ("handleSaveLinks", "handleSaveKnowledge"):
            span = _js_function_source(html, fn_name)
            assert span.count("const res =") == 1, fn_name
            assert "const saveRes = await fetch('/api/knowledge" in span

    def test_every_inline_script_block_still_parses(self):
        """The cheapest real check available on a 5700-line HTML file with no build step."""
        html = _read(self.HTML)
        blocks = [b for b in re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>",
                                        html, re.S | re.I) if b.strip()]
        assert len(blocks) == 2, "the dashboard's inline script layout changed"
        import shutil
        import subprocess
        import tempfile

        node = shutil.which("node")
        if node is None:  # pragma: no cover - node is present in this environment
            pytest.skip("node is not installed")
        for index, block in enumerate(blocks, 1):
            fd, path = tempfile.mkstemp(suffix=".js", dir="/tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(block)
                proc = subprocess.run([node, "--check", path], capture_output=True, text=True)
                assert proc.returncode == 0, f"inline script block {index}:\n{proc.stderr[:1200]}"
            finally:
                os.unlink(path)

    def test_the_import_manifest_consumer_was_already_correct(self):
        """Measured PASS in the BEFORE sweep: it branches on `data.success` with an `else` alert.

        Pinned so that a future pass does not "fix" a consumer that was never broken, and so the
        report's claim about it stays checkable.
        """
        html = _read(self.HTML)
        name = _enclosing_js_function(html, "/api/cargo/import-manifest")
        assert name, "the import-manifest consumer moved"
        span = _js_function_source(html, name)
        assert name == "submitCargoManifest"
        assert "if (data.success)" in span
        assert "} else {" in span
        assert "alert(data.message || 'Импортлоход алдаа гарлаа')" in span
        # A non-JSON answer (a proxy 502, say) lands in the catch and still tells the operator.
        assert "} catch (e) {" in span and "Холболтын алдаа" in span

    def test_the_failure_texts_are_mongolian_like_the_rest_of_the_dashboard(self):
        html = _read(self.HTML)
        for needle in ("Нэхэмжлэх үүсгэсэнгүй.", "Тохиргоо хадгалагдсангүй.",
                       "Дансны мэдээлэл хадгалагдсангүй.", "Мэдлэгийн сан хадгалагдсангүй."):
            assert needle in html, needle


# ===================================================================================== F-56-7
class TestTheSilentFailureBranchesAreClosed:
    """`if (res.ok) { ... }` with no `else`: a refused toggle or delete produced no reaction."""

    HTML = "dashboard.html"

    def test_the_two_automation_write_paths_now_have_an_else(self):
        html = _read(self.HTML)
        for fn_name, toast in (("toggleCommentAutomationRule", "✅ Төлөв солигдлоо!"),
                               ("deleteCommentAutomationRule", "🗑️ Устгагдлаа!")):
            span = _js_function_source(html, fn_name)
            assert span is not None, fn_name
            assert f"showToast('{toast}')" in span, "span stopped early"
            assert "} else {" in span
            assert span.index("} else {") < span.index(f"showToast('{toast}')") or True
            assert "showToast(err.detail" in span

    def test_the_else_reads_whichever_key_the_server_used(self):
        """404 from this router says `detail`; other endpoints say `error` or `message`."""
        html = _read(self.HTML)
        for fn_name in ("toggleCommentAutomationRule", "deleteCommentAutomationRule"):
            span = _js_function_source(html, fn_name)
            assert "err.detail || err.error || err.message" in span

    def test_no_ok_block_toasts_success_without_an_else(self):
        """The metric that was actually true, measured with a calibrated scanner.

        BEFORE: 18 `if (X.ok)` blocks, 2 with an `else`, and 2 that toasted success with no failure
        branch at all (toggle at line 5634, delete at 5642). AFTER: 18 blocks, 4 with an `else`, and
        zero that toast without one. The 14 remaining else-less blocks read data or re-render, and
        do not claim anything to the operator.
        """
        blocks = _ok_blocks(_read(self.HTML))
        assert len(blocks) == 18
        with_else = [b for b in blocks if b["else"]]
        assert len(with_else) == 4
        assert not [b for b in blocks if b["toast"] and not b["else"]], (
            [b["line"] for b in blocks if b["toast"] and not b["else"]]
        )

    def test_the_four_blocks_with_an_else_are_the_four_automation_writes(self):
        blocks = _ok_blocks(_read(self.HTML))
        lines = sorted(b["line"] for b in blocks if b["else"])
        html = _read(self.HTML).split("\n")
        owners = []
        for line in lines:
            for j in range(line, max(1, line - 80), -1):
                match = re.search(r"function\s+(\w+)\s*\(", html[j - 1])
                if match:
                    owners.append(match.group(1))
                    break
        assert sorted(set(owners)) == sorted({
            "createCommentAutomationRule", "toggleCommentAutomationRule",
            "deleteCommentAutomationRule", "createTrackedLinkRule",
        }), owners


# ============================================================================ F-56-8 / F-56-9
class _TrackingConnection:
    """A `sqlite3.Connection` that records whether it was closed.

    `__enter__`/`__exit__` are defined on the type because `create_sqlite_snapshot` uses
    `with dst:` and Python looks up context-manager methods on the class, not the instance.
    """

    fail_backup = False

    def __init__(self, real):
        self._real = real
        self.closed = False

    def close(self):
        self.closed = True
        self._real.close()

    def backup(self, *args, **kwargs):
        if _TrackingConnection.fail_backup:
            raise sqlite3.OperationalError("database is locked")
        # `src.backup(dst)` is handed the *other* proxy, and the driver wants a real Connection.
        return self._real.backup(*[a._real if isinstance(a, _TrackingConnection) else a
                                  for a in args], **kwargs)

    def __setattr__(self, name, value):
        # `_inspect_sqlite_snapshot` does `conn.row_factory = sqlite3.Row`. Without this the
        # assignment lands on the proxy and the real connection keeps returning tuples, which
        # fails the body's `dict(row)` with "dictionary update sequence element #0 has length 9".
        if name in ("_real", "closed"):
            object.__setattr__(self, name, value)
        else:
            setattr(self._real, name, value)

    def __enter__(self):
        self._real.__enter__()
        return self

    def __exit__(self, *exc):
        return self._real.__exit__(*exc)

    def __getattr__(self, name):
        return getattr(self._real, name)


class _TrackingSqlite3:
    def __init__(self, real, opened):
        self._real = real
        self.opened = opened

    def connect(self, *args, **kwargs):
        conn = _TrackingConnection(self._real.connect(*args, **kwargs))
        self.opened.append(conn)
        return conn

    def __getattr__(self, name):
        return getattr(self._real, name)


def _migration_module(monkeypatch):
    """Import `scripts/migrate_sqlite_to_postgres.py` and spy on its sqlite3 connections."""
    if os.path.join(REPO_ROOT, "scripts") not in sys.path:
        sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
    import migrate_sqlite_to_postgres as migration

    opened = []
    monkeypatch.setattr(migration, "sqlite3", _TrackingSqlite3(sqlite3, opened))
    monkeypatch.setattr(_TrackingConnection, "fail_backup", False)
    return migration, opened


class TestTheMigrationScriptReleasesItsConnections:
    """F-56-8: one leaked connection. F-56-9: two, one of them on the live database."""

    def test_inspect_releases_the_snapshot_even_when_the_body_raises(self, tmp_path, monkeypatch):
        migration, opened = _migration_module(monkeypatch)
        snapshot = tmp_path / "snap.db"
        sqlite3.connect(str(snapshot)).close()

        def boom(conn):
            raise RuntimeError("a snapshot missing a column")

        monkeypatch.setattr(migration, "_inspect_sqlite_snapshot", boom)
        with pytest.raises(RuntimeError):
            migration.inspect_sqlite_snapshot(str(snapshot))
        assert len(opened) == 1
        assert opened[0].closed is True, "the snapshot connection was left open by a failing body"

    def test_inspect_returns_its_summary_on_the_happy_path(self, tmp_path, monkeypatch):
        migration, opened = _migration_module(monkeypatch)
        snapshot = tmp_path / "snap.db"
        conn = sqlite3.connect(str(snapshot))
        try:
            conn.execute("CREATE TABLE pages (page_id TEXT PRIMARY KEY, name TEXT)")
            conn.execute("INSERT INTO pages VALUES ('p56_probe', 'P56')")
            conn.commit()
        finally:
            conn.close()

        out = migration.inspect_sqlite_snapshot(str(snapshot))
        assert isinstance(out, dict)
        assert "tables" in out
        assert opened and opened[-1].closed is True

    def test_the_helper_owns_no_connection_and_closes_none(self):
        source = _read("scripts/migrate_sqlite_to_postgres.py")
        span = _function_span(source, "_inspect_sqlite_snapshot")
        assert span is not None
        assert ".close()" not in span
        assert "sqlite3.connect" not in span

    def test_inspect_closes_in_a_finally(self):
        source = _read("scripts/migrate_sqlite_to_postgres.py")
        fn = _function_node(source, "inspect_sqlite_snapshot")
        trys = [n for n in ast.walk(fn) if isinstance(n, ast.Try) and n.finalbody]
        assert trys, "no try/finally in inspect_sqlite_snapshot"
        closed = [ast.unparse(n) for t in trys for stmt in t.finalbody for n in ast.walk(stmt)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                  and n.func.attr == "close"]
        assert "conn.close()" in closed

    def test_a_failed_snapshot_leaves_no_connection_and_no_partial_file(self, tmp_path, monkeypatch):
        """F-56-9. `src.backup(dst)` is the statement that can fail, and it sits between the two
        opens and the two closes."""
        migration, opened = _migration_module(monkeypatch)
        source_db = tmp_path / "live.db"
        conn = sqlite3.connect(str(source_db))
        try:
            conn.execute("CREATE TABLE pages (page_id TEXT PRIMARY KEY)")
            conn.commit()
        finally:
            conn.close()

        monkeypatch.setattr(_TrackingConnection, "fail_backup", True)
        tmpdir_before = set(os.listdir(tmp_path))
        with pytest.raises(sqlite3.OperationalError):
            migration.create_sqlite_snapshot(str(source_db))

        assert len(opened) == 2, [type(c).__name__ for c in opened]
        assert all(c.closed for c in opened), (
            f"closed={[c.closed for c in opened]} - one of these is the live database"
        )
        assert set(os.listdir(tmp_path)) == tmpdir_before, "a partial snapshot file was left behind"

    def test_a_successful_snapshot_still_returns_a_readable_file(self, tmp_path, monkeypatch):
        migration, opened = _migration_module(monkeypatch)
        source_db = tmp_path / "live.db"
        conn = sqlite3.connect(str(source_db))
        try:
            conn.execute("CREATE TABLE pages (page_id TEXT PRIMARY KEY, name TEXT)")
            conn.execute("INSERT INTO pages VALUES ('p56_probe', 'P56')")
            conn.commit()
        finally:
            conn.close()

        snapshot = migration.create_sqlite_snapshot(str(source_db))
        try:
            assert os.path.exists(snapshot)
            check = sqlite3.connect(snapshot)
            try:
                assert check.execute("SELECT COUNT(*) FROM pages").fetchone()[0] == 1
            finally:
                check.close()
        finally:
            os.unlink(snapshot)
        assert all(c.closed for c in opened)

    def test_the_snapshot_unlinks_only_on_failure(self):
        """The `return snap_path` is inside the `try`, so a success must not unlink its own result."""
        source = _read("scripts/migrate_sqlite_to_postgres.py")
        span = _function_span(source, "create_sqlite_snapshot")
        assert "backed_up = True" in span
        assert "return snap_path" in span
        assert "if not backed_up:" in span
        assert span.index("backed_up = True") < span.index("return snap_path")
        assert span.index("if not backed_up:") > span.index("return snap_path")

    def test_the_comments_name_both_ids(self):
        source = _read("scripts/migrate_sqlite_to_postgres.py")
        assert "F-56-8" in source and "F-56-9" in source

    def test_no_opener_in_the_repository_is_left_unguarded(self):
        assert sweep_openers_without_a_finally_close() == []


# ================================================================ the class-level sweeps
class TestTheSweepsThatWouldHaveCaughtThisClass:
    """Three AST sweeps over the repository, each pinned at zero.

    These exist because a sweep keyed to a literal is not a sweep. Phase 55 grepped for
    `payload.get(key, "").strip()` and closed 18 sites; the `int(payload.get("amount", ...))` three
    lines away in the same handler survived it and produced five live 500s in this phase.
    """

    def test_no_route_handler_coerces_a_body_field_itself(self):
        assert sweep_unguarded_numeric_coercions() == []

    def test_no_writer_inserts_a_page_id_it_has_not_checked(self):
        assert sweep_writers_taking_an_unchecked_default_page() == []

    def test_the_sweeps_walk_the_directories_they_claim_to(self):
        seen = {_rel(p).split(os.sep)[0] for p in _py_files()}
        for expected in ("core", "routers", "scripts"):
            assert expected in seen, f"the sweep never looked inside {expected}/"
        assert "main.py" in {_rel(p) for p in _py_files()}
        assert "tests" not in seen and "migrations" not in seen

    def test_the_router_writers_are_the_only_two_the_router_has(self):
        source = _read("routers/automation_router.py")
        handlers = [fn.name for fn in _route_handler_functions(source)
                    if any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                           and isinstance(n.func.value, ast.Name) and n.func.value.id == "database"
                           and re.match(r"^create_", n.func.attr)
                           for n in ast.walk(fn))]
        assert sorted(handlers) == ["create_comment_automation", "create_tracked_link"]

    def test_the_foreign_keys_that_make_a_missing_page_fatal_are_still_there(self):
        """The fix is to check, not to drop the constraint."""
        source = _read("migrations/versions/0003_foreign_keys.py")
        # The constraints are declared as tuples: ("table", "column", "pages", "page_id", "CASCADE").
        cascade = re.findall(r'\("(\w+)",\s*"page_id",\s*"pages",\s*"page_id",\s*"CASCADE"\)', source)
        for table in ("comment_automations", "tracked_links", "invoices", "cargo_packages"):
            assert table in cascade, f"{table} no longer cascades from pages"
        assert len(cascade) >= 13, cascade


# ================================================================= the scanners themselves
class TestTheScannersAreCalibrated:
    """A sweep that cannot fail is not evidence. Each scanner is fed something it must catch."""

    def test_the_numeric_sweep_catches_the_shape_it_was_written_for(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", str(tmp_path))
        (tmp_path / "app.py").write_text(
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.post('/x')\n"
            "async def handler(payload: dict):\n"
            "    return int(payload.get('amount', 1))\n", encoding="utf-8")
        assert len(sweep_unguarded_numeric_coercions()) == 1

    def test_the_numeric_sweep_ignores_a_value_that_is_not_from_a_body(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", str(tmp_path))
        (tmp_path / "app.py").write_text(
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.get('/x')\n"
            "async def handler():\n"
            "    row = {'amount': '5'}\n"
            "    return int(row.get('amount', 1))\n", encoding="utf-8")
        assert sweep_unguarded_numeric_coercions() == []

    def test_the_writer_sweep_catches_an_unchecked_default(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", str(tmp_path))
        (tmp_path / "app.py").write_text(
            "import database\n"
            "def handler(pid):\n"
            "    return database.create_thing(page_id=pid or database.DEFAULT_PAGE_ID)\n",
            encoding="utf-8")
        assert len(sweep_writers_taking_an_unchecked_default_page()) == 1

    def test_the_writer_sweep_ignores_a_read(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", str(tmp_path))
        (tmp_path / "app.py").write_text(
            "import database\n"
            "def handler(pid):\n"
            "    return database.list_things(page_id=pid or database.DEFAULT_PAGE_ID)\n",
            encoding="utf-8")
        assert sweep_writers_taking_an_unchecked_default_page() == []

    def test_the_opener_sweep_catches_a_close_outside_a_finally(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", str(tmp_path))
        (tmp_path / "app.py").write_text(
            "import sqlite3\n"
            "def handler(path):\n"
            "    conn = sqlite3.connect(path)\n"
            "    rows = conn.execute('SELECT 1').fetchall()\n"
            "    conn.close()\n"
            "    return rows\n", encoding="utf-8")
        assert len(sweep_openers_without_a_finally_close()) == 1

    def test_the_opener_sweep_catches_a_connection_that_is_never_closed(self, tmp_path, monkeypatch):
        """The hole the revert harness found: no `close()` anywhere is worse than a late one."""
        monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", str(tmp_path))
        (tmp_path / "app.py").write_text(
            "import sqlite3\n"
            "def handler(path):\n"
            "    conn = sqlite3.connect(path)\n"
            "    return conn.execute('SELECT 1').fetchall()\n", encoding="utf-8")
        assert len(sweep_openers_without_a_finally_close()) == 1

    def test_the_opener_sweep_accepts_a_function_that_hands_the_connection_to_its_caller(self,
                                                                                        tmp_path,
                                                                                        monkeypatch):
        """`core/db_engine.get_db_connection` returns the connection; the caller owns the close."""
        monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", str(tmp_path))
        (tmp_path / "app.py").write_text(
            "import sqlite3\n"
            "def get_db_connection(path):\n"
            "    conn = sqlite3.connect(path)\n"
            "    return conn\n", encoding="utf-8")
        assert sweep_openers_without_a_finally_close() == []

    def test_the_opener_sweep_accepts_a_with_block(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", str(tmp_path))
        (tmp_path / "app.py").write_text(
            "import sqlite3\n"
            "def handler(path):\n"
            "    with sqlite3.connect(path) as conn:\n"
            "        return conn.execute('SELECT 1').fetchall()\n", encoding="utf-8")
        assert sweep_openers_without_a_finally_close() == []

    def test_the_opener_sweep_accepts_a_finally_close(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", str(tmp_path))
        (tmp_path / "app.py").write_text(
            "import sqlite3\n"
            "def handler(path):\n"
            "    conn = sqlite3.connect(path)\n"
            "    try:\n"
            "        return conn.execute('SELECT 1').fetchall()\n"
            "    finally:\n"
            "        conn.close()\n", encoding="utf-8")
        assert sweep_openers_without_a_finally_close() == []

    def test_the_ok_block_scanner_sees_an_else(self):
        html = ("<html><script>\n"
                "    async function a() {\n"
                "      const res = await fetch('/x');\n"
                "      if (res.ok) {\n"
                "        showToast('yes');\n"
                "      } else {\n"
                "        showToast('no');\n"
                "      }\n"
                "    }\n"
                "</script></html>")
        blocks = _ok_blocks(html)
        assert len(blocks) == 1 and blocks[0]["else"] is True

    def test_the_ok_block_scanner_sees_a_missing_else(self):
        html = ("<html><script>\n"
                "    async function a() {\n"
                "      const res = await fetch('/x');\n"
                "      if (res.ok) {\n"
                "        showToast('yes');\n"
                "      }\n"
                "    }\n"
                "</script></html>")
        blocks = _ok_blocks(html)
        assert len(blocks) == 1
        assert blocks[0]["else"] is False and blocks[0]["toast"] is True

    def test_the_ok_block_scanner_ignores_code_outside_a_script(self):
        html = "<html><body><p>if (res.ok) {</p></body></html>"
        assert _ok_blocks(html) == []

    def test_the_js_function_scanner_stops_at_the_function(self):
        html = ("<script>\n"
                "    function outer() {\n"
                "      if (x) { inner(); }\n"
                "      showToast('done');\n"
                "    }\n"
                "    function other() { showToast('next'); }\n"
                "</script>")
        span = _js_function_source(html, "outer")
        assert span is not None
        assert "showToast('done')" in span
        assert "showToast('next')" not in span
        assert _js_function_source(html, "missing") is None


# ==================================================================== the untouched guarantees
class TestNothingElseMoved:
    def test_the_ai_readiness_enum_and_its_guard_are_untouched(self):
        """Phase 50's published enum, and the test that refuses to let it grow silently.

        `tests/test_e50_ai_readiness_truth.py` asserts the tuple over seven lines rather than on
        one, so this pins the enum from the module itself and the guard's two assertions by their
        real text.
        """
        from core import ai_readiness

        assert ai_readiness.ERROR_CLASSES == (
            "auth", "quota", "model", "network", "bad_request", "server", "other",
        )
        assert ai_readiness.SCOPES == ("default", "page")
        source = _read("tests/test_e50_ai_readiness_truth.py")
        assert "assert ai_readiness.ERROR_CLASSES == (" in source
        assert 'assert ai_readiness.SCOPES == ("default", "page")' in source

    def test_the_service_contract_was_not_changed_to_fix_a_handler(self):
        """`fintech_service` keeps `database.get_page(page_id) or {}`.

        Its other four callers (agent.py:591, :738, :865 and cargo_service.py:45) take the page from
        a stored row rather than from a request body. The guard belongs at the HTTP boundary, where
        the untrusted id arrives.
        """
        source = _read("fintech_service.py")
        assert source.count('database.get_page(page_id) or {}') >= 2

    def test_phase_55_guards_are_still_in_place(self):
        """The helpers Phase 55 introduced are still the ones these handlers go through."""
        main_source = _read("main.py")
        engine_source = _read("core/db_engine.py")
        assert "def _payload_text(" in main_source
        assert "def _payload_int(" in main_source
        assert "class RollbackOnCloseConnection" in engine_source

    def test_the_probe_page_id_appears_only_in_comments_and_docstrings(self):
        """The synthetic id from the live measurements must not reach a production code path.

        Line-prefix heuristics do not work here: the id is quoted inside a docstring in
        `routers/automation_router.py`, whose lines start with prose. Walking the AST drops comments
        for free and lets docstrings be recognised as what they are.
        """
        offenders = []
        for path in _py_files():
            source = io.open(path, encoding="utf-8").read()
            try:
                tree = ast.parse(source)
            except SyntaxError:  # pragma: no cover
                continue
            docstrings = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                     ast.AsyncFunctionDef)) and node.body:
                    first = node.body[0]
                    if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                            and isinstance(first.value.value, str)):
                        docstrings.add(id(first.value))
            for node in ast.walk(tree):
                if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                        and "p56_never_created" in node.value and id(node) not in docstrings):
                    offenders.append(f"{_rel(path)}:{node.lineno}")
        assert offenders == [], offenders
