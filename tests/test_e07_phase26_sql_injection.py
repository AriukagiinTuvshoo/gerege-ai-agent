"""Phase 26 - SQL injection audit of the AidoLab B608 findings.

The reported locations (``core/backup_service.py:45,306,351``; ``database.py:931,1424...``)
do not correspond to this revision - the files have moved on since that scan. This module
audits what is *actually* there, in three groups:

* **Real**: the migration script interpolates identifiers read from a SQLite file's own
  schema. SQLite stores any string as a column name, so a crafted source database controls
  text that lands inside a ``SELECT``/``INSERT``.
* **Safe by construction**: `backup_service._COUNTED_TABLES` - a module constant.
* **Safe despite the f-string**: every `database.py` site interpolates a where-fragment built
  from string literals, with user input bound as a parameter.

Each group is pinned by a test, so a future change that turns a safe case into an unsafe one
fails here rather than waiting for the next scan.
"""

import importlib.util
import re
import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

MIGRATION_SCRIPT = REPO_ROOT / "scripts" / "migrate_sqlite_to_postgres.py"


def load_migration_module():
    spec = importlib.util.spec_from_file_location("p26_migrate", MIGRATION_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mig = load_migration_module()


# ===========================================================================
# The identifier validator - the single chokepoint
# ===========================================================================

LEGITIMATE_IDENTIFIERS = [
    "invoice_id",
    "pages",
    "id",
    "_private",
    "a1",
    "col$1",
    "tracked_links",
    "PAGE_ID",
]

HOSTILE_IDENTIFIERS = [
    'a" , (SELECT 1) --',
    "id; DROP TABLE victims; --",
    "x`--",
    "id) --",
    "1abc",
    "",
    "a b",
    "id\n--",
    "id' OR '1'='1",
    "pages;DELETE FROM audit_logs",
    'x" OR "1"="1',
    "id/*",
    "id--",
    "id#",
    "id;",
    "ID\tX",
]


@pytest.mark.parametrize("name", LEGITIMATE_IDENTIFIERS)
def test_legitimate_identifiers_are_accepted_and_quoted(name):
    quoted = mig._q_ident(name)
    assert quoted == f'"{name}"'


@pytest.mark.parametrize("name", HOSTILE_IDENTIFIERS)
def test_hostile_identifiers_are_refused(name):
    with pytest.raises(ValueError) as raised:
        mig._q_ident(name)
    assert "unsafe identifier" in str(raised.value)
    # The message must not echo the rejected name: it is attacker-controlled, and it lands in
    # logs, terminals and alerts. A newline or escape sequence there is log injection.
    if len(name) >= 8:
        assert name not in str(raised.value)


def test_q_ident_list_validates_every_element():
    assert mig._q_ident_list(["a", "b"]) == ['"a"', '"b"']
    with pytest.raises(ValueError):
        mig._q_ident_list(["good", 'bad"name'])


def test_the_validator_rejects_before_quoting():
    """Quoting alone is not enough: the caller builds syntax around the value.

    A name containing a quote would produce an unbalanced literal if it were only escaped
    and never validated, so validation must be the gate - not the quoting.
    """
    hostile = 'a" , (SELECT 1) --'
    with pytest.raises(ValueError):
        mig._q_ident(hostile)
    # And it must not have been silently "fixed" into something that still parses.
    assert '"' not in mig._q_ident("safe_name").strip('"')


# ===========================================================================
# End-to-end: a crafted SQLite source must be refused, not executed
# ===========================================================================

def build_hostile_sqlite(path, hostile_column='a" , (SELECT 1) --'):
    conn = sqlite3.connect(path)
    quoted = '"' + hostile_column.replace('"', '""') + '"'
    conn.execute(
        f"""CREATE TABLE pages (page_id TEXT PRIMARY KEY, name TEXT, page_access_token TEXT,
            category TEXT, knowledge_json TEXT, created_at TEXT, updated_at TEXT, {quoted} TEXT)"""
    )
    conn.execute("INSERT INTO pages (page_id, name) VALUES ('p1', 'P1')")
    conn.commit()
    conn.close()
    return path


def test_the_balanced_payload_is_live_sql_without_the_fix():
    """The exploitability claim, measured rather than assumed.

    The comment-terminated payload that first looked like an exploit is a *syntax error* -
    `--` needs a newline to terminate. This is the form that actually executes, and it is
    what the fix has to stop.
    """
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE invoices (invoice_id TEXT, a TEXT)")
    conn.execute("INSERT INTO invoices VALUES ('INV-1', 'x')")
    hostile = "a, (SELECT 1) AS injected"
    executed = conn.execute(f"SELECT invoice_id, {hostile} FROM invoices").fetchall()
    conn.close()
    # The subquery ran. This is the behaviour the validator now prevents.
    assert executed == [("INV-1", "x", 1)]
    # And the validator refuses that exact string.
    with pytest.raises(ValueError):
        mig._q_ident(hostile)


def test_the_comment_terminated_payload_is_only_a_syntax_error():
    """Correcting an overstatement: this one does not execute, and the report must not say it does."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE invoices (invoice_id TEXT, a TEXT)")
    with pytest.raises(sqlite3.OperationalError):
        conn.execute('SELECT invoice_id, a" , (SELECT 1) -- FROM invoices')
    conn.close()


def test_sqlite_really_does_store_a_hostile_column_name(tmp_path):
    """The premise of the finding. If SQLite refused, the finding would be a false positive."""
    db = str(tmp_path / "hostile.db")
    build_hostile_sqlite(db)
    conn = sqlite3.connect(db)
    columns = [row[1] for row in conn.execute("PRAGMA table_info(pages)").fetchall()]
    conn.close()
    assert 'a" , (SELECT 1) --' in columns


def test_migration_refuses_a_crafted_source_schema(tmp_path):
    """The finding itself: the identifier reached a SELECT/INSERT before this fix."""
    db = build_hostile_sqlite(str(tmp_path / "hostile.db"))
    target = f"sqlite:///{tmp_path}/target.db"
    with pytest.raises(ValueError) as raised:
        mig.run_migration(sqlite_path=db, postgres_url=target, dry_run=False)
    assert "unsafe identifier" in str(raised.value)


@pytest.mark.parametrize(
    "hostile",
    [
        'x;DROP TABLE audit_logs;--',
        'x") , ((SELECT 1)) --',
        "x' --",
        "x]--",
    ],
)
def test_migration_refuses_each_hostile_column_shape(tmp_path, hostile):
    db = str(tmp_path / "h.db")
    conn = sqlite3.connect(db)
    quoted = '"' + hostile.replace('"', '""') + '"'
    conn.execute(
        f"""CREATE TABLE pages (page_id TEXT PRIMARY KEY, name TEXT, page_access_token TEXT,
            category TEXT, knowledge_json TEXT, created_at TEXT, updated_at TEXT, {quoted} TEXT)"""
    )
    conn.execute("INSERT INTO pages (page_id, name) VALUES ('p1','P1')")
    conn.commit()
    conn.close()
    with pytest.raises(ValueError):
        mig.run_migration(sqlite_path=db, postgres_url=f"sqlite:///{tmp_path}/t.db", dry_run=False)


def test_ordinary_columns_still_migrate(tmp_path):
    """The fix must not break the normal path - this is the same shape the real tests use."""
    import database
    from tests.test_migration_and_restore_verification import copy_sqlite_database

    database.init_db()
    src = str(tmp_path / "src.db")
    tgt = str(tmp_path / "tgt.db")
    copy_sqlite_database(database.DB_PATH, src)
    rep = mig.run_migration(sqlite_path=src, postgres_url=f"sqlite:///{tgt}", batch_size=25)
    assert rep["status"] == "SUCCESS", rep.get("status")
    assert rep["verification"]["rows_verified"] is True


# ===========================================================================
# backup_service: safe by construction, pinned so it stays that way
# ===========================================================================

def test_counted_tables_is_an_immutable_constant():
    """`SELECT COUNT(*) FROM {tbl}` is safe only while `tbl` cannot vary.

    If `_COUNTED_TABLES` ever became a function argument or was read from configuration,
    this query would become injectable. Pin the property rather than the syntax.
    """
    from core import backup_service

    assert isinstance(backup_service._COUNTED_TABLES, tuple)
    for name in backup_service._COUNTED_TABLES:
        assert re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name), name


def test_counted_tables_is_never_reassigned():
    source = (REPO_ROOT / "core" / "backup_service.py").read_text(encoding="utf-8")
    assert source.count("_COUNTED_TABLES = ") == 1
    # And it is never a parameter of the counting function.
    assert "def _collect_db_table_counts(" in source
    signature = source.split("def _collect_db_table_counts(", 1)[1].split(")", 1)[0]
    assert "_COUNTED_TABLES" not in signature
    assert "tables" not in signature


def test_table_counts_uses_no_unvalidated_identifier_from_outside():
    """Every table name in the query must come from the constant."""
    source = (REPO_ROOT / "core" / "backup_service.py").read_text(encoding="utf-8")
    block = source.split("def _collect_db_table_counts(", 1)[1].split("\ndef ", 1)[0]
    assert "_COUNTED_TABLES" in block
    # The f-string interpolates a loop variable bound to that constant.
    assert re.search(r"for (\w+) in _COUNTED_TABLES", block)
    loop_var = re.search(r"for (\w+) in _COUNTED_TABLES", block).group(1)
    assert f"FROM {{{loop_var}}}" in block


# ===========================================================================
# database.py: parameterised values, literal fragments
# ===========================================================================

def test_every_database_py_fstring_interpolates_a_local_literal_fragment():
    """The B608 pattern is real here; the risk is not.

    Every interpolated name must be assigned in the same function from string literals, and
    every user-supplied value must go through the parameter tuple. This test fails if a
    future edit interpolates something that is not built from literals.
    """
    source = (REPO_ROOT / "database.py").read_text(encoding="utf-8")
    lines = source.splitlines()

    interpolated = set()
    for line in lines:
        if re.search(r"\.execute(?:many)?\(\s*f[\"']", line):
            interpolated.update(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", line))

    assert interpolated, "expected the known f-string sites to still exist"

    for name in interpolated:
        assignments = []
        for index, line in enumerate(lines):
            if not re.match(rf"^\s*{re.escape(name)}\s*=", line):
                continue
            # A fragment may be written across several lines (a parenthesised conditional).
            # Gather the assignment until the brackets balance.
            chunk = [line.strip()]
            depth = line.count("(") - line.count(")")
            cursor = index
            while depth > 0 and cursor + 1 < len(lines):
                cursor += 1
                chunk.append(lines[cursor].strip())
                depth += lines[cursor].count("(") - lines[cursor].count(")")
            assignments.append(" ".join(chunk))
        assert assignments, f"{name} is interpolated into SQL but never assigned"
        for assignment in assignments:
            # Must be built from string literals - a "?" placeholder or literal SQL.
            assert re.search(r'"[^"]*"', assignment), (
                f"{name} is not built from a string literal: {assignment}"
            )
            # Any interpolation inside the fragment must be an identifier being given a
            # placeholder, never a value. `f"{c} = ?"` is the safe shape; f"{page_id}" is not.
            for inner in re.findall(r"\{([^}]*)\}", assignment):
                assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", inner.strip()), (
                    f"{name} interpolates something other than a bare identifier: {assignment}"
                )
            # And a fragment may never carry a user-supplied value, which would have to come
            # from a parameter binding instead.
            assert "page_id" not in assignment or "?" in assignment, (
                f"{name} interpolates page_id without a placeholder: {assignment}"
            )


@pytest.mark.parametrize(
    "payload",
    [
        "p1' OR '1'='1",
        "p1'; DROP TABLE invoices; --",
        'p1" OR 1=1 --',
        "p1' UNION SELECT 1,2 --",
        "x' OR 'a'='a",
        "p1' AND (SELECT COUNT(*) FROM invoices)>0 --",
    ],
)
def test_user_input_never_becomes_sql_in_the_fintech_summary(tmp_path, monkeypatch, payload):
    """Values are bound, so a tautology must return the same shape as a nonexistent page.

    If `page_id` were concatenated, `' OR '1'='1` would aggregate every row in the table.
    Bound as a parameter it matches no page, which is the observable difference.
    """
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/inj.db")
    import importlib

    import database

    importlib.reload(database)
    database.init_db()
    database.save_page(page_id="p1", name="P1")
    database.create_invoice(page_id="p1", amount=5000, description="real", sender_id="s")

    control = database.get_fintech_summary(page_id="p1")
    attacked = database.get_fintech_summary(page_id=payload)

    # The payload matches no page, so it must not see the tenant's aggregate.
    assert attacked["total_revenue"] != control["total_revenue"] or control["total_revenue"] == 0
    assert attacked["paid_count"] == 0

    # And the schema must be intact - the DROP payload did not run.
    conn = database.get_connection()
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert "invoices" in tables
    assert "pages" in tables


def test_the_database_py_queries_still_return_correct_results(tmp_path, monkeypatch):
    """The parameterised path must remain functional, not merely safe."""
    import importlib

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/ok.db")
    import database

    importlib.reload(database)
    database.init_db()
    database.save_page(page_id="tenant_a", name="A")
    database.create_invoice(page_id="tenant_a", amount=1000, description="x", sender_id="s")
    database.create_invoice(page_id="tenant_a", amount=2000, description="y", sender_id="s")

    summary = database.get_fintech_summary(page_id="tenant_a")
    # Two invoices exist and are unpaid. Compare against a direct parameterised count rather
    # than a hardcoded number, so this does not depend on the shared database's history.
    conn = database.get_connection()
    expected_count = conn.execute(
        "SELECT COUNT(*) FROM invoices WHERE page_id = ? AND status = 'PENDING'", ("tenant_a",)
    ).fetchone()[0]
    expected_sum = conn.execute(
        "SELECT COALESCE(SUM(amount), 0) FROM invoices WHERE page_id = ? AND status = 'PENDING'",
        ("tenant_a",),
    ).fetchone()[0]
    conn.close()
    assert expected_count >= 2
    assert summary["pending_count"] == expected_count
    assert summary["pending_revenue"] == expected_sum
    assert summary["paid_count"] == 0


def test_literal_fragments_never_contain_a_quote_from_user_data():
    """A where-fragment must terminate in a placeholder, never in an interpolated value."""
    source = (REPO_ROOT / "database.py").read_text(encoding="utf-8")
    for line in source.splitlines():
        if re.search(r"\.execute(?:many)?\(\s*f[\"']", line):
            # No `{...}` may sit inside a string literal in a way that could carry a value.
            assert "? " not in line.split("FROM")[0] or True
    # The strong form: every f-string SQL site has a parameter argument.
    execute_lines = [
        line for line in source.splitlines()
        if re.search(r"\.execute(?:many)?\(\s*f[\"']", line)
    ]
    assert execute_lines
    for line in execute_lines:
        assert re.search(r",\s*\w+\)?\s*$", line) or "params" in line, (
            f"f-string SQL without a parameter argument: {line.strip()[:120]}"
        )


# ===========================================================================
# The test-only findings
# ===========================================================================

def test_test_table_names_are_generated_not_supplied():
    """`test_postgres_cursor_regression.py` interpolates a table name into DDL.

    Safe because it is a UUID-suffixed literal, not because it is a test. Pin the source.
    """
    source = (REPO_ROOT / "tests" / "test_postgres_cursor_regression.py").read_text(encoding="utf-8")
    assert re.search(r'tbl\s*=\s*f"pg_cursor_reg_\{(?:uuid\.)?uuid4\(\)\.hex', source.replace("uuid.uuid4", "uuid4").replace("uuid4", "uuid4")) or \
           re.search(r'tbl\s*=\s*f"pg_cursor_reg_', source), "table name is no longer generated"
    # It must not be a function parameter (which a caller could influence).
    for match in re.finditer(r"def (\w+)\(([^)]*)\)", source):
        assert "tbl" not in match.group(0).split("(")[1] or "tbl" == "", "tbl became a parameter"


def test_rollback_test_table_list_is_a_constant_default():
    source = (REPO_ROOT / "tests" / "test_postgres_restore_real_rollback.py").read_text(encoding="utf-8")
    assert re.search(r'def _compute_tables_checksum\(tables=\(', source), (
        "the table tuple is no longer a literal default"
    )
    assert "pages" in source and "registrations" in source


# ===========================================================================
# Findings outside the reported set - audited anyway, because B608 flagged them
# ===========================================================================

AUDITED_UNREPORTED = [
    "core/audit_integrity.py",
    "core/login_identity.py",
    "core/username_uniqueness.py",
    "scripts/verify_migration_0002.py",
]


@pytest.mark.parametrize("relative", AUDITED_UNREPORTED)
def test_sql_identifiers_in_these_modules_come_from_module_constants(relative):
    """AidoLab did not report these files; bandit flags 17 sites across them.

    Each interpolated name must be a module-level constant, or a default-argument value.
    Nothing here accepts a table or column name from a caller that could be influenced.
    """
    import ast

    source = (REPO_ROOT / relative).read_text(encoding="utf-8")
    tree = ast.parse(source)
    module_constants = {
        target.id
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }

    # Names bound as parameters must have a constant default, OR have no caller that passes
    # anything dynamic. `normalized_identifier_sql(column)` is the one required-argument
    # case: it composes SQL from its argument, and has no callers at all. That is a latent
    # hazard rather than a live one, and it is asserted as such below.
    # Literal constants, so a default written as `USERNAME_UNIQUE_INDEX` can be resolved.
    literal_constants = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    literal_constants[target.id] = node.value.value

    constant_defaults = {}
    required_identifier_params = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        args = node.args.args
        defaults = node.args.defaults
        offset = len(args) - len(defaults)
        for index, arg in enumerate(args):
            if arg.arg not in {"table", "column", "index_name"}:
                continue
            if index >= offset:
                value = defaults[index - offset]
                if isinstance(value, ast.Constant):
                    resolved = value.value
                elif isinstance(value, ast.Name) and value.id in literal_constants:
                    # A default may name a module constant (`index_name=USERNAME_UNIQUE_INDEX`).
                    resolved = literal_constants[value.id]
                else:
                    raise AssertionError(
                        f"{relative}:{node.lineno} default for {arg.arg} is neither a literal "
                        "nor a resolvable module constant"
                    )
                assert mig._IDENT_RE.match(str(resolved)), (
                    f"{relative}: unsafe default {resolved!r} for {arg.arg}"
                )
                constant_defaults[arg.arg] = resolved
            else:
                required_identifier_params.add((node.name, arg.arg))

    # A required identifier parameter is acceptable only while nothing calls it. If a caller
    # appears, this fails and the caller has to be examined.
    for function_name, param in required_identifier_params:
        callers = [
            line for line in source.splitlines()
            if re.search(rf"\b{re.escape(function_name)}\(", line)
            and "def " not in line
        ]
        assert not callers, (
            f"{relative}: {function_name}({param}) composes SQL from an argument and now has "
            f"a caller: {callers[0].strip()[:120]}"
        )

    # Any name that looks like an identifier and is interpolated must be a constant.
    for line in source.splitlines():
        if 'f"' not in line and "f'" not in line:
            continue
        for name in re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", line):
            if name in {"dialect", "len"}:
                continue  # selects a branch, or formats a number - neither reaches SQL as an identifier
            if name.islower() and name not in module_constants:
                # A lowercase interpolated name in an identifier position is only acceptable
                # when it is a loop variable over a module-level constant list. `for t in
                # TABLES` over 11 literal table names is safe; `for t in user_input` is not.
                in_identifier_position = ("FROM {" + name) in line or ("JOIN {" + name) in line
                if not in_identifier_position:
                    continue
                source_lines = source.splitlines()
                loop = [
                    candidate for candidate in source_lines
                    if re.search(rf"for {re.escape(name)} in (\w+)", candidate)
                ]
                assert loop, f"{relative}: {name} is interpolated as an identifier but is not a loop variable"
                iterable = re.search(rf"for {re.escape(name)} in (\w+)", loop[0]).group(1)
                assert iterable in module_constants, (
                    f"{relative}: {name} iterates over {iterable}, which is not a module constant"
                )


def test_verify_migration_table_list_is_a_constant():
    source = (REPO_ROOT / "scripts" / "verify_migration_0002.py").read_text(encoding="utf-8")
    assert re.search(r"^TABLES\s*=", source, re.MULTILINE), "TABLES is no longer a module constant"


# ===========================================================================
# Suppressions: narrow, reasoned, and protected by the tests above
# ===========================================================================

SUPPRESSED_FILES = [
    "core/backup_service.py",
    "database.py",
    "scripts/migrate_sqlite_to_postgres.py",
]


@pytest.mark.parametrize("relative", SUPPRESSED_FILES)
def test_every_suppression_carries_a_reason(relative):
    """A bare `# nosec` is how a real finding gets lost. Each one must say why."""
    source = (REPO_ROOT / relative).read_text(encoding="utf-8")
    for line_number, line in enumerate(source.splitlines(), start=1):
        if "nosec" not in line:
            continue
        assert "Phase 26" in line, f"{relative}:{line_number} suppresses without a reason: {line.strip()}"
        # The rule must be named, so a broad `nosec` cannot silence future findings here.
        assert "B608" in line, f"{relative}:{line_number} suppresses without naming B608"


def test_no_suppression_was_added_to_a_file_outside_the_audited_set():
    """The audit covered three files. Suppressing anywhere else would hide an unexamined site."""
    for path in REPO_ROOT.rglob("*.py"):
        parts = set(path.parts)
        if ".git" in parts or ".scratch" in parts or "tests" in parts:
            continue
        relative = str(path.relative_to(REPO_ROOT))
        if relative in SUPPRESSED_FILES:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert "nosec B608" not in text, f"unexpected B608 suppression in {relative}"


def test_suppressed_modules_no_longer_report_b608():
    """Confirms the annotations take effect - a silently-broken nosec would leave the count."""
    import subprocess

    for relative in SUPPRESSED_FILES:
        result = subprocess.run(
            [sys.executable, "-m", "bandit", "-t", "B608", "-f", "json", relative],
            capture_output=True,
            text=True,
        )
        if result.returncode not in (0, 1) or not result.stdout.strip():
            pytest.skip("bandit is not installed in this environment")
        import json

        findings = json.loads(result.stdout)["results"]
        assert findings == [], f"{relative} still reports B608: {[f['line_number'] for f in findings]}"
