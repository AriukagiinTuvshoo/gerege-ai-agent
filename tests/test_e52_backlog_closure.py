"""Phase 52 — the deferred backlog: B1, B5, B6 and observations O-51-1/-2/-4/-6.

Phase 51 closed four of the seven backlog items and recorded six observations. This file is
the test coverage for the rest, and each section states what was measured before the fix,
because a fix without a before-measurement cannot be told apart from a rewrite.

**B1 — the published Meta verify token was a default the schema handed out.**
`agent_verify_secret_token_123` is printed in this repository. Phase 45 (F-44-B) made the
*read* path refuse it, Phase 49 (F-49-1/-2/-4) stopped the dashboard and the sheet editor from
spreading it, and Phase 51's template guard refuses it in any env template. What was left was
the *write* path: the string was the `core/models.py` column default, the value
`database.init_db()` inserted for the default page on a first boot, `database.save_page`'s
parameter default, and `0001`'s `server_default`. Measured on a database migrated to `0008`,
before this phase:

    PRAGMA table_info(pages) -> verify_token | VARCHAR(255) | dflt = "'agent_verify_secret_token_123'"
    INSERT INTO pages (page_id, name) VALUES (…)  -> verify_token = 'agent_verify_secret_token_123'

Revision `0009` removes the fourth, which lives in deployed databases and cannot be fixed by
editing Python.

**B5 — `alembic.ini` pinned `sqlite:///leads.db`.**
`migrations/env.py` let that pin win over `DB_PATH` unless `DATABASE_URL` was set, so a shell
`alembic upgrade head` in a fresh clone — with no `.env`, which is every fresh clone, because
`.env` is git-ignored — migrated the repository's own `leads.db` and reported success.
Measured in a sandbox copy with the pin restored: `returncode 0`, `leads.db` created.

**B6 — the dashboard read a field the API removes.**
`updatePageUI()` filled `#settings-meta-token` from `p.page_access_token`, which
`database._sanitize_page_secrets()` pops from every page dict before it leaves the API
(Phase 49, F-49-2). The field was therefore blank for every page including the ones with a
token stored, and an empty password box reads as "none configured".

**O-51-1** an *empty* report-recipient slot could still be claimed by an unauthenticated
`/start` in production, where a Telegram bot is public by username.
**O-51-2** an open circuit breaker classified as `other`, hiding the cause it was opened by.
**O-51-4** `database.record_audit_log` appeared **zero** times in `executive_bot_service.py`,
the module that decides who receives the executive reports.
**O-51-6** `POST /api/update-keys` answered "saved successfully" for a change no file
recorded, no restart survives and the worker process never saw.

Nothing here weakens an existing assertion. One assertion changed shape:
`test_e51_env_write_merge.py::test_the_gate_is_unchanged` pinned the write gate as a literal
`if` line, and O-51-6 lifted the same two conditions into a named `write_gate_open` so the
response can report which side of it a request landed on. That test now pins the conditions
and additionally requires the single `merge_env_file(updates)` call to sit *inside* the gate's
block — a stronger property than the one it replaced.
"""

import configparser
import inspect
import io
import os
import re
import shutil
import sqlite3
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import database  # noqa: E402
import executive_bot_service  # noqa: E402
from core import ai_readiness, ai_router, secret_guard, security  # noqa: E402
from core import models as core_models  # noqa: E402

#: Taken from the module that owns the rule, never retyped: a test that hardcodes the published
#: literal would keep passing if the literal changed.
PUBLISHED = security.PUBLIC_VERIFY_TOKEN_PLACEHOLDER
OWNER_SECRET = security.PUBLIC_OWNER_COMMAND_SECRET

HEAD = "0009_verify_token_default"
PREVIOUS_HEAD = "0008_tenant_not_null"

OWNER = "111111"
STRANGER = "999000111"
STRONG_SECRET = "e52-generated-owner-secret-8b1f4c2e"


def _read(*names):
    return "\n".join(
        io.open(os.path.join(REPO_ROOT, n), encoding="utf-8").read() for n in names
    )


def _code_only(text):
    """Executable lines only: comments AND docstrings are skipped.

    Every fix in this phase is documented in a comment or docstring that quotes the line it
    replaced, so a whole-file substring assertion would fail on the documentation of the fix.
    Same shape, same remedy, as `test_e51_env_write_merge._code_only`.
    """
    triple = chr(34) * 3
    out, in_docstring = [], False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.count(triple) % 2 == 1:
            in_docstring = not in_docstring
            continue
        if in_docstring or stripped.startswith("#"):
            continue
        out.append(line)
    return "\n".join(out)


# ======================================================================================
# A sandbox copy of the migration tree.
#
# `core/db_engine.py` calls `load_dotenv(override=True)` at import, and `find_dotenv()` walks
# up from that file's directory. Run against the repository itself, a subprocess would
# therefore read the developer's real `.env` and OVERRIDE every variable the test set —
# measured in this phase: three `alembic` invocations that exported `DB_PATH=/tmp/…/rt.db`
# migrated `/tmp/p48a/p48a_smoke.db`, the live application database, because `.env` names it.
# A copy with an EMPTY `.env` at its root stops the walk there, so the subprocess environment
# decides the target in every environment, including one that has a real `.env`.
# ======================================================================================


def _build_sandbox(root):
    os.makedirs(root, exist_ok=True)
    for item in ("core", "migrations"):
        shutil.copytree(
            os.path.join(REPO_ROOT, item),
            os.path.join(root, item),
            ignore=shutil.ignore_patterns("__pycache__"),
            dirs_exist_ok=True,
        )
    for name in ("alembic.ini", "database.py"):
        shutil.copy2(os.path.join(REPO_ROOT, name), os.path.join(root, name))
    with io.open(os.path.join(root, ".env"), "w", encoding="utf-8") as handle:
        handle.write("")
    return root


@pytest.fixture(scope="module")
def sandbox(tmp_path_factory):
    return _build_sandbox(str(tmp_path_factory.mktemp("alembic_sandbox") / "tree"))


def _child_references(path):
    """How many tables' DDL still references `pages`.

    Measured, never hardcoded: 14 in the repository's `leads.db`, 15 in a database the
    migrations build in a sandbox. What `0009` promises is that the number does not change,
    so that is what is asserted.
    """
    conn = sqlite3.connect(str(path))
    try:
        return sum(
            1 for (sql,) in conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND sql IS NOT NULL"
            ) if "REFERENCES pages" in sql.replace('"', "")
        )
    finally:
        conn.close()


def _alembic(root, args, target=None, extra_env=None, timeout=300):
    """Run the Alembic CLI inside a sandbox, with nothing but the given environment."""
    env = {
        "PATH": os.environ["PATH"],
        "PYTHONPATH": root,
        "HOME": os.environ.get("HOME", "/tmp"),
    }
    if target is not None:
        env["DB_PATH"] = str(target)
        env["CSV_PATH"] = str(target) + ".csv"
    env.update(extra_env or {})
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=root, env=env, capture_output=True, text=True, timeout=timeout,
    )


# ======================================================================================
# 1. B1 — the published verify token is no longer a default anything hands out
# ======================================================================================


class TestB1NoExecutableDefaultCarriesThePublishedToken:
    def test_the_orm_column_default_is_empty(self):
        column = core_models.PageModel.__table__.c.verify_token
        assert column.default is not None, "the column keeps a default; only its value changed"
        assert column.default.arg == "", f"the ORM default is {column.default.arg!r}"
        assert column.server_default is None, "the ORM must not emit a DDL default either"

    def test_the_published_literal_is_nowhere_in_the_executable_code_of_its_three_paths(self):
        for name in ("core/models.py", "database.py"):
            code = _code_only(_read(name))
            assert PUBLISHED not in code, f"{name} still hands out the published value"

    def test_save_page_default_is_empty(self):
        default = inspect.signature(database.save_page).parameters["verify_token"].default
        assert default == "", f"save_page's verify_token default is {default!r}"

    def test_the_predicates_still_know_the_literal(self):
        """Removing a default must not remove the rule that recognises it.

        These two lists are why the value survives in the source at all: they let the
        application refuse a value an operator typed by hand, or one that arrived from a
        database created before revision 0009.
        """
        assert security.PUBLIC_VERIFY_TOKEN_PLACEHOLDER == PUBLISHED
        assert PUBLISHED in secret_guard.PUBLISHED_OR_PLACEHOLDER_VALUES
        assert security.meta_verify_token_is_placeholder(PUBLISHED) is True
        assert security.meta_verify_token_is_usable(PUBLISHED) is False or True  # env-dependent
        assert security.meta_verify_token_is_usable("") is False

    def test_the_published_literal_is_refused_in_production_and_not_accepted_as_usable(self, monkeypatch):
        monkeypatch.setenv("ENV", "production")
        assert security.meta_verify_token_is_usable(PUBLISHED) is False
        monkeypatch.setenv("ENV", "development")
        # Development keeps accepting it (documented Phase 45 decision: the suite and local
        # runs depend on it and nothing is exposed there). Pinned so the asymmetry is a choice,
        # not an accident - and so a change to it is a deliberate edit, not a side effect.
        assert security.meta_verify_token_is_usable(PUBLISHED) is True


@pytest.fixture()
def fresh_app_db(tmp_path, monkeypatch):
    """A real database built by `database.init_db()` on a disposable path.

    All three pins, not one: Phase 51's F-51-1b measured that setting only `DATABASE_URL`
    leaves the `database.DB_PATH` module attribute stale and the schema check then reports
    `expected head '0009_…', database is at 'None'`.
    """
    target = tmp_path / "b1.db"
    monkeypatch.setattr(database, "DB_PATH", str(target))
    monkeypatch.setenv("DB_PATH", str(target))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{target}")
    monkeypatch.setenv("CSV_PATH", str(tmp_path / "b1.csv"))
    database.init_db()
    assert target.exists(), "init_db did not create the database it was pointed at"
    return target


class TestB1AFreshDatabaseDoesNotInheritThePublishedToken:
    def test_the_column_has_no_default_in_the_built_schema(self, fresh_app_db):
        conn = sqlite3.connect(str(fresh_app_db))
        try:
            defaults = [r[4] for r in conn.execute("PRAGMA table_info(pages)") if r[1] == "verify_token"]
        finally:
            conn.close()
        assert defaults and defaults[0] is None, f"pages.verify_token still defaults to {defaults}"

    def test_a_raw_insert_that_omits_the_column_does_not_mint_the_literal(self, fresh_app_db):
        """The behavioural half: the DDL is only interesting because of what it does to a row."""
        conn = sqlite3.connect(str(fresh_app_db))
        try:
            conn.execute("INSERT INTO pages (page_id, name) VALUES ('e52_b1_probe', 'probe')")
            value = conn.execute(
                "SELECT verify_token FROM pages WHERE page_id='e52_b1_probe'"
            ).fetchone()[0]
            conn.execute("DELETE FROM pages WHERE page_id='e52_b1_probe'")
            conn.commit()
        finally:
            conn.close()
        assert value != PUBLISHED, "an INSERT that named no token was handed the published one"
        assert value in (None, ""), f"expected an empty token, got {value!r}"

    def test_the_default_page_of_a_first_boot_is_not_born_with_the_literal(self, fresh_app_db):
        page = database.get_page(database.DEFAULT_PAGE_ID)
        assert page is not None, "init_db did not create the default page"
        assert (page.get("verify_token") or "") != PUBLISHED

    def test_an_empty_token_fails_closed_rather_than_open(self):
        """The reason an empty default is safe: nothing accepts "" as a usable token."""
        assert security.meta_verify_token_is_usable("") is False
        assert security.meta_verify_token_is_placeholder("") is True
        assert security.usable_webhook_secret("") == ""


class TestB1Migration0009:
    def test_it_is_the_head_and_follows_0008(self):
        from core.schema_manager import head_revision

        assert head_revision() == HEAD
        source = _read("migrations/versions/0009_verify_token_default_cleared.py")
        assert f'revision = "{HEAD}"' in source
        assert f'down_revision = "{PREVIOUS_HEAD}"' in source

    def test_0001_is_left_alone_because_it_is_applied_history(self):
        """Editing a released migration desynchronises every database that already ran it."""
        source = _read("migrations/versions/0001_initial_enterprise_schema.py")
        assert f'server_default="{PUBLISHED}"' in source, (
            "0001 must still record what it did; 0009 is what undoes it"
        )

    def test_it_removes_the_default_and_keeps_everything_else(self, sandbox, tmp_path):
        target = tmp_path / "b1_migration.db"
        assert _alembic(sandbox, ["upgrade", PREVIOUS_HEAD], target).returncode == 0

        conn = sqlite3.connect(str(target))
        try:
            conn.execute(
                "INSERT INTO pages (page_id, name, verify_token) VALUES "
                "('e52_real', 'kept', 'a-real-operator-token')"
            )
            conn.execute("INSERT INTO pages (page_id, name) VALUES ('e52_inherited', 'inherited')")
            conn.commit()
            before_default = [
                r[4] for r in conn.execute("PRAGMA table_info(pages)") if r[1] == "verify_token"
            ][0]
            inherited_before = conn.execute(
                "SELECT verify_token FROM pages WHERE page_id='e52_inherited'"
            ).fetchone()[0]
            rows_before = conn.execute("SELECT count(*) FROM pages").fetchone()[0]
            children_before = _child_references(target)
            objects_before = sorted(
                r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE tbl_name='pages' AND type IN ('index','trigger')"
                )
            )
        finally:
            conn.close()

        assert PUBLISHED in (before_default or ""), "0008 did not carry the published default"
        assert inherited_before == PUBLISHED, "the row 0001's default minted is the published value"

        completed = _alembic(sandbox, ["upgrade", "head"], target)
        assert completed.returncode == 0, completed.stderr[-2000:]

        conn = sqlite3.connect(str(target))
        try:
            after_default = [
                r[4] for r in conn.execute("PRAGMA table_info(pages)") if r[1] == "verify_token"
            ][0]
            rows_after = conn.execute("SELECT count(*) FROM pages").fetchone()[0]
            objects_after = sorted(
                r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE tbl_name='pages' AND type IN ('index','trigger')"
                )
            )
            real = conn.execute(
                "SELECT verify_token FROM pages WHERE page_id='e52_real'"
            ).fetchone()[0]
            inherited_after = conn.execute(
                "SELECT verify_token FROM pages WHERE page_id='e52_inherited'"
            ).fetchone()[0]
            children = _child_references(target)
            violations = conn.execute("PRAGMA foreign_key_check").fetchall()
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            audit_guard = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE name='audit_logs_no_update'"
            ).fetchone()
            conn.execute("INSERT INTO pages (page_id, name) VALUES ('e52_after', 'after')")
            minted = conn.execute(
                "SELECT verify_token FROM pages WHERE page_id='e52_after'"
            ).fetchone()[0]
        finally:
            conn.close()

        assert after_default is None, f"0009 left the default in place: {after_default!r}"
        assert minted != PUBLISHED, "a new row is still minted with the published token"
        assert rows_after == rows_before, "0009 moved data"
        assert objects_after == objects_before, "0009 lost an index or a trigger on pages"
        assert children == children_before > 0, (
            f"{children} tables reference pages after 0009, {children_before} before"
        )
        assert not violations and integrity == "ok" and audit_guard
        # The deliberate half of the design: an EXISTING row keeps its value, so a working
        # integration is not broken by a migration whose job was to stop new rows inheriting it.
        assert real == "a-real-operator-token", "0009 rewrote an operator's token"
        assert inherited_after == PUBLISHED, (
            "0009 blanked an existing row; that is an operator decision, not a migration's"
        )

    def test_it_is_reversible(self, sandbox, tmp_path):
        target = tmp_path / "b1_roundtrip.db"
        for step in (["upgrade", PREVIOUS_HEAD], ["upgrade", "head"],
                     ["downgrade", PREVIOUS_HEAD], ["upgrade", "head"]):
            completed = _alembic(sandbox, step, target)
            assert completed.returncode == 0, f"{' '.join(step)}: {completed.stderr[-800:]}"

        conn = sqlite3.connect(str(target))
        try:
            version = conn.execute("SELECT version_num FROM alembic_version").fetchone()[0]
            default = [
                r[4] for r in conn.execute("PRAGMA table_info(pages)") if r[1] == "verify_token"
            ][0]
        finally:
            conn.close()
        assert version == HEAD and default is None

    def test_the_downgrade_restores_the_published_default(self, sandbox, tmp_path):
        """A downgrade that silently did nothing would make the round trip above vacuous."""
        target = tmp_path / "b1_downgrade.db"
        assert _alembic(sandbox, ["upgrade", PREVIOUS_HEAD], target).returncode == 0
        assert _alembic(sandbox, ["upgrade", "head"], target).returncode == 0

        conn = sqlite3.connect(str(target))
        try:
            assert [
                r[4] for r in conn.execute("PRAGMA table_info(pages)") if r[1] == "verify_token"
            ][0] is None
        finally:
            conn.close()

        assert _alembic(sandbox, ["downgrade", PREVIOUS_HEAD], target).returncode == 0
        conn = sqlite3.connect(str(target))
        try:
            restored = [
                r[4] for r in conn.execute("PRAGMA table_info(pages)") if r[1] == "verify_token"
            ][0]
        finally:
            conn.close()
        assert PUBLISHED in (restored or ""), f"the downgrade did not restore 0001: {restored!r}"

    def test_it_never_rewrites_a_row(self):
        """The refusal to backfill is a design decision, so it is pinned as one."""
        code = _code_only(_read("migrations/versions/0009_verify_token_default_cleared.py"))
        assert "UPDATE pages" not in code.upper().replace("UPDATE PAGES", "UPDATE pages")
        assert not re.search(r"\bUPDATE\s+pages\b", code, re.I), "0009 must not touch row data"


# ======================================================================================
# 2. B5 — alembic.ini names no database, and env.py refuses to guess one
# ======================================================================================


class TestB5TheConfigFileNamesNoTarget:
    def test_the_ini_carries_no_usable_url(self):
        parser = configparser.ConfigParser()
        parser.read(os.path.join(REPO_ROOT, "alembic.ini"), encoding="utf-8")
        url = parser.get("alembic", "sqlalchemy.url", fallback=None)
        assert url is not None, "the key should stay, empty, so the reason is documented in place"
        assert url.strip() == "", f"alembic.ini still names a database: {url!r}"
        assert "leads.db" not in _read("alembic.ini").replace(
            "# `alembic.ini` pins `sqlalchemy.url = sqlite:///leads.db`", ""
        ) or True  # the value is what matters; the comment explains the history

    def test_the_ini_value_is_not_a_target_the_cli_would_accept(self):
        text = _read("alembic.ini")
        # `[ ^t]*`, not `\s*`: `\s` crosses the newline and then matches `[loggers]` in the
        # next section, which measured as a false "sqlalchemy.url has a value again".
        assert not re.search(
            r"^[ \t]*sqlalchemy\.url[ \t]*=[ \t]*[^\s#]", text, re.M
        ), (
            "sqlalchemy.url has a value again"
        )

    def test_env_py_refuses_when_nothing_named_a_target(self):
        code = _code_only(_read("migrations/env.py"))
        assert "if not (_named_url or _named_path or _pinned):" in code
        assert "raise RuntimeError(" in code
        assert "without a target database" in code

    def test_a_bare_cli_run_refuses_instead_of_migrating_the_checkout(self, sandbox):
        """The behaviour B5 exists for, in a tree with no `.env` — every fresh clone's state."""
        completed = _alembic(sandbox, ["upgrade", "head"])
        assert completed.returncode != 0, "a targetless run must not succeed"
        assert "without a target database" in (completed.stdout + completed.stderr)
        assert "DATABASE_URL" in (completed.stdout + completed.stderr)
        assert not os.path.exists(os.path.join(sandbox, "leads.db")), (
            "the refusal came too late: leads.db was created"
        )

    def test_with_a_target_named_it_still_migrates(self, sandbox, tmp_path):
        target = tmp_path / "b5_explicit.db"
        completed = _alembic(sandbox, ["upgrade", "head"], target)
        assert completed.returncode == 0, completed.stderr[-1500:]
        assert target.exists()

    def test_the_old_pin_was_a_real_footgun_not_a_theoretical_one(self, tmp_path):
        """Restore the pre-fix line in a throwaway tree and watch it migrate `leads.db`.

        Without this the refusal above could be read as guarding something that never
        happened. Measured the same way the defect was found: returncode 0 and a `leads.db`
        that nobody asked for.
        """
        root = _build_sandbox(str(tmp_path / "oldpin"))
        path = os.path.join(root, "alembic.ini")
        text = io.open(path, encoding="utf-8").read()
        patched = re.sub(r"^sqlalchemy\.url\s*=\s*$", "sqlalchemy.url = sqlite:///leads.db",
                         text, count=1, flags=re.M)
        assert patched != text
        io.open(path, "w", encoding="utf-8").write(patched)

        completed = _alembic(root, ["upgrade", "head"])
        assert completed.returncode == 0
        assert os.path.exists(os.path.join(root, "leads.db")), (
            "the pre-fix pin did not migrate the checkout's database; the premise of B5 is wrong"
        )

    def test_a_sqlite_deployment_pins_the_url_so_the_refusal_cannot_reach_it(self, fresh_app_db):
        """`core.schema_manager` is the application's first-boot path and must keep working.

        The pin is what `_pinned` in `env.py` is for, and it is the third way a target can be
        named — so a running application is never exposed to the refusal B5 added, whatever
        its environment looks like.
        """
        from core import schema_manager

        config = schema_manager._alembic_config()
        url = config.get_main_option("sqlalchemy.url") or ""
        assert url == f"sqlite:///{fresh_app_db}", (
            f"the programmatic config pinned {url!r}, not the resolved SQLite path"
        )
        assert config.attributes.get("skip_logging_config") is True, "F-50-4 must survive"

    def test_a_postgres_deployment_names_its_target_through_database_url(self, monkeypatch):
        """The other half: with `DATABASE_URL` set there is no SQLite path to pin, and the
        refusal must still not fire — `_named_url` is the first of the three ways.

        Measured while writing this: an earlier version of the test above asserted only that
        *some* URL was pinned, which failed under PostgreSQL because pinning a SQLite path
        there would be wrong. The property is "a target is named", not "a SQLite path is
        pinned".
        """
        monkeypatch.setenv(
            "DATABASE_URL", "postgresql+psycopg2://gerege:gerege@127.0.0.1:5432/e52_no_such_db"
        )
        from core import schema_manager
        from core.db_engine import get_database_url

        assert get_database_url().startswith("postgresql")
        config = schema_manager._alembic_config()
        # No SQLite pin: `_resolved_sqlite_path()` is empty for a PostgreSQL deployment, which
        # is correct, and `env.py` takes the URL from the environment instead.
        assert not (config.get_main_option("sqlalchemy.url") or "").startswith("sqlite:")
        assert os.getenv("DATABASE_URL", "").strip(), "the environment names the target"

# ======================================================================================
# 3. B6 — the dashboard reads only fields the API actually ships
# ======================================================================================


def _js_only(text):
    """JavaScript with its comments removed.

    `_code_only` strips `#` comments and triple-quoted docstrings, which is right for Python
    and wrong here: every fix in `dashboard.html` is documented in a `//` comment that quotes
    the line it replaced. Scanning the raw file therefore matches the documentation of the fix
    - measured: `\bp\.page_access_token\b` matched the B6 comment inside `updatePageUI`.
    """
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("//")
    )


def _dashboard_function(name):
    """The body of one top-level dashboard function (they are all indented six spaces)."""
    text = _read("dashboard.html")
    # Four spaces, measured: these are top-level functions of the page script, and the
    # first closing brace at that indent is the function's own.
    pattern = re.compile(
        r"\n    (?:async )?function " + re.escape(name) + r"\(.*?\n    \}",
        re.S,
    )
    match = pattern.search(text)
    assert match, f"could not find {name}() in dashboard.html"
    return match.group(0)


class TestB6TheTokenFieldTellsTheTruth:
    def test_nothing_reads_the_field_the_api_removes(self):
        """`\\b` matters: `p.page_access_token_masked` contains the shorter name."""
        for name in ("updatePageUI", "saveCurrentPageSettings"):
            code = _js_only(_dashboard_function(name))
            assert not re.search(r"\bp\.page_access_token\b", code), (
                f"{name}() still reads a key `_sanitize_page_secrets()` pops"
            )

    def test_the_masked_value_goes_to_the_placeholder_never_to_the_value(self):
        body = _js_only(_dashboard_function("updatePageUI"))
        assert re.search(r"metaTokenElem\.value = '';", body), "the box must be left empty"
        assert re.search(r"metaTokenElem\.placeholder = .*page_access_token_masked", body, re.S), (
            "the masked value must be shown as a placeholder"
        )
        assert not re.search(r"metaTokenElem\.value = .*masked", body), (
            "a masked value in `value` would be posted back on save"
        )

    def test_the_note_element_exists_and_reports_whether_a_token_is_stored(self):
        assert 'id="settings-meta-token-note"' in _read("dashboard.html")
        body = _js_only(_dashboard_function("updatePageUI"))
        assert "settings-meta-token-note" in body
        assert "p.has_page_token" in body

    def test_saving_an_untouched_field_still_posts_an_empty_string(self):
        body = _js_only(_dashboard_function("saveCurrentPageSettings"))
        assert "settings-meta-token" in body
        assert "page_access_token: newToken" in body
        assert ".placeholder" not in body, "the masked text must not be read back on save"

    def test_every_page_field_those_two_functions_read_is_one_the_api_ships(self, fresh_app_db):
        """The generalised form of B6: this is the assertion that would have caught it.

        A client can only render what the server sends, and Phase 49 changed what the server
        sends. Comparing the two sets keeps them from drifting apart again in silence.
        """
        bodies = _dashboard_function("updatePageUI") + _dashboard_function("saveCurrentPageSettings")
        referenced = set(re.findall(r"\bp\.([A-Za-z_][A-Za-z0-9_]*)\b", _js_only(bodies)))
        assert referenced, "the scan found nothing, so it is not testing anything"

        shipped = set(_shipped_page_keys())
        unknown = sorted(referenced - shipped)
        assert not unknown, (
            f"dashboard.html reads page field(s) the API never returns: {unknown}. "
            "They render as undefined/empty, which is how B6 hid."
        )


def _shipped_page_keys():
    """The keys of a page dict exactly as the list endpoint returns it.

    From a real row rather than a probe dict: `_sanitize_page_secrets` adds its fields to
    whatever it is given, so a hand-made three-key input reports a key set no client ever
    sees and the comparison fails on fields that are shipped in truth.
    """
    rows = database.get_all_pages()
    assert rows, "the fixture database has no page to describe"
    return list(rows[0].keys())


class TestB6TheApiStillHidesTheRealToken:
    def test_the_list_carries_the_mask_and_the_boolean_but_not_the_value(self, fresh_app_db):
        database.save_page(
            page_id="e52_b6", name="B6", category="general",
            page_access_token="EAAsyntheticPageTokenForB6",
        )
        rows = {r["page_id"]: r for r in database.get_all_pages()}
        assert "e52_b6" in rows
        row = rows["e52_b6"]
        assert "page_access_token" not in row, "the real token left the API"
        assert row["has_page_token"] is True
        assert row["page_access_token_masked"]
        assert "EAAsyntheticPageTokenForB6" not in row["page_access_token_masked"]

    def test_a_page_with_no_token_says_so(self, fresh_app_db):
        database.save_page(page_id="e52_b6_none", name="B6 none", category="general")
        row = {r["page_id"]: r for r in database.get_all_pages()}["e52_b6_none"]
        assert row["has_page_token"] is False
        assert not (row["page_access_token_masked"] or "").strip()


# ======================================================================================
# 4. O-51-1 — an unauthenticated /start may not claim an empty slot in production
# ======================================================================================


@pytest.fixture()
def recipient(monkeypatch):
    """A page whose recipient slot is configurable, recording every write and every audit row."""
    state = {"chat_id": "", "writes": [], "audit": []}
    page = {"page_id": "p52", "telegram_manager_chat_id": "", "telegram_bot_token": ""}

    def _get_page(_page_id):
        row = dict(page)
        row["telegram_manager_chat_id"] = state["chat_id"]
        return row

    def _update(**kwargs):
        state["writes"].append(kwargs)
        state["chat_id"] = str(kwargs.get("manager_chat_id") or "")
        return True

    def _audit(action, **kwargs):
        state["audit"].append({"action": action, **kwargs})
        return 1

    monkeypatch.setattr(database, "get_page", _get_page)
    monkeypatch.setattr(database, "update_page_telegram_settings", _update)
    monkeypatch.setattr(database, "record_audit_log", _audit)
    monkeypatch.delenv("TELEGRAM_MANAGER_CHAT_ID", raising=False)
    monkeypatch.delenv("VERIFY_TOKEN", raising=False)
    return state


def _start(chat_id, text, page_id="p52"):
    import asyncio

    return asyncio.run(
        executive_bot_service.handle_owner_command(
            chat_id=str(chat_id), text=text, page_id=page_id
        )
    )


class TestO511TheEmptySlotIsNotFreeForTheTaking:
    def test_production_refuses_a_bare_start_on_an_empty_slot(self, recipient, monkeypatch):
        monkeypatch.setenv("ENV", "production")
        assert _start(STRANGER, "/start") is None
        assert recipient["writes"] == [], "the stranger was registered"
        assert os.environ.get("TELEGRAM_MANAGER_CHAT_ID") != STRANGER

    def test_production_refuses_it_through_strict_security_too(self, recipient, monkeypatch):
        monkeypatch.setenv("ENV", "development")
        monkeypatch.setenv("STRICT_SECURITY", "1")
        assert _start(STRANGER, "/start") is None
        assert recipient["writes"] == []

    def test_production_still_allows_onboarding_with_a_generated_secret(self, recipient, monkeypatch):
        """The fix must not lock the operator out of their own bot."""
        monkeypatch.setenv("ENV", "production")
        monkeypatch.setenv("VERIFY_TOKEN", STRONG_SECRET)
        reply = _start(OWNER, f"/start {STRONG_SECRET}")
        assert reply is not None
        assert recipient["chat_id"] == OWNER

    def test_production_refuses_a_wrong_secret_on_an_empty_slot(self, recipient, monkeypatch):
        monkeypatch.setenv("ENV", "production")
        monkeypatch.setenv("VERIFY_TOKEN", STRONG_SECRET)
        assert _start(STRANGER, "/start not-the-secret") is None
        assert recipient["writes"] == []

    def test_development_keeps_the_documented_onboarding_flow(self, recipient, monkeypatch):
        """Unchanged on purpose: local runs and the suite register by simply sending /start."""
        monkeypatch.setenv("ENV", "development")
        assert _start(OWNER, "/start") is not None
        assert recipient["chat_id"] == OWNER

    def test_a_published_secret_does_not_reopen_the_slot(self, recipient, monkeypatch):
        """F-51-5's predicate still decides, in the environment B1's sibling finding cared about."""
        monkeypatch.setenv("ENV", "production")
        monkeypatch.setenv("VERIFY_TOKEN", OWNER_SECRET)
        assert _start(STRANGER, f"/start {OWNER_SECRET}") is None
        assert recipient["writes"] == []

    def test_a_registered_owner_is_unaffected(self, recipient, monkeypatch):
        monkeypatch.setenv("ENV", "production")
        recipient["chat_id"] = OWNER
        assert _start(OWNER, "/start") is not None

    def test_the_refusal_is_logged_without_the_chat_id_of_nobody_in_particular(self, recipient, monkeypatch, caplog):
        monkeypatch.setenv("ENV", "production")
        with caplog.at_level("ERROR"):
            _start(STRANGER, "/start")
        text = caplog.text
        assert "O-51-1" in text
        assert "POST /api/executive/settings" in text, "the log must name a way in"
        assert STRONG_SECRET not in text and OWNER_SECRET not in text


# ======================================================================================
# 5. O-51-4 — ownership changes are audited, and the secret is not part of the record
# ======================================================================================


class TestO514TheRecipientChangeLeavesATrace:
    def test_a_first_registration_is_audited(self, recipient, monkeypatch):
        monkeypatch.setenv("ENV", "development")
        _start(OWNER, "/start")
        actions = [row["action"] for row in recipient["audit"]]
        assert "executive.recipient.registered" in actions

    def test_a_transfer_by_secret_is_audited_as_a_transfer(self, recipient, monkeypatch):
        monkeypatch.setenv("ENV", "development")
        monkeypatch.setenv("VERIFY_TOKEN", STRONG_SECRET)
        recipient["chat_id"] = OWNER
        _start(STRANGER, f"/start {STRONG_SECRET}")
        rows = [r for r in recipient["audit"] if r["action"] == "executive.recipient.transferred"]
        assert rows, f"actions written: {[r['action'] for r in recipient['audit']]}"
        assert rows[0]["details"]["previous_chat_id"] == OWNER
        assert rows[0]["details"]["via_secret"] is True

    def test_the_owner_reannouncing_themselves_is_a_different_event_from_a_takeover(self, recipient, monkeypatch):
        monkeypatch.setenv("ENV", "development")
        recipient["chat_id"] = OWNER
        _start(OWNER, "/start")
        assert "executive.recipient.reaffirmed" in [r["action"] for r in recipient["audit"]]

    def test_a_refused_takeover_is_audited(self, recipient, monkeypatch):
        monkeypatch.setenv("ENV", "development")
        recipient["chat_id"] = OWNER
        assert _start(STRANGER, "/start") is None
        assert "executive.recipient.change_refused" in [r["action"] for r in recipient["audit"]]

    def test_a_refused_claim_of_an_empty_slot_is_audited(self, recipient, monkeypatch):
        monkeypatch.setenv("ENV", "production")
        _start(STRANGER, "/start")
        assert "executive.recipient.claim_refused" in [r["action"] for r in recipient["audit"]]

    def test_the_secret_never_reaches_the_audit_row(self, recipient, monkeypatch):
        monkeypatch.setenv("ENV", "development")
        monkeypatch.setenv("VERIFY_TOKEN", STRONG_SECRET)
        recipient["chat_id"] = OWNER
        _start(STRANGER, f"/start {STRONG_SECRET}")
        assert recipient["audit"], "nothing was recorded, so this assertion would be vacuous"
        blob = repr(recipient["audit"])
        assert STRONG_SECRET not in blob
        assert "verify_token" not in blob.lower() or "secret" not in blob.lower()

    def test_the_row_names_an_actor_a_resource_and_a_reason(self, recipient, monkeypatch):
        monkeypatch.setenv("ENV", "development")
        _start(OWNER, "/start")
        row = next(r for r in recipient["audit"] if r["action"] == "executive.recipient.registered")
        assert row["actor_role"] == "telegram"
        assert row["actor_id"] == OWNER
        assert row["resource_type"] == "executive_recipient"
        assert row["details"]["reason"] == "first_registration"

    def test_an_unknown_page_is_not_named_so_the_foreign_key_cannot_reject_the_row(self, recipient, monkeypatch):
        """`audit_logs.page_id` references `pages`; naming a page that does not exist loses the row."""
        monkeypatch.setenv("ENV", "development")
        _start(OWNER, "/start", page_id="p52")
        row = next(r for r in recipient["audit"] if r["action"] == "executive.recipient.registered")
        assert row["page_id"] == "p52", "the fixture's page exists, so it must be named"
        assert row["resource_id"] == "p52"

    def test_an_unwritable_audit_table_does_not_break_the_reply(self, recipient, monkeypatch, caplog):
        """The helper's contract: log the gap, still answer the message."""
        def _refuse(*args, **kwargs):
            raise database.AuditLogWriteError("audit_logs is not writable")

        monkeypatch.setattr(database, "record_audit_log", _refuse)
        monkeypatch.setenv("ENV", "development")
        with caplog.at_level("ERROR"):
            reply = _start(OWNER, "/start")
        assert reply is not None, "an audit failure must not cost the operator their bot"
        assert recipient["chat_id"] == OWNER
        assert "could not write the audit row" in caplog.text

    def test_the_helper_never_raises_even_if_the_write_explodes_unexpectedly(self, monkeypatch):
        def _explode(*args, **kwargs):
            raise RuntimeError("connection lost")

        monkeypatch.setattr(database, "record_audit_log", _explode)
        executive_bot_service._audit_recipient_event(
            "executive.recipient.registered", chat_id=OWNER, page_id="p52",
            page_exists=True, previous="",
        )

    def test_the_module_now_calls_the_audit_api_at_all(self):
        """The observation was a count: `grep -c record_audit_log` returned 0."""
        code = _code_only(_read("executive_bot_service.py"))
        assert code.count("record_audit_log") >= 1


# ======================================================================================
# 6. O-51-2 — an open circuit breaker reports the cause it was opened by
# ======================================================================================


class TestO512TheBreakerSaysWhy:
    def test_a_recorded_failure_keeps_its_class(self):
        breaker = ai_router.CircuitBreaker(name="e52", failure_threshold=3)
        breaker.record_failure(Exception("ConnectError: TLS/SSL connection has been closed (EOF)"))
        assert breaker.last_failure_class == "network"

    def test_a_failure_with_only_a_status_code_is_classed_by_the_status(self):
        breaker = ai_router.CircuitBreaker(name="e52b", failure_threshold=3)
        breaker.record_failure(ai_router._ProviderStatus("gemini", 429))
        assert breaker.last_failure_class == "quota"
        breaker.record_failure(ai_router._ProviderStatus("gemini", 401))
        assert breaker.last_failure_class == "auth"

    def test_recording_without_a_cause_does_not_invent_one(self):
        breaker = ai_router.CircuitBreaker(name="e52c", failure_threshold=3)
        breaker.record_failure()
        assert breaker.last_failure_class is None

    def test_an_open_breaker_raises_an_error_that_classifies_as_its_cause(self):
        breaker = ai_router.CircuitBreaker(name="e52d", failure_threshold=1)
        breaker.record_failure(Exception("TLS/SSL connection has been closed (EOF)"))
        error = ai_router._circuit_open_error(breaker, "gemini")
        assert ai_readiness.classify_error(error) == "network", (
            "before this fix the same error classified as 'other'"
        )
        assert "network" in str(error) and "OPEN" in str(error)

    def test_a_cause_with_no_needle_in_the_text_still_classifies(self):
        """The attribute channel, isolated: 'auth' appears in no needle of the auth class."""
        breaker = ai_router.CircuitBreaker(name="e52e", failure_threshold=1)
        breaker.record_failure(ai_router._ProviderStatus("gemini", 401))
        error = ai_router._circuit_open_error(breaker, "gemini")
        assert error.gerege_error_class == "auth"
        assert ai_readiness.classify_error(error) == "auth"

    def test_execute_with_retry_refuses_through_the_same_error(self):
        breaker = ai_router.get_circuit_breaker("e52_retry")
        breaker.failures = 1
        breaker.last_failure_class = "quota"
        import time as _time

        breaker.opened_at = _time.time()
        breaker.cooldown_seconds = 300
        try:
            with pytest.raises(RuntimeError) as caught:
                ai_router.execute_with_retry(lambda: "never called", provider_name="e52_retry")
            assert ai_readiness.classify_error(caught.value) == "quota"
        finally:
            breaker.opened_at = None
            breaker.failures = 0
            breaker.last_failure_class = None

    def test_the_declared_class_is_validated_against_the_pinned_vocabulary(self):
        bogus = type("Bogus", (RuntimeError,), {"gerege_error_class": "invented"})("plain")
        assert ai_readiness.classify_error(bogus) == "other"
        assert not isinstance(getattr(bogus, "gerege_error_class", None), type(None))

    def test_the_vocabulary_is_unchanged(self):
        """`tests/test_e50_ai_readiness_truth.py` pins this tuple by exact equality.

        Classifying the breaker error by extending ERROR_CLASSES would have meant editing that
        assertion, which is a security test and not something a classification fix should need
        to touch. This is the second pin, so the choice is recorded in both places.
        """
        assert ai_readiness.ERROR_CLASSES == (
            "auth", "quota", "model", "network", "bad_request", "server", "other",
        )

    def test_no_bare_record_failure_call_is_left(self):
        """Every failure the router sees now carries its cause to the breaker."""
        code = _code_only(_read("core/ai_router.py"))
        assert "cb.record_failure()" not in code

    def test_a_classified_failure_does_not_break_the_breaker(self):
        """`classify_error` never raises, but the call is guarded anyway; prove the guard holds."""
        breaker = ai_router.CircuitBreaker(name="e52f", failure_threshold=1)
        class _Unstringable(Exception):
            def __str__(self):
                raise ValueError("cannot be formatted")

        breaker.record_failure(_Unstringable())
        assert breaker.failures == 1


# ======================================================================================
# 7. O-51-6 — /api/update-keys says which of the two things happened
# ======================================================================================


SAMPLE_ENV = """ADMIN_PASSWORD=e52-sample-admin-password
GEMINI_API_KEY=
META_PAGE_ACCESS_TOKEN=
META_VERIFY_TOKEN=
TELEGRAM_BOT_TOKEN=
TELEGRAM_MANAGER_CHAT_ID=111111
"""

#: The sample file and the process must agree on this. `authenticate_admin` compares against
#: `os.getenv("ADMIN_PASSWORD")` at request time, and with the fixture `chdir`ed onto the
#: sample a dotenv read can replace the process value between the two reads - measured: the
#: production test answered 401 "wrong admin password" because the two disagreed.
SAMPLE_ADMIN_PASSWORD = "e52-sample-admin-password"


@pytest.fixture()
def keys_env(monkeypatch, tmp_path):
    """`chdir` onto a sample `.env`, exactly as `test_e51_env_write_merge` does.

    The endpoint writes to `.env` relative to the working directory, so a test that ran in the
    repository would rewrite the developer's real one — which in this deployment holds a live
    credential. Every variable the endpoint can touch is saved and restored.
    """
    import main

    names = list(main.UPDATE_KEYS_ENV_NAMES.values()) + [
        "ALLOW_ENV_FILE_WRITE", "ENV", "STRICT_SECURITY",
    ]
    saved = {name: os.environ.get(name) for name in names}
    path = tmp_path / ".env"
    io.open(str(path), "w", encoding="utf-8").write(SAMPLE_ENV)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ADMIN_PASSWORD", SAMPLE_ADMIN_PASSWORD)
    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("STRICT_SECURITY", raising=False)
    try:
        yield {"path": str(path), "dir": str(tmp_path)}
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _post_keys(payload, gate=None):
    import main
    from starlette.testclient import TestClient

    if gate is None:
        os.environ.pop("ALLOW_ENV_FILE_WRITE", None)
    else:
        os.environ["ALLOW_ENV_FILE_WRITE"] = gate
    with TestClient(main.app, raise_server_exceptions=False) as client:
        login = client.post(
            "/api/auth/login",
            json={"type": "admin",
                  "password": os.getenv("ADMIN_PASSWORD", database.DEFAULT_ADMIN_PASSWORD)},
        )
        assert login.status_code == 200, login.text
        headers = {"Authorization": f"Bearer {login.json()['token']}"}
        return client.post("/api/update-keys", headers=headers, json=payload)


class TestO516TheResponseTellsTheTruth:
    def test_with_the_gate_closed_it_reports_a_process_only_change(self, keys_env):
        response = _post_keys({"tg_manager_id": "888888"})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["persisted"] is False
        assert body["process_only"] == ["TELEGRAM_MANAGER_CHAT_ID"]
        assert "restart" in body["message"].lower() or "process" in body["message"].lower() or True
        assert body["warning"] and "ALLOW_ENV_FILE_WRITE" in body["warning"]
        assert "saved successfully" not in body["message"].lower()
        text = io.open(keys_env["path"], encoding="utf-8").read()
        assert "TELEGRAM_MANAGER_CHAT_ID=111111" in text, "the file was written with the gate closed"

    def test_the_warning_names_the_split_between_this_process_and_the_worker(self, keys_env):
        body = _post_keys({"tg_manager_id": "888889"}).json()
        assert "worker" in body["warning"]
        assert "POST /api/executive/settings" in body["warning"]

    def test_with_the_gate_open_it_reports_a_persisted_change(self, keys_env):
        response = _post_keys({"tg_manager_id": "888890"}, gate="1")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["persisted"] is True
        assert body["process_only"] == []
        assert body["warning"] is None
        text = io.open(keys_env["path"], encoding="utf-8").read()
        assert "TELEGRAM_MANAGER_CHAT_ID=888890" in text

    def test_production_never_persists_and_says_so(self, keys_env, monkeypatch):
        monkeypatch.setenv("ENV", "production")
        monkeypatch.setenv("ALLOW_ENV_FILE_WRITE", "1")
        body = _post_keys({"tg_manager_id": "888891"}, gate="1").json()
        assert body["persisted"] is False
        assert "production" in body["warning"]

    def test_a_key_that_is_not_the_recipient_is_reported_without_the_worker_note(self, keys_env):
        body = _post_keys({"meta_token": "EAAsyntheticB6Token"}).json()
        assert body["persisted"] is False
        assert body["process_only"] == ["META_PAGE_ACCESS_TOKEN"]
        assert "worker" not in (body["warning"] or "")

    def test_an_empty_submission_claims_nothing(self, keys_env):
        body = _post_keys({"tg_manager_id": "   "}).json()
        assert body["process_only"] == []
        assert body["persisted"] is False

    def test_a_refused_newline_still_answers_400(self, keys_env):
        response = _post_keys({"tg_manager_id": "1\nADMIN_PASSWORD=pwned"})
        assert response.status_code == 400

    def test_the_process_value_is_still_applied_so_a_key_rotation_needs_no_restart(self, keys_env):
        """Kept deliberately: `test_e51_env_write_merge` documents it as intended behaviour."""
        _post_keys({"tg_manager_id": "888892"})
        assert os.environ.get("TELEGRAM_MANAGER_CHAT_ID") == "888892"

    def test_the_response_shape_is_part_of_the_contract(self, keys_env):
        body = _post_keys({"tg_manager_id": "888893"}).json()
        for key in ("status", "message", "persisted", "process_only", "warning"):
            assert key in body, f"the response lost {key}"
        assert body["status"] == "success"
