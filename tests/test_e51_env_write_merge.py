"""Phase 51 — F-51-3: `POST /api/update-keys` truncated `.env` instead of updating it.

The endpoint ended with::

    keys_map = {                                   # exactly 8 fixed keys
        "GEMINI_API_KEY": ..., "GEMINI_MODEL": ..., "META_PAGE_ACCESS_TOKEN": ...,
        "META_VERIFY_TOKEN": ..., "TELEGRAM_BOT_TOKEN": ..., "TELEGRAM_MANAGER_CHAT_ID": ...,
        "ADMIN_PASSWORD": ..., "PORT": ...,
    }
    with open(".env", "w", encoding="utf-8") as f:
        for k, v in keys_map.items():
            f.write(f"{k}={v}\\n")

`"w"` truncates. Measured against this repository's own `.env` (171 lines, 42 keys, 112
comment lines, mode 0600) by replaying that exact statement sequence: the result was a
**9-line, 8-key file with no comments**. Saving one field in the dashboard therefore deleted
`DATABASE_URL`, `DB_PATH`, `CSV_PATH`, `REDIS_URL`, `ALLOWED_ORIGINS`, `TRUSTED_PROXIES`,
`E02_ACCOUNT_KEY_SECRET`, `MANYCHAT_WEBHOOK_SECRET`, `VERIFY_TOKEN` and the whole `BACKUP_*`
block — 34 keys. The next restart came up on SQLite with no shared rate-limit store, no
account-key secret (the limiter silently degrades to a per-worker counter), no ManyChat
webhook secret, no owner-command secret and no offsite backup configuration, and the file
could no longer be read as documentation because every comment was gone.

It also wrote two keys the endpoint does not accept as input (`GEMINI_MODEL`, `PORT`),
inventing them from process defaults, and wrote `ADMIN_PASSWORD` from
`database.DEFAULT_ADMIN_PASSWORD` when unset — putting the published default *into* a file.

Two smaller defects rode along and are fixed with it:

* the comparison/write was not atomic, so a reader (or a restart) could observe a
  half-written `.env`;
* a value containing a newline was written verbatim, so a payload of
  `"x\\nADMIN_PASSWORD=pwned"` appended a second assignment nobody submitted. The payload
  arrives over HTTP, so that is attacker-shaped input even though the caller is an
  authenticated admin.

`merge_env_file` now writes only the keys this request submitted, preserves every other line
byte for byte, keeps the file's mode, and refuses a newline. The gate that decides *whether*
to write at all (not production, `ALLOW_ENV_FILE_WRITE=1`) is unchanged.

Every test here was run against the pre-fix code where that was possible: the endpoint tests
failed because the file came back with 8 keys, and `merge_env_file` did not exist to import.
"""

import io
import os
import re
import stat
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import database  # noqa: E402
import main  # noqa: E402

#: The shape of the repository's own `.env`: a key the endpoint writes, keys it does not,
#: comments, and a blank line. Values are synthetic.
SAMPLE = """# --- AI Provider ---
# GEMINI_API_KEY — the platform AI credential.
GEMINI_API_KEY=old-platform-key
GEMINI_MODEL=gemini-3.5-flash-lite
TELEGRAM_BOT_TOKEN=123456:ABC-old
META_VERIFY_TOKEN=old-meta-verify

# --- Not written by this endpoint, and must survive it ---
DATABASE_URL=postgresql+psycopg2://gerege_app:synthetic@127.0.0.1:5432/gerege
REDIS_URL=redis://127.0.0.1:6379/0
E02_ACCOUNT_KEY_SECRET=c2VjcmV0LXN5bnRoZXRpYy12YWx1ZS1ub3QtYS1rZXk
MANYCHAT_WEBHOOK_SECRET=bWMtc3ludGhldGljLXZhbHVlLW5vdC1hLWtleQ
VERIFY_TOKEN=b3duZXItc3ludGhldGljLXZhbHVlLW5vdC1hLWtleQ
BACKUP_ENCRYPTION=on
# TELEGRAM_MANAGER_CHAT_ID — where the executive report is sent.
TELEGRAM_MANAGER_CHAT_ID=111111
ADMIN_PASSWORD=old-admin-password
"""

WRITTEN_BY_THE_ENDPOINT = (
    "GEMINI_API_KEY",
    "META_PAGE_ACCESS_TOKEN",
    "META_VERIFY_TOKEN",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_MANAGER_CHAT_ID",
    "ADMIN_PASSWORD",
)


@pytest.fixture()
def env_file(tmp_path):
    """A dotenv file with the sample content, mode 0600, and a record of every line."""
    path = tmp_path / ".env"
    path.write_text(SAMPLE, encoding="utf-8")
    os.chmod(str(path), 0o600)
    return str(path)


def _keys(text):
    return {
        line.split("=", 1)[0].strip(): line.split("=", 1)[1]
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#") and "=" in line
    }


# --------------------------------------------------------------------------------------
# 1. The merge itself
# --------------------------------------------------------------------------------------


class TestMergeEnvFile:
    def test_one_key_changes_one_line_and_nothing_else(self, env_file):
        before = io.open(env_file, encoding="utf-8").read()
        report = main.merge_env_file({"TELEGRAM_BOT_TOKEN": "123456:ABC-new"}, path=env_file)
        after = io.open(env_file, encoding="utf-8").read()

        assert report["updated"] == ["TELEGRAM_BOT_TOKEN"]
        assert report["appended"] == []
        assert report["preserved"] == len(_keys(before)) - 1, (
            "preserved counts the keys this call did NOT touch"
        )

        changed = [
            (i, a, b)
            for i, (a, b) in enumerate(zip(after.splitlines(), before.splitlines()), 1)
            if a != b
        ]
        assert len(changed) == 1, f"exactly one line may differ: {changed}"
        assert changed[0][1:] == (
            "TELEGRAM_BOT_TOKEN=123456:ABC-new",
            "TELEGRAM_BOT_TOKEN=123456:ABC-old",
        ), f"and it must be the submitted key: {changed}"
        assert _keys(after)["TELEGRAM_BOT_TOKEN"] == "123456:ABC-new"

    def test_the_keys_the_old_code_deleted_are_still_there(self, env_file):
        """The whole finding, in one assertion: nothing outside the request is lost."""
        before = _keys(io.open(env_file, encoding="utf-8").read())
        main.merge_env_file({"GEMINI_API_KEY": "new-platform-key"}, path=env_file)
        after = _keys(io.open(env_file, encoding="utf-8").read())

        assert set(after) == set(before), "the key set must not change"
        for name, value in before.items():
            if name != "GEMINI_API_KEY":
                assert after[name] == value, f"{name} was destroyed by the write"

    def test_comments_and_blank_lines_survive(self, env_file):
        before = io.open(env_file, encoding="utf-8").read().splitlines()
        main.merge_env_file({"ADMIN_PASSWORD": "new-admin-password"}, path=env_file)
        after = io.open(env_file, encoding="utf-8").read().splitlines()
        assert [l for l in before if l.strip().startswith("#")] == [
            l for l in after if l.strip().startswith("#")
        ]
        assert before.count("") == after.count("")

    def test_the_file_mode_is_kept(self, env_file):
        os.chmod(env_file, 0o640)
        main.merge_env_file({"GEMINI_API_KEY": "x" * 24}, path=env_file)
        assert stat.S_IMODE(os.stat(env_file).st_mode) == 0o640

    def test_a_key_that_is_not_in_the_file_is_appended(self, env_file):
        before = io.open(env_file, encoding="utf-8").read()
        report = main.merge_env_file({"PORT": "8080"}, path=env_file)
        after = io.open(env_file, encoding="utf-8").read()
        assert report["appended"] == ["PORT"]
        assert report["updated"] == []
        assert after.startswith(before.rstrip("\n"))
        assert _keys(after)["PORT"] == "8080"

    def test_several_keys_at_once(self, env_file):
        report = main.merge_env_file(
            {"GEMINI_API_KEY": "k1", "META_VERIFY_TOKEN": "k2", "PORT": "k3"}, path=env_file
        )
        assert report["updated"] == ["GEMINI_API_KEY", "META_VERIFY_TOKEN"]
        assert report["appended"] == ["PORT"]
        keys = _keys(io.open(env_file, encoding="utf-8").read())
        assert keys["GEMINI_API_KEY"] == "k1"
        assert keys["META_VERIFY_TOKEN"] == "k2"
        assert keys["PORT"] == "k3"

    def test_the_last_assignment_of_a_repeated_key_wins(self, env_file):
        """dotenv keeps the last one, so the merge must edit the last one and not add a third."""
        with io.open(env_file, "a", encoding="utf-8") as fh:
            fh.write("PORT=1\nPORT=2\n")
        main.merge_env_file({"PORT": "3"}, path=env_file)
        text = io.open(env_file, encoding="utf-8").read()
        assert text.count("PORT=") == 2
        assert _keys(text)["PORT"] == "3"

    def test_a_commented_out_key_is_not_treated_as_an_assignment(self, env_file):
        """`# PORT=8000` documents a key; writing must append, not edit the comment."""
        with io.open(env_file, "a", encoding="utf-8") as fh:
            fh.write("# PORT=8000\n")
        report = main.merge_env_file({"PORT": "9000"}, path=env_file)
        text = io.open(env_file, encoding="utf-8").read()
        assert report["appended"] == ["PORT"]
        assert "# PORT=8000" in text
        assert _keys(text)["PORT"] == "9000"

    @pytest.mark.parametrize("value", ["x\nADMIN_PASSWORD=pwned", "x\r\nPORT=1", "a\nb"])
    def test_a_newline_in_a_value_is_refused(self, env_file, value):
        """It would append an assignment nobody submitted."""
        before = io.open(env_file, encoding="utf-8").read()
        with pytest.raises(ValueError) as exc:
            main.merge_env_file({"GEMINI_API_KEY": value}, path=env_file)
        assert "newline" in str(exc.value)
        assert "GEMINI_API_KEY" in str(exc.value)
        assert value.strip() not in str(exc.value), "the refused value must not be echoed"
        assert io.open(env_file, encoding="utf-8").read() == before, "the file must be untouched"

    def test_one_bad_value_means_nothing_is_written(self, env_file):
        """Validation happens before the write, not per key."""
        before = io.open(env_file, encoding="utf-8").read()
        with pytest.raises(ValueError):
            main.merge_env_file({"GEMINI_API_KEY": "fine", "PORT": "1\nX=2"}, path=env_file)
        assert io.open(env_file, encoding="utf-8").read() == before

    def test_a_missing_file_is_an_error_not_a_creation(self, tmp_path):
        """Creating a brand new `.env` from one submitted key is the same loss in reverse."""
        absent = str(tmp_path / "no-such.env")
        with pytest.raises(FileNotFoundError):
            main.merge_env_file({"PORT": "1"}, path=absent)
        assert not os.path.exists(absent)

    def test_an_empty_update_leaves_the_file_byte_identical(self, env_file):
        before = io.open(env_file, encoding="utf-8").read()
        report = main.merge_env_file({}, path=env_file)
        assert report == {
            "path": env_file,
            "updated": [],
            "appended": [],
            "preserved": len(_keys(before)),
            "mode": "0o600",
        }
        assert io.open(env_file, encoding="utf-8").read() == before

    def test_no_temporary_file_is_left_behind(self, env_file):
        directory = os.path.dirname(env_file)
        main.merge_env_file({"PORT": "1"}, path=env_file)
        with pytest.raises(ValueError):
            main.merge_env_file({"PORT": "1\nX=2"}, path=env_file)
        assert sorted(os.listdir(directory)) == [".env"]

    def test_a_value_is_written_verbatim_including_equals_signs(self, env_file):
        """Base64 and URL-shaped secrets contain `=`; only the first one separates."""
        value = "abc=def==ghi"
        main.merge_env_file({"GEMINI_API_KEY": value}, path=env_file)
        assert _keys(io.open(env_file, encoding="utf-8").read())["GEMINI_API_KEY"] == value


# --------------------------------------------------------------------------------------
# 2. The endpoint
# --------------------------------------------------------------------------------------




@pytest.fixture()
def writable_env(monkeypatch, tmp_path, env_file):
    """`chdir` onto the sample file with the write gate open, and no global side effects.

    The endpoint mutates `os.environ` for the fields it accepts, so the values it could touch
    are saved and restored: a test that leaves `ADMIN_PASSWORD` or `GEMINI_API_KEY` behind
    would decide the outcome of every test that runs after it.
    """
    saved = {
        name: os.environ.get(name)
        for name in list(WRITTEN_BY_THE_ENDPOINT)
        + ["ALLOW_ENV_FILE_WRITE", "ENV", "STRICT_SECURITY", "GEMINI_MODEL", "PORT"]
    }
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ALLOW_ENV_FILE_WRITE", "1")
    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("STRICT_SECURITY", raising=False)
    try:
        yield env_file
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _post(payload):
    """Log in as the admin and post, in one client (one lifespan, not two)."""
    from starlette.testclient import TestClient

    with TestClient(main.app, raise_server_exceptions=False) as client:
        login = client.post(
            "/api/auth/login",
            json={
                "type": "admin",
                "password": os.getenv("ADMIN_PASSWORD", database.DEFAULT_ADMIN_PASSWORD),
            },
        )
        assert login.status_code == 200, login.text
        headers = {"Authorization": f"Bearer {login.json()['token']}"}
        return client.post("/api/update-keys", headers=headers, json=payload)


class TestTheEndpoint:
    def test_saving_one_field_keeps_every_other_setting(self, writable_env):
        before = _keys(io.open(writable_env, encoding="utf-8").read())
        response = _post({"tg_manager_id": "222222"})
        assert response.status_code == 200, response.text

        after = _keys(io.open(writable_env, encoding="utf-8").read())
        assert after["TELEGRAM_MANAGER_CHAT_ID"] == "222222"
        assert set(after) >= set(before), "no key may disappear"
        for name, value in before.items():
            if name != "TELEGRAM_MANAGER_CHAT_ID":
                assert after[name] == value, f"{name} was destroyed by saving one field"
        assert os.environ.get("TELEGRAM_MANAGER_CHAT_ID") == "222222"

    def test_the_keys_the_endpoint_does_not_accept_are_not_invented(self, writable_env):
        """The old code wrote GEMINI_MODEL and PORT from process defaults."""
        before = io.open(writable_env, encoding="utf-8").read()
        _post({"tg_manager_id": "333333"})
        after = io.open(writable_env, encoding="utf-8").read()
        assert after.count("GEMINI_MODEL=") == before.count("GEMINI_MODEL=")
        assert "PORT=" not in after

    def test_a_field_that_was_not_submitted_is_not_written(self, writable_env):
        before = _keys(io.open(writable_env, encoding="utf-8").read())
        _post({"meta_token": "EAAsyntheticPageToken"})
        after = _keys(io.open(writable_env, encoding="utf-8").read())
        assert after["ADMIN_PASSWORD"] == before["ADMIN_PASSWORD"]
        assert after["GEMINI_API_KEY"] == before["GEMINI_API_KEY"]
        assert after["META_PAGE_ACCESS_TOKEN"] == "EAAsyntheticPageToken"

    def test_an_empty_value_writes_nothing(self, writable_env):
        before = io.open(writable_env, encoding="utf-8").read()
        _post({"tg_manager_id": "   "})
        assert io.open(writable_env, encoding="utf-8").read() == before

    def test_a_newline_in_the_payload_is_a_400(self, writable_env):
        before = io.open(writable_env, encoding="utf-8").read()
        response = _post({"tg_manager_id": "1\nADMIN_PASSWORD=pwned"})
        assert response.status_code == 400, response.text
        assert "tg_manager_id" in response.text
        assert io.open(writable_env, encoding="utf-8").read() == before, (
            "a refused payload must not reach the process environment either"
        )
        assert os.environ.get("ADMIN_PASSWORD") != "pwned"

    def test_production_never_writes_the_file(self, writable_env, monkeypatch):
        monkeypatch.setenv("ENV", "production")
        monkeypatch.setenv("META_APP_SECRET", "9f2a1c7e5b8d4036a1e9c4f7b2d8e5a3")
        # A production login refuses the built-in default password, so this needs a real one.
        monkeypatch.setenv("ADMIN_PASSWORD", "9f2a1c7e5b8d4036a1e9c4f7b2d8e5a3")
        before = io.open(writable_env, encoding="utf-8").read()
        response = _post({"tg_manager_id": "444444"})
        assert response.status_code == 200, response.text
        assert io.open(writable_env, encoding="utf-8").read() == before

    def test_the_write_gate_still_has_to_be_open(self, writable_env, monkeypatch):
        monkeypatch.delenv("ALLOW_ENV_FILE_WRITE", raising=False)
        before = io.open(writable_env, encoding="utf-8").read()
        assert _post({"tg_manager_id": "555555"}).status_code == 200
        assert io.open(writable_env, encoding="utf-8").read() == before

    def test_a_missing_file_is_reported_not_created(self, writable_env, monkeypatch):
        os.unlink(writable_env)
        response = _post({"tg_manager_id": "666666"})
        assert response.status_code == 200, "the in-process update still succeeds"
        assert not os.path.exists(writable_env)

    def test_a_non_admin_cannot_write(self, writable_env):
        from starlette.testclient import TestClient

        with TestClient(main.app, raise_server_exceptions=False) as client:
            response = client.post("/api/update-keys", json={"tg_manager_id": "777777"})
        assert response.status_code == 401
        assert _keys(io.open(writable_env, encoding="utf-8").read())[
            "TELEGRAM_MANAGER_CHAT_ID"
        ] == "111111"


# --------------------------------------------------------------------------------------
# 3. Source contract
# --------------------------------------------------------------------------------------


class TestTheSourceContract:
    def _read(self, *names):
        return "\n".join(
            io.open(os.path.join(REPO_ROOT, n), encoding="utf-8").read() for n in names
        )

    @staticmethod
    def _code_only(text):
        """Executable lines only: comments AND docstrings are skipped.

        `merge_env_file`'s own docstring quotes the statement it replaced, so a whole-file
        substring assertion would fail on the documentation of the fix. This is the same
        shape that made a naive assertion misfire in Phase 43, and the same remedy
        `test_main_has_no_published_fallback` uses.
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

    def test_main_no_longer_truncates_the_env_file(self):
        code = self._code_only(self._read("main.py"))
        assert 'open(".env", "w"' not in code
        assert "keys_map" not in code

    def test_the_write_goes_through_the_merge_helper(self):
        body = self._read("main.py")
        assert "merge_env_file(updates)" in body

    def test_the_gate_is_unchanged(self):
        """Not production AND ALLOW_ENV_FILE_WRITE=1 — the fix must not widen it.

        Phase 52 (O-51-6) lifted the same two conditions into a named `write_gate_open`,
        because the response now has to report which side of the gate the request landed on.
        So this pin follows the conditions instead of the line's punctuation, and it is
        stronger than the one it replaces: the single `merge_env_file(updates)` call must not
        merely exist somewhere in the file, it must sit *inside* the gate's block.
        """
        code = self._code_only(self._read("main.py"))
        # The closing paren is anchored to its own line: `(.*?)\)\n` would stop at the first
        # `)` before a newline, which is `is_production_mode()`'s own (measured: it did).
        gate = re.search(r"write_gate_open = \(\n(.*?)\n\s*\)\n", code, re.S)
        assert gate, "the write gate must still be one named expression"
        conditions = " ".join(gate.group(1).split())
        assert conditions == (
            "not core_security.is_production_mode() "
            'and os.getenv("ALLOW_ENV_FILE_WRITE", "0") == "1"'
        ), f"the gate was widened or narrowed: {conditions!r}"

        lines = code.splitlines()
        gate_at = next(i for i, ln in enumerate(lines) if ln.strip() == "if write_gate_open:")
        calls = [i for i, ln in enumerate(lines) if "merge_env_file(updates)" in ln]
        assert len(calls) == 1, f"expected exactly one gated write, found {len(calls)}"
        assert calls[0] > gate_at, "the write must come after the gate, not before it"
        indent = lambda ln: len(ln) - len(ln.lstrip())  # noqa: E731
        assert indent(lines[calls[0]]) > indent(lines[gate_at]), (
            "the write must be inside the gate's block, not beside it"
        )

    def test_the_endpoint_writes_only_the_keys_it_accepts(self):
        body = self._read("main.py")
        for name in WRITTEN_BY_THE_ENDPOINT:
            assert f'"{name}"' in body
        for name in ("GEMINI_MODEL", "PORT"):
            assert f'"{name}": os.getenv' not in body, (
                f"{name} is not an input of this endpoint and must not be written from a default"
            )
