"""F-51-6 — a tracked template must not carry a credential.

WHY THIS FILE EXISTS
====================
On 2026-11-26 a commit landed on the public default branch titled "Add example
GEMINI_API_KEY to .env.example". It put a 53-character value on ``GEMINI_API_KEY=`` that was
byte-identical to the live key in one deployment's git-ignored ``.env``. The repository is public,
so the key became readable by anyone, and it stays readable in that commit's history.

CI ran on it and passed: ``45773782793``, conclusion ``success``.

Nothing in the suite caught it because nothing looked. ``core/secret_guard.py`` states the invariant
in its own docstring — *"The templates (``.env.example``,
``docs/deployment/PRODUCTION_ENV_TEMPLATE.env``) leave every secret blank with a ``generate:``
hint"* — but that module only ever evaluates the **process environment**. The tests that read the
templates (``test_e39_staging_operational_readiness.py``'s ``TEMPLATES`` tuple) assert which
*variable names* appear, never what a value is. So the invariant was documentation, and the class of
defect this repository has now met four times — F-44-B, F-49-1, F-51-5 and this — is a rule that
lives in prose instead of code.

These tests are that rule in code.

WHAT THEY ACCEPT
================
Every convention the three tracked templates already use, measured before this file was written:

* a blank assignment — ``GEMINI_API_KEY=``
* an angle-bracket hint — ``ADMIN_PASSWORD=<generate: openssl rand -base64 24>``,
  ``GEMINI_API_KEY=<from Google AI Studio>``
* a compose-style reference — ``SOMETHING=${VAR:?err}``
* a flag or number under a credential-shaped *name* — ``ALLOW_QUERY_TOKEN=0``,
  ``DISALLOW_QUERY_TOKEN=0``
* a name that points at a location rather than holding a secret —
  ``BACKUP_ENCRYPTION_KEY_FILE=backups/.backup.key``
* a URL whose userinfo password is itself a hint —
  ``DATABASE_OWNER_URL=postgresql://gerege_owner:<password>@db:5432/gerege_crm``

WHAT THEY REFUSE
================
Any other non-empty value on a credential-shaped name, and any URL carrying a literal password.
The failure message names the file, the line, the variable and the value's *shape* — never the
value, because a test that prints a committed credential into a CI log has leaked it a second time.

HOW THEY REPORT
===============
No assertion in this file ever has a credential as an operand. Pytest's assertion rewriting prints
the operands of a failed ``assert``, so ``assert value == ""`` publishes the value into the CI log —
which is how the first version of this file leaked the key it was written to catch. Checks compute a
boolean, or a list of variable *names* with a shape description, and assert on that.

WHAT THEY NEVER READ
====================
The repository's own ``.env``. It is git-ignored, it is where a deployment's real credentials live,
and scanning it would fail for every developer who has configured the app. Only tracked files are
scanned, and there is a test that pins that boundary.
"""

from __future__ import annotations

import io
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# ----------------------------------------------------------------------------------------
# Which files are templates
# ----------------------------------------------------------------------------------------

#: The three files `core/secret_guard.py`'s docstring names. Used as the fallback list if `git`
#: is unavailable, and asserted to always be part of the scanned set so the two cannot drift.
KNOWN_TEMPLATES = (
    ".env.example",
    ".env.staging.example",
    "docs/deployment/PRODUCTION_ENV_TEMPLATE.env",
)

#: Tracked files that are environment templates. Matched on the name, not on a frozen list, so a
#: template added later is scanned by default rather than silently excluded.
_TEMPLATE_NAME = re.compile(
    r"(?:^|/)\.env(?:\.[a-z0-9_]+)?\.example$|(?:^|/)PRODUCTION_ENV_TEMPLATE\.env$|"
    r"(?:^|/)[A-Z0-9_]*ENV_TEMPLATE[A-Z0-9_]*\.env$",
    re.IGNORECASE,
)


def _git_tracked_files() -> Optional[List[str]]:
    """Every tracked path, or None when git cannot answer (a tarball checkout, for example)."""
    try:
        proc = subprocess.run(
            ["git", "ls-files"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return [line for line in proc.stdout.split("\n") if line.strip()]


def _filesystem_fallback() -> List[str]:
    """Walk the tree for template-shaped names when git is unavailable.

    ``.env`` itself is excluded by name, not by trust: it is untracked and holds real credentials.
    """
    # Directories that are large, generated, or never templates. `backups/` alone holds thousands
    # of files in a deployment that has been running a while, and walking it to find three text
    # files would make collection slower than the suite.
    skip_prefixes = (".git/", "backups/", "node_modules/", ".venv/", "venv/", "__pycache__/", ".scratch/", "scratch/")
    found = []
    for path in REPO_ROOT.rglob("*"):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel == ".env" or rel.startswith(skip_prefixes) or "/node_modules/" in rel:
            continue
        if not path.is_file():
            continue
        if _TEMPLATE_NAME.search(rel):
            found.append(rel)
    return sorted(found)


def _tracked_templates() -> List[str]:
    """The template files this guard scans: tracked ones only, always including the known three."""
    tracked = _git_tracked_files()
    if tracked is None:
        return list(_filesystem_fallback())
    found = [f for f in tracked if _TEMPLATE_NAME.search(f)]
    for known in KNOWN_TEMPLATES:
        if known not in found and (REPO_ROOT / known).is_file():
            found.append(known)
    return sorted(found)


# ----------------------------------------------------------------------------------------
# What counts as a credential, and what counts as a safe value
# ----------------------------------------------------------------------------------------

#: A name that holds a secret. Deliberately broad: the point is that a *name* like this should
#: never carry a literal value in a tracked file.
CREDENTIAL_NAME = re.compile(
    r"(SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE|CREDENTIAL|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|"
    r"_KEY$|^KEY_|_KEY_|SIGNING)",
)

#: A name that points at a location. ``BACKUP_ENCRYPTION_KEY_FILE=backups/.backup.key`` is a path,
#: not a secret, and every template already assigns one.
LOCATION_NAME = re.compile(r"(_FILE|_PATH|_DIR|_HOME|_SOCKET)$")

#: Values that are configuration, not credentials, however the variable is named:
#: ``ALLOW_QUERY_TOKEN=0`` and ``DISALLOW_QUERY_TOKEN=0`` are feature flags.
NON_SECRET_VALUE = re.compile(r"^(?:|0|1|true|false|on|off|yes|no|none|null|disabled|enabled)$", re.IGNORECASE)

#: The only acceptable non-empty shapes. ``<...>`` is what every template uses today
#: (``<generate: openssl rand -base64 24>``, ``<from Google AI Studio>``); ``${...}`` is what the
#: compose stack uses. Both are structurally incapable of being a working credential.
#:
#: A *bare* placeholder word is deliberately NOT accepted here. ``ADMIN_PASSWORD=changeme`` copies
#: into a deployment as a credential that is printed in this repository, which is F-44-B, F-49-1 and
#: F-51-5 again; `core.secret_guard` already keeps that list and this guard defers to it.
STRUCTURAL_HINT = re.compile(r"^<[^>]*>$|^\$\{[^}]+\}$", re.DOTALL)

#: Minimum length at which a non-placeholder value is treated as a probable real credential.
#: Below it the value is still reported, but as a lower-confidence shape; see `_classify`.
PROBABLE_CREDENTIAL_LENGTH = 16

_ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")

#: scheme://user:password@host — the userinfo, if any.
_URL_USERINFO = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://([^/@\s]+)@")


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1].strip()
    return value


def _is_hint(value: str) -> bool:
    """A value that is documentation rather than a credential: ``<...>`` or ``${...}``, exactly."""
    return bool(STRUCTURAL_HINT.match(value.strip()))


def _looks_like_published_literal(value: str) -> bool:
    """The F-44-B / F-49-1 / F-51-5 family: a value this repository already publishes."""
    try:
        from core import secret_guard
    except Exception:  # pragma: no cover - the guard module is part of the app
        return False
    published = set(getattr(secret_guard, "PUBLISHED_OR_PLACEHOLDER_VALUES", ()) or ())
    markers = tuple(str(m).lower() for m in (getattr(secret_guard, "PLACEHOLDER_MARKERS", ()) or ()))
    lowered = value.strip().lower()
    if lowered in {str(p).lower() for p in published}:
        return True
    return bool(markers) and any(m in lowered for m in markers)


def _shape(value: str) -> str:
    """A description of a value that cannot be used to reconstruct it.

    The whole point of the finding is that this string travels further than the value: into a CI
    log, into a terminal, into a pull-request comment. So it reports length and character classes,
    and nothing else.
    """
    classes = []
    if re.search(r"[a-z]", value):
        classes.append("lower")
    if re.search(r"[A-Z]", value):
        classes.append("upper")
    if re.search(r"[0-9]", value):
        classes.append("digit")
    if re.search(r"[^A-Za-z0-9]", value):
        classes.append("punct")
    return f"{len(value)} chars, {'+'.join(classes) or 'empty'}"


def _classify(name: str, value: str) -> Optional[str]:
    """Why this assignment is a problem, or None when it is fine."""
    if LOCATION_NAME.search(name):
        return None
    if NON_SECRET_VALUE.match(value):
        return None
    if value == "":
        return None
    # Before the published-literal check, and this order is load-bearing: `secret_guard`'s
    # PLACEHOLDER_MARKERS contains "<generate" and "<from", so testing the marker list first would
    # refuse the very hint style every template uses. A value fully wrapped in <...> or ${...}
    # cannot be a credential, so it is settled here; everything else faces the marker list.
    if _is_hint(value):
        return None
    if _looks_like_published_literal(value):
        return (
            "a value this repository publishes as a placeholder, which is the F-44-B / F-49-1 / "
            "F-51-5 family: copied into a deployment it becomes a working credential"
        )
    if len(value) >= PROBABLE_CREDENTIAL_LENGTH:
        return "a probable real credential: long, and not a hint or a placeholder"
    return "a literal value where every other template leaves a blank or a <generate: ...> hint"


def _url_password_problem(value: str) -> Optional[str]:
    """A URL whose userinfo carries a literal password."""
    match = _URL_USERINFO.match(value.strip())
    if not match:
        return None
    userinfo = match.group(1)
    password = userinfo.split(":", 1)[1] if ":" in userinfo else ""
    if password == "":
        return None
    if _is_hint(password) or NON_SECRET_VALUE.match(password):
        return None
    return f"a URL with a literal password in its userinfo ({_shape(password)})"


def _scan(path: str) -> List[Tuple[int, str, str, str]]:
    """Every offending assignment in one template: (line, name, shape, reason)."""
    text = io.open(REPO_ROOT / path, encoding="utf-8", errors="replace").read()
    problems: List[Tuple[int, str, str, str]] = []
    for lineno, raw in enumerate(text.split("\n"), 1):
        stripped = raw.strip()
        if stripped.startswith("#"):
            continue
        match = _ASSIGNMENT.match(raw)
        if not match:
            continue
        name, value = match.group(1), _strip_quotes(match.group(2))
        if CREDENTIAL_NAME.search(name.upper()):
            reason = _classify(name.upper(), value)
            if reason:
                problems.append((lineno, name, _shape(value), reason))
        url_reason = _url_password_problem(value)
        if url_reason:
            problems.append((lineno, name, _shape(value), url_reason))
    return problems


TEMPLATES = _tracked_templates()


# ----------------------------------------------------------------------------------------
# 1. The scan list itself
# ----------------------------------------------------------------------------------------


class TestWhatGetsScanned:
    def test_the_known_templates_are_all_present(self):
        """The three files `core/secret_guard.py` names must be in the scanned set."""
        missing = [t for t in KNOWN_TEMPLATES if t not in TEMPLATES]
        assert not missing, f"these templates were not scanned: {missing}"

    def test_the_list_is_derived_not_frozen(self):
        """A template added later must be picked up without editing this file."""
        assert len(TEMPLATES) >= len(KNOWN_TEMPLATES)
        assert _TEMPLATE_NAME.search(".env.production.example"), "a new template name must match"
        assert _TEMPLATE_NAME.search("docs/ENV_TEMPLATE.env"), "a new template name must match"
        assert not _TEMPLATE_NAME.search("templates/payment.html"), "an HTML template is not an env file"
        assert not _TEMPLATE_NAME.search("main.py")

    def test_the_repository_env_file_is_never_scanned(self):
        """`.env` is git-ignored and holds a deployment's real credentials.

        Scanning it would fail for every developer who has configured the app, and would put a real
        secret in a test report. The boundary is pinned here so it cannot be widened by accident.
        """
        assert ".env" not in TEMPLATES
        assert not any(t == ".env" or t.endswith("/.env") for t in TEMPLATES)
        assert ".env" not in _filesystem_fallback(), "the git-less fallback must also exclude it"

    def test_every_scanned_file_exists_and_is_readable(self):
        for rel in TEMPLATES:
            path = REPO_ROOT / rel
            assert path.is_file(), f"{rel} is listed but missing"
            io.open(path, encoding="utf-8", errors="replace").read()


# ----------------------------------------------------------------------------------------
# 2. The guard
# ----------------------------------------------------------------------------------------


class TestNoTrackedTemplateCarriesACredential:
    @pytest.mark.parametrize("template", TEMPLATES)
    def test_no_credential_shaped_assignment_holds_a_literal(self, template):
        problems = _scan(template)
        assert not problems, _message(template, problems)

    def test_the_production_template_keeps_its_generate_hints(self):
        """The convention that makes the guard passable, so the fix is obvious to an author.

        Booleans only. `assert "<generate:" in text` would, on failure, print `text` - the whole
        template, credentials included - because pytest shows the operands of a failed assert.
        """
        text = io.open(REPO_ROOT / "docs/deployment/PRODUCTION_ENV_TEMPLATE.env", encoding="utf-8").read()
        has_hint = "<generate: openssl rand" in text
        admin_is_hint = bool(re.search(r"^ADMIN_PASSWORD=<", text, re.MULTILINE))
        gemini_is_hint = bool(re.search(r"^GEMINI_API_KEY=<", text, re.MULTILINE))
        assert has_hint and admin_is_hint and gemini_is_hint, (
            "the production template lost its <generate: ...> convention "
            f"(hint present={has_hint}, ADMIN_PASSWORD={admin_is_hint}, GEMINI_API_KEY={gemini_is_hint})"
        )

    @pytest.mark.parametrize("rel", [".env.example", ".env.staging.example"])
    def test_the_other_templates_leave_secrets_blank(self, rel):
        """Names and shapes only - see `_literal_secret_names`, which is why this is a helper."""
        violations = _literal_secret_names(rel, ("GEMINI_API_KEY", "ADMIN_PASSWORD", "META_APP_SECRET"))
        assert not violations, f"{rel} holds a literal value for: {violations}"


# ----------------------------------------------------------------------------------------
# 3. The predicate, on values that must and must not be accepted
# ----------------------------------------------------------------------------------------


class TestThePredicate:
    @pytest.mark.parametrize("value", [
        "",
        "<generate: openssl rand -base64 24>",
        "<generate: openssl rand -hex 32>",
        "<from Google AI Studio>",
        "<from Meta app dashboard>",
        "<per-page token from Meta>",
        "<from @BotFather>",
        "${GEMINI_API_KEY:?set me}",
        "${POSTGRES_OWNER_PASSWORD}",
    ])
    def test_accepted_values(self, value):
        """Blank, or a shape that cannot be a working credential. Every one of these appears in a
        tracked template today, so the guard is measured against real usage, not an idea of it."""
        assert _classify("GEMINI_API_KEY", value) is None, value

    @pytest.mark.parametrize("value", [
        "changeme",
        "change-me",
        "your-key-here",
        "example",
        "password",
        "secret",
        "todo",
        "ADMIN2026",
    ])
    def test_a_bare_placeholder_word_is_refused(self, value):
        """`ADMIN_PASSWORD=changeme` in a template is not documentation, it is a credential that
        works in any deployment that copied the line. Angle brackets are the convention."""
        assert _classify("ADMIN_PASSWORD", value) is not None, value

    @pytest.mark.parametrize("name,value", [
        ("ALLOW_QUERY_TOKEN", "0"),
        ("DISALLOW_QUERY_TOKEN", "0"),
        ("TELEGRAM_WEBHOOK_SECRET", "1"),
        ("ADMIN_PASSWORD", "true"),
    ])
    def test_flags_and_numbers_are_not_credentials(self, name, value):
        assert _classify(name, value) is None

    @pytest.mark.parametrize("name,value", [
        ("BACKUP_ENCRYPTION_KEY_FILE", "backups/.backup.key"),
        ("BACKUP_OFFSITE_KEY_PATH", "/etc/gerege/offsite.key"),
    ])
    def test_a_name_that_points_at_a_location_is_exempt(self, name, value):
        assert _classify(name, value) is None

    def test_a_long_literal_on_a_credential_name_is_refused(self):
        """The shape of the commit this file exists because of.

        The value below is synthetic — a real credential is never written into a test file, not even
        to prove that it would be caught.
        """
        synthetic = "AIzaSy" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9"
        reason = _classify("GEMINI_API_KEY", synthetic)
        assert reason, "a 42-character literal on GEMINI_API_KEY must be refused"
        assert "probable real credential" in reason

    def test_a_short_literal_is_still_reported(self):
        assert _classify("ADMIN_PASSWORD", "hunter2") is not None

    @pytest.mark.parametrize("value", [
        "agent_verify_secret_token_123",
        "GEREGE_VERIFY_2026",
    ])
    def test_a_value_this_repository_publishes_is_refused_by_name(self, value):
        """F-44-B, F-49-1 and F-51-5 all started as a line in a source file. A template is the
        next place one could appear, and `core.secret_guard` already keeps the list."""
        assert _looks_like_published_literal(value), value

    @pytest.mark.parametrize("value,ok", [
        ("postgresql://gerege_owner:<password>@db:5432/gerege_crm", True),
        ("postgresql://gerege_owner:${POSTGRES_OWNER_PASSWORD:?}@db:5432/gerege_crm", True),
        ("redis://127.0.0.1:6379/0", True),
        ("sqlite:///leads.db", True),
        ("http://localhost:8000,http://127.0.0.1:8000", True),
        ("postgresql://gerege_owner:Sup3rRealPassword@db:5432/gerege_crm", False),
    ])
    def test_url_userinfo(self, value, ok):
        problem = _url_password_problem(value)
        assert (problem is None) is ok, value


# ----------------------------------------------------------------------------------------
# 4. The failure message must not leak the value it is reporting
# ----------------------------------------------------------------------------------------


class TestTheReportIsSafeToPrint:
    def test_the_message_names_the_variable_and_never_the_value(self):
        secret = "AIzaSy" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp9Oo"
        problems = [(17, "GEMINI_API_KEY", _shape(secret), "a probable real credential")]
        message = _message(".env.example", problems)
        assert "GEMINI_API_KEY" in message
        assert ".env.example" in message
        assert "17" in message
        assert secret not in message, "the guard leaked the credential it was reporting"
        assert secret[:12] not in message
        assert f"{len(secret)} chars" in message, "the shape is reported instead"

    def test_the_shape_description_cannot_reconstruct_the_value(self):
        assert _shape("abc") == "3 chars, lower"
        assert _shape("aA1-") == "4 chars, lower+upper+digit+punct"
        assert _shape("") == "0 chars, empty"


# ----------------------------------------------------------------------------------------
# 5. The invariant and its enforcement must not drift apart
# ----------------------------------------------------------------------------------------


class TestTheInvariantIsEnforcedWhereItIsStated:
    def test_secret_guard_still_states_the_template_invariant(self):
        """This file is the code behind a sentence in that module's docstring. If the sentence goes,
        the reason these tests exist goes with it — so the pairing is pinned, the way
        `test_e45_final_hardening.py` pins `ADMIN_PASSWORD` to its enforcing code."""
        source = io.open(REPO_ROOT / "core" / "secret_guard.py", encoding="utf-8").read()
        assert "leave every secret blank" in source
        assert ".env.example" in source

    def test_secret_guard_evaluates_the_environment_not_the_files(self):
        """Why this guard had to be written separately: that module never opens a template."""
        source = io.open(REPO_ROOT / "core" / "secret_guard.py", encoding="utf-8").read()
        has_entry_point = "def evaluate_secrets" in source
        reads_templates = ".env.example" in source.split("def evaluate_secrets", 1)[-1]
        assert has_entry_point, "evaluate_secrets disappeared from core/secret_guard.py"
        assert not reads_templates, (
            "evaluate_secrets started reading templates; this file may now be redundant"
        )

    def test_the_templates_the_two_modules_agree_on(self):
        """`test_e39`'s TEMPLATES tuple and this file's KNOWN_TEMPLATES name the same three files."""
        source = io.open(
            REPO_ROOT / "tests" / "test_e39_staging_operational_readiness.py", encoding="utf-8"
        ).read()
        for rel in KNOWN_TEMPLATES:
            assert rel in source, f"test_e39 stopped naming {rel}"


# ----------------------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------------------


def _literal_secret_names(rel: str, names: Tuple[str, ...]) -> List[str]:
    """Which of `names` holds a literal value in `rel` — reported as NAME (shape), never as a value.

    This exists because the obvious spelling leaks. `assert match.group(1).strip() == ""` puts the
    credential in the assertion, and pytest's rewriting prints the operands of a failed assert, so
    the first run of this file published the very key it was checking for into its own output. A
    guard that does that has leaked the secret a second time, into a CI log.
    """
    text = io.open(REPO_ROOT / rel, encoding="utf-8", errors="replace").read()
    violations: List[str] = []
    for name in names:
        match = re.search(rf"^{name}=(.*)$", text, re.MULTILINE)
        if match is None:
            violations.append(f"{name} (no longer assigned)")
            continue
        value = _strip_quotes(match.group(1))
        if value != "":
            violations.append(f"{name} ({_shape(value)})")
    return violations


def _message(template: str, problems: List[Tuple[int, str, str, str]]) -> str:
    """An actionable failure message that carries no secret.

    A guard that prints the credential it found into a CI log has leaked it twice, so the value is
    described by length and character class only.
    """
    lines = [
        f"{template} carries a credential in a tracked file (F-51-6).",
        "",
        "A tracked template is public: whoever reads the repository reads the value, and it stays",
        "in history after the line is deleted. Templates leave secrets blank or use a hint:",
        "",
        "    GEMINI_API_KEY=                                # blank, fill it in locally",
        "    ADMIN_PASSWORD=<generate: openssl rand -base64 24>",
        "",
        "If this value is real, rotate it — removing the line does not un-publish it.",
        "",
    ]
    for lineno, name, shape, reason in problems:
        lines.append(f"  line {lineno}: {name} is {reason} [{shape}]")
    return "\n".join(lines)
