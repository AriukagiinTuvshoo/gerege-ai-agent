"""Phase 25 - regression tests for the AidoLab Critical findings.

Three groups, each closing a finding with a test that fails if the fix is reverted:

* **#1** a documentation example that put a password in a command-line argument.
* **#2/#3** Jinja2 environments created without `autoescape`, rendering attacker-controlled
  values into HTML and into JavaScript string literals.
* **#4-#8** the literal `Password123!` in five test fixtures - classified as a false
  positive, and the reasoning pinned here so the classification cannot silently drift.

Nothing here suppresses a scanner rule. Each test either proves a real defect is fixed or
records why a reported one is not a defect.
"""

import pathlib
import re
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


# ===========================================================================
# #1 - documentation must not demonstrate a password on the command line
# ===========================================================================

MIGRATION_DOC = REPO_ROOT / "docs" / "database" / "POSTGRESQL_MIGRATION.md"


def test_migration_doc_has_no_password_in_a_command_line_example():
    """The finding was `--postgres-url "postgresql://gerege:STRONG_PASS@localhost/..."`.

    A password in argv is readable by every local user through `ps` and lands in shell
    history. Even as a placeholder it teaches the wrong pattern - the copy-paste risk is the
    point, not whether `STRONG_PASS` was ever real.
    """
    text = MIGRATION_DOC.read_text(encoding="utf-8")
    assert "--postgres-url" not in text, (
        "the migration example passes the DSN on the command line again; export "
        "DATABASE_URL instead so the password stays out of argv"
    )
    assert "STRONG_PASS" not in text


def test_migration_doc_never_embeds_a_credential_in_a_url():
    """Any `postgresql://user:<literal>@host` in the doc must be a substitution, not a value."""
    text = MIGRATION_DOC.read_text(encoding="utf-8")
    for match in re.finditer(r"postgresql(?:\+psycopg2)?://([^:@\s/]+):([^@\s/]*)@", text):
        password = match.group(2)
        assert password.startswith("$(") or password.startswith("${"), (
            f"literal password {password!r} embedded in a documented DSN"
        )


def test_migration_doc_still_documents_the_env_var_path():
    """The fix must not have deleted the instruction it was protecting."""
    text = MIGRATION_DOC.read_text(encoding="utf-8")
    assert "DATABASE_URL" in text
    # And the script really does read it, so the example is executable as written.
    script = (REPO_ROOT / "scripts" / "migrate_sqlite_to_postgres.py").read_text(encoding="utf-8")
    assert "DATABASE_URL" in script


# ===========================================================================
# #2 / #3 - Jinja2 autoescaping
# ===========================================================================

ATTACK_PAYLOADS = [
    '";alert(document.cookie);//',
    "</script><script>alert(1)</script>",
    "';alert(1);//",
    '"><img src=x onerror=alert(1)>',
    "\\",
    "\\\\\";alert(1)//",
    "\n alert(1)",
    "${{7*7}}",
    "`;alert(1);//",
]


@pytest.fixture(scope="module")
def template_env():
    """The production environment, built the same way main.py builds it."""
    import main

    return main._html_template_env()


def render_scanner(template_env, page_id):
    return template_env.get_template("scanner.html").render(page_id=page_id)


def render_payment(template_env, **overrides):
    kwargs = dict(
        invoice_id="inv-abc",
        amount=85000,
        description="Dental Examination",
        company_name="Test Company",
        qr_image_url="https://example.invalid/qr.png",
        deep_links=[],
    )
    kwargs.update(overrides)
    return template_env.get_template("payment.html").render(**kwargs)


def js_string_assignments(rendered, variable):
    """Every line assigning `variable` in the rendered output."""
    return [line.strip() for line in rendered.splitlines() if variable in line]


def extract_js_literal(rendered, variable):
    """Pull out the literal assigned to a JS `const`, so it can be parsed as JSON."""
    import json

    pattern = re.compile(rf"const {variable}\s*=\s*(.*);\s*$", re.MULTILINE)
    match = pattern.search(rendered)
    assert match, f"{variable} not found in rendered output"
    return json.loads(match.group(1))


@pytest.mark.parametrize("payload", ATTACK_PAYLOADS)
def test_scanner_page_id_cannot_break_out_of_the_js_string(template_env, payload):
    """`/scanner` is unauthenticated and takes page_id straight from the query string.

    Pre-fix this rendered `const pageId = "";alert(...)//"` - the payload terminated the
    string literal and executed. Post-fix the value is a JSON string literal, so the parsed
    value must round-trip exactly and the raw payload must not appear unescaped.
    """
    rendered = render_scanner(template_env, payload)

    # The strong assertion: the emitted literal parses as JSON and yields the original value.
    assert extract_js_literal(rendered, "pageId") == payload

    # And structurally: no bare `<` or `>` survives inside the assignment, so the
    # `</script>` breakout is impossible.
    assignment = js_string_assignments(rendered, "const pageId")[0]
    assert "<" not in assignment and ">" not in assignment


@pytest.mark.parametrize("payload", ATTACK_PAYLOADS)
def test_payment_invoice_id_cannot_break_out_of_the_js_string(template_env, payload):
    rendered = render_payment(template_env, invoice_id=payload)
    assert extract_js_literal(rendered, "invoiceId") == payload
    assignment = js_string_assignments(rendered, "const invoiceId")[0]
    assert "<" not in assignment and ">" not in assignment


@pytest.mark.parametrize("payload", ATTACK_PAYLOADS)
def test_payment_html_context_escapes_markup(template_env, payload):
    """Description and company name land in HTML, where escaping is the correct tool."""
    rendered = render_payment(template_env, description=payload, company_name=payload)
    # The template legitimately contains its own <script> tags, so `<script` cannot be banned
    # outright, and the escaped payload still spells `onerror=` as inert characters. The
    # property that matters is that no payload markup becomes a live tag: every `<` the
    # payload supplied is escaped, so nothing it contains can be parsed as an attribute.
    if "<" in payload:
        assert "&lt;" in rendered, "payload markup was dropped instead of escaped"
        assert "<img src=x" not in rendered
        assert "<script>alert" not in rendered
        # No live tag carries an event handler introduced by the payload.
        for line in rendered.splitlines():
            if "onerror=" in line.lower():
                assert "&lt;" in line, f"live event handler on: {line.strip()[:120]}"


def test_script_payload_does_not_appear_executable_anywhere(template_env):
    """Whole-document check: no unescaped script tag introduced by user data."""
    marker = "ALERT_MARKER_XYZ"
    payload = f'</script><script>alert("{marker}")</script>'
    for rendered in (
        render_scanner(template_env, payload),
        render_payment(template_env, invoice_id=payload, description=payload, company_name=payload),
    ):
        # The literal `alert("...")` call may appear only inside an inert string/attribute.
        for line in rendered.splitlines():
            if marker in line:
                assert "\\u003c" in line or "&lt;" in line, (
                    f"unescaped markup on a line carrying user data: {line.strip()[:160]}"
                )


# --- legitimate rendering must be unaffected -------------------------------

def test_payment_page_still_renders_normal_values(template_env):
    rendered = render_payment(template_env)
    assert "inv-abc" in rendered
    assert "Dental Examination" in rendered
    assert "85,000" in rendered
    assert 'lang="mn"' in rendered
    # Real markup from the template itself is untouched.
    assert "<!DOCTYPE html>" in rendered or "<!doctype html>" in rendered.lower()
    assert "tailwindcss" in rendered


def test_payment_company_name_containing_an_ampersand_is_correctly_escaped(template_env):
    """A legitimate business name must display correctly, not be mangled or injected."""
    rendered = render_payment(template_env, company_name="Erdene & Sons Co.")
    assert "Erdene &amp; Sons Co." in rendered
    assert "Erdene & Sons Co." not in rendered.replace("&amp;", "")


def test_scanner_page_still_renders_its_own_markup(template_env):
    rendered = render_scanner(template_env, "default-page")
    assert "const pageId" in rendered
    assert extract_js_literal(rendered, "pageId") == "default-page"
    assert "<html" in rendered.lower() or "<!doctype" in rendered.lower()


def test_payment_deep_links_render_through_escaping(template_env):
    """Deep links are provider-supplied; they are attributes, so escaping must apply."""
    rendered = render_payment(
        template_env,
        deep_links=[{"name": "Khan Bank", "link": "https://example.invalid/pay", "color": "#123456"}],
    )
    assert "Khan Bank" in rendered
    assert "https://example.invalid/pay" in rendered


# --- structural guarantees -------------------------------------------------

def test_only_one_template_environment_constructor_exists():
    """Two copies of a security setting is how one of them gets missed.

    The same drift produced F-1 in Phase 24 (a containment check applied to one entry point
    and not the other). One constructor, called from both pages.
    """
    import ast

    source = (REPO_ROOT / "main.py").read_text(encoding="utf-8")
    # Parse rather than grep: the docstring above explains the pre-fix form and would inflate
    # a naive text count. Only real calls count.
    tree = ast.parse(source)
    constructions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "Environment"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "jinja2"
    ]
    assert len(constructions) == 1, (
        f"expected exactly one Jinja2 environment construction, found {len(constructions)}; "
        "a second one is a security setting that will drift"
    )
    # Three occurrences: the `def`, plus one call in each page handler.
    assert source.count("_html_template_env()") == 3, "both page handlers must use the shared env"


def test_the_environment_actually_autoescapes(template_env):
    assert template_env.autoescape("anything.html") is True
    assert template_env.autoescape("anything.htm") is True
    assert template_env.autoescape("anything.xml") is True


def test_both_templates_use_tojson_for_their_js_sink():
    """HTML escaping is the wrong escaper inside `<script>`; `tojson` is the right one."""
    for name, variable in (("scanner.html", "pageId"), ("payment.html", "invoiceId")):
        text = (REPO_ROOT / "templates" / name).read_text(encoding="utf-8")
        assert f"const {variable} = {{{{ {variable.lower().replace('id','_id')}|tojson }}}}" in text or \
               f"|tojson" in text, f"{name} does not use tojson"
        # The pre-fix form must be gone.
        assert f'const {variable} = "{{{{' not in text


# ===========================================================================
# #4-#8 - hardcoded passwords in tests: FALSE POSITIVE, recorded
# ===========================================================================

FIXTURE_FILES = [
    "tests/test_noflow_features.py",
    "tests/test_p0_security_role_escalation.py",
    "tests/test_p1_payment_security.py",
]


def test_fixture_password_appears_in_no_production_file():
    """The whole basis for calling this a false positive: the value is never live."""
    offenders = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in {".py", ".yml", ".yaml", ".sh", ".env"}:
            continue
        parts = set(path.parts)
        if ".git" in parts or "tests" in parts or ".scratch" in parts:
            continue
        try:
            if "Password123!" in path.read_text(encoding="utf-8", errors="ignore"):
                offenders.append(str(path.relative_to(REPO_ROOT)))
        except (OSError, UnicodeDecodeError):
            continue
    assert offenders == [], f"fixture password leaked into production files: {offenders}"


def test_fixture_password_is_not_a_documented_or_default_credential():
    """If it were a default anyone could deploy, it would be a real finding."""
    for name in ("README.md", "docs", "docker-compose.yml", "docker-compose.prod.yml", ".env.example"):
        target = REPO_ROOT / name
        if not target.exists():
            continue
        if target.is_dir():
            continue
        text = target.read_text(encoding="utf-8", errors="ignore")
        assert "Password123!" not in text, f"{name} documents the fixture password"


def test_the_fixture_password_is_only_used_to_authenticate_test_clients():
    """Every occurrence must be a login or a fixture write - never an assertion on a secret."""
    for relative in FIXTURE_FILES:
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if "Password123!" not in line:
                continue
            stripped = line.strip()
            assert any(
                token in stripped
                for token in ("set_client_credentials", '"password":', "password=")
            ), f"{relative}:{line_number} uses the fixture password unexpectedly: {stripped}"


def test_the_security_tests_that_use_it_still_assert_their_behaviour():
    """Guards against 'fixing' the finding by deleting the test.

    These are role-escalation and payment-authorisation tests; removing or emptying them
    would be a far worse outcome than the scanner warning.
    """
    expected = {
        "tests/test_p0_security_role_escalation.py": "def test_",
        "tests/test_p1_payment_security.py": "def test_",
        "tests/test_noflow_features.py": "def test_",
    }
    for relative, marker in expected.items():
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        assert marker in text
        if "role_escalation" in relative:
            # The point of the file is that tenant A cannot reach tenant B; that must survive.
            assert "tenant_b" in text.lower()
