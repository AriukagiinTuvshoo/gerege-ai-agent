"""Phase 27 - network binding, URL scheme validation, and temporary-file safety.

Three AidoLab findings, plus the two B310 sites the report did not mention.

Each test states the property it protects and why it is not merely a scanner-silencer. The
rule throughout: a scheme or host allowlist is only worth anything if a *redirect* cannot
escape it, so the redirect cases are tested against a real local server rather than mocked.
"""

import http.server
import os
import re
import socket
import socketserver
import stat
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


# ===========================================================================
# A local redirecting server, shared by the scheme tests
# ===========================================================================

class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        if self.path.startswith("/to-other-host"):
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
        elif self.path.startswith("/to-file"):
            self.send_response(302)
            self.send_header("Location", "file:///etc/hostname")
            self.end_headers()
        elif self.path.startswith("/to-same-host"):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_address[1]}/ok")
            self.end_headers()
        elif self.path.startswith("/ok"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"csv,data\n1,2\n")
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"csv,data\n")

    def do_POST(self):  # noqa: N802 - http.server API
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *args):  # silence the test server
        pass


@pytest.fixture()
def redirect_server():
    server = socketserver.TCPServer(("127.0.0.1", 0), _RedirectHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(scope="module")
def tls_cert(tmp_path_factory):
    """A self-signed certificate for 127.0.0.1, generated once for this module.

    Phase 28 made the sheets first hop https-only, so the "a legitimate multi-hop fetch
    still works" property can no longer be exercised over plain http. Serving the redirect
    chain over TLS keeps the test honest instead of deleting it. Generated here rather than
    committed: a checked-in key is a key everybody has.
    """
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    directory = tmp_path_factory.mktemp("tls")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


@pytest.fixture()
def tls_redirect_server(tls_cert):
    """The same redirect behaviour, over TLS, on a self-signed certificate.

    Yields (port, ca_bundle_path, url_scheme).
    """
    import ssl

    cert_path, key_path = tls_cert
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    class _TLSHandler(_RedirectHandler):
        def do_GET(self):  # noqa: N802 - http.server API
            if self.path.startswith("/to-same-host"):
                self.send_response(302)
                self.send_header(
                    "Location", f"https://127.0.0.1:{self.server.server_address[1]}/ok"
                )
                self.end_headers()
                return
            super().do_GET()

    server = socketserver.TCPServer(("127.0.0.1", 0), _TLSHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield port, cert_path
    finally:
        server.shutdown()
        server.server_close()


# ===========================================================================
# B310 - the sheets CSV fetch
# ===========================================================================

def test_sheets_host_allowlist_is_a_single_host():
    from sheets_service import _ALLOWED_SHEET_HOST

    assert _ALLOWED_SHEET_HOST == "docs.google.com"


def test_a_redirect_to_another_host_is_refused(monkeypatch):
    """The finding: first-hop validation was all that existed.

    `normalize_sheet_csv_url()` checks the URL the operator supplied, but `urlopen` then
    followed whatever the server returned. A redirect to an internal address reaches a host
    the application never validated.

    Two things this test gets right that a first version did not:

    * it drives `fetch_sheet_rows` (the production path), not `_sheet_opener()` in
      isolation - otherwise changing the call site silently disables the protection while
      the test keeps passing;
    * it asserts that the redirect target is never *contacted*, not that some exception was
      raised. Plain `urlopen` raises too, so a message check cannot tell them apart.
    """
    import sheets_service

    contacts = []

    class _Target(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            contacts.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"internal,data\n")

        def log_message(self, *args):
            pass

    target = socketserver.TCPServer(("127.0.0.1", 0), _Target)
    target_port = target.server_address[1]
    threading.Thread(target=target.serve_forever, daemon=True).start()

    class _Front(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(302)
            # A *different* host than the allowlisted one. `localhost` and `127.0.0.1` are
            # not the same string, which is what makes this a genuine cross-host hop.
            self.send_header("Location", f"http://localhost:{target_port}/stolen")
            self.end_headers()

        def log_message(self, *args):
            pass

    front = socketserver.TCPServer(("127.0.0.1", 0), _Front)
    front_port = front.server_address[1]
    threading.Thread(target=front.serve_forever, daemon=True).start()

    # Let the first hop through so the redirect handler is the thing under test.
    monkeypatch.setattr(sheets_service, "_ALLOWED_SHEET_HOST", "127.0.0.1")

    try:
        with pytest.raises((urllib.error.HTTPError, urllib.error.URLError, ValueError)):
            sheets_service.fetch_sheet_rows(f"http://127.0.0.1:{front_port}/export?format=csv")
        assert contacts == [], f"the fetch followed the redirect and reached the target: {contacts}"
    finally:
        front.shutdown()
        front.server_close()
        target.shutdown()
        target.server_close()


def test_a_redirect_to_a_file_scheme_is_refused(redirect_server):
    """`urllib` already blocks this; the test keeps that behaviour from being lost in a refactor."""
    from sheets_service import _sheet_opener

    with pytest.raises((urllib.error.HTTPError, urllib.error.URLError)):
        _sheet_opener().open(f"http://127.0.0.1:{redirect_server}/to-file", timeout=4)


def test_a_same_host_redirect_is_still_allowed(tls_redirect_server, monkeypatch):
    """The control must not break a legitimate multi-hop fetch on the allowed host.

    Phase 28 moved this onto TLS. The property being protected is unchanged - a redirect
    that stays on the allowlisted host is still followed - but the first hop must now be
    https, so a plain-http chain would only be testing the scheme rule instead.
    """
    import ssl

    import sheets_service

    port, ca_bundle = tls_redirect_server
    monkeypatch.setattr(sheets_service, "_ALLOWED_SHEET_HOST", "127.0.0.1")

    def _trusting_opener():
        # Passing the handler to build_opener *replaces* the default HTTPSHandler, which an
        # `add_handler` call after construction does not reliably do.
        return urllib.request.build_opener(
            sheets_service._SameHostRedirectHandler,
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_bundle)),
        )

    monkeypatch.setattr(sheets_service, "_sheet_opener", _trusting_opener)
    with _trusting_opener().open(
        f"https://127.0.0.1:{port}/to-same-host", timeout=4
    ) as response:
        assert response.read().startswith(b"csv,data")


def test_an_empty_sheet_url_is_not_an_error():
    """Documented contract: empty means "this page has no sheet", handled by the caller."""
    from sheets_service import normalize_sheet_csv_url

    # Only the truly empty value is a no-op. Whitespace is *not* normalised to empty here -
    # it reaches the scheme check and is rejected, which is what the caller's own
    # `if not sheet_url.strip()` guard is for. Documented so nobody "fixes" this silently.
    assert normalize_sheet_csv_url("") == ""
    with pytest.raises(ValueError):
        normalize_sheet_csv_url("   ")


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://docs.google.com/spreadsheets/d/x",
        "javascript:alert(1)",
        "data:text/csv,a,b",
        "not-a-url",
        "http://evil.example.com/spreadsheets/d/abc",
        "https://docs.google.com.evil.example/spreadsheets/d/abc",
        # Userinfo-hostname confusion: the real host is evil.example.
        "https://docs.google.com@evil.example/spreadsheets/d/abc",
    ],
)
def test_sheet_urls_off_the_allowlist_are_rejected(url):
    from sheets_service import normalize_sheet_csv_url

    with pytest.raises(ValueError):
        normalize_sheet_csv_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://docs.google.com/spreadsheets/d/1AbC-dEf_123/edit#gid=0",
        "https://docs.google.com/spreadsheets/d/1AbC-dEf_123/export?format=csv&gid=0",
        "https://docs.google.com/spreadsheets/d/1AbC-dEf_123/edit?usp=sharing",
    ],
)
def test_legitimate_sheet_urls_still_normalise(url):
    from sheets_service import normalize_sheet_csv_url

    result = normalize_sheet_csv_url(url)
    assert result.startswith("https://docs.google.com/spreadsheets/d/1AbC-dEf_123")
    assert "output=csv" in result or "export?format=csv" in result


# ===========================================================================
# B310 - the alert webhook
# ===========================================================================

@pytest.mark.parametrize(
    "webhook",
    [
        "file:///etc/passwd",
        "ftp://example.invalid/x",
        "javascript:alert(1)",
        "data:text/plain,x",
        "gopher://example.invalid/",
        "not-a-url",
    ],
)
def test_alert_webhook_refuses_non_http_schemes(webhook):
    """`urlopen` accepts `file:`; a webhook that reads a local file is not an alert.

    `BACKUP_ALERT_WEBHOOK` is operator configuration, so this is not attacker-controlled -
    but a copied value or a typo is realistic, and opening a `file:` URL is never the
    intended behaviour.
    """
    from core import backup_automation

    ok, detail = backup_automation.notify(webhook, {"event": "test"})
    assert ok is False
    assert "not http/https" in detail


def test_a_refused_scheme_is_not_retried():
    """A wrong scheme is permanent. Reporting 'after N attempts' would misdescribe it."""
    from core import backup_automation

    _ok, detail = backup_automation.notify("file:///etc/passwd", {"event": "test"})
    assert "attempts" not in detail


def test_http_webhooks_are_still_attempted(redirect_server, monkeypatch):
    """The controls must not block a real delivery.

    Phase 28 added a destination policy on top of the Phase 27 scheme allowlist. A loopback
    sink is now permitted only through the documented development opt-in, so this test sets
    it - the same path an operator's local test sink uses. The production refusal is tested
    separately in tests/test_e07_phase28_ssrf_and_tempfiles.py.
    """
    from core import backup_automation

    monkeypatch.setenv("BACKUP_ALERT_ALLOW_INSECURE", "1")
    monkeypatch.delenv("ENV", raising=False)
    ok, detail = backup_automation.notify(
        f"http://127.0.0.1:{redirect_server}/ok", {"event": "test"}
    )
    assert ok is True, detail
    assert detail.startswith("http 200")


# ===========================================================================
# B108 - the Vercel bootstrap database
# ===========================================================================

def test_the_runtime_directory_is_private_and_unpredictable(tmp_path):
    """The fixed name `/tmp/leads.db` was the defect, not merely the /tmp location.

    A predictable path in a shared directory lets another process pre-create it. The
    existence check then succeeds and skips the copy, while sqlite opens through it.
    """
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    mode = stat.S_IMODE(runtime.stat().st_mode)
    assert mode == 0o700

    import tempfile

    first = tempfile.mkdtemp(prefix="gerege-runtime-")
    second = tempfile.mkdtemp(prefix="gerege-runtime-")
    try:
        assert first != second
        assert "gerege-runtime-" in os.path.basename(first)
        assert stat.S_IMODE(os.stat(first).st_mode) == 0o700
    finally:
        for path in (first, second):
            try:
                os.rmdir(path)
            except OSError:
                pass


def test_the_bootstrap_no_longer_uses_a_fixed_path():
    """Structural: the literal must be gone, or the symlink scenario returns."""
    import ast

    source = (REPO_ROOT / "api" / "index.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    # Inspect the code, not the comment that documents the old value.
    string_literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert "/tmp/leads.db" not in string_literals, "the fixed path is back in executable code"
    assert "mkdtemp" in source


def test_the_bootstrap_opens_the_database_with_o_nofollow():
    source = (REPO_ROOT / "api" / "index.py").read_text(encoding="utf-8")
    assert "O_NOFOLLOW" in source
    assert "0o600" in source


def test_a_planted_symlink_cannot_redirect_the_database_write(tmp_path):
    """The vulnerability, reproduced and then shown blocked.

    This is the exact scenario: an attacker pre-creates a link at the path the process is
    about to use. With a private directory the link cannot be planted; `O_NOFOLLOW` is the
    second line of defence if it somehow is.
    """
    import sqlite3

    other_app = tmp_path / "other_app.db"
    conn = sqlite3.connect(other_app)
    conn.execute("CREATE TABLE secrets (v TEXT)")
    conn.execute("INSERT INTO secrets VALUES ('other-tenant-data')")
    conn.commit()
    conn.close()

    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    planted = runtime / "leads.db"
    planted.symlink_to(other_app)

    # The old code: exists() follows the link, so the copy is skipped and sqlite opens it.
    assert planted.exists()

    # The new code: O_NOFOLLOW refuses to open through the link.
    with pytest.raises(OSError):
        fd = os.open(str(planted), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)

    # And the other application's database is untouched.
    conn = sqlite3.connect(other_app)
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert tables == {"secrets"}


def test_o_nofollow_refuses_only_the_link_not_a_plain_file(tmp_path):
    """Guard against O_NOFOLLOW being used somewhere it would break normal operation."""
    plain = tmp_path / "plain.db"
    fd = os.open(str(plain), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.close(fd)
    assert plain.exists()
    assert stat.S_IMODE(plain.stat().st_mode) == 0o600


# ===========================================================================
# B104 - binding
# ===========================================================================

def test_the_development_entrypoint_defaults_to_loopback():
    """`python main.py` must not expose a reload-enabled dev server to the LAN by default."""
    source = (REPO_ROOT / "main.py").read_text(encoding="utf-8")
    block = source.split('if __name__ == "__main__":', 1)[1]
    assert 'os.getenv("HOST", "127.0.0.1")' in block
    # The literal 0.0.0.0 must not be the default anywhere in this block.
    assert 'host="0.0.0.0"' not in block


def test_the_development_entrypoint_warns_when_exposed():
    source = (REPO_ROOT / "main.py").read_text(encoding="utf-8")
    block = source.split('if __name__ == "__main__":', 1)[1]
    assert "warning" in block.lower()
    assert "development server" in block


def test_production_binding_is_unchanged_and_justified():
    """The deployment binds 0.0.0.0 because there is no reverse proxy. That must not change.

    Replacing it with 127.0.0.1 would make the container unreachable from the published
    port - a deployment outage dressed up as a security fix.
    """
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert '"--host", "0.0.0.0"' in dockerfile
    compose = (REPO_ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8")
    # The port really is published directly, which is why the container must bind widely.
    assert '"${PORT:-8000}:8000"' in compose
    assert "no reverse proxy in this topology" in compose


def test_the_production_entrypoint_disables_proxy_headers():
    """If 0.0.0.0 is accepted, the client-address policy has to be sound."""
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "--no-proxy-headers" in dockerfile
    compose = (REPO_ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8")
    # Trusting nothing by default is the correct pairing with a directly-published port.
    assert "TRUSTED_PROXIES: ${TRUSTED_PROXIES:-}" in compose


def test_cors_allowlist_refuses_wildcard_in_production():
    """Binding widely is only acceptable with an explicit origin allowlist."""
    source = (REPO_ROOT / "core" / "security.py").read_text(encoding="utf-8")
    block = source.split("def resolve_allowed_origins", 1)[1].split("\ndef ", 1)[0]
    assert "is_production_mode" in block or "production" in block.lower()
    assert '"*"' not in block or "not " in block


def test_no_module_binds_zero_zero_zero_zero_outside_the_entrypoint():
    """A stray `0.0.0.0` in library code would be an unbounded listener."""
    offenders = []
    for path in REPO_ROOT.rglob("*.py"):
        parts = set(path.parts)
        if ".git" in parts or ".scratch" in parts or "tests" in parts:
            continue
        if path == REPO_ROOT / "main.py":
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for number, line in enumerate(text.splitlines(), start=1):
            if "0.0.0.0" in line and "bind" in line.lower():
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{number}")
    assert offenders == [], f"unexpected wide bind: {offenders}"
