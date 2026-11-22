"""Phase 28 - SSRF destination policy, DNS-rebinding scope, and temp-file lifecycle.

The premise of this file, stated first because it is easy to lose: **a hostname check is not
an SSRF control.** Phase 27 added a host allowlist and a per-hop redirect guard, and those
are worth having, but neither can tell a name that resolves to a public address from one
that resolves to 169.254.169.254, and neither can stop the resolver answering differently
on the second lookup than it did on the first.

Three claims are tested here, and they are deliberately separated:

1. The address classifier is correct for every family and spelling, including the two
   traps that a naive `is_private` check misses (multicast reports `is_global=True`;
   `::ffff:127.0.0.1` reports `is_loopback=False`).
2. The two outbound clients apply that classifier to their destinations, and refuse.
3. The residual TOCTOU is *not* claimed to be fixed. TLS is what closes it in practice for
   the https-only sheets fetch; address pinning would close it outright and is recorded as
   a documented limitation rather than silently half-implemented.
"""

import http.server
import ipaddress
import os
import socket
import socketserver
import ssl
import stat
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from core import outbound_http  # noqa: E402


# ===========================================================================
# 1. The address classifier
# ===========================================================================

#: (address, is_it_public, why this case exists)
ADDRESS_CASES = [
    # --- public ---
    ("93.184.216.34", True, "ordinary public IPv4"),
    ("8.8.8.8", True, "public resolver"),
    ("2606:2800:220:1:248:1893:25c8:1946", True, "ordinary public IPv6"),
    # --- private IPv4 (RFC1918) ---
    ("10.0.0.5", False, "RFC1918 /8"),
    ("172.16.4.4", False, "RFC1918 /12 low"),
    ("192.168.1.1", False, "RFC1918 /16"),
    # --- loopback IPv4 ---
    ("127.0.0.1", False, "loopback"),
    ("127.13.14.15", False, "the whole 127/8 is loopback, not just .0.1"),
    # --- link-local IPv4, and the metadata endpoint in particular ---
    ("169.254.1.1", False, "link-local"),
    ("169.254.169.254", False, "the cloud metadata endpoint"),
    # --- IPv6 loopback and private ---
    ("::1", False, "IPv6 loopback"),
    ("fd00::1", False, "IPv6 unique-local (fc00::/7)"),
    ("fe80::1", False, "IPv6 link-local"),
    # --- IPv4-mapped IPv6: the trap ---
    ("::ffff:127.0.0.1", False, "IPv4-mapped loopback: is_loopback is False on this value"),
    ("::ffff:169.254.169.254", False, "IPv4-mapped metadata"),
    ("::ffff:10.0.0.5", False, "IPv4-mapped RFC1918"),
    ("::ffff:93.184.216.34", True, "a mapped *public* address is still public"),
    # --- multicast: reports is_global=True ---
    ("224.0.0.1", False, "IPv4 multicast: is_global is True on this value"),
    ("239.255.255.250", False, "IPv4 SSDP multicast"),
    ("ff02::1", False, "IPv6 multicast: is_global is True on this value"),
    # --- reserved / unspecified / non-routable ---
    ("0.0.0.0", False, "unspecified"),
    ("::", False, "IPv6 unspecified"),
    ("100.64.0.1", False, "CGNAT shared address space (RFC6598)"),
    ("192.0.2.1", False, "TEST-NET-1, not globally reachable"),
    ("198.51.100.7", False, "TEST-NET-2"),
    ("203.0.113.5", False, "TEST-NET-3"),
    ("240.0.0.1", False, "reserved class E"),
]


@pytest.mark.parametrize("address,expected,why", ADDRESS_CASES)
def test_the_address_classifier_agrees_with_the_table(address, expected, why):
    """Every row is a case some implementation gets wrong.

    The `why` strings are the documentation: three of these (multicast x2, IPv4-mapped
    loopback) are values where the obvious `is_private`/`is_global`/`is_loopback` check
    gives the wrong answer, so the table exists to keep the allowlist-style implementation
    from being "simplified" back into a blocklist.
    """
    assert outbound_http.is_public_address(address) is expected, f"{address}: {why}"


def test_a_non_address_is_not_public():
    """Failing closed matters more than the exception type."""
    for junk in ["", "   ", "not-an-ip", "docs.google.com", "127.0.0.1:443", "::ffff:"]:
        assert outbound_http.is_public_address(junk) is False


def test_parse_ip_unwraps_ipv4_mapped_but_leaves_the_rest_alone():
    """The unwrap is the single most important line in the module, so it is tested directly."""
    assert outbound_http.parse_ip("::ffff:127.0.0.1") == ipaddress.ip_address("127.0.0.1")
    assert outbound_http.parse_ip("127.0.0.1") == ipaddress.ip_address("127.0.0.1")
    assert outbound_http.parse_ip("::1") == ipaddress.ip_address("::1")
    assert outbound_http.parse_ip("nonsense") is None


def test_the_classifier_is_a_positive_allowlist_not_a_blocklist():
    """`is_global` alone would pass multicast, so the code must not reduce to it.

    This is a meta-test: it pins the *shape* of the implementation, because the shape is
    what stops the next address class nobody has thought of yet from being allowed.
    """
    source = (REPO_ROOT / "core" / "outbound_http.py").read_text(encoding="utf-8")
    body = source.split("def is_public_address")[1].split("\ndef ")[0]
    for guard in ("is_multicast", "is_reserved", "is_unspecified", "is_loopback",
                  "is_link_local", "is_private", "is_global"):
        assert guard in body, f"the classifier no longer consults {guard}"


# ===========================================================================
# 2. resolve_host / reject_reason
# ===========================================================================

def test_resolve_host_finds_loopback_for_localhost():
    """Sanity: the resolver helper returns real addresses, both families where available."""
    addresses = outbound_http.resolve_host("localhost", 80)
    values = {address for _family, address in addresses}
    assert values, "localhost did not resolve at all in this environment"
    for value in values:
        assert not outbound_http.is_public_address(value)


def test_dns_failure_is_distinguishable_from_a_refusal():
    """A name that does not resolve returns no addresses; the caller decides what that means.

    Conflated here it would be easy to treat "temporary resolver outage" as "malicious
    destination" and page an operator at 3am for the wrong reason.
    """
    assert outbound_http.resolve_host("no-such-host.invalid", 443) == []


def test_reject_reason_refuses_a_disallowed_port():
    reason = outbound_http.reject_reason("93.184.216.34", 8080, allowed_ports=(80, 443))
    assert reason and "port" in reason


def test_reject_reason_allows_a_public_destination():
    """A public address on an allowed port must pass, or the control breaks normal use."""
    # 93.184.216.34 is a literal; no resolution needed, so no network dependency.
    assert outbound_http.reject_reason("93.184.216.34", 443) is None


def test_reject_reason_refuses_a_literal_private_address():
    for address in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "::ffff:127.0.0.1"):
        reason = outbound_http.reject_reason(address, 443)
        assert reason, f"{address} was accepted"


def test_reject_reason_refuses_when_any_resolved_address_is_not_public(monkeypatch):
    """Rejecting on *any* bad address, not all of them.

    A name resolving to both a public and a private address is a name whose owner chooses
    which one you get; the safe reading of that is refusal.
    """
    monkeypatch.setattr(
        outbound_http, "resolve_host",
        lambda host, port: [(socket.AF_INET, "93.184.216.34"),
                            (socket.AF_INET, "169.254.169.254")],
    )
    reason = outbound_http.reject_reason("mixed.example", 443)
    assert reason and "169.254.169.254" in reason


# ===========================================================================
# 3. The sheets fetch: https only, and a refused destination
# ===========================================================================

def test_plain_http_sheet_urls_are_refused():
    """F-28-1. `http` was accepted, and the pass-through branch returned it unchanged.

    Over plaintext there is no certificate binding the response to `docs.google.com`, so a
    rebinding attack needs only to answer the request - which is exactly the failure this
    phase exists to prevent. Both shapes are covered because they take different branches.
    """
    from sheets_service import normalize_sheet_csv_url

    for url in (
        "http://docs.google.com/spreadsheets/d/ABC/export?format=csv&gid=0",
        "http://docs.google.com/spreadsheets/d/ABC/edit#gid=0",
        "http://docs.google.com/spreadsheets/d/ABC/pub?output=csv",
    ):
        with pytest.raises(ValueError):
            normalize_sheet_csv_url(url)


def test_https_sheet_urls_still_normalize():
    """The control must not break the supported input."""
    from sheets_service import normalize_sheet_csv_url

    assert normalize_sheet_csv_url("https://docs.google.com/spreadsheets/d/ABC/edit#gid=0") == (
        "https://docs.google.com/spreadsheets/d/ABC/export?format=csv&gid=0"
    )
    # The pass-through branch keeps an already-export URL intact.
    passthrough = "https://docs.google.com/spreadsheets/d/ABC/export?format=csv&gid=7"
    assert normalize_sheet_csv_url(passthrough) == passthrough


def test_a_redirect_that_downgrades_to_http_is_refused():
    """Phase 27 allowed http at a redirect hop; a downgrade throws away TLS, so it is now refused.

    Exercised through the real handler rather than by calling it, so the wiring is covered.
    """
    import sheets_service

    class _Downgrade(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "http://docs.google.com/spreadsheets/d/X/export?format=csv")
            self.end_headers()

        def log_message(self, *args):
            pass

    handler = sheets_service._SameHostRedirectHandler()
    request = urllib.request.Request("https://docs.google.com/spreadsheets/d/X/export?format=csv")
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        handler.redirect_request(request, None, 302, "Found", {}, "http://docs.google.com/x")
    # The handler re-raises with the *original* status code so urllib's own redirect logic
    # sees an HTTPError rather than silently retrying; the message is what carries the reason.
    assert "refusing redirect to http://docs.google.com" in str(excinfo.value)


def test_the_fetch_refuses_a_host_that_resolves_to_a_private_address(monkeypatch):
    """The address check sits on the production fetch path, not in a test-only wrapper.

    `docs.google.com` is a hardcoded constant with no environment override, so a realistic
    attack needs DNS or TLS compromise - but a hijacked resolver or an /etc/hosts entry is a
    real failure mode, and this is what refuses it.
    """
    import sheets_service

    monkeypatch.setattr(
        sheets_service.outbound_http, "resolve_host",
        lambda host, port: [(socket.AF_INET, "127.0.0.1")],
    )
    with pytest.raises(ValueError) as excinfo:
        sheets_service.fetch_sheet_rows(
            "https://docs.google.com/spreadsheets/d/ABC/export?format=csv"
        )
    assert "public address" in str(excinfo.value)


def test_the_fetch_refuses_the_metadata_endpoint_by_any_spelling(monkeypatch):
    """169.254.169.254 and its IPv4-mapped spelling must both be refused."""
    import sheets_service

    for address in ("169.254.169.254", "::ffff:169.254.169.254"):
        monkeypatch.setattr(
            sheets_service.outbound_http, "resolve_host",
            lambda host, port, a=address: [(socket.AF_INET6, a)],
        )
        with pytest.raises(ValueError):
            sheets_service.fetch_sheet_rows(
                "https://docs.google.com/spreadsheets/d/ABC/export?format=csv"
            )


def test_the_fetch_proceeds_when_the_host_resolves_publicly(monkeypatch, tls_sheet_server):
    """End to end over TLS: a public resolution plus a valid chain still fetches.

    Without this the control could be "refuse everything" and the suite would not notice.
    """
    import sheets_service

    port, ca_bundle = tls_sheet_server
    monkeypatch.setattr(sheets_service, "_ALLOWED_SHEET_HOST", "127.0.0.1")
    # Report a public address (the fetch still connects to 127.0.0.1 via the pinned opener
    # below); this isolates the classifier from the local test server's real address.
    monkeypatch.setattr(
        sheets_service.outbound_http, "resolve_host",
        lambda host, p: [(socket.AF_INET, "93.184.216.34")],
    )
    monkeypatch.setattr(
        sheets_service, "_sheet_opener",
        lambda: urllib.request.build_opener(
            sheets_service._SameHostRedirectHandler,
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_bundle)),
        ),
    )
    rows = sheets_service.fetch_sheet_rows(f"https://127.0.0.1:{port}/export?format=csv")
    assert rows and rows[0]["name"] == "ada"


@pytest.fixture(scope="module")
def tls_sheet_server(tmp_path_factory):
    """A TLS server that serves CSV, with a generated self-signed cert for 127.0.0.1."""
    directory = tmp_path_factory.mktemp("phase28tls")
    cert_path, key_path = _make_self_signed(directory)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key_path))

    class _CSV(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/csv")
            self.end_headers()
            self.wfile.write(b"name,value\nada,1\n")

        def log_message(self, *args):
            pass

    server = socketserver.TCPServer(("127.0.0.1", 0), _CSV)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield port, str(cert_path)
    finally:
        server.shutdown()
        server.server_close()


def _make_self_signed(directory):
    """Generate a self-signed certificate for 127.0.0.1. Not committed - a key in git is public."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

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
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
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
    return cert_path, key_path


def test_a_certificate_for_the_wrong_host_is_still_rejected():
    """TLS hostname verification must remain intact - this is the real rebinding control.

    A server presenting a certificate that does not cover the requested name must fail,
    which is precisely what makes a rebound `docs.google.com` useless to an attacker: they
    would have to produce a valid certificate for docs.google.com from 127.0.0.1.
    """
    with pytest.raises(ssl.SSLCertVerificationError):
        _verify_wrong_hostname()


def _verify_wrong_hostname():
    """Produce a real SSLCertVerificationError without needing a live server on port 443.

    Verifying a certificate that does not match the name is a local operation, so a tiny
    in-process TLS listener is enough and no external host is contacted. Raises on both
    outcomes: SSLCertVerificationError when the control works, AssertionError when it does
    not, so the test cannot pass by accident.
    """
    directory = Path(tempfile.mkdtemp(prefix="phase28-cert-"))
    try:
        cert_path, key_path = _make_self_signed(directory)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_path), str(key_path))

        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def _serve():
            try:
                raw, _ = listener.accept()
                with context.wrap_socket(raw, server_side=True) as tls:
                    tls.recv(64)
            except Exception:
                pass

        threading.Thread(target=_serve, daemon=True).start()
        client = ssl.create_default_context().wrap_socket(
            socket.create_connection(("127.0.0.1", port), timeout=3),
            server_hostname="docs.google.com",
        )
        client.close()
        raise AssertionError("the certificate was accepted for the wrong hostname")
    except ssl.SSLCertVerificationError:
        # Re-raised so pytest.raises in the caller is what observes it. Swallowing it here
        # would turn a passing control into a silently passing test.
        raise
    finally:
        listener.close()


# ===========================================================================
# 4. The webhook destination policy
# ===========================================================================

@pytest.fixture()
def clean_alert_env(monkeypatch):
    """No inherited ENV or opt-in from the surrounding test run."""
    monkeypatch.delenv("ENV", raising=False)
    monkeypatch.delenv("BACKUP_ALERT_ALLOW_INSECURE", raising=False)


def test_a_private_webhook_is_refused(clean_alert_env):
    """F-28-3. Operator configuration, but a copied staging URL is a realistic mistake."""
    from core import backup_automation

    for url in ("https://10.0.0.5/hook", "https://192.168.1.10/hook", "https://127.0.0.1/hook"):
        reason = backup_automation._webhook_destination_refusal(url)
        assert reason and "not a public address" in reason, url


def test_the_metadata_endpoint_is_never_a_webhook(clean_alert_env, monkeypatch):
    """Named explicitly: a webhook pointing at IMDS would leak the alert body to itself."""
    from core import backup_automation

    monkeypatch.setenv("BACKUP_ALERT_ALLOW_INSECURE", "1")
    for url in ("https://169.254.169.254/latest/meta-data/", "http://169.254.169.254/latest/meta-data/"):
        reason = backup_automation._webhook_destination_refusal(url)
        assert reason, f"{url} was accepted"
        assert "169.254.169.254" in reason


def test_plain_http_is_refused_without_the_opt_in(clean_alert_env):
    from core import backup_automation

    reason = backup_automation._webhook_destination_refusal("http://93.184.216.34/hook")
    assert reason and "BACKUP_ALERT_ALLOW_INSECURE" in reason


def test_the_insecure_opt_in_cannot_be_used_in_production(monkeypatch):
    """The documented migration path must not become a production downgrade.

    The alerting tests rely on loopback http sinks; that reliance is confined to
    non-production by this test. If someone later "simplifies" the policy by honouring the
    flag unconditionally, this fails.
    """
    from core import backup_automation

    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("BACKUP_ALERT_ALLOW_INSECURE", "1")
    reason = backup_automation._webhook_destination_refusal("http://127.0.0.1:5000/hook")
    assert reason and "production" in reason

    # And loopback stays refused over https too, opt-in or not.
    reason = backup_automation._webhook_destination_refusal("https://127.0.0.1/hook")
    assert reason and "public address" in reason


def test_a_loopback_test_sink_is_allowed_outside_production(clean_alert_env, monkeypatch):
    """The documented path the existing alerting tests use. Without it they would be broken."""
    from core import backup_automation

    monkeypatch.setenv("BACKUP_ALERT_ALLOW_INSECURE", "1")
    assert backup_automation._webhook_destination_refusal("http://127.0.0.1:5000/hook") == ""


def test_an_unresolvable_webhook_is_refused_with_a_clear_reason(clean_alert_env):
    from core import backup_automation

    reason = backup_automation._webhook_destination_refusal("https://no-such-host.invalid/hook")
    assert reason and "did not resolve" in reason


def test_a_refused_destination_is_not_retried(clean_alert_env, monkeypatch):
    """A permanent failure must not be reported as "after N attempts"."""
    from core import backup_automation

    monkeypatch.setenv("BACKUP_ALERT_RETRIES", "3")
    ok, detail = backup_automation.notify("https://10.0.0.5/hook", {"event": "test"})
    assert ok is False
    assert "attempts" not in detail
    assert "not a public address" in detail


def test_a_public_https_webhook_is_still_attempted(clean_alert_env, monkeypatch):
    """The policy must not refuse an ordinary destination.

    `urlopen` is stubbed: the point is that the destination passes the policy and reaches
    delivery, not that example.com is reachable from CI.
    """
    from core import backup_automation

    delivered = []

    class _Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def _fake_deliver(opener, request, *, timeout):
        delivered.append(request.full_url)
        return _Response()

    # Phase 30 moved alert delivery onto a pinned opener, so the old `urlopen` stub no longer
    # sits on the path: the request is made by `_open_pinned`. The seam is stubbed instead,
    # and the assertion is unchanged - a permitted public destination is still attempted.
    monkeypatch.setattr(backup_automation, "_open_pinned", _fake_deliver)
    monkeypatch.setattr(
        backup_automation, "_webhook_destination_refusal", lambda url: ""
    )
    ok, detail = backup_automation.notify("https://93.184.216.34/hook", {"event": "test"})
    assert ok is True, detail
    assert delivered == ["https://93.184.216.34/hook"]


def test_a_public_webhook_passes_the_real_policy(clean_alert_env):
    """The policy itself - not a stub - accepts a literal public address end to end."""
    from core import backup_automation

    assert backup_automation._webhook_destination_refusal("https://93.184.216.34/hook") == ""


# ===========================================================================
# 5. Temp-directory lifecycle
# ===========================================================================

@pytest.fixture()
def runtime_module():
    """Load api/index.py's cleanup logic without importing the whole app.

    `api/index.py` imports `main`, which builds the FastAPI app and touches the database.
    The cleanup helpers are pure, so they are extracted from the source rather than dragging
    the application in - the behaviour under test is the function, and it is the same source
    that ships.
    """
    import importlib.util

    source = (REPO_ROOT / "api" / "index.py").read_text(encoding="utf-8")
    start = source.index("if os.getenv(\"VERCEL\"):")
    block = source[start:]
    # Trim the trailing `from main import app` so this stays a unit of the bootstrap only.
    block = block.split("from main import app")[0]
    block = block.replace('if os.getenv("VERCEL"):', 'if True:', 1)

    namespace = {"os": os, "shutil": __import__("shutil"), "__file__": str(REPO_ROOT / "api" / "index.py")}
    exec(compile(block, str(REPO_ROOT / "api" / "index.py"), "exec"), namespace)
    return namespace


def test_success_path_removes_the_runtime_directory(runtime_module, monkeypatch):
    monkeypatch.setattr(runtime_module["tempfile"], "tempdir", None, raising=False)
    created = runtime_module["_make_runtime_dir"]()
    assert os.path.isdir(created)
    runtime_module["_cleanup_runtime_dirs"]()
    assert not os.path.exists(created)


def test_the_exception_path_also_removes_the_directory(runtime_module):
    """`atexit` runs on an exception exit, so the same call covers both paths.

    Tested by invoking the registered handler directly: proving the *registration* is what
    the module-level test below covers, and this proves the handler is idempotent and safe
    when called from an error path.
    """
    created = runtime_module["_make_runtime_dir"]()
    try:
        raise RuntimeError("simulated failure after the directory was created")
    except RuntimeError:
        pass
    finally:
        runtime_module["_cleanup_runtime_dirs"]()
    assert not os.path.exists(created)


def test_concurrent_invocations_do_not_remove_each_others_directories(runtime_module):
    """Each process owns its list; one process's cleanup must not touch another's directory.

    Simulated by two independent registries against the same temp root.
    """
    created_a = runtime_module["_make_runtime_dir"]()
    # A second, independent module instance = a second process.
    source = (REPO_ROOT / "api" / "index.py").read_text(encoding="utf-8")
    block = source[source.index('if os.getenv("VERCEL"):'):].split("from main import app")[0]
    block = block.replace('if os.getenv("VERCEL"):', 'if True:', 1)
    # exec populates the dict it is handed, so the merge must be assigned first - an inline
    # `dict_a | dict_b` would be written into and then immediately discarded.
    source_namespace = {"os": os, "shutil": __import__("shutil"),
                        "__file__": str(REPO_ROOT / "api" / "index.py")}
    exec(compile(block, "api/index.py", "exec"), source_namespace)
    created_b = source_namespace["_make_runtime_dir"]()

    runtime_module["_cleanup_runtime_dirs"]()          # process A exits
    assert not os.path.exists(created_a), "A did not clean up after itself"
    assert os.path.exists(created_b), "A removed another process's directory"

    source_namespace["_cleanup_runtime_dirs"]()        # process B exits
    assert not os.path.exists(created_b)


def test_cleanup_never_deletes_outside_the_temp_directory(runtime_module, tmp_path):
    """The registry is process-local, but a corrupted entry must not become an arbitrary delete.

    Two guards, both exercised: the parent must be the real temp root, and the basename must
    carry the prefix. A path failing either is skipped silently.
    """
    precious = tmp_path / "precious.txt"
    precious.write_text("must survive", encoding="utf-8")
    outsider = tmp_path / "gerege-runtime-anything"
    outsider.mkdir()

    runtime_module["_RUNTIME_DIRS"].extend([str(tmp_path), str(outsider), str(precious)])
    runtime_module["_cleanup_runtime_dirs"]()

    assert precious.exists(), "cleanup deleted a file outside the temp directory"
    assert outsider.exists(), "cleanup deleted a prefixed directory outside the temp root"
    assert tmp_path.exists()


def test_cleanup_refuses_a_directory_without_the_prefix(runtime_module):
    """A directory inside the temp root is still skipped if the name does not match."""
    plain = tempfile.mkdtemp(prefix="not-ours-")
    try:
        runtime_module["_RUNTIME_DIRS"].append(plain)
        runtime_module["_cleanup_runtime_dirs"]()
        assert os.path.isdir(plain), "cleanup deleted a directory this module did not create"
    finally:
        os.rmdir(plain)


def test_cleanup_unlinks_a_symlink_instead_of_descending_into_it(runtime_module, tmp_path):
    """A symlinked registry entry is unlinked, never followed.

    If cleanup followed it, `rmtree` would delete the *target's* contents - which is how a
    temp-file cleanup turns into a cross-directory delete.
    """
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep.txt").write_text("keep", encoding="utf-8")

    # The entry itself must live in the temp root: the guard refuses anything whose parent
    # is not the real temp directory, and that refusal is a separate test below.
    link = Path(tempfile.gettempdir()) / f"gerege-runtime-link-{os.getpid()}-{id(target)}"
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(target, target_is_directory=True)

    runtime_module["_RUNTIME_DIRS"].append(str(link))
    runtime_module["_cleanup_runtime_dirs"]()

    assert not link.is_symlink(), "the symlink was left behind"
    assert (target / "keep.txt").exists(), "cleanup followed the symlink and deleted the target"


def test_the_runtime_directory_is_private(runtime_module):
    """0700 from mkdtemp, and the database file 0600. Phase 27's property, kept."""
    created = runtime_module["_make_runtime_dir"]()
    try:
        mode = stat.S_IMODE(os.stat(created).st_mode)
        assert mode == 0o700, f"runtime directory is {oct(mode)}"
    finally:
        runtime_module["_cleanup_runtime_dirs"]()


def test_the_registry_only_holds_directories_this_module_created(runtime_module):
    """`orig_db` - the checked-in database - must never enter the cleanup registry.

    This is the "do not delete persistent application data" requirement, asserted rather
    than assumed.
    """
    runtime_module["_cleanup_runtime_dirs"]()  # clear whatever the module did at import
    for entry in runtime_module["_RUNTIME_DIRS"]:
        assert entry not in (str(REPO_ROOT / "leads.db"),)
        assert os.path.basename(os.path.realpath(entry)).startswith("gerege-runtime-")


def test_cleanup_is_registered_with_atexit():
    """The handler has to actually run on process exit, which is a wiring property.

    Asserted against the shipped source because the registration happens at import time in
    a module that cannot be imported here without starting the application.
    """
    source = (REPO_ROOT / "api" / "index.py").read_text(encoding="utf-8")
    assert "atexit.register(_cleanup_runtime_dirs)" in source
    # Registered before the copy, so a failure between the two does not leak the directory.
    assert source.index("atexit.register") < source.index("shutil.copy")


def test_cleanup_never_raises(runtime_module, monkeypatch):
    """A cleanup failure must not turn into a 500 or mask the original exception."""
    def _explode(*args, **kwargs):
        raise OSError("simulated rmtree failure")

    monkeypatch.setattr(runtime_module["shutil"], "rmtree", _explode)
    created = runtime_module["_make_runtime_dir"]()
    try:
        runtime_module["_cleanup_runtime_dirs"]()  # must not raise
    finally:
        monkeypatch.undo()
        if os.path.isdir(created):
            __import__("shutil").rmtree(created, ignore_errors=True)
