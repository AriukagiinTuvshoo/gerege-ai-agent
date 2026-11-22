"""Phase 31 - proxy-bypass of the pin, and final review of the Phase 30 fix.

Phase 30 concluded that pinning closed the resolve/connect race. For HTTPS it did. For
plaintext it did not, and Phase 30's own tests could not see that.

**The defect (F-31-1).** A pinned opener was built by `build_opener(...)` and then its
handlers were copied onto a `PinnedOpenerDirector`. That copy included the `ProxyHandler`
that `build_opener` installs by default. With `HTTP_PROXY` set, `ProxyHandler.proxy_open`
takes the request before any connection handler runs, so `PinnedHTTPConnection.connect()`
is never called and the pin never applies. Measured against a local mock proxy:

    proxy saw: ['GET http://pinned.example/hook HTTP/1.1']
    result:    200, from the proxy

The proxy resolves and fetches the destination itself. Whatever the validator approved is
irrelevant - the request never goes to that address.

**Why Phase 30's tests missed it.** Every test ran with no proxy variables set. The pin was
configurable away by the environment, and no test varied the environment.

**Why HTTPS was safe, and why that is not a defence.** `HTTPS_PROXY` goes through
`set_tunnel`, which sets `_tunnel_host`, which `PinnedHTTPSConnection.connect()` refuses.
So the plaintext path was the hole. Relying on that asymmetry would mean the plaintext path
is safe only because its TLS sibling is stricter.

**The policy chosen (Policy A: no environment proxy).** Neither consumer of a pinned opener
needs an egress proxy: the webhook posts to an operator-configured public URL, and the sheet
fetch is restricted by a host allowlist to `docs.google.com`. The repository documents no
outbound proxy (`_TRUSTED_PROXY` in `.env.example` is about trusting inbound
`X-Forwarded-For`, a different thing). So the pin is made unconditional rather than
configurable, and an operator behind a mandatory egress proxy gets a clear error instead of
a silently unpinned connection.

Legitimate egress proxying is a deployment concern; `PROXY_ALLOW_RESIDUAL` below states what
would have to change to support it safely.
"""

import asyncio
import http.server
import os
import socket
import socketserver
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request

import pytest

from core import outbound_http, pinned_http


# ===========================================================================
# A mock forward proxy. Local only; it never forwards anything anywhere.
# ===========================================================================

class _MockProxy:
    """Accepts a proxied request and records it instead of forwarding it."""

    def __init__(self):
        self.seen = []
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(5)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            try:
                data = conn.recv(4096)
                self.seen.append(data.split(b"\r\n")[0].decode(errors="replace"))
                if data.startswith(b"CONNECT"):
                    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                else:
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            finally:
                conn.close()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass


@pytest.fixture
def proxy():
    server = _MockProxy()
    try:
        yield server
    finally:
        server.close()


@pytest.fixture
def clean_proxy_env(monkeypatch):
    """Remove any proxy variables, so a test proves its own environment."""
    for name in (
        "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
        "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy",
    ):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def _plaintext_opener(**kwargs):
    return pinned_http.build_pinned_opener_from(
        [(socket.AF_INET, "127.0.0.1")],
        scheme="http",
        require_public=False,
        allow_loopback=True,
        **kwargs,
    )


# ===========================================================================
# 1. F-31-1: the proxy bypass, and its closure
# ===========================================================================

def test_no_proxy_handler_is_installed_on_a_pinned_opener(clean_proxy_env):
    """The structural fix: a pinned opener must not contain a ProxyHandler at all.

    The environment has to have a proxy set for this test to mean anything: `build_opener`
    only installs its default `ProxyHandler` when `getproxies()` returns something, so with
    a clean environment the handler list is clean whether or not the bug exists. Measured -
    the first version of this test passed against the vulnerable code for exactly that
    reason, which is the same class of false-positive negative control Phase 30 had to fix.
    """
    clean_proxy_env.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    clean_proxy_env.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    assert urllib.request.getproxies(), "the test environment is not actually proxied"

    for opener in (_plaintext_opener(), pinned_http.build_pinned_opener_from(
        [(socket.AF_INET, "93.184.216.34")]
    )):
        names = [type(handler).__name__ for handler in opener.handlers]
        assert "ProxyHandler" not in names, (
            "a ProxyHandler is installed on a pinned opener; with a proxy variable set it "
            "takes the request before the pinned connection handler and the pin is unused"
        )


def test_http_proxy_env_var_cannot_steal_a_plaintext_pinned_request(clean_proxy_env, proxy):
    """The reproduction, now refused. This is the test Phase 30 was missing.

    With `HTTP_PROXY` pointing at the mock, the request must NOT arrive at the proxy. It
    either connects directly to the pinned address or fails; either is acceptable, and the
    one unacceptable outcome is that the proxy sees it.
    """
    clean_proxy_env.setenv("HTTP_PROXY", proxy.url)
    clean_proxy_env.setenv("http_proxy", proxy.url)

    opener = _plaintext_opener()
    try:
        opener.open("http://pinned.example/hook", timeout=3).read()
    except Exception:
        pass

    assert proxy.seen == [], (
        f"the proxy saw the request: {proxy.seen}. The pin was bypassed and the proxy "
        "resolved the destination itself."
    )


def test_https_proxy_env_var_cannot_steal_a_tls_pinned_request(clean_proxy_env, proxy):
    """The TLS path already refused this; the assertion now covers the environment too."""
    clean_proxy_env.setenv("HTTPS_PROXY", proxy.url)
    clean_proxy_env.setenv("https_proxy", proxy.url)

    opener = pinned_http.build_pinned_opener_from([(socket.AF_INET, "93.184.216.34")])
    with pytest.raises(Exception):
        opener.open("https://pinned.example/hook", timeout=3).read()

    assert proxy.seen == []


def test_all_proxy_env_var_cannot_steal_a_request(clean_proxy_env, proxy):
    """`ALL_PROXY` is consulted for both schemes; it must not reintroduce the bypass."""
    clean_proxy_env.setenv("ALL_PROXY", proxy.url)
    clean_proxy_env.setenv("all_proxy", proxy.url)

    opener = _plaintext_opener()
    try:
        opener.open("http://pinned.example/hook", timeout=3).read()
    except Exception:
        pass
    assert proxy.seen == []


def test_the_webhook_does_not_route_through_an_environment_proxy(clean_proxy_env, proxy):
    """End to end on the real caller, not just on the opener in isolation."""
    from core import backup_automation

    clean_proxy_env.setenv("HTTP_PROXY", proxy.url)
    clean_proxy_env.setenv("http_proxy", proxy.url)
    clean_proxy_env.setenv("BACKUP_ALERT_ALLOW_INSECURE", "1")
    clean_proxy_env.setenv("BACKUP_ALERT_RETRIES", "1")
    clean_proxy_env.delenv("ENV", raising=False)

    ok, _detail = backup_automation.notify(
        "http://pinned.example/hook", {"event": "backup.failure"}
    )
    assert ok is False, "a request that could not be pinned should report failure"
    assert proxy.seen == [], f"the alert body went to the proxy: {proxy.seen}"


def test_the_sheet_fetch_does_not_route_through_an_environment_proxy(clean_proxy_env, proxy):
    """Same requirement for the other pinned caller."""
    import sheets_service

    clean_proxy_env.setenv("HTTPS_PROXY", proxy.url)
    clean_proxy_env.setenv("https_proxy", proxy.url)

    opener = sheets_service._sheet_opener()
    names = [type(handler).__name__ for handler in opener.handlers]
    assert "ProxyHandler" not in names, names


# ===========================================================================
# 2. NO_PROXY must not create an inconsistent picture
# ===========================================================================

def test_no_proxy_does_not_change_which_handler_serves_the_request(clean_proxy_env, proxy):
    """`NO_PROXY=*` disables proxying, so behaviour must be identical, not merely "also safe".

    A control whose effect depends on `NO_PROXY` is a control an operator can switch off by
    accident. Both settings must produce the same handler set.
    """
    opener_without = _plaintext_opener()
    baseline = [type(handler).__name__ for handler in opener_without.handlers]

    clean_proxy_env.setenv("HTTP_PROXY", proxy.url)
    clean_proxy_env.setenv("NO_PROXY", "*")
    clean_proxy_env.setenv("no_proxy", "*")
    opener_with = _plaintext_opener()
    after = [type(handler).__name__ for handler in opener_with.handlers]

    assert baseline == after
    assert "ProxyHandler" not in after


# ===========================================================================
# 3. The pin still does its original job (no regression from the change)
# ===========================================================================

def test_pinning_still_targets_the_validated_address(clean_proxy_env):
    """Removing the proxy must not have removed the pin with it."""
    addresses = outbound_http.resolve_host("93.184.216.34", 80)
    opener = pinned_http.build_pinned_opener_from(addresses, scheme="http")
    names = [type(handler).__name__ for handler in opener.handlers]
    assert "PinnedHTTPHandler" in names
    assert "HTTPHandler" not in names, "the unpinned default handler is installed"


def test_tls_pinning_still_installs_the_pinned_tls_handler(clean_proxy_env):
    opener = pinned_http.build_pinned_opener_from([(socket.AF_INET, "93.184.216.34")])
    names = [type(handler).__name__ for handler in opener.handlers]
    assert "PinnedHTTPSHandler" in names
    assert "HTTPSHandler" not in names


def test_tls_hostname_verification_still_applies_after_the_proxy_change(clean_proxy_env):
    """A wrong-name certificate is still refused, so the fix did not disturb TLS."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except Exception:  # pragma: no cover - dependency guard
        pytest.skip("cryptography not installed")

    import datetime
    import tempfile

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attacker.example")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("attacker.example")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    directory = tempfile.mkdtemp()
    cert_path, key_path = f"{directory}/c.pem", f"{directory}/k.pem"
    with open(cert_path, "wb") as handle:
        handle.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as handle:
        handle.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

    class _Okay(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    server = socketserver.TCPServer(("127.0.0.1", 0), _Okay)
    port = server.server_address[1]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    try:
        opener = pinned_http.build_pinned_opener_from(
            [(socket.AF_INET, "127.0.0.1")],
            context=ssl.create_default_context(cafile=cert_path),
            require_public=False,
            allow_loopback=True,
        )
        with pytest.raises(urllib.error.URLError) as excinfo:
            opener.open(f"https://docs.google.com:{port}/x", timeout=5)
        assert isinstance(excinfo.value.reason, ssl.SSLCertVerificationError)
    finally:
        server.server_close()
        thread.join(timeout=5)


# ===========================================================================
# 4. Scheme handling must fail closed without relying on a default
# ===========================================================================

def test_opener_director_has_no_default_scheme():
    """A default `pinned_scheme` of https made a mis-built plaintext opener look correct.

    Requiring the attribute means the only way to get an opener is through a builder that
    states its scheme, so there is no silent value to inherit.
    """
    assert pinned_http.PinnedOpenerDirector.pinned_scheme is None


def test_a_directly_built_opener_director_refuses_rather_than_assuming_a_scheme():
    opener = pinned_http.PinnedOpenerDirector()
    with pytest.raises(pinned_http.PinnedAddressError):
        opener.open("https://example.com/")


def test_both_opener_builders_reject_proxies(clean_proxy_env, proxy):
    """The host-based builder is not used by the application, but it is public API.

    Leaving a second entry point that installs a ProxyHandler would be a bypass waiting for
    someone to wire it up.
    """
    clean_proxy_env.setenv("HTTP_PROXY", proxy.url)
    opener = pinned_http.build_pinned_opener(
        "127.0.0.1", 80, scheme="http", require_public=False, allow_loopback=True
    )
    names = [type(handler).__name__ for handler in opener.handlers]
    assert "ProxyHandler" not in names


# ===========================================================================
# 5. The image downloader inherits the same policy
# ===========================================================================

def test_image_download_refuses_to_use_an_environment_proxy(clean_proxy_env, proxy):
    """`download_remote_image` builds its opener from the same helper, so it inherits too.

    Stated as a test rather than an assumption: if its opener were ever built another way,
    this is the assertion that would fail.
    """
    clean_proxy_env.setenv("HTTP_PROXY", proxy.url)
    clean_proxy_env.setenv("HTTPS_PROXY", proxy.url)

    result = asyncio.run(
        pinned_http.download_remote_image("http://127.0.0.1:1/x.jpg", timeout=2)
    )
    assert result is None
    assert proxy.seen == []


# ===========================================================================
# 6. Residual risk, written down where the code is
# ===========================================================================

def test_proxy_residual_risk_is_documented_in_the_module():
    """An operator behind a mandatory egress proxy must be able to find out why it fails."""
    import inspect

    doc = inspect.getdoc(pinned_http) or ""
    assert "proxy" in doc.lower(), "the module does not explain its proxy policy"
    assert "ProxyHandler" in doc, "the module does not name the mechanism it removes"
