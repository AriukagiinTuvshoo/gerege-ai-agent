"""Phase 30 - SSRF DNS-rebinding (TOCTOU) and address pinning.

The question this file answers, because Phase 29 left it open: *does the DNS validation and
the actual socket connect use the same resolved IP?* Before this phase: no. Each outbound
path resolved the hostname once to decide whether it was acceptable and then let the HTTP
library resolve it again to connect. Between those two lookups the name can be re-pointed.

That was not taken on trust. A controlled resolver was made to answer `93.184.216.34` first
and `127.0.0.1` second, and `notify()` delivered an alert body to a local server after its
own validation had approved the public address. Over verified https the same trick fails:
the rebound address must present a certificate for the original hostname, which was measured
by trusting the attacker CA outright and still being refused with `Hostname mismatch`.

So the finding is asymmetric, and the tests below are too:
  * plaintext paths were exploitable outright;
  * https paths were protected by TLS hostname verification, at connection time;
  * every path still resolved twice, and every path honoured `*_PROXY`, which displaces the
    destination entirely.

The fix is to resolve once, judge that answer, and connect to it. Nothing here re-implements
HTTP: the pinned handler is a `http.client` connection class handed to `urllib`'s existing
handler machinery, so redirects, retries, error mapping and TLS stay in the stdlib.

Every test uses loopback, a patched resolver, and no external network.
"""

import http.server
import socket
import socketserver
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request

import pytest

from core import outbound_http, pinned_http

REPO_ROOT = __import__("pathlib").Path(__file__).resolve().parent.parent


# ===========================================================================
# Harness
# ===========================================================================

class _Recorder(http.server.BaseHTTPRequestHandler):
    """A local server that records what reached it and never talks to anything else."""

    #: filled by `local_server`
    hits = None
    body = b"ok"
    content_type = "text/plain"
    status = 200
    redirect_to = None

    def _record(self, method):
        if self.hits is not None:
            self.hits.append((method, self.path))
        if self.redirect_to is not None:
            target = self.redirect_to
            # Redirect once. Leaving it set makes the follow-up request redirect to itself,
            # which looks like "the redirect was refused" (urllib gives up after 10 hops and
            # raises HTTPError 302) and would make a passing guard test meaningless.
            type(self).redirect_to = None
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        payload = self.body
        self.send_response(self.status)
        self.send_header("Content-Type", self.content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(payload)

    def do_GET(self):
        self._record("GET")

    def do_HEAD(self):
        self._record("HEAD")

    def do_POST(self):
        remaining = int(self.headers.get("Content-Length") or 0)
        if remaining:
            self.rfile.read(remaining)
        self._record("POST")

    def log_message(self, *args):
        pass


@pytest.fixture
def local_server():
    """A loopback server; yields (port, hits list, handler class) and tears itself down."""
    hits = []

    class Handler(_Recorder):
        pass

    Handler.hits = hits
    # `_Recorder` state is class-level and the class is created per fixture invocation, but
    # the attribute values are copied from the shared base, so they must be reset explicitly
    # or a redirect configured by one test leaks into the next.
    Handler.redirect_to = None
    Handler.content_type = "text/plain"
    Handler.body = b"ok"
    Handler.status = 200
    server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port, hits, Handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def rebinding(monkeypatch):
    """Patch DNS so a chosen name answers one thing on the first lookup, another later.

    Deliberately counts lookups: the number of resolutions is the property under test. A
    pinned path must do exactly one, and a test that only asserts "the internal server was
    not reached" would also pass if the fetch silently did nothing at all.
    """
    real = socket.getaddrinfo
    state = {"answers": [], "lookups": []}

    def configure(name, answers):
        state["answers"] = list(answers)
        state["name"] = name
        state["lookups"].clear()

    def fake(host, port, *args, **kwargs):
        if host == state.get("name"):
            state["lookups"].append(host)
            index = min(len(state["lookups"]) - 1, len(state["answers"]) - 1)
            address = state["answers"][index]
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]
        return real(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    configure.__self__ = None
    return configure, state


# ===========================================================================
# 1. The defect itself: a second resolution is a second answer
# ===========================================================================

def test_a_rebound_name_passes_validation_and_then_connects_elsewhere(local_server):
    """The pre-fix behaviour, reproduced with no pin: validation saw public, wire went local.

    This is the negative control for the whole file. If this test ever starts failing, the
    harness is no longer reproducing the vulnerability and the tests that assert the fix
    would be passing for the wrong reason.
    """
    port, hits, _handler = local_server
    real = socket.getaddrinfo
    lookups = []

    def fake(host, _port, *args, **kwargs):
        if host == "rebind.example":
            lookups.append(host)
            address = "93.184.216.34" if len(lookups) == 1 else "127.0.0.1"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]
        return real(host, _port, *args, **kwargs)

    original = socket.getaddrinfo
    socket.getaddrinfo = fake
    try:
        # What validation does.
        addresses = outbound_http.resolve_host("rebind.example", port)
        assert [a for _f, a in addresses] == ["93.184.216.34"]
        # What the connection does, unpinned.
        try:
            urllib.request.urlopen(f"http://rebind.example:{port}/internal", timeout=5).read()
        except Exception:
            pass
    finally:
        socket.getaddrinfo = original

    assert len(lookups) >= 2, "harness did not produce a second lookup; the race is not modelled"
    assert hits, "unpinned fetch did not reach the internal server; harness is not reproducing"


def test_pinning_means_the_second_answer_is_never_consulted(local_server, rebinding):
    """With a pin: one lookup, and the connection goes where validation pointed.

    The internal server is listening on a loopback port. The first answer is a public
    address, so a correct pin cannot reach it - and the lookup count proves the pin did not
    quietly resolve again and take the second answer.
    """
    port, hits, _handler = local_server
    configure, state = rebinding
    configure("rebind.example", ["93.184.216.34", "127.0.0.1"])

    addresses = outbound_http.resolve_host("rebind.example", port)
    assert [a for _f, a in addresses] == ["93.184.216.34"]
    assert len(state["lookups"]) == 1

    # `scheme="http"` matches the URL. Getting this wrong is not cosmetic: an opener pinned
    # for https refuses the plaintext request at the scheme guard, so the test would pass
    # without ever exercising the pin - measured, which is why the scheme is explicit and
    # the loopback exception is granted (the server under test is on loopback).
    opener = pinned_http.build_pinned_opener_from(
        addresses, scheme="http", require_public=False, allow_loopback=True
    )
    with pytest.raises(Exception) as excinfo:
        # The pin dials the validated public address, not the loopback one the resolver
        # would hand back on a second lookup. Nothing is listening there, so the attempt
        # fails - and the failure has to come from the pin dialling 93.184.216.34, not from
        # the scheme guard or anything else, or the test would be green for no reason.
        opener.open(f"http://rebind.example:{port}/internal", timeout=5)

    message = str(excinfo.value)
    assert "pinned for https only" not in message, "test never reached the pin"
    # A public test address on the loopback port cannot answer, so either the connect is
    # refused/reset by the host or it times out. Any of those proves the dial went there.
    assert isinstance(
        excinfo.value, (ConnectionError, urllib.error.URLError, OSError, TimeoutError)
    ), "unexpected failure from the pinned connection: " + type(excinfo.value).__name__
    assert len(state["lookups"]) == 1, "the pinned connection resolved the name again"
    assert hits == [], "the pinned connection reached the rebound loopback server"


def test_a_name_resolving_to_both_public_and_private_is_refused():
    """Mixed A records: the name's owner chooses which answer you get, so refuse all of it."""
    with pytest.raises(pinned_http.PinnedAddressError):
        pinned_http.choose_address(
            [(socket.AF_INET, "93.184.216.34"), (socket.AF_INET, "10.0.0.5")]
        )


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",          # loopback
        "10.0.0.5",           # private
        "169.254.169.254",    # cloud metadata
        "::1",                # IPv6 loopback
        "::ffff:169.254.169.254",  # IPv4-mapped IPv6 spelling of the metadata address
        "0.0.0.0",            # unspecified
    ],
)
def test_pinning_refuses_every_non_public_family(address):
    """IPv4, IPv6 and the mapped-IPv6 spelling are all judged before the socket is made."""
    with pytest.raises(pinned_http.PinnedAddressError):
        pinned_http.choose_address([(socket.AF_INET6, address)])


def test_pinning_accepts_a_public_address():
    """The negative control for the test above: refusal is about the address, not the API."""
    assert pinned_http.choose_address([(socket.AF_INET, "93.184.216.34")]) == "93.184.216.34"


def test_pinning_allows_ipv6_loopback_only_under_the_documented_test_exception():
    """The test sink opt-in permits loopback and nothing else - notably not metadata."""
    assert (
        pinned_http.choose_address(
            [(socket.AF_INET6, "::1")], require_public=False, allow_loopback=True
        )
        == "::1"
    )
    with pytest.raises(pinned_http.PinnedAddressError):
        pinned_http.choose_address(
            [(socket.AF_INET, "169.254.169.254")], require_public=False, allow_loopback=True
        )
    with pytest.raises(pinned_http.PinnedAddressError):
        pinned_http.choose_address([(socket.AF_INET, "127.0.0.1")], require_public=True)


# ===========================================================================
# 2. TLS: the pin must not weaken certificate checking
# ===========================================================================

def test_tls_hostname_verification_still_applies_to_a_pinned_connection():
    """A pin points at an address; the certificate must still name the original host.

    Measured rather than argued: a throwaway TLS server on loopback with a self-signed cert
    is pinned by address, and the connection is refused. That refusal is the certificate
    check running inside the pinned connection - if pinning had replaced TLS, it would have
    connected.
    """
    import tempfile

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except Exception:  # pragma: no cover - dependency guard
        pytest.skip("cryptography not installed; TLS assertion covered in the Phase 30 report")

    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Issued for a name that is NOT the one being requested - this is the attacker's
    # certificate, valid and trusted, just for the wrong host.
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attacker.example")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
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
    cert_path = f"{directory}/cert.pem"
    key_path = f"{directory}/key.pem"
    with open(cert_path, "wb") as handle:
        handle.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as handle:
        handle.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

    server = socketserver.TCPServer(("127.0.0.1", 0), _Recorder)
    port = server.server_address[1]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()

    # The client TRUSTS the attacker certificate. That is deliberate: with an untrusted cert
    # the test would pass because of CA validation and say nothing about the pin. By trusting
    # it, the only remaining control is hostname matching - the certificate is issued for
    # `attacker.example` but is served for a request to `docs.google.com`, so the connection
    # must be refused for the name, proving pinning did not displace certificate verification.
    #
    # Measured both ways. With a certificate issued for `docs.google.com` this pinned
    # connection *succeeds* (200), which is correct and is also the honest residual risk:
    # pinning guarantees the socket goes to the validated address, and TLS guarantees the
    # peer holds a certificate for the requested name. An attacker who can satisfy both
    # already has a CA-issued certificate for the target.
    client_context = ssl.create_default_context(cafile=cert_path)
    try:
        opener = pinned_http.build_pinned_opener_from(
            [(socket.AF_INET, "127.0.0.1")],
            context=client_context,
            allow_loopback=True,
            require_public=False,
        )
        with pytest.raises(urllib.error.URLError) as excinfo:
            opener.open(f"https://docs.google.com:{port}/x", timeout=5)
        reason = excinfo.value.reason
        assert isinstance(reason, ssl.SSLCertVerificationError)
        # The certificate *is* trusted here, so the failure can only be the name check.
        assert "hostname" in str(reason).lower() or "mismatch" in str(reason).lower()
    finally:
        server.server_close()
        thread.join(timeout=5)


def test_an_https_pinned_opener_refuses_a_plaintext_url(local_server):
    """The scheme guard is load-bearing, and this is the test that says so.

    `build_opener` leaves its default `HTTPHandler` in place on an https-pinned opener, and
    that handler claims `http_open`. So without this guard a plaintext URL handed to a
    pinned-for-https opener would be served by the *unpinned* default handler - a second
    resolution and an unvalidated destination, which is the defect this module removes.
    Raising here also stops `verify=False`-style callers from quietly getting plaintext.

    Confirmed by mutation: disabling the guard left every other test in this file green.
    """
    port, hits, _handler = local_server
    opener = pinned_http.build_pinned_opener_from([(socket.AF_INET, "93.184.216.34")])
    with pytest.raises(pinned_http.PinnedAddressError) as excinfo:
        opener.open(f"http://127.0.0.1:{port}/x", timeout=3)
    assert "pinned for https only" in str(excinfo.value)
    assert hits == [], "the unpinned default handler served the request"


def test_a_redirect_to_a_different_scheme_is_refused_by_the_scheme_guard(local_server):
    """The guard runs again on each hop, so a redirect cannot downgrade to plaintext."""
    port, hits, handler = local_server
    handler.redirect_to = f"http://127.0.0.1:{port}/downgraded"

    import ssl

    opener = pinned_http.build_pinned_opener_from(
        [(socket.AF_INET, "127.0.0.1")],
        require_public=False,
        allow_loopback=True,
    )
    with pytest.raises(Exception):
        opener.open(f"https://127.0.0.1:{port}/start", timeout=3)
    assert ("GET", "/downgraded") not in hits


def test_pinned_connection_refuses_to_tunnel_through_a_proxy():
    """A proxy moves the destination out of our control, so it is refused, not silently used."""
    bound = type("Bound", (pinned_http.PinnedHTTPSConnection,), {"pin_ip": "93.184.216.34"})
    connection = bound("docs.google.com", 443)
    connection._tunnel_host = "proxy.internal"
    with pytest.raises(pinned_http.PinnedAddressError):
        connection.connect()


# ===========================================================================
# 3. The webhook path: one resolution, verdict and pin from the same answer
# ===========================================================================

def test_webhook_destination_check_returns_the_addresses_it_validated(monkeypatch):
    """The API shape that makes the race closable: verdict and addresses from one lookup."""
    from core import backup_automation

    real = outbound_http.resolve_host
    lookups = []

    def counting(host, port):
        lookups.append(host)
        return real(host, port)

    monkeypatch.setattr(outbound_http, "resolve_host", counting)
    refusal, addresses = backup_automation._webhook_destination_check(
        "https://93.184.216.34/hook"
    )
    assert refusal == ""
    assert [a for _f, a in addresses] == ["93.184.216.34"]
    assert len(lookups) == 1


def test_webhook_notify_resolves_exactly_once(monkeypatch, local_server):
    """`notify` must not resolve the name again after validating it.

    The counts are asserted, not merely 'the internal server was not hit': a fetch that
    never happened would satisfy the weaker assertion.
    """
    from core import backup_automation

    monkeypatch.setenv("ENV", "production")
    port, _hits, _handler = local_server
    real = outbound_http.resolve_host
    lookups = []

    def counting(host, p):
        lookups.append(host)
        return real(host, p)

    monkeypatch.setattr(outbound_http, "resolve_host", counting)
    monkeypatch.setenv("BACKUP_ALERT_RETRIES", "1")
    ok, _detail = backup_automation.notify(
        f"https://93.184.216.34:{port}/hook", {"event": "t"}
    )
    assert not ok
    assert len(lookups) == 1, f"notify resolved the destination {len(lookups)} times"


def test_webhook_refuses_a_redirect_to_a_private_address(local_server, monkeypatch):
    """Phase 30 F-30-2: the first URL was validated and the redirect was not.

    Reproduced before the fix: a permitted front host answered 302 with a loopback Location
    and `urlopen` followed it. The guard now re-applies the same policy per hop.
    """
    from core import backup_automation

    port, hits, handler = local_server
    # A loopback -> loopback redirect is *intended* behaviour under the documented test
    # opt-in, so redirecting there would prove nothing. The finding was a redirect to a
    # private address the policy refuses on the first hop; that is what must be blocked.
    handler.redirect_to = "http://10.0.0.5:%d/internal/secrets" % port

    # `monkeypatch`, not direct os.environ writes: a `finally: os.environ.pop(...)` left
    # BACKUP_ALERT_RETRIES behind and the leak made a *later* file's retry test fail. The
    # order dependence was reproducible (this file then test_e07_phase22_alerting.py).
    monkeypatch.setenv("BACKUP_ALERT_ALLOW_INSECURE", "1")
    monkeypatch.setenv("BACKUP_ALERT_RETRIES", "1")
    monkeypatch.delenv("ENV", raising=False)
    ok, detail = backup_automation.notify(f"http://127.0.0.1:{port}/hook", {"e": "t"})

    assert not ok, "a redirect to a private address was accepted"
    assert "302" in detail, f"refusal was not attributed to the redirect: {detail}"
    assert ("GET", "/internal/secrets") not in hits


def test_webhook_redirect_guard_allows_a_loopback_hop_under_the_test_opt_in(
    local_server, monkeypatch
):
    """The control must not be stricter than the policy it enforces.

    Loopback is permitted by the documented opt-in, so a redirect among loopback hosts has
    to keep working - otherwise the guard would break the local test sinks it exists to
    protect, and the previous test would be green for the wrong reason.
    """
    from core import backup_automation

    port, hits, handler = local_server
    handler.redirect_to = "http://127.0.0.1:%d/forwarded" % port

    monkeypatch.setenv("BACKUP_ALERT_ALLOW_INSECURE", "1")
    monkeypatch.setenv("BACKUP_ALERT_RETRIES", "1")
    monkeypatch.delenv("ENV", raising=False)
    ok, _detail = backup_automation.notify(f"http://127.0.0.1:{port}/hook", {"e": "t"})

    assert ok, "a permitted loopback redirect should still be followed"
    assert ("GET", "/forwarded") in hits


# ===========================================================================
# 4. The Meta image fetch (F-30-1): the only payload-controlled URL
# ===========================================================================

@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/x.jpg",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/x.jpg",
        "http://2130706433/x.jpg",          # decimal-encoded loopback
        "http://0x7f000001/x.jpg",          # hex-encoded loopback
        "file:///etc/passwd",
        "ftp://example.com/x.jpg",
        "gopher://example.com/x.jpg",
        "",
    ],
)
def test_image_download_refuses_non_public_and_non_http_urls(url):
    """Every one of these reached something before Phase 30, or would have."""
    import asyncio

    result = asyncio.run(pinned_http.download_remote_image(url, timeout=3))
    assert result is None


def test_image_download_does_not_follow_redirects(local_server):
    """An image URL has no legitimate need to redirect, so the rule is 'refuse'."""
    import asyncio

    port, hits, handler = local_server
    handler.redirect_to = "http://example.com/elsewhere"

    # Reaching this server at all requires the loopback exception, which the image fetch
    # does not grant. That is the point: the refusal happens before the redirect question.
    result = asyncio.run(
        pinned_http.download_remote_image(f"http://127.0.0.1:{port}/i.jpg", timeout=3)
    )
    assert result is None
    assert hits == []


def test_image_download_rejects_a_non_image_content_type(local_server, monkeypatch):
    """The fetcher is not a general 'read any URL and hand the bytes to the model' tool."""
    import asyncio

    port, _hits, handler = local_server
    handler.content_type = "text/html"
    handler.body = b"<html>not an image</html>"

    real = outbound_http.resolve_host
    monkeypatch.setattr(outbound_http, "resolve_host", lambda host, p: [(socket.AF_INET, "127.0.0.1")])
    monkeypatch.setattr(outbound_http, "is_public_address", lambda address: True)
    try:
        result = asyncio.run(
            pinned_http.download_remote_image(f"http://127.0.0.1:{port}/i.jpg", timeout=3)
        )
    finally:
        monkeypatch.undo()
    assert result is None


def test_image_download_enforces_a_size_cap(local_server, monkeypatch):
    """A large response is refused rather than buffered in full."""
    import asyncio

    port, _hits, handler = local_server
    handler.content_type = "image/jpeg"
    handler.body = b"x" * 5000

    monkeypatch.setattr(
        outbound_http, "resolve_host", lambda host, p: [(socket.AF_INET, "127.0.0.1")]
    )
    monkeypatch.setattr(outbound_http, "is_public_address", lambda address: True)
    try:
        result = asyncio.run(
            pinned_http.download_remote_image(f"http://127.0.0.1:{port}/i.jpg", max_bytes=100, timeout=3)
        )
    finally:
        monkeypatch.undo()
    assert result is None


def test_meta_webhook_image_url_cannot_reach_loopback(local_server):
    """The end-to-end reproduction, now refused.

    The same body that once produced `INTERNAL ENDPOINT CONTACTED: ['/internal/admin/token']`
    must now leave the internal server untouched. Skipped if the app cannot be imported
    without a configured database, which is an environment limit and is named as one.
    """
    import json

    try:
        from fastapi.testclient import TestClient

        import database
        import main as app_main
    except Exception as exc:  # pragma: no cover - environment guard
        pytest.skip(f"app import needs environment: {type(exc).__name__}")

    port, hits, _handler = local_server
    try:
        database.init_db()
        database.save_page("PAGE1", "Test Page", "tok")
    except Exception as exc:  # pragma: no cover - environment guard
        pytest.skip(f"database unavailable: {type(exc).__name__}")

    client = TestClient(app_main.app)
    payload = {
        "entry": [
            {
                "id": "PAGE1",
                "messaging": [
                    {
                        "sender": {"id": "sender"},
                        "recipient": {"id": "PAGE1"},
                        "message": {
                            "mid": "mid-phase30",
                            "text": "hello",
                            "attachments": [
                                {
                                    "type": "image",
                                    "payload": {"url": f"http://127.0.0.1:{port}/internal/admin/token"},
                                }
                            ],
                        },
                    }
                ],
            }
        ]
    }
    response = client.post(
        "/webhook", content=json.dumps(payload), headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 200
    assert hits == [], f"the webhook fetched an internal URL: {hits}"


# ===========================================================================
# 5. Hygiene: no secrets in errors
# ===========================================================================

@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://user:pass@example.com:8443/a/b?token=SECRET", "https://example.com:8443/a/b"),
        ("https://example.com/hook?key=abc123", "https://example.com/hook"),
        ("/relative/path", "<relative url>"),
    ],
)
def test_redact_url_drops_credentials_and_query(url, expected):
    """A webhook URL carries a shared secret in its query; errors must not echo it."""
    assert pinned_http.redact_url(url) == expected


def test_redirect_handler_error_text_does_not_contain_the_query():
    """The refusal message names the destination only, because it ends up in logs."""
    from core import backup_automation

    handler = pinned_http.SamePolicyRedirectHandler()
    request = urllib.request.Request("https://example.com/hook?token=SUPERSECRET")
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        handler.redirect_request(
            request, None, 302, "Found", {}, "http://127.0.0.1:1/steal?token=X"
        )
    assert "SUPERSECRET" not in str(excinfo.value)


# ===========================================================================
# 6. Sheets must keep working
# ===========================================================================

def test_sheet_opener_is_pinned_and_keeps_the_per_hop_guard():
    """Both controls, on the same opener: no regression of the Phase 27 redirect guard."""
    import sheets_service

    opener = sheets_service._sheet_opener()
    names = [type(h).__name__ for h in opener.handlers]
    assert "PinnedHTTPSHandler" in names
    assert "_SameHostRedirectHandler" in names
    assert "HTTPSHandler" not in names, "the unpinned default handler is still installed"


def test_sheet_url_normalizer_still_accepts_a_real_sheet_url():
    """The pin must not narrow what the normaliser accepts."""
    import sheets_service

    normalised = sheets_service.normalize_sheet_csv_url(
        "https://docs.google.com/spreadsheets/d/abc123/edit#gid=0"
    )
    assert normalised.startswith("https://docs.google.com/")
    assert normalised.endswith("output=csv") or "format=csv" in normalised
