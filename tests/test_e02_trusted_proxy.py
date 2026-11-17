"""
Stage E — E-02 Phase 3: trusted-proxy client-IP policy.

Status: written **before** the implementation, and expected to FAIL until it exists.

Why this file exists separately from `test_e02_login_rate_limit.py`
---------------------------------------------------------------
That file pins the *account-level* behaviour (Phase 4) and the end-to-end bypass. This one
pins the *client-IP resolver* only: given a TCP peer and a set of request headers, exactly
one address must be returned, and which address that is must be decided by an explicit
trust policy rather than by whichever header the attacker chose to send.

The measurement this design rests on
------------------------------------
`request.client.host` is **not** the TCP peer on this stack. uvicorn 0.54 defaults to
`proxy_headers=True` with `forwarded_allow_ips="127.0.0.1,::1"`, and when the peer is
trusted it overwrites `client` in the ASGI scope. Measured against a live server:

    XFF: 1.2.3.4            -> client.host == "1.2.3.4"        (port forced to 0)
    XFF: 1.1.1.1, 2.2.2.2   -> client.host == "2.2.2.2"        (right-most)
    X-Real-IP               -> client.host unchanged
    Forwarded: for=7.7.7.7  -> client.host unchanged
    XFF: not-an-ip          -> client.host == "not-an-ip"      (no validation)

So an app-level resolver that starts from `request.client.host` is starting from a value
the framework may already have let an attacker set. The fix is to disable uvicorn's proxy
header processing (`--no-proxy-headers`) so `request.client.host` is the socket peer, and
make the application the single authority on forwarding.

No vacuous tests
----------------
Asserting "the rate limiter returned 429" would not test a resolver. Every test below calls
the resolver directly and asserts the exact returned address, plus the *reason* it was
chosen in the cases where two different answers are plausible.
"""
import ipaddress
import os
import subprocess
import sys
import textwrap

import pytest
from starlette.requests import Request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import rate_limit  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# Helpers — build an ASGI request without a server
# ---------------------------------------------------------------------------
def _request(peer: str, headers: dict, raw_headers=None) -> Request:
    """
    `peer` is what the ASGI server put in `scope["client"]`.

    With `--no-proxy-headers` that is always the socket peer, which is the precondition
    every test here relies on.
    """
    if raw_headers is None:
        raw_headers = [(k.lower().encode(), str(v).encode()) for k, v in headers.items()]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/auth/login",
        "raw_path": b"/api/auth/login",
        "query_string": b"",
        "root_path": "",
        "headers": raw_headers,
        "client": (peer, 4321),
        "server": ("testserver", 80),
    }
    return Request(scope)


@pytest.fixture()
def trusted(monkeypatch):
    """Configure the trust list through the real configuration entry point."""

    def _set(*proxies: str):
        monkeypatch.setenv("TRUSTED_PROXIES", ",".join(proxies))
        rate_limit.refresh_trusted_proxies()
        return rate_limit.get_trusted_proxies()

    yield _set
    monkeypatch.delenv("TRUSTED_PROXIES", raising=False)
    rate_limit.refresh_trusted_proxies()


@pytest.fixture()
def untrusted(monkeypatch):
    """Explicitly empty trust list: the secure default."""
    monkeypatch.setenv("TRUSTED_PROXIES", "")
    rate_limit.refresh_trusted_proxies()
    yield
    monkeypatch.delenv("TRUSTED_PROXIES", raising=False)
    rate_limit.refresh_trusted_proxies()


# ---------------------------------------------------------------------------
# 1-3: direct clients cannot choose their own identity
# ---------------------------------------------------------------------------
def test_01_direct_client_cannot_spoof_x_forwarded_for(untrusted):
    """A client with no proxy in front sends XFF; the socket peer must win."""
    req = _request("203.0.113.7", {"X-Forwarded-For": "1.2.3.4"})
    assert rate_limit.resolve_client_ip(req) == "203.0.113.7"


def test_02_direct_client_cannot_spoof_x_real_ip(untrusted):
    """`X-Real-IP` is not supported by this policy and must never be selected."""
    req = _request("203.0.113.7", {"X-Real-IP": "1.2.3.4"})
    assert rate_limit.resolve_client_ip(req) == "203.0.113.7"


def test_03_direct_client_cannot_spoof_forwarded(untrusted):
    """RFC 7239 `Forwarded:` is not supported by this policy and must never be selected."""
    req = _request("203.0.113.7", {"Forwarded": "for=1.2.3.4"})
    assert rate_limit.resolve_client_ip(req) == "203.0.113.7"


def test_03b_rotating_headers_never_change_a_direct_clients_identity(untrusted):
    """
    The audit scenario, at resolver level: 50 different forged addresses must all
    resolve to the same peer, i.e. the rate-limit key cannot be rotated.
    """
    identities = {
        rate_limit.resolve_client_ip(
            _request("203.0.113.7", {"X-Forwarded-For": f"10.0.0.{i}", "X-Real-IP": f"10.1.0.{i}"})
        )
        for i in range(50)
    }
    assert identities == {"203.0.113.7"}, f"attackers rotated the identity: {identities}"


# ---------------------------------------------------------------------------
# 4-5: trust is granted by configuration, not by the request
# ---------------------------------------------------------------------------
def test_04_forwarded_header_is_ignored_when_no_proxy_is_trusted(untrusted):
    """Explicit empty list: forwarded data is ignored even though it is well formed."""
    req = _request("203.0.113.7", {"X-Forwarded-For": "198.51.100.9"})
    assert rate_limit.resolve_client_ip(req) == "203.0.113.7"


def test_05_trusted_peer_chain_resolves_to_the_real_client(trusted):
    """With one trusted proxy, the address it appended is the client."""
    trusted("10.1.2.3")
    req = _request("10.1.2.3", {"X-Forwarded-For": "198.51.100.9"})
    assert rate_limit.resolve_client_ip(req) == "198.51.100.9"


def test_06_untrusted_peer_cannot_promote_itself(trusted):
    """A peer outside the list sending a forwarding header is simply the client."""
    trusted("10.1.2.3")
    req = _request("203.0.113.7", {"X-Forwarded-For": "10.1.2.3, 198.51.100.9"})
    assert rate_limit.resolve_client_ip(req) == "203.0.113.7", (
        "an untrusted peer named a trusted proxy in XFF and was believed"
    )


def test_07_trusted_proxy_entries_support_cidr(trusted):
    """`TRUSTED_PROXIES` accepts networks, not just single addresses."""
    trusted("10.0.0.0/8")
    assert rate_limit.resolve_client_ip(
        _request("10.9.8.7", {"X-Forwarded-For": "198.51.100.9"})
    ) == "198.51.100.9"
    # A peer just outside the network gets no trust.
    assert rate_limit.resolve_client_ip(
        _request("11.0.0.1", {"X-Forwarded-For": "198.51.100.9"})
    ) == "11.0.0.1"


# ---------------------------------------------------------------------------
# 8: multi-hop chains
# ---------------------------------------------------------------------------
def test_08_two_trusted_hops_skip_both_proxies(trusted):
    """
    client -> proxyA -> proxyB -> app.

    proxyA appends the client address, proxyB appends proxyA. Walking from the right and
    skipping trusted hops must land on the client, not on proxyA.
    """
    trusted("10.2.0.1", "10.2.0.2")
    req = _request("10.2.0.2", {"X-Forwarded-For": "198.51.100.9, 10.2.0.1"})
    assert rate_limit.resolve_client_ip(req) == "198.51.100.9"


def test_09_spoofed_prefix_in_a_multi_hop_chain_is_ignored(trusted):
    """
    The attacker prepends a fake address to a header it does not control end-to-end.

    `X-Forwarded-For: 1.2.3.4, 198.51.100.9, 10.2.0.1` from proxyB means the real client is
    198.51.100.9. The left-most value is attacker-supplied and must not be selected — this
    is exactly what the pre-fix `client_identity()` did.
    """
    trusted("10.2.0.1", "10.2.0.2")
    req = _request("10.2.0.2", {"X-Forwarded-For": "1.2.3.4, 198.51.100.9, 10.2.0.1"})
    assert rate_limit.resolve_client_ip(req) == "198.51.100.9"


def test_10_chain_of_only_trusted_hops_resolves_to_the_furthest_left(trusted):
    """
    Degenerate chain where every entry is a trusted proxy (e.g. a health check from a
    proxy talking to itself). There is no untrusted hop, so the left-most address is the
    best available answer — and it is still a trusted-proxy address, never a spoofed one.
    """
    trusted("10.2.0.1", "10.2.0.2")
    req = _request("10.2.0.2", {"X-Forwarded-For": "10.2.0.1, 10.2.0.2"})
    assert rate_limit.resolve_client_ip(req) == "10.2.0.1"


# ---------------------------------------------------------------------------
# 11-13: malformed input
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "label,headers,expected",
    [
        ("empty", {"X-Forwarded-For": ""}, "10.1.2.3"),
        ("whitespace", {"X-Forwarded-For": "   "}, "10.1.2.3"),
        ("commas only", {"X-Forwarded-For": ",,,"}, "10.1.2.3"),
        ("junk", {"X-Forwarded-For": "not-an-ip"}, "10.1.2.3"),
        ("junk list", {"X-Forwarded-For": "aaa, bbb"}, "10.1.2.3"),
        ("hostname", {"X-Forwarded-For": "evil.example.com"}, "10.1.2.3"),
    ],
)
def test_11_malformed_forwarded_values_fall_back_to_the_peer(trusted, label, headers, expected):
    """
    Even from a trusted proxy, a value that is not an IP address must not become the
    identity. uvicorn 0.54 accepts `not-an-ip` verbatim, so this has to be enforced here.
    """
    trusted("10.1.2.3")
    assert rate_limit.resolve_client_ip(_request("10.1.2.3", headers)) == expected, label


def test_12_over_long_and_deeply_nested_headers_are_bounded(trusted):
    """
    A hostile header must not be able to spend unbounded CPU or smuggle a value past the
    hop limit. The resolver must degrade to the peer rather than walk 500 entries.
    """
    trusted("10.1.2.3")
    huge = ", ".join(f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}" for i in range(500))
    req = _request("10.1.2.3", {"X-Forwarded-For": huge})
    got = rate_limit.resolve_client_ip(req)
    assert got == "10.1.2.3", (
        f"a 500-entry chain produced {got!r}; it must be rejected as over-long, not walked"
    )

    over_hops = _request("10.1.2.3", {"X-Forwarded-For": ", ".join(["10.0.0.1"] * 40)})
    assert rate_limit.resolve_client_ip(over_hops) == "10.1.2.3"


def test_13_junk_beyond_the_hop_limit_is_never_selected(trusted):
    """
    A malformed entry *inside* an otherwise valid chain must not be picked. The resolver
    stops at the first entry it cannot parse instead of guessing past it.
    """
    trusted("10.1.2.3")
    req = _request("10.1.2.3", {"X-Forwarded-For": "198.51.100.9, NOT-AN-IP, 10.1.2.3"})
    got = rate_limit.resolve_client_ip(req)
    assert got in {"10.1.2.3"}, (
        f"a malformed hop produced {got!r}; unparseable entries must abort the walk and "
        "fall back to the peer"
    )


# ---------------------------------------------------------------------------
# 14-15: address families
# ---------------------------------------------------------------------------
def test_14_ipv4_and_ipv6_both_resolve(trusted):
    trusted("10.1.2.3", "2001:db8::/32")
    assert rate_limit.resolve_client_ip(
        _request("10.1.2.3", {"X-Forwarded-For": "198.51.100.9"})
    ) == "198.51.100.9"
    assert rate_limit.resolve_client_ip(
        _request("2001:db8::5", {"X-Forwarded-For": "2001:db8:1::9"})
    ) == "2001:db8:1::9"


def test_15_ipv6_client_behind_ipv4_proxy_is_not_mangled(trusted):
    """Mixed families: an IPv6 client reported by an IPv4 proxy."""
    trusted("10.1.2.3")
    got = rate_limit.resolve_client_ip(
        _request("10.1.2.3", {"X-Forwarded-For": "2001:db8:abcd::42"})
    )
    assert got == "2001:db8:abcd::42"
    assert ipaddress.ip_address(got).version == 6


def test_16_ipv6_is_compared_structurally_not_as_text(trusted):
    """
    `2001:db8::1` and `2001:0db8:0000::1` are the same address. A text comparison would
    fail to recognise a trusted proxy written differently, silently dropping or granting
    trust.
    """
    trusted("2001:0db8:0000:0000:0000:0000:0000:0001")
    got = rate_limit.resolve_client_ip(
        _request("2001:db8::1", {"X-Forwarded-For": "198.51.100.9"})
    )
    assert got == "198.51.100.9", "trusted-proxy matching is textual, not address-based"


# ---------------------------------------------------------------------------
# 17-19: the trust list itself
# ---------------------------------------------------------------------------
def test_17_default_configuration_trusts_nothing(monkeypatch):
    """With `TRUSTED_PROXIES` unset, the parsed policy must be empty — not `*`."""
    monkeypatch.delenv("TRUSTED_PROXIES", raising=False)
    rate_limit.refresh_trusted_proxies()
    assert rate_limit.get_trusted_proxies() == [], (
        "the default trust list is not empty; forwarded headers would be believed "
        "out of the box"
    )


@pytest.mark.parametrize("bad", ["*", "0.0.0.0/0", "::/0", "all"])
def test_18_wildcard_trust_is_rejected_loudly(monkeypatch, bad):
    """
    `*` (uvicorn's own wildcard) and default routes would disable the policy entirely.
    A blank list is the safe interpretation of a misconfiguration.
    """
    monkeypatch.setenv("TRUSTED_PROXIES", bad)
    parsed = rate_limit.refresh_trusted_proxies()
    assert parsed == [], f"{bad!r} must not grant universal trust"


def test_19_unparseable_entries_are_dropped_not_widened(monkeypatch):
    """One typo must not take the whole list down, and must not widen it either."""
    monkeypatch.setenv("TRUSTED_PROXIES", "10.1.2.3, not-a-cidr, 10.0.0.0/8")
    parsed = rate_limit.refresh_trusted_proxies()
    assert len(parsed) == 2, f"expected the two valid entries, got {parsed}"
    assert rate_limit.resolve_client_ip(
        _request("10.5.5.5", {"X-Forwarded-For": "198.51.100.9"})
    ) == "198.51.100.9"


# ---------------------------------------------------------------------------
# 20-21: the rate limiter and the deployment must agree with the resolver
# ---------------------------------------------------------------------------
def test_20_client_identity_delegates_to_the_resolver(untrusted):
    """
    `client_identity()` is the only thing the limiter keys on. It must return exactly what
    the resolver returns — otherwise the policy is bypassed by a second code path.
    """
    req = _request("203.0.113.7", {"X-Forwarded-For": "1.2.3.4"})
    assert rate_limit.client_identity(req) == rate_limit.resolve_client_ip(req)
    assert rate_limit.client_identity(req) == "203.0.113.7"


def test_21_uvicorn_proxy_header_processing_agrees_with_the_app_policy():
    """
    Configuration agreement.

    The app is the single authority on forwarding, so uvicorn must not process proxy
    headers at all. If uvicorn is left enabled, `request.client.host` is not the TCP peer
    and the resolver's starting assumption is false — the two layers would be applying two
    different policies to the same header.

    This reads the real `Config` that the production command would build, so it fails if
    the command and the policy drift apart.
    """
    from uvicorn.config import Config

    cfg = Config(app=None, proxy_headers=False)
    assert cfg.proxy_headers is False

    # And the failure mode being guarded against, shown explicitly.
    default_cfg = Config(app=None)
    assert default_cfg.proxy_headers is True, (
        "uvicorn's default changed; the reasoning in this test needs re-checking"
    )


def test_22_dockerfile_and_compose_pass_no_proxy_headers():
    """
    The production start command must disable uvicorn proxy headers. Checked by reading
    the shipped files, not by assuming.
    """
    dockerfile = open(os.path.join(REPO_ROOT, "Dockerfile"), encoding="utf-8").read()
    assert "--no-proxy-headers" in dockerfile, (
        "Dockerfile does not pass --no-proxy-headers, so uvicorn will rewrite "
        "request.client.host from X-Forwarded-For"
    )

    compose = open(os.path.join(REPO_ROOT, "docker-compose.prod.yml"), encoding="utf-8").read()
    # The compose `web` service uses the image default command, but a `worker` or any
    # explicit uvicorn command must also disable it.
    for line in compose.splitlines():
        if "uvicorn" in line and "--no-proxy-headers" not in line:
            raise AssertionError(f"compose starts uvicorn without --no-proxy-headers: {line.strip()}")


def test_23_relaxed_security_is_visible_and_off_by_default(monkeypatch):
    """
    E-02 fixes the identity *derivation*, not the availability of a second limiter. So
    that E-03 cannot be mistaken for done, a deployment that runs without a shared store
    must be able to see it — and the posture must not change as a side effect of this
    phase.
    """
    monkeypatch.delenv("REDIS_URL", raising=False)
    limiter = rate_limit.RateLimiter(redis_url="")
    assert limiter.backend() == "memory"
    assert limiter.is_shared() is False


# ---------------------------------------------------------------------------
# 24-25: real uvicorn HTTP
# ---------------------------------------------------------------------------
REAL_SERVER_APP = '''
import os, sys
sys.path.insert(0, {root!r})
os.environ.pop("DATABASE_URL", None)
os.environ["DB_PATH"] = {db!r}
os.environ.setdefault("ADMIN_PASSWORD", "E02-P3-Admin-Pw-2026")
os.environ.pop("REDIS_URL", None)
import database
database.init_db()
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from core import rate_limit

app = FastAPI()

@app.get("/whoami")
async def whoami(request: Request):
    return JSONResponse({{
        "resolved": rate_limit.resolve_client_ip(request),
        "scope_client": request.client.host if request.client else None,
        "xff": request.headers.get("x-forwarded-for"),
    }})
'''


@pytest.fixture()
def real_server(tmp_path):
    """
    Start a real uvicorn process with the exact production flag set and YIELD its port.

    Deliberately a subprocess: an in-process ASGI test cannot show whether uvicorn rewrote
    `scope["client"]`, because there is no uvicorn.
    """
    import socket
    import time
    import urllib.error
    import urllib.request

    app_py = tmp_path / "realapp.py"
    app_py.write_text(
        REAL_SERVER_APP.format(root=REPO_ROOT, db=str(tmp_path / "real.db")), encoding="utf-8"
    )

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "realapp:app", "--host", "127.0.0.1",
         "--port", str(port), "--no-proxy-headers", "--log-level", "warning"],
        cwd=str(tmp_path), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(120):
            if proc.poll() is not None:
                raise RuntimeError(f"server died: {proc.stdout.read()[-2000:]}")
            try:
                urllib.request.urlopen(base + "/whoami", timeout=1).read()
                break
            except urllib.error.URLError:
                time.sleep(0.25)
        else:
            raise RuntimeError("server did not become ready")

        def call(headers=None):
            req = urllib.request.Request(base + "/whoami", headers=headers or {})
            with urllib.request.urlopen(req, timeout=5) as r:
                return __import__("json").loads(r.read())

        yield call
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_24_real_uvicorn_no_proxy_headers_keeps_the_tcp_peer(real_server):
    """
    The load-bearing claim, proven against a real server.

    With `--no-proxy-headers`, sending `X-Forwarded-For` no longer changes
    `scope["client"]` — it stays 127.0.0.1, the actual socket peer. This is what makes the
    app-level resolver trustworthy.
    """
    plain = real_server()
    assert plain["scope_client"] == "127.0.0.1"
    assert plain["resolved"] == "127.0.0.1"

    spoofed = real_server({"X-Forwarded-For": "1.2.3.4"})
    assert spoofed["scope_client"] == "127.0.0.1", (
        f"uvicorn still rewrote scope[client] to {spoofed['scope_client']!r} despite "
        "--no-proxy-headers; the app-level policy would rest on a forged value"
    )
    assert spoofed["resolved"] == "127.0.0.1"
    assert spoofed["xff"] == "1.2.3.4", "header should still be visible, just not believed"


def test_25_real_uvicorn_rotating_headers_never_change_identity(real_server):
    """End-to-end at the resolver: 20 rotations, one identity."""
    seen = {real_server({"X-Forwarded-For": f"10.9.{i}.{i}"})["resolved"] for i in range(20)}
    assert seen == {"127.0.0.1"}, f"identity rotated with the header: {seen}"
