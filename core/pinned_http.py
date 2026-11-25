"""Pinned-address HTTP connections: close the resolve/connect race.

Phase 30. Phase 28 recorded this as a limitation rather than fixing it, which was
correct at the time. It is fixed now for the two paths that can use it, because the
prototype in Phase 30 showed the integration is small:

    validate the address -> dial that exact address -> keep the hostname for TLS

**What the race was.** `reject_reason()` resolves a hostname and checks the answers;
`urlopen()` then resolves the same hostname again when it connects. Those are two
independent lookups, so a resolver that answers "public" first and "127.0.0.1" second
passes the check and connects to loopback. Phase 30 proved that end to end on the
webhook path: the validation saw `93.184.216.34`, the connection reached a local server,
and the alert body was delivered to it.

**What this module does.** `PinnedHTTPSConnection` overrides `connect()` so the socket
is opened to an address the caller already validated. `self.host` is untouched, so
`urllib` still writes the correct `Host` header and `ssl` still verifies the certificate
against the original hostname (via `server_hostname=self.host`). One lookup, one
destination, no window.

**Why https, not http.** For plaintext there is no certificate to bind the response to
the name, so pinning is the only control - and pinning a plaintext connection gives
integrity of *destination* but not of *content*. The webhook path keeps a documented
plaintext escape for local test sinks; that path is pinned too, and its remaining
weakness is the absence of transport confidentiality, which is stated rather than fixed.

**Proxy policy: no environment proxy (Phase 31, F-31-1).** Phase 30 handled the HTTPS case
and missed the plaintext one. `_tunnel_host` is set when `urllib` CONNECTs through a proxy,
so `PinnedHTTPSConnection` refused those - but `ProxyHandler.proxy_open` serves a plaintext
request *before* any connection handler runs, so `PinnedHTTPConnection.connect()` was never
called and the pin was silently unused. Measured with `HTTP_PROXY` pointing at a local mock:
the proxy received `GET http://pinned.example/hook` and fetched it itself. The pin protected
nothing there, and no Phase 30 test noticed because none of them set a proxy variable.

The fix removes `ProxyHandler` from every opener this module builds, unconditionally. That
is Policy A: the application controls the destination, and the proxy is not part of the
trusted path. Neither caller needs one - the webhook posts to an operator-configured public
URL, and the sheet fetch is allowlisted to `docs.google.com`. An operator behind a mandatory
egress proxy gets a clear connection error rather than a quietly unpinned request.

**Residual risk, stated rather than hidden.** Environments that *require* an outbound proxy
will not work with these two paths. Supporting one safely needs an explicitly configured
trusted proxy (Policy B) with its own address validation and credential handling - a
deployment decision, not something to infer from `HTTP_PROXY`.

**What is deliberately refused.** A proxy: `_tunnel_host` is set when `urllib` decides to
CONNECT through one, and honouring the pin while a proxy is configured would dial the
proxy instead of the validated address. Refusing is the safe reading - an operator who
needs an egress proxy gets a clear error rather than a silently unpinned connection.

**Tested properties** (tests/test_e30_ssrf_pinning.py):
  * the socket goes to the pinned address, not to whatever DNS returns second;
  * TLS still verifies the original hostname (a wrong-name cert is refused);
  * the `Host` header carries the original host;
  * IPv4 and IPv6 both work;
  * redirects still flow through `urllib`'s machinery, one hop at a time;
  * a proxied request is refused rather than silently dialling the proxy.
"""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from http.client import HTTPConnection, HTTPSConnection
from typing import List, Optional, Tuple

from core import outbound_http


class PinnedAddressError(urllib.error.URLError):
    """The pinned address could not be used.

    A `URLError`, because that is the class every other "this request could not be made"
    failure raises and callers already catch it. It was `OSError` first, which quietly failed
    the Phase 27 assertion that a refused request surfaces as `HTTPError`/`URLError`: the
    refusal was working, but in a shape no caller was written to expect. Raised from
    `connect()`, where `urllib`'s own handler turns it into `URLError` anyway - declaring it
    as one means the direct calls in this module report the same thing.
    """


def choose_address(
    addresses: List[Tuple[int, str]],
    *,
    require_public: bool = True,
    allow_loopback: bool = False,
) -> str:
    """Pick the address to pin, or refuse.

    Preference order is IPv4 then IPv6 only because `create_connection` prefers the
    first supplied address; correctness does not depend on the order. Every candidate is
    checked, so a mixed record set cannot smuggle a prohibited address through by being
    second in the list.
    """
    if not addresses:
        raise PinnedAddressError("host did not resolve to any address")
    for _family, address in addresses:
        if require_public and not outbound_http.is_public_address(address):
            raise PinnedAddressError(
                f"refusing to connect: host resolves to non-public address {address}"
            )
        if allow_loopback:
            # The documented test-sink exception: a loopback address is acceptable *as the
            # first resolution's answer*, which is what this list is. It is not a licence to
            # accept a private address the resolver produced later - the whole point is that
            # there is no later lookup. Everything not public and not loopback is refused.
            parsed = outbound_http.parse_ip(address)
            if parsed is None or not (
                parsed.is_loopback or outbound_http.is_public_address(address)
            ):
                raise PinnedAddressError(
                    f"refusing to connect: {address} is neither public nor loopback, and "
                    "only a loopback test sink may be exempt"
                )
    # Sorted for determinism: the same host should pin the same way across runs, so a
    # failure is reproducible rather than depending on resolver ordering.
    return sorted(address for _f, address in addresses)[0]


class PinnedHTTPSConnection(HTTPSConnection):
    """An HTTPS connection whose socket dials `pin_ip` instead of re-resolving `host`.

    `host` keeps its normal meaning everywhere else: it is the `Host` header value and
    the name presented for certificate verification. Only the socket destination is
    replaced.
    """

    #: Set by the handler through a subclass; class attribute so `http.client`'s
    #: positional `(host, port, **kwargs)` construction from `do_open` needs no changes.
    pin_ip: Optional[str] = None

    def connect(self) -> None:  # pragma: no cover - exercised through a live TLS server
        pin = self.pin_ip
        if pin is None:
            # No pin configured: behave exactly as the base class, which is what keeps
            # this class safe to use as a drop-in when validation is unavailable.
            return super().connect()
        if self._tunnel_host:
            # A proxy would be dialled instead of the pinned address. Fail visibly.
            raise PinnedAddressError(
                "refusing to connect through a proxy: a pinned connection must reach the "
                "validated address directly. Unset the proxy environment variables, or "
                "remove the pin if the proxy itself is the trusted egress path."
            )
        sock = socket.create_connection((pin, self.port), self.timeout)
        try:
            # `server_hostname=self.host` is what keeps TLS honest: the certificate must
            # still match the original name, so a rebound address cannot serve content.
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


class SamePolicyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-apply the webhook destination policy to every redirect hop.

    Phase 30 found the webhook followed a 302 from an allowed endpoint to an internal
    address with no re-validation - the same class of bug Phase 27 fixed for the sheets
    fetch, still open here. `notify()` validated the first URL only.

    Implemented as a handler rather than a check after the fact: `urllib` calls
    `redirect_request` before issuing the follow-up, so refusing here means the internal
    request is never made. Phase 27's test proved the difference matters by asserting the
    target is never *contacted*, not merely that an exception surfaced.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        refusal = _redirect_refusal(newurl)
        if refusal:
            raise urllib.error.HTTPError(
                req.full_url,
                code,
                f"refusing redirect to {_safe_netloc(newurl)}: {refusal}",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _redirect_refusal(url: str) -> Optional[str]:
    """Why a redirect target is unacceptable, or None.

    Imported lazily because the policy lives in `core.backup_automation`, which imports
    this module - a top-level import would be circular.
    """
    from core import backup_automation

    return backup_automation._webhook_destination_refusal(url) or None


def _safe_netloc(url: str) -> str:
    """scheme://host:port only - never the query, which may carry a signed token."""
    import urllib.parse

    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "<unparseable>"
    netloc = parts.hostname or ""
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return f"{parts.scheme}://{netloc}"


class PinnedHTTPConnection(HTTPConnection):
    """The plaintext equivalent, for the documented local test-sink path only."""

    pin_ip: Optional[str] = None

    def connect(self) -> None:  # pragma: no cover - exercised via a live server
        pin = self.pin_ip
        if pin is None:
            return super().connect()
        if self._tunnel_host:
            raise PinnedAddressError("refusing to connect through a proxy")
        self.sock = socket.create_connection((pin, self.port), self.timeout)


class PinnedHTTPHandler(urllib.request.HTTPHandler):
    """`HTTPHandler` that dials the validated address."""

    def __init__(self, pin_ip: str) -> None:
        super().__init__()
        self._pinned_class = type(
            "BoundPinnedHTTPConnection", (PinnedHTTPConnection,), {"pin_ip": pin_ip}
        )

    def http_open(self, req):  # pragma: no cover - exercised via a live server
        return self.do_open(self._pinned_class, req)


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """An `HTTPSHandler` that uses `PinnedHTTPSConnection` with a fixed address.

    `AbstractHTTPHandler.do_open(http_class, req, **kwargs)` takes the connection class
    as a parameter, so the pin is injected by binding a subclass - no redirect, retry or
    error-handling behaviour is reimplemented. That is the whole reason this integration
    is small enough to trust: `urllib`'s own machinery still drives the request.
    """

    def __init__(self, pin_ip: str, *, context: Optional[ssl.SSLContext] = None) -> None:
        super().__init__(context=context)
        self._pinned_class = type(
            "BoundPinnedHTTPSConnection", (PinnedHTTPSConnection,), {"pin_ip": pin_ip}
        )

    def https_open(self, req):  # pragma: no cover - exercised via a live TLS server
        return self.do_open(self._pinned_class, req, context=self._context)


class PinnedOpenerDirector(urllib.request.OpenerDirector):
    """An opener that refuses any request whose scheme it did not pin.

    Without this the pin is silently bypassable by getting the scheme wrong: a plaintext
    request handed to an opener built with `scheme="https"` finds no pinned handler, falls
    through to `build_opener`'s default `HTTPHandler`, and resolves the name again - the exact
    defect this module exists to remove. Found by a test that expected a refusal and got a
    connection. The check is at `open` time because the URL is not known when the opener is
    built, and redirects re-enter here, so every hop is covered.
    """

    #: No default on purpose. A default of "https" let a mis-built plaintext opener look
    #: correct while the guard never fired; requiring it means the only way to obtain this
    #: class is through a builder that states the scheme it pinned.
    pinned_scheme: Optional[str] = None

    def open(self, fullurl, data=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        request = (
            fullurl
            if isinstance(fullurl, urllib.request.Request)
            else urllib.request.Request(fullurl, data=data)
        )
        scheme = self.pinned_scheme
        if scheme is None:
            raise PinnedAddressError(
                "refusing request: this opener was built without a pinned scheme, so it "
                "cannot tell whether the request would be served by a pinned handler"
            )
        if request.type.lower() != scheme:
            raise PinnedAddressError(
                f"refusing {request.type} request: this opener is pinned for "
                f"{self.pinned_scheme} only, and an unpinned scheme would resolve the "
                "destination a second time"
            )
        return super().open(request, data, timeout)


def _build_without_proxy(*handlers) -> urllib.request.OpenerDirector:
    """`build_opener`, with the environment proxy disabled.

    `build_opener` installs a `ProxyHandler` whenever `getproxies()` is non-empty, and
    `ProxyHandler.proxy_open` claims a plaintext request before any connection handler runs -
    so with a proxy variable set, `PinnedHTTPConnection.connect()` is never called and the
    pin is unused. See the module docstring for the measurement (F-31-1).

    `ProxyHandler({})` is the stdlib's own way to say "no proxies". It suppresses the
    environment-reading default, and because `__init__` only registers a `*_open` method per
    configured scheme, an empty mapping registers none - so it claims nothing and the pinned
    handler keeps the dispatch slot. Verified by reading `ProxyHandler.__init__`.

    Two earlier attempts are worth recording so they are not repeated: deleting the handler
    from `handlers` alone left `proxy_open` still claiming http; deleting it from
    `handle_open` as well left the scheme with no connection handler at all, and
    re-registering the survivors hung because `add_handler` does a `bisect.insort` into the
    very list being iterated.
    """
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), *handlers)


def build_pinned_opener(
    host: str,
    port: int,
    *,
    context: Optional[ssl.SSLContext] = None,
    extra_handlers: tuple = (),
    require_public: bool = True,
    allow_loopback: bool = False,
    scheme: str = "https",
) -> urllib.request.OpenerDirector:
    """Validate `host` once and return an opener that connects to the validated address.

    This is the single entry point the callers use, so the validation and the pin cannot
    drift apart: both come from the same resolution.
    """
    addresses = outbound_http.resolve_host(host, port)
    pin = choose_address(
        addresses, require_public=require_public, allow_loopback=allow_loopback
    )
    if scheme == "http":
        # The plaintext test-sink path. Pinning still closes the resolve/connect race;
        # what it cannot provide is content integrity, which is exactly why that path is
        # confined to a documented non-production opt-in.
        handlers = list(extra_handlers) + [PinnedHTTPHandler(pin)]
    else:
        handlers = list(extra_handlers) + [PinnedHTTPSHandler(pin, context=context)]
    # `build_opener` suppresses its default handler for a scheme when a handler instance is
    # a subclass of it (`isinstance(check, klass)`), which is exactly what Pinned*Handler is.
    # Verified by reading the source rather than assumed: relying on an extra suppression
    # mechanism here would have been dead code. The proxy handler is not suppressed by that
    # mechanism, which is why it is removed explicitly.
    return _build_without_proxy(*handlers)


def build_pinned_opener_from(
    addresses: List[Tuple[int, str]],
    *,
    context: Optional[ssl.SSLContext] = None,
    extra_handlers: tuple = (),
    require_public: bool = True,
    allow_loopback: bool = False,
    scheme: str = "https",
) -> urllib.request.OpenerDirector:
    """Build an opener from an ALREADY-VALIDATED address list.

    This exists because the obvious version had the bug it was meant to fix: `notify()`
    called `reject_reason()` (one resolution) and then `build_pinned_opener()` (a second
    resolution). The pin then used the *second* answer, which is precisely the answer an
    attacker controls. A single resolution has to be shared by the check and the pin, or
    the race is merely moved.
    """
    pin = choose_address(addresses, require_public=require_public, allow_loopback=allow_loopback)
    if scheme == "http":
        handlers = list(extra_handlers) + [PinnedHTTPHandler(pin)]
    else:
        handlers = list(extra_handlers) + [PinnedHTTPSHandler(pin, context=context)]
    base = _build_without_proxy(*handlers)
    opener = PinnedOpenerDirector()
    opener.pinned_scheme = scheme
    for handler in base.handlers:
        opener.add_handler(handler)
    return opener


#: Image types the agent will accept from a remote URL. A content-type check is not a
#: security boundary on its own, but it stops the fetch being used as a general-purpose
#: "read any URL" primitive whose bytes then reach an LLM prompt.
ALLOWED_IMAGE_PREFIXES = ("image/",)


async def download_remote_image(
    url: str,
    *,
    max_bytes: int = 8 * 1024 * 1024,
    timeout: float = 15.0,
) -> Optional[bytes]:
    """Fetch an image from an attacker-influenced URL, safely. Returns None if refused.

    Phase 30. The caller is the Meta webhook, whose `attachments[].payload.url` comes from
    the request body. Before this, the URL was passed straight to `httpx` - no scheme check,
    no address check, no redirect check, and `httpx`'s default `trust_env=True` meant an
    environment proxy could be used.

    Constraints applied, in order: http/https only; the host must resolve to a public
    address; the connection is pinned to that validated address so no second lookup can
    redirect it; redirects are not followed at all (an image URL has no legitimate need for
    one, and the simplest correct rule is to refuse rather than re-validate); the body is
    read with a hard size cap so a large response cannot exhaust memory.

    What this does NOT do: verify the image is *legitimate*. It bounds where a request can
    go and how much it can return - the authenticity question is Meta's signature's job,
    and that fails closed only in production (see `verify_meta_webhook_signature`).
    """
    import urllib.parse

    parsed = urllib.parse.urlsplit(url or "")
    if parsed.scheme.lower() not in ("http", "https"):
        return None
    host = parsed.hostname
    if not host:
        return None
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    if port not in outbound_http.DEFAULT_ALLOWED_PORTS:
        return None

    addresses = outbound_http.resolve_host(host, port)
    if not addresses:
        return None
    # Every address must be public: a name resolving to both a public and a private address
    # is a name whose owner chooses which one you get.
    for _family, address in addresses:
        if not outbound_http.is_public_address(address):
            return None

    # A pinned, non-following opener. `urllib` here rather than `httpx` because the pin only
    # exists for the former; introducing an httpx transport hook to duplicate it would be a
    # second implementation of the same control.
    import asyncio
    import ssl

    def _fetch() -> Optional[bytes]:
        import urllib.error
        import urllib.request

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None  # surface the 3xx as an HTTPError instead of following it

        try:
            opener = build_pinned_opener_from(
                addresses,
                scheme=parsed.scheme.lower(),
                context=ssl.create_default_context(),
                extra_handlers=(_NoRedirect,),
            )
            req = urllib.request.Request(url, method="GET")
            with opener.open(req, timeout=timeout) as resp:
                ctype = (resp.headers.get("Content-Type") or "").lower()
                if not ctype.startswith(ALLOWED_IMAGE_PREFIXES):
                    return None
                data = resp.read(max_bytes + 1)
                return data if len(data) <= max_bytes else None
        except Exception:
            return None

    return await asyncio.to_thread(_fetch)


def redact_url(url: str) -> str:
    """A URL safe to log: scheme, host and path, with credentials and query removed.

    A query string is where signed URLs, tokens and API keys live, and an alert or log
    line is exactly the place they must not reach.
    """
    import urllib.parse

    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "<unparseable url>"
    netloc = parts.hostname or ""
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return f"{parts.scheme}://{netloc}{parts.path}" if parts.scheme else "<relative url>"


__all__ = [
    "PinnedAddressError",
    "PinnedHTTPConnection",
    "PinnedHTTPHandler",
    "PinnedHTTPSConnection",
    "PinnedHTTPSHandler",
    "SamePolicyRedirectHandler",
    "build_pinned_opener",
    "build_pinned_opener_from",
    "PinnedOpenerDirector",
    "choose_address",
    "download_remote_image",
    "redact_url",
]

# `urllib.error` is imported for callers that catch URLError from this module's failures;
# referencing it keeps the import meaningful to linters.
_ = urllib.error
