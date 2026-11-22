"""Address and destination validation shared by outbound HTTP clients.

Phase 28. Two callers need the same judgement about a destination - the Google Sheets CSV
fetch and the backup alert webhook - and a second copy of "is this IP safe?" is a copy that
will drift from the first. The same drift produced F-1 in Phase 24 (a containment check
applied to one entry point and not the other) and repeated the pattern in Phase 27 (a host
allowlist written twice, in `normalize_sheet_csv_url` and in the redirect handler).

What this module is for, stated precisely, because the honest scope matters:

**A hostname check is not an SSRF control.** It cannot distinguish a name that resolves to
`93.184.216.34` from one that resolves to `169.254.169.254`, and it cannot stop DNS from
returning a different answer for the second lookup than it did for the first. `urlopen`
performs its own resolution at connect time, so "resolve, check, then connect by name" has a
window between the two lookups.

**TLS is the control that actually closes it.** When the connection is HTTPS, the server must
present a certificate valid for the requested hostname. An attacker who rebinds the name to
127.0.0.1 must then present a certificate for `docs.google.com` from 127.0.0.1, which they
cannot. Resolution-based defences are therefore a second layer here, not the first - and for
the sheets fetch, which is HTTPS-only, they matter considerably less than they would appear.

**Address pinning closes the remainder** for clients that can support it: resolve once,
validate the address, then connect to that exact address while keeping the hostname as the
TLS identity. That removes the second lookup entirely.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import List, Optional, Tuple

#: Ports allowed for outbound webhook delivery. Operators who need another port are better
#: served by a proxy than by a wider allowlist here.
DEFAULT_ALLOWED_PORTS = (80, 443)


def parse_ip(value: str) -> Optional[ipaddress._BaseAddress]:
    """Parse an address, unwrapping IPv4-mapped IPv6 so both spellings agree."""
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        # `::ffff:127.0.0.1` reports is_loopback=False and is_private=True; unwrapping makes
        # it indistinguishable from `127.0.0.1`, which is the whole point.
        return mapped
    return address


def is_public_address(value: str) -> bool:
    """True only for a globally routable unicast address.

    Deliberately a positive test rather than a list of things to block. An allowlist of
    "public" cannot be bypassed by an address class nobody thought of; a blocklist of
    "private, loopback, link-local" can, and two of those traps are easy to miss:

    * `224.0.0.1` and `ff02::1` (multicast) report `is_global=True`, so a test built only on
      `is_global` or only on `is_private` lets them through.
    * `::ffff:169.254.169.254` reports `is_loopback=False`, so a test built on loopback alone
      lets the metadata address through in its IPv6 spelling.
    """
    address = parse_ip(value)
    if address is None:
        return False
    if getattr(address, "is_multicast", False):
        return False
    if address.is_reserved or address.is_unspecified:
        return False
    if address.is_loopback or address.is_link_local or address.is_private:
        return False
    return bool(address.is_global)


def resolve_host(host: str, port: int) -> List[Tuple[int, str]]:
    """Every address a host resolves to, as (family, address) pairs.

    Returns an empty list when resolution fails; the caller decides whether that is a
    refusal or a transient error worth retrying.
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        return []
    seen: List[Tuple[int, str]] = []
    for family, _type, _proto, _canon, sockaddr in infos:
        address = sockaddr[0]
        pair = (family, address)
        if pair not in seen:
            seen.append(pair)
    return seen


def describe_destination(host: str, port: int) -> str:
    """One line naming the destination, for an error message that does not leak much."""
    return f"{host}:{port}"


def reject_reason(
    host: str,
    port: int,
    *,
    allowed_ports: Tuple[int, ...] = DEFAULT_ALLOWED_PORTS,
) -> Optional[str]:
    """Return why a destination must be refused, or None when it is acceptable.

    Refuses: a disallowed port; a host that does not resolve; and any host where *any*
    returned address is not globally routable. Rejecting on any rather than all is the safe
    direction - a name resolving to both a public and a private address is a name whose
    owner can steer the connection.
    """
    if port not in allowed_ports:
        return f"port {port} is not in the allowed set {allowed_ports}"
    addresses = resolve_host(host, port)
    if not addresses:
        return "host did not resolve"
    for _family, address in addresses:
        if not is_public_address(address):
            return f"resolves to a non-public address ({address})"
    return None
