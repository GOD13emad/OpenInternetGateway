#!/usr/bin/env python3
"""Read-only Linux IPv6 route-inventory guard for OIG-owned tun/tap paths.

Conservative safety check: every non-link-local IPv6 route, across all
kernel tables, must use the exact OIG-owned tunnel. This is NOT proof
of DNS containment, traffic filtering, packet interception, or kill-switch.
"""
import ipaddress
import re
import sys

TUNNEL = re.compile(r"(?:tun|tap)[A-Za-z0-9_.:-]{0,12}\Z")
DEV = re.compile(r"\bdev\s+([A-Za-z0-9_.:-]+)(?:\s|$)")


class NonlocalIpv6Route(ValueError):
    """A nonlocal IPv6 route does not have an accepted owner."""


def verify_ipv6_route_inventory(routes, owned="tun1"):
    # owned=None is for read-only preflight: *no* nonlocal IPv6 route
    # is allowed before activating a full-device VPN.
    if owned is not None and not TUNNEL.fullmatch(owned):
        raise ValueError("Invalid owned tunnel interface")
    if not isinstance(routes, str) or len(routes) > 262144:
        raise ValueError("Invalid or oversized IPv6 route inventory")
    for line in routes.splitlines():
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0] in ("unreachable", "prohibit", "blackhole", "throw"):
            continue
        destination = tokens[1] if tokens[0] in ("local", "anycast", "multicast") and len(tokens) > 1 else tokens[0]
        try:
            prefix = ipaddress.ip_network(
                "::/0" if destination == "default" else destination, strict=False
            )
        except ValueError as exc:
            raise ValueError("Unrecognized IPv6 routing prefix") from exc
        if prefix.version != 6:
            raise ValueError("Non-IPv6 entry in IPv6 routing inventory")
        # Link-local, multicast and loopback cannot be a public Internet
        # escape route; keep these normal local kernel routes allowed.
        if prefix.is_link_local or prefix.is_multicast or prefix.is_loopback:
            continue
        dev = DEV.search(line)
        if owned is None or not dev or dev.group(1) != owned:
            raise NonlocalIpv6Route("Non-local IPv6 route outside owned tunnel")
    return True


def main(argv):
    if len(argv) != 2:
        return 64
    routes = sys.stdin.read(262145)
    try:
        verify_ipv6_route_inventory(routes, argv[1])
    except (ValueError, TypeError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
