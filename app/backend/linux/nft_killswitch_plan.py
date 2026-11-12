#!/usr/bin/env python3
"""Render-only OIG nftables output confinement policy (NOT a deployed kill switch).

This deliberately does not execute nft or change network configuration.
Only a separately authorized, privileged controller can apply it, after
verifying the interface and pinned server identity, and must handle lifecycle
and fail-closed recovery. The generated inet/output chain is a disposable
network-namespace prototype; it is NOT whole-device production acceptance.
"""
import argparse
import ipaddress
import re
import sys

TUN = re.compile(r"(?:tun|tap|vpn)[A-Za-z0-9_.:-]{0,12}\Z")
DEV = re.compile(r"[A-Za-z0-9_.:-]{1,15}\Z")
TABLE = "oig_qa_killswitch"


class UnsafePlan(ValueError):
    pass


def render(interface, underlay, peer, port, transport):
    if (not isinstance(interface, str) or not TUN.fullmatch(interface)
            or not isinstance(underlay, str) or not DEV.fullmatch(underlay)
            or underlay == interface or underlay == "lo"
            or underlay.startswith(("tun", "tap", "vpn", "wg"))):
        raise UnsafePlan("Untrusted tunnel or underlay interface")
    try:
        address = ipaddress.ip_address(peer)
    except (TypeError, ValueError) as exc:
        raise UnsafePlan("OpenVPN peer must be a pinned literal IPv4 address") from exc
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
        raise UnsafePlan("OpenVPN peer must be a public literal IPv4 address")
    if type(port) is not int or not 1 <= port <= 65535 or transport not in ("tcp", "udp"):
        raise UnsafePlan("Untrusted OpenVPN endpoint or transport")
    # An isolated, independent nftables table. Never flush or replace the
    # owner's existing ruleset. The default is DROP; only loopback, OIG
    # tunnel and exactly one pinned OpenVPN control endpoint are allowed.
    # DHCPv4 renewals on the underlay are allowed to preserve link leasing,
    # but NO physical DNS, other IPv4, or physical IPv6 egress is permitted.
    # This table does NOT authenticate the kernel interface's owner.
    return "\n".join((
        f"add table inet {TABLE}",
        f"add chain inet {TABLE} output {{ type filter hook output priority -150; policy drop; }}",
        f'add rule inet {TABLE} output oifname "lo" accept',
        f'add rule inet {TABLE} output oifname "{interface}" accept',
        f'add rule inet {TABLE} output meta nfproto ipv4 oifname "{underlay}" ip daddr {address} {transport} dport {port} accept',
        f'add rule inet {TABLE} output meta nfproto ipv4 oifname "{underlay}" udp sport 68 udp dport 67 accept',
        f"add rule inet {TABLE} output counter drop",
        ""
    ))


def main(argv):
    parser = argparse.ArgumentParser(description="Read-only nftables output policy generator")
    parser.add_argument("--tunnel", required=True)
    parser.add_argument("--underlay", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--transport", required=True, choices=("tcp", "udp"))
    args = parser.parse_args(argv)
    try:
        sys.stdout.write(render(args.tunnel, args.underlay, args.peer,
                                args.port, args.transport))
    except UnsafePlan:
        print("REFUSED: invalid scoped nftables kill-switch plan", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
