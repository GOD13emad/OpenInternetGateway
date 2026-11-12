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
# Reserved for a separately approved boot-time root enforcer; never auto-installed.
BOOT_TABLE = "oig_guard"


class UnsafePlan(ValueError):
    pass


def validated_table(table):
    if type(table) is not str or table not in (TABLE, BOOT_TABLE):
        raise UnsafePlan("Untrusted target table")
    return table


def render(interface, underlay, peer, port, transport, *, table=TABLE):
    validated_table(table)
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
    return _create(interface, underlay, address, port, transport, True, table)


def _output_rules(interface, underlay, peer, port, transport, tunnel_allowed, table):
    # No blanket conntrack established ACCEPT: it could permit an existing
    # underlay connection to survive route fallback.
    rules = [f'add rule inet {table} output oifname "lo" accept']
    if tunnel_allowed:
        rules.append(f'add rule inet {table} output oifname "{interface}" accept')
    rules.extend((
        f'add rule inet {table} output meta nfproto ipv4 oifname "{underlay}" ip daddr {peer} {transport} dport {port} accept',
        f'add rule inet {table} output meta nfproto ipv4 oifname "{underlay}" udp sport 68 udp dport 67 accept',
        f'add rule inet {table} output counter drop'
    ))
    return rules


def _create(interface, underlay, address, port, transport, tunnel_allowed, table):
    # Private independent table: never flush the owner's entire nft ruleset.
    # Output and forwarded traffic are both fail-closed by default.
    # Forward traffic is intentionally NOT enabled here: this is not yet
    # a production gateway or consented root-owned service.
    return "\n".join([
        f"add table inet {table}",
        f"add chain inet {table} output {{ type filter hook output priority -150; policy drop; }}",
        f"add chain inet {table} forward {{ type filter hook forward priority -150; policy drop; }}",
        *_output_rules(interface, underlay, address, port, transport, tunnel_allowed, table),
        f"add rule inet {table} forward counter drop",
        ""
    ])


def render_lockdown(interface, underlay, peer, port, transport, *, table=TABLE):
    """Pre-tunnel lockdown: only loopback, pinned VPN transport and DHCPv4."""
    render(interface, underlay, peer, port, transport, table=table)  # Validate first.
    return _create(interface, underlay, ipaddress.IPv4Address(peer),
                   port, transport, False, table)


def render_transition(interface, underlay, peer, port, transport, *, tunnel_allowed, table=TABLE):
    """Single atomic nft -f batch for an existing default-DROP table.

    Only a separately authorized root-owned operator may apply a rendered
    transition. A TUN name alone does not prove interface ownership.
    """
    render(interface, underlay, peer, port, transport, table=table)  # Validate first.
    if type(tunnel_allowed) is not bool:
        raise UnsafePlan("Transition state must be a boolean")
    rules = _output_rules(interface, underlay, ipaddress.IPv4Address(peer),
                          port, transport, tunnel_allowed, table)
    return "\n".join((
        f"flush chain inet {table} output",
        *rules,
        # Forward base chain never changes and remains default-DROP.
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
