#!/usr/bin/env python3
"""Read-only, fail-closed active Linux OIG NetworkManager DNS ownership gate.

Never changes a connection, resolver, firewall, or route. A matching OIG
profile is insufficient: verify systemd-resolved's *effective* DNS inventory
and the DNS server's effective kernel route through the owned TUN.
"""
import argparse
import ipaddress
import os
import re
import subprocess
import sys

TUN = re.compile(r"(tun|tap|vpn)[A-Za-z0-9_.:-]{0,12}\Z")
LINK = re.compile(r"Link\s+\d+\s+\(([^)]+)\):\s*(.*)\Z")
APPROVED = "1.1.1.1"
PRIORITY = "-2147483647"


def read(argv):
    try:
        p = subprocess.run(argv, capture_output=True, check=False, timeout=6,
                           env={**os.environ, "LC_ALL": "C", "LANG": "C"})
    except (OSError, subprocess.TimeoutExpired):
        return None
    if p.returncode or not p.stdout or len(p.stdout) > 8192:
        return None
    try:
        return p.stdout.decode("utf8", "strict").strip()
    except UnicodeError:
        return None


def dns_inventory(text, interface):
    """Reject any effective resolver on Global or another active interface."""
    found = False
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Global:"):
            # Any global server is a possible non-VPN fallback.
            if line.partition(":")[2].strip():
                return False
        else:
            match = LINK.fullmatch(line)
            if not match:
                return False
            dev, values = match.groups()
            if dev == interface:
                if values.split() != [APPROVED] or found:
                    return False
                found = True
            elif values.strip():
                return False
    return found


def permitted():
    opts = argparse.ArgumentParser()
    opts.add_argument("--managed-name", required=True)
    opts.add_argument("--interface", required=True)
    args = opts.parse_args()
    if args.managed_name != "OIG-VPN-LIVE" or not TUN.fullmatch(args.interface):
        return False
    fields = (
        ("ipv4.dns", APPROVED),
        ("ipv4.dns-search", "~."),
        ("ipv4.dns-priority", PRIORITY),
        ("ipv4.ignore-auto-dns", "yes"),
        ("ipv6.ignore-auto-dns", "yes"),
        ("ipv6.method", "disabled"),
    )
    for field, expected in fields:
        actual = read(["nmcli", "-g", field, "connection", "show", args.managed_name])
        if actual != expected:
            return False

    link_dns = read(["resolvectl", "dns", args.interface])
    link_domains = read(["resolvectl", "domain", args.interface])
    all_dns = read(["resolvectl", "dns"])
    if not all((link_dns, link_domains, all_dns)):
        return False
    if (not dns_inventory(link_dns, args.interface)
            or not dns_inventory(all_dns, args.interface)):
        return False
    domain_line = link_domains.strip()
    match = LINK.fullmatch(domain_line)
    if not match or match.groups() != (args.interface, "~."):
        return False
    route = read(["ip", "-4", "route", "get", APPROVED])
    if not route:
        return False
    fields = route.split()
    if "dev" not in fields or fields.index("dev") + 1 >= len(fields):
        return False
    if fields[fields.index("dev") + 1] != args.interface:
        return False
    try:
        if ipaddress.ip_address(fields[0]) != ipaddress.ip_address(APPROVED):
            return False
    except ValueError:
        return False
    return True


if __name__ == "__main__":
    try:
        allowed = permitted()
    except Exception:
        allowed = False
    sys.exit(0 if allowed else 1)
