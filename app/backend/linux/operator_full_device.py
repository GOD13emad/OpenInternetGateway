#!/usr/bin/env python3
"""Read-only Linux full-device feasibility check; never connects or changes a route.

A clean result is NOT authorization to activate an OpenVPN tunnel. The
independently armed active-tunnel rollback and real data-plane acceptance are
separate gates. No credential material is read, stored or printed here.
"""
import argparse
import json
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import operator_profile


class PreflightError(RuntimeError):
    pass


def read_command(argv):
    """Bounded, read-only platform observation; fail closed on unknown output."""
    if argv[0] not in {"nmcli", "ip"}:
        raise PreflightError("Unexpected observer executable")
    try:
        result = subprocess.run(
            argv, capture_output=True, timeout=6, check=False,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PreflightError("Network observation unavailable") from exc
    if len(result.stdout) > 16384 or len(result.stderr) > 4096:
        raise PreflightError("Network observation exceeds size limit")
    return result.returncode, result.stdout.decode("utf-8", "replace"), result.stderr.decode("utf-8", "replace")


def check_desired_off(path):
    try:
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            return False
        info = path.stat()
        if (info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 16):
            return False
        return path.read_text(encoding="utf-8").strip() == "off"
    except (OSError, UnicodeError):
        return False


def active_tunnels():
    rc, stdout, _ = read_command(
        ["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show", "--active"])
    if rc:
        raise PreflightError("Cannot verify NetworkManager active connections")
    types = {"vpn", "tun", "wireguard", "ip-tunnel"}
    for line in stdout.splitlines():
        name, delimiter, kind = line.rpartition(":")
        if not delimiter or not name or not kind:
            raise PreflightError("Ambiguous active-connection inventory")
        if kind.strip().lower() in types:
            return True
    # A manual tunnel may exist without any IPv4 route or NetworkManager
    # profile. Inspect kernel link *types*, then both address-family routes.
    # Unknown/malformed inventories fail closed instead of reporting isolation.
    rc, stdout, _ = read_command(["ip", "-j", "-d", "link", "show"])
    if rc:
        raise PreflightError("Cannot inspect kernel link inventory")
    try:
        interfaces = json.loads(stdout)
    except (ValueError, TypeError) as exc:
        raise PreflightError("Kernel link inventory is malformed") from exc
    if not isinstance(interfaces, list) or not interfaces:
        raise PreflightError("Kernel link inventory is incomplete")
    tunnel_kinds = {
        "tun", "tap", "wireguard", "gre", "gretap", "ip6gre",
        "ip6gretap", "ipip", "sit", "vti", "vti6", "vxlan",
        "geneve", "erspan", "ip6erspan", "l2tpeth", "macvtap",
    }
    for interface in interfaces:
        if not isinstance(interface, dict) or not isinstance(interface.get("ifname"), str):
            raise PreflightError("Kernel link inventory is ambiguous")
        detail = interface.get("linkinfo") or {}
        if not isinstance(detail, dict):
            raise PreflightError("Kernel link metadata is ambiguous")
        kind = detail.get("info_kind", "")
        if not isinstance(kind, str):
            raise PreflightError("Kernel link kind is ambiguous")
        name = interface["ifname"]
        if kind.lower() in tunnel_kinds or re.fullmatch(
                r"(?:tun|tap|wg|tailscale|vpn)[A-Za-z0-9_.:-]*", name):
            return True
    for family in ("-4", "-6"):
        rc, stdout, _ = read_command(["ip", family, "route", "show", "table", "main"])
        if rc:
            raise PreflightError("Cannot inspect kernel route inventory")
        for route in stdout.splitlines():
            if re.search(r"\bdev\s+(?:tun|tap|wg|tailscale|vpn)[A-Za-z0-9_.:-]*\b", route):
                return True
    return False


def public_ipv6_route_present():
    """Representative physical IPv6 egress check; not an IPv6 leak proof."""
    for destination in ("2606:4700:4700::1111", "2001:4860:4860::8888"):
        rc, stdout, stderr = read_command(["ip", "-6", "route", "get", destination])
        head = stdout.splitlines()[0].strip() if stdout.splitlines() else ""
        if rc == 0:
            if head.startswith(("unreachable ", "prohibit ", "blackhole ")):
                continue
            # A valid route through any physical/foreign device blocks a
            # trial until a separately verified IPv6 fail-closed plan exists.
            return True
        if rc != 0 and ("Network is unreachable" in stderr or "No route to host" in stderr):
            continue
        raise PreflightError("Cannot verify public IPv6 route absence")
    return False


def preflight(profile, ca_pin, peer_cn, desired_state):
    checked, _, _ = operator_profile.load_and_check(profile, ca_pin, peer_cn)
    if not checked:
        raise PreflightError("Invalid pinned profile")
    reasons = []
    if not check_desired_off(desired_state):
        reasons.append("DESIRED_STATE_NOT_VERIFIED_OFF")
    try:
        if active_tunnels():
            reasons.append("INDEPENDENT_TUNNEL_ACTIVE")
    except PreflightError:
        reasons.append("ACTIVE_TUNNEL_INVENTORY_UNKNOWN")
    try:
        if public_ipv6_route_present():
            reasons.append("PUBLIC_IPV6_ROUTE_PRESENT")
    except PreflightError:
        reasons.append("IPV6_ROUTE_STATUS_UNKNOWN")
    return {
        "ok": True,
        "mode": "read-only-full-device-preflight",
        "pinnedProviderProfileChecked": True,
        "noIndependentTunnelObserved": "INDEPENDENT_TUNNEL_ACTIVE" not in reasons
            and "ACTIVE_TUNNEL_INVENTORY_UNKNOWN" not in reasons,
        "publicIpv6AbsenceRepresentativelyChecked": "PUBLIC_IPV6_ROUTE_PRESENT" not in reasons
            and "IPV6_ROUTE_STATUS_UNKNOWN" not in reasons,
        "blockers": reasons,
        "candidateHostIsolation": not reasons,
        # Nothing in this script imports, activates, sets routes/DNS, stores a
        # password, arms a timer or satisfies actual full-device acceptance.
        "activationRequested": False,
        "independentRollbackArmed": False,
        "fullDevicePathEnabled": False,
        "fullDeviceTunnelVerified": False,
        "readyForAutomaticConnection": False,
    }


def main():
    parser = argparse.ArgumentParser(description="Read-only Linux full-device preflight; no VPN activation")
    parser.add_argument("action", choices=["preflight"])
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--ca-sha256", required=True)
    parser.add_argument("--peer-cn", required=True)
    parser.add_argument("--desired-state", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = preflight(args.profile, args.ca_sha256, args.peer_cn, args.desired_state)
        print(json.dumps(result, separators=(",", ":")))
    except (operator_profile.UnsafeProfile, PreflightError, OSError, ValueError):
        # No exception message can disclose profile, credentials or local paths.
        print("REJECTED: Cannot verify pinned full-device preflight inputs", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
