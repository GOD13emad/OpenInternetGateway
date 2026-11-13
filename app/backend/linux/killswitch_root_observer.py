#!/usr/bin/env python3
"""Bounded read-only root-broker NetworkManager/kernel observation prototype.

NO nft, NetworkManager mutation or external network probes. The observer's
own process invokes a narrowly fixed command set, never a command requested
over a socket. Preliminary link/route metadata CANNOT prove OpenVPN server
identity, DNS ownership, IPv6 leak freedom or full-device routing. Its
output deliberately cannot satisfy lifecycle_contract.LIVE_FIELDS and
cannot authorize a tunnel unlock.
"""
from dataclasses import dataclass
import json
import os
import subprocess

import killswitch_lifecycle_contract as contract

# Ubuntu/Debian system binary paths; none are shell commands or PATH lookup.
NMCLI = "/usr/bin/nmcli"
IP = "/usr/sbin/ip"
MAX_OUTPUT = 16_384
ALLOWED_COMMANDS = frozenset(("nmcli-active", "link-detail", "peer-route"))


class ObservationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Partial:
    nm_uuid_active: bool
    kernel_tunnel_link_present: bool
    pinned_peer_uses_underlay: bool
    unlock_authorized: bool = False
    full_device_proven: bool = False
    dns_proven: bool = False
    ipv6_proven: bool = False
    tls_peer_identity_proven: bool = False


def _command_args(kind, approved):
    if not isinstance(approved, contract.Approved) or kind not in ALLOWED_COMMANDS:
        raise ObservationError("Unapproved observation command")
    return {
        "nmcli-active": [NMCLI, "-t", "-f", "UUID,TYPE,DEVICE",
                         "connection", "show", "--active"],
        "link-detail": [IP, "-j", "-d", "link", "show", "dev", approved.tunnel],
        "peer-route": [IP, "-j", "-4", "route", "get", approved.peer_ipv4],
    }[kind]


def _run_readonly(args, approved):
    """Execute ONLY the three exact approved read-only command vectors.

    Matching an executable path alone is NOT sufficient: ip/nmcli also
    contain network-mutating subcommands. No caller-provided argv is allowed.
    """
    if not isinstance(approved, contract.Approved):
        raise ObservationError("Approved manifest required")
    allow = tuple(_command_args(kind, approved) for kind in
                  ("nmcli-active", "link-detail", "peer-route"))
    if (not isinstance(args, list) or
            not all(type(arg) is str for arg in args) or
            args not in allow):
        raise ObservationError("Command is not on the exact read-only allowlist")
    try:
        p = subprocess.run(
            args, stdin=subprocess.DEVNULL, capture_output=True,
            timeout=5, check=False, env={
                "LC_ALL": "C", "LANG": "C",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            }
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ObservationError("NetworkManager/kernel observer unavailable") from exc
    if p.returncode != 0 or len(p.stdout) > MAX_OUTPUT or len(p.stderr) > 4096:
        raise ObservationError("NetworkManager/kernel observer refused")
    return p.stdout


def _one_json_list(raw, source):
    if not isinstance(raw, bytes) or len(raw) > MAX_OUTPUT:
        raise ObservationError("Unbounded kernel observation")
    try:
        result = json.loads(raw.decode("utf8"))
    except (UnicodeError, ValueError) as exc:
        raise ObservationError("Malformed kernel observation") from exc
    if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
        raise ObservationError("Ambiguous kernel observation: " + source)
    return result[0]


def parse_observation(approved, nm, link, route):
    """Parse strictly corroborating OS metadata, NEVER client JSON."""
    if not isinstance(approved, contract.Approved):
        raise ObservationError("Approved fixed manifest required")
    if not isinstance(nm, bytes) or len(nm) > MAX_OUTPUT:
        raise ObservationError("Unbounded NetworkManager inventory")
    try:
        lines = nm.decode("utf8").splitlines()
    except UnicodeError as exc:
        raise ObservationError("Invalid NetworkManager encoding") from exc
    matches = []
    for line in lines:
        if not line or "\x00" in line:
            raise ObservationError("Invalid NetworkManager record")
        fields = line.split(":")
        if len(fields) != 3:
            raise ObservationError("Ambiguous NetworkManager record")
        uuid, kind, device = fields
        if uuid == approved.connection_uuid:
            matches.append(kind == "vpn" and device == approved.tunnel)
    if len(matches) > 1:
        raise ObservationError("Duplicate active NM UUID")
    active = len(matches) == 1 and matches[0] is True
    lnk = _one_json_list(link, "link")
    route_entry = _one_json_list(route, "route")
    if any(type(lnk.get(k)) is not t for k, t in (("ifname", str), ("ifindex", int))):
        raise ObservationError("Invalid kernel link metadata")
    if not isinstance(lnk.get("linkinfo"), dict):
        raise ObservationError("Kernel link kind unavailable")
    link_kind = lnk["linkinfo"].get("info_kind")
    tunnel_present = (active and lnk["ifname"] == approved.tunnel
                      and lnk["ifindex"] > 0 and link_kind in ("tun", "tap"))
    # IPv4 route-to-peer is only corroborating underlay topology;
    # neither a CA pin nor full-device forwarding proof.
    peer_route = (
        route_entry.get("dst") == approved.peer_ipv4
        and route_entry.get("dev") == approved.underlay
        and isinstance(route_entry.get("dev"), str)
    )
    return Partial(active, tunnel_present, peer_route)


def observe_readonly(approved, runner=None):
    """Collect from local NM/kernel; caller cannot inject request bytes.

    `runner` is solely for deterministic tests and must NEVER be exposed
    as a broker IPC option. Even all true observations leave unlock False.
    """
    if not isinstance(approved, contract.Approved):
        raise ObservationError("Approved manifest required")
    reader = (lambda args: _run_readonly(args, approved)) if runner is None else runner
    observations = []
    for kind in ("nmcli-active", "link-detail", "peer-route"):
        raw = reader(_command_args(kind, approved))
        if not isinstance(raw, bytes) or len(raw) > MAX_OUTPUT:
            raise ObservationError("Read-only observer returned invalid bytes")
        observations.append(raw)
    return parse_observation(approved, *observations)
