#!/usr/bin/env python3
"""Offline contract for a future installer-approved, root-owned Linux broker.

NO privileged operations, socket, systemd installation, nft invocation or
NetworkManager calls are made by this module. Manifest attestation does not
make caller-supplied data trusted: a production broker must obtain live
evidence itself from kernel/NM and authenticate the caller. All unverified
inputs produce LOCKED, never an unlocked policy. Not a production kill switch.
"""
from dataclasses import dataclass
import ipaddress
import json
import os
import re
import stat

import nft_killswitch_plan as nft

SCHEMA = "oig.killswitch.lifecycle.v1"
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
CN = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?\Z")
MANIFEST_FIELDS = frozenset((
    "schema", "approved", "owner_uid", "connection_uuid", "tunnel",
    "underlay", "peer_ipv4", "peer_port", "transport", "ca_sha256", "peer_cn"
))
LIVE_FIELDS = frozenset((
    "source", "connection_uuid", "kind", "tunnel", "underlay", "peer_ipv4",
    "peer_port", "transport", "ca_sha256", "peer_cn",
    "authenticated", "full_ipv4_owned", "dns_owned", "ipv6_leak_absent"
))


class ContractError(ValueError):
    """Invalid or unauthenticated lifecycle intent."""


@dataclass(frozen=True)
class Approved:
    owner_uid: int
    connection_uuid: str
    tunnel: str
    underlay: str
    peer_ipv4: str
    peer_port: int
    transport: str
    ca_sha256: str
    peer_cn: str


def _literal_dict(data, fields):
    if not isinstance(data, dict) or frozenset(data) != fields:
        raise ContractError("Unexpected or missing contract fields")
    if not all(isinstance(key, str) for key in data):
        raise ContractError("Invalid contract key")


def _valid_ipv4(value):
    if not isinstance(value, str):
        raise ContractError("Public IPv4 literal required")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ContractError("Public IPv4 literal required") from exc
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
        raise ContractError("Public IPv4 literal required")
    return str(address)


def approve_manifest(data):
    """Parse data, never read OS files or accept generic root execution."""
    _literal_dict(data, MANIFEST_FIELDS)
    if data["schema"] != SCHEMA or data["approved"] is not True:
        raise ContractError("No explicit install approval")
    uid = data["owner_uid"]
    if type(uid) is not int or uid < 1000 or uid >= 60000:
        raise ContractError("Invalid regular user UID")
    uuid = data["connection_uuid"]
    if not isinstance(uuid, str) or not UUID.fullmatch(uuid):
        raise ContractError("Invalid pinned NM UUID")
    ca = data["ca_sha256"]
    cn = data["peer_cn"]
    if not isinstance(ca, str) or not HASH.fullmatch(ca):
        raise ContractError("Invalid pinned CA identity")
    if not isinstance(cn, str) or not CN.fullmatch(cn) or ".." in cn:
        raise ContractError("Invalid pinned peer CN")
    # Delegate endpoint, tunnel-name, protocol and quote injection checks
    # to the same policy generator exercised by the isolated nft kernel QA.
    try:
        nft.render(data["tunnel"], data["underlay"], data["peer_ipv4"],
                   data["peer_port"], data["transport"])
    except (nft.UnsafePlan, TypeError, ValueError) as exc:
        raise ContractError("Invalid protected endpoint") from exc
    return Approved(
        uid, uuid, data["tunnel"], data["underlay"],
        _valid_ipv4(data["peer_ipv4"]), data["peer_port"],
        data["transport"], ca, cn
    )


def manifest_owner_attributes(uid, mode, is_regular, is_symlink, parent_root_owned):
    """Additional root-owned /etc manifest precondition, not an OS stat.

    Fail closed for user-owned or writable configuration. Reading and
    verifying actual inode and its parent is a future root-broker duty.
    """
    return (type(uid) is int and uid == 0 and type(mode) is int
            and mode in (0o600, 0o640)
            and is_regular is True and is_symlink is False
            and parent_root_owned is True)

ROOT_CONFIG_DIR = "/etc/openinternetgateway"
ROOT_CONFIG_NAME = "killswitch-policy.json"
MAX_CONFIG_BYTES = 4096


def decode_root_manifest(raw):
    """Reject malformed and ambiguous JSON before checking approved fields."""
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_CONFIG_BYTES:
        raise ContractError("Invalid bounded root config")
    def strict_pairs(pairs):
        names = [key for key, _ in pairs]
        if len(names) != len(set(names)):
            raise ContractError("Duplicate JSON keys")
        return dict(pairs)
    try:
        data = json.loads(raw.decode("utf8"), object_pairs_hook=strict_pairs)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ContractError("Invalid JSON root manifest") from exc
    return approve_manifest(data)


def read_installed_root_manifest():
    """Read ONLY the fixed root-owned OS config using directory-relative fd.

    The app MUST NOT call this method with elevated privileges. Only a
    separately approved and audited system broker may use this loader.
    It does not grant permission to update the nft ruleset.
    """
    parent = None
    file_fd = None
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        parent = os.open(ROOT_CONFIG_DIR, flags | os.O_DIRECTORY)
        parent_stat = os.fstat(parent)
        if (not stat.S_ISDIR(parent_stat.st_mode)
                or parent_stat.st_uid != 0
                or parent_stat.st_mode & 0o022):
            raise ContractError("Untrusted config directory")
        file_fd = os.open(ROOT_CONFIG_NAME, flags, dir_fd=parent)
        st = os.fstat(file_fd)
        if (not manifest_owner_attributes(
                st.st_uid, stat.S_IMODE(st.st_mode),
                stat.S_ISREG(st.st_mode), False, True)
                or st.st_nlink != 1 or st.st_size > MAX_CONFIG_BYTES
                or st.st_size <= 0):
            raise ContractError("Untrusted root manifest file")
        return decode_root_manifest(os.read(file_fd, MAX_CONFIG_BYTES + 1))
    except OSError as exc:
        raise ContractError("Root config unavailable or unreadable") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if parent is not None:
            os.close(parent)


def live_tunnel_verified(approved, data):
    """Pure verifier over evidence a FUTURE root broker must collect itself.

    A normal application cannot assert the `source` tag as an authority.
    The privileged broker MUST obtain NM and kernel evidence directly.
    """
    if not isinstance(approved, Approved):
        raise ContractError("Approved root manifest required")
    try:
        _literal_dict(data, LIVE_FIELDS)
    except ContractError:
        return False
    matches = {
        "connection_uuid": approved.connection_uuid,
        "kind": "vpn",
        "tunnel": approved.tunnel,
        "underlay": approved.underlay,
        "peer_ipv4": approved.peer_ipv4,
        "peer_port": approved.peer_port,
        "transport": approved.transport,
        "ca_sha256": approved.ca_sha256,
        "peer_cn": approved.peer_cn,
        "source": "root-collected-nm-and-kernel",
    }
    if any(type(data.get(key)) is not type(value) or data.get(key) != value
           for key, value in matches.items()):
        return False
    return all(data[key] is True for key in (
        "authenticated", "full_ipv4_owned", "dns_owned", "ipv6_leak_absent"
    ))


def preview_state(approved, live=None):
    """Never use this result as authorization without privileged live proof."""
    if not isinstance(approved, Approved):
        raise ContractError("Approved root manifest required")
    if live is None or not live_tunnel_verified(approved, live):
        return "LOCKED"
    return "TUNNEL_ELIGIBLE_PENDING_BROKER_ATTESTATION"


def preview_rules(approved, state):
    """Only emit text. No nft operations, state files or systemd actions."""
    if not isinstance(approved, Approved):
        raise ContractError("Approved root manifest required")
    a = (approved.tunnel, approved.underlay, approved.peer_ipv4,
         approved.peer_port, approved.transport)
    if state == "LOCKED":
        return nft.render_lockdown(*a)
    if state == "TUNNEL_ELIGIBLE_PENDING_BROKER_ATTESTATION":
        # This is a PREVIEW. No live principal or interface evidence is
        # established by rendering it. The production broker must repeat
        # authorization at commit time and subscribe to forced disconnects.
        return nft.render_transition(*a, tunnel_allowed=True)
    raise ContractError("Unknown or unapproved state")


def preview_service_unit():
    """Non-installable service design; rejects pretending a preview is live.

    A production version must contain a real trusted root broker installed
    by a native OS-authorized package transaction; this unit is not deployed.
    """
    return """# DESIGN PREVIEW ONLY: do not install or enable this unit.
[Unit]
Description=Open Internet Gateway opt-in firewall lifecycle (unimplemented)
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
User=root
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
# No ExecStart: a tested, authenticated, root-owned broker is REQUIRED
# before any systemd installation. A generated firewall policy alone
# cannot prevent leaks between boot and network initialization.

[Install]
# Deliberately no WantedBy: no accidental enablement.
"""
