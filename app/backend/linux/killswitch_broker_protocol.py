#!/usr/bin/env python3
"""Read-only Linux AF_UNIX broker protocol prototype.

NO service, listener, privileged command, nft application, disk mutation or
NetworkManager change is implemented here. The kernel's SO_PEERCRED is the
only caller identity source. Intent is constrained to status/preview only.
All responses explicitly report enforcementInstalled=False. A future
root-owned broker must independently observe the VPN and enforce lockdown
before exposing any state-changing method.
"""
import json
import os
import socket
import struct

import killswitch_lifecycle_contract as contract

WIRE_SCHEMA = "oig.killswitch.broker.v1"
MAX_REQUEST_BYTES = 512
REQUEST_FIELDS = frozenset(("schema", "op"))
OPS = frozenset(("status", "lockdown-preview"))
_UCRED = struct.Struct("3i")


class BrokerRefused(ValueError):
    """Caller or request cannot be safely accepted."""


def kernel_peer_credentials(connected):
    """Read Linux kernel AF_UNIX credentials, never JSON-supplied credentials.

    Only a connected local AF_UNIX SOCK_STREAM or socketpair is eligible.
    UNIX filesystem permissions protect access to a future socket path, but
    are NOT a replacement for this per-connection credential check.
    """
    if not isinstance(connected, socket.socket):
        raise BrokerRefused("Real connected AF_UNIX socket required")
    if connected.family != socket.AF_UNIX or connected.type & socket.SOCK_STREAM != socket.SOCK_STREAM:
        raise BrokerRefused("Local stream socket required")
    if not hasattr(socket, "SO_PEERCRED") or os.name != "posix":
        raise BrokerRefused("Linux SO_PEERCRED unavailable")
    try:
        raw = connected.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size)
        if len(raw) != _UCRED.size:
            raise BrokerRefused("Invalid kernel peer credentials")
        pid, uid, gid = _UCRED.unpack(raw)
    except OSError as exc:
        raise BrokerRefused("Kernel peer credential lookup failed") from exc
    if any(type(x) is not int for x in (pid, uid, gid)) or pid <= 0 or uid < 0 or gid < 0:
        raise BrokerRefused("Kernel returned invalid identity")
    return pid, uid, gid


def authorize_connected_owner(connected, approved):
    """Allow only the exact UID chosen during the one-time native install.

    Root is never implicitly authorized to act as the normal desktop client.
    A root-owned service needs a separate, explicitly reviewed maintenance
    channel; allowing root-as-user here would widen the app's permission.
    """
    if not isinstance(approved, contract.Approved):
        raise BrokerRefused("Missing approved fixed manifest")
    pid, uid, gid = kernel_peer_credentials(connected)
    if uid != approved.owner_uid or uid == 0:
        raise BrokerRefused("UNAUTHORIZED_CALLER_UID")
    return {"pid": pid, "uid": uid, "gid": gid}


def _strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BrokerRefused("Ambiguous duplicate request field")
        result[key] = value
    return result


def decode_request(raw):
    """Length-bounded exact-schema request; no arbitrary paths or shell args."""
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_REQUEST_BYTES:
        raise BrokerRefused("Invalid request length")
    if b"\x00" in raw:
        raise BrokerRefused("NUL in request")
    try:
        data = json.loads(raw.decode("utf8"), object_pairs_hook=_strict_pairs)
    except (UnicodeError, ValueError) as exc:
        raise BrokerRefused("Malformed request") from exc
    if not isinstance(data, dict) or frozenset(data) != REQUEST_FIELDS:
        raise BrokerRefused("Unexpected request fields")
    if data["schema"] != WIRE_SCHEMA or type(data["op"]) is not str or data["op"] not in OPS:
        raise BrokerRefused("Unrecognized or state-changing request")
    return data["op"]


def preview_response(approved, operation):
    """Never report a VPN connection or actual kernel enforcement as active."""
    if not isinstance(approved, contract.Approved) or operation not in OPS:
        raise BrokerRefused("Invalid status operation")
    response = {
        "schema": WIRE_SCHEMA,
        "approvedConfigParsed": True,
        "enforcementInstalled": False,
        "actualKernelProtectionVerified": False,
        "rootBrokerRunning": False,
        "state": "LOCKED_PREVIEW_ONLY",
        "requiredAttestation": "root-collected-nm-kernel-and-peer-identity",
    }
    if operation == "lockdown-preview":
        # The returned rules are text, NEVER applied by this protocol.
        # Do not return them to unknown peers or treat as active status.
        response["renderOnly"] = True
        response["rules"] = contract.preview_rules(approved, "LOCKED")
    return response


def handle_connected_request(connected, approved, raw):
    """Authorize at the socket before parsing or using any client bytes.

    This helper does not bind/listen/send. Future deployment must also use
    a root-owned 0700/0750 parent, restrictive AF_UNIX socket ACL, bounded
    read timeouts, one writer, and a single durable startup lockdown.
    """
    authorize_connected_owner(connected, approved)
    op = decode_request(raw)
    return preview_response(approved, op)
