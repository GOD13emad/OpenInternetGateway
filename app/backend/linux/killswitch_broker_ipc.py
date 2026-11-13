#!/usr/bin/env python3
"""Bounded one-shot AF_UNIX IPC transport for a READ-ONLY broker prototype.

No root service, listening socket, filesystem bind, systemd unit, or network
firewall operation is performed by this module. A separate, native-approved
system service would have to supply its own protected socket, root-owned
manifest and real kernel-enforcement before any mutating operation could exist.
"""
import json
import socket

import killswitch_broker_protocol as protocol

MAX_RESPONSE_BYTES = 2048
SOCKET_TIMEOUT_SECONDS = 1.25


class TransportRefused(protocol.BrokerRefused):
    pass


def receive_single_frame(conn):
    """One newline-delimited JSON object; disallow pipelining or oversized IO."""
    if not isinstance(conn, socket.socket) or conn.family != socket.AF_UNIX:
        raise TransportRefused("A connected local socket is required")
    conn.settimeout(SOCKET_TIMEOUT_SECONDS)
    data = bytearray()
    try:
        while True:
            # Extra byte beyond the maximum is deliberate, to distinguish
            # legal 512-byte frames from oversized payloads.
            chunk = conn.recv(protocol.MAX_REQUEST_BYTES + 2 - len(data))
            if not chunk:
                raise TransportRefused("Truncated or empty frame")
            data.extend(chunk)
            if len(data) > protocol.MAX_REQUEST_BYTES + 1:
                raise TransportRefused("Overlong client frame")
            if b"\n" in chunk:
                # A client may not hide commands after a first valid frame.
                # One request per accepted socket, then immediate close.
                if data.count(b"\n") != 1 or not data.endswith(b"\n"):
                    raise TransportRefused("Pipelined client messages")
                raw = bytes(data[:-1])
                if len(raw) > protocol.MAX_REQUEST_BYTES:
                    raise TransportRefused("Overlong JSON object")
                return raw
    except (socket.timeout, OSError) as exc:
        raise TransportRefused("Client IPC timeout or socket failure") from exc


def serve_accepted(conn, approved):
    """Authenticate BEFORE receiving client bytes; reply once and close.

    Returns only the request's approved preview. Reject unauthorized users
    without sending a response. No socket bind, accept loop or elevation.
    """
    if not isinstance(conn, socket.socket):
        raise TransportRefused("Invalid accepted peer")
    conn.settimeout(SOCKET_TIMEOUT_SECONDS)
    protocol.authorize_connected_owner(conn, approved)
    frame = receive_single_frame(conn)
    result = protocol.handle_connected_request(conn, approved, frame)
    payload = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("utf8")
    if len(payload) > MAX_RESPONSE_BYTES:
        # A preview with a larger policy is not a reason to send oversized
        # data to a GUI; deny rather than silently truncating the JSON.
        raise TransportRefused("Response exceeds bounded IPC limit")
    try:
        conn.sendall(payload)
    except (socket.timeout, OSError) as exc:
        raise TransportRefused("Client IPC response failure") from exc
    return result
