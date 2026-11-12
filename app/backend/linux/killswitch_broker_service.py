#!/usr/bin/env python3
"""Socket-activated READ-ONLY Linux broker entrypoint (NOT a kill switch).

No nft invocation, no NetworkManager mutation, no systemd installation and
no listener binding. An OS-installed, root-owned service might start this
entrypoint after receiving a trusted listening AF_UNIX socket from systemd.
The only IPC verbs are "status" and "lockdown-preview"; enforcement remains
explicitly uninstalled and cannot be unlocked by any request.

Never install this entrypoint as the production kill-switch service. A
different, reviewed startup-first enforcer and independently authenticated
live TLS/DNS/IPv6 proofs are prerequisites to any production protection.
"""
import os
import socket
import time
from collections.abc import Mapping

import killswitch_broker_ipc as ipc
import killswitch_broker_protocol as protocol
import killswitch_lifecycle_contract as contract

SOCKET_PATH = "/run/openinternetgateway/status.sock"
FD_NAME = "oig-status"
MAX_CONNECTIONS = 12
MAX_RUNTIME_SECONDS = 25


class ActivationRefused(protocol.BrokerRefused):
    """No authentic-looking activation socket is available."""


def inherited_listener(env, *, fd=3, pid=None, expected_path=SOCKET_PATH):
    """Validate one systemd AF_UNIX listening socket inherited via fd 3.

    A valid environment is necessary but never a privilege grant: systemd
    service identity, installed executable ownership and the root-owned
    manifest must be independently trusted by native OS packaging.
    """
    if pid is None:
        pid = os.getpid()
    if (not isinstance(env, Mapping) or
            env.get("LISTEN_PID") != str(pid) or
            env.get("LISTEN_FDS") != "1" or
            env.get("LISTEN_FDNAMES") != FD_NAME or
            type(fd) is not int or fd < 3 or
            not isinstance(expected_path, str) or
            not expected_path.startswith("/") or
            "\x00" in expected_path):
        raise ActivationRefused("Invalid systemd activation contract")
    try:
        dup = os.dup(fd)
    except OSError as exc:
        raise ActivationRefused("No inherited descriptor") from exc
    try:
        listener = socket.socket(fileno=dup)
    except OSError as exc:
        os.close(dup)
        raise ActivationRefused("Inherited descriptor is not a socket") from exc
    try:
        if (listener.family != socket.AF_UNIX or
                listener.type & socket.SOCK_STREAM != socket.SOCK_STREAM or
                listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1 or
                listener.getsockname() != expected_path):
            raise ActivationRefused("Unexpected listening socket")
        return listener
    except (OSError, ActivationRefused) as exc:
        listener.close()
        raise ActivationRefused("Rejected inherited listener") from exc


def serve_limited(listener, approved, *, max_connections=MAX_CONNECTIONS):
    """Serve bounded authenticated read-only requests, then exit.

    This is not a long-running network controller, watchdog or service
    implementation. If a client faults, reject and continue; never count a
    rejected request as successful. No sensitive frame contents are logged.
    """
    if not isinstance(approved, contract.Approved):
        raise ActivationRefused("Root-owned approved config required")
    if (not isinstance(listener, socket.socket) or
            listener.family != socket.AF_UNIX or
            listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1 or
            type(max_connections) is not int or
            not 1 <= max_connections <= MAX_CONNECTIONS):
        raise ActivationRefused("Invalid service listener")
    deadline = time.monotonic() + MAX_RUNTIME_SECONDS
    accepted = 0
    served = 0
    while accepted < max_connections and time.monotonic() < deadline:
        listener.settimeout(min(1.0, max(0.01, deadline - time.monotonic())))
        try:
            client, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError as exc:
            raise ActivationRefused("Listener failed") from exc
        accepted += 1
        with client:
            try:
                ipc.serve_accepted(client, approved)
            except protocol.BrokerRefused:
                continue
            served += 1
    return {"connectionsReceived": accepted, "readOnlyReplies": served,
            "enforcementInstalled": False, "fullDeviceProtectionVerified": False}


def main():
    # Root or CAP_NET_ADMIN alone is NOT enough to make this a kill-switch.
    # This program intentionally does not apply even an initial nft policy.
    if os.geteuid() != 0:
        raise SystemExit("REFUSED: native root service not installed")
    try:
        manifest = contract.read_installed_root_manifest()
        with inherited_listener(os.environ) as listener:
            serve_limited(listener, manifest)
    except (contract.ContractError, protocol.BrokerRefused, OSError):
        raise SystemExit("REFUSED: untrusted root broker startup") from None
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
