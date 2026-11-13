#!/usr/bin/env python3
"""Real kernel SO_PEERCRED exercised with socketpair, no listener or nft."""
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend/linux"))
import killswitch_broker_protocol as broker
import killswitch_lifecycle_contract as contract

def refuse(action, label):
    try:
        action()
    except broker.BrokerRefused:
        return
    raise AssertionError("BROKER_FAIL_OPEN_" + label)


def main():
    # Test UID comes from kernel, never from a forged JSON frame. No elevated
    # service, firewall changes or filesystem socket bind is involved.
    user_uid = os.getuid()
    if user_uid < 1000 or user_uid >= 60000:
        raise RuntimeError("TEST_REQUIRES_NON_ROOT_DESKTOP_USER")
    a = contract.Approved(
        user_uid, "c1234567-1234-4234-8234-123456789abc",
        "tun7", "eth0", "1.1.1.1", 443, "tcp", "a" * 64, "server.example.com"
    )
    x, y = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        pid, uid, gid = broker.kernel_peer_credentials(x)
        assert pid == os.getpid()
        assert uid == user_uid and gid == os.getgid()
        assert broker.authorize_connected_owner(x, a) == {
            "pid": pid, "uid": uid, "gid": gid
        }
        status = json.dumps({"schema": broker.WIRE_SCHEMA, "op": "status"}).encode()
        preview = json.dumps({"schema": broker.WIRE_SCHEMA, "op": "lockdown-preview"}).encode()
        info = broker.handle_connected_request(x, a, status)
        assert info["enforcementInstalled"] is False
        assert info["rootBrokerRunning"] is False
        assert info["actualKernelProtectionVerified"] is False
        assert info["state"] == "LOCKED_PREVIEW_ONLY"
        assert "rules" not in info
        rules = broker.handle_connected_request(x, a, preview)
        assert rules["enforcementInstalled"] is False
        assert rules["renderOnly"] is True
        assert 'oifname "tun7" accept' not in rules["rules"]
        assert "hook output" in rules["rules"] and "hook forward" in rules["rules"]
        assert "policy drop" in rules["rules"]
        assert "flush ruleset" not in rules["rules"]
        refused_peers = [
            ("different_uid", replace(a, owner_uid=user_uid+1)),
            ("root_uid", replace(a, owner_uid=0)),
        ]
        for label, approved in refused_peers:
            refuse(lambda approved=approved: broker.handle_connected_request(x, approved, status),label)
        malformed = [
            b"", b"null", b"[]", b"{", b" " * 513,
            b'{"schema":"oig.killswitch.broker.v1","op":"status","op":"apply"}',
            b'{"schema":"oig.killswitch.broker.v1","op":"status","uid":1000}',
            b'{"schema":"oig.killswitch.broker.v1","op":"status","pid":123}',
            b'{"schema":"oig.killswitch.broker.v1","op":"status","live":true}',
            b'{"schema":"oig.killswitch.broker.v1","op":"apply"}',
            b'{"schema":"oig.killswitch.broker.v1","op":"unlock"}',
            b'{"schema":"oig.killswitch.broker.v1","op":"nft"}',
            b'{"schema":"oig.killswitch.broker.v1","op":"install"}',
            b'{"schema":"oig.killswitch.broker.v1","op":"disconnect"}',
            b'{"schema":"oig.killswitch.broker.v1","op":"run"}',
            b'{"schema":"oig.killswitch.broker.v1","op":true}',
            b'{"schema":"oig.killswitch.broker.v1","op":["status"]}',
            b'{"schema":"oig.killswitch.broker.v1","op":"status"}\x00',
            bytes([0xff]),
            b'{"schema":"invalid.v0","op":"status"}',
        ]
        for i, data in enumerate(malformed):
            refuse(lambda data=data: broker.handle_connected_request(x, a, data), str(i))
        refuse(lambda: broker.handle_connected_request(x, None, status), "missing_manifest")
    finally:
        x.close()
        y.close()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as inet_sock:
        refuse(lambda: broker.kernel_peer_credentials(inet_sock), "inet_peer")
    assert broker.MAX_REQUEST_BYTES <= 512
    source = Path(broker.__file__).read_text()
    assert "SO_PEERCRED" in source
    assert "socket.socket(" not in source
    assert "subprocess" not in source
    assert "os.system(" not in source
    assert "os.exec" not in source
    assert "nft -f " not in source
    print("KERNEL_SO_PEERCRED_PROTOCOL_PASS 20_REQUEST_REJECTIONS 2_PEER_REJECTIONS"
          " 1_NO_MANIFEST 1_NON_UNIX_SOCKET NO_HOST_MUTATION")


if __name__ == "__main__":
    main()
