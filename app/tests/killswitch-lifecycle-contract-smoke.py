#!/usr/bin/env python3
"""Read-only verifier for privileged-killswitch contract; no network writes."""
import copy
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend/linux"))
import killswitch_lifecycle_contract as ks

MANIFEST = {
    "schema": ks.SCHEMA,
    "approved": True,
    "owner_uid": 1001,
    "connection_uuid": "c1234567-1234-4234-8234-123456789abc",
    "tunnel": "tun7",
    "underlay": "eth0",
    "peer_ipv4": "1.1.1.1",
    "peer_port": 443,
    "transport": "tcp",
    "ca_sha256": "a" * 64,
    "peer_cn": "server.example.com",
}
LIVE = {
    "source": "root-collected-nm-and-kernel",
    "connection_uuid": MANIFEST["connection_uuid"],
    "kind": "vpn",
    "tunnel": MANIFEST["tunnel"],
    "underlay": MANIFEST["underlay"],
    "peer_ipv4": MANIFEST["peer_ipv4"],
    "peer_port": MANIFEST["peer_port"],
    "transport": MANIFEST["transport"],
    "ca_sha256": MANIFEST["ca_sha256"],
    "peer_cn": MANIFEST["peer_cn"],
    "authenticated": True,
    "full_ipv4_owned": True,
    "dns_owned": True,
    "ipv6_leak_absent": True,
}


def expect_reject(mutator, label):
    d = copy.deepcopy(MANIFEST)
    mutator(d)
    try:
        ks.approve_manifest(d)
    except ks.ContractError:
        return
    raise AssertionError("FAIL_OPEN_" + label)


def main():
    approved = ks.approve_manifest(MANIFEST)
    encoded = json.dumps(MANIFEST, sort_keys=True).encode("utf8")
    assert ks.decode_root_manifest(encoded) == approved
    for raw in (
        b'',
        b'[]',
        b'{"schema":"x","schema":"x"}',
        encoded + b" ",
        bytes([255]),
        b"{" + b" " * 4096 + b"}",
        encoded.replace(b'"approved": true', b'"approved": "true"'),
        encoded[:-1],
    ):
        try:
            ks.decode_root_manifest(raw)
        except ks.ContractError:
            pass
        else:
            # JSON trailing whitespace is legal: treat as normal; all other
            # malformed/ambiguous data must be rejected.
            if raw != encoded + b" ":
                raise AssertionError("MANIFEST_DECODER_FAIL_OPEN")
    assert approved.connection_uuid == MANIFEST["connection_uuid"]
    assert ks.preview_state(approved) == "LOCKED"
    assert ks.preview_state(approved, {}) == "LOCKED"
    assert "oifname \"tun7\" accept" not in ks.preview_rules(approved, "LOCKED")
    assert "policy drop" in ks.preview_rules(approved, "LOCKED")
    assert "hook forward" in ks.preview_rules(approved, "LOCKED")
    assert ks.preview_state(approved, LIVE) == "TUNNEL_ELIGIBLE_PENDING_BROKER_ATTESTATION"
    unlocked = ks.preview_rules(approved, ks.preview_state(approved, LIVE))
    assert unlocked.startswith("flush chain inet oig_qa_killswitch output")
    assert 'oifname "tun7" accept' in unlocked
    assert "flush ruleset" not in unlocked

    negative_manifests = [
        ("approval_false", lambda d: d.update(approved=False)),
        ("approval_string", lambda d: d.update(approved="true")),
        ("unauthorized_uid", lambda d: d.update(owner_uid=0)),
        ("uid_bool", lambda d: d.update(owner_uid=True)),
        ("uuid_upper", lambda d: d.update(connection_uuid=MANIFEST["connection_uuid"].upper())),
        ("uuid_invalid", lambda d: d.update(connection_uuid="fake")),
        ("unsafe_tunnel", lambda d: d.update(tunnel='tun7"; flush ruleset')),
        ("same_underlay", lambda d: d.update(underlay="tun7")),
        ("wg_underlay", lambda d: d.update(underlay="wg0")),
        ("peer_private", lambda d: d.update(peer_ipv4="10.0.0.2")),
        ("peer_ipv6", lambda d: d.update(peer_ipv4="2001:4860:4860::8888")),
        ("peer_hostname", lambda d: d.update(peer_ipv4="vpn.test")),
        ("port_zero", lambda d: d.update(peer_port=0)),
        ("port_bool", lambda d: d.update(peer_port=True)),
        ("transport", lambda d: d.update(transport="udp;drop")),
        ("unpinned_ca", lambda d: d.update(ca_sha256="a" * 63)),
        ("invalid_cn", lambda d: d.update(peer_cn="evil; rm -rf")),
        ("extra_key", lambda d: d.update(operator="root")),
        ("missing_key", lambda d: d.pop("underlay")),
        ("invalid_schema", lambda d: d.update(schema="oig.killswitch.v0")),
    ]
    for label, mutator in negative_manifests:
        expect_reject(mutator, label)

    false_live = [
        ("auth", {"authenticated": False}),
        ("auth_str", {"authenticated": "true"}),
        ("wrong_uuid", {"connection_uuid": "a1234567-1234-4234-8234-123456789abc"}),
        ("wrong_tunnel", {"tunnel": "tun12"}),
        ("wrong_peer", {"peer_ipv4": "8.8.8.8"}),
        ("wrong_ca", {"ca_sha256": "b" * 64}),
        ("wrong_cn", {"peer_cn": "another.example.com"}),
        ("non_vpn", {"kind": "wireguard"}),
        ("dns_route", {"dns_owned": False}),
        ("ipv6", {"ipv6_leak_absent": False}),
        ("v4", {"full_ipv4_owned": False}),
        ("untrusted_source", {"source": "renderer-or-user"}),
    ]
    for label, fields in false_live:
        case = {**LIVE, **fields}
        assert not ks.live_tunnel_verified(approved, case), label
        assert ks.preview_state(approved, case) == "LOCKED", label
    case = {**LIVE, "uid": 1001}
    assert not ks.live_tunnel_verified(approved, case)

    assert ks.manifest_owner_attributes(0, 0o600, True, False, True)
    assert ks.manifest_owner_attributes(0, 0o640, True, False, True)
    for args in [
        (1001, 0o600, True, False, True),
        (0, 0o666, True, False, True),
        (0, 0o4600, True, False, True),
        (0, 0o600, False, False, True),
        (0, 0o600, True, True, True),
        (0, 0o600, True, False, False),
    ]:
        assert not ks.manifest_owner_attributes(*args), args
    for bad in ("ACTIVE", "UNLOCK", "UNLOCK_ROOT", "CONNECTED", "RELEASE"):
        try:
            ks.preview_rules(approved, bad)
        except ks.ContractError:
            pass
        else:
            raise AssertionError("FORBIDDEN_STATE_" + bad)
    unit = ks.preview_service_unit()
    assert "DefaultDependencies=no" in unit
    assert "Before=network-pre.target" in unit
    assert "CapabilityBoundingSet=CAP_NET_ADMIN" in unit
    assert "NoNewPrivileges=true" in unit
    assert "No ExecStart" in unit and "\nWantedBy=" not in unit
    assert "Deliberately no WantedBy" in unit
    # Must remain an offline-only design, never claim production enforcement.
    code = (Path(__file__).resolve().parents[1] / "backend/linux" /
            "killswitch_lifecycle_contract.py").read_text()
    for danger in ("subprocess.run(", "os.system(", "os.exec", "socket.socket(",
                   "nft -f ", "systemctl enable", "pkexec "):
        assert danger not in code, danger
    print("OIG_ROOT_BROKER_OFFLINE_CONTRACT_PASS"
          " 20_MANIFEST_REJECTIONS 13_LIVE_REJECTIONS"
          " 6_OWNERSHIP_REJECTIONS 5_FORBIDDEN_STATES")


if __name__ == "__main__":
    main()
