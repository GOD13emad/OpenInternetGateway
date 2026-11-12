#!/usr/bin/env python3
"""Offline fixture tests for independent NM/kernel partial observations."""
from dataclasses import replace
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend/linux"))
import killswitch_lifecycle_contract as contract
import killswitch_root_observer as observer

APPROVED = contract.Approved(
    1001, "c1234567-1234-4234-8234-123456789abc",
    "tun7", "eth0", "1.1.1.1", 443, "tcp", "a"*64, "server.example.com"
)
ACTIVE = (APPROVED.connection_uuid + ":vpn:tun7\n").encode()
LINK = json.dumps([{"ifname":"tun7", "ifindex":7,
                    "linkinfo":{"info_kind":"tun"}}]).encode()
ROUTE = json.dumps([{"dst":"1.1.1.1", "dev":"eth0",
                     "prefsrc":"192.0.2.10"}]).encode()
EXPECTED = [
    [observer.NMCLI, "-t", "-f", "UUID,TYPE,DEVICE", "connection", "show", "--active"],
    [observer.IP, "-j", "-d", "link", "show", "dev", "tun7"],
    [observer.IP, "-j", "-4", "route", "get", "1.1.1.1"],
]


def read_fixture(outs):
    calls=[]
    def fake(cmd):
        calls.append(cmd)
        return outs[len(calls)-1]
    evidence=observer.observe_readonly(APPROVED, fake)
    assert calls==EXPECTED, calls
    return evidence


def refused(call, reason):
    try:
        call()
    except observer.ObservationError:
        return
    raise AssertionError("OBSERVER_FAIL_OPEN_"+reason)


def main():
    info=read_fixture([ACTIVE, LINK, ROUTE])
    assert info.nm_uuid_active and info.kernel_tunnel_link_present
    assert info.pinned_peer_uses_underlay
    assert not info.unlock_authorized and not info.full_device_proven
    assert not info.dns_proven and not info.ipv6_proven
    assert not info.tls_peer_identity_proven
    # No caller-supplied `source` tag can turn partial facts into approval.
    assert not contract.live_tunnel_verified(APPROVED, vars(info))

    active_cases=[
        (b"not-a-uuid:vpn:tun7\n", False),
        ((APPROVED.connection_uuid + ":ethernet:tun7\n").encode(), False),
        ((APPROVED.connection_uuid + ":vpn:eth0\n").encode(), False),
    ]
    for nm, expected in active_cases:
        result=read_fixture([nm,LINK,ROUTE])
        assert result.nm_uuid_active is expected
        assert result.unlock_authorized is False

    link_cases=[
        ({"ifname":"tun12","ifindex":7,"linkinfo":{"info_kind":"tun"}},False),
        ({"ifname":"tun7","ifindex":0,"linkinfo":{"info_kind":"tun"}},False),
        ({"ifname":"tun7","ifindex":7,"linkinfo":{"info_kind":"veth"}},False),
        ({"ifname":"tun7","ifindex":7,"linkinfo":{"info_kind":"tap"}},True),
    ]
    for link, result in link_cases:
        found=read_fixture([ACTIVE, json.dumps([link]).encode(), ROUTE])
        assert found.kernel_tunnel_link_present is result
        assert not found.unlock_authorized

    route_cases=[
        ({"dst":"1.1.1.1", "dev":"tun7"},False),
        ({"dst":"8.8.8.8", "dev":"eth0"},False),
        ({"dst":"1.1.1.1", "dev":"eth0"},True),
    ]
    for item, result in route_cases:
        found=read_fixture([ACTIVE, LINK, json.dumps([item]).encode()])
        assert found.pinned_peer_uses_underlay is result
        assert not found.unlock_authorized

    failure_cases=[
        ("duplicate_nm", [ACTIVE+ACTIVE, LINK, ROUTE]),
        ("ambiguous_nm", [b'uuid:vpn:tun7:extra', LINK,ROUTE]),
        ("blank_nm", [b'\n',LINK,ROUTE]),
        ("invalid_utf8", [bytes([255]),LINK,ROUTE]),
        ("oversized_nm", [b'X'*17000,LINK,ROUTE]),
        ("bad_link", [ACTIVE,b'not-json',ROUTE]),
        ("empty_link", [ACTIVE,b'[]',ROUTE]),
        ("double_link", [ACTIVE,b'[{},{}]',ROUTE]),
        ("link_missing_kind", [ACTIVE,b'[{"ifname":"tun7","ifindex":7}]',ROUTE]),
        ("link_bool_index", [ACTIVE,b'[{"ifname":"tun7","ifindex":true,"linkinfo":{"info_kind":"tun"}}]',ROUTE]),
        ("bad_route", [ACTIVE,LINK,b'not-json']),
        ("route_dict", [ACTIVE,LINK,b'{}']),
        ("route_many", [ACTIVE,LINK,b'[{},{}]']),
        ("runner_nonbytes", [ACTIVE,LINK,{}]),
        ("runner_too_long", [ACTIVE,LINK,b'x'*17000]),
    ]
    for label, outs in failure_cases:
        refused(lambda outs=outs: read_fixture(outs), label)
    refused(lambda: observer.observe_readonly(None, lambda _: b''), "no_manifest")
    refused(lambda: observer._command_args("nft", APPROVED), "command_injection")
    refused(lambda: observer._command_args("disconnect", APPROVED), "network_mutation")
    refused(lambda: observer._run_readonly(["/bin/sh","-c","id"]), "shell")
    assert len(failure_cases)==15
    text=Path(observer.__file__).read_text()
    for mutation in ("nft -f", "nmcli connection up", "nmcli connection down",
                     "os.system(", "shell=True", "systemctl enable"):
        assert mutation not in text,mutation
    print("NM_KERNEL_INDEPENDENT_PARTIAL_OBSERVER_FIXTURES_PASS"
          " 15_INVALID_RECORDS 4_MUTATION_REFUSALS NO_UNLOCK_NO_HOST_MUTATION")


if __name__=="__main__":
    main()
