#!/usr/bin/env python3
"""Disposable Windows OpenVPN 2.7.9 DCO IPv6/DNS *policy feasibility* QA.

Conclusions distinguish tested routing policy from actual leak prevention:
an unreachable native IPv6/DNS baseline is INCONCLUSIVE, never PASS.
No kill-switch or user-facing full-device acceptance is implied.
The only host route/DNS changes are those made by our pinned OpenVPN child
inside a disposable GitHub-hosted Windows VM, with exact owned cleanup.
"""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import time

CA_PIN = "c0c7c3663bd229bce127647dece873d37e022a5d283a35b162bb125ac70bb9ff"
PROVIDER_HOST = "uk205.vpnbook.com"
SERVER_CN = "server.vpnbook.com"
IPV4_PAIR = ("0.0.0.0/1", "128.0.0.0/1")
IPV6_PAIR = ("2000::/4", "3000::/4")
OUTSIDE_DNS = ("1.1.1.1", "8.8.8.8")


def load(path):
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(
        "oig_dco_policy_" + path.stem.replace("-", "_"), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def ps_values(family, prefix):
    # Query-only, no automatic route writes.
    raw = scoped.ps(
        "@(Get-NetRoute -AddressFamily " + family +
        " -DestinationPrefix '" + prefix + "' -ErrorAction SilentlyContinue | " +
        "Select-Object -ExpandProperty InterfaceIndex) | ConvertTo-Json -Compress")
    if not raw or raw == "null":
        return []
    parsed = json.loads(raw)
    return [int(x) for x in (parsed if isinstance(parsed, list) else [parsed])]


def host_physical_ipv4():
    raw = scoped.ps(
        "$g=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
        "-ErrorAction Stop | Sort-Object RouteMetric | Select-Object -First 1; "
        "if(-not $g){throw 'NO_PHYSICAL_DEFAULT'}; "
        "$a=Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $g.InterfaceIndex "
        "-ErrorAction Stop | Where-Object { "
        "$_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } "
        "| Select-Object -First 1; "
        "if(-not $a){throw 'NO_SOURCE_IP'}; "
        "@{index=[int]$g.InterfaceIndex;address=[string]$a.IPAddress} "
        "| ConvertTo-Json -Compress")
    item = json.loads(raw)
    ip = ipaddress.IPv4Address(item["address"])
    if ip.is_loopback or ip.is_link_local:
        raise RuntimeError("NO_ROUTABLE_HOST_NIC")
    return int(item["index"]), str(ip)


def dns_query(source_ip, target_ip, physical_ifindex=None):
    """A real UDP/53 response, with a pinned physical interface when supplied.

    This is a behavioral DNS probe, not an inference from OpenVPN options.
    """
    txid = os.urandom(2)
    q = (txid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00" +
         b"\x07example\x03org\x00\x00\x01\x00\x01")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.settimeout(2.8)
        try:
            if physical_ifindex is not None:
                # Windows IP_UNICAST_IF=31 takes an interface ID in network order.
                sock.setsockopt(
                    socket.IPPROTO_IP, getattr(socket, "IP_UNICAST_IF", 31),
                    struct.pack("I", socket.htonl(physical_ifindex)))
            sock.bind((source_ip, 0))
            sock.sendto(q, (target_ip, 53))
            response, remote = sock.recvfrom(512)
            return (remote[0] == target_ip and len(response) >= 12 and
                    response[:2] == txid and bool(response[2] & 0x80))
        except (OSError, TimeoutError):
            return False


def public_ipv6_available():
    r = subprocess.run(
        ["curl.exe", "-6", "--noproxy", "*", "--fail", "--silent",
         "--connect-timeout", "4", "--max-time", "7", "https://api6.ipify.org"],
        capture_output=True, text=True, timeout=12)
    if r.returncode:
        return False
    try:
        return ipaddress.ip_address(r.stdout.strip()).version == 6
    except ValueError:
        return False


def exact_route_cleanup(family, prefix, adapter_index):
    if adapter_index in ps_values(family, prefix):
        scoped.ps(
            "Get-NetRoute -AddressFamily " + family +
            " -DestinationPrefix '" + prefix + "' -ErrorAction Stop | "
            "Where-Object {$_.InterfaceIndex -eq " + str(adapter_index) +
            "} | Remove-NetRoute -Confirm:$false -ErrorAction Stop")
    if adapter_index in ps_values(family, prefix):
        raise RuntimeError("OWNED_" + family + "_ROUTE_REMAINS")


def guarded(args):
    if os.environ.get("OIG_HOSTED_DCO_LEAK_POLICY_QA") != "1":
        raise RuntimeError("HOSTED_DCO_LEAK_POLICY_EXPLICIT_OPT_IN_REQUIRED")
    root, receipt, binary = scoped.qa_guard(args)
    if any(ps_values("IPv4", x) for x in IPV4_PAIR):
        raise RuntimeError("UNEXPECTED_PREEXISTING_IPV4_SPLIT_ROUTE")
    if any(ps_values("IPv6", x) for x in IPV6_PAIR):
        raise RuntimeError("UNEXPECTED_PREEXISTING_IPV6_SPLIT_ROUTE")
    return root, receipt, binary


def main(args):
    root, receipt, binary = guarded(args)
    provider, helper = scoped.provider_modules()
    if (provider.EXPECTED_CA != CA_PIN or
        provider.EXPECTED_CN != SERVER_CN or
        provider.ENDPOINT != PROVIDER_HOST):
        raise RuntimeError("PINNED_PROVIDER_CONTRACT_MISMATCH")
    profile, profile_sha = provider.official_profile()
    password, updated = provider.official_login()
    if not re.fullmatch(r"[A-Za-z0-9]{4,32}", password):
        raise RuntimeError("PUBLIC_CREDENTIAL_FORMAT_CHANGED")
    files = []

    def private(name, value):
        out = scoped.write_private(root, name, value)
        files.append(out)
        return out

    pem = {tag: helper.extract_unique_pem(profile, tag)
           for tag in ("ca", "cert", "key")}
    ca = private("policy-ca.pem", pem["ca"] + "\n")
    cert = private("policy-client.pem", pem["cert"] + "\n")
    key = private("policy-client.key", pem["key"] + "\n")
    login = private("policy-public-login.txt", "vpnbook\n" + password + "\n")
    password = ""
    log = root / "policy-private-openvpn.log"
    # OpenVPN 2.7 Windows supports WFP block-outside-dns. OpenVPN's own
    # --block-ipv6 needs IPv6 routed INTO tun (per official 2.7 manual).
    config = private("policy-qa.ovpn", "\n".join([
        "client", "dev tun", "dev-node " + args.adapter, "proto tcp-client",
        "remote " + PROVIDER_HOST + " 443", "nobind", "resolv-retry 1",
        "remote-cert-tls server", "verify-x509-name " + SERVER_CN + " name",
        'ca "' + ca.as_posix() + '"',
        'cert "' + cert.as_posix() + '"',
        'key "' + key.as_posix() + '"',
        'auth-user-pass "' + login.as_posix() + '"', "auth-nocache",
        "data-ciphers AES-256-GCM:AES-128-GCM",
        "pull-filter ignore redirect-gateway",
        "pull-filter ignore dhcp-option",
        "pull-filter ignore route-ipv6",
        "dhcp-option DNS 1.1.1.1",
        "redirect-gateway def1 ipv6 block-local",
        "ifconfig-ipv6 fd15:53b6:dead::2/64 fd15:53b6:dead::1",
        "block-ipv6", "block-outside-dns",
        "auth-retry none", "connect-retry-max 1",
        "verb 4", 'log "' + log.as_posix() + '"', ""
    ]))
    before = scoped.host_snapshot()
    direct_ipv4 = scoped.echo_ipv4()
    import socket as _socket
    probe_ip = str(ipaddress.IPv4Address(_socket.gethostbyname(scoped.PROBE_HOST)))
    physical_index, physical_ip = host_physical_ipv4()

    dns_baseline = next(
        (ip for ip in OUTSIDE_DNS
         if dns_query(physical_ip, ip, physical_ifindex=physical_index)), None)
    baseline_ipv6 = public_ipv6_available()
    report = {
        "schema": "oig-hosted-windows-community-dco-dualstack-dns-policy-v1",
        "sourceSha": os.environ["GITHUB_SHA"],
        "scope": "disposable DCO IPv4/IPv6 route and WFP DNS policy feasibility, NOT kill switch",
        "caSha256": CA_PIN, "profileSha256": profile_sha,
        "publicCredentialUpdated": updated,
        "pinnedPeerVerified": False, "ipv4RoutePairActive": False,
        "ipv6GlobalRoutePairOnDco": False, "sourceBoundHttpsOverVpn": False,
        "dnsPhysicalBaselineEligible": bool(dns_baseline),
        "ipv6PublicBaselineEligible": baseline_ipv6,
        "dnsResponseOverTun": False, "physicalDnsBlockedWhileVpn": None,
        "ipv6PublicEgressDeniedWhileVpn": None,
        "dnsLeakProtectionProven": False, "ipv6LeakProtectionProven": False,
        "killSwitchProven": False, "fullDeviceAccepted": False,
        "ownedRoutesRemoved": False, "vpnProcessStopped": False,
        "hostRoutesRestored": False, "hostDnsRestored": False,
        "productionBackendChanged": False, "ownerHostTouched": False,
        "pass": False,
    }
    # Ownership is established BEFORE spawning OpenVPN. If the child dies
    # during init, cleanup can still remove only routes on our own adapter.
    pre_nic = json.loads(scoped.ps(
        "Get-NetAdapter -Name '" + args.adapter + "' -ErrorAction Stop | "
        "Select-Object Name,Status,ifIndex,InterfaceDescription | "
        "ConvertTo-Json -Compress"))
    if ("OpenVPN" not in pre_nic["InterfaceDescription"] and
            "Data Channel Offload" not in pre_nic["InterfaceDescription"]):
        raise RuntimeError("DCO_POLICY_PREEXISTING_DRIVER_IDENTITY_INVALID")
    adapter_index = int(pre_nic["ifIndex"])
    if adapter_index <= 0:
        raise RuntimeError("DCO_POLICY_PREEXISTING_ADAPTER_INDEX_INVALID")
    proc = None
    failure = ""
    try:
        proc = subprocess.Popen(
            [str(binary), "--config", str(config)], cwd=str(root),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        deadline = time.monotonic() + 70
        while time.monotonic() < deadline:
            data = log.read_text(errors="replace")[-160000:] if log.exists() else ""
            if ("Initialization Sequence Completed" in data and
                    "VERIFY X509NAME OK: CN=" + SERVER_CN in data):
                report["pinnedPeerVerified"] = True
                break
            if proc.poll() is not None:
                raise RuntimeError("DCO_POLICY_CLIENT_EXITED_EARLY")
            time.sleep(0.35)
        if not report["pinnedPeerVerified"]:
            raise RuntimeError("DCO_POLICY_HANDSHAKE_TIMEOUT")
        nic = json.loads(scoped.ps(
            "Get-NetAdapter -Name '" + args.adapter + "' -ErrorAction Stop | "
            "Select-Object Name,Status,ifIndex,InterfaceDescription | "
            "ConvertTo-Json -Compress"))
        if ("OpenVPN" not in nic["InterfaceDescription"] and
                "Data Channel Offload" not in nic["InterfaceDescription"]):
            raise RuntimeError("DCO_POLICY_ADAPTER_MISMATCH")
        if int(nic["ifIndex"]) != adapter_index:
            raise RuntimeError("DCO_POLICY_ADAPTER_INDEX_CHANGED_DURING_TEST")
        vpn_ipv4 = scoped.interface_ip(args.adapter)
        if not vpn_ipv4:
            raise RuntimeError("DCO_POLICY_IPV4_MISSING")
        route_deadline = time.monotonic() + 15
        while time.monotonic() < route_deadline:
            if (all(ps_values("IPv4", x) == [adapter_index] for x in IPV4_PAIR) and
                    all(ps_values("IPv6", x) == [adapter_index] for x in IPV6_PAIR)):
                report["ipv4RoutePairActive"] = True
                report["ipv6GlobalRoutePairOnDco"] = True
                break
            time.sleep(0.5)
        if not report["ipv6GlobalRoutePairOnDco"]:
            raise RuntimeError("DCO_POLICY_GLOBAL_IPV6_ROUTES_NOT_ON_TUN")
        via_vpn = scoped.echo_ipv4(
            "--resolve", scoped.PROBE_HOST + ":443:" + probe_ip)
        if via_vpn == direct_ipv4:
            raise RuntimeError("DCO_POLICY_IPV4_EGRESS_NOT_THROUGH_VPN")
        report["sourceBoundHttpsOverVpn"] = True
        report["dnsResponseOverTun"] = dns_query(vpn_ipv4, dns_baseline or "1.1.1.1")
        if dns_baseline:
            report["physicalDnsBlockedWhileVpn"] = not dns_query(
                physical_ip, dns_baseline, physical_ifindex=physical_index)
            report["dnsLeakProtectionProven"] = bool(
                report["physicalDnsBlockedWhileVpn"] and report["dnsResponseOverTun"])
        if baseline_ipv6:
            report["ipv6PublicEgressDeniedWhileVpn"] = not public_ipv6_available()
            report["ipv6LeakProtectionProven"] = bool(
                report["ipv6GlobalRoutePairOnDco"] and
                report["ipv6PublicEgressDeniedWhileVpn"])
        if not report["dnsResponseOverTun"]:
            raise RuntimeError("DCO_POLICY_TUNNEL_DNS_NOT_REACHABLE")
        if dns_baseline and not report["dnsLeakProtectionProven"]:
            raise RuntimeError("DCO_POLICY_OFF_TUN_DNS_NOT_BLOCKED")
        if baseline_ipv6 and not report["ipv6LeakProtectionProven"]:
            raise RuntimeError("DCO_POLICY_IPV6_EGRESS_NOT_BLOCKED")
    except Exception as exc:
        failure = type(exc).__name__ + ":" + str(exc)[:120]
    finally:
        if proc:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=11)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=4)
                report["vpnProcessStopped"] = proc.poll() is not None
            except Exception as exc:
                failure += ";STOP_" + type(exc).__name__
        if adapter_index is not None:
            for family, prefixes in (("IPv4", IPV4_PAIR), ("IPv6", IPV6_PAIR)):
                for prefix in prefixes:
                    try:
                        exact_route_cleanup(family, prefix, adapter_index)
                    except Exception as exc:
                        failure += ";ROUTE_" + type(exc).__name__
        try:
            report["ownedRoutesRemoved"] = all(
                not ps_values(family, prefix)
                for family, prefixes in (("IPv4", IPV4_PAIR), ("IPv6", IPV6_PAIR))
                for prefix in prefixes)
            after = scoped.host_snapshot()
            report["hostRoutesRestored"] = before["routes"] == after["routes"]
            report["hostDnsRestored"] = before["dns"] == after["dns"]
        except Exception as exc:
            failure += ";RECHECK_" + type(exc).__name__
        for path in reversed(files):
            try:
                path.unlink(missing_ok=True)
            except Exception as exc:
                failure += ";PRIVATE_SCRATCH_" + type(exc).__name__
        # Diagnostics are fixed booleans, never raw logs, credentials or IPs.
        data = log.read_text(errors="replace")[-100000:] if log.exists() else ""
        report["diagnosticSignals"] = {
            "optionsError": "Options error:" in data,
            "tunOrDcoError": any(x in data for x in (
                "Failed to open TUN/TAP", "ERROR: DCO device",
                "DCO device failed", "TUN/TAP device failed")),
            "ipv6RouteError": ("route-ipv6 add failed" in data or
                               "ERROR: IPv6 route" in data),
            "dnsWfpError": any(
                "block-outside-dns" in line.lower() and
                any(marker in line.lower() for marker in ("error", "failed", "not supported"))
                for line in data.splitlines()),
            "tlsError": "TLS Error" in data,
            "authFailed": "AUTH_FAILED" in data,
            "fatalError": "Exiting due to fatal error" in data
        }
        report["openvpnExitCode"] = proc.poll() if proc else None
        report["failureCategory"] = failure[:180]
        report["pass"] = not failure and all(report[k] for k in (
            "pinnedPeerVerified", "ipv4RoutePairActive",
            "ipv6GlobalRoutePairOnDco", "sourceBoundHttpsOverVpn",
            "dnsResponseOverTun", "ownedRoutesRemoved",
            "vpnProcessStopped", "hostRoutesRestored", "hostDnsRestored"))
        with receipt.open("x", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
    if not report["pass"]:
        raise RuntimeError("DCO_POLICY_FEASIBILITY_NOT_ACCEPTED_" + failure[:140])
    print("PASS_HOSTED_DCO_IPV6_ROUTE_AND_DNS_POLICY_SCOPED_QA")


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--root", required=True)
        parser.add_argument("--openvpn", required=True)
        parser.add_argument("--adapter", required=True)
        parser.add_argument("--receipt", required=True)
        args = parser.parse_args()
        scoped = load(Path(__file__).resolve().parent /
                      "windows-community-dco-tunnel-qa.py")
        main(args)
    except Exception as exc:
        print("FAIL_HOSTED_DCO_DUALSTACK_DNS_POLICY_" +
              type(exc).__name__ + "_" + str(exc)[:145], file=sys.stderr)
        sys.exit(1)
