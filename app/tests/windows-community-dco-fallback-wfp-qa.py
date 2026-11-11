#!/usr/bin/env python3
"""Windows hosted DCO packet-layer WFP fallback QA (NOT a global kill switch).

Run only inside a disposable GitHub-hosted Windows runner as an opt-in QA job.
Demonstrate a native WFP IPPACKET_V4 dynamic-session rule on one physical
interface and pinned HTTPS destination while the probe succeeds over DCO.
After dropping the owned VPN, direct fallback must remain blocked until the
exact rule is removed, when direct access must be restored.
No persistent firewall policy, profile, IPv6 or owner VPN is modified.
This dynamic-session policy is fail-open if its helper crashes; it cannot
serve as a production kill switch.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

import importlib.util


def load_module(path):
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(
        "oig_hosted_fallback_" + path.stem.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ps(command, timeout=18):
    return scoped.ps(command, timeout=timeout)


def precise_guard(args):
    if os.environ.get("OIG_HOSTED_DCO_FALLBACK_QA") != "1":
        raise RuntimeError("FALLBACK_QA_NOT_OPTED_IN")
    root, receipt, exe = scoped.qa_guard(args)
    if any(fullroute.route_indices(x) for x in fullroute.ROUTE_PAIR):
        raise RuntimeError("PREEXISTING_FULLROUTE_POLICY_REFUSED")
    curl = (Path(os.environ["WINDIR"]) / "System32" / "curl.exe").resolve(strict=True)
    if not curl.is_file():
        raise RuntimeError("WINDOWS_SYSTEM_CURL_NOT_FOUND")
    resolved_curl = Path(os.environ["WINDIR"]) / "System32" / "curl.exe"
    if not resolved_curl.is_file():
        raise RuntimeError("SYSTEM_CURL_NOT_AVAILABLE")
    return root, receipt, exe, resolved_curl


def physical_nic():
    raw = ps(
        "$routes=@(Get-NetRoute -AddressFamily IPv4 "
        "-DestinationPrefix '0.0.0.0/0' -ErrorAction Stop "
        "| Sort-Object RouteMetric,InterfaceMetric);"
        "if($routes.Count -ne 1){throw 'AMBIGUOUS_PHYSICAL_DEFAULT'};"
        "$r=$routes[0];"
        "$a=Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -ErrorAction Stop;"
        "if($a.Status -ne 'Up' -or $a.Name -like 'OIG-QA-DCO-*'){"
        "throw 'UNTRUSTED_PHYSICAL_NIC'};"
        "$np=Get-NetConnectionProfile -InterfaceIndex $r.InterfaceIndex "
        "-ErrorAction Stop;"
        "$p=Get-NetFirewallProfile -Name $np.NetworkCategory -ErrorAction Stop;"
        "if(-not $p.Enabled){throw 'FIREWALL_PROFILE_NOT_ENABLED'};"
        "$v4=@(Get-NetIPAddress -InterfaceIndex $r.InterfaceIndex "
        "-AddressFamily IPv4 -ErrorAction Stop | Where-Object {"
        "$_.IPAddress -notlike '169.254.*' -and "
        "$_.IPAddress -ne '127.0.0.1' -and -not $_.SkipAsSource});"
        "if($v4.Count -ne 1){throw 'AMBIGUOUS_PHYSICAL_IPV4_SOURCE'};"
        "@{alias=[string]$a.Name;index=[int]$a.ifIndex;"
        "source=[string]$v4[0].IPAddress;"
        "category=[string]$np.NetworkCategory} | ConvertTo-Json -Compress")
    data = json.loads(raw)
    if not data["alias"] or int(data["index"]) <= 0:
        raise RuntimeError("UNTRUSTED_PHYSICAL_NIC")
    source = ipaddress.IPv4Address(data["source"])
    if source.is_unspecified or source.is_loopback or source.is_link_local:
        raise RuntimeError("UNTRUSTED_PHYSICAL_SOURCE_IPV4")
    if data["category"] not in ("Public", "Private", "DomainAuthenticated"):
        raise RuntimeError("UNSUPPORTED_PHYSICAL_NIC_PROFILE")
    return data


def exact_firewall_rule_name():
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not re.fullmatch(r"\d{7,16}", run_id):
        raise RuntimeError("INVALID_HOSTED_RUN_ID")
    return "OIG-QA-FALLBACK-" + run_id


# Native WFP packet-layer probe. Unlike the Windows Defender app rule,
# the filter matches actual outbound NIC and target at IPPACKET_V4.
# It is dynamic and vanishes on helper exit: this is feasibility QA ONLY.
_packet_process = None
_packet_filter_id = None
_packet_index = None
_packet_destination = None
_packet_name = None
_packet_exe = None


def helper_path():
    path = Path(os.environ.get("OIG_PACKET_WFP_HELPER", "")).resolve(strict=True)
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if path.parent != root or path.name != "oig-dco-packet-wfp-helper.exe":
        raise RuntimeError("NON_RUNNER_PACKET_WFP_HELPER_REFUSED")
    if os.environ.get("OIG_HOSTED_DCO_PACKET_QA") != "1":
        raise RuntimeError("NATIVE_PACKET_QA_OPT_IN_MISSING")
    return path


def native_inspect(exe, filter_id, ifindex, destination):
    r = subprocess.run(
        [str(exe), "inspect", str(filter_id), str(ifindex), destination],
        capture_output=True, text=True, timeout=10)
    return r.returncode == 0 and r.stdout.strip() == "MATCH"


def rule_present(name):
    if _packet_process is None or name != _packet_name:
        return False
    if _packet_process.poll() is not None:
        return False
    return native_inspect(
        _packet_exe, _packet_filter_id, _packet_index, _packet_destination)


def add_rule(name, ifindex, destination, curl):
    global _packet_process, _packet_filter_id
    global _packet_index, _packet_destination, _packet_name, _packet_exe
    if _packet_process is not None:
        raise RuntimeError("PACKET_WFP_ALREADY_ARMED")
    exe = helper_path()
    if int(ifindex) < 1:
        raise RuntimeError("UNOWNED_PHYSICAL_INDEX")
    target = str(ipaddress.IPv4Address(destination))
    # The exact target must differ from the pinned VPN outer endpoint
    # (the filter must never prevent the encrypted provider transport).
    if target in socket.gethostbyname_ex(fullroute.PROVIDER_HOST)[2]:
        raise RuntimeError("WFP_TARGET_COLLIDES_WITH_PROVIDER")
    proc = subprocess.Popen(
        [str(exe), "arm", str(ifindex), target],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    import concurrent.futures
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = executor.submit(proc.stdout.readline)
    try:
        line = future.result(timeout=12)
    except Exception as exc:
        proc.kill()
        proc.wait(timeout=5)
        raise RuntimeError("NATIVE_WFP_HELPER_DID_NOT_ARM") from exc
    finally:
        executor.shutdown(wait=False)
    if not line.startswith("READY:") or not line[6:].strip().isdigit():
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
        raise RuntimeError("NATIVE_WFP_HELPER_READY_INVALID")
    filter_id = int(line[6:].strip())
    _packet_process, _packet_filter_id = proc, filter_id
    _packet_index, _packet_destination = int(ifindex), target
    _packet_name, _packet_exe = name, exe
    if not rule_present(name):
        raise RuntimeError("NATIVE_WFP_PACKET_FILTER_NOT_INSTALLED")


def rule_contract(name, ifindex, destination, curl):
    return (name == _packet_name and int(ifindex) == _packet_index and
            destination == _packet_destination and rule_present(name))


def remove_exact_rule(name):
    global _packet_process, _packet_filter_id, _packet_index
    global _packet_destination, _packet_name, _packet_exe
    if _packet_process is None:
        return
    if name != _packet_name:
        raise RuntimeError("UNOWNED_PACKET_FILTER_REMOVE_REFUSED")
    proc, exe, fid, index, target = (
        _packet_process, _packet_exe, _packet_filter_id,
        _packet_index, _packet_destination)
    try:
        if proc.poll() is None:
            stdout, _ = proc.communicate(input="STOP\n", timeout=12)
            if proc.returncode != 0 or "REMOVED" not in stdout:
                raise RuntimeError("PACKET_FILTER_STOP_NOT_CONFIRMED")
        if native_inspect(exe, fid, index, target):
            raise RuntimeError("WFP_PACKET_FILTER_PERSISTED")
    finally:
        # Even on native error, terminate only the exact owned helper child.
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        _packet_process = None
        _packet_filter_id = None
        _packet_index = None
        _packet_destination = None
        _packet_name = None
        _packet_exe = None


def curl_probe(curl, target, timeout=15, source=None, diagnostic=None):
    # Explicit source-bound probe is diagnostic ONLY after a failed regular
    # HTTPS attempt; it must never turn a failure into acceptance.
    bind = []
    if source is not None:
        bind = ["--interface", str(ipaddress.IPv4Address(source))]
    cmd = [
        str(curl), "--ipv4", "--noproxy", "*", "--fail", "--silent",
        "--show-error", "--connect-timeout", "5", "--max-time",
        str(timeout), "--resolve", scoped.PROBE_HOST + ":443:" + target,
        *bind, "https://" + scoped.PROBE_HOST
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout + 3)
    except subprocess.TimeoutExpired:
        if diagnostic is not None:
            diagnostic["timedOut"] = True
        return None
    if diagnostic is not None:
        # Only numeric status; never include stderr, raw IP or credentials.
        diagnostic["exitCode"] = p.returncode
    if p.returncode:
        return None
    try:
        return str(ipaddress.IPv4Address(p.stdout.strip()))
    except ValueError:
        if diagnostic is not None:
            diagnostic["unexpectedResponse"] = True
        return None


def main(args):
    root, receipt, binary, curl = precise_guard(args)
    provider, helper = scoped.provider_modules()
    if (provider.EXPECTED_CA != fullroute.PROVIDER_CA or
        provider.EXPECTED_CN != fullroute.PROVIDER_CN or
        provider.ENDPOINT != fullroute.PROVIDER_HOST):
        raise RuntimeError("OFFICIAL_PEER_PIN_CHANGED")
    profile, sha = provider.official_profile()
    password, updated = provider.official_login()
    if not re.fullmatch(r"[A-Za-z0-9]{4,32}", password):
        raise RuntimeError("PUBLIC_PROVIDER_LOGIN_NOT_VALID")
    nic = physical_nic()
    name = exact_firewall_rule_name()
    if rule_present(name):
        raise RuntimeError("PREEXISTING_NAMED_FIREWALL_RULE_REFUSED")
    target = str(ipaddress.IPv4Address(socket.gethostbyname(scoped.PROBE_HOST)))
    if curl_probe(curl, target) is None:
        raise RuntimeError("NO_POSITIVE_DIRECT_HTTPS_BASELINE")
    original_network = scoped.host_snapshot()
    private_files = []

    def private(filename, content):
        file = scoped.write_private(root, filename, content)
        private_files.append(file)
        return file

    tags = {tag: helper.extract_unique_pem(profile, tag)
            for tag in ("ca", "cert", "key")}
    ca = private("fallback-ca.pem", tags["ca"] + "\n")
    cert = private("fallback-client.pem", tags["cert"] + "\n")
    key = private("fallback-client.key", tags["key"] + "\n")
    login = private("fallback-login.txt", "vpnbook\n" + password + "\n")
    password = ""
    private_log = root / "fallback-private-openvpn.log"
    config = private("fallback-qa.ovpn", "\n".join([
        "client", "dev tun", "dev-node " + args.adapter, "proto tcp-client",
        "remote " + fullroute.PROVIDER_HOST + " 443", "nobind",
        "resolv-retry 1", "remote-cert-tls server",
        "verify-x509-name " + fullroute.PROVIDER_CN + " name",
        'ca "' + ca.as_posix() + '"',
        'cert "' + cert.as_posix() + '"',
        'key "' + key.as_posix() + '"',
        'auth-user-pass "' + login.as_posix() + '"', "auth-nocache",
        "data-ciphers AES-256-GCM:AES-128-GCM",
        "pull-filter ignore redirect-gateway",
        "pull-filter ignore route-ipv6",
        "pull-filter ignore dhcp-option",
        "redirect-gateway def1 block-local",
        "auth-retry none", "connect-retry-max 1", "verb 4",
        'log "' + private_log.as_posix() + '"', ""
    ]))
    report = {
        "schema": "oig-hosted-windows-community-dco-packet-wfp-fallback-v1",
        "sourceSha": os.environ["GITHUB_SHA"],
        "scope": "native dynamic WFP outbound IPv4 packet filter on one physical NIC and IP target; not persistent kill switch",
        "officialProfileSha256": sha, "publicCredentialUpdated": updated,
        "pinnedPeerVerified": False, "dcoRoutePairActive": False,
        "wfpRuleFilterVerified": False, "packetLayerFilterVerified": False,
        "packetFilterIsDynamic": True,
        "ownedPacketWfpFilterRemoved": False,
        "directBlockedBeforeVpn": False,
        "physicalIpv4DistinctFromDco": False,
        "explicitTunSourceCurlAllowedIfFailed": None,
        "wfpOnCurlDiagnostic": None,
        "wfpOffCurlDiagnostic": None,
        "vpnHttpsAllowedWithRuleTemporarilyRemoved": None,
        "wfpRuleReinstalledAfterDiagnostic": None,
        "fullRouteUnchangedByDiagnostic": None,
        "httpsOverVpnAllowed": False, "ownedTunnelStopped": False,
        "directFallbackBlockedAfterDrop": False,
        "directEgressRestoredAfterRuleRemoval": False,
        "ownedWfpRuleRemoved": False, "ownedRoutesRemoved": False,
        "hostRoutesRestored": False, "hostDnsRestored": False,
        "globalKillSwitchProven": False, "ipv6LeakProtectionProven": False,
        "systemDnsLeakProtectionProven": False,
        "productionEngineChanged": False, "ownerHostTouched": False,
        "pass": False
    }
    proc = None
    index = None
    failure = ""
    try:
        add_rule(name, nic["index"], target, curl)
        report["wfpRuleFilterVerified"] = rule_contract(
            name, nic["index"], target, curl)
        report["packetLayerFilterVerified"] = report["wfpRuleFilterVerified"]
        if not report["wfpRuleFilterVerified"]:
            raise RuntimeError("WFP_RULE_FILTER_CONTRACT_NOT_PROVEN")
        # Firewall must actively block direct HTTPS before opening VPN.
        report["directBlockedBeforeVpn"] = curl_probe(curl, target, 9) is None
        if not report["directBlockedBeforeVpn"]:
            raise RuntimeError("WFP_DIRECT_PATH_NOT_BLOCKED")
        # Record the adapter index BEFORE VPN creates any route.
        adapter = json.loads(ps(
            "Get-NetAdapter -Name '" + args.adapter + "' -ErrorAction Stop | "
            "Select-Object ifIndex,InterfaceDescription | ConvertTo-Json -Compress"))
        if ("OpenVPN" not in adapter["InterfaceDescription"] and
                "Data Channel Offload" not in adapter["InterfaceDescription"]):
            raise RuntimeError("UNOWNED_DCO_ADAPTER")
        index = int(adapter["ifIndex"])
        proc = subprocess.Popen(
            [str(binary), "--config", str(config)], cwd=str(root),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        until = time.monotonic() + 70
        while time.monotonic() < until:
            data = private_log.read_text(errors="replace")[-150000:] if private_log.exists() else ""
            if ("Initialization Sequence Completed" in data and
                "VERIFY X509NAME OK: CN=" + fullroute.PROVIDER_CN in data):
                report["pinnedPeerVerified"] = True
                break
            if proc.poll() is not None:
                raise RuntimeError("VPN_EXITED_BEFORE_TUNNEL_INIT")
            time.sleep(0.4)
        if not report["pinnedPeerVerified"]:
            raise RuntimeError("TUNNEL_SETUP_TIMEOUT")
        tunnel_ipv4 = scoped.interface_ip(args.adapter)
        report["physicalIpv4DistinctFromDco"] = bool(
            tunnel_ipv4 and tunnel_ipv4 != nic["source"])
        if not report["physicalIpv4DistinctFromDco"]:
            raise RuntimeError("PHYSICAL_SOURCE_NOT_DISTINCT_FROM_TUNNEL")
        until = time.monotonic() + 14
        while time.monotonic() < until:
            if all(fullroute.route_indices(p) == [index]
                   for p in fullroute.ROUTE_PAIR):
                report["dcoRoutePairActive"] = True
                break
            time.sleep(0.4)
        if not report["dcoRoutePairActive"]:
            raise RuntimeError("DCO_SPLIT_DEFAULT_ROUTE_NOT_PROVEN")
        # The exact same curl.exe is permitted through the DCO interface.
        on_status = {}
        vpn_public = curl_probe(curl, target, 18, diagnostic=on_status)
        if vpn_public is None:
            report["wfpOnCurlDiagnostic"] = on_status
            report["explicitTunSourceCurlAllowedIfFailed"] = (
                curl_probe(curl, target, 12, source=tunnel_ipv4) is not None)
            # Diagnostic A/B, on a disposable GitHub VM ONLY:
            # while pinned VPN is up, temporarily remove ONLY OUR WFP rule,
            # check the identical HTTPS endpoint, then immediately re-arm it.
            # This is NOT a PASS or fail-closed guarantee.
            try:
                remove_exact_rule(name)
                off_status = {}
                off_ip = curl_probe(curl, target, 16, diagnostic=off_status)
                report["wfpOffCurlDiagnostic"] = off_status
                report["vpnHttpsAllowedWithRuleTemporarilyRemoved"] = (
                    off_ip is not None)
                report["fullRouteUnchangedByDiagnostic"] = all(
                    fullroute.route_indices(p) == [index]
                    for p in fullroute.ROUTE_PAIR)
            finally:
                # Must restore the exact prior block even if diagnostic fails.
                if not rule_present(name):
                    add_rule(name, nic["index"], target, curl)
                report["wfpRuleReinstalledAfterDiagnostic"] = rule_contract(
                    name, nic["index"], target, curl)
            if not report["wfpRuleReinstalledAfterDiagnostic"]:
                raise RuntimeError("OWNED_WFP_RULE_NOT_RESTORED_AFTER_AB")
            raise RuntimeError("VPN_PATH_DENIED_WITH_WFP_AB_DIAGNOSTICS")
        report["httpsOverVpnAllowed"] = True
        # Simulate tunnel disappearance, retaining the owned WFP rule.
        proc.terminate()
        try:
            proc.wait(timeout=12)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=4)
        report["ownedTunnelStopped"] = proc.poll() is not None
        if not report["ownedTunnelStopped"]:
            raise RuntimeError("OWNED_TUNNEL_NOT_STOPPED")
        for prefix in fullroute.ROUTE_PAIR:
            fullroute.cleanup_owned_pair(prefix, index)
        if any(fullroute.route_indices(p) for p in fullroute.ROUTE_PAIR):
            raise RuntimeError("RESIDUAL_OWNED_SPLIT_ROUTE")
        report["directFallbackBlockedAfterDrop"] = (
            curl_probe(curl, target, 10) is None)
        if not report["directFallbackBlockedAfterDrop"]:
            raise RuntimeError("DIRECT_FALLBACK_ALLOWED_WHILE_WFP_RULE_ACTIVE")
        remove_exact_rule(name)
        report["ownedWfpRuleRemoved"] = True
        restored = curl_probe(curl, target, 15)
        report["directEgressRestoredAfterRuleRemoval"] = restored is not None
        if restored is None:
            raise RuntimeError("DIRECT_EGRESS_NOT_RESTORED_AFTER_WFP_CLEANUP")
    except Exception as exc:
        failure = type(exc).__name__ + ":" + str(exc)[:130]
    finally:
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            except Exception as exc:
                failure += ";STOP_" + type(exc).__name__
        if proc:
            report["ownedTunnelStopped"] = proc.poll() is not None
        if index is not None:
            for prefix in fullroute.ROUTE_PAIR:
                try:
                    fullroute.cleanup_owned_pair(prefix, index)
                except Exception as exc:
                    failure += ";ROUTE_" + type(exc).__name__
        try:
            remove_exact_rule(name)
            report["ownedWfpRuleRemoved"] = True
            report["ownedPacketWfpFilterRemoved"] = True
        except Exception as exc:
            failure += ";FIREWALL_" + type(exc).__name__
        try:
            report["ownedRoutesRemoved"] = all(
                not fullroute.route_indices(x) for x in fullroute.ROUTE_PAIR)
            after = scoped.host_snapshot()
            report["hostRoutesRestored"] = (after["routes"] == original_network["routes"])
            report["hostDnsRestored"] = (after["dns"] == original_network["dns"])
        except Exception as exc:
            failure += ";NETWORK_" + type(exc).__name__
        for file in private_files:
            try:
                file.unlink(missing_ok=True)
            except Exception as exc:
                failure += ";SCRATCH_" + type(exc).__name__
        # Never emit raw log, account strings, IPs, WFP rule or private files.
        report["failureCategory"] = failure[:200]
        must = (
            "pinnedPeerVerified", "dcoRoutePairActive",
            "wfpRuleFilterVerified", "packetLayerFilterVerified",
            "ownedPacketWfpFilterRemoved", "directBlockedBeforeVpn",
            "physicalIpv4DistinctFromDco",
            "httpsOverVpnAllowed", "ownedTunnelStopped",
            "directFallbackBlockedAfterDrop",
            "directEgressRestoredAfterRuleRemoval",
            "ownedWfpRuleRemoved", "ownedRoutesRemoved",
            "hostRoutesRestored", "hostDnsRestored"
        )
        report["pass"] = not failure and all(report[k] for k in must)
        with receipt.open("x", encoding="utf-8") as out:
            json.dump(report, out, indent=2)
            out.write("\n")
    if not report["pass"]:
        raise RuntimeError("PROCESS_SCOPED_FALLBACK_QA_NOT_ACCEPTED_" + failure[:130])
    print("PASS_DCO_CURL_PROCESS_SCOPED_FIREWALL_FALLBACK_AND_TEARDOWN")


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--root", required=True)
        parser.add_argument("--openvpn", required=True)
        parser.add_argument("--adapter", required=True)
        parser.add_argument("--receipt", required=True)
        args = parser.parse_args()
        directory = Path(__file__).resolve().parent
        scoped = load_module(directory / "windows-community-dco-tunnel-qa.py")
        fullroute = load_module(directory / "windows-community-dco-fullroute-qa.py")
        # Imported fullroute helper functions depend on their module-global
        # scoped harness (normally set only by that script's __main__).
        # Bind the exact same QA guard object before route preflight.
        fullroute.scoped = scoped
        main(args)
    except Exception as exc:
        print("FAIL_DCO_FALLBACK_" + type(exc).__name__ + "_" +
              str(exc)[:150], file=sys.stderr)
        sys.exit(1)
