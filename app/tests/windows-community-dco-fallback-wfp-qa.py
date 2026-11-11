#!/usr/bin/env python3
"""Windows hosted DCO fallback-policy QA (NOT a global kill switch).

Run only inside a disposable GitHub-hosted Windows runner as an opt-in QA job.
Demonstrate that a narrowly owned WFP rule blocks curl.exe to one pinned HTTPS
destination over the physical adapter, while the same probe works over DCO.
After dropping the owned VPN, direct fallback must remain blocked until the
exact rule is removed, when direct access must be restored.
No global firewall policy, profiles, IPv6 or user-owned VPN are modified.
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
        "@{alias=[string]$a.Name;index=[int]$a.ifIndex;"
        "category=[string]$np.NetworkCategory} | ConvertTo-Json -Compress")
    data = json.loads(raw)
    if not data["alias"] or int(data["index"]) <= 0:
        raise RuntimeError("UNTRUSTED_PHYSICAL_NIC")
    if data["category"] not in ("Public", "Private", "DomainAuthenticated"):
        raise RuntimeError("UNSUPPORTED_PHYSICAL_NIC_PROFILE")
    return data


def exact_firewall_rule_name():
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not re.fullmatch(r"\d{7,16}", run_id):
        raise RuntimeError("INVALID_HOSTED_RUN_ID")
    return "OIG-QA-FALLBACK-" + run_id


def rule_present(name):
    return ps("@(Get-NetFirewallRule -Name '" + name +
              "' -ErrorAction SilentlyContinue).Count") == "1"


def add_rule(name, nic_alias, destination, curl):
    # Permit only one explicitly named rule, scoped to one program, NIC, IPv4
    # destination and TCP/443, on disposable runner; no blanket deny.
    for value in (name, nic_alias, str(curl)):
        if "'" in value:
            raise RuntimeError("WFP_ARGUMENT_NOT_SAFE")
    ps(
        "New-NetFirewallRule -Name '" + name +
        "' -DisplayName '" + name + "' -Direction Outbound -Action Block "
        "-Enabled True -Profile Any -Program '" + str(curl) +
        "' -InterfaceAlias '" + nic_alias +
        "' -RemoteAddress '" + destination +
        "' -Protocol TCP -RemotePort 443 -ErrorAction Stop | Out-Null",
        timeout=25)
    if not rule_present(name):
        raise RuntimeError("OWNED_FIREWALL_RULE_MISSING")


def rule_contract(name, nic_alias, destination, curl):
    # Independent verification of all rule filters on the current host.
    result = json.loads(ps(
        "$r=Get-NetFirewallRule -Name '" + name + "' -ErrorAction Stop;"
        "$a=$r|Get-NetFirewallApplicationFilter;"
        "$i=$r|Get-NetFirewallInterfaceFilter;"
        "$d=$r|Get-NetFirewallAddressFilter;"
        "$p=$r|Get-NetFirewallPortFilter;"
        "@{count=@($r).Count;action=[string]$r.Action;"
        "enabled=[string]$r.Enabled;direction=[string]$r.Direction;"
        "program=[string]$a.Program;aliases=@($i.InterfaceAlias);"
        "remoteAddress=@($d.RemoteAddress);protocol=[string]$p.Protocol;"
        "remotePort=@($p.RemotePort)}|ConvertTo-Json -Compress"))
    aliases = result["aliases"]
    aliases = aliases if isinstance(aliases, list) else [aliases]
    remote = result["remoteAddress"]
    remote = remote if isinstance(remote, list) else [remote]
    ports = result["remotePort"]
    ports = ports if isinstance(ports, list) else [ports]
    return bool(
        result["count"] == 1 and result["action"] == "Block"
        and result["direction"] == "Outbound"
        and result["enabled"] == "True"
        and str(result["program"]).lower() == str(curl).lower()
        and aliases == [nic_alias] and remote == [destination]
        and str(result["protocol"]) in ("TCP", "6")
        and [str(x) for x in ports] == ["443"])


def remove_exact_rule(name):
    if rule_present(name):
        ps("Remove-NetFirewallRule -Name '" + name +
           "' -Confirm:$false -ErrorAction Stop")
    if rule_present(name):
        raise RuntimeError("OWNED_FIREWALL_RULE_STILL_PRESENT")


def curl_probe(curl, target, timeout=15):
    cmd = [
        str(curl), "--ipv4", "--noproxy", "*", "--fail", "--silent",
        "--show-error", "--connect-timeout", "5", "--max-time",
        str(timeout), "--resolve", scoped.PROBE_HOST + ":443:" + target,
        "https://" + scoped.PROBE_HOST
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout + 3)
    except subprocess.TimeoutExpired:
        return None
    if p.returncode:
        return None
    try:
        return str(ipaddress.IPv4Address(p.stdout.strip()))
    except ValueError:
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
        "schema": "oig-hosted-windows-community-dco-process-scoped-fallback-v1",
        "sourceSha": os.environ["GITHUB_SHA"],
        "scope": "one curl.exe, physical NIC, IPv4 destination, TCP 443; not system kill-switch",
        "officialProfileSha256": sha, "publicCredentialUpdated": updated,
        "pinnedPeerVerified": False, "dcoRoutePairActive": False,
        "wfpRuleFilterVerified": False, "directBlockedBeforeVpn": False,
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
        add_rule(name, nic["alias"], target, curl)
        report["wfpRuleFilterVerified"] = rule_contract(
            name, nic["alias"], target, curl)
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
        vpn_public = curl_probe(curl, target, 18)
        if vpn_public is None:
            raise RuntimeError("VPN_PATH_DENIED_BY_OWNED_WFP_RULE")
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
            "wfpRuleFilterVerified", "directBlockedBeforeVpn",
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
        main(args)
    except Exception as exc:
        print("FAIL_DCO_FALLBACK_" + type(exc).__name__ + "_" +
              str(exc)[:150], file=sys.stderr)
        sys.exit(1)
