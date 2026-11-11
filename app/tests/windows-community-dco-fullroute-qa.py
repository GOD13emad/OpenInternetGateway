#!/usr/bin/env python3
"""Disposable GitHub-hosted Windows: OpenVPN Community DCO IPv4 default-route QA.

This is NOT IPv6/DNS leak protection or a kill-switch acceptance test.
All network mutations are confined to a disposable GitHub Windows runner.
The test uses only a pinned peer, an owned adapter and bounded connection.
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
import subprocess
import sys
import time

PROVIDER_CA = 'c0c7c3663bd229bce127647dece873d37e022a5d283a35b162bb125ac70bb9ff'
PROVIDER_CN = 'server.vpnbook.com'
PROVIDER_HOST = 'uk205.vpnbook.com'
ROUTE_PAIR = ('0.0.0.0/1', '128.0.0.0/1')


def module_from_path(path):
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('oig_fullroute_' +
        path.stem.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def route_indices(prefix):
    # Probe only, not a route mutation.
    output = scoped.ps(
        "@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '" + prefix +
        "' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InterfaceIndex)"
        " | ConvertTo-Json -Compress")
    if not output:
        return []
    result = json.loads(output)
    return [int(i) for i in (result if isinstance(result, list) else [result])]


def cleanup_owned_pair(prefix, index):
    if index in route_indices(prefix):
        scoped.ps(
            "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '" + prefix +
            "' -ErrorAction Stop | Where-Object {$_.InterfaceIndex -eq " +
            str(index) +
            "} | Remove-NetRoute -Confirm:$false -ErrorAction Stop", timeout=12)
    if index in route_indices(prefix):
        raise RuntimeError('OWNED_ROUTE_REMAINS_AFTER_CLEANUP')


def check_host_guard(args):
    if os.environ.get('OIG_HOSTED_DCO_FULL_IPV4_QA') != '1':
        raise RuntimeError('FULL_IPV4_QA_EXPLICIT_OPT_IN_MISSING')
    root, receipt, exe = scoped.qa_guard(args)
    # Do not touch a host which has already been partially routed or managed
    # by an unrelated VPN, even when the host is a GitHub disposable runner.
    if any(route_indices(prefix) for prefix in ROUTE_PAIR):
        raise RuntimeError('PREEXISTING_SPLIT_DEFAULT_REFUSE_TO_TOUCH')
    return root, receipt, exe


def main(args):
    root, receipt, exe = check_host_guard(args)
    provider, helper = scoped.provider_modules()
    if (provider.EXPECTED_CA != PROVIDER_CA or
        provider.EXPECTED_CN != PROVIDER_CN or
        provider.ENDPOINT != PROVIDER_HOST):
        raise RuntimeError('PROVIDER_PIN_NOT_ACCEPTED')
    profile, profile_sha = provider.official_profile()
    password, updated = provider.official_login()
    if not re.fullmatch(r'[A-Za-z0-9]{4,32}', password):
        raise RuntimeError('PUBLIC_SHARED_LOGIN_CHANGED')
    files = []
    def private(name, value):
        output = scoped.write_private(root, name, value)
        files.append(output)
        return output
    pem = {tag: helper.extract_unique_pem(profile, tag)
           for tag in ('ca', 'cert', 'key')}
    ca = private('fullroute-ca.pem', pem['ca'] + '\n')
    cert = private('fullroute-client.pem', pem['cert'] + '\n')
    key = private('fullroute-client.key', pem['key'] + '\n')
    login = private('fullroute-login.txt', 'vpnbook\n' + password + '\n')
    password = ''
    log = root / 'fullroute-private-openvpn.log'
    # Use forward slashes; Windows backslashes are escapes in .ovpn files.
    lines = [
        'client', 'dev tun', 'dev-node ' + args.adapter, 'proto tcp-client',
        'remote ' + PROVIDER_HOST + ' 443', 'nobind', 'resolv-retry 1',
        'remote-cert-tls server', 'verify-x509-name ' + PROVIDER_CN + ' name',
        'ca "' + ca.as_posix() + '"', 'cert "' + cert.as_posix() + '"',
        'key "' + key.as_posix() + '"',
        'auth-user-pass "' + login.as_posix() + '"', 'auth-nocache',
        'data-ciphers AES-256-GCM:AES-128-GCM',
        'pull-filter ignore redirect-gateway',
        'pull-filter ignore route-ipv6',
        'pull-filter ignore dhcp-option',
        'redirect-gateway def1 block-local',
        'auth-retry none', 'connect-retry-max 1', 'verb 4',
        'log "' + log.as_posix() + '"', ''
    ]
    config = private('fullroute.ovpn', '\n'.join(lines))
    baseline = scoped.host_snapshot()
    baseline_ipv4 = scoped.echo_ipv4()
    pre_resolved_probe_ip = str(ipaddress.IPv4Address(socket.gethostbyname(scoped.PROBE_HOST)))
    result = {
        'schema': 'oig-hosted-windows-community-dco-ipv4-fullroute-v1',
        'sourceSha': os.environ['GITHUB_SHA'],
        'scope': 'disposable Windows real ovpn-dco IPv4 /1 route-pair only',
        'pinnedCaSha256': PROVIDER_CA, 'profileSha256': profile_sha,
        'publicCredentialUpdated': updated,
        'pinnedPeerVerified': False, 'dcoRoutePairActive': False,
        'publicIpv4ViaVpnVerified': False, 'ownedRoutesRemoved': False,
        'vpnProcessStopped': False, 'hostRoutesRestored': False,
        'hostDnsRestored': False,
        'ipv6LeakProtectionProven': False,
        'dnsLeakProtectionProven': False,
        'killSwitchProven': False, 'fullDeviceAccepted': False,
        'productionEngineChanged': False, 'ownerHostTouched': False,
        'pass': False
    }
    proc = None
    adapter_index = None
    failure = ''
    try:
        if any(route_indices(prefix) for prefix in ROUTE_PAIR):
            raise RuntimeError('PREEXISTING_SPLIT_ROUTE_LATE_REFUSED')
        proc = subprocess.Popen(
            [str(exe), '--config', str(config)], cwd=str(root),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        deadline = time.monotonic() + 70
        while time.monotonic() < deadline:
            info = log.read_text(errors='replace')[-180000:] if log.exists() else ''
            if ('Initialization Sequence Completed' in info and
                'VERIFY X509NAME OK: CN=' + PROVIDER_CN in info):
                result['pinnedPeerVerified'] = True
                break
            if proc.poll() is not None:
                raise RuntimeError('FULLROUTE_OPENVPN_EXITED_EARLY')
            time.sleep(0.4)
        if not result['pinnedPeerVerified']:
            raise RuntimeError('FULLROUTE_VPN_INIT_TIMEOUT')
        adapter = json.loads(scoped.ps(
            "Get-NetAdapter -Name '" + args.adapter +
            "' -ErrorAction Stop | Select-Object Name,Status,ifIndex,"
            "InterfaceDescription | ConvertTo-Json -Compress"))
        if ('OpenVPN' not in adapter['InterfaceDescription'] and
            'Data Channel Offload' not in adapter['InterfaceDescription']):
            raise RuntimeError('FULLROUTE_ADAPTER_UNTRUSTED')
        adapter_index = int(adapter['ifIndex'])
        if not scoped.interface_ip(args.adapter):
            raise RuntimeError('FULLROUTE_DCO_TUNNEL_IP_MISSING')
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if all(route_indices(p) == [adapter_index] for p in ROUTE_PAIR):
                result['dcoRoutePairActive'] = True
                break
            time.sleep(0.4)
        if not result['dcoRoutePairActive']:
            raise RuntimeError('FULLROUTE_TWO_SPLIT_ROUTES_MISSING')
        target = pre_resolved_probe_ip
        tunneled = scoped.echo_ipv4(
            '--resolve', scoped.PROBE_HOST + ':443:' + target)
        if tunneled == baseline_ipv4:
            raise RuntimeError('FULLROUTE_EGRESS_MATCHES_DIRECT')
        result['publicIpv4ViaVpnVerified'] = True
    except Exception as exc:
        failure = type(exc).__name__ + ':' + str(exc)[:120]
    finally:
        # This process was started by this test alone. Never kill by name.
        if proc:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=12)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=4)
                result['vpnProcessStopped'] = proc.poll() is not None
            except Exception as exc:
                failure += ';STOP_' + type(exc).__name__
        # OpenVPN should remove its routes. Only remove entries on our exact
        # owned adapter if it crashes before ordinary cleanup.
        if adapter_index is not None:
            for prefix in ROUTE_PAIR:
                try:
                    cleanup_owned_pair(prefix, adapter_index)
                except Exception as exc:
                    failure += ';ROUTE_' + type(exc).__name__
        try:
            result['ownedRoutesRemoved'] = all(
                not route_indices(prefix) for prefix in ROUTE_PAIR)
            restored = scoped.host_snapshot()
            result['hostRoutesRestored'] = baseline['routes'] == restored['routes']
            result['hostDnsRestored'] = baseline['dns'] == restored['dns']
        except Exception as exc:
            failure += ';RECHECK_' + type(exc).__name__
        for p in reversed(files):
            try:
                p.unlink(missing_ok=True)
            except Exception as exc:
                failure += ';SCRATCH_' + type(exc).__name__
        result['failureCategory'] = failure[:180]
        result['pass'] = not failure and all(result[k] for k in (
            'pinnedPeerVerified', 'dcoRoutePairActive',
            'publicIpv4ViaVpnVerified', 'ownedRoutesRemoved',
            'vpnProcessStopped', 'hostRoutesRestored', 'hostDnsRestored'))
        with receipt.open('x', encoding='utf-8') as f:
            json.dump(result, f, indent=2)
            f.write('\n')
    if not result['pass']:
        raise RuntimeError('FULLROUTE_IPV4_QA_NOT_ACCEPTED_' + failure[:130])
    print('PASS_DISPOSABLE_DCO_IPV4_FULLROUTE_EGRESS_AND_TEARDOWN')


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('--root', required=True)
        parser.add_argument('--openvpn', required=True)
        parser.add_argument('--adapter', required=True)
        parser.add_argument('--receipt', required=True)
        args = parser.parse_args()
        scoped = module_from_path(
            Path(__file__).resolve().parent /
            'windows-community-dco-tunnel-qa.py')
        main(args)
    except Exception as exc:
        print('FAIL_HOSTED_DCO_IPV4_FULLROUTE_' +
              type(exc).__name__ + '_' + str(exc)[:170], file=sys.stderr)
        sys.exit(1)
