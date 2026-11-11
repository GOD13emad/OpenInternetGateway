#!/usr/bin/env python3
"""Hosted Windows ONLY: scoped OpenVPN 2.7 ovpn-dco TUN and HTTPS egress QA.

Not a full-device, IPv6, DNS-leak or kill-switch acceptance. The only new
route is an owned temporary /32 to a probe endpoint on a disposable runner.
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

CA_PIN = 'c0c7c3663bd229bce127647dece873d37e022a5d283a35b162bb125ac70bb9ff'
EXE_PIN = '0b9b5ad60279b912ae826da5e13a57750fdc918d9ec28b73f031aaffef8dd485'
HOST = 'uk205.vpnbook.com'
PEER_CN = 'server.vpnbook.com'
PROBE_HOST = 'api.ipify.org'


def ps(script, timeout=15):
    r = subprocess.run(
        ['pwsh.exe', '-NoProfile', '-NonInteractive', '-Command',
         "$ErrorActionPreference='Stop'; " + script],
        text=True, capture_output=True, timeout=timeout)
    if r.returncode:
        raise RuntimeError('POWERSHELL_NETWORK_QUERY_FAILED')
    return r.stdout.strip()


def qa_guard(args):
    required = {
        'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Windows',
        'RUNNER_ENVIRONMENT': 'github-hosted',
        'GITHUB_REPOSITORY': 'GOD13emad/OpenInternetGateway',
        'GITHUB_HEAD_REF': 'qa/v2.5.20-operator-safety-20261019',
        'OIG_HOSTED_DCO_DATA_QA': '1',
    }
    if os.name != 'nt' or any(os.environ.get(k) != v for k, v in required.items()):
        raise RuntimeError('HOSTED_WINDOWS_TUN_ONLY')
    temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    root = Path(args.root).resolve(strict=True)
    if root.parent != temp or not root.name.startswith('oig-dco-driver-') or root.is_symlink():
        raise RuntimeError('TUN_SCRATCH_NOT_PRIVATE_RUNNER_TEMP')
    receipt = Path(args.receipt).resolve()
    if receipt.parent != temp or receipt.exists():
        raise RuntimeError('TUN_RECEIPT_NOT_PRIVATE_OR_EXISTS')
    if args.adapter != 'OIG-QA-DCO-' + os.environ['GITHUB_RUN_ID']:
        raise RuntimeError('UNOWNED_ADAPTER_REFUSED')
    exe = Path(args.openvpn).resolve(strict=True)
    if hashlib.sha256(exe.read_bytes()).hexdigest() != EXE_PIN:
        raise RuntimeError('OPENVPN_PE_PIN_MISMATCH')
    return root, receipt, exe


def provider_modules():
    directory = Path(__file__).resolve().parent

    def load(name):
        sys.dont_write_bytecode = True
        spec = importlib.util.spec_from_file_location(
            'oig_' + name.replace('-', '_'), directory / name)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    return (load('hosted-linux-provider-data-plane.py'),
            load('windows-community-provider-live.py'))


def write_private(root, name, value):
    target = root / name
    fd = os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w', encoding='ascii', newline='\n') as f:
        f.write(value)
    return target


def host_snapshot():
    query = (
        "$routes=@(Get-NetRoute -ErrorAction Stop | Where-Object {"
        "$_.DestinationPrefix -in @('0.0.0.0/0','::/0','0.0.0.0/1',"
        "'128.0.0.0/1','::/1','8000::/1')} | "
        "Sort-Object AddressFamily,DestinationPrefix,InterfaceIndex,NextHop | "
        "ForEach-Object {\"$($_.AddressFamily)|$($_.DestinationPrefix)|"
        "$($_.InterfaceIndex)|$($_.NextHop)\"}); "
        "$dns=@(Get-DnsClientServerAddress -ErrorAction Stop | "
        "Where-Object {$_.InterfaceAlias -notlike 'OIG-QA-DCO-*'} | "
        "Sort-Object InterfaceIndex,AddressFamily | "
        "ForEach-Object {\"$($_.InterfaceIndex)|$($_.AddressFamily)|"
        "$($_.ServerAddresses -join ',')\"}); "
        "@{routes=$routes;dns=$dns} | ConvertTo-Json -Compress"
    )
    return json.loads(ps(query))


def interface_ip(alias):
    result = ps(
        "@(Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias '" + alias +
        "' -ErrorAction SilentlyContinue | Where-Object {"
        "$_.IPAddress -notlike '169.254.*'} | "
        "Select-Object -ExpandProperty IPAddress) | ConvertTo-Json -Compress")
    if not result:
        return None
    value = json.loads(result)
    options = value if isinstance(value, list) else [value]
    addresses = [v for v in options if ipaddress.ip_address(v).is_private]
    return addresses[0] if len(addresses) == 1 else None


def assert_absent_route(prefix):
    if ps("@((Get-NetRoute -DestinationPrefix '" + prefix +
          "' -ErrorAction SilentlyContinue)).Count") != '0':
        raise RuntimeError('PREEXISTING_PROBE_ROUTE_REFUSED')


def add_route(prefix, index):
    ps("New-NetRoute -DestinationPrefix '" + prefix + "' -InterfaceIndex " +
       str(index) +
       " -NextHop '0.0.0.0' -PolicyStore ActiveStore -RouteMetric 5 | Out-Null")


def remove_route(prefix, index):
    ps("Remove-NetRoute -DestinationPrefix '" + prefix +
       "' -InterfaceIndex " + str(index) +
       " -NextHop '0.0.0.0' -PolicyStore ActiveStore -Confirm:$false")


def echo_ipv4(*options):
    r = subprocess.run([
        'curl.exe', '--ipv4', '--noproxy', '*', '--fail', '--silent',
        '--show-error', '--connect-timeout', '8', '--max-time', '22',
        *options, 'https://' + PROBE_HOST],
        text=True, capture_output=True, timeout=27)
    if r.returncode:
        raise RuntimeError('HTTPS_EGRESS_PROBE_FAILED')
    try:
        return str(ipaddress.IPv4Address(r.stdout.strip()))
    except ipaddress.AddressValueError as exc:
        raise RuntimeError('HTTPS_EGRESS_IPV4_INVALID') from exc


def run(args):
    root, receipt, binary = qa_guard(args)
    provider, helper = provider_modules()
    if (provider.EXPECTED_CA != CA_PIN or provider.EXPECTED_CN != PEER_CN
            or provider.ENDPOINT != HOST):
        raise RuntimeError('OFFICIAL_PEER_TRUST_CHANGED')
    official, profile_sha = provider.official_profile()
    password, updated = provider.official_login()
    if not re.fullmatch(r'[A-Za-z0-9]{4,32}', password):
        raise RuntimeError('PUBLIC_LOGIN_INVALID')
    pem = {tag: helper.extract_unique_pem(official, tag)
           for tag in ('ca', 'cert', 'key')}
    ca = write_private(root, 'provider-ca.pem', pem['ca'] + '\n')
    cert = write_private(root, 'provider-client.pem', pem['cert'] + '\n')
    key = write_private(root, 'provider-client.key', pem['key'] + '\n')
    auth = write_private(root, 'provider-public-login.txt',
                         'vpnbook\n' + password + '\n')
    password = ''
    log = root / 'private-openvpn-tun.log'
    config = write_private(root, 'dco-test.ovpn', '\n'.join([
        'client', 'dev tun', 'dev-node ' + args.adapter, 'proto tcp-client',
        'remote ' + HOST + ' 443', 'nobind', 'resolv-retry 1',
        'remote-cert-tls server',
        'verify-x509-name ' + PEER_CN + ' name',
        'ca ' + str(ca), 'cert ' + str(cert), 'key ' + str(key),
        'auth-user-pass ' + str(auth), 'auth-nocache',
        'data-ciphers AES-256-GCM:AES-128-GCM',
        'route-nopull', 'route-noexec',
        'pull-filter ignore redirect-gateway',
        'pull-filter ignore dhcp-option',
        'pull-filter ignore route-ipv6',
        'auth-retry none', 'connect-retry-max 1',
        'verb 4', 'log ' + str(log), ''
    ]))
    report = {
        'schema': 'oig-hosted-windows-community-dco-scoped-dataplane-v1',
        'sourceSha': os.environ['GITHUB_SHA'],
        'caSha256': CA_PIN,
        'officialProfileSha256': profile_sha,
        'publicCredentialUpdated': updated,
        'connectionScope': 'owned-ovpn-dco-adapter-with-one-temporary-/32-probe-route',
        'defaultRoutesUnchanged': False, 'hostDnsUnchanged': False,
        'tunnelIpAssigned': False, 'peerIdentityVerified': False,
        'sourceBoundHttpsOverVpn': False, 'routeRemoved': False,
        'vpnProcessStopped': False, 'productionEngineChanged': False,
        'fullDeviceOrKillSwitchProven': False, 'pass': False
    }
    route, process, index = None, None, None
    failure = ''
    prior = host_snapshot()
    try:
        direct = echo_ipv4()
        process = subprocess.Popen(
            [str(binary), '--config', str(config)],
            cwd=str(root), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        deadline = time.monotonic() + 65
        while time.monotonic() < deadline:
            output = log.read_text(errors='replace')[-180000:] if log.exists() else ''
            if ('Initialization Sequence Completed' in output and
                    'VERIFY X509NAME OK: CN=' + PEER_CN in output):
                report['peerIdentityVerified'] = True
                break
            if process.poll() is not None:
                raise RuntimeError('OPENVPN_TUN_PROCESS_EXITED_EARLY')
            time.sleep(0.4)
        if not report['peerIdentityVerified']:
            raise RuntimeError('OPENVPN_TUN_SESSION_NOT_INITIALIZED')
        adapter = json.loads(ps(
            "Get-NetAdapter -Name '" + args.adapter + "' -ErrorAction Stop | "
            "Select-Object Name,Status,ifIndex,InterfaceDescription | "
            "ConvertTo-Json -Compress"))
        if ('OpenVPN' not in adapter['InterfaceDescription'] and
                'Data Channel Offload' not in adapter['InterfaceDescription']):
            raise RuntimeError('DCO_ADAPTER_NOT_IN_USE')
        index = int(adapter['ifIndex'])
        vpn_ip = interface_ip(args.adapter)
        if not vpn_ip:
            raise RuntimeError('DCO_ADAPTER_IPV4_NOT_ASSIGNED')
        report['tunnelIpAssigned'] = True
        during = host_snapshot()
        if prior['routes'] != during['routes'] or prior['dns'] != during['dns']:
            raise RuntimeError('SERVER_PUSH_CHANGED_HOST_DEFAULT_OR_DNS')
        target = str(ipaddress.IPv4Address(socket.gethostbyname(PROBE_HOST)))
        assert_absent_route(target + '/32')
        route = target + '/32'
        add_route(route, index)
        count = ps("@(Get-NetRoute -DestinationPrefix '" + route +
                   "' -ErrorAction Stop | Where-Object {$_.InterfaceIndex -eq " +
                   str(index) + "}).Count")
        if count != '1':
            raise RuntimeError('SCOPED_PROBE_ROUTE_NOT_ON_DCO')
        tunneled = echo_ipv4('--interface', vpn_ip, '--resolve',
                             PROBE_HOST + ':443:' + target)
        if tunneled == direct:
            raise RuntimeError('SOURCE_BOUND_EGRESS_NOT_DISTINCT')
        report['sourceBoundHttpsOverVpn'] = True
    except Exception as exc:
        failure = type(exc).__name__ + ':' + str(exc)[:120]
    finally:
        if route and index is not None:
            try:
                remove_route(route, index)
                report['routeRemoved'] = True
            except Exception as exc:
                failure += ';ROUTE_CLEANUP_' + type(exc).__name__
        else:
            report['routeRemoved'] = True
        if process:
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=4)
                report['vpnProcessStopped'] = process.poll() is not None
            except Exception as exc:
                failure += ';OPENVPN_CLEANUP_' + type(exc).__name__
        try:
            after = host_snapshot()
            report['defaultRoutesUnchanged'] = prior['routes'] == after['routes']
            report['hostDnsUnchanged'] = prior['dns'] == after['dns']
        except Exception as exc:
            failure += ';NETWORK_RECHECK_' + type(exc).__name__
        report['pass'] = (
            all(report[k] for k in (
                'peerIdentityVerified', 'tunnelIpAssigned',
                'sourceBoundHttpsOverVpn', 'routeRemoved', 'vpnProcessStopped',
                'defaultRoutesUnchanged', 'hostDnsUnchanged')) and not failure)
        report['failure'] = failure[:260]
        with receipt.open('x', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
            f.write('\n')
    if not report['pass']:
        raise RuntimeError('SCOPED_DCO_DATAPLANE_NOT_VERIFIED_' + failure[:150])
    print('PASS_HOSTED_DCO_TUNNEL_SOURCE_BOUND_HTTPS_AND_CLEANUP')


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('--root', required=True)
        parser.add_argument('--openvpn', required=True)
        parser.add_argument('--adapter', required=True)
        parser.add_argument('--receipt', required=True)
        values = parser.parse_args()
        qa_guard(values)
        run(values)
    except Exception as exc:
        sys.stderr.write('FAIL_HOSTED_DCO_TUNNEL_' +
                         type(exc).__name__ + '_' + str(exc)[:180] + '\n')
        sys.exit(1)
