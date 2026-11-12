#!/usr/bin/env python3
"""One-shot GitHub-hosted, disposable Linux OpenVPN data-plane QA.

NEVER run this on an owner device. Root-mode requires GitHub-hosted runner
identity, and confines the real TUN/route mutations to an ephemeral netns.
The receipt has no password, private key, raw profile or OpenVPN log.
"""
import argparse
import datetime as dt
import hashlib
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.request

SOURCE = 'https://www.vpnbook.com/freevpn/openvpn'
PROFILE_URL = 'https://www.vpnbook.com/api/openvpn?hostname=uk205.vpnbook.com&protocol=tcp443'
ENDPOINT = 'uk205.vpnbook.com'
EXPECTED_CA = 'c0c7c3663bd229bce127647dece873d37e022a5d283a35b162bb125ac70bb9ff'
EXPECTED_CN = 'server.vpnbook.com'
PREFIX = '10.243.254.0/30'
HOST_IP = '10.243.254.1/30'
GUEST_IP = '10.243.254.2/30'

def https_get(url, limit=160000):
    request = urllib.request.Request(url, headers={'User-Agent': 'OIG-GitHub-Hosted-Linux-Provider-QA/1.0'})
    with urllib.request.urlopen(request, timeout=12, context=ssl.create_default_context()) as r:
        if r.status != 200 or r.url != url:
            raise RuntimeError('Unexpected URL, redirect or non-200 official HTTPS response')
        data = r.read(limit + 1)
        if not data or len(data) > limit:
            raise RuntimeError('Official HTTPS data missing or too large')
        return data

def official_login():
    page = https_get(SOURCE, 600000).decode('utf8', 'strict')
    page = re.sub(r'<script\b[^>]*>[\s\S]*?</script>', ' ', page, flags=re.I)
    page = re.sub(r'<style\b[^>]*>[\s\S]*?</style>', ' ', page, flags=re.I)
    page = html.unescape(re.sub(r'<[^>]+>', ' ', page))
    page = re.sub(r'\s+', ' ', page)
    section = re.search(r'VPN Credentials\b(.{0,1000})', page, re.I)
    if not section:
        raise RuntimeError('Public credential section not found')
    found = re.findall(
        r'Username\s+vpnbook\s+Copy\s+Password\s+([A-Za-z0-9]{4,32})'
        r'\s+Copy\s+Last updated:\s+([A-Za-z]{3}\s+\d{1,2},\s+\d{4})',
        section.group(1), flags=re.I)
    if len(found) != 1:
        raise RuntimeError('Public credential ambiguous or missing')
    password, updated = found[0]
    date = dt.datetime.strptime(updated, '%b %d, %Y').replace(tzinfo=dt.timezone.utc)
    age = dt.datetime.now(dt.timezone.utc) - date
    if age.total_seconds() < -86400 or age.total_seconds() > 21 * 86400:
        raise RuntimeError('Public shared credential date outside freshness policy')
    return password, date.date().isoformat()

def official_profile():
    raw = https_get(PROFILE_URL, 100000)
    s = raw.decode('utf8', 'strict')
    remotes = re.findall(r'(?m)^\s*remote\s+(\S+)\s+(\d+)\s*$', s)
    if remotes != [(ENDPOINT, '443')] or not re.search(r'(?mi)^\s*proto\s+tcp\s*$', s):
        raise RuntimeError('Official config target or transport changed')
    if not re.search(r'(?mi)^\s*dev\s+tun1\s*$', s):
        raise RuntimeError('Official config TUN device changed')
    if not re.search(r'(?mi)^\s*auth-user-pass\s*$', s):
        raise RuntimeError('Unexpected external credential file in official profile')
    if not re.search(r'(?mi)^\s*client\s*$', s):
        raise RuntimeError('Official profile is not client configuration')
    for tag in ('ca', 'cert', 'key'):
        if len(re.findall(r'(?mi)^<' + tag + r'>', s)) != 1:
            raise RuntimeError('Missing or ambiguous inline profile certificate')
    ca = re.search(r'<ca>\s*(-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----)\s*</ca>', s)
    if not ca:
        raise RuntimeError('Official inline CA unavailable')
    ca_hash = hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca.group(1))).hexdigest()
    if ca_hash != EXPECTED_CA:
        raise RuntimeError('Official provider CA no longer matches preaccepted trust pin')
    # The official payload must never supply executable hooks or management sockets.
    if re.search(r'(?mi)^\s*(?:script-security|plugin|up|down|route-up|ipchange|'
                 r'client-connect|client-disconnect|learn-address|tls-verify|'
                 r'management|daemon|log|status|cd|chroot|remote-random)\b', s):
        raise RuntimeError('Unexpected active directive in official provider profile')
    if re.search(r'(?mi)^\s*(?:verify-x509-name|remote-cert-tls)\b', s):
        raise RuntimeError('Unexpected pre-existing trust override in official profile')
    hardened = s.rstrip() + '\nremote-cert-tls server\n' \
        + 'verify-x509-name ' + EXPECTED_CN + ' name\n' \
        + 'auth-nocache\nverb 3\n'
    return hardened, hashlib.sha256(raw).hexdigest()

def sh(args, timeout=12, check=True):
    p = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError('Command failed safely: ' + args[0] + ' ' + (args[1] if len(args) > 1 else ''))
    return p.stdout.strip()

def get_host_snapshot():
    return {
        'routes': sh(['ip','-4','route','show'], check=False),
        'ipv6_routes': sh(['ip','-6','route','show'], check=False),
        'iptables': sh(['iptables-save'], check=False),
        'ip_forward': Path('/proc/sys/net/ipv4/ip_forward').read_text().strip(),
        'resolv_sha256': hashlib.sha256(Path('/etc/resolv.conf').read_bytes()).hexdigest()
    }

def canonical_effective_iptables(text):
    """Ignore only newly materialized, empty ACCEPT-only builtin tables.

    iptables-nft may retain an empty table after the last temporary rule is
    deleted. Nonempty rules, custom chains and non-ACCEPT policies MUST still
    match byte-for-byte after comment removal; no global flush is allowed.
    """
    defaults = {
        'filter': {'INPUT', 'OUTPUT', 'FORWARD'},
        'nat': {'PREROUTING', 'INPUT', 'OUTPUT', 'POSTROUTING'},
        'mangle': {'PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING'},
        'raw': {'PREROUTING', 'OUTPUT'},
        'security': {'INPUT', 'OUTPUT', 'FORWARD'},
    }
    tables = {}
    table = None
    contents = []
    def process(name, rows):
        if not rows:
            return
        has_rule = any(not x.startswith(':') for x in rows)
        benign_chains = all(
            re.fullmatch(r':([A-Za-z0-9_-]+) ACCEPT \[0:0\]', x)
            and x.split()[0][1:] in defaults.get(name, set())
            for x in rows
        )
        if not has_rule and benign_chains:
            return
        tables[name] = tuple(rows)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('*'):
            if table is not None:
                raise RuntimeError('Malformed firewall snapshot: nested table')
            table = line[1:]
            contents = []
        elif line == 'COMMIT':
            if table is None:
                raise RuntimeError('Malformed firewall snapshot: unexpected COMMIT')
            process(table, contents)
            table, contents = None, []
        elif table is not None:
            # Packet/byte counters are traffic state, not effective firewall rules.
            if line.startswith(':'):
                line = re.sub(r'\[\d+:\d+\]$', '[0:0]', line)
            contents.append(line)
        else:
            raise RuntimeError('Malformed firewall snapshot outside table')
    if table is not None:
        raise RuntimeError('Malformed firewall snapshot: unterminated table')
    return tables

def firewall_shape(tables):
    # Only chain names/policies, counts and digest; no rules or host IPs.
    return {
        name: {
            'chain_policies': [row.split()[0][1:] + ':' + row.split()[1]
                               for row in rows if row.startswith(':')],
            'rule_count': sum(row.startswith('-A ') for row in rows),
            'other_line_count': sum(not row.startswith(':') and
                                    not row.startswith('-A ') for row in rows),
            'effective_sha256': hashlib.sha256(
                ('\\n'.join(rows)).encode()).hexdigest(),
        }
        for name, rows in tables.items()
    }

def public_trace(ns, interface=None):
    cmd = ['ip','netns','exec',ns,'curl','-4','--noproxy','*','-fsS',
           '--connect-timeout','6','--max-time','18']
    if interface:
        cmd += ['--interface',interface]
    trace = sh(cmd + ['https://www.cloudflare.com/cdn-cgi/trace'], timeout=22)
    values = dict(line.split('=',1) for line in trace.splitlines() if '=' in line)
    ipaddress.IPv4Address(values['ip'])
    return {'ip': values['ip'], 'loc': values.get('loc','')}


def verify_dns_route_owned(route, resolver='1.1.1.1'):
    """Refuse a configured DNS resolver that can egress outside owned TUN."""
    address = ipaddress.ip_address(resolver)
    if address.version != 4 or not address.is_global:
        raise RuntimeError('Isolated DNS resolver must be a public IPv4 address')
    if not re.search(r'\bdev\s+tun1(?:\s|$)', route) or not re.search(r'\bsrc\s+\d+\.\d+\.\d+\.\d+(?:\s|$)', route):
        raise RuntimeError('Configured DNS resolver route is not owned by TUN')
    return True


def verify_ipv6_route_inventory(routes):
    """Reject every non-local IPv6 route not owned by the test TUN, including policy tables."""
    for line in routes.splitlines():
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0] in ('unreachable', 'prohibit', 'blackhole', 'throw'):
            continue
        destination = tokens[1] if tokens[0] in ('local', 'anycast', 'multicast') and len(tokens) > 1 else tokens[0]
        try:
            prefix = ipaddress.ip_network('::/0' if destination == 'default' else destination, strict=False)
        except ValueError as exc:
            raise RuntimeError('IPv6 route inventory has an unrecognized prefix') from exc
        if prefix.version != 6:
            raise RuntimeError('Non-IPv6 entry in IPv6 routing inventory')
        if prefix.is_link_local or prefix.is_multicast or prefix.is_loopback:
            continue
        match = re.search(r'\bdev\s+([A-Za-z0-9_.:-]+)(?:\s|$)', line)
        if not match or match.group(1) != 'tun1':
            raise RuntimeError('Foreign global or private IPv6 route remains outside TUN')
    return True


def offline_leak_guard_regression():
    safe = 'local ::1 dev lo table local\nfe80::/64 dev guest0 proto kernel\nff00::/8 dev guest0\nunreachable default dev lo\n'
    assert verify_ipv6_route_inventory(safe)
    assert verify_ipv6_route_inventory(safe + '2001:4860:1::/48 dev tun1\n')
    assert verify_dns_route_owned('1.1.1.1 dev tun1 src 10.8.0.2 uid 1000')
    dangerous = (
        'default via fe80::1 dev guest0',
        '2001:4860:4860::/48 dev guest0 table 123',
        'fc00::/7 dev guest0',
        'local 2001:4860::2 dev lo table local',
        'unknown-token-prefix dev guest0',
    )
    for route in dangerous:
        try:
            verify_ipv6_route_inventory(safe + route + '\n')
        except RuntimeError:
            pass
        else:
            raise RuntimeError('Fail-closed IPv6 leak guard accepted foreign route')
    for route, resolver in (
        ('1.1.1.1 via 10.243.254.1 dev guest0 src 10.243.254.2', '1.1.1.1'),
        ('1.1.1.1 dev tun1 src 10.8.0.2', '127.0.0.53'),
        ('1.1.1.1 dev tun1', '1.1.1.1'),
    ):
        try:
            verify_dns_route_owned(route, resolver)
        except RuntimeError:
            pass
        else:
            raise RuntimeError('Fail-closed DNS leak guard accepted bypass or ambiguous source')
    print('HOSTED_LINUX_OFFLINE_DNS_IPV6_ROUTE_LEAK_NEGATIVE_PASS')


class Trial:
    def __init__(self, scratch, receipt):
        suffix = str(os.getpid() % 100000)
        self.ns = 'oig-ci-' + suffix
        self.host_link = 'oigch' + suffix
        self.guest_link = 'oigcn' + suffix
        self.scratch = scratch
        self.receipt = receipt
        self.proc = None
        self.ns_created = False
        self.host_link_created = False
        self.changed_forward = False
        self.forward_before = ''
        self.firewall_undo = []
    def ns_run(self, *args, timeout=12):
        return sh(['ip','netns','exec',self.ns,*args], timeout=timeout)
    def create(self):
        if sh(['ip','route','show',PREFIX],check=False):
            raise RuntimeError('Existing host route conflicts with isolated trial prefix')
        default = sh(['ip','-4','route','show','default'])
        m = re.search(r'\bdev\s+([A-Za-z0-9_.:-]+)', default)
        if not m:
            raise RuntimeError('No explicit physical runner default-route interface')
        outbound = m.group(1)
        sh(['ip','netns','add',self.ns])
        self.ns_created = True
        sh(['ip','link','add',self.host_link,'type','veth','peer','name',self.guest_link])
        self.host_link_created = True
        sh(['ip','link','set',self.guest_link,'netns',self.ns])
        sh(['ip','addr','add',HOST_IP,'dev',self.host_link])
        sh(['ip','link','set',self.host_link,'up'])
        self.ns_run('ip','link','set','lo','up')
        self.ns_run('ip','addr','add',GUEST_IP,'dev',self.guest_link)
        self.ns_run('ip','link','set',self.guest_link,'up')
        self.ns_run('ip','route','add','default','via','10.243.254.1')
        self.forward_before = Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()
        if self.forward_before != '1':
            Path('/proc/sys/net/ipv4/ip_forward').write_text('1\n')
            self.changed_forward = True
        rules = [
            (['iptables','-I','FORWARD','1','-i',self.host_link,'-o',outbound,'-j','ACCEPT'],
             ['iptables','-D','FORWARD','-i',self.host_link,'-o',outbound,'-j','ACCEPT']),
            (['iptables','-I','FORWARD','1','-i',outbound,'-o',self.host_link,
              '-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT'],
             ['iptables','-D','FORWARD','-i',outbound,'-o',self.host_link,
              '-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT']),
            (['iptables','-t','nat','-I','POSTROUTING','1','-s',PREFIX,'-o',outbound,
              '-j','MASQUERADE'],
             ['iptables','-t','nat','-D','POSTROUTING','-s',PREFIX,'-o',outbound,
              '-j','MASQUERADE'])
        ]
        for insert, remove in rules:
            sh(insert)
            self.firewall_undo.append(remove)
        # netns-local resolver file bind mount, never replaces the runner host DNS.
        nsdir = Path('/etc/netns') / self.ns
        nsdir.mkdir(parents=True, exist_ok=False)
        # Explicit public test resolver. This file is bind-mounted only into
        # ip netns exec; it never edits the owner/runner /etc/resolv.conf.
        # The real DNS path is verified through the connected TUN below.
        (nsdir/'resolv.conf').write_text('nameserver 1.1.1.1\n')
        # Pin DNS once via the runner host; OpenVPN still verifies the actual peer cert.
        addr = socket.getaddrinfo(ENDPOINT, 443, family=socket.AF_INET,
                                  type=socket.SOCK_STREAM)[0][4][0]
        (nsdir/'hosts').write_text(Path('/etc/hosts').read_text() + '\n' + addr + ' ' + ENDPOINT + '\n')
        self.receipt['namespace_created'] = True
        self.receipt['runner_interface'] = outbound
    def start_vpn(self, conf, auth):
        log = self.scratch / 'openvpn.log'
        args = ['ip','netns','exec',self.ns,'openvpn','--config',str(conf),
                '--auth-user-pass',str(auth),'--auth-nocache','--auth-retry','none',
                '--connect-timeout','10','--connect-retry-max','1','--resolv-retry','0',
                '--verb','3','--log',str(log)]
        self.proc = subprocess.Popen(args, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     start_new_session=True)
        deadline = time.monotonic() + 65
        while time.monotonic() < deadline:
            text = log.read_text(errors='replace') if log.exists() else ''
            if 'AUTH_FAILED' in text or 'VERIFY ERROR' in text or 'TLS Error:' in text:
                raise RuntimeError('Provider rejected credentials, trust or TLS')
            if 'Initialization Sequence Completed' in text:
                checks = {
                    'trusted_ca': 'VERIFY OK: depth=1, CN=vpnbook.com' in text,
                    'trusted_server_certificate': 'VERIFY OK: depth=0, CN=server.vpnbook.com' in text,
                    'exact_peer_cn': 'VERIFY X509NAME OK: CN=server.vpnbook.com' in text,
                    'public_user_authenticated': 'PUSH_REPLY' in text
                }
                self.receipt['trust_checks'] = checks
                if not all(checks.values()):
                    raise RuntimeError('Provider initialization occurred without all trust proofs')
                return
            if self.proc.poll() is not None:
                raise RuntimeError('OpenVPN exited before initialization')
            time.sleep(.3)
        raise RuntimeError('Timed out waiting for authenticated TUN initialization')
    def route_is_tunnel(self):
        a = self.ns_run('ip','-4','route','get','1.1.1.1')
        b = self.ns_run('ip','-4','route','get','8.8.8.8')
        return 'dev tun1' in a and 'dev tun1' in b
    def benchmark(self):
        ns = ['ip','netns','exec',self.ns]
        route = self.route_is_tunnel()
        self.receipt['route_tunnel_two_destinations'] = route
        if not route:
            raise RuntimeError('Two representative IPv4 destinations not routed via TUN')
        # A clean default alone is insufficient: a foreign specific route or
        # policy-routing table can leak IPv6 while both default probes pass.
        ipv6_routes = self.ns_run('ip','-6','route','show','table','all')
        self.receipt['ipv6_no_foreign_routes_all_tables'] = verify_ipv6_route_inventory(ipv6_routes)
        for address in ('2606:4700:4700::1111', '2001:4860:4860::8888'):
            check = subprocess.run(['ip','netns','exec',self.ns,'ip','-6','route','get',address],
                                   text=True,capture_output=True,timeout=8)
            if check.returncode != 0:
                if not re.search(r'Network is unreachable|No route to host',check.stderr):
                    raise RuntimeError('IPv6 route lookup failed without proved unreachable state')
            elif not re.search(r'\bdev\s+tun1(?:\s|$)',check.stdout) and not check.stdout.startswith(
                    ('unreachable ', 'prohibit ', 'blackhole ')):
                raise RuntimeError('IPv6 probe has foreign effective egress route')
        self.receipt['ipv6_representative_destinations_no_foreign_egress'] = True
        resolver = Path('/etc/netns') / self.ns / 'resolv.conf'
        contents = resolver.read_text(encoding='ascii')
        effective_resolver = self.ns_run('cat','/etc/resolv.conf')
        if contents.strip() != 'nameserver 1.1.1.1' or effective_resolver != contents.strip():
            raise RuntimeError('Isolated DNS resolver was unexpectedly replaced or not mounted')
        self.receipt['namespace_resolver_effective'] = True
        self.receipt['configured_dns_route_tunnel_owned'] = verify_dns_route_owned(
            self.ns_run('ip','-4','route','get','1.1.1.1'))
        exit_trace = public_trace(self.ns, 'tun1')
        self.receipt['vpn_egress'] = exit_trace
        if exit_trace['loc'] == 'IR':
            raise RuntimeError('VPN egress unexpectedly located in IR')
        # No @server override: dig reads the netns-owned /etc/resolv.conf.
        # A passing explicit @1.1.1.1 test alone would not validate normal
        # resolver behavior. Recheck its effective route after DNS execution.
        dns = self.ns_run('dig','+short','+time=4','+tries=1','dns.google','A',timeout=10)
        addresses = [x for x in dns.splitlines() if re.fullmatch(r'\d+\.\d+\.\d+\.\d+', x)]
        self.receipt['configured_dns_resolver_clean'] = (
            '8.8.8.8' in addresses and '10.10.34.35' not in addresses and
            verify_dns_route_owned(self.ns_run('ip','-4','route','get','1.1.1.1')))
        if not self.receipt['configured_dns_resolver_clean']:
            raise RuntimeError('Configured DNS resolver through tunnel not proven')
        # Keep trial traffic small; bind to TUN rather than using runner direct NIC.
        dl = sh(ns + ['curl','-4','--noproxy','*','-fsS','--interface','tun1',
                      '--connect-timeout','6','--max-time','30',
                      '--output','/dev/null','--write-out','%{size_download} %{time_total}',
                      'https://speed.cloudflare.com/__down?bytes=1000000'],timeout=35)
        dbytes,dsecs = map(float,dl.split())
        if dbytes < 900000 or dsecs <= 0:
            raise RuntimeError('VPN-bound download size/timing invalid')
        payload = self.scratch/'upload.bin'
        payload.write_bytes(os.urandom(262144))
        payload.chmod(0o600)
        ul = sh(ns + ['curl','-4','--noproxy','*','-fsS','--interface','tun1',
                      '--connect-timeout','6','--max-time','30',
                      '--data-binary','@'+str(payload),
                      '--output','/dev/null','--write-out','%{size_upload} %{time_total}',
                      'https://speed.cloudflare.com/__up'],timeout=35)
        ubytes,usecs = map(float,ul.split())
        if ubytes < 262144 or usecs <= 0:
            raise RuntimeError('VPN-bound upload size/timing invalid')
        self.receipt['download_mbps'] = round(dbytes * 8 / dsecs / 1000000, 2)
        self.receipt['upload_mbps'] = round(ubytes * 8 / usecs / 1000000, 2)
        self.receipt['throughput_path'] = 'tunnel-interface-bound'
        self.receipt['tunnel_route_verified_after_transfer'] = self.route_is_tunnel()
        if not self.receipt['tunnel_route_verified_after_transfer']:
            raise RuntimeError('TUN routes changed during throughput transfer')
        self.receipt['configured_dns_route_owned_after_transfer'] = verify_dns_route_owned(
            self.ns_run('ip','-4','route','get','1.1.1.1'))
        self.receipt['ipv6_no_foreign_routes_after_transfer'] = verify_ipv6_route_inventory(
            self.ns_run('ip','-6','route','show','table','all'))
        self.receipt['data_plane_pass'] = True
    def stop_vpn(self):
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:self.proc.wait(timeout=9)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=4)
                self.receipt['openvpn_forced_kill'] = True
        self.receipt['openvpn_exit_code'] = self.proc.returncode
        self.proc = None
    def cleanup(self):
        errors = []
        try:self.stop_vpn()
        except Exception as e:errors.append('openvpn stop: '+type(e).__name__)
        if self.ns_created:
            try:
                # Verify OpenVPN removed its own routes before deleting the netns.
                self.receipt['route_restored_in_namespace'] = not self.route_is_tunnel()
            except Exception:
                self.receipt['route_restored_in_namespace'] = False
        for undo in reversed(self.firewall_undo):
            try:sh(undo)
            except Exception as e:errors.append('firewall undo: '+type(e).__name__)
        if self.host_link_created:
            try:sh(['ip','link','del',self.host_link])
            except Exception as e:errors.append('veth cleanup: '+type(e).__name__)
        if self.ns_created:
            try:sh(['ip','netns','del',self.ns])
            except Exception as e:errors.append('netns cleanup: '+type(e).__name__)
        if self.changed_forward:
            try:Path('/proc/sys/net/ipv4/ip_forward').write_text(self.forward_before + '\n')
            except Exception as e:errors.append('forward restore: '+type(e).__name__)
        nsdir = Path('/etc/netns') / self.ns
        for part in ('resolv.conf','hosts'):
            try:(nsdir/part).unlink(missing_ok=True)
            except Exception as e:errors.append('netns resolver cleanup: '+type(e).__name__)
        try:nsdir.rmdir()
        except FileNotFoundError:pass
        except Exception as e:errors.append('netns dir cleanup: '+type(e).__name__)
        self.receipt['cleanup_errors'] = errors

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--offline-leak-guard-regression', action='store_true')
    parser.add_argument('--probe-official-source-only', action='store_true')
    parser.add_argument('--run-hosted-tunnel', action='store_true')
    args = parser.parse_args()
    if sum((args.offline_leak_guard_regression, args.probe_official_source_only,
            args.run_hosted_tunnel)) != 1:
        parser.error('Select exactly one mode')
    if args.offline_leak_guard_regression:
        offline_leak_guard_regression()
        return 0
    if args.run_hosted_tunnel and (os.geteuid() != 0 or
            os.getenv('GITHUB_ACTIONS') != 'true' or
            os.getenv('RUNNER_ENVIRONMENT') != 'github-hosted' or
            os.getenv('GITHUB_REPOSITORY') != 'GOD13emad/OpenInternetGateway'):
        raise SystemExit('REFUSED: owner host or non-disposable runner')
    conf, profile_sha = official_profile()
    password, credential_date = official_login()
    if args.probe_official_source_only:
        print(json.dumps({'source':'official HTTPS', 'target':ENDPOINT,'profile_sha256':profile_sha,
                          'ca_der_sha256':EXPECTED_CA,'credential_update':credential_date,
                          'credential_value_emitted':False,'tunnel_started':False}, sort_keys=True))
        return 0
    if not Path('/dev/net/tun').exists():
        raise SystemExit('NO_TUN_DEVICE_ON_HOSTED_RUNNER')
    temp = Path(os.environ['RUNNER_TEMP'])
    receipt_file = temp/'oig-linux-provider-dataplane.json'
    if receipt_file.exists():
        raise SystemExit('Receipt already exists; no blind rerun')
    rec = {'schema':'oig-hosted-linux-provider-v1','utc':dt.datetime.now(dt.timezone.utc).isoformat(),
           'scope':'disposable GitHub-hosted Linux TUN data-plane only; not owner physical Linux',
           'provider':ENDPOINT, 'ca_der_sha256':EXPECTED_CA,'server_cn':EXPECTED_CN,
           'profile_sha256':profile_sha,'public_credential_updated':credential_date,
           'server_identity_verified':False,'public_user_authenticated':False,
           'data_plane_pass':False,'host_runner_recovered':False}
    baseline = get_host_snapshot()
    with tempfile.TemporaryDirectory(prefix='oig-hosted-provider-',dir=temp) as path:
        scratch = Path(path)
        os.chmod(scratch,0o700)
        cfg = scratch/'vpnbook.ovpn'
        cfg.write_text(conf)
        cfg.chmod(0o600)
        auth = scratch/'auth.txt'
        with os.fdopen(os.open(auth,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'w') as file:
            file.write('vpnbook\n' + password + '\n')
        password = ''
        trial = Trial(scratch, rec)
        try:
            trial.create()
            rec['direct_ip_before_tunnel'] = public_trace(trial.ns)
            trial.start_vpn(cfg,auth)
            rec['server_identity_verified'] = True
            rec['public_user_authenticated'] = True
            trial.benchmark()
        except Exception as e:
            rec['failure_category'] = type(e).__name__
            rec['failure_message'] = str(e)[:300]
        finally:
            trial.cleanup()
    after = get_host_snapshot()
    rec['host_snapshot_surface_equal'] = {
        name: baseline[name] == after[name] for name in baseline
    }
    effective_before = canonical_effective_iptables(baseline['iptables'])
    effective_after = canonical_effective_iptables(after['iptables'])
    rec['firewall_effective_equivalent'] = effective_before == effective_after
    rec['firewall_before_shape'] = firewall_shape(effective_before)
    rec['firewall_after_shape'] = firewall_shape(effective_after)
    rec['host_runner_recovered'] = (
        all(same for name, same in rec['host_snapshot_surface_equal'].items()
            if name != 'iptables')
        and rec['firewall_effective_equivalent']
        and not rec.get('cleanup_errors')
    )
    rec['completed_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
    rec['pass'] = bool(rec['server_identity_verified'] and rec['public_user_authenticated'] and
                       rec['data_plane_pass'] and rec['tunnel_route_verified_after_transfer'] and
                       rec.get('configured_dns_route_tunnel_owned') and
                       rec.get('configured_dns_resolver_clean') and
                       rec.get('namespace_resolver_effective') and
                       rec.get('configured_dns_route_owned_after_transfer') and
                       rec.get('ipv6_no_foreign_routes_all_tables') and
                       rec.get('ipv6_representative_destinations_no_foreign_egress') and
                       rec.get('ipv6_no_foreign_routes_after_transfer') and
                       rec.get('route_restored_in_namespace') and rec['host_runner_recovered'] and
                       not rec.get('openvpn_forced_kill') and not rec.get('failure_message'))
    with os.fdopen(os.open(receipt_file,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'w') as file:
        json.dump(rec,file,indent=2,sort_keys=True)
        file.write('\n')
    # The receipt contains no credentials or key material; make it readable by
    # the unprivileged GitHub artifact-upload step without relaxing its mode.
    os.chown(receipt_file, temp.stat().st_uid, temp.stat().st_gid)
    print('HOSTED_PROVIDER_RECEIPT='+json.dumps(rec,sort_keys=True))
    return 0 if rec['pass'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
