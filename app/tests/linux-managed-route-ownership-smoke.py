"""Offline end-to-end status regression for Linux owned full-route attribution.

All ip/nmcli/curl/getent/systemctl commands are local synthetic shims.
No real connections, routes, DNS, network probes, or credentials are used.
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "backend/linux/oig-linux.sh"

FAKE = r'''#!/usr/bin/env python3
import os,sys
from pathlib import Path
cmd=Path(sys.argv[0]).name
args=sys.argv[1:]
scenario=os.environ['OIG_ROUTE_FIXTURE']
managed=scenario!='foreign_tun'
source='10.7.0.2'
wrong_source=scenario in ('wrong_source','no_nm_ip')
missing_addr=scenario=='no_kernel_address'

if cmd=='curl':
    print('ip=198.51.100.25\nloc=US\ncolo=TEST')
elif cmd=='getent':
    print('8.8.8.8 STREAM dns.google')
elif cmd=='systemctl':
    recovery=os.environ.get('OIG_RECOVERY_FIXTURE','disabled')
    unit='openinternetgateway-recovery.service'
    timer='openinternetgateway-recovery.timer'
    if args==['--user','is-enabled',timer]:
        if recovery=='disabled': sys.exit(1)
        print('enabled')
    elif args==['--user','show','-P','Environment',unit]:
        if recovery=='missing_service': sys.exit(1)
        if recovery=='foreign':
            print('OIG_HOME=/tmp/foreign OIG_COMMON=/tmp/foreign/common')
        elif recovery=='missing_env':
            print('OIG_COMMON='+os.environ['OIG_COMMON'])
        else:
            print('OIG_HOME='+os.environ['OIG_HOME']+' OIG_COMMON='+os.environ['OIG_COMMON'])
    elif args==['--user','show','-P','ExecStart',unit]:
        root=('/tmp/foreign' if recovery=='wrong_exec' else os.environ['OIG_HOME'])
        print('{ path=/bin/bash ; argv[]=/bin/bash '+root+'/linux/oig-linux.sh ensure ; ignore_errors=no }')
    elif args==['--user','is-active',timer]:
        print('active')
    else:
        raise RuntimeError('Unexpected systemctl argv: '+repr(args))
elif cmd=='nmcli':
    if args==['-t','-f','NAME,TYPE','connection','show','--active']:
        print('Home Ethernet:802-3-ethernet')
        print('IPbaz:vpn')
        if managed:print('OIG-VPN-LIVE:vpn')
    elif len(args)==5 and args[0]=='-g' and args[2:]==['connection','show','OIG-VPN-LIVE']:
        field=args[1]
        if field=='ipv4.dns': print('8.8.8.8' if scenario=='dns_profile_wrong' else '1.1.1.1')
        elif field=='ipv4.dns-search':print('example.com' if scenario=='dns_domain_wrong' else '~.')
        elif field=='ipv4.dns-priority':print('-100' if scenario=='dns_priority_wrong' else '-2147483647')
        elif field=='ipv4.ignore-auto-dns':print('no' if scenario=='dns_auto_enabled' else 'yes')
        elif field=='ipv6.ignore-auto-dns':print('yes')
        elif field=='ipv6.method':print('disabled')
        else:sys.exit(4)
    elif args==['-t','-f','NAME,TYPE,DEVICE','connection','show','--active']:
        print('Home Ethernet:802-3-ethernet:enp1s0')
        print('IPbaz:vpn:enp1s0')
        if managed:
            # Underlying device is Ethernet even though VPN owns tun0.
            print('OIG-VPN-LIVE:vpn:enp1s0')
    elif args==['-g','IP4.ADDRESS','connection','show','--active','OIG-VPN-LIVE']:
        if not managed:
            sys.exit(10)
        if not (scenario=='no_nm_ip'):
            print(('10.7.0.99' if wrong_source else source)+'/24')
    else:
        raise RuntimeError('Unexpected nmcli argv: '+repr(args))
elif cmd=='resolvectl':
    if scenario=='dns_resolvectl_missing':
        sys.exit(1)
    if args==['dns','tun0']:
        print('Link 9 (tun0): '+('8.8.8.8' if scenario=='dns_active_server_wrong' else '1.1.1.1'))
    elif args==['domain','tun0']:
        print('Link 9 (tun0): '+('' if scenario=='dns_link_domain_missing' else '~.'))
    elif args==['dns']:
        print('Global: '+('9.9.9.9' if scenario=='dns_global_fallback' else ''))
        print('Link 9 (tun0): '+('8.8.8.8' if scenario=='dns_active_server_wrong' else '1.1.1.1'))
        print('Link 5 (enp1s0): '+('9.9.9.9' if scenario=='dns_physical_fallback' else ''))
    else:
        raise RuntimeError('Unexpected resolvectl argv: '+repr(args))
elif cmd=='ip':
    if args==['-4','route','get','1.1.1.1'] or args==['-4','route','get','208.67.222.222']:
        target=args[3]
        iface='tun1' if scenario=='upper_effective_foreign' and target=='208.67.222.222' else 'tun0'
        print(target+' dev '+iface+' src '+source+' uid 1000')
    elif args==['-6','route','show','table','all']:
        if scenario=='ipv6_inventory_error':
            sys.stderr.write('Cannot enumerate policy tables\\n')
            sys.exit(2)
        print('local ::1 dev lo table local')
        print('fe80::/64 dev enp1s0 proto kernel')
        if scenario=='foreign_ipv6_specific':
            print('2001:db8:321::/48 dev enp1s0 table 123')
        elif scenario=='owned_ipv6_specific':
            print('2001:db8:321::/48 dev tun0 table 123')
        elif scenario=='ipv6_inventory_malformed':
            print('unrecognized-route-prefix dev enp1s0')
    elif args[:3]==['-6','route','get']:
        target=args[3]
        if scenario=='foreign_ipv6' or (scenario=='foreign_ipv6_upper' and target=='2001:4860:4860::8888'):
            print(target+' via fe80::1 dev enp1s0 src 2001:db8::2')
        elif scenario=='owned_ipv6':
            print(target+' dev tun0 src 2001:db8:5::2')
        elif scenario=='ipv6_probe_error':
            sys.stderr.write('RTNETLINK answers: Operation not permitted\n')
            sys.exit(1)
        else:
            sys.stderr.write('RTNETLINK answers: Network is unreachable\n')
            sys.exit(2)
    elif args==['-4','route','show','table','main']:
        if scenario=='owned_default':
            print('default dev tun0 metric 50')
        else:
            print('default via 192.168.20.1 dev enp1s0 metric 500')
            print('0.0.0.0/1 dev tun0 metric 50')
            if scenario!='only_lower':
                print('128.0.0.0/1 dev '+('tun1' if scenario=='upper_table_foreign' else 'tun0')+' metric 50')
    elif args==['-4','-o','addr','show','dev','tun0']:
        if not missing_addr:
            print('16: tun0 inet '+source+'/24 scope global tun0')
    else:
        raise RuntimeError('Unexpected ip argv: '+repr(args))
else:
    raise RuntimeError('Unexpected executable: '+cmd)
'''


def verify_case(name, expect_connected, recovery='disabled'):
    with tempfile.TemporaryDirectory(prefix="oig-owned-tunnel-status-") as d:
        root = pathlib.Path(d)
        stubs = root / "bin"
        stubs.mkdir()
        shim = stubs / "ip"
        shim.write_text(FAKE)
        shim.chmod(0o700)
        for tool in ("nmcli", "curl", "getent", "systemctl", "resolvectl"):
            (stubs / tool).symlink_to(shim)
        state = root / "home" / "state"
        state.mkdir(parents=True)
        guard_dir = root / "home" / "linux"
        guard_dir.mkdir(parents=True)
        for module in ("ipv6_route_guard.py", "dns_route_guard.py"):
            shutil.copyfile(SOURCE.parent / module, guard_dir / module)
        (state / "desired-state").write_text("off\n")
        env = {**os.environ, "PATH": str(stubs) + os.pathsep + os.environ["PATH"],
               "OIG_HOME": str(root / "home"),
               "OIG_COMMON": str(root / "home" / "common"),
               "OIG_ROUTE_FIXTURE": name,
               "OIG_RECOVERY_FIXTURE": recovery,
               "PYTHONDONTWRITEBYTECODE": "1"}
        done = subprocess.run(["/bin/bash", str(SOURCE), "status"], env=env,
                              capture_output=True, text=True, timeout=8)
        assert done.returncode == 0, (name, done.stderr, done.stdout)
        status = json.loads(done.stdout)
        assert status["desiredState"] == "off", (name, status)
        assert status["autoRecovery"] is (recovery == 'owned'), (name, recovery, status)
        expected_state = 'Missing' if recovery == 'disabled' else ('active' if recovery == 'owned' else 'Unverified')
        assert status["autoRecoveryState"] == expected_state, (name, recovery, status)
        assert status["managedTunnelActive"] == (name != "foreign_tun"), (name,status)
        assert status["fullRoutes"] == (2 if expect_connected or name in ("foreign_ipv6","foreign_ipv6_upper","foreign_ipv6_specific","ipv6_probe_error","ipv6_inventory_error","ipv6_inventory_malformed",
            "dns_profile_wrong","dns_domain_wrong","dns_priority_wrong",
            "dns_auto_enabled","dns_resolvectl_missing",
            "dns_active_server_wrong","dns_link_domain_missing",
            "dns_global_fallback","dns_physical_fallback") else 0), (name,status)
        assert status["connected"] == expect_connected, (name,status)
        policy_bad = name in {
            "dns_profile_wrong", "dns_domain_wrong", "dns_priority_wrong",
            "dns_auto_enabled", "dns_resolvectl_missing",
            "dns_active_server_wrong", "dns_link_domain_missing",
            "dns_global_fallback", "dns_physical_fallback"
        }
        assert status["dnsRoutingVerified"] == (name != "foreign_tun"
            and not policy_bad and status["fullRoutes"] == 2), (name,status)
        assert status["ipv6LeakRisk"] == (name in ("foreign_ipv6","foreign_ipv6_upper","foreign_ipv6_specific","ipv6_probe_error","ipv6_inventory_error","ipv6_inventory_malformed")), (name,status)
        assert (state / "desired-state").read_text() == "off\n"
        assert not (state / "benchmark-upload.bin").exists()
        if name == "foreign_tun":
            # A user-requested Connect cannot touch the independent IPbaz
            # VPN. It must refuse before the factory, watchdog, or import.
            refused = subprocess.run(['/bin/bash', str(SOURCE), 'connect'],
                env=env, capture_output=True, text=True, timeout=8)
            assert refused.returncode == 24, (refused.stdout,refused.stderr)
            assert 'independent VPN/tunnel' in refused.stderr
            assert not (state / 'watchdog.pid').exists()
            assert not (root / 'home' / 'common').exists()


if __name__ == "__main__":
    for case, accepted in (
        ("owned_def1", True),
        ("owned_default", True),
        ("foreign_tun", False),
        ("wrong_source", False),
        ("no_nm_ip", False),
        ("no_kernel_address", False),
        ("only_lower", False),
        ("upper_table_foreign", False),
        ("upper_effective_foreign", False),
        ("foreign_ipv6", False),
        ("foreign_ipv6_upper", False),
        ("owned_ipv6", True),
        ("owned_ipv6_specific", True),
        ("foreign_ipv6_specific", False),
        ("ipv6_inventory_error", False),
        ("ipv6_inventory_malformed", False),
        ("ipv6_probe_error", False),
        ("dns_profile_wrong", False),
        ("dns_domain_wrong", False),
        ("dns_priority_wrong", False),
        ("dns_auto_enabled", False),
        ("dns_resolvectl_missing", False),
        ("dns_active_server_wrong", False),
        ("dns_link_domain_missing", False),
        ("dns_global_fallback", False),
        ("dns_physical_fallback", False),
    ):
        verify_case(case, accepted)
    for recovery in ('owned','foreign','wrong_exec','missing_env','missing_service'):
        verify_case('foreign_tun', False, recovery)
    print("PASS: only managed VPN source with owned full IPv4 routes can claim tunnel health (26 offline cases), plus 5 systemd recovery-ownership cases")
