"""Offline end-to-end status regression for Linux owned full-route attribution.

All ip/nmcli/curl/getent/systemctl commands are local synthetic shims.
No real connections, routes, DNS, network probes, or credentials are used.
"""
import json
import os
import pathlib
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
    sys.exit(1)  # recovery timer is disabled in isolated test home
elif cmd=='nmcli':
    if args==['-t','-f','NAME,TYPE,DEVICE','connection','show','--active']:
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
elif cmd=='ip':
    if args==['-4','route','get','1.1.1.1'] or args==['-4','route','get','208.67.222.222']:
        target=args[3]
        iface='tun1' if scenario=='upper_effective_foreign' and target=='208.67.222.222' else 'tun0'
        print(target+' dev '+iface+' src '+source+' uid 1000')
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


def verify_case(name, expect_connected):
    with tempfile.TemporaryDirectory(prefix="oig-owned-tunnel-status-") as d:
        root = pathlib.Path(d)
        stubs = root / "bin"
        stubs.mkdir()
        shim = stubs / "ip"
        shim.write_text(FAKE)
        shim.chmod(0o700)
        for tool in ("nmcli", "curl", "getent", "systemctl"):
            (stubs / tool).symlink_to(shim)
        state = root / "home" / "state"
        state.mkdir(parents=True)
        (state / "desired-state").write_text("off\n")
        env = {**os.environ, "PATH": str(stubs) + os.pathsep + os.environ["PATH"],
               "OIG_HOME": str(root / "home"),
               "OIG_COMMON": str(root / "home" / "common"),
               "OIG_ROUTE_FIXTURE": name,
               "PYTHONDONTWRITEBYTECODE": "1"}
        done = subprocess.run(["/bin/bash", str(SOURCE), "status"], env=env,
                              capture_output=True, text=True, timeout=8)
        assert done.returncode == 0, (name, done.stderr, done.stdout)
        status = json.loads(done.stdout)
        assert status["desiredState"] == "off", (name, status)
        assert status["managedTunnelActive"] == (name != "foreign_tun"), (name,status)
        assert status["fullRoutes"] == (2 if expect_connected or name in ("foreign_ipv6","foreign_ipv6_upper","ipv6_probe_error") else 0), (name,status)
        assert status["connected"] == expect_connected, (name,status)
        assert status["ipv6LeakRisk"] == (name in ("foreign_ipv6","foreign_ipv6_upper","ipv6_probe_error")), (name,status)
        assert (state / "desired-state").read_text() == "off\n"
        assert not (state / "benchmark-upload.bin").exists()


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
        ("ipv6_probe_error", False),
    ):
        verify_case(case, accepted)
    print("PASS: only managed VPN source with owned full IPv4 routes can claim tunnel health (13 offline cases)")
