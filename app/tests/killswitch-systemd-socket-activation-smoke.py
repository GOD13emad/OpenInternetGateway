#!/usr/bin/env python3
"""Real unprivileged systemd-socket-activate FD3 integration (NO root install).

Uses a private temporary AF_UNIX filesystem socket and a one-shot READ-ONLY
test wrapper. No systemd unit is enabled and no firewall, VPN or DNS changes
are made. A passing test is NOT evidence of a root production kill switch.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1] / "backend/linux"
ACTIVATE = "/usr/bin/systemd-socket-activate"
WRAPPER = r"""
import os,sys
sys.path.insert(0,sys.argv[2])
import killswitch_broker_service as service
import killswitch_lifecycle_contract as contract
a=contract.Approved(
    os.getuid(),"c1234567-1234-4234-8234-123456789abc",
    "tun7","eth0","1.1.1.1",443,"tcp","a"*64,"server.example.com"
)
with service.inherited_listener(os.environ,expected_path=sys.argv[1]) as sock:
    result=service.serve_limited(sock,a,max_connections=1)
    assert result["readOnlyReplies"]==1
    assert result["enforcementInstalled"] is False
"""


def main():
    if not (1000 <= os.getuid() < 60000):
        raise RuntimeError("USER_LOCAL_TEST_REQUIRES_NON_ROOT_USER")
    if not os.path.isfile(ACTIVATE) or not os.access(ACTIVATE,os.X_OK):
        print("SYSTEMD_SOCKET_ACTIVATE_TEST_NOT_AVAILABLE")
        return 0
    with tempfile.TemporaryDirectory(prefix="oig-systemd-fd-") as folder:
        os.chmod(folder,0o700)
        address=str(Path(folder)/"status.sock")
        env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"}
        cmd=[ACTIVATE,"--listen="+address,"--fdname=oig-status",
             sys.executable,"-B","-c",WRAPPER,address,str(ROOT)]
        process=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,
             stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
        try:
            deadline=time.monotonic()+5
            while not Path(address).exists() and time.monotonic() < deadline:
                if process.poll() is not None:
                    stdout,stderr=process.communicate(timeout=2)
                    raise AssertionError("SYSTEMD_ACTIVATION_EARLY_EXIT: "+stderr[-400:])
                time.sleep(0.05)
            assert Path(address).exists(),"systemd did not create socket"
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                client.settimeout(3.0)
                client.connect(address)
                data=b'{"schema":"oig.killswitch.broker.v1","op":"status"}\n'
                client.sendall(data)
                response=b""
                while b"\n" not in response:
                    part=client.recv(2048)
                    if not part:
                        break
                    response+=part
                result=json.loads(response.strip())
            assert result["state"]=="LOCKED_PREVIEW_ONLY"
            assert result["enforcementInstalled"] is False
            assert result["actualKernelProtectionVerified"] is False
            assert result["rootBrokerRunning"] is False
            stdout,stderr=process.communicate(timeout=7)
            assert process.returncode==0,stderr[-550:]
        except BaseException as exc:
            if process.poll() is None:
                process.kill()
            stdout,stderr=process.communicate(timeout=3)
            raise AssertionError("ACTIVATION_FAILED: "+
                type(exc).__name__+" "+str(exc)+
                " child_stderr="+stderr[-950:]) from exc
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=3)
    assert not Path(address).exists()
    print("REAL_SYSTEMD_SOCKET_ACTIVATION_FD3_PASS"
          " USER_LOCAL_PRIVATE_SOCKET READ_ONLY NO_ROOT_NO_NETWORK_MUTATION")


if __name__=="__main__":
    main()
