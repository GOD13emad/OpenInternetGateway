#!/usr/bin/env python3
"""Real AF_UNIX listener/client interprocess test; user-local socket only.

The child process really connect(2)s to a temporary socket, so SO_PEERCRED
must expose the CHILD's PID, not credentials frozen at socketpair(2).
No app-managed VPN, firewall, routes, DNS, systemd, pkexec or sudo involved.
"""
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend/linux"))
import killswitch_broker_ipc as ipc
import killswitch_broker_protocol as broker
import killswitch_lifecycle_contract as contract

CHILD = r'''
import socket,sys,time
client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
client.settimeout(3.0)
client.connect(sys.argv[1])
try:
    client.sendall(bytes.fromhex(sys.argv[2]))
except (BrokenPipeError, ConnectionResetError):
    # An unauthorized peer is deliberately rejected BEFORE its request is
    # read. The server may close while the sender is still writing; that
    # race is a correct denial, not a failed security test.
    sys.stdout.write("NO_REPLY")
    client.close()
    sys.exit(0)
if sys.argv[3] == "half-close":
    client.shutdown(socket.SHUT_WR)
if sys.argv[3] == "stall":
    time.sleep(1.75)
try:
    data=client.recv(4096)
    sys.stdout.write(data.decode("utf8","replace") if data else "NO_REPLY")
except (OSError,TimeoutError):
    sys.stdout.write("NO_REPLY")
finally:
    client.close()
'''
SCHEMA = broker.WIRE_SCHEMA
STATUS = json.dumps({"schema": SCHEMA, "op": "status"}).encode() + b"\n"
PREVIEW = json.dumps({"schema": SCHEMA, "op": "lockdown-preview"}).encode() + b"\n"


def trial(approved, payload, *, expect_accept, stall=None, show_pid=False):
    with tempfile.TemporaryDirectory(prefix="oig-ipc-") as root:
        folder=Path(root)
        folder.chmod(0o700)
        sockpath=str(folder/"one-shot.sock")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.settimeout(3)
            server.bind(sockpath)
            os.chmod(sockpath,0o600)
            server.listen(1)
            assert stat.S_IMODE(os.lstat(sockpath).st_mode)==0o600
            child=subprocess.Popen(
                [sys.executable,"-B","-c",CHILD,sockpath,payload.hex(),
                 stall or "normal"],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"},
                text=True,
            )
            try:
                with server.accept()[0] as accepted:
                    pid,uid,gid=broker.kernel_peer_credentials(accepted)
                    assert uid==os.getuid()
                    assert gid==os.getgid()
                    assert pid==child.pid, (pid,child.pid)
                    try:
                        result=ipc.serve_accepted(accepted,approved)
                    except broker.BrokerRefused:
                        if expect_accept: raise
                        result=None
                    else:
                        assert expect_accept,"unauthorized or malformed request was served"
                stdout,stderr=child.communicate(timeout=5)
                assert child.returncode==0,(child.returncode,stderr[:300])
                if expect_accept:
                    reply=json.loads(stdout)
                    assert reply==result
                    assert reply["enforcementInstalled"] is False
                    assert reply["actualKernelProtectionVerified"] is False
                    assert reply["rootBrokerRunning"] is False
                else:
                    assert stdout=="NO_REPLY",repr(stdout[:300])
                return result
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=2)


def main():
    uid=os.getuid()
    assert 1000 <= uid < 60000
    approved=contract.Approved(
        uid, "c1234567-1234-4234-8234-123456789abc",
        "tun7","eth0","1.1.1.1",443,"tcp","a"*64,"server.example.com"
    )
    result=trial(approved,STATUS,expect_accept=True,show_pid=True)
    assert "rules" not in result
    preview=trial(approved,PREVIEW,expect_accept=True)
    assert preview["renderOnly"] is True
    assert "policy drop" in preview["rules"]
    assert 'oifname "tun7" accept' not in preview["rules"]
    trial(replace(approved,owner_uid=uid+1),STATUS,expect_accept=False)
    trial(replace(approved,owner_uid=0),STATUS,expect_accept=False)
    malformed=[
        STATUS+STATUS,
        b'{"schema":"oig.killswitch.broker.v1","op":"unlock"}\n',
        b'{"schema":"oig.killswitch.broker.v1","op":"status","uid":1000}\n',
        b'{"schema":"oig.killswitch.broker.v1","op":"status","op":"apply"}\n',
        b'not-json\n',
        b'\n',
        b'a'*513+b'\n',
        b'{"schema":"oig.killswitch.broker.v1","op":"status"}\nJUNK',
    ]
    for request in malformed:
        trial(approved,request,expect_accept=False)
    trial(approved,b'{"schema":"oig.killswitch.broker.v1","op":"status"}',
          expect_accept=False,stall="half-close")
    trial(approved,b'{"schema":"oig.killswitch.broker.v1"',
          expect_accept=False,stall="stall")
    assert len(malformed)==8
    assert not any(x in Path(ipc.__file__).read_text()
                   for x in ("subprocess.run(", "nft -f", "systemctl enable",
                             "socket.bind(", "socket.listen(", "os.system("))
    print("OIG_INTERPROCESS_SO_PEERCRED_TRANSPORT_PASS "
          "2_VALID 2_UNAUTHORIZED_UID 8_BAD_FRAMES "
          "1_HALF_CLOSE 1_TIMEOUT NO_PRIVILEGED_SIDE_EFFECTS")


if __name__=="__main__":
    main()
