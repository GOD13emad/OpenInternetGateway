#!/usr/bin/env python3
"""User-local AF_UNIX systemd-style FD handoff and bounded read-only service.

No root, nftables, network-route, DNS, actual service or persistent socket.
All paths are temporary. This test does NOT validate real PID 1 systemd
activation, production privileges, boot-time firewall rules or VPN recovery.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend/linux"))
import killswitch_broker_service as svc
import killswitch_broker_protocol as proto
import killswitch_lifecycle_contract as contract

STATUS=(json.dumps({"schema":proto.WIRE_SCHEMA,"op":"status"})+"\n").encode()
PREVIEW=(json.dumps({"schema":proto.WIRE_SCHEMA,"op":"lockdown-preview"})+"\n").encode()
INVALID=b'{"schema":"oig.killswitch.broker.v1","op":"activate"}\n'
DUP=b'{"schema":"oig.killswitch.broker.v1","op":"status","op":"unlock"}\n'

def refuse(call, label):
    try:
        call()
    except svc.ActivationRefused:
        return
    raise AssertionError("ACTIVATION_FAIL_OPEN_"+label)

def main():
    if not 1000<=os.getuid()<60000:
        raise RuntimeError("NON_ROOT_DESKTOP_USER_REQUIRED")
    approved=contract.Approved(
        os.getuid(),"c1234567-1234-4234-8234-123456789abc",
        "tun7","eth0","1.1.1.1",443,"tcp","a"*64,"server.example.com"
    )
    # The entrypoint cannot be run as a user: no listening socket, manifest,
    # nft or service state may be established via a normal application.
    result=subprocess.run(
        [sys.executable,"-B",str(Path(svc.__file__).resolve())],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=4,
        env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"}
    )
    assert result.returncode!=0
    assert b"REFUSED: native root service not installed" in result.stderr
    with tempfile.TemporaryDirectory(prefix="oig-service-fd-") as tmp:
        os.chmod(tmp,0o700)
        path=str(Path(tmp)/"status.sock")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listen:
            listen.bind(path);os.chmod(path,0o600);listen.listen(4)
            assert stat.S_IMODE(os.lstat(path).st_mode)==0o600
            env={"LISTEN_PID":str(os.getpid()),"LISTEN_FDS":"1",
                 "LISTEN_FDNAMES":svc.FD_NAME}
            positive=svc.inherited_listener(env,fd=listen.fileno(),
                                           pid=os.getpid(),expected_path=path)
            with positive:
                assert positive.getsockname()==path
                assert positive.fileno()!=listen.fileno()
                vectors=[
                    ({"LISTEN_PID":"99999","LISTEN_FDS":"1","LISTEN_FDNAMES":svc.FD_NAME},"wrong_pid"),
                    ({"LISTEN_PID":str(os.getpid()),"LISTEN_FDS":"2","LISTEN_FDNAMES":svc.FD_NAME},"two_fds"),
                    ({"LISTEN_PID":str(os.getpid()),"LISTEN_FDS":"1","LISTEN_FDNAMES":"foreign"},"wrong_fdname"),
                    ({"LISTEN_PID":str(os.getpid()),"LISTEN_FDS":"1"},"missing_fdname"),
                ]
                for wrong,label in vectors:
                    refuse(lambda wrong=wrong:svc.inherited_listener(
                        wrong,fd=listen.fileno(),pid=os.getpid(),expected_path=path),label)
                refuse(lambda:svc.inherited_listener(
                    env,fd=listen.fileno(),expected_path=path+"-foreign"),"wrong_path")
                refuse(lambda:svc.inherited_listener(env,fd=-1,
                    expected_path=path),"invalid_fd")
                refuse(lambda:svc.inherited_listener(env,fd=10361,
                    expected_path=path),"closed_fd")
                refuse(lambda:svc.serve_limited(positive,approved,
                    max_connections=0),"zero_clients")
                refuse(lambda:svc.serve_limited(positive,approved,
                    max_connections=svc.MAX_CONNECTIONS+1),"too_many_clients")

                with ThreadPoolExecutor(max_workers=1) as pool:
                    server=pool.submit(svc.serve_limited,positive,approved,
                                       max_connections=4)
                    outcomes=[]
                    for payload in (STATUS,PREVIEW,INVALID,DUP):
                        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                            client.settimeout(3.0)
                            client.connect(path)
                            try: client.sendall(payload)
                            except (BrokenPipeError,ConnectionResetError):
                                outcomes.append(None)
                                continue
                            try:
                                raw=client.recv(4096)
                            except (BrokenPipeError,ConnectionResetError):
                                raw=b''
                            outcomes.append(json.loads(raw) if raw else None)
                    summary=server.result(timeout=7)
                assert summary=={
                    "connectionsReceived":4,"readOnlyReplies":2,
                    "enforcementInstalled":False,"fullDeviceProtectionVerified":False
                },summary
                assert outcomes[0]["state"]=="LOCKED_PREVIEW_ONLY"
                assert outcomes[0]["enforcementInstalled"] is False
                assert outcomes[1]["renderOnly"] is True
                assert "policy drop" in outcomes[1]["rules"]
                assert outcomes[2] is None and outcomes[3] is None
        # Closing a listening socket does NOT unlink its pathname; systemd's
        # socket unit or our TemporaryDirectory owns that file lifecycle.
        assert Path(path).exists()
    assert not Path(path).exists()
    # Wrong protocol type is not an activated stream listener.
    with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as datagram:
        refuse(lambda:svc.inherited_listener(env,fd=datagram.fileno(),
             expected_path="/tmp/not-a-listener"),"datagram")
    service_source=Path(svc.__file__).read_text()
    for forbidden in ("subprocess.run(", "subprocess.Popen(", "os.system(",
                      "nft -f", "systemctl enable", "nmcli connection up",
                      "nmcli connection down"):
        assert forbidden not in service_source, forbidden
    print("SYSTEMD_FD3_READONLY_SERVICE_HANDOFF_PASS"
          " 4_ACCEPTED_SOCKETS 2_STATUS_ONLY_REPLIES"
          " 9_INVALID_ACTIVATION_REFUSALS NO_ROOT_NO_NETWORK_MUTATION")


if __name__=="__main__":
    main()
