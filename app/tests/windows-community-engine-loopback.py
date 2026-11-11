#!/usr/bin/env python3
"""Disposable loopback-only OpenVPN 2.7 management-password/TLS regression.

Uses a local fake CA, two OpenVPN processes with --dev null, and synthetic
credentials. Never installs drivers, opens TUN, or changes host routes/DNS.
Run only inside an isolated CI worker; private test keys die with TemporaryDirectory.
"""
import argparse
import json
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


def execute(args, timeout=12):
    outcome = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                             text=True, timeout=timeout)
    if outcome.returncode:
        raise RuntimeError("certificate utility exited " + str(outcome.returncode))
    return outcome


def make_certificates(root, openssl):
    ca = root / "ca.pem"
    cak = root / "ca.key"
    execute([openssl, "req", "-new", "-x509", "-newkey", "ec", "-nodes",
             "-pkeyopt", "ec_paramgen_curve:prime256v1", "-sha256",
             "-days", "1", "-subj", "/CN=OIG synthetic local test CA",
             "-keyout", str(cak), "-out", str(ca)])
    pairs = {}
    for role in ("server", "client"):
        key = root / (role + ".key")
        csr = root / (role + ".csr")
        cert = root / (role + ".pem")
        ext = root / (role + ".ext")
        execute([openssl, "req", "-new", "-newkey", "ec", "-nodes",
                 "-pkeyopt", "ec_paramgen_curve:prime256v1", "-sha256",
                 "-subj", "/CN=oig-local-" + role,
                 "-keyout", str(key), "-out", str(csr)])
        ext.write_text("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n"
                       "extendedKeyUsage=" +
                       ("serverAuth" if role == "server" else "clientAuth") + "\n")
        execute([openssl, "x509", "-req", "-in", str(csr), "-CA", str(ca),
                 "-CAkey", str(cak), "-CAcreateserial", "-days", "1",
                 "-sha256", "-extfile", str(ext), "-out", str(cert)])
        pairs[role] = (cert, key)
    return ca, pairs


def local_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as check:
        check.bind(("127.0.0.1", 0))
        return check.getsockname()[1]


def launch(argv, diagnostic_path):
    options = {"stdin": subprocess.DEVNULL, "stderr": subprocess.STDOUT}
    if os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        options["start_new_session"] = True
    # Keep startup/option errors that happen before --log initialization.
    # Only synthetic credentials and local test certificates exist here.
    with diagnostic_path.open("wb") as sink:
        return subprocess.Popen(argv, stdout=sink, **options)


def stop(proc):
    if proc is None or proc.poll() is not None:
        return
    if os.name == "nt":
        proc.terminate()
    else:
        os.killpg(proc.pid, signal.SIGTERM)
    try:
        proc.wait(timeout=4)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            proc.kill()
        else:
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=3)


def log_contents(path):
    if not path.exists():
        return ""
    if path.stat().st_size > 150000:
        raise RuntimeError("OpenVPN log exceeded isolated QA bound")
    return path.read_text(encoding="utf-8", errors="replace")


def connect_management(port, proc, client_log, server_log):
    end = time.monotonic() + 8
    while time.monotonic() < end:
        if proc.poll() is not None:
            raise RuntimeError("client exited before local management was ready; CLIENT: " + " | ".join(log_contents(client_log).splitlines()[-9:]) + "; SERVER: " + " | ".join(log_contents(server_log).splitlines()[-9:]))
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=0.35)
            sock.settimeout(0.2)
            return sock
        except (OSError, TimeoutError):
            time.sleep(0.12)
    raise RuntimeError("local management port was never opened")


def test_case(root, common, ca, pairs, mode, controller_node=None, node_bin=None):
    port, mgmt_port = local_port(), local_port()
    # Windows OpenVPN 2.7.9 checks --auth-user-pass-verify as ONE directly
    # executable pathname; an interpreter followed by a script is rejected
    # with Win32 errno 123. Compile a synthetic-only executable in private
    # runner scratch; do not install it or add anything to system PATH.
    if os.name == "nt":
        source = root / "verify-auth.cs"
        binary = root / "verify-auth.exe"
        source.write_text(
            "using System; using System.IO;\n"
            "public class VerifyAuth { public static int Main(string[] a) {\n"
            " if(a.Length < 1) return 1;\n"
            " try { var l=File.ReadAllLines(a[a.Length-1]);\n"
            " return l.Length >= 2 && l[0] == \"oig_user\" && "
            "l[1] == \"oig_pass\" ? 0 : 1; }\n"
            " catch { return 1; } } }\n", encoding="utf-8")
        system = Path(os.environ.get("SystemRoot", "C:/Windows"))
        compilers = [system / "Microsoft.NET" / family / "v4.0.30319" / "csc.exe"
                     for family in ("Framework64", "Framework")]
        compiler = next((str(p) for p in compilers if p.is_file()), None)
        if compiler is None:
            raise RuntimeError("Windows .NET Framework C# compiler not available")
        execute([compiler, "/nologo", "/target:exe", "/out:" + str(binary),
                 str(source)], timeout=18)
        if not binary.is_file():
            raise RuntimeError("synthetic Windows verifier was not compiled")
        command = str(binary)
    else:
        auth = root / "verify-auth.py"
        auth.write_text(
            "import pathlib,sys\n"
            "p=pathlib.Path(sys.argv[-1])\n"
            "lines=p.read_text(encoding='utf-8').splitlines()\n"
            "sys.exit(0 if lines[:2]==['oig_user','oig_pass'] else 1)\n",
            encoding="utf-8")
        command = '"{}" "{}"'.format(sys.executable, auth)
    # OpenVPN appends its temporary username/password file as the final argv.
    # Only synthetic local test credentials exist in this verification flow.
    server_log = root / (mode + "-server.log")
    client_log = root / (mode + "-client.log")
    server_raw = root / (mode + "-server-startup.log")
    client_raw = root / (mode + "-client-startup.log")
    server = client = None
    saw_prompt = saw_auth_rejection = False
    try:
        # Native Windows OpenVPN 2.7 checks that a tun-type server declares
        # --ifconfig even with --dev null. These test-only RFC1918 values are
        # never applied: common includes --ifconfig-noexec and --route-noexec.
        server_config = ["--topology", "subnet", "--ifconfig",
                         "10.253.253.1", "255.255.255.0"] if os.name == "nt" else []
        server = launch(common + server_config + [
            "--proto", "tcp-server", "--local", "127.0.0.1", "--lport", str(port),
            "--tls-server", "--mode", "server", "--dh", "none",
            "--cert", str(pairs["server"][0]), "--key", str(pairs["server"][1]),
            "--script-security", "2", "--auth-user-pass-verify", command,
            "via-file", "--log", str(server_log)], server_raw)
        if controller_node:
            payload = {
                "root": str(root), "exe": str(Path(common[0]).resolve()),
                "ca": str(ca), "cert": str(pairs["client"][0]),
                "key": str(pairs["client"][1]), "port": port, "mode": mode,
                "username": "oig_user",
                "password": "wrong-pass" if mode == "bad-password" else "oig_pass"
            }
            # The QA-only app backend owns the OpenVPN child, management TCP
            # listener, credentials and teardown. Secrets are sent over stdin,
            # never command-line arguments or a stored credential file.
            controlled = subprocess.run(
                [str(node_bin), str(controller_node)],
                input=json.dumps(payload), capture_output=True, text=True,
                timeout=27, cwd=str(root))
            if controlled.returncode != 0:
                failure = controlled.stderr.strip()[:700]
                raise RuntimeError(mode + ": QA-owned backend controller failed: " +
                                   failure + "; SERVER: " +
                                   " | ".join(log_contents(server_log).splitlines()[-8:]))
            result = json.loads(controlled.stdout.strip())
            if (result.get("schema") != "oig-community-controller-qa-v1" or
                    result.get("mode") != mode or
                    result.get("ownedProcessStopped") is not True or
                    result.get("managementHoldObserved") is not True or
                    result.get("managementPromptObserved") is not True or
                    result.get("managementConnected") is not True or
                    result.get("closedManagementListener") is not True):
                raise RuntimeError(mode + ": QA-owned backend control receipt invalid")
            expectation = {
                "valid": (True, False, False),
                "bad-cn": (False, True, False),
                "bad-password": (False, False, True)
            }[mode]
            if tuple(result.get(k) for k in ("tlsAccepted", "identityRejected",
                                              "authRejected")) != expectation:
                raise RuntimeError(mode + ": QA-owned backend TLS/auth fail-closed mismatch")
            return result
        client = launch(common + [
            "--proto", "tcp-client", "--nobind", "--remote", "127.0.0.1", str(port),
            "--tls-client", "--remote-cert-tls", "server",
            "--verify-x509-name", ("wrong-oig-local-server" if mode == "bad-cn"
                                    else "oig-local-server"), "name",
            "--cert", str(pairs["client"][0]), "--key", str(pairs["client"][1]),
            "--auth-user-pass", "--pull", "--auth-retry", "none",
            "--management", "127.0.0.1", str(mgmt_port),
            "--management-query-passwords", "--management-hold",
            "--connect-retry-max", "1", "--tls-exit",
            "--log", str(client_log)], client_raw)
        if server.poll() is not None:
            raise RuntimeError(mode + ": server exited before local TLS listener; server exit " +
                               str(server.returncode) + "; SERVER_RAW: " +
                               " | ".join(log_contents(server_raw).splitlines()[-12:]) +
                               "; SERVER: " + " | ".join(log_contents(server_log).splitlines()[-8:]))
        with connect_management(mgmt_port, client, client_log, server_log) as sock:
            # OpenVPN 2.7 can accept a management TCP connection before its
            # initial HOLD event. Issuing release before observing HOLD is a
            # race on Windows: the command is logged but the client stays held.
            collected = ""
            ready_by = time.monotonic() + 6
            while time.monotonic() < ready_by:
                try:
                    chunk = sock.recv(4096)
                    if chunk:
                        collected += chunk.decode("utf-8", errors="replace")
                        if len(collected) > 32000:
                            raise RuntimeError("unexpected management handshake length")
                        if ">HOLD:" in collected:
                            break
                    elif client.poll() is not None:
                        break
                except socket.timeout:
                    pass
            if ">HOLD:" not in collected:
                raise RuntimeError(mode + ": management HOLD notification missing; client: " +
                                   " | ".join(log_contents(client_log).splitlines()[-8:]) +
                                   "; server: " + " | ".join(log_contents(server_log).splitlines()[-8:]) +
                                   "; management: " + repr(collected[-500:]))
            sock.sendall(b"hold release\n")
            deadline = time.monotonic() + 14
            while time.monotonic() < deadline:
                try:
                    chunk = sock.recv(4096)
                    if chunk:
                        collected += chunk.decode("utf-8", errors="replace")
                        if len(collected) > 32000:
                            raise RuntimeError("unexpected management output length")
                        if "Need 'Auth' username/password" in collected and not saw_prompt:
                            saw_prompt = True
                            pw = "wrong-pass" if mode == "bad-password" else "oig_pass"
                            sock.sendall(('username "Auth" oig_user\n'
                                          'password "Auth" ' + pw + '\n').encode("ascii"))
                        if "Verification Failed" in collected:
                            saw_auth_rejection = True
                    elif client.poll() is not None:
                        break
                except socket.timeout:
                    pass
                status = log_contents(client_log)
                if "Initialization Sequence Completed" in status:
                    break
                if mode == "bad-cn" and "VERIFY X509NAME ERROR" in status:
                    break
                if mode == "bad-password" and (
                    "AUTH_FAILED" in status or saw_auth_rejection):
                    break
                if client.poll() is not None and saw_prompt:
                    break
        logs = log_contents(client_log)
        srv = log_contents(server_log)
        initialized = "Initialization Sequence Completed" in logs
        if not saw_prompt and mode != "bad-cn":
            raise RuntimeError(mode + ": actual management credential prompt missing; " +
                               " | ".join(logs.splitlines()[-4:]))
        if mode == "valid":
            if not initialized:
                raise RuntimeError(mode + ": positive authenticated TLS not initialized; " +
                                   " | ".join(logs.splitlines()[-5:]) +
                                   " SERVER: " + " | ".join(srv.splitlines()[-5:]) +
                                   "; SERVER_RAW: " + " | ".join(log_contents(server_raw).splitlines()[-8:]) +
                                   "; CLIENT_RAW: " + " | ".join(log_contents(client_raw).splitlines()[-8:]))
        elif mode == "bad-cn":
            if initialized or "VERIFY X509NAME ERROR" not in logs:
                raise RuntimeError(mode + ": untrusted name not rejected; client: " +
                                   " | ".join(logs.splitlines()[-12:]) +
                                   "; server: " + " | ".join(srv.splitlines()[-12:]) +
                                   "; client_raw: " + " | ".join(log_contents(client_raw).splitlines()[-8:]) +
                                   "; server_raw: " + " | ".join(log_contents(server_raw).splitlines()[-8:]) +
                                   "; management: " + repr(collected[-500:]) +
                                   "; client_exit=" + str(client.poll()) +
                                   "; server_exit=" + str(server.poll()))
        elif mode == "bad-password":
            if initialized or not ("AUTH_FAILED" in logs or saw_auth_rejection or
                                   "AUTH_FAILED" in srv):
                raise RuntimeError(mode + ": bad credential not rejected; " +
                                   " | ".join(logs.splitlines()[-6:]) +
                                   " SERVER: " + " | ".join(srv.splitlines()[-5:]) +
                                   "; SERVER_RAW: " + " | ".join(log_contents(server_raw).splitlines()[-8:]) +
                                   "; CLIENT_RAW: " + " | ".join(log_contents(client_raw).splitlines()[-8:]))
        else:
            raise RuntimeError("invalid test case")
        return {"mode": mode, "managementPromptObserved": saw_prompt,
                "tlsAccepted": initialized, "identityRejected":
                mode == "bad-cn" and "VERIFY X509NAME ERROR" in logs,
                "authRejected": mode == "bad-password"}
    finally:
        stop(client)
        stop(server)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--openvpn", required=True)
    parser.add_argument("--openssl", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--controller-node", action="store_true")
    parser.add_argument("--node-bin", default="node")
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or os.environ.get("RUNNER_OS") != "Windows":
        if not (os.environ.get("OIG_LOOPBACK_LOCAL_QA") == "1" and os.name != "nt"):
            raise RuntimeError("DISPOSABLE_WINDOWS_RUNNER_REQUIRED")
    if not (Path(args.openvpn).is_file() and Path(args.openssl).is_file()):
        raise RuntimeError("verified tool binary missing")
    receipt = Path(args.receipt)
    if receipt.exists():
        raise RuntimeError("receipt already exists")
    with tempfile.TemporaryDirectory(prefix="oig-community-loopback-") as tmp:
        root = Path(tmp)
        ca, pairs = make_certificates(root, args.openssl)
        common = [args.openvpn, "--dev", "null", "--ifconfig-noexec",
                  "--route-noexec", "--ca", str(ca), "--data-ciphers", "AES-256-GCM",
                  "--verb", "3"]
        controller_path = (Path(__file__).resolve().parent /
                           "qa-community-cli-controller.cjs")
        if args.controller_node:
            if not controller_path.is_file():
                raise RuntimeError("QA-owned Windows backend controller missing")
            node_exe = shutil.which(args.node_bin)
            if not node_exe:
                raise RuntimeError("Node runtime unavailable for QA controller")
        else:
            node_exe = None
        checks = [test_case(root, common, ca, pairs, mode,
                            controller_path if args.controller_node else None,
                            node_exe)
                  for mode in ("valid", "bad-cn", "bad-password")]
    result = {"schema": ("oig-community-controller-loopback-v1" if args.controller_node
                         else "oig-community-windows-loopback-v1"),
              "sourceSha": os.environ.get("GITHUB_SHA", ""),
              "localOnly": True, "tunCreated": False,
              "routesOrDnsMutatedByTest": False,
              "serverIdentityIndependentlyVerified": False,
              "appOwnedManagementClientTested": bool(args.controller_node),
              "cases": checks, "pass": True}
    receipt.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("PASS: synthetic OpenVPN "+
          ("app-owned controller" if args.controller_node else "direct CLI") +
          " management/TLS identity and password cases without TUN")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        sys.exit(1)
