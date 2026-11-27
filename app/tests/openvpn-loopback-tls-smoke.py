#!/usr/bin/env python3
"""Private OpenVPN TLS loopback smoke: --dev null, no TUN, routes or DNS changes.

Only localhost TCP is used. Generated certificate private keys never leave a
TemporaryDirectory; no outside VPN endpoints, systemctl or NetworkManager calls.
A successful TLS handshake does not prove a working device-wide VPN tunnel.
"""
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


def run(command, *, deadline=8):
    p = subprocess.run(command, capture_output=True, text=True, timeout=deadline)
    if p.returncode:
        raise AssertionError(
            "Private test certificate generation failed with exit " + str(p.returncode))
    return p


def certificate(root, ca_cert, ca_key, label, *, server=False):
    key = root / (label + ".key")
    csr = root / (label + ".csr")
    crt = root / (label + ".crt")
    run(["openssl", "req", "-new", "-newkey", "ec",
         "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-sha256",
         "-subj", "/CN=" + label, "-keyout", str(key), "-out", str(csr)])
    ext = root / (label + ".ext")
    ext.write_text("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n"
                   "extendedKeyUsage=" + ("serverAuth" if server else "clientAuth") + "\n")
    run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
         "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(crt),
         "-days", "1", "-sha256", "-extfile", str(ext)])
    return crt, key


def local_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def terminate(process):
    if process is None:
        return
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)


def attempt(root, common, port, cert, key, expected_name):
    log = root / ("client-" + expected_name.replace(".", "-") + ".log")
    command = common + [
        "--proto", "tcp-client", "--remote", "127.0.0.1", str(port),
        "--tls-client", "--remote-cert-tls", "server",
        "--verify-x509-name", expected_name, "name",
        "--cert", str(cert), "--key", str(key), "--connect-retry-max", "1",
        "--log", str(log)]
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        until = time.monotonic() + 11
        while time.monotonic() < until:
            data = log.read_text(errors="replace") if log.exists() else ""
            if "Initialization Sequence Completed" in data:
                return True, data
            if process.poll() is not None:
                break
            time.sleep(0.12)
        return False, log.read_text(errors="replace") if log.exists() else ""
    finally:
        terminate(process)


def main():
    # A bounded runner timeout must not orphan a localhost OpenVPN process.
    signal.signal(signal.SIGTERM, lambda sig, frame: sys.exit(128 + sig))
    if not all(shutil.which(x) for x in ("openvpn", "openssl")):
        raise RuntimeError("OpenVPN and OpenSSL must be installed for native loopback smoke")
    with tempfile.TemporaryDirectory(prefix="oig-loopback-tls-") as folder:
        root = pathlib.Path(folder)
        os.chmod(root, 0o700)
        ca_key = root / "ca.key"
        ca_cert = root / "ca.crt"
        run(["openssl", "req", "-new", "-x509", "-newkey", "ec",
             "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
             "-days", "1", "-sha256", "-subj", "/CN=OIG-qa-loopback-CA",
             "-keyout", str(ca_key), "-out", str(ca_cert)])
        server_cert, server_key = certificate(
            root, ca_cert, ca_key, "oig-loopback-server", server=True)
        client_cert, client_key = certificate(
            root, ca_cert, ca_key, "oig-loopback-client")
        common = ["openvpn", "--dev", "null", "--ifconfig-noexec", "--route-noexec",
                  "--local", "127.0.0.1", "--ca", str(ca_cert),
                  "--data-ciphers", "AES-256-GCM", "--verb", "3",
                  "--connect-retry-max", "1", "--tls-exit"]
        # The deliberate identity rejection may terminate the server due to
        # --tls-exit. Every trial therefore has its own fresh TCP listener.
        for identity, should_connect in (
                ("oig-loopback-server", True),
                ("wrong-oig-loopback-server", False)):
            port = local_port()
            server_log = root / ("server-" + identity + ".log")
            server = subprocess.Popen(
                common + ["--proto", "tcp-server", "--lport", str(port),
                          "--tls-server", "--dh", "none",
                          "--cert", str(server_cert), "--key", str(server_key),
                          "--log", str(server_log)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True)
            try:
                time.sleep(0.35)
                actual, client_log = attempt(
                    root, common, port, client_cert, client_key, identity)
                if should_connect and not actual:
                    details = server_log.read_text(errors="replace") if server_log.exists() else ""
                    raise AssertionError(
                        "Valid local OpenVPN handshake failed; client: " +
                        " | ".join(client_log.splitlines()[-5:]) +
                        "; server: " + " | ".join(details.splitlines()[-5:]))
                if not should_connect and (
                        actual or "VERIFY X509NAME ERROR" not in client_log):
                    details = server_log.read_text(errors="replace") if server_log.exists() else ""
                    raise AssertionError(
                        "Untrusted server identity was not explicitly rejected; " +
                        "client: " + " | ".join(client_log.splitlines()[-5:]) +
                        "; server: " + " | ".join(details.splitlines()[-5:]))
            finally:
                terminate(server)
        print("PASS: real OpenVPN TLS loopback authenticated peer, "
              "rejected wrong server identity, no TUN/routes/DNS used")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        sys.exit(1)
