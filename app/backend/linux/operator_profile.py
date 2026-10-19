#!/usr/bin/env python3
"""Opt-in, offline OpenVPN operator-profile trust gate. Never connects or stores login."""
import argparse
import hashlib
import json
import os
import re
import shlex
import ssl
import stat
import subprocess
import tempfile
from pathlib import Path

MAX_BYTES = 256 * 1024
BLOCKS = {"ca", "cert", "key", "tls-auth", "tls-crypt"}
FLAGS = {"client", "nobind", "persist-key", "persist-tun", "auth-nocache", "remote-random", "fast-io", "pull"}
SIMPLE = {
    "dev": {"tun", "tun0", "tun1"},
    "proto": {"tcp-client", "tcp", "udp"},
    "resolv-retry": {"infinite"},
    "remote-cert-tls": {"server"},
    "cipher": {"AES-256-CBC", "AES-256-GCM", "AES-128-GCM"},
    "auth": {"SHA256", "SHA512"},
    "tls-version-min": {"1.2", "1.3"},
    "data-ciphers": {"AES-256-GCM:AES-128-GCM", "AES-256-GCM:AES-128-GCM:AES-256-CBC"},
    "key-direction": {"1"},
}
NUMERIC = {"route-delay": (0, 60), "verb": (0, 5), "tun-mtu": (576, 9000), "mssfix": (500, 1500),
           "reneg-sec": (0, 86400), "connect-retry": (1, 60)}
HEX_SHA = re.compile(r"[a-fA-F0-9]{64}\Z")
HOST = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.vpnbook\.com\Z")
CN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
PEM_CERT = re.compile(r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/\s=]+-----END CERTIFICATE-----\s*\Z")
PEM_KEY = re.compile(r"-----BEGIN (RSA |EC |)PRIVATE KEY-----\s+[A-Za-z0-9+/\s=]+-----END \1PRIVATE KEY-----\s*\Z")


class UnsafeProfile(ValueError):
    pass


def load_and_check(profile: Path, ca_sha: str, expected_cn: str):
    if not HEX_SHA.fullmatch(ca_sha):
        raise UnsafeProfile("Expected independently obtained CA SHA-256 is required")
    if not CN.fullmatch(expected_cn):
        raise UnsafeProfile("Expected peer common name is invalid")
    if profile.is_symlink() or not profile.is_file() or profile.stat().st_size > MAX_BYTES:
        raise UnsafeProfile("Input must be a regular bounded file, not a symlink")
    raw = profile.read_bytes()
    if not raw or len(raw) > MAX_BYTES or b"\x00" in raw:
        raise UnsafeProfile("Profile is empty, oversized, or contains NUL")
    try:
        data = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnsafeProfile("Profile must be UTF-8") from exc
    if re.search(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", data):
        raise UnsafeProfile("Control characters are forbidden")
    data = data.replace("\r\n", "\n")
    if "\r" in data:
        raise UnsafeProfile("Invalid line endings")

    blocks = {}
    directives = {}
    inside = None
    lines = []
    for line in data.splitlines():
        stripped = line.strip()
        if inside is not None:
            if stripped == f"</{inside}>":
                blocks[inside] = "\n".join(lines)
                lines = []
                inside = None
            elif stripped.startswith("<") or stripped.startswith("</"):
                raise UnsafeProfile("Nested or unexpected PEM block")
            else:
                lines.append(line)
            continue
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if stripped.startswith("<"):
            tag = re.fullmatch(r"<([a-z-]+)>", stripped)
            if not tag or tag.group(1) not in BLOCKS or tag.group(1) in blocks:
                raise UnsafeProfile("Unknown or duplicate inline block")
            inside = tag.group(1)
            continue
        try:
            args = shlex.split(stripped, posix=True)
        except ValueError as exc:
            raise UnsafeProfile("Unparseable directive") from exc
        if not args:
            continue
        name, values = args[0], args[1:]
        if name not in FLAGS | SIMPLE.keys() | NUMERIC.keys() | {
            "remote", "auth-user-pass", "verify-x509-name", "explicit-exit-notify",
            "redirect-gateway"
        }:
            raise UnsafeProfile(f"Unsupported OpenVPN directive: {name}")
        if name in FLAGS and values:
            raise UnsafeProfile(f"Unexpected {name} parameters")
        elif name in SIMPLE and (len(values) != 1 or values[0] not in SIMPLE[name]):
            raise UnsafeProfile(f"Unsupported {name} value")
        elif name in NUMERIC and (len(values) != 1 or not values[0].isdigit()
                                  or not NUMERIC[name][0] <= int(values[0]) <= NUMERIC[name][1]):
            raise UnsafeProfile(f"Unsupported {name} value")
        elif name == "remote":
            if (len(values) != 2 or not HOST.fullmatch(values[0].lower())
                    or not values[1].isdigit() or int(values[1]) not in {53, 80, 443, 25000}):
                raise UnsafeProfile("Remote must be an expected VPNBook host and supported port")
        elif name == "redirect-gateway" and values not in ([], ["def1"]):
            raise UnsafeProfile("Only bounded provider redirect-gateway def1 is recognized")
        elif name == "auth-user-pass" and values:
            raise UnsafeProfile("External or embedded credential files are forbidden")
        elif name == "verify-x509-name" and values != [expected_cn, "name"]:
            raise UnsafeProfile("Conflicting peer certificate identity constraint")
        elif name == "explicit-exit-notify" and values != ["1"]:
            raise UnsafeProfile("Unsupported explicit-exit-notify")
        directives.setdefault(name, []).append(values)

    if inside is not None or not {"ca", "cert", "key"}.issubset(blocks):
        raise UnsafeProfile("Unclosed or missing required inline CA, cert, key")
    if "tls-auth" in blocks and "tls-crypt" in blocks:
        raise UnsafeProfile("Conflicting TLS control-channel blocks")
    for required in ("client", "dev", "proto", "remote", "auth-user-pass"):
        if required not in directives:
            raise UnsafeProfile(f"Missing required directive: {required}")
    if len(directives["remote"]) != 1:
        raise UnsafeProfile("Exactly one remote endpoint must be selected")
    for name, items in directives.items():
        if name != "remote" and len(items) != 1:
            raise UnsafeProfile(f"Duplicate directive: {name}")
    ca_text = blocks["ca"].strip()
    if not PEM_CERT.fullmatch(ca_text):
        raise UnsafeProfile("Expected a single inline CA certificate")
    try:
        ca_der = ssl.PEM_cert_to_DER_cert(ca_text)
    except ValueError as exc:
        raise UnsafeProfile("Invalid CA PEM") from exc
    if hashlib.sha256(ca_der).hexdigest() != ca_sha.lower():
        raise UnsafeProfile("Independently pinned CA certificate mismatch")
    if not PEM_CERT.fullmatch(blocks["cert"].strip()):
        raise UnsafeProfile("Malformed inline client certificate")
    try:
        ssl.PEM_cert_to_DER_cert(blocks["cert"].strip())
    except ValueError as exc:
        raise UnsafeProfile("Invalid inline client certificate") from exc
    if not PEM_KEY.fullmatch(blocks["key"].strip()):
        raise UnsafeProfile("Malformed inline private key")
    if "key-direction" in directives and "tls-auth" not in blocks:
        raise UnsafeProfile("key-direction requires tls-auth")
    # Never import provider default-route directives in a scoped trial.
    # Full-device routing requires its own explicit, separately validated mode.
    if "redirect-gateway" in directives:
        data = "\n".join(line for line in data.split("\n")
                         if not re.fullmatch(r"\s*redirect-gateway(?:\s+def1)?\s*", line))
    if "remote-cert-tls" not in directives:
        data += "\nremote-cert-tls server\n"
    if "verify-x509-name" not in directives:
        data += f"\nverify-x509-name {expected_cn} name\n"
    data += "\nauth-nocache\n" if "auth-nocache" not in directives else ""
    return data.encode("utf-8"), directives["remote"][0], directives["proto"][0][0]



def _run_nmcli(*args, timeout=8):
    # Never print nmcli output: some plugins can include profile material.
    try:
        p = subprocess.run(["nmcli", "--wait", "5", *args], capture_output=True,
                           timeout=timeout, check=False,
                           env={**os.environ, "LC_ALL": "C", "LANG": "C"})
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise UnsafeProfile("NetworkManager native importer unavailable or timed out") from exc
    return p


def _connection_uuids():
    listing = _run_nmcli("-t", "-f", "UUID", "connection", "show")
    if listing.returncode:
        raise UnsafeProfile("Unable to inspect NetworkManager connection UUIDs")
    uuids = set()
    for line in listing.stdout.decode(errors="replace").splitlines():
        value = line.strip().lower()
        if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value):
            uuids.add(value)
    return uuids


def native_import_check(profile: Path, ca_sha: str, expected_cn: str):
    """Import-only parser QA; never activate a VPN or persist its credentials."""
    checked, _, _ = load_and_check(profile, ca_sha, expected_cn)
    baseline = _connection_uuids()
    matched = None
    imported = False
    vpn_type_ok = False
    cleaned = False
    # Never use a caller-supplied UUID to delete an existing connection.
    with tempfile.TemporaryDirectory(prefix="oig-operator-native-") as td:
        os.chmod(td, 0o700)
        tmp = Path(td) / "validated.ovpn"
        tmp.write_bytes(checked)
        tmp.chmod(0o600)
        try:
            output_uuids = set()
            try:
                response = _run_nmcli("connection", "import", "--temporary", "type",
                                      "openvpn", "file", str(tmp), timeout=10)
                imported = response.returncode == 0
                output_uuids = {s.lower() for s in re.findall(
                    r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b",
                    response.stdout.decode(errors="replace"))}
            finally:
                # Even a failed/timed-out import may have created a temporary
                # connection. Reconcile NetworkManager state before returning.
                fresh = _connection_uuids() - baseline
                if len(fresh) == 1 and (
                        not output_uuids or output_uuids == fresh):
                    matched = next(iter(fresh))
                elif len(fresh) > 1 and len(output_uuids) == 1 and (
                        output_uuids <= fresh):
                    # Concurrent creation: only clean the UUID returned by
                    # our import; never delete unrelated new connections.
                    matched = next(iter(output_uuids))
                if matched:
                    inspected = _run_nmcli("-g", "connection.type", "connection",
                                           "show", "uuid", matched)
                    vpn_type_ok = (inspected.returncode == 0 and
                                   inspected.stdout.decode(errors="replace").strip() == "vpn")
        finally:
            if matched:
                # Deletion is UUID-scoped; never invoke connection down/up here.
                deleted = _run_nmcli("connection", "delete", "uuid", matched)
                cleaned = deleted.returncode == 0 and matched not in _connection_uuids()
    if not cleaned:
        raise UnsafeProfile("Temporary import cleanup could not be verified")
    if not imported or not vpn_type_ok:
        raise UnsafeProfile("NetworkManager did not accept a safe temporary VPN profile")
    return {"ok": True, "nativeImportCompatible": True,
            "temporaryProfileRemoved": True, "connectionActivated": False,
            "liveTlsVerified": False, "networkActivationRequested": False,
            "readyForAutomaticConnection": False}


def write_private_atomic(path, content):
    fd, tmp = tempfile.mkstemp(prefix=".oig-stage-", dir=str(path.parent))
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "wb") as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def stage(profile: Path, base: Path, ca_sha: str, expected_cn: str):
    # Offline only: importing never invokes OpenVPN, NetworkManager, or routing.
    content, remote, protocol = load_and_check(profile, ca_sha, expected_cn)
    if base.is_symlink() or (base / "operator-profiles").is_symlink():
        raise UnsafeProfile("Symlinked output directory is forbidden")
    base = base.resolve()
    # Keep private client keys out of Git checkouts, even on explicit import.
    if any((parent / ".git").exists() for parent in (base, *base.parents)):
        raise UnsafeProfile("Refusing private profile storage inside a Git checkout")
    target_dir = base / "operator-profiles"
    target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target_dir.stat().st_mode & 0o077:
        raise UnsafeProfile("Operator profile directory must be private (0700)")
    source_sha = hashlib.sha256(content).hexdigest()
    target = target_dir / f"{source_sha}.ovpn"
    if target.is_symlink() or (target.exists() and
                               (not target.is_file() or target.stat().st_nlink != 1)):
        raise UnsafeProfile("Refusing non-regular or hard-linked output")
    if not target.exists() or hashlib.sha256(target.read_bytes()).hexdigest() != source_sha:
        write_private_atomic(target, content)
    os.chmod(target, 0o600)
    metadata = {
        "schemaVersion": 1, "provider": "VPNBook", "profileSha256": source_sha,
        "sourceProfileSha256": hashlib.sha256(profile.read_bytes()).hexdigest(),
        "providerDefaultRouteDirectiveRemoved": bool(re.search(
            r"(?m)^[ \t]*redirect-gateway(?:[ \t]+def1)?[ \t]*$",
            profile.read_text(encoding="utf-8"))),
        "profile": target.name, "remoteHost": remote[0], "remotePort": int(remote[1]),
        "protocol": protocol, "caDerSha256": ca_sha.lower(), "expectedPeerCN": expected_cn,
        "profilePolicyValidated": True, "operatorIdentityTrust": "owner-supplied-ca-pin-and-cn",
        "liveTlsVerified": False, "connected": False, "readyForAutomaticConnection": False
    }
    index = target_dir / "current.json"
    encoded = (json.dumps(metadata, indent=2) + "\n").encode()
    if index.is_symlink() or (index.exists() and
                              (not index.is_file() or index.stat().st_nlink != 1)):
        raise UnsafeProfile("Refusing linked metadata")
    if not index.exists() or index.read_bytes() != encoded:
        write_private_atomic(index, encoded)
    os.chmod(index, 0o600)
    return {"ok": True, "provider": "VPNBook", "profileSha256": source_sha,
            "profilePolicyValidated": True, "liveTlsVerified": False,
            "readyForAutomaticConnection": False}


def main():
    p = argparse.ArgumentParser(description="Offline, explicit VPNBook OpenVPN trust staging")
    p.add_argument("action", choices=["check", "stage", "native-check"])
    p.add_argument("--profile", required=True, type=Path)
    p.add_argument("--ca-sha256", required=True)
    p.add_argument("--peer-cn", required=True)
    p.add_argument("--common", type=Path)
    a = p.parse_args()
    try:
        if a.action == "stage":
            if a.common is None:
                p.error("--common is required for stage")
            result = stage(a.profile, a.common, a.ca_sha256, a.peer_cn)
        elif a.action == "native-check":
            result = native_import_check(a.profile, a.ca_sha256, a.peer_cn)
        else:
            _, remote, _ = load_and_check(a.profile, a.ca_sha256, a.peer_cn)
            result = {"ok": True, "profilePolicyValidated": True, "remoteHost": remote[0],
                      "liveTlsVerified": False}
        print(json.dumps(result, separators=(",", ":")))
    except (UnsafeProfile, OSError, ValueError) as exc:
        # No untrusted profile content or embedded key may enter logs.
        print(f"REJECTED: {exc}", file=__import__("sys").stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
