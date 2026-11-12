#!/usr/bin/env python3
"""Accept the *actual* OIG NetworkManager import/trust path, no activation.

Only runs in a disposable Ubuntu Docker network namespace on GitHub-hosted
runners. Public provider profile is fetched over trusted HTTPS and pinned.
Never prints, stores or requests user/provider credentials.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

EXPECTED_REPO = "GOD13emad/OpenInternetGateway"
HERE = Path(__file__).resolve().parent
LINUX = HERE.parent / "backend" / "linux"
OUT = Path("/out/oig-hosted-native-nm.json")


def check_scope():
    if (sys.argv[1:] != ["--native-import"]
            or os.geteuid() != 0
            or os.environ.get("OIG_HOSTED_CONTAINER") != "1"
            or not Path("/.dockerenv").exists()
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("GITHUB_REPOSITORY") != EXPECTED_REPO
            or not Path("/work/app/backend/linux/operator_profile.py").is_file()):
        raise SystemExit("REFUSED: owner host or non-disposable runner")


def checked_snapshot():
    values = []
    for cmd in (["ip", "-4", "route", "show", "table", "all"],
                ["ip", "-6", "route", "show", "table", "all"]):
        p = subprocess.run(cmd, capture_output=True, timeout=8, check=False)
        if p.returncode != 0 or len(p.stdout) > 30000:
            raise RuntimeError("CONTAINER_ROUTE_OBSERVATION_FAILED")
        values.append(hashlib.sha256(p.stdout).hexdigest())
    resolv = Path("/etc/resolv.conf").read_bytes()
    return values + [hashlib.sha256(resolv).hexdigest()]


def write_receipt(data):
    OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(data, sort_keys=True) + "\n").encode()
    fd = os.open(OUT, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())


def main():
    check_scope()
    sys.path.insert(0, str(LINUX))
    import operator_profile

    spec = importlib.util.spec_from_file_location(
        "hosted_provider", HERE / "hosted-linux-provider-data-plane.py")
    provider = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(provider)

    result = {
        "schema": "oig-hosted-native-networkmanager-v1",
        "scope": "disposable Docker netns, real NetworkManager OpenVPN importer; never activates VPN",
        "ca_sha256": provider.EXPECTED_CA,
        "expectedPeerCN": provider.EXPECTED_CN,
        "networkActivated": False,
        "readyForFullDevice": False,
        "pass": False,
    }
    # Observability is limited to fixed error categories and exit codes.
    # Never include nmcli stdout/stderr, an imported UUID, PEM, or credentials.
    fixed_errors = {
        "NetworkManager import, trust preservation, or cleanup was not verified": "NM_IMPORT_TRUST_OR_CLEANUP_NOT_VERIFIED",
        "NetworkManager native importer unavailable or timed out": "NM_IMPORTER_TIMEOUT",
        "Unable to inspect NetworkManager connection UUIDs": "NM_INVENTORY_UNAVAILABLE",
        "Temporary import identity is ambiguous; refusing deletion": "NM_IMPORT_AMBIGUOUS",
        "NetworkManager did not preserve the unique imported profile identity": "NM_PROFILE_IDENTITY_CHANGED",
        "Imported NetworkManager profile is not an OpenVPN VPN": "NM_PROFILE_TYPE_CHANGED",
        "NetworkManager changed the pinned provider endpoint": "NM_ENDPOINT_CHANGED",
        "NetworkManager did not preserve server certificate role validation": "NM_TLS_SERVER_ROLE_LOST",
        "NetworkManager did not preserve the exact server certificate CN": "NM_TLS_PEER_CN_LOST",
        "NetworkManager changed the selected TCP transport": "NM_TRANSPORT_CHANGED",
        "NetworkManager omitted an imported certificate or key": "NM_KEY_OR_CA_OMITTED",
        "NetworkManager stored identity material outside the unique QA namespace": "NM_IDENTITY_STORAGE_UNSAFE",
        "Imported identity material is missing or linked": "NM_IDENTITY_MISSING",
        "Imported identity material is not private and uniquely owned": "NM_IDENTITY_NOT_PRIVATE",
        "NetworkManager changed imported identity material": "NM_IDENTITY_BYTES_CHANGED",
        "NetworkManager returned ambiguous VPN data": "NM_VPN_DATA_AMBIGUOUS",
        "NetworkManager returned malformed VPN data": "NM_VPN_DATA_MALFORMED",
        "NetworkManager certificate storage ownership or permissions are unsafe": "NM_CERT_DIRECTORY_UNSAFE",
    }
    raw_nmcli = operator_profile._run_nmcli
    def observed_nmcli(*args, **kwargs):
        response = raw_nmcli(*args, **kwargs)
        if args[:2] == ("connection", "import"):
            result["nmImportExitCode"] = response.returncode
        elif args[:2] == ("connection", "delete"):
            result["nmDeleteExitCode"] = response.returncode
        return response
    operator_profile._run_nmcli = observed_nmcli
    raw_vpn_data = operator_profile._nm_vpn_data
    def observed_vpn_data(uuid):
        data = raw_vpn_data(uuid)
        candidates = {
            "xdg": Path.home() / ".local/share/networkmanagement/certificates/nm-openvpn",
            "legacy": Path.home() / ".cert/nm-openvpn",
        }
        fields = {}
        for key in ("ca", "cert", "key"):
            value = data.get(key, "")
            path = Path(value)
            cls = next((name for name, parent in candidates.items()
                        if path.parent == parent), "other")
            fields[key] = {
                "class": cls,
                "expectedSuffix": path.name.startswith("oig-native-")
                                  and path.name.endswith("-" + key + ".pem"),
                "regularPrivate": path.is_file() and not path.is_symlink()
                                  and path.stat().st_uid == os.geteuid()
                                  and (path.stat().st_mode & 0o777) == 0o600,
            }
        result["importedIdentityShape"] = fields
        return data
    operator_profile._nm_vpn_data = observed_vpn_data
    stage = "POLICY"
    try:
        before = checked_snapshot()
        profile, profile_sha = provider.official_profile()
        with tempfile.TemporaryDirectory(prefix="oig-hosted-nm-import-") as tmp:
            os.chmod(tmp, 0o700)
            path = Path(tmp) / "verified.ovpn"
            path.write_text(profile, encoding="utf-8")
            path.chmod(0o600)
            checked, _, _ = operator_profile.load_and_check(
                path, provider.EXPECTED_CA, provider.EXPECTED_CN)
            if not checked:
                raise RuntimeError("PINNED_PROFILE_NOT_ACCEPTED")
            result["profilePolicyAccepted"] = True
            stage = "NATIVE_IMPORT"
            gate = operator_profile.native_import_check(
                path, provider.EXPECTED_CA, provider.EXPECTED_CN)
            for k in ("ok", "nativeImportCompatible", "trustConstraintsPreserved",
                      "temporaryProfileRemoved", "certificateArtifactsRemoved"):
                if gate.get(k) is not True:
                    raise RuntimeError("NATIVE_NM_IMPORT_OR_TRUST_GATE_FAILED")
            if gate.get("connectionActivated") is not False:
                raise RuntimeError("UNEXPECTED_NETWORK_ACTIVATION")
            result["profileSha256"] = profile_sha
            result["nativeImportCompatible"] = True
            result["trustConstraintsPreserved"] = True
            result["temporaryProfileRemoved"] = True
            result["certificateArtifactsRemoved"] = True
        result["containerNetworkUntouched"] = before == checked_snapshot()
        result["pass"] = result["containerNetworkUntouched"]
    except Exception as exc:
        result["failureClass"] = type(exc).__name__
        result["failureGate"] = stage
        result["failureCode"] = fixed_errors.get(str(exc), "UNCLASSIFIED_OR_EXTERNAL_ERROR")
        result["pass"] = False
    write_receipt(result)
    print("HOSTED_NATIVE_NETWORKMANAGER_IMPORT_RECEIPT=" + json.dumps(result, sort_keys=True))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
