#!/usr/bin/env python3
"""Independent user-session timer rollback for opt-in Linux operator VPN QA.

The CLI deliberately has no connect or route-changing action. It only arms a
one-shot timer, or cleans a uniquely named, explicitly scoped QA profile.
"""
import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

UUID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z")
QA_NAME = re.compile(r"OIG-Operator-QA-[a-f0-9]{12}\Z")
HASH = re.compile(r"[a-f0-9]{64}\Z")


class RollbackError(RuntimeError):
    pass


def check_identity(uuid, name):
    if not UUID.fullmatch(uuid) or not QA_NAME.fullmatch(name):
        raise RollbackError("Expected an OIG-Operator-QA name and full UUID")


def command(args, timeout=10):
    try:
        return subprocess.run(args, capture_output=True, timeout=timeout, check=False,
                              env={**os.environ, "LC_ALL": "C", "LANG": "C"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RollbackError("Rollback utility or NetworkManager is unavailable") from exc


def get_profile_name(uuid):
    listed = command(["nmcli", "--wait", "5", "-t", "-f", "UUID",
                      "connection", "show"])
    if listed.returncode:
        raise RollbackError("Cannot verify NetworkManager connection inventory")
    if uuid not in listed.stdout.decode(errors="replace").lower().splitlines():
        return None
    proc = command(["nmcli", "--wait", "5", "-g", "connection.id",
                    "connection", "show", "uuid", uuid])
    if proc.returncode:
        raise RollbackError("Cannot verify QA profile name")
    return proc.stdout.decode("utf-8", errors="replace").strip()



def checked_certificate_directory(value):
    directory = Path(value)
    data_home = Path(os.environ.get("XDG_DATA_HOME") or
                     (Path.home() / ".local" / "share"))
    if not data_home.is_absolute():
        raise RollbackError("NetworkManager data home must be absolute")
    expected = data_home / "networkmanagement" / "certificates" / "nm-openvpn"
    legacy = Path.home() / ".cert" / "nm-openvpn"
    if directory == expected:
        parents = (data_home, data_home / "networkmanagement",
                   data_home / "networkmanagement" / "certificates", directory)
    elif directory == legacy:
        parents = (Path.home() / ".cert", directory)
    else:
        raise RollbackError("Temporary certificate directory is not the configured XDG NetworkManager path or approved legacy path")
    for item in parents:
        if item.is_symlink():
            raise RollbackError("Temporary certificate directory cannot contain symlinks")
        if item.exists():
            info = item.stat()
            if (not item.is_dir() or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o022):
                raise RollbackError("Temporary certificate directory ownership or permissions changed")
    return directory


def checked_artifact_hashes(values):
    if not isinstance(values, dict) or set(values) != {"ca", "cert", "key"}:
        raise RollbackError("Expected SHA-256 pins for exactly the CA, certificate and private key")
    if any(not isinstance(values[name], str) or not HASH.fullmatch(values[name])
           for name in ("ca", "cert", "key")):
        raise RollbackError("Temporary certificate SHA-256 pin is invalid")
    return dict(values)


def parse_vpn_data(raw):
    result = {}
    for item in re.split(r",\s*(?=[A-Za-z0-9_-]+\s*=)", raw.strip()):
        if not item:
            continue
        key, sep, value = item.partition("=")
        if not sep:
            raise RollbackError("Cannot parse NetworkManager VPN data")
        key = key.strip()
        if not key or key in result:
            raise RollbackError("Ambiguous NetworkManager VPN data")
        result[key] = value.strip().replace(r"\:", ":").replace(r"\,", ",")
    return result


def cleanup_import_artifacts(artifact_stem, certificate_directory, artifact_hashes):
    """Delete only uniquely named, unreferenced and hash-pinned imported cert copies."""
    if not QA_NAME.fullmatch(artifact_stem):
        raise RollbackError("Temporary certificate artifact identity is invalid")
    artifact_hashes = checked_artifact_hashes(artifact_hashes)
    directory = checked_certificate_directory(certificate_directory)
    paths = {name: directory / f"{artifact_stem}-{name}.pem"
             for name in ("ca", "cert", "key")}
    if not directory.exists():
        return True
    if not directory.is_dir() or directory.is_symlink():
        raise RollbackError("NetworkManager certificate directory is not regular")

    listing = command(["nmcli", "--wait", "5", "-t", "-f", "UUID",
                       "connection", "show"])
    if listing.returncode:
        raise RollbackError("Cannot enumerate NetworkManager profiles before certificate cleanup")
    for uuid in listing.stdout.decode(errors="replace").lower().splitlines():
        if not UUID.fullmatch(uuid):
            continue
        kind = command(["nmcli", "--wait", "5", "-g", "connection.type",
                        "connection", "show", "uuid", uuid])
        if kind.returncode:
            raise RollbackError("Cannot prove NetworkManager certificate references are absent")
        if kind.stdout.decode(errors="replace").strip() != "vpn":
            continue
        data = command(["nmcli", "--wait", "5", "-g", "vpn.data",
                        "connection", "show", "uuid", uuid])
        if data.returncode:
            raise RollbackError("Cannot inspect NetworkManager VPN certificate references")
        values = parse_vpn_data(data.stdout.decode(errors="replace"))
        if any(str(path) in values.values() for path in paths.values()):
            raise RollbackError("Temporary certificate is still referenced by a VPN profile")

    # Do not enumerate /proc/<pid>/fd: container/user namespaces may hide
    # unrelated descriptors. No NM VPN profile references these exact unique
    # paths; unlink removes their names and prevents future opens.
    for name, path in paths.items():
        if not path.exists() and not path.is_symlink():
            continue
        if path.is_symlink() or not path.is_file():
            raise RollbackError("Refusing to remove linked or non-regular certificate material")
        info = path.stat()
        raw = path.read_bytes()
        if (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1 or info.st_size > 256 * 1024):
            raise RollbackError("Temporary certificate ownership or permissions changed")
        if hashlib.sha256(raw.strip()).hexdigest() != artifact_hashes[name]:
            raise RollbackError("Temporary certificate contents do not match the trial's original SHA-256 pin")
        if name in ("ca", "cert") and b"-----BEGIN CERTIFICATE-----" not in raw:
            raise RollbackError("Temporary certificate contents are not PEM")
        if name == "key" and (b"-----BEGIN " not in raw or b"PRIVATE KEY-----" not in raw):
            raise RollbackError("Temporary private key contents are not PEM")
    for path in paths.values():
        if path.exists():
            path.unlink()
    if any(path.exists() or path.is_symlink() for path in paths.values()):
        raise RollbackError("Temporary certificate cleanup could not be verified")
    return True


def cleanup(uuid, name, artifact_stem, certificate_directory, artifact_hashes):
    check_identity(uuid, name)
    if artifact_stem != name:
        raise RollbackError("Temporary certificate namespace does not match the QA profile")
    artifact_hashes = checked_artifact_hashes(artifact_hashes)
    current = get_profile_name(uuid)
    if current is None:
        artifacts_removed = cleanup_import_artifacts(
            artifact_stem, certificate_directory, artifact_hashes)
        return {"ok": True, "alreadyAbsent": True, "profileRemoved": True,
                "certificateArtifactsRemoved": artifacts_removed}
    if current != name:
        raise RollbackError("Refusing to modify a profile with a different identity")
    kind = command(["nmcli", "--wait", "5", "-g", "connection.type",
                    "connection", "show", "uuid", uuid])
    if kind.returncode or kind.stdout.decode(errors="replace").strip() != "vpn":
        raise RollbackError("Refusing to remove a QA profile that is not an OpenVPN VPN")
    # This UUID-scoped cleanup is the ONLY connection mutation this script permits.
    down = command(["nmcli", "--wait", "5", "connection", "down", "uuid", uuid])
    # It is legitimate for the connection to be inactive. A failure to down an
    # actually active QA tunnel must not be silently treated as success.
    active = command(["nmcli", "--wait", "5", "-t", "-f", "UUID",
                      "connection", "show", "--active"])
    if active.returncode or uuid in active.stdout.decode(errors="replace").lower().splitlines():
        raise RollbackError("Unable to confirm QA tunnel is inactive")
    deleted = command(["nmcli", "--wait", "5", "connection", "delete", "uuid", uuid])
    if deleted.returncode or get_profile_name(uuid) is not None:
        raise RollbackError("QA profile deletion could not be verified")
    artifacts_removed = cleanup_import_artifacts(
        artifact_stem, certificate_directory, artifact_hashes)
    return {"ok": True, "alreadyAbsent": False, "profileRemoved": True,
            "certificateArtifactsRemoved": artifacts_removed}


def durable_rollback_helper():
    """Pin a byte-identical cleanup script outside ephemeral AppImage mounts."""
    data_root = Path(os.environ.get("XDG_DATA_HOME") or
                     str(Path.home() / ".local" / "share"))
    if not data_root.is_absolute():
        raise RollbackError("Rollback storage must be an absolute user data path")
    parent = data_root / "OpenInternetGateway"
    folder = parent / "qa-rollback"
    if any(item.is_symlink() for item in (data_root, parent, folder)):
        raise RollbackError("Rollback helper storage cannot use symlinked directories")
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (folder.stat().st_mode & 0o077) or not folder.is_dir():
        raise RollbackError("Rollback helper directory must be private (0700)")
    payload = Path(__file__).read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    target = folder / ("cleanup-" + digest + ".py")
    if target.is_symlink() or (target.exists() and
                               (not target.is_file() or target.stat().st_nlink != 1)):
        raise RollbackError("Rollback helper must be a private regular file")
    if target.exists():
        if target.read_bytes() != payload:
            raise RollbackError("Existing rollback helper contents changed")
    else:
        fd, temp = tempfile.mkstemp(prefix=".oig-rollback-", dir=str(folder))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, target)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
    if target.stat().st_mode & 0o077:
        raise RollbackError("Rollback helper must have private permissions")
    return str(target)


def arm(uuid, name, seconds, artifact_stem, certificate_directory, artifact_hashes):
    check_identity(uuid, name)
    if artifact_stem != name:
        raise RollbackError("Temporary certificate namespace does not match the QA profile")
    artifact_hashes = checked_artifact_hashes(artifact_hashes)
    checked_certificate_directory(certificate_directory)
    if not 10 <= seconds <= 300:
        raise RollbackError("Safety timer must be between 10 and 300 seconds")
    if get_profile_name(uuid) != name:
        raise RollbackError("Cannot arm rollback for a missing or unrelated QA profile")
    kind = command(["nmcli", "--wait", "5", "-g", "connection.type",
                    "connection", "show", "uuid", uuid])
    if kind.returncode or kind.stdout.decode(errors="replace").strip() != "vpn":
        raise RollbackError("Cannot arm rollback for a profile that is not an OpenVPN VPN")
    active = command(["nmcli", "--wait", "5", "-t", "-f", "UUID",
                      "connection", "show", "--active"])
    if active.returncode or uuid in active.stdout.decode(errors="replace").lower().splitlines():
        raise RollbackError("Refusing to arm a trial timer for a connection that is already active")
    # Timer payload MUST survive exit/crash/unmount of the AppImage process.
    # Fail closed before registration or VPN activation if it cannot be pinned.
    runner = durable_rollback_helper()
    unit = "oig-operator-qa-" + name[-12:]
    proc = command(["systemd-run", "--user", "--quiet", "--collect",
                    "--unit=" + unit, "--on-active=" + str(seconds) + "s",
                    "--timer-property=AccuracySec=1s",
                    "--timer-property=RandomizedDelaySec=0",
                    "--property=TimeoutStartSec=30",
                    "--setenv=XDG_DATA_HOME=" + str(Path(os.environ.get(
                        "XDG_DATA_HOME") or (Path.home() / ".local" / "share"))),
                    sys.executable, "-B", runner, "cleanup",
                    "--uuid", uuid, "--name", name,
                    "--artifact-stem", artifact_stem,
                    "--certificate-directory", str(certificate_directory),
                    "--ca-sha256", artifact_hashes["ca"],
                    "--cert-sha256", artifact_hashes["cert"],
                    "--key-sha256", artifact_hashes["key"]], timeout=10)
    if proc.returncode:
        raise RollbackError("Failed to schedule an independent rollback timer")
    active = command(["systemctl", "--user", "is-active", unit + ".timer"], timeout=8)
    if active.returncode or active.stdout.decode(errors="replace").strip() != "active":
        raise RollbackError("Independent rollback timer is not confirmed active")
    return {"ok": True, "timerArmed": True, "unit": unit + ".timer",
            "deadlineSeconds": seconds, "connectionActivated": False}


def main():
    parser = argparse.ArgumentParser(description="UUID-scoped OpenVPN QA rollback")
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("cleanup", "arm"):
        p = sub.add_parser(action)
        p.add_argument("--uuid", required=True)
        p.add_argument("--name", required=True)
        p.add_argument("--artifact-stem", required=True)
        p.add_argument("--certificate-directory", required=True)
        p.add_argument("--ca-sha256", required=True)
        p.add_argument("--cert-sha256", required=True)
        p.add_argument("--key-sha256", required=True)
        if action == "arm":
            p.add_argument("--seconds", type=int, default=90)
    args = parser.parse_args()
    try:
        hashes = {"ca": args.ca_sha256, "cert": args.cert_sha256, "key": args.key_sha256}
        result = (arm(args.uuid, args.name, args.seconds, args.artifact_stem,
                      args.certificate_directory, hashes) if args.action == "arm" else
                  cleanup(args.uuid, args.name, args.artifact_stem,
                          args.certificate_directory, hashes))
        print(json.dumps(result, separators=(",", ":")))
    except RollbackError as exc:
        print("REJECTED: " + str(exc), file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
