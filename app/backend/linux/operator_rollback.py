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
import subprocess
import sys
import tempfile
from pathlib import Path

UUID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z")
QA_NAME = re.compile(r"OIG-Operator-QA-[a-f0-9]{12}\Z")


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


def cleanup(uuid, name):
    check_identity(uuid, name)
    current = get_profile_name(uuid)
    if current is None:
        return {"ok": True, "alreadyAbsent": True, "profileRemoved": True}
    if current != name:
        raise RollbackError("Refusing to modify a profile with a different identity")
    # This UUID-scoped cleanup is the ONLY mutation this script permits.
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
    return {"ok": True, "alreadyAbsent": False, "profileRemoved": True}



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


def arm(uuid, name, seconds):
    check_identity(uuid, name)
    if not 10 <= seconds <= 300:
        raise RollbackError("Safety timer must be between 10 and 300 seconds")
    if get_profile_name(uuid) != name:
        raise RollbackError("Cannot arm rollback for a missing or unrelated QA profile")
    # Timer payload MUST survive exit/crash/unmount of the AppImage process.
    # Fail closed before registration or VPN activation if it cannot be pinned.
    runner = durable_rollback_helper()
    unit = "oig-operator-qa-" + name[-12:]
    proc = command(["systemd-run", "--user", "--quiet", "--collect",
                    "--unit=" + unit, "--on-active=" + str(seconds) + "s",
                    "--timer-property=AccuracySec=1s",
                    "--timer-property=RandomizedDelaySec=0",
                    "--property=TimeoutStartSec=30",
                    sys.executable, "-B", runner, "cleanup",
                    "--uuid", uuid, "--name", name], timeout=10)
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
        if action == "arm":
            p.add_argument("--seconds", type=int, default=90)
    args = parser.parse_args()
    try:
        result = arm(args.uuid, args.name, args.seconds) if args.action == "arm" else cleanup(args.uuid, args.name)
        print(json.dumps(result, separators=(",", ":")))
    except RollbackError as exc:
        print("REJECTED: " + str(exc), file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
