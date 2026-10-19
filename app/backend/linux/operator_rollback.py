#!/usr/bin/env python3
"""Independent user-session timer rollback for opt-in Linux operator VPN QA.

The CLI deliberately has no connect or route-changing action. It only arms a
one-shot timer, or cleans a uniquely named, explicitly scoped QA profile.
"""
import argparse
import json
import os
import re
import subprocess
import sys

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


def arm(uuid, name, seconds):
    check_identity(uuid, name)
    if not 10 <= seconds <= 300:
        raise RollbackError("Safety timer must be between 10 and 300 seconds")
    if get_profile_name(uuid) != name:
        raise RollbackError("Cannot arm rollback for a missing or unrelated QA profile")
    # Unit ID is derived only from the strictly validated randomized QA name.
    unit = "oig-operator-qa-" + name[-12:]
    proc = command(["systemd-run", "--user", "--quiet", "--collect",
                    "--unit=" + unit, "--on-active=" + str(seconds) + "s",
                    "--timer-property=AccuracySec=1s",
                    "--timer-property=RandomizedDelaySec=0",
                    "--property=TimeoutStartSec=30",
                    sys.executable, "-B", os.path.realpath(__file__), "cleanup",
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
