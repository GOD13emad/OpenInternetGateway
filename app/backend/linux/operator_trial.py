#!/usr/bin/env python3
"""Explicit, bounded Linux-only OpenVPN provider QA; never used by normal Connect.

Credentials arrive ONLY on stdin; password is passed to nmcli through an
anonymous memfd and never appears in argv, env, logs, Git or on-disk files.
The independent systemd timer is confirmed BEFORE any connection activation.
"""
import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import operator_profile
import operator_rollback

SAFE_USER = re.compile(r"[A-Za-z0-9._@+-]{1,96}\Z")


class TrialError(RuntimeError):
    pass


def checked(command, timeout=8, pass_fds=()):
    try:
        # Do not report subprocess stdout/stderr: provider plugins could log
        # confidential account information on failure.
        return subprocess.run(command, capture_output=True, timeout=timeout,
                              check=False, pass_fds=pass_fds,
                              env={**os.environ, "LC_ALL": "C", "LANG": "C"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TrialError("Bounded NetworkManager operation unavailable or timed out") from exc


def read_login():
    raw = sys.stdin.buffer.read(2049)
    if not raw or len(raw) > 2048:
        raise TrialError("Missing or oversized private credential input")
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise TrialError("Invalid credential input") from exc
    if not isinstance(data, dict) or set(data) != {"username", "password"}:
        raise TrialError("Credential input must have only username/password")
    username, password = data["username"], data["password"]
    if not isinstance(username, str) or not SAFE_USER.fullmatch(username):
        raise TrialError("Invalid provider username")
    if (not isinstance(password, str) or not 1 <= len(password) <= 256
            or any(ord(ch) < 32 or ord(ch) > 126 for ch in password)):
        raise TrialError("Invalid provider password format")
    return username, password


def inventory():
    try:
        return operator_profile._connection_uuids()
    except operator_profile.UnsafeProfile as exc:
        raise TrialError("Cannot check NetworkManager inventory") from exc


def config_is_scoped(uuid, username):
    p = checked(["nmcli", "-g",
                 "connection.autoconnect,ipv4.never-default,ipv6.never-default,"
                 "ipv4.ignore-auto-dns,ipv6.ignore-auto-dns,"
                 "ipv4.ignore-auto-routes,ipv6.ignore-auto-routes,vpn.user-name",
                 "connection", "show", "uuid", uuid])
    return p.returncode == 0 and p.stdout.decode(errors="replace").splitlines() == [
        "no", "yes", "yes", "yes", "yes", "yes", "yes", username
    ]


def import_qa(profile, ca_sha, peer_cn, folder):
    checked_profile, _, _ = operator_profile.load_and_check(profile, ca_sha, peer_cn)
    baseline = inventory()
    fresh_uuid = None
    ovpn = folder / "provider.ovpn"
    ovpn.write_bytes(checked_profile)
    ovpn.chmod(0o600)
    result = None
    try:
        result = checked(["nmcli", "--wait", "5", "connection", "import",
                          "--temporary", "type", "openvpn", "file", str(ovpn)])
    except TrialError:
        # A timed-out import can still leave a temporary NM profile behind.
        # Reconcile the UUID inventory rather than assuming no side effect.
        pass
    after = inventory()
    added = after - baseline
    returned_ids = set(x.lower() for x in re.findall(
        r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b",
        result.stdout.decode(errors="replace"))) if result else set()
    if len(added) == 1 and (not returned_ids or returned_ids == added):
        fresh_uuid = next(iter(added))
    elif len(returned_ids) == 1 and returned_ids <= added:
        fresh_uuid = next(iter(returned_ids))
    if fresh_uuid is None:
        raise TrialError("Import identity ambiguous; no existing profile modified")
    initial_name = checked(["nmcli", "-g", "connection.id", "connection", "show",
                            "uuid", fresh_uuid])
    imported_name = initial_name.stdout.decode(errors="replace").strip() if initial_name.returncode == 0 else ""
    return fresh_uuid, result is not None and result.returncode == 0, imported_name


def make_password_fd(password):
    if not hasattr(os, "memfd_create"):
        raise TrialError("Linux memory-only secret transport unsupported")
    fd = os.memfd_create("oig-transient-nm-secret", flags=getattr(os, "MFD_CLOEXEC", 1))
    try:
        value = ("vpn.secrets.password:" + password + "\n").encode("ascii")
        os.write(fd, value)
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def ensure_no_active_managed_gateway():
    active = checked(["nmcli", "-t", "-f", "NAME,TYPE", "connection",
                      "show", "--active"])
    if active.returncode:
        raise TrialError("Cannot verify active connections before a provider trial")
    # A saved desired-state=off is not sufficient evidence that an older
    # managed OpenVPN connection has actually gone down.
    managed = {"OIG-VPN-LIVE", "OIG-VPN-PREFLIGHT", "OIG-JP-UDP-LIVE",
               "OIG-Console-Gateway"}
    for line in active.stdout.decode(errors="replace").splitlines():
        # NM escapes colons in connection names; matching the entire
        # predictable project-owned prefix avoids third-party interfaces.
        if line.startswith(("OIG-VPN-LIVE:", "OIG-VPN-PREFLIGHT:",
                            "OIG-JP-UDP-LIVE:", "OIG-Console-Gateway:")):
            raise TrialError("A regular OpenInternetGateway connection is still active")


def trial(profile, ca_sha, peer_cn, seconds, hold):
    if not 30 <= seconds <= 180 or not 0 <= hold <= 15:
        raise TrialError("Unsupported bounded QA timer or hold interval")
    # The only invocation that can activate a VPN requires fresh stdin
    # credentials and a profile with independently trusted CA/name constraints.
    username, password = read_login()
    ensure_no_active_managed_gateway()
    # Validate before even registering the temporary NetworkManager profile.
    operator_profile.load_and_check(profile, ca_sha, peer_cn)
    before = inventory()
    uuid = None
    name = None
    imported_name = None
    armed = False
    removed = False
    outcome = "unverified"
    # Keep imported inline PEM source available until nmcli has fully exited.
    with tempfile.TemporaryDirectory(prefix="oig-trial-import-") as temp:
        folder = Path(temp)
        os.chmod(folder, 0o700)
        try:
            uuid, imported, imported_name = import_qa(profile, ca_sha, peer_cn, folder)
            if not imported:
                raise TrialError("NetworkManager importer failed after temporary profile creation")
            name = "OIG-Operator-QA-" + secrets.token_hex(6)
            changed = checked(["nmcli", "--wait", "5", "connection", "modify",
                               "--temporary", "uuid", uuid,
                               "connection.id", name,
                               "connection.autoconnect", "no",
                               "vpn.user-name", username,
                               "ipv4.never-default", "yes",
                               "ipv6.never-default", "yes",
                               "ipv4.ignore-auto-dns", "yes",
                               "ipv6.ignore-auto-dns", "yes",
                               "ipv4.ignore-auto-routes", "yes",
                               "ipv6.ignore-auto-routes", "yes"])
            if changed.returncode or not config_is_scoped(uuid, username):
                raise TrialError("Cannot verify scope of temporary QA connection")
            timer = operator_rollback.arm(uuid, name, seconds)
            armed = timer["timerArmed"]
            if not armed:
                raise TrialError("Independent QA cleanup timer is not active")
            fd = make_password_fd(password)
            password = ""  # best-effort reference drop (Python strings are immutable)
            try:
                activated = checked(["nmcli", "--wait", "25", "connection", "up",
                                     "uuid", uuid, "passwd-file", f"/proc/self/fd/{fd}"],
                                    timeout=30, pass_fds=(fd,))
                if activated.returncode != 0:
                    raise TrialError("Provider trial could not activate with supplied credentials")
                active = checked(["nmcli", "-t", "-f", "UUID",
                                  "connection", "show", "--active"])
                if active.returncode or uuid not in active.stdout.decode(errors="replace").lower().splitlines():
                    raise TrialError("Temporary QA connection is not confirmed active")
                outcome = "transport-active-unverified"
                if hold:
                    time.sleep(hold)
            finally:
                os.close(fd)
        finally:
            if uuid:
                try:
                    current = checked(["nmcli", "-g", "connection.id",
                                       "connection", "show", "uuid", uuid])
                    current_name = current.stdout.decode(errors="replace").strip() if current.returncode == 0 else None
                    if name and current_name == name:
                        removed = operator_rollback.cleanup(uuid, name)["profileRemoved"]
                    elif current_name == imported_name and uuid not in before:
                        # Still at the importer's original name: never invoke
                        # 'connection down' on this never-activated profile.
                        kind = checked(["nmcli", "-g", "connection.type",
                                        "connection", "show", "uuid", uuid])
                        active = checked(["nmcli", "-t", "-f", "UUID",
                                          "connection", "show", "--active"])
                        if kind.returncode or kind.stdout.decode().strip() != "vpn" or (
                            active.returncode or uuid in active.stdout.decode().lower().splitlines()
                        ):
                            raise TrialError("Unlabelled temporary VPN identity not safely removable")
                        gone = checked(["nmcli", "--wait", "5", "connection", "delete", "uuid", uuid])
                        removed = gone.returncode == 0 and uuid not in inventory()
                    elif current_name is None and uuid not in inventory():
                        removed = True
                    else:
                        raise TrialError("Temporary VPN identity changed unexpectedly")
                    if not removed:
                        raise TrialError("Temporary import cleanup could not be verified")
                    if name and armed:
                        checked(["systemctl", "--user", "stop",
                                 "oig-operator-qa-" + name[-12:] + ".timer"])
                except (operator_rollback.RollbackError, TrialError) as exc:
                    raise TrialError("Cleanup unverified; independent timer retained if armed") from exc
    if not removed or uuid in inventory() or uuid in before:
        raise TrialError("QA connection remains or inventory was not isolated")
    return {"ok": True, "trialTransport": outcome, "tempProfileRemoved": True,
            "independentTimerArmedBeforeActivation": armed,
            "liveTlsVerified": False, "identityVerifiedByApp": False,
            "fullDeviceTunnelVerified": False, "readyForAutomaticConnection": False}


def main():
    ap = argparse.ArgumentParser(description="Opt-in isolated Linux provider QA ONLY")
    ap.add_argument("action", choices=["trial"])
    ap.add_argument("--profile", type=Path, required=True)
    ap.add_argument("--ca-sha256", required=True)
    ap.add_argument("--peer-cn", required=True)
    ap.add_argument("--timer-seconds", type=int, default=90)
    ap.add_argument("--hold-seconds", type=int, default=0)
    args = ap.parse_args()
    try:
        answer = trial(args.profile, args.ca_sha256, args.peer_cn,
                       args.timer_seconds, args.hold_seconds)
        print(json.dumps(answer, separators=(",", ":")))
    except (TrialError, operator_profile.UnsafeProfile,
            operator_rollback.RollbackError, OSError, ValueError) as exc:
        # Never print login, password, untrusted provider config or nmcli output.
        print("REJECTED: " + str(exc), file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
