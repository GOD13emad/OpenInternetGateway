#!/usr/bin/env python3
"""Actual nft executor acceptance ONLY in disposable GitHub Docker netns.

No user machine, host namespace, installed VPN, systemd service or release.
The test uses a dedicated inet table AFTER prior VPN tests and removes it
only on a fully verified safe-test path. A kernel veto or unknown mutation
is a FAIL; the disposable container is destroyed after the job.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend/linux"))
import killswitch_lifecycle_contract as contract
import killswitch_nft_executor as exe

RECEIPT = Path("/out/oig-hosted-nft-executor.json")
APPROVED = contract.Approved(
    1001, "c1234567-1234-4234-8234-123456789abc",
    "tun99", "eth0", "1.1.1.1", 443, "tcp",
    "a" * 64, "server.example.com"
)


def command(args):
    completed = subprocess.run(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=8, check=False
    )
    if completed.returncode or len(completed.stdout) > 65536:
        raise RuntimeError("ISOLATED_READONLY_PROBE_FAILED")
    return completed.stdout


def snapshot():
    # Only private container's interfaces, routes, and DNS are observed.
    inputs = (
        command(["/usr/sbin/ip", "-4", "route", "show", "table", "all"]),
        command(["/usr/sbin/ip", "-6", "route", "show", "table", "all"]),
        Path("/etc/resolv.conf").read_bytes(),
    )
    return tuple(hashlib.sha256(x).hexdigest() for x in inputs)


def drop_count():
    raw = command([exe.NFT_BINARY, "-j", "list", "chain", "inet",
                   exe.NFT_TABLE, "output"])
    doc = json.loads(raw)
    drops = []
    for row in doc.get("nftables", []):
        rule = row.get("rule", {}) if isinstance(row, dict) else {}
        expr = rule.get("expr", [])
        if not isinstance(expr, list):
            continue
        if any(isinstance(x, dict) and "drop" in x for x in expr):
            counters = [x["counter"] for x in expr
                        if isinstance(x, dict) and isinstance(x.get("counter"), dict)]
            if len(counters) == 1:
                drops.append(int(counters[0]["packets"]))
    if len(drops) != 1:
        raise RuntimeError("DROP_COUNTER_NOT_UNIQUE")
    return drops[0]


def dns_drop_probe():
    before = drop_count()
    denied = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _ in range(8):
            try:
                sock.sendto(b"\x00", ("9.9.9.9", 53))
            except PermissionError:
                denied += 1
    delta = drop_count() - before
    if delta < 8:
        raise RuntimeError("PHYSICAL_DNS_DROP_NOT_PROVEN")
    return denied, delta


def new_receipt():
    """All required gate fields exist even if the very first nft action fails."""
    return {
        "schema": "oig-hosted-nft-executor-v1",
        "pass": False,
        "productionKillSwitchVerified": False,
        "bootPersistenceVerified": False,
        "physicalHostNetworkChanged": False,
        "authorizedTunnelUnlockVerified": False,
        "forwardPacketProbeVerified": False,
        "physicalIPv6EgressProbeVerified": False,
        "initialKernelLockdownVerified": False,
        "initialDnsDropDelta": 0,
        "unverifiedTunnelRefused": False,
        "realKernelRelockVerified": False,
        "relockedDnsDropDelta": 0,
        "forwardPolicyDropVerified": False,
        "isolatedOwnedTableRemoved": False,
        "containerRouteDnsBaselineRestored": False,
    }


def finalize_receipt(out):
    """Fail closed after any partial result; retain original failure context."""
    required = (
        "initialKernelLockdownVerified",
        "unverifiedTunnelRefused",
        "realKernelRelockVerified",
        "forwardPolicyDropVerified",
        "isolatedOwnedTableRemoved",
        "containerRouteDnsBaselineRestored",
    )
    out["pass"] = (
        out["pass"] is True
        and all(out.get(k) is True for k in required)
        and type(out.get("initialDnsDropDelta")) is int
        and out["initialDnsDropDelta"] >= 8
        and type(out.get("relockedDnsDropDelta")) is int
        and out["relockedDnsDropDelta"] >= 8
        and "failureClass" not in out
        and out.get("schema") == "oig-hosted-nft-executor-v1"
        and all(out.get(k) is False for k in (
            "productionKillSwitchVerified", "bootPersistenceVerified",
            "physicalHostNetworkChanged", "authorizedTunnelUnlockVerified",
            "forwardPacketProbeVerified", "physicalIPv6EgressProbeVerified",
        ))
    )
    return out["pass"]


def cleanup_disposable_session(out, *, created, state, baseline,
                               snapshot_fn, remove_fn):
    """Record cleanup/restore failures without hiding the primary failure.

    All injected functions are for disposable QA only; no production caller
    is permitted. A missing or failed intermediate field can never PASS.
    """
    if created and state == "LOCKED" and out.get("pass") is True:
        try:
            out["isolatedOwnedTableRemoved"] = remove_fn() is True
        except Exception as exc:
            out.setdefault("failureStage", "ISOLATED_TABLE_CLEANUP")
            out.setdefault("failureClass", type(exc).__name__)
    if baseline is not None:
        try:
            out["containerRouteDnsBaselineRestored"] = snapshot_fn() == baseline
        except Exception as exc:
            out.setdefault("failureStage", "CONTAINER_NETWORK_RESTORE_CHECK")
            out.setdefault("failureClass", type(exc).__name__)
    # When the baseline could not be read, restoration cannot be claimed.
    return finalize_receipt(out)


def main():
    if sys.argv[1:] != ["--isolated-docker-only"]:
        raise SystemExit("REFUSED: owner host or non-disposable runner")
    try:
        exe.disposable_scope()
    except exe.NftSafetyError:
        raise SystemExit("REFUSED: owner host or non-disposable runner") from None

    if RECEIPT.exists():
        raise SystemExit("REFUSED: existing nft executor receipt")
    out = new_receipt()
    baseline = None
    ctl = None
    created = False
    stage = "BASELINE_SNAPSHOT"
    try:
        baseline = snapshot()
        stage = "ISOLATED_EXECUTOR_PREFLIGHT"
        backend = exe.IsolatedNftBackend(APPROVED)
        if ("inet", exe.NFT_TABLE) in backend.tables():
            raise exe.NftSafetyError("Existing nft table: ownership ambiguous")
        ctl = exe.LockdownOnlyController(APPROVED, backend)
        stage = "LOCKDOWN_INSTALL"
        ctl.install_lockdown()
        created = True
        out["initialKernelLockdownVerified"] = ctl.state == "LOCKED"
        stage = "INITIAL_PHYSICAL_DNS_DROP"
        _, first_drop = dns_drop_probe()
        out["initialDnsDropDelta"] = first_drop

        stage = "UNVERIFIED_TUNNEL_UNLOCK_DENIAL"
        try:
            ctl.allow_tunnel({"source": "untrusted-app", "authenticated": True})
        except exe.NftSafetyError:
            out["unverifiedTunnelRefused"] = True
        else:
            raise RuntimeError("UNVERIFIED_TUNNEL_ALLOWED")

        stage = "ATOMIC_RELOCK"
        ctl.relock()
        out["realKernelRelockVerified"] = ctl.state == "LOCKED"
        _, second_drop = dns_drop_probe()
        out["relockedDnsDropDelta"] = second_drop
        out["forwardPolicyDropVerified"] = (
            backend.chain("forward") == ("forward", "drop", -150)
        )
        out["pass"] = (out["initialKernelLockdownVerified"]
                       and out["unverifiedTunnelRefused"]
                       and out["realKernelRelockVerified"]
                       and out["forwardPolicyDropVerified"])
    except Exception as exc:
        out["failureStage"] = stage
        out["failureClass"] = type(exc).__name__
    finally:
        # No deletion in an unknown state: the disposable namespace itself
        # is destroyed when this CI job ends.
        def remove_verified_test_table():
            deletion = subprocess.run(
                [exe.NFT_BINARY, "delete", "table", "inet", exe.NFT_TABLE],
                capture_output=True, timeout=8, check=False
            )
            return deletion.returncode == 0

        cleanup_disposable_session(
            out, created=created,
            state=ctl.state if ctl is not None else "UNKNOWN",
            baseline=baseline, snapshot_fn=snapshot,
            remove_fn=remove_verified_test_table
        )
        fd = os.open(RECEIPT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf8") as target:
            json.dump(out, target, sort_keys=True)
            target.write("\n")
        print("HOSTED_NFT_LOCKDOWN_EXECUTOR_RECEIPT=" + json.dumps(out, sort_keys=True))
    return 0 if out["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
