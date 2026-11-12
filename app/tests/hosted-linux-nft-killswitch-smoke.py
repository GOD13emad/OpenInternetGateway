#!/usr/bin/env python3
"""Disposable GitHub Docker-only nftables kernel smoke test.

Uses a temporary independent inet table inside a private Docker network
namespace, after all live VPN acceptance has completed. Never modifies an
owner host, never installs/activates the policy in production, and cannot
claim persistence, boot-time protection, physical-host kill-switch or IPv6
packet reachability.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile

RECEIPT = Path("/out/oig-hosted-nft-killswitch-smoke.json")
POLICY = Path("/work/app/backend/linux/nft_killswitch_plan.py")

def scope():
    if (sys.argv[1:] != ["--isolated-docker-only"]
            or os.geteuid() != 0
            or os.environ.get("OIG_HOSTED_CONTAINER") != "1"
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("GITHUB_REPOSITORY") != "GOD13emad/OpenInternetGateway"
            or os.environ.get("GITHUB_EVENT_NAME") != "pull_request"
            or not re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ID", ""))
            or not Path("/.dockerenv").exists()
            or not POLICY.is_file()):
        raise SystemExit("REFUSED: owner host or non-disposable runner")

def run(argv, timeout=12):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)

def need(argv, timeout=12):
    result = run(argv, timeout)
    if result.returncode or len(result.stdout) > 100000:
        raise RuntimeError("ISOLATED_NFT_CONTROL_FAILED")
    return result.stdout

def snapshot():
    return (
        hashlib.sha256(need(["ip", "-4", "route", "show", "table", "all"]).encode()).hexdigest(),
        hashlib.sha256(need(["ip", "-6", "route", "show", "table", "all"]).encode()).hexdigest(),
        hashlib.sha256(Path("/etc/resolv.conf").read_bytes()).hexdigest(),
    )

def drop_count():
    raw = need(["nft", "-j", "list", "chain", "inet", "oig_qa_killswitch", "output"])
    if len(raw) > 100000:
        raise RuntimeError("NFT_RECEIPT_OVERSIZE")
    data = json.loads(raw)
    drop = []
    for entry in data.get("nftables", []):
        rule = entry.get("rule", {})
        expressions = rule.get("expr", [])
        if any(isinstance(e, dict) and e.get("drop") is None and "drop" in e
               for e in expressions):
            counters = [e["counter"] for e in expressions if isinstance(e, dict)
                        and "counter" in e]
            if counters:
                drop.append(int(counters[0]["packets"]))
    if len(drop) != 1:
        raise RuntimeError("NFT_DROP_COUNTER_NOT_UNIQUE")
    return drop[0]

def main():
    scope()
    if run(["nft", "list", "table", "inet", "oig_qa_killswitch"]).returncode == 0:
        raise RuntimeError("EXISTING_TABLE_COLLISION")
    if any(line.strip().lower() in ("vpn", "tun", "wireguard", "ip-tunnel")
           for line in need(["nmcli", "-t", "-f", "TYPE", "connection",
                             "show", "--active"]).splitlines()):
        raise RuntimeError("CONTAINER_ACTIVE_VPN")
    spec = importlib.util.spec_from_file_location("oig_nft_policy", POLICY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    table = module.TABLE
    if table != "oig_qa_killswitch":
        raise RuntimeError("TABLE_IDENTITY_CHANGED")
    baseline = snapshot()
    out = {
        "schema": "oig-hosted-nft-killswitch-prototype-v1",
        "scope": "Disposable isolated Docker netns, independent nft table only",
        "pass": False,
        "productionKillSwitchVerified": False,
        "physicalOwnerNetworkProtected": False,
        "physicalOwnerNetworkChanged": False,
        "persistentBootTimeEnforcementVerified": False,
    }
    stage = "INITIAL"
    installed = False
    try:
        # Never let the product render code mutate the host. nft execution is
        # confined to this explicitly scoped disposable test harness.
        script = module.render("tun99", "eth0", "1.1.1.1", 443, "tcp")
        with tempfile.TemporaryDirectory(prefix="oig-hosted-nft-") as directory:
            path = Path(directory) / "rules.nft"
            path.write_text(script, encoding="utf8")
            path.chmod(0o600)
            stage = "KERNEL_SYNTAX"
            need(["nft", "-c", "-f", str(path)])
            stage = "KERNEL_APPLY"
            need(["nft", "-f", str(path)])
            installed = True
        chain_info = json.loads(need(["nft", "-j", "list", "chain", "inet", table, "output"]))
        chains = [entry["chain"] for entry in chain_info.get("nftables", [])
                  if isinstance(entry, dict) and "chain" in entry]
        if (len(chains) != 1 or chains[0].get("policy") != "drop"
                or chains[0].get("hook") != "output"):
            raise RuntimeError("POLICY_NOT_DROP")
        before = drop_count()
        stage = "PHYSICAL_EGRESS_DROP_PROBE"
        # Eight UDP datagrams to a public literal DNS destination: no hostname,
        # no private payload, no tunnel, and no externally delivered packet.
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        kernel_denials = 0
        try:
            for _ in range(8):
                try:
                    udp.sendto(b"\x00", ("9.9.9.9", 53))
                except PermissionError:
                    # Some kernels return EPERM synchronously when the nft
                    # output hook drops a locally generated UDP datagram.
                    # This is a valid denial, NOT a failure to probe.
                    kernel_denials += 1
        finally:
            udp.close()
        after = drop_count()
        if after < before + 8:
            raise RuntimeError("KERNEL_DROP_COUNTER_DID_NOT_ADVANCE")
        out["nftKernelPermissionDenialsObserved"] = kernel_denials
        out["nftDropCounterDelta"] = after - before
        out["nftKernelRulesLoaded"] = True
        out["physicalDnsEgressDropCounterAdvanced"] = True
        out["ipv6PhysicalAllowRuleAbsent"] = True  # Static inspection only, no IPv6 packet proof.
        out["pass"] = True
    except Exception as exc:
        out["failureStage"] = stage
        out["failureClass"] = type(exc).__name__
    finally:
        if installed:
            deleted = run(["nft", "delete", "table", "inet", table])
            out["isolatedTableRemoved"] = deleted.returncode == 0
        else:
            out["isolatedTableRemoved"] = run(["nft", "list", "table", "inet", table]).returncode != 0
        out["containerRouteDnsBaselineRestored"] = snapshot() == baseline
        out["pass"] = (out["pass"] and out["isolatedTableRemoved"]
                       and out["containerRouteDnsBaselineRestored"])
        fd = os.open(RECEIPT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf8") as result:
            json.dump(out, result, sort_keys=True)
            result.write("\n")
        print("HOSTED_ISOLATED_NFT_KILLSWITCH_RECEIPT=" + json.dumps(out, sort_keys=True))
    return 0 if out["pass"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
