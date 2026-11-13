#!/usr/bin/env python3
"""Root boot-lockdown core against REAL nft kernel in disposable hosted Docker.

Not a boot service or production Kill Switch. Uses a dedicated TEST adapter
for the exact root boot policy, never relaxes installed-root-file validation
of NativeBootBackend, and only touches inet/oig_guard in disposable Docker.
It MUST refuse an owner host even if invoked by root or with a spoofed flag.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

BACKEND = Path(__file__).resolve().parents[1] / "backend/linux"
sys.path.insert(0, str(BACKEND))
import killswitch_bootstrap as boot
import killswitch_lifecycle_contract as contract
import killswitch_nft_executor as verifier
import nft_killswitch_plan as policy

RECEIPT = Path("/out/oig-hosted-root-boot-kernel.json")
APPROVED = contract.Approved(
    1001, "c1234567-1234-4234-8234-123456789abc",
    "tun99", "eth0", "1.1.1.1", 443, "tcp",
    "a" * 64, "server.example.com"
)


def scope_guard():
    if sys.argv[1:] != ["--isolated-docker-only"]:
        raise RuntimeError("REFUSED: owner host or non-disposable runner")
    try:
        verifier.disposable_scope()
    except verifier.NftSafetyError as exc:
        raise RuntimeError("REFUSED: owner host or non-disposable runner") from exc
    if (boot.TABLE != policy.BOOT_TABLE
            or boot.TABLE == verifier.NFT_TABLE
            or not RECEIPT.parent.is_dir()
            or RECEIPT.exists()):
        raise RuntimeError("REFUSED: untrusted disposable boot test scope")


def nft_command(args, *, approved_batch=None):
    """Never shell; batch argv must reference this transaction's exact file."""
    if type(args) is not list or not all(type(x) is str for x in args):
        raise RuntimeError("Untrusted nft argv")
    allowed_read = (
        ["-j", "list", "tables"],
        ["-j", "list", "table", "inet", boot.TABLE],
        ["-j", "list", "chain", "inet", boot.TABLE, "output"],
        ["-j", "list", "chain", "inet", boot.TABLE, "forward"],
    )
    permitted_batch = (
        ["-c", "-f", approved_batch],
        ["-f", approved_batch],
    ) if type(approved_batch) is str else ()
    if args not in allowed_read and args not in permitted_batch:
        raise RuntimeError("Unexpected nft kernel command")
    if args in permitted_batch:
        policy_file = Path(approved_batch)
        if (not policy_file.is_absolute()
                or not policy_file.parent.name.startswith(
                    "oig-disposable-root-boot-")
                or policy_file.name != "lockdown.nft"
                or not policy_file.is_file()
                or policy_file.is_symlink()
                or policy_file.stat().st_mode & 0o777 != 0o600
                or policy_file.stat().st_nlink != 1):
            raise RuntimeError("Untrusted nft file")
    proc = subprocess.run(
        [verifier.NFT_BINARY, *args], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8,
        env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        check=False
    )
    if proc.returncode or len(proc.stdout) > 65536 or len(proc.stderr) > 4096:
        raise RuntimeError("Disposable nft command failed: " +
                           proc.stderr.decode("utf8", "replace")[:300])
    return proc.stdout


def read_json(args):
    def unique_pairs(pairs):
        keys = [key for key, _ in pairs]
        if len(keys) != len(set(keys)):
            raise RuntimeError("Duplicate nft JSON keys")
        return dict(pairs)

    payload = json.loads(nft_command(args), object_pairs_hook=unique_pairs)
    if type(payload) is not dict or set(payload) != {"nftables"}:
        raise RuntimeError("Bad nft JSON")
    rows = payload["nftables"]
    if type(rows) is not list or len(rows) > 128:
        raise RuntimeError("Unbounded nft JSON")
    return rows


class DisposableBootBackend:
    def __init__(self):
        scope_guard()
        self.applies = 0

    def tables(self):
        return [(row["table"]["family"], row["table"]["name"])
                for row in read_json(["-j", "list", "tables"])
                if "table" in row]

    def verify_sole_table(self):
        document = nft_command(
            ["-j", "list", "table", "inet", boot.TABLE]
        )
        return verifier.verify_sole_lockdown_table(
            document, table_name=boot.TABLE
        )

    def chain(self, name):
        if name not in ("output", "forward"):
            raise RuntimeError("Untrusted chain")
        rows = [row["chain"] for row in read_json(
            ["-j", "list", "chain", "inet", boot.TABLE, name]
        ) if "chain" in row]
        if len(rows) != 1:
            raise RuntimeError("Unexpected chain cardinality")
        row = rows[0]
        if (row.get("family") != "inet" or row.get("table") != boot.TABLE
                or row.get("name") != name or row.get("type") != "filter"):
            raise RuntimeError("Wrong kernel chain")
        return row.get("hook"), row.get("policy"), row.get("prio")

    def rules(self, name):
        if name not in ("output", "forward"):
            raise RuntimeError("Untrusted rule chain")
        return [row["rule"] for row in read_json(
            ["-j", "list", "chain", "inet", boot.TABLE, name]
        ) if "rule" in row]

    def apply(self, script):
        assert self.applies == 0, "Bootstrap must never replay a transaction"
        expected = policy.render_lockdown(
            APPROVED.tunnel, APPROVED.underlay, APPROVED.peer_ipv4,
            APPROVED.peer_port, APPROVED.transport, table=boot.TABLE
        )
        if type(script) is not str or script != expected:
            raise RuntimeError("Untrusted lockdown policy")
        with tempfile.TemporaryDirectory(
                prefix="oig-disposable-root-boot-") as folder:
            target = Path(folder) / "lockdown.nft"
            fd = os.open(
                target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
            with os.fdopen(fd, "w", encoding="utf8") as stream:
                stream.write(script)
                stream.flush()
                os.fsync(stream.fileno())
            nft_command(["-c", "-f", str(target)], approved_batch=str(target))
            nft_command(["-f", str(target)], approved_batch=str(target))
            self.applies += 1


def snapshot():
    def run_ip(args):
        proc = subprocess.run(
            ["/usr/sbin/ip", *args], capture_output=True,
            timeout=8, check=False
        )
        if proc.returncode or len(proc.stdout) > 65536:
            raise RuntimeError("Disposable route snapshot unavailable")
        return proc.stdout

    return tuple(hashlib.sha256(x).hexdigest() for x in (
        run_ip(["-4", "route", "show", "table", "all"]),
        run_ip(["-6", "route", "show", "table", "all"]),
        Path("/etc/resolv.conf").read_bytes()
    ))


def drop_count():
    rows = read_json(["-j", "list", "chain", "inet", boot.TABLE, "output"])
    drops = []
    for row in rows:
        data = row.get("rule", {})
        expr = data.get("expr", [])
        if any(isinstance(x, dict) and "drop" in x for x in expr):
            counters = [x["counter"] for x in expr
                        if isinstance(x, dict) and
                        isinstance(x.get("counter"), dict)]
            if len(counters) != 1 or type(counters[0].get("packets")) is not int:
                raise RuntimeError("Untrusted packet counter")
            drops.append(counters[0]["packets"])
    if len(drops) != 1:
        raise RuntimeError("Unexpected DROP counter cardinality")
    return drops[0]


def probe_dns():
    before = drop_count()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _ in range(8):
            try:
                sock.sendto(b"q", ("9.9.9.9", 53))
            except OSError:
                pass
    return drop_count() - before


def new_receipt():
    return {
        "schema": "oig-hosted-root-boot-kernel-v1",
        "pass": False,
        "isolatedDockerScopeVerified": False,
        "kernelInitialLockdownVerified": False,
        "kernelIdempotentRestartVerified": False,
        "kernelTableContentsVerified": False,
        "outputDefaultDropVerified": False,
        "forwardDefaultDropVerified": False,
        "physicalIpv4DnsDropDelta": 0,
        "isolatedOwnedTableRemoved": False,
        "containerRouteDnsBaselineRestored": False,
        "productionKillSwitchVerified": False,
        "bootPersistenceVerified": False,
        "installedRootServiceVerified": False,
        "realOpenVpnIdentityVerified": False,
        "physicalOwnerNetworkChanged": False,
    }


def main():
    try:
        scope_guard()
    except RuntimeError:
        raise SystemExit("REFUSED: owner host or non-disposable runner") from None

    result = new_receipt()
    result["isolatedDockerScopeVerified"] = True
    baseline = None
    backend = None
    stage = "SNAPSHOT"
    try:
        baseline = snapshot()
        stage = "NO_FOREIGN_BOOT_TABLE"
        backend = DisposableBootBackend()
        if ("inet", boot.TABLE) in backend.tables():
            raise RuntimeError("REFUSED: preexisting root boot table")
        stage = "BOOT_LOCKDOWN"
        first = boot.boot_lockdown_core(APPROVED, backend, policy, verifier, contract)
        result["kernelInitialLockdownVerified"] = first == "NEW_LOCKED"
        result["kernelTableContentsVerified"] = backend.verify_sole_table()
        stage = "KERNEL_DNS_DROP"
        result["physicalIpv4DnsDropDelta"] = probe_dns()
        stage = "IDEMPOTENT_BOOT_RESTART"
        restarted = boot.boot_lockdown_core(
            APPROVED, backend, policy, verifier, contract
        )
        result["kernelIdempotentRestartVerified"] = (
            restarted == "ALREADY_LOCKED" and backend.applies == 1
        )
        result["outputDefaultDropVerified"] = (
            backend.chain("output") == ("output", "drop", -150)
        )
        result["forwardDefaultDropVerified"] = (
            backend.chain("forward") == ("forward", "drop", -150)
        )
    except Exception as exc:
        result["failureStage"] = stage
        result["failureClass"] = type(exc).__name__
        result["failureDetail"] = str(exc)[:240]
    finally:
        # Only delete a table whose exact contents we independently verified,
        # in this disposable netns. Failure never authorizes destructive
        # reconciliation; Docker itself destroys the entire namespace.
        if (backend is not None
                and result["kernelTableContentsVerified"] is True
                and result["kernelInitialLockdownVerified"] is True
                and "failureClass" not in result):
            try:
                deletion = subprocess.run(
                    [verifier.NFT_BINARY, "delete", "table", "inet", boot.TABLE],
                    capture_output=True, timeout=8, check=False
                )
                result["isolatedOwnedTableRemoved"] = (
                    deletion.returncode == 0 and
                    ("inet", boot.TABLE) not in backend.tables()
                )
            except Exception as exc:
                result.setdefault("failureStage", "ISOLATED_TABLE_CLEANUP")
                result.setdefault("failureClass", type(exc).__name__)
        if baseline is not None:
            try:
                result["containerRouteDnsBaselineRestored"] = snapshot() == baseline
            except Exception as exc:
                result.setdefault("failureStage", "ISOLATED_ROUTE_DNS_POSTCHECK")
                result.setdefault("failureClass", type(exc).__name__)
        needed = (
            "isolatedDockerScopeVerified",
            "kernelInitialLockdownVerified",
            "kernelIdempotentRestartVerified",
            "kernelTableContentsVerified",
            "outputDefaultDropVerified",
            "forwardDefaultDropVerified",
            "isolatedOwnedTableRemoved",
            "containerRouteDnsBaselineRestored",
        )
        result["pass"] = (
            all(result[k] is True for k in needed) and
            type(result["physicalIpv4DnsDropDelta"]) is int and
            result["physicalIpv4DnsDropDelta"] >= 8 and
            "failureClass" not in result and
            all(result[k] is False for k in (
                "productionKillSwitchVerified", "bootPersistenceVerified",
                "installedRootServiceVerified", "realOpenVpnIdentityVerified",
                "physicalOwnerNetworkChanged",
            ))
        )
        fd = os.open(
            RECEIPT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(fd, "w", encoding="utf8") as stream:
            json.dump(result, stream, sort_keys=True)
            stream.write("\n")
        print("HOSTED_ROOT_BOOT_KERNEL_RECEIPT=" +
              json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
