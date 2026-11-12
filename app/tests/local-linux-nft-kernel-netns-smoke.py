#!/usr/bin/env python3
"""Real nftables kernel lockdown test ONLY after native OS-approved netns isolation.

Invocation (on the Linux QA host):
  pkexec /usr/bin/unshare --net /usr/bin/python3 -B -I
    .../app/tests/local-linux-nft-kernel-netns-smoke.py --disposable-root-netns

The ONLY permitted changes are to a newly empty temporary NETWORK
namespace. It never edits host firewall, routes, DNS files, VPN, systemd,
or packages, and it installs no permanent helper. A successful receipt
proves only isolated synthetic-interface kernel behavior, not production
first-connect, boot persistence, or an actual OpenVPN tunnel.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile

BACKEND = Path(__file__).resolve().parents[1] / "backend/linux"
sys.path.insert(0, str(BACKEND))
import killswitch_lifecycle_contract as contract
import killswitch_nft_executor as nft_test
import nft_killswitch_plan as plan

IP = "/usr/sbin/ip"
NFT = "/usr/sbin/nft"
TEST_TABLE = "oig_qa_killswitch"
MANIFEST = contract.Approved(
    1001, "c1234567-1234-4234-8234-123456789abc",
    "tun7", "eth0", "1.1.1.1", 443, "tcp", "a" * 64, "server.example.com"
)
SCHEMA = "oig-isolated-netns-kernel-v1"
CLI_FLAG = "--disposable-root-netns"


def call(args, *, timeout=8, check=True):
    if not isinstance(args, list) or not all(type(x) is str for x in args):
        raise RuntimeError("UNSAFE_ARGV")
    if args[0] not in (IP, NFT, "/usr/sbin/sysctl"):
        raise RuntimeError("UNSAFE_EXECUTABLE")
    result = subprocess.run(
        args, input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=timeout, check=False, env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"
        }
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            "ISOLATED_COMMAND_FAILED: " + args[0] + " " + " ".join(args[1:4])
            + " exit " + str(result.returncode) + " "
            + result.stderr.decode("utf8", "replace")[-700:]
        )
    return result


def jlist(args):
    out = call([NFT, "-j", "list", *args]).stdout
    if not 0 < len(out) <= nft_test.MAX_NFT_OUTPUT:
        raise RuntimeError("UNTRUSTED_NFT_JSON_SIZE")
    value = json.loads(out)
    if not isinstance(value, dict) or not isinstance(value.get("nftables"), list):
        raise RuntimeError("UNTRUSTED_NFT_JSON")
    return value["nftables"]


def guarded_netns_only():
    """Prove new network namespace BEFORE executing a mutating command."""
    if sys.argv[1:] != [CLI_FLAG] or os.geteuid() != 0:
        raise RuntimeError("REFUSED: native OS-approved isolated namespace required")
    if not all(Path(x).is_file() for x in (IP, NFT, "/usr/sbin/sysctl")):
        raise RuntimeError("REFUSED: fixed Linux tools missing")
    current = os.stat("/proc/self/ns/net").st_ino
    host_pid1 = os.stat("/proc/1/ns/net").st_ino
    if current == host_pid1:
        raise RuntimeError("REFUSED: host network namespace")
    # Use netlink from the CURRENT namespace. A sysfs mount inherited
    # from another mount namespace can expose stale interface names.
    links = json.loads(call([IP, "-j", "link", "show"]).stdout)
    if not isinstance(links, list) or {
        item.get("ifname") for item in links if isinstance(item, dict)
    } != {"lo"}:
        raise RuntimeError("REFUSED: nonempty network namespace")
    if any("table" in entry for entry in jlist(["tables"])):
        raise RuntimeError("REFUSED: nonempty nft namespace")
    if call([IP, "-j", "route", "show"]).stdout.strip() not in (b"[]", b""):
        raise RuntimeError("REFUSED: existing IPv4 route")
    if call([IP, "-j", "-6", "route", "show"]).stdout.strip() not in (b"[]", b""):
        raise RuntimeError("REFUSED: existing IPv6 route")
    return current, host_pid1


class NamespaceNftBackend:
    """Independent adapter; NEVER disables the hosted-CI executor guard.

    Same interface consumed by the production-intended verifier/controller,
    but with an independent stronger precondition: the OS created an EMPTY
    disposable network namespace before this adapter can exist.
    """
    def __init__(self, manifest):
        if manifest != MANIFEST or not isinstance(manifest, contract.Approved):
            raise RuntimeError("REFUSED: changed test manifest")
        guarded_netns_only()  # This constructor runs before setup and nft.
        self.manifest = manifest
        self.active_file = None

    def tables(self):
        return [(x["table"]["family"], x["table"]["name"])
                for x in jlist(["tables"]) if "table" in x]

    def verify_sole_table(self):
        doc = json.dumps({"nftables": jlist(["table", "inet", TEST_TABLE])}).encode()
        return nft_test.verify_sole_lockdown_table(doc)

    def chain(self, name):
        if name not in ("output", "forward"):
            raise RuntimeError("Invalid chain")
        entries = [x["chain"] for x in jlist(
            ["chain", "inet", TEST_TABLE, name]) if "chain" in x]
        if len(entries) != 1:
            raise RuntimeError("Unexpected NFT chain cardinality")
        chain = entries[0]
        if chain.get("family") != "inet" or chain.get("table") != TEST_TABLE:
            raise RuntimeError("Wrong chain identity")
        return (chain.get("hook"), chain.get("policy"), chain.get("prio"))

    def rules(self, name="output"):
        if name not in ("output", "forward"):
            raise RuntimeError("Invalid rule chain")
        return [x["rule"] for x in jlist(
            ["chain", "inet", TEST_TABLE, name]) if "rule" in x]

    def apply(self, script):
        a = self.manifest
        args = (a.tunnel, a.underlay, a.peer_ipv4, a.peer_port, a.transport)
        if script not in (
            plan.render_lockdown(*args),
            plan.render_transition(*args, tunnel_allowed=False),
        ):
            raise RuntimeError("REFUSED: not an exact lockdown/relock policy")
        if self.active_file is not None:
            raise RuntimeError("REFUSED: concurrent nft transaction")
        with tempfile.TemporaryDirectory(prefix="oig-nft-netns-") as tmp:
            file = Path(tmp) / "policy.nft"
            fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="utf8") as stream:
                stream.write(script)
                stream.flush()
                os.fsync(stream.fileno())
            self.active_file = str(file)
            try:
                call([NFT, "-c", "-f", str(file)])
                call([NFT, "-f", str(file)])
            finally:
                self.active_file = None


def setup_synthetic_links():
    """Veth endpoints exist only in the already-proven empty namespace."""
    call([IP, "link", "set", "lo", "up"])
    call([IP, "link", "add", "eth0", "type", "veth",
          "peer", "name", "stub0"])
    call([IP, "link", "set", "eth0", "up"])
    call([IP, "link", "set", "stub0", "up"])
    call([IP, "addr", "add", "198.51.100.2/24", "dev", "eth0"])
    call([IP, "-4", "route", "add", "default", "dev", "eth0"])
    call([IP, "-6", "addr", "add", "2001:db8:1::2/64", "dev", "eth0"])
    call([IP, "-6", "route", "add", "default", "dev", "eth0"])
    call(["/usr/sbin/sysctl", "-w", "net.ipv4.ip_forward=1"])
    links = json.loads(call([IP, "-j", "link", "show"]).stdout)
    if not {"lo", "eth0", "stub0"}.issubset({
            item.get("ifname") for item in links if isinstance(item, dict)}):
        raise RuntimeError("SYNTHETIC_LINKS_MISSING")


def drop_packets(chain):
    rows = [x for x in jlist(["chain", "inet", TEST_TABLE, chain])
            if isinstance(x, dict) and "rule" in x]
    result = []
    for row in rows:
        expr = row["rule"].get("expr", [])
        if any(isinstance(x, dict) and "drop" in x for x in expr):
            counters = [x["counter"] for x in expr if isinstance(x, dict)
                        and isinstance(x.get("counter"), dict)]
            if len(counters) == 1:
                result.append(int(counters[0]["packets"]))
    if len(result) != 1:
        raise RuntimeError("NO_UNIQUE_KERNEL_DROP_COUNTER")
    return result[0]


def probe_local_v4():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _ in range(8):
            try:
                sock.sendto(b"Q", ("9.9.9.9", 53))
            except OSError:
                pass


def probe_local_v6():
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        for _ in range(8):
            try:
                sock.sendto(b"Q", ("2001:4860:4860::8888", 53))
            except OSError:
                pass


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack("!" + "H" * (len(data) // 2), data)
    value = sum(words)
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff


def probe_forwarded_v4():
    """Inject L2 frame from stub0 into eth0; must hit FORWARD, not OUTPUT."""
    def address(interface):
        details = json.loads(call([IP, "-j", "link", "show", "dev", interface]).stdout)
        if len(details) != 1 or details[0].get("ifname") != interface:
            raise RuntimeError("INVALID_NAMESPACE_INTERFACE")
        return bytes.fromhex(details[0]["address"].replace(":", ""))
    mac_dst = address("eth0")
    mac_src = address("stub0")
    src = ipaddress.IPv4Address("203.0.113.5").packed
    dst = ipaddress.IPv4Address("9.9.9.9").packed
    ipheader = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 1, 0,
                           64, 17, 0, src, dst)
    ipheader = ipheader[:10] + struct.pack("!H", checksum(ipheader)) + ipheader[12:]
    udp = struct.pack("!HHHH", 12345, 53, 8, 0)
    frame = mac_dst + mac_src + b"\x08\x00" + ipheader + udp
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                       socket.htons(0x0800)) as raw:
        raw.bind(("stub0", 0))
        for _ in range(8):
            raw.send(frame)


def probe_drop_counter(probe, chain):
    before = drop_packets(chain)
    probe()
    after = drop_packets(chain)
    return after - before


def main():
    receipt = {
        "schema": SCHEMA, "pass": False,
        "productionKillSwitchVerified": False,
        "ownerHostFirewallChanged": False,
        "ownerHostVpnChanged": False,
        "vpnAuthenticated": False,
        "bootPersistenceVerified": False,
        "authorizedTunnelUnlockVerified": False,
        "dnsOwnedByVpnVerified": False,
        "isolatedNetnsVerified": False,
        "kernelInitialLockdownVerified": False,
        "kernelAtomicRelockVerified": False,
        "forwardPolicyDropVerified": False,
        "initialV4DnsDropDelta": 0,
        "initialV6DnsDropDelta": 0,
        "initialForwardDropDelta": 0,
        "relockedV4DnsDropDelta": 0,
        "relockedV6DnsDropDelta": 0,
    }
    stage = "ISOLATED_PRECONDITIONS"
    try:
        current, pid1 = guarded_netns_only()
        receipt["isolatedNetnsVerified"] = current != pid1
        stage = "SYNTHETIC_LINK_SETUP"
        backend = NamespaceNftBackend(MANIFEST)
        setup_synthetic_links()
        stage = "INSTALL_LOCKDOWN"
        controller = nft_test.LockdownOnlyController(MANIFEST, backend)
        controller.install_lockdown()
        receipt["kernelInitialLockdownVerified"] = controller.state == "LOCKED"
        stage = "PROBE_INITIAL_DROPS"
        receipt["initialV4DnsDropDelta"] = probe_drop_counter(probe_local_v4, "output")
        receipt["initialV6DnsDropDelta"] = probe_drop_counter(probe_local_v6, "output")
        receipt["initialForwardDropDelta"] = probe_drop_counter(probe_forwarded_v4, "forward")
        receipt["forwardPolicyDropVerified"] = (
            backend.chain("forward") == ("forward", "drop", -150)
        )
        stage = "UNVERIFIED_UNLOCK_REFUSAL"
        try:
            controller.allow_tunnel({"authenticated": True})
        except nft_test.NftSafetyError:
            receipt["unverifiedTunnelUnlockDenied"] = True
        else:
            raise RuntimeError("UNVERIFIED_TUNNEL_UNLOCKED")
        stage = "ATOMIC_RELOCK"
        controller.relock()
        receipt["kernelAtomicRelockVerified"] = controller.state == "LOCKED"
        stage = "PROBE_RELOCKED_DROPS"
        receipt["relockedV4DnsDropDelta"] = probe_drop_counter(probe_local_v4, "output")
        receipt["relockedV6DnsDropDelta"] = probe_drop_counter(probe_local_v6, "output")
        receipt["pass"] = (
            receipt["isolatedNetnsVerified"]
            and receipt["kernelInitialLockdownVerified"]
            and receipt["kernelAtomicRelockVerified"]
            and receipt["forwardPolicyDropVerified"]
            and receipt["unverifiedTunnelUnlockDenied"]
            and all(type(receipt[k]) is int and receipt[k] >= 8 for k in (
                "initialV4DnsDropDelta", "initialV6DnsDropDelta",
                "initialForwardDropDelta", "relockedV4DnsDropDelta",
                "relockedV6DnsDropDelta"
            ))
        )
    except Exception as exc:
        receipt["failureStage"] = stage
        receipt["failureClass"] = type(exc).__name__
        receipt["failureDetail"] = str(exc)[:900]
        if receipt["isolatedNetnsVerified"] and stage == "INSTALL_LOCKDOWN":
            try:
                receipt["diagnosticKernelOutputRuleExpr"] = [
                    row["rule"]["expr"] for row in jlist(
                        ["chain", "inet", TEST_TABLE, "output"]
                    ) if isinstance(row, dict) and "rule" in row
                ]
                receipt["diagnosticKernelForwardRuleExpr"] = [
                    row["rule"]["expr"] for row in jlist(
                        ["chain", "inet", TEST_TABLE, "forward"]
                    ) if isinstance(row, dict) and "rule" in row
                ]
            except Exception:
                receipt["diagnosticKernelRuleReadbackUnavailable"] = True
    print("OIG_NATIVE_ISOLATED_NETNS_KERNEL_RECEIPT="
          + json.dumps(receipt, sort_keys=True), flush=True)
    return 0 if receipt["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
