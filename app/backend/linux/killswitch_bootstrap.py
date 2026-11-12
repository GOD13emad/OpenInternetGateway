#!/usr/bin/env python3
"""Opt-in root-owned OIG LOCKED-ONLY boot primitive; NOT installed or enabled.

This is a narrow first step toward fail-closed Linux startup, not an accepted
whole-device kill switch. The ordinary app must NEVER run it or invoke pkexec
for it. The OS-approved installer must later place a root-owned manifest and
root-owned executable, install the service plus explicit network-manager
ordering, and demonstrate failure/boot/restart coverage BEFORE enabling it.

Production invocation (only AFTER an independently approved installation):
  /usr/bin/python3 -I /opt/open-internet-gateway/resources/backend/linux/
      killswitch_bootstrap.py --bootstrap-lockdown

This helper NEVER allows tunnel egress, deletes any firewall table, changes
routes/DNS/NetworkManager, or installs a systemd unit. It creates only the
dedicated inet/oig_guard table, refuses colliding/ambiguous contents, and
verifies output/forward default-DROP and exact allowances after applying.
It will not accept a root-prompt under a user-owned source checkout.
"""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


INSTALLED_SCRIPT = Path(
    "/opt/open-internet-gateway/resources/backend/linux/killswitch_bootstrap.py"
)
MODULE_NAMES = (
    "nft_killswitch_plan.py",
    "killswitch_lifecycle_contract.py",
    "killswitch_nft_executor.py",
    "killswitch_bootstrap.py",
)
NFT = "/usr/sbin/nft"
TABLE = "oig_guard"
MAX_NFT_OUTPUT = 65536


class BootRefused(RuntimeError):
    pass


def _is_immutable_root_path(path, *, regular):
    """Refuse symlinks and any user/group-writable path component."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    expected = stat.S_ISREG if regular else stat.S_ISDIR
    return (expected(st.st_mode) and st.st_uid == 0
            and not (st.st_mode & 0o022)
            and (not regular or st.st_nlink == 1))


def validate_installed_root_runtime():
    """Before imports/network effects, validate exact root-owned install tree."""
    if os.geteuid() != 0 or Path(__file__).absolute() != INSTALLED_SCRIPT:
        raise BootRefused("REFUSED: not the trusted native root installation")
    parent = INSTALLED_SCRIPT.parent
    for entry in (Path("/"), Path("/opt"), Path("/opt/open-internet-gateway"),
                  Path("/opt/open-internet-gateway/resources"),
                  Path("/opt/open-internet-gateway/resources/backend"), parent):
        if not _is_immutable_root_path(entry, regular=False):
            raise BootRefused("REFUSED: writable or untrusted native code directory")
    for name in MODULE_NAMES:
        if not _is_immutable_root_path(parent / name, regular=True):
            raise BootRefused("REFUSED: mutable native security module")
    if not _is_immutable_root_path(NFT, regular=True):
        raise BootRefused("REFUSED: nft executable not root-owned")
    return parent


def _load_trusted_modules():
    parent = validate_installed_root_runtime()
    # -I removes script-dir from sys.path: add it only AFTER verifying every
    # root-owned source file and every ancestor. No PYTHONPATH is trusted.
    sys.path.insert(0, str(parent))
    import nft_killswitch_plan as policy
    import killswitch_lifecycle_contract as contract
    import killswitch_nft_executor as verifier
    if (policy.BOOT_TABLE != TABLE
            or policy.TABLE == TABLE
            or verifier.NFT_TABLE == TABLE):
        raise BootRefused("REFUSED: bootstrap and QA table names collide")
    return policy, contract, verifier


def boot_lockdown_core(approved, backend, policy, verifier, contract):
    """Pure state machine; tests inject a fake backend, never Root nft."""
    if not isinstance(approved, contract.Approved):
        raise BootRefused("Root-installed manifest approval required")
    expected = (
        approved.tunnel, approved.underlay, approved.peer_ipv4,
        approved.peer_port, approved.transport,
    )
    existing = backend.tables()
    if not isinstance(existing, list) or any(
            not isinstance(x, tuple) or len(x) != 2
            or not all(type(y) is str for y in x) for x in existing):
        raise BootRefused("Untrusted nft inventory")
    if ("inet", TABLE) not in existing:
        script = policy.render_lockdown(*expected, table=TABLE)
        # Failed/uncertain commit stays UNKNOWN. Never try a delete/retry
        # against a half-applied or potentially foreign table.
        backend.apply(script)
        if ("inet", TABLE) not in backend.tables():
            raise BootRefused("Boot lockdown not visible after transaction")
        result = "NEW_LOCKED"
    else:
        result = "ALREADY_LOCKED"
    # No unlock, reconciliation, automatic deletion or exception downgrade.
    backend.verify_sole_table()
    if backend.chain("output") != ("output", "drop", -150):
        raise BootRefused("Output chain is not fail-closed")
    if backend.chain("forward") != ("forward", "drop", -150):
        raise BootRefused("Forward chain is not fail-closed")
    verifier.verify_locked_nft_rules(
        approved, backend.rules("output"), backend.rules("forward")
    )
    return result


class NativeBootBackend:
    """Fixed-command root backend. Never open a tunnel or delete rules."""

    def __init__(self, approved, policy, verifier, contract):
        validate_installed_root_runtime()
        if not isinstance(approved, contract.Approved):
            raise BootRefused("Trusted approved config required")
        self.approved = approved
        self.policy = policy
        self.verifier = verifier
        self.active_batch = None

    def _run(self, argv):
        validate_installed_root_runtime()
        allowed_read = (
            ["-j", "list", "tables"],
            ["-j", "list", "table", "inet", TABLE],
            ["-j", "list", "chain", "inet", TABLE, "output"],
            ["-j", "list", "chain", "inet", TABLE, "forward"],
        )
        allowed_batch = (
            ["-c", "-f", self.active_batch],
            ["-f", self.active_batch],
        ) if self.active_batch is not None else ()
        if (type(argv) is not list or not all(type(x) is str for x in argv)
                or (argv not in allowed_read and argv not in allowed_batch)):
            raise BootRefused("REFUSED: nft argv not allowed")
        try:
            proc = subprocess.run(
                [NFT, *argv], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=8, check=False,
                env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BootRefused("Uncertain nft transaction") from exc
        if (proc.returncode != 0 or len(proc.stdout) > MAX_NFT_OUTPUT
                or len(proc.stderr) > 4096):
            raise BootRefused("Nft command failed or oversized")
        return proc.stdout

    def _inventory(self, argv):
        """Parse only nft JSON variants for our fixed read-only commands.

        Refuse duplicate JSON keys, unknown object families and misplaced
        rule/chain objects instead of silently dropping them. No nft command
        is executed until the separately checked _run boundary.
        """
        def unique_pairs(pairs):
            keys = [key for key, _ in pairs]
            if len(keys) != len(set(keys)):
                raise ValueError("Duplicate nft JSON keys")
            return dict(pairs)

        if argv == ["-j", "list", "tables"]:
            permitted = frozenset(("metainfo", "table"))
        elif argv in (
                ["-j", "list", "chain", "inet", TABLE, "output"],
                ["-j", "list", "chain", "inet", TABLE, "forward"]):
            permitted = frozenset(("metainfo", "chain", "rule"))
        else:
            raise BootRefused("Invalid nft inventory query")
        try:
            doc = json.loads(self._run(argv), object_pairs_hook=unique_pairs)
            if type(doc) is not dict or set(doc) != {"nftables"}:
                raise ValueError("Unexpected NFT document structure")
            rows = doc["nftables"]
            if type(rows) is not list or len(rows) > 128:
                raise ValueError("Unbounded NFT inventory")
            seen_meta = False
            for row in rows:
                if type(row) is not dict or len(row) != 1:
                    raise ValueError("Ambiguous NFT inventory row")
                kind, value = next(iter(row.items()))
                if kind not in permitted or type(value) is not dict:
                    raise ValueError("Unexpected NFT inventory object")
                if kind == "metainfo":
                    if seen_meta:
                        raise ValueError("Duplicate nft metadata")
                    seen_meta = True
            return rows
        except (ValueError, KeyError, TypeError, UnicodeError) as exc:
            raise BootRefused("Invalid nft JSON response") from exc

    def tables(self):
        found = []
        for row in self._inventory(["-j", "list", "tables"]):
            if "metainfo" in row:
                continue
            data = row["table"]
            # nft's documented JSON may include a numeric handle, flags
            # and a comment on table objects. Do not reject valid foreign
            # tables merely because they have a harmless handle.
            valid_keys = {"family", "name", "handle", "flags", "comment"}
            if (not {"family", "name"} <= set(data)
                    or not set(data) <= valid_keys
                    or type(data["family"]) is not str
                    or data["family"] not in (
                        "inet", "ip", "ip6", "arp", "bridge", "netdev")
                    or type(data["name"]) is not str
                    or not data["name"] or len(data["name"]) > 64
                    or ("handle" in data and
                        (type(data["handle"]) is not int or data["handle"] < 0))
                    or ("flags" in data and not (
                        data["flags"] in ("dormant", "owner", "persist")
                        if type(data["flags"]) is str
                        else (type(data["flags"]) is list
                              and all(type(x) is str and x in (
                                  "dormant", "owner", "persist"
                              ) for x in data["flags"]))))
                    or ("comment" in data and type(data["comment"]) is not str)):
                raise BootRefused("Untrusted nft table identity")
            identity = (data["family"], data["name"])
            if identity in found:
                raise BootRefused("Duplicate nft table identity")
            # A dormant (or process-owned) boot table DOES NOT guarantee
            # fail-closed packet filtering even with exact stored rules.
            # All boot-guard-specific flags must be absent or empty.
            if identity == ("inet", TABLE) and data.get("flags"):
                raise BootRefused("Boot table has unsafe flags")
            found.append(identity)
        return found

    def verify_sole_table(self):
        raw = self._run(["-j", "list", "table", "inet", TABLE])
        return self.verifier.verify_sole_lockdown_table(
            raw, table_name=TABLE
        )

    def chain(self, name):
        if name not in ("output", "forward"):
            raise BootRefused("Untrusted nft chain request")
        rows = [x["chain"] for x in self._inventory(
            ["-j", "list", "chain", "inet", TABLE, name])
            if isinstance(x, dict) and "chain" in x]
        if len(rows) != 1:
            raise BootRefused("Unexpected chain inventory")
        data = rows[0]
        if (data.get("family") != "inet"
                or data.get("table") != TABLE or data.get("name") != name
                or data.get("type") != "filter"
                or type(data.get("prio")) is not int):
            raise BootRefused("Invalid chain identity")
        return data.get("hook"), data.get("policy"), data["prio"]

    def rules(self, name):
        if name not in ("output", "forward"):
            raise BootRefused("Untrusted rule request")
        rows = [x["rule"] for x in self._inventory(
            ["-j", "list", "chain", "inet", TABLE, name])
            if isinstance(x, dict) and "rule" in x]
        if (len(rows) != (4 if name == "output" else 1)
                or any(x.get("family") != "inet" or x.get("table") != TABLE
                       or x.get("chain") != name for x in rows)):
            raise BootRefused("Invalid rule identity/cardinality")
        return rows

    def apply(self, script):
        approved = self.approved
        expected = self.policy.render_lockdown(
            approved.tunnel, approved.underlay, approved.peer_ipv4,
            approved.peer_port, approved.transport, table=TABLE
        )
        if type(script) is not str or script != expected:
            raise BootRefused("Refused non-lockdown nft batch")
        if self.active_batch is not None:
            raise BootRefused("Concurrent nft transaction refused")
        with tempfile.TemporaryDirectory(prefix="oig-root-lockdown-") as folder:
            path = Path(folder) / "lockdown.nft"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="utf8") as out:
                out.write(expected)
                out.flush()
                os.fsync(out.fileno())
            self.active_batch = str(path)
            try:
                self._run(["-c", "-f", str(path)])
                self._run(["-f", str(path)])
            finally:
                self.active_batch = None


def service_unit_preview():
    """Contract review only. The ordinary installer does NOT deploy this."""
    return """# REVIEW PREVIEW ONLY. DO NOT INSTALL OR ENABLE.
# NetworkManager must have a separate Requires/After drop-in before enabling,
# or a failed bootstrap will not stop NetworkManager from starting.
# Other network stacks and forced-disconnect events remain unverified.
[Unit]
Description=Open Internet Gateway opt-in root lockdown bootstrap (preview)
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target NetworkManager.service
Wants=network-pre.target

[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/bin/python3 -I /opt/open-internet-gateway/resources/backend/linux/killswitch_bootstrap.py --bootstrap-lockdown
RemainAfterExit=yes
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN
UMask=0077
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_NETLINK
RestrictNamespaces=true
LockPersonality=true
RestrictRealtime=true
SystemCallArchitectures=native
# No [Install] section until audited boot ordering and loss coverage.
"""


def networkmanager_dependency_preview():
    """REVIEW ONLY: no NetworkManager drop-in is installed by this project."""
    return """# REVIEW PREVIEW ONLY. DO NOT DEPLOY.
# An opt-in native installer must first independently attest full boot/loss
# coverage and have an owner-approved rollback/recovery method.
# If the root-locked startup service fails, do not start NetworkManager.
[Unit]
Requires=openinternetgateway-lockdown.service
After=openinternetgateway-lockdown.service
"""


def main(argv):
    if argv == ["--print-noninstallable-unit-preview"]:
        sys.stdout.write(service_unit_preview())
        return 0
    if argv == ["--print-noninstallable-nm-gate-preview"]:
        sys.stdout.write(networkmanager_dependency_preview())
        return 0
    if argv != ["--bootstrap-lockdown"]:
        raise BootRefused("REFUSED: unknown root bootstrap request")
    policy, contract, verifier = _load_trusted_modules()
    approved = contract.read_installed_root_manifest()
    backend = NativeBootBackend(approved, policy, verifier, contract)
    result = boot_lockdown_core(approved, backend, policy, verifier, contract)
    print("OIG_ROOT_BOOT_LOCKED_ONLY=" + result)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (BootRefused, RuntimeError, OSError, ValueError) as exc:
        print("OIG_ROOT_BOOTSTRAP_REFUSED:" + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1) from exc
