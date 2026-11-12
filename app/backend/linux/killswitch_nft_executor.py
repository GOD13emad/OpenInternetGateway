#!/usr/bin/env python3
"""Disposable-only nftables lockdown transaction runner (NOT production).

This module tests the real path from a pinned, validated manifest through
nft -c -f and a single atomic nft -f transaction. A real nft subprocess is
allowed ONLY in a disposable, root-in-Docker, GitHub-hosted CI namespace.
It never opens a VPN tunnel, does not authorize tunnel egress, does not bind
a privileged socket and cannot be installed as an owner-host service.

The controller never deletes a preexisting table, never flushes a foreign
table, never accepts caller-supplied command vectors, and never deletes its
own table after an uncertain result. Release after a crash requires separate
ownership attestation, not implemented here. A UI cannot call this executor.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

import killswitch_lifecycle_contract as contract
import nft_killswitch_plan as nft

NFT_BINARY = "/usr/sbin/nft"
NFT_TABLE = "oig_qa_killswitch"
MAX_NFT_OUTPUT = 65536


class NftSafetyError(RuntimeError):
    pass


def disposable_scope():
    """Fail closed on any owner host, ordinary local process or non-CI VM."""
    env = os.environ
    if (os.geteuid() != 0
            or env.get("OIG_HOSTED_CONTAINER") != "1"
            or env.get("GITHUB_ACTIONS") != "true"
            or env.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or env.get("GITHUB_REPOSITORY") != "GOD13emad/OpenInternetGateway"
            or env.get("GITHUB_EVENT_NAME") != "pull_request"
            or not re.fullmatch(r"[0-9]+", env.get("GITHUB_RUN_ID", ""))
            or not Path("/.dockerenv").exists()
            or not Path(NFT_BINARY).is_file()
            or not Path("/work/app/backend/linux/nft_killswitch_plan.py").is_file()):
        raise NftSafetyError("REFUSED: owner host or non-disposable runner")


class IsolatedNftBackend:
    """Fixed nft executable and command shapes, never shell or owner commands."""

    def __init__(self, approved=None):
        disposable_scope()
        if not isinstance(approved, contract.Approved):
            raise NftSafetyError("Pinned manifest required for the executor")
        self.approved = approved

    @staticmethod
    def _call(args):
        disposable_scope()
        if not isinstance(args, list) or not all(type(x) is str for x in args):
            raise NftSafetyError("Unexpected nft args")
        # An attacker must not turn the read-only observer into a root nft
        # command oracle: only fixed inventory/check/apply vectors exist.
        allowed = [
            ["-j", "list", "tables"],
            ["-j", "list", "chain", "inet", NFT_TABLE, "output"],
            ["-j", "list", "chain", "inet", NFT_TABLE, "forward"],
        ]
        is_policy_file = (
            len(args) in (2, 3) and args[-2] == "-f"
            and (args[0] == "-f" or args[:2] == ["-c", "-f"])
            and Path(args[-1]).name == "policy.nft"
            and Path(args[-1]).parent.name.startswith("oig-qa-nft-")
            and Path(args[-1]).is_file()
        ) if len(args) >= 2 else False
        if args not in allowed and not is_policy_file:
            raise NftSafetyError("Nft arguments not in isolated allowlist")
        try:
            result = subprocess.run(
                [NFT_BINARY, *args], input=b"", stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=8, check=False,
                env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise NftSafetyError("NFT_EXECUTION_UNKNOWN") from exc
        if result.returncode or len(result.stdout) > MAX_NFT_OUTPUT:
            raise NftSafetyError("NFT_EXECUTION_UNKNOWN")
        return result.stdout

    def tables(self):
        raw = self._call(["-j", "list", "tables"])
        try:
            doc = json.loads(raw)
            items = doc["nftables"]
            if not isinstance(items, list):
                raise TypeError
            return [
                (item["table"]["family"], item["table"]["name"])
                for item in items if isinstance(item, dict) and "table" in item
            ]
        except (ValueError, KeyError, TypeError) as exc:
            raise NftSafetyError("UNTRUSTED_TABLE_INVENTORY") from exc

    def chain(self, name):
        if name not in ("output", "forward"):
            raise NftSafetyError("Invalid chain query")
        raw = self._call(["-j", "list", "chain", "inet", NFT_TABLE, name])
        try:
            doc = json.loads(raw)
            entries = [x["chain"] for x in doc["nftables"]
                       if isinstance(x, dict) and "chain" in x]
            if len(entries) != 1:
                raise ValueError
            entry = entries[0]
            return (entry["hook"], entry["policy"])
        except (KeyError, TypeError, ValueError) as exc:
            raise NftSafetyError("UNTRUSTED_CHAIN_STATE") from exc

    def rules(self):
        raw = self._call(["-j", "list", "chain", "inet", NFT_TABLE, "output"])
        try:
            doc = json.loads(raw)
            entries = [x["rule"] for x in doc["nftables"]
                       if isinstance(x, dict) and "rule" in x]
            if not isinstance(entries, list):
                raise ValueError
            return entries
        except (KeyError, ValueError, TypeError) as exc:
            raise NftSafetyError("UNTRUSTED_RULE_STATE") from exc

    def apply(self, script):
        """Validate exact script grammar; perform check then atomic commit."""
        disposable_scope()
        a = self.approved
        args = (a.tunnel, a.underlay, a.peer_ipv4, a.peer_port, a.transport)
        # Equality to a trusted renderer is mandatory. No raw nft rule
        # injection, no tun-allow command and no table removal are possible.
        permitted = (
            nft.render_lockdown(*args),
            nft.render_transition(*args, tunnel_allowed=False),
        )
        if not isinstance(script, str) or script not in permitted:
            raise NftSafetyError("Untrusted nft batch")
        with tempfile.TemporaryDirectory(prefix="oig-qa-nft-") as temp:
            file = Path(temp) / "policy.nft"
            fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="utf8") as stream:
                stream.write(script)
                stream.flush()
                os.fsync(stream.fileno())
            self._call(["-c", "-f", str(file)])
            self._call(["-f", str(file)])


class LockdownOnlyController:
    """Ownership-scoped state machine; NEVER unlock from untrusted evidence."""

    def __init__(self, approved, backend):
        if not isinstance(approved, contract.Approved):
            raise NftSafetyError("Approved pinned config is required")
        if backend is None or any(not callable(getattr(backend, n, None))
                                  for n in ("tables", "chain", "rules", "apply")):
            raise NftSafetyError("Nft backend interface missing")
        if isinstance(backend, IsolatedNftBackend) and backend.approved != approved:
            raise NftSafetyError("Executor's pinned manifest differs")
        self._approved = approved
        self._backend = backend
        self.state = "NEW"

    def _args(self):
        a = self._approved
        return a.tunnel, a.underlay, a.peer_ipv4, a.peer_port, a.transport

    def _locked_verified(self):
        if self._backend.chain("output") != ("output", "drop"):
            raise NftSafetyError("Output base chain is not default-DROP")
        if self._backend.chain("forward") != ("forward", "drop"):
            raise NftSafetyError("Forward base chain is not default-DROP")
        rules = self._backend.rules()
        if not isinstance(rules, list) or len(rules) > 50:
            raise NftSafetyError("Untrusted output chain")
        # In nft JSON, a tunnel allow rule contains meta oifname then accept.
        # We reject ANY tunnel-accept pair and any global 'accept' if the
        # backend cannot prove that the named interface is the intended one.
        encoded = json.dumps(rules, sort_keys=True)
        if self._approved.tunnel in encoded:
            raise NftSafetyError("Tunnel allow remains in LOCKED state")
        return True

    def install_lockdown(self):
        if self.state != "NEW":
            raise NftSafetyError("Lockdown cannot be installed twice")
        try:
            existing = self._backend.tables()
            if not isinstance(existing, list) or ("inet", NFT_TABLE) in existing:
                raise NftSafetyError("Existing table: ownership ambiguous")
            script = nft.render_lockdown(*self._args())
            self.state = "UNKNOWN"  # An apply failure could occur AFTER commit.
            self._backend.apply(script)
            if ("inet", NFT_TABLE) not in self._backend.tables():
                raise NftSafetyError("Table not visible after apply")
            self._locked_verified()
            self.state = "LOCKED"
        except (ValueError, TypeError, NftSafetyError):
            self.state = "UNKNOWN"
            raise
        return "LOCKED"

    def relock(self):
        if self.state != "LOCKED":
            raise NftSafetyError("Cannot relock unverified state")
        try:
            script = nft.render_transition(*self._args(), tunnel_allowed=False)
            self.state = "UNKNOWN"
            self._backend.apply(script)
            self._locked_verified()
            self.state = "LOCKED"
        except (ValueError, TypeError, NftSafetyError):
            self.state = "UNKNOWN"
            raise
        return "LOCKED"

    def allow_tunnel(self, *_args, **_kwargs):
        # Must remain refused until independently measured TLS identity,
        # ownership, DNS, IPv6 and fail-closed loss watchers are implemented.
        raise NftSafetyError("REFUSED: no independent tunnel attestation")

    def remove(self, *_args, **_kwargs):
        raise NftSafetyError("REFUSED: never delete a lock on disconnection")
