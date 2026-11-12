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


def nft_argv_permitted(args, active_policy_file=None):
    """Pure exact-argv gate. A similarly named arbitrary file is not trusted."""
    read_only = (
        ["-j", "list", "tables"],
        ["-j", "list", "table", "inet", NFT_TABLE],
        ["-j", "list", "chain", "inet", NFT_TABLE, "output"],
        ["-j", "list", "chain", "inet", NFT_TABLE, "forward"],
    )
    if not isinstance(args, list) or not all(type(x) is str for x in args):
        return False
    if args in read_only:
        return True
    if (type(active_policy_file) is not str or
            not active_policy_file.startswith("/")):
        return False
    return args in (
        ["-c", "-f", active_policy_file],
        ["-f", active_policy_file],
    )


def verify_sole_lockdown_table(raw):
    """Reject extra chains/sets/maps/foreign rules in the disposable table.

    Merely checking output/forward chains would miss a malicious extra
    chain (possibly attached to a second hook) in the same table.
    This validation is limited to our disposable QA table and does not
    attest to all other host firewall tables.
    """
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_NFT_OUTPUT:
        raise NftSafetyError("UNTRUSTED_LOCKDOWN_TABLE_JSON")
    try:
        doc = json.loads(raw)
        if not isinstance(doc, dict) or not isinstance(doc.get("nftables"), list):
            raise ValueError("Missing NFT inventory")
        kind_counts = {"table": 0, "chain": 0, "rule": 0}
        chain_names = []
        rule_names = []
        for item in doc["nftables"]:
            if not isinstance(item, dict) or len(item) != 1:
                raise ValueError("Ambiguous NFT item")
            kind, data = next(iter(item.items()))
            if kind == "metainfo":
                continue
            if kind not in kind_counts or not isinstance(data, dict):
                raise ValueError("Unknown NFT object in owned table")
            if data.get("family") != "inet" or data.get("table", data.get("name")) != NFT_TABLE:
                raise ValueError("Wrong table identity")
            kind_counts[kind] += 1
            if kind == "table":
                if data.get("name") != NFT_TABLE:
                    raise ValueError("Wrong table name")
            elif kind == "chain":
                chain_names.append(data.get("name"))
            else:
                rule_names.append(data.get("chain"))
        if (kind_counts != {"table": 1, "chain": 2, "rule": 5}
                or set(chain_names) != {"output", "forward"}
                or chain_names.count("output") != 1 or chain_names.count("forward") != 1
                or rule_names.count("output") != 4
                or rule_names.count("forward") != 1):
            raise ValueError("Unexpected lockdown table contents")
    except (UnicodeError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise NftSafetyError("UNTRUSTED_LOCKDOWN_TABLE_JSON") from exc
    return True


class IsolatedNftBackend:
    """Fixed nft executable and command shapes, never shell or owner commands."""

    def __init__(self, approved=None):
        disposable_scope()
        if not isinstance(approved, contract.Approved):
            raise NftSafetyError("Pinned manifest required for the executor")
        self.approved = approved
        self._active_policy_file = None

    def _call(self, args):
        disposable_scope()
        if not nft_argv_permitted(args, self._active_policy_file):
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

    def verify_sole_table(self):
        raw = self._call(["-j", "list", "table", "inet", NFT_TABLE])
        return verify_sole_lockdown_table(raw)

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
            if (entry.get("family") != "inet" or entry.get("table") != NFT_TABLE
                    or entry.get("name") != name
                    or type(entry.get("prio")) is not int
                    or entry.get("type") != "filter"):
                raise ValueError
            return (entry["hook"], entry["policy"], entry["prio"])
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise NftSafetyError("UNTRUSTED_CHAIN_STATE") from exc

    def rules(self, name="output"):
        if name not in ("output", "forward"):
            raise NftSafetyError("Invalid rule chain")
        raw = self._call(["-j", "list", "chain", "inet", NFT_TABLE, name])
        try:
            doc = json.loads(raw)
            entries = [x["rule"] for x in doc["nftables"]
                       if isinstance(x, dict) and "rule" in x]
            if not entries or len(entries) > 16:
                raise ValueError
            if any(not isinstance(x, dict) or
                   x.get("family") != "inet" or x.get("table") != NFT_TABLE
                   or x.get("chain") != name for x in entries):
                raise ValueError
            return entries
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
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
            if self._active_policy_file is not None:
                raise NftSafetyError("Concurrent policy transaction refused")
            self._active_policy_file = str(file)
            try:
                self._call(["-c", "-f", str(file)])
                self._call(["-f", str(file)])
            finally:
                self._active_policy_file = None


def _match_expr(expr, category, field, value):
    """Narrow nft JSON comparison; other operators and wildcards are denied."""
    if not isinstance(expr, dict) or set(expr) != {"match"}:
        return False
    match = expr["match"]
    if not isinstance(match, dict) or set(match) != {"op", "left", "right"}:
        return False
    if match["op"] != "==" or type(match["right"]) is not type(value):
        return False
    left = match["left"]
    if not isinstance(left, dict) or set(left) != {category}:
        return False
    attr = left[category]
    if category == "meta":
        return isinstance(attr, dict) and attr == {"key": field} and match["right"] == value
    protocol, part = field
    return (isinstance(attr, dict)
            and attr == {"protocol": protocol, "field": part}
            and match["right"] == value)


def _accept_rule(rule, specs):
    expressions = rule.get("expr") if isinstance(rule, dict) else None
    if not isinstance(expressions, list) or len(expressions) != len(specs) + 1:
        return False
    if expressions[-1] != {"accept": None}:
        return False
    return all(_match_expr(expr, *spec) for expr, spec in zip(expressions, specs))


def _counter_drop(rule):
    expressions = rule.get("expr") if isinstance(rule, dict) else None
    if not isinstance(expressions, list) or len(expressions) != 2:
        return False
    count, verdict = expressions
    if not isinstance(count, dict) or set(count) != {"counter"}:
        return False
    data = count["counter"]
    return (isinstance(data, dict) and
            set(data) == {"packets", "bytes"} and
            all(type(data[key]) is int and data[key] >= 0 for key in ("packets", "bytes"))
            and verdict == {"drop": None})


def verify_locked_nft_rules(approved, output, forward):
    """Accept EXACTLY the rendered locked output/forward semantics.

    An extra ACCEPT anywhere, a wrong port, a changed priority, a missing
    DROP, masquerading, NAT, lookup, jump, goto or wildcard rejects. This
    is a narrow prototype verifier, not whole-device leak acceptance.
    """
    if not isinstance(approved, contract.Approved):
        raise NftSafetyError("Root-pinned manifest absent")
    if not isinstance(output, list) or not isinstance(forward, list):
        raise NftSafetyError("Nft rules must be lists")
    if len(output) != 4 or len(forward) != 1:
        raise NftSafetyError("Unexpected nft rule count")
    oif = lambda interface: [("meta", "oifname", interface)]
    nfproto = ("meta", "nfproto", "ipv4")
    ip_peer = ("payload", ("ip", "daddr"), approved.peer_ipv4)
    port = ("payload", (approved.transport, "dport"), approved.peer_port)
    dhcp_sport = ("payload", ("udp", "sport"), 68)
    dhcp_dport = ("payload", ("udp", "dport"), 67)
    # The real nft 1.1.6 kernel JSON canonicalizes away a redundant
    # explicit "meta nfproto ipv4" preceding an "ip daddr" predicate:
    # the IPv4 payload match itself constrains the family. Accept ONLY
    # these two equivalent, pinned forms (not a generic missing selector).
    peer_explicit = [nfproto, *oif(approved.underlay), ip_peer, port]
    peer_implicit = [*oif(approved.underlay), ip_peer, port]
    if (not _accept_rule(output[0], oif("lo"))
            or not (_accept_rule(output[1], peer_explicit)
                    or _accept_rule(output[1], peer_implicit))
            or not _accept_rule(output[2], [
                nfproto, *oif(approved.underlay), dhcp_sport, dhcp_dport
            ])):
        raise NftSafetyError("Output ACCEPT not exactly pinned")
    if not _counter_drop(output[3]) or not _counter_drop(forward[0]):
        raise NftSafetyError("Output or forward DROP missing")
    return True


class LockdownOnlyController:
    """Ownership-scoped state machine; NEVER unlock from untrusted evidence."""

    def __init__(self, approved, backend):
        if not isinstance(approved, contract.Approved):
            raise NftSafetyError("Approved pinned config is required")
        if backend is None or any(not callable(getattr(backend, n, None))
                                  for n in ("tables", "chain", "rules", "verify_sole_table", "apply")):
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
        self._backend.verify_sole_table()
        if self._backend.chain("output") != ("output", "drop", -150):
            raise NftSafetyError("Output base chain policy/priority changed")
        if self._backend.chain("forward") != ("forward", "drop", -150):
            raise NftSafetyError("Forward base chain policy/priority changed")
        return verify_locked_nft_rules(
            self._approved, self._backend.rules("output"),
            self._backend.rules("forward")
        )

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
