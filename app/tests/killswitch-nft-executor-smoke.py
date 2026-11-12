#!/usr/bin/env python3
"""Offline transaction/state regression; never executes nft on owner host."""
from pathlib import Path
import copy
import os
import runpy
import stat
import subprocess
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend/linux"))
import killswitch_lifecycle_contract as contract
import killswitch_nft_executor as executor


APPROVED = contract.Approved(
    1001, "c1234567-1234-4234-8234-123456789abc",
    "tun7", "eth0", "1.1.1.1", 443, "tcp",
    "a" * 64, "server.example.com"
)


def eq(category, key, right):
    if category == "meta":
        left = {"meta": {"key": key}}
    else:
        left = {"payload": {"protocol": key[0], "field": key[1]}}
    return {"match": {"op": "==", "left": left, "right": right}}


def sample_rules():
    return [
        {"expr": [eq("meta", "oifname", "lo"), {"accept": None}]},
        {"expr": [eq("meta", "nfproto", "ipv4"),
                  eq("meta", "oifname", "eth0"),
                  eq("payload", ("ip", "daddr"), "1.1.1.1"),
                  eq("payload", ("tcp", "dport"), 443),
                  {"accept": None}]},
        {"expr": [eq("meta", "nfproto", "ipv4"),
                  eq("meta", "oifname", "eth0"),
                  eq("payload", ("udp", "sport"), 68),
                  eq("payload", ("udp", "dport"), 67),
                  {"accept": None}]},
        {"expr": [{"counter": {"packets": 0, "bytes": 0}}, {"drop": None}]},
    ]


class FakeBackend:
    def __init__(self):
        self.exists = False
        self.output = ("output", "drop", -150)
        self.forward = ("forward", "drop", -150)
        self.allow_tunnel = False
        self.extra_accept = False
        self.wrong_peer = False
        self.wrong_port = False
        self.missing_drop = False
        self.fail = False
        self.scripts = []
        self.calls = []

    def tables(self):
        self.calls.append("tables")
        return [("inet", executor.NFT_TABLE)] if self.exists else []

    def chain(self, kind):
        self.calls.append("chain:" + kind)
        return {"output": self.output, "forward": self.forward}[kind]

    def rules(self, name="output"):
        self.calls.append("rules:" + name)
        if name == "forward":
            return [{"expr": [{"counter": {"packets": 0, "bytes": 0}},
                               {"drop": None}]}]
        values = sample_rules()
        if self.allow_tunnel:
            values[0] = {"expr": [eq("meta", "oifname", "tun7"), {"accept": None}]}
        if self.extra_accept:
            values.insert(0, {"expr": [{"accept": None}]})
        if self.wrong_peer:
            values[1]["expr"][2] = eq("payload", ("ip", "daddr"), "8.8.8.8")
        if self.wrong_port:
            values[1]["expr"][3] = eq("payload", ("tcp", "dport"), 80)
        if self.missing_drop:
            values.pop()
        return values

    def apply(self, script):
        self.calls.append("apply")
        self.scripts.append(script)
        if self.fail:
            raise executor.NftSafetyError("SIMULATED_COMMIT_UNKNOWN")
        if script.startswith("add table inet " + executor.NFT_TABLE):
            assert not self.exists
            self.exists = True
            self.allow_tunnel = False
        else:
            assert script.startswith("flush chain inet " + executor.NFT_TABLE + " output")
            self.allow_tunnel = False


def refuse(call, label):
    try:
        call()
    except executor.NftSafetyError:
        return
    raise AssertionError("FAIL_OPEN_" + label)


def isolated_nft_subprocess_simulation():
    """Exercise actual executor argv/file lifecycle without ever running nft.

    Both the scope guard AND subprocess are patched together; the host's
    firewall/kernel are never queried or modified by this test.
    """
    args = (APPROVED.tunnel, APPROVED.underlay,
            APPROVED.peer_ipv4, APPROVED.peer_port, APPROVED.transport)
    policy = executor.nft.render_lockdown(*args)
    observed = []

    def fake_kernel(command, **options):
        path = Path(command[-1])
        assert path.is_file()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.read_text() == policy
        assert command[0] == executor.NFT_BINARY
        assert options["timeout"] == 8
        assert options["check"] is False
        assert options["input"] == b""
        observed.append(tuple(command[1:]))
        return subprocess.CompletedProcess(command, 0, b"", b"")

    with (patch.object(executor, "disposable_scope"),
          patch.object(executor.subprocess, "run", side_effect=fake_kernel)):
        backend = executor.IsolatedNftBackend(APPROVED)
        backend.apply(policy)
        assert len(observed) == 2
        assert observed[0][:2] == ("-c", "-f")
        assert observed[1][0] == "-f"
        assert observed[0][-1] == observed[1][-1]
        assert backend._active_policy_file is None
        assert not Path(observed[0][-1]).exists(), "Temporary batch survived"
        refuse(lambda: backend._call([
            "-f", "/tmp/oig-qa-nft-fake/policy.nft"
        ]), "not_current_batch")
        refuse(lambda: backend.apply(
            executor.nft.render_transition(*args, tunnel_allowed=True)
        ), "tunnel_activation_without_attestation")
        assert len(observed) == 2, "Forbidden command reached subprocess"

    invoked = []

    def reject_check(command, **_options):
        invoked.append(tuple(command[1:]))
        return subprocess.CompletedProcess(command, 1, b"", b"error")

    with (patch.object(executor, "disposable_scope"),
          patch.object(executor.subprocess, "run", side_effect=reject_check)):
        backend = executor.IsolatedNftBackend(APPROVED)
        refuse(lambda: backend.apply(policy), "check_failure")
        assert len(invoked) == 1 and invoked[0][0:2] == ("-c", "-f")
        assert backend._active_policy_file is None
        assert not Path(invoked[0][-1]).exists()

    print("NFT_EXECUTOR_MOCKED_SUBPROCESS_ORDER_AND_0600_PASS")


def hosted_receipt_failure_regressions():
    """Run failure-path receipt logic, not a privileged nft action."""
    fixture = runpy.run_path(str(Path(__file__).with_name(
        "hosted-linux-nft-executor-smoke.py"
    )))
    new = fixture["new_receipt"]
    clean = fixture["cleanup_disposable_session"]
    baseline = ("route4", "route6", "dns")
    calls = []

    def remove_ok():
        calls.append("remove")
        return True

    def untouched():
        calls.append("snapshot")
        return baseline

    # First nft batch fails before any DNS counter exists. Must still emit
    # a negative receipt with the true first failure and no deletion.
    premature = new()
    premature["failureStage"] = "LOCKDOWN_INSTALL"
    premature["failureClass"] = "NftSafetyError"
    assert not clean(premature, created=False, state="UNKNOWN", baseline=baseline,
                     snapshot_fn=untouched, remove_fn=remove_ok)
    assert premature["initialDnsDropDelta"] == 0
    assert premature["relockedDnsDropDelta"] == 0
    assert premature["failureStage"] == "LOCKDOWN_INSTALL"
    assert calls == ["snapshot"], calls

    no_baseline = new()
    no_baseline["failureStage"] = "BASELINE_SNAPSHOT"
    no_baseline["failureClass"] = "RuntimeError"
    calls.clear()
    assert not clean(no_baseline, created=False, state="UNKNOWN", baseline=None,
                     snapshot_fn=lambda: calls.append("invalid_baseline_probe"),
                     remove_fn=remove_ok)
    assert calls == []
    assert no_baseline["containerRouteDnsBaselineRestored"] is False
    assert no_baseline["failureStage"] == "BASELINE_SNAPSHOT"

    good = new()
    good.update({
        "pass": True,
        "initialKernelLockdownVerified": True,
        "initialDnsDropDelta": 8,
        "unverifiedTunnelRefused": True,
        "realKernelRelockVerified": True,
        "relockedDnsDropDelta": 8,
        "forwardPolicyDropVerified": True,
    })
    calls.clear()
    clean(good, created=True, state="LOCKED", baseline=baseline,
          snapshot_fn=untouched, remove_fn=remove_ok)
    assert good["pass"] is True
    assert calls == ["remove", "snapshot"]

    def failed_remove():
        raise subprocess.TimeoutExpired("nft", 8)

    removed = copy.deepcopy(good)
    calls.clear()
    assert not clean(removed, created=True, state="LOCKED", baseline=baseline,
                     snapshot_fn=untouched, remove_fn=failed_remove)
    assert removed["failureClass"] == "TimeoutExpired"
    assert removed["failureStage"] == "ISOLATED_TABLE_CLEANUP"
    assert calls == ["snapshot"]

    def failed_snapshot():
        raise RuntimeError("ISOLATED_ROUTE_READ_FAILED")

    bad_snapshot = copy.deepcopy(good)
    assert not clean(bad_snapshot, created=True, state="LOCKED", baseline=baseline,
                     snapshot_fn=failed_snapshot, remove_fn=remove_ok)
    assert bad_snapshot["failureClass"] == "RuntimeError"
    assert bad_snapshot["failureStage"] == "CONTAINER_NETWORK_RESTORE_CHECK"

    no_cleanup = copy.deepcopy(good)
    assert not clean(no_cleanup, created=True, state="LOCKED", baseline=baseline,
                     snapshot_fn=untouched, remove_fn=lambda: False)
    assert no_cleanup["isolatedOwnedTableRemoved"] is False

    changed_network = copy.deepcopy(good)
    assert not clean(changed_network, created=True, state="LOCKED", baseline=baseline,
                     snapshot_fn=lambda: ("changed", "route6", "dns"),
                     remove_fn=remove_ok)
    assert changed_network["containerRouteDnsBaselineRestored"] is False

    claim_production = copy.deepcopy(good)
    claim_production["productionKillSwitchVerified"] = True
    assert not clean(claim_production, created=True, state="LOCKED", baseline=baseline,
                     snapshot_fn=untouched, remove_fn=remove_ok)

    forged_delta = copy.deepcopy(good)
    forged_delta["relockedDnsDropDelta"] = True  # bool is NOT an integer counter
    assert not clean(forged_delta, created=True, state="LOCKED", baseline=baseline,
                     snapshot_fn=untouched, remove_fn=remove_ok)

    not_accepted = copy.deepcopy(good)
    not_accepted.pop("initialDnsDropDelta")
    assert not clean(not_accepted, created=True, state="LOCKED", baseline=baseline,
                     snapshot_fn=untouched, remove_fn=remove_ok)

    print("NFT_EXECUTOR_HOSTED_RECEIPT_FAILURE_PATHS_PASS")


def main():
    a = FakeBackend()
    controller = executor.LockdownOnlyController(APPROVED, a)
    assert controller.install_lockdown() == "LOCKED"
    assert controller.state == "LOCKED"
    assert len(a.scripts) == 1
    assert "hook output priority -150; policy drop;" in a.scripts[0]
    assert "hook forward priority -150; policy drop;" in a.scripts[0]
    assert 'oifname "tun7" accept' not in a.scripts[0]
    assert controller.relock() == "LOCKED"
    assert len(a.scripts) == 2
    assert a.scripts[1].startswith("flush chain inet oig_qa_killswitch output")
    assert 'oifname "tun7" accept' not in a.scripts[1]
    refuse(controller.allow_tunnel, "unauthenticated_open")
    refuse(lambda: controller.allow_tunnel({"authenticated": True}), "forged_attestation")
    refuse(controller.remove, "remove_lock")
    refuse(controller.install_lockdown, "duplicate_install")
    assert controller.state == "LOCKED"

    collision = FakeBackend()
    collision.exists = True
    b = executor.LockdownOnlyController(APPROVED, collision)
    refuse(b.install_lockdown, "preexisting_table_collision")
    assert b.state == "UNKNOWN" and not collision.scripts
    refuse(b.relock, "recover_foreign_state")
    refuse(b.install_lockdown, "retry_unknown")

    failed = FakeBackend()
    failed.fail = True
    c = executor.LockdownOnlyController(APPROVED, failed)
    refuse(c.install_lockdown, "install_commit_unknown")
    assert c.state == "UNKNOWN"
    refuse(c.relock, "relock_after_unknown")

    broken = FakeBackend()
    broken.output = ("output", "accept", -150)
    d = executor.LockdownOnlyController(APPROVED, broken)
    refuse(d.install_lockdown, "unsafe_output_chain")
    assert d.state == "UNKNOWN" and broken.exists

    broken_forward = FakeBackend()
    broken_forward.forward = ("forward", "accept", -150)
    e = executor.LockdownOnlyController(APPROVED, broken_forward)
    refuse(e.install_lockdown, "unsafe_forward_chain")
    assert e.state == "UNKNOWN" and broken_forward.exists

    leftover = FakeBackend()
    z = executor.LockdownOnlyController(APPROVED, leftover)
    z.install_lockdown()
    leftover.allow_tunnel = True
    refuse(z._locked_verified, "tunnel_allow_detected")
    # Failed relock must never be reported as safely locked.
    leftover.fail = True
    refuse(z.relock, "relock_transaction_failed")
    assert z.state == "UNKNOWN"

    # Reject fail-open mutations even if the base chain still says DROP.
    for condition in ("extra_accept", "wrong_peer", "wrong_port", "missing_drop"):
        forged = FakeBackend()
        ctl = executor.LockdownOnlyController(APPROVED, forged)
        assert ctl.install_lockdown() == "LOCKED"
        setattr(forged, condition, True)
        refuse(ctl._locked_verified, "forged_" + condition)

    bad_priority = FakeBackend()
    bad_priority.output = ("output", "drop", 0)
    refuse(lambda: executor.LockdownOnlyController(
        APPROVED, bad_priority).install_lockdown(), "wrong_priority")

    # No extra accept, no missing forward drop, no partial four-rule match.
    good = sample_rules()
    forward = [{"expr": [{"counter": {"packets": 0, "bytes": 0}},
                         {"drop": None}]}]
    assert executor.verify_locked_nft_rules(APPROVED, good, forward)
    refuse(lambda: executor.verify_locked_nft_rules(
        APPROVED, good + [{"expr": [{"accept": None}]}], forward), "extra_allow")
    refuse(lambda: executor.verify_locked_nft_rules(
        APPROVED, good, []), "empty_forward")
    refuse(lambda: executor.verify_locked_nft_rules(
        APPROVED, good, [{"expr": [{"accept": None}]}]), "forward_accept")
    read_only = [
        ["-j", "list", "tables"],
        ["-j", "list", "chain", "inet", executor.NFT_TABLE, "output"],
        ["-j", "list", "chain", "inet", executor.NFT_TABLE, "forward"],
    ]
    for command in read_only:
        assert executor.nft_argv_permitted(command)
    own_file = "/tmp/oig-qa-nft-trusted/policy.nft"
    assert executor.nft_argv_permitted(["-c", "-f", own_file], own_file)
    assert executor.nft_argv_permitted(["-f", own_file], own_file)
    forbidden_commands = [
        ["-f", "/tmp/oig-qa-nft-evil/policy.nft"],
        ["-c", "-f", "/tmp/oig-qa-nft-evil/policy.nft"],
        ["flush", "ruleset"],
        ["delete", "table", "inet", executor.NFT_TABLE],
        ["add", "rule", "inet", executor.NFT_TABLE, "output", "accept"],
        ["-j", "list", "ruleset"],
        ["-j", "list", "chain", "inet", executor.NFT_TABLE, "input"],
        ["-f", "../policy.nft"],
    ]
    for command in forbidden_commands:
        assert not executor.nft_argv_permitted(command, own_file), command
        assert not executor.nft_argv_permitted(command), command
    assert not executor.nft_argv_permitted(["-f", own_file])
    assert not executor.nft_argv_permitted(["-c", "-f", own_file])
    assert not executor.nft_argv_permitted("nft -f", own_file)

    refuse(lambda: executor.LockdownOnlyController(None, FakeBackend()), "missing_manifest")
    refuse(lambda: executor.LockdownOnlyController(APPROVED, None), "missing_backend")
    try:
        executor.IsolatedNftBackend()
    except executor.NftSafetyError as err:
        assert "non-disposable runner" in str(err)
    else:
        raise AssertionError("OWNER_HOST_NFT_EXECUTOR_NOT_REFUSED")
    isolated_nft_subprocess_simulation()
    hosted_receipt_failure_regressions()
    source = Path(executor.__file__).read_text()
    assert "shell=True" not in source and "Nft arguments not in isolated allowlist" in source
    assert "sudo " not in source and "pkexec " not in source
    print("OIG_DISPOSABLE_NFT_ENGINE_OFFLINE_PASS"
          " INITIAL_LOCKED RELOCK NO_UNLOCK NO_DELETE"
          " COLLISION_AND_FAILED_COMMIT_UNKNOWN REFUSE_OWNER_HOST")


if __name__ == "__main__":
    main()
