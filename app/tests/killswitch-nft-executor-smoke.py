#!/usr/bin/env python3
"""Offline transaction/state regression; never executes nft on owner host."""
from pathlib import Path
import os
import sys

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
    refuse(lambda: executor.LockdownOnlyController(None, FakeBackend()), "missing_manifest")
    refuse(lambda: executor.LockdownOnlyController(APPROVED, None), "missing_backend")
    try:
        executor.IsolatedNftBackend()
    except executor.NftSafetyError as err:
        assert "non-disposable runner" in str(err)
    else:
        raise AssertionError("OWNER_HOST_NFT_EXECUTOR_NOT_REFUSED")
    source = Path(executor.__file__).read_text()
    assert "shell=True" not in source and "Nft arguments not in isolated allowlist" in source
    assert "sudo " not in source and "pkexec " not in source
    print("OIG_DISPOSABLE_NFT_ENGINE_OFFLINE_PASS"
          " INITIAL_LOCKED RELOCK NO_UNLOCK NO_DELETE"
          " COLLISION_AND_FAILED_COMMIT_UNKNOWN REFUSE_OWNER_HOST")


if __name__ == "__main__":
    main()
