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


class FakeBackend:
    def __init__(self):
        self.exists = False
        self.output = ("output", "drop")
        self.forward = ("forward", "drop")
        self.allow_tunnel = False
        self.fail = False
        self.scripts = []
        self.calls = []

    def tables(self):
        self.calls.append("tables")
        return [("inet", executor.NFT_TABLE)] if self.exists else []

    def chain(self, kind):
        self.calls.append("chain:" + kind)
        return {"output": self.output, "forward": self.forward}[kind]

    def rules(self):
        self.calls.append("rules")
        return [{"expr": [{"match": {"right": "tun7"}}]}] if self.allow_tunnel else [
            {"expr": [{"match": {"right": "lo"}}, {"accept": None}]},
            {"expr": [{"match": {"right": "eth0"}}, {"accept": None}]},
            {"expr": [{"match": {"right": "eth0"}}, {"accept": None}]},
            {"expr": [{"counter": {"packets": 0}}, {"drop": None}]},
        ]

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
    broken.output = ("output", "accept")
    d = executor.LockdownOnlyController(APPROVED, broken)
    refuse(d.install_lockdown, "unsafe_output_chain")
    assert d.state == "UNKNOWN" and broken.exists

    broken_forward = FakeBackend()
    broken_forward.forward = ("forward", "accept")
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
