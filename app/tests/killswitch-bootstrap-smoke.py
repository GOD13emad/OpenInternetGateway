#!/usr/bin/env python3
"""Offline boot-lockdown core regression; never calls root nft on the owner."""
import copy
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

BACKEND = Path(__file__).resolve().parents[1] / "backend/linux"
sys.path.insert(0, str(BACKEND))
import killswitch_bootstrap as boot
import killswitch_lifecycle_contract as contract
import killswitch_nft_executor as verifier
import nft_killswitch_plan as policy

sample = runpy.run_path(str(Path(__file__).with_name(
    "killswitch-nft-executor-smoke.py"
)))
APPROVED = sample["APPROVED"]
SAMPLE_RULES = sample["sample_rules"]
EQ = sample["eq"]


class SimulatedBoot:
    def __init__(self, *, exists=False):
        self.exists = exists
        self.extra_object = False
        self.wrong_peer = False
        self.forward_unlocked = False
        self.fail_apply = False
        self.output = ("output", "drop", -150)
        self.forward = ("forward", "drop", -150)
        self.calls = []
        self.batches = []

    def tables(self):
        self.calls.append("tables")
        return [("inet", boot.TABLE)] if self.exists else []

    def verify_sole_table(self):
        self.calls.append("verify_sole_table")
        data = {"nftables": [
            {"table": {"family": "inet", "name": boot.TABLE}},
            {"chain": {"family": "inet", "table": boot.TABLE, "name": "output"}},
            {"chain": {"family": "inet", "table": boot.TABLE, "name": "forward"}},
            *[{"rule": {"family": "inet", "table": boot.TABLE, "chain": "output"}}
              for _ in range(4)],
            {"rule": {"family": "inet", "table": boot.TABLE, "chain": "forward"}},
        ]}
        if self.extra_object:
            data["nftables"].append(
                {"set": {"family": "inet", "table": boot.TABLE, "name": "unexpected"}}
            )
        return verifier.verify_sole_lockdown_table(
            json.dumps(data).encode("utf8"), table_name=boot.TABLE
        )

    def chain(self, name):
        self.calls.append("chain:" + name)
        return {"output": self.output, "forward": self.forward}[name]

    def rules(self, name):
        self.calls.append("rules:" + name)
        if name == "forward":
            if self.forward_unlocked:
                return [{"expr": [{"accept": None}]}]
            return [{"expr": [{"counter": {"packets": 0, "bytes": 0}},
                              {"drop": None}]}]
        result = SAMPLE_RULES()
        if self.wrong_peer:
            result[1]["expr"][2] = EQ(
                "payload", ("ip", "daddr"), "8.8.8.8"
            )
        return result

    def apply(self, script):
        self.calls.append("apply")
        self.batches.append(script)
        if self.fail_apply:
            raise boot.BootRefused("SIMULATED_UNCERTAIN_NFT_COMMIT")
        if self.exists:
            raise AssertionError("Never modify a foreign or existing table")
        self.exists = True


def must_refuse(fn, label):
    try:
        fn()
    except (boot.BootRefused, verifier.NftSafetyError, policy.UnsafePlan):
        return
    raise AssertionError("BOOT_FAIL_OPEN_" + label)


def main():
    assert boot.INSTALLED_SCRIPT.as_posix() == (
        "/opt/open-internet-gateway/resources/backend/linux/killswitch_bootstrap.py"
    )
    assert boot.TABLE == "oig_guard"
    assert boot.TABLE == policy.BOOT_TABLE
    assert verifier.NFT_TABLE == policy.TABLE
    assert boot.TABLE != verifier.NFT_TABLE
    assert isinstance(APPROVED, contract.Approved)

    new = SimulatedBoot()
    assert boot.boot_lockdown_core(
        APPROVED, new, policy, verifier, contract
    ) == "NEW_LOCKED"
    assert len(new.batches) == 1
    batch = new.batches[0]
    assert batch.startswith("add table inet oig_guard\n")
    assert 'oifname "tun7" accept' not in batch
    assert "hook output priority -150; policy drop;" in batch
    assert "hook forward priority -150; policy drop;" in batch
    assert "flush ruleset" not in batch and "delete table" not in batch

    # Idempotent restart accepts the exact locked table without applying
    # another transaction (and must never delete the original table).
    assert boot.boot_lockdown_core(
        APPROVED, new, policy, verifier, contract
    ) == "ALREADY_LOCKED"
    assert len(new.batches) == 1

    rejected = SimulatedBoot(exists=True)
    rejected.extra_object = True
    must_refuse(lambda: boot.boot_lockdown_core(
        APPROVED, rejected, policy, verifier, contract
    ), "foreign_existing_set")
    assert not rejected.batches

    bad_peer = SimulatedBoot(exists=True)
    bad_peer.wrong_peer = True
    must_refuse(lambda: boot.boot_lockdown_core(
        APPROVED, bad_peer, policy, verifier, contract
    ), "changed_peer")
    assert not bad_peer.batches

    bad_forward = SimulatedBoot(exists=True)
    bad_forward.forward_unlocked = True
    must_refuse(lambda: boot.boot_lockdown_core(
        APPROVED, bad_forward, policy, verifier, contract
    ), "forward_accept")
    assert not bad_forward.batches

    broken_output = SimulatedBoot(exists=True)
    broken_output.output = ("output", "accept", -150)
    must_refuse(lambda: boot.boot_lockdown_core(
        APPROVED, broken_output, policy, verifier, contract
    ), "output_allow")
    assert not broken_output.batches

    failed = SimulatedBoot()
    failed.fail_apply = True
    must_refuse(lambda: boot.boot_lockdown_core(
        APPROVED, failed, policy, verifier, contract
    ), "unknown_commit")
    assert len(failed.batches) == 1  # No retry / cleanup!

    must_refuse(lambda: boot.boot_lockdown_core(
        None, SimulatedBoot(), policy, verifier, contract
    ), "no_pinned_manifest")
    for candidate in (
        "oig_guard;flush ruleset",
        "oig_guard input", "inet/oig_guard",
        "filter", "OIG_GUARD", 123, None
    ):
        must_refuse(lambda: policy.render_lockdown(
            "tun7", "eth0", "1.1.1.1", 443, "tcp",
            table=candidate
        ), "arbitrary_target_table")

    try:
        boot.validate_installed_root_runtime()
    except boot.BootRefused:
        pass
    else:
        raise AssertionError("USER_SOURCE_TREE_ACCEPTED_AS_INSTALLED_ROOT")

    unit = boot.service_unit_preview()
    assert unit.startswith("# REVIEW PREVIEW ONLY.")
    assert "\n[Install]\n" not in unit
    assert "Before=network-pre.target NetworkManager.service" in unit
    assert "NoNewPrivileges=true" in unit
    assert "CapabilityBoundingSet=CAP_NET_ADMIN" in unit
    assert "ExecStop=" not in unit and "pkexec" not in unit
    assert "systemctl" not in unit

    print("OIG_ROOT_BOOT_LOCKED_ONLY_OFFLINE_PASS"
          " NEW_LOCKED ALREADY_LOCKED NO_UNLOCK NO_DELETE"
          " INVALID_CONFIG_EXISTING_TABLE_REFUSED")


if __name__ == "__main__":
    main()
