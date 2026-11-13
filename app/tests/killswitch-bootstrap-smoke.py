#!/usr/bin/env python3
"""Offline boot-lockdown core regression; never calls root nft on the owner."""
import configparser
import copy
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import stat
from unittest.mock import patch

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


def malformed_root_nft_inventory_tests():
    """Parse adversarial nft JSON offline; no nft executable is spawned."""
    candidate = object.__new__(boot.NativeBootBackend)
    raw = None

    def feed(value):
        candidate._run = lambda _argv: value
        return candidate.tables()

    valid = {
        "nftables": [
            {"metainfo": {"version": "1.1.6", "json_schema_version": 1}},
            {"table": {"family": "inet", "name": "foreign", "handle": 4}},
            {"table": {"family": "inet", "name": boot.TABLE,
                       "handle": 6, "flags": []}},
        ]
    }
    assert feed(json.dumps(valid).encode()) == [
        ("inet", "foreign"), ("inet", boot.TABLE)
    ]
    good_other_flags = copy.deepcopy(valid)
    good_other_flags["nftables"][1]["table"]["flags"] = ["dormant"]
    assert feed(json.dumps(good_other_flags).encode())[-1] == (
        "inet", boot.TABLE
    )
    # The official nft JSON schema allows a singleton string OR array.
    good_other_flags["nftables"][1]["table"]["flags"] = "dormant"
    assert feed(json.dumps(good_other_flags).encode())[-1] == (
        "inet", boot.TABLE
    )

    examples = [
        b"not-json", b"[]", b'{"nftables":{}}',
        b'{"nftables":[],"nftables":[]}',
        b'{"nftables":[],"foreign":false}',
        b'{"nftables":[{"table":{"name":"oig_guard","name":"foreign","family":"inet"}}]}',
        b'{"nftables":[{"metainfo":{}},{"metainfo":{}}]}',
        b'{"nftables":[{"chain":{"family":"inet","name":"bad"}}]}',
        b'{"nftables":[{"rule":{}}]}',
        b'{"nftables":[{"table":{"family":"inet"}}]}',
        b'{"nftables":[{"table":{"family":"inet","name":false}}]}',
        b'{"nftables":[{"table":{"family":"inet","name":"oig_guard","handle":true}}]}',
        b'{"nftables":[{"table":{"family":"inet","name":"oig_guard","flags":true}}]}',
        b'{"nftables":[{"table":{"family":"inet","name":"oig_guard","flags":["dormant"]}}]}',
        b'{"nftables":[{"table":{"family":"inet","name":"oig_guard","flags":["owner"]}}]}',
        b'{"nftables":[{"table":{"family":"inet","name":"oig_guard","flags":["persist"]}}]}',
        b'{"nftables":[{"table":{"family":"inet","name":"oig_guard","flags":["owner","persist"]}}]}',
        b'{"nftables":[{"table":{"family":"inet","name":"oig_guard","unknown":1}}]}',
        b'{"nftables":[{"table":{"family":"bogus","name":"oig_guard"}}]}',
        b'{"nftables":[{"table":{"family":"inet","name":"oig_guard","handle":-1}}]}',
        b'{"nftables":[{"table":{"family":"inet","name":"oig_guard"}},{"table":{"family":"inet","name":"oig_guard"}}]}',
    ]
    for i, payload in enumerate(examples):
        must_refuse(lambda raw=payload: feed(raw), f"nft_json_inventory_{i}")

    for payload in (b'{"nftables":null}', b'{"nftables":[{}]}'):
        must_refuse(lambda raw=payload: feed(raw), "invalid_root_inventory")

    # The locked-readback verifier must reject dormant and transient tables
    # even if the stored output/forward rules appear perfect.
    table = {"family": "inet", "name": boot.TABLE}
    locked = [
        {"table": table},
        {"chain": {"family": "inet", "table": boot.TABLE, "name": "output"}},
        {"chain": {"family": "inet", "table": boot.TABLE, "name": "forward"}},
        *[{"rule": {"family": "inet", "table": boot.TABLE, "chain": "output"}}
          for _ in range(4)],
        {"rule": {"family": "inet", "table": boot.TABLE, "chain": "forward"}},
    ]
    verifier.verify_sole_lockdown_table(
        json.dumps({"nftables": locked}).encode(), table_name=boot.TABLE
    )
    valid_table_json = json.dumps({"nftables": locked}).encode()
    # Ensure these are otherwise-valid policies: absent duplicate-key checks,
    # normal JSON would silently overwrite the first member and PASS.
    duplicated_top = valid_table_json.replace(
        b'{"nftables": [', b'{"nftables": [], "nftables": [', 1
    )
    duplicated_nested = valid_table_json.replace(
        b'"family": "inet", "name": "oig_guard"',
        b'"family": "ip", "family": "inet", "name": "oig_guard"', 1
    )
    for payload in (duplicated_top, duplicated_nested):
        must_refuse(lambda raw=payload: verifier.verify_sole_lockdown_table(
            raw, table_name=boot.TABLE
        ), "duplicate_locked_nft_json_keys")

    for flags in (["dormant"], ["owner"], ["persist"],
                  ["owner", "persist"], "dormant", None, True):
        mutated = copy.deepcopy(locked)
        mutated[0]["table"]["flags"] = flags
        must_refuse(lambda mutated=mutated: verifier.verify_sole_lockdown_table(
            json.dumps({"nftables": mutated}).encode(), table_name=boot.TABLE
        ), "inactive_table_is_not_lockdown")

    print("OIG_BOOT_NFT_JSON_STRICT_FAIL_CLOSED_PASS",
          len(examples) + 2, "malformed_inventory_cases")


def mocked_native_boot_transaction_boundary():
    """Exercise true NativeBootBackend subprocess argv, not real nft."""
    args = (
        APPROVED.tunnel, APPROVED.underlay, APPROVED.peer_ipv4,
        APPROVED.peer_port, APPROVED.transport,
    )
    locked = policy.render_lockdown(*args, table=boot.TABLE)
    calls = []

    def fake_kernel(argv, **kwargs):
        assert argv[0] == boot.NFT
        assert argv[1:3] in (["-c", "-f"], ["-f", argv[-1]])
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["timeout"] == 8
        assert kwargs["check"] is False
        assert "shell" not in kwargs
        assert "LC_ALL" in kwargs["env"]
        file = Path(argv[-1])
        assert file.is_file() and file.read_text() == locked
        assert stat.S_IMODE(file.stat().st_mode) == 0o600
        calls.append(tuple(argv))
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    with (patch.object(boot, "validate_installed_root_runtime"),
          patch.object(boot.subprocess, "run", side_effect=fake_kernel)):
        backend = boot.NativeBootBackend(APPROVED, policy, verifier, contract)
        backend.apply(locked)
        assert len(calls) == 2
        assert calls[0][1:3] == ("-c", "-f")
        assert calls[1][1] == "-f"
        assert calls[0][-1] == calls[1][-1]
        assert backend.active_batch is None
        assert not Path(calls[0][-1]).exists()
        must_refuse(lambda: backend._run(["flush", "ruleset"]),
                    "arbitrary_nft_shellless_command")
        must_refuse(lambda: backend._run(["delete", "table", "inet", boot.TABLE]),
                    "delete_owned_table")
        must_refuse(lambda: backend.apply(
            policy.render_transition(*args, tunnel_allowed=True, table=boot.TABLE)
        ), "unverified_tunnel_unlocked")
        assert len(calls) == 2

    preflight = []

    def failed_check(argv, **_options):
        preflight.append(tuple(argv))
        return subprocess.CompletedProcess(argv, 1, b"", b"invalid")

    with (patch.object(boot, "validate_installed_root_runtime"),
          patch.object(boot.subprocess, "run", side_effect=failed_check)):
        backend = boot.NativeBootBackend(APPROVED, policy, verifier, contract)
        must_refuse(lambda: backend.apply(locked), "nft_preflight_failed")
        assert len(preflight) == 1 and preflight[0][1:3] == ("-c", "-f")
        assert backend.active_batch is None
        assert not Path(preflight[0][-1]).exists()

    print("OIG_ROOT_BOOT_MOCKED_NFT_0600_CHECK_THEN_COMMIT_PASS")


def hosted_boot_kernel_receipt_negative_tests():
    """Offline QA on the real Docker receipt validator; no kernel touched."""
    exported = runpy.run_path(
        str(Path(__file__).with_name("hosted-linux-root-boot-kernel-smoke.py")),
        run_name="oig_kernel_receipt_offline_qa"
    )
    blank = exported["new_receipt"]
    verify = exported["finalize_receipt"]
    assert verify(blank()) is False, "No measurements can never PASS"

    trusted = blank()
    for key in (
        "isolatedDockerScopeVerified", "kernelInitialLockdownVerified",
        "kernelIdempotentRestartVerified", "kernelTableContentsVerified",
        "outputDefaultDropVerified", "forwardDefaultDropVerified",
        "isolatedOwnedTableRemoved", "containerRouteDnsBaselineRestored",
    ):
        trusted[key] = True
    trusted["physicalIpv4DnsDropDelta"] = 8
    assert verify(trusted) is True

    negative = 0
    for key in (
        "isolatedDockerScopeVerified", "kernelInitialLockdownVerified",
        "kernelIdempotentRestartVerified", "kernelTableContentsVerified",
        "outputDefaultDropVerified", "forwardDefaultDropVerified",
        "isolatedOwnedTableRemoved", "containerRouteDnsBaselineRestored",
    ):
        for invalid in (False, None):
            tampered = copy.deepcopy(trusted)
            tampered[key] = invalid
            assert verify(tampered) is False, ("False positive", key, invalid)
            negative += 1
        missing = copy.deepcopy(trusted)
        missing.pop(key)
        assert verify(missing) is False, ("Missing proof passed", key)
        negative += 1

    for field in (
        "productionKillSwitchVerified", "bootPersistenceVerified",
        "installedRootServiceVerified", "realOpenVpnIdentityVerified",
        "physicalOwnerNetworkChanged",
    ):
        tampered = copy.deepcopy(trusted)
        tampered[field] = True
        assert verify(tampered) is False, ("Unmeasured production proof", field)
        negative += 1

    for count in (True, False, 7, -1, None, "8", 8.0):
        tampered = copy.deepcopy(trusted)
        tampered["physicalIpv4DnsDropDelta"] = count
        assert verify(tampered) is False, ("Forged counter", count)
        negative += 1

    missing_count = copy.deepcopy(trusted)
    del missing_count["physicalIpv4DnsDropDelta"]
    assert verify(missing_count) is False
    negative += 1

    for field, value in (
        ("failureClass", "KernelRefused"),
        ("schema", "oig-hosted-root-boot-kernel-v0"),
    ):
        tampered = copy.deepcopy(trusted)
        tampered[field] = value
        assert verify(tampered) is False
        negative += 1
    print("OIG_HOSTED_BOOT_KERNEL_RECEIPT_FAIL_CLOSED_PASS", negative)


def review_noninstalled_boot_ordering_contract():
    """Pure negative contract for opt-in, nondeployed systemd previews.

    systemd.unit(5): Requires+After gates failed startup but BindsTo+After
    also stops a dependent service when the requirement becomes inactive.
    This cannot replace a live kernel-state watchdog or physical boot QA.
    """
    root = boot.service_unit_preview()
    nm_gate = boot.networkmanager_dependency_preview()

    def accept(root_unit, gate):
        def parsed(raw):
            cp = configparser.ConfigParser(
                interpolation=None, strict=True, delimiters=("=",)
            )
            cp.optionxform = str
            cp.read_string(raw)
            return cp

        try:
            a = parsed(root_unit)
            b = parsed(gate)
            service = a["Service"]
            unit = a["Unit"]
            nm = b["Unit"]
            expected = "openinternetgateway-lockdown.service"
            root_before = unit["Before"].split()
            root_after = unit["After"].split()
            return all((
                "Install" not in a,
                "Install" not in b,
                set(a.sections()) == {"Unit", "Service"},
                set(b.sections()) == {"Unit"},
                unit.get("DefaultDependencies") == "no",
                "local-fs.target" in root_after,
                "network-pre.target" in root_before,
                "NetworkManager.service" in root_before,
                unit.get("Wants") == "network-pre.target",
                service.get("Type") == "oneshot",
                service.get("RemainAfterExit") == "yes",
                service.get("User") == "root",
                service.get("Group") == "root",
                service.get("NoNewPrivileges") == "true",
                service.get("CapabilityBoundingSet") == "CAP_NET_ADMIN",
                service.get("RestrictAddressFamilies") == "AF_UNIX AF_NETLINK",
                service.get("ProtectSystem") == "strict",
                service.get("PrivateNetwork") is None,
                service.get("UMask") == "0077",
                service.get("ExecStop") is None,
                service.get("ExecStart") == (
                    "/usr/bin/python3 -I "
                    "/opt/open-internet-gateway/resources/backend/linux/"
                    "killswitch_bootstrap.py --bootstrap-lockdown"
                ),
                nm.get("BindsTo") == expected,
                nm.get("After") == expected,
                nm.get("Requires") is None,
                nm.get("Wants") is None,
            ))
        except (configparser.Error, KeyError, ValueError):
            return False

    assert accept(root, nm_gate)
    negative = [
        (root, nm_gate.replace(
            "BindsTo=openinternetgateway-lockdown.service",
            "Requires=openinternetgateway-lockdown.service")),
        (root, nm_gate.replace(
            "BindsTo=openinternetgateway-lockdown.service",
            "Wants=openinternetgateway-lockdown.service")),
        (root, nm_gate.replace(
            "After=openinternetgateway-lockdown.service",
            "After=network-pre.target")),
        (root, nm_gate.replace(
            "BindsTo=openinternetgateway-lockdown.service",
            "BindsTo=another.service")),
        (root, nm_gate + "\n[Install]\nWantedBy=multi-user.target\n"),
        (root.replace(
            "Before=network-pre.target NetworkManager.service",
            "Before=network-pre.target"), nm_gate),
        (root.replace("After=local-fs.target",
                      "After=network-online.target"), nm_gate),
        (root.replace("DefaultDependencies=no",
                      "DefaultDependencies=yes"), nm_gate),
        (root.replace("RemainAfterExit=yes",
                      "RemainAfterExit=no"), nm_gate),
        (root.replace("CapabilityBoundingSet=CAP_NET_ADMIN",
                      "CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN"), nm_gate),
        (root.replace("RestrictAddressFamilies=AF_UNIX AF_NETLINK",
                      "RestrictAddressFamilies=AF_INET AF_INET6"), nm_gate),
        (root.replace("UMask=0077", "UMask=0000"), nm_gate),
        (root.replace(
            "NoNewPrivileges=true", "NoNewPrivileges=false"), nm_gate),
        (root.replace(
            "ExecStart=/usr/bin/python3 -I ",
            "ExecStart=/usr/bin/python3 "), nm_gate),
        (root.replace(
            "[Service]", "[Service]\nPrivateNetwork=true"), nm_gate),
        (root.replace(
            "[Service]", "[Service]\nExecStop=/usr/sbin/nft flush ruleset"), nm_gate),
        (root + "\n[Install]\nWantedBy=multi-user.target\n", nm_gate),
    ]
    for idx, pair in enumerate(negative):
        assert not accept(*pair), ("BOOT_ORDER_FAIL_OPEN", idx)
    print("OIG_ROOT_BOOT_SYSTEMD_DEPENDENCY_REVIEW_PASS",
          len(negative), "dangerous_dependency_mutations_rejected")


def main():
    review_noninstalled_boot_ordering_contract()
    hosted_boot_kernel_receipt_negative_tests()
    mocked_native_boot_transaction_boundary()
    assert boot.INSTALLED_SCRIPT.as_posix() == (
        "/opt/open-internet-gateway/resources/backend/linux/killswitch_bootstrap.py"
    )
    malformed_root_nft_inventory_tests()
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
