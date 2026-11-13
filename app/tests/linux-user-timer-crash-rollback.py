#!/usr/bin/env python3
"""Non-network, real user-systemd timer integration with simulated parent SIGKILL.

Run explicitly as a regular Linux desktop user:
    python3 -B app/tests/linux-user-timer-crash-rollback.py --isolated-stub-only

The timer executes the *unchanged durable OIG operator rollback helper* using
a private PATH containing ONLY a synthetic nmcli. This cannot access the
owner's NetworkManager even if the shim disappears; no host VPN, route, DNS,
firewall, persistent user unit, or elevated permission is modified.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

HELPER = Path(__file__).resolve().parents[1] / "backend/linux/operator_rollback.py"
SYSTEMD_RUN = "/usr/bin/systemd-run"
SYSTEMCTL = "/usr/bin/systemctl"

# No real nmcli or systemctl may be used by the transient service. Its PATH
# contains a single private nmcli shim and NO system executable directories.
MOCK_NMCLI = r'''#!/usr/bin/python3
import json,os,pathlib,sys
p=pathlib.Path(os.environ["OIG_TIMER_TEST_STATE"])
log=pathlib.Path(os.environ["OIG_TIMER_TEST_EVENTS"])
a=sys.argv[1:]
s=json.loads(p.read_text())
with log.open("a",encoding="utf8") as stream:
    stream.write(json.dumps(a,separators=(",",":"))+"\n")
qa=s["qaUuid"]
foreign=s["foreignUuid"]
def done(code=0,text=""):
    p.write_text(json.dumps(s),encoding="utf8")
    if text:print(text)
    sys.exit(code)
if a==["--wait","5","-t","-f","UUID","connection","show"]:
    done(text=("\n".join(([qa] if s["qaPresent"] else [])+[foreign])))
if a[:5]==["--wait","5","-g","connection.id","connection"] and a[5:7]==["show","uuid"]:
    if a[7:]==[qa] and s["qaPresent"]:done(text=s["qaName"])
    if a[7:]==[foreign]:done(text="Independent-User-VPN")
    done(10)
if a[:5]==["--wait","5","-g","connection.type","connection"] and a[5:7]==["show","uuid"]:
    if (a[7:]==[qa] and s["qaPresent"]) or a[7:]==[foreign]:done(text="vpn")
    done(10)
if a==["--wait","5","-t","-f","UUID","connection","show","--active"]:
    done(text="\n".join(([qa] if s["qaActive"] else [])+[foreign]))
if a==["--wait","5","connection","down","uuid",qa] and s["qaPresent"]:
    s["qaActive"]=False
    done()
if a==["--wait","5","connection","delete","uuid",qa] and s["qaPresent"]:
    if s["qaActive"]:done(11)
    s["qaPresent"]=False
    done()
if a==["--wait","5","-g","vpn.data","connection","show","uuid",foreign]:
    done(text="remote=independent.example:1194")
done(70)
'''


# These test-only interceptors let the UNMODIFIED operator_rollback.arm()
# register a REAL user-systemd timer while forcing the timer callback's PATH
# to contain only a synthetic nmcli. No production code gets a PATH override.
MOCK_SYSTEMD_RUN = r'''#!/usr/bin/python3
import os,subprocess,sys
a=sys.argv[1:]
if (a[:3] != ["--user","--quiet","--collect"]
        or "--unit="+os.environ["OIG_TIMER_TEST_UNIT"] not in a
        or "--on-active=10s" not in a):
    sys.exit(77)
envs=[
    "--setenv=PATH="+os.environ["OIG_TIMER_TEST_BIN"],
    "--setenv=OIG_TIMER_TEST_STATE="+os.environ["OIG_TIMER_TEST_STATE"],
    "--setenv=OIG_TIMER_TEST_EVENTS="+os.environ["OIG_TIMER_TEST_EVENTS"],
    "--setenv=PYTHONDONTWRITEBYTECODE=1",
]
p=subprocess.run(["/usr/bin/systemd-run"]+a[:3]+envs+a[3:],
                 capture_output=True,text=True,timeout=12)
sys.stdout.write(p.stdout)
sys.stderr.write(p.stderr)
sys.exit(p.returncode)
'''

MOCK_SYSTEMCTL = r'''#!/usr/bin/python3
import os,subprocess,sys
a=sys.argv[1:]
if a!=["--user","is-active",os.environ["OIG_TIMER_TEST_UNIT"]+".timer"]:
    sys.exit(77)
p=subprocess.run(["/usr/bin/systemctl"]+a,
                 capture_output=True,text=True,timeout=8)
sys.stdout.write(p.stdout)
sys.stderr.write(p.stderr)
sys.exit(p.returncode)
'''

def checked(argv, *, timeout=12, env=None):
    return subprocess.run(argv, capture_output=True, text=True,
                          timeout=timeout, check=False, env=env)


def main():
    if (sys.argv[1:] != ["--isolated-stub-only"] or os.name != "posix"
            or sys.platform != "linux" or os.geteuid() == 0
            or not all(Path(p).is_file() for p in (SYSTEMD_RUN, SYSTEMCTL, HELPER))):
        raise SystemExit("REFUSED: only an explicit regular-user Linux stub timer test is allowed")

    session = checked([SYSTEMCTL, "--user", "is-system-running"], timeout=8)
    if session.returncode not in (0, 1) or session.stdout.strip() not in (
            "running", "degraded", "starting"):
        raise RuntimeError("User systemd manager unavailable; no timer created")

    qa_name = "OIG-Operator-QA-" + secrets.token_hex(6)
    qa_uuid = str(uuid.uuid4())
    foreign_uuid = str(uuid.uuid4())
    unit = "oig-operator-qa-" + qa_name[-12:]
    with tempfile.TemporaryDirectory(prefix="oig-real-user-timer-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        bin_dir = root / "bin"
        bin_dir.mkdir(mode=0o700)
        shim = bin_dir / "nmcli"
        shim.write_text(MOCK_NMCLI, encoding="utf8")
        shim.chmod(0o700)
        for tool, contents in (("systemd-run", MOCK_SYSTEMD_RUN),
                               ("systemctl", MOCK_SYSTEMCTL)):
            wrapper = bin_dir / tool
            wrapper.write_text(contents, encoding="utf8")
            wrapper.chmod(0o700)
        state = root / "state.json"
        events = root / "events.jsonl"
        data_home = root / "xdg-data"
        cert_dir = data_home / "networkmanagement" / "certificates" / "nm-openvpn"
        cert_dir.mkdir(parents=True, mode=0o700)
        cert_dir.chmod(0o700)
        original = {
            "qaName": qa_name, "qaUuid": qa_uuid, "foreignUuid": foreign_uuid,
            "qaPresent": True, "qaActive": False, "foreignActive": True
        }
        state.write_text(json.dumps(original), encoding="utf8")
        state.chmod(0o600)
        events.write_text("", encoding="utf8")
        events.chmod(0o600)
        pem = {
            "ca": b"-----BEGIN CERTIFICATE-----\nsynthetic-ca\n-----END CERTIFICATE-----\n",
            "cert": b"-----BEGIN CERTIFICATE-----\nsynthetic-cert\n-----END CERTIFICATE-----\n",
            "key": b"-----BEGIN PRIVATE KEY-----\nsynthetic-key\n-----END PRIVATE KEY-----\n",
        }
        hashes = {}
        for kind, body in pem.items():
            target = cert_dir / f"{qa_name}-{kind}.pem"
            target.write_bytes(body)
            target.chmod(0o600)
            hashes[kind] = hashlib.sha256(body.strip()).hexdigest()

        armed_file = root / "arm-result.json"
        env = {
            **os.environ, "PATH": str(bin_dir),
            "XDG_DATA_HOME": str(data_home),
            "OIG_TIMER_TEST_BIN": str(bin_dir),
            "OIG_TIMER_TEST_STATE": str(state),
            "OIG_TIMER_TEST_EVENTS": str(events),
            "OIG_TIMER_TEST_UNIT": unit,
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        # The actual product 'arm' call checks UUID/name identity, verifies
        # that its QA VPN is INACTIVE, installs its byte-pinned durable helper,
        # schedules a real transient timer, and verifies timer is-active.
        # Only then do we mark our synthetic VPN active and kill the caller.
        parent_code = "\n".join([
            "import json,os,signal,subprocess,sys,pathlib",
            "cmd=" + repr([
                "/usr/bin/python3", "-B", str(HELPER), "arm",
                "--uuid", qa_uuid, "--name", qa_name,
                "--seconds", "10", "--artifact-stem", qa_name,
                "--certificate-directory", str(cert_dir),
                "--ca-sha256", hashes["ca"], "--cert-sha256", hashes["cert"],
                "--key-sha256", hashes["key"],
            ]),
            "p=subprocess.run(cmd,capture_output=True,text=True,timeout=16)",
            "if p.returncode:print('PRODUCT_ARM_FAILED',p.stderr,file=sys.stderr);sys.exit(73)",
            "armed=json.loads(p.stdout)",
            "assert armed.get('timerArmed') is True and armed.get('connectionActivated') is False",
            "assert armed.get('unit')==" + repr(unit + ".timer"),
            "state=pathlib.Path(" + repr(str(state)) + ")",
            "record=json.loads(state.read_text())",
            "assert record['qaPresent'] and not record['qaActive']",
            "record['qaActive']=True",
            "state.write_text(json.dumps(record))",
            "pathlib.Path(" + repr(str(armed_file)) + ").write_text(p.stdout)",
            "os.kill(os.getpid(),signal.SIGKILL)",
        ])
        runner = (data_home / "OpenInternetGateway" / "qa-rollback" /
                  ("cleanup-" + hashlib.sha256(HELPER.read_bytes()).hexdigest() + ".py"))
        scheduled = True  # Reclaim this unique unit even after partial arming.
        try:
            parent = checked(["/usr/bin/python3", "-B", "-c",
                              parent_code], timeout=20, env=env)
            if parent.returncode != -signal.SIGKILL:
                raise AssertionError(
                    "The scheduling parent did not die from SIGKILL: "
                    + str(parent.returncode) + " " + parent.stderr[:200])
            if not armed_file.exists():
                raise AssertionError("Product arm receipt missing before parent kill")
            armed = json.loads(armed_file.read_text(encoding="utf8"))
            if armed.get("timerArmed") is not True:
                raise AssertionError("Product did not arm rollback")
            if not runner.is_file() or runner.read_bytes() != HELPER.read_bytes():
                raise AssertionError("Product durable helper was not byte-identical")
            if stat.S_IMODE(runner.stat().st_mode) != 0o600:
                raise AssertionError("Product durable helper not private")
            deadline = time.monotonic() + 22
            while time.monotonic() < deadline:
                current = json.loads(state.read_text(encoding="utf8"))
                # Profile down/delete is not completion: the helper then
                # scans unrelated VPN certificate references and removes its
                # own SHA-pinned PEM files. Observe the entire transaction.
                certs_removed = all(
                    not (cert_dir / f"{qa_name}-{kind}.pem").exists()
                    for kind in pem)
                if (not current["qaPresent"] and not current["qaActive"]
                        and certs_removed):
                    break
                time.sleep(0.2)
            else:
                raise AssertionError("Independent timer did not remove QA VPN")
            current = json.loads(state.read_text(encoding="utf8"))
            if not current["foreignActive"] or current["foreignUuid"] != foreign_uuid:
                raise AssertionError("Unrelated VPN state changed")
            if any((cert_dir / f"{qa_name}-{kind}.pem").exists() for kind in pem):
                raise AssertionError("Pinned certificate cleanup failed")
            observed = [json.loads(line) for line in events.read_text().splitlines()]
            if ["--wait","5","connection","down","uuid",qa_uuid] not in observed:
                raise AssertionError("Active QA VPN was never disconnected")
            if ["--wait","5","connection","delete","uuid",qa_uuid] not in observed:
                raise AssertionError("QA VPN was never deleted")
            if any("down" in step or "delete" in step for step in
                   (" ".join(args) for args in observed if foreign_uuid in args)):
                raise AssertionError("An unrelated connection was modified")
            print(json.dumps({
                "pass": True,
                "scope": "Real user-systemd timer, synthetic nmcli only; no host network mutations",
                "schedulingParentKilled": True,
                "productArmAndUserTimerVerified": True,
                "durablePackagedCleanupHelperExecuted": True,
                "ownedActiveQaProfileRemoved": True,
                "pinnedSyntheticCertificateArtifactsRemoved": True,
                "independentVpnStateUntouched": True,
                "noRealNmcliAvailableToTimer": True
            }, sort_keys=True))
        finally:
            # Names are unguessable and exclusively owned by this test.
            if scheduled:
                checked([SYSTEMCTL, "--user", "stop", unit + ".timer"],
                        timeout=8)
                checked([SYSTEMCTL, "--user", "reset-failed", unit + ".service"],
                        timeout=8)


if __name__ == "__main__":
    main()
