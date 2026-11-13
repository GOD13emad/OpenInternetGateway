#!/usr/bin/env python3
"""Bounded, real NetworkManager OpenVPN crash cleanup in GitHub Docker only.

The activator imports a pinned profile and starts an independent, detached
watcher BEFORE establishing a real TUN. The controller SIGKILLs the activator
after verified TUN HTTPS; the watcher invokes the UNMODIFIED operator_rollback
cleanup on the real UUID, then all scoped routes, PEMs and DNS are checked.
This tests real-NM cleanup following an actual crash, NOT systemd timer wiring
or any owner/physical network recovery (covered separately with fake NM).
"""
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
BACKEND = HERE.parent / "backend" / "linux"
TIMER_MODE = len(sys.argv) > 1 and sys.argv[1] in ("--timer-supervise", "--timer-activate")
RECEIPT = Path("/out/oig-hosted-active-timer-rollback.json" if TIMER_MODE
               else "/out/oig-hosted-active-crash-rollback.json")
STATE = Path("/tmp/oig-hosted-active-timer-private" if TIMER_MODE
             else "/tmp/oig-hosted-active-crash-private")
BRIDGE = Path("/out/oig-hosted-timer-bridge")


def scope():
    if (sys.argv[1:] not in (["--supervise"], ["--activate"], ["--watch"],
                                 ["--timer-supervise"], ["--timer-activate"])
            or os.geteuid() != 0 or os.environ.get("OIG_HOSTED_CONTAINER") != "1"
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("GITHUB_REPOSITORY") != "GOD13emad/OpenInternetGateway"
            or os.environ.get("GITHUB_EVENT_NAME") != "pull_request"
            or not re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ID", ""))
            or not Path("/.dockerenv").exists()
            or not Path("/work/app/backend/linux/operator_rollback.py").is_file()):
        raise SystemExit("REFUSED: owner host or non-disposable runner")


def cmd(args, timeout=10, pass_fds=()):
    return subprocess.run(args, capture_output=True, check=False,
                          timeout=timeout, pass_fds=pass_fds)


def required(args, timeout=10):
    p = cmd(args, timeout=timeout)
    if p.returncode or len(p.stdout) > 32000:
        raise RuntimeError("BOUNDED_CONTROL_UNAVAILABLE")
    return p.stdout


def snapshot():
    return [
        hashlib.sha256(required(["ip", "-4", "route", "show", "table", "all"])).hexdigest(),
        hashlib.sha256(required(["ip", "-6", "route", "show", "table", "all"])).hexdigest(),
        hashlib.sha256(Path("/etc/resolv.conf").read_bytes()).hexdigest(),
    ]


def store(path, value):
    encoded = (json.dumps(value, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


def metadata():
    obj = json.loads((STATE / "profile.json").read_text())
    if (not re.fullmatch(r"[a-f0-9-]{36}", obj["uuid"])
            or not re.fullmatch(r"OIG-Operator-QA-[a-f0-9]{12}", obj["name"])
            or obj["name"] != obj["stem"]
            or set(obj["hashes"]) != {"ca", "cert", "key"}):
        raise RuntimeError("CRASH_METADATA_INVALID")
    return obj


def environment():
    sys.path.insert(0, str(BACKEND))
    import operator_profile
    import operator_rollback
    import operator_trial
    spec = importlib.util.spec_from_file_location(
        "hosted_provider_crash", HERE / "hosted-linux-provider-data-plane.py")
    provider = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(provider)
    return operator_profile, operator_rollback, operator_trial, provider


def watch():
    _, rollback, _, _ = environment()
    obj = metadata()
    parent = int(obj["activator"])
    if parent < 2 or parent != os.getppid():
        raise RuntimeError("WATCHER_PARENT_IDENTITY_MISMATCH")
    # Reparenting proves SIGKILL or exit: the parent cannot execute finally.
    # A fixed upper bound also protects against a hung activator.
    deadline = time.monotonic() + 125
    while os.getppid() == parent and time.monotonic() < deadline:
        time.sleep(.25)
    stage = "ROLLBACK"
    try:
        result = rollback.cleanup(
            obj["uuid"], obj["name"], obj["stem"],
            obj["certificate_directory"], obj["hashes"])
        if not result.get("ok") or not result.get("profileRemoved") \
                or not result.get("certificateArtifactsRemoved"):
            raise RuntimeError("REAL_NM_CLEANUP_NOT_CONFIRMED")
        store(STATE / "watcher-result.json", {
            "ok": True, "usedUnmodifiedRollbackHelper": True,
            "observedActivatorGone": os.getppid() != parent
        })
    except Exception:
        store(STATE / "watcher-result.json", {"ok": False, "stage": stage})


def activate():
    profile, rollback, trial, provider = environment()
    baseline = profile._connection_uuids()
    if any("vpn" in row.lower() for row in required(
            ["nmcli", "-t", "-f", "TYPE", "connection", "show", "--active"]
    ).decode(errors="replace").splitlines()):
        raise RuntimeError("UNRELATED_ACTIVE_VPN")
    raw, _ = provider.official_profile()
    password, _ = provider.official_login()
    probe_ips = sorted({item[4][0] for item in socket.getaddrinfo(
        "www.cloudflare.com", 443, socket.AF_INET, socket.SOCK_STREAM)
        if ipaddress.ip_address(item[4][0]).is_global})
    if not probe_ips:
        raise RuntimeError("PUBLIC_HTTPS_SOURCE_UNAVAILABLE")
    ip = probe_ips[0]
    name = "OIG-Operator-QA-" + secrets.token_hex(6)
    source = STATE / (name + ".ovpn")
    source.write_text(raw, encoding="utf8")
    source.chmod(0o600)
    checked, endpoint, transport = profile.load_and_check(
        source, provider.EXPECTED_CA, provider.EXPECTED_CN)
    source.write_bytes(checked)
    imported = profile._run_nmcli("connection", "import", "--temporary",
                                  "type", "openvpn", "file", str(source), timeout=14)
    additions = profile._connection_uuids() - baseline
    if len(additions) != 1 or imported.returncode:
        raise RuntimeError("QA_IMPORT_AMBIGUOUS")
    uuid = next(iter(additions))
    profile.verify_nm_import(uuid, name, checked, endpoint, transport,
                             provider.EXPECTED_CA, provider.EXPECTED_CN)
    cert_dir = profile._nm_imported_certificate_directory(uuid, name)
    blocks = profile._inline_identity_blocks(checked)
    hashes = {key: hashlib.sha256(blocks[key]).hexdigest()
              for key in ("ca", "cert", "key")}
    # UUID-bound cleanup metadata is durable BEFORE the connection is active.
    store(STATE / "profile.json", {
        "uuid": uuid, "name": name, "stem": name,
        "certificate_directory": str(cert_dir),
        "hashes": hashes, "activator": os.getpid()
    })
    if TIMER_MODE:
        if os.environ.get("OIG_HOSTED_TIMER_BRIDGE") != "1":
            raise RuntimeError("HOSTED_REAL_USER_TIMER_BRIDGE_UNAVAILABLE")
        # The unchanged production arm() verifies the genuine *inactive*
        # imported NM UUID, saves a byte-identical durable runner and then
        # registers a user timer. Only systemd-run/systemctl cross the test
        # bridge: real nmcli remains untouched inside Docker.
        binary = STATE / "timer-bin"
        binary.mkdir(mode=0o700)
        for tool, action in (("systemd-run", "--client-run"),
                             ("systemctl", "--client-check")):
            wrapper = binary / tool
            wrapper.write_text(
                "#!/bin/sh\nexec /usr/bin/python3 -B "
                "/work/app/tests/hosted-linux-user-timer-bridge.py "
                + action + ' "$@"\n', encoding="utf8")
            wrapper.chmod(0o700)
        os.environ["PATH"] = str(binary) + ":" + os.environ["PATH"]
        receipt = rollback.arm(uuid, name, 100, name, str(cert_dir), hashes)
        durable = Path(rollback.durable_rollback_helper())
        if (not receipt.get("timerArmed") or receipt.get("connectionActivated")
                or durable.read_bytes() != Path(rollback.__file__).read_bytes()):
            raise RuntimeError("PRODUCT_DURABLE_USER_TIMER_NOT_CONFIRMED")
        store(STATE / "timer-armed.json", {
            "productArmVerifiedBeforeActivation": True,
            "durableRunnerByteIdentical": True,
            "realHostedUserSystemdTimerArmed": True
        })
    else:
        # The prior independent-process watchdog acceptance stays unchanged.
        watcher = subprocess.Popen(
            [sys.executable, "-B", str(Path(__file__)), "--watch"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=(STATE / "watcher-errors.log").open("wb"),
            start_new_session=True)
        store(STATE / "watcher-armed.json", {"watcherSpawnedBeforeActivation": True})
    modified = required(["nmcli", "--wait", "5", "connection", "modify",
                         "--temporary", "uuid", uuid,
                         "connection.autoconnect", "no", "vpn.user-name", "vpnbook",
                         "ipv4.never-default", "yes", "ipv6.never-default", "yes",
                         "ipv4.ignore-auto-dns", "yes", "ipv6.ignore-auto-dns", "yes",
                         "ipv4.ignore-auto-routes", "yes",
                         "ipv6.ignore-auto-routes", "yes",
                         "ipv4.routes", ip + "/32"], timeout=14)
    del modified
    profile.verify_nm_import(uuid, name, checked, endpoint, transport,
                             provider.EXPECTED_CA, provider.EXPECTED_CN)
    fd = trial.make_password_fd(password)
    password = None
    try:
        up = cmd(["nmcli", "--wait", "75", "connection", "up", "uuid", uuid,
                  "ifname", "oigqa0", "passwd-file", f"/proc/self/fd/{fd}"],
                 timeout=83, pass_fds=(fd,))
        if up.returncode:
            raise RuntimeError("NM_REAL_TUN_ACTIVATION_FAILED")
    finally:
        os.close(fd)
    if uuid not in required(["nmcli", "-t", "-f", "UUID", "connection",
                              "show", "--active"]).decode().lower().splitlines():
        raise RuntimeError("ACTIVATED_PROFILE_NOT_PRESENT")
    interfaces = json.loads(required(["ip", "-j", "-4", "address", "show"]))
    tun = [x["ifname"] for x in interfaces
           if re.fullmatch(r"(?:tun|vpn)[a-zA-Z0-9_.-]*", x.get("ifname", ""))
           and any(item.get("family") == "inet" for item in x.get("addr_info", []))]
    if len(tun) != 1:
        raise RuntimeError("TUN_INTERFACE_NOT_UNIQUE")
    path = required(["ip", "-4", "route", "get", ip])
    if not re.search(rb"\bdev\s+" + re.escape(tun[0].encode()) + rb"\b", path):
        raise RuntimeError("HTTPS_SOURCE_ROUTE_NOT_TUN_OWNED")
    https = cmd(["curl", "-4", "--noproxy", "*", "--resolve",
                 "www.cloudflare.com:443:" + ip, "--interface", tun[0],
                 "--connect-timeout", "12", "--max-time", "32", "--fail",
                 "--silent", "--show-error",
                 "https://www.cloudflare.com/cdn-cgi/trace"], timeout=36)
    if https.returncode or len(https.stdout) > 4000:
        raise RuntimeError("ACTIVE_TUN_VPN_HTTPS_UNAVAILABLE")
    facts = dict(line.split("=", 1) for line in
                 https.stdout.decode("ascii", "replace").splitlines() if "=" in line)
    if not ipaddress.ip_address(facts.get("ip", "127.0.0.1")).is_global:
        raise RuntimeError("ACTIVE_TUN_PUBLIC_EGRESS_UNVERIFIED")
    store(STATE / "active.json", {
        "realNmTunnelActive": True, "tunnelBoundHttpsSucceeded": True,
        "ownedRouteVerified": True, "pinnedPeerVerifiedByNM": True
    })
    # Controller must SIGKILL us: NEVER invoke rollback from this process.
    time.sleep(150)


def supervise():
    out = {
        "schema": ("oig-hosted-native-nm-active-user-timer-rollback-v1" if TIMER_MODE
                   else "oig-hosted-native-nm-active-crash-rollback-v1"),
        "scope": ("Disposable Docker real NM TUN; product arm bridged to real GitHub hosted user-systemd manager"
                  if TIMER_MODE else
                  "Disposable GitHub Docker netns with real NM+OpenVPN; independent subprocess watchdog, NOT systemd timer"),
        "pass": False, "productionCrashRollbackVerified": False,
        "systemDnsLeakContainmentVerified": False,
        "productionKillSwitchVerified": False
    }
    STATE.mkdir(mode=0o700)
    baseline = snapshot()
    base = required(["nmcli", "-t", "-f", "NAME", "connection", "show", "--active"])
    if b"oig-hosted-base" not in base:
        raise RuntimeError("ISOLATED_BASE_LINK_MISSING")
    child = None
    stage = "ACTIVATION"
    try:
        child = subprocess.Popen([sys.executable, "-B", str(Path(__file__)),
                                  "--timer-activate" if TIMER_MODE else "--activate"],
                                 stdout=subprocess.DEVNULL,
                                 stderr=(STATE / "activator-errors.log").open("wb"))
        deadline = time.monotonic() + 105
        while time.monotonic() < deadline:
            if (STATE / "active.json").is_file():
                break
            if child.poll() is not None:
                raise RuntimeError("ACTIVATOR_EXITED_BEFORE_ACTIVE_TUN")
            time.sleep(.25)
        else:
            raise RuntimeError("ACTIVE_TUN_TIMEOUT")
        active = json.loads((STATE / "active.json").read_text())
        if not all(active.get(key) is True for key in (
                "realNmTunnelActive", "tunnelBoundHttpsSucceeded",
                "ownedRouteVerified", "pinnedPeerVerifiedByNM")):
            raise RuntimeError("ACTIVE_TUN_RECEIPT_NOT_VERIFIED")
        if not (STATE / ("timer-armed.json" if TIMER_MODE else "watcher-armed.json")).is_file():
            raise RuntimeError("INDEPENDENT_ROLLBACK_NOT_ARMED_BEFORE_ACTIVATION")
        stage = "SIGKILL_ACTIVATOR"
        child.kill()
        if child.wait(timeout=6) != -signal.SIGKILL:
            raise RuntimeError("ACTIVATOR_NOT_SIGKILL_TERMINATED")
        out["activatorKilledAfterRealTunHttps"] = True
        stage = "REAL_USER_TIMER_CLEANUP" if TIMER_MODE else "INDEPENDENT_REAL_NM_CLEANUP"
        cleanup_file = (BRIDGE / "fired.json" if TIMER_MODE
                        else STATE / "watcher-result.json")
        deadline = time.monotonic() + (175 if TIMER_MODE else 40)
        while time.monotonic() < deadline:
            if cleanup_file.is_file() and not cleanup_file.is_symlink():
                break
            time.sleep(.25)
        else:
            raise RuntimeError("INDEPENDENT_CLEANUP_TIMEOUT")
        receipt = json.loads(cleanup_file.read_text())
        if TIMER_MODE:
            if not (receipt.get("realHostedUserTimerFired")
                    and receipt.get("unmodifiedDurableHelperCleanup")
                    and receipt.get("scopedUuidCleaned")
                    and receipt.get("dockerExecExitCode") == 0):
                raise RuntimeError("REAL_USER_TIMER_ROLLBACK_FAILED")
            out["realHostedUserSystemdTimerFiredAfterSIGKILL"] = True
            out["productArmAndDurableHelperVerified"] = True
        else:
            if not (receipt.get("ok") and receipt.get("usedUnmodifiedRollbackHelper")
                    and receipt.get("observedActivatorGone")):
                raise RuntimeError("WATCHDOG_ROLLBACK_FAILED")
            out["independentWatcherSurvivedSIGKILL"] = True
        meta = metadata()
        pro = environment()[0]
        if meta["uuid"] in pro._connection_uuids():
            raise RuntimeError("OWNED_PROFILE_STILL_PRESENT")
        if any((Path(meta["certificate_directory"]) /
                f"{meta['name']}-{kind}.pem").exists() for kind in meta["hashes"]):
            raise RuntimeError("PINNED_CERTS_STILL_PRESENT")
        # NM removes owned route/device asynchronously after deleting the
        # profile. Poll only, do not mutate a non-owned route to force PASS.
        restored = False
        for _ in range(16):
            if baseline == snapshot():
                restored = True
                break
            time.sleep(.25)
        if not restored:
            raise RuntimeError("CONTAINER_ROUTES_OR_RESOLVER_NOT_RESTORED")
        if b"oig-hosted-base" not in required(
                ["nmcli", "-t", "-f", "NAME", "connection", "show", "--active"]):
            raise RuntimeError("INDEPENDENT_BASE_CONNECTION_CHANGED")
        out["realActiveVpnProfileAndCertificatesRemoved"] = True
        out["containerNetworkRestored"] = True
        out["independentBasePreserved"] = True
        out["pass"] = True
    except Exception as exc:
        out["failureStage"] = stage
        out["failureClass"] = type(exc).__name__
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=6)
        # Never leave an active QA profile on failure; Docker --rm provides
        # the final namespace boundary, but also reconcile our scoped UUID.
        if (STATE / "profile.json").is_file():
            try:
                meta = metadata()
                profile, rollback, _, _ = environment()
                if meta["uuid"] in profile._connection_uuids():
                    rollback.cleanup(meta["uuid"], meta["name"], meta["stem"],
                                     meta["certificate_directory"], meta["hashes"])
            except Exception:
                out["failureCleanupUnverified"] = True
        store(RECEIPT, out)
        print("HOSTED_REAL_ACTIVE_TUN_CRASH_ROLLBACK_RECEIPT=" +
              json.dumps(out, sort_keys=True))
        # Private container-only files (incl. original imported key) disappear
        # with Docker --rm; none are bind-mounted or uploaded.
    return 0 if out["pass"] else 1


if __name__ == "__main__":
    scope()
    mode = sys.argv[1]
    if mode in ("--supervise", "--timer-supervise"):
        raise SystemExit(supervise())
    if not STATE.is_dir() or STATE.is_symlink() or STATE.stat().st_mode & 0o077:
        raise SystemExit("REFUSED: private crash QA state unavailable")
    if mode in ("--activate", "--timer-activate"):
        activate()
    else:
        watch()
