#!/usr/bin/env python3
"""GitHub-hosted-only bridge: real user-systemd timer, isolated Docker VPN.

The product's unmodified operator_rollback.arm() is invoked INSIDE the
disposable Docker netns against genuine NetworkManager. Its systemd-run
request crosses a tightly validated file bridge to the hosted runner's
real user-systemd manager. On expiry, that manager invokes the unmodified,
durably pinned product cleanup helper with docker exec inside the SAME
disposable container. The bridge is test infrastructure, NOT a production
systemd integration or proof for a physical owner host.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

CONTAINER_RE = re.compile(r"oig-hosted-nm-[0-9]+\Z")
QA_RE = re.compile(r"OIG-Operator-QA-[0-9a-f]{12}\Z")
UUID_RE = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z")
HASH_RE = re.compile(r"[a-f0-9]{64}\Z")
BRIDGE = Path("/out/oig-hosted-timer-bridge")
SOURCE = Path(__file__).resolve().parents[1] / "backend/linux/operator_rollback.py"


def scope(host):
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("GITHUB_REPOSITORY") != "GOD13emad/OpenInternetGateway"
            or os.environ.get("GITHUB_EVENT_NAME") != "pull_request"
            or not re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ID", ""))):
        raise RuntimeError("REFUSED: owner host or non-disposable runner")
    if host:
        if os.geteuid() == 0 or Path("/.dockerenv").exists():
            raise RuntimeError("REFUSED: owner host or non-disposable runner")
    else:
        if (os.geteuid() != 0 or os.environ.get("OIG_HOSTED_CONTAINER") != "1"
                or not Path("/.dockerenv").exists()
                or not Path("/work/app/backend/linux/operator_rollback.py").is_file()):
            raise RuntimeError("REFUSED: owner host or non-disposable runner")


def read_json(file):
    if file.is_symlink() or not file.is_file() or file.stat().st_size > 4096:
        raise RuntimeError("BRIDGE_RECORD_INVALID")
    return json.loads(file.read_text(encoding="utf8"))


def store(file, obj, mode=0o600):
    payload = (json.dumps(obj, sort_keys=True) + "\n").encode()
    if len(payload) > 4096:
        raise RuntimeError("BRIDGE_RECORD_TOO_LARGE")
    fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as writer:
        writer.write(payload)
        writer.flush()
        os.fsync(writer.fileno())


def ensure_bridge(folder, host):
    if folder.is_symlink() or not folder.is_dir():
        raise RuntimeError("BRIDGE_FOLDER_UNAVAILABLE")
    info = folder.stat()
    if info.st_mode & 0o077:
        raise RuntimeError("BRIDGE_FOLDER_NOT_PRIVATE")
    if host and info.st_uid != os.getuid():
        raise RuntimeError("BRIDGE_FOLDER_OWNER_MISMATCH")


def wait_file(path, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.is_file() and not path.is_symlink():
            return read_json(path)
        time.sleep(0.15)
    raise RuntimeError("BRIDGE_TIMEOUT")


def validate_run_args(args):
    if not isinstance(args, list) or len(args) != 27 or not all(
            isinstance(x, str) and len(x) <= 512 and "\n" not in x and "\0" not in x
            for x in args):
        raise RuntimeError("TIMER_COMMAND_SHAPE_INVALID")
    expected = ["--user", "--quiet", "--collect"]
    if args[:3] != expected or args[4:9] != [
            "--on-active=100s", "--timer-property=AccuracySec=1s",
            "--timer-property=RandomizedDelaySec=0", "--property=TimeoutStartSec=30",
            "--setenv=XDG_DATA_HOME=/root/.local/share"]:
        raise RuntimeError("TIMER_OPTIONS_NOT_PRODUCT_SCOPED")
    if args[9:11] != ["/usr/bin/python3", "-B"] or args[12] != "cleanup":
        raise RuntimeError("TIMER_NOT_PRODUCT_CLEANUP")
    name = args[16]
    uuid = args[14]
    if not QA_RE.fullmatch(name) or not UUID_RE.fullmatch(uuid):
        raise RuntimeError("TIMER_IDENTITY_INVALID")
    unit = "oig-operator-qa-" + name[-12:]
    if args[3] != "--unit=" + unit:
        raise RuntimeError("TIMER_UNIT_MISMATCH")
    runner = args[11]
    digest = hashlib.sha256(Path("/work/app/backend/linux/operator_rollback.py").read_bytes()).hexdigest() if Path("/work/app/backend/linux/operator_rollback.py").is_file() else hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    if runner != "/root/.local/share/OpenInternetGateway/qa-rollback/cleanup-" + digest + ".py":
        raise RuntimeError("TIMER_HELPER_NOT_DURABLE_OR_UNPINNED")
    if args[13] != "--uuid" or args[15] != "--name" or args[17:20] != [
            "--artifact-stem", name, "--certificate-directory"]:
        raise RuntimeError("TIMER_ARGUMENTS_UNEXPECTED")
    if args[20] not in (
            "/root/.local/share/networkmanagement/certificates/nm-openvpn",
            "/root/.cert/nm-openvpn"):
        raise RuntimeError("TIMER_CERTIFICATE_NAMESPACE_UNEXPECTED")
    if args[21::2] != ["--ca-sha256", "--cert-sha256", "--key-sha256"]:
        raise RuntimeError("TIMER_CERTIFICATE_HASH_ARGS_UNEXPECTED")
    if any(not HASH_RE.fullmatch(x) for x in args[22::2]):
        raise RuntimeError("TIMER_CERTIFICATE_PINS_INVALID")
    return unit


def container_client(mode, argv):
    scope(False)
    ensure_bridge(BRIDGE, False)
    if mode == "--client-run":
        unit = validate_run_args(argv)
        store(BRIDGE / "request.json", {"args": argv, "unit": unit}, mode=0o644)
        armed = wait_file(BRIDGE / "armed.json", 22)
        if not armed.get("realUserSystemdTimerActive") or armed.get("unit") != unit:
            raise RuntimeError("TIMER_HOST_NOT_ARMED")
        return 0
    if mode == "--client-check":
        if len(argv) != 3 or argv[:2] != ["--user", "is-active"]:
            raise RuntimeError("SYSTEMCTL_REQUEST_NOT_SCOPED")
        armed = wait_file(BRIDGE / "armed.json", 5)
        if argv[2] != armed.get("unit", "") + ".timer" or not armed.get("realUserSystemdTimerActive"):
            raise RuntimeError("SYSTEMCTL_TIMER_NOT_CONFIRMED")
        print("active")
        return 0
    raise RuntimeError("INVALID_CLIENT_MODE")


def cmd(argv, timeout=10):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)


def host_service(folder, container):
    # This process is executed by the actual GitHub runner's user-systemd
    # manager. It receives NO provider password or private PEM over the bridge.
    scope(True)
    if (not CONTAINER_RE.fullmatch(container)
            or container != "oig-hosted-nm-" + os.environ["GITHUB_RUN_ID"]):
        raise RuntimeError("REFUSED: invalid hosted timer callback")
    ensure_bridge(folder, True)
    data = read_json(folder / "request.json")
    args = data["args"]
    unit = validate_run_args(args)
    if data.get("unit") != unit or not (folder / "armed.json").is_file():
        raise RuntimeError("CALLBACK_NOT_ARMED")
    proc = cmd(["docker", "exec", "--user", "root", container, args[9], "-B",
                args[11], *args[12:]], timeout=55)
    try:
        answer = json.loads(proc.stdout)
    except (ValueError, TypeError):
        answer = {}
    success = (proc.returncode == 0 and answer.get("ok") is True
               and answer.get("profileRemoved") is True
               and answer.get("certificateArtifactsRemoved") is True)
    store(folder / "fired.json", {
        "realHostedUserTimerFired": True,
        "unmodifiedDurableHelperCleanup": success,
        "dockerExecExitCode": proc.returncode,
        "scopedUuidCleaned": bool(success),
    })
    if not success:
        raise RuntimeError("TIMER_CALLBACK_CLEANUP_FAILED")


def host_agent(folder, container):
    scope(True)
    if not CONTAINER_RE.fullmatch(container) or container != "oig-hosted-nm-" + os.environ["GITHUB_RUN_ID"]:
        raise RuntimeError("HOSTED_DOCKER_TARGET_INVALID")
    ensure_bridge(folder, True)
    user = cmd(["systemctl", "--user", "is-system-running"], timeout=8)
    if user.returncode not in (0, 1) or user.stdout.strip() not in ("running", "degraded", "starting"):
        raise RuntimeError("RUNNER_USER_SYSTEMD_UNAVAILABLE")
    # Host runner user manager is available before any container starts.
    store(folder / "ready.json", {"realHostedUserManagerAvailable": True}, mode=0o644)
    unit = None
    try:
        request = wait_file(folder / "request.json", 520)
        args = request["args"]
        unit = validate_run_args(args)
        if request.get("unit") != unit:
            raise RuntimeError("BRIDGE_UNIT_INVALID")
        service = ["systemd-run", "--user", "--quiet", "--collect",
                   "--unit=" + unit, "--on-active=100s",
                   "--timer-property=AccuracySec=1s",
                   "--timer-property=RandomizedDelaySec=0",
                   "--property=TimeoutStartSec=65",
                   "--setenv=GITHUB_ACTIONS=true",
                   "--setenv=RUNNER_ENVIRONMENT=github-hosted",
                   "--setenv=GITHUB_REPOSITORY=GOD13emad/OpenInternetGateway",
                   "--setenv=GITHUB_EVENT_NAME=pull_request",
                   "--setenv=GITHUB_RUN_ID=" + os.environ["GITHUB_RUN_ID"],
                   "/usr/bin/python3", "-B", str(Path(__file__).resolve()),
                   "--timer-service", str(folder), container]
        p = cmd(service, timeout=14)
        if p.returncode:
            raise RuntimeError("REAL_HOSTED_TIMER_REGISTRATION_FAILED")
        p = cmd(["systemctl", "--user", "is-active", unit + ".timer"], timeout=8)
        if p.returncode or p.stdout.strip() != "active":
            raise RuntimeError("REAL_HOSTED_TIMER_NOT_ACTIVE")
        store(folder / "armed.json", {"unit": unit, "realUserSystemdTimerActive": True}, mode=0o644)
        fired = wait_file(folder / "fired.json", 180)
        if not fired.get("unmodifiedDurableHelperCleanup"):
            raise RuntimeError("REAL_HOSTED_TIMER_CLEANUP_FAILED")
        print("OIG_HOSTED_REAL_USER_SYSTEMD_AND_DOCKER_NM_ROLLBACK=PASS", flush=True)
    finally:
        if unit:
            cmd(["systemctl", "--user", "stop", unit + ".timer"], timeout=8)
            cmd(["systemctl", "--user", "reset-failed", unit + ".service"], timeout=8)


def main():
    if len(sys.argv) < 2:
        raise RuntimeError("INVALID_MODE")
    mode = sys.argv[1]
    if mode in ("--client-run", "--client-check"):
        return container_client(mode, sys.argv[2:])
    if mode == "--host-agent" and len(sys.argv) == 4:
        host_agent(Path(sys.argv[2]), sys.argv[3])
        return 0
    if mode == "--timer-service" and len(sys.argv) == 4:
        host_service(Path(sys.argv[2]), sys.argv[3])
        return 0
    raise RuntimeError("INVALID_MODE")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, KeyError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print("OIG_HOSTED_TIMER_BRIDGE_REFUSED: " + str(exc), file=sys.stderr)
        raise SystemExit(2) from None
