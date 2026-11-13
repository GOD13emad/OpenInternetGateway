#!/usr/bin/env python3
"""GitHub-hosted disposable user-systemd BindsTo/After crash propagation QA.

Only synthetic, uniquely scoped user units run /usr/bin/sleep; no root
privilege, firewall, NetworkManager, VPN, host routes or DNS are changed.
This tests systemd dependency semantics, NOT installed root boot enforcement.
"""
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import time

SCHEMA = "oig-hosted-systemd-dependency-loss-v1"
REPO = Path(__file__).resolve().parents[2]
BOOTSTRAP = REPO / "app/backend/linux/killswitch_bootstrap.py"
MAX_WAIT = 10


def refuse(message):
    raise RuntimeError(message)


def scope():
    env = os.environ
    uid = os.geteuid()
    run_id = env.get("GITHUB_RUN_ID", "")
    if (sys.argv[1:] != ["--github-hosted-only"]
            or uid == 0 or pwd.getpwuid(uid).pw_name != "runner"
            or Path("/.dockerenv").exists()
            or env.get("GITHUB_ACTIONS") != "true"
            or env.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or env.get("GITHUB_REPOSITORY") != "GOD13emad/OpenInternetGateway"
            or env.get("GITHUB_EVENT_NAME") != "pull_request"
            or not re.fullmatch(r"[0-9]{6,15}", run_id)
            or not env.get("GITHUB_WORKSPACE")
            or Path(env["GITHUB_WORKSPACE"]).resolve() != REPO
            or Path("/proc/1/comm").read_text().strip() != "systemd"):
        refuse("REFUSED: owner host or non-disposable runner")
    temp = Path(env.get("RUNNER_TEMP", "/not-the-runner-temp"))
    if (not temp.is_dir() or temp.is_symlink()
            or temp.stat().st_uid != uid or temp.stat().st_mode & 0o022):
        refuse("REFUSED: untrusted runner receipt directory")
    name = "oig-qa-loss-" + run_id
    return name, temp


def execute(args, timeout=10):
    if not isinstance(args, list) or not all(type(x) is str for x in args):
        refuse("Untrusted systemd argv")
    if args[:2] != ["/usr/bin/systemctl", "--user"]:
        refuse("Only user systemd permitted")
    p = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=timeout, check=False)
    return p


def systemctl(*args, must=False):
    p = execute(["/usr/bin/systemctl", "--user", *args])
    if must and p.returncode != 0:
        refuse("User systemd refused " + args[0] + ": "
               + p.stderr.decode("utf8", "replace")[-280:])
    return p


def active(unit):
    return systemctl("is-active", "--quiet", unit).returncode == 0


def wait_until(check, seconds=MAX_WAIT):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return True
        time.sleep(0.125)
    return bool(check())


def write_exclusive(file, text):
    fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600)
    with os.fdopen(fd, "w", encoding="utf8") as out:
        out.write(text)
        out.flush()
        os.fsync(out.fileno())


def preview_is_strict():
    result = subprocess.run(
        ["/usr/bin/python3", "-B", "-I", str(BOOTSTRAP),
         "--print-noninstallable-nm-gate-preview"],
        capture_output=True, text=True, timeout=6, check=False)
    if result.returncode:
        refuse("Native boot preview unavailable")
    lines = [line.strip() for line in result.stdout.splitlines()
             if line and not line.lstrip().startswith("#")]
    if lines != ["[Unit]", "BindsTo=openinternetgateway-lockdown.service",
                 "After=openinternetgateway-lockdown.service"]:
        refuse("Unexpected real production preview dependency")
    return True


def main():
    name, temp = scope()  # MUST precede ALL systemd/filesystem actions
    preview_is_strict()
    if systemctl("is-system-running").returncode not in (0, 1):
        refuse("Hosted user systemd manager not running")
    if not Path("/usr/bin/sleep").is_file():
        refuse("Fixed synthetic executable unavailable")
    unit_dir = Path.home() / ".config/systemd/user"
    if unit_dir.is_symlink():
        refuse("Untrusted unit directory")
    unit_dir.mkdir(parents=True, exist_ok=True)
    if unit_dir.stat().st_uid != os.geteuid() or unit_dir.stat().st_mode & 0o022:
        refuse("User unit directory not private")
    guard = name + "-guard.service"
    dependent = name + "-dependent.service"
    guard_path = unit_dir / guard
    dependent_path = unit_dir / dependent
    if guard_path.exists() or dependent_path.exists():
        refuse("Existing unit collision")
    receipt_path = temp / "oig-hosted-systemd-dependency-loss.json"
    if receipt_path.exists() or receipt_path.is_symlink():
        refuse("Receipt collision")
    record = {
        "schema": SCHEMA,
        "pass": False,
        "hostedUserSystemdVerified": True,
        "productionBootServiceInstalled": False,
        "productionKillSwitchVerified": False,
        "ownerNetworkManagerTouched": False,
        "ownerNetworkChanged": False,
        "onlySyntheticUnits": True,
        "previewBindsToAfterExact": True,
        "syntheticDependenciesActive": False,
        "unexpectedGuardKillPropagatesStop": False,
        "skippedGuardBlocksDependent": False,
        "ownUnitsRemoved": False,
    }
    cleanup_error = None
    started = False
    created = []
    try:
        write_exclusive(guard_path, (
            "[Unit]\nDescription=Disposable OIG QA guard (not a firewall)\n"
            "[Service]\nType=simple\nExecStart=/usr/bin/sleep 70\n"
            "Restart=no\n"))
        created.append(guard_path)
        write_exclusive(dependent_path, (
            "[Unit]\nDescription=Disposable OIG QA dependent (not NM)\n"
            "BindsTo=" + guard + "\nAfter=" + guard + "\n"
            "[Service]\nType=simple\nExecStart=/usr/bin/sleep 70\n"
            "Restart=no\n"))
        created.append(dependent_path)
        systemctl("daemon-reload", must=True)
        systemctl("start", dependent, must=True)
        started = True
        if not wait_until(lambda: active(guard) and active(dependent), 4):
            refuse("Synthetic dependency startup not observed")
        record["syntheticDependenciesActive"] = True
        # Signal only the synthetic guard's main sleep process. No real
        # service is ever named in a mutating systemctl command.
        systemctl("kill", "--kill-whom=main", "--signal=SIGKILL", guard, must=True)
        if not wait_until(lambda: not active(dependent) and not active(guard)):
            refuse("BindsTo failed to propagate unexpected guard loss")
        if systemctl("is-failed", "--quiet", guard).returncode != 0:
            refuse("Synthetic guard did not enter failed state after SIGKILL")
        record["unexpectedGuardKillPropagatesStop"] = True
        systemctl("stop", dependent)
        systemctl("stop", guard)
        systemctl("reset-failed", dependent, guard)
        # Start condition skip must not leave BindsTo+After dependent active.
        guard_path.write_text(
            "[Unit]\nDescription=Disposable OIG QA skipped guard\n"
            "ConditionPathExists=" + str(temp / (name + "-never-created")) + "\n"
            "[Service]\nType=oneshot\nExecStart=/usr/bin/true\n"
            "RemainAfterExit=yes\n", encoding="utf8")
        systemctl("daemon-reload", must=True)
        systemctl("start", dependent)
        # Do not accept a transitory initial inactive state before systemd
        # has actually processed the skipped prerequisite start job.
        time.sleep(0.75)
        condition = systemctl("show", "-p", "ConditionResult", "--value",
                              guard, must=True).stdout.strip()
        if (condition != b"no"
                or active(guard) or active(dependent)):
            refuse("Skipped guard allowed dependent to start")
        time.sleep(0.25)
        if active(guard) or active(dependent):
            refuse("Skipped guard reactivated dependent")
        record["skippedGuardBlocksDependent"] = True
    finally:
        # The only systemd unit names we ever mutate are this run's exact
        # synthetic names; restore even if an assertion fails.
        for unit in (dependent, guard):
            p = systemctl("stop", unit)
            if p.returncode and started:
                cleanup_error = "SCOPED_UNIT_STOP_FAILED"
        systemctl("reset-failed", dependent, guard)
        for file in reversed(created):
            if file.is_symlink() or not file.is_file():
                cleanup_error = "SCOPED_UNIT_FILE_CHANGED"
            else:
                file.unlink()
        reload = systemctl("daemon-reload")
        if reload.returncode:
            cleanup_error = "SCOPED_RELOAD_FAILED"
        record["ownUnitsRemoved"] = (cleanup_error is None and
                                      not guard_path.exists() and
                                      not dependent_path.exists())
    record["pass"] = (record["syntheticDependenciesActive"]
                      and record["unexpectedGuardKillPropagatesStop"]
                      and record["skippedGuardBlocksDependent"]
                      and record["ownUnitsRemoved"])
    if cleanup_error:
        record["cleanupFailure"] = cleanup_error
    write_exclusive(receipt_path, json.dumps(record, sort_keys=True) + "\n")
    print("OIG_HOSTED_REAL_USER_SYSTEMD_DEPENDENCY_LOSS_RECEIPT="
          + json.dumps(record, sort_keys=True), flush=True)
    if not record["pass"]:
        refuse("Hosted synthetic systemd dependency loss not accepted")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
