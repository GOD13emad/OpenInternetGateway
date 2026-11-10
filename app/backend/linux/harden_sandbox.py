#!/usr/bin/env python3
import hashlib
import json
import os
import stat
import subprocess
import sys


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_compatible_helper(local_hash):
    candidates = []
    env_candidate = os.environ.get("OIG_CHROME_SANDBOX", "").strip()
    if env_candidate:
        candidates.append(env_candidate)
    candidates.extend([
        "/opt/open-internet-gateway/chrome-sandbox",
        "/opt/google/chrome/chrome-sandbox",
        "/usr/lib/chromium/chrome-sandbox",
        "/usr/lib/chromium-browser/chrome-sandbox",
    ])

    for candidate in candidates:
        try:
            details = os.stat(candidate)
            if (
                details.st_uid != 0
                or details.st_gid != 0
                or stat.S_IMODE(details.st_mode) != 0o4755
            ):
                continue
            if sha256_file(candidate) == local_hash:
                return os.path.realpath(candidate)
        except Exception:
            continue
    return ""


def user_namespaces_available():
    try:
        result = subprocess.run(
            ["unshare", "-Ur", "true"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def emit(result):
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))


def main():
    runtime = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else ""
    app_run = os.path.join(runtime, "AppRun")
    local_sandbox = os.path.join(runtime, "chrome-sandbox")
    has_app_run = os.path.isfile(app_run)
    has_sandbox = os.path.lexists(local_sandbox)
    result = {
        "supported": False,
        "hardened": False,
        "changed": False,
        "runtimeRoot": runtime,
        "helper": "",
        "method": "",
        "reason": "Packaged Linux runtime files are unavailable.",
    }

    if not runtime or not os.path.isdir(runtime) or (not has_app_run and not has_sandbox):
        emit(result)
        return 0

    result["supported"] = True
    try:
        if has_app_run:
            local_hash = sha256_file(local_sandbox) if os.path.isfile(local_sandbox) else ""
            helper = find_compatible_helper(local_hash) if local_hash else ""
            selected = os.environ.get("CHROME_DEVEL_SANDBOX", "").strip()
            if (
                helper
                and selected
                and os.path.islink(local_sandbox)
                and os.path.realpath(local_sandbox) == helper
                and os.path.realpath(selected) == helper
            ):
                details = os.stat(local_sandbox)
                if (
                    details.st_uid == 0
                    and details.st_gid == 0
                    and stat.S_IMODE(details.st_mode) == 0o4755
                ):
                    result["helper"] = helper
                    result["method"] = "verified-setuid-helper"
                    result["hardened"] = True
                    result["reason"] = "AppImage launcher installed the exact-hash root-owned setuid helper at Chromium's required local path."
            elif not os.path.lexists(local_sandbox) and user_namespaces_available():
                result["method"] = "user-namespaces"
                result["hardened"] = True
                result["reason"] = "AppImage launcher removed the unusable bundled SUID helper and unprivileged Linux user namespaces are available."
            if not result["hardened"]:
                result["reason"] = (
                    "AppImage launcher did not install a verified root-owned helper at "
                    "chrome-sandbox or remove the bundled helper for user-namespace sandboxing."
                )
        else:
            if has_sandbox:
                details = os.stat(local_sandbox)
                if (
                    details.st_uid == 0
                    and details.st_gid == 0
                    and stat.S_IMODE(details.st_mode) == 0o4755
                ):
                    result["helper"] = os.path.realpath(local_sandbox)
                    result["method"] = "installed-setuid-helper"
                    result["hardened"] = True
                    result["reason"] = "Installed Linux package has a root-owned setuid Chromium sandbox helper."
    except Exception as exc:
        result["reason"] = "Sandbox verification failed safely: " + str(exc)

    emit(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
