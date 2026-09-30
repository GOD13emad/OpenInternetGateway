#!/usr/bin/env python3
import hashlib
import json
import os
import sys

MARKER = "# OIG sandbox hardening: prefer a compatible root-owned setuid helper."
NEEDLE = """if [ $HAVE_NO_SANDBOX -eq 0 ] && ! unshare -Ur true 2>/dev/null ; then
  NO_SANDBOX=(--no-sandbox)
fi"""
REPLACEMENT = """if [ $HAVE_NO_SANDBOX -eq 0 ]; then
  # OIG sandbox hardening: prefer a compatible root-owned setuid helper.
  if [ "$(stat -Lc '%u:%g:%a' "$APPDIR/chrome-sandbox" 2>/dev/null || true)" = "0:0:4755" ]; then
    :
  elif ! unshare -Ur true 2>/dev/null ; then
    NO_SANDBOX=(--no-sandbox)
  fi
fi"""

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def emit(result):
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))

def main():
    runtime = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else ""
    result = {
        "supported": False,
        "hardened": False,
        "changed": False,
        "runtimeRoot": runtime,
        "helper": "",
        "reason": "",
    }
    app_run = os.path.join(runtime, "AppRun")
    local_sandbox = os.path.join(runtime, "chrome-sandbox")
    if not runtime or not os.path.isfile(app_run) or not os.path.lexists(local_sandbox):
        result["reason"] = "Packaged Linux runtime files are unavailable."
        emit(result)
        return 0

    result["supported"] = True
    try:
        local_hash = sha256_file(local_sandbox)
    except Exception as exc:
        result["reason"] = f"Could not hash runtime chrome-sandbox: {exc}"
        emit(result)
        return 0

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

    helper = ""
    for candidate in candidates:
        try:
            st = os.stat(candidate)
            mode = st.st_mode & 0o7777
            if st.st_uid != 0 or st.st_gid != 0 or mode != 0o4755:
                continue
            if sha256_file(candidate) != local_hash:
                continue
            helper = os.path.realpath(candidate)
            break
        except Exception:
            continue

    if not helper:
        result["reason"] = "No hash-compatible root-owned setuid Chromium sandbox was found."
        emit(result)
        return 0

    result["helper"] = helper
    try:
        if os.path.realpath(local_sandbox) != helper:
            tmp_link = local_sandbox + f".oig-link-{os.getpid()}"
            try:
                os.unlink(tmp_link)
            except FileNotFoundError:
                pass
            os.symlink(helper, tmp_link)
            os.replace(tmp_link, local_sandbox)
            result["changed"] = True

        with open(app_run, "r", encoding="utf-8") as f:
            text = f.read()
        if MARKER not in text:
            if NEEDLE not in text:
                result["reason"] = "AppRun sandbox heuristic does not match the expected electron-builder template."
                emit(result)
                return 0
            patched = text.replace(NEEDLE, REPLACEMENT, 1)
            tmp_run = app_run + f".oig-patch-{os.getpid()}"
            mode = os.stat(app_run).st_mode & 0o777
            with open(tmp_run, "w", encoding="utf-8", newline="\n") as f:
                f.write(patched)
            os.chmod(tmp_run, mode)
            os.replace(tmp_run, app_run)
            result["changed"] = True

        st = os.stat(local_sandbox)
        mode = st.st_mode & 0o7777
        with open(app_run, "r", encoding="utf-8") as f:
            patched_now = MARKER in f.read()
        result["hardened"] = (
            st.st_uid == 0
            and st.st_gid == 0
            and mode == 0o4755
            and os.path.realpath(local_sandbox) == helper
            and patched_now
        )
        result["reason"] = (
            "Compatible setuid Chromium sandbox active."
            if result["hardened"]
            else "Sandbox helper or AppRun verification did not pass."
        )
    except Exception as exc:
        result["reason"] = f"Sandbox hardening failed safely: {exc}"

    emit(result)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
