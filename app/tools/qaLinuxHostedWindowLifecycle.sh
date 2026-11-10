#!/usr/bin/env bash
# Real packaged-DEB WM close/reopen/quit test on disposable Linux CI only.
set -Eeuo pipefail
[[ "${RUNNER_ENVIRONMENT:-}" == "github-hosted" &&
   "${GITHUB_REPOSITORY:-}" == "GOD13emad/OpenInternetGateway" &&
   -n "${GITHUB_RUN_ID:-}" &&
   "$(id -u)" -ne 0 ]] || { echo DISPOSABLE_GITHUB_HOSTED_LINUX_REQUIRED >&2; exit 71; }

if [[ "${OIG_QA_X11_CHILD:-0}" == 1 ]]; then
  : "${OIG_QA_X11_ROOT:?}" "${OIG_QA_X11_EXE:?}"
  work="$OIG_QA_X11_ROOT"; exe="$OIG_QA_X11_EXE"
  mainpid=''; wmpid=''; dockpid=''
  cleanup() {
    if [[ -n "$mainpid" ]] && kill -0 "$mainpid" 2>/dev/null; then
      kill -TERM "$mainpid" 2>/dev/null || :
      sleep 1
      kill -KILL "$mainpid" 2>/dev/null || :
    fi
    [[ -z "$wmpid" ]] || kill "$wmpid" 2>/dev/null || :
    [[ -z "$dockpid" ]] || kill "$dockpid" 2>/dev/null || :
  }
  trap cleanup EXIT
  openbox >"$work/openbox.log" 2>&1 & wmpid=$!
  tint2 >"$work/tray-host.log" 2>&1 & dockpid=$!
  for _ in $(seq 1 80); do
    if xprop -root _NET_SUPPORTING_WM_CHECK 2>/dev/null | grep -q 'window id'; then break; fi
    sleep .2
  done
  xprop -root _NET_SUPPORTING_WM_CHECK | grep -q 'window id' || exit 72

  "$exe" >"$work/app.log" 2>&1 & mainpid=$!
  window=''
  for _ in $(seq 1 160); do
    window="$(xdotool search --onlyvisible --name '^Open Internet Gateway$' 2>/dev/null | head -1 || :)"
    [[ -z "$window" ]] || break
    kill -0 "$mainpid" 2>/dev/null || { echo APP_EXITED_EARLY >&2; tail -25 "$work/app.log" >&2; exit 73; }
    sleep .2
  done
  [[ -n "$window" ]] || { echo NO_VISIBLE_DASHBOARD >&2; tail -25 "$work/app.log" >&2; exit 74; }
  xwininfo -id "$window" | grep -q 'Map State: IsViewable' || exit 75
  xdotool windowclose "$window"
  hidden=false
  for _ in $(seq 1 80); do
    if xwininfo -id "$window" 2>/dev/null | grep -q 'Map State: IsUnMapped'; then hidden=true; break; fi
    sleep .2
  done
  [[ "$hidden" == true ]] || { echo WM_CLOSE_FAILED_TO_HIDE >&2; exit 76; }
  kill -0 "$mainpid" 2>/dev/null || { echo WM_CLOSE_KILLED_PROCESS >&2; exit 77; }
  [[ "$(cat "$OIG_HOME/state/desired-state")" == off ]] || exit 78

  timeout 25s "$exe" >"$work/reopen.log" 2>&1 || { echo SECOND_INSTANCE_FAILED >&2; tail -20 "$work/reopen.log" >&2; exit 79; }
  reopened=false
  for _ in $(seq 1 80); do
    if xwininfo -id "$window" 2>/dev/null | grep -q 'Map State: IsViewable'; then reopened=true; break; fi
    sleep .2
  done
  [[ "$reopened" == true ]] || { echo SECOND_INSTANCE_WINDOW_NOT_SHOWN >&2; exit 80; }

  timeout 25s "$exe" --quit >"$work/quit.log" 2>&1 || { echo QUIT_INTENT_FAILED >&2; tail -20 "$work/quit.log" >&2; exit 81; }
  stopped=false
  for _ in $(seq 1 100); do
    if ! kill -0 "$mainpid" 2>/dev/null; then stopped=true; break; fi
    sleep .2
  done
  [[ "$stopped" == true ]] || { echo QUIT_LEFT_PROCESS_ALIVE >&2; tail -30 "$work/app.log" >&2; exit 82; }
  set +e; wait "$mainpid"; rc=$?; set -e
  mainpid=''
  [[ "$rc" == 0 && "$(cat "$OIG_HOME/state/desired-state")" == off ]] || exit 83
  python3 - "$window" <<'PY'
import datetime,hashlib,json,os,pathlib,sys
p=pathlib.Path(os.environ['RUNNER_TEMP'])/'oig-linux-window-lifecycle-receipt.json'
d={'head':os.environ['GITHUB_SHA'],'scope':'Disposable GitHub Ubuntu runner, exact built DEB extracted into scratch, root:root 4755 Chromium sandbox, Xvfb/Openbox/tint2; no owner GUI or VPN','windowId':sys.argv[1],'nativeCloseHidWindow':True,'mainRemainedRunning':True,'secondInstanceReopenedSameWindow':True,'quitExitedZero':True,'desiredOff':True,'sandboxEnabled':True,'pass':True,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
p.write_text(json.dumps(d,sort_keys=True,indent=2)+'\n')
print('LINUX_HOSTED_PACKAGED_WINDOW_LIFECYCLE_PASS=true')
print('RECEIPT_SHA256='+hashlib.sha256(p.read_bytes()).hexdigest())
PY
  exit 0
fi

[[ $# -eq 1 && -f "$1" && "$1" == *.deb ]] || exit 84
work="$(mktemp -d "${RUNNER_TEMP:?}/oig-linux-x11-${GITHUB_RUN_ID}-XXXXXXXX")"
umask 077
mkdir -p "$work/image" "$work/home/.config" "$work/home/.cache" "$work/home/.local/share/OpenInternetGateway/state" "$work/home/.local/state" "$work/runtime"
chmod 700 "$work/home" "$work/runtime"
printf 'off\n' >"$work/home/.local/share/OpenInternetGateway/state/desired-state"
dpkg-deb -x "$1" "$work/image"
exe="$work/image/opt/open-internet-gateway/open-internet-gateway"
helper="$work/image/opt/open-internet-gateway/chrome-sandbox"
[[ -x "$exe" && -f "$helper" && ! -L "$helper" ]] || exit 85
# Simulate only the DEB's root-owned SUID helper in private CI scratch.
sudo chown root:root "$helper"
sudo chmod 4755 "$helper"
[[ "$(stat -Lc '%u:%g:%a' "$helper")" == 0:0:4755 ]] || exit 86
export OIG_QA_X11_ROOT="$work" OIG_QA_X11_EXE="$exe"
export HOME="$work/home" XDG_RUNTIME_DIR="$work/runtime"
export XDG_CONFIG_HOME="$work/home/.config" XDG_CACHE_HOME="$work/home/.cache"
export XDG_DATA_HOME="$work/home/.local/share" XDG_STATE_HOME="$work/home/.local/state"
export OIG_HOME="$work/home/.local/share/OpenInternetGateway" OIG_COMMON="$work/home/.local/share/OpenInternetGateway/common"
export LIBGL_ALWAYS_SOFTWARE=1
unset OIG_CAPTURE_ONLY OIG_CAPTURE_PATH
xvfb-run -a --server-args="-screen 0 1440x960x24 -nolisten tcp" \
  dbus-run-session -- env OIG_QA_X11_CHILD=1 bash "$0" "$1"
