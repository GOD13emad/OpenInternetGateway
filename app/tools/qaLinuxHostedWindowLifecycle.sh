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

  export OIG_QA_WINDOW_TRACE=1
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
  # xdotool windowclose calls XDestroyWindow and bypasses Electron's
  # BrowserWindow 'close' handler. wmctrl sends _NET_CLOSE_WINDOW via WM.
  wmctrl -ic "$(printf '0x%x' "$window")"
  echo "NATIVE_WM_CLOSE_REQUESTED=graceful"
  # Black-box UX contract: no dashboard remains visible and the background
  # process stays alive. X11 is allowed to destroy/recreate its native XID.
  hidden=false
  visibleMatches=''
  for _ in $(seq 1 80); do
    visibleMatches="$(xdotool search --onlyvisible --name '^Open Internet Gateway$' 2>/dev/null || :)"
    if [[ -z "$visibleMatches" ]]; then hidden=true; break; fi
    sleep .2
  done
  echo "AFTER_CLOSE_VISIBLE_WINDOW_IDS=${visibleMatches:-none}"
  if [[ "$hidden" != true ]]; then
    echo WM_CLOSE_LEFT_DASHBOARD_VISIBLE >&2
    xwininfo -id "$window" 2>&1 | tail -24 >&2 || :
    xprop -id "$window" _NET_WM_STATE WM_STATE 2>&1 | tail -8 >&2 || :
    tail -35 "$work/app.log" >&2 || :
    exit 76
  fi
  # A true titlebar Close must execute the Electron handler, not destroy the XID.
  if ! grep -Eq 'OIG_QA_WINDOW_EVENT close-after-hide .*"visible":false' "$work/app.log"; then
    echo ELECTRON_CLOSE_EVENT_NOT_RECEIVED >&2
    tail -50 "$work/app.log" >&2 || :
    exit 76
  fi
  echo "ELECTRON_NATIVE_CLOSE_HANDLER_PASS=true"
  mainState="$(ps -o stat= -p "$mainpid" 2>/dev/null | tr -d ' ' || : )"
  echo "MAIN_PROCESS_STATE_AFTER_CLOSE=${mainState:-not-found} PID=$mainpid"
  if [[ -z "$mainState" || "$mainState" == *Z* ]]; then
    echo WM_CLOSE_TERMINATED_OR_ZOMBIFIED_BACKGROUND_PROCESS >&2
    tail -35 "$work/app.log" >&2 || :
    exit 77
  fi
  [[ "$(cat "$OIG_HOME/state/desired-state")" == off ]] || exit 78

  timeout 25s "$exe" >"$work/reopen.log" 2>&1 || { echo SECOND_INSTANCE_FAILED >&2; tail -20 "$work/reopen.log" >&2; exit 79; }
  reopenedWindow=''
  for _ in $(seq 1 80); do
    reopenedWindow="$(xdotool search --onlyvisible --name '^Open Internet Gateway$' 2>/dev/null | head -1 || :)"
    [[ -z "$reopenedWindow" ]] || break
    sleep .2
  done
  if [[ -z "$reopenedWindow" ]]; then
    echo SECOND_INSTANCE_WINDOW_NOT_SHOWN >&2
    echo "MAIN_STATE_AFTER_REOPEN=$(ps -o stat= -p "$mainpid" 2>/dev/null || :)"
    echo 'ALL_X11_WINDOWS:' >&2
    xdotool search --name 'Open Internet Gateway' 2>&1 | tail -20 >&2 || :
    echo 'MAIN_APP_LOG:' >&2
    tail -45 "$work/app.log" >&2 || :
    echo 'SECOND_INSTANCE_LOG:' >&2
    tail -40 "$work/reopen.log" >&2 || :
    echo 'ELECTRON_PROCESSES:' >&2
    ps -eo pid,ppid,stat,etime,args | grep -E 'open-internet-gateway|chrome-sandbox' | tail -20 >&2 || :
    exit 80
  fi
  xwininfo -id "$reopenedWindow" | grep -q 'Map State: IsViewable' || exit 80
  grep -q 'OIG_QA_WINDOW_EVENT second-instance-show' "$work/app.log" || exit 80
  grep -q 'OIG_QA_WINDOW_EVENT show-after' "$work/app.log" || exit 80
  echo "DASHBOARD_REOPENED_X11_ID=$reopenedWindow"

  timeout 25s "$exe" --quit >"$work/quit.log" 2>&1 || { echo QUIT_INTENT_FAILED >&2; tail -20 "$work/quit.log" >&2; exit 81; }
  stopped=false
  for _ in $(seq 1 100); do
    stat="$(ps -o stat= -p "$mainpid" 2>/dev/null | tr -d ' ' || :)"
    if [[ -z "$stat" || "$stat" == *Z* ]]; then stopped=true; break; fi
    sleep .2
  done
  [[ "$stopped" == true ]] || { echo QUIT_LEFT_PROCESS_ALIVE >&2; tail -30 "$work/app.log" >&2; exit 82; }
  set +e; wait "$mainpid"; rc=$?; set -e
  mainpid=''
  [[ "$rc" == 0 && "$(cat "$OIG_HOME/state/desired-state")" == off ]] || exit 83
  # The hosted runner has no NetworkManager daemon or live OIG VPN. Verify
  # that the real packaged quit invoked only read-only empty-NM queries.
  [[ -s "$work/nmcli-readonly.log" ]] || { echo NM_FIXTURE_WAS_NOT_EXERCISED >&2; exit 84; }
  grep -q 'UUID,NAME connection show' "$work/nmcli-readonly.log" || exit 84
  if grep -Eq 'connection (down|delete|up|add|modify|import)' "$work/nmcli-readonly.log"; then
    echo UNEXPECTED_NM_MUTATION_ATTEMPT >&2
    exit 84
  fi
  echo 'NATIVE_QUIT_NO_ACTIVE_VPN_WITH_READONLY_EMPTY_NM_PASS=true'
  python3 - "$window" "$reopenedWindow" <<'PY'
import datetime,hashlib,json,os,pathlib,sys
p=pathlib.Path(os.environ['RUNNER_TEMP'])/'oig-linux-window-lifecycle-receipt.json'
d={'head':os.environ['GITHUB_SHA'],'scope':'Disposable hosted Ubuntu, real packaged DEB with 4755 Chromium sandbox, Xvfb/Openbox/tint2, private read-only empty-NetworkManager fixture; actual connected VPN rollback tested separately, no owner GUI/VPN','windowIdBeforeClose':sys.argv[1],'windowIdAfterReopen':sys.argv[2],'nativeCloseRemovedVisibleDashboard':True,'mainRemainedRunning':True,'secondInstanceReopenedDashboard':True,'quitExitedZero':True,'desiredOff':True,'emptyNmFixtureReadOnly':True,'actualVpnDisconnectExercised':False,'sandboxEnabled':True,'pass':True,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
p.write_text(json.dumps(d,sort_keys=True,indent=2)+'\n')
print('LINUX_HOSTED_PACKAGED_WINDOW_LIFECYCLE_PASS=true')
print('RECEIPT_SHA256='+hashlib.sha256(p.read_bytes()).hexdigest())
PY
  exit 0
fi

[[ $# -eq 1 && -f "$1" && "$1" == *.deb ]] || exit 84
work="$(mktemp -d "${RUNNER_TEMP:?}/oig-linux-x11-${GITHUB_RUN_ID}-XXXXXXXX")"
umask 077
mkdir -p "$work/bin" "$work/image" "$work/home/.config" "$work/home/.cache" "$work/home/.local/share/OpenInternetGateway/state" "$work/home/.local/state" "$work/runtime"
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
# The separately-tested provider data plane needs a real NetworkManager;
# this window-lifecycle test only covers Quit while no OIG VPN was ever started.
# Route every nmcli invocation to a private fail-closed empty-NM fixture.
cat >"$work/bin/nmcli" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
: "${OIG_QA_X11_ROOT:?}"
printf '%s\n' "$*" >>"$OIG_QA_X11_ROOT/nmcli-readonly.log"
case " $* " in
  *" connection show "*|*" device show "*|*" device status "*) exit 0 ;;
  *) echo CI_NMCLI_MUTATION_FORBIDDEN >&2; exit 93 ;;
esac
SH
chmod 700 "$work/bin/nmcli"
export PATH="$work/bin:$PATH"
export OIG_QA_X11_ROOT="$work" OIG_QA_X11_EXE="$exe"
export HOME="$work/home" XDG_RUNTIME_DIR="$work/runtime"
export XDG_CONFIG_HOME="$work/home/.config" XDG_CACHE_HOME="$work/home/.cache"
export XDG_DATA_HOME="$work/home/.local/share" XDG_STATE_HOME="$work/home/.local/state"
export OIG_HOME="$work/home/.local/share/OpenInternetGateway" OIG_COMMON="$work/home/.local/share/OpenInternetGateway/common"
export LIBGL_ALWAYS_SOFTWARE=1
unset OIG_CAPTURE_ONLY OIG_CAPTURE_PATH
xvfb-run -a --server-args="-screen 0 1440x960x24 -nolisten tcp" \
  dbus-run-session -- env OIG_QA_X11_CHILD=1 bash "$0" "$1"
