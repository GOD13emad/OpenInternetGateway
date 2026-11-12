#!/usr/bin/env bash
# Disposable GitHub-hosted Docker acceptance of the REAL OIG NM importer.
# Never called by the installed app; neither Docker nor NetworkManager is
# started on an owner host. No OpenVPN tunnel is activated.
set -euo pipefail

scope_guard() {
  [[ "${GITHUB_ACTIONS:-}" == "true" &&
     "${RUNNER_ENVIRONMENT:-}" == "github-hosted" &&
     "${GITHUB_REPOSITORY:-}" == "GOD13emad/OpenInternetGateway" &&
     "${GITHUB_EVENT_NAME:-}" == "pull_request" &&
     "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ ]] || {
    echo 'REFUSED: owner host or non-disposable runner' >&2
    exit 64
  }
}

if [[ "${1:-}" == '--inner' ]]; then
  scope_guard
  [[ "${OIG_HOSTED_CONTAINER:-}" == "1" && -f /.dockerenv && "$(id -u)" == 0 ]] || exit 64
  test -f /work/app/tests/hosted-linux-native-nm.py
  # Explicit per-container XDG root makes the plugin's inline PEM import
  # location deterministic; no host user-data path is mounted.
  export HOME=/root XDG_DATA_HOME=/root/.local/share
  mkdir -p "$XDG_DATA_HOME"
  chmod 0700 "$XDG_DATA_HOME"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/out/apt-setup.log 2>&1
  apt-get install -y -qq --no-install-recommends \
    python3 ca-certificates iproute2 dbus network-manager network-manager-openvpn openvpn curl \
    >>/out/apt-setup.log 2>&1
  mkdir -p /run/dbus
  dbus-daemon --system --fork
  mkdir -p /etc/NetworkManager
  cat > /etc/NetworkManager/NetworkManager.conf <<'NMCONF'
[main]
plugins=keyfile
dns=none
[device-oig-container-underlay]
match-device=interface-name:eth0
managed=0
NMCONF
  NetworkManager --no-daemon --config=/etc/NetworkManager/NetworkManager.conf \
    >/out/nm-service.log 2>&1 &
  nm_pid="$!"
  finish_inner() {
    # The container creates its private receipt as 0600/root. Transfer only
    # the artifact's ownership to the runner user for actions/upload-artifact.
    # Never loosen permissions or mount owner-host sensitive directories.
    for receipt in /out/oig-hosted-native-nm.json /out/oig-hosted-native-nm-live.json; do
      if [[ -f "$receipt" ]]; then
        chown "${OIG_RUNNER_UID:?}:${OIG_RUNNER_GID:?}" "$receipt"
        chmod 0600 "$receipt"
      fi
    done
    kill "$nm_pid" 2>/dev/null || true
  }
  trap finish_inner EXIT
  nm_ready=false
  for _ in $(seq 1 30); do
    if nmcli --wait 2 general status >/dev/null 2>&1; then
      nm_ready=true
      break
    fi
    kill -0 "$nm_pid" 2>/dev/null || break
    sleep .5
  done
  [[ "$nm_ready" == true ]] || {
    echo 'HOSTED_DISPOSABLE_NM_SERVICE_NOT_AVAILABLE' >&2
    exit 68
  }
  # A native VPN connection needs a NetworkManager-owned *active base*
  # interface. Docker eth0 stays unmanaged to preserve the runner's bridge
  # underlay; a disposable dummy with a documentation-only /30 is used as the
  # NM activation base. This modifies no owner or runner-host interface.
  if ! nmcli --wait 5 connection add save no type dummy ifname oigqa0 \
      con-name oig-hosted-base ipv4.method manual \
      ipv4.addresses 198.51.100.1/30 ipv4.never-default yes \
      ipv6.method disabled >/out/nm-base-setup.log 2>&1; then
    echo 'HOSTED_DISPOSABLE_NM_BASE_CREATE_FAILED' >&2
    tail -n 8 /out/nm-base-setup.log >&2
    exit 69
  fi
  if ! nmcli --wait 12 connection up id oig-hosted-base \
      >>/out/nm-base-setup.log 2>&1; then
    echo 'HOSTED_DISPOSABLE_NM_BASE_ACTIVATION_FAILED' >&2
    tail -n 8 /out/nm-base-setup.log >&2
    exit 70
  fi
  echo 'HOSTED_DISPOSABLE_NM_BASE_ACTIVE=PASS'
  python3 -B /work/app/tests/hosted-linux-native-nm.py --native-import
  # Only the disposable container progresses to real NM/OpenVPN activation.
  # The native live receipt is deliberately separate from the import receipt.
  python3 -B /work/app/tests/hosted-linux-native-nm-live.py --native-scoped-live
  exit 0
fi

[[ "${1:-}" == '--run-hosted-container' && "$#" == 1 ]] || exit 64
scope_guard
[[ -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" ]] || exit 64
test -f app/tests/hosted-linux-native-nm.py
command -v docker >/dev/null
name="oig-hosted-nm-${GITHUB_RUN_ID}"
out="$RUNNER_TEMP/oig-hosted-nm"
mkdir -m 700 "$out"
# The only writable mount is a fresh artifact folder. Source is read-only.
# Docker has its own separate network namespace and only CAP_NET_ADMIN and
# /dev/net/tun, not --privileged or host networking.
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
timeout 600s docker run --rm --name "$name" \
  --cap-add=NET_ADMIN --device=/dev/net/tun \
  --network bridge --security-opt no-new-privileges \
  -v "$PWD:/work:ro" -v "$out:/out:rw" \
  -e OIG_HOSTED_CONTAINER=1 \
  -e OIG_RUNNER_UID="$(id -u)" -e OIG_RUNNER_GID="$(id -g)" \
  -e GITHUB_ACTIONS -e RUNNER_ENVIRONMENT -e GITHUB_REPOSITORY \
  -e GITHUB_EVENT_NAME -e GITHUB_RUN_ID \
  ubuntu:24.04 bash /work/app/tests/hosted-linux-native-nm.sh --inner
test -s "$out/oig-hosted-native-nm.json"
python3 -B - "$out/oig-hosted-native-nm.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1],encoding='utf-8'))
assert d.get('pass') is True and d.get('nativeImportCompatible') is True
assert d.get('trustConstraintsPreserved') is True
assert d.get('containerNetworkUntouched') is True
assert d.get('temporaryProfileRemoved') is True
assert d.get('certificateArtifactsRemoved') is True
assert d.get('networkActivated') is False
print('HOSTED_DISPOSABLE_NATIVE_NETWORKMANAGER_IMPORT_TRUST_ROLLBACK_PASS')
PY

test -s "$out/oig-hosted-native-nm-live.json"
python3 -B - "$out/oig-hosted-native-nm-live.json" <<'PYLIVE'
import json,sys
d=json.load(open(sys.argv[1],encoding='utf-8'))
assert d.get('pass') is True
assert d.get('nativeNmAuthenticated') is True
assert d.get('tunnelBoundHttpsSucceeded') is True
assert d.get('containerNetworkRestored') is True
assert d.get('temporaryProfileAndPEMCleanupVerified') is True
assert d.get('fullDeviceTunnelVerified') is False
assert d.get('systemDnsLeakContainmentVerified') is False
assert d.get('productionKillSwitchVerified') is False
print('HOSTED_DISPOSABLE_NATIVE_NM_SCOPED_LIVE_TUN_AND_ROLLBACK_PASS')
PYLIVE
