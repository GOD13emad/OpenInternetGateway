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
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/out/apt-setup.log 2>&1
  apt-get install -y -qq --no-install-recommends \
    python3 ca-certificates iproute2 dbus network-manager network-manager-openvpn openvpn \
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
  trap 'kill "$nm_pid" 2>/dev/null || true' EXIT
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
  python3 -B /work/app/tests/hosted-linux-native-nm.py --native-import
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
