#!/usr/bin/env bash
# Disposable GitHub-hosted Docker acceptance of the REAL OIG NM importer.
# Never called by the installed app; neither Docker nor NetworkManager is
# started on an owner host. OpenVPN activates ONLY in the private Docker netns.
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
    python3 ca-certificates iproute2 dbus network-manager network-manager-openvpn openvpn curl dnsutils systemd-resolved nftables \
    >>/out/apt-setup.log 2>&1
  mkdir -p /run/dbus
  dbus-daemon --system --fork
  # Run a genuine disposable systemd-resolved D-Bus service. Without this,
  # NetworkManager profile DNS priority proves only saved properties.
  # Docker does not run PID 1 systemd/RuntimeDirectory: the Ubuntu package
  # may leave /run/systemd/resolve root-owned while the daemon runs as the
  # dedicated systemd-resolve user. Repair ONLY this private container path.
  [[ ! -L /run/systemd/resolve ]] || exit 74
  id -u systemd-resolve >/dev/null 2>&1 || exit 74
  install -d -m 0755 -o systemd-resolve -g systemd-resolve /run/systemd/resolve
  resolved_bin=/usr/lib/systemd/systemd-resolved
  [[ -x "$resolved_bin" ]] || {
    echo 'HOSTED_RESOLVED_EXECUTABLE_UNAVAILABLE' >&2
    exit 72
  }
  "$resolved_bin" >/out/resolved-service.log 2>&1 &
  resolved_pid="$!"
  resolved_ready=false
  for _ in $(seq 1 40); do
    if resolvectl status >/dev/null 2>&1; then
      resolved_ready=true
      break
    fi
    kill -0 "$resolved_pid" 2>/dev/null || break
    sleep .25
  done
  [[ "$resolved_ready" == true ]] || {
    echo 'HOSTED_RESOLVED_DBUS_NOT_READY' >&2
    tail -n 8 /out/resolved-service.log >&2
    exit 73
  }
  mkdir -p /etc/NetworkManager
  cat > /etc/NetworkManager/NetworkManager.conf <<'NMCONF'
[main]
plugins=keyfile
dns=systemd-resolved
rc-manager=unmanaged
# Keep Docker's original resolv.conf untouched by NM; real DNS routing is
# checked via resolvectl D-Bus, independent of the container file probe.
# Ubuntu's distribution keyfile policy can mark *all* non-WiFi devices
# strictly unmanaged; unlike device.managed, it cannot be overridden by
# nmcli. Scope it to ONLY the Docker underlay in this disposable namespace.
[keyfile]
unmanaged-devices=interface-name:eth0
[device-oig-container-underlay]
match-device=interface-name:eth0
managed=0
[device-oig-container-base]
match-device=interface-name:oigqa0
managed=1
NMCONF
  NetworkManager --no-daemon --config=/etc/NetworkManager/NetworkManager.conf \
    >/out/nm-service.log 2>&1 &
  nm_pid="$!"
  finish_inner() {
    # The container creates its private receipt as 0600/root. Transfer only
    # the artifact's ownership to the runner user for actions/upload-artifact.
    # Never loosen permissions or mount owner-host sensitive directories.
    for receipt in /out/oig-hosted-native-nm.json /out/oig-hosted-native-nm-live.json /out/oig-hosted-native-nm-fullipv4.json /out/oig-hosted-active-crash-rollback.json /out/oig-hosted-active-timer-rollback.json /out/oig-hosted-nft-killswitch-smoke.json; do
      if [[ -f "$receipt" ]]; then
        chown "${OIG_RUNNER_UID:?}:${OIG_RUNNER_GID:?}" "$receipt"
        chmod 0600 "$receipt"
      fi
    done
    kill "$nm_pid" 2>/dev/null || true
    kill "$resolved_pid" 2>/dev/null || true
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
  # Ensure the fresh, disposable NM instance is not disabled by a
  # distribution networking state file; physical owner hosts never run this.
  nmcli networking on >/out/nm-networking-state.log 2>&1
  test "$(nmcli networking)" = enabled
  # A native VPN connection needs a NetworkManager-owned *active base*
  # interface. Docker eth0 stays unmanaged to preserve the runner's bridge
  # underlay; a disposable dummy with a documentation-only /30 is used as the
  # NM activation base. This modifies no owner or runner-host interface.
  # A pre-created link avoids NM treating an auto-created virtual dummy as
  # unmanaged on Ubuntu's default container device policy.
  ip link add name oigqa0 type dummy
  ip link set oigqa0 up
  if ! nmcli --wait 5 device set oigqa0 managed yes \
      >/out/nm-base-setup.log 2>&1; then
    echo 'HOSTED_DISPOSABLE_NM_BASE_MANAGEMENT_FAILED' >&2
    tail -n 8 /out/nm-base-setup.log >&2
    exit 71
  fi
  if ! nmcli --wait 5 connection add save no type dummy ifname oigqa0 \
      con-name oig-hosted-base ipv4.method manual \
      ipv4.addresses 198.51.100.1/30 ipv4.never-default yes \
      ipv4.dns 9.9.9.9 ipv4.dns-search '~.' ipv4.dns-priority 100 \
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

  # The real full-route acceptance process first fetches the independently
  # pinned provider configuration and public credential page using Docker's
  # original bootstrap resolver, and resolves its peer/HTTPS targets. All
  # sensitive state remains in that process memory. It then pauses BEFORE
  # any VPN activation/route ownership and signals a marker; only --inner
  # switches the disposable resolver to fail-closed normal stub mode.
  OIG_HOSTED_RESOLVER_HANDOFF=1     python3 -B /work/app/tests/hosted-linux-native-nm-live.py --native-fullipv4 &
  full_pid="$!"
  bootstrap_ready=false
  for _ in $(seq 1 160); do
    if [[ -f /run/oig-docker-bootstrap-ready && ! -L /run/oig-docker-bootstrap-ready ]]; then
      bootstrap_ready=true
      break
    fi
    if ! kill -0 "$full_pid" 2>/dev/null; then
      wait "$full_pid" || true
      echo 'HOSTED_FULL_IPV4_PROVIDER_BOOTSTRAP_FAILED_BEFORE_STUB' >&2
      exit 75
    fi
    sleep .25
  done
  [[ "$bootstrap_ready" == true ]] || {
    echo 'HOSTED_FULL_IPV4_PROVIDER_BOOTSTRAP_TIMEOUT' >&2
    exit 75
  }
  echo 'HOSTED_FULL_IPV4_IN_MEMORY_PROVIDER_BOOTSTRAP_BEFORE_TUN=PASS'

  # Disposable Docker ships a REGULAR /etc/resolv.conf with a foreign
  # nameserver. systemd-resolved imports that nameserver as Global even when
  # NM's negative VPN DNS priority suppresses the dummy base DNS. The shipped
  # fail-closed product guard correctly rejects this fallback. Now separately
  # exercise the standard resolved stub mode: the resolver must no longer
  # import the Docker underlay into Global. No host mount/network is used.
  python3 -B - <<'PYSTUB'
import os, pathlib, stat
p=pathlib.Path("/etc/resolv.conf")
info=p.lstat()
if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
        or info.st_nlink != 1 or info.st_size > 4096):
    raise SystemExit("REFUSED: disposable resolver file identity changed")
original=p.read_bytes()
if not original or b"nameserver " not in original:
    raise SystemExit("REFUSED: Docker DNS bootstrap baseline missing")
backup=pathlib.Path("/run/oig-disposable-docker-resolv-original")
fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,"wb") as f:
    f.write(original);f.flush();os.fsync(f.fileno())
with p.open("wb") as f:
    f.write(b"nameserver 127.0.0.53\n");f.flush();os.fsync(f.fileno())
if p.read_bytes()!=b"nameserver 127.0.0.53\n":
    raise SystemExit("REFUSED: Docker-only resolved stub file mismatch")
print("HOSTED_DISPOSABLE_DOCKER_RESOLVED_STUB_MODE_CONFIGURED")
PYSTUB
  # The standalone service in a Docker container does NOT install a
  # SIGHUP reload handler (observed 4452ea8: it died from Hangup). Restart
  # only this already-owned disposable daemon so it discovers the stub
  # resolver mode with no inherited Docker Global DNS. No host systemd unit
  # or DNS state is involved.
  kill -TERM "$resolved_pid" 2>/dev/null || true
  wait "$resolved_pid" 2>/dev/null || true
  "$resolved_bin" >/out/resolved-service-stub.log 2>&1 &
  resolved_pid="$!"
  stub_resolved_ready=false
  for _ in $(seq 1 40); do
    if resolvectl status >/dev/null 2>&1; then
      stub_resolved_ready=true
      break
    fi
    kill -0 "$resolved_pid" 2>/dev/null || break
    sleep .25
  done
  [[ "$stub_resolved_ready" == true ]] || {
    echo 'HOSTED_DOCKER_RESOLVED_STUB_RESTART_FAILED' >&2
    exit 73
  }
  # NM remains the ONLY manager of the dummy-base link DNS. Explicitly
  # reapply that owned link, not the runner's Docker eth0 underlay.
  nmcli --wait 12 device reapply oigqa0 >/out/nm-stub-dns-reapply.log 2>&1 || {
    echo 'HOSTED_DOCKER_NM_BASE_DNS_REAPPLY_FAILED' >&2
    exit 73
  }
  for _ in $(seq 1 15); do
    if python3 -B - <<'PYCHECK'
import re,subprocess,sys
p=subprocess.run(["resolvectl","dns"],capture_output=True,text=True,timeout=6)
if p.returncode or len(p.stdout)>8192:sys.exit(1)
for line in p.stdout.splitlines():
    if line.strip().startswith("Global:") and line.partition(":")[2].strip():
        sys.exit(1)
if not re.search(r"Link\s+\d+\s+\(oigqa0\):.*9\.9\.9\.9",p.stdout):
    sys.exit(1)
PYCHECK
    then
      echo 'HOSTED_DISPOSABLE_RESOLVED_GLOBAL_FALLBACK_REMOVED=PASS'
      break
    fi
    sleep .25
  done
  python3 -B - <<'PYCHECK_FINAL'
import re,subprocess,sys
p=subprocess.run(["resolvectl","dns"],capture_output=True,text=True,timeout=6)
assert p.returncode==0
assert not any(line.strip().startswith("Global:") and line.partition(":")[2].strip()
               for line in p.stdout.splitlines()),"DOCKER_GLOBAL_DNS_FALLBACK_PERSISTED"
assert re.search(r"Link\s+\d+\s+\(oigqa0\):.*9\.9\.9\.9",p.stdout),"DOCKER_BASE_NM_DNS_NOT_PRESERVED"
print("HOSTED_DISPOSABLE_NORMAL_RESOLVED_STUB_INVENTORY_PASS")
PYCHECK_FINAL
  [[ ! -e /run/oig-docker-stub-ready && ! -L /run/oig-docker-stub-ready ]] || exit 75
  (umask 077; : > /run/oig-docker-stub-ready)
  wait "$full_pid"
  echo 'HOSTED_FULL_IPV4_IN_MEMORY_BOOTSTRAP_AND_STUB_HANDOFF_PASS'
  # Re-enter the original Docker DNS bootstrap mode between independent test
  # cases. The exact private baseline file is restored only inside --inner.
  python3 -B - <<'PYRESTORE'
import os,pathlib,stat
b=pathlib.Path("/run/oig-disposable-docker-resolv-original")
i=b.lstat()
assert stat.S_ISREG(i.st_mode) and i.st_uid==0 and stat.S_IMODE(i.st_mode)==0o600
assert i.st_size<=4096 and i.st_nlink==1
raw=b.read_bytes()
assert raw and b"nameserver " in raw
p=pathlib.Path("/etc/resolv.conf")
assert p.read_bytes()==b"nameserver 127.0.0.53\n"
with p.open("wb") as f:
    f.write(raw);f.flush();os.fsync(f.fileno())
assert p.read_bytes()==raw
print("HOSTED_DOCKER_RESOLVER_BOOTSTRAP_RESTORED_EXACT")
PYRESTORE
  # No daemon reload required after restoring Docker's own libc resolver:
  # the scoped crash QA uses Docker bootstrap directly and the container is
  # destroyed after this last independent test.
  # Separate proof: a real authenticated OpenVPN TUN is active while its
  # owning process is SIGKILLed. An independent watchdog then executes the
  # unchanged production rollback helper on that exact UUID. This does NOT
  # claim a real systemd timer in the Docker container.
  python3 -B /work/app/tests/hosted-linux-nm-active-crash-rollback.py --supervise
  # The next gate exercises the same REAL NM/TUN lifecycle with the actual
  # product arm(), real hosted user-systemd timer and durable helper. Only the
  # timer transport is bridged across the disposable Docker user-bus boundary.
  python3 -B /work/app/tests/hosted-linux-nm-active-crash-rollback.py --timer-supervise
  # PROTOTYPE only: temporary nftables table is applied and removed INSIDE
  # this disposable Docker netns, after every real VPN test has finished.
  python3 -B /work/app/tests/hosted-linux-nft-killswitch-smoke.py --isolated-docker-only
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
mkdir -m 700 "$out/oig-hosted-timer-bridge"
# A real GitHub-hosted user-systemd manager schedules a single, scoped cleanup
# inside the isolated container. No host network namespace is entered.
python3 -B app/tests/hosted-linux-user-timer-bridge.py --host-agent \
  "$out/oig-hosted-timer-bridge" "$name" > "$out/hosted-timer-agent.log" 2>&1 &
timer_agent_pid=$!
trap 'docker rm -f "$name" >/dev/null 2>&1 || true; kill "$timer_agent_pid" >/dev/null 2>&1 || true' EXIT
for _ in $(seq 1 40); do
  [[ -f "$out/oig-hosted-timer-bridge/ready.json" ]] && break
  kill -0 "$timer_agent_pid" 2>/dev/null || break
  sleep .25
done
[[ -f "$out/oig-hosted-timer-bridge/ready.json" ]] || {
  echo 'HOSTED_USER_SYSTEMD_MANAGER_UNAVAILABLE_BEFORE_DOCKER' >&2
  tail -n 12 "$out/hosted-timer-agent.log" >&2
  exit 78
}
# The only writable mount is a fresh artifact folder. Source is read-only.
# Docker has its own separate network namespace and only CAP_NET_ADMIN and
# /dev/net/tun, not --privileged or host networking.
timeout 600s docker run --rm --name "$name" \
  --cap-add=NET_ADMIN --device=/dev/net/tun \
  --network bridge --security-opt no-new-privileges \
  -v "$PWD:/work:ro" -v "$out:/out:rw" \
  -e OIG_HOSTED_CONTAINER=1 -e OIG_HOSTED_TIMER_BRIDGE=1 \
  -e OIG_RUNNER_UID="$(id -u)" -e OIG_RUNNER_GID="$(id -g)" \
  -e GITHUB_ACTIONS -e RUNNER_ENVIRONMENT -e GITHUB_REPOSITORY \
  -e GITHUB_EVENT_NAME -e GITHUB_RUN_ID \
  ubuntu:24.04 bash /work/app/tests/hosted-linux-native-nm.sh --inner
wait "$timer_agent_pid" || {
  echo 'HOSTED_REAL_USER_SYSTEMD_TIMER_BRIDGE_FAILED' >&2
  tail -n 12 "$out/hosted-timer-agent.log" >&2
  exit 78
}
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

test -s "$out/oig-hosted-native-nm-fullipv4.json"
python3 -B - "$out/oig-hosted-native-nm-fullipv4.json" <<'PYFULL'
import json,sys
d=json.load(open(sys.argv[1],encoding='utf-8'))
assert d.get('pass') is True
assert d.get('nativeNmAuthenticated') is True
assert d.get('fullIPv4RoutesOwned') is True
assert d.get('nmPinnedDnsPriorityConfigVerified') is True
assert d.get('nmActiveDnsRoutingPolicyVerified') is True
assert d.get('resolvedVpnDnsOnlyPolicyVerified') is True
assert d.get('resolvedQueryViaVpnVerified') is True
assert d.get('productionDnsGuardRealNmResolvedVerified') is True
assert d.get('productionDnsGuardForeignLinkRejected') is True
assert d.get('productionDnsGuardRecoveredAfterForeignRevert') is True
assert d.get('foreignLinkDnsBaselineRestoredExact') is True
assert d.get('temporaryNmAliasRestored') is True
assert d.get('resolvedDnsPolicyRestored') is True
assert d.get('explicitResolverDnsViaTun') is True
assert d.get('containerDefaultDnsViaTunVerified') is True
assert d.get('containerDefaultResolverRestoredExact') is True
assert d.get('nativeNmMeasuredVpnBoundThroughput') is True
assert d.get('nativeNmDownloadBytes', 0) >= 900000
assert d.get('nativeNmUploadBytes', 0) >= 262144
assert d.get('nativeNmDownloadMbps', 0) > 0
assert d.get('nativeNmUploadMbps', 0) > 0
assert d.get('tunnelBoundHttpsSucceeded') is True
assert d.get('containerNetworkRestored') is True
assert d.get('temporaryProfileAndPEMCleanupVerified') is True
assert d.get('fullDeviceTunnelVerified') is False
assert d.get('systemDnsLeakContainmentVerified') is False
assert d.get('productionKillSwitchVerified') is False
print('HOSTED_NATIVE_NM_DISPOSABLE_IPV4_FULL_ROUTE_AND_ROLLBACK_PASS')
PYFULL

test -s "$out/oig-hosted-active-crash-rollback.json"
python3 -B - "$out/oig-hosted-active-crash-rollback.json" <<'PYCRASH'
import json,sys
r=json.load(open(sys.argv[1],encoding="utf8"))
assert r.get("pass") is True
assert r.get("activatorKilledAfterRealTunHttps") is True
assert r.get("independentWatcherSurvivedSIGKILL") is True
assert r.get("realActiveVpnProfileAndCertificatesRemoved") is True
assert r.get("containerNetworkRestored") is True
assert r.get("independentBasePreserved") is True
assert r.get("productionCrashRollbackVerified") is False
assert r.get("systemDnsLeakContainmentVerified") is False
assert r.get("productionKillSwitchVerified") is False
print("HOSTED_DISPOSABLE_REAL_ACTIVE_OPENVPN_SIGKILL_CLEANUP_PASS")
PYCRASH

test -s "$out/oig-hosted-active-timer-rollback.json"
python3 -B - "$out/oig-hosted-active-timer-rollback.json" <<'PYTIMER'
import json,sys
r=json.load(open(sys.argv[1],encoding="utf8"))
assert r.get("pass") is True
assert r.get("activatorKilledAfterRealTunHttps") is True
assert r.get("realHostedUserSystemdTimerFiredAfterSIGKILL") is True
assert r.get("productArmAndDurableHelperVerified") is True
assert r.get("realActiveVpnProfileAndCertificatesRemoved") is True
assert r.get("containerNetworkRestored") is True
assert r.get("independentBasePreserved") is True
assert r.get("productionCrashRollbackVerified") is False
assert r.get("systemDnsLeakContainmentVerified") is False
assert r.get("productionKillSwitchVerified") is False
print("HOSTED_REAL_USER_SYSTEMD_TIMER_AND_REAL_NM_ACTIVE_TUN_ROLLBACK_PASS")
PYTIMER

test -s "$out/oig-hosted-nft-killswitch-smoke.json"
python3 -B - "$out/oig-hosted-nft-killswitch-smoke.json" <<'PYNFT'
import json,sys
r=json.load(open(sys.argv[1],encoding="utf8"))
assert r.get("pass") is True
assert r.get("nftKernelRulesLoaded") is True
assert r.get("lockdownToTunnelToRelock") is True
assert r.get("nftAtomicTransitionsKernelApplied") is True
assert r.get("kernelForwardPolicyDropPresent") is True
assert r.get("activePhysicalDropCounterDelta", 0) >= 8
assert r.get("relockedPhysicalDropCounterDelta", 0) >= 8
assert r.get("forwardPacketsProbed") is False
assert r.get("bootPersistenceVerified") is False
assert r.get("operatorInterfaceOwnershipVerified") is False
assert r.get("physicalDnsEgressDropCounterAdvanced") is True
assert r.get("isolatedTableRemoved") is True
assert r.get("containerRouteDnsBaselineRestored") is True
assert r.get("productionKillSwitchVerified") is False
assert r.get("persistentBootTimeEnforcementVerified") is False
assert r.get("physicalOwnerNetworkChanged") is False
print("HOSTED_DISPOSABLE_NFT_OUTPUT_DROP_AND_ROLLBACK_PASS")
PYNFT
