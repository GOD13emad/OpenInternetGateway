#!/usr/bin/env bash
set -euo pipefail

OIG_HOME="${OIG_HOME:-$HOME/.local/share/OpenInternetGateway}"
OIG_COMMON="${OIG_COMMON:-$OIG_HOME/common}"
STATE="$OIG_HOME/state"
EVIDENCE="$OIG_HOME/evidence"
CONN="OIG-JP-UDP-LIVE"
CONSOLE_CONN="OIG-Console-Gateway"
KEEP="$STATE/linux.keep"
LOCK="$STATE/gateway.lock"
FACTORY_PY="$OIG_HOME/linux/config_factory.py"
DESIRED="$STATE/desired-state"
mkdir -p "$STATE" "$EVIDENCE"

set_desired() {
  printf '%s\n' "$1" > "$DESIRED"
}

desired_state() {
  if [[ -f "$DESIRED" ]]; then
    tr -d '\r\n' < "$DESIRED"
  else
    echo on
  fi
}

delete_connection_name() {
  local target="$1"
  nmcli -t -f UUID,NAME connection show 2>/dev/null |
    awk -F: -v n="$target" '$2==n {print $1}' |
    while read -r uuid; do
      [[ -n "$uuid" ]] || continue
      nmcli connection down uuid "$uuid" >/dev/null 2>&1 || true
      nmcli connection delete uuid "$uuid" >/dev/null 2>&1 || true
    done
}

delete_named_connections() {
  delete_connection_name "$CONN"
}

json_status() {
  local cf ip loc dns poison routes iface relay auto_state auto effective desired
  cf="$(curl -4 --max-time 4 -s https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)"
  ip="$(printf '%s\n' "$cf" | awk -F= '$1=="ip"{print $2;exit}')"
  loc="$(printf '%s\n' "$cf" | awk -F= '$1=="loc"{print $2;exit}')"
  dns="$(getent ahostsv4 dns.google 2>/dev/null | awk '{print $1}' | sort -u | paste -sd, - || true)"
  if printf '%s' "$dns" | grep -q '10.10.34.35'; then poison=true; else poison=false; fi

  effective="$(ip -4 route get 1.1.1.1 2>/dev/null | head -1 || true)"
  iface="$(printf '%s\n' "$effective" | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')"
  if [[ "$iface" == tun* || "$iface" == tap* ]]; then routes=2; else routes=0; fi

  relay=""
  if [[ -f "$STATE/current-linux-profile.json" ]]; then
    relay="$(python3 - "$STATE/current-linux-profile.json" <<'PY'
import json,sys
try:
    d=json.load(open(sys.argv[1],encoding="utf-8"))
    print(f"{d.get('serverIP','')}:{d.get('port','')}".strip(':'))
except Exception:
    pass
PY
)"
  fi

  desired="$(desired_state)"

  if systemctl --user is-enabled openinternetgateway-recovery.timer >/dev/null 2>&1; then
    auto=true
    auto_state="$(systemctl --user is-active openinternetgateway-recovery.timer 2>/dev/null || true)"
  else
    auto=false
    auto_state="Missing"
  fi

  python3 - "$ip" "$loc" "$dns" "$poison" "$routes" "$relay" "$auto" "$auto_state" "$iface" "$desired" <<'PY'
import json,sys
ip,loc,dns,poison,routes,relay,auto,state,iface,desired=sys.argv[1:]
dns_list=[x for x in dns.split(",") if x]
r=int(routes or 0)
connected=(r>=2 and bool(loc) and loc!="IR" and poison=="false")
print(json.dumps({
    "connected":connected,"ip":ip,"country":loc,"dns":dns_list,
    "poison":poison=="true","fullRoutes":r,"relay":relay,
    "autoRecovery":auto=="true","autoRecoveryState":state,"interface":iface,
    "desiredState":desired
},separators=(",",":")))
PY
}

healthy() {
  python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("connected") and not d.get("poison") and int(d.get("fullRoutes",0))>=2 else 1)' <<<"$(json_status)"
}

stop_watchdog() {
  if [[ -f "$STATE/watchdog.pid" ]]; then
    kill "$(cat "$STATE/watchdog.pid")" 2>/dev/null || true
    rm -f "$STATE/watchdog.pid"
  fi
}

start_watchdog() {
  stop_watchdog
  rm -f "$KEEP"
  (
    sleep 180
    if [[ ! -f "$KEEP" ]]; then
      delete_named_connections
    fi
  ) &
  echo $! > "$STATE/watchdog.pid"
}

profile_lines() {
  python3 - "$OIG_COMMON/runtime/udp-cache/index.json" "$OIG_COMMON/runtime/config-factory/quarantine.json" <<'PY'
import json,sys,os
data=json.load(open(sys.argv[1],encoding="utf-8-sig"))
try:
    q=json.load(open(sys.argv[2],encoding="utf-8-sig"))
except Exception:
    q={}
n=0
for c in data:
    key=str(c.get("SHA256","")).lower() or f"{c.get('IP','')}:{c.get('Port','')}"
    if key in q:
        continue
    p=str(c.get("Profile","")).replace("\\","/")
    leaf=os.path.basename(p)
    print("\t".join([
        str(c.get("Host","")),str(c.get("IP","")),str(c.get("Port","")),
        leaf,str(c.get("SHA256","")),str(c.get("Protocol","unknown"))
    ]))
    n+=1
    if n>=10:
        break
PY
}

connect_one() {
  local host="$1" ipaddr="$2" port="$3" leaf="$4" expected="$5" protocol="$6"
  local profile="$OIG_COMMON/runtime/udp-cache/$leaf"
  [[ -f "$profile" ]] || return 10

  if [[ -n "$expected" ]]; then
    local actual
    actual="$(sha256sum "$profile" | awk '{print $1}')"
    [[ "$actual" == "$expected" ]] || return 11
  fi

  delete_named_connections
  local import_name imported uuid
  import_name="$(basename "$profile" .ovpn)"
  delete_connection_name "$import_name"

  imported="$(nmcli connection import type openvpn file "$profile" 2>&1)" || return 12
  uuid="$(nmcli -t -f UUID,NAME connection show | awk -F: -v n="$import_name" '$2==n {print $1; exit}')"
  [[ -n "$uuid" ]] || return 12

  nmcli connection modify uuid "$uuid" connection.id "$CONN" connection.autoconnect no ipv6.method disabled ipv4.never-default no
  if ! nmcli -w 30 connection up uuid "$uuid" >/dev/null 2>&1; then
    nmcli connection delete uuid "$uuid" >/dev/null 2>&1 || true
    return 13
  fi

  for _ in 1 2 3 4 5 6; do
    sleep 3
    if healthy; then
      python3 - "$STATE/current-linux-profile.json" "$host" "$ipaddr" "$port" "$profile" "$expected" "$protocol" <<'PY'
import json,sys,datetime
path,host,ip,port,profile,sha,protocol=sys.argv[1:]
json.dump({
    "at":datetime.datetime.now().astimezone().isoformat(),
    "host":host,"serverIP":ip,"port":int(port),"profile":profile,
    "sha256":sha,"protocol":protocol
},open(path,"w"),indent=2)
PY
      touch "$KEEP"
      stop_watchdog
      return 0
    fi
  done

  nmcli connection down uuid "$uuid" >/dev/null 2>&1 || true
  nmcli connection delete uuid "$uuid" >/dev/null 2>&1 || true
  delete_named_connections
  return 14
}

record_success() {
  local sha="$1" host="$2" ipaddr="$3" port="$4" stat="$5"
  local obsip country
  obsip="$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(d.get("ip",""))' "$stat")"
  country="$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(d.get("country",""))' "$stat")"
  python3 "$FACTORY_PY" success --common "$OIG_COMMON" --sha "$sha" --host "$host" --ip "$ipaddr" --port "$port" --observed-ip "$obsip" --country "$country" >/dev/null
}

record_failure() {
  local sha="$1" host="$2" ipaddr="$3" port="$4" reason="$5"
  python3 "$FACTORY_PY" failure --common "$OIG_COMMON" --sha "$sha" --host "$host" --ip "$ipaddr" --port "$port" --reason "$reason" >/dev/null 2>&1 || true
}

connect_gateway() {
  if healthy; then
    touch "$KEEP"
    python3 "$FACTORY_PY" status --common "$OIG_COMMON" >/dev/null 2>&1 || true
    echo "ALREADY CONNECTED"
    return 0
  fi

  command -v nmcli >/dev/null
  command -v curl >/dev/null
  command -v python3 >/dev/null

  python3 "$FACTORY_PY" ensure --common "$OIG_COMMON" >/dev/null
  [[ -f "$OIG_COMMON/runtime/udp-cache/index.json" ]] || { echo "Config pool index missing" >&2; return 20; }

  start_watchdog
  local attempts="$EVIDENCE/connect-linux-attempts.jsonl"
  : > "$attempts"

  local cycle rc reason stat
  for cycle in 0 1; do
    local had=0
    while IFS=$'\t' read -r host ipaddr port leaf sha protocol; do
      [[ -n "$ipaddr" ]] || continue
      had=1
      if connect_one "$host" "$ipaddr" "$port" "$leaf" "$sha" "$protocol"; then
        stat="$(json_status)"
        printf '%s\n' "$stat" > "$EVIDENCE/connect-last-success.json"
        record_success "$sha" "$host" "$ipaddr" "$port" "$stat"
        echo "CONNECTED $ipaddr:$port $protocol"
        return 0
      else
        rc=$?
        reason="CODE_$rc"
        printf '{"host":"%s","ip":"%s","port":"%s","protocol":"%s","result":"FAIL","code":%s,"cycle":%s}\n' "$host" "$ipaddr" "$port" "$protocol" "$rc" "$cycle" >> "$attempts"
        record_failure "$sha" "$host" "$ipaddr" "$port" "$reason"
      fi
    done < <(profile_lines)

    if [[ "$cycle" -eq 0 ]]; then
      python3 "$FACTORY_PY" refresh --common "$OIG_COMMON" >/dev/null || true
    elif [[ "$had" -eq 0 ]]; then
      break
    fi
  done

  rm -f "$KEEP"
  stop_watchdog
  delete_named_connections
  python3 "$FACTORY_PY" status --common "$OIG_COMMON" >/dev/null 2>&1 || true
  echo "No generated relay configuration passed validation." >&2
  return 21
}

disconnect_gateway() {
  set_desired off
  rm -f "$KEEP"
  stop_watchdog
  delete_named_connections
  sleep 2
  echo "DISCONNECTED"
}

refresh_cache() {
  python3 "$FACTORY_PY" refresh --common "$OIG_COMMON"
}

ensure_gateway() {
  if [[ "$(desired_state)" != "on" ]]; then
    if healthy; then disconnect_gateway >/dev/null 2>&1 || true; fi
    echo "DESIRED OFF"
    return 0
  fi
  python3 "$FACTORY_PY" ensure --common "$OIG_COMMON" >/dev/null 2>&1 || true
  if healthy; then
    json_status > "$EVIDENCE/auto-recovery-last.json"
    echo "HEALTHY"
    return 0
  fi

  if connect_gateway; then
    json_status > "$EVIDENCE/auto-recovery-last.json"
    echo "RECOVERED"
    return 0
  fi
  return 1
}

install_auto() {
  local userdir="$HOME/.config/systemd/user"
  mkdir -p "$userdir"

  cat > "$userdir/openinternetgateway-recovery.service" <<EOF
[Unit]
Description=Open Internet Gateway health recovery
After=network-online.target NetworkManager.service
Wants=network-online.target

[Service]
Type=oneshot
Environment=OIG_HOME=$OIG_HOME
Environment=OIG_COMMON=$OIG_COMMON
ExecStart=/bin/bash $OIG_HOME/linux/oig-linux.sh ensure
TimeoutStartSec=240
EOF

  cat > "$userdir/openinternetgateway-recovery.timer" <<EOF
[Unit]
Description=Open Internet Gateway recovery timer

[Timer]
OnBootSec=45
OnUnitActiveSec=10min
Persistent=true
Unit=openinternetgateway-recovery.service

[Install]
WantedBy=timers.target
EOF

  systemctl --user daemon-reload
  systemctl --user enable --now openinternetgateway-recovery.timer >/dev/null
  echo "AUTO-RECOVERY INSTALLED"
}

remove_auto() {
  systemctl --user disable --now openinternetgateway-recovery.timer >/dev/null 2>&1 || true
  rm -f "$HOME/.config/systemd/user/openinternetgateway-recovery.timer" "$HOME/.config/systemd/user/openinternetgateway-recovery.service"
  systemctl --user daemon-reload
  echo "AUTO-RECOVERY REMOVED"
}

console_iface() {
  if [[ -n "${OIG_CONSOLE_IF:-}" ]]; then
    echo "$OIG_CONSOLE_IF"
    return
  fi
  local uplink
  uplink="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')"
  nmcli -t -f DEVICE,TYPE,STATE device status |
    awk -F: -v up="$uplink" '$2=="ethernet" && $1!="" && $1!=up && $3!="unmanaged" {print $1; exit}'
}

console_status() {
  local iface state
  iface="$(console_iface)"
  state="missing"
  [[ -n "$iface" ]] && state="$(nmcli -g GENERAL.STATE device show "$iface" 2>/dev/null || echo unknown)"
  python3 - "$iface" "$state" <<'PY'
import json,sys
print(json.dumps({"interface":sys.argv[1],"state":sys.argv[2],"connection":"OIG-Console-Gateway"},separators=(",",":")))
PY
}

console_enable() {
  local iface
  iface="$(console_iface)"
  [[ -n "$iface" ]] || { echo "No dedicated Ethernet adapter found." >&2; return 30; }
  healthy || { echo "Validated VPN tunnel must be active first." >&2; return 31; }
  nmcli connection delete "$CONSOLE_CONN" >/dev/null 2>&1 || true
  nmcli connection add type ethernet ifname "$iface" con-name "$CONSOLE_CONN" ipv4.method shared ipv4.addresses 10.42.42.1/24 ipv6.method disabled >/dev/null
  nmcli connection up "$CONSOLE_CONN" >/dev/null
  echo "CONSOLE GATEWAY ENABLED on $iface"
}

console_disable() {
  nmcli connection down "$CONSOLE_CONN" >/dev/null 2>&1 || true
  nmcli connection delete "$CONSOLE_CONN" >/dev/null 2>&1 || true
  echo "CONSOLE GATEWAY DISABLED"
}

action="${1:-status}"
if [[ "$action" == "connect" || "$action" == "refresh" || "$action" == "ensure" || "$action" == "factory-refresh" ]]; then
  exec 9>"$LOCK"
  if ! flock -n 9; then
    echo "Another gateway operation is active."
    exit 0
  fi
fi

case "$action" in
  status) json_status ;;
  connect) set_desired on; connect_gateway ;;
  disconnect) disconnect_gateway ;;
  refresh) set_desired on; refresh_cache; connect_gateway ;;
  ensure) ensure_gateway ;;
  factory-status) python3 "$FACTORY_PY" status --common "$OIG_COMMON" ;;
  factory-refresh) python3 "$FACTORY_PY" refresh --common "$OIG_COMMON" ;;
  auto-install) install_auto ;;
  auto-remove) remove_auto ;;
  console-status) console_status ;;
  console-enable) console_enable ;;
  console-disable) console_disable ;;
  *) echo "Unknown action: $action" >&2; exit 64 ;;
esac
