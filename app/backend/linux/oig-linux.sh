#!/usr/bin/env bash
set -euo pipefail

OIG_HOME="${OIG_HOME:-$HOME/.local/share/OpenInternetGateway}"
OIG_COMMON="${OIG_COMMON:-$OIG_HOME/common}"
STATE="$OIG_HOME/state"
EVIDENCE="$OIG_HOME/evidence"
CONN="OIG-VPN-LIVE"
PREFLIGHT_CONN="OIG-VPN-PREFLIGHT"
LEGACY_CONN="OIG-JP-UDP-LIVE"
CONSOLE_CONN="OIG-Console-Gateway"
KEEP="$STATE/linux.keep"
LOCK="$STATE/gateway.lock"
FACTORY_PY="$OIG_HOME/linux/config_factory.py"
DESIRED="$STATE/desired-state"
mkdir -p "$STATE" "$EVIDENCE"

record_intent() {
  local value="$1" reason="${2:-${action:-unknown}}" parent=""
  if [[ -r "/proc/$PPID/cmdline" ]]; then parent="$(tr '\0' ' ' < "/proc/$PPID/cmdline" 2>/dev/null || true)"; fi
  python3 - "$EVIDENCE/intent-history.jsonl" "$value" "$reason" "$$" "$PPID" "$parent" <<'PY' || true
import datetime,json,sys
path,value,reason,pid,ppid,parent=sys.argv[1:]
with open(path,"a",encoding="utf-8") as f:
    f.write(json.dumps({
        "at":datetime.datetime.now().astimezone().isoformat(),
        "desired":value,"reason":reason,"pid":int(pid),"ppid":int(ppid),
        "parentCommand":parent.strip()
    },separators=(",",":"))+"\n")
PY
}

set_desired() {
  printf '%s\n' "$1" > "$DESIRED"
  record_intent "$1" "${2:-${action:-unknown}}"
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
  delete_connection_name "$PREFLIGHT_CONN"
  delete_connection_name "$CONN"
  delete_connection_name "$LEGACY_CONN"
}

json_status() {
  local cf ip loc dns poison routes iface relay auto_state auto effective desired managed_active profile_ip profile_country probe_degraded
  cf="$(curl -4 --max-time 4 -s https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)"
  ip="$(printf '%s\n' "$cf" | awk -F= '$1=="ip"{print $2;exit}')"
  loc="$(printf '%s\n' "$cf" | awk -F= '$1=="loc"{print $2;exit}')"
  dns="$(getent ahostsv4 dns.google 2>/dev/null | awk '{print $1}' | sort -u | paste -sd, - || true)"
  if printf '%s' "$dns" | grep -q '10.10.34.35'; then poison=true; else poison=false; fi

  effective="$(ip -4 route get 1.1.1.1 2>/dev/null | head -1 || true)"
  iface="$(printf '%s\n' "$effective" | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')"
  if [[ "$iface" == tun* || "$iface" == tap* ]]; then routes=2; else routes=0; fi

  managed_active=false
  if nmcli -t -f NAME,TYPE,DEVICE connection show --active 2>/dev/null |
      awk -F: -v n="$CONN" '$1==n && $2=="vpn" {found=1} END{exit(found?0:1)}'; then
    managed_active=true
  fi

  relay=""
  profile_ip=""
  profile_country=""
  profile_pending=false
  if [[ -f "$STATE/current-linux-profile.json" ]]; then
    read -r relay profile_ip profile_country profile_pending < <(python3 - "$STATE/current-linux-profile.json" <<'PY'
import json,sys
try:
    d=json.load(open(sys.argv[1],encoding="utf-8"))
    relay=f"{d.get('serverIP','')}:{d.get('port','')}".strip(':')
    pending=bool(d.get("validationPending",False))
    profile_ip="" if pending else d.get("serverIP","")
    profile_country="" if pending else (d.get("country") or d.get("configuredCountry") or "")
    print(relay, profile_ip, profile_country, "true" if pending else "false")
except Exception:
    print("", "", "", "false")
PY
)
  fi

  probe_degraded=false
  if [[ -z "$loc" && "$managed_active" == true && "$routes" -ge 2 && "$poison" == false && -n "$profile_country" ]]; then
    loc="$profile_country"
    [[ -n "$ip" ]] || ip="$profile_ip"
    probe_degraded=true
  fi

  desired="$(desired_state)"

  if systemctl --user is-enabled openinternetgateway-recovery.timer >/dev/null 2>&1; then
    auto=true
    auto_state="$(systemctl --user is-active openinternetgateway-recovery.timer 2>/dev/null || true)"
  else
    auto=false
    auto_state="Missing"
  fi

  python3 - "$ip" "$loc" "$dns" "$poison" "$routes" "$relay" "$auto" "$auto_state" "$iface" "$desired" "$managed_active" "$probe_degraded" <<'PY'
import json,sys
ip,loc,dns,poison,routes,relay,auto,state,iface,desired,managed,probe_degraded=sys.argv[1:]
dns_list=[x for x in dns.split(",") if x]
r=int(routes or 0)
connected=(r>=2 and managed=="true" and bool(loc) and loc!="IR" and poison=="false")
print(json.dumps({
    "connected":connected,"ip":ip,"country":loc,"dns":dns_list,
    "poison":poison=="true","fullRoutes":r,"relay":relay,
    "autoRecovery":auto=="true","autoRecoveryState":state,"interface":iface,
    "desiredState":desired,"managedTunnelActive":managed=="true",
    "healthProbeDegraded":probe_degraded=="true"
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
    exec 9>&-
    sleeper=''
    trap 'if [[ -n "$sleeper" ]]; then kill "$sleeper" 2>/dev/null || true; wait "$sleeper" 2>/dev/null || true; fi; exit 0' TERM INT
    sleep 180 &
    sleeper=$!
    wait "$sleeper" || exit 0
    trap - TERM INT
    if [[ ! -f "$KEEP" ]]; then
      delete_named_connections
    fi
  ) </dev/null >/dev/null 2>&1 &
  echo $! > "$STATE/watchdog.pid"
}

profile_lines() {
  local only_sha="${1:-}"
  python3 - "$OIG_COMMON/runtime/udp-cache/index.json" "$OIG_COMMON/runtime/config-factory/quarantine.json" "$STATE/preferred-profile.json" "$only_sha" "$STATE/connection-benchmarks.json" "$OIG_COMMON/runtime/config-factory/successes.json" "$OIG_COMMON/runtime/config-factory/failures.json" <<'PY'
import json,sys,os,math,datetime as dt

def load(path,default):
    try: return json.load(open(path,encoding="utf-8-sig"))
    except Exception: return default

data=load(sys.argv[1],[])
q=load(sys.argv[2],{})
pref=load(sys.argv[3],{}).get("sha256","").lower()
only_sha=(sys.argv[4] if len(sys.argv)>4 else "").lower()
bench=load(sys.argv[5],{})
success=load(sys.argv[6],{})
failures=load(sys.argv[7],{})

def num(v,default=None):
    try:
        x=float(v)
        return x if math.isfinite(x) else default
    except Exception: return default

def fresh_iso(value,hours=48):
    if not value: return False
    try:
        ts=dt.datetime.fromisoformat(str(value).replace("Z","+00:00"))
        return (dt.datetime.now(dt.timezone.utc)-ts.astimezone(dt.timezone.utc)).total_seconds() <= hours*3600
    except Exception: return False

def quality(c):
    sha=str(c.get("SHA256","")).lower()
    proto=str(c.get("Protocol","")).lower()
    port=int(c.get("Port",0) or 0)
    b=bench.get(sha,{}) if isinstance(bench.get(sha,{}),dict) else {}
    s=success.get(sha,{}) if isinstance(success.get(sha,{}),dict) else {}
    f=failures.get(sha,{}) if isinstance(failures.get(sha,{}),dict) else {}
    score=0.0
    # OpenVPN is optimized for UDP; TCP remains a restricted-network fallback.
    score += 45.0 if proto=="udp" else 0.0
    # VPN Gate notes that ports below 2000 tend to be more stable.
    if 0 < port < 2000: score += 30.0
    elif proto=="tcp" and port==443: score += 20.0
    sp=num(c.get("Ping"))
    if sp is not None: score += max(-30.0,110.0-sp)
    src_speed=max(0.0,num(c.get("Speed"),0.0) or 0.0)
    if src_speed>0: score += min(120.0,math.log10(src_speed+1.0)*15.0)
    src_score=max(0.0,num(c.get("Score"),0.0) or 0.0)
    if src_score>0: score += min(80.0,math.log10(src_score+1.0)*12.0)
    if s:
        score += 90.0 + min(60.0,15.0*max(1,int(s.get("count",1) or 1)))
    score -= min(240.0,60.0*max(0,int(f.get("count",0) or 0)))
    # A relay that just failed a real handshake/validation is poor recovery
    # material even if VPN Gate still advertises excellent source metrics.
    # Keep the penalty temporary so transient outages can recover naturally.
    if fresh_iso(f.get("last"),6): score -= 320.0
    if pref and sha==pref: score += 20.0
    fast=num(b.get("fastPingMs"))
    if fresh_iso(b.get("fastAt"),24):
        if fast is not None: score += max(-80.0,140.0-fast*0.45)
        elif proto=="tcp" and b.get("fastReachable") is False: score -= 180.0
    down=num(b.get("downloadMbps")); up=num(b.get("uploadMbps")); lat=num(b.get("httpsLatencyMs"))
    if fresh_iso(b.get("at"),72) and (down is not None or up is not None or lat is not None):
        if down is not None: score += min(260.0,down*12.0)
        if up is not None: score += min(120.0,up*15.0)
        if lat is not None: score -= min(220.0,lat*0.25)
    return score

if only_sha:
    data=[c for c in data if str(c.get("SHA256","")).lower()==only_sha]
else:
    for c in data: c["_quality"]=quality(c)
    data=sorted(data,key=lambda c:(-float(c.get("_quality",0.0)),int(c.get("Rank",9999) or 9999)))
n=0
for c in data:
    key=str(c.get("SHA256","")).lower() or f"{c.get('IP','')}:{c.get('Port','')}"
    if key in q: continue
    raw=str(c.get("Profile","")).replace("\\","/")
    leaf=os.path.basename(raw)
    print("\t".join([
        str(c.get("Host","")),str(c.get("IP","")),str(c.get("Port","")),
        leaf,str(c.get("SHA256","")),str(c.get("Protocol","unknown")),str(c.get("Country",""))
    ]))
    n+=1
    if n >= (1 if only_sha else 16): break
PY
}

dns_server_fingerprint() {
  # Compare resolver server values, not transient link identifiers. A parallel
  # VPN with ignore-auto-dns may add an empty tun link to resolvectl output.
  { resolvectl dns 2>/dev/null |
      sed -E 's/^Global:[[:space:]]*//; s/^Link [0-9]+ \([^)]*\):[[:space:]]*//' |
      tr ' ' '\n' |
      grep -E '^(([0-9]{1,3}\.){3}[0-9]{1,3}|[0-9A-Fa-f:]+)$' || true; } |
    sed '/^$/d' | sort -u | sha256sum | awk '{print $1}'
}

preflight_one() {
  local host="$1" ipaddr="$2" port="$3" leaf="$4" expected="$5" protocol="$6" country="$7"
  local profile="$OIG_COMMON/runtime/udp-cache/$leaf"
  [[ -f "$profile" ]] || return 10
  if [[ -n "$expected" ]]; then
    local actual
    actual="$(sha256sum "$profile" | awk '{print $1}')"
    [[ "$actual" == "$expected" ]] || return 11
  fi

  delete_connection_name "$PREFLIGHT_CONN"
  local import_name imported uuid before_route before_dns after_route after_dns
  import_name="$(basename "$profile" .ovpn)"
  delete_connection_name "$import_name"
  before_route="$(ip -4 route get 1.1.1.1 2>/dev/null | head -1 || true)"
  before_dns="$(dns_server_fingerprint)"

  imported="$(nmcli connection import type openvpn file "$profile" 2>&1)" || return 12
  uuid="$(nmcli -t -f UUID,NAME connection show | awk -F: -v n="$import_name" '$2==n {print $1; exit}')"
  [[ -n "$uuid" ]] || return 12
  nmcli connection modify uuid "$uuid" connection.id "$PREFLIGHT_CONN" connection.autoconnect no \
    ipv6.method disabled ipv4.never-default yes ipv4.ignore-auto-routes yes ipv4.ignore-auto-dns yes

  if ! nmcli -w 10 connection up uuid "$uuid" >/dev/null 2>&1; then
    nmcli connection delete uuid "$uuid" >/dev/null 2>&1 || true
    return 13
  fi
  if ! nmcli -t -f UUID,NAME,TYPE connection show --active 2>/dev/null |
      awk -F: -v u="$uuid" '$1==u && $2=="OIG-VPN-PREFLIGHT" && $3=="vpn" {ok=1} END{exit(ok?0:1)}'; then
    nmcli connection down uuid "$uuid" >/dev/null 2>&1 || true
    nmcli connection delete uuid "$uuid" >/dev/null 2>&1 || true
    return 14
  fi

  after_route="$(ip -4 route get 1.1.1.1 2>/dev/null | head -1 || true)"
  after_dns="$(dns_server_fingerprint)"
  nmcli connection down uuid "$uuid" >/dev/null 2>&1 || true
  nmcli connection delete uuid "$uuid" >/dev/null 2>&1 || true
  python3 - "$EVIDENCE/preflight-last.json" "$host" "$ipaddr" "$port" "$protocol" "$country" "$expected" "$before_route" "$after_route" "$before_dns" "$after_dns" <<'PY'
import datetime,json,sys
path,host,ip,port,protocol,country,sha,before_route,after_route,before_dns,after_dns=sys.argv[1:]
route_ok=before_route==after_route
dns_ok=before_dns==after_dns
json.dump({
  "at":datetime.datetime.now().astimezone().isoformat(),"ok":route_ok and dns_ok,
  "host":host,"ip":ip,"port":int(port),"protocol":protocol,"country":country,"sha256":sha,
  "defaultRoutePreserved":route_ok,"dnsStatePreserved":dns_ok,
  "beforeRoute":before_route,"afterRoute":after_route,
  "beforeDnsFingerprint":before_dns,"afterDnsFingerprint":after_dns
},open(path,"w"),indent=2)
PY
  [[ "$before_route" == "$after_route" && "$before_dns" == "$after_dns" ]] || return 15
  return 0
}

write_profile_state() {
  local path="$1" host="$2" ipaddr="$3" port="$4" profile="$5" sha="$6" protocol="$7" configured_country="$8" observed_country="$9" pending="${10:-false}" observed_ip="${11:-}"
  python3 - "$path" "$host" "$ipaddr" "$port" "$profile" "$sha" "$protocol" "$configured_country" "$observed_country" "$pending" "$observed_ip" <<'PY'
import datetime,json,os,sys
path,host,ip,port,profile,sha,protocol,configured_country,observed_country,pending,observed_ip=sys.argv[1:]
data={
  "at":datetime.datetime.now().astimezone().isoformat(),
  "host":host,"serverIP":ip,"port":int(port),"profile":profile,"sha256":sha,
  "protocol":protocol,"configuredCountry":configured_country,"country":observed_country,
  "validationPending":pending.lower()=="true"
}
if observed_ip: data["observedIP"]=observed_ip
tmp=path+".partial"
with open(tmp,"w") as f: json.dump(data,f,indent=2)
os.replace(tmp,path)
PY
}

connect_one() {
  local host="$1" ipaddr="$2" port="$3" leaf="$4" expected="$5" protocol="$6" country="$7"
  local profile="$OIG_COMMON/runtime/udp-cache/$leaf"
  [[ -f "$profile" ]] || return 10

  if [[ -n "$expected" ]]; then
    local actual
    actual="$(sha256sum "$profile" | awk '{print $1}')"
    [[ "$actual" == "$expected" ]] || return 11
  fi

  local state_file="$STATE/current-linux-profile.json"
  local previous_state="$STATE/current-linux-profile.before-connect.json"
  if [[ -f "$state_file" ]]; then cp -f "$state_file" "$previous_state"; else rm -f "$previous_state"; fi

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

  # Persist relay identity immediately. If the caller disappears during the
  # slower geo/data validation phase, status reports the actual active remote
  # instead of stale metadata. Pending state is never a health geo fallback.
  write_profile_state "$state_file" "$host" "$ipaddr" "$port" "$profile" "$expected" "$protocol" "$country" "" true ""

  for _ in 1 2 3 4 5 6; do
    sleep 3
    if healthy; then
      local stat observed_country
      stat="$(json_status)"
      observed_country="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("country",""))' "$stat")"
      if [[ -n "$country" && "$observed_country" != "$country" ]]; then
        continue
      fi
      local observed_ip
      observed_ip="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("ip",""))' "$stat")"
      write_profile_state "$state_file" "$host" "$ipaddr" "$port" "$profile" "$expected" "$protocol" "$country" "$observed_country" false "$observed_ip"
      rm -f "$previous_state"
      touch "$KEEP"
      stop_watchdog
      return 0
    fi
  done

  nmcli connection down uuid "$uuid" >/dev/null 2>&1 || true
  nmcli connection delete uuid "$uuid" >/dev/null 2>&1 || true
  delete_named_connections
  if [[ -f "$previous_state" ]]; then mv -f "$previous_state" "$state_file"; else rm -f "$state_file"; fi
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
  local exact_sha="${1:-}"
  if [[ -z "$exact_sha" ]] && healthy; then
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

  local cycle rc reason stat max_cycle
  max_cycle=1
  [[ -n "$exact_sha" ]] && max_cycle=0
  for ((cycle=0; cycle<=max_cycle; cycle++)); do
    local had=0
    while IFS="$(printf '\t')" read -r host ipaddr port leaf sha protocol country; do
      [[ -n "$ipaddr" ]] || continue
      had=1
      if connect_one "$host" "$ipaddr" "$port" "$leaf" "$sha" "$protocol" "$country"; then
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
    done < <(profile_lines "$exact_sha")

    if [[ -n "$exact_sha" ]]; then
      break
    elif [[ "$cycle" -eq 0 ]]; then
      python3 "$FACTORY_PY" refresh --common "$OIG_COMMON" >/dev/null || true
    elif [[ "$had" -eq 0 ]]; then
      break
    fi
  done

  rm -f "$KEEP"
  stop_watchdog
  delete_named_connections
  python3 "$FACTORY_PY" status --common "$OIG_COMMON" >/dev/null 2>&1 || true
  if [[ -n "$exact_sha" ]]; then
    # A failed foreground relay choice must not turn the whole gateway intent
    # off. The caller can restore the previous preferred relay deterministically.
    echo "Selected relay failed validation." >&2
  else
    echo "No generated relay configuration passed validation." >&2
  fi
  return 21
}

teardown_gateway() {
  rm -f "$KEEP"
  stop_watchdog
  delete_named_connections
  # Do not impose a fixed outage on explicit switches. Wait only while an OIG
  # VPN is actually still active, bounded to one second.
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ! nmcli -t -f NAME,TYPE connection show --active 2>/dev/null | grep -q '^OIG-VPN-.*:vpn$'; then break; fi
    sleep 0.1
  done
}

disconnect_gateway() {
  set_desired off "${1:-${action:-disconnect}}"
  teardown_gateway
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
if [[ "$action" == "connect" || "$action" == "connect-profile" || "$action" == "refresh" || "$action" == "ensure" || "$action" == "factory-refresh" ]]; then
  exec 9>"$LOCK"
  if [[ "$action" == "ensure" ]]; then
    if ! flock -n 9; then
      echo "Another gateway operation is active; periodic recovery skipped."
      exit 0
    fi
  else
    if ! flock -w 90 9; then
      echo "Another gateway operation did not finish within 90 seconds." >&2
      exit 75
    fi
  fi
fi

case "$action" in
  status) json_status ;;
  connect) set_desired on; connect_gateway ;;
  connect-profile)
    [[ -n "${2:-}" ]] || { echo "Profile SHA-256 is required." >&2; exit 64; }
    # When a protected tunnel is already healthy, prove the candidate can
    # complete an OpenVPN handshake without taking default-route/DNS ownership
    # before touching the working connection.
    if healthy; then
      candidate="$(profile_lines "$2" | head -n1 || true)"
      [[ -n "$candidate" ]] || { echo "Selected relay is missing or quarantined." >&2; exit 21; }
      IFS="$(printf '	')" read -r phost pip pport pleaf psha pproto pcountry <<<"$candidate"
      if preflight_one "$phost" "$pip" "$pport" "$pleaf" "$psha" "$pproto" "$pcountry"; then
        :
      else
        rc=$?
        record_failure "$psha" "$phost" "$pip" "$pport" "PREFLIGHT_$rc"
        echo "Selected relay failed non-disruptive OpenVPN preflight; current tunnel preserved." >&2
        exit 21
      fi
    fi
    # Relay switching is not a user disconnect: preserve desired=on before
    # teardown so interruption cannot strand the gateway intent at off.
    set_desired on "connect-profile"
    teardown_gateway >/dev/null 2>&1 || true
    connect_gateway "$2"
    ;;
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
