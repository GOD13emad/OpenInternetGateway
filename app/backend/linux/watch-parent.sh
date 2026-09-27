#!/usr/bin/env bash
set -u

pid="$1"
start="$2"
root="$3"
lease="$root/state/app-process.lease"
log="$root/evidence/app-exit-watchdog.log"

mkdir -p "$root/state" "$root/evidence"

while [ -r "/proc/$pid/stat" ]; do
  current="$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null || true)"
  [ "$current" = "$start" ] || break
  sleep 1
done

expected="$pid $start"
actual="$(tr -d '\r\n' < "$lease" 2>/dev/null || true)"
if [ "$actual" != "$expected" ]; then
  printf '%s replacement-active expected=%s actual=%s\n' "$(date -Iseconds)" "$expected" "$actual" >>"$log"
  exit 0
fi

printf '%s parent-exited pid=%s\n' "$(date -Iseconds)" "$pid" >>"$log"
OIG_HOME="$root" OIG_COMMON="$root/common" /bin/bash "$root/linux/oig-linux.sh" disconnect >>"$log" 2>&1 || true
rm -f "$lease"
