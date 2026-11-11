#!/usr/bin/env bash
# App-owned Debian update handoff. Invoked only for /opt OIG installations;
# the embedded one-file installer performs integrity, tunnel and OS-authorization checks.
set -euo pipefail

[[ $# -eq 6 ]] || exit 64
installer="$1"; expected="$2"; version="$3"; wait_pid="$4"; result="$5"; fallback="$6"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ &&
   "$expected" =~ ^[a-f0-9]{64}$ &&
   "$wait_pid" =~ ^[1-9][0-9]{0,9}$ ]] || exit 65
[[ -f "$installer" && ! -L "$installer" &&
   "$(basename "$installer")" == "OpenInternetGateway-Linux-Setup-$version-amd64.run" ]] || exit 65
[[ "$result" == /* && "$fallback" == "/opt/open-internet-gateway/open-internet-gateway" ]] || exit 65
[[ "$(id -u)" -ne 0 ]] || exit 65
umask 077

write_result() {
  local ok="$1" reason="$2"
  python3 - "$result" "$ok" "$reason" "$version" "$expected" <<'PY'
import datetime,json,os,pathlib,sys
name,ok,reason,version,digest=sys.argv[1:]
p=pathlib.Path(name)
p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
temp=p.with_name(p.name+'.writing-'+str(os.getpid()))
fd=os.open(temp,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
try:
    with os.fdopen(fd,'w',encoding='utf-8') as f:
        json.dump({'ok':ok=='true','version':version,'sha256':digest,
                   'installScope':'system-deb','requiresOsAuthorization':True,
                   'reason':reason,'at':datetime.datetime.now(
                       datetime.timezone.utc).isoformat()},f)
        f.write('\n');f.flush();os.fsync(f.fileno())
    os.replace(temp,p)
finally:
    if temp.exists():temp.unlink()
PY
}

fail() {
  write_result false "$1" || :
  if [[ -x "$fallback" ]]; then
    nohup "$fallback" </dev/null >/dev/null 2>&1 &
  fi
  exit 1
}

deadline=$((SECONDS+120))
while kill -0 "$wait_pid" 2>/dev/null; do
  [[ "$SECONDS" -lt "$deadline" ]] || fail 'WAIT_FOR_APP_EXIT_TIMEOUT'
  sleep .2
done

actual="$(sha256sum -- "$installer" | awk '{print tolower($1)}')" || fail 'INSTALLER_HASH_UNAVAILABLE'
[[ "$actual" == "$expected" ]] || fail 'INSTALLER_HASH_CHANGED'
verified="$(timeout 45s bash "$installer" --verify-only)" || fail 'EMBEDDED_DEB_VERIFICATION_FAILED'
[[ "$verified" == "OIG_LINUX_ONECLICK_EMBEDDED_DEB_VERIFIED version=$version sha256="* ]] ||
  fail 'EMBEDDED_DEB_VERSION_MISMATCH'

# Native one-file setup refuses independent active VPNs before apt, installs
# OS dependencies from trusted configured repositories, and launches as user.
# This may show the normal polkit OS-authorization dialog. Never bypass it.
if ! timeout 600s bash "$installer" </dev/null >/dev/null 2>&1; then
  fail 'NATIVE_INSTALLER_REFUSED_OR_FAILED'
fi

installed="$(dpkg-query -W -f='${Version}' open-internet-gateway 2>/dev/null || :)"
[[ "$installed" == "$version" && -x "$fallback" ]] || fail 'INSTALLED_VERSION_OR_EXECUTABLE_MISMATCH'
write_result true 'NATIVE_DEB_INSTALL_COMPLETE'
# The one-file installer already launched exactly this installed app in GUI
# sessions. Do not create another AppImage installation or a second instance.
exit 0
