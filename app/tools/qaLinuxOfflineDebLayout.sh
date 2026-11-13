#!/usr/bin/env bash
# Offline package layout: no apt, no dpkg install, no package scripts, no VPN.
set -euo pipefail
[[ $# -eq 3 && "$(uname -s)" == Linux && "$(id -u)" -ne 0 ]] || { echo NONROOT_LINUX_AND_ARGUMENTS_REQUIRED >&2; exit 71; }
deb="$1"; setup="$2"; version="$3"
[[ -f "$deb" && -f "$setup" && ! -L "$deb" && ! -L "$setup" && "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 72
[[ "$(dpkg-deb -f "$deb" Package)" == open-internet-gateway && "$(dpkg-deb -f "$deb" Version)" == "$version" && "$(dpkg-deb -f "$deb" Architecture)" == amd64 ]] || exit 73
digest="$(sha256sum -- "$deb")"; digest="${digest%% *}"
[[ "$(bash "$setup" --verify-only)" == "OIG_LINUX_ONECLICK_EMBEDDED_DEB_VERIFIED version=$version sha256=$digest" ]] || { echo DEB_ONEFILE_SHA_MISMATCH >&2; exit 74; }
scratch="$(mktemp -d "${TMPDIR:-/tmp}/oig-offline-deb-layout-XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT
mkdir -p "$scratch/control" "$scratch/image"
dpkg-deb -e "$deb" "$scratch/control"
dpkg-deb -x "$deb" "$scratch/image"
exe="$scratch/image/opt/open-internet-gateway/open-internet-gateway"
helper="$scratch/image/opt/open-internet-gateway/chrome-sandbox"
ipv6_guard="$scratch/image/opt/open-internet-gateway/resources/backend/linux/ipv6_route_guard.py"
dns_guard="$scratch/image/opt/open-internet-gateway/resources/backend/linux/dns_route_guard.py"
backend_root="$scratch/image/opt/open-internet-gateway/resources/backend/linux"
source_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
desktop="$scratch/image/usr/share/applications/OpenInternetGateway.desktop"
icon="$scratch/image/usr/share/icons/hicolor/512x512/apps/open-internet-gateway.png"
postrm="$scratch/control/postrm"
[[ -f "$exe" && -x "$exe" && ! -L "$exe" && -f "$helper" && ! -L "$helper" && -f "$desktop" && ! -L "$desktop" && -s "$icon" && ! -L "$icon" && -f "$postrm" && -x "$postrm" ]] || { echo INSTALLED_LAYOUT_MISSING >&2; exit 75; }
[[ -s "$ipv6_guard" && ! -L "$ipv6_guard" ]] || { echo PACKAGED_IPV6_ROUTE_GUARD_MISSING >&2; exit 80; }
[[ -s "$dns_guard" && ! -L "$dns_guard" ]] || { echo PACKAGED_DNS_ROUTE_GUARD_MISSING >&2; exit 80; }
# The native root enforcer is deliberately NOT activated. Nevertheless, the
# installed Debian files must be root-owned, immutable to regular users,
# and identical to this exact checked-out commit. Proves the new security
# code was not silently omitted or mutated by electron-builder.
backend_listing="$(dpkg-deb --contents "$deb")"
for module in killswitch_bootstrap.py killswitch_nft_executor.py \
    nft_killswitch_plan.py killswitch_lifecycle_contract.py \
    killswitch_broker_service.py killswitch_root_observer.py \
    killswitch_broker_ipc.py operator_full_device.py; do
  packaged="$backend_root/$module"
  original="$source_root/backend/linux/$module"
  [[ -f "$packaged" && ! -L "$packaged" && -s "$original" ]] || {
    echo "PACKAGED_ROOT_BACKEND_MISSING=$module" >&2
    exit 81
  }
  cmp -s -- "$original" "$packaged" || {
    echo "PACKAGED_ROOT_BACKEND_SOURCE_MISMATCH=$module" >&2
    exit 81
  }
  mode="$(printf '%s\n' "$backend_listing" |
    grep -F " ./opt/open-internet-gateway/resources/backend/linux/$module" || true)"
  [[ "$mode" == -rw-r--r--\ root/root* ]] || {
    echo "PACKAGED_ROOT_BACKEND_PERMISSIONS_UNTRUSTED=$module" >&2
    exit 81
  }
done
[[ "$backend_listing" != *'/systemd/system/openinternetgateway-lockdown.service'* ]] || {
  echo 'UNAPPROVED_ROOT_SERVICE_INSTALLED' >&2
  exit 82
}
echo 'OIG_DEB_ROOT_BACKEND_EXACT_SOURCE_ROOT_0644_NOT_ACTIVATED_PASS'
python3 -B - "$dns_guard" <<'PYDNS'
import ast, pathlib, sys
ast.parse(pathlib.Path(sys.argv[1]).read_text())
print("PACKAGED_DNS_ROUTE_GUARD_AST_PASS")
PYDNS
printf 'local ::1 dev lo table local\nfe80::/64 dev enp1s0\n' |
  python3 -B "$ipv6_guard" tun0 || { echo PACKAGED_IPV6_ROUTE_GUARD_REJECTED_SAFE_LOCAL >&2; exit 80; }
if printf '2001:4860:4860::/48 dev enp1s0 table 123\n' | python3 -B "$ipv6_guard" tun0; then
  echo PACKAGED_IPV6_ROUTE_GUARD_ACCEPTED_FOREIGN >&2
  exit 80
fi
elf="$(od -An -tx1 -N4 "$exe" | tr -d '[:space:]')"
[[ "$elf" == 7f454c46 ]] || { echo EXECUTABLE_NOT_ELF >&2; exit 76; }
# The archive must retain the root-owned Chromium sandbox mode; never activate it in the scratch directory.
dpkg-deb -c "$deb" | grep -E '^-rwsr-xr-x root/root +[0-9]+ .* \./opt/open-internet-gateway/chrome-sandbox$' >/dev/null || { echo SANDBOX_MODE_MISSING >&2; exit 77; }
grep -Fqx 'Exec=/opt/open-internet-gateway/open-internet-gateway %U' "$desktop" || exit 78
grep -Fqx 'Icon=open-internet-gateway' "$desktop" || exit 78
grep -Fq '/opt/open-internet-gateway/open-internet-gateway' "$postrm" || exit 79
! grep -Fq '/opt/Open Internet Gateway/open-internet-gateway' "$postrm" || exit 79
echo "OIG_OFFLINE_REAL_DEB_LAYOUT_PASS version=$version sha256=$digest"
