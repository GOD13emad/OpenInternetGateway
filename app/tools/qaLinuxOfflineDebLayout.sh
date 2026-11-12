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
desktop="$scratch/image/usr/share/applications/OpenInternetGateway.desktop"
icon="$scratch/image/usr/share/icons/hicolor/512x512/apps/open-internet-gateway.png"
postrm="$scratch/control/postrm"
[[ -f "$exe" && -x "$exe" && ! -L "$exe" && -f "$helper" && ! -L "$helper" && -f "$desktop" && ! -L "$desktop" && -s "$icon" && ! -L "$icon" && -f "$postrm" && -x "$postrm" ]] || { echo INSTALLED_LAYOUT_MISSING >&2; exit 75; }
[[ -s "$ipv6_guard" && ! -L "$ipv6_guard" ]] || { echo PACKAGED_IPV6_ROUTE_GUARD_MISSING >&2; exit 80; }
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
