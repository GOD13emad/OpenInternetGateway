#!/usr/bin/env bash
# Open Internet Gateway: signed/checksummed DEB embedded in one executable.
# System dependencies are resolved only by native apt, with OS authorization.
set -euo pipefail
OIG_PACKAGE='@PACKAGE@'
OIG_VERSION='@VERSION@'
OIG_ARCH='@ARCH@'
OIG_PAYLOAD_BYTES='@PAYLOAD_BYTES@'
OIG_PAYLOAD_SHA256='@PAYLOAD_SHA256@'
OIG_APP='/opt/open-internet-gateway/open-internet-gateway'
usage() {
  printf '%s\n' 'Open Internet Gateway — Linux one-file installer' \
    '  --verify-only  Verify embedded package without installing anything' \
    '  (no arguments) Install/update app dependencies and launch app'
}
if [[ $# -gt 1 ]] || [[ $# -eq 1 && "$1" != '--verify-only' && "$1" != '--help' ]]; then usage >&2; exit 64; fi
if [[ "${1:-}" == '--help' ]]; then usage; exit 0; fi
verify_only=false
if [[ "${1:-}" == '--verify-only' ]]; then verify_only=true; fi
fail() { printf 'Open Internet Gateway setup refused: %s\n' "$*" >&2; exit 1; }
for cmd in tail sha256sum stat dpkg-deb dpkg apt-get mktemp; do
  command -v "$cmd" >/dev/null 2>&1 || fail "Missing Debian package utility: $cmd"
done
[[ "$(uname -s)" == 'Linux' ]] || fail 'Linux-only installer.'
[[ -f /etc/debian_version ]] || fail 'Supported on Debian/Ubuntu family only.'
[[ "$(dpkg --print-architecture)" == "$OIG_ARCH" ]] || fail "Requires $OIG_ARCH Linux."
[[ "$OIG_PAYLOAD_BYTES" =~ ^[1-9][0-9]+$ ]] || fail 'Invalid payload length.'
[[ "$OIG_PAYLOAD_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail 'Invalid payload digest.'
self="$0"
[[ -f "$self" && ! -L "$self" ]] || fail 'Run the original regular installer file.'
[[ "$(stat -c '%s' -- "$self")" -gt "$OIG_PAYLOAD_BYTES" ]] || fail 'Truncated installer.'
umask 077
work="$(mktemp -d "${TMPDIR:-/tmp}/oig-installer.XXXXXXXX")" || fail 'Cannot allocate private temporary directory.'
cleanup() { if [[ -n "${work:-}" && -d "$work" ]]; then rm -rf -- "$work"; fi; }
trap cleanup EXIT
deb="$work/$(basename "$OIG_PACKAGE")"
tail -c "$OIG_PAYLOAD_BYTES" -- "$self" > "$deb" || fail 'Cannot extract embedded Debian package.'
actual="$(sha256sum -- "$deb" | cut -d' ' -f1)"
[[ "$actual" == "$OIG_PAYLOAD_SHA256" ]] || fail 'Embedded Debian package SHA-256 mismatch.'
[[ "$(stat -c '%s' -- "$deb")" -eq "$OIG_PAYLOAD_BYTES" ]] || fail 'Embedded package length mismatch.'
[[ "$(dpkg-deb -f "$deb" Package)" == 'open-internet-gateway' ]] || fail 'Unexpected Debian package name.'
[[ "$(dpkg-deb -f "$deb" Version)" == "$OIG_VERSION" ]] || fail 'Unexpected Debian version.'
[[ "$(dpkg-deb -f "$deb" Architecture)" == "$OIG_ARCH" ]] || fail 'Unexpected Debian architecture.'
if [[ "$verify_only" == true ]]; then
  printf 'OIG_LINUX_ONECLICK_EMBEDDED_DEB_VERIFIED version=%s sha256=%s\n' "$OIG_VERSION" "$actual"
  exit 0
fi
[[ "$EUID" -ne 0 ]] || fail 'Run as a normal user; native OS authorization is requested separately.'
# A package-manager operation could restart the NetworkManager daemon. Refuse
# instead of silently interrupting an active third-party VPN or routed tunnel.
if command -v nmcli >/dev/null 2>&1; then
  if nmcli -t -f TYPE connection show --active 2>/dev/null | grep -qx vpn; then
    fail 'An active NetworkManager VPN exists. Install after safely ending that session yourself.'
  fi
fi
if command -v ip >/dev/null 2>&1; then
  active_dev="$(ip -4 route get 1.1.1.1 2>/dev/null |
    awk '{for (i=1; i<NF; i++) if ($i=="dev") {print $(i+1); exit}}' || true)"
  if [[ "$active_dev" =~ ^(tun|tap|wg|tailscale|vpn)[A-Za-z0-9_.:-]*$ ]]; then
    fail 'The effective Internet route uses a VPN/tunnel. Refusing to change system packages during the session.'
  fi
  # A split-tunnel VPN can leave the default Internet route on eth0 while
  # serving sensitive IPv4/IPv6 prefixes through tun/wg. A package update
  # may restart NetworkManager and disconnect that independent session.
  # Observe kernel routes in ALL tables, never manipulate the route tables.
  for family in -4 -6; do
    routes="$(ip "$family" route show table all 2>/dev/null)" ||
      fail "Cannot verify $family routes before package changes."
    if grep -Eq '(^|[[:space:]])dev[[:space:]]+(tun|tap|wg|tailscale|vpn)[A-Za-z0-9_.:-]*([[:space:]]|$)' <<< "$routes"; then
      fail "An active $family tunnel route exists. Refusing to change system packages during the session."
    fi
  done
fi
existing="$(dpkg-query -W -f='${Version}' open-internet-gateway 2>/dev/null || true)"
if [[ -n "$existing" ]] && dpkg --compare-versions "$existing" gt "$OIG_VERSION"; then
  fail "Installed version $existing is newer; downgrade refused."
fi
printf '%s\n' \
  'Installing required packages using system repositories. NetworkManager setup may restart network services.' \
  'Do not install during a critical active network session.'
if [[ -t 0 ]] && command -v sudo >/dev/null 2>&1; then
  sudo apt-get update -qq || fail 'Could not update apt package indices.'
  sudo env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends -- "$deb" ||
    fail 'Package installation or dependencies failed.'
elif command -v pkexec >/dev/null 2>&1; then
  pkexec /usr/bin/apt-get update -qq || fail 'OS authorization or apt refresh failed.'
  pkexec /usr/bin/env DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get install --yes --no-install-recommends -- "$deb" ||
    fail 'OS authorization or package installation failed.'
else
  fail 'No OS authorization helper. Run in a terminal with sudo or use the .deb package.'
fi
[[ -x "$OIG_APP" ]] || fail 'Package reported success but application executable is missing.'
if [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
  # Launch as the user; never run Electron as root and never auto-connect VPN.
  nohup "$OIG_APP" >/dev/null 2>&1 </dev/null &
  printf '%s\n' 'OIG_LINUX_ONECLICK_INSTALL_AND_LAUNCH_SUBMITTED'
else
  printf '%s\n' 'OIG_LINUX_ONECLICK_INSTALLED_NO_DISPLAY: launch via the desktop menu.'
fi
exit 0
