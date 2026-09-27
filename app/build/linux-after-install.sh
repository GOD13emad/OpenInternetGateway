#!/bin/sh
set -eu
APPDIR="/opt/Open Internet Gateway"
if [ -d "$APPDIR" ]; then
  chmod 0755 "$APPDIR"
  find "$APPDIR" -type d -exec chmod 0755 {} \;
  [ ! -f "$APPDIR/open-internet-gateway" ] || chmod 0755 "$APPDIR/open-internet-gateway"
  [ ! -f "$APPDIR/chrome_crashpad_handler" ] || chmod 0755 "$APPDIR/chrome_crashpad_handler"
  if [ -f "$APPDIR/chrome-sandbox" ]; then
    chown root:root "$APPDIR/chrome-sandbox"
    chmod 4755 "$APPDIR/chrome-sandbox"
  fi
fi
DESKTOP="/usr/share/applications/OpenInternetGateway.desktop"
if [ -f "$DESKTOP" ]; then
  chown root:root "$DESKTOP" 2>/dev/null || true
  chmod 0644 "$DESKTOP"
fi
exit 0
