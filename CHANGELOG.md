# Changelog

## 2.2.2

- Fixed Linux Debian packaging so the installed application lives at `/opt/open-internet-gateway` instead of a path containing spaces.
- Fixed Chromium/Electron zygote startup under the setuid sandbox on Linux.
- Preserved the public product name “Open Internet Gateway” while changing only the internal Linux FPM install directory.
- Updated Debian post-install hardening to target the no-space install path.
- Added a regression test for the Linux package-path/sandbox contract.

## 2.2.1

- Decoupled the Windows product runtime from the OpenVPN Connect desktop UI.
- Added headless Windows runtime through `ovpnconnector.exe` / `OVPNConnectorService`.
- Preserved OpenVPN Connect as an independent manual application.
- Added OIG-owned dynamic system tray with live Connected/Disconnected state.
- Added background-at-login tray startup and single-instance restore behavior.
- Added close-to-tray behavior without terminating the OIG process.
- Hardened Windows Connect/Disconnect state gates around the headless service.
- Added headless relay success prioritization and faster relay failover.
- Added Self-Healing Config Factory cold-start recovery and multi-transport pool management.
- Added success/failure/quarantine ledgers and last-known-good preservation.
- Updated Electron to 44.4.5; npm audit returned zero known vulnerabilities at validation time.
- Added Windows NSIS 2.2.1 installer.
- Rebuilt Linux AppImage and Debian 2.2.1 from the same final Electron source.
- Corrected Debian desktop-entry permissions and package post-install permissions.
- Validated Linux NetworkManager/OpenVPN cold start, JP egress, clean DNS, rollback, and systemd user recovery.

## 2.2.0

- Added modern cross-platform Electron desktop UI.
- Added Overview, Diagnostics, Activity, Settings, Config Factory and Console Gateway surfaces.
- Added Windows/Linux packaging targets and cross-platform backend abstraction.
- Added Config Factory pool telemetry to the dashboard.

## 2.1.0

- Added initial modern cross-platform Electron desktop shell.
- Added Linux NetworkManager/OpenVPN backend.
- Added Linux systemd user Auto-Recovery.
- Added UUID-only NetworkManager lifecycle and connection serialization.
