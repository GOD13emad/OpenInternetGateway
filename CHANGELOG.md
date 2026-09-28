# Changelog

## 2.4.1

- Fixed GitHub release-asset downloads stalling on some networks by reusing OIG's proven cross-platform curl transport with IPv4, redirects, bounded connect/transfer timeouts and retries.
- Preserved fail-closed update verification: GitHub asset digest, published SHA256SUMS and downloaded bytes must all agree before an installer/package is opened.
- Live updater regression downloaded the published v2.4.0 Linux DEB (99,192,580 bytes) in 6.349 seconds and verified SHA-256 exactly.
- Includes all v2.4.0 features: fast parallel Test all, sortable Connections, per-row real Speed, GitHub Updates center, Node 24 LTS CI and current GitHub Action generations.

## 2.4.0

- Replaced slow Test current with parallel Test all: relay reachability/ping probes run concurrently without changing the active tunnel; live Linux validation tested 27 usable relays in 3.821 seconds while preserving the active JP tunnel.
- Made the Connections table sortable by country, relay, protocol, source ping, live ping, actual download, actual upload and status; missing measurements sort after measured values.
- Kept per-row Speed as the explicit real-tunnel throughput measurement and reduced bounded test payload/time while preserving locally measured download/upload semantics.
- Added an in-app GitHub Updates center for GOD13emad/OpenInternetGateway with current/latest version, release asset and published SHA-256.
- Added fail-closed update verification across the GitHub release asset digest, SHA256SUMS and downloaded bytes before opening an installer/package.
- Updated GitHub Actions to current hosted-runner action generations and Node 24 LTS; npm dependencies report no outdated packages and npm audit reports zero vulnerabilities.
- Preserved all v2.3.1 lifecycle, multi-country, exact-relay, headless OpenVPN, Auto-Recovery and Console Gateway behavior.

## 2.3.1

- Fixed stale ACTIVE relay presentation after the managed tunnel had already disconnected; a relay is now active only when live tunnel health is connected and its SHA matches the current profile state.
- Preserves all 2.3.0 Linux Dock/Quit, multi-country, exact-relay, Connections inventory and real benchmark behavior.

## 2.3.0

- Changed Linux window close behavior: X now hides the dashboard while keeping the application and managed connection alive; explicit “Quit and disconnect” fully exits and disconnects.
- Added a dedicated Connections page with country filtering, relay inventory, protocol, source ping, live measured latency, actual download/upload throughput, and per-relay Connect/Test actions.
- Added honest source-vs-live measurement separation: VPN Gate metadata is never presented as a device measurement.
- Added bounded active-tunnel throughput tests with persisted per-profile results and ICMP/HTTPS latency handling.
- Expanded Config Factory from JP-only discovery to a JP-first diversified multi-country pool, retaining LastKnownGood profiles and country metadata.
- Added explicit preferred-relay selection on Windows and Linux with fallback candidates and exit-country validation.
- Added schema-v2 migration so legacy countryless JP pools self-refresh to the multi-country format.
- Preserved headless Windows OpenVPN runtime, Linux NetworkManager runtime, Auto-Recovery, Console Gateway, failure quarantine, and independent Linux exit watchdog.

## 2.2.4

- Added an independent Linux parent-exit watchdog so closing, terminating, or crashing the desktop process cannot leave the OIG-managed tunnel running.
- The watchdog binds to PID plus Linux process start-time and an app-process lease to avoid PID-reuse and rapid-restart races.
- Preserved the in-process graceful disconnect path as the first line of defense; the independent watchdog is the fail-safe.
- Live design regression proved app exit -> tunnel removed -> desired state OFF -> Auto-Recovery remains OFF.
- Corrected Windows runtime-state auditing to use the authoritative %LOCALAPPDATA%\\OpenInternetGateway backend root rather than the immutable packaged resources copy.

## 2.2.3

- Fixed the dashboard version label so it is derived from the packaged application version instead of a stale hard-coded 2.2.1 string.
- Linux window close / application quit now performs a managed tunnel disconnect before the Electron process exits.
- Added SIGTERM/SIGINT graceful shutdown handling so desktop-environment quit paths also disconnect the managed tunnel.
- Added Linux desired-state persistence: explicit Disconnect/Quit records OFF and Auto-Recovery refuses to reconnect while OFF.
- Preserved Windows close-to-tray behavior; explicit Quit disconnects the OIG-managed tunnel before exit.
- Added regression coverage for runtime-derived version display and quit/disconnect lifecycle.

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
