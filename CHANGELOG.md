# Changelog

## 2.5.10

- Fixed a Windows Speed TOCTOU race: `benchmarkActive()` now reuses the already validated live status when mapping the active relay instead of running a second independent status probe that could transiently time out and hide the active relay.
- Added regression coverage proving a validated status override marks the live profile active without a second probe.
- Preserves fail-closed behavior: the first live status must still confirm a connected tunnel before throughput measurement begins.

## 2.5.6

- Hardened Linux live status against transient geo/trace failures: when the managed `OIG-VPN-LIVE` connection is active, the effective route is on the tunnel, protected routes are present and DNS is clean, a temporary Cloudflare trace timeout no longer makes the UI falsely report Protection off. The last validated profile supplies temporary IP/country fallback and status exposes `healthProbeDegraded`.
- Kept fail-closed semantics: an explicit trace result of IR, missing managed VPN connection, missing protected route, or DNS poison still reports disconnected/unhealthy.
- Fixed Linux exact-relay failure semantics so a failed foreground relay choice no longer sets global `desired=off`; Auto-Recovery can deterministically restore the previous preferred relay.
- Live Linux regression: forced trace failure remained Connected with `healthProbeDegraded=true`; forced nonexistent exact SHA failed with rc=21 while `desired=on`, and Ensure restored the preferred FI tunnel with two protected routes and clean DNS.
- Preserves v2.5.5 foreground-operation serialization/watchdog hardening, v2.5.4 startup reconciliation/Live Ping/native typography/direct-ISP binding, and v2.5.3 Windows exact Connect/Speed fixes.
- Standardized native form-control typography: select/input/textarea/button controls now inherit the same platform `system-ui` stack as the dashboard, fixing Chromium's Arial fallback in the country selector while keeping the compact 11px selector size.

## 2.5.5

- Serialized Linux foreground Connect/Connect-profile/Refresh against the periodic recovery timer: foreground operations now wait up to 90 seconds for the gateway lock instead of falsely succeeding when the timer owns it, while periodic Ensure yields harmlessly when a foreground operation is active.
- Fully detached the Linux 180-second connection watchdog from stdin/stdout/stderr and made cancellation reap its `sleep` child, preventing orphaned watchdog processes from keeping Electron/Node pipes open after a successful `connect-profile`.
- Hardened Windows Auto-Recovery against an externally disabled Scheduled Task: Repair/Ensure now re-enables the existing user-owned task without a UAC prompt before running recovery.
- Windows status now reports a disabled recovery task explicitly as `Disabled`, and the UI treats that state as unhealthy instead of presenting it as a healthy installed recovery service.
- Preserves all v2.5.4 startup reconciliation, exact Connect/Speed serialization, honest Live Ping labels, native system typography, Linux physical-ISP binding, and stale-request cleanup.

## 2.5.4

- Made **Test all relays** literally cover the entire current relay pool, including quarantined rows, as a read-only direct-path probe; quarantine still blocks Connect/Speed and is not cleared by the test.
- Clarified live latency truth in the Connections table: a completed direct probe with no ICMP/TCP response now shows **No reply**, while **Not tested** is reserved for rows that have not been probed. Source Ping remains separate and is never substituted as a fake live measurement.
- Added explicit tested / replied / no-reply result counts for the fast all-relay probe.
- Standardized the dashboard on the platform-native `system-ui` font stack and `ui-monospace` code stack rather than assuming Inter/Cascadia Code are installed.
- Increased Connections table typography to a more conventional desktop UI size while preserving the compact layout.
- Live Windows validation: the revised fast probe covered all 28 current relays in 4.549 seconds; 4 returned a direct live probe and 24 explicitly returned no reply, with no ambiguous untested rows.
- The same renderer and backend probe semantics are shared with Linux and are validated again in the v2.5.4 Linux release artifact.
- Fixed reopen/startup reconciliation: when the previous session requested protection but the service/routes are down, the UI now restores the protected tunnel through the elevated recovery task instead of showing a dead 0% state.
- Fixed Windows Repair/Ensure from a normal user session by delegating privileged connector work to the existing Highest-runlevel Scheduled Task and waiting for the real service/routes outcome.
- Fixed Linux direct-ISP measurements so an active VPN cannot make `tun0` masquerade as the physical Internet path; Ethernet/Wi-Fi is selected explicitly.
- Removed stale Linux `exact-profile.request` coordination files; exact SHA selection is passed directly to the Linux backend.

## 2.5.3

- Fixed Windows per-relay **Connect** and **Speed** foreground operations racing the elevated Auto-Recovery task.
- Exact relay requests are now owned by the foreground operation: legacy requests are removed before waiting for task idle, then recreated only after the task is ready.
- Exact-connect waits up to 90 seconds for a previous recovery operation to leave Running state instead of firing into a task configured with IgnoreNew.
- Exact-connect validation is bounded to 150 seconds and no longer treats request-file consumption itself as failure; final task/tunnel state is authoritative.
- A failed selected relay no longer sets the whole gateway intent to OFF, so the previous preferred relay can be restored deterministically.
- Windows backend now passes the selected profile SHA explicitly to the Connect control path; Linux exact-profile behavior is unchanged.
- Added regression coverage for foreground request ownership, task serialization, preserved desired state, exact SHA validation and rollback.
- Live Windows validation after the hotfix: Connect reached an exact US relay with current SHA == preferred SHA, desired=on, connector Running and two full routes; Speed then persisted a real benchmark for the same active SHA.

## 2.5.2

- Fixed exact per-row relay switching on Windows so the selected relay request cannot be consumed during a redundant disconnect phase and silently replaced by another relay.
- Exact relay success now requires the active profile SHA and observed exit country to match the selected relay; mismatches fail closed.
- If a selected relay fails, OIG restores the previous validated relay when possible and reports the requested operation as failed rather than presenting a hidden fallback as success.
- Improved the Connect/Speed busy overlay with explicit switching, validation, and throughput progress so a bounded relay transition no longer looks frozen.
- Kept per-row Speed semantics strict: OIG connects and validates the selected relay first, then measures real ping/HTTPS latency, download, and upload through that tunnel.
- Added regression coverage for atomic exact switching, stale-request cleanup, preferred-relay preservation, and recovery behavior.
- Windows installed-product validation: failed exact selection rejected fallback, previous TH relay restored with exact SHA, and real Speed measured 4.39 Mbps download / 0.57 Mbps upload with 936 ms HTTPS latency.
- Published Windows, Linux AppImage, Linux Debian, and SHA256SUMS assets from the same v2.5.2 release workflow.

## 2.5.1

- Fixed Connections live-state desynchronization after Auto-Recovery or independent headless relay changes.
- Backend status now exposes the authoritative active profile SHA when connected.
- The Connections table reconciles its ACTIVE row on every status refresh/event instead of only when the page inventory is first loaded.
- If the live tunnel profile is no longer present in the refreshed relay pool, OIG shows a synthetic ACTIVE row from current tunnel state rather than displaying “nothing connected”.
- Preserves all v2.5.0 Direct ISP benchmark, direct-path Test all, verified updater, Windows upgrade intent-preservation and headless recovery behavior.

## 2.5.0

- Fixed Connections/backend desynchronization after Auto-Recovery or external headless relay changes: live status now carries the active profile SHA, the relay table re-marks ACTIVE on every status refresh, and a synthetic ACTIVE row is shown if the live tunnel profile is no longer present in the current pool.
- Windows upgrade/process shutdown is now distinguished from explicit user Quit: installer-driven dashboard replacement preserves the desired tunnel state, while tray/desktop explicit Quit still disconnects before exit.
- Added **Direct Internet / ISP Baseline** on the Connections page: real ping, download, upload, direct public IP and country measured from the physical Internet adapter rather than the active OIG VPN route.
- Direct measurements explicitly bypass HTTP/SOCKS proxy settings and bind the physical path: Windows uses the physical adapter IPv4 address; Linux binds the physical interface.
- Added observable bypass proof by comparing normal routed egress with direct physical-adapter egress. On the validated Windows machine, OIG VPN remained TH / 27.130.95.200 while Direct Internet measured IR / 164.215.159.13.
- Changed **Test all relays** to probe relay reachability from the direct physical Internet path, not through the active VPN/proxy route, while keeping the active tunnel unchanged.
- Preserved per-row **Speed** as the honest real-throughput measurement through the selected VPN tunnel; application-level proxy settings are disabled for that measurement.
- Optimized direct relay testing by avoiding the full live-status path and using up to 16 bounded concurrent probes.
- Includes the unreleased 2.4.2 Windows Auto-Recovery race hardening: the connector service is stopped and verified Stopped before set-config; configuration fails closed if the service cannot stop.
- Live verification: Windows Direct ISP ≈ 40.46 Mbps down / 5.70 Mbps up / 84 ms while OIG VPN remained connected; Linux Direct ISP ≈ 43.38 Mbps down / 11.11 Mbps up / 84.2 ms, with 27 relays probed in 2.055 seconds.

## 2.4.2 — superseded before release

- This intermediate baseline was not published; its recovery hardening is included in v2.5.0.
- Hardened Windows Auto-Recovery against an observed connector configuration race: when OVPNConnectorService exists but is running while the tunnel is unhealthy, OIG now stops the connector service and verifies the Stopped state before any set-config operation.
- Added a fail-closed guard if the service cannot be stopped within the bounded wait instead of attempting an unsafe configuration mutation.
- Preserved the successful 2.4.1 fast Test all, sortable Connections, verified GitHub updater, Linux lifecycle and multi-country behavior.

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

## 2.5.7 - 2026-09-29
- Fixed exact-relay failure recovery when no tunnel is currently active: the desktop backend now restores the saved preferred/LKG relay instead of requiring `previousActive`.
- Sanitized ANSI terminal escape sequences from backend command stdout/stderr before errors reach the Electron UI.
- Added regression coverage for disconnected-state preferred-relay restoration and terminal-error sanitization.
## 2.5.8 - 2026-09-29
- Fixed explicit Quit so it always performs the idempotent managed disconnect instead of trusting a transient status probe.
- Hardened Windows tunnel status against transient geo-probe loss by reusing the verified managed profile only when the headless connector is running, both protected routes exist, and no DNS poison is observed; degraded status is surfaced explicitly.
- Added regression coverage ensuring Windows explicit Quit is not gated by status.connected and Windows degraded-status semantics match the established Linux pattern.
- Fixed the renderer busy-overlay completion race: delayed terminal backend events now close only the matching action overlay and cannot clear a newer operation.


## 2.5.9 - 2026-09-29
- Treat a failed selected relay with successful rollback as a recovered outcome instead of an IPC exception.
- Prevent Speed from benchmarking the restored fallback when the requested relay failed.
- Strip Electron IPC / PowerShell framing from user-facing relay errors while retaining backend evidence logs.
