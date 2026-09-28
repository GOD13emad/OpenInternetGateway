# Open Internet Gateway

Open Internet Gateway (OIG) is a cross-platform desktop application for maintaining a validated, full-device Internet egress path on restrictive or unreliable networks.

The Windows and Linux backends are different, but both sit behind the same Electron dashboard, lifecycle model, health gates, multi-country relay inventory, Self-Healing Config Factory, and verified GitHub update workflow.

## Current release: 2.5.2

### Connections

The Connections page exposes the current relay inventory with country, endpoint, protocol, source metadata, locally measured latency, real tunnel throughput results, and relay status. Connections active state follows the authoritative live tunnel on every status refresh, including Auto-Recovery changes; if the active tunnel profile is absent from the latest pool, OIG still shows it as an ACTIVE managed relay.

- **Test all relays** performs bounded parallel reachability/latency probes from the physical Internet adapter, bypassing the active OIG VPN route and HTTP/SOCKS proxy settings without switching or disconnecting the tunnel.
- **Test direct Internet** measures the user's own ISP baseline: ping, real download, real upload, direct public IP and country. Windows binds the physical adapter IPv4 address; Linux binds the physical interface.
- **Speed** on a relay performs a real throughput measurement through that selected VPN tunnel; app-level proxy settings are disabled so the measurement is the VPN path itself.
- Columns are sortable by country, relay, protocol, source ping, live ping, measured download, measured upload, and status.
- Source metadata and device-measured results are kept separate; missing or blocked measurements are shown as unavailable rather than fabricated.

The Config Factory keeps a diversified multi-country pool with last-known-good retention, validation history, failure quarantine, and refresh behavior.

### Direct ISP truth boundary

OIG's Direct Internet test binds the physical network path and disables ordinary HTTP/SOCKS proxy use. The UI records the physical adapter/local IP/gateway plus direct public egress. When the active routed egress differs from the direct public egress, the bypass is explicitly marked as observed. A third-party kernel/WFP/endpoint-security product that intercepts traffic below normal socket routing can still override OS routing; OIG surfaces the observed egress instead of assuming bypass succeeded.

### GitHub updates

The **Updates** page checks the official `GOD13emad/OpenInternetGateway` GitHub release feed.

Before an update file is opened, OIG requires all three integrity checks to agree:

1. the SHA-256 digest published by the GitHub release asset,
2. the matching entry in the release `SHA256SUMS.txt`,
3. the SHA-256 of the bytes downloaded by OIG.

Windows selects the NSIS installer. Linux selects the amd64 Debian package with AppImage fallback. The application does not bypass OS privilege approval for installation.

### Windows

OIG does **not** use the OpenVPN Connect desktop UI as its runtime.

- OIG owns its own dashboard and system-tray icon.
- Connect/Disconnect run through OpenVPN Connect's headless `ovpnconnector.exe` / `OVPNConnectorService`.
- `OpenVPNConnect.exe` is not launched by the OIG production backend.
- Your normal OpenVPN Connect application remains independent for manual use.
- Closing the OIG dashboard hides it to the OIG tray and keeps the application/tunnel alive.
- Explicit Quit disconnects the OIG-managed tunnel before the application exits.
- Installer/OS replacement of the Windows dashboard is not treated as explicit Quit: it preserves the persisted connection intent and independent headless tunnel so upgrades do not silently turn protection off.
- OIG can start at login with `--background`.
- Auto-Recovery runs through one elevated scheduled task and a headless backend.

### Linux

Linux uses NetworkManager's OpenVPN integration and user-level recovery.

- UUID-only connection lifecycle avoids duplicate-name races.
- Effective routing is validated through the active tunnel interface.
- Auto-Recovery respects the persisted desired state.
- Closing the dashboard hides the window while the application and managed tunnel remain alive.
- **Quit and disconnect** is the explicit full-exit path and disconnects the managed tunnel.
- If the application process terminates unexpectedly, the independent parent-exit watchdog provides a disconnect fail-safe.
- Release assets include Debian and AppImage builds.

## Self-Healing Config Factory

The Config Factory is designed so the application does not depend on one manually supplied profile.

It can:

- discover current public relay metadata,
- derive complete client profiles when the source publishes the required material,
- prefer UDP while retaining TCP fallback,
- keep last-known-good profiles across generations,
- stage and hash-check new profiles before promotion,
- record live successes and failures,
- quarantine repeatedly failing profiles,
- prioritize previously validated relays,
- refresh before the usable pool is depleted,
- preserve an offline fallback pool when discovery is temporarily unavailable.

### Truth boundary

A client cannot create a real external VPN server or valid server-side credentials out of nothing. Automatic profile generation works only when a reachable, authorized/public relay source supplies the parameters needed by the transport.

## Health gates

OIG does not label a connection healthy merely because a tunnel process exists. A validated connection requires the expected foreign egress, protected full-route state, and absence of the observed DNS poisoning fingerprint.

The dashboard exposes:

- public IP and exit country,
- protected route state,
- DNS integrity,
- active relay,
- Auto-Recovery status,
- Config Factory pool health,
- Connections inventory and live measurements,
- diagnostics and activity evidence,
- GitHub update status and release integrity information.

## Requirements

### Windows

- Windows 10/11 x64
- OpenVPN Connect 3.x installed in the standard location

OIG uses the headless connector component shipped with OpenVPN Connect. The OpenVPN Connect desktop application itself remains separate.

### Linux

Validated on Ubuntu 24.04-class systems with:

- NetworkManager
- NetworkManager OpenVPN plugin
- OpenVPN 2.6+
- systemd user services
- `curl`

The Debian package is the preferred Linux install. Linux Debian installs to `/opt/open-internet-gateway` so Chromium's setuid sandbox does not inherit a path containing spaces. AppImage is also provided for portable use; some distributions may require FUSE compatibility or an extracted AppImage workflow.

## Building

```bash
cd app
npm install
npm run lint
npm test
```

Windows:

```powershell
npm run dist:win
```

Linux:

```bash
npm run dist:linux
```

Generated relay profiles, local runtime state, machine evidence, dependencies, and release outputs are intentionally excluded from Git. A source build must generate/seed its local relay pool before packaging.

## Security model

- Electron: `contextIsolation: true`, renderer sandbox enabled, Node integration disabled.
- Downloaded/generated profiles are staged and hash-checked before promotion.
- A new relay is not promoted as healthy until live network validation passes.
- Repeated failures are quarantined.
- Runtime state and generated credentials/profiles are excluded from source control.
- Windows OIG uses a headless service backend rather than automating or hiding another application's UI.
- GitHub update downloads are fail-closed on SHA-256 mismatch.

See [SECURITY.md](SECURITY.md).

## Release verification

Every published release includes `SHA256SUMS.txt`. The in-app updater verifies the selected release asset before opening it.

No Authenticode signing certificate is configured in the repository build configuration as of v2.5.2, so Windows users should verify the published checksum when installing manually.

## Scope

A foreign network exit does not guarantee that every online service will treat an account as belonging to that country. Services can also use account region, billing region, GPS/device signals, reputation, or other policy signals.

External relay providers are independent third parties; their availability and policies can change.

## License

MIT.
