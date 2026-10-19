# Open Internet Gateway

Open Internet Gateway (OIG) is a cross-platform desktop application for maintaining a validated, full-device Internet egress path on restrictive or unreliable networks.

The Windows and Linux backends are different, but both sit behind the same Electron dashboard, lifecycle model, health gates, multi-country relay inventory, Self-Healing Config Factory, and verified GitHub update workflow.

## Current release line: 2.5.14

### Connections

The Connections page exposes the current relay inventory with country, endpoint, protocol, source metadata, locally measured latency, real tunnel throughput results, and relay status. Connections active state follows the authoritative live tunnel on every status refresh, including Auto-Recovery changes; if the active tunnel profile is absent from the latest pool, OIG still shows it as an ACTIVE managed relay.

- **Test all relays** performs bounded parallel reachability/latency probes for every row in the current pool from the physical Internet adapter, bypassing the active OIG VPN route and HTTP/SOCKS proxy settings without switching or disconnecting the tunnel. **No reply** means the direct ICMP/TCP probe completed but the relay did not answer it; **Not tested** is reserved for rows that have not yet been probed.
- **Test direct Internet** measures the user's own ISP baseline: ping, real download, real upload, direct public IP and country. Windows binds the physical adapter IPv4 address; Linux binds the physical interface.
- **Speed** on a relay performs a real throughput measurement through that selected VPN tunnel; app-level proxy settings are disabled so the measurement is the VPN path itself.
- Columns are sortable by country, relay, protocol, source ping, live ping, measured download, measured upload, and status.
- Source metadata and device-measured results are kept separate; missing or blocked measurements are shown as unavailable rather than fabricated.

The Config Factory keeps a diversified multi-country pool with last-known-good retention, validation history, failure quarantine, and refresh behavior.

### Direct ISP truth boundary

OIG's Direct Internet test binds the physical network path and disables ordinary HTTP/SOCKS proxy use. The UI records the physical adapter/local IP/gateway plus direct public egress. When the active routed egress differs from the direct public egress, the bypass is explicitly marked as observed. A third-party kernel/WFP/endpoint-security product that intercepts traffic below normal socket routing can still override OS routing; OIG surfaces the observed egress instead of assuming bypass succeeded.

### GitHub updates

The **Updates** page checks the official `GOD13emad/OpenInternetGateway` GitHub release feed.

Before an update is applied, OIG requires all three integrity checks to agree:

1. the SHA-256 digest published by the GitHub release asset,
2. the matching entry in the release `SHA256SUMS.txt`,
3. the SHA-256 of the bytes downloaded by OIG.

Windows automatic updates use a current-user one-click NSIS install under the user profile, so routine application updates do not request UAC. Linux automatic updates use the AppImage release under `~/.local/opt`; the Debian package remains available for manual/system-managed installation. The updater never bypasses OS security: privileged backend bootstrap/console operations remain explicit, separate actions.

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

The Debian package remains the preferred system-managed Linux install. Linux Debian installs to `/opt/open-internet-gateway` so Chromium's setuid sandbox does not inherit a path containing spaces. The Debian artifact post-build step repairs the desktop launcher and icon to mode `0644` and repacks with broadly supported `gzip` compression at level 1 to keep QA packaging bounded. It also normalizes the generated uninstall maintainer script's `update-alternatives --remove` target to `/opt/open-internet-gateway/open-internet-gateway`; the older product-name path was inconsistent with the installed payload. The desktop Quit action and Chromium sandbox modes are validated in a user-namespace install-script smoke test, not by installation on the host. Automatic in-app updates use the AppImage release extracted into `~/.local/opt` so they do not require root; some distributions may require FUSE compatibility only when launching AppImage directly.

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


## Opt-in operator-pinned OpenVPN profile gate (Linux development only)

An independently trusted operator may provide a `.ovpn` file, the DER SHA-256
fingerprint of its **CA certificate** from an authenticated independent source,
and the exact expected server certificate CN. The offline trust gate
`app/backend/linux/operator_profile.py` checks these inputs before any
NetworkManager import. It currently accepts a narrow VPNBook-compatible
inline-profile grammar, one `*.vpnbook.com` remote endpoint, an inlined CA,
client certificate/private key and only allowlisted non-executable options.

The official VPNBook API profile can include `redirect-gateway` (with no
arguments or `def1`). In isolated QA only, the parser recognizes these
exact directives but removes them from the staged copy. Other redirect
variants and executable options remain rejected. Both the original source
SHA-256 and normalized profile SHA-256 are recorded in private metadata.
This does not enable full-device protection.

On 2026-10-19 a fresh official `uk205.vpnbook.com:443` TCP profile was
retrieved as raw HTTPS `application/x-openvpn-profile` and its CA matched
independent earlier pinned evidence. The narrowed profile passed a real
Linux NetworkManager import/removal without route or DNS changes. OpenVPN
2.7 subsequently verified the actual remote CA and `server.vpnbook.com`
certificate name in a rootless TLS handshake; a wrong name was rejected.
An intentionally invalid test login received `AUTH_FAILED`. These results
do **not** establish a successful provider login, tunneled throughput,
full-device VPN protection or production release.


In the Linux desktop app, open **Settings → Import operator-pinned OpenVPN profile**,
enter the trusted CA fingerprint and exact server certificate CN, then select a
local `.ovpn` file in the native file chooser. Staging is completely separate
from **Connect**, the dynamic VPN Gate pool, and Auto-Recovery. The Windows
Settings page does not show this experimental Linux-only control.
After staging, **Check NetworkManager import (no connection)** uses a bounded
`nmcli connection import --temporary` to verify that the local NetworkManager
OpenVPN plugin can parse the profile. It identifies the newly imported UUID,
deletes that exact temporary profile and checks that deletion completed. It
never invokes `connection up`, requests provider credentials, or changes
the live VPN. A successful import proves **only parser compatibility**, not
provider identity, external TLS authentication, routing or data transfer.

For **inspection only** (no writes), run:

```bash
python3 app/backend/linux/operator_profile.py check \
  --profile /path/to/provider.ovpn \
  --ca-sha256 YOUR_INDEPENDENT_CA_DER_SHA256 \
  --peer-cn YOUR_INDEPENDENT_EXPECTED_SERVER_CN
```

For explicit **private staging only**, add `stage` and
`--common "$HOME/.local/share/OpenInternetGateway/common"`.
Staging creates a user-private `operator-profiles` directory and a
`current.json` record. It **does copy the inline client private key** into a
mode-0600 private file. Neither command downloads a config, accepts or stores
VPN login passwords, creates NetworkManager profiles, connects a VPN, changes
routing, or marks the relay as live-authenticated. It is **not integrated into Connect,
auto-recovery, or the Windows engine**. An import that passes a supplied CA pin
and name is not an external TLS/data-plane PASS; the pin's provenance and
provider account/credentials remain operator responsibilities. Do not stage
private key material under a Git checkout, and never commit it.

### Independent Linux QA rollback (not enabled for normal Connect)

The experimental helper `app/backend/linux/operator_rollback.py` supports
`arm` (an independent transient `systemd --user` timer) and `cleanup`
(UUID-scoped removal) for a randomly named
`OIG-Operator-QA-<12-hex>` *temporary* NetworkManager profile. It refuses
to delete existing profiles with a different name, does not activate VPN,
and does not change network routes. The timer is armed **before** any future
opt-in connection attempt; `AccuracySec=1s` bounds scheduling jitter.
A real synthetic, inactive NetworkManager QA profile was deleted by
the independent timer; this is not validation of connection rollback under
live traffic. The helper is **not invoked by the production Connect button**
and must not be used for automatic activation, credential storage, or Windows.

### Explicit memory-only Linux provider QA (Linux Settings experimental control; not released)

The separate `app/backend/linux/operator_trial.py` tool is **not** wired to
the normal Connect button or automatic recovery. Linux **Settings** exposes a
separately consented **Trial transport briefly** control only when a privately
staged profile remains hash-valid; the ordinary gateway must have saved
`desired-state=off`. It is intentionally a
short, opt-in Linux-only provider trial, requiring a current `.ovpn`,
an independently authenticated CA DER SHA-256 + exact server CN, and
username/password JSON delivered over **stdin** (never command arguments or
environment). Do not put credentials into shell history or logs.

The password is transferred to NetworkManager using an anonymous Linux
`memfd` exposed to one child through `/proc/self/fd/N` as
`vpn.secrets.password` in the documented `nmcli connection up passwd-file`
format. The username is briefly passed as a `nmcli` argument during
temporary profile setup and remains visible in local process inspection.
The temporary profile is configured `autoconnect=no`,
IPv4/IPv6 `never-default=yes`, `ignore-auto-dns=yes`, and
`ignore-auto-routes=yes`, verified before the systemd user-session rollback
timer is armed. The last setting also suppresses automatically supplied
specific or split-default routes; `never-default` alone is insufficient for
that scope. These settings passed a real temporary NetworkManager import,
readback and removal with full IPv4/IPv6 route tables and DNS unchanged.
Live server-pushed route handling is still untested until a real authenticated
provider trial. **Only after
confirmed independent rollback** may `connection up` be attempted.
Immediate UUID/name-scoped cleanup is attempted in all normal/failure
paths; the independent timer remains armed when immediate cleanup fails.
A successful command reports transport activation only—not externally
verified server identity, full-device routing, DNS integrity or throughput.

While a scoped trial runs, the backend refuses ordinary Connect/refresh and
profile replacement/re-import; the app also blocks applying an update or
explicit Quit until the trial cleans up. Import and Native Check now share a
process-local lease: a trial cannot begin until either profile task finishes,
and a second profile task cannot modify files during the first. Quit and update
handoff also wait for these tasks to complete. Emergency Disconnect remains
available. An update in progress blocks starting a trial. These guards are
process-local; an external crash still relies on the independent systemd
rollback timer, and active-tunnel cleanup remains unverified.

The whole Settings → IPC → backend → stdin → Python → NetworkManager path
has only passed with **synthetic credentials and an isolated NetworkManager
stub**; no real provider username/password or VPN has been connected by this
feature. No provider password is saved to application settings.

Only mocked credential transport/ordering/failure branches have passed;
the current provider credentials and a real in-app authenticated tunnel
remain unverified. The test command is deliberately not exposed as a
general-purpose application connection or Windows feature.

## Security model

- Electron: `contextIsolation: true`, renderer sandbox enabled, Node integration disabled.
- Downloaded/generated profiles are staged and hash-checked before promotion.
- A new relay is not promoted as healthy until live network validation passes.
- Repeated failures are quarantined.
- Runtime state and generated credentials/profiles are excluded from source control.
- Windows OIG uses a headless service backend rather than automating or hiding another application's UI.
- GitHub update downloads are fail-closed on SHA-256 mismatch.
- Linux Chromium sandbox hardening is fail-safe: when user namespaces are restricted, OIG only reuses a root-owned `4755` setuid `chrome-sandbox` whose SHA-256 is byte-identical to the packaged helper. OIG does not disable AppArmor or change global user-namespace policy.

See [SECURITY.md](SECURITY.md).

## Release verification

Every published release includes `SHA256SUMS.txt`. The in-app updater verifies the selected release asset against both GitHub's published digest and `SHA256SUMS.txt`, re-hashes the downloaded bytes, then applies the user-space update and restarts the dashboard.

No publicly trusted Authenticode signing credential is configured for v2.5.16, so Windows users installing manually should verify the published checksum. The in-app updater verifies GitHub digest + `SHA256SUMS.txt` + the downloaded bytes before applying an update.

## Scope

A foreign network exit does not guarantee that every online service will treat an account as belonging to that country. Services can also use account region, billing region, GPS/device signals, reputation, or other policy signals.

External relay providers are independent third parties; their availability and policies can change.

## License

MIT.
