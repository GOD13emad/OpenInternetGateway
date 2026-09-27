# Open Internet Gateway

Open Internet Gateway (OIG) is a cross-platform desktop application that maintains a validated, full-device Internet egress path on restrictive or unreliable networks.

The Windows and Linux backends are different, but both sit behind the same Electron dashboard, system-tray workflow, health model, and Self-Healing Config Factory.

## Release 2.2.3

### Windows

OIG does **not** use the OpenVPN Connect desktop UI as its runtime.

- OIG owns its own dashboard and system-tray icon.
- Connect/Disconnect run through OpenVPN Connect's headless `ovpnconnector.exe` / `OVPNConnectorService`.
- `OpenVPNConnect.exe` is not launched by the OIG production backend.
- Your normal OpenVPN Connect application remains independent for manual use.
- Closing the OIG dashboard on Windows hides it to the OIG tray; explicit Quit disconnects the managed tunnel before the application exits.
- OIG starts at login with `--background` so the tray can remain available without opening the dashboard.
- Auto-Recovery runs through one elevated scheduled task and a headless backend.

Validated Windows 2.2.3 state includes JP egress, clean DNS, two protected IPv4 routes, Config Factory recovery, and a live headless connector with zero OpenVPN Connect GUI processes.

### Linux

Linux uses NetworkManager's OpenVPN integration and systemd user recovery.

- UUID-only connection lifecycle avoids duplicate-name races.
- Effective routing is validated through the active tunnel interface.
- Auto-Recovery uses a user-level systemd timer.
- On Linux, closing/quitting the application disconnects the OIG-managed tunnel; Auto-Recovery respects the persisted OFF state and does not reconnect until the user connects again.
- Release assets include Debian and AppImage builds.

Validated Linux 2.2.3 state includes JP egress, `tun0`, clean DNS, full-route validation, cold-start Config Factory recovery, clean disconnect rollback, and persistent Auto-Recovery.

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
- diagnostics and activity evidence.

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

See [SECURITY.md](SECURITY.md).

## Release signing

The Windows 2.2.3 installer is reproducibly hashed but is **not Authenticode-signed by a trusted publisher**. Verify release checksums before installation.

## Scope

A foreign network exit does not guarantee that every online service will treat an account as belonging to that country. Services can also use account region, billing region, GPS/device signals, reputation, or other policy signals.

External relay providers are independent third parties; their availability and policies can change.

## License

MIT.
