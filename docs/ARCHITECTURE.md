# Architecture

## Desktop shell

Electron provides the product-owned desktop shell and tray.

Security boundary:

- `contextIsolation: true`
- `nodeIntegration: false`
- renderer `sandbox: true`
- narrow preload API through `contextBridge`

The renderer does not receive direct filesystem or unrestricted shell access.

The app is single-instance. On Windows it registers itself for login with `--background`; closing the main window hides it while leaving the OIG tray alive.

## Windows backend

### UI ownership

OpenInternetGateway owns the only UI required for OIG operation.

The production Windows backend does not launch `OpenVPNConnect.exe`, does not automate its tray icon, and does not hide/show its windows. The user's OpenVPN Connect desktop app is independent.

### Tunnel engine

OIG uses the headless connector shipped with OpenVPN Connect 3.x:

- `ovpnconnector.exe`
- `OVPNConnectorService`

The flow is:

1. Dashboard/tray writes desired state and starts the single elevated Auto-Recovery task.
2. The task runs `Ensure-OpenInternet.ps1`.
3. The headless controller selects a Config Factory candidate.
4. The profile is copied to the protected OIG service-profile location.
5. `ovpnconnector` starts the Windows service without opening the OpenVPN desktop UI.
6. OIG validates egress country, DNS integrity, and two protected IPv4 routes.
7. Only a validated connection is recorded as successful.
8. Failure information is returned to the Config Factory for reprioritization/quarantine.

Disconnect performs the inverse operation and requires both route removal and stopped headless service state before reporting success.

## Linux backend

Linux uses NetworkManager's OpenVPN plugin.

The backend:

1. imports a candidate,
2. resolves the exact connection UUID,
3. mutates/activates/deactivates/deletes by UUID,
4. validates the effective route and tunnel interface,
5. verifies foreign egress and DNS integrity,
6. serializes recovery operations,
7. uses a systemd user timer for Auto-Recovery.

## Config Factory

The Config Factory is shared conceptually across both platforms.

Pipeline:

`discovery -> staging -> structural/hash validation -> live validation -> promotion -> success/failure ledger -> quarantine/rotation`

A working pool is never discarded before a replacement pool is staged. Last-known-good profiles can be retained so live discovery failure does not automatically mean loss of connectivity.

## Console Gateway

Console sharing is intentionally separate from the core PC tunnel.

- Windows: guarded sharing/NAT workflow only when a dedicated private adapter is available.
- Linux: NetworkManager shared Ethernet connection with explicit exclusion of the primary uplink.

## Release state

Generated relay profiles, runtime state, evidence from a specific machine, dependencies, and built artifacts are not committed to source control. Release installers may contain a generated fallback pool created during the release process.
