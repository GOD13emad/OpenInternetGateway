# Security

Open Internet Gateway treats discovered relay profiles and update artifacts as untrusted input until structural, integrity, and live validation gates pass.

## Runtime controls

- Profiles are staged and SHA-256 checked before promotion.
- Last-known-good pools are preserved until replacements are ready.
- Repeatedly failing profiles are quarantined.
- Health requires live egress, route, and DNS checks rather than process presence alone.
- Electron uses context isolation, renderer sandboxing, and no Node integration.
- The Windows production backend uses the headless OpenVPN connector service and does not depend on automating the OpenVPN Connect GUI.
- Linux connect/recovery operations are serialized.
- Explicit Quit disconnects the OIG-managed tunnel; Linux also has an independent parent-exit watchdog as a fail-safe for unexpected application termination.
- Generated relay profiles, runtime state, machine evidence, local logs, and dependencies are excluded from source control.

## Update integrity

The in-app GitHub updater checks the official `GOD13emad/OpenInternetGateway` release feed and is fail-closed.

Before OIG opens a downloaded installer/package, all of the following must agree:

1. the GitHub release asset SHA-256 digest,
2. the asset entry in the published `SHA256SUMS.txt`,
3. the SHA-256 calculated from the downloaded file.

Update transfers use bounded `curl` requests with redirect handling, connection/transfer timeouts, retries, and a `.partial` file. A partial or hash-mismatched download is not promoted or opened.

## Release verification

Published releases include `SHA256SUMS.txt`.

No Authenticode signing certificate is configured in the repository build configuration as of v2.4.1. Windows users performing a manual install should verify the published SHA-256 checksum. The in-app updater performs the checksum verification automatically before handing the installer/package to the operating system.

## Reporting

Use GitHub Security Advisories for vulnerabilities that could affect users. Do not post credentials, private infrastructure addresses, personal logs, or private network captures in public issues.
