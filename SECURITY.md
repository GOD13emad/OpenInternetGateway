# Security

Open Internet Gateway treats discovered relay profiles as untrusted input until structural and live validation pass.

## Controls

- Profiles are staged and SHA-256 checked before promotion.
- Last-known-good pools are preserved until replacements are ready.
- Repeatedly failing profiles are quarantined.
- Health requires live egress, route, and DNS checks rather than process presence alone.
- Electron uses context isolation, renderer sandboxing, and no Node integration.
- The Windows production backend uses a headless service and does not depend on automating another application's GUI.
- Linux connect/recovery operations are serialized.
- Generated relay profiles, runtime state, machine evidence, local logs, and dependencies are excluded from source control.

## Release verification

Published releases include SHA-256 checksums. The Windows 2.2.1 installer is not Authenticode-signed by a trusted publisher; verify its checksum before installation.

## Reporting

Use GitHub Security Advisories for vulnerabilities that could affect users. Do not post credentials, private infrastructure addresses, personal logs, or private network captures in public issues.
