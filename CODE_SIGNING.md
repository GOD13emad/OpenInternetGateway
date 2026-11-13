# Code signing policy

## Current publisher trust

Open Internet Gateway (OIG) publishes Windows and Linux desktop packages through the [official GitHub Releases](https://github.com/GOD13emad/OpenInternetGateway/releases). The repository's release checksums, GitHub source history, and download-integrity checks do **not** constitute an Authenticode signature or a certificate issued to OIG.

**No publicly trusted Windows Authenticode publisher certificate or provider-approved production signing workflow is evidenced for this project at the time of this policy.** Windows users should inspect the actual installer with the Windows signature viewer or `Get-AuthenticodeSignature`, compare SHA-256 against the exact release manifest, and expect that unsigned installers can display an Unknown publisher warning. Do not disable Defender, SmartScreen, or Smart App Control to work around such warnings.

The project's MIT license does not mean bundled third-party utilities, packaged upstream executables, network drivers, or other dependencies may be signed under OIG's name.

## Possible provider routes, not approvals

1. **Standard commercial code signing** through a publicly trusted CA, only if the real publisher identity, jurisdiction, product functions, sanctions/export controls, lawful purchase, verification, and HSM/token use are approved. A single authorized first-party publisher certificate may support multiple first-party Windows products subject to the provider's rules.
2. **SignPath Foundation OSS program** only after confirming project eligibility and an independently verifiable build/provenance chain. OIG's networking, VPN, relay, routing, and traffic-management functions may make it ineligible even with an OSI-approved license. **No Foundation approval, certificate or OIG-specific signing request is claimed.** See [SignPath Foundation conditions](https://signpath.org/terms.html).
3. **Microsoft Store package signing** only if genuine developer-country eligibility, account enrollment, app/package certification and compatible MSIX packaging are established. This is not a way to sign an arbitrary off-Store NSIS installer.
4. **Azure Artifact Signing Public Trust** is subject to Microsoft individual/organization identity and country eligibility rules. Do not misrepresent the publisher's location to obtain access.

## Requirements for a future signed Windows release

- Select and document the exact committed source, approved publisher identity, legal rights and third-party provenance. Preserve existing user settings and installer identity.
- Build the exact Windows application and installer in a reviewed, verifiable workflow. Identify every first-party executable/DLL/script requiring signature and distinguish independently published third-party components.
- Sign only the authorized first-party artifacts with a publicly trusted provider. Verify Authenticode certificate chain and code-signing EKU, valid signer identity, product/version attributes and RFC 3161 timestamp. If installer payloads need signatures, sign and verify inner binaries **before** packaging and outer installer signing.
- Inspect the resulting release file's signature and digest independently; verify install, update, uninstall, rollback and Smart App Control behavior in an applicable clean system. No synthetic or self-signed development signature can satisfy the public-trust gate.
- Publish **new immutable versioned assets** with updated SHA-256 manifest, SBOM/dependency provenance and factual signature status. Never overwrite existing GitHub release artifacts to retrofit a signature. A build/test PASS does not imply certificate issuance, provider acceptance, or signed publication.

## Approval and custody boundaries

The repository maintainer `GOD13emad` reviews source, dependencies, build provenance and release artifacts and makes the explicit signing decision. No build, workflow or assistant may infer permission to use or export signing keys from a passing CI run. Certificates, HSM/cloud credentials, private keys, identity documents, OTPs and billing information must not be committed to GitHub or written into public evidence. Human identity verification and provider acceptance remain external.

## Security concerns

Report suspected release or signing provenance problems using [SECURITY.md](SECURITY.md). Halt promotion of affected new artifacts until their source, signature and delivery integrity have been independently reconciled.
