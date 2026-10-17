#!/usr/bin/env bash
# Verify cryptographic GitHub/Sigstore origin of every exact release package.
# This is not Windows Authenticode publisher signing.
set -euo pipefail
shopt -s nullglob

# GHSA-wjmr-j3rp-mh2g: gh 2.51.0..2.101.0 accepted a signer-workflow prefix.
# Reject vulnerable GH CLI clients instead of silently weakening issuer identity.
installed="$(gh version | head -n 1 | awk '{print $3}')"
minimum="2.102.0"
test -n "$installed"
if [ "$(printf '%s\n%s\n' "$minimum" "$installed" | sort -V | head -n 1)" != "$minimum" ]; then
  echo "REFUSE_VULNERABLE_GH_CLI: $installed; minimum $minimum" >&2
  exit 1
fi

: "${GITHUB_REPOSITORY:?}"
: "${GITHUB_REF:?}"
: "${GITHUB_SHA:?}"
: "${GH_TOKEN:?}"
windows=(release/OpenInternetGateway-Setup-*.exe)
appimages=(release/OpenInternetGateway-*.AppImage)
debs=(release/OpenInternetGateway-*.deb)
if [ "${#windows[@]}" -lt 1 ] || [ "${#appimages[@]}" -lt 1 ] || [ "${#debs[@]}" -lt 1 ]; then
  echo "RELEASE_ARTIFACT_TYPES_MISSING" >&2
  exit 1
fi

for file in "${windows[@]}" "${appimages[@]}" "${debs[@]}"; do
  echo "Verifying exact artifact provenance: $file"
  gh attestation verify "$file" \
    --repo "$GITHUB_REPOSITORY" \
    --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml" \
    --source-ref "$GITHUB_REF" \
    --source-digest "$GITHUB_SHA" \
    --deny-self-hosted-runners
done
echo "ALL_RELEASE_ARTIFACT_PROVENANCE_VERIFIED"
