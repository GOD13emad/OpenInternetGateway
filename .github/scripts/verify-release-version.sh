#!/usr/bin/env bash
# Fail-closed version/asset invariant for release candidates and real tag publication.
# This never signs, uploads, installs, or publishes an artifact.
set -euo pipefail
shopt -s nullglob
mode="${1:-}"
if [[ "$mode" != preview && "$mode" != publish ]]; then
  echo "RELEASE_VERSION_MODE_INVALID" >&2; exit 1
fi
: "${GITHUB_EVENT_NAME:?}"
: "${GITHUB_REF:?}"
version="$(python3 -c 'import json; from pathlib import Path; print(json.loads(Path("app/package.json").read_text(encoding="utf-8"))["version"])')"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "RELEASE_PACKAGE_VERSION_INVALID:$version" >&2; exit 1
fi
if [[ "$mode" == preview ]]; then
  if [[ "$GITHUB_EVENT_NAME" != workflow_dispatch || "$GITHUB_REF" != refs/heads/* ]]; then
    echo "RELEASE_PREVIEW_EVENT_INVALID" >&2; exit 1
  fi
else
  if [[ "$GITHUB_EVENT_NAME" != push || "$GITHUB_REF" != "refs/tags/v$version" ]]; then
    echo "RELEASE_TAG_PACKAGE_VERSION_MISMATCH:tag=$GITHUB_REF:package=$version" >&2; exit 1
  fi
fi
expected=(
  "release/OpenInternetGateway-Setup-$version.exe"
  "release/OpenInternetGateway-$version-x86_64.AppImage"
  "release/OpenInternetGateway-$version-amd64.deb"
)
for asset in "${expected[@]}"; do
  if [[ ! -f "$asset" || ! -s "$asset" ]]; then
    echo "RELEASE_EXPECTED_ASSET_MISSING:$asset" >&2; exit 1
  fi
done
all=(release/*)
expected_files=3
if [[ "$mode" == publish ]]; then
  expected_files=4
  [[ -s release/SHA256SUMS.txt ]] || { echo "RELEASE_CHECKSUM_MANIFEST_MISSING" >&2; exit 1; }
fi
if (( ${#all[@]} != expected_files )); then
  echo "RELEASE_UNEXPECTED_OR_DUPLICATE_ASSET_COUNT:${#all[@]}:$expected_files" >&2; exit 1
fi
for asset in "${all[@]}"; do
  if [[ "$asset" == release/SHA256SUMS.txt && "$mode" == publish ]]; then continue; fi
  match=0
  for wanted in "${expected[@]}"; do
    if [[ "$asset" == "$wanted" ]]; then match=1; break; fi
  done
  if (( match != 1 )); then echo "RELEASE_UNEXPECTED_ASSET:$asset" >&2; exit 1; fi
done
if [[ "$mode" == publish ]]; then
  actual_names="$(awk '{print $2}' release/SHA256SUMS.txt | LC_ALL=C sort)"
  expected_names="$(for wanted in "${expected[@]}"; do printf '%s\n' "${wanted#release/}"; done | LC_ALL=C sort)"
  if [[ "$actual_names" != "$expected_names" ]]; then
    echo "RELEASE_CHECKSUM_MANIFEST_FILES_MISMATCH" >&2; exit 1
  fi
  ( cd release && sha256sum --check --strict --status SHA256SUMS.txt ) || {
    echo "RELEASE_CHECKSUM_CONTENT_MISMATCH" >&2; exit 1;
  }
fi
echo "RELEASE_VERSION_ASSET_CONTRACT_PASS:$mode:v$version"
