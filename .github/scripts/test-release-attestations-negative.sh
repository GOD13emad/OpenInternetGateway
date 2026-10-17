#!/usr/bin/env bash
# Negative controls run only in a nonpublishing GitHub Actions job.
# Do not alter any producer artifact, checksum manifest or published release.
set -euo pipefail
: "$GITHUB_REPOSITORY"
: "$GITHUB_REF"
: "$GITHUB_SHA"
: "$GH_TOKEN"
set -- release/OpenInternetGateway-Setup-*.exe
test "$#" -eq 1
original="$1"
test -s "$original"
test "$(printf '%s' "$GITHUB_SHA" | wc -c)" -eq 40
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT

reject() {
  local case_id="$1"
  shift
  local out="$scratch/$case_id.log"
  if gh attestation verify "$@" > "$out" 2>&1; then
    echo "CRITICAL_FALSE_ACCEPTANCE:$case_id" >&2
    exit 1
  fi
  # For tampered bytes, GitHub returns a digest-specific HTTP 404 when
  # the nonexistent subject SHA-256 has no attestation. Accept ONLY that exact
  # subject-path 404; the preceding positive case already checked credentials.
  if [ "$case_id" = TAMPERED_FILE ]; then
    local changed_sha
    changed_sha="$(sha256sum "$tampered" | cut -d' ' -f1)"
    if grep -Fq "HTTP 404: Not Found" "$out" &&
       grep -Fq "/repos/$GITHUB_REPOSITORY/attestations/sha256:$changed_sha" "$out"; then
      echo "EXPECTED_REJECTION:$case_id:EXACT_DIGEST_404"
      return
    fi
  fi
  if [ "$case_id" = WRONG_SOURCE_DIGEST ]; then
    if grep -Fq "expected SourceRepositoryDigest to be $wrong_source, got $GITHUB_SHA" "$out"; then
      echo "EXPECTED_REJECTION:$case_id:EXACT_SOURCE_DIGEST_POLICY"
      return
    fi
  fi
  # Do not count any arbitrary HTTP/auth or CLI error as a true negative.
  if ! grep -Eiq 'No attestations found for subject|no matching attestations|no verified attestations|source digest|policy criteria.*not met|verification failed|failed to verify' "$out"; then
    echo "INCONCLUSIVE_NEGATIVE:$case_id" >&2
    tail -n 12 "$out" >&2
    exit 1
  fi
  echo "EXPECTED_REJECTION:$case_id"
}

tampered="$scratch/OpenInternetGateway-Setup-tampered.exe"
cp -- "$original" "$tampered"
printf '\x7f' >> "$tampered"
test "$(sha256sum "$original" | cut -d' ' -f1)" != "$(sha256sum "$tampered" | cut -d' ' -f1)"
reject TAMPERED_FILE "$tampered" \
  --repo "$GITHUB_REPOSITORY" \
  --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml" \
  --source-ref "$GITHUB_REF" \
  --source-digest "$GITHUB_SHA" \
  --deny-self-hosted-runners

wrong_source="0000000000000000000000000000000000000000"
test "$wrong_source" != "$GITHUB_SHA"
reject WRONG_SOURCE_DIGEST "$original" \
  --repo "$GITHUB_REPOSITORY" \
  --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml" \
  --source-ref "$GITHUB_REF" \
  --source-digest "$wrong_source" \
  --deny-self-hosted-runners

echo "NEGATIVE_ATTESTATION_GATES_PASS"
