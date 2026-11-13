#!/usr/bin/env bash
# Disposable GitHub-hosted Ubuntu only. Prefer Canonical's primary archive
# when the runner image points apt at the intermittently failing Azure mirror.
# APT package signatures, security pockets and release suites are unchanged.
set -euo pipefail
if [[ $# -ne 0 ||
      "${RUNNER_ENVIRONMENT:-}" != github-hosted ||
      "${GITHUB_ACTIONS:-}" != true ||
      "${GITHUB_REPOSITORY:-}" != GOD13emad/OpenInternetGateway ||
      "$(id -u)" -eq 0 ]]; then
  echo OIG_HOSTED_APT_RECONFIG_REFUSED >&2
  exit 71
fi
# The workflow uses ubuntu-24.04; do not repurpose this helper on user hosts
# or different distributions.
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]] || {
  echo OIG_UNEXPECTED_HOSTED_OS >&2
  exit 72
}
mirrors=/etc/apt/apt-mirrors.txt
if [[ ! -e "$mirrors" ]]; then
  echo OIG_HOSTED_APT_NO_MIRROR_LIST_NOOP
  exit 0
fi
[[ -f "$mirrors" && ! -L "$mirrors" ]] || {
  echo OIG_HOSTED_APT_UNEXPECTED_MIRROR_FILE >&2
  exit 73
}
if ! grep -Fq azure.archive.ubuntu.com "$mirrors"; then
  echo OIG_HOSTED_APT_PRIMARY_MIRROR_ALREADY_SELECTED
  exit 0
fi
# Do not change sources unless the official Canonical primary archive resolves.
timeout 15s getent ahostsv4 archive.ubuntu.com >/dev/null || {
  echo OIG_HOSTED_APT_PRIMARY_DNS_UNAVAILABLE >&2
  exit 74
}
sudo sed -i 's#azure\.archive\.ubuntu\.com#archive.ubuntu.com#g' "$mirrors"
if grep -Fq azure.archive.ubuntu.com "$mirrors" ||
   ! grep -Fq archive.ubuntu.com "$mirrors"; then
  echo OIG_HOSTED_APT_MIRROR_REWRITE_FAILED >&2
  exit 75
fi
echo OIG_HOSTED_APT_PRIMARY_OFFICIAL_ARCHIVE_SELECTED
