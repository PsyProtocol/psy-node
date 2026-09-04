#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSIONS_FILE="${1:?usage: prepare-profile-sources.sh SOURCE_VERSIONS_FILE}"

[ -f "$VERSIONS_FILE" ] || {
  echo "missing profile source versions: $VERSIONS_FILE" >&2
  exit 1
}

# shellcheck disable=SC1090
source "$VERSIONS_FILE"

checkout_source() {
  local label="$1"
  local directory="$2"
  local expected_commit="$3"
  local dirty

  [ -e "$directory/.git" ] || {
    echo "$label is not initialized: $directory" >&2
    exit 1
  }

  dirty="$(git -C "$directory" status --porcelain --untracked-files=normal)"
  [ -z "$dirty" ] || {
    echo "$label contains local changes and cannot switch profiles: $directory" >&2
    printf '%s\n' "$dirty" >&2
    exit 1
  }

  if ! git -C "$directory" cat-file -e "$expected_commit^{commit}" 2>/dev/null; then
    git -C "$directory" fetch origin "$expected_commit"
  fi
  git -C "$directory" checkout --quiet --detach "$expected_commit"
  git -C "$directory" submodule update --init --recursive
  echo "[profile-sources] $label=$expected_commit"
}

checkout_source psy-genesis "$ROOT/psy-genesis" "$EXPECTED_PSY_GENESIS_COMMIT"
checkout_source psy-contracts "$ROOT/psy-contracts" "$EXPECTED_PSY_CONTRACTS_COMMIT"
checkout_source psy-dapp "$ROOT/psy-dapp" "$EXPECTED_PSY_DAPP_COMMIT"

profile_name="$(basename "$(dirname "$(dirname "$VERSIONS_FILE")")")"
echo "[profile-sources] prepared $profile_name sources"
