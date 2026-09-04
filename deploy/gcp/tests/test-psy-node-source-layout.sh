#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROFILE="${DEPLOY_NETWORK_PROFILE:-ethereum-sepolia}"
VERSIONS_FILE="$ROOT/deploy/$PROFILE/gcp/source-versions.env"
[ -f "$VERSIONS_FILE" ] || {
  echo "unknown deployment network profile: $PROFILE" >&2
  exit 1
}
# shellcheck disable=SC1090
source "$VERSIONS_FILE"

runtime_head="$(git -C "$ROOT" rev-parse HEAD)"
git -C "$ROOT" merge-base --is-ancestor "$EXPECTED_PARTH_RUNTIME_COMMIT" "$runtime_head" || {
  echo "psy-node deployment branch does not contain the pinned runtime commit" >&2
  exit 1
}
non_deploy_changes="$(
  git -C "$ROOT" diff --name-only "$EXPECTED_PARTH_RUNTIME_COMMIT" "$runtime_head" \
    | awk '$0 !~ /^deploy\//'
)"
[ -z "$non_deploy_changes" ] || {
  echo "deployment branch contains unapproved product changes:" >&2
  printf '%s\n' "$non_deploy_changes" >&2
  exit 1
}

assert_commit() {
  local label="$1"
  local path="$2"
  local expected="$3"
  local actual

  [ -e "$path/.git" ] || {
    echo "$label submodule is not initialized: $path" >&2
    exit 1
  }
  actual="$(git -C "$path" rev-parse HEAD)"
  [ "$actual" = "$expected" ] || {
    echo "$label commit mismatch: expected $expected, got $actual" >&2
    exit 1
  }
}

assert_commit psy-genesis "$ROOT/psy-genesis" "$EXPECTED_PSY_GENESIS_COMMIT"
assert_commit psy-contracts "$ROOT/psy-contracts" "$EXPECTED_PSY_CONTRACTS_COMMIT"
assert_commit psy-dapp "$ROOT/psy-dapp" "$EXPECTED_PSY_DAPP_COMMIT"

assert_runtime_gitlink() {
  local path="$1"
  local expected actual

  expected="$(git -C "$ROOT" ls-tree "$EXPECTED_PARTH_RUNTIME_COMMIT" -- "$path" | awk '$1 == "160000" {print $3}')"
  actual="$(git -C "$ROOT" ls-tree "$runtime_head" -- "$path" | awk '$1 == "160000" {print $3}')"
  [ "$actual" = "$expected" ] || {
    echo "$path gitlink drifted from the pinned runtime: expected $expected, got ${actual:-<missing or not a submodule>}" >&2
    exit 1
  }
}

assert_runtime_gitlink psy-genesis
assert_runtime_gitlink psy-contracts
assert_runtime_gitlink psy-dapp

actual_contracts_sha="$(sha256sum "$ROOT/psy-genesis/genesis_contracts.json" | awk '{print $1}')"
[ "$actual_contracts_sha" = "$EXPECTED_GENESIS_CONTRACTS_SHA256" ] || {
  echo "canonical genesis contracts checksum mismatch" >&2
  exit 1
}

cmp -s "$ROOT/psy-genesis/config.json" "$ROOT/psy-dapp/psy-genesis/config.json" || {
  echo "psy-genesis and psy-dapp client configs differ" >&2
  exit 1
}

for app in bridge explorer ide; do
  [ -f "$ROOT/psy-dapp/apps/$app/package.json" ] || {
    echo "missing psy-dapp app: $app" >&2
    exit 1
  }
done

echo "[ok] psy-node deployment source layout and canonical artifacts"
