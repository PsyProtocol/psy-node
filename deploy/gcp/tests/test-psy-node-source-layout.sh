#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=../../source-versions.env
source "$ROOT/deploy/source-versions.env"

runtime_head="$(git -C "$ROOT" rev-parse HEAD)"
git -C "$ROOT" merge-base --is-ancestor "$EXPECTED_PARTH_RUNTIME_COMMIT" "$runtime_head" || {
  echo "psy-node deployment branch does not contain the pinned runtime commit" >&2
  exit 1
}
non_deploy_changes="$(
  git -C "$ROOT" diff --name-only "$EXPECTED_PARTH_RUNTIME_COMMIT" "$runtime_head" \
    | awk '$0 !~ /^deploy\// && $0 !~ /^(psy-genesis|psy-contracts|psy-dapp)$/'
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

assert_gitlink() {
  local label="$1"
  local path="$2"
  local expected="$3"
  local actual

  actual="$(git -C "$ROOT" ls-tree "$runtime_head" -- "$path" | awk '$1 == "160000" {print $3}')"
  [ "$actual" = "$expected" ] || {
    echo "$label gitlink mismatch: expected $expected, got ${actual:-<missing or not a submodule>}" >&2
    exit 1
  }
}

assert_gitlink psy-genesis psy-genesis "$EXPECTED_PSY_GENESIS_COMMIT"
assert_gitlink psy-contracts psy-contracts "$EXPECTED_PSY_CONTRACTS_COMMIT"
assert_gitlink psy-dapp psy-dapp "$EXPECTED_PSY_DAPP_COMMIT"

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
