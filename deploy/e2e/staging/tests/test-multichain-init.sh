#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGING_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT="$(cd "$STAGING_DIR/../../.." && pwd)"
test_parent="$(mktemp -d "${TMPDIR:-/tmp}/psy-multichain-init-test.XXXXXX")"
test_dir="$test_parent/matrix"
trap 'rm -rf "$test_parent"' EXIT

# A fake checkout and dummy deployment JSON make this test independent of live
# addresses, private config and initialized submodules. Init performs no RPCs.
binary="$ROOT/deploy/e2e/cli-full-e2e/target/release/psy-cli-full-e2e"
if [ ! -x "$binary" ]; then
  cargo build --locked --release --manifest-path "$ROOT/deploy/e2e/cli-full-e2e/Cargo.toml"
fi
fixture="$test_parent/repo"
mkdir -p "$fixture/deploy/e2e/staging" "$fixture/deploy/e2e/cli-full-e2e/target/release" "$fixture/psy-genesis"
cp "$STAGING_DIR/run-cli-e2e.sh" "$STAGING_DIR/run-multichain-e2e.sh" "$fixture/deploy/e2e/staging/"
ln -s "$binary" "$fixture/deploy/e2e/cli-full-e2e/target/release/psy-cli-full-e2e"
printf '%s\n' '{"networks":{"sepolia":{"l1_chain_id":11155111}}}' > "$fixture/psy-genesis/config.json"
for network in sepolia bscTestnet baseSepolia; do
  mkdir -p "$fixture/psy-contracts/deployments/$network"
  for artifact in deployed-contracts.json Bridge_Proxy.json; do
    printf '%s\n' '{}' > "$fixture/psy-contracts/deployments/$network/$artifact"
  done
done
git init -q "$fixture"
git -C "$fixture" -c user.name='E2E Fixture' -c user.email='fixture@example.invalid' \
  commit --allow-empty -qm fixture
STAGING_DIR="$fixture/deploy/e2e/staging"
# Never import a user's funded test signer into disposable test directories.
unset MULTICHAIN_EVM_KEY_FILE SEPOLIA_EVM_KEY_FILE BSC_EVM_KEY_FILE BASE_EVM_KEY_FILE

fail() {
  echo "[test-multichain-init] FAIL: $*" >&2
  exit 1
}

assert_profile() {
  local profile="$1"
  local network="$2"
  local deployments_network="$3"
  local chain_id="$4"
  local chain_index="$5"
  local run_dir="$test_dir/$profile"

  jq -e \
    --arg network "$network" \
    --arg deployments_network "$deployments_network" \
    --argjson chain_id "$chain_id" \
    --argjson chain_index "$chain_index" \
    '.network == $network
     and .deployments_network == $deployments_network
     and .l1_chain_id == $chain_id
     and .l1_chain_index == $chain_index' \
    "$run_dir/manifest.json" >/dev/null || fail "$profile manifest mismatch"

  jq -e \
    --arg network "$network" \
    --argjson chain_id "$chain_id" \
    '.defaultNetwork == $network
     and .networks[$network].l1_chain_id == $chain_id
     and (.networks[$network].l1_rpc_urls | length) == 1' \
    "$run_dir/config.json" >/dev/null || fail "$profile config mismatch"

  [ -f "$run_dir/deployments/$deployments_network/Bridge_Proxy.json" ] ||
    fail "$profile selected deployment artifacts are incomplete"
  [ -f "$run_dir/deployments/localhost/Bridge_Proxy.json" ] ||
    fail "$profile localhost compatibility artifacts are incomplete"
  [ "$(stat -c %a "$run_dir")" = "700" ] || fail "$profile run directory mode is not 700"
  [ "$(stat -c %a "$run_dir/secrets/e.key")" = "600" ] ||
    fail "$profile EVM key mode is not 600"
}

"$STAGING_DIR/run-multichain-e2e.sh" init "$test_dir" >/dev/null

jq -e '.required_chains == ["base", "bsc", "sepolia"]' \
  "$test_dir/matrix.json" >/dev/null || fail "matrix execution order mismatch"

assert_profile sepolia sepolia sepolia 11155111 0
assert_profile bsc bsc-testnet bscTestnet 97 1
assert_profile base base-sepolia baseSepolia 84532 2

if STAGING_CHAIN=bsc "$STAGING_DIR/run-cli-e2e.sh" status "$test_dir/base" >/dev/null 2>&1; then
  fail "single-chain runner accepted a BSC/Base profile mismatch"
fi

shared_dir="$test_parent/shared-matrix"
MULTICHAIN_EVM_KEY_FILE="$test_dir/bsc/secrets/e.key" \
  "$STAGING_DIR/run-multichain-e2e.sh" init "$shared_dir" >/dev/null
shared_address="$(jq -r .evm_address "$shared_dir/sepolia/manifest.json")"
for profile in bsc base; do
  [ "$(jq -r .evm_address "$shared_dir/$profile/manifest.json")" = "$shared_address" ] ||
    fail "shared EVM key produced a different $profile address"
done

echo "[test-multichain-init] PASS"
