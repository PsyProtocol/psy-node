#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export GCP_DIR="$tmp/gcp" PSY_CONTRACTS_DIR="$tmp/contracts"
export TEST_DEPLOY_CALLS="$tmp/calls" TEST_REMOTE="$tmp/remote"
export MULTICHAIN_L1_RUNTIME_FILE="$tmp/runtime/l1-deployments.json"
mkdir -p "$GCP_DIR/lib" "$PSY_CONTRACTS_DIR" "$TEST_REMOTE" "$tmp/bin" "$tmp/runtime"
cp "$ROOT/deploy/gcp/deploy-multichain-l1-contracts.sh" "$GCP_DIR/"
cp "$ROOT/deploy/gcp/lib/multichain.sh" "$GCP_DIR/lib/"
cat > "$GCP_DIR/lib/common.sh" <<'SH'
run_remote_command() { cat "$TEST_REMOTE/l1.env"; }
SH
cat > "$GCP_DIR/deploy-l1-contracts.sh" <<'SH'
set -euo pipefail
network="$MULTICHAIN_CURRENT_L1_NETWORK"
echo "$network" >> "$TEST_DEPLOY_CALLS"
if [ "$network" = "${TEST_FAIL_NETWORK:-}" ]; then exit 8; fi
index=$(jq -r --arg network "$network" '.[] | select(.network == $network) | .chain_index' <<< "$MULTICHAIN_L1_CHAINS_JSON")
printf 'L1_DEPLOYMENTS_NETWORK=%s\nCHAIN_ID=%s\nSTART_BLOCK=%s\n' \
  "$network" "$MULTICHAIN_CURRENT_CHAIN_ID" "$((100 + index))" > "$TEST_REMOTE/l1.env"
mkdir -p "$TEST_REMOTE/$network"
jq -n --argjson index "$index" \
  --arg bridge "$(printf '0x%040d' "$((index * 10 + 1))")" \
  --arg manager "$(printf '0x%040d' "$((index * 10 + 2))")" \
  --arg multicall "$(printf '0x%040d' "$((index * 10 + 3))")" \
  '{core:{Bridge:$bridge,StateManager:$manager,Multicall3:$multicall},protocol:{chain:{l1ChainIndex:$index}}}' \
  > "$TEST_REMOTE/$network/deployed-contracts.json"
SH
cat > "$tmp/bin/rsync" <<'SH'
set -euo pipefail
target="${!#}"
network="$(basename "$target")"
cp "$TEST_REMOTE/$network/deployed-contracts.json" "$target/deployed-contracts.json"
SH
chmod +x "$tmp/bin/rsync"
export PATH="$tmp/bin:$PATH"
export MULTICHAIN_L1_CHAINS_JSON
MULTICHAIN_L1_CHAINS_JSON="$(jq -cn '
  [["sepolia",11155111,0],["bscTestnet",97,1],["baseSepolia",84532,2]] | map({
    name:.[0],network:.[0],chain_id:.[1],chain_index:.[2],
    rpc_url:"https://rpc.example.test",public_rpc_domain:(.[0]+".example.test"),
    explorer_url:"https://explorer.example.test"
  })')"
printf '%s\n' '{"generated_at":"previous-release"}' > "$MULTICHAIN_L1_RUNTIME_FILE"

exec 8>>"${MULTICHAIN_L1_RUNTIME_FILE}.lock"
flock -n 8
if bash "$GCP_DIR/deploy-multichain-l1-contracts.sh" > "$tmp/locked.log" 2>&1; then exit 1; fi
grep -q 'another L1 deployment is running' "$tmp/locked.log"
[ ! -e "$TEST_DEPLOY_CALLS" ]
flock -u 8
exec 8>&-

# Simulate a transaction failure on chain 1 after chain 0 has succeeded.
set +e
TEST_FAIL_NETWORK=bscTestnet bash "$GCP_DIR/deploy-multichain-l1-contracts.sh" > "$tmp/failed.log" 2>&1
result=$?
set -e
[ "$result" = 8 ]
[ "$(paste -sd, "$TEST_DEPLOY_CALLS")" = 'sepolia,bscTestnet' ]
jq -e '.in_progress == "bscTestnet" and [.chains[].network] == ["sepolia"]' \
  "${MULTICHAIN_L1_RUNTIME_FILE}.pending" >/dev/null
jq -e '.generated_at == "previous-release"' "$MULTICHAIN_L1_RUNTIME_FILE" >/dev/null
[ "$(stat -c %a "${MULTICHAIN_L1_RUNTIME_FILE}.pending")" = 600 ]
# shellcheck source=../lib/multichain.sh
source "$GCP_DIR/lib/multichain.sh"
if multichain_require_runtime > /dev/null 2>&1; then exit 1; fi
if bash "$GCP_DIR/deploy-multichain-l1-contracts.sh" > /dev/null 2>&1; then exit 1; fi
[ "$(wc -l < "$TEST_DEPLOY_CALLS")" = 2 ]

# Start a separate successful fixture; no production markers are touched.
export MULTICHAIN_L1_RUNTIME_FILE="$tmp/success/l1-deployments.json"
: > "$TEST_DEPLOY_CALLS"
bash "$GCP_DIR/deploy-multichain-l1-contracts.sh" > "$tmp/success.log"
[ "$(paste -sd, "$TEST_DEPLOY_CALLS")" = 'sepolia,bscTestnet,baseSepolia' ]
[ ! -e "${MULTICHAIN_L1_RUNTIME_FILE}.pending" ]
[ "$(stat -c %a "$MULTICHAIN_L1_RUNTIME_FILE")" = 600 ]
multichain_require_runtime
jq -e '[.chains[].chain_index] == [0,1,2] and [.chains[].start_block] == [100,101,102]' \
  "$MULTICHAIN_L1_RUNTIME_FILE" > /dev/null
[ "$(grep -c 'completed network=' "$tmp/success.log")" = 3 ]
echo '[ok] failed L1 deployment preserves progress and blocks stale manifests; success publishes all three chains'
