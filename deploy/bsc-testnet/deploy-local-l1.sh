#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=deploy/bsc-testnet/lib.sh
source "$(dirname "$0")/lib.sh"

require_local_transaction_authorization
require_command jq
require_command pnpm
require_bsc_local_rpc

[ -f "$PSY_CONTRACTS_DIR/package.json" ] || die "invalid PSY_CONTRACTS_DIR: $PSY_CONTRACTS_DIR"
[ -f "$PSY_CONTRACTS_DIR/config/bsc-testnet.json" ] ||
  die "missing BSC contract profile: $PSY_CONTRACTS_DIR/config/bsc-testnet.json"

profile_index="$(jq -er '.l1ChainIndex' "$PSY_CONTRACTS_DIR/config/bsc-testnet.json")"
[ "$profile_index" -eq 1 ] || die "BSC l1ChainIndex must be 1, got $profile_index"

mkdir -p "$BSC_EVIDENCE_DIR"

echo "[bsc-testnet] deploying contracts: rpc=$BSC_LOCAL_RPC_URL chain_id=$BSC_LOCAL_CHAIN_ID psy_index=$profile_index"
(
  cd "$PSY_CONTRACTS_DIR"
  BSC_TESTNET_RPC_URL="$BSC_LOCAL_RPC_URL" \
  CHAIN_ID="$BSC_LOCAL_CHAIN_ID" \
  PSY_INTERNAL_DEPLOY_FROM_KEYSTORE=1 \
  PSY_INTERNAL_DEPLOY_PRIVATE_KEY="$BSC_LOCAL_DEPLOY_PRIVATE_KEY" \
    pnpm exec hardhat deploy --network bsc-testnet --reset
)

[ -s "$BSC_DEPLOYMENT_FILE" ] || die "deployment did not produce $BSC_DEPLOYMENT_FILE"
jq -e \
  --argjson chain_id "$BSC_LOCAL_CHAIN_ID" \
  --argjson chain_index "$profile_index" '
    (.chainId | tonumber) == $chain_id and
    (.protocol.chain.l1ChainIndex | tonumber) == $chain_index and
    ([.core.Bridge, .core.StateManager, .core.Router, .core.ERC20Gateway, .core.Multicall3] | all(type == "string" and length == 42))
  ' "$BSC_DEPLOYMENT_FILE" >/dev/null || die "generated deployment manifest is inconsistent"

cp "$BSC_DEPLOYMENT_FILE" "$BSC_EVIDENCE_DIR/deployed-contracts.json"
sha256sum "$BSC_DEPLOYMENT_FILE" > "$BSC_EVIDENCE_DIR/deployed-contracts.sha256"
date -u +'%Y-%m-%dT%H:%M:%SZ' > "$BSC_EVIDENCE_DIR/deployed-at.txt"

bash "$BSC_DEPLOY_DIR/check-local-l1.sh"
