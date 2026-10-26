#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=deploy/bsc-testnet/lib.sh
source "$(dirname "$0")/lib.sh"

require_command cast
require_command jq
require_bsc_local_rpc
[ -s "$BSC_DEPLOYMENT_FILE" ] || die "missing deployment manifest: $BSC_DEPLOYMENT_FILE"

state_manager="$(jq -er '.core.StateManager' "$BSC_DEPLOYMENT_FILE")"
chain_index="$(cast call --rpc-url "$BSC_LOCAL_RPC_URL" "$state_manager" 'l1ChainIndex()(uint8)')"
[ "$((chain_index))" -eq 1 ] || die "StateManager l1ChainIndex is $chain_index; expected 1"

for name in Bridge StateManager Router ERC20Gateway TokenFaucetManager PsyToken USDTToken; do
  address="$(jq -er --arg name "$name" '.core[$name]' "$BSC_DEPLOYMENT_FILE")"
  code="$(rpc_call eth_getCode "[\"$address\",\"latest\"]" | jq -er '.result')"
  [ "$code" != "0x" ] || die "$name has no bytecode at $address"
done

block_number="$(rpc_call eth_blockNumber | jq -er '.result')"
echo "[bsc-testnet] local L1 healthy: chain_id=$BSC_LOCAL_CHAIN_ID block=$((block_number)) l1_chain_index=$((chain_index))"
echo "[bsc-testnet] manifest: $BSC_DEPLOYMENT_FILE"
