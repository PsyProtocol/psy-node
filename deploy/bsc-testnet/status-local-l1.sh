#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=deploy/bsc-testnet/lib.sh
source "$(dirname "$0")/lib.sh"

if pid_is_running; then
  echo "[bsc-testnet] Anvil process: running pid=$(read_pid)"
else
  echo "[bsc-testnet] Anvil process: stopped"
fi

if probe_bsc_local_rpc; then
  chain_hex="$(rpc_call eth_chainId | jq -er '.result')"
  block_hex="$(rpc_call eth_blockNumber | jq -er '.result')"
  echo "[bsc-testnet] RPC: ready url=$BSC_LOCAL_RPC_URL chain_id=$((chain_hex)) block=$((block_hex))"
else
  echo "[bsc-testnet] RPC: unavailable url=$BSC_LOCAL_RPC_URL"
fi

if [ -s "$BSC_DEPLOYMENT_FILE" ]; then
  echo "[bsc-testnet] deployment: present $BSC_DEPLOYMENT_FILE"
  jq '{network, chainId, l1ChainIndex: .protocol.chain.l1ChainIndex, core: {Bridge: .core.Bridge, StateManager: .core.StateManager, Router: .core.Router}}' "$BSC_DEPLOYMENT_FILE"
else
  echo "[bsc-testnet] deployment: missing $BSC_DEPLOYMENT_FILE"
fi
