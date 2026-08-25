#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

if [ "${UPLOAD_GROTH16_BEFORE_L1:-1}" = "1" ]; then
  log_step "uploading Groth16 trust setup before L1 contract deployment"
  bash "$FRESH_DIR/15_upload_bridge_trust_setup.sh"
fi

run_gcp_script deploy-l1-contracts.sh

log_step "syncing remote /etc/parth/l1.env into $CONFIG_FILE"
sync_remote_l1_env_to_config

log_step "syncing remote L1 deployment artifacts into local psy-contracts/deployments"
require_cmd rsync
l1_host="${ANVIL_VM_NAME:-${NODE_VM_NAME:-gcp-cp-ce}}"
l1_contracts_home="${L1_CONTRACTS_HOME:-/opt/parth/l1-contracts/current}"
l1_deployments_network="$(awk -F= '$1 == "L1_DEPLOYMENTS_NETWORK" { value = substr($0, index($0, "=") + 1); gsub(/^"|"$/, "", value); print value; exit }' "$CONFIG_FILE")"
[ -n "$l1_deployments_network" ] || l1_deployments_network="${L1_DEPLOYMENTS_NETWORK:-localhost}"
install -d -m 0755 "$PARTH_DIR/psy-contracts/deployments/$l1_deployments_network"
rsync -az --delete \
  "$l1_host:$l1_contracts_home/deployments/$l1_deployments_network/" \
  "$PARTH_DIR/psy-contracts/deployments/$l1_deployments_network/"

log_step "current synced L1 config"
grep -E '^(ETH_RPC_URL|CHAIN_ID|L1_DEPLOYMENTS_NETWORK|L1_DEPLOYER_ADDRESS|ADDRESSES_PROVIDER_ADDRESS|BRIDGE_ADDRESS|STATE_MANAGER_ADDRESS|MULTICALL3_ADDRESS|ROUTER_ADDRESS|ERC20_GATEWAY_ADDRESS|ETH_GATEWAY_ADDRESS|WETH_ADDRESS|PSY_TOKEN_ADDRESS|USDT_TOKEN_ADDRESS|TOKEN_FAUCET_MANAGER_ADDRESS)=' "$CONFIG_FILE"
