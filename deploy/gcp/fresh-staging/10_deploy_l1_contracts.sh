#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"
# shellcheck source=../lib/multichain.sh
source "$GCP_DIR/lib/multichain.sh"

if [ "${UPLOAD_GROTH16_BEFORE_L1:-1}" = "1" ]; then
  log_step "uploading Groth16 trust setup before L1 contract deployment"
  bash "$FRESH_DIR/15_upload_bridge_trust_setup.sh"
fi

if multichain_enabled; then
  run_gcp_script deploy-multichain-l1-contracts.sh

  primary_chain="$(multichain_primary_chain)"
  update_config_var ETH_RPC_URL "$(jq -r '.rpc_url' <<<"$primary_chain")"
  update_config_var CHAIN_ID "$(jq -r '.chain_id' <<<"$primary_chain")"
  update_config_var START_BLOCK "$(jq -r '.start_block' <<<"$primary_chain")"
  update_config_var L1_DEPLOYMENTS_NETWORK "$(jq -r '.network' <<<"$primary_chain")"
  update_config_var ADDRESSES_PROVIDER_ADDRESS "$(jq -r '.contracts.PsyAddressesProvider // empty' <<<"$primary_chain")"
  update_config_var BRIDGE_ADDRESS "$(jq -r '.contracts.Bridge' <<<"$primary_chain")"
  update_config_var STATE_MANAGER_ADDRESS "$(jq -r '.contracts.StateManager' <<<"$primary_chain")"
  update_config_var MULTICALL3_ADDRESS "$(jq -r '.contracts.Multicall3' <<<"$primary_chain")"
  update_config_var ROUTER_ADDRESS "$(jq -r '.contracts.Router' <<<"$primary_chain")"
  update_config_var ERC20_GATEWAY_ADDRESS "$(jq -r '.contracts.ERC20Gateway' <<<"$primary_chain")"
  update_config_var ETH_GATEWAY_ADDRESS "$(jq -r '.contracts.ETHGateway' <<<"$primary_chain")"
  update_config_var WETH_ADDRESS "$(jq -r '.contracts.WETH9' <<<"$primary_chain")"
  update_config_var PSY_TOKEN_ADDRESS "$(jq -r '.contracts.PsyToken' <<<"$primary_chain")"
  update_config_var USDT_TOKEN_ADDRESS "$(jq -r '.contracts.USDTToken' <<<"$primary_chain")"
  update_config_var TOKEN_FAUCET_MANAGER_ADDRESS "$(jq -r '.contracts.TokenFaucetManager' <<<"$primary_chain")"

  log_step "multichain L1 runtime manifest: $(multichain_runtime_file)"
  jq '{chains: [.chains[] | {network, chain_id, chain_index, start_block, public_rpc_domain}]}' \
    "$(multichain_runtime_file)"
  exit 0
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
