#!/usr/bin/env bash
set -euo pipefail

FRESH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GCP_DIR="$(cd "$FRESH_DIR/.." && pwd)"

# shellcheck source=../lib/common.sh
source "$GCP_DIR/lib/common.sh"

log_step() {
  printf '\n[%s] %s\n' "$(basename "$0")" "$*"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

unique_hosts() {
  awk 'NF && !seen[$0]++'
}

deploys_gcp_realm_workers() {
  case "${DEPLOY_REALM_WORKERS:-0}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

deploys_cloud_prove_proxy() {
  case "${DEPLOY_CLOUD_PROVE_PROXY:-1}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

deployment_runtime_hosts() {
  printf '%s\n' \
    "${NODE_VM_NAME:-gcp-cp-ce}" \
    "${RELAYER_VM_NAME:-${NODE_VM_NAME:-gcp-cp-ce}}" \
    "${FAUCET_VM_NAME:-${PROVE_PROXY_VM_NAME:-gcp-prove-proxy}}" \
    "${COORDINATOR_WORKER_VM_NAME:-gcp-coordinator-worker}"

  if deploys_cloud_prove_proxy; then
    printf '%s\n' "${PROVE_PROXY_VM_NAME:-gcp-prove-proxy}"
  fi

  if deploys_gcp_realm_workers; then
    printf '%s\n' \
      "${REALM_WORKER_1_VM_NAME:-gcp-realm-worker-0}" \
      "${REALM_WORKER_2_VM_NAME:-realm-worker-1}"
  fi
}

remote_sudo() {
  local host="$1"
  local script="$2"

  provision_vm "$host"
  run_remote_command "$host" "sudo bash -lc $(printf '%q' "$script")"
}

run_gcp_script() {
  local script="$1"
  shift || true

  log_step "running deploy/gcp/${script}"
  bash "$GCP_DIR/$script" "$@"
}

double_quote_escape() {
  sed 's/\\/\\\\/g; s/"/\\"/g'
}

update_config_var() {
  local key="$1"
  local value="$2"
  local escaped tmp

  [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || {
    echo "invalid config key: $key" >&2
    exit 1
  }

  escaped="$(printf '%s' "$value" | double_quote_escape)"
  tmp="$(mktemp)"
  if grep -q "^${key}=" "$CONFIG_FILE"; then
    awk -v key="$key" -v value="$escaped" '
      $0 ~ "^" key "=" {
        print key "=\"" value "\""
        next
      }
      { print }
    ' "$CONFIG_FILE" > "$tmp"
  else
    cp "$CONFIG_FILE" "$tmp"
    printf '\n%s="%s"\n' "$key" "$escaped" >> "$tmp"
  fi
  mv "$tmp" "$CONFIG_FILE"
}

sync_remote_l1_env_to_config() {
  local host="${ANVIL_VM_NAME:-${NODE_VM_NAME:-gcp-cp-ce}}"
  local tmp key value

  tmp="$(mktemp)"
  run_remote_command "$host" "sudo cat /etc/parth/l1.env" > "$tmp"

  for key in \
    ETH_RPC_URL \
    CHAIN_ID \
    L1_DEPLOYMENTS_NETWORK \
    L1_DEPLOYER_ADDRESS \
    ADDRESSES_PROVIDER_ADDRESS \
    BRIDGE_ADDRESS \
    STATE_MANAGER_ADDRESS \
    MULTICALL3_ADDRESS \
    ROUTER_ADDRESS \
    ERC20_GATEWAY_ADDRESS \
    ETH_GATEWAY_ADDRESS \
    WETH_ADDRESS \
    PSY_TOKEN_ADDRESS \
    USDT_TOKEN_ADDRESS \
    TOKEN_FAUCET_MANAGER_ADDRESS
  do
    value="$(awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$tmp")"
    [ -n "$value" ] && update_config_var "$key" "$value"
  done

  rm -f "$tmp"
}

require_cloudflare_pages_env() {
  : "${CLOUDFLARE_ACCOUNT_ID:?CLOUDFLARE_ACCOUNT_ID is required for Cloudflare Pages deploy}"
  : "${CLOUDFLARE_API_TOKEN:?CLOUDFLARE_API_TOKEN is required for Cloudflare Pages deploy}"
}

export_public_frontend_env() {
  local coordinator_url="https://${PUBLIC_COORDINATOR_DOMAIN}"
  local realm0_url="https://${PUBLIC_REALM0_DOMAIN}"
  local realm1_url="https://${PUBLIC_REALM1_DOMAIN}"
  local prove_proxy_url="https://${PUBLIC_PROVE_PROXY_DOMAIN}"
  local services_url="https://${PUBLIC_PSY_SERVICES_DOMAIN}"
  local indexer_url="https://${PUBLIC_INDEXER_DOMAIN}"
  local explorer_url="${PUBLIC_PSY_EXPLORER_URL}"
  local rpc_url="${ETH_RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}"
  if [ -n "${PUBLIC_L1_RPC_DOMAIN:-}" ]; then
    rpc_url="https://${PUBLIC_L1_RPC_DOMAIN}"
  elif [ -n "${PUBLIC_RPC_DOMAIN:-}" ]; then
    rpc_url="https://${PUBLIC_RPC_DOMAIN}"
  fi
  local nostr_url="${NOSTR_RELAY_URL}"
  local l1_network="${VITE_L1_NETWORK:-${L1_DEPLOYMENTS_NETWORK:-sepolia}}"
  local default_l1_chain_id="${CHAIN_ID:-31337}"
  local default_l1_chain_name="Psy Testnet"
  local default_l1_chain_short_name="PSY-L1"
  local default_l1_explorer_url="$rpc_url"

  if [ "$l1_network" = "sepolia" ]; then
    default_l1_chain_id="${CHAIN_ID:-11155111}"
    default_l1_chain_name="Sepolia"
    default_l1_chain_short_name="Sepolia"
    default_l1_explorer_url="https://sepolia.etherscan.io"
  fi

  export VITE_PSY_NODE_URL="${VITE_PSY_NODE_URL:-$coordinator_url}"
  export VITE_NOSTR_RELAY_URL="${VITE_NOSTR_RELAY_URL:-$nostr_url}"

  export VITE_NETWORK="${VITE_NETWORK:-$l1_network}"
  export VITE_FORK="${VITE_FORK:-false}"
  export VITE_L1_NETWORK="$l1_network"
  export VITE_L1_FORK="${VITE_L1_FORK:-false}"
  export VITE_DEPLOYMENTS_NETWORK="${VITE_DEPLOYMENTS_NETWORK:-${L1_DEPLOYMENTS_NETWORK:-localhost}}"
  export VITE_L1_CHAIN_ID="${VITE_L1_CHAIN_ID:-$default_l1_chain_id}"
  export VITE_L1_CHAIN_NAME="${VITE_L1_CHAIN_NAME:-$default_l1_chain_name}"
  export VITE_L1_CHAIN_SHORT_NAME="${VITE_L1_CHAIN_SHORT_NAME:-$default_l1_chain_short_name}"
  export VITE_DEFAULT_CHAIN_ID="${VITE_DEFAULT_CHAIN_ID:-$default_l1_chain_id}"
  export VITE_L1_RPC_URL="${VITE_L1_RPC_URL:-$rpc_url}"
  export VITE_L1_EXPLORER_URL="${VITE_L1_EXPLORER_URL:-$default_l1_explorer_url}"
  export VITE_L1_ROUTER_ADDRESS="${VITE_L1_ROUTER_ADDRESS:-${ROUTER_ADDRESS:-}}"
  export VITE_L1_BRIDGE_ADDRESS="${VITE_L1_BRIDGE_ADDRESS:-${BRIDGE_ADDRESS:-}}"
  export VITE_L1_STATE_MANAGER_ADDRESS="${VITE_L1_STATE_MANAGER_ADDRESS:-${STATE_MANAGER_ADDRESS:-}}"
  export VITE_L1_ERC20_GATEWAY_ADDRESS="${VITE_L1_ERC20_GATEWAY_ADDRESS:-${ERC20_GATEWAY_ADDRESS:-}}"
  export VITE_L1_WETH_ADDRESS="${VITE_L1_WETH_ADDRESS:-${WETH_ADDRESS:-}}"
  export VITE_PSY_TOKEN_ADDRESS="${VITE_PSY_TOKEN_ADDRESS:-${PSY_TOKEN_ADDRESS:-}}"
  export VITE_USDT_TOKEN_ADDRESS="${VITE_USDT_TOKEN_ADDRESS:-${USDT_TOKEN_ADDRESS:-}}"
  export VITE_PSY_SERVICES_URL="${VITE_PSY_SERVICES_URL:-$services_url}"
  export VITE_INDEXER_URL="${VITE_INDEXER_URL:-${indexer_url}/v1/graphql}"
  export VITE_PSY_COORDINATOR_URL="${VITE_PSY_COORDINATOR_URL:-$coordinator_url}"
  export VITE_PSY_REALM_URLS="${VITE_PSY_REALM_URLS:-${realm0_url},${realm1_url}}"
  export VITE_PSY_PROVE_PROXY_URL="${VITE_PSY_PROVE_PROXY_URL:-$prove_proxy_url}"
  export VITE_PSY_INDEXER_API_URL="${VITE_PSY_INDEXER_API_URL:-$services_url}"
  export VITE_PSY_EXPLORER_URL="${VITE_PSY_EXPLORER_URL:-$explorer_url}"
  export VITE_COORDINATOR_URL="${VITE_COORDINATOR_URL:-$coordinator_url}"
  export VITE_PROVE_PROXY_URL="${VITE_PROVE_PROXY_URL:-$prove_proxy_url}"

  # These are not emitted by the current L1 deploy script. Keep explicit env
  # overrides possible, otherwise use the prior staging defaults.
  export VITE_L1_ADDRESSES_PROVIDER_ADDRESS="${VITE_L1_ADDRESSES_PROVIDER_ADDRESS:-${ADDRESSES_PROVIDER_ADDRESS:-0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0}}"
  export VITE_L1_ETH_GATEWAY_ADDRESS="${VITE_L1_ETH_GATEWAY_ADDRESS:-${ETH_GATEWAY_ADDRESS:-0x9A676e781A523b5d0C0e43731313A708CB607508}}"
}
