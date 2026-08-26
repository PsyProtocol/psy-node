#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
: "${WORKSPACE_HOME:=$(cd "$REPO_ROOT/.." && pwd)}"
CONFIG_FILE="${GCP_DEPLOY_CONFIG:-$SCRIPT_DIR/config.env}"
SOURCE_VERSIONS_FILE="${DEPLOY_SOURCE_VERSIONS_FILE:-$SCRIPT_DIR/source-versions.env}"

[ -f "$CONFIG_FILE" ] || {
  echo "missing BSC deploy config: $CONFIG_FILE" >&2
  echo "copy $SCRIPT_DIR/config.example.env to $SCRIPT_DIR/config.env" >&2
  exit 1
}

bash -n "$CONFIG_FILE"
set -a
# shellcheck disable=SC1090
source "$CONFIG_FILE"
set +a

fail() {
  echo "[bsc-preflight] $*" >&2
  exit 1
}

expect_equal() {
  local name="$1"
  local expected="$2"
  local actual="${!name:-}"
  [ "$actual" = "$expected" ] || fail "$name must be '$expected', got '${actual:-<empty>}'"
}

expect_bsc_domain() {
  local name="$1"
  local actual="${!name:-}"
  case "$actual" in
    *-bsc-testnet.psy-protocol.xyz) ;;
    *) fail "$name is not isolated to the BSC Testnet namespace: ${actual:-<empty>}" ;;
  esac
}

command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v curl >/dev/null 2>&1 || fail "curl is required"

expect_equal L1_DEPLOYMENTS_NETWORK bsc-testnet
expect_equal RELAYER_DEPLOYMENTS_NETWORK bsc-testnet
expect_equal CHAIN_ID 97
expect_equal PUBLIC_ENV_SLUG bsc-testnet
expect_equal PUBLIC_ENABLE_RELEASE_BACKEND_ALIASES 0
expect_equal DEPLOY_CLOUD_PROVE_PROXY 0
expect_equal DEPLOY_OFFSITE_PROVE_PROXY 1
expect_equal OFFSITE_PROVE_PROXY_HOST arc99x2
expect_equal DEPLOY_CLOUD_REALM_WORKERS 1
expect_equal CLOUD_REALM_WORKER_LAYOUT "0:0 1:0"
expect_equal DEPLOY_OFFSITE_WORKERS 1
expect_equal OFFSITE_WORKER_HOST arc99x4

# Preserve the currently deployed machine topology. This profile changes the L1
# and public namespace, not the number or size of machines.
expect_equal SCYLLA_VM_NAME gcp-scylla
expect_equal NATS_VM_NAME gcp-nats
expect_equal REDIS_VM_NAME gcp-redis
expect_equal POSTGRES_VM_NAME gcp-postgres
expect_equal NODE_VM_NAME gcp-cp-ce
expect_equal COORDINATOR_WORKER_VM_NAME gcp-coordinator-worker
expect_equal FAUCET_VM_NAME gcp-faucet
expect_equal RELAYER_VM_NAME gcp-faucet
expect_equal ENVIO_VM_NAME gcp-postgres
expect_equal NOSTR_VM_NAME gcp-nostr

for domain_var in \
  NOSTR_DOMAIN \
  PUBLIC_COORDINATOR_DOMAIN \
  PUBLIC_REALM_DOMAIN \
  PUBLIC_REALM1_DOMAIN \
  PUBLIC_PROVE_PROXY_DOMAIN \
  PUBLIC_FAUCET_DOMAIN \
  PUBLIC_L1_RPC_DOMAIN \
  PUBLIC_PSY_SERVICES_DOMAIN \
  PUBLIC_INDEXER_DOMAIN; do
  expect_bsc_domain "$domain_var"
done

for alias_var in \
  NOSTR_ALIAS_DOMAINS \
  PUBLIC_COORDINATOR_ALIAS_DOMAINS \
  PUBLIC_REALM_ALIAS_DOMAINS \
  PUBLIC_REALM1_ALIAS_DOMAINS \
  PUBLIC_PROVE_PROXY_ALIAS_DOMAINS \
  PUBLIC_FAUCET_ALIAS_DOMAINS \
  PUBLIC_L1_RPC_ALIAS_DOMAINS \
  PUBLIC_PSY_SERVICES_ALIAS_DOMAINS \
  PUBLIC_INDEXER_ALIAS_DOMAINS; do
  [ -z "${!alias_var:-}" ] || fail "$alias_var must be empty for an isolated BSC deployment"
done

jq -e '
  .networks["bsc-testnet"]
  | .l1_chain_id == 97
    and .magic == "0x1337CF514544C269"
    and (.coordinator_configs[0].rpc_url[0] | contains("-bsc-testnet."))
    and all(.realm_configs[]; (.rpc_url[0] | contains("-bsc-testnet.")))
' "$REPO_ROOT/psy-genesis/config.json" >/dev/null \
  || fail "psy-genesis BSC Testnet profile is missing or inconsistent"

grep -A8 "'bsc-testnet':" "$REPO_ROOT/psy-contracts/protocol-config/index.ts" \
  | grep -q 'l1ChainId: 97' \
  || fail "psy-contracts BSC Testnet chain ID is missing"
grep -A8 "'bsc-testnet':" "$REPO_ROOT/psy-contracts/protocol-config/index.ts" \
  | grep -q 'l1ChainIndex: 1' \
  || fail "psy-contracts BSC Testnet chain index must be 1"

[ -n "${BSC_TESTNET_RPC_URL:-}" ] || fail "BSC_TESTNET_RPC_URL is required"
[ "$ETH_RPC_URL" = "$BSC_TESTNET_RPC_URL" ] || fail "ETH_RPC_URL must use BSC_TESTNET_RPC_URL"
[ -n "${ENVIO_API_TOKEN:-}" ] || fail "ENVIO_API_TOKEN is required for BSC HyperSync"

if [ "${BSC_PREFLIGHT_SKIP_RPC:-0}" != "1" ]; then
  rpc_chain_hex="$(curl -fsS --max-time 15 "$BSC_TESTNET_RPC_URL" \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
    | jq -er '.result')"
  rpc_chain_id="$((rpc_chain_hex))"
  [ "$rpc_chain_id" = "97" ] || fail "BSC RPC returned chain ID $rpc_chain_id"
  echo "[bsc-preflight] verified BSC Testnet RPC chain ID: $rpc_chain_id"
fi

if [ "${BSC_WALLET_PROFILE_VERIFIED:-0}" != "1" ]; then
  echo "[bsc-preflight] warning: wallet BSC profile is not yet marked verified; R2 wallet publication remains blocked"
fi

echo "[bsc-preflight] machine topology unchanged"
echo "[bsc-preflight] network and public namespace checks passed"
echo "[bsc-preflight] source versions: $SOURCE_VERSIONS_FILE"
