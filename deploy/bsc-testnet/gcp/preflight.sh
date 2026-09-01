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

[ -f "$SOURCE_VERSIONS_FILE" ] || fail "missing BSC source versions: $SOURCE_VERSIONS_FILE"
bash -n "$SOURCE_VERSIONS_FILE"
set -a
# shellcheck disable=SC1090
source "$SOURCE_VERSIONS_FILE"
set +a

expect_equal() {
  local name="$1"
  local expected="$2"
  local actual="${!name:-}"
  [ "$actual" = "$expected" ] || fail "$name must be '$expected', got '${actual:-<empty>}'"
}

command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v curl >/dev/null 2>&1 || fail "curl is required"

rpc_request() {
  local method="$1"
  local params="$2"
  local response_file http_status curl_error rpc_error result

  response_file="$(mktemp)"
  if ! http_status="$(curl -sS --max-time 15 \
    -o "$response_file" \
    -w '%{http_code}' \
    "$BSC_TESTNET_RPC_URL" \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
    2>"$response_file.curl-error")"; then
    curl_error="$(cat "$response_file.curl-error")"
    rm -f "$response_file" "$response_file.curl-error"
    fail "BSC RPC transport failed for $method: $curl_error"
  fi
  rm -f "$response_file.curl-error"

  if ! jq -e . "$response_file" >/dev/null 2>&1; then
    rm -f "$response_file"
    fail "BSC RPC returned non-JSON response for $method (HTTP $http_status)"
  fi

  rpc_error="$(jq -r '.error.message // empty' "$response_file")"
  if [ -n "$rpc_error" ]; then
    rm -f "$response_file"
    fail "BSC RPC rejected $method (HTTP $http_status): $rpc_error"
  fi
  case "$http_status" in
    2??) ;;
    *)
      rm -f "$response_file"
      fail "BSC RPC returned HTTP $http_status for $method"
      ;;
  esac

  result="$(jq -er '.result' "$response_file")" || {
    rm -f "$response_file"
    fail "BSC RPC response is missing result for $method"
  }
  rm -f "$response_file"
  printf '%s\n' "$result"
}

decimal_ge() {
  local left="$1"
  local right="$2"

  while [ "${#left}" -gt 1 ] && [ "${left#0}" != "$left" ]; do left="${left#0}"; done
  while [ "${#right}" -gt 1 ] && [ "${right#0}" != "$right" ]; do right="${right#0}"; done
  [ "${#left}" -gt "${#right}" ] \
    || { [ "${#left}" -eq "${#right}" ] && [[ "$left" > "$right" || "$left" = "$right" ]]; }
}

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
expect_equal COORDINATOR_WORKER_LAYOUT "0"
expect_equal COORDINATOR_WORKER_KEY_INDEXES "0"
expect_equal REQUIRE_MIN_COORDINATOR_WORKERS 1
expect_equal DEPLOY_OFFSITE_WORKERS 1
expect_equal OFFSITE_WORKER_HOST arc99x4
expect_equal WALLET_PACKAGE_MODE bsc-testnet
expect_equal BSC_WALLET_PROFILE_VERIFIED 1
expect_equal EXPECTED_PSY_SDK_NPM_VERSION 2.0.5
expect_equal CF_PAGES_BRANCH staging
expect_equal CF_PAGES_APP_PROJECT psy-privacy-bridge-demo-stg
expect_equal CF_PAGES_EXPLORER_PROJECT psy-explorer-stg
expect_equal CF_PAGES_IDE_PROJECT psy-ide-stg
expect_equal CF_PAGES_CONFIG_PROJECT psy-config-stg

expected_wallet_release_url="${BSC_WALLET_R2_PUBLIC_BASE_URL%/}/${BSC_WALLET_R2_METADATA_KEY}"
[ "$VITE_WALLET_RELEASE_URL" = "$expected_wallet_release_url" ] \
  || fail "VITE_WALLET_RELEASE_URL must use isolated BSC metadata: $expected_wallet_release_url"

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

expect_equal NOSTR_DOMAIN nostr-stg.psy-protocol.xyz
expect_equal PUBLIC_COORDINATOR_DOMAIN coordinator-stg.psy-protocol.xyz
expect_equal PUBLIC_REALM_DOMAIN realm0-stg.psy-protocol.xyz
expect_equal PUBLIC_REALM1_DOMAIN realm1-stg.psy-protocol.xyz
expect_equal PUBLIC_PROVE_PROXY_DOMAIN prove-stg.psy-protocol.xyz
expect_equal PUBLIC_FAUCET_DOMAIN faucet-stg.psy-protocol.xyz
expect_equal PUBLIC_L1_RPC_DOMAIN rpc-stg.psy-protocol.xyz
expect_equal PUBLIC_PSY_SERVICES_DOMAIN services-stg.psy-protocol.xyz
expect_equal PUBLIC_INDEXER_DOMAIN indexer-stg.psy-protocol.xyz

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
    and .coordinator_configs[0].rpc_url[0] == "https://coordinator-stg.psy-protocol.xyz"
    and .realm_configs[0].rpc_url[0] == "https://realm0-stg.psy-protocol.xyz"
    and .realm_configs[1].rpc_url[0] == "https://realm1-stg.psy-protocol.xyz"
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
if [ "${ENVIO_USE_HYPERSYNC:-1}" = "1" ]; then
  [ -n "${ENVIO_API_TOKEN:-}" ] || fail "ENVIO_API_TOKEN is required for BSC HyperSync"
fi

if [ "${BSC_PREFLIGHT_SKIP_RPC:-0}" != "1" ]; then
  command -v cast >/dev/null 2>&1 || fail "cast is required for BSC balance validation"

  rpc_chain_hex="$(rpc_request eth_chainId '[]')"
  rpc_chain_id="$((rpc_chain_hex))"
  [ "$rpc_chain_id" = "97" ] || fail "BSC RPC returned chain ID $rpc_chain_id"
  echo "[bsc-preflight] verified BSC Testnet RPC chain ID: $rpc_chain_id"

  deployer_address="${L1_DEPLOYER_ADDRESS:-${RELAYER_FINALIZE_EXPECTED_ADDRESS:-}}"
  [[ "$deployer_address" =~ ^0x[0-9a-fA-F]{40}$ ]] \
    || fail "L1_DEPLOYER_ADDRESS must contain the BSC deployer/relayer address"
  minimum_balance_wei="${BSC_MIN_DEPLOYER_BALANCE_WEI:-100000000000000000}"
  [[ "$minimum_balance_wei" =~ ^[0-9]+$ ]] \
    || fail "BSC_MIN_DEPLOYER_BALANCE_WEI must be an unsigned decimal integer"
  balance_params="$(jq -cn --arg address "$deployer_address" '[$address, "latest"]')"
  balance_hex="$(rpc_request eth_getBalance "$balance_params")"
  balance_wei="$(cast to-dec "$balance_hex")"
  decimal_ge "$balance_wei" "$minimum_balance_wei" \
    || fail "BSC deployer $deployer_address has $balance_wei wei; minimum required is $minimum_balance_wei wei"
  echo "[bsc-preflight] verified deployer/relayer tBNB balance: address=$deployer_address wei=$balance_wei"
fi

if [ "${BSC_REQUIRE_PUBLISHED_WALLET:-0}" = "1" ]; then
  wallet_metadata="$(curl -fsSL --max-time 20 "$VITE_WALLET_RELEASE_URL")" \
    || fail "published BSC wallet metadata is not reachable: $VITE_WALLET_RELEASE_URL"
  [ "$(jq -r '.network // empty' <<<"$wallet_metadata")" = "bsc-testnet" ] \
    || fail "published wallet metadata does not describe bsc-testnet"
  [ "$(jq -r '.walletCommit // empty' <<<"$wallet_metadata")" = "$EXPECTED_PSY_WALLET_COMMIT" ] \
    || fail "published wallet commit does not match source-versions.env"
  echo "[bsc-preflight] verified published BSC wallet metadata"
else
  echo "[bsc-preflight] wallet profile verified; publish R2 metadata before public frontend deployment"
fi

echo "[bsc-preflight] machine topology unchanged"
echo "[bsc-preflight] network and public namespace checks passed"
echo "[bsc-preflight] source versions: $SOURCE_VERSIONS_FILE"
