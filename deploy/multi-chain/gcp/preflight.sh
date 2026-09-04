#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
: "${WORKSPACE_HOME:=$(cd "$REPO_ROOT/.." && pwd)}"
CONFIG_FILE="${GCP_DEPLOY_CONFIG:-$SCRIPT_DIR/config.env}"
SOURCE_VERSIONS_FILE="${DEPLOY_SOURCE_VERSIONS_FILE:-$SCRIPT_DIR/source-versions.env}"

fail() {
  echo "[multichain-preflight] $*" >&2
  exit 1
}

[ -f "$CONFIG_FILE" ] || fail "missing config: $CONFIG_FILE (copy config.example.env to config.env)"
[ -f "$SOURCE_VERSIONS_FILE" ] || fail "missing source versions: $SOURCE_VERSIONS_FILE"
command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v rg >/dev/null 2>&1 || fail "rg is required"
bash -n "$CONFIG_FILE"
bash -n "$SOURCE_VERSIONS_FILE"

set -a
# shellcheck disable=SC1090
source "$CONFIG_FILE"
# shellcheck disable=SC1090
source "$SOURCE_VERSIONS_FILE"
set +a

# shellcheck source=../../gcp/lib/multichain.sh
source "$REPO_ROOT/deploy/gcp/lib/multichain.sh"
multichain_enabled || fail "MULTICHAIN_L1_ENABLED must be 1"
multichain_validate_specs || fail "invalid multichain chain registry"

[ "${MULTICHAIN_PRIMARY_NETWORK:-}" = "sepolia" ] \
  || fail "MULTICHAIN_PRIMARY_NETWORK must be sepolia"
[ "${L1_DEPLOYMENTS_NETWORK:-}" = "sepolia" ] \
  || fail "legacy primary L1_DEPLOYMENTS_NETWORK must be sepolia"
[ "${CHAIN_ID:-}" = "11155111" ] \
  || fail "legacy primary CHAIN_ID must be 11155111"
[ -z "${PUBLIC_L1_RPC_DOMAIN:-}" ] \
  || fail "PUBLIC_L1_RPC_DOMAIN must be empty; use one hostname per chain"
[ -z "${PUBLIC_RPC_DOMAIN:-}" ] \
  || fail "PUBLIC_RPC_DOMAIN must be empty; use one hostname per chain"

actual_chain_matrix="$(multichain_specs_json | jq -c 'sort_by(.chain_index) | map([.network, .chain_id, .chain_index])')"
expected_chain_matrix='[["sepolia",11155111,0],["bscTestnet",97,1],["baseSepolia",84532,2]]'
[ "$actual_chain_matrix" = "$expected_chain_matrix" ] \
  || fail "chain registry must be sepolia=0, bscTestnet=1, baseSepolia=2; got $actual_chain_matrix"

for name in SEPOLIA_RPC_URL BSC_TESTNET_RPC_URL BASE_SEPOLIA_RPC_URL \
  ENVIO_API_TOKEN L1_DEPLOYER_ADDRESS L1_DEPLOYER_KEYSTORE_PATH \
  L1_DEPLOYER_WALLET_PASSWORD POSTGRES_PASSWORD HASURA_GRAPHQL_ADMIN_SECRET \
  PSY_JWT_SECRET CLIENT_PROVE_PROXY_URL PUBLIC_PROVE_PROXY_UPSTREAM; do
  [ -n "${!name:-}" ] || fail "$name is required"
done
[ "$POSTGRES_PASSWORD" != "change-me" ] || fail "POSTGRES_PASSWORD still uses the example value"
[ "$PSY_JWT_SECRET" != "dev-secret-key" ] || fail "PSY_JWT_SECRET still uses the example value"
[[ "$L1_DEPLOYER_ADDRESS" =~ ^0x[0-9a-fA-F]{40}$ ]] \
  || fail "L1_DEPLOYER_ADDRESS must be a 20-byte EVM address"
[ -f "$L1_DEPLOYER_KEYSTORE_PATH" ] \
  || fail "missing L1 deployer keystore: $L1_DEPLOYER_KEYSTORE_PATH"

for host in \
  gcp-scylla gcp-nats gcp-redis gcp-postgres gcp-cp-ce \
  gcp-coordinator-worker gcp-faucet gcp-nostr arc99x2 arc99x4; do
  ssh -F "${SSH_CONFIG_FILE:-$HOME/.ssh/config}" -G "$host" >/dev/null 2>&1 \
    || fail "SSH host alias is missing: $host"
done

for expected in \
  "psy-genesis:$EXPECTED_PSY_GENESIS_COMMIT" \
  "psy-contracts:$EXPECTED_PSY_CONTRACTS_COMMIT" \
  "psy-dapp:$EXPECTED_PSY_DAPP_COMMIT"; do
  directory="${expected%%:*}"
  commit="${expected#*:}"
  actual="$(git -C "$REPO_ROOT/$directory" rev-parse HEAD 2>/dev/null || true)"
  [ "$actual" = "$commit" ] || fail "$directory must be at $commit, got ${actual:-<missing>}"
done

services_dir="${PSY_SERVICES_DIR:-$WORKSPACE_HOME/psy-services-merge-multi-chain}"
[ "$(git -C "$services_dir" rev-parse HEAD 2>/dev/null || true)" = "$EXPECTED_PSY_SERVICES_COMMIT" ] \
  || fail "psy-services is not at the pinned multichain commit"
rg -q 'pub chains: Vec<L1Config>' "$REPO_ROOT/psy_cli/psy_relayer_cli/src/bridge/daemon.rs" \
  || fail "psy-node does not contain the multichain relayer daemon"
rg -q 'PSY_L1_CHAINS' "$services_dir/src/config" \
  || fail "psy-services does not contain the multichain L1 registry"
rg -q "activeNetworks: \['sepolia', 'bscTestnet', 'baseSepolia'\]" \
  "$REPO_ROOT/psy-contracts/protocol-config/index.ts" \
  || fail "psy-contracts active network registry is incomplete"

if multichain_specs_json | jq -e 'any(.[]; .use_hypersync == true)' >/dev/null; then
  [ -n "$ENVIO_API_TOKEN" ] || fail "ENVIO_API_TOKEN is required when HyperSync is enabled"
fi

rpc_request() {
  local label="$1"
  local url="$2"
  local method="$3"
  local params="$4"
  local response status error
  response="$(mktemp)"
  status="$(curl -sS --max-time 20 -o "$response" -w '%{http_code}' \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
    "$url")" || {
      rm -f "$response"
      fail "$label RPC transport failed for $method"
    }
  case "$status" in 2??) ;; *) rm -f "$response"; fail "$label RPC returned HTTP $status" ;; esac
  error="$(jq -r '.error.message // empty' "$response")"
  [ -z "$error" ] || { rm -f "$response"; fail "$label RPC rejected $method: $error"; }
  jq -er '.result' "$response"
  rm -f "$response"
}

decimal_ge() {
  local left="${1#0}" right="${2#0}"
  [ -n "$left" ] || left=0
  [ -n "$right" ] || right=0
  [ "${#left}" -gt "${#right}" ] \
    || {
      # Equal-length decimal strings can be compared lexicographically without
      # overflowing Bash's signed integer arithmetic.
      # shellcheck disable=SC2071
      [ "${#left}" -eq "${#right}" ] && [[ "$left" > "$right" || "$left" = "$right" ]]
    }
}

if [ "${MULTICHAIN_PREFLIGHT_SKIP_RPC:-0}" != "1" ]; then
  command -v cast >/dev/null 2>&1 || fail "cast is required for signer and balance validation"
  actual_signer="$(cast wallet address --keystore "$L1_DEPLOYER_KEYSTORE_PATH" --password "$L1_DEPLOYER_WALLET_PASSWORD")"
  [ "${actual_signer,,}" = "${L1_DEPLOYER_ADDRESS,,}" ] \
    || fail "L1 keystore address does not match L1_DEPLOYER_ADDRESS"

  minimum_balance="${MULTICHAIN_MIN_DEPLOYER_BALANCE_WEI:-100000000000000000}"
  while IFS= read -r chain; do
    label="$(jq -r '.name' <<<"$chain")"
    rpc_url="$(jq -r '.rpc_url' <<<"$chain")"
    expected_chain_id="$(jq -r '.chain_id' <<<"$chain")"
    chain_hex="$(rpc_request "$label" "$rpc_url" eth_chainId '[]')"
    actual_chain_id="$((chain_hex))"
    [ "$actual_chain_id" = "$expected_chain_id" ] \
      || fail "$label RPC chain ID mismatch: expected $expected_chain_id, got $actual_chain_id"
    params="$(jq -cn --arg address "$L1_DEPLOYER_ADDRESS" '[$address, "latest"]')"
    balance_hex="$(rpc_request "$label" "$rpc_url" eth_getBalance "$params")"
    balance_wei="$(cast to-dec "$balance_hex")"
    decimal_ge "$balance_wei" "$minimum_balance" \
      || fail "$label deployer balance $balance_wei wei is below $minimum_balance"
    echo "[multichain-preflight] $label chain_id=$actual_chain_id signer_balance_wei=$balance_wei"
  done < <(multichain_specs_json | jq -c 'sort_by(.chain_index)[]')
else
  echo "[multichain-preflight] RPC and signer balance checks skipped"
fi

if [ "${MULTICHAIN_PREFLIGHT_SKIP_DNS:-0}" != "1" ]; then
  while IFS= read -r domain; do
    getent ahosts "$domain" >/dev/null 2>&1 \
      || fail "public L1 RPC DNS is not resolvable: $domain"
  done < <(multichain_specs_json | jq -r '.[].public_rpc_domain')
fi

echo "[multichain-preflight] source, topology, chain registry, signer, and public routing checks passed"
