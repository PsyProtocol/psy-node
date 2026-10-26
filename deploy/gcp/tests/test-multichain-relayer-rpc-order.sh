#!/usr/bin/env bash
set -euo pipefail
# Ported from 79778b79700cd474bba2008d4835578287bfda14 (RPC preference order).
unset RELAYER_CHAINS_JSON
export MULTICHAIN_L1_RPC_PROVIDER=any

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

export REPO_ROOT
export MULTICHAIN_L1_ENABLED=1
export MULTICHAIN_PRIMARY_NETWORK=sepolia
export MULTICHAIN_L1_RUNTIME_FILE="$TMP_DIR/l1-deployments.json"
export INDEXER_GRAPHQL_URL="http://10.0.0.3:18080/v1/graphql"

cat >"$MULTICHAIN_L1_RUNTIME_FILE" <<'JSON'
{
  "schema_version": 1,
  "generated_at": "2026-09-04T00:00:00Z",
  "chains": [
    {
      "name": "Ethereum Sepolia",
      "network": "sepolia",
      "chain_id": 11155111,
      "chain_index": 0,
      "start_block": 100,
      "rpc_url": "https://private.example/eth/key-a",
      "rpc_fallback_url": "https://a-backup.example/eth",
      "public_rpc_domain": "rpc-eth-stg.example.test",
      "explorer_url": "https://sepolia.etherscan.io",
      "use_hypersync": true,
      "hypersync_url": "https://sepolia.hypersync.xyz",
      "contracts": {"Bridge":"0x0000000000000000000000000000000000000011","StateManager":"0x0000000000000000000000000000000000000012","Multicall3":"0x0000000000000000000000000000000000000013"},
      "protocol": {"chain":{"bridgeChain":"ethereum","name":"Sepolia","shortName":"ETH","nativeCurrency":{"name":"Ether","symbol":"ETH","decimals":18}},"tokens":{"PSY":{"symbol":"PSY","decimals":9,"l1Address":"0x0000000000000000000000000000000000000014","l2TokenContractId":"0x00"},"USDT":{"symbol":"USDT","decimals":6,"l1Address":"0x0000000000000000000000000000000000000015","l2TokenContractId":"0x04"}}}
    },
    {
      "name": "BSC Testnet",
      "network": "bscTestnet",
      "chain_id": 97,
      "chain_index": 1,
      "start_block": 200,
      "rpc_url": "https://private.example/bsc/key-b",
      "rpc_fallback_url": "https://private.example/bsc/key-b",
      "public_rpc_domain": "rpc-bsc-stg.example.test",
      "explorer_url": "https://testnet.bscscan.com",
      "contracts": {"Bridge":"0x0000000000000000000000000000000000000021","StateManager":"0x0000000000000000000000000000000000000022","Multicall3":"0x0000000000000000000000000000000000000023"},
      "protocol": {"chain":{"bridgeChain":"bsc","name":"BSC Testnet","shortName":"BSC","nativeCurrency":{"name":"Test BNB","symbol":"tBNB","decimals":18}},"tokens":{"PSY":{"symbol":"PSY","decimals":9,"l1Address":"0x0000000000000000000000000000000000000024","l2TokenContractId":"0x00"},"USDT":{"symbol":"USDT","decimals":6,"l1Address":"0x0000000000000000000000000000000000000025","l2TokenContractId":"0x04"}}}
    },
    {
      "name": "Base Sepolia",
      "network": "baseSepolia",
      "chain_id": 84532,
      "chain_index": 2,
      "start_block": 300,
      "rpc_url": "https://private.example/base/key-c",
      "public_rpc_domain": "rpc-base-stg.example.test",
      "explorer_url": "https://sepolia.basescan.org",
      "contracts": {"Bridge":"0x0000000000000000000000000000000000000031","StateManager":"0x0000000000000000000000000000000000000032","Multicall3":"0x0000000000000000000000000000000000000033"},
      "protocol": {"chain":{"bridgeChain":"base","name":"Base Sepolia","shortName":"BASE","nativeCurrency":{"name":"Ether","symbol":"ETH","decimals":18}},"tokens":{"PSY":{"symbol":"PSY","decimals":9,"l1Address":"0x0000000000000000000000000000000000000034","l2TokenContractId":"0x00"},"USDT":{"symbol":"USDT","decimals":6,"l1Address":"0x0000000000000000000000000000000000000035","l2TokenContractId":"0x04"}}}
    }
  ]
}
JSON

# shellcheck source=../lib/multichain.sh
source "$REPO_ROOT/deploy/gcp/lib/multichain.sh"
export MULTICHAIN_L1_CHAINS_JSON
MULTICHAIN_L1_CHAINS_JSON="$(jq -c '.chains' "$MULTICHAIN_L1_RUNTIME_FILE")"

chains="$(multichain_relayer_chains_json)"
expect() {
  local index="$1" expected="$2" actual
  actual="$(jq -c --argjson i "$index" '.[$i].rpc_urls' <<<"$chains")"
  if [[ "$actual" != "$expected" ]]; then
    echo "chain $index rpc_urls: expected $expected, got $actual" >&2
    exit 1
  fi
}
expect 0 '["https://private.example/eth/key-a","https://a-backup.example/eth"]'
expect 1 '["https://private.example/bsc/key-b"]'
expect 2 '["https://private.example/base/key-c"]'
echo "relayer rpc_urls keep primary-first order"
