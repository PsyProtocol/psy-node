#!/usr/bin/env bash
set -euo pipefail

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
multichain_require_runtime

envio_json="$(multichain_envio_chains_json)"
services_json="$(multichain_services_l1_json)"
relayer_json="$(multichain_relayer_chains_json)"
public_json="$(multichain_public_l1_config_json)"

jq -e '.chains | map(.chain_index) == [0,1,2] and map(.start_block) == [100,200,300]' \
  <<<"$envio_json" >/dev/null
jq -e 'map(.chain_index) == [0,1,2] and all(.[]; .graphql_url == "http://10.0.0.3:18080/v1/graphql")' \
  <<<"$services_json" >/dev/null
jq -e 'map(.chain_index) == [0,1,2] and all(.[]; (.rpc_urls | length) == 1)' \
  <<<"$relayer_json" >/dev/null
jq -e 'map(.rpc_url) == ["https://rpc-eth-stg.example.test","https://rpc-bsc-stg.example.test","https://rpc-base-stg.example.test"]' \
  <<<"$public_json" >/dev/null
if grep -q 'private.example' <<<"$public_json"; then
  echo "public multichain config leaked a private upstream RPC" >&2
  exit 1
fi

export ENVIO_CONFIG_FILE="$TMP_DIR/envio-config.yaml"
export ENVIO_CHAINS_JSON="$envio_json"
export ENVIO_CONFIRMED_BLOCK_THRESHOLD=8
export ENVIO_RPC_INITIAL_BLOCK_INTERVAL=50000
export ENVIO_RPC_BACKOFF_MULTIPLICATIVE=0.8
export ENVIO_RPC_ACCELERATION_ADDITIVE=10000
export ENVIO_RPC_INTERVAL_CEILING=100000
export ENVIO_RPC_BACKOFF_MILLIS=5000
export ENVIO_RPC_FALLBACK_STALL_TIMEOUT_MILLIS=10000
export ENVIO_RPC_QUERY_TIMEOUT_MILLIS=20000
# shellcheck source=../lib/envio-config.sh
source "$REPO_ROOT/deploy/gcp/lib/envio-config.sh"
write_envio_config

[ "$(grep -Ec '^  - id: (11155111|97|84532)$' "$ENVIO_CONFIG_FILE")" = "3" ] \
  || { echo "rendered Envio config does not contain all chain IDs" >&2; exit 1; }
[ "$(grep -Fc 'event: DepositRecorded(uint32 indexed index, bytes32 shieldAddress, address indexed token, bytes32 l2TokenContractId, uint256 amount, uint8 chainIndex, bytes32 noteCommitment, bytes32 leafHash)' "$ENVIO_CONFIG_FILE")" = "1" ] \
  || { echo "rendered Envio config has the wrong DepositRecorded ABI" >&2; exit 1; }
[ "$(grep -Fc '    hypersync_config:' "$ENVIO_CONFIG_FILE")" = "1" ] \
  || { echo "rendered Envio config lost the HyperSync source" >&2; exit 1; }
[ "$(grep -Fc '    rpc_config:' "$ENVIO_CONFIG_FILE")" = "2" ] \
  || { echo "rendered Envio config lost direct RPC sources" >&2; exit 1; }
for address in 0x0000000000000000000000000000000000000011 \
  0x0000000000000000000000000000000000000021 \
  0x0000000000000000000000000000000000000031; do
  grep -Fq -- "$address" "$ENVIO_CONFIG_FILE" \
    || { echo "rendered Envio config is missing $address" >&2; exit 1; }
done

RELAYER_CONFIG="$TMP_DIR/bridge-relayer.toml"
RELAYER_CONFIG="$RELAYER_CONFIG" \
RELAYER_SERVICES_URL="http://10.0.0.1:3000" \
RELAYER_L2_PRIVATE_KEY="l2-test-key" \
RELAYER_FINALIZE_KEYSTORE_PATH="/var/lib/parth/keystore/l1" \
RELAYER_CHAINS_JSON="$relayer_json" \
RELAYER_PROOF_DIR="$TMP_DIR/proofs" \
  bash "$REPO_ROOT/deploy/gcp/remote/write-relayer-config.sh" >/dev/null

python3 - "$RELAYER_CONFIG" <<'PY'
import pathlib
import sys
import tomllib

config = tomllib.loads(pathlib.Path(sys.argv[1]).read_text())
assert [chain["chain_index"] for chain in config["chains"]] == [0, 1, 2]
assert [chain["deployments_network"] for chain in config["chains"]] == [
    "sepolia", "bscTestnet", "baseSepolia"
]
assert all(chain["keystore_path"] == "/var/lib/parth/keystore/l1" for chain in config["chains"])
assert "finalize" not in config
PY

mkdir -p "$TMP_DIR/bin" "$TMP_DIR/nostr"
cat >"$TMP_DIR/bin/docker" <<'SH'
#!/usr/bin/env bash
case "${1:-}" in
  inspect) exit 1 ;;
  compose) exit 0 ;;
  *) exit 0 ;;
esac
SH
chmod +x "$TMP_DIR/bin/docker"

routes_json="$(multichain_public_rpc_routes_json)"
PATH="$TMP_DIR/bin:$PATH" \
NOSTR_HOME="$TMP_DIR/nostr" \
NOSTR_DOMAIN="nostr-stg.example.test" \
PUBLIC_L1_RPC_ROUTES_JSON="$routes_json" \
  bash "$REPO_ROOT/deploy/gcp/remote/update-caddy-entrypoints.sh" >/dev/null

for domain in rpc-eth-stg.example.test rpc-bsc-stg.example.test rpc-base-stg.example.test; do
  [ "$(grep -Fxc "$domain {" "$TMP_DIR/nostr/Caddyfile")" = "1" ] \
    || { echo "missing Caddy route for $domain" >&2; exit 1; }
done
grep -Fq 'rewrite * /eth/key-a' "$TMP_DIR/nostr/Caddyfile" \
  || { echo "Caddy did not preserve the authenticated RPC path" >&2; exit 1; }
grep -Fq 'reverse_proxy https://private.example {' "$TMP_DIR/nostr/Caddyfile" \
  || { echo "Caddy did not isolate the RPC origin from its path" >&2; exit 1; }
if grep -Fq 'reverse_proxy https://private.example/eth/key-a' "$TMP_DIR/nostr/Caddyfile"; then
  echo "Caddy rendered an invalid reverse_proxy upstream containing a path" >&2
  exit 1
fi

MULTICHAIN_L1_ENABLED=1 PUBLIC_L1_RPC_DOMAIN="" PUBLIC_RPC_DOMAIN="" \
  bash -c 'source "$1"; set_public_domain_defaults; [ -z "$PUBLIC_L1_RPC_DOMAIN" ] && [ -z "$PUBLIC_RPC_DOMAIN" ]' \
  _ "$REPO_ROOT/deploy/gcp/lib/public-domains.sh"

echo "[ok] multichain runtime drives Envio, psy-services, relayer, public config, and Caddy"
