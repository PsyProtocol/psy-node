#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=deploy/bsc-testnet/full-stack-lib.sh
source "$(dirname "$0")/full-stack-lib.sh"

require_command jq
[ -f "$BSC_PSY_GENESIS_DIR/config.json" ] || die "missing BSC genesis config: $BSC_PSY_GENESIS_DIR/config.json"
mkdir -p "$(dirname "$LOCAL_STAGING_RPC_CONFIG")"

jq \
  --arg network "$LOCAL_STAGING_CHAIN_CONFIG_NETWORK" \
  --arg coordinator "http://127.0.0.1:$LOCAL_STAGING_COORDINATOR_EDGE_PORT" \
  --arg realm0 "http://127.0.0.1:$LOCAL_STAGING_REALM_EDGE_BASE_PORT" \
  --arg realm1 "http://127.0.0.1:$((LOCAL_STAGING_REALM_EDGE_BASE_PORT + LOCAL_STAGING_REALM_EDGE_PORT_STRIDE))" \
  --arg prove "http://$LOCAL_STAGING_PROVE_PROXY_ADDR" \
  --arg faucet "http://$LOCAL_STAGING_FAUCET_ADDR" \
  --arg services "http://$LOCAL_STAGING_PSY_SERVICES_ADDR" \
  --arg indexer "http://127.0.0.1:$LOCAL_STAGING_INDEXER_PORT/v1/graphql" \
  --arg l1rpc "$BSC_LOCAL_RPC_URL" \
  --arg nostr "ws://127.0.0.1:$LOCAL_NOSTR_PORT" \
  --argjson l1chain "$BSC_LOCAL_CHAIN_ID" \
  '
    if (.networks[$network] | type) != "object" then
      error("missing network profile: " + $network)
    else . end
    | .defaultNetwork = $network
    | .networks[$network].coordinator_configs = [{id: 0, rpc_url: [$coordinator]}]
    | .networks[$network].realm_configs = [
        {id: 0, rpc_url: [$realm0]},
        {id: 1, rpc_url: [$realm1]}
      ]
    | .networks[$network].prove_proxy_url = [$prove]
    | .networks[$network].faucet_rpc_url = [$faucet]
    | .networks[$network].api_services_url = [$services]
    | .networks[$network].indexer_graphql_url = [$indexer]
    | .networks[$network].l1_rpc_urls = [$l1rpc]
    | .networks[$network].l1_chain_id = $l1chain
    | .networks[$network].nostr_relay_url = $nostr
  ' "$BSC_PSY_GENESIS_DIR/config.json" > "$LOCAL_STAGING_RPC_CONFIG"

jq -e \
  --arg network "$LOCAL_STAGING_CHAIN_CONFIG_NETWORK" \
  --argjson chain "$BSC_LOCAL_CHAIN_ID" \
  '.defaultNetwork == $network and (.networks[$network].l1_chain_id | tonumber) == $chain' \
  "$LOCAL_STAGING_RPC_CONFIG" >/dev/null || die "rendered BSC client config is inconsistent"

echo "[bsc-testnet] rendered local client config: $LOCAL_STAGING_RPC_CONFIG"
