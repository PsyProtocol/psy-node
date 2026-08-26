#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARTH_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$PARTH_ROOT/deploy/local-testnet/stack/docker-compose.yml"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

for command in bash docker grep jq; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "[bsc-testnet] missing command: $command" >&2
    exit 1
  }
done

env -i PATH="$PATH" HOME="$HOME" \
  docker compose -p parth-local-staging -f "$COMPOSE_FILE" config --format json \
  > "$TMP_DIR/localhost-compose.json"

jq -e '
  .services.valkey.container_name == "parth-local-valkey"
  and .services.nats.container_name == "parth-local-nats"
  and any(.services.valkey.ports[]; .published == "6379")
  and any(.services.nats.ports[]; .published == "4222")
  and any(.services.scylla.ports[]; .published == "9042")
' "$TMP_DIR/localhost-compose.json" >/dev/null

# shellcheck source=deploy/bsc-testnet/full-stack-lib.sh
source "$SCRIPT_DIR/full-stack-lib.sh"
bsc_full_stack_export

BSC_LOCAL_REQUIRE_FREE_PORTS=0 \
BSC_LOCAL_REQUIRE_SCYLLA_AIO=0 \
BSC_LOCAL_PHASE=preflight \
  bash "$SCRIPT_DIR/preflight-local-stack.sh"

docker compose -p "$LOCAL_STAGING_COMPOSE_PROJECT" -f "$COMPOSE_FILE" config --format json \
  > "$TMP_DIR/bsc-compose.json"

jq -e \
  --arg scylla_image "scylladb/scylla:$BSC_LOCAL_SCYLLA_IMAGE_TAG" \
  '
    .name == "parth-bsc-testnet"
    and .services.valkey.container_name == "parth-bsc-local-valkey"
    and .services.nats.container_name == "parth-bsc-local-nats"
    and .services.scylla.image == $scylla_image
    and any(.services.valkey.ports[]; .published == "16379")
    and any(.services.nats.ports[]; .published == "14222")
    and any(.services.scylla.ports[]; .published == "19042")
    and any(.services.postgres.ports[]; .published == "25432")
    and any(.services.nostr.ports[]; .published == "18081")
  ' "$TMP_DIR/bsc-compose.json" >/dev/null

jq -e \
  --arg network "$LOCAL_STAGING_CHAIN_CONFIG_NETWORK" \
  --arg coordinator "http://127.0.0.1:$LOCAL_STAGING_COORDINATOR_EDGE_PORT" \
  --arg l1 "$BSC_LOCAL_RPC_URL" \
  --argjson chain "$BSC_LOCAL_CHAIN_ID" \
  '
    .defaultNetwork == $network
    and .networks[$network].l1_chain_id == $chain
    and .networks[$network].l1_rpc_urls == [$l1]
    and .networks[$network].coordinator_configs[0].rpc_url == [$coordinator]
  ' "$LOCAL_STAGING_RPC_CONFIG" >/dev/null

test -x "$LOCAL_STAGING_TARGET_DIR/release/psy_node_cli"
test -x "$LOCAL_STAGING_TARGET_DIR/release/psy_worker_cli"
test -x "$LOCAL_STAGING_TARGET_DIR/release/psy_user_cli"
test -x "$LOCAL_STAGING_TARGET_DIR/release/psy_relayer_cli"
test -x "$LOCAL_STAGING_PSY_SERVICES_TARGET_DIR/release/psy-services"
test -x "$LOCAL_STAGING_PSY_SERVICES_TARGET_DIR/release/psy-indexer"
test -f "$PARTH_ROOT/deploy/bin/run-parth-service"
test "$LOCAL_CF_BACKEND_ABI_SNAPSHOT_ROOT" = "$BSC_LOCAL_STATE_ROOT/backend-abi"
test "$LOCAL_CF_ORIGINAL_CHAIN_CONFIG" = "$BSC_PSY_GENESIS_DIR/config.json"
test "$LOCAL_STAGING_PSY_FAUCET_TEMPLATE_JSON_PATH" = "$BSC_LOCAL_STATE_ROOT/faucetOperators.template.json"
test "$LOCAL_STAGING_GENESIS_PATH" = "$BSC_LOCAL_STATE_ROOT/genesis.json"
test "$LOCAL_STAGING_PRIVATE_KEYS_PATH" = "$BSC_LOCAL_STATE_ROOT/private_keys.json"
test "$LOCAL_STAGING_PSY_SERVICES_GENESIS_PATH" = "$BSC_PSY_GENESIS_DIR/genesis_contracts.json"
test "$BSC_LOCAL_HOME" = "$BSC_LOCAL_STATE_ROOT/home"
test "$LOCAL_STAGING_PROVE_PROXY_HOME" = "$BSC_LOCAL_HOME"
test "$LOCAL_GROTH16_KEYSTORE_ROOT" = "$BSC_LOCAL_HOME/.psy/keystore"
test "$LOCAL_STAGING_REALM_INDEXER_START_CHECKPOINT" = "0"
test "$LOCAL_CF_ENVIO_NETWORK_NAME" = "parth-bsc-envio-network"
grep -q 'configure_envio_compose_network' \
  "$PARTH_ROOT/deploy/local-testnet/cloudflare-tunnel/up.sh"
expected_withdraw_method_id="$(
  jq -er '.contract.methods[] | select(.name == "withdraw") | .method_id' \
    "$BSC_LOCAL_TOKEN_CONTRACT_ABI"
)"
test "$BSC_LOCAL_RELAYER_WITHDRAW_METHOD_ID" = "$expected_withdraw_method_id"
test "$LOCAL_STAGING_RELAYER_WITHDRAW_METHOD_ID" = "$expected_withdraw_method_id"

runtime_runner_pattern='\$PARTH_DIR/deploy/bin/run-parth-service'
if grep -q "$runtime_runner_pattern" \
  "$PARTH_ROOT/deploy/local-testnet/cloudflare-tunnel/up.sh"; then
  echo "[bsc-testnet] cloudflare runner still depends on the runtime checkout's deploy directory" >&2
  exit 1
fi

echo "[bsc-testnet] static checks passed; no services were started"
