#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"
# shellcheck source=lib/psy-services-nostr.sh
source "$(dirname "$0")/lib/psy-services-nostr.sh"
# shellcheck source=lib/multichain.sh
source "$(dirname "$0")/lib/multichain.sh"

if [ -z "${PSY_SERVICES_DATABASE_URL:-}" ]; then
  : "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set in deploy/gcp/config.env or PSY_SERVICES_DATABASE_URL must be provided}"
fi

NAME="${NODE_VM_NAME:-parth-node-1}"
NODE_HOST="$(instance_internal_dns "$NAME")"
POSTGRES_HOST="${POSTGRES_HOST:-$(instance_internal_dns "${POSTGRES_VM_NAME:-parth-postgres-1}")}"
REDIS_HOST="${REDIS_HOST:-$(instance_internal_dns "${REDIS_VM_NAME:-parth-redis-1}")}"
ENVIO_HOST="${ENVIO_HOST:-$(instance_internal_dns "${ENVIO_VM_NAME:-${POSTGRES_VM_NAME:-gcp-postgres}}")}"
ANVIL_VM_NAME="${ANVIL_VM_NAME:-${NODE_VM_NAME:-gcp-cp-ce}}"
ANVIL_HOST="${ANVIL_HOST:-$(instance_internal_dns "$ANVIL_VM_NAME")}"
ANVIL_PORT="${ANVIL_PORT:-8545}"
ETH_RPC_URL="${ETH_RPC_URL:-http://${ANVIL_HOST}:${ANVIL_PORT}}"
PSY_SERVICES_PORT="${PSY_SERVICES_PORT:-3000}"
DATABASE_URL="${PSY_SERVICES_DATABASE_URL:-$(
  postgres_url "$POSTGRES_HOST" 5432 "${PSY_SERVICES_DATABASE_NAME:-psy_services}"
)}"
UNIT="parth-psy-services.service"
INDEXER_GRAPHQL_URL="${INDEXER_GRAPHQL_URL:-http://${ENVIO_HOST}:${HASURA_EXTERNAL_PORT:-18080}/v1/graphql}"
PSY_L1_CHAINS="${PSY_L1_CHAINS:-}"
if multichain_enabled; then
  PSY_L1_CHAINS="$(multichain_services_l1_json)"
fi

resolve_psy_services_nostr_config
ensure_postgres_database "${PSY_SERVICES_DATABASE_NAME:-psy_services}"
ensure_parth_vm "$NAME"

deploy_parth_service "$NAME" "psy-services" "deploy-psy-services" "$UNIT" \
  "DATABASE_URL=$DATABASE_URL" \
  "PSY_SERVICES_REDIS_URL=${PSY_SERVICES_REDIS_URL:-redis://${REDIS_HOST}:6379}" \
  "API_LISTEN=${API_LISTEN:-0.0.0.0:${PSY_SERVICES_PORT}}" \
  "PSY_NETWORK_TYPE=${PSY_NETWORK_TYPE:-${PARTH_NETWORK:-local-devnet}}" \
  "PSY_SERVICES_DISABLE_AUTH=${PSY_SERVICES_DISABLE_AUTH:-1}" \
  "PSY_JWT_SECRET=${PSY_JWT_SECRET:-dev-secret-key}" \
  "PSY_SERVICES_RUN_MIGRATIONS=${PSY_SERVICES_RUN_MIGRATIONS:-true}" \
  "PSY_NOSTR_ENABLED=$PSY_NOSTR_ENABLED" \
  "PSY_NOSTR_RELAY_URL=$PSY_NOSTR_RELAY_URL" \
  "PSY_NOSTR_RELAY_URLS=$PSY_NOSTR_RELAY_URLS" \
  "PSY_NOSTR_LOOKBACK_SECONDS=$PSY_NOSTR_LOOKBACK_SECONDS" \
  "PSY_GENESIS_PATH=${PSY_GENESIS_PATH:-}" \
  "PSY_GENESIS_USERS_PATH=${PSY_GENESIS_USERS_PATH:-}" \
  "INDEXER_GRAPHQL_URL=$INDEXER_GRAPHQL_URL" \
  "HASURA_GRAPHQL_ADMIN_SECRET=${HASURA_GRAPHQL_ADMIN_SECRET:-testing}" \
  "PSY_NODE_URL=${PSY_NODE_URL:-http://${NODE_HOST}:${COORDINATOR_EDGE_PORT:-1337}}" \
  "L1_RPC_URL=${L1_RPC_URL:-$ETH_RPC_URL}" \
  "STATE_MANAGER_ADDRESS=${STATE_MANAGER_ADDRESS:-}" \
  "PSY_L1_CHAINS=$PSY_L1_CHAINS"

run_health_check "$NAME" "ports" \
  "HEALTHCHECK_PORTS=${PSY_SERVICES_HEALTHCHECK_PORTS:-$PSY_SERVICES_PORT}" \
  "HEALTHCHECK_HTTP_URLS=${PSY_SERVICES_HEALTHCHECK_HTTP_URLS:-http://127.0.0.1:${PSY_SERVICES_PORT}/health}" \
  "HEALTHCHECK_HTTP_REQUIRE_SUCCESS=${PSY_SERVICES_HEALTHCHECK_HTTP_REQUIRE_SUCCESS:-1}" \
  "SYSTEMD_UNIT=$UNIT" \
  "HEALTHCHECK_START_DELAY=${PSY_SERVICES_HEALTHCHECK_START_DELAY:-10}"
