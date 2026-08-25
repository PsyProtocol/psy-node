#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/psy-services-nostr.sh
source "$SCRIPT_DIR/lib/psy-services-nostr.sh"

if [ -z "${PARTH_BUNDLE:-}" ]; then
  PARTH_BUNDLE="$(bash "$SCRIPT_DIR/build-parth-bundle.sh")"
  export PARTH_BUNDLE
fi

NAME="${NODE_VM_NAME:-gcp-cp-ce}"
NODE_HOST="$(instance_internal_dns "$NAME")"
COORDINATOR_EDGE_PORT="${COORDINATOR_EDGE_PORT:-1337}"
REALM_IDS="${REALM_IDS:-0 1}"
REALM_SUB_ID="${REALM_SUB_ID:-1}"
REALM_EDGE_BASE_PORT="${REALM_EDGE_BASE_PORT:-1338}"
REALM_EDGE_PORT_STRIDE="${REALM_EDGE_PORT_STRIDE:-1}"
PSY_SERVICES_PORT="${PSY_SERVICES_PORT:-3000}"
POSTGRES_HOST="${POSTGRES_HOST:-$(instance_internal_dns "${POSTGRES_VM_NAME:-gcp-postgres}")}"
REDIS_HOST="${REDIS_HOST:-$(instance_internal_dns "${REDIS_VM_NAME:-gcp-redis}")}"
ENVIO_HOST="${ENVIO_HOST:-$(instance_internal_dns "${ENVIO_VM_NAME:-${POSTGRES_VM_NAME:-gcp-postgres}}")}"
PSY_SERVICES_DATABASE_URL="${PSY_SERVICES_DATABASE_URL:-$(postgres_url "$POSTGRES_HOST" 5432 "${PSY_SERVICES_DATABASE_NAME:-psy_services}")}"
PSY_SERVICES_URL="${PSY_SERVICES_URL:-http://${NODE_HOST}:${PSY_SERVICES_PORT}}"
COORDINATOR_EDGE_URL="${COORDINATOR_API_URLS:-http://${NODE_HOST}:${COORDINATOR_EDGE_PORT}}"

resolve_psy_services_nostr_config

realm_edge_port() {
  local realm_id="$1"
  local port_var="REALM${realm_id}_EDGE_PORT"
  printf '%s\n' "${!port_var:-$(( REALM_EDGE_BASE_PORT + realm_id * REALM_EDGE_PORT_STRIDE ))}"
}

run_jsonrpc_health_check() {
  local label="$1"
  local url="$2"
  local unit="${3:-}"
  local start_delay="${4:-2}"

  echo "[cp-ce] waiting for ${label}: ${url}"
  if [ -n "$unit" ]; then
    run_health_check "$NAME" "jsonrpc" \
      "HEALTHCHECK_JSONRPC_URLS=$url" \
      "HEALTHCHECK_JSONRPC_METHOD=${PARTH_EDGE_HEALTHCHECK_METHOD:-psy_get_latest_checkpoint_id}" \
      "SYSTEMD_UNIT=$unit" \
      "HEALTHCHECK_START_DELAY=$start_delay"
  else
    run_health_check "$NAME" "jsonrpc" \
      "HEALTHCHECK_JSONRPC_URLS=$url" \
      "HEALTHCHECK_JSONRPC_METHOD=${PARTH_EDGE_HEALTHCHECK_METHOD:-psy_get_latest_checkpoint_id}" \
      "HEALTHCHECK_START_DELAY=$start_delay"
  fi
}

stop_cp_ce_dependents_first() {
  [ "${CP_CE_STOP_DEPENDENTS_FIRST:-1}" = "1" ] || return 0

  echo "[cp-ce] stopping ingress and dependent services before ordered restart"
  run_remote_command "$NAME" '
set -e
stop_units() {
  pattern="$1"
  units="$(systemctl list-units --all --plain --no-legend "$pattern" | awk "{ print \$1 }" || true)"
  if [ -n "$units" ]; then
    echo "[cp-ce remote] stopping $pattern: $units"
    sudo systemctl stop $units || true
  fi
}
stop_units "parth-psy-indexer@*.service"
stop_units "parth-realm-edge@*.service"
stop_units "parth-realm-processor@*.service"
stop_units "parth-coordinator-edge@*.service"
stop_units "parth-coordinator-processor.service"
'
}

echo "[cp-ce] target host: ${NAME}"
ensure_parth_vm "$NAME"
stop_cp_ce_dependents_first

echo "[cp-ce] deploying coordinator processor"
deploy_parth_service "$NAME" "coordinator-processor" "deploy-coordinator-processor" "parth-coordinator-processor.service" \
  "COORDINATOR_ID=${COORDINATOR_ID:-0}" \
  "COORDINATOR_SUB_ID=${COORDINATOR_SUB_ID:-0}" \
  "DB_NAMESPACE=${COORDINATOR_DB_NAMESPACE:-coordinator}"

echo "[cp-ce] deploying coordinator edge"
deploy_parth_service "$NAME" "coordinator-edge" "deploy-coordinator-edge" "parth-coordinator-edge@0.service" \
  "DEPLOY_INSTANCE=0" \
  "COORDINATOR_ID=${COORDINATOR_ID:-0}" \
  "COORDINATOR_SUB_ID=${COORDINATOR_SUB_ID:-0}" \
  "DB_NAMESPACE=${COORDINATOR_DB_NAMESPACE:-coordinator}" \
  "COORDINATOR_EDGE_PORT=$COORDINATOR_EDGE_PORT" \
  "LISTEN_ADDR=${LISTEN_ADDR:-0.0.0.0}"
run_jsonrpc_health_check \
  "coordinator edge RPC" \
  "${COORDINATOR_EDGE_HEALTHCHECK_JSONRPC_URL:-http://127.0.0.1:${COORDINATOR_EDGE_PORT}}" \
  "parth-coordinator-edge@0.service" \
  "${COORDINATOR_EDGE_HEALTHCHECK_START_DELAY:-2}"

for realm_id in $REALM_IDS; do
  realm_port="$(realm_edge_port "$realm_id")"

  echo "[cp-ce] deploying realm processor ${realm_id}"
  deploy_parth_service "$NAME" "realm-processor" "deploy-realm-processor" "parth-realm-processor@${realm_id}.service" \
    "DEPLOY_INSTANCE=$realm_id" \
    "REALM_ID=$realm_id" \
    "REALM_SUB_ID=$REALM_SUB_ID" \
    "DB_NAMESPACE=realm_${realm_id}" \
    "COORDINATOR_API_URLS=$COORDINATOR_EDGE_URL"
done

for realm_id in $REALM_IDS; do
  realm_port="$(realm_edge_port "$realm_id")"

  echo "[cp-ce] deploying realm edge ${realm_id}"
  deploy_parth_service "$NAME" "realm-edge" "deploy-realm-edge" "parth-realm-edge@${realm_id}.service" \
    "DEPLOY_INSTANCE=$realm_id" \
    "REALM_ID=$realm_id" \
    "REALM_SUB_ID=$REALM_SUB_ID" \
    "DB_NAMESPACE=realm_${realm_id}" \
    "REALM_EDGE_PORT=$realm_port" \
    "LISTEN_ADDR=${LISTEN_ADDR:-0.0.0.0}"
  run_jsonrpc_health_check \
    "realm ${realm_id} edge RPC" \
    "http://127.0.0.1:${realm_port}" \
    "parth-realm-edge@${realm_id}.service" \
    "${REALM_EDGE_HEALTHCHECK_START_DELAY:-2}"
done

if [ "${DISABLE_CP_CE_COORDINATOR_WORKERS:-1}" = "1" ]; then
  echo "[cp-ce] disabling stale coordinator worker units on ${NAME}"
  run_remote_command "$NAME" "units=\$(systemctl list-units --all --plain --no-legend 'parth-worker@coordinator-*.service' | awk '{ print \$1 }' || true); if [ -n \"\$units\" ]; then sudo systemctl disable --now \$units || true; sudo systemctl reset-failed \$units >/dev/null 2>&1 || true; fi"
fi

echo "[cp-ce] deploying psy-services"
ensure_postgres_database "${PSY_SERVICES_DATABASE_NAME:-psy_services}"
deploy_parth_service "$NAME" "psy-services" "deploy-psy-services" "parth-psy-services.service" \
  "DATABASE_URL=$PSY_SERVICES_DATABASE_URL" \
  "PSY_SERVICES_REDIS_URL=${PSY_SERVICES_REDIS_URL:-redis://${REDIS_HOST}:6379}" \
  "API_LISTEN=${API_LISTEN:-0.0.0.0:${PSY_SERVICES_PORT}}" \
  "PSY_NETWORK_TYPE=${PSY_NETWORK_TYPE:-${PARTH_NETWORK:-local-devnet}}" \
  "PSY_SERVICES_DISABLE_AUTH=${PSY_SERVICES_DISABLE_AUTH:-1}" \
  "PSY_JWT_SECRET=${PSY_JWT_SECRET:-dev-secret-key}" \
  "PSY_SERVICES_RUN_MIGRATIONS=${PSY_SERVICES_RUN_MIGRATIONS:-true}" \
  "PSY_NOSTR_ENABLED=$PSY_NOSTR_ENABLED" \
  "PSY_NOSTR_RELAY_URLS=$PSY_NOSTR_RELAY_URLS" \
  "PSY_NOSTR_LOOKBACK_SECONDS=$PSY_NOSTR_LOOKBACK_SECONDS" \
  "PSY_GENESIS_PATH=${PSY_GENESIS_PATH:-}" \
  "PSY_GENESIS_USERS_PATH=${PSY_GENESIS_USERS_PATH:-}" \
  "INDEXER_GRAPHQL_URL=${INDEXER_GRAPHQL_URL:-http://${ENVIO_HOST}:${HASURA_EXTERNAL_PORT:-18080}/v1/graphql}" \
  "HASURA_GRAPHQL_ADMIN_SECRET=${HASURA_GRAPHQL_ADMIN_SECRET:-testing}" \
  "PSY_NODE_URL=${PSY_NODE_URL:-http://${NODE_HOST}:${COORDINATOR_EDGE_PORT}}" \
  "L1_RPC_URL=${L1_RPC_URL:-${ETH_RPC_URL:-}}" \
  "STATE_MANAGER_ADDRESS=${STATE_MANAGER_ADDRESS:-}"
run_health_check "$NAME" "ports" \
  "HEALTHCHECK_PORTS=${PSY_SERVICES_HEALTHCHECK_PORTS:-$PSY_SERVICES_PORT}" \
  "HEALTHCHECK_HTTP_URLS=${PSY_SERVICES_HEALTHCHECK_HTTP_URLS:-http://127.0.0.1:${PSY_SERVICES_PORT}/health}" \
  "HEALTHCHECK_HTTP_REQUIRE_SUCCESS=${PSY_SERVICES_HEALTHCHECK_HTTP_REQUIRE_SUCCESS:-1}" \
  "SYSTEMD_UNIT=parth-psy-services.service" \
  "HEALTHCHECK_START_DELAY=${PSY_SERVICES_HEALTHCHECK_START_DELAY:-10}"

echo "[cp-ce] deploying coordinator psy-indexer"
deploy_parth_service "$NAME" "psy-indexer" "deploy-psy-indexer" "parth-psy-indexer@coordinator.service" \
  "DEPLOY_INSTANCE=coordinator" \
  "PSY_INDEXER_MODE=coordinator" \
  "PSY_EDGE_RPC_URL=${COORDINATOR_PSY_EDGE_RPC_URL:-$COORDINATOR_EDGE_URL}" \
  "PSY_SERVICES_URL=$PSY_SERVICES_URL" \
  "PSY_JWT_SECRET=${PSY_JWT_SECRET:-dev-secret-key}" \
  "PSY_BACKUP_DIR=${PSY_BACKUP_DIR:-/var/lib/parth/checkpoints}" \
  "PSY_POLL_INTERVAL_MS=${PSY_POLL_INTERVAL_MS:-5000}" \
  "PSY_LOG_LEVEL=${PSY_LOG_LEVEL:-info}" \
  "PSY_NETWORK_TYPE=${PSY_NETWORK_TYPE:-${PARTH_NETWORK:-local-devnet}}"

for realm_id in $REALM_IDS; do
  realm_port="$(realm_edge_port "$realm_id")"
  realm_url="http://${NODE_HOST}:${realm_port}"
  echo "[cp-ce] deploying realm ${realm_id} psy-indexer"
  deploy_parth_service "$NAME" "psy-indexer" "deploy-psy-indexer" "parth-psy-indexer@realm-${realm_id}.service" \
    "DEPLOY_INSTANCE=realm-${realm_id}" \
    "PSY_INDEXER_MODE=realm" \
    "PSY_EDGE_RPC_URL=$realm_url" \
    "PSY_SERVICES_URL=$PSY_SERVICES_URL" \
    "PSY_JWT_SECRET=${PSY_JWT_SECRET:-dev-secret-key}" \
    "PSY_BACKUP_DIR=${PSY_BACKUP_DIR:-/var/lib/parth/checkpoints}" \
    "PSY_POLL_INTERVAL_MS=${PSY_POLL_INTERVAL_MS:-5000}" \
    "PSY_LOG_LEVEL=${PSY_LOG_LEVEL:-info}" \
    "PSY_NETWORK_TYPE=${PSY_NETWORK_TYPE:-${PARTH_NETWORK:-local-devnet}}" \
    "REALM_ID=$realm_id" \
    "REALM_SUB_ID=$REALM_SUB_ID"
done

echo "[cp-ce] cp-ce stack deployment finished"
