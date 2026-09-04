#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

NAME="${NODE_VM_NAME:-parth-node-1}"
DEPLOY_INSTANCE="${DEPLOY_INSTANCE:-0}"
REALM_ID="${REALM_ID:-0}"
REALM_SUB_ID="${REALM_SUB_ID:-1}"
REALM_EDGE_PORT="${REALM_EDGE_PORT:-1338}"
UNIT="parth-realm-edge@${DEPLOY_INSTANCE}.service"

ensure_parth_vm "$NAME"

deploy_parth_service "$NAME" "realm-edge" "deploy-realm-edge" "$UNIT" \
  "DEPLOY_INSTANCE=$DEPLOY_INSTANCE" \
  "REALM_ID=$REALM_ID" \
  "REALM_SUB_ID=$REALM_SUB_ID" \
  "DB_NAMESPACE=${REALM_DB_NAMESPACE:-realm_${REALM_ID}}" \
  "REALM_EDGE_PORT=$REALM_EDGE_PORT" \
  "LISTEN_ADDR=${LISTEN_ADDR:-0.0.0.0}"

run_health_check "$NAME" "jsonrpc" \
  "HEALTHCHECK_JSONRPC_URLS=${REALM_EDGE_HEALTHCHECK_JSONRPC_URL:-http://127.0.0.1:${REALM_EDGE_PORT}}" \
  "HEALTHCHECK_JSONRPC_METHOD=${PARTH_EDGE_HEALTHCHECK_METHOD:-psy_get_latest_checkpoint_id}" \
  "SYSTEMD_UNIT=$UNIT" \
  "HEALTHCHECK_START_DELAY=${REALM_EDGE_HEALTHCHECK_START_DELAY:-2}"
