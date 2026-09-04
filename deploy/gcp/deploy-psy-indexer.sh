#!/usr/bin/env bash
set -euo pipefail

INPUT_DEPLOY_INSTANCE="${DEPLOY_INSTANCE:-}"
INPUT_PSY_INDEXER_MODE="${PSY_INDEXER_MODE:-}"
INPUT_PSY_EDGE_RPC_URL="${PSY_EDGE_RPC_URL:-}"
INPUT_REALM_ID="${REALM_ID:-}"
INPUT_REALM_SUB_ID="${REALM_SUB_ID:-}"

source "$(dirname "$0")/lib/common.sh"

NAME="${NODE_VM_NAME:-parth-node-1}"
DEPLOY_INSTANCE="${DEPLOY_INSTANCE:-coordinator}"
PSY_INDEXER_MODE="${PSY_INDEXER_MODE:-coordinator}"
PSY_EDGE_RPC_URL="${PSY_EDGE_RPC_URL:-}"
REALM_ID="${REALM_ID:-0}"
REALM_SUB_ID="${REALM_SUB_ID:-1}"

[ -n "$INPUT_DEPLOY_INSTANCE" ] && DEPLOY_INSTANCE="$INPUT_DEPLOY_INSTANCE"
[ -n "$INPUT_PSY_INDEXER_MODE" ] && PSY_INDEXER_MODE="$INPUT_PSY_INDEXER_MODE"
[ -n "$INPUT_PSY_EDGE_RPC_URL" ] && PSY_EDGE_RPC_URL="$INPUT_PSY_EDGE_RPC_URL"
[ -n "$INPUT_REALM_ID" ] && REALM_ID="$INPUT_REALM_ID"
[ -n "$INPUT_REALM_SUB_ID" ] && REALM_SUB_ID="$INPUT_REALM_SUB_ID"

NODE_HOST="$(instance_internal_dns "$NAME")"
UNIT="parth-psy-indexer@${DEPLOY_INSTANCE}.service"

realm_edge_port() {
  local realm_id="$1"
  local port_var="REALM${realm_id}_EDGE_PORT"
  printf '%s\n' "${!port_var:-$(( ${REALM_EDGE_BASE_PORT:-1338} + realm_id * ${REALM_EDGE_PORT_STRIDE:-1} ))}"
}

if [ -z "$PSY_EDGE_RPC_URL" ]; then
  if [ "$PSY_INDEXER_MODE" = "realm" ]; then
    PSY_EDGE_RPC_URL="http://${NODE_HOST}:$(realm_edge_port "$REALM_ID")"
  else
    PSY_EDGE_RPC_URL="http://${NODE_HOST}:${COORDINATOR_EDGE_PORT:-1337}"
  fi
fi

ensure_parth_vm "$NAME"

deploy_parth_service "$NAME" "psy-indexer" "deploy-psy-indexer" "$UNIT" \
  "DEPLOY_INSTANCE=$DEPLOY_INSTANCE" \
  "PSY_INDEXER_MODE=$PSY_INDEXER_MODE" \
  "PSY_EDGE_RPC_URL=$PSY_EDGE_RPC_URL" \
  "PSY_SERVICES_URL=${PSY_SERVICES_URL:-http://${NODE_HOST}:${PSY_SERVICES_PORT:-3000}}" \
  "PSY_JWT_SECRET=${PSY_JWT_SECRET:-dev-secret-key}" \
  "PSY_BACKUP_DIR=${PSY_BACKUP_DIR:-/var/lib/parth/checkpoints}" \
  "PSY_POLL_INTERVAL_MS=${PSY_POLL_INTERVAL_MS:-5000}" \
  "PSY_LOG_LEVEL=${PSY_LOG_LEVEL:-info}" \
  "PSY_NETWORK_TYPE=${PSY_NETWORK_TYPE:-${PARTH_NETWORK:-local-devnet}}" \
  "REALM_ID=$REALM_ID" \
  "REALM_SUB_ID=$REALM_SUB_ID"
