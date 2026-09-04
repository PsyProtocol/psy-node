#!/usr/bin/env bash
set -euo pipefail

input_WORKER_VM_NAME_set="${WORKER_VM_NAME+x}"
input_WORKER_VM_NAME="${WORKER_VM_NAME:-}"
input_WORKER_ROLE_set="${WORKER_ROLE+x}"
input_WORKER_ROLE="${WORKER_ROLE:-}"
input_WORKER_INDEX_set="${WORKER_INDEX+x}"
input_WORKER_INDEX="${WORKER_INDEX:-}"
input_REALM_ID_set="${REALM_ID+x}"
input_REALM_ID="${REALM_ID:-}"
input_DEPLOY_INSTANCE_set="${DEPLOY_INSTANCE+x}"
input_DEPLOY_INSTANCE="${DEPLOY_INSTANCE:-}"
input_WORKER_USER_ID_set="${WORKER_USER_ID+x}"
input_WORKER_USER_ID="${WORKER_USER_ID:-}"
input_WORKER_KEY_INDEX_set="${WORKER_KEY_INDEX+x}"
input_WORKER_KEY_INDEX="${WORKER_KEY_INDEX:-}"
input_PRIVATE_KEY_set="${PRIVATE_KEY+x}"
input_PRIVATE_KEY="${PRIVATE_KEY:-}"
input_BATCH_SIZE_set="${BATCH_SIZE+x}"
input_BATCH_SIZE="${BATCH_SIZE:-}"

source "$(dirname "$0")/lib/common.sh"

[ -n "$input_WORKER_VM_NAME_set" ] && WORKER_VM_NAME="$input_WORKER_VM_NAME"
[ -n "$input_WORKER_ROLE_set" ] && WORKER_ROLE="$input_WORKER_ROLE"
[ -n "$input_WORKER_INDEX_set" ] && WORKER_INDEX="$input_WORKER_INDEX"
[ -n "$input_REALM_ID_set" ] && REALM_ID="$input_REALM_ID"
[ -n "$input_DEPLOY_INSTANCE_set" ] && DEPLOY_INSTANCE="$input_DEPLOY_INSTANCE"
if [ -n "$input_WORKER_USER_ID_set" ]; then
  WORKER_USER_ID="$input_WORKER_USER_ID"
else
  unset WORKER_USER_ID
fi
if [ -n "$input_WORKER_KEY_INDEX_set" ]; then
  WORKER_KEY_INDEX="$input_WORKER_KEY_INDEX"
else
  unset WORKER_KEY_INDEX
fi
if [ -n "$input_PRIVATE_KEY_set" ]; then
  PRIVATE_KEY="$input_PRIVATE_KEY"
else
  unset PRIVATE_KEY
fi
[ -n "$input_BATCH_SIZE_set" ] && BATCH_SIZE="$input_BATCH_SIZE"

NAME="${WORKER_VM_NAME:-gcp-realm-worker-0}"
WORKER_ROLE="${WORKER_ROLE:-realm}"
WORKER_INDEX="${WORKER_INDEX:-0}"
NODE_NAME="${NODE_VM_NAME:-parth-node-1}"
NODE_HOST="$(instance_internal_dns "$NODE_NAME")"
COORDINATOR_EDGE_URL="http://${NODE_HOST}:${COORDINATOR_EDGE_PORT:-1337}"
REALM_ID="${REALM_ID:-0}"
REALM_EDGE_BASE_PORT="${REALM_EDGE_BASE_PORT:-1338}"
REALM_EDGE_PORT_STRIDE="${REALM_EDGE_PORT_STRIDE:-1}"
realm_port_var="REALM${REALM_ID}_EDGE_PORT"
if [ -n "${!realm_port_var:-}" ]; then
  REALM_EDGE_PORT="${!realm_port_var}"
elif [ "$REALM_ID" = "0" ] && [ -n "${REALM_EDGE_PORT:-}" ]; then
  REALM_EDGE_PORT="$REALM_EDGE_PORT"
else
  REALM_EDGE_PORT="$(( REALM_EDGE_BASE_PORT + REALM_ID * REALM_EDGE_PORT_STRIDE ))"
fi
REALM_EDGE_URL="http://${NODE_HOST}:${REALM_EDGE_PORT}"

case "$WORKER_ROLE" in
  coordinator)
    DEPLOY_INSTANCE="${DEPLOY_INSTANCE:-coordinator-${WORKER_INDEX}}"
    DEFAULT_COMPLETED_JOBS_LOG_FILE="/var/lib/parth/checkpoints/coordinator_worker_${WORKER_INDEX}.backup"
    DEFAULT_COORDINATOR_API_URLS="$COORDINATOR_EDGE_URL"
    DEFAULT_REALM_API_URLS=""
    DEFAULT_WORKER_KEY_INDEX="${WORKER_KEY_INDEX:-$(select_cyclic_space_list_item "${COORDINATOR_WORKER_KEY_INDEXES:-0 1}" "$WORKER_INDEX")}"
    DEFAULT_WORKER_USER_ID="${COORDINATOR_WORKER_USER_ID:-$(genesis_user_id_for_key_index "$DEFAULT_WORKER_KEY_INDEX")}"
    DEFAULT_PRIVATE_KEY="${COORDINATOR_WORKER_PRIVATE_KEY:-$(genesis_private_key_or_empty "$DEFAULT_WORKER_KEY_INDEX")}"
    ;;
  realm)
    DEPLOY_INSTANCE="${DEPLOY_INSTANCE:-realm-${REALM_ID}-${WORKER_INDEX}}"
    DEFAULT_COMPLETED_JOBS_LOG_FILE="/var/lib/parth/checkpoints/realm_${REALM_ID}_worker_${WORKER_INDEX}.backup"
    DEFAULT_COORDINATOR_API_URLS=""
    DEFAULT_REALM_API_URLS="$REALM_EDGE_URL"
    realm_user_var="REALM${REALM_ID}_WORKER_USER_ID"
    realm_key_var="REALM${REALM_ID}_WORKER_PRIVATE_KEY"
    realm_key_indexes_var="REALM${REALM_ID}_WORKER_KEY_INDEXES"
    DEFAULT_WORKER_KEY_INDEX="${WORKER_KEY_INDEX:-$(select_cyclic_space_list_item "${!realm_key_indexes_var:-${REALM_WORKER_KEY_INDEXES:-3}}" "$WORKER_INDEX")}"
    DEFAULT_WORKER_USER_ID="${!realm_user_var:-${REALM_WORKER_USER_ID:-$(genesis_user_id_for_key_index "$DEFAULT_WORKER_KEY_INDEX")}}"
    DEFAULT_PRIVATE_KEY="${!realm_key_var:-${REALM_WORKER_PRIVATE_KEY:-$(genesis_private_key_or_empty "$DEFAULT_WORKER_KEY_INDEX")}}"
    ;;
  *)
    echo "WORKER_ROLE must be coordinator or realm" >&2
    exit 1
    ;;
esac

UNIT="parth-worker@${DEPLOY_INSTANCE}.service"

ensure_parth_vm "$NAME"

echo "[deploy-worker] role=${WORKER_ROLE} instance=${DEPLOY_INSTANCE} reward_key_index=${WORKER_KEY_INDEX:-$DEFAULT_WORKER_KEY_INDEX} reward_user_id=${WORKER_USER_ID:-$DEFAULT_WORKER_USER_ID}"

deploy_parth_service "$NAME" "worker" "deploy-worker" "$UNIT" \
  "DEPLOY_INSTANCE=$DEPLOY_INSTANCE" \
  "WORKER_USER_ID=${WORKER_USER_ID:-$DEFAULT_WORKER_USER_ID}" \
  "PRIVATE_KEY=${PRIVATE_KEY:-${DEFAULT_PRIVATE_KEY:-}}" \
  "KEYSTORE_PATH=${KEYSTORE_PATH:-}" \
  "WALLET_PASSWORD=${WALLET_PASSWORD:-}" \
  "COMPLETED_JOBS_LOG_FILE=${COMPLETED_JOBS_LOG_FILE:-$DEFAULT_COMPLETED_JOBS_LOG_FILE}" \
  "COORDINATOR_API_URLS=${COORDINATOR_API_URLS:-$DEFAULT_COORDINATOR_API_URLS}" \
  "REALM_API_URLS=${REALM_API_URLS:-$DEFAULT_REALM_API_URLS}" \
  "URL_ROTATION_STRATEGY=${URL_ROTATION_STRATEGY:-random}" \
  "BATCH_SIZE=${BATCH_SIZE:-4}"
