#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

NAME="${NODE_VM_NAME:-parth-node-1}"
DEPLOY_INSTANCE="${DEPLOY_INSTANCE:-0}"
REALM_ID="${REALM_ID:-0}"
REALM_SUB_ID="${REALM_SUB_ID:-1}"
NODE_HOST="$(instance_internal_dns "$NAME")"
UNIT="parth-realm-processor@${DEPLOY_INSTANCE}.service"

ensure_parth_vm "$NAME"

deploy_parth_service "$NAME" "realm-processor" "deploy-realm-processor" "$UNIT" \
  "DEPLOY_INSTANCE=$DEPLOY_INSTANCE" \
  "REALM_ID=$REALM_ID" \
  "REALM_SUB_ID=$REALM_SUB_ID" \
  "DB_NAMESPACE=${REALM_DB_NAMESPACE:-realm_${REALM_ID}}" \
  "COORDINATOR_API_URLS=${COORDINATOR_API_URLS:-http://${NODE_HOST}:${COORDINATOR_EDGE_PORT:-1337}}"
