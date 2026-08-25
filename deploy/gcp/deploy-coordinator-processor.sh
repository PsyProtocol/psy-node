#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

NAME="${NODE_VM_NAME:-parth-node-1}"
ensure_parth_vm "$NAME"

deploy_parth_service "$NAME" "coordinator-processor" "deploy-coordinator-processor" "parth-coordinator-processor.service" \
  "COORDINATOR_ID=${COORDINATOR_ID:-0}" \
  "COORDINATOR_SUB_ID=${COORDINATOR_SUB_ID:-0}" \
  "DB_NAMESPACE=${COORDINATOR_DB_NAMESPACE:-coordinator}"
