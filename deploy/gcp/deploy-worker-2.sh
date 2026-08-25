#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKER_VM_NAME="${WORKER_VM_NAME:-${REALM_WORKER_2_VM_NAME:-realm-worker-1}}"
REALM_WORKER_LAYOUT="${REALM_WORKER_2_LAYOUT:-${REALM_WORKER_LAYOUT:-0:0 0:1 1:0 1:1}}"

for item in $REALM_WORKER_LAYOUT; do
  realm_id="${item%%:*}"
  worker_index="${item#*:}"
  echo "[realm-worker-2] deploying worker realm=${realm_id} index=${worker_index}"
  WORKER_VM_NAME="$WORKER_VM_NAME" \
  WORKER_ROLE=realm \
  REALM_ID="$realm_id" \
  WORKER_INDEX="$worker_index" \
  DEPLOY_INSTANCE="realm-${realm_id}-${worker_index}" \
  "$SCRIPT_DIR/deploy-worker.sh"
done
