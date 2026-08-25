#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

WORKER_VM_NAME="${WORKER_VM_NAME:-${COORDINATOR_WORKER_VM_NAME:-${REALM_WORKER_1_VM_NAME:-gcp-realm-worker-0}}}"
COORDINATOR_WORKER_LAYOUT="${COORDINATOR_WORKER_LAYOUT:-0 1}"
NODE_NAME="${NODE_VM_NAME:-gcp-cp-ce}"

if [ "${DISABLE_CP_CE_COORDINATOR_WORKERS:-1}" = "1" ] && [ "$WORKER_VM_NAME" != "$NODE_NAME" ]; then
  echo "[coordinator-workers] disabling stale coordinator worker units on ${NODE_NAME}"
  provision_vm "$NODE_NAME"
  run_remote_command "$NODE_NAME" "units=\$(systemctl list-units --all --plain --no-legend 'parth-worker@coordinator-*.service' | awk '{ print \$1 }' || true); if [ -n \"\$units\" ]; then sudo systemctl disable --now \$units || true; sudo systemctl reset-failed \$units >/dev/null 2>&1 || true; fi"
fi

for worker_index in $COORDINATOR_WORKER_LAYOUT; do
  echo "[coordinator-workers] deploying coordinator worker index=${worker_index} on ${WORKER_VM_NAME}"
  WORKER_VM_NAME="$WORKER_VM_NAME" \
  WORKER_ROLE=coordinator \
  WORKER_INDEX="$worker_index" \
  DEPLOY_INSTANCE="coordinator-${worker_index}" \
  BATCH_SIZE="${COORDINATOR_WORKER_BATCH_SIZE:-${BATCH_SIZE:-4}}" \
  "$SCRIPT_DIR/deploy-worker.sh"
done
