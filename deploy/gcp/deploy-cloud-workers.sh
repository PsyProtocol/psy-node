#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

WORKER_VM_NAME="${WORKER_VM_NAME:-${COORDINATOR_WORKER_VM_NAME:-gcp-coordinator-worker}}"
CLOUD_REALM_WORKER_LAYOUT="${CLOUD_REALM_WORKER_LAYOUT:-0:0 1:0}"

echo "[cloud-workers] deploying coordinator baseline on ${WORKER_VM_NAME}"
WORKER_VM_NAME="$WORKER_VM_NAME" "$SCRIPT_DIR/deploy-coordinator-workers.sh"

if [ "${DEPLOY_CLOUD_REALM_WORKERS:-1}" = "1" ]; then
  echo "[cloud-workers] disabling stale realm worker units on ${WORKER_VM_NAME}"
  ensure_parth_vm "$WORKER_VM_NAME"
  run_remote_command "$WORKER_VM_NAME" \
    "units=\$(systemctl list-unit-files --type=service --no-legend 'parth-worker@realm-*.service' | awk '{ print \$1 }' || true); if [ -n \"\$units\" ]; then sudo systemctl disable --now \$units || true; sudo systemctl reset-failed \$units >/dev/null 2>&1 || true; fi"

  for item in $CLOUD_REALM_WORKER_LAYOUT; do
    realm_id="${item%%:*}"
    worker_index="${item#*:}"
    [[ "$realm_id" =~ ^[0-9]+$ && "$worker_index" =~ ^[0-9]+$ ]] || {
      echo "invalid CLOUD_REALM_WORKER_LAYOUT item: $item; expected REALM_ID:WORKER_INDEX" >&2
      exit 1
    }

    echo "[cloud-workers] deploying realm=${realm_id} worker=${worker_index} on ${WORKER_VM_NAME}"
    WORKER_VM_NAME="$WORKER_VM_NAME" \
    WORKER_ROLE=realm \
    REALM_ID="$realm_id" \
    WORKER_INDEX="$worker_index" \
    DEPLOY_INSTANCE="realm-${realm_id}-${worker_index}" \
    BATCH_SIZE="${CLOUD_REALM_WORKER_BATCH_SIZE:-${BATCH_SIZE:-4}}" \
    "$SCRIPT_DIR/deploy-worker.sh"
  done
fi

"$SCRIPT_DIR/verify-cloud-workers.sh"
