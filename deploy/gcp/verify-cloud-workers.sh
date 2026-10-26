#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

WORKER_VM_NAME="${WORKER_VM_NAME:-${COORDINATOR_WORKER_VM_NAME:-gcp-coordinator-worker}}"
COORDINATOR_WORKER_LAYOUT="${COORDINATOR_WORKER_LAYOUT:-0}"
CLOUD_REALM_WORKER_LAYOUT="${CLOUD_REALM_WORKER_LAYOUT:-0:0 1:0}"
units=()

for worker_index in $COORDINATOR_WORKER_LAYOUT; do
  units+=("parth-worker@coordinator-${worker_index}.service")
done

if [ "${DEPLOY_CLOUD_REALM_WORKERS:-1}" = "1" ]; then
  for item in $CLOUD_REALM_WORKER_LAYOUT; do
    realm_id="${item%%:*}"
    worker_index="${item#*:}"
    units+=("parth-worker@realm-${realm_id}-${worker_index}.service")
  done
fi

[ "${#units[@]}" -gt 0 ] || {
  echo "cloud worker baseline is empty" >&2
  exit 1
}

quoted_units="$(printf ' %q' "${units[@]}")"
echo "[cloud-workers] verifying baseline on ${WORKER_VM_NAME}:${quoted_units}"
run_remote_command "$WORKER_VM_NAME" "
set -e
for unit in${quoted_units}; do
  sudo systemctl is-enabled --quiet \"\$unit\"
  sudo systemctl is-active --quiet \"\$unit\"
done
"
echo "[cloud-workers] baseline ready on ${WORKER_VM_NAME}"
