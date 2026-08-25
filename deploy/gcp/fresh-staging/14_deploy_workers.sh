#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

read -r -a coordinator_workers <<< "${COORDINATOR_WORKER_LAYOUT:-0 1}"
coordinator_worker_count="${#coordinator_workers[@]}"
if [ "${REQUIRE_MIN_COORDINATOR_WORKERS:-2}" -gt 0 ] && [ "$coordinator_worker_count" -lt "${REQUIRE_MIN_COORDINATOR_WORKERS:-2}" ]; then
  echo "COORDINATOR_WORKER_LAYOUT must contain at least ${REQUIRE_MIN_COORDINATOR_WORKERS:-2} worker indexes; current: ${COORDINATOR_WORKER_LAYOUT:-0 1}" >&2
  exit 1
fi

run_gcp_script deploy-cloud-workers.sh

if [ "${DEPLOY_REALM_WORKERS:-0}" = "1" ]; then
  log_step "deploying additional realm workers on legacy dedicated GCP realm-worker VMs"
  run_gcp_script deploy-worker-1.sh
  run_gcp_script deploy-worker-2.sh
else
  log_step "skipping legacy dedicated realm-worker VMs; cloud baseline realm workers are already active on ${COORDINATOR_WORKER_VM_NAME:-gcp-coordinator-worker}"
fi
