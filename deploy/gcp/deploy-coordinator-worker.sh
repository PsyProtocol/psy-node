#!/usr/bin/env bash
set -euo pipefail

export WORKER_ROLE="${WORKER_ROLE:-coordinator}"
export WORKER_VM_NAME="${WORKER_VM_NAME:-${COORDINATOR_WORKER_VM_NAME:-${REALM_WORKER_1_VM_NAME:-gcp-realm-worker-0}}}"
export WORKER_INDEX="${WORKER_INDEX:-0}"
export DEPLOY_INSTANCE="${DEPLOY_INSTANCE:-coordinator-${WORKER_INDEX}}"

exec "$(dirname "$0")/deploy-worker.sh"
