#!/usr/bin/env bash
set -euo pipefail

export WORKER_ROLE="${WORKER_ROLE:-realm}"
export WORKER_VM_NAME="${WORKER_VM_NAME:-${NODE_VM_NAME:-gcp-cp-ce}}"
export WORKER_INDEX="${WORKER_INDEX:-0}"
export DEPLOY_INSTANCE="${DEPLOY_INSTANCE:-realm-${WORKER_INDEX}}"

exec "$(dirname "$0")/deploy-worker.sh"
