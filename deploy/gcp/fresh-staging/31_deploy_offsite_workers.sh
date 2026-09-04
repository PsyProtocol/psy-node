#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

if [ "${DEPLOY_OFFSITE_WORKERS:-0}" != "1" ]; then
  log_step "skipping offsite workers; set DEPLOY_OFFSITE_WORKERS=1 to add offsite capacity"
  exit 0
fi

log_step "verifying the cloud worker baseline before adding offsite capacity"
run_gcp_script verify-cloud-workers.sh

log_step "deploying optional offsite workers after the cloud deployment passed smoke tests"
if ! OFFSITE_WORKER_HOST="${OFFSITE_WORKER_HOST:-arc99x4}" \
  RESET_OFFSITE_WORKER_STATE="${RESET_OFFSITE_WORKER_STATE:-1}" \
  bash "$REPO_ROOT/deploy/offsite-worker/deploy-arc99x4-release.sh"; then
  if [ "${OFFSITE_WORKER_REQUIRED:-0}" = "1" ]; then
    echo "offsite worker deployment failed and OFFSITE_WORKER_REQUIRED=1" >&2
    exit 1
  fi
  echo "warning: offsite worker deployment failed; cloud baseline remains active" >&2
  exit 0
fi

log_step "offsite workers added as incremental capacity; cloud workers remain active"
