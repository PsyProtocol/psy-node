#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

if [ "${DEPLOY_RELAYER:-0}" != "1" ]; then
  log_step "skipping cloud relayer; set DEPLOY_RELAYER=1 to deploy deploy-relayer.sh"
  exit 0
fi

run_gcp_script deploy-relayer.sh
