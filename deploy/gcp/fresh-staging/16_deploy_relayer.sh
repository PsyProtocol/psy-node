#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"
if [ -n "${DEPLOY_TOPOLOGY_FILE:-}" ]; then
  python3 "$REPO_ROOT/deploy/multi-chain/gcp/fresh-topology/steps.py" 16-relayer \
    --topology "$DEPLOY_TOPOLOGY_FILE" --config "$CONFIG_FILE" \
    --versions "$SOURCE_VERSIONS_FILE" --apply
  exit 0
fi

if [ "${DEPLOY_RELAYER:-0}" != "1" ]; then
  log_step "skipping cloud relayer; set DEPLOY_RELAYER=1 to deploy deploy-relayer.sh"
  exit 0
fi

run_gcp_script deploy-relayer.sh
