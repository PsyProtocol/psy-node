#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"
if [ -n "${DEPLOY_TOPOLOGY_FILE:-}" ]; then
  python3 "$REPO_ROOT/deploy/multi-chain/gcp/fresh-topology/steps.py" 12-nodes \
    --topology "$DEPLOY_TOPOLOGY_FILE" --config "$CONFIG_FILE" \
    --versions "$SOURCE_VERSIONS_FILE" --apply
  exit 0
fi
run_gcp_script deploy-cp-ce-stack.sh
