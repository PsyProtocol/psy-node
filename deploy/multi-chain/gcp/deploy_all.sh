#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
: "${WORKSPACE_HOME:=$(cd "$REPO_ROOT/.." && pwd)}"

export WORKSPACE_HOME
export GCP_DEPLOY_CONFIG="${GCP_DEPLOY_CONFIG:-$SCRIPT_DIR/config.env}"
export DEPLOY_SOURCE_VERSIONS_FILE="${DEPLOY_SOURCE_VERSIONS_FILE:-$SCRIPT_DIR/source-versions.env}"

bash "$SCRIPT_DIR/prepare-sources.sh"
bash "$SCRIPT_DIR/preflight.sh"

if [ "${DRY_RUN:-0}" != "1" ] \
  && [ "${CONFIRM_MULTICHAIN_REPLACES_CURRENT_STAGING:-0}" != "1" ]; then
  cat >&2 <<'EOF'
This profile reuses the current staging GCP hosts and persistent state paths.
A fresh deployment erases the current Psy L2/databases and deploys new bridge
contracts on Sepolia, BSC Testnet, and Base Sepolia.

Set both confirmations for the real deployment:
  CONFIRM_MULTICHAIN_REPLACES_CURRENT_STAGING=1
  CONFIRM_FULL_FRESH_DEPLOY=1
EOF
  exit 1
fi

exec bash "$REPO_ROOT/deploy/gcp/fresh-staging/deploy_all.sh"
