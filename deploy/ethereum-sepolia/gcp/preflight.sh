#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
: "${WORKSPACE_HOME:=$(cd "$REPO_ROOT/.." && pwd)}"

export WORKSPACE_HOME
export GCP_DEPLOY_CONFIG="${GCP_DEPLOY_CONFIG:-$SCRIPT_DIR/config.env}"
export DEPLOY_SOURCE_VERSIONS_FILE="${DEPLOY_SOURCE_VERSIONS_FILE:-$SCRIPT_DIR/source-versions.env}"

[ -f "$GCP_DEPLOY_CONFIG" ] || {
  echo "missing Sepolia deploy config: $GCP_DEPLOY_CONFIG" >&2
  echo "copy $SCRIPT_DIR/config.example.env to $SCRIPT_DIR/config.env" >&2
  exit 1
}

set -a
# shellcheck disable=SC1090
source "$GCP_DEPLOY_CONFIG"
# shellcheck disable=SC1090
source "$DEPLOY_SOURCE_VERSIONS_FILE"
set +a

[ "${L1_DEPLOYMENTS_NETWORK:-}" = "sepolia" ] || {
  echo "Sepolia profile requires L1_DEPLOYMENTS_NETWORK=sepolia" >&2
  exit 1
}
[ "${CHAIN_ID:-}" = "11155111" ] || {
  echo "Sepolia profile requires CHAIN_ID=11155111" >&2
  exit 1
}
[ "${RELAYER_DEPLOYMENTS_NETWORK:-sepolia}" = "sepolia" ] || {
  echo "Sepolia profile requires RELAYER_DEPLOYMENTS_NETWORK=sepolia" >&2
  exit 1
}

jq -e '
  .networks.sepolia
  | .coordinator_configs[0].rpc_url[0] == "https://coordinator-stg.psy-protocol.xyz"
    and .realm_configs[0].rpc_url[0] == "https://realm0-stg.psy-protocol.xyz"
    and .realm_configs[1].rpc_url[0] == "https://realm1-stg.psy-protocol.xyz"
' \
  "$REPO_ROOT/psy-genesis/config.json" >/dev/null || {
  echo "psy-genesis Sepolia profile is missing or inconsistent" >&2
  exit 1
}

grep -A8 'sepolia: {' "$REPO_ROOT/psy-contracts/protocol-config/index.ts" \
  | grep -q 'l1ChainId: 11155111' || {
  echo "psy-contracts Sepolia chain ID is missing or inconsistent" >&2
  exit 1
}
grep -A8 'sepolia: {' "$REPO_ROOT/psy-contracts/protocol-config/index.ts" \
  | grep -q 'l1ChainIndex: 0' || {
  echo "psy-contracts Sepolia chain index is missing or inconsistent" >&2
  exit 1
}

exec bash "$REPO_ROOT/deploy/gcp/fresh-staging/preflight.sh"
