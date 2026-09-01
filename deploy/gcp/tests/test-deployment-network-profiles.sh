#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORKSPACE_HOME="$(cd "$ROOT/.." && pwd)"

read_profile() {
  local profile="$1"

  env WORKSPACE_HOME="$WORKSPACE_HOME" PROFILE="$profile" ROOT="$ROOT" bash -c '
    set -euo pipefail
    source "$ROOT/deploy/$PROFILE/gcp/config.example.env"
    printf "%s|%s|%s\n" \
      "$L1_DEPLOYMENTS_NETWORK" \
      "$RELAYER_DEPLOYMENTS_NETWORK" \
      "$CHAIN_ID"
  '
}

[ "$(read_profile ethereum-sepolia)" = "sepolia|sepolia|11155111" ] || {
  echo "Ethereum Sepolia profile has inconsistent network identity" >&2
  exit 1
}

[ "$(read_profile bsc-testnet)" = "bsc-testnet|bsc-testnet|97" ] || {
  echo "BSC Testnet profile has inconsistent network identity" >&2
  exit 1
}

WORKSPACE_HOME="$WORKSPACE_HOME" \
GCP_DEPLOY_CONFIG="$ROOT/deploy/ethereum-sepolia/gcp/config.example.env" \
DEPLOY_SOURCE_VERSIONS_FILE="$ROOT/deploy/ethereum-sepolia/gcp/source-versions.env" \
DEPLOY_ALL_SELECTED_STEPS="99" \
  bash "$ROOT/deploy/ethereum-sepolia/gcp/preflight.sh" >/dev/null

for profile in ethereum-sepolia bsc-testnet; do
  profile_dir="$ROOT/deploy/$profile/gcp"
  for file in config.example.env source-versions.env prepare-sources.sh preflight.sh deploy_all.sh; do
    [ -f "$profile_dir/$file" ] || {
      echo "$profile is missing $file" >&2
      exit 1
    }
  done

  grep -Fq 'DEPLOY_SOURCE_VERSIONS_FILE=' "$profile_dir/deploy_all.sh" || {
    echo "$profile deploy entrypoint does not select its source manifest" >&2
    exit 1
  }
  grep -Fq 'prepare-sources.sh' "$profile_dir/deploy_all.sh" || {
    echo "$profile deploy entrypoint does not prepare pinned sources" >&2
    exit 1
  }
done

if grep -Eq '^[[:space:]]*source .*ethereum-sepolia' \
  "$ROOT/deploy/bsc-testnet/gcp/config.example.env"; then
  echo "BSC config must not inherit the Sepolia profile" >&2
  exit 1
fi
if grep -Eq '^[[:space:]]*source .*bsc-testnet' \
  "$ROOT/deploy/ethereum-sepolia/gcp/config.example.env"; then
  echo "Sepolia config must not inherit the BSC profile" >&2
  exit 1
fi

echo "[ok] Sepolia and BSC deployment profiles are independent"
