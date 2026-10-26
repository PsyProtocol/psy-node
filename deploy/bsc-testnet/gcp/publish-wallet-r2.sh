#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
: "${WORKSPACE_HOME:=$(cd "$REPO_ROOT/.." && pwd)}"
CONFIG_FILE="${GCP_DEPLOY_CONFIG:-$SCRIPT_DIR/config.env}"
SOURCE_VERSIONS_FILE="${DEPLOY_SOURCE_VERSIONS_FILE:-$SCRIPT_DIR/source-versions.env}"

for file in "$CONFIG_FILE" "$SOURCE_VERSIONS_FILE"; do
  [ -f "$file" ] || {
    echo "missing required configuration: $file" >&2
    exit 1
  }
  bash -n "$file"
done

set -a
# shellcheck disable=SC1090
source "$CONFIG_FILE"
# shellcheck disable=SC1090
source "$SOURCE_VERSIONS_FILE"
set +a

wallet_dir="${PSY_WALLET_DIR:-$WORKSPACE_HOME/psy-wallet-bsc-testnet}"
publisher="${WALLET_PUBLISH_SCRIPT:-$wallet_dir/scripts/publish-wallet-r2-stg.sh}"

command -v git >/dev/null 2>&1 || { echo "git is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }
git -C "$wallet_dir" rev-parse --git-dir >/dev/null 2>&1 \
  || { echo "missing wallet checkout: $wallet_dir" >&2; exit 1; }
[ -x "$publisher" ] || { echo "missing wallet publisher: $publisher" >&2; exit 1; }

wallet_commit="$(git -C "$wallet_dir" rev-parse HEAD)"
[ "$wallet_commit" = "$EXPECTED_PSY_WALLET_COMMIT" ] || {
  echo "wallet commit mismatch: expected $EXPECTED_PSY_WALLET_COMMIT got $wallet_commit" >&2
  exit 1
}
[ -z "$(git -C "$wallet_dir" status --porcelain)" ] || {
  echo "wallet checkout must be clean before publication: $wallet_dir" >&2
  exit 1
}

jq -e '
  .networks["bsc-testnet"]
  | .l1_chain_id == 97
    and .magic == "0x1337CF514544C269"
    and .coordinator_configs[0].rpc_url[0] == "https://coordinator-stg.psy-protocol.xyz"
    and .prove_proxy_url[0] == "https://prove-stg.psy-protocol.xyz"
' "$wallet_dir/config.json" >/dev/null || {
  echo "wallet BSC Testnet profile is missing or inconsistent" >&2
  exit 1
}

wallet_sdk_version="$(jq -r '.dependencies["@psy-protocol/psy-sdk"] // empty' "$wallet_dir/package.json")"
[ "$wallet_sdk_version" = "$EXPECTED_PSY_SDK_NPM_VERSION" ] || {
  echo "wallet psy-sdk mismatch: expected npm $EXPECTED_PSY_SDK_NPM_VERSION got ${wallet_sdk_version:-<empty>}" >&2
  exit 1
}

export WALLET_PACKAGE_MODE="bsc-testnet"
export WALLET_BUILD_COMMAND="pnpm build:bsc-testnet"
export R2_BUCKET="${BSC_WALLET_R2_BUCKET:-psy-wallet-assets-stg}"
export R2_PUBLIC_BASE_URL="${BSC_WALLET_R2_PUBLIC_BASE_URL:-https://wallet-assets-stg.psy-protocol.xyz}"
export R2_METADATA_KEY="${BSC_WALLET_R2_METADATA_KEY:-bsc-testnet/wallet-release.json}"
export WALLET_COMMIT="$wallet_commit"
export WALLET_REF="feat/bsc-testnet-network-support"
export VITE_PSY_COORDINATOR_URL="https://${PUBLIC_COORDINATOR_DOMAIN}"
export VITE_PSY_PROVE_PROXY_URL="https://${PUBLIC_PROVE_PROXY_DOMAIN}"
export VITE_PSY_FAUCET_RPC_URL="https://${PUBLIC_FAUCET_DOMAIN}"
export VITE_NOSTR_RELAY_URL="$NOSTR_RELAY_URL"

echo "[bsc-wallet] source: $wallet_dir@$wallet_commit"
echo "[bsc-wallet] SDK: @psy-protocol/psy-sdk@$wallet_sdk_version"
echo "[bsc-wallet] metadata: ${R2_PUBLIC_BASE_URL%/}/$R2_METADATA_KEY"

exec bash "$publisher"
