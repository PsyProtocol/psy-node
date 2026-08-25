#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/cloudflare-pages/lib-direct-upload.sh
source "$SCRIPT_DIR/lib-direct-upload.sh"

PROJECT_NAME="${CF_PAGES_PROJECT:-psy-privacy-bridge-demo-stg}"
BRANCH="${CF_PAGES_BRANCH:-staging}"
FRONTEND_DIR="${PSY_PRIVACY_BRIDGE_DEMO_DIR:-$ROOT/psy-dapp/apps/bridge}"
CONFIG_FILE="${GCP_DEPLOY_CONFIG:-$ROOT/deploy/gcp/config.env}"
if [ -f "$CONFIG_FILE" ]; then
  set -a
  # shellcheck source=../gcp/config.env
  source "$CONFIG_FILE"
  set +a
fi
set_public_domain_defaults

PSY_SDK_DIR="${PSY_SDK_DIR:-$ROOT/../psy-sdk}"
PSY_SDK_PACKAGE_DIR="${PSY_SDK_PACKAGE_DIR:-$PSY_SDK_DIR/psy-ts-sdk/packages/psy-sdk}"
PSY_WALLET_DIR="${PSY_WALLET_DIR:-$ROOT/../psy-wallet}"
WALLET_PACKAGE_MODE="${WALLET_PACKAGE_MODE:-staging}"
PSY_FAUCET_SERVER_MODE="${PSY_FAUCET_SERVER_MODE:-1}"
GENERATE_PRIVACY_FAUCET_OPERATORS="${GENERATE_PRIVACY_FAUCET_OPERATORS:-0}"

is_truthy() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

# Staging keeps Psy faucet operator private keys on prove-proxy. Local devnets
# may opt back into the legacy in-tab SDK-key signer by setting
# PSY_FAUCET_SERVER_MODE=0 and GENERATE_PRIVACY_FAUCET_OPERATORS=1.
if ! is_truthy "$PSY_FAUCET_SERVER_MODE" \
  && [ "$GENERATE_PRIVACY_FAUCET_OPERATORS" = "1" ] \
  && [ -z "${BUILD_LOCAL_PSY_SDK+x}" ]; then
  BUILD_LOCAL_PSY_SDK=1
fi

l1_network="${L1_DEPLOYMENTS_NETWORK:-sepolia}"
deployment_file="$ROOT/psy-dapp/psy-contracts/deployments/$l1_network/deployed-contracts.json"
deployment_backup="$(mktemp)"
deployment_existed=0
if [ -f "$deployment_file" ]; then
  cp "$deployment_file" "$deployment_backup"
  deployment_existed=1
fi
cleanup_frontend_source() {
  restore_tracked_node_modules "$FRONTEND_DIR"
  if [ "$deployment_existed" = "1" ]; then
    cp "$deployment_backup" "$deployment_file"
  else
    rm -f "$deployment_file"
  fi
  rm -f "$deployment_backup"
}
trap cleanup_frontend_source EXIT

default_l1_chain_id="${CHAIN_ID:-31337}"
default_l1_chain_name="Psy Testnet"
default_l1_chain_short_name="PSY-L1"
default_l1_rpc_url="${ETH_RPC_URL:-https://${PUBLIC_L1_RPC_DOMAIN}}"
default_l1_explorer_url="${PUBLIC_L1_EXPLORER_URL:-$default_l1_rpc_url}"
if [ "$l1_network" = "sepolia" ]; then
  default_l1_chain_id="${CHAIN_ID:-11155111}"
  default_l1_chain_name="Sepolia"
  default_l1_chain_short_name="Sepolia"
  default_l1_rpc_url="${ETH_RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}"
  default_l1_explorer_url="${PUBLIC_L1_EXPLORER_URL:-https://sepolia.etherscan.io}"
fi

set_demo_env() {
  local name="$1"
  local value="$2"
  export "$name=$value"
}

sha256_file() {
  local file="$1"

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    echo ""
  fi
}

wallet_version() {
  node -p "JSON.parse(require('fs').readFileSync('$PSY_WALLET_DIR/package.json', 'utf8')).version"
}

include_wallet_download() {
  local download_dir="$FRONTEND_DIR/public/downloads"
  if [ "${INCLUDE_WALLET_DOWNLOAD:-0}" != "1" ]; then
    # Staging wallet releases are published to R2. Remove artifacts left by
    # earlier/manual builds so Cloudflare Pages never receives the large zip.
    rm -f "$download_dir"/psy-wallet-*.zip
    echo "[cloudflare-pages] wallet package: R2 metadata only (no embedded Pages zip)"
    return 0
  fi

  [ -d "$PSY_WALLET_DIR" ] || {
    echo "missing psy-wallet checkout: $PSY_WALLET_DIR" >&2
    exit 1
  }

  local version zip_name zip_path digest
  version="$(wallet_version)"
  zip_name="psy-wallet-${WALLET_PACKAGE_MODE}-v${version}.zip"
  zip_path="$PSY_WALLET_DIR/release/$WALLET_PACKAGE_MODE/psy-wallet/v$version/$zip_name"
  download_dir="$FRONTEND_DIR/public/downloads"

  [ -f "$zip_path" ] || {
    cat >&2 <<EOF
missing wallet package: $zip_path
Build it first, for example:
  (cd "$PSY_WALLET_DIR" && npm run build:${WALLET_PACKAGE_MODE})
EOF
    exit 1
  }

  unzip -p "$zip_path" 'src/content/webHook.js' | grep -q "psy_getNetworkConfig" || {
    echo "wallet package is missing psy_getNetworkConfig in content script" >&2
    exit 1
  }

  mkdir -p "$download_dir"
  cp "$zip_path" "$download_dir/$zip_name"
  echo "[cloudflare-pages] embedded wallet package: $zip_name"

  set_demo_env VITE_WALLET_VERSION "$version"
  set_demo_env VITE_WALLET_MODE "$WALLET_PACKAGE_MODE"
  set_demo_env VITE_WALLET_CHROME_URL "/downloads/$zip_name"

  digest="$(sha256_file "$download_dir/$zip_name")"
  if [ -n "$digest" ]; then
    set_demo_env VITE_WALLET_SHA256 "$digest"
    echo "[cloudflare-pages] embedded wallet sha256: $digest"
  fi
}

# The demo targets the current staging deployment. Force values sourced from
# config.env so stale VITE_* variables in the caller's shell cannot point
# the built bundle at an old bridge deployment.
set_demo_env VITE_PSY_RPC_MODE "remote"
set_demo_env VITE_NETWORK "$l1_network"
set_demo_env VITE_FORK "false"
set_demo_env VITE_L1_NETWORK "$l1_network"
set_demo_env VITE_L1_FORK "false"
set_demo_env VITE_DEFAULT_CHAIN_ID "$default_l1_chain_id"
set_demo_env VITE_L1_CHAIN_ID "$default_l1_chain_id"
set_demo_env VITE_L1_CHAIN_NAME "$default_l1_chain_name"
set_demo_env VITE_L1_CHAIN_SHORT_NAME "$default_l1_chain_short_name"
set_demo_env VITE_L1_RPC_URL "$default_l1_rpc_url"
set_demo_env VITE_L1_EXPLORER_URL "$default_l1_explorer_url"
set_demo_env VITE_L1_ADDRESSES_PROVIDER_ADDRESS "${ADDRESSES_PROVIDER_ADDRESS:-}"
set_demo_env VITE_L1_ROUTER_ADDRESS "${ROUTER_ADDRESS:-}"
set_demo_env VITE_L1_BRIDGE_ADDRESS "${BRIDGE_ADDRESS:-}"
set_demo_env VITE_L1_STATE_MANAGER_ADDRESS "${STATE_MANAGER_ADDRESS:-}"
set_demo_env VITE_L1_ERC20_GATEWAY_ADDRESS "${ERC20_GATEWAY_ADDRESS:-}"
set_demo_env VITE_L1_ETH_GATEWAY_ADDRESS "${ETH_GATEWAY_ADDRESS:-}"
set_demo_env VITE_L1_WETH_ADDRESS "${WETH_ADDRESS:-}"
set_demo_env VITE_PSY_TOKEN_ADDRESS "${PSY_TOKEN_ADDRESS:-}"
set_demo_env VITE_USDT_TOKEN_ADDRESS "${USDT_TOKEN_ADDRESS:-}"
set_demo_env VITE_PSY_COORDINATOR_URL "https://${PUBLIC_COORDINATOR_DOMAIN}"
set_demo_env VITE_PSY_REALM_URLS "https://${PUBLIC_REALM_DOMAIN},https://${PUBLIC_REALM1_DOMAIN}"
set_demo_env VITE_PSY_PROVE_PROXY_URL "https://${PUBLIC_PROVE_PROXY_DOMAIN}"
set_demo_env VITE_PSY_SERVICES_URL "https://${PUBLIC_PSY_SERVICES_DOMAIN}"
set_demo_env VITE_PSY_INDEXER_API_URL "https://${PUBLIC_PSY_SERVICES_DOMAIN}"
set_demo_env VITE_INDEXER_URL "https://${PUBLIC_INDEXER_DOMAIN}/v1/graphql"
set_demo_env VITE_PSY_IDE_URL "$PUBLIC_PSY_IDE_URL"
set_demo_env VITE_PSY_CONFIG_URL "$PUBLIC_CONFIG_PAGE_URL"
set_demo_env VITE_PSY_FAUCET_SERVER_MODE "$PSY_FAUCET_SERVER_MODE"
set_demo_env VITE_PSY_FAUCET_TURNSTILE_SITE_KEY "${PSY_FAUCET_TURNSTILE_SITE_KEY:-}"
include_wallet_download

if ! is_truthy "$PSY_FAUCET_SERVER_MODE" && [ "$GENERATE_PRIVACY_FAUCET_OPERATORS" = "1" ]; then
  faucet_operators_json="$(bash "$ROOT/deploy/gcp/generate-privacy-faucet-operators.sh")"
  set_demo_env VITE_PSY_FAUCET_OPERATORS_JSON "$faucet_operators_json"
  faucet_operator_count="$(jq '.operators | length' <<< "$faucet_operators_json")"
  echo "[cloudflare-pages] generated local Psy faucet operator config: operators=$faucet_operator_count"
fi

if [ "${BUILD_LOCAL_PSY_SDK:-0}" = "1" ]; then
  echo "[cloudflare-pages] building local @psy/psy-sdk package in $PSY_SDK_PACKAGE_DIR"
  (
    cd "$PSY_SDK_PACKAGE_DIR"
    pnpm install --frozen-lockfile
    PSY_COMPILER_WASM_WORKSPACE="${PSY_COMPILER_WASM_WORKSPACE:-$ROOT/client_prover/psy_ide}" \
      pnpm run build
  )
  sdk_pack_dir="$(mktemp -d /tmp/psy-sdk-pack.XXXXXX)"
  sdk_pack_name="$(
    cd "$PSY_SDK_PACKAGE_DIR"
    npm_config_cache="${npm_config_cache:-/tmp/npm-cache}" npm pack --silent --pack-destination "$sdk_pack_dir" | tail -n 1
  )"
  sdk_pack_path="$sdk_pack_dir/$sdk_pack_name"
  echo "[cloudflare-pages] installing local SDK override: @psy-protocol/psy-sdk@file:$sdk_pack_path"
  (
    cd "$FRONTEND_DIR"
    npm ci
    npm install --no-save --package-lock=false "@psy-protocol/psy-sdk@file:$sdk_pack_path"
  )
fi

echo "[cloudflare-pages] demo L1 config: router=$VITE_L1_ROUTER_ADDRESS erc20_gateway=$VITE_L1_ERC20_GATEWAY_ADDRESS usdt=$VITE_USDT_TOKEN_ADDRESS"

if [ "${BUILD_LOCAL_PSY_SDK:-0}" = "1" ]; then
  CF_PAGES_SKIP_INSTALL=1 build_frontend_dir "$FRONTEND_DIR" "psy-privacy-bridge-demo"
else
  build_frontend_dir "$FRONTEND_DIR" "psy-privacy-bridge-demo"
fi

for token_icon in tokens/psy.svg tokens/usdt.svg; do
  icon_path="$FRONTEND_DIR/dist/$token_icon"
  if [ ! -s "$icon_path" ]; then
    cat >&2 <<EOF
privacy bridge demo build is missing $token_icon.
This usually means the app was built from an old checkout that does not include
psy-dapp/apps/bridge/public/$token_icon.
EOF
    exit 1
  fi
  if ! head -c 128 "$icon_path" | grep -q '<svg'; then
    echo "privacy bridge demo build has invalid $token_icon; expected SVG content" >&2
    exit 1
  fi
done

if [ "${REQUIRE_PRIVACY_FAUCET_SDK_KEY_WASM:-$(is_truthy "$PSY_FAUCET_SERVER_MODE" && printf 0 || printf "%s" "$GENERATE_PRIVACY_FAUCET_OPERATORS")}" = "1" ]; then
  if ! grep -R -q 'wasmrpcserver_register_sdk_key_circuit' "$FRONTEND_DIR/dist/assets"; then
    cat >&2 <<EOF
privacy bridge demo bundle is missing SDK-key WASM export.
Expected bundled @psy/psy-sdk to contain wasmrpcserver_register_sdk_key_circuit.
Publish/use an @psy-protocol/psy-sdk package with SDK-key WASM support, or set
BUILD_LOCAL_PSY_SDK=1 for a local override.
EOF
    exit 1
  fi
fi

deploy_pages_dir "$FRONTEND_DIR/dist" "$PROJECT_NAME" "$BRANCH"
