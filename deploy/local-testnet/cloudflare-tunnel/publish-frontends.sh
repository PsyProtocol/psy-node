#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

local_cf_render_chain_config

LOCAL_CF_LOCALHOST_DEPLOYMENT_FILE="${LOCAL_CF_LOCALHOST_DEPLOYMENT_FILE:-$PARTH_DIR/psy-contracts/deployments/localhost/deployed-contracts.json}"
LOCAL_CF_PUBLISH_NGINX_ROOT="${LOCAL_STAGING_NGINX_ROOT:-$PARTH_DIR/.local-staging/nginx/html}"

validate_tunnel_frontend_bundle() {
  local app_root="$1/app"
  local expected_coordinator
  local expected_faucet
  local expected_l1_rpc
  local expected_nostr
  local local_rpc_matches
  local stale_nostr_matches

  expected_coordinator="$(local_cf_url "$LOCAL_CF_COORDINATOR_HOST")"
  expected_faucet="$(local_cf_url "$LOCAL_CF_FAUCET_HOST")"
  expected_l1_rpc="$(local_cf_l1_rpc_public_url)"
  expected_nostr="$LOCAL_CF_NOSTR_RELAY_URL"

  if [ ! -d "$app_root" ]; then
    echo "[local-cf-tunnel] app publish output missing: $app_root" >&2
    exit 1
  fi

  local_rpc_matches="$(
    grep -R -E -n \
      'http://127\.0\.0\.1:(1337|13380|13390|9998|9999|3000|8080)' \
      "$app_root/index.html" "$app_root/assets" 2>/dev/null || true
  )"
  if [ -n "$local_rpc_matches" ]; then
    echo "[local-cf-tunnel] tunnel app bundle still contains localhost RPC URLs; refusing to publish a CF-broken frontend" >&2
    printf '%s\n' "$local_rpc_matches" | head -20 >&2
    exit 1
  fi

  stale_nostr_matches="$(
    grep -R -E -n \
      'ws://127\.0\.0\.1:8081' \
      "$app_root/index.html" "$app_root/assets" 2>/dev/null || true
  )"
  if [ -n "$stale_nostr_matches" ]; then
    echo "[local-cf-tunnel] tunnel app bundle contains a localhost Nostr endpoint; refusing to publish" >&2
    printf '%s\n' "$stale_nostr_matches" | head -20 >&2
    exit 1
  fi

  if ! grep -R -F -q "$expected_coordinator" "$app_root/index.html" "$app_root/assets" 2>/dev/null; then
    echo "[local-cf-tunnel] tunnel app bundle missing coordinator endpoint: $expected_coordinator" >&2
    exit 1
  fi

  if ! grep -R -F -q "$expected_faucet" "$app_root/index.html" "$app_root/assets" 2>/dev/null; then
    echo "[local-cf-tunnel] tunnel app bundle missing faucet endpoint: $expected_faucet" >&2
    exit 1
  fi

  if ! grep -R -F -q "$expected_l1_rpc" "$app_root/index.html" "$app_root/assets" 2>/dev/null; then
    echo "[local-cf-tunnel] tunnel app bundle missing L1 RPC endpoint: $expected_l1_rpc" >&2
    exit 1
  fi

  if ! grep -R -F -q "$expected_nostr" "$app_root/index.html" "$app_root/assets" 2>/dev/null; then
    echo "[local-cf-tunnel] tunnel app bundle missing Nostr relay endpoint: $expected_nostr" >&2
    exit 1
  fi

  echo "[local-cf-tunnel] verified tunnel frontend endpoints: $expected_coordinator, $expected_faucet, $expected_l1_rpc, $expected_nostr"
}

backup="$(mktemp)"
cp "$LOCAL_CF_ORIGINAL_CHAIN_CONFIG" "$backup"
deployment_backup="$(mktemp)"
cp "$LOCAL_CF_LOCALHOST_DEPLOYMENT_FILE" "$deployment_backup"

restore_config() {
  cp "$backup" "$LOCAL_CF_ORIGINAL_CHAIN_CONFIG"
  rm -f "$backup"
  cp "$deployment_backup" "$LOCAL_CF_LOCALHOST_DEPLOYMENT_FILE"
  rm -f "$deployment_backup"
}
trap restore_config EXIT

echo "[local-cf-tunnel] temporarily applying tunnel client_prover/config.json"
cp "$LOCAL_CF_CHAIN_CONFIG_FILE" "$LOCAL_CF_ORIGINAL_CHAIN_CONFIG"

echo "[local-cf-tunnel] temporarily applying tunnel localhost deployed-contracts.json"
tmp_deployment="${LOCAL_CF_LOCALHOST_DEPLOYMENT_FILE}.tmp.$$"
jq \
  --arg l1rpc "$(local_cf_l1_rpc_public_url)" \
  --arg explorer "$(local_cf_url "$LOCAL_CF_EXPLORER_HOST")" \
  '
    .protocol.chain.defaultRpcUrl = $l1rpc
    | .protocol.chain.defaultExplorerUrl = $explorer
  ' "$LOCAL_CF_LOCALHOST_DEPLOYMENT_FILE" > "$tmp_deployment"
mv "$tmp_deployment" "$LOCAL_CF_LOCALHOST_DEPLOYMENT_FILE"

LOCAL_STAGING_BUILD_FRONTENDS="${LOCAL_STAGING_BUILD_FRONTENDS:-1}" \
LOCAL_STAGING_NPM_INSTALL="${LOCAL_STAGING_NPM_INSTALL:-0}" \
LOCAL_STAGING_BUILD_WALLET="${LOCAL_STAGING_BUILD_WALLET:-0}" \
LOCAL_STAGING_NGINX_ROOT="$LOCAL_CF_PUBLISH_NGINX_ROOT" \
LOCAL_STAGING_ALLOW_PUBLISH_WITH_CF=1 \
VITE_WALLET_RELEASE_URL="${LOCAL_CF_WALLET_RELEASE_URL:-https://wallet-assets-stg.psy-protocol.xyz/local-devnet/wallet-release.json}" \
PSY_WALLET_DIR="${PSY_WALLET_DIR:-$PARTH_DIR/../psy-wallet}" \
  bash "$LOCAL_CF_TOOLS_PARTH_DIR/deploy/local-testnet/stack/publish-frontends.sh"

validate_tunnel_frontend_bundle "$LOCAL_CF_PUBLISH_NGINX_ROOT"

echo "[local-cf-tunnel] published tunnel-configured frontends"
