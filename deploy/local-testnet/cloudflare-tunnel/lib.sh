#!/usr/bin/env bash
set -euo pipefail

LOCAL_CF_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_CF_TOOLS_PARTH_DIR="$(cd "$LOCAL_CF_SCRIPT_DIR/../../.." && pwd)"
PARTH_DIR="${LOCAL_CF_SOURCE_PARTH_DIR:-${PARTH_DIR:-$LOCAL_CF_TOOLS_PARTH_DIR}}"
LOCAL_CF_LIVE_PARTH_DIR="${LOCAL_CF_LIVE_PARTH_DIR:-$LOCAL_CF_TOOLS_PARTH_DIR}"

# shellcheck source=../local-staging/lib.sh
source "$LOCAL_CF_TOOLS_PARTH_DIR/deploy/local-testnet/stack/lib.sh"

local_staging_source_env_defaults "$LOCAL_CF_TOOLS_PARTH_DIR/deploy/local-testnet/stack/local.env"
local_staging_source_env_defaults "$LOCAL_CF_SCRIPT_DIR/local.env"

: "${LOCAL_CF_STATE_DIR:=$LOCAL_CF_LIVE_PARTH_DIR/.local-staging-cf-tunnel}"
: "${LOCAL_CF_TUNNEL_NAME:=psy-local-staging}"
: "${LOCAL_CF_TUNNEL_ID:=}"
: "${LOCAL_CF_TUNNEL_CREDENTIALS_FILE:=}"
: "${LOCAL_CF_DOMAIN_SUFFIX:=psy-protocol.xyz}"

: "${LOCAL_CF_APP_HOST:=app-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_EXPLORER_HOST:=explorer-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_IDE_HOST:=ide-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_COORDINATOR_HOST:=coordinator-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_REALM0_HOST:=realm0-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_REALM1_HOST:=realm1-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_PROVE_HOST:=prove-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_FAUCET_HOST:=faucet-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_SERVICES_HOST:=services-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_INDEXER_HOST:=indexer-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_L1_RPC_HOST:=rpc-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_ETH_FAUCET_HOST:=eth-faucet-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_NOSTR_HOST:=nostr-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_NOSTR_RELAY_URL:=wss://${LOCAL_CF_NOSTR_HOST}/}"

: "${LOCAL_STAGING_COORDINATOR_EDGE_PORT:=1337}"
: "${LOCAL_STAGING_REALM_EDGE_BASE_PORT:=13380}"
: "${LOCAL_STAGING_REALM_EDGE_PORT_STRIDE:=10}"
: "${LOCAL_STAGING_PROVE_PROXY_ADDR:=127.0.0.1:9999}"
: "${LOCAL_STAGING_FAUCET_ADDR:=127.0.0.1:9998}"
: "${LOCAL_STAGING_PSY_SERVICES_ADDR:=127.0.0.1:3000}"
: "${LOCAL_STAGING_APP_PORT:=8088}"
: "${LOCAL_STAGING_EXPLORER_PORT:=8089}"
: "${LOCAL_STAGING_IDE_PORT:=8090}"
: "${LOCAL_STAGING_L1_RPC_PORT:=8545}"
: "${LOCAL_STAGING_INDEXER_PORT:=8080}"
: "${LOCAL_NOSTR_PORT:=8081}"
: "${LOCAL_CF_ETH_FAUCET_PORT:=8555}"

: "${LOCAL_CF_CONFIG_FILE:=$LOCAL_CF_STATE_DIR/cloudflared/config.yml}"
: "${LOCAL_CF_CHAIN_CONFIG_FILE:=$LOCAL_CF_STATE_DIR/client_prover/config.json}"
: "${LOCAL_CF_ORIGINAL_CHAIN_CONFIG:=$PARTH_DIR/psy-genesis/config.json}"
: "${LOCAL_CF_BIN_DIR:=$LOCAL_CF_LIVE_PARTH_DIR/.local-staging/bin}"

export PATH="$LOCAL_CF_BIN_DIR:$PATH"

local_cf_url() {
  printf 'https://%s\n' "$1"
}

local_cf_l1_rpc_public_url() {
  # MetaMask keys custom networks by RPC endpoint URL. If a user previously
  # saved the bare rpc-local URL while it pointed at chain 31337, MetaMask will
  # reject adding the same endpoint for a new chain ID. A harmless query string
  # keeps the endpoint distinct while Cloudflare/Anvil still route it normally.
  printf 'https://%s/?chain=%s\n' "$LOCAL_CF_L1_RPC_HOST" "${LOCAL_STAGING_L1_CHAIN_ID:-31338}"
}

local_cf_require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[local-cf-tunnel] missing command: $1" >&2
    exit 1
  }
}

local_cf_cloudflared_download_url() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os:$arch" in
    Linux:x86_64|Linux:amd64)
      printf '%s\n' 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64'
      ;;
    Linux:aarch64|Linux:arm64)
      printf '%s\n' 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64'
      ;;
    *)
      echo "[local-cf-tunnel] unsupported cloudflared auto-install platform: $os $arch" >&2
      echo "[local-cf-tunnel] install cloudflared manually or add it to PATH" >&2
      return 1
      ;;
  esac
}

local_cf_ensure_cloudflared() {
  if command -v cloudflared >/dev/null 2>&1; then
    return 0
  fi

  local_cf_require_command curl

  local url tmp target
  url="$(local_cf_cloudflared_download_url)"
  target="$LOCAL_CF_BIN_DIR/cloudflared"
  tmp="${target}.tmp.$$"

  mkdir -p "$LOCAL_CF_BIN_DIR"
  echo "[local-cf-tunnel] installing cloudflared -> $target"
  curl -fL --retry 3 --retry-delay 2 "$url" -o "$tmp"
  chmod 0755 "$tmp"
  mv "$tmp" "$target"
  hash -r
}

local_cf_require_file() {
  local path="$1"
  [ -f "$path" ] || {
    echo "[local-cf-tunnel] missing file: $path" >&2
    exit 1
  }
}

local_cf_tunnel_ref() {
  if [ -n "$LOCAL_CF_TUNNEL_ID" ]; then
    printf '%s\n' "$LOCAL_CF_TUNNEL_ID"
  else
    printf '%s\n' "$LOCAL_CF_TUNNEL_NAME"
  fi
}

local_cf_realm_port() {
  local realm_id="$1"
  printf '%s\n' "$(( LOCAL_STAGING_REALM_EDGE_BASE_PORT + realm_id * LOCAL_STAGING_REALM_EDGE_PORT_STRIDE ))"
}

local_cf_render_cloudflared_config() {
  mkdir -p "$(dirname "$LOCAL_CF_CONFIG_FILE")"

  {
    printf 'tunnel: %s\n' "$(local_cf_tunnel_ref)"
    printf 'protocol: %s\n' "${LOCAL_CF_TUNNEL_PROTOCOL:-quic}"
    if [ -n "$LOCAL_CF_TUNNEL_CREDENTIALS_FILE" ]; then
      printf 'credentials-file: %s\n' "$LOCAL_CF_TUNNEL_CREDENTIALS_FILE"
    fi
    cat <<YAML
ingress:
  - hostname: ${LOCAL_CF_APP_HOST}
    path: /eth-faucet*
    service: http://127.0.0.1:${LOCAL_CF_ETH_FAUCET_PORT}
  - hostname: ${LOCAL_CF_APP_HOST}
    service: http://127.0.0.1:${LOCAL_STAGING_APP_PORT}
  - hostname: ${LOCAL_CF_EXPLORER_HOST}
    service: http://127.0.0.1:${LOCAL_STAGING_EXPLORER_PORT}
  - hostname: ${LOCAL_CF_IDE_HOST}
    service: http://127.0.0.1:${LOCAL_STAGING_IDE_PORT}
  - hostname: ${LOCAL_CF_COORDINATOR_HOST}
    service: http://127.0.0.1:${LOCAL_STAGING_COORDINATOR_EDGE_PORT}
  - hostname: ${LOCAL_CF_REALM0_HOST}
    service: http://127.0.0.1:$(local_cf_realm_port 0)
  - hostname: ${LOCAL_CF_REALM1_HOST}
    service: http://127.0.0.1:$(local_cf_realm_port 1)
  - hostname: ${LOCAL_CF_PROVE_HOST}
    service: http://${LOCAL_STAGING_PROVE_PROXY_ADDR}
  - hostname: ${LOCAL_CF_FAUCET_HOST}
    service: http://${LOCAL_STAGING_FAUCET_ADDR}
  - hostname: ${LOCAL_CF_SERVICES_HOST}
    service: http://${LOCAL_STAGING_PSY_SERVICES_ADDR}
  - hostname: ${LOCAL_CF_INDEXER_HOST}
    service: http://127.0.0.1:${LOCAL_STAGING_INDEXER_PORT}
  - hostname: ${LOCAL_CF_L1_RPC_HOST}
    service: http://127.0.0.1:${LOCAL_STAGING_L1_RPC_PORT}
  - hostname: ${LOCAL_CF_ETH_FAUCET_HOST}
    service: http://127.0.0.1:${LOCAL_CF_ETH_FAUCET_PORT}
  - hostname: ${LOCAL_CF_NOSTR_HOST}
    service: http://127.0.0.1:${LOCAL_NOSTR_PORT}
  - service: http_status:404
YAML
  } > "$LOCAL_CF_CONFIG_FILE"
}

local_cf_render_chain_config() {
  local_cf_require_command jq
  local_cf_require_file "$LOCAL_CF_ORIGINAL_CHAIN_CONFIG"
  mkdir -p "$(dirname "$LOCAL_CF_CHAIN_CONFIG_FILE")"

  jq \
    --arg coordinator "$(local_cf_url "$LOCAL_CF_COORDINATOR_HOST")" \
    --arg realm0 "$(local_cf_url "$LOCAL_CF_REALM0_HOST")" \
    --arg realm1 "$(local_cf_url "$LOCAL_CF_REALM1_HOST")" \
    --arg prove "$(local_cf_url "$LOCAL_CF_PROVE_HOST")" \
    --arg faucet "$(local_cf_url "$LOCAL_CF_FAUCET_HOST")" \
    --arg services "$(local_cf_url "$LOCAL_CF_SERVICES_HOST")" \
    --arg indexer "$(local_cf_url "$LOCAL_CF_INDEXER_HOST")/v1/graphql" \
    --arg explorer "$(local_cf_url "$LOCAL_CF_EXPLORER_HOST")" \
    --arg l1rpc "$(local_cf_l1_rpc_public_url)" \
    --arg nostr "$LOCAL_CF_NOSTR_RELAY_URL" \
    --argjson l1chain "${LOCAL_STAGING_L1_CHAIN_ID:-31338}" \
    '
      .networks.localhost.coordinator_configs = [{id: 0, rpc_url: [$coordinator]}]
      | .networks.localhost.realm_configs = [
          {id: 0, rpc_url: [$realm0]},
          {id: 1, rpc_url: [$realm1]}
        ]
      | .networks.localhost.prove_proxy_url = [$prove]
      | .networks.localhost.faucet_rpc_url = [$faucet]
      | .networks.localhost.api_services_url = [$services]
      | .networks.localhost.indexer_graphql_url = [$indexer]
      | .networks.localhost.explorer_url = [$explorer]
      | .networks.localhost.l1_rpc_urls = [$l1rpc]
      | .networks.localhost.l1_chain_id = $l1chain
      | .networks.localhost.nostr_relay_urls = [$nostr]
    ' "$LOCAL_CF_ORIGINAL_CHAIN_CONFIG" > "$LOCAL_CF_CHAIN_CONFIG_FILE"
}

local_cf_render_all() {
  local_cf_render_cloudflared_config
  local_cf_render_chain_config
}

local_cf_print_urls() {
  cat <<EOF
app:          $(local_cf_url "$LOCAL_CF_APP_HOST")
explorer:     $(local_cf_url "$LOCAL_CF_EXPLORER_HOST")
ide:          $(local_cf_url "$LOCAL_CF_IDE_HOST")
coordinator:  $(local_cf_url "$LOCAL_CF_COORDINATOR_HOST")
realm 0:      $(local_cf_url "$LOCAL_CF_REALM0_HOST")
realm 1:      $(local_cf_url "$LOCAL_CF_REALM1_HOST")
prove-proxy:  $(local_cf_url "$LOCAL_CF_PROVE_HOST")
faucet:       $(local_cf_url "$LOCAL_CF_FAUCET_HOST")
psy-services: $(local_cf_url "$LOCAL_CF_SERVICES_HOST")
indexer:      $(local_cf_url "$LOCAL_CF_INDEXER_HOST")
l1 rpc:       $(local_cf_l1_rpc_public_url)
nostr relay:  $LOCAL_CF_NOSTR_RELAY_URL
eth faucet:   $(local_cf_url "$LOCAL_CF_ETH_FAUCET_HOST")
EOF
}
