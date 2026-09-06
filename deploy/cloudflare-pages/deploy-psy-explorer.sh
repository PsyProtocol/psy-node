#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/cloudflare-pages/lib-direct-upload.sh
source "$SCRIPT_DIR/lib-direct-upload.sh"
# shellcheck source=deploy/gcp/lib/multichain.sh
source "$ROOT/deploy/gcp/lib/multichain.sh"

PROJECT_NAME="${CF_PAGES_PROJECT:-psy-explorer-stg}"
BRANCH="${CF_PAGES_BRANCH:-staging}"

PARTH_DIR="${PARTH_DIR:-$ROOT}"
PSY_DAPP_DIR="${PSY_DAPP_DIR:-$PARTH_DIR/psy-dapp}"

EXPLORER_DIR="${PSY_EXPLORER_DIR:-$PSY_DAPP_DIR/apps/explorer}"
CONFIG_FILE="${GCP_DEPLOY_CONFIG:-$PARTH_DIR/deploy/gcp/config.env}"

if [ -f "$CONFIG_FILE" ]; then
  set -a
  # shellcheck source=../gcp/config.env
  source "$CONFIG_FILE"
  set +a
fi
set_public_domain_defaults

[ -d "$EXPLORER_DIR" ] || {
  echo "missing psy explorer frontend: $EXPLORER_DIR" >&2
  echo "initialize the psy-dapp submodule or set PSY_EXPLORER_DIR" >&2
  exit 1
}

if multichain_enabled; then
  explorer_network="${PSY_EXPLORER_NETWORK:-${MULTICHAIN_PRIMARY_NETWORK:-sepolia}}"
else
  explorer_network="${PSY_EXPLORER_NETWORK:-${L1_DEPLOYMENTS_NETWORK:-sepolia}}"
fi
explorer_fork="${PSY_EXPLORER_L1_FORK:-false}"
deployment_path="$PSY_DAPP_DIR/psy-contracts/deployments/$explorer_network/deployed-contracts.json"
deployment_backup="$(mktemp)"
deployment_existed=0
if [ -f "$deployment_path" ]; then
  cp "$deployment_path" "$deployment_backup"
  deployment_existed=1
fi
cleanup_explorer_source() {
  if [ "$deployment_existed" = "1" ]; then
    cp "$deployment_backup" "$deployment_path"
  else
    rm -f "$deployment_path"
  fi
  rm -f "$deployment_backup"
}
trap cleanup_explorer_source EXIT

if multichain_enabled; then
  multichain_write_frontend_deployment "$explorer_network" "$deployment_path"
fi

export VITE_NETWORK="$explorer_network"
export VITE_L1_NETWORK="$explorer_network"
export VITE_FORK="$explorer_fork"
export VITE_L1_FORK="$explorer_fork"
export PSY_CONFIG_URL="${PSY_CONFIG_URL:-${PUBLIC_CONFIG_PAGE_URL%/}/config.json}"

# Explorer reads token metadata through `@deployments`, not config.json.
# Regenerate that snapshot from the freshly deployed L1 addresses before
# validating or building the frontend.
SYNC_SCRIPT="$PSY_DAPP_DIR/apps/bridge/scripts/sync-staging-config.mjs"
if ! multichain_enabled \
  && [ -f "$SYNC_SCRIPT" ] \
  && { [ "$VITE_NETWORK" = "sepolia" ] || [ "$VITE_NETWORK" = "bsc-testnet" ]; }; then
  echo "[cloudflare-pages] syncing $VITE_NETWORK deployed-contracts.json for explorer"
  node "$SYNC_SCRIPT"
fi

echo "[cloudflare-pages] explorer config:"
echo "  VITE_NETWORK=$VITE_NETWORK"
echo "  VITE_L1_NETWORK=$VITE_L1_NETWORK"
echo "  VITE_FORK=$VITE_FORK"
echo "  VITE_L1_FORK=$VITE_L1_FORK"
echo "  PSY_CONFIG_URL=$PSY_CONFIG_URL"
echo "  config=$PSY_DAPP_DIR/psy-genesis/config.json"

if command -v jq >/dev/null 2>&1; then
  jq -e --arg network "$VITE_L1_NETWORK" '
    def first_url($v): if ($v | type) == "array" then $v[0] else $v end;
    .networks[$network] as $n
    | if $n == null then false else
        (($n.coordinator_configs[0].rpc_url[0] // "") | test("^https://"))
        and (($n.api_services_url[0] // "") | test("^https://"))
        and ((first_url($n.indexer_graphql_url) // "") | test("^https://"))
      and (($n.explorer_url[0] // "") | test("^https://"))
      and (($n.realm_configs // []) | length > 0)
      and all($n.realm_configs[]; ((.rpc_url[0] // "") | test("^https://")))
      end
  ' "$PSY_DAPP_DIR/psy-genesis/config.json" >/dev/null || {
    echo "selected explorer config '$VITE_L1_NETWORK' is missing endpoints" >&2
    exit 1
  }

  [ -f "$deployment_path" ] || {
    echo "missing explorer deployment metadata: $deployment_path" >&2
    exit 1
  }
  expected_psy="${PSY_TOKEN_ADDRESS:-}"
  expected_usdt="${USDT_TOKEN_ADDRESS:-}"
  expected_bridge="${BRIDGE_ADDRESS:-}"
  if multichain_enabled; then
    expected_psy="$(multichain_runtime_json | jq -er --arg network "$explorer_network" \
      '.chains[] | select(.network == $network) | .protocol.tokens.PSY.l1Address')"
    expected_usdt="$(multichain_runtime_json | jq -er --arg network "$explorer_network" \
      '.chains[] | select(.network == $network) | .protocol.tokens.USDT.l1Address')"
    expected_bridge="$(multichain_runtime_json | jq -er --arg network "$explorer_network" \
      '.chains[] | select(.network == $network) | .contracts.Bridge')"
  fi
  jq -e \
    --arg psy "$expected_psy" \
    --arg usdt "$expected_usdt" \
    --arg bridge "$expected_bridge" '
      def lower_or_empty($v): ($v // "" | ascii_downcase);
      .protocol.tokens as $tokens
      | (($tokens.PSY.l1Address // "") | test("^0x[0-9a-fA-F]{40}$"))
        and (($tokens.PSY.decimals // -1) >= 0)
        and (($tokens.USDT.l1Address // "") | test("^0x[0-9a-fA-F]{40}$"))
        and (($tokens.USDT.decimals // -1) >= 0)
        and (($psy == "") or (lower_or_empty($tokens.PSY.l1Address) == lower_or_empty($psy)))
        and (($usdt == "") or (lower_or_empty($tokens.USDT.l1Address) == lower_or_empty($usdt)))
        and (($bridge == "") or (lower_or_empty(.contracts.Bridge) == lower_or_empty($bridge)))
    ' "$deployment_path" >/dev/null || {
    echo "explorer deployment metadata does not match the selected runtime" >&2
    exit 1
  }
fi

echo "[cloudflare-pages] building psy explorer in ${EXPLORER_DIR}"
build_frontend_dir "$EXPLORER_DIR" "psy explorer"

deploy_pages_dir "$EXPLORER_DIR/dist" "$PROJECT_NAME" "$BRANCH"
