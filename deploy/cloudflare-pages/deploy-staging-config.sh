#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/cloudflare-pages/lib-direct-upload.sh
source "$SCRIPT_DIR/lib-direct-upload.sh"
# shellcheck source=deploy/gcp/lib/multichain.sh
source "$ROOT/deploy/gcp/lib/multichain.sh"

PROJECT_NAME="${CF_PAGES_PROJECT:-psy-config-stg}"
BRANCH="${CF_PAGES_BRANCH:-staging}"
CONFIG_FILE="${GCP_DEPLOY_CONFIG:-$ROOT/deploy/gcp/config.env}"
OUT_DIR="${PSY_CONFIG_PAGE_DIST:-$ROOT/dist/staging-config}"

[ -f "$CONFIG_FILE" ] || {
  echo "missing deploy config: $CONFIG_FILE" >&2
  exit 1
}

set -a
# shellcheck source=../gcp/config.env
source "$CONFIG_FILE"
set +a
set_public_domain_defaults

require_value() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "$name is required in $CONFIG_FILE" >&2
    exit 1
  fi
}

require_value CHAIN_ID
require_value L1_DEPLOYMENTS_NETWORK
require_value BRIDGE_ADDRESS
require_value STATE_MANAGER_ADDRESS
require_value ROUTER_ADDRESS
require_value ERC20_GATEWAY_ADDRESS
require_value ETH_GATEWAY_ADDRESS
require_value PSY_TOKEN_ADDRESS
require_value USDT_TOKEN_ADDRESS

l1_network="${L1_DEPLOYMENTS_NETWORK:-sepolia}"
l1_chain_id="${CHAIN_ID:-11155111}"
l1_chain_name="${VITE_L1_CHAIN_NAME:-Psy Testnet}"
l1_chain_short_name="${VITE_L1_CHAIN_SHORT_NAME:-PSY-L1}"
l1_explorer_url="${PUBLIC_L1_EXPLORER_URL:-${VITE_L1_EXPLORER_URL:-}}"
l1_rpc_url="${PUBLIC_CONFIG_L1_RPC_URL:-}"

if [ -n "${PUBLIC_L1_RPC_DOMAIN:-}" ]; then
  l1_rpc_url="https://${PUBLIC_L1_RPC_DOMAIN}"
elif [ -n "${PUBLIC_RPC_DOMAIN:-}" ]; then
  l1_rpc_url="https://${PUBLIC_RPC_DOMAIN}"
fi

if [ "$l1_network" = "sepolia" ] || [ "$l1_chain_id" = "11155111" ]; then
  l1_chain_name="${VITE_L1_CHAIN_NAME:-Sepolia}"
  l1_chain_short_name="${VITE_L1_CHAIN_SHORT_NAME:-Sepolia}"
  l1_explorer_url="${l1_explorer_url:-https://sepolia.etherscan.io}"
  l1_rpc_url="${l1_rpc_url:-https://ethereum-sepolia-rpc.publicnode.com}"
elif [ "$l1_network" = "bsc-testnet" ] || [ "$l1_chain_id" = "97" ]; then
  l1_chain_name="${VITE_L1_CHAIN_NAME:-BSC Testnet}"
  l1_chain_short_name="${VITE_L1_CHAIN_SHORT_NAME:-BSC Testnet}"
  l1_explorer_url="${l1_explorer_url:-https://testnet.bscscan.com}"
  l1_rpc_url="${l1_rpc_url:-https://data-seed-prebsc-1-s1.bnbchain.org:8545}"
fi

l1_rpc_url="${l1_rpc_url:-https://${PUBLIC_L1_RPC_DOMAIN}}"
l1_explorer_url="${l1_explorer_url:-$l1_rpc_url}"
generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
public_environment="${PUBLIC_CONFIG_ENVIRONMENT:-staging}"
l1_chains_json="[]"
if multichain_enabled; then
  l1_chains_json="$(multichain_public_l1_config_json)"
  primary_chain="$(multichain_primary_chain)"
  l1_rpc_url="https://$(jq -r '.public_rpc_domain' <<<"$primary_chain")"
  l1_explorer_url="$(jq -r '.explorer_url' <<<"$primary_chain")"
fi

coordinator_url="https://${PUBLIC_COORDINATOR_DOMAIN}"
realm0_url="https://${PUBLIC_REALM0_DOMAIN}"
realm1_url="https://${PUBLIC_REALM1_DOMAIN}"
prove_proxy_url="https://${PUBLIC_PROVE_PROXY_DOMAIN}"
faucet_rpc_url="https://${PUBLIC_FAUCET_DOMAIN}"
psy_services_url="https://${PUBLIC_PSY_SERVICES_DOMAIN}"
indexer_graphql_url="https://${PUBLIC_INDEXER_DOMAIN}/v1/graphql"
app_url="$PUBLIC_PRIVACY_BRIDGE_URL"
psy_explorer_url="$PUBLIC_PSY_EXPLORER_URL"
psy_ide_url="$PUBLIC_PSY_IDE_URL"
config_page_url="$PUBLIC_CONFIG_PAGE_URL"
wallet_download_url="$PUBLIC_WALLET_DOWNLOAD_URL"
trust_setup_archive_name="${TRUST_SETUP_ARCHIVE_NAME:-psy-groth16-trust-setup.tar.gz}"
trust_setup_url="${PUBLIC_TRUST_SETUP_URL:-https://${PUBLIC_TRUST_SETUP_DOMAIN}${PUBLIC_TRUST_SETUP_PATH:-/trust-setup}/${trust_setup_archive_name}}"
trust_setup_sha256="${PUBLIC_TRUST_SETUP_SHA256:-}"
trust_setup_sha256_file="${TRUST_SETUP_SHA256_FILE:-$ROOT/dist/trust-setup/${trust_setup_archive_name}.sha256}"
trust_setup_install_script_name="${TRUST_SETUP_INSTALL_SCRIPT_NAME:-install-groth16-trust-setup.sh}"
trust_setup_install_script_url="${PUBLIC_TRUST_SETUP_INSTALL_SCRIPT_URL:-${config_page_url%/}/${trust_setup_install_script_name}}"
if [ -z "$trust_setup_sha256" ] && [ -f "$trust_setup_sha256_file" ]; then
  trust_setup_sha256="$(awk '{print $1; exit}' "$trust_setup_sha256_file")"
fi

# The page itself lives in psy-dapp/apps/config: plain index.html + styles.css
# + main.js + icons, no build step. It used to be a heredoc in this script,
# which is how it got left behind when the deployment went multi-chain — this
# script grew an `l1_chains` array in config.json while the embedded page went
# on reading the single-chain fields, so config-stg showed only Sepolia. A
# deploy script generates config data; the page ships with the frontend.
PAGE_SRC="${PSY_CONFIG_PAGE_SRC:-$ROOT/psy-dapp/apps/config}"
[ -f "$PAGE_SRC/index.html" ] || {
  echo "missing config page source: $PAGE_SRC/index.html" >&2
  echo "(is the psy-dapp submodule checked out?)" >&2
  exit 1
}

# Rebuilt from scratch each run: OUT_DIR is uploaded wholesale, so a file left
# over from an older layout would be published alongside the current one.
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
cp -R "$PAGE_SRC/." "$OUT_DIR/"

# Everything below is generated: it must be written after the page copy so the
# deployment's own data wins over anything carried in the source directory.

jq -n \
  --arg generated_at "$generated_at" \
  --arg environment "$public_environment" \
  --arg l1_network "$l1_network" \
  --argjson l1_chain_id "$l1_chain_id" \
  --arg l1_chain_name "$l1_chain_name" \
  --arg l1_chain_short_name "$l1_chain_short_name" \
  --arg l1_rpc_url "$l1_rpc_url" \
  --arg l1_explorer_url "$l1_explorer_url" \
  --arg coordinator_url "$coordinator_url" \
  --arg realm0_url "$realm0_url" \
  --arg realm1_url "$realm1_url" \
  --arg prove_proxy_url "$prove_proxy_url" \
  --arg faucet_rpc_url "$faucet_rpc_url" \
  --arg psy_services_url "$psy_services_url" \
  --arg indexer_graphql_url "$indexer_graphql_url" \
  --arg app_url "$app_url" \
  --arg psy_explorer_url "$psy_explorer_url" \
  --arg psy_ide_url "$psy_ide_url" \
  --arg config_page_url "$config_page_url" \
  --arg wallet_download_url "$wallet_download_url" \
  --arg trust_setup_url "$trust_setup_url" \
  --arg trust_setup_sha256 "$trust_setup_sha256" \
  --arg trust_setup_install_script_url "$trust_setup_install_script_url" \
  --arg addresses_provider "${ADDRESSES_PROVIDER_ADDRESS:-}" \
  --arg bridge "$BRIDGE_ADDRESS" \
  --arg state_manager "$STATE_MANAGER_ADDRESS" \
  --arg router "$ROUTER_ADDRESS" \
  --arg erc20_gateway "$ERC20_GATEWAY_ADDRESS" \
  --arg eth_gateway "$ETH_GATEWAY_ADDRESS" \
  --arg multicall3 "${MULTICALL3_ADDRESS:-}" \
  --arg weth "${WETH_ADDRESS:-}" \
  --arg faucet "${TOKEN_FAUCET_MANAGER_ADDRESS:-}" \
  --arg psy_token "$PSY_TOKEN_ADDRESS" \
  --argjson psy_decimals "${PSY_TOKEN_DECIMALS:-9}" \
  --arg usdt_token "$USDT_TOKEN_ADDRESS" \
  --argjson usdt_decimals "${USDT_TOKEN_DECIMALS:-6}" \
  --argjson l1_chains "$l1_chains_json" \
  '{
    generated_at: $generated_at,
    environment: $environment,
    l1: {
      network: $l1_network,
      chain_id: $l1_chain_id,
      chain_name: $l1_chain_name,
      chain_short_name: $l1_chain_short_name,
      rpc_url: $l1_rpc_url,
      explorer_url: $l1_explorer_url
    },
    l1_chains: $l1_chains,
    services: {
      coordinator_rpc: $coordinator_url,
      realm_rpcs: [$realm0_url, $realm1_url],
      prove_proxy: $prove_proxy_url,
      faucet_rpc: $faucet_rpc_url,
      psy_services: $psy_services_url,
      indexer_graphql: $indexer_graphql_url
    },
    frontends: {
      app: $app_url,
      psy_bridge: $app_url,
      psy_explorer: $psy_explorer_url,
      psy_ide: $psy_ide_url,
      config: $config_page_url,
      wallet: $wallet_download_url
    },
    trust_setup: {
      archive_url: $trust_setup_url,
      install_script_url: $trust_setup_install_script_url,
      sha256: $trust_setup_sha256,
      install_target: "~/.psy"
    },
    contracts: [
      {name: "AddressesProvider", address: $addresses_provider},
      {name: "Bridge", address: $bridge},
      {name: "StateManager", address: $state_manager},
      {name: "Router", address: $router},
      {name: "ERC20Gateway", address: $erc20_gateway},
      {name: "ETHGateway", address: $eth_gateway},
      {name: "Multicall3", address: $multicall3},
      {name: "WETH", address: $weth},
      {name: "TokenFaucetManager", address: $faucet}
    ] | map(select(.address != "")),
    tokens: [
      {symbol: "PSY", name: "Psy Token", address: $psy_token, decimals: $psy_decimals},
      {symbol: "USDT", name: "USDT", address: $usdt_token, decimals: $usdt_decimals}
    ]
  }' > "$OUT_DIR/config.json"

cat > "$OUT_DIR/_headers" <<'EOF'
/*
  Access-Control-Allow-Origin: *
  Cache-Control: no-store

/config.json
  Content-Type: application/json; charset=utf-8
  Access-Control-Allow-Origin: *
  Cache-Control: no-store

/install-groth16-trust-setup.sh
  Content-Type: text/x-shellscript; charset=utf-8
  Access-Control-Allow-Origin: *
  Cache-Control: no-store
EOF

cat > "$OUT_DIR/robots.txt" <<'EOF'
User-agent: *
Disallow:
EOF

cat > "$OUT_DIR/$trust_setup_install_script_name" <<EOF
#!/usr/bin/env bash
set -euo pipefail

url="$trust_setup_url"
expected_sha="$trust_setup_sha256"
target="\$HOME/.psy"
tmp_dir="\$(mktemp -d)"
archive="\$tmp_dir/$trust_setup_archive_name"

cleanup() {
  rm -rf "\$tmp_dir"
}
trap cleanup EXIT

if command -v curl >/dev/null 2>&1; then
  curl -fL --retry 3 --connect-timeout 10 "\$url" -o "\$archive"
elif command -v wget >/dev/null 2>&1; then
  wget -O "\$archive" "\$url"
else
  echo "curl or wget is required" >&2
  exit 1
fi

if [ -n "\$expected_sha" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    actual_sha="\$(sha256sum "\$archive" | awk '{print \$1}')"
  else
    actual_sha="\$(shasum -a 256 "\$archive" | awk '{print \$1}')"
  fi
  if [ "\$actual_sha" != "\$expected_sha" ]; then
    echo "sha256 mismatch: expected \$expected_sha, got \$actual_sha" >&2
    exit 1
  fi
fi

conflicts=()
while IFS= read -r path; do
  [ -e "\$target/\$path" ] && conflicts+=("\$target/\$path")
done <<'PATHS'
keystore/circuit_groth16.bin
keystore/pk_groth16.bin
keystore/vk_groth16.bin
keystore/deposit_append/circuit_groth16.bin
keystore/deposit_append/pk_groth16.bin
keystore/deposit_append/vk_groth16.bin
keystore/withdrawal_claim/circuit_groth16.bin
keystore/withdrawal_claim/pk_groth16.bin
keystore/withdrawal_claim/vk_groth16.bin
PATHS

if [ "\${#conflicts[@]}" -gt 0 ]; then
  echo "The following trust setup files already exist:"
  printf "  %s\n" "\${conflicts[@]}"
  printf "Overwrite them? [y/N] "
  read -r answer
  case "\$answer" in
    y|Y|yes|YES) ;;
    *)
      echo "Install cancelled; existing files were not changed."
      exit 1
      ;;
  esac
fi

mkdir -p "\$target"
tar -xzf "\$archive" -C "\$target"
while IFS= read -r path; do
  chmod 0600 "\$target/\$path"
done <<'PATHS'
keystore/circuit_groth16.bin
keystore/pk_groth16.bin
keystore/vk_groth16.bin
keystore/deposit_append/circuit_groth16.bin
keystore/deposit_append/pk_groth16.bin
keystore/deposit_append/vk_groth16.bin
keystore/withdrawal_claim/circuit_groth16.bin
keystore/withdrawal_claim/pk_groth16.bin
keystore/withdrawal_claim/vk_groth16.bin
PATHS

echo "Installed Groth16 trust setup into \$target/keystore"
EOF

echo "[cloudflare-pages] assembled staging config page:"
echo "  page: $PAGE_SRC -> $OUT_DIR"
echo "  json: $OUT_DIR/config.json"
echo "[cloudflare-pages] config summary:"
# Print every chain the page will show. The old summary read .l1 only, so a
# multi-chain deployment logged as if it were single-chain.
jq -r '
  if (.l1_chains | length) > 0 then
    .l1_chains[]
    | "  chain=\(.name) (\(.chain_id), index \(.chain_index))",
      "    bridge=\(.contracts.Bridge // "-")",
      "    psy=\(.tokens[] | select(.symbol == "PSY") | .l1_address)",
      "    usdt=\(.tokens[] | select(.symbol == "USDT") | .l1_address)"
  else
    "  chain=\(.l1.chain_short_name) (\(.l1.chain_id))",
    "    bridge=\(.contracts[] | select(.name == "Bridge") | .address)",
    "    psy=\(.tokens[] | select(.symbol == "PSY") | .address)",
    "    usdt=\(.tokens[] | select(.symbol == "USDT") | .address)"
  end
' "$OUT_DIR/config.json"

deploy_pages_dir "$OUT_DIR" "$PROJECT_NAME" "$BRANCH"
