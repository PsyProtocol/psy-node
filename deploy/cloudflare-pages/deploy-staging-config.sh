#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/cloudflare-pages/lib-direct-upload.sh
source "$SCRIPT_DIR/lib-direct-upload.sh"

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
fi

l1_rpc_url="${l1_rpc_url:-https://${PUBLIC_L1_RPC_DOMAIN}}"
l1_explorer_url="${l1_explorer_url:-$l1_rpc_url}"
generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

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

mkdir -p "$OUT_DIR"
favicon_source_dir="$ROOT/psy-dapp/apps/bridge/public"
for asset in favicon.svg favicon.ico psy-icon.svg; do
  if [ -f "$favicon_source_dir/$asset" ]; then
    cp -f "$favicon_source_dir/$asset" "$OUT_DIR/$asset"
  fi
done

jq -n \
  --arg generated_at "$generated_at" \
  --arg environment "staging" \
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

cat > "$OUT_DIR/index.html" <<'EOF'
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="theme-color" media="(prefers-color-scheme: light)" content="#0a0a0d" />
    <meta name="theme-color" media="(prefers-color-scheme: dark)" content="#0a0a0d" />
    <meta name="theme-color" content="#0a0a0d" />

    <link rel="icon" type="image/svg+xml" href="/favicon.svg?v=2" />
    <link rel="alternate icon" type="image/x-icon" href="/favicon.ico?v=2" />

    <title>Psy Protocol &ndash; Staging Config</title>
    <meta name="description" content="Public staging endpoints, contract addresses, token metadata, and trusted setup links for Psy Protocol testing." />
    <meta name="author" content="Psy Protocol" />
    <meta name="creator" content="Psy Protocol" />
    <meta name="keywords" content="Psy,Blockchain,zkp,privacy,testnet,staging config,contract addresses,trusted setup" />

    <meta property="og:title" content="Psy Protocol &ndash; Staging Config" />
    <meta property="og:description" content="Public staging endpoints, contract addresses, token metadata, and trusted setup links for Psy Protocol testing." />
    <meta property="og:url" content="https://config-stg.psy-protocol.xyz/" />
    <meta property="og:site_name" content="Psy Protocol" />
    <meta property="og:locale" content="en_US" />
    <meta property="og:type" content="website" />
    <meta property="og:image" content="https://www.psy.xyz/og.png" />
    <meta property="og:image:alt" content="Psy Protocol" />

    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:creator" content="@PsyProtocol" />
    <meta name="twitter:title" content="Psy Protocol &ndash; Staging Config" />
    <meta name="twitter:description" content="Public staging endpoints, contract addresses, token metadata, and trusted setup links for Psy Protocol testing." />
    <meta name="twitter:image" content="https://www.psy.xyz/og.png" />
    <style>
      @import url("https://fonts.googleapis.com/css2?family=Cabin+Condensed:wght@500;600;700&display=swap");

      :root {
        color-scheme: dark;
        --bg-primary: #0a0a0d;
        --bg-card: #131316;
        --bg-elevated: #1c1c20;
        --border-primary: #232328;
        --border-secondary: #2a2a30;
        --border-active: #3a3a42;
        --text-primary: #fafafa;
        --text-secondary: #a3a3a8;
        --text-tertiary: #52525b;
        --accent-primary: #0070f3;
        --accent-primary-hover: #0061d6;
        --accent-active: #62ffcc;
        --accent-warning: #f59e0b;
        --accent-danger: #ef4444;
        --font-display: "Cabin Condensed", ui-sans-serif, system-ui, -apple-system, sans-serif;
        --font-sans: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Courier New", monospace;
        --radius-sm: 6px;
        --radius-md: 8px;
        --radius-lg: 12px;
        --radius-pill: 9999px;
      }

      * {
        box-sizing: border-box;
      }

      body {
        margin: 0;
        min-height: 100vh;
        background:
          radial-gradient(circle at 82% 10%, rgba(98, 255, 204, 0.07), transparent 28rem),
          radial-gradient(circle at 12% 30%, rgba(0, 112, 243, 0.08), transparent 24rem),
          var(--bg-primary);
        color: var(--text-primary);
        font-family: var(--font-sans);
        font-size: 15px;
        line-height: 1.5;
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
      }

      a {
        color: inherit;
        text-decoration: none;
      }

      .site-header {
        position: fixed;
        top: 0;
        right: 0;
        left: 0;
        z-index: 20;
        border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        background: rgba(10, 10, 9, 0.72);
        backdrop-filter: blur(18px);
        -webkit-backdrop-filter: blur(18px);
      }

      main,
      .header-inner {
        width: min(1080px, calc(100% - 6rem));
        margin: 0 auto;
      }

      .header-inner {
        display: flex;
        min-height: 76px;
        align-items: center;
        justify-content: space-between;
        gap: 2rem;
      }

      .brand {
        display: inline-flex;
        align-items: center;
        color: var(--text-primary);
        transition: opacity 0.15s ease;
      }

      .brand:hover {
        opacity: 0.8;
      }

      .brand-logo {
        display: block;
        width: 61.6px;
        height: 28px;
      }

      .nav {
        display: flex;
        align-items: center;
        gap: 2rem;
      }

      .nav a {
        color: var(--text-tertiary);
        font-size: 0.875rem;
        transition: color 0.15s ease;
      }

      .nav a:hover {
        color: var(--text-primary);
      }

      .hero {
        padding: 11rem 0 3rem;
      }

      .hero-kicker {
        margin: 0 0 1.1rem;
        color: var(--accent-active);
        font-size: 0.78rem;
        font-weight: 650;
        letter-spacing: 0.08em;
        text-transform: uppercase;
      }

      h1 {
        margin: 0 0 1.35rem;
        color: var(--text-primary);
        font-size: 64px;
        font-weight: 600;
        line-height: 0.98;
        letter-spacing: 0;
      }

      .subtitle {
        max-width: 56ch;
        margin: 0;
        color: var(--text-secondary);
        font-size: 1.05rem;
        line-height: 1.55;
      }

      .actions {
        display: flex;
        flex-wrap: wrap;
        gap: 0.8rem;
        margin-top: 2rem;
      }

      button,
      a.button {
        display: inline-flex;
        min-height: 42px;
        align-items: center;
        justify-content: center;
        gap: 0.5rem;
        border: 1px solid var(--border-primary);
        border-radius: var(--radius-pill);
        background: rgba(255, 255, 255, 0.025);
        color: var(--text-primary);
        padding: 0 1.05rem;
        font: inherit;
        font-size: 0.88rem;
        font-weight: 650;
        text-decoration: none;
        cursor: pointer;
        transition: opacity 0.15s ease, border-color 0.15s ease, background 0.15s ease;
      }

      button.primary,
      a.button.primary {
        border-color: var(--accent-primary);
        background: var(--accent-primary);
        color: #fff;
      }

      button:hover,
      a.button:hover {
        border-color: var(--border-active);
      }

      button.primary:hover,
      a.button.primary:hover {
        background: var(--accent-primary-hover);
      }

      main {
        padding: 0 0 5.5rem;
      }

      .grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 1rem;
      }

      section {
        min-width: 0;
        overflow: hidden;
        border: 1px solid var(--border-primary);
        border-radius: 18px;
        background:
          linear-gradient(180deg, rgba(255, 255, 255, 0.026), transparent 45%),
          var(--bg-card);
        box-shadow: 0 24px 70px rgba(0, 0, 0, 0.18);
      }

      section.wide {
        grid-column: 1 / -1;
      }

      section.hero {
        overflow: visible;
        border: 0;
        border-radius: 0;
        background: transparent;
        box-shadow: none;
      }

      .section-head {
        display: flex;
        align-items: baseline;
        justify-content: space-between;
        gap: 1rem;
        border-bottom: 1px solid var(--border-primary);
        padding: 1.1rem 1.25rem;
      }

      h2 {
        margin: 0;
        color: var(--text-primary);
        font-size: 1rem;
        font-weight: 650;
        letter-spacing: 0;
      }

      .table-wrap {
        overflow-x: auto;
      }

      table {
        width: 100%;
        border-collapse: collapse;
      }

      th,
      td {
        border-bottom: 1px solid var(--border-primary);
        padding: 0.85rem 1.25rem;
        text-align: left;
        vertical-align: middle;
      }

      thead th {
        color: var(--text-tertiary);
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
      }

      tbody th {
        width: 10rem;
        color: var(--text-secondary);
        font-size: 0.86rem;
        font-weight: 600;
      }

      tr:last-child td {
        border-bottom: 0;
      }

      tr:last-child th {
        border-bottom: 0;
      }

      code {
        overflow-wrap: anywhere;
        color: var(--text-primary);
        font-family: var(--font-mono);
        font-size: 13px;
      }

      .address-link {
        color: var(--text-primary);
        font-family: var(--font-mono);
        font-size: 13px;
        overflow-wrap: anywhere;
        text-decoration: underline;
        text-decoration-color: transparent;
        text-underline-offset: 0.18em;
        transition: color 0.15s ease, text-decoration-color 0.15s ease;
      }

      .address-link:hover {
        color: var(--accent-active);
        text-decoration-color: currentColor;
      }

      .url-link {
        color: var(--text-primary);
        font-family: var(--font-mono);
        font-size: 13px;
        overflow-wrap: anywhere;
        text-decoration: underline;
        text-decoration-color: transparent;
        text-underline-offset: 0.18em;
        transition: color 0.15s ease, text-decoration-color 0.15s ease;
      }

      .url-link:hover {
        color: var(--accent-active);
        text-decoration-color: currentColor;
      }

      .pill {
        display: inline-flex;
        align-items: center;
        border-radius: 999px;
        background: rgba(98, 255, 204, 0.08);
        border: 1px solid rgba(98, 255, 204, 0.2);
        color: var(--accent-active);
        padding: 5px 10px;
        font-size: 12px;
        font-weight: 700;
      }

      .row-actions {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        justify-content: flex-end;
      }

      .small {
        min-height: 30px;
        padding: 0 9px;
        font-size: 13px;
      }

      .notice {
        margin: 0 0 1rem;
        border: 1px solid rgba(245, 158, 11, 0.28);
        border-radius: var(--radius-lg);
        background: rgba(245, 158, 11, 0.08);
        color: #fbbf24;
        padding: 0.9rem 1rem;
      }

      .status {
        color: var(--text-secondary);
        font-size: 13px;
      }

      strong {
        color: var(--text-primary);
        font-weight: 650;
      }

      ::selection {
        background: rgba(0, 204, 136, 0.2);
        color: #fff;
      }

      @media (max-width: 860px) {
        main,
        .header-inner {
          width: min(100% - 2.5rem, 1080px);
        }

        .header-inner {
          min-height: 68px;
        }

        .nav {
          gap: 1rem;
        }

        .grid {
          grid-template-columns: 1fr;
        }
      }

      @media (max-width: 560px) {
        main,
        .header-inner {
          width: min(100% - 2rem, 1080px);
        }

        .nav a:not(:last-child) {
          display: none;
        }

        .hero {
          padding-top: 8rem;
        }

        h1 {
          font-size: 44px;
        }

        .actions {
          align-items: stretch;
          flex-direction: column;
        }

        button,
        a.button {
          width: 100%;
        }

        thead th,
        tbody th,
        td {
          padding: 11px 12px;
        }

        tbody th {
          width: auto;
        }
      }
    </style>
  </head>
  <body>
    <header class="site-header">
      <div class="header-inner">
        <a class="brand" href="/" aria-label="Psy Config home">
          <svg
            class="brand-logo"
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 660 300"
            fill="none"
            role="img"
            aria-label="Psy"
          >
            <title>Psy</title>
            <path fill="currentColor" d="M116.214 5.31161C114.559 18.2955 113.099 33.3943 111.834 50.6078C110.569 67.8214 109.595 85.8218 108.914 104.609C108.33 123.298 108.038 141.446 108.038 159.053C108.038 171.447 108.281 184.382 108.768 197.857C109.352 211.235 110.082 223.776 110.958 235.481C111.834 247.186 112.807 256.58 113.878 263.662C110.763 264.843 106.383 266.367 100.738 268.236C95.1902 270.105 90.7129 271.728 87.3063 273.105C86.2357 272.515 85.311 271.876 84.5324 271.187C83.7537 270.499 82.8777 269.613 81.9044 268.531C83.6564 257.22 85.165 243.99 86.4303 228.842C87.793 213.694 88.815 197.611 89.4963 180.595C90.2749 163.578 90.6643 146.561 90.6643 129.544C90.6643 116.068 90.3723 102.101 89.7883 87.6415C89.3016 73.1822 88.5716 59.2638 87.5983 45.8864C86.625 32.4106 85.5057 20.4595 84.2404 10.033C88.9123 7.96741 93.8762 6.04933 99.1321 4.2788C104.388 2.50826 108.719 1.08199 112.126 0C112.807 0.590179 113.586 1.47545 114.462 2.6558C115.435 3.83616 116.019 4.72143 116.214 5.31161ZM172.715 62.5589C175.343 68.1656 177.338 74.9527 178.701 82.9201C180.161 90.8875 180.891 98.3631 180.891 105.347C180.891 116.265 179.236 127.724 175.927 139.725C172.617 151.627 167.556 162.742 160.743 173.07C154.027 183.398 145.462 191.808 135.047 198.3C124.633 204.694 112.369 207.89 98.2561 207.89C83.2671 207.89 70.8086 205.874 60.8808 201.841C50.953 197.808 43.0692 192.398 37.2293 185.611C31.4867 178.824 27.3988 171.25 24.9655 162.889C22.6296 154.528 21.4616 145.971 21.4616 137.217C21.4616 130.528 21.8022 123.397 22.4836 115.823C23.1649 108.249 23.5055 100.921 23.5055 93.8384C23.5055 89.2153 22.0456 85.4775 19.1256 82.625C16.2057 79.6741 9.83048 77.8544 0 77.1659V69.7886C8.85716 68.805 16.887 67.4771 24.0895 65.8049C31.2921 64.1327 37.0833 62.2147 41.4632 60.0507C43.7992 61.0343 45.7945 62.9524 47.4491 65.8049C49.2011 68.6574 50.077 74.2641 50.077 82.625C50.077 90.1006 49.6877 98.1664 48.9091 106.822C48.2277 115.478 47.8871 123.397 47.8871 130.577C47.8871 141.79 49.5417 151.922 52.851 160.971C56.1603 169.922 61.8541 177.054 69.9327 182.365C78.1085 187.578 89.4963 190.185 104.096 190.185C114.997 190.185 124.292 187.037 131.981 180.742C139.768 174.447 145.705 166.086 149.793 155.66C153.978 145.233 156.071 133.971 156.071 121.872C156.071 113.413 154.66 104.757 151.837 95.904C149.014 86.953 144.878 80.2643 139.427 75.838C142.931 73.3789 147.311 70.5755 152.567 67.4279C157.92 64.2803 162.398 61.7228 165.999 59.7556C167.264 60.3458 168.335 60.8376 169.211 61.231C170.184 61.6245 171.352 62.0671 172.715 62.5589Z" />
            <path fill="currentColor" d="M582.857 220.227L529.336 78.8105H557.143L596.312 189.103L632.193 78.8105H660L581.362 300H553.555L582.857 220.227Z" />
            <path fill="currentColor" d="M474.812 229.896C457.67 229.896 442.819 225.867 430.261 217.809L433.55 191.218C446.308 201.291 459.464 206.327 473.018 206.327C480.194 206.327 485.776 204.816 489.763 201.794C493.949 198.773 496.042 194.341 496.042 188.499C496.042 184.067 495.045 180.441 493.052 177.621C491.258 174.8 488.168 172.081 483.783 169.462C479.397 166.843 472.62 163.418 463.45 159.188C452.686 154.152 444.813 148.411 439.829 141.964C434.846 135.518 432.354 127.158 432.354 116.884C432.354 104.797 436.54 94.9263 444.912 87.2713C453.284 79.6163 464.547 75.7888 478.699 75.7888C493.052 75.7888 505.61 79.0119 516.374 85.4582L513.085 109.934C507.703 106.308 502.62 103.689 497.836 102.078C493.052 100.265 487.371 99.3581 480.792 99.3581C473.816 99.3581 468.334 100.869 464.347 103.891C460.361 106.912 458.367 111.143 458.367 116.582C458.367 122.021 460.062 126.151 463.45 128.971C467.038 131.791 473.915 135.518 484.082 140.151C498.234 146.598 508.201 153.145 513.982 159.792C519.762 166.239 522.653 174.8 522.653 185.477C522.653 199.377 518.367 210.255 509.796 218.112C501.224 225.968 489.563 229.896 474.812 229.896Z" />
            <path fill="currentColor" d="M293.019 15.3545H346.839C368.766 15.3545 385.809 21.1965 397.969 32.8805C410.328 44.5644 416.507 61.5867 416.507 83.9474C416.507 106.308 410.328 123.431 397.969 135.317C385.809 147.001 368.766 152.843 346.839 152.843H320.527V226.875H293.019V15.3545ZM344.447 127.46C373.55 127.46 388.102 112.956 388.102 83.9474C388.102 54.939 373.55 40.4347 344.447 40.4347H320.527V127.46H344.447Z" />
          </svg>
        </a>
        <nav class="nav" aria-label="Primary">
          <a href="https://app-stg.psy-protocol.xyz/" target="_blank" rel="noreferrer">App</a>
          <a href="https://explorer-stg.psy-protocol.xyz/" target="_blank" rel="noreferrer">Explorer</a>
          <a href="./config.json">JSON</a>
        </nav>
      </div>
    </header>

    <main>
      <section class="hero" aria-label="Psy staging config">
        <p class="hero-kicker">Psy testnet resources</p>
        <h1>Staging Config</h1>
        <p class="subtitle">Public endpoints, contract addresses, token metadata, and trusted setup links for the current Psy staging deployment.</p>
        <div class="actions">
          <a class="button primary" href="./config.json">Open JSON</a>
          <button id="copy-json" type="button">Copy JSON</button>
        </div>
      </section>

      <p class="notice">
        Use these addresses for the current staging deployment only. If staging is redeployed, refresh this
        page before adding tokens or sharing addresses.
      </p>

      <div class="grid">
        <section>
          <div class="section-head">
            <h2>Network</h2>
            <div class="row-actions">
              <span class="pill" id="network-pill">Loading</span>
              <button class="small" id="add-network" type="button">Add to MetaMask</button>
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <tbody id="network-table"></tbody>
            </table>
          </div>
        </section>

        <section>
          <div class="section-head">
            <h2>Services</h2>
            <span class="status" id="generated-at"></span>
          </div>
          <div class="table-wrap">
            <table>
              <tbody id="services-table"></tbody>
            </table>
          </div>
        </section>

        <section class="wide">
          <div class="section-head">
            <h2>Frontends</h2>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>URL</th>
                  <th></th>
                </tr>
              </thead>
              <tbody id="frontends-table"></tbody>
            </table>
          </div>
        </section>

        <section class="wide">
          <div class="section-head">
            <div>
              <h2>Trust Setup</h2>
              <span class="status">Groth16 setup package for local relayer/prove workflows</span>
            </div>
            <div class="row-actions">
              <a class="button small" id="trust-setup-script-link" href="./install-groth16-trust-setup.sh" target="_blank" rel="noreferrer">Install Script</a>
              <button class="small" id="copy-trust-setup-command" type="button">Copy Command</button>
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <tbody id="trust-setup-table"></tbody>
            </table>
          </div>
        </section>

        <section class="wide">
          <div class="section-head">
            <h2>Tokens</h2>
            <span class="status">Add these ERC20 tokens to MetaMask on Sepolia</span>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Token</th>
                  <th>Address</th>
                  <th>Decimals</th>
                  <th></th>
                </tr>
              </thead>
              <tbody id="tokens-table"></tbody>
            </table>
          </div>
        </section>

        <section class="wide">
          <div class="section-head">
            <h2>Contracts</h2>
            <span class="status">L1 deployment addresses</span>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Address</th>
                  <th></th>
                </tr>
              </thead>
              <tbody id="contracts-table"></tbody>
            </table>
          </div>
        </section>
      </div>
    </main>

    <script>
      const state = { config: null };

      function explorerAddressUrl(address) {
        const base = state.config?.l1?.explorer_url;
        if (!base || !address) return null;
        return `${base.replace(/\/$/, "")}/address/${address}`;
      }

      function row(label, value) {
        return `<tr><th>${label}</th><td><code>${value || ""}</code></td></tr>`;
      }

      function actionButtons(value) {
        return `
          <div class="row-actions">
            <button class="small" type="button" data-copy="${value}">Copy</button>
          </div>
        `;
      }

      function urlActionButtons(value) {
        return `
          <div class="row-actions">
            <button class="small" type="button" data-copy="${value}">Copy</button>
          </div>
        `;
      }

      function urlLink(value) {
        return `<a class="url-link" href="${value}" target="_blank" rel="noreferrer">${value}</a>`;
      }

      function tokenImageUrl(token) {
        if (token.symbol === "PSY") return new URL("./psy-icon.svg", window.location.href).href;
        return undefined;
      }

      function tokenActionButtons(token) {
        return `
          <div class="row-actions">
            <button class="small" type="button" data-copy="${token.address}">Copy</button>
            <button class="small" type="button" data-add-token="${token.symbol}">Add to MetaMask</button>
          </div>
        `;
      }

      function addressLink(address) {
        const explorer = explorerAddressUrl(address);
        if (!explorer) return `<code>${address}</code>`;
        return `<a class="address-link" href="${explorer}" target="_blank" rel="noreferrer">${address}</a>`;
      }

      function trustSetupInstallCommand(config) {
        const scriptUrl = config.trust_setup?.install_script_url || "./install-groth16-trust-setup.sh";
        return `bash -c "$(curl -fsSL '${scriptUrl}')"`;
      }

      function render(config) {
        state.config = config;
        document.getElementById("network-pill").textContent = `${config.l1.chain_short_name} · ${config.l1.chain_id}`;
        document.getElementById("generated-at").textContent = `Generated ${config.generated_at}`;
        document.getElementById("network-table").innerHTML = [
          row("Environment", config.environment),
          row("Network", config.l1.network),
          row("Chain ID", config.l1.chain_id),
          row("RPC", config.l1.rpc_url),
          row("Explorer", config.l1.explorer_url),
        ].join("");
        document.getElementById("services-table").innerHTML = [
          row("Coordinator", config.services.coordinator_rpc),
          row("Realm 0", config.services.realm_rpcs[0]),
          row("Realm 1", config.services.realm_rpcs[1]),
          row("Prove proxy", config.services.prove_proxy),
          row("Psy services", config.services.psy_services),
          row("Indexer GraphQL", config.services.indexer_graphql),
        ].join("");
        document.getElementById("frontends-table").innerHTML = [
          { name: "Psy App", url: config.frontends?.app || config.frontends?.psy_bridge },
          { name: "Psy Explorer", url: config.frontends?.psy_explorer },
          { name: "Psy IDE", url: config.frontends?.psy_ide },
          { name: "Config", url: config.frontends?.config },
          { name: "Wallet", url: config.frontends?.wallet },
        ]
          .filter((frontend) => frontend.url)
          .map(
            (frontend) => `
              <tr>
                <td><strong>${frontend.name}</strong></td>
                <td>${urlLink(frontend.url)}</td>
                <td>${urlActionButtons(frontend.url)}</td>
              </tr>
            `,
          )
          .join("");
        const installCommand = trustSetupInstallCommand(config);
        document.getElementById("trust-setup-script-link").href =
          config.trust_setup?.install_script_url || "./install-groth16-trust-setup.sh";
        document.getElementById("trust-setup-table").innerHTML = [
          row("Archive", config.trust_setup?.archive_url),
          row("Shell script", config.trust_setup?.install_script_url || "./install-groth16-trust-setup.sh"),
          row("Install command", installCommand),
          row("SHA256", config.trust_setup?.sha256 || "Not published in config"),
          row("Install target", config.trust_setup?.install_target || "~/.psy"),
        ].join("");
        document.getElementById("copy-trust-setup-command").dataset.copy = installCommand;
        document.getElementById("tokens-table").innerHTML = config.tokens
          .map(
            (token) => `
              <tr>
                <td><strong>${token.symbol}</strong><br><span class="status">${token.name}</span></td>
                <td>${addressLink(token.address)}</td>
                <td>${token.decimals}</td>
                <td>${tokenActionButtons(token)}</td>
              </tr>
            `,
          )
          .join("");
        document.getElementById("contracts-table").innerHTML = config.contracts
          .map(
            (contract) => `
              <tr>
                <td><strong>${contract.name}</strong></td>
                <td>${addressLink(contract.address)}</td>
                <td>${actionButtons(contract.address)}</td>
              </tr>
            `,
          )
          .join("");
      }

      async function copyText(value) {
        await navigator.clipboard.writeText(value);
      }

      function walletProvider() {
        const ethereum = window.ethereum;
        if (!ethereum || typeof ethereum.request !== "function") {
          throw new Error("MetaMask extension not detected.");
        }
        return ethereum;
      }

      function chainIdHex(chainId) {
        const numeric = Number(chainId);
        if (!Number.isFinite(numeric) || numeric <= 0) throw new Error(`Invalid chain id: ${chainId}`);
        return `0x${numeric.toString(16)}`;
      }

      async function ensureWalletChain(config) {
        const ethereum = walletProvider();
        const requestedChainId = chainIdHex(config.l1.chain_id);
        try {
          await ethereum.request({
            method: "wallet_switchEthereumChain",
            params: [{ chainId: requestedChainId }],
          });
        } catch (error) {
          if (error?.code !== 4902) throw error;
          await ethereum.request({
            method: "wallet_addEthereumChain",
            params: [
              {
                chainId: requestedChainId,
                chainName: config.l1.chain_name || config.l1.network || "Psy L1",
                nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
                rpcUrls: [config.l1.rpc_url].filter(Boolean),
                blockExplorerUrls: [config.l1.explorer_url].filter(Boolean),
              },
            ],
          });
        }
      }

      async function addTokenToWallet(token) {
        if (!state.config) throw new Error("Config has not loaded yet.");
        await ensureWalletChain(state.config);
        const options = {
          address: token.address,
          symbol: token.symbol,
          decimals: Number(token.decimals),
        };
        const image = tokenImageUrl(token);
        if (image) options.image = image;
        return walletProvider().request({
          method: "wallet_watchAsset",
          params: {
            type: "ERC20",
            options,
          },
        });
      }

      async function addNetworkToWallet() {
        if (!state.config) throw new Error("Config has not loaded yet.");
        await ensureWalletChain(state.config);
      }

      document.addEventListener("click", async (event) => {
        const target = event.target;
        if (!(target instanceof HTMLElement)) return;
        const value = target.dataset.copy;
        if (value) {
          await copyText(value);
          const old = target.textContent;
          target.textContent = "Copied";
          setTimeout(() => {
            target.textContent = old;
          }, 900);
        }
        const tokenSymbol = target.dataset.addToken;
        if (tokenSymbol) {
          const token = state.config?.tokens?.find((item) => item.symbol === tokenSymbol);
          if (!token) return;
          const old = target.textContent;
          target.textContent = "Open wallet";
          try {
            const added = await addTokenToWallet(token);
            target.textContent = added ? "Added" : "Cancelled";
          } catch (error) {
            target.textContent = "Failed";
            alert(error instanceof Error ? error.message : "Failed to add token to MetaMask");
          } finally {
            setTimeout(() => {
              target.textContent = old;
            }, 1400);
          }
        }
      });

      document.getElementById("copy-json").addEventListener("click", async () => {
        if (!state.config) return;
        await copyText(JSON.stringify(state.config, null, 2));
      });

      document.getElementById("add-network").addEventListener("click", async (event) => {
        const target = event.currentTarget;
        const old = target.textContent;
        target.textContent = "Open wallet";
        try {
          await addNetworkToWallet();
          target.textContent = "Added";
        } catch (error) {
          target.textContent = "Failed";
          alert(error instanceof Error ? error.message : "Failed to add network to MetaMask");
        } finally {
          setTimeout(() => {
            target.textContent = old;
          }, 1400);
        }
      });

      fetch("./config.json", { cache: "no-store" })
        .then((response) => {
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          return response.json();
        })
        .then(render)
        .catch((error) => {
          document.getElementById("network-pill").textContent = "Error";
          document.querySelector("main").insertAdjacentHTML(
            "afterbegin",
            `<p class="notice">Failed to load config.json: ${error.message}</p>`,
          );
        });
    </script>
  </body>
</html>
EOF

echo "[cloudflare-pages] generated staging config page:"
echo "  html: $OUT_DIR/index.html"
echo "  json: $OUT_DIR/config.json"
echo "[cloudflare-pages] config summary:"
jq -r '
  "  chain=\(.l1.chain_short_name) (\(.l1.chain_id))",
  "  bridge=\(.contracts[] | select(.name == "Bridge") | .address)",
  "  psy=\(.tokens[] | select(.symbol == "PSY") | .address)",
  "  usdt=\(.tokens[] | select(.symbol == "USDT") | .address)"
' "$OUT_DIR/config.json"

deploy_pages_dir "$OUT_DIR" "$PROJECT_NAME" "$BRANCH"
