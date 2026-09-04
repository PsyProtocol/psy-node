#!/usr/bin/env bash
set -Eeuo pipefail

LOCAL_DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PSY_NODE_DIR="$(cd "$LOCAL_DEPLOY_DIR/../.." && pwd)"
LOCAL_DEPLOY_STATE_DIR="${LOCAL_DEPLOY_STATE_DIR:-$LOCAL_DEPLOY_DIR/.runtime}"

load_env_file() {
  local file="$1"
  [ -f "$file" ] || return 0
  set -a
  # shellcheck disable=SC1090
  source "$file"
  set +a
}

load_env_file "$LOCAL_DEPLOY_DIR/local.env"

: "${LOCAL_CF_TUNNEL_NAME:=psy-local-staging}"
: "${LOCAL_CF_TUNNEL_ID:=}"
: "${LOCAL_CF_TUNNEL_CREDENTIALS_FILE:=}"
: "${LOCAL_CF_DOMAIN_SUFFIX:=psy-protocol.xyz}"
: "${LOCAL_CF_TUNNEL_PROTOCOL:=quic}"
: "${LOCAL_CF_CLOUDFLARED_BIN:=}"

: "${LOCAL_CF_APP_HOST:=app-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_CONFIG_HOST:=config-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_EXPLORER_HOST:=explorer-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_IDE_HOST:=ide-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_COORDINATOR_HOST:=coordinator-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_REALM0_HOST:=realm0-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_REALM1_HOST:=realm1-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_PROVE_HOST:=prove-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_FAUCET_HOST:=faucet-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_SERVICES_HOST:=services-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_INDEXER_HOST:=indexer-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_NOSTR_HOST:=nostr-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_ETH_RPC_HOST:=rpc-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_BSC_RPC_HOST:=rpc-bsc-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_BASE_RPC_HOST:=rpc-base-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_ETH_FAUCET_HOST:=eth-faucet-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_BSC_FAUCET_HOST:=bnb-faucet-local.${LOCAL_CF_DOMAIN_SUFFIX}}"
: "${LOCAL_CF_BASE_FAUCET_HOST:=base-faucet-local.${LOCAL_CF_DOMAIN_SUFFIX}}"

: "${LOCAL_DEPLOY_BUILD:=1}"
: "${LOCAL_DEPLOY_START_TIMEOUT_SECONDS:=1200}"
: "${LOCAL_DEPLOY_PUBLIC_TIMEOUT_SECONDS:=180}"
: "${LOCAL_DEPLOY_GAS_FAUCET_BALANCE_ETH:=10}"
: "${LOCAL_DEPLOY_ENVIO_PORT:=9080}"
: "${LOCAL_DEPLOY_CONFIG_PAGE_PORT:=5180}"
: "${LOCAL_DEPLOY_SERVICES_REPO_URL:=git@github.com:PsyProtocol/psy-services.git}"
: "${LOCAL_DEPLOY_SERVICES_BRANCH:=multi_chain}"

# These variables are consumed by scripts which source this library.
# shellcheck disable=SC2034
LOCAL_DEPLOY_PID_DIR="$LOCAL_DEPLOY_STATE_DIR/pids"
# shellcheck disable=SC2034
LOCAL_DEPLOY_LOG_DIR="$LOCAL_DEPLOY_STATE_DIR/logs"
LOCAL_DEPLOY_CLOUDFLARED_CONFIG="$LOCAL_DEPLOY_STATE_DIR/cloudflared/config.yml"
LOCAL_DEPLOY_PUBLIC_CONFIG="$LOCAL_DEPLOY_STATE_DIR/public-config.json"
LOCAL_DEPLOY_CONFIG_PAGE_DIR="$LOCAL_DEPLOY_STATE_DIR/config-page"
LOCAL_DEPLOY_CONFIG_PAGE_TEMPLATE="$LOCAL_DEPLOY_DIR/config-page.html"
LOCAL_DEPLOY_CONFIG_PAGE_SERVER="$LOCAL_DEPLOY_DIR/config-server.py"
LOCAL_DEPLOY_DAPP_CONFIG="$PSY_NODE_DIR/psy-dapp/psy-genesis/config.json"
LOCAL_DEPLOY_DAPP_CONFIG_BACKUP="$LOCAL_DEPLOY_STATE_DIR/original-dapp-config.json"
LOCAL_DEPLOY_DAPP_PATCH="$LOCAL_DEPLOY_DIR/public-rpc.patch"
LOCAL_DEPLOY_DAPP_HOSTS_PATCH="$LOCAL_DEPLOY_DIR/dapp-public-hosts.patch"
LOCAL_DEPLOY_NODE_PATCH="$LOCAL_DEPLOY_DIR/runtime-projects.patch"
LOCAL_DEPLOY_ENVIO_PATCH="$LOCAL_DEPLOY_DIR/envio-port.patch"
LOCAL_DEPLOY_ENVIO_NODE_PATCH="$LOCAL_DEPLOY_DIR/envio-node26.patch"
LOCAL_DEPLOY_SERVICES_DIR="$LOCAL_DEPLOY_STATE_DIR/projects/psy-services"
LOCAL_DEPLOY_COMPILER_DIR="$LOCAL_DEPLOY_STATE_DIR/projects/psy-compiler"
LOCAL_DEPLOY_COMPILER_PATCH="$LOCAL_DEPLOY_DIR/compiler-local-node.patch"
LOCAL_DEPLOY_COMPILER_API_PATCH="$LOCAL_DEPLOY_DIR/compiler-api-compat.patch"
LOCAL_DEPLOY_GENESIS_STAMP="$PSY_NODE_DIR/psy-genesis/.genesis_contracts.compiler-artifact.json"
LOCAL_DEPLOY_GENESIS_STAMP_BACKUP="$LOCAL_DEPLOY_STATE_DIR/original-genesis-compiler-artifact.json"

local_deploy_tunnel_ref() {
  if [ -n "$LOCAL_CF_TUNNEL_ID" ]; then
    printf '%s\n' "$LOCAL_CF_TUNNEL_ID"
  else
    printf '%s\n' "$LOCAL_CF_TUNNEL_NAME"
  fi
}

local_deploy_cloudflared() {
  if [ -n "$LOCAL_CF_CLOUDFLARED_BIN" ] && [ -x "$LOCAL_CF_CLOUDFLARED_BIN" ]; then
    printf '%s\n' "$LOCAL_CF_CLOUDFLARED_BIN"
    return 0
  fi
  if command -v cloudflared >/dev/null 2>&1; then
    command -v cloudflared
    return 0
  fi

  local target="$LOCAL_DEPLOY_STATE_DIR/bin/cloudflared"
  if [ ! -x "$target" ]; then
    local arch url tmp
    case "$(uname -m)" in
      x86_64|amd64) arch="amd64" ;;
      aarch64|arm64) arch="arm64" ;;
      *) echo "[local-multichain] unsupported cloudflared architecture: $(uname -m)" >&2; return 1 ;;
    esac
    url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}"
    tmp="${target}.tmp.$$"
    mkdir -p "$(dirname "$target")"
    echo "[local-multichain] downloading cloudflared"
    curl -fL --retry 3 --retry-delay 2 "$url" -o "$tmp"
    chmod 0755 "$tmp"
    mv "$tmp" "$target"
  fi
  printf '%s\n' "$target"
}

local_deploy_url() {
  printf 'https://%s\n' "$1"
}

local_deploy_rpc_url() {
  local host="$1"
  local chain_id="$2"
  printf 'https://%s/?chain=%s\n' "$host" "$chain_id"
}

local_deploy_hosts() {
  printf '%s\n' \
    "$LOCAL_CF_APP_HOST" "$LOCAL_CF_CONFIG_HOST" "$LOCAL_CF_EXPLORER_HOST" "$LOCAL_CF_IDE_HOST" \
    "$LOCAL_CF_COORDINATOR_HOST" "$LOCAL_CF_REALM0_HOST" "$LOCAL_CF_REALM1_HOST" \
    "$LOCAL_CF_PROVE_HOST" "$LOCAL_CF_FAUCET_HOST" "$LOCAL_CF_SERVICES_HOST" \
    "$LOCAL_CF_INDEXER_HOST" "$LOCAL_CF_NOSTR_HOST" \
    "$LOCAL_CF_ETH_RPC_HOST" "$LOCAL_CF_BSC_RPC_HOST" "$LOCAL_CF_BASE_RPC_HOST" \
    "$LOCAL_CF_ETH_FAUCET_HOST" "$LOCAL_CF_BSC_FAUCET_HOST" "$LOCAL_CF_BASE_FAUCET_HOST"
}

local_deploy_render_tunnel_config() {
  mkdir -p "$(dirname "$LOCAL_DEPLOY_CLOUDFLARED_CONFIG")"
  {
    printf 'tunnel: %s\n' "$(local_deploy_tunnel_ref)"
    printf 'protocol: %s\n' "$LOCAL_CF_TUNNEL_PROTOCOL"
    if [ -n "$LOCAL_CF_TUNNEL_CREDENTIALS_FILE" ]; then
      printf 'credentials-file: %s\n' "$LOCAL_CF_TUNNEL_CREDENTIALS_FILE"
    fi
    cat <<YAML
ingress:
  - hostname: ${LOCAL_CF_APP_HOST}
    path: /eth-faucet*
    service: http://127.0.0.1:8555
  - hostname: ${LOCAL_CF_APP_HOST}
    service: http://127.0.0.1:5177
  - hostname: ${LOCAL_CF_CONFIG_HOST}
    service: http://127.0.0.1:${LOCAL_DEPLOY_CONFIG_PAGE_PORT}
  - hostname: ${LOCAL_CF_EXPLORER_HOST}
    service: http://127.0.0.1:5178
  - hostname: ${LOCAL_CF_IDE_HOST}
    service: http://127.0.0.1:5176
  - hostname: ${LOCAL_CF_COORDINATOR_HOST}
    service: http://127.0.0.1:1337
  - hostname: ${LOCAL_CF_REALM0_HOST}
    service: http://127.0.0.1:13380
  - hostname: ${LOCAL_CF_REALM1_HOST}
    service: http://127.0.0.1:13390
  - hostname: ${LOCAL_CF_PROVE_HOST}
    service: http://127.0.0.1:9999
  - hostname: ${LOCAL_CF_FAUCET_HOST}
    service: http://127.0.0.1:9998
  - hostname: ${LOCAL_CF_SERVICES_HOST}
    service: http://127.0.0.1:3000
  - hostname: ${LOCAL_CF_INDEXER_HOST}
    service: http://127.0.0.1:${LOCAL_DEPLOY_ENVIO_PORT}
  - hostname: ${LOCAL_CF_NOSTR_HOST}
    service: http://127.0.0.1:8081
  - hostname: ${LOCAL_CF_ETH_RPC_HOST}
    service: http://127.0.0.1:8545
  - hostname: ${LOCAL_CF_BSC_RPC_HOST}
    service: http://127.0.0.1:9545
  - hostname: ${LOCAL_CF_BASE_RPC_HOST}
    service: http://127.0.0.1:10545
  - hostname: ${LOCAL_CF_ETH_FAUCET_HOST}
    service: http://127.0.0.1:8555
  - hostname: ${LOCAL_CF_BSC_FAUCET_HOST}
    service: http://127.0.0.1:9555
  - hostname: ${LOCAL_CF_BASE_FAUCET_HOST}
    service: http://127.0.0.1:10555
  - service: http_status:404
YAML
  } > "$LOCAL_DEPLOY_CLOUDFLARED_CONFIG"
}

local_deploy_pid_alive() {
  local file="$1"
  local pid=""
  [ -f "$file" ] || return 1
  pid="$(sed -n '1p' "$file" 2>/dev/null || true)"
  [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1
}

local_deploy_stop_pid() {
  local label="$1"
  local file="$2"
  local pid=""
  [ -f "$file" ] || return 0
  pid="$(sed -n '1p' "$file" 2>/dev/null || true)"
  if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
    echo "[local-multichain] stopping $label pid=$pid"
    kill -- "-$pid" >/dev/null 2>&1 || kill "$pid" >/dev/null 2>&1 || true
    for _ in $(seq 1 60); do
      kill -0 "$pid" >/dev/null 2>&1 || break
      sleep 1
    done
    if kill -0 "$pid" >/dev/null 2>&1; then
      echo "[local-multichain] $label did not stop gracefully; sending SIGKILL" >&2
      kill -9 "$pid" >/dev/null 2>&1 || true
    fi
  fi
  rm -f "$file"
}

local_deploy_start_gas_faucet() {
  local label="$1" rpc_port="$2" faucet_port="$3" chain_id="$4" rpc_host="$5" pid_file="$6" log_file="$7"
  local_deploy_stop_pid "$label faucet" "$pid_file"
  if command -v setsid >/dev/null 2>&1; then
    setsid env \
      LOCAL_CF_ETH_FAUCET_PORT="$faucet_port" \
      LOCAL_CF_ETH_FAUCET_RPC_URL="http://127.0.0.1:$rpc_port" \
      LOCAL_CF_ETH_FAUCET_PUBLIC_RPC_URL="$(local_deploy_rpc_url "$rpc_host" "$chain_id")" \
      LOCAL_CF_ETH_FAUCET_CHAIN_NAME="$label" \
      LOCAL_STAGING_L1_CHAIN_ID="$chain_id" \
      LOCAL_CF_ETH_FAUCET_BALANCE_ETH="$LOCAL_DEPLOY_GAS_FAUCET_BALANCE_ETH" \
      python3 "$PSY_NODE_DIR/deploy/local-testnet/cloudflare-tunnel/eth-faucet.py" >"$log_file" 2>&1 &
  else
    nohup env \
      LOCAL_CF_ETH_FAUCET_PORT="$faucet_port" \
      LOCAL_CF_ETH_FAUCET_RPC_URL="http://127.0.0.1:$rpc_port" \
      LOCAL_CF_ETH_FAUCET_PUBLIC_RPC_URL="$(local_deploy_rpc_url "$rpc_host" "$chain_id")" \
      LOCAL_CF_ETH_FAUCET_CHAIN_NAME="$label" \
      LOCAL_STAGING_L1_CHAIN_ID="$chain_id" \
      LOCAL_CF_ETH_FAUCET_BALANCE_ETH="$LOCAL_DEPLOY_GAS_FAUCET_BALANCE_ETH" \
      python3 "$PSY_NODE_DIR/deploy/local-testnet/cloudflare-tunnel/eth-faucet.py" >"$log_file" 2>&1 &
  fi
  echo "$!" > "$pid_file"
}

local_deploy_start_gas_faucets() {
  local_deploy_start_gas_faucet "Psy Local Ethereum" 8545 8555 31337 "$LOCAL_CF_ETH_RPC_HOST" \
    "$LOCAL_DEPLOY_PID_DIR/eth-faucet.pid" "$LOCAL_DEPLOY_LOG_DIR/eth-faucet.log"
  local_deploy_start_gas_faucet "Psy Local BSC" 9545 9555 31338 "$LOCAL_CF_BSC_RPC_HOST" \
    "$LOCAL_DEPLOY_PID_DIR/bsc-faucet.pid" "$LOCAL_DEPLOY_LOG_DIR/bsc-faucet.log"
  local_deploy_start_gas_faucet "Psy Local Base" 10545 10555 31339 "$LOCAL_CF_BASE_RPC_HOST" \
    "$LOCAL_DEPLOY_PID_DIR/base-faucet.pid" "$LOCAL_DEPLOY_LOG_DIR/base-faucet.log"
}

local_deploy_render_config_page() {
  local eth_deployment="$PSY_NODE_DIR/psy-contracts/deployments/localhost/deployed-contracts.json"
  local bsc_deployment="$PSY_NODE_DIR/psy-contracts/deployments/localhostBsc/deployed-contracts.json"
  local base_deployment="$PSY_NODE_DIR/psy-contracts/deployments/localhostBase/deployed-contracts.json"
  local deployment generated_at node_commit services_commit

  for deployment in "$eth_deployment" "$bsc_deployment" "$base_deployment"; do
    if [ ! -s "$deployment" ]; then
      echo "[local-multichain] missing chain deployment for config page: $deployment" >&2
      return 1
    fi
  done

  generated_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  node_commit="$(git -C "$PSY_NODE_DIR" rev-parse HEAD)"
  services_commit="$(git -C "$LOCAL_DEPLOY_SERVICES_DIR" rev-parse HEAD)"
  mkdir -p "$LOCAL_DEPLOY_CONFIG_PAGE_DIR"
  cp "$LOCAL_DEPLOY_CONFIG_PAGE_TEMPLATE" "$LOCAL_DEPLOY_CONFIG_PAGE_DIR/index.html"
  cp "$LOCAL_DEPLOY_PUBLIC_CONFIG" "$LOCAL_DEPLOY_CONFIG_PAGE_DIR/client-config.json"

  jq -s \
    --arg generated_at "$generated_at" \
    --arg node_commit "$node_commit" \
    --arg services_commit "$services_commit" \
    --arg app "$(local_deploy_url "$LOCAL_CF_APP_HOST")" \
    --arg config "$(local_deploy_url "$LOCAL_CF_CONFIG_HOST")" \
    --arg explorer "$(local_deploy_url "$LOCAL_CF_EXPLORER_HOST")" \
    --arg ide "$(local_deploy_url "$LOCAL_CF_IDE_HOST")" \
    --arg coordinator "$(local_deploy_url "$LOCAL_CF_COORDINATOR_HOST")" \
    --arg realm0 "$(local_deploy_url "$LOCAL_CF_REALM0_HOST")" \
    --arg realm1 "$(local_deploy_url "$LOCAL_CF_REALM1_HOST")" \
    --arg prove "$(local_deploy_url "$LOCAL_CF_PROVE_HOST")" \
    --arg faucet "$(local_deploy_url "$LOCAL_CF_FAUCET_HOST")" \
    --arg services "$(local_deploy_url "$LOCAL_CF_SERVICES_HOST")" \
    --arg indexer "$(local_deploy_url "$LOCAL_CF_INDEXER_HOST")/v1/graphql" \
    --arg nostr "wss://${LOCAL_CF_NOSTR_HOST}/" \
    --arg eth_rpc "$(local_deploy_rpc_url "$LOCAL_CF_ETH_RPC_HOST" 31337)" \
    --arg bsc_rpc "$(local_deploy_rpc_url "$LOCAL_CF_BSC_RPC_HOST" 31338)" \
    --arg base_rpc "$(local_deploy_rpc_url "$LOCAL_CF_BASE_RPC_HOST" 31339)" \
    --arg eth_faucet "$(local_deploy_url "$LOCAL_CF_ETH_FAUCET_HOST")" \
    --arg bsc_faucet "$(local_deploy_url "$LOCAL_CF_BSC_FAUCET_HOST")" \
    --arg base_faucet "$(local_deploy_url "$LOCAL_CF_BASE_FAUCET_HOST")" \
    '
      def chain($deployment; $rpc; $gas_faucet): {
        network: $deployment.network,
        bridge_chain: $deployment.protocol.chain.bridgeChain,
        chain_id: ($deployment.chainId | tonumber),
        chain_index: $deployment.protocol.chain.l1ChainIndex,
        name: $deployment.protocol.chain.name,
        short_name: $deployment.protocol.chain.shortName,
        native_currency: $deployment.protocol.chain.nativeCurrency,
        rpc_url: $rpc,
        gas_faucet_url: $gas_faucet,
        contracts: $deployment.core,
        tokens: ($deployment.protocol.tokens | to_entries | map({
          symbol: .value.symbol,
          decimals: .value.decimals,
          l1_address: .value.l1Address,
          l2_contract_id: .value.l2TokenContractId
        }))
      };
      [
        chain(.[0]; $eth_rpc; $eth_faucet),
        chain(.[1]; $bsc_rpc; $bsc_faucet),
        chain(.[2]; $base_rpc; $base_faucet)
      ] as $chains
      | {
          schema_version: 2,
          generated_at: $generated_at,
          environment: "local-multichain",
          source: {
            psy_node: {branch: "multi_chain", commit: $node_commit},
            psy_services: {branch: "multi_chain", commit: $services_commit}
          },
          l1: $chains[0],
          l1_chains: $chains,
          services: {
            coordinator_rpc: $coordinator,
            realm_rpcs: [$realm0, $realm1],
            prove_proxy: $prove,
            faucet_rpc: $faucet,
            psy_services: $services,
            indexer_graphql: $indexer,
            nostr_relay: $nostr
          },
          frontends: {app: $app, config: $config, explorer: $explorer, ide: $ide},
          client_config_url: ($config + "/client-config.json")
        }
    ' "$eth_deployment" "$bsc_deployment" "$base_deployment" \
    > "$LOCAL_DEPLOY_CONFIG_PAGE_DIR/config.json"
}

local_deploy_start_config_page() {
  local pid_file="$LOCAL_DEPLOY_PID_DIR/config-page.pid"
  local log_file="$LOCAL_DEPLOY_LOG_DIR/config-page.log"
  local_deploy_stop_pid "config page" "$pid_file"
  if command -v setsid >/dev/null 2>&1; then
    setsid python3 "$LOCAL_DEPLOY_CONFIG_PAGE_SERVER" \
      --directory "$LOCAL_DEPLOY_CONFIG_PAGE_DIR" \
      --port "$LOCAL_DEPLOY_CONFIG_PAGE_PORT" >"$log_file" 2>&1 &
  else
    nohup python3 "$LOCAL_DEPLOY_CONFIG_PAGE_SERVER" \
      --directory "$LOCAL_DEPLOY_CONFIG_PAGE_DIR" \
      --port "$LOCAL_DEPLOY_CONFIG_PAGE_PORT" >"$log_file" 2>&1 &
  fi
  echo "$!" > "$pid_file"
}

local_deploy_restore_dapp() {
  if git -C "$PSY_NODE_DIR/psy-dapp" apply --reverse --check "$LOCAL_DEPLOY_DAPP_HOSTS_PATCH" >/dev/null 2>&1; then
    git -C "$PSY_NODE_DIR/psy-dapp" apply --reverse "$LOCAL_DEPLOY_DAPP_HOSTS_PATCH"
  fi
  if git -C "$PSY_NODE_DIR/psy-dapp" apply --reverse --check "$LOCAL_DEPLOY_DAPP_PATCH" >/dev/null 2>&1; then
    git -C "$PSY_NODE_DIR/psy-dapp" apply --reverse "$LOCAL_DEPLOY_DAPP_PATCH"
  fi
  if [ -f "$LOCAL_DEPLOY_DAPP_CONFIG_BACKUP" ]; then
    cp "$LOCAL_DEPLOY_DAPP_CONFIG_BACKUP" "$LOCAL_DEPLOY_DAPP_CONFIG"
    rm -f "$LOCAL_DEPLOY_DAPP_CONFIG_BACKUP"
  fi
}

local_deploy_restore_node() {
  if git -C "$PSY_NODE_DIR" apply --reverse --check "$LOCAL_DEPLOY_ENVIO_NODE_PATCH" >/dev/null 2>&1; then
    git -C "$PSY_NODE_DIR" apply --reverse "$LOCAL_DEPLOY_ENVIO_NODE_PATCH"
  fi
  if git -C "$PSY_NODE_DIR" apply --reverse --check "$LOCAL_DEPLOY_ENVIO_PATCH" >/dev/null 2>&1; then
    git -C "$PSY_NODE_DIR" apply --reverse "$LOCAL_DEPLOY_ENVIO_PATCH"
  fi
  if git -C "$PSY_NODE_DIR" apply --reverse --check "$LOCAL_DEPLOY_NODE_PATCH" >/dev/null 2>&1; then
    git -C "$PSY_NODE_DIR" apply --reverse "$LOCAL_DEPLOY_NODE_PATCH"
  fi
}

local_deploy_prepare_services() {
  mkdir -p "$(dirname "$LOCAL_DEPLOY_SERVICES_DIR")"
  if [ ! -d "$LOCAL_DEPLOY_SERVICES_DIR/.git" ]; then
    echo "[local-multichain] cloning psy-services ${LOCAL_DEPLOY_SERVICES_BRANCH}"
    git clone --branch "$LOCAL_DEPLOY_SERVICES_BRANCH" --single-branch \
      "$LOCAL_DEPLOY_SERVICES_REPO_URL" "$LOCAL_DEPLOY_SERVICES_DIR"
  else
    if [ -n "$(git -C "$LOCAL_DEPLOY_SERVICES_DIR" status --porcelain)" ]; then
      echo "[local-multichain] deployment-local psy-services is unexpectedly dirty" >&2
      git -C "$LOCAL_DEPLOY_SERVICES_DIR" status --short >&2
      return 1
    fi
    git -C "$LOCAL_DEPLOY_SERVICES_DIR" remote set-url origin "$LOCAL_DEPLOY_SERVICES_REPO_URL"
    git -C "$LOCAL_DEPLOY_SERVICES_DIR" fetch --no-tags origin \
      "+refs/heads/${LOCAL_DEPLOY_SERVICES_BRANCH}:refs/remotes/origin/${LOCAL_DEPLOY_SERVICES_BRANCH}"
    git -C "$LOCAL_DEPLOY_SERVICES_DIR" checkout -B "$LOCAL_DEPLOY_SERVICES_BRANCH" \
      "origin/$LOCAL_DEPLOY_SERVICES_BRANCH"
  fi

  local actual expected
  actual="$(git -C "$LOCAL_DEPLOY_SERVICES_DIR" rev-parse HEAD)"
  expected="$(git -C "$LOCAL_DEPLOY_SERVICES_DIR" rev-parse "origin/$LOCAL_DEPLOY_SERVICES_BRANCH")"
  if [ "$actual" != "$expected" ]; then
    echo "[local-multichain] psy-services HEAD $actual does not match origin/$LOCAL_DEPLOY_SERVICES_BRANCH $expected" >&2
    return 1
  fi
  echo "[local-multichain] psy-services ready: ${LOCAL_DEPLOY_SERVICES_BRANCH}@${actual}"
}

local_deploy_prepare_compiler() {
  mkdir -p "$(dirname "$LOCAL_DEPLOY_COMPILER_DIR")"
  if [ ! -d "$LOCAL_DEPLOY_COMPILER_DIR/.git" ]; then
    echo "[local-multichain] cloning deployment-local psy-compiler"
    git clone --branch mainnet-beta --single-branch \
      git@github.com:QEDProtocol/psy-compiler.git "$LOCAL_DEPLOY_COMPILER_DIR"
  fi
  if git -C "$LOCAL_DEPLOY_COMPILER_DIR" apply --check "$LOCAL_DEPLOY_COMPILER_PATCH" >/dev/null 2>&1; then
    git -C "$LOCAL_DEPLOY_COMPILER_DIR" apply "$LOCAL_DEPLOY_COMPILER_PATCH"
    echo "[local-multichain] resolving compiler lockfile against current multi_chain crates"
    cargo metadata --manifest-path "$LOCAL_DEPLOY_COMPILER_DIR/Cargo.toml" --format-version 1 >/dev/null
    git -C "$LOCAL_DEPLOY_COMPILER_DIR" add Cargo.toml Cargo.lock
    git -C "$LOCAL_DEPLOY_COMPILER_DIR" \
      -c user.name='Psy Local Deploy' -c user.email='local-deploy@invalid' \
      commit -m 'local deploy: use current psy-node crates' >/dev/null
  elif ! git -C "$LOCAL_DEPLOY_COMPILER_DIR" apply --reverse --check "$LOCAL_DEPLOY_COMPILER_PATCH" >/dev/null 2>&1; then
    echo "[local-multichain] compiler local-node patch no longer matches mainnet-beta" >&2
    return 1
  fi
  if git -C "$LOCAL_DEPLOY_COMPILER_DIR" apply --check "$LOCAL_DEPLOY_COMPILER_API_PATCH" >/dev/null 2>&1; then
    git -C "$LOCAL_DEPLOY_COMPILER_DIR" apply "$LOCAL_DEPLOY_COMPILER_API_PATCH"
    git -C "$LOCAL_DEPLOY_COMPILER_DIR" add psy-interpreter/src/lib.rs
    git -C "$LOCAL_DEPLOY_COMPILER_DIR" \
      -c user.name='Psy Local Deploy' -c user.email='local-deploy@invalid' \
      commit -m 'local deploy: adapt compiler to multi-chain VM API' >/dev/null
  elif ! git -C "$LOCAL_DEPLOY_COMPILER_DIR" apply --reverse --check "$LOCAL_DEPLOY_COMPILER_API_PATCH" >/dev/null 2>&1; then
    echo "[local-multichain] compiler VM API compatibility patch no longer matches" >&2
    return 1
  fi
  if [ -n "$(git -C "$LOCAL_DEPLOY_COMPILER_DIR" status --porcelain)" ]; then
    echo "[local-multichain] deployment-local psy-compiler is unexpectedly dirty" >&2
    git -C "$LOCAL_DEPLOY_COMPILER_DIR" status --short >&2
    return 1
  fi
}

local_deploy_restore_genesis_stamp() {
  if [ -f "$LOCAL_DEPLOY_GENESIS_STAMP_BACKUP" ]; then
    cp "$LOCAL_DEPLOY_GENESIS_STAMP_BACKUP" "$LOCAL_DEPLOY_GENESIS_STAMP"
    rm -f "$LOCAL_DEPLOY_GENESIS_STAMP_BACKUP"
  fi
}

local_deploy_prepare_genesis_stamp() {
  local_deploy_restore_genesis_stamp
  if [ -f "$LOCAL_DEPLOY_GENESIS_STAMP" ]; then
    mkdir -p "$LOCAL_DEPLOY_STATE_DIR"
    cp "$LOCAL_DEPLOY_GENESIS_STAMP" "$LOCAL_DEPLOY_GENESIS_STAMP_BACKUP"
    rm -f "$LOCAL_DEPLOY_GENESIS_STAMP"
  fi
}

local_deploy_prepare_node() {
  local_deploy_restore_node
  if git -C "$PSY_NODE_DIR" apply --check "$LOCAL_DEPLOY_NODE_PATCH" >/dev/null 2>&1; then
    git -C "$PSY_NODE_DIR" apply "$LOCAL_DEPLOY_NODE_PATCH"
  elif ! git -C "$PSY_NODE_DIR" apply --reverse --check "$LOCAL_DEPLOY_NODE_PATCH" >/dev/null 2>&1; then
    echo "[local-multichain] runtime projects patch no longer matches the multi_chain checkout" >&2
    return 1
  fi
  if git -C "$PSY_NODE_DIR" apply --check "$LOCAL_DEPLOY_ENVIO_PATCH" >/dev/null 2>&1; then
    git -C "$PSY_NODE_DIR" apply "$LOCAL_DEPLOY_ENVIO_PATCH"
  elif ! git -C "$PSY_NODE_DIR" apply --reverse --check "$LOCAL_DEPLOY_ENVIO_PATCH" >/dev/null 2>&1; then
    echo "[local-multichain] Envio port patch no longer matches the multi_chain checkout" >&2
    return 1
  fi
  if git -C "$PSY_NODE_DIR" apply --check "$LOCAL_DEPLOY_ENVIO_NODE_PATCH" >/dev/null 2>&1; then
    git -C "$PSY_NODE_DIR" apply "$LOCAL_DEPLOY_ENVIO_NODE_PATCH"
  elif ! git -C "$PSY_NODE_DIR" apply --reverse --check "$LOCAL_DEPLOY_ENVIO_NODE_PATCH" >/dev/null 2>&1; then
    echo "[local-multichain] Envio Node compatibility patch no longer matches" >&2
    return 1
  fi
}

local_deploy_prepare_dapp() {
  local_deploy_restore_dapp
  mkdir -p "$LOCAL_DEPLOY_STATE_DIR"
  cp "$LOCAL_DEPLOY_DAPP_CONFIG" "$LOCAL_DEPLOY_DAPP_CONFIG_BACKUP"

  jq \
    --arg coordinator "$(local_deploy_url "$LOCAL_CF_COORDINATOR_HOST")" \
    --arg realm0 "$(local_deploy_url "$LOCAL_CF_REALM0_HOST")" \
    --arg realm1 "$(local_deploy_url "$LOCAL_CF_REALM1_HOST")" \
    --arg prove "$(local_deploy_url "$LOCAL_CF_PROVE_HOST")" \
    --arg faucet "$(local_deploy_url "$LOCAL_CF_FAUCET_HOST")" \
    --arg services "$(local_deploy_url "$LOCAL_CF_SERVICES_HOST")" \
    --arg indexer "$(local_deploy_url "$LOCAL_CF_INDEXER_HOST")/v1/graphql" \
    --arg explorer "$(local_deploy_url "$LOCAL_CF_EXPLORER_HOST")" \
    --arg nostr "wss://${LOCAL_CF_NOSTR_HOST}/" \
    --arg l1rpc "$(local_deploy_rpc_url "$LOCAL_CF_ETH_RPC_HOST" 31337)" \
    --arg bridge "$(local_deploy_url "$LOCAL_CF_APP_HOST")" \
    '
      .defaultNetwork = "localhost"
      | .networks.localhost.coordinator_configs = [{id: 0, rpc_url: [$coordinator]}]
      | .networks.localhost.realm_configs = [
          {id: 0, rpc_url: [$realm0]},
          {id: 1, rpc_url: [$realm1]}
        ]
      | .networks.localhost.prove_proxy_url = [$prove]
      | .networks.localhost.faucet_rpc_url = [$faucet]
      | .networks.localhost.api_services_url = [$services]
      | .networks.localhost.indexer_graphql_url = [$indexer]
      | .networks.localhost.explorer_url = [$explorer]
      | .networks.localhost.nostr_relay_url = $nostr
      | .networks.localhost.l1_rpc_urls = [$l1rpc]
      | .networks.localhost.l1_chain_id = 31337
      | .networks.localhost.bridge_url = [$bridge]
      | .networks.localhost.l1_config_url = ($bridge + "/config.json")
    ' "$LOCAL_DEPLOY_DAPP_CONFIG_BACKUP" > "$LOCAL_DEPLOY_PUBLIC_CONFIG"
  cp "$LOCAL_DEPLOY_PUBLIC_CONFIG" "$LOCAL_DEPLOY_DAPP_CONFIG"

  if git -C "$PSY_NODE_DIR/psy-dapp" apply --check "$LOCAL_DEPLOY_DAPP_PATCH" >/dev/null 2>&1; then
    git -C "$PSY_NODE_DIR/psy-dapp" apply "$LOCAL_DEPLOY_DAPP_PATCH"
  elif ! git -C "$PSY_NODE_DIR/psy-dapp" apply --reverse --check "$LOCAL_DEPLOY_DAPP_PATCH" >/dev/null 2>&1; then
    echo "[local-multichain] DApp public RPC patch no longer matches the multi_chain checkout" >&2
    return 1
  fi
  if git -C "$PSY_NODE_DIR/psy-dapp" apply --check "$LOCAL_DEPLOY_DAPP_HOSTS_PATCH" >/dev/null 2>&1; then
    git -C "$PSY_NODE_DIR/psy-dapp" apply "$LOCAL_DEPLOY_DAPP_HOSTS_PATCH"
  elif ! git -C "$PSY_NODE_DIR/psy-dapp" apply --reverse --check "$LOCAL_DEPLOY_DAPP_HOSTS_PATCH" >/dev/null 2>&1; then
    echo "[local-multichain] DApp public host patch no longer matches the multi_chain checkout" >&2
    return 1
  fi
}
