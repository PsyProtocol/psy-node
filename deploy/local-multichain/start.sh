#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

fresh=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-build) LOCAL_DEPLOY_BUILD=0 ;;
    --build) LOCAL_DEPLOY_BUILD=1 ;;
    --fresh) fresh=1 ;;
    -h|--help)
      echo "Usage: $0 [--build|--no-build] [--fresh]"
      exit 0
      ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

for command_name in bash bun cargo curl docker git jq make node pnpm python3; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "[local-multichain] missing command: $command_name" >&2
    exit 1
  }
done
docker info >/dev/null

git -C "$PSY_NODE_DIR" merge-base --is-ancestor origin/multi_chain HEAD || {
  echo "[local-multichain] HEAD does not contain origin/multi_chain" >&2
  exit 1
}
git -C "$PSY_NODE_DIR" submodule status --recursive | grep -q '^-' && {
  echo "[local-multichain] initialize all psy-node submodules before deployment" >&2
  exit 1
}

mkdir -p "$LOCAL_DEPLOY_PID_DIR" "$LOCAL_DEPLOY_LOG_DIR"

echo "[local-multichain] stopping the previous runtime while preserving state"
bash "$SCRIPT_DIR/stop.sh"

if [ "$fresh" = "1" ]; then
  echo "[local-multichain] purging local chain/database state by explicit request"
  (cd "$PSY_NODE_DIR" && bun run dev/locSetupV4.ts --teardown --purge)
  rm -rf \
    "$PSY_NODE_DIR/psy-contracts/deployments/localhostBsc" \
    "$PSY_NODE_DIR/psy-contracts/deployments/localhostBase"
fi

echo "[local-multichain] preparing deployment-only runtime overlays"
local_deploy_prepare_services
local_deploy_prepare_node
local_deploy_prepare_compiler
local_deploy_prepare_genesis_stamp
local_deploy_prepare_dapp
local_deploy_render_tunnel_config

if [ "$LOCAL_DEPLOY_BUILD" = "1" ]; then
  echo "[local-multichain] release binaries will be rebuilt by the native launcher"
  PSY_SKIP_BUILD=0
else
  PSY_SKIP_BUILD=1
fi

echo "[local-multichain] starting native multi_chain devnet"
export VITE_NETWORK=localhost
export VITE_FORK=false
VITE_PSY_CONFIG_URL="$(local_deploy_url "$LOCAL_CF_CONFIG_HOST")"
export VITE_PSY_CONFIG_URL
export PSY_SKIP_BRANCH_CHECK=1
export PSY_SKIP_KEYSTORE="${PSY_SKIP_KEYSTORE:-1}"
export PSY_SKIP_BUILD
export PSY_PROJECTS_DIR="$LOCAL_DEPLOY_STATE_DIR/projects"
export PSY_ENVIO_HASURA_PORT="$LOCAL_DEPLOY_ENVIO_PORT"
export HASURA_EXTERNAL_PORT="$LOCAL_DEPLOY_ENVIO_PORT"
VITE_LOCALHOST_ETH_RPC_URL="$(local_deploy_rpc_url "$LOCAL_CF_ETH_RPC_HOST" 31337)"
VITE_LOCALHOST_BSC_RPC_URL="$(local_deploy_rpc_url "$LOCAL_CF_BSC_RPC_HOST" 31338)"
VITE_LOCALHOST_BASE_RPC_URL="$(local_deploy_rpc_url "$LOCAL_CF_BASE_RPC_HOST" 31339)"
export VITE_LOCALHOST_ETH_RPC_URL VITE_LOCALHOST_BSC_RPC_URL VITE_LOCALHOST_BASE_RPC_URL

if command -v setsid >/dev/null 2>&1; then
  setsid make -C "$PSY_NODE_DIR" run-all >"$LOCAL_DEPLOY_LOG_DIR/devnet.log" 2>&1 &
else
  nohup make -C "$PSY_NODE_DIR" run-all >"$LOCAL_DEPLOY_LOG_DIR/devnet.log" 2>&1 &
fi
echo "$!" > "$LOCAL_DEPLOY_PID_DIR/devnet.pid"

wait_jsonrpc() {
  local label="$1" port="$2" method="$3" deadline=$((SECONDS + LOCAL_DEPLOY_START_TIMEOUT_SECONDS))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if ! local_deploy_pid_alive "$LOCAL_DEPLOY_PID_DIR/devnet.pid"; then
      echo "[local-multichain] devnet exited while waiting for $label" >&2
      tail -160 "$LOCAL_DEPLOY_LOG_DIR/devnet.log" >&2 || true
      return 1
    fi
    if curl -fsS --max-time 3 -H 'content-type: application/json' \
      --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":[]}" \
      "http://127.0.0.1:$port" 2>/dev/null | jq -e 'has("result") and .error == null' >/dev/null 2>&1; then
      echo "[local-multichain] ready: $label"
      return 0
    fi
    sleep 2
  done
  echo "[local-multichain] timed out waiting for $label" >&2
  return 1
}

wait_http() {
  local label="$1" url="$2" deadline=$((SECONDS + LOCAL_DEPLOY_START_TIMEOUT_SECONDS))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if ! local_deploy_pid_alive "$LOCAL_DEPLOY_PID_DIR/devnet.pid"; then
      echo "[local-multichain] devnet exited while waiting for $label" >&2
      tail -160 "$LOCAL_DEPLOY_LOG_DIR/devnet.log" >&2 || true
      return 1
    fi
    if curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
      echo "[local-multichain] ready: $label"
      return 0
    fi
    sleep 2
  done
  echo "[local-multichain] timed out waiting for $label" >&2
  return 1
}

wait_config_page() {
  local deadline=$((SECONDS + LOCAL_DEPLOY_START_TIMEOUT_SECONDS))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if ! local_deploy_pid_alive "$LOCAL_DEPLOY_PID_DIR/config-page.pid"; then
      echo "[local-multichain] Psy Config server exited during startup" >&2
      tail -80 "$LOCAL_DEPLOY_LOG_DIR/config-page.log" >&2 || true
      return 1
    fi
    if curl -fsS --max-time 3 "http://127.0.0.1:${LOCAL_DEPLOY_CONFIG_PAGE_PORT}/health" 2>/dev/null \
      | jq -e '.ok == true and .service == "psy-config-local"' >/dev/null 2>&1; then
      echo "[local-multichain] ready: Psy Config"
      return 0
    fi
    sleep 1
  done
  echo "[local-multichain] timed out waiting for Psy Config" >&2
  return 1
}

wait_jsonrpc "local Ethereum" 8545 eth_chainId
wait_jsonrpc "local BSC" 9545 eth_chainId
wait_jsonrpc "local Base" 10545 eth_chainId
wait_jsonrpc "coordinator" 1337 psy_get_latest_checkpoint_id
wait_http "psy-services" http://127.0.0.1:3000/health
wait_http "Envio" "http://127.0.0.1:${LOCAL_DEPLOY_ENVIO_PORT}/healthz"
wait_http "Bridge app" http://127.0.0.1:5177
wait_http "Explorer" http://127.0.0.1:5178
wait_http "IDE" http://127.0.0.1:5176

local_deploy_start_gas_faucets
local_deploy_render_config_page
local_deploy_start_config_page
wait_config_page

cloudflared_bin="$(local_deploy_cloudflared)"
echo "[local-multichain] starting Cloudflare tunnel $(local_deploy_tunnel_ref)"
if command -v setsid >/dev/null 2>&1; then
  setsid "$cloudflared_bin" tunnel --config "$LOCAL_DEPLOY_CLOUDFLARED_CONFIG" run "$(local_deploy_tunnel_ref)" \
    >"$LOCAL_DEPLOY_LOG_DIR/cloudflared.log" 2>&1 &
else
  nohup "$cloudflared_bin" tunnel --config "$LOCAL_DEPLOY_CLOUDFLARED_CONFIG" run "$(local_deploy_tunnel_ref)" \
    >"$LOCAL_DEPLOY_LOG_DIR/cloudflared.log" 2>&1 &
fi
echo "$!" > "$LOCAL_DEPLOY_PID_DIR/cloudflared.pid"

public_deadline=$((SECONDS + LOCAL_DEPLOY_PUBLIC_TIMEOUT_SECONDS))
while [ "$SECONDS" -lt "$public_deadline" ]; do
  if ! local_deploy_pid_alive "$LOCAL_DEPLOY_PID_DIR/cloudflared.pid"; then
    echo "[local-multichain] cloudflared exited during startup" >&2
    tail -160 "$LOCAL_DEPLOY_LOG_DIR/cloudflared.log" >&2 || true
    exit 1
  fi
  if curl -fsS --max-time 10 "$(local_deploy_url "$LOCAL_CF_APP_HOST")" >/dev/null 2>&1 \
    && curl -fsS --max-time 10 -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
      "$(local_deploy_url "$LOCAL_CF_BASE_RPC_HOST")" | jq -e '.result == "0x7a6b"' >/dev/null 2>&1; then
    echo "[local-multichain] public tunnel is ready"
    bash "$SCRIPT_DIR/status.sh"
    exit 0
  fi
  sleep 3
done

echo "[local-multichain] timed out waiting for public Cloudflare routes" >&2
tail -160 "$LOCAL_DEPLOY_LOG_DIR/cloudflared.log" >&2 || true
exit 1
