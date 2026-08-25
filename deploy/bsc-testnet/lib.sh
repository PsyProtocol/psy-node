#!/usr/bin/env bash
set -euo pipefail

BSC_DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARTH_ROOT="$(cd "$BSC_DEPLOY_DIR/../.." && pwd)"

if [ -f "$BSC_DEPLOY_DIR/local.env" ]; then
  # shellcheck disable=SC1091
  source "$BSC_DEPLOY_DIR/local.env"
fi

: "${BSC_LOCAL_CHAIN_ID:=97}"
: "${BSC_LOCAL_RPC_HOST:=127.0.0.1}"
: "${BSC_LOCAL_RPC_PORT:=18545}"
: "${BSC_LOCAL_BLOCK_TIME:=1}"
: "${BSC_LOCAL_STATE_ROOT:=$PARTH_ROOT/.local-bsc-testnet}"
: "${PSY_CONTRACTS_DIR:=$PARTH_ROOT/psy-contracts}"
: "${BSC_LOCAL_DEPLOY_PRIVATE_KEY:=ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

# These paths are consumed by scripts that source this library.
# shellcheck disable=SC2034
BSC_LOCAL_RPC_URL="http://${BSC_LOCAL_RPC_HOST}:${BSC_LOCAL_RPC_PORT}"
# shellcheck disable=SC2034
BSC_ANVIL_PID_FILE="$BSC_LOCAL_STATE_ROOT/anvil.pid"
# shellcheck disable=SC2034
BSC_ANVIL_LOG_FILE="$BSC_LOCAL_STATE_ROOT/logs/anvil.log"
# shellcheck disable=SC2034
BSC_ANVIL_STATE_FILE="$BSC_LOCAL_STATE_ROOT/anvil/state.json"
# shellcheck disable=SC2034
BSC_DEPLOYMENT_FILE="$PSY_CONTRACTS_DIR/deployments/bsc-testnet/deployed-contracts.json"
# shellcheck disable=SC2034
BSC_EVIDENCE_DIR="$BSC_LOCAL_STATE_ROOT/evidence"

die() {
  echo "[bsc-testnet] $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

require_local_transaction_authorization() {
  [ "${AUTHORIZED_BSC_LOCAL_TRANSACTIONS:-0}" = "1" ] ||
    die "set AUTHORIZED_BSC_LOCAL_TRANSACTIONS=1 to authorize local chain transactions"
}

rpc_call() {
  local method="$1"
  local params="${2:-[]}"
  curl -fsS --max-time 5 \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\",\"params\":${params}}" \
    "$BSC_LOCAL_RPC_URL"
}

probe_bsc_local_rpc() {
  local chain_hex chain_decimal
  chain_hex="$(rpc_call eth_chainId 2>/dev/null | jq -er '.result' 2>/dev/null)" || return 1
  chain_decimal="$((chain_hex))"
  [ "$chain_decimal" -eq "$BSC_LOCAL_CHAIN_ID" ]
}

require_bsc_local_rpc() {
  probe_bsc_local_rpc || die "BSC local RPC at $BSC_LOCAL_RPC_URL is unavailable or does not use chain ID $BSC_LOCAL_CHAIN_ID"
}

read_pid() {
  [ -s "$BSC_ANVIL_PID_FILE" ] || return 1
  cat "$BSC_ANVIL_PID_FILE"
}

pid_is_running() {
  local pid
  pid="$(read_pid 2>/dev/null || true)"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}
