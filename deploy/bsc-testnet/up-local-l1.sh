#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=deploy/bsc-testnet/lib.sh
source "$(dirname "$0")/lib.sh"

require_command anvil
require_command curl
require_command jq

if pid_is_running; then
  require_bsc_local_rpc
  echo "[bsc-testnet] Anvil is already running: pid=$(read_pid) rpc=$BSC_LOCAL_RPC_URL chain_id=$BSC_LOCAL_CHAIN_ID"
  exit 0
fi

mkdir -p "$(dirname "$BSC_ANVIL_LOG_FILE")" "$(dirname "$BSC_ANVIL_STATE_FILE")" "$BSC_EVIDENCE_DIR"

if [ "${BSC_LOCAL_RESET:-0}" = "1" ]; then
  require_local_transaction_authorization
  rm -f "$BSC_ANVIL_STATE_FILE"
fi

anvil_args=(
  --host "$BSC_LOCAL_RPC_HOST"
  --port "$BSC_LOCAL_RPC_PORT"
  --chain-id "$BSC_LOCAL_CHAIN_ID"
  --block-time "$BSC_LOCAL_BLOCK_TIME"
  --state "$BSC_ANVIL_STATE_FILE"
  --silent
)

if command -v setsid >/dev/null 2>&1; then
  nohup setsid anvil "${anvil_args[@]}" \
    </dev/null >"$BSC_ANVIL_LOG_FILE" 2>&1 &
else
  nohup anvil "${anvil_args[@]}" \
    </dev/null >"$BSC_ANVIL_LOG_FILE" 2>&1 &
fi
pid=$!
printf '%s\n' "$pid" > "$BSC_ANVIL_PID_FILE"

for _ in $(seq 1 40); do
  if probe_bsc_local_rpc; then
    echo "[bsc-testnet] Anvil ready: pid=$pid rpc=$BSC_LOCAL_RPC_URL chain_id=$BSC_LOCAL_CHAIN_ID"
    exit 0
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    tail -n 80 "$BSC_ANVIL_LOG_FILE" >&2 || true
    die "Anvil exited before becoming ready"
  fi
  sleep 0.25
done

tail -n 80 "$BSC_ANVIL_LOG_FILE" >&2 || true
die "timed out waiting for Anvil at $BSC_LOCAL_RPC_URL"
