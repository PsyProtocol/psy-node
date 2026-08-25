#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=deploy/bsc-testnet/lib.sh
source "$(dirname "$0")/lib.sh"

if ! pid_is_running; then
  echo "[bsc-testnet] Anvil is not running"
  exit 0
fi

pid="$(read_pid)"
kill "$pid"
for _ in $(seq 1 40); do
  kill -0 "$pid" 2>/dev/null || break
  sleep 0.25
done
kill -0 "$pid" 2>/dev/null && die "Anvil pid $pid did not stop"
rm -f "$BSC_ANVIL_PID_FILE"
echo "[bsc-testnet] Anvil stopped; state retained at $BSC_ANVIL_STATE_FILE"
