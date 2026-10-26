#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

local_cf_ensure_cloudflared
local_cf_render_cloudflared_config

PID_DIR="$PARTH_DIR/.local-staging/pids"
LOG_DIR="$PARTH_DIR/.local-staging/logs"
PID_FILE="$PID_DIR/cloudflared.pid"
LOG_FILE="$LOG_DIR/cloudflared.log"
CONFIG_STAMP="$PARTH_DIR/.local-staging/cloudflared-config.sha256"

mkdir -p "$PID_DIR" "$LOG_DIR"

if [ -f "$PID_FILE" ]; then
  old_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [ -n "$old_pid" ] && kill -0 "$old_pid" >/dev/null 2>&1; then
    echo "[local-cf-tunnel] stopping cloudflared pid=$old_pid"
    kill -- "-$old_pid" >/dev/null 2>&1 || kill "$old_pid" >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do
      kill -0 "$old_pid" >/dev/null 2>&1 || break
      sleep 1
    done
  fi
  rm -f "$PID_FILE"
fi

echo "[local-cf-tunnel] starting cloudflared -> $LOG_FILE"
if command -v setsid >/dev/null 2>&1; then
  setsid bash "$SCRIPT_DIR/run-tunnel.sh" > "$LOG_FILE" 2>&1 &
else
  nohup bash "$SCRIPT_DIR/run-tunnel.sh" > "$LOG_FILE" 2>&1 &
fi
echo "$!" > "$PID_FILE"

for _ in $(seq 1 60); do
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [ -z "$pid" ] || ! kill -0 "$pid" >/dev/null 2>&1; then
    echo "[local-cf-tunnel] cloudflared exited during startup" >&2
    tail -120 "$LOG_FILE" >&2 || true
    exit 1
  fi

  if curl -fsS --max-time 10 \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_psy_faucet_config","params":[]}' \
    "$(local_cf_url "$LOCAL_CF_FAUCET_HOST")" \
    | jq -e '.error == null and .result.enabled == true' >/dev/null 2>&1; then
    sha256sum "$LOCAL_CF_CONFIG_FILE" | awk '{print $1}' > "$CONFIG_STAMP"
    echo "[local-cf-tunnel] ready: $(local_cf_url "$LOCAL_CF_FAUCET_HOST")"
    exit 0
  fi
  sleep 2
done

echo "[local-cf-tunnel] timed out waiting for public faucet endpoint" >&2
tail -120 "$LOG_FILE" >&2 || true
exit 1
