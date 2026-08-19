#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

[ "${LOCAL_CF_START_RELAYER:-1}" = "1" ] || exit 0

pid_file="$PARTH_DIR/.local-staging/pids/bridge-relayer.pid"
state_file="${LOCAL_STAGING_RELAYER_PROOF_DIR:-$PARTH_DIR/.local-staging/bridge-relayer}/daemon_state.toml"
log_file="$PARTH_DIR/.local-staging/logs/bridge-relayer.log"
timeout_secs="${LOCAL_STAGING_RELAYER_READY_TIMEOUT_SECS:-14400}"
poll_secs="${LOCAL_STAGING_RELAYER_READY_POLL_SECS:-5}"
max_checkpoint_batch="${LOCAL_STAGING_RELAYER_MAX_CHECKPOINT_BATCH:-32}"
confirmation_lag="${LOCAL_STAGING_RELAYER_CONFIRMATION_LAG_CHECKPOINTS:-1}"
deadline=$((SECONDS + timeout_secs))
attempts=0

echo "[local-cf-tunnel] waiting for bridge relayer to leave catchup mode"
while [ "$SECONDS" -lt "$deadline" ]; do
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [ -z "$pid" ] || ! kill -0 "$pid" >/dev/null 2>&1; then
    echo "[local-cf-tunnel] bridge relayer exited while catching up" >&2
    tail -120 "$log_file" >&2 || true
    exit 1
  fi

  latest="$(curl -fsS --max-time 10 \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_latest_checkpoint_id","params":[]}' \
    "http://127.0.0.1:${LOCAL_STAGING_COORDINATOR_EDGE_PORT}" \
    | jq -er '.result' 2>/dev/null || true)"
  finalized="$(sed -n 's/^last_finalized_checkpoint = \([0-9][0-9]*\)$/\1/p' "$state_file" 2>/dev/null | head -1)"

  if [[ "$latest" =~ ^[0-9]+$ ]] && [[ "$finalized" =~ ^[0-9]+$ ]]; then
    if [ "$latest" -gt $((finalized + confirmation_lag)) ]; then
      confirmed_backlog=$((latest - confirmation_lag - finalized))
    else
      confirmed_backlog=0
    fi

    if [ "$confirmed_backlog" -le "$max_checkpoint_batch" ]; then
      echo "[local-cf-tunnel] ready: bridge relayer finalized=$finalized latest=$latest confirmed_backlog=$confirmed_backlog"
      exit 0
    fi

    if [ $((attempts % 12)) -eq 0 ]; then
      echo "[local-cf-tunnel] bridge relayer catching up: finalized=$finalized latest=$latest confirmed_backlog=$confirmed_backlog target<=${max_checkpoint_batch}"
    fi
  elif [ $((attempts % 12)) -eq 0 ]; then
    echo "[local-cf-tunnel] bridge relayer state is not available yet"
  fi

  attempts=$((attempts + 1))
  sleep "$poll_secs"
done

echo "[local-cf-tunnel] timed out waiting for bridge relayer to leave catchup mode after ${timeout_secs}s" >&2
tail -120 "$log_file" >&2 || true
exit 1
