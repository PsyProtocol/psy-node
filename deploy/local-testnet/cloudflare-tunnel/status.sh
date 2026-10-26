#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

jsonrpc_check() {
  local label="$1"
  local url="$2"
  local method="${3:-psy_get_latest_checkpoint_id}"
  printf '%-14s %s ' "$label" "$url"
  if curl -fsS --max-time 10 \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":[]}" \
    "$url" | jq -e '.error == null and has("result")' >/dev/null; then
    echo "ok"
  else
    echo "failed"
  fi
}

jsonrpc_missing_check() {
  local label="$1"
  local url="$2"
  local method="$3"
  printf '%-14s %s ' "$label" "$url"
  if curl -fsS --max-time 10 \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":[]}" \
    "$url" | jq -e '.error.code == -32601' >/dev/null; then
    echo "ok method-not-found"
  else
    echo "failed"
  fi
}

http_check() {
  local label="$1"
  local url="$2"
  printf '%-14s %s ' "$label" "$url"
  if curl -fsS --max-time 10 "$url" >/dev/null; then
    echo "ok"
  else
    echo "failed"
  fi
}

nostr_check() {
  local label="$1"
  local url="$2"
  printf '%-14s %s ' "$label" "$url"
  if curl -fsS --max-time 10 \
    -H 'accept: application/nostr+json' \
    "$url" | jq -e '.name == "psy-local-devnet-nostr"' >/dev/null; then
    echo "ok"
  else
    echo "failed"
  fi
}

pid_check() {
  local label="$1"
  local pid_file="$2"
  local pid

  printf '%-14s ' "$label"
  if [ -f "$pid_file" ]; then
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
      echo "ok pid=$pid"
      return 0
    fi
  fi
  echo "failed"
}

pid_check cloudflared "$PARTH_DIR/.local-staging/pids/cloudflared.pid"
http_check app "$(local_cf_url "$LOCAL_CF_APP_HOST")"
http_check explorer "$(local_cf_url "$LOCAL_CF_EXPLORER_HOST")"
http_check ide "$(local_cf_url "$LOCAL_CF_IDE_HOST")"
jsonrpc_check coordinator "$(local_cf_url "$LOCAL_CF_COORDINATOR_HOST")"
jsonrpc_check realm0 "$(local_cf_url "$LOCAL_CF_REALM0_HOST")"
jsonrpc_check realm1 "$(local_cf_url "$LOCAL_CF_REALM1_HOST")"
jsonrpc_check prove "$(local_cf_url "$LOCAL_CF_PROVE_HOST")" "psy_get_circuits_data"
jsonrpc_missing_check prove-boundary "$(local_cf_url "$LOCAL_CF_PROVE_HOST")" "psy_get_psy_faucet_config"
jsonrpc_check faucet "$(local_cf_url "$LOCAL_CF_FAUCET_HOST")" "psy_get_psy_faucet_config"
http_check services "$(local_cf_url "$LOCAL_CF_SERVICES_HOST")/health"
http_check indexer "$(local_cf_url "$LOCAL_CF_INDEXER_HOST")/healthz"
jsonrpc_check l1-rpc "$(local_cf_url "$LOCAL_CF_L1_RPC_HOST")" "eth_chainId"
http_check app-faucet "$(local_cf_url "$LOCAL_CF_APP_HOST")/eth-faucet/health"
http_check eth-faucet "$(local_cf_url "$LOCAL_CF_ETH_FAUCET_HOST")/health"
nostr_check nostr "$(local_cf_url "$LOCAL_CF_NOSTR_HOST")/"

find_envio_worker_pid() {
  local envio_dir="$1"
  {
    pgrep -f "$envio_dir/.*/envio dev --config ./config.yaml" || true
    pgrep -f "$envio_dir/generated/.*/ts-node/.*/bin.js src/Index.res.js" || true
  } | sort -u | head -1 || true
}

envio_pid_file="$PARTH_DIR/.local-staging/pids/envio.pid"
envio_log_file="$PARTH_DIR/.local-staging/logs/envio.log"
envio_err_file="$PARTH_DIR/.local-staging/logs/envio.err.log"
envio_worker_pid="$(find_envio_worker_pid "$PARTH_DIR/psy_cli/psy_relayer_cli/indexer/envio")"
printf '%-14s ' "envio-worker"
if [ -f "$envio_pid_file" ] && envio_pid="$(cat "$envio_pid_file" 2>/dev/null)" && [ -n "$envio_pid" ] && kill -0 "$envio_pid" >/dev/null 2>&1; then
  if [ -f "$envio_err_file" ] && tail -80 "$envio_err_file" | rg -q 'ELIFECYCLE|Command failed|Reorg threshold reached|Error:'; then
    echo "unhealthy pid=$envio_pid"
    tail -40 "$envio_err_file" || true
  else
    echo "ok pid=$envio_pid"
  fi
elif [ -n "$envio_worker_pid" ] && kill -0 "$envio_worker_pid" >/dev/null 2>&1; then
  echo "$envio_worker_pid" > "$envio_pid_file"
  if [ -f "$envio_err_file" ] && tail -80 "$envio_err_file" | rg -q 'ELIFECYCLE|Command failed|Reorg threshold reached|Error:'; then
    echo "unhealthy pid=$envio_worker_pid"
    tail -40 "$envio_err_file" || true
  else
    echo "ok pid=$envio_worker_pid"
  fi
else
  echo "failed"
  if [ -f "$envio_log_file" ]; then
    tail -60 "$envio_log_file" || true
  fi
  if [ -f "$envio_err_file" ]; then
    tail -40 "$envio_err_file" || true
  fi
fi

if [ "${LOCAL_CF_AUTODEPLOY_ENABLED:-0}" = "1" ]; then
  autodeploy_service="${LOCAL_CF_AUTODEPLOY_SERVICE_NAME:-parth-local-frontend-autodeploy}"
  autodeploy_state_dir="${LOCAL_CF_AUTODEPLOY_STATE_DIR:-$LOCAL_CF_LIVE_PARTH_DIR/.local-staging-cf-tunnel/autodeploy}"
  printf '%-14s ' "frontend-auto"
  if systemctl --user is-active --quiet "$autodeploy_service.timer"; then
    current_release="$(cat "$LOCAL_CF_LIVE_PARTH_DIR/.local-staging/nginx/html/frontend-release.current" 2>/dev/null || true)"
    current_source="$(jq -r '.sourceKey // empty' "$autodeploy_state_dir/current-source.json" 2>/dev/null || true)"
    last_success="$(jq -r '.sourceKey // empty' "$autodeploy_state_dir/last-success.json" 2>/dev/null || true)"
    last_failure="$(jq -r '.sourceKey // empty' "$autodeploy_state_dir/last-failure.json" 2>/dev/null || true)"
    last_blocked="$(jq -r '.sourceKey // empty' "$autodeploy_state_dir/last-blocked.json" 2>/dev/null || true)"
    if [ -n "$last_blocked" ] && [ "$last_blocked" = "$current_source" ]; then
      echo "waiting backend-update timer=active release=${current_release:-unknown} source=$last_blocked"
    elif [ -n "$last_failure" ] && [ "$last_failure" != "$last_success" ]; then
      echo "unhealthy timer=active release=${current_release:-unknown} last_source_failed=$last_failure"
    else
      echo "ok timer=active release=${current_release:-unknown}"
    fi
  else
    echo "failed timer=inactive"
  fi
fi

pid_file="$PARTH_DIR/.local-staging/pids/bridge-relayer.pid"
log_file="$PARTH_DIR/.local-staging/logs/bridge-relayer.log"
state_file="${LOCAL_STAGING_RELAYER_PROOF_DIR:-$PARTH_DIR/.local-staging/bridge-relayer}/daemon_state.toml"
printf '%-14s ' "relayer"
if [ -f "$pid_file" ] && pid="$(cat "$pid_file" 2>/dev/null)" && [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
  if [ -f "$log_file" ] && tail -120 "$log_file" | rg -q 'ERROR|bridge daemon .*failed|constraint #[0-9]+ is not satisfied|bridge aggregation requires at least'; then
    echo "unhealthy pid=$pid"
  else
    echo "ok pid=$pid"
  fi
  latest="$(curl -fsS --max-time 10 \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_latest_checkpoint_id","params":[]}' \
    "http://127.0.0.1:${LOCAL_STAGING_COORDINATOR_EDGE_PORT}" \
    | jq -er '.result' 2>/dev/null || true)"
  finalized="$(sed -n 's/^last_finalized_checkpoint = \([0-9][0-9]*\)$/\1/p' "$state_file" 2>/dev/null | head -1)"
  if [[ "$latest" =~ ^[0-9]+$ ]] && [[ "$finalized" =~ ^[0-9]+$ ]]; then
    confirmation_lag="${LOCAL_STAGING_RELAYER_CONFIRMATION_LAG_CHECKPOINTS:-1}"
    max_checkpoint_batch="${LOCAL_STAGING_RELAYER_MAX_CHECKPOINT_BATCH:-32}"
    if [ "$latest" -gt $((finalized + confirmation_lag)) ]; then
      confirmed_backlog=$((latest - confirmation_lag - finalized))
    else
      confirmed_backlog=0
    fi
    if [ "$confirmed_backlog" -le "$max_checkpoint_batch" ]; then
      echo "relayer-sync   ready finalized=$finalized latest=$latest confirmed_backlog=$confirmed_backlog"
    else
      echo "relayer-sync   catching-up finalized=$finalized latest=$latest confirmed_backlog=$confirmed_backlog target<=${max_checkpoint_batch}"
    fi
  else
    echo "relayer-sync   unavailable"
  fi
  if [ -f "$log_file" ]; then
    tail -40 "$log_file" | rg 'bridge relayer checkpoint window|bridge deposit cursor sync|bridge daemon finalized round|bridge daemon .*failed|ERROR|WARN' || true
  fi
else
  echo "failed"
  if [ -f "$log_file" ]; then
    rg 'bridge relayer started|bridge relayer warmup complete|Bridge aggregation proof generated successfully|bridge daemon finalized round|bridge daemon .*failed|generate_groth16_proof failed|constraint #[0-9]+ is not satisfied|bridge aggregation requires at least|ERROR|WARN' "$log_file" | tail -40 || true
  fi
fi
