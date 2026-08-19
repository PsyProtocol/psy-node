#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARTH_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

local_staging_source_env_defaults "$SCRIPT_DIR/local.env"

: "${LOCAL_STAGING_STATE_DIR:=$PARTH_DIR/.local-staging}"
: "${LOCAL_STAGING_REALMS:=0 1}"
: "${LOCAL_STAGING_COORDINATOR_EDGE_PORT:=1337}"
: "${LOCAL_STAGING_REALM_EDGE_BASE_PORT:=13380}"
: "${LOCAL_STAGING_REALM_EDGE_PORT_STRIDE:=10}"
: "${LOCAL_STAGING_PROVE_PROXY_ADDR:=127.0.0.1:9999}"
: "${LOCAL_STAGING_FAUCET_ADDR:=127.0.0.1:9998}"
: "${LOCAL_STAGING_PSY_SERVICES_ADDR:=127.0.0.1:3000}"
: "${LOCAL_STAGING_APP_PORT:=8088}"
: "${LOCAL_STAGING_EXPLORER_PORT:=8089}"
: "${LOCAL_STAGING_IDE_PORT:=8090}"
: "${LOCAL_NOSTR_PORT:=8081}"

PID_DIR="$LOCAL_STAGING_STATE_DIR/pids"
LOG_DIR="$LOCAL_STAGING_STATE_DIR/logs"

realm_port() {
  local realm_id="$1"
  printf '%s\n' "$(( LOCAL_STAGING_REALM_EDGE_BASE_PORT + realm_id * LOCAL_STAGING_REALM_EDGE_PORT_STRIDE ))"
}

find_envio_worker_pid() {
  local envio_dir="$1"
  {
    pgrep -f "$envio_dir/.*/envio dev --config ./config.yaml" || true
    pgrep -f "$envio_dir/generated/.*/ts-node/.*/bin.js src/Index.res.js" || true
  } | sort -u | head -1 || true
}

print_pid_status() {
  echo "== processes =="
  if [ ! -d "$PID_DIR" ]; then
    echo "no pid directory: $PID_DIR"
    return 0
  fi
  for pid_file in "$PID_DIR"/*.pid; do
    [ -e "$pid_file" ] || continue
    label="$(basename "$pid_file" .pid)"
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
      echo "ok       $label pid=$pid"
    elif [ "$label" = "envio" ]; then
      envio_pid="$(find_envio_worker_pid "$PARTH_DIR/psy_cli/psy_relayer_cli/indexer/envio")"
      if [ -n "$envio_pid" ] && kill -0 "$envio_pid" >/dev/null 2>&1; then
        echo "$envio_pid" > "$pid_file"
        echo "ok       $label pid=$envio_pid"
      else
        echo "stopped  $label"
      fi
    else
      echo "stopped  $label"
    fi
  done
}

check_jsonrpc() {
  local label="$1"
  local url="$2"
  local method="${3:-psy_get_latest_checkpoint_id}"

  printf '%-18s %s ' "$label" "$url"
  if result="$(local_staging_jsonrpc_result "$url" "$method" 2>/dev/null)"; then
    printf 'ok %s\n' "$result"
  else
    printf 'failed\n'
  fi
}

check_jsonrpc_ok() {
  local label="$1"
  local url="$2"
  local method="$3"

  printf '%-18s %s ' "$label" "$url"
  if local_staging_jsonrpc_result "$url" "$method" 2>/dev/null \
    | jq -e '.error == null and has("result")' >/dev/null; then
    echo "ok"
  else
    echo "failed"
  fi
}

check_jsonrpc_missing() {
  local label="$1"
  local url="$2"
  local method="$3"

  printf '%-18s %s ' "$label" "$url"
  if local_staging_jsonrpc_result "$url" "$method" 2>/dev/null \
    | jq -e '.error.code == -32601' >/dev/null; then
    echo "ok method-not-found"
  else
    echo "failed"
  fi
}

print_endpoint_status() {
  echo
  echo "== endpoints =="
  check_jsonrpc "coordinator" "http://127.0.0.1:$LOCAL_STAGING_COORDINATOR_EDGE_PORT"
  local realm_id
  for realm_id in $LOCAL_STAGING_REALMS; do
    check_jsonrpc "realm-$realm_id" "http://127.0.0.1:$(realm_port "$realm_id")"
  done
  check_jsonrpc_ok "prove-proxy" "http://$LOCAL_STAGING_PROVE_PROXY_ADDR" "psy_get_circuits_data"
  check_jsonrpc_missing "prove-boundary" "http://$LOCAL_STAGING_PROVE_PROXY_ADDR" "psy_get_psy_faucet_config"
  check_jsonrpc_ok "faucet-server" "http://$LOCAL_STAGING_FAUCET_ADDR" "psy_get_psy_faucet_config"

  printf '%-18s http://%s ' "psy-services" "$LOCAL_STAGING_PSY_SERVICES_ADDR"
  if curl -fsS --max-time 5 "http://$LOCAL_STAGING_PSY_SERVICES_ADDR/health" >/dev/null 2>&1; then
    echo "ok"
  else
    echo "failed"
  fi

  printf '%-18s http://127.0.0.1:%s ' "nostr relay" "$LOCAL_NOSTR_PORT"
  if curl -fsS --max-time 5 -H 'Accept: application/nostr+json' \
    "http://127.0.0.1:$LOCAL_NOSTR_PORT/" >/dev/null 2>&1; then
    echo "ok"
  else
    echo "failed"
  fi

  printf '%-18s http://127.0.0.1:%s ' "app" "$LOCAL_STAGING_APP_PORT"
  if curl -fsS --max-time 5 "http://127.0.0.1:$LOCAL_STAGING_APP_PORT/" >/dev/null 2>&1; then echo "ok"; else echo "failed"; fi
  printf '%-18s http://127.0.0.1:%s ' "explorer" "$LOCAL_STAGING_EXPLORER_PORT"
  if curl -fsS --max-time 5 "http://127.0.0.1:$LOCAL_STAGING_EXPLORER_PORT/" >/dev/null 2>&1; then echo "ok"; else echo "failed"; fi
  printf '%-18s http://127.0.0.1:%s ' "ide" "$LOCAL_STAGING_IDE_PORT"
  if curl -fsS --max-time 5 "http://127.0.0.1:$LOCAL_STAGING_IDE_PORT/" >/dev/null 2>&1; then echo "ok"; else echo "failed"; fi
}

print_docker_status() {
  echo
  echo "== docker =="
  if ! local_staging_compose "$SCRIPT_DIR" ps; then
    echo "docker compose status unavailable; check Docker permissions or daemon state"
  fi
}

print_tail_hint() {
  echo
  echo "logs:"
  echo "  tail -f $LOG_DIR/*.log"
}

print_pid_status
print_endpoint_status
print_docker_status
print_tail_hint
