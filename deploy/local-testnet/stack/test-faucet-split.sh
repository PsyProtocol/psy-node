#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARTH_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"
local_staging_source_env_defaults "$SCRIPT_DIR/local.env"

: "${LOCAL_STAGING_STATE_DIR:=$PARTH_DIR/.local-staging}"
: "${LOCAL_STAGING_PROVE_PROXY_ADDR:=127.0.0.1:9999}"
: "${LOCAL_STAGING_FAUCET_ADDR:=127.0.0.1:9998}"
: "${LOCAL_STAGING_RPC_CONFIG:=$PARTH_DIR/client_prover/config.json}"

jsonrpc() {
  local url="$1"
  local method="$2"
  curl -fsS --max-time 30 "$url" \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":[]}"
}

require_running_pid() {
  local label="$1"
  local pid_file="$LOCAL_STAGING_STATE_DIR/pids/$label.pid"
  local pid

  [ -f "$pid_file" ] || {
    echo "[faucet-split] missing pid file: $pid_file" >&2
    exit 1
  }
  pid="$(cat "$pid_file")"
  kill -0 "$pid" >/dev/null 2>&1 || {
    echo "[faucet-split] process is not running: $label pid=$pid" >&2
    exit 1
  }
  printf '%s\n' "$pid"
}

prove_pid="$(require_running_pid prove-proxy)"
faucet_pid="$(require_running_pid faucet-server)"

jsonrpc "http://$LOCAL_STAGING_PROVE_PROXY_ADDR" psy_get_circuits_data \
  | jq -e '.error == null and has("result")' >/dev/null
jsonrpc "http://$LOCAL_STAGING_PROVE_PROXY_ADDR" psy_get_psy_faucet_config \
  | jq -e '.error.code == -32601' >/dev/null
jsonrpc "http://$LOCAL_STAGING_FAUCET_ADDR" psy_get_psy_faucet_config \
  | jq -e '.error == null and .result.enabled == true' >/dev/null

if tr '\0' '\n' < "/proc/$prove_pid/environ" | grep -q '^PSY_FAUCET_'; then
  echo "[faucet-split] FAIL: prove-proxy received PSY_FAUCET_* environment" >&2
  exit 1
fi
if ! tr '\0' '\n' < "/proc/$faucet_pid/environ" | grep -q '^PSY_FAUCET_OPERATORS_JSON='; then
  echo "[faucet-split] FAIL: faucet-server is missing operator configuration" >&2
  exit 1
fi

prove_url="$(jq -er '.defaultNetwork as $network | .networks[$network].prove_proxy_url[0]' "$LOCAL_STAGING_RPC_CONFIG")"
faucet_url="$(jq -er '.defaultNetwork as $network | .networks[$network].faucet_rpc_url[0]' "$LOCAL_STAGING_RPC_CONFIG")"
if [ "$prove_url" = "$faucet_url" ]; then
  echo "[faucet-split] FAIL: prove_proxy_url and faucet_rpc_url are identical" >&2
  exit 1
fi

echo "[faucet-split] PASS"
echo "  prove-proxy: http://$LOCAL_STAGING_PROVE_PROXY_ADDR pid=$prove_pid"
echo "  faucet:      http://$LOCAL_STAGING_FAUCET_ADDR pid=$faucet_pid"
echo "  config:      $LOCAL_STAGING_RPC_CONFIG"
