#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=deploy/bsc-testnet/full-stack-lib.sh
source "$(dirname "$0")/full-stack-lib.sh"
bsc_full_stack_export

phase="${1:-all}"
case "$phase" in
  l1 | core | bridge | all) ;;
  *) die "usage: $0 [l1|core|bridge|all]" ;;
esac

require_command curl
require_command docker
require_command jq

failures=0

pass() {
  echo "[PASS] $*"
}

fail() {
  echo "[FAIL] $*" >&2
  failures=$((failures + 1))
}

check_pid() {
  local label="$1"
  local pid_file="$LOCAL_STAGING_STATE_DIR/pids/$label.pid"
  local pid=""
  if [ -s "$pid_file" ]; then
    pid="$(cat "$pid_file" 2>/dev/null || true)"
  fi
  if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
    pass "$label process pid=$pid"
  else
    fail "$label process is not running"
  fi
}

check_container() {
  local service="$1"
  local container="${LOCAL_STAGING_CONTAINER_PREFIX}-$service"
  local running
  running="$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)"
  if [ "$running" = "true" ]; then
    pass "$service container"
  else
    fail "$service container is not running ($container)"
  fi
}

jsonrpc_result() {
  local url="$1"
  local method="$2"
  curl -fsS --max-time 10 \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":[]}" \
    "$url" | jq -er 'if .error then error(.error.message) else .result end'
}

checkpoint() {
  jsonrpc_result "$1" psy_get_latest_checkpoint_id
}

check_l1() {
  if bash "$BSC_DEPLOY_DIR/check-local-l1.sh"; then
    pass "local BSC L1 contracts"
  else
    fail "local BSC L1 contracts"
  fi
}

check_core() {
  local service label
  for service in valkey nats scylla postgres nostr; do
    check_container "$service"
  done

  for label in \
    coordinator-processor coordinator-edge coordinator-worker \
    realm-0-processor realm-0-edge realm-0-worker \
    realm-1-processor realm-1-edge realm-1-worker \
    psy-services psy-indexer-coordinator psy-indexer-realm-0 psy-indexer-realm-1 \
    prove-proxy faucet-server; do
    check_pid "$label"
  done

  local coordinator_url="http://127.0.0.1:$LOCAL_STAGING_COORDINATOR_EDGE_PORT"
  local realm0_url="http://127.0.0.1:$LOCAL_STAGING_REALM_EDGE_BASE_PORT"
  local realm1_url="http://127.0.0.1:$((LOCAL_STAGING_REALM_EDGE_BASE_PORT + LOCAL_STAGING_REALM_EDGE_PORT_STRIDE))"
  local before after realm0 realm1 min_height max_height
  local poll_attempts poll_seconds max_skew attempt saw_progress saw_sync
  before="$(checkpoint "$coordinator_url" 2>/dev/null || true)"
  realm0="$(checkpoint "$realm0_url" 2>/dev/null || true)"
  realm1="$(checkpoint "$realm1_url" 2>/dev/null || true)"

  if [[ "$before" =~ ^[0-9]+$ && "$realm0" =~ ^[0-9]+$ && "$realm1" =~ ^[0-9]+$ ]]; then
    poll_attempts="${BSC_LOCAL_CHECKPOINT_POLL_ATTEMPTS:-15}"
    poll_seconds="${BSC_LOCAL_CHECKPOINT_POLL_SECONDS:-2}"
    max_skew="${BSC_LOCAL_CHECKPOINT_MAX_SKEW:-1}"
    saw_progress=0
    saw_sync=0
    after="$before"

    for attempt in $(seq 1 "$poll_attempts"); do
      after="$(checkpoint "$coordinator_url" 2>/dev/null || true)"
      realm0="$(checkpoint "$realm0_url" 2>/dev/null || true)"
      realm1="$(checkpoint "$realm1_url" 2>/dev/null || true)"
      if [[ "$after" =~ ^[0-9]+$ && "$realm0" =~ ^[0-9]+$ && "$realm1" =~ ^[0-9]+$ ]]; then
        [ "$after" -gt "$before" ] && saw_progress=1
        min_height="$after"
        max_height="$after"
        for height in "$realm0" "$realm1"; do
          [ "$height" -lt "$min_height" ] && min_height="$height"
          [ "$height" -gt "$max_height" ] && max_height="$height"
        done
        [ $((max_height - min_height)) -le "$max_skew" ] && saw_sync=1
      fi
      if [ "$saw_progress" = "1" ] && [ "$saw_sync" = "1" ]; then
        break
      fi
      [ "$attempt" -lt "$poll_attempts" ] && sleep "$poll_seconds"
    done

    if [ "$saw_sync" = "1" ]; then
      pass "checkpoint sync coordinator=$after realm0=$realm0 realm1=$realm1"
    else
      fail "checkpoint skew did not converge coordinator=$after realm0=$realm0 realm1=$realm1"
    fi
    if [ "$saw_progress" = "1" ]; then
      pass "checkpoint progress $before -> $after"
    else
      fail "coordinator checkpoint did not advance from $before"
    fi
  else
    fail "checkpoint RPC unavailable coordinator=$before realm0=$realm0 realm1=$realm1"
  fi

  if jsonrpc_result "http://$LOCAL_STAGING_PROVE_PROXY_ADDR" psy_get_circuits_data >/dev/null 2>&1; then
    pass "prove-proxy RPC"
  else
    fail "prove-proxy RPC"
  fi
  if jsonrpc_result "http://$LOCAL_STAGING_FAUCET_ADDR" psy_get_psy_faucet_config >/dev/null 2>&1; then
    pass "faucet-server RPC"
  else
    fail "faucet-server RPC"
  fi
  if curl -fsS --max-time 10 "http://$LOCAL_STAGING_PSY_SERVICES_ADDR/health" >/dev/null; then
    pass "psy-services health"
  else
    fail "psy-services health"
  fi
  if curl -fsS --max-time 10 -H 'Accept: application/nostr+json' \
    "http://127.0.0.1:$LOCAL_NOSTR_PORT/" >/dev/null; then
    pass "Nostr relay"
  else
    fail "Nostr relay"
  fi
}

check_bridge() {
  check_pid bridge-relayer
  check_pid envio

  if curl -fsS --max-time 10 "http://127.0.0.1:$LOCAL_STAGING_INDEXER_PORT/healthz" >/dev/null; then
    pass "Envio/Hasura health"
  else
    fail "Envio/Hasura health"
  fi

  local relayer_state="$LOCAL_STAGING_RELAYER_PROOF_DIR/daemon_state.toml"
  if [ -s "$relayer_state" ]; then
    pass "relayer state file"
  else
    fail "relayer state file is missing: $relayer_state"
  fi
}

check_l1
if [ "$phase" != "l1" ]; then
  check_core
fi
if [ "$phase" = "bridge" ] || [ "$phase" = "all" ]; then
  check_bridge
fi

if [ "$failures" -ne 0 ]; then
  die "$phase health check failed: $failures component(s)"
fi

echo "[bsc-testnet] $phase health check passed"
