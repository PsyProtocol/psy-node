#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

failures=0

check_pid() {
  local label="$1" file="$2"
  printf '%-18s ' "$label"
  if local_deploy_pid_alive "$file"; then
    echo "ok pid=$(sed -n '1p' "$file")"
  else
    echo "failed"
    failures=$((failures + 1))
  fi
}

check_git_source() {
  local label="$1" repo="$2" branch="$3"
  local actual="" expected="" current_branch=""
  printf '%-18s ' "$label"
  if [ -d "$repo/.git" ]; then
    actual="$(git -C "$repo" rev-parse HEAD 2>/dev/null || true)"
    expected="$(git -C "$repo" rev-parse "origin/$branch" 2>/dev/null || true)"
    current_branch="$(git -C "$repo" branch --show-current 2>/dev/null || true)"
  fi
  if [ -n "$actual" ] && [ "$actual" = "$expected" ] && [ "$current_branch" = "$branch" ]; then
    echo "ok branch=$branch commit=${actual:0:8}"
  else
    echo "failed branch=${current_branch:-none} commit=${actual:0:8} expected=origin/$branch"
    failures=$((failures + 1))
  fi
}

check_http() {
  local label="$1" url="$2"
  printf '%-18s ' "$label"
  if curl -fsS --max-time 10 "$url" >/dev/null 2>&1; then
    echo "ok $url"
  else
    echo "failed $url"
    failures=$((failures + 1))
  fi
}

check_http_status() {
  local label="$1" url="$2" expected="$3"
  local status=""
  printf '%-18s ' "$label"
  status="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$url" 2>/dev/null || true)"
  if [ "$status" = "$expected" ]; then
    echo "ok status=$status $url"
  else
    echo "failed status=${status:-none} expected=$expected $url"
    failures=$((failures + 1))
  fi
}

check_json_health() {
  local label="$1" url="$2" service="$3"
  printf '%-18s ' "$label"
  if curl -fsS --max-time 10 "$url" 2>/dev/null \
    | jq -e --arg service "$service" '.ok == true and .service == $service' >/dev/null 2>&1; then
    echo "ok $url"
  else
    echo "failed $url"
    failures=$((failures + 1))
  fi
}

check_config_payload() {
  local label="$1" url="$2" expected_services_commit=""
  expected_services_commit="$(git -C "$LOCAL_DEPLOY_SERVICES_DIR" rev-parse HEAD 2>/dev/null || true)"
  printf '%-18s ' "$label"
  if curl -fsS --max-time 10 "$url" 2>/dev/null \
    | jq -e --arg commit "$expected_services_commit" '
        .schema_version == 2
        and .environment == "local-multichain"
        and .source.psy_services.branch == "multi_chain"
        and .source.psy_services.commit == $commit
        and ([.l1_chains[].chain_index] == [0, 1, 2])
        and ([.l1_chains[].chain_id] == [31337, 31338, 31339])
      ' >/dev/null 2>&1; then
    echo "ok chains=3 services=${expected_services_commit:0:8}"
  else
    echo "failed $url"
    failures=$((failures + 1))
  fi
}

check_rpc() {
  local label="$1" url="$2" method="$3" expected="${4:-}"
  local result=""
  printf '%-18s ' "$label"
  result="$(curl -fsS --max-time 10 -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":[]}" \
    "$url" | jq -er '.result' 2>/dev/null || true)"
  if [ -n "$result" ] && { [ -z "$expected" ] || [ "$result" = "$expected" ]; }; then
    echo "ok result=$result"
  else
    echo "failed result=${result:-none} expected=${expected:-any}"
    failures=$((failures + 1))
  fi
}

echo "== managed processes =="
check_pid devnet "$LOCAL_DEPLOY_PID_DIR/devnet.pid"
check_pid cloudflared "$LOCAL_DEPLOY_PID_DIR/cloudflared.pid"
check_pid config-page "$LOCAL_DEPLOY_PID_DIR/config-page.pid"
check_pid eth-faucet "$LOCAL_DEPLOY_PID_DIR/eth-faucet.pid"
check_pid bsc-faucet "$LOCAL_DEPLOY_PID_DIR/bsc-faucet.pid"
check_pid base-faucet "$LOCAL_DEPLOY_PID_DIR/base-faucet.pid"

echo
echo "== source checkouts =="
check_git_source psy-services "$LOCAL_DEPLOY_SERVICES_DIR" "$LOCAL_DEPLOY_SERVICES_BRANCH"

echo
echo "== local endpoints =="
check_rpc coordinator http://127.0.0.1:1337 psy_get_latest_checkpoint_id
check_rpc realm-0 http://127.0.0.1:13380 psy_get_latest_checkpoint_id
check_rpc realm-1 http://127.0.0.1:13390 psy_get_latest_checkpoint_id
check_rpc ethereum-rpc http://127.0.0.1:8545 eth_chainId 0x7a69
check_rpc bsc-rpc http://127.0.0.1:9545 eth_chainId 0x7a6a
check_rpc base-rpc http://127.0.0.1:10545 eth_chainId 0x7a6b
check_http psy-services http://127.0.0.1:3000/health
check_http envio "http://127.0.0.1:${LOCAL_DEPLOY_ENVIO_PORT}/healthz"
check_http prove-proxy http://127.0.0.1:9999/health
check_http_status faucet-server http://127.0.0.1:9998/ 405
check_http nostr http://127.0.0.1:8081/
check_http app http://127.0.0.1:5177
check_json_health psy-config "http://127.0.0.1:${LOCAL_DEPLOY_CONFIG_PAGE_PORT}/health" psy-config-local
check_config_payload psy-config-json "http://127.0.0.1:${LOCAL_DEPLOY_CONFIG_PAGE_PORT}/config.json"
check_http explorer http://127.0.0.1:5178
check_http ide http://127.0.0.1:5176
check_http eth-faucet http://127.0.0.1:8555/health
check_http bsc-faucet http://127.0.0.1:9555/health
check_http base-faucet http://127.0.0.1:10555/health

echo
echo "== public Cloudflare routes =="
check_http app "$(local_deploy_url "$LOCAL_CF_APP_HOST")"
check_json_health psy-config "$(local_deploy_url "$LOCAL_CF_CONFIG_HOST")/health" psy-config-local
check_config_payload psy-config-json "$(local_deploy_url "$LOCAL_CF_CONFIG_HOST")/config.json"
check_http explorer "$(local_deploy_url "$LOCAL_CF_EXPLORER_HOST")"
check_http ide "$(local_deploy_url "$LOCAL_CF_IDE_HOST")"
check_rpc coordinator "$(local_deploy_url "$LOCAL_CF_COORDINATOR_HOST")" psy_get_latest_checkpoint_id
check_rpc realm-0 "$(local_deploy_url "$LOCAL_CF_REALM0_HOST")" psy_get_latest_checkpoint_id
check_rpc realm-1 "$(local_deploy_url "$LOCAL_CF_REALM1_HOST")" psy_get_latest_checkpoint_id
check_rpc ethereum-rpc "$(local_deploy_url "$LOCAL_CF_ETH_RPC_HOST")" eth_chainId 0x7a69
check_rpc bsc-rpc "$(local_deploy_url "$LOCAL_CF_BSC_RPC_HOST")" eth_chainId 0x7a6a
check_rpc base-rpc "$(local_deploy_url "$LOCAL_CF_BASE_RPC_HOST")" eth_chainId 0x7a6b
check_http psy-services "$(local_deploy_url "$LOCAL_CF_SERVICES_HOST")/health"
check_http envio "$(local_deploy_url "$LOCAL_CF_INDEXER_HOST")/healthz"
check_http prove-proxy "$(local_deploy_url "$LOCAL_CF_PROVE_HOST")/health"
check_http_status faucet-server "$(local_deploy_url "$LOCAL_CF_FAUCET_HOST")/" 405
check_http nostr "$(local_deploy_url "$LOCAL_CF_NOSTR_HOST")/"
check_http app-faucet-proxy "$(local_deploy_url "$LOCAL_CF_APP_HOST")/eth-faucet/health"
check_http eth-faucet "$(local_deploy_url "$LOCAL_CF_ETH_FAUCET_HOST")/health"
check_http bsc-faucet "$(local_deploy_url "$LOCAL_CF_BSC_FAUCET_HOST")/health"
check_http base-faucet "$(local_deploy_url "$LOCAL_CF_BASE_FAUCET_HOST")/health"

echo
echo "branch=$(git -C "$PSY_NODE_DIR" branch --show-current)"
echo "source=$(git -C "$PSY_NODE_DIR" rev-parse HEAD)"
echo "state=$LOCAL_DEPLOY_STATE_DIR"
if [ "$failures" -gt 0 ]; then
  echo "[local-multichain] FAIL failures=$failures" >&2
  exit 1
fi
echo "[local-multichain] PASS"
