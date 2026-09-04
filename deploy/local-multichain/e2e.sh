#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Resolved relative to this deployment script at runtime.
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'USAGE'
Usage: deploy/local-multichain/e2e.sh [options]

Run local multichain bridge E2E cases. The default runs Ethereum, BSC and Base
as independent cases and reports every result even when an earlier case fails.

Options:
  --chain NAME       all (default), ethereum, bsc, or base
  --preflight-only   Validate the test matrix and runtime without transactions
  --skip-status      Skip deploy/local-multichain/status.sh
  -h, --help         Show this help

Environment overrides:
  PARTH_PRIVATE_KEY          Defaults to Anvil account 0
  DEPOSIT_AMOUNT             Defaults to 1000000
  WITHDRAW_AMOUNT            Defaults to 250000
  TOKEN_CONTRACT_ID          Defaults to 4 (USDT)
  WAIT_SECONDS               Defaults to 420 per asynchronous phase
  POLL_SECONDS               Defaults to 5
  COMMAND_TIMEOUT_SECONDS    Defaults to 300 for each proving CLI command
  READ_TIMEOUT_SECONDS       Defaults to 30 for each read-only CLI command
  RUN_FUND_TEST_USER         Set to 0 to skip Psy faucet funding
  RUN_DEPOSIT                Set to 0 to skip deposit and claim
  RUN_WITHDRAW               Set to 0 to skip withdrawal and L1 settlement
  PSY_SERVICES_DB_URL        Defaults to the local multichain services database
USAGE
}

CHAIN_SELECTION="all"
PREFLIGHT_ONLY=0
RUN_STATUS="${RUN_STATUS:-1}"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --chain) CHAIN_SELECTION="${2:-}"; shift 2 ;;
    --preflight-only) PREFLIGHT_ONLY=1; shift ;;
    --skip-status) RUN_STATUS=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[local-multichain-e2e] unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$CHAIN_SELECTION" in
  all|ethereum|bsc|base) ;;
  *) echo "[local-multichain-e2e] unsupported chain: $CHAIN_SELECTION" >&2; exit 2 ;;
esac

PRIVATE_KEY="${PARTH_PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
SIGN_TYPE="${SIGN_TYPE:-zk}"
CLI="${PSY_USER_CLI:-$PSY_NODE_DIR/target/release/psy_user_cli}"
CLIENT_DIR="${CLIENT_PROVER_DIR:-$PSY_NODE_DIR/client_prover}"
RPC_CONFIG="${RPC_CONFIG:-$PSY_NODE_DIR/psy-genesis/config.json}"
TOKEN_CONTRACT_ABI="${TOKEN_CONTRACT_ABI:-$PSY_NODE_DIR/psy-genesis/genesis_abi/USDTTokenContract.json}"
PSY_SERVICES_DB_URL="${PSY_SERVICES_DB_URL:-postgresql://postgres:testing@127.0.0.1:5433/psy_services}"
FAUCET_RPC_URL="${FAUCET_RPC_URL:-http://127.0.0.1:9998}"
RELAYER_LOG="${RELAYER_LOG:-$PSY_NODE_DIR/logs/bridge_relayer_logs.txt}"
DEPOSIT_AMOUNT="${DEPOSIT_AMOUNT:-1000000}"
WITHDRAW_AMOUNT="${WITHDRAW_AMOUNT:-250000}"
TOKEN_CONTRACT_ID="${TOKEN_CONTRACT_ID:-4}"
WAIT_SECONDS="${WAIT_SECONDS:-420}"
POLL_SECONDS="${POLL_SECONDS:-5}"
COMMAND_TIMEOUT_SECONDS="${COMMAND_TIMEOUT_SECONDS:-300}"
READ_TIMEOUT_SECONDS="${READ_TIMEOUT_SECONDS:-30}"
RUN_FUND_TEST_USER="${RUN_FUND_TEST_USER:-1}"
RUN_DEPOSIT="${RUN_DEPOSIT:-1}"
RUN_WITHDRAW="${RUN_WITHDRAW:-1}"
TEST_USER_MIN_FEE_BALANCE="${TEST_USER_MIN_FEE_BALANCE:-1000000}"
TOKEN_CONTRACT_STATE_TREE_HEIGHT="${TOKEN_CONTRACT_STATE_TREE_HEIGHT:-32}"
RUN_ID="${LOCAL_MULTICHAIN_E2E_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
RESULT_ROOT="${LOCAL_MULTICHAIN_E2E_RESULT_DIR:-$LOCAL_DEPLOY_STATE_DIR/e2e/$RUN_ID}"

fail() {
  echo "[local-multichain-e2e] ERROR: $*" >&2
  exit 1
}

log() {
  echo "[local-multichain-e2e] $*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

require_file() {
  [ -f "$1" ] || fail "missing file: $1"
}

chain_field() {
  local chain="$1" field="$2"
  case "$chain:$field" in
    ethereum:index) echo 0 ;;
    ethereum:rpc) echo http://127.0.0.1:8545 ;;
    ethereum:network) echo localhost ;;
    bsc:index) echo 1 ;;
    bsc:rpc) echo http://127.0.0.1:9545 ;;
    bsc:network) echo localhostBsc ;;
    base:index) echo 2 ;;
    base:rpc) echo http://127.0.0.1:10545 ;;
    base:network) echo localhostBase ;;
    *) fail "unknown chain field: $chain:$field" ;;
  esac
}

read_deployed_address() {
  local deploy_dir="$1" name="$2"
  if [ -s "$deploy_dir/deployed-contracts.json" ]; then
    jq -er --arg name "$name" \
      '.proxies[($name + "_Proxy")] // .core[$name] // .contracts[$name]' \
      "$deploy_dir/deployed-contracts.json"
    return
  fi
  jq -er '.address' "$deploy_dir/$name.json"
}

rpc_result() {
  local url="$1" method="$2"
  curl -fsS --max-time 10 -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":[]}" \
    "$url" | jq -er '.result'
}

psql_scalar() {
  psql "$PSY_SERVICES_DB_URL" -Atq -v ON_ERROR_STOP=1 -c "$1"
}

decimal_first_field() {
  awk '{print $1}'
}

rand_u32() {
  od -An -N4 -tu4 /dev/urandom | tr -d ' '
}

rand_hex32() {
  printf '0x'
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
  printf '\n'
}

rand_u64x4() {
  printf '%s,%s,%s,%s\n' "$(rand_u32)" "$(rand_u32)" "$(rand_u32)" "$(rand_u32)"
}

wait_until() {
  local label="$1" deadline="$2"
  shift 2
  while true; do
    if "$@"; then
      return 0
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      fail "timed out waiting for $label"
    fi
    sleep "$POLL_SECONDS"
  done
}

for command_name in awk cast curl grep head jq od pgrep psql sed tail tee timeout tr wc; do
  need_cmd "$command_name"
done
[ -x "$CLI" ] || fail "missing executable: $CLI"
[ -d "$CLIENT_DIR" ] || fail "missing client prover directory: $CLIENT_DIR"
require_file "$RPC_CONFIG"
require_file "$TOKEN_CONTRACT_ABI"
require_file "$RELAYER_LOG"

WITHDRAW_METHOD_ID="${WITHDRAW_METHOD_ID:-$(
  jq -er '.contract.methods[] | select(.name == "withdraw") | .method_id' "$TOKEN_CONTRACT_ABI"
)}"
CLAIM_DEPOSIT_METHOD_ID="${CLAIM_DEPOSIT_METHOD_ID:-$(
  jq -er '.contract.methods[] | select(.name == "claim_deposit") | .method_id' "$TOKEN_CONTRACT_ABI"
)}"

validate_chain() {
  local chain="$1" index rpc network deploy_dir chain_id expected_chain_id
  index="$(chain_field "$chain" index)"
  rpc="$(chain_field "$chain" rpc)"
  network="$(chain_field "$chain" network)"
  deploy_dir="$PSY_NODE_DIR/psy-contracts/deployments/$network"
  for contract in Router Bridge USDTToken ERC20Gateway; do
    require_file "$deploy_dir/$contract.json"
    read_deployed_address "$deploy_dir" "$contract" >/dev/null
  done
  chain_id="$(rpc_result "$rpc" eth_chainId)"
  printf -v expected_chain_id '0x%x' "$((31337 + index))"
  [ "$chain_id" = "$expected_chain_id" ] \
    || fail "$chain chain ID mismatch: got=$chain_id expected=$expected_chain_id"
  log "preflight chain=$chain index=$index network=$network chain_id=$chain_id"
}

run_preflight() {
  if [ "$RUN_STATUS" = "1" ]; then
    "$SCRIPT_DIR/status.sh"
  fi
  psql_scalar 'select 1;' >/dev/null
  if [ "$CHAIN_SELECTION" = all ]; then
    for chain in ethereum bsc base; do
      validate_chain "$chain"
    done
  else
    validate_chain "$CHAIN_SELECTION"
  fi
  local relayer_pid
  relayer_pid="$(pgrep -n -x psy_relayer_cli || true)"
  [ -n "$relayer_pid" ] || fail "psy_relayer_cli is not running"
  log "preflight relayer_pid=$relayer_pid rpc_config=$RPC_CONFIG"
}

if [ "${LOCAL_MULTICHAIN_E2E_CHILD:-0}" != 1 ]; then
  run_preflight
  if [ "$PREFLIGHT_ONLY" = 1 ]; then
    log "PASS preflight-only chains=ethereum,bsc,base"
    exit 0
  fi
fi

if [ "$CHAIN_SELECTION" = all ] && [ "${LOCAL_MULTICHAIN_E2E_CHILD:-0}" != 1 ]; then
  mkdir -p "$RESULT_ROOT"
  failures=0
  passed=()
  failed=()
  for chain in ethereum bsc base; do
    log "starting independent case chain=$chain"
    if LOCAL_MULTICHAIN_E2E_CHILD=1 \
      LOCAL_MULTICHAIN_E2E_RUN_ID="$RUN_ID" \
      LOCAL_MULTICHAIN_E2E_RESULT_DIR="$RESULT_ROOT" \
      RUN_STATUS=0 \
      "$0" --chain "$chain" 2>&1 | tee "$RESULT_ROOT/$chain.log"; then
      passed+=("$chain")
    else
      failures=$((failures + 1))
      failed+=("$chain")
    fi
  done
  log "summary passed=${passed[*]:-none} failed=${failed[*]:-none} results=$RESULT_ROOT"
  [ "$failures" -eq 0 ] || fail "$failures multichain E2E case(s) failed"
  log "PASS chains=ethereum,bsc,base"
  exit 0
fi

CHAIN="$CHAIN_SELECTION"
CHAIN_INDEX="$(chain_field "$CHAIN" index)"
L1_RPC_URL="$(chain_field "$CHAIN" rpc)"
DEPLOYMENTS_NETWORK="$(chain_field "$CHAIN" network)"
DEPLOY_DIR="$PSY_NODE_DIR/psy-contracts/deployments/$DEPLOYMENTS_NETWORK"
CASE_RESULT_DIR="$RESULT_ROOT/$CHAIN"
mkdir -p "$CASE_RESULT_DIR"

PHASE=setup
on_error() {
  local status=$?
  trap - ERR
  echo "[local-multichain-e2e] FAIL chain=$CHAIN phase=$PHASE status=$status results=$CASE_RESULT_DIR" >&2
  exit "$status"
}
trap on_error ERR

validate_chain "$CHAIN"
ROUTER_ADDRESS="$(read_deployed_address "$DEPLOY_DIR" Router)"
BRIDGE_ADDRESS="$(read_deployed_address "$DEPLOY_DIR" Bridge)"
TOKEN_ADDRESS="$(read_deployed_address "$DEPLOY_DIR" USDTToken)"
GATEWAY_ADDRESS="$(read_deployed_address "$DEPLOY_DIR" ERC20Gateway)"
L1_RECIPIENT="${L1_RECIPIENT:-$(cast wallet address --private-key "$PRIVATE_KEY")}"

pending_deposit_count() {
  cast call "$BRIDGE_ADDRESS" 'pendingDepositCount()(uint32)' --rpc-url "$L1_RPC_URL" | decimal_first_field
}

proved_deposit_count() {
  cast call "$BRIDGE_ADDRESS" 'provedDepositCount()(uint32)' --rpc-url "$L1_RPC_URL" | decimal_first_field
}

balance_of() {
  cast call "$TOKEN_ADDRESS" 'balanceOf(address)(uint256)' "$L1_RECIPIENT" \
    --rpc-url "$L1_RPC_URL" | decimal_first_field
}

cast_send_json() {
  cast send "$@" --rpc-url "$L1_RPC_URL" --private-key "$PRIVATE_KEY" --json
}

WALLET_INFO="$(timeout "${READ_TIMEOUT_SECONDS}s" "$CLI" wallet info \
  --private-key "$PRIVATE_KEY" --sign-type "$SIGN_TYPE")"
PUBLIC_KEY="$(printf '%s\n' "$WALLET_INFO" | awk '/^public_key:/ {print $2; exit}')"
[ -n "$PUBLIC_KEY" ] || fail "could not parse public_key from wallet info"

get_user_id() {
  (cd "$CLIENT_DIR" && timeout "${READ_TIMEOUT_SECONDS}s" "$CLI" get-user-id \
    --rpc-config "$RPC_CONFIG" --pub-key "$PUBLIC_KEY" 2>/dev/null || true) \
    | awk '/user_id:/ {print $2; exit}'
}

USER_ID="$(get_user_id)"
if [ -z "$USER_ID" ]; then
  PHASE=register-user
  log "chain=$CHAIN registering deterministic test user"
  (cd "$CLIENT_DIR" && RUST_LOG=info timeout --signal=INT --kill-after=30s "${COMMAND_TIMEOUT_SECONDS}s" "$CLI" register-user \
    --private-key "$PRIVATE_KEY" --sign-type "$SIGN_TYPE") \
    | tee "$CASE_RESULT_DIR/register-user.log"
  deadline="$(( $(date +%s) + WAIT_SECONDS ))"
  wait_for_user_id() {
    USER_ID="$(get_user_id)"
    [ -n "$USER_ID" ]
  }
  wait_until "registered test user" "$deadline" wait_for_user_id
  sleep 12
fi
log "case chain=$CHAIN chain_index=$CHAIN_INDEX user_id=$USER_ID token=$TOKEN_ADDRESS"

test_user_fee_balance() {
  local checkpoint raw
  checkpoint="$(rpc_result http://127.0.0.1:1337 psy_get_latest_checkpoint_id)" || return 1
  raw="$(
    cd "$CLIENT_DIR" && timeout "${READ_TIMEOUT_SECONDS}s" "$CLI" get-user-contract-state-tree-leaf-hash \
      --rpc-config "$RPC_CONFIG" \
      --checkpoint-id "$checkpoint" \
      --user-id "$USER_ID" \
      --contract-id 0 \
      --height "$TOKEN_CONTRACT_STATE_TREE_HEIGHT" \
      --leaf-id 0 2>/dev/null
  )" || return 1
  raw="$(printf '%s' "$raw" | tr -d '"[:space:]')"
  [[ "$raw" =~ ^[0-9a-fA-F]{64}$ ]] || return 1
  cast to-dec "0x$raw"
}

claimable_operator_for_user() {
  curl -fsS -X POST http://127.0.0.1:3000/api/v1/wallet/public-claimable \
    -H 'content-type: application/json' \
    --data "{\"user_id\":$USER_ID,\"token_contract_ids\":[0]}" \
    | jq -r '.data.items[]? | select((.token_contract_id|tostring)=="0" and ((.amount|tonumber) > 0)) | .sender_user_id' \
    | head -1
}

fund_test_user_for_fees() {
  local current_balance faucet_json operator deadline
  current_balance="$(test_user_fee_balance || true)"
  if [[ "$current_balance" =~ ^[0-9]+$ ]] \
    && [ "$current_balance" -ge "$TEST_USER_MIN_FEE_BALANCE" ]; then
    log "chain=$CHAIN fee balance=$current_balance; faucet funding not needed"
    return
  fi
  PHASE=faucet
  faucet_json="$(
    curl -fsS -X POST "$FAUCET_RPC_URL" \
      -H 'content-type: application/json' \
      --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"psy_claim_faucet\",\"params\":[{\"recipient_user_id\":$USER_ID}]}" || true
  )"
  operator="$(printf '%s' "$faucet_json" | jq -r '.result.operator_user_id // empty' 2>/dev/null || true)"
  if [ -z "$operator" ]; then
    operator="$(claimable_operator_for_user || true)"
  fi
  if [ -z "$operator" ]; then
    log "chain=$CHAIN no new faucet claim; continuing with existing balance"
    return
  fi
  deadline="$(( $(date +%s) + 120 ))"
  wait_for_claimable_operator() { [ -n "$(claimable_operator_for_user || true)" ]; }
  wait_until "Psy faucet claimable" "$deadline" wait_for_claimable_operator
  (cd "$CLIENT_DIR" && timeout --signal=INT --kill-after=30s "${COMMAND_TIMEOUT_SECONDS}s" "$CLI" call \
    --rpc-config "$RPC_CONFIG" \
    --private-key "$PRIVATE_KEY" \
    --sign-type "$SIGN_TYPE" \
    --contract-id 0 \
    --method-name simple_claim \
    --inputs "[$operator]" \
    --wait-until-confirmation) | tee "$CASE_RESULT_DIR/faucet-claim.log"
}

if [ "$RUN_FUND_TEST_USER" = "1" ]; then
  fund_test_user_for_fees
fi

if [ "$RUN_DEPOSIT" = "1" ]; then
  PHASE=deposit
  L1_TOKEN_BALANCE="$(balance_of)"
  [ "$L1_TOKEN_BALANCE" -ge "$DEPOSIT_AMOUNT" ] \
    || fail "chain=$CHAIN L1 token balance $L1_TOKEN_BALANCE is below deposit $DEPOSIT_AMOUNT"
  log "chain=$CHAIN approving deposit amount=$DEPOSIT_AMOUNT"
  cast_send_json "$TOKEN_ADDRESS" 'approve(address,uint256)' "$ROUTER_ADDRESS" "$DEPOSIT_AMOUNT" \
    >"$CASE_RESULT_DIR/approve-router.json"
  cast_send_json "$TOKEN_ADDRESS" 'approve(address,uint256)' "$GATEWAY_ADDRESS" "$DEPOSIT_AMOUNT" \
    >"$CASE_RESULT_DIR/approve-gateway.json"

  DEPOSIT_INDEX="$(pending_deposit_count)"
  PROVED_BEFORE="$(proved_deposit_count)"
  R0="${R0:-$(rand_u32)}"
  R1="${R1:-$(rand_u32)}"
  NOTE_SECRET="${NOTE_SECRET:-$(rand_u64x4)}"
  NULLIFIER_SECRET="${NULLIFIER_SECRET:-$(rand_u64x4)}"
  DEPOSIT_PROOF="$CASE_RESULT_DIR/deposit-proof-$DEPOSIT_INDEX.json"
  log "chain=$CHAIN deposit start index=$DEPOSIT_INDEX proved_before=$PROVED_BEFORE amount=$DEPOSIT_AMOUNT"
  (cd "$CLIENT_DIR" && timeout --signal=INT --kill-after=30s "${COMMAND_TIMEOUT_SECONDS}s" "$CLI" deposit \
    --l1-rpc-url "$L1_RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --router-address "$ROUTER_ADDRESS" \
    --token "$TOKEN_ADDRESS" \
    --amount "$DEPOSIT_AMOUNT" \
    --user-id "$USER_ID" \
    --r0 "$R0" \
    --r1 "$R1" \
    --note-secret "$NOTE_SECRET" \
    --nullifier-secret "$NULLIFIER_SECRET" \
    --rpc-config "$RPC_CONFIG" \
    --deposit-proof-output "$DEPOSIT_PROOF") \
    | tee "$CASE_RESULT_DIR/deposit.log"

  TARGET_DEPOSIT_COUNT="$((DEPOSIT_INDEX + 1))"
  deadline="$(( $(date +%s) + WAIT_SECONDS ))"
  wait_for_deposit_proved() {
    local pending proved
    pending="$(pending_deposit_count)"
    proved="$(proved_deposit_count)"
    log "chain=$CHAIN deposit counts pending=$pending proved=$proved target=$TARGET_DEPOSIT_COUNT"
    [ "$pending" -ge "$TARGET_DEPOSIT_COUNT" ] && [ "$proved" -ge "$TARGET_DEPOSIT_COUNT" ]
  }
  wait_until "$CHAIN Bridge provedDepositCount >= $TARGET_DEPOSIT_COUNT" "$deadline" wait_for_deposit_proved

  PHASE=claim-deposit
  CLAIM_EVENT_ID_BEFORE="$(
    psql_scalar "select coalesce(max(id), 0) from contract_events where user_id=$USER_ID and contract_id=$TOKEN_CONTRACT_ID and method_id=$CLAIM_DEPOSIT_METHOD_ID;"
  )"
  (cd "$CLIENT_DIR" && timeout --signal=INT --kill-after=30s "${COMMAND_TIMEOUT_SECONDS}s" "$CLI" claim-deposit \
    --rpc-config "$RPC_CONFIG" \
    --private-key "$PRIVATE_KEY" \
    --sign-type "$SIGN_TYPE" \
    --l1-rpc-url "$L1_RPC_URL" \
    --token-l1-address "$TOKEN_ADDRESS" \
    --amount "$DEPOSIT_AMOUNT" \
    --source-chain-index "$CHAIN_INDEX" \
    --user-id "$USER_ID" \
    --deposit-index "$DEPOSIT_INDEX" \
    --r0 "$R0" \
    --r1 "$R1" \
    --note-secret "$NOTE_SECRET" \
    --nullifier-secret "$NULLIFIER_SECRET" \
    --deposit-proof "$DEPOSIT_PROOF") \
    | tee "$CASE_RESULT_DIR/claim-deposit.log"
  deadline="$(( $(date +%s) + WAIT_SECONDS ))"
  wait_for_deposit_claim_event() {
    CLAIM_EVENT_ROW="$(
      psql_scalar "select id || ':' || checkpoint_id || ':' || realm_id || ':' || event_index from contract_events where id > $CLAIM_EVENT_ID_BEFORE and user_id=$USER_ID and contract_id=$TOKEN_CONTRACT_ID and method_id=$CLAIM_DEPOSIT_METHOD_ID order by id desc limit 1;"
    )"
    [ -n "$CLAIM_EVENT_ROW" ]
  }
  wait_until "$CHAIN deposit claim event" "$deadline" wait_for_deposit_claim_event
  log "chain=$CHAIN deposit claim event=$CLAIM_EVENT_ROW"
fi

if [ "$RUN_WITHDRAW" = "1" ]; then
  PHASE=withdraw
  WITHDRAW_NONCE="${WITHDRAW_NONCE:-$(rand_hex32)}"
  BALANCE_BEFORE="$(balance_of)"
  RELAYER_START_LINE="$(wc -l < "$RELAYER_LOG" | tr -d ' ')"
  WITHDRAW_EVENT_ID_BEFORE="$(
    psql_scalar "select coalesce(max(id), 0) from contract_events where user_id=$USER_ID and contract_id=$TOKEN_CONTRACT_ID and method_id=$WITHDRAW_METHOD_ID;"
  )"
  log "chain=$CHAIN withdraw start amount=$WITHDRAW_AMOUNT nonce=$WITHDRAW_NONCE balance_before=$BALANCE_BEFORE"
  (cd "$CLIENT_DIR" && timeout --signal=INT --kill-after=30s "${COMMAND_TIMEOUT_SECONDS}s" "$CLI" withdraw \
    --rpc-config "$RPC_CONFIG" \
    --private-key "$PRIVATE_KEY" \
    --sign-type "$SIGN_TYPE" \
    --destination-chain-id "$CHAIN_INDEX" \
    --token-address "$TOKEN_ADDRESS" \
    --amount "$WITHDRAW_AMOUNT" \
    --recipient "$L1_RECIPIENT" \
    --nonce "$WITHDRAW_NONCE" \
    --l1-rpc-url "$L1_RPC_URL" \
    --contract-id "$TOKEN_CONTRACT_ID") \
    | tee "$CASE_RESULT_DIR/withdraw.log"

  deadline="$(( $(date +%s) + WAIT_SECONDS ))"
  wait_for_realm_withdraw_event() {
    WITHDRAW_EVENT_ROW="$(
      psql_scalar "select id || ':' || checkpoint_id || ':' || realm_id || ':' || event_index from contract_events where id > $WITHDRAW_EVENT_ID_BEFORE and user_id=$USER_ID and contract_id=$TOKEN_CONTRACT_ID and method_id=$WITHDRAW_METHOD_ID order by id desc limit 1;"
    )"
    [ -n "$WITHDRAW_EVENT_ROW" ]
  }
  wait_until "$CHAIN withdrawal event" "$deadline" wait_for_realm_withdraw_event
  log "chain=$CHAIN withdrawal event=$WITHDRAW_EVENT_ROW"

  PHASE=withdraw-settlement
  EXPECTED_BALANCE="$((BALANCE_BEFORE + WITHDRAW_AMOUNT))"
  wait_for_l1_balance() {
    BALANCE_AFTER="$(balance_of)"
    log "chain=$CHAIN withdrawal balance before=$BALANCE_BEFORE after=$BALANCE_AFTER expected=$EXPECTED_BALANCE"
    [ "$BALANCE_AFTER" -ge "$EXPECTED_BALANCE" ]
  }
  wait_until "$CHAIN L1 recipient balance >= $EXPECTED_BALANCE" "$deadline" wait_for_l1_balance
  wait_for_relayer_claim() {
    tail -n "+$((RELAYER_START_LINE + 1))" "$RELAYER_LOG" \
      | grep -F 'batchClaimWithdrawal confirmed' >/dev/null
  }
  wait_until "$CHAIN relayer batchClaimWithdrawal confirmation" "$deadline" wait_for_relayer_claim
  WITHDRAW_CLAIM_TX="$(
    tail -n "+$((RELAYER_START_LINE + 1))" "$RELAYER_LOG" \
      | sed -n 's/.*batchClaimWithdrawal confirmed.*tx_hash=\([^ ]*\).*/\1/p' \
      | tail -1
  )"
fi

PHASE=complete
cat <<SUMMARY
[local-multichain-e2e] PASS chain=$CHAIN
  chain_index=$CHAIN_INDEX
  deployments_network=$DEPLOYMENTS_NETWORK
  user_id=$USER_ID
  deposit_index=${DEPOSIT_INDEX:-skipped}
  deposit_claim_event=${CLAIM_EVENT_ROW:-skipped}
  withdrawal_nonce=${WITHDRAW_NONCE:-skipped}
  withdrawal_event=${WITHDRAW_EVENT_ROW:-skipped}
  l1_balance_before=${BALANCE_BEFORE:-skipped}
  l1_balance_after=${BALANCE_AFTER:-skipped}
  withdrawal_claim_tx=${WITHDRAW_CLAIM_TX:-skipped}
  results=$CASE_RESULT_DIR
SUMMARY
