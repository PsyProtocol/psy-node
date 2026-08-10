#!/usr/bin/env bash
set -euo pipefail

# ─── Bridge E2E Test Script ───────────────────────────────────────────────────
# Based on the internal Psy E2E test framework spec and bridge test records.
#
# Prerequisites:
#   - make run-all is running (fresh stack)
#   - psy_user_cli built: cargo build --release -p psy_user_cli
#   - psy-services built: cd ../psy-services && cargo build --release
#   - WALLET_PASSWORD env var set
#
# Usage:
#   ./e2e/bridge-e2e.sh
#
# What it tests:
#   1. Register user
#   2. Mint PSY for L2 fees
#   3. L1 deposit USDT (with correct shield_address_bytes32)
#   4. Wait for relayer to prove deposit
#   5. L2 claim-deposit
#   6. L2 withdraw
#   7. Wait for relayer to append + finalize + L1 batchClaimWithdrawal
#   8. Verify L1 USDT balance restored

# ─── Config ───────────────────────────────────────────────────────────────────
RPC_URL="${L1_RPC_URL:-http://127.0.0.1:8545}"
SERVICES_URL="${SERVICES_URL:-http://127.0.0.1:3000}"
RPC_CONFIG="client_prover/config.json"
USER_PK="${USER_PK:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
USER_ADDR="${USER_ADDR:-0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266}"
DEPOSIT_AMOUNT="${DEPOSIT_AMOUNT:-2000}"  # 0.002 USDT (6 decimals)
WITHDRAW_AMOUNT="${WITHDRAW_AMOUNT:-1000}"  # 0.001 USDT (6 decimals)
MINT_AMOUNT="${MINT_AMOUNT:-10000000000}"  # L2 PSY gas budget
R0=12345
R1=67890
NOTE_SECRET="${NOTE_SECRET:-$(python3 -c "import secrets; print(','.join(str(secrets.randbelow(2**64)) for _ in range(4)))")}"
NULLIFIER_SECRET="${NULLIFIER_SECRET:-$(python3 -c "import secrets; print(','.join(str(secrets.randbelow(2**64)) for _ in range(4)))")}"
MAX_WAIT_SECS=300
POLL_INTERVAL=15

# ─── Helpers ──────────────────────────────────────────────────────────────────
log() { echo "[$(date +%H:%M:%S)] $*"; }
fail() { log "FAIL: $*"; exit 1; }
ok() { log "OK: $*"; }

cast_call() {
  cast call "$@" --rpc-url "$RPC_URL" 2>/dev/null
}

cast_send() {
  cast send "$@" --rpc-url "$RPC_URL" --private-key "$USER_PK" 2>/dev/null
}

wait_for() {
  local desc="$1" check_expr="$2" max_secs="${3:-$MAX_WAIT_SECS}"
  local elapsed=0
  while [ "$elapsed" -lt "$max_secs" ]; do
    if eval "$check_expr"; then return 0; fi
    sleep "$POLL_INTERVAL"
    elapsed=$((elapsed + POLL_INTERVAL))
    log "  waiting for $desc... (${elapsed}s)"
  done
  fail "timeout waiting for $desc (${max_secs}s)"
}

# ─── Read deployed addresses ──────────────────────────────────────────────────
read_addresses() {
  local deploy_file="psy-contracts/deployments/localhost/deployed-contracts.json"
  [ -f "$deploy_file" ] || fail "deploy file not found: $deploy_file"
  BRIDGE=$(python3 -c "import json; print(json.load(open('$deploy_file'))['contracts']['Bridge'])")
  USDT=$(python3 -c "import json; print(json.load(open('$deploy_file'))['protocol']['tokens']['USDT']['l1Address'])")
  ROUTER=$(python3 -c "import json; print(json.load(open('$deploy_file'))['contracts']['Router'])")
  GATEWAY=$(python3 -c "import json; print(json.load(open('$deploy_file'))['contracts']['ERC20Gateway'])")
  STATE_MANAGER=$(python3 -c "import json; print(json.load(open('$deploy_file'))['core']['StateManager'])")
  log "Bridge=$BRIDGE USDT=$USDT Router=$ROUTER Gateway=$GATEWAY"
}

# ─── Step 1: Register user ────────────────────────────────────────────────────
register_user() {
  log "Step 1: Register user"
  local reg_output public_key
  if ! reg_output=$(./target/release/psy_user_cli register-user \
    --sign-type zk -p "$USER_PK" \
    --rpc-config "$RPC_CONFIG" 2>&1); then
    echo "$reg_output" >&2
    fail "user registration failed"
  fi

  public_key=$(echo "$reg_output" | grep -oP '"public_key_hash":\s*"\K[0-9a-fA-F]+' | head -1) || public_key=""
  [ -n "$public_key" ] || fail "register-user output did not contain public_key_hash"

  USER_ID=""
  wait_for "user_id for public key $public_key" "
    USER_ID=\$(./target/release/psy_user_cli get-user-id \\
      --pub-key '$public_key' \\
      --rpc-config '$RPC_CONFIG' 2>&1 | grep -oP 'user_id:\\s*\\K[0-9]+' | head -1) || USER_ID=''
    [ -n \"\$USER_ID\" ]
  "
  [ -n "$USER_ID" ] || fail "get-user-id returned no user_id for public key $public_key"
  ok "user registered/resolved"
  log "  user_id=$USER_ID"
}

# ─── Step 2: Mint PSY for L2 fees ────────────────────────────────────────────
mint_psy() {
  log "Step 2: Mint PSY ($MINT_AMOUNT) for L2 fees"
  local mint_output
  if ! mint_output=$(./target/release/psy_user_cli call \
    --sign-type zk -p "$USER_PK" \
    --rpc-config "$RPC_CONFIG" \
    --contract-id 0 --method-name simple_mint \
    --inputs "[$MINT_AMOUNT]" \
    --wait-until-confirmation 2>&1); then
    echo "$mint_output" >&2
    fail "PSY mint failed"
  fi
  echo "$mint_output" | tail -3
  ok "PSY minted"
}

# ─── Step 3: L1 deposit ───────────────────────────────────────────────────────
l1_deposit() {
  log "Step 3: L1 deposit USDT ($DEPOSIT_AMOUNT)"

  # Approve both Router and Gateway (learned from bridge-e2e-test-records.md)
  cast_send "$USDT" "approve(address,uint256)" "$ROUTER" "$DEPOSIT_AMOUNT" --gas-limit 100000 > /dev/null
  cast_send "$USDT" "approve(address,uint256)" "$GATEWAY" "$DEPOSIT_AMOUNT" --gas-limit 100000 > /dev/null
  ok "approved Router + Gateway"

  # Deposit via CLI to get correct shield_address_bytes32
  local dep_output
  dep_output=$(./target/release/psy_user_cli deposit \
    -p "$USER_PK" \
    --router-address "$ROUTER" \
    --token "$USDT" \
    --amount "$DEPOSIT_AMOUNT" \
    --note-secret "$NOTE_SECRET" \
    --nullifier-secret "$NULLIFIER_SECRET" \
    --deposit-proof-output /tmp/deposit_proof.json \
    --rpc-config "$RPC_CONFIG" \
    --r0 "$R0" --r1 "$R1" --user-id "$USER_ID" 2>&1)

  echo "$dep_output" | grep -q "shield_address_bytes32" || fail "deposit did not emit shield_address_bytes32"
  SHIELD_BYTES32=$(echo "$dep_output" | grep "shield_address_bytes32" | grep -o '0x[0-9a-fA-F]\{64\}')
  log "  shield_address_bytes32=$SHIELD_BYTES32"

  pending=$(cast_call "$BRIDGE" "pendingDepositCount()(uint256)" | awk '{print $1}')
  DEPOSIT_INDEX=$((pending - 1))
  ok "deposit done, index=$DEPOSIT_INDEX"
}

# ─── Step 4: Wait for relayer to prove ────────────────────────────────────────
wait_prove() {
  log "Step 4: Wait for relayer to prove deposit (index=$DEPOSIT_INDEX)"
  local target=$((DEPOSIT_INDEX + 1))
  wait_for "provedDepositCount >= $target" \
    "[ \"\$(cast_call '$BRIDGE' 'provedDepositCount()(uint256)' | awk '{print \$1}')\" -ge $target ]"
  ok "deposit proved"
}

# ─── Step 5: L2 claim-deposit ─────────────────────────────────────────────────
claim_deposit() {
  log "Step 5: L2 claim-deposit (index=$DEPOSIT_INDEX)"
  local output
  if ! output=$(./target/release/psy_user_cli claim-deposit \
    --sign-type zk -p "$USER_PK" \
    --rpc-config "$RPC_CONFIG" \
    --l1-rpc-url "$RPC_URL" \
    --token-l1-address "$USDT" \
    --amount "$DEPOSIT_AMOUNT" \
    --source-chain-index 0 \
    --user-id "$USER_ID" \
    --deposit-index "$DEPOSIT_INDEX" \
    --deposit-proof /tmp/deposit_proof.json \
    --r0 "$R0" --r1 "$R1" \
    --note-secret "$NOTE_SECRET" \
    --nullifier-secret "$NULLIFIER_SECRET" 2>&1); then
    echo "$output" >&2
    fail "claim-deposit failed"
  fi
  echo "$output" | grep -q "confirmed" || {
    echo "$output" | tail -20
    fail "claim-deposit output did not confirm inclusion"
  }
  ok "claim-deposit confirmed"
}

# ─── Step 6: L2 withdraw ──────────────────────────────────────────────────────
l2_withdraw() {
  log "Step 6: L2 withdraw USDT ($WITHDRAW_AMOUNT)"
  WITHDRAW_NONCE="0x$(python3 -c "import secrets; print(secrets.token_hex(32))")"
  log "  nonce=$WITHDRAW_NONCE"

  local token32 recipient32
  token32="0x$(echo "$USDT" | cut -c3- | python3 -c "import sys; print(sys.stdin.read().strip().rjust(64,'0'))")"
  recipient32="0x$(echo "$USER_ADDR" | cut -c3- | python3 -c "import sys; print(sys.stdin.read().strip().rjust(64,'0'))")"

  if ! output=$(./target/release/psy_user_cli withdraw \
    --sign-type zk -p "$USER_PK" \
    --rpc-config "$RPC_CONFIG" \
    --l1-rpc-url "$RPC_URL" \
    --destination-chain-id 0 \
    --token-address "$token32" \
    --amount "$WITHDRAW_AMOUNT" \
    --recipient "$recipient32" \
    --nonce "$WITHDRAW_NONCE" \
    --contract-id 4 2>&1); then
    echo "$output" >&2
    fail "withdraw failed"
  fi
  echo "$output" | grep -q "withdraw tx included" || {
    echo "$output" | tail -20
    fail "withdraw output did not confirm inclusion"
  }
  ok "withdraw succeeded"
}

# ─── Step 7: Wait for relayer L1 claim ────────────────────────────────────────
wait_l1_claim() {
  log "Step 7: Wait for relayer batchClaimWithdrawal"

  # Record balance before
  local bal_before
  bal_before=$(cast_call "$USDT" "balanceOf(address)(uint256)" "$USER_ADDR" | awk '{print $1}')
  log "  L1 USDT balance before: $bal_before"

  local expected=$((bal_before + WITHDRAW_AMOUNT))
  wait_for "withdrawal nullifier claimed" \
    "[ \"\$(cast_call '$BRIDGE' 'claimedNullifiers(bytes32)(bool)' '$WITHDRAW_NONCE')\" = true ]"
  wait_for "L1 USDT balance >= $expected" \
    "[ \"\$(cast_call '$USDT' 'balanceOf(address)(uint256)' '$USER_ADDR' | awk '{print \$1}')\" -ge $expected ]"
  wait_for "pending withdrawal claims empty" \
    "[ \"\$(python3 -c 'import tomllib; print(len(tomllib.load(open(\"local_checkpoints/bridge_proposer/daemon_state.toml\",\"rb\")).get(\"pending_claim_withdrawals\",{})))')\" -eq 0 ]"

  local bal_after
  bal_after=$(cast_call "$USDT" "balanceOf(address)(uint256)" "$USER_ADDR" | awk '{print $1}')
  local daemon_finalized l1_finalized l2_head gap
  daemon_finalized=$(python3 -c 'import tomllib; print(tomllib.load(open("local_checkpoints/bridge_proposer/daemon_state.toml","rb"))["last_finalized_checkpoint"])')
  l1_finalized=$(cast_call "$STATE_MANAGER" "lastFinalizedCheckpointId()(uint64)" | awk '{print $1}')
  l2_head=$(curl -fsS -X POST http://127.0.0.1:13380 -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_latest_checkpoint_id","params":[]}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])')
  gap=$((l2_head - 3 - l1_finalized))
  [ "$gap" -ge 0 ] || fail "L1 finalized checkpoint is ahead of confirmed L2 head: gap=$gap"
  [ "$daemon_finalized" -le "$l1_finalized" ] || fail "daemon finalized checkpoint is ahead of L1: $daemon_finalized > $l1_finalized"
  [ $((l1_finalized - daemon_finalized)) -le 64 ] || fail "daemon/L1 finalized gap exceeds 64: $daemon_finalized vs $l1_finalized"
  [ "$gap" -le 64 ] || fail "relayer finalized gap exceeds 64: $gap"
  pgrep -x psy_relayer_cli >/dev/null || fail "bridge relayer is not running"
  ok "chain state settled: claimed=true pending_claims=0 finalized=$l1_finalized gap=$gap"
  ok "L1 USDT balance after: $bal_after (expected >= $expected)"
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
  log "=== Bridge E2E Test ==="
  log "RPC=$RPC_URL Services=$SERVICES_URL"

  read_addresses
  register_user
  mint_psy
  l1_deposit
  wait_prove
  claim_deposit
  l2_withdraw
  wait_l1_claim

  log "=== Bridge E2E Test PASSED ==="
}

main "$@"