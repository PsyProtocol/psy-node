#!/usr/bin/env bash
set -euo pipefail

# ─── Bridge E2E Test Script ───────────────────────────────────────────────────
# L1→L2→L1 round trip against a running devnet stack:
#   1. Register user
#   2. Faucet claim + recipient simple_claim (L2 fee balance)
#   3. L1 deposit USDT (shield address derived from r0/r1/user_id; claim
#      material persisted BEFORE the L1 transaction)
#   4. Wait for relayer batchAppend (provedDepositCount) + checkpoint finalize
#   5. L2 claim-deposit with the sender-generated inclusion proof
#   6. L2 withdraw (burn)
#   7. Relayer batchClaimWithdrawal (registers pending) → script sends
#      claimPendingWithdrawal after claimableAt (relayer never does)
#   8. Verify L1 USDT balance = initial - deposit + withdraw and L2 claim state
#
# Prerequisites: make run-all running; release binaries built.
#
# The test wallet must be independent from the bridge relayer's anvil #0
# identity. Use a non-relayer devnet wallet such as anvil account #1.
#
# Required env:
#   USER_PK               private key for the test wallet
#
# Supported env overrides:
#   USER_ADDR             matching address; derived from USER_PK when omitted
#   MAX_WAIT_SECS         max seconds for relayer prove/claim waits (default 1800)
#   POLL_INTERVAL         seconds between poll checks (default 15)
#   RESULT_DIR            per-run result dir (default /tmp/br-e2e; chmod 700)
#
# All deposit claim material is persisted under RESULT_DIR/deposit-note.json.

# ─── Config ───────────────────────────────────────────────────────────────────
RPC_URL="${L1_RPC_URL:-http://127.0.0.1:8545}"
RPC_CONFIG="psy-genesis/config.json"
USER_PK="${USER_PK:?USER_PK is required; use a non-relayer devnet wallet such as anvil account #1}"
DERIVED_USER_ADDR="$(cast wallet address "$USER_PK")"
USER_ADDR="${USER_ADDR:-$DERIVED_USER_ADDR}"
if [[ "${USER_ADDR,,}" != "${DERIVED_USER_ADDR,,}" ]]; then
  echo "USER_ADDR does not match USER_PK" >&2
  exit 1
fi
if [[ "${USER_ADDR,,}" == "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266" ]]; then
  echo "USER_PK must not use the bridge relayer's anvil #0 identity" >&2
  exit 1
fi
DEPOSIT_AMOUNT="${DEPOSIT_AMOUNT:-2000}"  # 0.002 USDT (6 decimals)
WITHDRAW_AMOUNT="${WITHDRAW_AMOUNT:-1000}"  # 0.001 USDT (6 decimals)
DEPLOYER_PK="${DEPLOYER_PK:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"  # devnet deployer (anvil #0; funds USDT on fresh chains)
RESULT_DIR="${RESULT_DIR:-/tmp/br-e2e}"
mkdir -p "$RESULT_DIR" && chmod 700 "$RESULT_DIR"

# All field elements live in the Goldilocks field; limbs must be canonical
# (1..prime-1) or derive_note_commitment mis-hashes (bridge-common-operations.md).
GOLDILOCKS_PRIME=18446744069414584321
rand_limb() { python3 -c "import secrets; print(secrets.randbelow($GOLDILOCKS_PRIME - 1) + 1)"; }
rand_limbs4() { python3 -c "import secrets; print(','.join(str(secrets.randbelow($GOLDILOCKS_PRIME - 1) + 1) for _ in range(4)))"; }

R0="${R0:-$(rand_limb)}"
R1="${R1:-$(rand_limb)}"
NOTE_SECRET="${NOTE_SECRET:-$(rand_limbs4)}"
NULLIFIER_SECRET="${NULLIFIER_SECRET:-$(rand_limbs4)}"
WITHDRAW_NONCE="0x$(python3 -c "import secrets; print(secrets.token_hex(32))")"

# Nostr delivery target for the deposit backup (psy_deposit_proof + psy_deposit_secrets).
# A fresh throwaway keypair (secret key persisted in deposit-note.json) unless
# the caller pins one via RECIPIENT_NPUB.
if [[ -z "${RECIPIENT_NPUB:-}" ]]; then
  read -r RECIPIENT_NPUB NOSTR_SK < <(cd psy-dapp/apps/bridge && bun -e "
const { generateSecretKey, getPublicKey } = require('nostr-tools/pure');
const { nip19 } = require('nostr-tools');
const sk = generateSecretKey();
console.log(nip19.npubEncode(getPublicKey(sk)), Buffer.from(sk).toString('hex'));
")
else
  NOSTR_SK=""
fi
NOSTR_RELAY_URL="ws://127.0.0.1:8081"  # devnet nostr-relay container; CLI default is a public relay
# Relayer claim path can take up to 1800s (runbook); keep default conservative.
MAX_WAIT_SECS="${MAX_WAIT_SECS:-1800}"
POLL_INTERVAL="${POLL_INTERVAL:-15}"

# ─── Helpers ──────────────────────────────────────────────────────────────────
log() { echo "[$(date +%H:%M:%S)] $*"; }
fail() { log "FAIL: $*"; exit 1; }
ok() { log "OK: $*"; }

cast_call() {
  cast call "$@" --rpc-url "$RPC_URL" 2>/dev/null
}

cast_send_user() {
  # Keep stderr/stdout visible: under set -e a reverted send must surface its
  # reason instead of silently exiting the script.
  local out
  if ! out=$(cast send "$@" --rpc-url "$RPC_URL" --private-key "$USER_PK" 2>&1); then
    log "cast send failed: $out"
    fail "cast send $* failed"
  fi
  echo "$out"
}

wait_for() {
  local desc="$1" check_expr="$2" max_secs="${3:-$MAX_WAIT_SECS}"
  local deadline=$((SECONDS + max_secs))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if eval "$check_expr"; then return 0; fi
    sleep "$POLL_INTERVAL"
  done
  fail "timeout waiting for $desc (${max_secs}s)"
}

# ─── Read deployed addresses ──────────────────────────────────────────────────
read_addresses() {
  local deploy_file="psy-contracts/deployments/localhost/deployed-contracts.json"
  [ -f "$deploy_file" ] || fail "deploy file not found: $deploy_file"
  BRIDGE=$(python3 -c "import json; print(json.load(open('$deploy_file'))['contracts']['Bridge'])")
  ROUTER=$(python3 -c "import json; print(json.load(open('$deploy_file'))['contracts']['Router'])")
  GATEWAY=$(python3 -c "import json; print(json.load(open('$deploy_file'))['contracts']['ERC20Gateway'])")
  USDT=$(python3 -c "import json; print(json.load(open('$deploy_file'))['protocol']['tokens']['USDT']['l1Address'])")
  STATE_MANAGER=$(python3 -c "import json; print(json.load(open('$deploy_file'))['core']['StateManager'])")
  log "Bridge=$BRIDGE USDT=$USDT Gateway=$GATEWAY"
}

# ─── Step 1: Register user ────────────────────────────────────────────────────
register_user() {
  log "Step 1: Register user"
  local reg_output
  if ! reg_output=$(./target/release/psy_user_cli register-user \
    --sign-type zk -p "$USER_PK" \
    --result-file "$RESULT_DIR/register-user.json" \
    --rpc-config "$RPC_CONFIG" 2>&1); then
    echo "$reg_output" >&2
    fail "user registration failed"
  fi

  PUBLIC_KEY_HASH="$(jq -r '.public_key_hash // empty' "$RESULT_DIR/register-user.json")"
  [ -n "$PUBLIC_KEY_HASH" ] || fail "register-user result missing public_key_hash"

  USER_ID=""
  wait_for "user_id for public key $PUBLIC_KEY_HASH" "
    USER_ID=\$(./target/release/psy_user_cli get-user-id \
      --pub-key '$PUBLIC_KEY_HASH' \
      --result-file '$RESULT_DIR/get-user-id.json' \
      --rpc-config '$RPC_CONFIG' 2>&1 | grep -oP 'user_id:\s*\K[0-9]+' | head -1) || USER_ID=''
    [ -n \"\$USER_ID\" ]
  "
  [ -n "$USER_ID" ] || fail "get-user-id returned no user_id for public key $PUBLIC_KEY_HASH"
  ok "user registered/resolved"
  log "  user_id=$USER_ID"
}

# ─── Step 2: Faucet claim + recipient simple_claim ───────────────────────────
# The faucet operator transfer records amount_sent for the recipient; the
# recipient must simple_claim it into their contract-0 fee balance
# (psy-compiler/psy-precompiles/token/src/main.psy:444-465).
fee_balance() {
  # PSY token balance lives in the contract-0 state tree leaf 0, NOT in the
  # user-leaf staked `balance` field (common-operations.md Section 9).
  ./target/release/psy_user_cli get-user-contract-state-tree-leaf-hash \
    --leaf-id 0 --user-id "$USER_ID" --contract-id 0 --checkpoint-id 999999 \
    --rpc-config "$RPC_CONFIG" 2>/dev/null \
    | python3 -c "import sys; s=sys.stdin.read(); h=[l for l in s.splitlines() if l.startswith('\"0')]; print(int(h[-1].strip('\"'), 16) if h else 0)" || echo 0
}

claim_faucet() {
  log "Step 2: Faucet claim + simple_claim (L2 fee funding)"
  local bal
  bal=$(fee_balance)
  if [ "${bal:-0}" -gt 0 ]; then
    ok "fee balance already $bal; skipping faucet"
    return 0
  fi

  local resp operator
  resp=$(curl -fsS -m 120 -X POST http://127.0.0.1:9998 \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"psy_claim_faucet\",\"params\":{\"input\":{\"recipient_user_id\":$USER_ID,\"recipient_public_key\":\"$PUBLIC_KEY_HASH\"}}}")
  echo "$resp" | jq -e '.error == null and .result.operator_user_id != null' >/dev/null \
    || fail "faucet claim failed: $resp"
  operator=$(echo "$resp" | jq -r '.result.operator_user_id')
  log "  faucet tx=$(echo "$resp" | jq -r '.result.tx_hash') operator=$operator already_submitted=$(echo "$resp" | jq -r '.result.already_submitted')"
  # Submit simple_claim directly; the recipient's first UPS session starts
  # from the register-user path and credits the claim before the end-of-session
  # fee burn, so no pre-existing leaf is required.
  local claim_output claim_ok=0
  for attempt in 1 2 3; do
    claim_output=$(./target/release/psy_user_cli \
      --result-file "$RESULT_DIR/claim-psy.json" \
      call --sign-type zk -p "$USER_PK" \
      --rpc-config "$RPC_CONFIG" \
      --contract-id 0 --method-name simple_claim \
      --inputs "[$operator]" --wait-until-confirmation 2>&1) && claim_ok=1 && break
    log "  simple_claim attempt $attempt failed; operator transfer may not be included yet: $(echo "$claim_output" | grep -m1 'Error' || echo "$claim_output" | tail -1)"
    sleep 30
  done
  [ "$claim_ok" -eq 1 ] || fail "simple_claim failed after retries: $claim_output"
  jq -e '.status == "confirmed" and .confirmed_checkpoint != null' "$RESULT_DIR/claim-psy.json" >/dev/null \
    || fail "simple_claim not confirmed"
  echo "$resp" | jq -e '.error == null and .result.operator_user_id != null' >/dev/null \
    || fail "faucet claim failed: $resp"

  bal=$(fee_balance)
  [ "${bal:-0}" -gt 0 ] || fail "fee balance still 0 after simple_claim"
  ok "L2 fee balance funded: $bal"
}

# ─── Step 3: L1 deposit ───────────────────────────────────────────────────────
# Persist secrets BEFORE the L1 transaction; a crash after the tx but before
# proof generation must still leave recoverable claim material on disk.
persist_secrets() {
  python3 - "$USER_ID" "$R0" "$R1" "$NOTE_SECRET" "$NULLIFIER_SECRET" \
    "$RECIPIENT_NPUB" "${NOSTR_SK:-}" > "$RESULT_DIR/deposit-note.json" <<'PYEOF'
import json, sys
print(json.dumps({
    "user_id": int(sys.argv[1]),
    "r0": sys.argv[2],
    "r1": sys.argv[3],
    "note_secret": sys.argv[4],
    "nullifier_secret": sys.argv[5],
    "recipient_npub": sys.argv[6],
    "nostr_secret_key": sys.argv[7],
    "tx_hash": None,
    "deposit_index": None,
    "shield_address": None,
    "deposit_proof": None,
}, indent=1))
PYEOF
  chmod 600 "$RESULT_DIR/deposit-note.json"
}

update_note() {
  python3 - "$1" "$2" "$3" "$4" "$RESULT_DIR/deposit-note.json" <<'PYEOF'
import json, sys
note = json.load(open(sys.argv[5]))
note["tx_hash"], note["deposit_index"], note["shield_address"], note["deposit_proof"] = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
json.dump(note, open(sys.argv[5], "w"), indent=1)
PYEOF
  chmod 600 "$RESULT_DIR/deposit-note.json"
}

l1_deposit() {
  log "Step 3: L1 deposit USDT ($DEPOSIT_AMOUNT)"

  # Fund the depositor from the devnet deployer on a fresh chain (USDT mints
  # to the deployer only; anvil accounts start with ETH but no USDT).
  local bal
  bal=$(cast_call "$USDT" "balanceOf(address)(uint256)" "$USER_ADDR" | awk '{print $1}')
  if [ "${bal:-0}" -lt "$DEPOSIT_AMOUNT" ]; then
    cast send "$USDT" "transfer(address,uint256)" "$USER_ADDR" "$DEPOSIT_AMOUNT" \
      --rpc-url "$RPC_URL" --private-key "$DEPLOYER_PK" --gas-limit 100000 > /dev/null
    ok "funded depositor with $DEPOSIT_AMOUNT USDT"
  fi

  # The ERC20Gateway is the L1 spender; Router approval is unnecessary
  # (deposit-withdrawal.md preconditions).
  cast_send_user "$USDT" "approve(address,uint256)" "$GATEWAY" "$DEPOSIT_AMOUNT" --gas-limit 100000
  ok "approved Gateway"

  # Capture the finalize cursor BEFORE the L1 deposit so Step 4 waits for a
  # measured advance, not the always-true > 0 (bridge-common-operations.md:197).
  FINALIZED_BEFORE_DEPOSIT=$(cast_call "$STATE_MANAGER" "lastFinalizedCheckpointId()(uint64)" | awk '{print $1}')
  log "  finalized cursor before deposit: $FINALIZED_BEFORE_DEPOSIT"

  # Secrets hit disk before any L1 transaction.
  persist_secrets

  # NO automatic retry here: the "deposit tx:" marker prints only after
  # eth_sendRawTransaction returns, so an ambiguous failure cannot be
  # distinguished from an accepted deposit, and a retry would broadcast a
  # second deposit with the same nullifier secret (unclaimable duplicate).
  local dep_output
  if ! dep_output=$(./target/release/psy_user_cli deposit \
    -p "$USER_PK" \
    --router-address "$ROUTER" \
    --token "$USDT" \
    --amount "$DEPOSIT_AMOUNT" \
    --note-secret "$NOTE_SECRET" \
    --nullifier-secret "$NULLIFIER_SECRET" \
    --deposit-proof-output "$RESULT_DIR/deposit-proof.json" \
    --rpc-config "$RPC_CONFIG" \
    --r0 "$R0" --r1 "$R1" --user-id "$USER_ID" \
    --recipient-npub "$RECIPIENT_NPUB" \
    --nostr-relay "$NOSTR_RELAY_URL" 2>&1); then
    fail "deposit failed; claim material preserved in $RESULT_DIR/deposit-note.json. NEVER rerun deposit for the same secrets: $(echo "$dep_output" | grep -m1 'Error' || echo "$dep_output" | tail -2 | head -1)"
  fi

  tx_hash=$(echo "$dep_output" | grep -oP 'deposit tx:\s*\K0x[0-9a-fA-F]+' | head -1)
  SHIELD_BYTES32=$(jq -c '.shield_address' "$RESULT_DIR/deposit-proof.json" | python3 -c "import sys; w=[int(x.strip('\"')) for x in sys.stdin.read().strip().strip('[]').split(',')]; print('0x'+''.join(f'{x:016x}' for x in w))")
  log "  shield_address_bytes32=$SHIELD_BYTES32"

  # The proof file is written only after relayer proof readiness; take the
  # index from it, never from the global pendingDepositCount.
  [ -f "$RESULT_DIR/deposit-proof.json" ] || fail "deposit proof file missing"
  proof_index=$(jq -r '.deposit_index // empty' "$RESULT_DIR/deposit-proof.json")
  [ -n "$proof_index" ] || fail "deposit proof missing deposit_index"
  DEPOSIT_INDEX="$proof_index"

  update_note "$tx_hash" "$DEPOSIT_INDEX" "$SHIELD_BYTES32" "$RESULT_DIR/deposit-proof.json"
  ok "deposit done, index=$DEPOSIT_INDEX (claim material in $RESULT_DIR/deposit-note.json)"
}

# ─── Step 4: Wait for relayer to prove + finalize ─────────────────────────────
wait_prove() {
  log "Step 4: Wait for relayer to prove deposit (index=$DEPOSIT_INDEX)"
  local target=$((DEPOSIT_INDEX + 1))
  wait_for "provedDepositCount >= $target and checkpoint finalized" "
    [ \"\$(cast_call '$BRIDGE' 'provedDepositCount()(uint256)' | awk '{print \$1}')\" -ge $target ] \
    && [ \"\$(cast_call '$STATE_MANAGER' 'lastFinalizedCheckpointId()(uint64)' | awk '{print \$1}')\" -gt '${FINALIZED_BEFORE_DEPOSIT:-0}' ]
  "
  ok "deposit proved"
}

# ─── Step 5: L2 claim-deposit ─────────────────────────────────────────────────
claim_deposit() {
  log "Step 5: L2 claim-deposit (index=$DEPOSIT_INDEX)"
  # Retry ONLY pre-submit failures (stale anchor). A timeout after submit
  # leaves the EndCap in flight; a same-nullifier retry would then report
  # "already spent" even though the first claim later lands. After any
  # failure, check the indexer first: an already-claimed deposit is success.
  local output c_ok=0
  for attempt in 1 2 3; do
    if output=$(./target/release/psy_user_cli \
      --result-file "$RESULT_DIR/claim-deposit.json" \
      claim-deposit \
      --sign-type zk -p "$USER_PK" \
      --rpc-config "$RPC_CONFIG" \
      --l1-rpc-url "$RPC_URL" \
      --token-l1-address "$USDT" \
      --amount "$DEPOSIT_AMOUNT" \
      --source-chain-index 0 \
      --user-id "$USER_ID" \
      --deposit-index "$DEPOSIT_INDEX" \
      --deposit-proof "$RESULT_DIR/deposit-proof.json" \
      --r0 "$R0" --r1 "$R1" \
      --note-secret "$NOTE_SECRET" \
      --nullifier-secret "$NULLIFIER_SECRET" 2>&1); then c_ok=1 && break; fi
    log "  claim-deposit attempt $attempt failed: $(echo "$output" | grep -m1 'Error' || echo "$output" | tail -1)"
    if echo "$output" | grep -qE "stale trace anchor|Key not found in IMT"; then
      sleep 20; continue
    fi
    # Post-submit ambiguity: is the deposit already claimed?
    if curl -fsS -m 5 "http://127.0.0.1:3000/api/v1/get/bridge/deposits?shield_address=0x${SHIELD_BYTES32#0x}&chain_index=0" \
      | jq -e ".data.items[] | select(.deposit_index == $DEPOSIT_INDEX) | .claimed == true" >/dev/null 2>&1; then
      c_ok=1; log "  deposit already claimed on L2 (inflight EndCap landed late)"; break
    fi
    fail "claim-deposit failed with non-retryable error: $output"
  done
  [ "$c_ok" -eq 1 ] || fail "claim-deposit failed after retries: $output"
  jq -e '.status == "confirmed"' "$RESULT_DIR/claim-deposit.json" >/dev/null \
    || fail "claim-deposit not confirmed: $(echo "$output" | tail -5)"
}

# ─── Step 6: L2 withdraw ──────────────────────────────────────────────────────
l2_withdraw() {
  log "Step 6: L2 withdraw USDT ($WITHDRAW_AMOUNT)"
  log "  nonce=$WITHDRAW_NONCE"
  # Capture the L1 balance BEFORE the deposit-side effect baseline is used:
  # the deposit is already settled on L1 funds (locked in Bridge), so the
  # exact identity check in final_verify uses this pre-withdraw value.
  for baseline_attempt in 1 2 3 4 5; do
    L1_BAL_INITIAL=$(cast_call "$USDT" "balanceOf(address)(uint256)" "$USER_ADDR" | awk '{print $1}')
    [ -n "$L1_BAL_INITIAL" ] && break
    sleep 5
  done
  [ -n "$L1_BAL_INITIAL" ] || fail "cannot read L1 USDT balance"
  log "  L1 USDT balance initial: $L1_BAL_INITIAL"

  # The chain advances while the session proves; a stale trace anchor is the
  # documented retryable failure. Retry ONLY pre-submit failures: a timeout
  # after submit leaves the EndCap in flight and the nonce is unique per L2
  # IMT, so a blind retry would report "nonce already used" or double-submit.
  local output w_ok=0
  for attempt in 1 2 3 4; do
    if output=$(./target/release/psy_user_cli \
      --result-file "$RESULT_DIR/withdraw.json" \
      withdraw \
      --sign-type zk -p "$USER_PK" \
      --rpc-config "$RPC_CONFIG" \
      --l1-rpc-url "$RPC_URL" \
      --destination-chain-index 0 \
      --token-address "$USDT" \
      --amount "$WITHDRAW_AMOUNT" \
      --recipient "$USER_ADDR" \
      --nonce "$WITHDRAW_NONCE" 2>&1); then w_ok=1 && break; fi
    log "  withdraw attempt $attempt failed: $(echo "$output" | grep -m1 'Error' || echo "$output" | tail -1)"
    if echo "$output" | grep -qE "stale trace anchor|Key not found in IMT"; then
      sleep 10; continue
    fi
    fail "withdraw failed with non-retryable error (EndCap may be in flight; check $RESULT_DIR/withdraw.json): $output"
  done
  [ "$w_ok" -eq 1 ] || fail "withdraw failed after retries: $output"
  jq -e '.status == "confirmed"' "$RESULT_DIR/withdraw.json" >/dev/null \
    || fail "withdraw not confirmed: $(echo "$output" | tail -5)"
  ok "withdraw confirmed"
}

# ─── Step 7: Relayer batch claim + user claimPendingWithdrawal ────────────────
# batchClaimWithdrawal only REGISTERS a pending withdrawal; the token transfer
# happens in claimPendingWithdrawal, which the relayer never sends.
wait_l1_claim() {
  log "Step 7: Wait for relayer batchClaimWithdrawal, then claimPendingWithdrawal"

  wait_for "withdrawal nullifier claimed" \
    "[ \"\$(cast_call '$BRIDGE' 'claimedNullifiers(bytes32)(bool)' '$WITHDRAW_NONCE')\" = \"true\" ]"
  ok "relayer registered pending withdrawal"

  local pending claimable
  wait_for "pending withdrawal registered" "
    pending=\$(cast_call '$BRIDGE' 'pendingWithdrawals(bytes32)(address,address,uint256,uint64)' '$WITHDRAW_NONCE' 2>/dev/null | tail -n 2 | head -1 | tr -d '[:space:]')
    [ \"\${pending:-0}\" -gt 0 ]
  "
  pending=$(cast_call "$BRIDGE" "pendingWithdrawals(bytes32)(address,address,uint256,uint64)" "$WITHDRAW_NONCE")
  claimable=$(echo "$pending" | tail -n 1 | tr -d '[:space:]' | cut -d'[' -f1)
  log "  pending amount=$(echo "$pending" | sed -n 3p) claimableAt=$claimable"

  if [ "${claimable:-0}" -gt 0 ]; then
    # claimableAt is an L1 block timestamp; compare against the chain clock,
    # not the host clock (anvil time can drift after a state reload).
    wait_for "claimableAt reached ($claimable)" "[ \"\$(cast block latest --field timestamp --rpc-url '$RPC_URL' 2>/dev/null | python3 -c 'import sys; print(int(sys.stdin.read().strip(), 16))')\" -ge $claimable ]" 300
  fi

  cast_send_user "$BRIDGE" "claimPendingWithdrawal(bytes32)" "$WITHDRAW_NONCE" --gas-limit 200000 > /dev/null
  ok "claimPendingWithdrawal sent"

  # L1_BAL_INITIAL was captured after the deposit locked its funds in the
  # Bridge, so the settlement identity is initial + withdraw (the deposit
  # side already moved out of the free balance).
  local expected=$((L1_BAL_INITIAL + WITHDRAW_AMOUNT))
  wait_for "pending cleared and L1 USDT balance == $expected" "
    [ \"\$(cast_call '$BRIDGE' 'pendingWithdrawals(bytes32)(address,address,uint256,uint64)' '$WITHDRAW_NONCE' 2>/dev/null | tail -n +3 | head -1 | tr -d '[:space:]')\" -eq 0 ] \
    && [ \"\$(cast_call '$USDT' 'balanceOf(address)(uint256)' '$USER_ADDR' | awk '{print \$1}')\" -eq $expected ]
  "
  ok "L1 settlement complete"
}

final_verify() {
  log "Step 8: Final verification"
  local l1_bal
  l1_bal=$(cast_call "$USDT" "balanceOf(address)(uint256)" "$USER_ADDR" | awk '{print $1}')
  local expected=$((L1_BAL_INITIAL + WITHDRAW_AMOUNT))
  if [ "$l1_bal" -ne "$expected" ]; then
    fail "L1 balance identity violated: got $l1_bal, expected pre-withdraw($L1_BAL_INITIAL) + withdraw($WITHDRAW_AMOUNT) = $expected"
  fi
  log "  L1 USDT: $l1_bal == pre-withdraw($L1_BAL_INITIAL) + withdraw($WITHDRAW_AMOUNT)"

  # Deposit must be marked claimed in the indexer (L2 nullifier consumed).
  local shield_no0x="${SHIELD_BYTES32#0x}"
  curl -fsS -m 5 "http://127.0.0.1:3000/api/v1/get/bridge/deposits?shield_address=0x$shield_no0x&chain_index=0" \
    | jq -e ".data.items[] | select(.deposit_index == $DEPOSIT_INDEX) | .claimed == true" >/dev/null \
    || fail "deposit index=$DEPOSIT_INDEX not marked claimed in indexer"
  ok "deposit marked claimed"
  ok "E2E PASSED (L1 USDT $L1_BAL_INITIAL -> $l1_bal)"
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
  read_addresses
  register_user
  claim_faucet
  l1_deposit
  wait_prove
  claim_deposit
  l2_withdraw
  wait_l1_claim
  final_verify
}

main "$@"