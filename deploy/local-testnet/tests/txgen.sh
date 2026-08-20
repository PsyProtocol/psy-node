#!/usr/bin/env bash
# Continuous transaction load for the rollback acceptance run.
#
# An idle chain rolls back cleanly and proves almost nothing: of the twelve
# defects found on 2026-08-19, eleven appeared only with transactions in flight,
# and several only on the Realm that actually held state of its own.
#
# Each round uses a fresh key, because the faucet dedupes per recipient per
# window and a reused one silently does nothing.  The contract call is what
# exercises a Realm other than the operator's: every faucet operator lives in
# realm 0, so without it realm 1 never commits state of its own.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

OUT="${1:?usage: txgen.sh <log-file>}"
CFG="${PSY_RPC_CONFIG:-client_prover/config.json}"
CONTRACT="${PSY_TX_CONTRACT:-client_prover/psy_cli/psy_user_cli/contract.json}"
CALLS="${PSY_TX_CALLS:-client_prover/contract_call.json}"
FAUCET="${PSY_FAUCET_URL:-http://127.0.0.1:9998}"
CLI=./target/release/psy_user_cli

say() { echo "[$(date -u +%T)] $*" >> "$OUT"; }

round=0
while true; do
  round=$((round + 1))
  KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))")

  PUB=$(timeout 400 $CLI register-user --rpc-config "$CFG" --sign-type secp256k1 -p "$KEY" 2>&1 \
        | grep -oE '"public_key_hash": "[a-f0-9]+"' | grep -oE '[a-f0-9]{64}')
  if [ -z "$PUB" ]; then say "round $round: register FAILED"; sleep 10; continue; fi
  say "round $round: registered $PUB"

  # Nothing may depend on the user before its id has landed on chain.  An empty
  # answer here means "not yet", not "never".
  USERID=""
  for _ in $(seq 1 20); do
    USERID=$($CLI get-user-id --rpc-config "$CFG" --pub-key "$PUB" 2>&1 \
             | grep -oE 'user_id: [0-9]+' | grep -oE '[0-9]+')
    [ -n "$USERID" ] && break
    sleep 10
  done
  if [ -z "$USERID" ]; then say "round $round: user id never landed"; continue; fi
  say "round $round: user_id=$USERID"

  # --is-deploy is what submits it.  Without the flag the subcommand generates
  # the circuits locally and returns success having sent nothing, so 1292
  # consecutive "deploy ok" lines coexisted with a chain whose only contracts
  # were the six from genesis -- and contract_leaf, contract_code_definition,
  # contract_state_tree_height and contract_function_tree were never written
  # inside a rollback window, so no rollback ever archived one.
  if timeout 900 $CLI deploy-contract --rpc-config "$CFG" --sign-type secp256k1 \
       -p "$KEY" --contract-path "$CONTRACT" --is-deploy >> "$OUT" 2>&1; then
    say "round $round: deploy ok"
  else
    say "round $round: deploy FAILED"
  fi

  R=$(curl -s -X POST "$FAUCET" -H 'Content-Type: application/json' \
      -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"psy_claim_faucet\",\"params\":[{\"recipient_user_id\":$USERID,\"recipient_public_key\":\"$PUB\"}]}" \
      --max-time 400)
  say "round $round: faucet $(echo "$R" | head -c 200)"

  if timeout 500 $CLI call --rpc-config "$CFG" --sign-type secp256k1 \
       -p "$KEY" --contract-calls-file "$CALLS" >> "$OUT" 2>&1; then
    say "round $round: call ok (user $USERID)"
  else
    say "round $round: call FAILED (user $USERID)"
  fi

  sleep 5
done
