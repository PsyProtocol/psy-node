#!/bin/bash
set -euo pipefail

# Full UPS (User Proof System) end-to-end example
# Demonstrates: register -> deploy -> mint -> transfer -> claim
#
# Usage:
#   Terminal 1: cd <repo-root> && make run-all
#   Terminal 2: ./client_prover/dev/ups_e2e.sh
#
# This script runs all client operations sequentially against a running local devnet.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$CLIENT_DIR/.." && pwd)"
BIN="$ROOT_DIR/target/release/psy_user_cli"

LOG_LEVEL="psy_user_cli=info,psy_prover=info"
SIGN_TYPE="${SIGN_TYPE:-zk}"
WAIT_CHECKPOINT="${WAIT_CHECKPOINT:-12}"

# Test user keys (insecure - for local devnet only)
USER0_KEY="c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359"
USER1_KEY="f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d"
USER2_KEY="73ae514d6f69510ad778a05128d980951d9d8c097beb022471b2f50f19c41268"

CONTRACT_ID=0

echo "========================================================"
echo "  PSY UPS End-to-End Example"
echo "  Sign Type: $SIGN_TYPE"
echo "  Checkpoint Wait: ${WAIT_CHECKPOINT}s"
echo "========================================================"
echo ""

# Build
if [ ! -f "$BIN" ]; then
    echo "[BUILD] Building psy_user_cli..."
    cd "$ROOT_DIR" && RUSTFLAGS="-A warnings" cargo build --release --bin psy_user_cli
    echo "[BUILD] Done."
    echo ""
fi

cd "$CLIENT_DIR"

# Step 1: Register users
echo "========================================================"
echo "  STEP 1: Register Users"
echo "========================================================"
for i in 0 1 2; do
    eval KEY=\$USER${i}_KEY
    echo "  Registering USER$i ($SIGN_TYPE)..."
    RUST_LOG=error "$BIN" register-user --private-key="$KEY" --sign-type "$SIGN_TYPE" 2>&1 | tail -3 || true
    sleep 0.5
done

echo ""
echo "  Waiting ${WAIT_CHECKPOINT}s for registrations to be processed..."
sleep "$WAIT_CHECKPOINT"
echo ""

# Step 2: Deploy token contract
echo "========================================================"
echo "  STEP 2: Deploy Token Contract"
echo "========================================================"
echo "  USER0 deploying token.json..."
RUST_LOG="$LOG_LEVEL" "$BIN" deploy-contract \
    --private-key="$USER0_KEY" \
    --contract-path "$CLIENT_DIR/token.json" \
    --is-deploy 2>&1 | tail -5 || true

echo ""
echo "  Waiting ${WAIT_CHECKPOINT}s for deployment to be processed..."
sleep "$WAIT_CHECKPOINT"
echo ""

# Step 3: Mint tokens
echo "========================================================"
echo "  STEP 3: Mint Tokens"
echo "========================================================"
echo "  USER0 minting 1000 tokens..."
RUST_LOG="$LOG_LEVEL" "$BIN" call \
    -p "$USER0_KEY" \
    --contract-id "$CONTRACT_ID" \
    --method-name simple_mint \
    --inputs "[1000000000000]" \
    --sign-type "$SIGN_TYPE" 2>&1 | tail -5

echo "  USER1 minting 1000 tokens..."
RUST_LOG="$LOG_LEVEL" "$BIN" call \
    -p "$USER1_KEY" \
    --contract-id "$CONTRACT_ID" \
    --method-name simple_mint \
    --inputs "[1000000000000]" \
    --sign-type "$SIGN_TYPE" 2>&1 | tail -5

echo ""
echo "  Waiting ${WAIT_CHECKPOINT}s for minting to be processed..."
sleep "$WAIT_CHECKPOINT"
echo ""

# Step 4: Transfer tokens
echo "========================================================"
echo "  STEP 4: Transfer Tokens"
echo "========================================================"
echo "  USER0 transferring 250 tokens to USER1..."
RUST_LOG="$LOG_LEVEL" "$BIN" call \
    -p "$USER0_KEY" \
    --contract-id "$CONTRACT_ID" \
    --method-name simple_transfer \
    --inputs "[1, 250000000000]" \
    --sign-type "$SIGN_TYPE" 2>&1 | tail -5

echo ""
echo "  Waiting ${WAIT_CHECKPOINT}s for transfer to be processed..."
sleep "$WAIT_CHECKPOINT"
echo ""

# Step 5: Claim transfer
echo "========================================================"
echo "  STEP 5: Claim Transfer"
echo "========================================================"
echo "  USER1 claiming transfer from USER0..."
RUST_LOG="$LOG_LEVEL" "$BIN" call \
    -p "$USER1_KEY" \
    --contract-id "$CONTRACT_ID" \
    --method-name simple_claim \
    --inputs "[0]" \
    --sign-type "$SIGN_TYPE" 2>&1 | tail -5

echo ""
echo "========================================================"
echo "  UPS E2E Complete!"
echo ""
echo "  Expected final state:"
echo "    USER0: 750 tokens (minted 1000, transferred 250)"
echo "    USER1: 1250 tokens (minted 1000, claimed 250)"
echo "========================================================"
