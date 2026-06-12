#!/bin/bash
set -euo pipefail

# Run transactions against a running local devnet with registered users + deployed contracts
# Usage: ./client_prover/dev/run_transactions.sh
#
# Prerequisites:
#   - Local devnet running (bun run dev/locSetupV4.ts)
#   - Users registered & contract deployed (./client_prover/dev/register_and_deploy.sh)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$CLIENT_DIR/.." && pwd)"
BIN="$ROOT_DIR/target/release/psy_user_cli"

LOG_LEVEL="psy_user_cli=info,psy_prover=info"

# Test user keys (insecure - for local devnet only)
USER0_KEY="c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359"
USER1_KEY="f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d"

CONTRACT_ID=0

echo "============================================"
echo "PSY Client E2E: Run Transactions"
echo "============================================"

cd "$CLIENT_DIR"

# Mint tokens
echo "[1/3] Minting tokens..."
echo "  USER0 minting 1000 tokens..."
RUST_LOG="$LOG_LEVEL" "$BIN" call \
    -p "$USER0_KEY" \
    --contract-id "$CONTRACT_ID" \
    --method-name simple_mint \
    --inputs "[1000000000000]" 2>&1 | tail -5

echo "  USER1 minting 1000 tokens..."
RUST_LOG="$LOG_LEVEL" "$BIN" call \
    -p "$USER1_KEY" \
    --contract-id "$CONTRACT_ID" \
    --method-name simple_mint \
    --inputs "[1000000000000]" 2>&1 | tail -5

echo "  Waiting for minting to be processed..."
sleep 10

# Transfer tokens
echo ""
echo "[2/3] Transferring tokens..."
echo "  USER0 transferring 250 tokens to USER1..."
RUST_LOG="$LOG_LEVEL" "$BIN" call \
    -p "$USER0_KEY" \
    --contract-id "$CONTRACT_ID" \
    --method-name simple_transfer \
    --inputs "[1, 250000000000]" 2>&1 | tail -5

echo "  Waiting for transfer to be processed..."
sleep 10

# Claim transfers
echo ""
echo "[3/3] Claiming transfers..."
echo "  USER1 claiming transfer from USER0..."
RUST_LOG="$LOG_LEVEL" "$BIN" call \
    -p "$USER1_KEY" \
    --contract-id "$CONTRACT_ID" \
    --method-name simple_claim \
    --inputs "[0]" 2>&1 | tail -5

echo ""
echo "============================================"
echo "Transactions complete!"
echo "============================================"
