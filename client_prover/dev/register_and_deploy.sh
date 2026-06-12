#!/bin/bash
set -euo pipefail

# Register users and deploy contracts against a running local devnet
# Usage: ./client_prover/dev/register_and_deploy.sh
#
# Prerequisites: local devnet must already be running (see: bun run dev/locSetupV4.ts)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$CLIENT_DIR/.." && pwd)"
BIN="$ROOT_DIR/target/release/psy_user_cli"

LOG_LEVEL="psy_user_cli=info"

# Test user keys (insecure - for local devnet only)
USER0_KEY="c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359"
USER1_KEY="f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d"
USER2_KEY="73ae514d6f69510ad778a05128d980951d9d8c097beb022471b2f50f19c41268"

echo "============================================"
echo "PSY Client E2E: Register & Deploy"
echo "============================================"

# Build if needed
if [ ! -f "$BIN" ]; then
    echo "[1/3] Building psy_user_cli..."
    cd "$ROOT_DIR" && RUSTFLAGS="-A warnings" cargo build --release --bin psy_user_cli
else
    echo "[1/3] psy_user_cli binary found, skipping build"
fi

# Register users
echo ""
echo "[2/3] Registering test users..."
cd "$CLIENT_DIR"
echo "  Registering USER0 (zk)..."
RUST_LOG=error "$BIN" register-user --private-key="$USER0_KEY" --sign-type zk 2>&1 | tail -5 || true
sleep 0.5

echo "  Registering USER1 (zk)..."
RUST_LOG=error "$BIN" register-user --private-key="$USER1_KEY" --sign-type zk 2>&1 | tail -5 || true
sleep 0.5

echo "  Registering USER2 (zk)..."
RUST_LOG=error "$BIN" register-user --private-key="$USER2_KEY" --sign-type zk 2>&1 | tail -5 || true

echo "  Waiting 8s for registrations to be processed..."
sleep 8

# Deploy contract
echo ""
echo "[3/3] Deploying token contract..."
RUST_LOG="$LOG_LEVEL" "$BIN" deploy-contract \
    --private-key="$USER0_KEY" \
    --contract-path "$CLIENT_DIR/token.json" \
    --is-deploy 2>&1 | tail -10 || true

echo ""
echo "============================================"
echo "Registration and deployment complete!"
echo "Wait for the next checkpoint to be processed"
echo "before running transactions."
echo "============================================"
