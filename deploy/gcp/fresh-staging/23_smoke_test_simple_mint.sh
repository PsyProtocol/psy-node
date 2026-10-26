#!/usr/bin/env bash
set -euo pipefail

FRESH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GCP_DIR="$(cd "$FRESH_DIR/.." && pwd)"

AMOUNT_PSY="${AMOUNT_PSY:-${1:-100}}"
SMOKE_USER_INDEXES="${SMOKE_USER_INDEXES:-2}"
SMOKE_SIMPLE_MINT_ENABLED="${SMOKE_SIMPLE_MINT_ENABLED:-0}"

if [ "$SMOKE_SIMPLE_MINT_ENABLED" != "1" ]; then
  echo "[23_smoke_test_simple_mint.sh] disabled; set SMOKE_SIMPLE_MINT_ENABLED=1 to mint ${AMOUNT_PSY} PSY for genesis users: ${SMOKE_USER_INDEXES}"
  exit 0
fi

echo "[23_smoke_test_simple_mint.sh] minting ${AMOUNT_PSY} PSY for genesis users: ${SMOKE_USER_INDEXES}"
SMOKE_AMOUNT_PSY="$AMOUNT_PSY" \
SMOKE_USER_INDEXES="$SMOKE_USER_INDEXES" \
  bash "$GCP_DIR/test-staging-simple-mint.sh"
