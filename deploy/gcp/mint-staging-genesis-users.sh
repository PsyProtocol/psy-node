#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PARTH_DIR="${PARTH_DIR:-$REPO_ROOT}"
KEYS_FILE="${GENESIS_PRIVATE_KEYS_FILE:-$PARTH_DIR/private_keys.json}"

AMOUNT_PSY="${1:-${AMOUNT_PSY:-1000}}"
USER_IDS="${MINT_USER_IDS:-2}"

if [ ! -f "$KEYS_FILE" ]; then
  echo "missing private keys file: $KEYS_FILE" >&2
  exit 1
fi

command -v jq >/dev/null 2>&1 || {
  echo "missing jq" >&2
  exit 1
}

echo "[mint-staging-genesis-users] amount_psy=${AMOUNT_PSY}"
echo "[mint-staging-genesis-users] users=${USER_IDS}"

for user_id in $USER_IDS; do
  private_key="$(jq -er --argjson idx "$user_id" '.[$idx] | select(type == "string") | select(test("^[0-9a-fA-F]{64}$"))' "$KEYS_FILE")"
  echo
  echo "[mint-staging-genesis-users] minting user_id=${user_id} key_prefix=${private_key:0:8}"
  MINT_USER_ID="$user_id" \
    MINT_QUERY_USER_LEAF="${MINT_QUERY_USER_LEAF:-0}" \
    bash "$SCRIPT_DIR/mint-staging-psy.sh" "$private_key" "$AMOUNT_PSY"
done

echo
echo "[mint-staging-genesis-users] completed"
