#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GENERATOR="$ROOT/psy_plonky2_circuits/src/node/config/networks/local_devnet.rs"
PREPARE="$ROOT/deploy/gcp/fresh-staging/04_prepare_local_bundle.sh"

operator_count="$(
  sed -n 's/.*const FAUCET_OPERATOR_COUNT: usize = \([0-9][0-9]*\);.*/\1/p' "$GENERATOR" \
    | head -1
)"
expected_user_count="$(
  sed -n 's/.*EXPECTED_GENESIS_USER_COUNT="${EXPECTED_GENESIS_USER_COUNT:-\([0-9][0-9]*\)}".*/\1/p' "$PREPARE" \
    | head -1
)"

[ "$operator_count" = "10" ] || {
  echo "expected genesis generator to create 10 faucet operators, got ${operator_count:-missing}" >&2
  exit 1
}
[ "$expected_user_count" = "$((4 + operator_count))" ] || {
  echo "genesis generator and deployment user counts disagree" >&2
  echo "generator users: $((4 + operator_count))" >&2
  echo "deployment users: ${expected_user_count:-missing}" >&2
  exit 1
}

dedicated_key_line="$(grep -n 'read_env("BRIDGE_RELAYER_L2_PRIVATE_KEY")' "$GENERATOR" | head -1 | cut -d: -f1)"
generic_key_line="$(grep -n 'read_env("PRIVATE_KEY")' "$GENERATOR" | head -1 | cut -d: -f1)"
[ -n "$dedicated_key_line" ] && [ -n "$generic_key_line" ] && [ "$dedicated_key_line" -le "$generic_key_line" ] || {
  echo "genesis generator must prefer BRIDGE_RELAYER_L2_PRIVATE_KEY over PRIVATE_KEY" >&2
  exit 1
}
grep -q 'genesis relayer private key does not match BRIDGE_RELAYER_L2_PRIVATE_KEY' "$PREPARE" || {
  echo "deployment must reject a generated relayer key mismatch" >&2
  exit 1
}

echo "[ok] genesis generator creates 4 reserved users and 10 faucet operators"
