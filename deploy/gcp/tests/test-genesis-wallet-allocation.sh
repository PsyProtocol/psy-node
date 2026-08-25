#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GCP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

EXPECTED_BRIDGE_RELAYER_KEY_INDEX=2
EXPECTED_FAUCET_OPERATOR_START_INDEX=4
EXPECTED_FAUCET_OPERATOR_COUNT=10
EXPECTED_GENESIS_ZK_FINGERPRINT="65e0169bfffd55f1c0ea9f76c111a5b15e652322ee253c1a9604a10d59066b50"
EXPECTED_GENESIS_SDK_KEY_FINGERPRINT="38755910c4dfb3c9bef528a4af697edced7e2607a6b769d054c4985a7000f0eb"
EXPECTED_GENESIS_RESERVED_SLOT_VALUE="0000000000000000000000000000000000000000000000000000000000000000"
EXPECTED_GENESIS_RELAYER_SLOT_VALUE="00000000000000000000000000000000000000000000000000038d7ea4c68000"
EXPECTED_GENESIS_FAUCET_OPERATOR_SLOT_VALUE="000000000000000000000000000000000000000000000000016345785d8a0000"
EXPECTED_GENESIS_LAST_FAUCET_OPERATOR_SLOT_VALUE="000000000000000000000000000000000000000000000000015fb7f9b8c38000"
EXPECTED_GENESIS_TOTAL_SUPPLY_NANO=1000000000000000000

# shellcheck source=deploy/gcp/lib/genesis-wallet-allocation.sh
source "$GCP_DIR/lib/genesis-wallet-allocation.sh"

fixture="$(mktemp)"
trap 'rm -f "$fixture"' EXIT

jq -n \
  --arg zk "$EXPECTED_GENESIS_ZK_FINGERPRINT" \
  --arg sdk "$EXPECTED_GENESIS_SDK_KEY_FINGERPRINT" \
  --arg zero "$EXPECTED_GENESIS_RESERVED_SLOT_VALUE" '
    {users: [range(0; 14) as $i | {
      public_key_info: {fingerprint: (if $i < 4 then $zk else $sdk end)},
      constract_state_tree_records: [{children: [{value: $zero}]}]
    }]}
  ' > "$fixture"

apply_genesis_wallet_allocation "$fixture"
verify_genesis_wallet_allocation "$fixture" "test genesis.json"

jq -e \
  --arg relayer "$EXPECTED_GENESIS_RELAYER_SLOT_VALUE" \
  --arg regular "$EXPECTED_GENESIS_FAUCET_OPERATOR_SLOT_VALUE" \
  --arg last "$EXPECTED_GENESIS_LAST_FAUCET_OPERATOR_SLOT_VALUE" '
    .users[2].constract_state_tree_records[0].children[0].value == $relayer
    and .users[12].constract_state_tree_records[0].children[0].value == $regular
    and .users[13].constract_state_tree_records[0].children[0].value == $last
  ' "$fixture" >/dev/null

jq \
  '.users[0].constract_state_tree_records[0].children[0].value
    = "0000000000000000000000000000000000000000000000000000000000000001"' \
  "$fixture" > "${fixture}.invalid"
if (verify_genesis_total_supply "${fixture}.invalid" "invalid genesis.json" >/dev/null 2>&1); then
  echo "total supply validation accepted an extra nano PSY" >&2
  exit 1
fi
rm -f "${fixture}.invalid"

echo "[ok] relayer and faucet Genesis allocation preserves 1B PSY supply"
