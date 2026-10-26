#!/usr/bin/env bash

genesis_slot_to_decimal() {
  local slot="$1"
  local significant

  [[ "$slot" =~ ^[0-9a-fA-F]{64}$ ]] || {
    echo "invalid 32-byte genesis slot value: $slot" >&2
    return 1
  }
  significant="${slot#"${slot%%[!0]*}"}"
  [ -n "$significant" ] || significant="0"
  printf '%s\n' "$((16#$significant))"
}

verify_genesis_total_supply() {
  local genesis_path="$1"
  local label="$2"
  local actual_total=0
  local slot
  local slot_value
  local -a slots

  mapfile -t slots < <(
    jq -r '.users[].constract_state_tree_records[0].children[0].value' "$genesis_path"
  )
  for slot in "${slots[@]}"; do
    slot_value="$(genesis_slot_to_decimal "$slot")"
    actual_total=$((actual_total + slot_value))
  done

  [ "$actual_total" = "$EXPECTED_GENESIS_TOTAL_SUPPLY_NANO" ] || {
    cat >&2 <<EOF
${label} PSY total supply mismatch.
Expected: ${EXPECTED_GENESIS_TOTAL_SUPPLY_NANO} nano PSY
Actual:   ${actual_total} nano PSY
EOF
    exit 1
  }
}

apply_genesis_wallet_allocation() {
  local genesis_path="$1"
  local tmp

  tmp="$(mktemp)"
  jq \
    --argjson relayer_index "$EXPECTED_BRIDGE_RELAYER_KEY_INDEX" \
    --argjson faucet_start "$EXPECTED_FAUCET_OPERATOR_START_INDEX" \
    --argjson faucet_count "$EXPECTED_FAUCET_OPERATOR_COUNT" \
    --arg reserved_slot "$EXPECTED_GENESIS_RESERVED_SLOT_VALUE" \
    --arg relayer_slot "$EXPECTED_GENESIS_RELAYER_SLOT_VALUE" \
    --arg faucet_slot "$EXPECTED_GENESIS_FAUCET_OPERATOR_SLOT_VALUE" \
    --arg last_faucet_slot "$EXPECTED_GENESIS_LAST_FAUCET_OPERATOR_SLOT_VALUE" '
      def set_slot($i; $v):
        .users[$i].constract_state_tree_records[0].children[0].value = $v;

      ($faucet_start + $faucet_count - 1) as $last_faucet_index
      | reduce ([0, 1, 3] | unique[]) as $i
        (. ; set_slot($i; $reserved_slot))
      | set_slot($relayer_index; $relayer_slot)
      | reduce range($faucet_start; $last_faucet_index) as $i
        (. ; set_slot($i; $faucet_slot))
      | set_slot($last_faucet_index; $last_faucet_slot)
    ' "$genesis_path" > "$tmp"
  cat "$tmp" > "$genesis_path"
  rm -f "$tmp"
}

verify_genesis_wallet_allocation() {
  local genesis_path="$1"
  local label="$2"

  jq -e \
    --argjson relayer_index "$EXPECTED_BRIDGE_RELAYER_KEY_INDEX" \
    --argjson faucet_start "$EXPECTED_FAUCET_OPERATOR_START_INDEX" \
    --argjson faucet_count "$EXPECTED_FAUCET_OPERATOR_COUNT" \
    --arg zk_fingerprint "$EXPECTED_GENESIS_ZK_FINGERPRINT" \
    --arg sdk_key_fingerprint "$EXPECTED_GENESIS_SDK_KEY_FINGERPRINT" \
    --arg reserved_slot "$EXPECTED_GENESIS_RESERVED_SLOT_VALUE" \
    --arg relayer_slot "$EXPECTED_GENESIS_RELAYER_SLOT_VALUE" \
    --arg faucet_slot "$EXPECTED_GENESIS_FAUCET_OPERATOR_SLOT_VALUE" \
    --arg last_faucet_slot "$EXPECTED_GENESIS_LAST_FAUCET_OPERATOR_SLOT_VALUE" '
      . as $genesis
      | def slot($i): $genesis.users[$i].constract_state_tree_records[0].children[0].value;
        def fingerprint($i): $genesis.users[$i].public_key_info.fingerprint;

        ($faucet_start + $faucet_count - 1) as $last_faucet_index
        |
        ([0, 1, 3] | all(. as $i | slot($i) == $reserved_slot and fingerprint($i) == $zk_fingerprint))
        and (slot($relayer_index) == $relayer_slot and fingerprint($relayer_index) == $zk_fingerprint)
        and ([range($faucet_start; $last_faucet_index)]
          | all(. as $i | slot($i) == $faucet_slot and fingerprint($i) == $sdk_key_fingerprint))
        and (slot($last_faucet_index) == $last_faucet_slot
          and fingerprint($last_faucet_index) == $sdk_key_fingerprint)
    ' "$genesis_path" >/dev/null || {
      cat >&2 <<EOF
${label} wallet allocation mismatch.
Expected:
  - worker reward ZK users 0,1,3: reserved token slot ${EXPECTED_GENESIS_RESERVED_SLOT_VALUE}
  - bridge relayer ZK user ${EXPECTED_BRIDGE_RELAYER_KEY_INDEX}: relayer token slot ${EXPECTED_GENESIS_RELAYER_SLOT_VALUE}
  - SDK-key faucet users ${EXPECTED_FAUCET_OPERATOR_START_INDEX}..$((EXPECTED_FAUCET_OPERATOR_START_INDEX + EXPECTED_FAUCET_OPERATOR_COUNT - 2)): faucet token slot ${EXPECTED_GENESIS_FAUCET_OPERATOR_SLOT_VALUE}
  - last SDK-key faucet user $((EXPECTED_FAUCET_OPERATOR_START_INDEX + EXPECTED_FAUCET_OPERATOR_COUNT - 1)): faucet token slot ${EXPECTED_GENESIS_LAST_FAUCET_OPERATOR_SLOT_VALUE}
EOF
      exit 1
    }
  verify_genesis_total_supply "$genesis_path" "$label"
}
