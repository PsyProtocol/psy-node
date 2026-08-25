#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PARTH_DIR="${PARTH_DIR:-$REPO_ROOT}"

CONFIG_FILE="${GCP_DEPLOY_CONFIG:-$SCRIPT_DIR/config.env}"
if [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
fi
# shellcheck source=lib/public-domains.sh
source "$SCRIPT_DIR/lib/public-domains.sh"
set_public_domain_defaults

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing command: $1" >&2
    exit 1
  }
}

require_cmd jq

KEYS_FILE="${GENESIS_PRIVATE_KEYS_FILE:-$PARTH_DIR/private_keys.json}"
GENESIS_FILE="${GENESIS_FILE:-$PARTH_DIR/genesis.json}"
USER_CLI="${USER_CLI:-$PARTH_DIR/target/release/psy_user_cli}"
OUTPUT_FILE="${OUTPUT_FILE:-}"
FAUCET_CONTRACT_ID="${PSY_FAUCET_CONTRACT_ID:-5}"
FAUCET_METHOD_NAME="${PSY_FAUCET_METHOD_NAME:-faucet}"
FAUCET_METHOD_ID="${PSY_FAUCET_METHOD_ID:-3375543263}"
SIMPLE_TRANSFER_METHOD_ID="${PSY_SIMPLE_TRANSFER_METHOD_ID:-354447671}"
SIMPLE_BURN_METHOD_ID="${PSY_SIMPLE_BURN_METHOD_ID:-2923993647}"
FAUCET_PER_CLAIM_AMOUNT_NANO="${PSY_FAUCET_PER_CLAIM_AMOUNT_NANO:-1000000000000}"
SDK_KEY_EXPECTED_TX_COUNT="${PSY_FAUCET_SDK_KEY_EXPECTED_TX_COUNT:-3}"
FAUCET_OPERATOR_START_INDEX="${FAUCET_OPERATOR_START_INDEX:-4}"
FAUCET_OPERATOR_COUNT="${FAUCET_OPERATOR_COUNT:-10}"

[ -f "$KEYS_FILE" ] || {
  echo "missing private keys file: $KEYS_FILE" >&2
  exit 1
}
[ -x "$USER_CLI" ] || {
  echo "missing executable: $USER_CLI" >&2
  exit 1
}

items_file="$(mktemp)"
genesis_users_file="$(mktemp)"
trap 'rm -f "$items_file" "$genesis_users_file"' EXIT

genesis_users=()
if [ -f "$GENESIS_FILE" ]; then
  jq -r '.users[] | [.public_key_info.public_key_param, .public_key_info.fingerprint] | @tsv' \
    "$GENESIS_FILE" > "$genesis_users_file"
  mapfile -t genesis_users < "$genesis_users_file"
fi

reverse_bits_in_limit() {
  local value="$1"
  local bit_count="$2"
  local out=0
  local i

  for ((i = 0; i < bit_count; i++)); do
    out=$(( (out << 1) | ((value >> i) & 1) ))
  done
  printf '%s\n' "$out"
}

genesis_user_id_for_key_index() {
  local key_index="$1"
  local realm_user_tree_height="${GENESIS_REALM_USER_TREE_HEIGHT:-20}"
  local group_realm_height="${GENESIS_GROUP_REALM_HEIGHT:-1}"
  local realm_mask=$(( (1 << group_realm_height) - 1 ))
  local user_mask=$(( (1 << realm_user_tree_height) - 1 ))
  local realm_index=$(( key_index & realm_mask ))
  local user_index=$(( (key_index >> group_realm_height) & user_mask ))
  local group_id=$(( key_index >> (group_realm_height + realm_user_tree_height) ))
  local reversed_realm_index
  local reversed_user_index
  local full_realm_id

  reversed_realm_index="$(reverse_bits_in_limit "$realm_index" "$group_realm_height")"
  reversed_user_index="$(reverse_bits_in_limit "$user_index" "$realm_user_tree_height")"
  full_realm_id=$(( (group_id << group_realm_height) | reversed_realm_index ))
  printf '%s\n' "$(( (full_realm_id << realm_user_tree_height) | reversed_user_index ))"
}

fingerprint="$(
  cd "$PARTH_DIR"
  RUST_LOG=error "$USER_CLI" wallet sd-key-fingerprint \
    --allowed-contract-id "$FAUCET_CONTRACT_ID" \
    --allowed-contract-id 0 \
    --allowed-contract-id 0 \
    --allowed-method-id "$FAUCET_METHOD_ID" \
    --allowed-method-id "$SIMPLE_TRANSFER_METHOD_ID" \
    --allowed-method-id "$SIMPLE_BURN_METHOD_ID" \
    --expected-tx-count "$SDK_KEY_EXPECTED_TX_COUNT"
)"

: > "$items_file"
end_index=$((FAUCET_OPERATOR_START_INDEX + FAUCET_OPERATOR_COUNT - 1))
for key_index in $(seq "$FAUCET_OPERATOR_START_INDEX" "$end_index"); do
  operator_number=$((key_index - FAUCET_OPERATOR_START_INDEX + 1))
  if [ "$operator_number" -eq 1 ] || [ $((operator_number % 10)) -eq 0 ]; then
    echo "[faucet-operators] validating operator ${operator_number}/${FAUCET_OPERATOR_COUNT}" >&2
  fi
  private_key="$(jq -er --argjson idx "$key_index" '.[$idx] | select(type == "string") | select(test("^[0-9a-fA-F]{64}$"))' "$KEYS_FILE")"
  wallet_info="$(
    cd "$PARTH_DIR"
    env -u KEYSTORE_PATH -u PRIVATE_KEY RUST_LOG=error "$USER_CLI" wallet info \
      --private-key "$private_key" \
      --sign-type sd-key \
      --fingerprint "$fingerprint"
  )"
  public_key_param="$(awk '/^public_key_param:/{print $2}' <<< "$wallet_info")"
  public_key="$(awk '/^public_key:/{print $2}' <<< "$wallet_info")"
  user_id="$(genesis_user_id_for_key_index "$key_index")"
  [ -n "$user_id" ] || {
    echo "failed to derive user id for faucet operator key index $key_index" >&2
    exit 1
  }
  [ -n "$public_key" ] || {
    echo "failed to derive public key for faucet operator key index $key_index" >&2
    exit 1
  }

  if [ "${#genesis_users[@]}" -gt 0 ]; then
    [ "$key_index" -lt "${#genesis_users[@]}" ] || {
      echo "genesis is missing faucet operator key index $key_index" >&2
      exit 1
    }
    IFS=$'\t' read -r genesis_public_key_param genesis_fingerprint <<< "${genesis_users[$key_index]}"
    [ "$genesis_public_key_param" = "$public_key_param" ] || {
      echo "faucet operator key index $key_index does not match genesis public_key_param" >&2
      exit 1
    }
    [ "$genesis_fingerprint" = "$fingerprint" ] || {
      echo "faucet operator key index $key_index fingerprint does not match genesis" >&2
      exit 1
    }
  fi

  jq -n \
    --arg userId "$user_id" \
    --arg address "$public_key" \
    --arg privateKey "$private_key" \
    --arg fingerprint "$fingerprint" \
    '{
      userId: $userId,
      address: $address,
      privateKey: $privateKey,
      fingerprint: $fingerprint,
      signType: "sd-key"
    }' >> "$items_file"
done

json="$(
  jq -s \
    --argjson faucetContractId "$FAUCET_CONTRACT_ID" \
    --arg faucetMethodName "$FAUCET_METHOD_NAME" \
    --argjson faucetMethodId "$FAUCET_METHOD_ID" \
    --argjson simpleTransferMethodId "$SIMPLE_TRANSFER_METHOD_ID" \
    --argjson simpleBurnMethodId "$SIMPLE_BURN_METHOD_ID" \
    --arg faucetPerClaimAmountNano "$FAUCET_PER_CLAIM_AMOUNT_NANO" \
    --argjson sdkKeyExpectedTxCount "$SDK_KEY_EXPECTED_TX_COUNT" \
    '{
      faucetContractId: $faucetContractId,
      faucetMethodName: $faucetMethodName,
      faucetMethodId: $faucetMethodId,
      faucetPerClaimAmount: $faucetPerClaimAmountNano,
      sdkKeyExpectedTxCount: $sdkKeyExpectedTxCount,
      sdKeyAllowedContractIds: [$faucetContractId, 0, 0],
      sdKeyAllowedMethodIds: [$faucetMethodId, $simpleTransferMethodId, $simpleBurnMethodId],
      operators: .
    }' "$items_file"
)"

if [ -n "$OUTPUT_FILE" ]; then
  mkdir -p "$(dirname "$OUTPUT_FILE")"
  printf '%s\n' "$json" > "$OUTPUT_FILE"
else
  printf '%s\n' "$json"
fi
