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

KEYS_FILE="${GENESIS_PRIVATE_KEYS_FILE:-$PARTH_DIR/private_keys.json}"
USER_CLI="${USER_CLI:-$PARTH_DIR/target/release/psy_user_cli}"
SOURCE_CONFIG="${CLIENT_CONFIG_SOURCE:-$REPO_ROOT/psy-wallet/config.json}"

INPUT_USER_INDEXES="${USER_INDEXES:-}"
INPUT_AMOUNT_PSY="${AMOUNT_PSY:-}"
INPUT_WAIT_SECONDS="${WAIT_SECONDS:-}"
INPUT_VERIFY_ATTEMPTS="${VERIFY_ATTEMPTS:-}"
INPUT_VERIFY_DELAY="${VERIFY_DELAY:-}"
INPUT_SKIP_MINT="${SKIP_MINT:-}"
INPUT_EXPECTED_NET_FEE_PSY="${EXPECTED_NET_FEE_PSY:-}"
INPUT_EXPECTED_NET_FEE_RAW="${EXPECTED_NET_FEE_RAW:-}"

USER_INDEXES="${SMOKE_USER_INDEXES:-${INPUT_USER_INDEXES:-2}}"
AMOUNT_PSY="${SMOKE_AMOUNT_PSY:-${INPUT_AMOUNT_PSY:-${1:-1000}}}"
CONTRACT_ID="${CONTRACT_ID:-0}"
BALANCE_SLOT="${SMOKE_BALANCE_SLOT:-0}"
CONTRACT_STATE_TREE_HEIGHT="${SMOKE_CONTRACT_STATE_TREE_HEIGHT:-32}"
WAIT_SECONDS="${SMOKE_WAIT_SECONDS:-${INPUT_WAIT_SECONDS:-30}}"
VERIFY_ATTEMPTS="${SMOKE_VERIFY_ATTEMPTS:-${INPUT_VERIFY_ATTEMPTS:-20}}"
VERIFY_DELAY="${SMOKE_VERIFY_DELAY:-${INPUT_VERIFY_DELAY:-10}}"
SKIP_MINT="${SMOKE_SKIP_MINT:-${INPUT_SKIP_MINT:-0}}"
EXPECTED_NET_FEE_PSY="${SMOKE_EXPECTED_NET_FEE_PSY:-${INPUT_EXPECTED_NET_FEE_PSY:-}}"
EXPECTED_NET_FEE_RAW="${SMOKE_EXPECTED_NET_FEE_RAW:-${INPUT_EXPECTED_NET_FEE_RAW:-}}"

require_file() {
  local path="$1"
  [ -f "$path" ] || {
    echo "missing file: $path" >&2
    exit 1
  }
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing command: $1" >&2
    exit 1
  }
}

amount_to_raw() {
  python3 - "$1" <<'PY'
from decimal import Decimal, InvalidOperation
import sys

try:
    value = Decimal(sys.argv[1])
except InvalidOperation:
    raise SystemExit("amount must be a number")

raw = value * Decimal(10) ** 9
if raw != raw.to_integral_value():
    raise SystemExit("amount supports at most 9 decimal places")
if raw <= 0:
    raise SystemExit("amount must be positive")
print(int(raw))
PY
}

raw_to_psy() {
  python3 - "$1" <<'PY'
from decimal import Decimal
import sys

value = Decimal(sys.argv[1]) / (Decimal(10) ** 9)
print(format(value.normalize(), "f"))
PY
}

raw_add() {
  python3 - "$1" "$2" <<'PY'
import sys

print(int(sys.argv[1]) + int(sys.argv[2]))
PY
}

raw_sub_nonnegative() {
  python3 - "$1" "$2" <<'PY'
import sys

value = int(sys.argv[1]) - int(sys.argv[2])
if value < 0:
    raise SystemExit("expected net fee cannot exceed mint amount")
print(value)
PY
}

raw_ge() {
  python3 - "$1" "$2" <<'PY'
import sys

raise SystemExit(0 if int(sys.argv[1]) >= int(sys.argv[2]) else 1)
PY
}

raw_gt() {
  python3 - "$1" "$2" <<'PY'
import sys

raise SystemExit(0 if int(sys.argv[1]) > int(sys.argv[2]) else 1)
PY
}

config_expected_net_fee_raw() {
  local rpc_config="$1"

  python3 - "$rpc_config" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

fees = data.get("networks", {}).get("localhost", {}).get("fees", {})
if not fees:
    print(10 ** 9)
else:
    print(int(fees.get("guta_fee", 0)) + int(fees.get("da_fee", 0)))
PY
}

hex_to_int() {
  python3 - "$1" <<'PY'
import sys

s = sys.argv[1].strip().strip('"')
if s.startswith("0x"):
    s = s[2:]
print(int(s or "0", 16))
PY
}

build_rpc_config() {
  local target="$1"
  local source_config="$SOURCE_CONFIG"

  [ -f "$source_config" ] || source_config="$REPO_ROOT/deploy/config/parth/client_prover_config.json"
  require_file "$source_config"

  local coordinator_url="${MINT_COORDINATOR_URL:-https://${PUBLIC_COORDINATOR_DOMAIN}}"
  local realm0_url="${MINT_REALM0_URL:-${MINT_REALM_URL:-https://${PUBLIC_REALM_DOMAIN}}}"
  local realm1_url="${MINT_REALM1_URL:-https://${PUBLIC_REALM1_DOMAIN}}"
  local prove_proxy_url="${MINT_PROVE_PROXY_URL:-https://${PUBLIC_PROVE_PROXY_DOMAIN}}"
  local psy_services_url="${MINT_PSY_SERVICES_URL:-https://${PUBLIC_PSY_SERVICES_DOMAIN}}"

  python3 - "$source_config" "$target" \
    "$coordinator_url" "$realm0_url" "$realm1_url" "$prove_proxy_url" "$psy_services_url" <<'PY'
import copy
import json
import sys

source, target, coordinator, realm0, realm1, prove_proxy, services = sys.argv[1:]

with open(source, "r", encoding="utf-8") as f:
    data = json.load(f)

networks = data.setdefault("networks", {})
base = copy.deepcopy(networks.get("staging") or networks.get("localhost") or {})
base["coordinator_configs"] = [{"id": 0, "rpc_url": [coordinator]}]
base["realm_configs"] = [
    {"id": 0, "rpc_url": [realm0]},
    {"id": 1, "rpc_url": [realm1]},
]
base["prove_proxy_url"] = [prove_proxy]
base["api_services_url"] = [services]
networks["localhost"] = base

with open(target, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
}

wallet_public_key() {
  local private_key="$1"
  local output

  output="$(cd "$PARTH_DIR" && env -u KEYSTORE_PATH -u PRIVATE_KEY RUST_LOG=error "$USER_CLI" wallet info -p "$private_key")"
  awk '/^public_key:/{print $2}' <<< "$output"
}

latest_checkpoint() {
  local rpc_config="$1"

  cd "$PARTH_DIR"
  RUST_LOG=error "$USER_CLI" get-latest-block-state --rpc-config "$rpc_config" \
    | python3 -c 'import json,sys; text=sys.stdin.read(); start=text.find("{"); print(json.loads(text[start:])["checkpoint_id"])'
}

user_id_for_public_key() {
  local rpc_config="$1"
  local public_key="$2"

  cd "$PARTH_DIR"
  RUST_LOG=error "$USER_CLI" get-user-id --rpc-config "$rpc_config" --pub-key "$public_key" \
    | awk '/user_id:/{print $2}'
}

user_leaf_json() {
  local rpc_config="$1"
  local checkpoint_id="$2"
  local user_id="$3"

  cd "$PARTH_DIR"
  RUST_LOG=error "$USER_CLI" get-user-leaf \
    --rpc-config "$rpc_config" \
    --checkpoint-id "$checkpoint_id" \
    --user-id "$user_id" \
    | python3 -c 'import json,re,sys; text=sys.stdin.read(); m=re.search(r"user_leaf_data:\s*(\{.*?\})\s*user_leaf_hash:", text, re.S); print(json.dumps(json.loads(m.group(1))))'
}

user_leaf_field() {
  local rpc_config="$1"
  local checkpoint_id="$2"
  local user_id="$3"
  local field="$4"

  user_leaf_json "$rpc_config" "$checkpoint_id" "$user_id" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$field"
}

contract_slot_raw() {
  local rpc_config="$1"
  local checkpoint_id="$2"
  local user_id="$3"

  local value_hex
  cd "$PARTH_DIR"
  value_hex="$(RUST_LOG=error "$USER_CLI" get-user-contract-state-tree-merkle-proof \
    --rpc-config "$rpc_config" \
    --checkpoint-id "$checkpoint_id" \
    --user-id "$user_id" \
    --contract-id "$CONTRACT_ID" \
    --height "$CONTRACT_STATE_TREE_HEIGHT" \
    --leaf-id "$BALANCE_SLOT" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["value"])')"
  hex_to_int "$value_hex"
}

print_state() {
  local label="$1"
  local key_index="$2"
  local public_key="$3"
  local user_id="$4"
  local checkpoint_id="$5"
  local nonce="$6"
  local raw="$7"

  printf '[%s] key_index=%s public_key=%s user_id=%s checkpoint=%s nonce=%s slot%s_raw=%s slot%s_psy=%s\n' \
    "$label" \
    "$key_index" \
    "${public_key:0:12}..." \
    "$user_id" \
    "$checkpoint_id" \
    "$nonce" \
    "$BALANCE_SLOT" \
    "$raw" \
    "$BALANCE_SLOT" \
    "$(raw_to_psy "$raw")"
}

require_cmd jq
require_cmd python3
require_file "$KEYS_FILE"
[ -x "$USER_CLI" ] || {
  echo "missing executable: $USER_CLI" >&2
  exit 1
}

rpc_config="$(mktemp)"
state_file="$(mktemp)"
trap 'rm -f "$rpc_config" "$state_file"' EXIT

build_rpc_config "$rpc_config"

amount_raw="$(amount_to_raw "$AMOUNT_PSY")"
if [ -n "$EXPECTED_NET_FEE_RAW" ]; then
  expected_net_fee_raw="$EXPECTED_NET_FEE_RAW"
elif [ -n "$EXPECTED_NET_FEE_PSY" ]; then
  expected_net_fee_raw="$(amount_to_raw "$EXPECTED_NET_FEE_PSY")"
else
  expected_net_fee_raw="$(config_expected_net_fee_raw "$rpc_config")"
fi
expected_delta_raw="$(raw_sub_nonnegative "$amount_raw" "$expected_net_fee_raw")"

echo "[test-staging-simple-mint] users=${USER_INDEXES}"
echo "[test-staging-simple-mint] amount_psy=${AMOUNT_PSY} amount_raw=${amount_raw}"
echo "[test-staging-simple-mint] expected_net_fee_raw=${expected_net_fee_raw} expected_delta_raw=${expected_delta_raw}"
echo "[test-staging-simple-mint] contract_id=${CONTRACT_ID} balance_slot=${BALANCE_SLOT}"

before_checkpoint="$(latest_checkpoint "$rpc_config")"
echo "[test-staging-simple-mint] before_checkpoint=${before_checkpoint}"

: > "$state_file"
for key_index in $USER_INDEXES; do
  private_key="$(jq -er --argjson idx "$key_index" '.[$idx] | select(type == "string") | select(test("^[0-9a-fA-F]{64}$"))' "$KEYS_FILE")"
  public_key="$(wallet_public_key "$private_key")"
  user_id="$(user_id_for_public_key "$rpc_config" "$public_key")"
  nonce="$(user_leaf_field "$rpc_config" "$before_checkpoint" "$user_id" nonce)"
  before_raw="$(contract_slot_raw "$rpc_config" "$before_checkpoint" "$user_id")"
  expected_raw="$(raw_add "$before_raw" "$expected_delta_raw")"

  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$key_index" "$private_key" "$public_key" "$user_id" "$nonce" "$expected_raw" >> "$state_file"
  print_state "before" "$key_index" "$public_key" "$user_id" "$before_checkpoint" "$nonce" "$before_raw"
done

if [ "$SKIP_MINT" = "1" ]; then
  echo "[test-staging-simple-mint] SMOKE_SKIP_MINT=1; skipping mint phase"
else
  while IFS=$'\t' read -r key_index private_key _public_key _user_id _nonce _expected_raw; do
    echo
    echo "[test-staging-simple-mint] minting key_index=${key_index} key_prefix=${private_key:0:8}"
    RUST_LOG="${SMOKE_MINT_RUST_LOG:-error}" \
      MINT_QUERY_USER_LEAF=0 \
      bash "$SCRIPT_DIR/mint-staging-psy.sh" "$private_key" "$AMOUNT_PSY"
  done < "$state_file"
fi

if [ "$WAIT_SECONDS" -gt 0 ]; then
  echo
  echo "[test-staging-simple-mint] waiting ${WAIT_SECONDS}s before verification"
  sleep "$WAIT_SECONDS"
fi

for attempt in $(seq 1 "$VERIFY_ATTEMPTS"); do
  checkpoint_id="$(latest_checkpoint "$rpc_config")"
  failures=0

  echo
  echo "[test-staging-simple-mint] verification attempt ${attempt}/${VERIFY_ATTEMPTS} checkpoint=${checkpoint_id}"

  while IFS=$'\t' read -r key_index _private_key public_key user_id before_nonce expected_raw; do
    nonce="$(user_leaf_field "$rpc_config" "$checkpoint_id" "$user_id" nonce)"
    current_raw="$(contract_slot_raw "$rpc_config" "$checkpoint_id" "$user_id")"
    print_state "after" "$key_index" "$public_key" "$user_id" "$checkpoint_id" "$nonce" "$current_raw"

    if [ "$SKIP_MINT" = "1" ]; then
      raw_gt "$current_raw" 0 || failures=$((failures + 1))
    elif ! raw_ge "$current_raw" "$expected_raw" || [ "$nonce" -le "$before_nonce" ]; then
      echo "[test-staging-simple-mint] pending key_index=${key_index}: expected_raw>=${expected_raw}, before_nonce=${before_nonce}" >&2
      failures=$((failures + 1))
    fi
  done < "$state_file"

  if [ "$failures" -eq 0 ]; then
    echo
    echo "[test-staging-simple-mint] passed"
    exit 0
  fi

  if [ "$attempt" -lt "$VERIFY_ATTEMPTS" ]; then
    echo "[test-staging-simple-mint] ${failures} users not updated yet; retrying in ${VERIFY_DELAY}s"
    sleep "$VERIFY_DELAY"
  fi
done

echo "[test-staging-simple-mint] failed: mint result did not become visible in time" >&2
exit 1
