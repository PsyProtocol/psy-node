#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PARTH_DIR="${PARTH_DIR:-$REPO_ROOT}"
WORKSPACE_ROOT="$(cd "$PARTH_DIR/.." && pwd)"
CONFIG_FILE="${GCP_DEPLOY_CONFIG:-$SCRIPT_DIR/config.env}"

if [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
fi
# shellcheck source=lib/public-domains.sh
source "$SCRIPT_DIR/lib/public-domains.sh"
set_public_domain_defaults

usage() {
  cat >&2 <<'EOF'
Usage:
  bash deploy/gcp/test-staging-deploy-contract-with-abi.sh

Environment overrides:
  PRIVATE_KEY=<64-hex-private-key>
  DEPLOY_CONTRACT_KEY_INDEX=2
  CONTRACT_NAME=mining_rewards
  CONTRACT_PATH=/path/to/contract.json
  ABI_PATH=/path/to/contract.abi.json
  USER_CLI=/path/to/psy_user_cli
  CLIENT_CONFIG_SOURCE=/path/to/psy-wallet/config.json
  VERIFY_ATTEMPTS=30
  VERIFY_DELAY=10

Examples:
  bash deploy/gcp/test-staging-deploy-contract-with-abi.sh
  CONTRACT_NAME=withdrawal_tree bash deploy/gcp/test-staging-deploy-contract-with-abi.sh
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing command: $1" >&2
    exit 1
  }
}

require_file() {
  local path="$1"
  [ -f "$path" ] || {
    echo "missing file: $path" >&2
    exit 1
  }
}

default_private_key() {
  [ -f "$PARTH_DIR/private_keys.json" ] || return 0
  jq -er --argjson idx "${DEPLOY_CONTRACT_KEY_INDEX:-2}" \
    '.[$idx] | select(type == "string") | select(test("^[0-9a-fA-F]{64}$"))' \
    "$PARTH_DIR/private_keys.json" 2>/dev/null || true
}

build_rpc_config() {
  local target="$1"
  local source_config="$2"
  local coordinator_url="$3"
  local realm0_url="$4"
  local realm1_url="$5"
  local prove_proxy_url="$6"
  local psy_services_url="$7"

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
data["defaultNetwork"] = "localhost"

with open(target, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
}

latest_contract_id() {
  curl -fsS "${PSY_SERVICES_URL%/}/api/v1/get/contract/list?limit=1" \
    | jq -r '.data.items[0].contract_id // -1'
}

print_contract_summary() {
  curl -fsS "${PSY_SERVICES_URL%/}/api/v1/get/contract/list?limit=${1:-10}" \
    | jq '.data.items[] | {
        contract_id,
        checkpoint_id,
        has_abi: ((.metadata.abi != null) or (.abi_raw != null) or (.abi_parsed != null)),
        contract_name: ([.metadata.abi.structs[]? | select(.is_contract == true) | .name][0] // null)
      }'
}

find_new_contract_with_abi() {
  local before_id="$1"
  curl -fsS "${PSY_SERVICES_URL%/}/api/v1/get/contract/list?limit=20" \
    | jq -r --argjson before_id "$before_id" '
        .data.items[]?
        | select(.contract_id > $before_id)
        | select((.metadata.abi != null) or (.abi_raw != null) or (.abi_parsed != null))
        | [
            .contract_id,
            .checkpoint_id,
            ([.metadata.abi.structs[]? | select(.is_contract == true) | .name][0] // "")
          ]
        | @tsv
      ' \
    | head -1
}

require_cmd jq
require_cmd curl
require_cmd python3

USER_CLI="${USER_CLI:-$PARTH_DIR/target/release/psy_user_cli}"
require_file "$USER_CLI"
[ -x "$USER_CLI" ] || {
  echo "not executable: $USER_CLI" >&2
  exit 1
}

PRIVATE_KEY="${PRIVATE_KEY:-$(default_private_key)}"
if [ -z "$PRIVATE_KEY" ]; then
  usage
  echo "missing PRIVATE_KEY and no usable $PARTH_DIR/private_keys.json[${DEPLOY_CONTRACT_KEY_INDEX:-2}]" >&2
  exit 1
fi
PRIVATE_KEY="${PRIVATE_KEY#0x}"
if ! [[ "$PRIVATE_KEY" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "invalid PRIVATE_KEY: expected 64 hex chars / 32 bytes; got ${#PRIVATE_KEY} chars" >&2
  exit 1
fi

CONTRACT_NAME="${CONTRACT_NAME:-mining_rewards}"
DEFAULT_CONTRACT_DIR="${PSY_CONTRACT_ARTIFACTS_DIR:-$WORKSPACE_ROOT/psy-contract-artifacts}/$CONTRACT_NAME"
CONTRACT_PATH="${CONTRACT_PATH:-$DEFAULT_CONTRACT_DIR/$CONTRACT_NAME.json}"
ABI_PATH="${ABI_PATH:-$DEFAULT_CONTRACT_DIR/$CONTRACT_NAME.abi.json}"
require_file "$CONTRACT_PATH"
require_file "$ABI_PATH"

SOURCE_CONFIG="${CLIENT_CONFIG_SOURCE:-$WORKSPACE_ROOT/psy-wallet/config.json}"
[ -f "$SOURCE_CONFIG" ] || SOURCE_CONFIG="$PARTH_DIR/psy-genesis/config.json"
require_file "$SOURCE_CONFIG"

COORDINATOR_URL="${ABI_TEST_COORDINATOR_URL:-https://${PUBLIC_COORDINATOR_DOMAIN}}"
REALM0_URL="${ABI_TEST_REALM0_URL:-https://${PUBLIC_REALM_DOMAIN}}"
REALM1_URL="${ABI_TEST_REALM1_URL:-https://${PUBLIC_REALM1_DOMAIN}}"
PROVE_PROXY_URL="${ABI_TEST_PROVE_PROXY_URL:-https://${PUBLIC_PROVE_PROXY_DOMAIN}}"
PSY_SERVICES_URL="${ABI_TEST_PSY_SERVICES_URL:-https://${PUBLIC_PSY_SERVICES_DOMAIN}}"
VERIFY_ATTEMPTS="${VERIFY_ATTEMPTS:-30}"
VERIFY_DELAY="${VERIFY_DELAY:-10}"

rpc_config="$(mktemp)"
deploy_cmd_output="${OUTPUT_PATH:-/tmp/psy-${CONTRACT_NAME}-deploy-cmd-$(date +%s).json}"
trap 'rm -f "$rpc_config"' EXIT

build_rpc_config "$rpc_config" "$SOURCE_CONFIG" \
  "$COORDINATOR_URL" "$REALM0_URL" "$REALM1_URL" "$PROVE_PROXY_URL" "$PSY_SERVICES_URL"

echo "[deploy-contract-with-abi] contract_name=$CONTRACT_NAME"
echo "[deploy-contract-with-abi] contract_path=$CONTRACT_PATH"
echo "[deploy-contract-with-abi] abi_path=$ABI_PATH"
echo "[deploy-contract-with-abi] coordinator=$COORDINATOR_URL"
echo "[deploy-contract-with-abi] psy_services=$PSY_SERVICES_URL"

before_contract_id="$(latest_contract_id)"
echo "[deploy-contract-with-abi] before_contract_id=$before_contract_id"

RUST_LOG="${RUST_LOG:-info}" "$USER_CLI" deploy-contract \
  --rpc-config "$rpc_config" \
  --private-key "$PRIVATE_KEY" \
  --contract-path "$CONTRACT_PATH" \
  --abi-path "$ABI_PATH" \
  --output-path "$deploy_cmd_output" \
  --is-deploy

echo "[deploy-contract-with-abi] deploy_cmd_output=$deploy_cmd_output"
echo "[deploy-contract-with-abi] waiting for psy-services to attach pending ABI after deploy_contract is indexed"

for attempt in $(seq 1 "$VERIFY_ATTEMPTS"); do
  match="$(find_new_contract_with_abi "$before_contract_id" || true)"
  if [ -n "$match" ]; then
    contract_id="$(printf '%s\n' "$match" | awk -F '\t' '{print $1}')"
    checkpoint_id="$(printf '%s\n' "$match" | awk -F '\t' '{print $2}')"
    contract_name="$(printf '%s\n' "$match" | awk -F '\t' '{print $3}')"
    echo "[deploy-contract-with-abi] ok contract_id=$contract_id checkpoint_id=$checkpoint_id contract_name=${contract_name:-unknown}"
    curl -fsS "${PSY_SERVICES_URL%/}/api/v1/get/contract/info?contract_id=${contract_id}&abi_format=raw" \
      | jq '.data | {
          contract_id,
          checkpoint_id,
          has_abi: ((.metadata.abi != null) or (.abi_raw != null) or (.abi_parsed != null)),
          contract_name: ([.metadata.abi.structs[]? | select(.is_contract == true) | .name][0] // null),
          function_count: ([.metadata.abi.structs[]? | select(.is_contract == true) | .functions[]?] | length)
        }'
    exit 0
  fi

  echo "[deploy-contract-with-abi] attempt ${attempt}/${VERIFY_ATTEMPTS}: ABI not indexed yet"
  sleep "$VERIFY_DELAY"
done

echo "[deploy-contract-with-abi] timed out waiting for a new contract with ABI" >&2
echo "[deploy-contract-with-abi] latest contracts:" >&2
print_contract_summary 10 >&2 || true
exit 1
