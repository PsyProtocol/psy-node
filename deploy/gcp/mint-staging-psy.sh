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

default_bridge_private_key() {
  [ -f "$PARTH_DIR/private_keys.json" ] || return 0
  command -v jq >/dev/null 2>&1 || return 0
  jq -er '.[2] | select(type == "string") | select(test("^[0-9a-fA-F]{64}$"))' "$PARTH_DIR/private_keys.json" 2>/dev/null || true
}

usage() {
  cat >&2 <<'EOF'
Usage:
  bash deploy/gcp/mint-staging-psy.sh [private-key] [amount-psy]

Examples:
  bash deploy/gcp/mint-staging-psy.sh
  bash deploy/gcp/mint-staging-psy.sh c716...b359
  bash deploy/gcp/mint-staging-psy.sh c716...b359 1000

Environment overrides:
  AMOUNT_RAW=1000000000000
  CONTRACT_ID=0
  MINT_COORDINATOR_URL=https://coordinator-stg.psy-protocol.xyz
  MINT_REALM0_URL=https://realm0-stg.psy-protocol.xyz
  MINT_REALM1_URL=https://realm1-stg.psy-protocol.xyz
  MINT_PROVE_PROXY_URL=https://prove-stg.psy-protocol.xyz
  MINT_PSY_SERVICES_URL=https://services-stg.psy-protocol.xyz
  MINT_QUERY_USER_LEAF=1
  MINT_USER_ID=0
EOF
}

PRIVATE_KEY="${1:-${PRIVATE_KEY:-${BRIDGE_USER_PRIVATE_KEY:-$(default_bridge_private_key)}}}"
AMOUNT_PSY="${2:-${AMOUNT_PSY:-1000}}"
CONTRACT_ID="${CONTRACT_ID:-0}"

if [ -z "$PRIVATE_KEY" ]; then
  usage
  exit 1
fi
PRIVATE_KEY="${PRIVATE_KEY#0x}"
if ! [[ "$PRIVATE_KEY" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "invalid private key: expected 64 hex chars / 32 bytes; got ${#PRIVATE_KEY} chars" >&2
  echo "hint: pass amount as a separate argument, with a space before 1000" >&2
  exit 1
fi

if [ -n "${AMOUNT_RAW:-}" ]; then
  amount_raw="$AMOUNT_RAW"
else
  amount_raw="$(python3 - "$AMOUNT_PSY" <<'PY'
from decimal import Decimal, InvalidOperation
import sys

try:
    value = Decimal(sys.argv[1])
except InvalidOperation:
    raise SystemExit("amount-psy must be a number")

raw = value * Decimal(10) ** 9
if raw != raw.to_integral_value():
    raise SystemExit("amount-psy supports at most 9 decimal places")
if raw <= 0:
    raise SystemExit("amount-psy must be positive")
print(int(raw))
PY
)"
fi

USER_CLI="${USER_CLI:-$PARTH_DIR/target/release/psy_user_cli}"
[ -x "$USER_CLI" ] || {
  echo "missing executable: $USER_CLI" >&2
  echo "build or package parth first" >&2
  exit 1
}

source_config="${CLIENT_CONFIG_SOURCE:-$REPO_ROOT/psy-wallet/config.json}"
[ -f "$source_config" ] || source_config="$REPO_ROOT/deploy/config/parth/client_prover_config.json"
[ -f "$source_config" ] || {
  echo "missing client config source" >&2
  exit 1
}

coordinator_url="${MINT_COORDINATOR_URL:-https://${PUBLIC_COORDINATOR_DOMAIN}}"
realm0_url="${MINT_REALM0_URL:-${MINT_REALM_URL:-https://${PUBLIC_REALM_DOMAIN}}}"
realm1_url="${MINT_REALM1_URL:-https://${PUBLIC_REALM1_DOMAIN}}"
prove_proxy_url="${MINT_PROVE_PROXY_URL:-https://${PUBLIC_PROVE_PROXY_DOMAIN}}"
psy_services_url="${MINT_PSY_SERVICES_URL:-https://${PUBLIC_PSY_SERVICES_DOMAIN}}"

rpc_config="$(mktemp)"
trap 'rm -f "$rpc_config"' EXIT

python3 - "$source_config" "$rpc_config" \
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

echo "[mint-staging-psy] using cloud endpoints:"
python3 - "$rpc_config" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    net = json.load(f)["networks"]["localhost"]

print("  coordinator: " + net["coordinator_configs"][0]["rpc_url"][0])
print("  realm0:      " + net["realm_configs"][0]["rpc_url"][0])
print("  realm1:      " + net["realm_configs"][1]["rpc_url"][0])
print("  prove proxy: " + net["prove_proxy_url"][0])
print("  services:    " + net["api_services_url"][0])
PY
echo "[mint-staging-psy] contract_id=${CONTRACT_ID} amount_raw=${amount_raw}"

cd "$PARTH_DIR"
env -u KEYSTORE_PATH -u PRIVATE_KEY RUST_LOG="${RUST_LOG:-info}" "$USER_CLI" call \
  --rpc-config "$rpc_config" \
  -p "$PRIVATE_KEY" \
  --contract-id "$CONTRACT_ID" \
  --method-name simple_mint \
  --inputs "[$amount_raw]"

if [ "${MINT_QUERY_USER_LEAF:-0}" = "1" ]; then
  if [ -z "${MINT_USER_ID:-}" ]; then
    echo "MINT_QUERY_USER_LEAF=1 requires MINT_USER_ID" >&2
    exit 1
  fi
  echo "[mint-staging-psy] querying updated user leaf for user_id=${MINT_USER_ID}"
  RUST_LOG="${RUST_LOG_QUERY:-error}" "$USER_CLI" get-user-leaf \
    --rpc-config "$rpc_config" \
    --user-id "$MINT_USER_ID"
fi
