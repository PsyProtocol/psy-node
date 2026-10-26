#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_SCRIPTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$TMP_DIR/psy-genesis/genesis_abi"
printf '{"networks":{}}\n' > "$TMP_DIR/psy-genesis/config.json"
: > "$TMP_DIR/psy-genesis/genesis_abi/PsyTokenContract.json"

write_valid_artifact() {
  local target="$1"
  cat > "$target" <<'JSON'
[{"name":"token","deployer":"0","function_whitelist":[],"code_root":"0","code_definition":{"state_tree_height":1,"functions":[{"code":"00","method_id":1,"num_inputs":0,"num_outputs":0,"vm_type":0}]}}]
JSON
}

artifact="$TMP_DIR/psy-genesis/genesis_contracts.json"
write_valid_artifact "$artifact"
PARTH_DIR="$TMP_DIR" bash "$DEPLOY_SCRIPTS_DIR/ensure-genesis-contracts.sh" >/dev/null

plain="$TMP_DIR/plain.json"
write_valid_artifact "$plain"
zstd -q -f "$plain" -o "$artifact"
PARTH_DIR="$TMP_DIR" bash "$DEPLOY_SCRIPTS_DIR/ensure-genesis-contracts.sh" >/dev/null

printf '{}\n' > "$artifact"
if PARTH_DIR="$TMP_DIR" bash "$DEPLOY_SCRIPTS_DIR/ensure-genesis-contracts.sh" >/dev/null 2>&1; then
  echo "invalid canonical artifact should be rejected" >&2
  exit 1
fi

echo "[ok] canonical genesis contract artifact validation"
