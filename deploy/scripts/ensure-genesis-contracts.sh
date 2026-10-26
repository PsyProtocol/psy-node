#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/json-artifact.sh
source "$SCRIPT_DIR/lib/json-artifact.sh"

PARTH_DIR="${PARTH_DIR:-$ROOT}"
PSY_GENESIS_DIR="${PSY_GENESIS_DIR:-$PARTH_DIR/psy-genesis}"
GENESIS_CONTRACTS_PATH="${GENESIS_CONTRACTS_PATH:-$PSY_GENESIS_DIR/genesis_contracts.json}"

is_usable_genesis_contracts() {
  local artifact_path="$1"

  [ -s "$artifact_path" ] || return 1
  command -v jq >/dev/null 2>&1 || {
    echo "jq is required to validate genesis contracts" >&2
    return 1
  }
  json_artifact_cat "$artifact_path" \
    | jq -e '
        type == "array"
        and length > 0
        and all(.[];
          has("name")
          and has("deployer")
          and has("function_whitelist")
          and has("code_root")
          and (.code_definition | has("state_tree_height"))
          and (.code_definition.functions | type == "array" and length > 0)
          and all(.code_definition.functions[];
            has("code")
            and has("method_id")
            and has("num_inputs")
            and has("num_outputs")
            and has("vm_type")
          )
        )
      ' >/dev/null 2>&1
}

[ -f "$PSY_GENESIS_DIR/config.json" ] || {
  echo "missing canonical Psy config: $PSY_GENESIS_DIR/config.json" >&2
  echo "initialize the psy-genesis submodule before building" >&2
  exit 1
}
[ -d "$PSY_GENESIS_DIR/genesis_abi" ] || {
  echo "missing canonical genesis ABI directory: $PSY_GENESIS_DIR/genesis_abi" >&2
  exit 1
}
is_usable_genesis_contracts "$GENESIS_CONTRACTS_PATH" || {
  echo "missing or invalid canonical genesis contracts: $GENESIS_CONTRACTS_PATH" >&2
  exit 1
}

echo "[genesis-contracts] verified canonical artifact: $GENESIS_CONTRACTS_PATH"
