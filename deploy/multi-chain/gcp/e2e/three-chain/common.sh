#!/usr/bin/env bash
# Shared by the three-chain acceptance drivers. Everything comes from the environment the step sets; nothing is
# hard-coded and no key is ever echoed. Source this file; do not run it.
set -euo pipefail

e2e_require() {
  local name
  for name in "$@"; do
    [ -n "${!name:-}" ] || { echo "three-chain: $name is not set" >&2; exit 2; }
  done
}

# The deployment document of one chain: doc <chain> <jq filter>
doc() {
  jq -r "$2" "$E2E_DEPLOYMENTS_DIR/$1/deployed-contracts.json"
}

# The local tunnel URL of one chain's private gateway port: rpc_url sepolia -> $E2E_RPC_SEPOLIA
rpc_url() {
  local variable="E2E_RPC_$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')"
  e2e_require "$variable"
  printf '%s' "${!variable}"
}

user_cli_env() {
  e2e_require E2E_USER_CLI E2E_RUNTIME_CONFIG E2E_USER_RPC_CONFIG E2E_DEPLOYMENTS_DIR
  export PSY_NETWORK=testnet PSY_CONFIG_PATH="$E2E_RUNTIME_CONFIG" PSY_DEPLOYMENTS_DIR="$E2E_DEPLOYMENTS_DIR"
  export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-4}" RUST_LOG="${RUST_LOG:-warn}"
}
