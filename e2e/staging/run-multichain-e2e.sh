#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
SINGLE_RUNNER="$SCRIPT_DIR/run-cli-e2e.sh"
CHAINS=(sepolia bsc base)

usage() {
  cat <<'USAGE'
Usage:
  run-multichain-e2e.sh init [MATRIX_DIR]
  run-multichain-e2e.sh status MATRIX_DIR
  AUTHORIZED_STAGING_TRANSACTIONS=1 run-multichain-e2e.sh run MATRIX_DIR [RUN_OPTIONS...]

This creates and runs three independent full E2E suites, one each for:
  Sepolia (chain ID 11155111, bridge index 0)
  BSC Testnet (chain ID 97, bridge index 1)
  Base Sepolia (chain ID 84532, bridge index 2)

Optional funded EVM key files for init:
  MULTICHAIN_EVM_KEY_FILE (one address shared by all three chains), or
  SEPOLIA_EVM_KEY_FILE, BSC_EVM_KEY_FILE, BASE_EVM_KEY_FILE

Optional per-chain RPC overrides:
  SEPOLIA_RPC_URL, BSC_TESTNET_RPC_URL, BASE_SEPOLIA_RPC_URL

Runs are serial to bound prove-proxy memory use. By default the matrix stops at
the first failed chain. Set MULTICHAIN_E2E_FAIL_FAST=0 to attempt every chain;
the final result still fails unless all three pass.
USAGE
}

fail() {
  echo "[staging-multichain-e2e] ERROR: $*" >&2
  exit 1
}

chain_key_file() {
  case "$1" in
    sepolia) printf '%s' "${SEPOLIA_EVM_KEY_FILE:-${MULTICHAIN_EVM_KEY_FILE:-}}" ;;
    bsc) printf '%s' "${BSC_EVM_KEY_FILE:-${MULTICHAIN_EVM_KEY_FILE:-}}" ;;
    base) printf '%s' "${BASE_EVM_KEY_FILE:-${MULTICHAIN_EVM_KEY_FILE:-}}" ;;
  esac
}

validate_matrix() {
  local matrix_dir="$1"
  [ -d "$matrix_dir" ] || fail "matrix directory not found: $matrix_dir"
  [ -f "$matrix_dir/matrix.json" ] || fail "missing matrix manifest: $matrix_dir/matrix.json"
  local chain
  for chain in "${CHAINS[@]}"; do
    [ -f "$matrix_dir/$chain/manifest.json" ] ||
      fail "missing $chain run manifest under $matrix_dir"
  done
}

run_for_all_chains() {
  local operation="$1"
  local matrix_dir="$2"
  shift 2
  local failed=0
  local chain result
  for chain in "${CHAINS[@]}"; do
    echo
    echo "[staging-multichain-e2e] $operation chain=$chain"
    if STAGING_CHAIN="$chain" "$SINGLE_RUNNER" "$operation" "$matrix_dir/$chain" "$@"; then
      echo "[staging-multichain-e2e] $operation chain=$chain PASS"
    else
      result=$?
      failed=1
      echo "[staging-multichain-e2e] $operation chain=$chain FAIL exit=$result" >&2
      if [ "${MULTICHAIN_E2E_FAIL_FAST:-1}" = "1" ]; then
        return "$result"
      fi
    fi
  done
  return "$failed"
}

command_name="${1:-}"
case "$command_name" in
  -h|--help|"")
    usage
    exit 0
    ;;
esac
shift

[ -x "$SINGLE_RUNNER" ] || fail "single-chain runner is not executable: $SINGLE_RUNNER"
[ -z "${STAGING_L1_RPC_URL:-}" ] ||
  fail "do not set STAGING_L1_RPC_URL for a matrix; use the per-chain RPC variables"

cd "$REPO_DIR"
umask 077

case "$command_name" in
  init)
    matrix_dir="${1:-$REPO_DIR/.private/e2e-runs/multichain.$(date -u +%Y%m%dT%H%M%SZ).$$}"
    [ ! -e "$matrix_dir" ] || fail "matrix directory already exists: $matrix_dir"
    mkdir -p "$matrix_dir"
    chmod 700 "$matrix_dir"

    for chain in "${CHAINS[@]}"; do
      key_file="$(chain_key_file "$chain")"
      echo "[staging-multichain-e2e] initializing chain=$chain"
      if [ -n "$key_file" ]; then
        [ -f "$key_file" ] || fail "$chain EVM key file not found: $key_file"
        STAGING_CHAIN="$chain" "$SINGLE_RUNNER" init "$matrix_dir/$chain" "$key_file"
      else
        STAGING_CHAIN="$chain" "$SINGLE_RUNNER" init "$matrix_dir/$chain"
      fi
    done

    jq -n \
      --arg created_at "$(date --iso-8601=seconds)" \
      --arg repo_revision "$(git rev-parse HEAD)" \
      --arg sepolia "$matrix_dir/sepolia" \
      --arg bsc "$matrix_dir/bsc" \
      --arg base "$matrix_dir/base" \
      '{version: 1, created_at: $created_at, repo_revision: $repo_revision,
        execution: "serial", required_chains: ["sepolia", "bsc", "base"],
        runs: {sepolia: $sepolia, bsc: $bsc, base: $base}}' \
      >"$matrix_dir/matrix.json"
    chmod 600 "$matrix_dir/matrix.json"

    echo
    echo "matrix_dir=$matrix_dir"
    for chain in "${CHAINS[@]}"; do
      address="$(jq -r .evm_address "$matrix_dir/$chain/manifest.json")"
      chain_id="$(jq -r .l1_chain_id "$matrix_dir/$chain/manifest.json")"
      echo "$chain chain_id=$chain_id l1_address=$address"
    done
    echo "next=Fund every address with that chain's native gas, then run status."
    ;;

  status)
    matrix_dir="${1:-}"
    [ -n "$matrix_dir" ] || fail "status requires MATRIX_DIR"
    validate_matrix "$matrix_dir"
    run_for_all_chains status "$matrix_dir"
    ;;

  run)
    matrix_dir="${1:-}"
    [ -n "$matrix_dir" ] || fail "run requires MATRIX_DIR"
    shift
    validate_matrix "$matrix_dir"
    [ "${AUTHORIZED_STAGING_TRANSACTIONS:-0}" = "1" ] ||
      fail "set AUTHORIZED_STAGING_TRANSACTIONS=1 after explicit authorization"
    if run_for_all_chains run "$matrix_dir" "$@"; then
      echo
      echo "[staging-multichain-e2e] PASS: all three L1 profiles completed"
    else
      result=$?
      fail "matrix failed; inspect each chain run directory before resuming (exit=$result)"
    fi
    ;;

  *)
    usage >&2
    fail "unknown command: $command_name"
    ;;
esac
