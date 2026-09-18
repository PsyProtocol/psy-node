#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
SINGLE_RUNNER="$SCRIPT_DIR/run-cli-e2e.sh"
CHAINS=(base bsc sepolia)

usage() {
  cat <<'USAGE'
Usage:
  run-multichain-e2e.sh init [MATRIX_DIR]
  run-multichain-e2e.sh status MATRIX_DIR
  AUTHORIZED_STAGING_TRANSACTIONS=1 run-multichain-e2e.sh run MATRIX_DIR [RUN_OPTIONS...]

This creates and runs three independent full E2E suites, one each for:
  Base Sepolia (chain ID 84532, bridge index 2)
  BSC Testnet (chain ID 97, bridge index 1)
  Sepolia (chain ID 11155111, bridge index 0)

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
  local fail_fast="${MULTICHAIN_E2E_FAIL_FAST:-1}"
  local run_id="${MULTICHAIN_E2E_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
  local evidence_dir="$matrix_dir/matrix-evidence/$run_id"
  local records="$evidence_dir/$operation-results.tsv"
  local chain result status log_file
  if [ "$operation" = "status" ]; then
    fail_fast="${MULTICHAIN_E2E_STATUS_FAIL_FAST:-0}"
  fi
  mkdir -p "$evidence_dir"
  chmod 700 "$matrix_dir/matrix-evidence" "$evidence_dir"
  : >"$records"
  chmod 600 "$records"
  for chain in "${CHAINS[@]}"; do
    echo
    echo "[staging-multichain-e2e] $operation chain=$chain"
    log_file="$evidence_dir/$operation-$chain.log"
    set +e
    STAGING_CHAIN="$chain" "$SINGLE_RUNNER" "$operation" "$matrix_dir/$chain" "$@" \
      2>&1 | tee "$log_file"
    result=${PIPESTATUS[0]}
    set -e
    chmod 600 "$log_file"
    if [ "$result" -eq 0 ]; then
      status="PASS"
      echo "[staging-multichain-e2e] $operation chain=$chain PASS"
    else
      status="FAIL"
      failed=1
      echo "[staging-multichain-e2e] $operation chain=$chain FAIL exit=$result" >&2
    fi
    printf '%s\t%s\t%s\t%s\n' "$chain" "$status" "$result" "$log_file" >>"$records"
    if [ "$result" -ne 0 ] && [ "$fail_fast" = "1" ]; then
      break
    fi
  done
  jq -Rn \
    --arg operation "$operation" \
    --arg run_id "$run_id" \
    --arg executed_at "$(date --iso-8601=seconds)" '
      [inputs | split("\t") | {
        chain: .[0], status: .[1], exit_code: (.[2] | tonumber), log: .[3]
      }] as $chains
      | {
          version: 1,
          operation: $operation,
          run_id: $run_id,
          executed_at: $executed_at,
          required_order: ["base", "bsc", "sepolia"],
          status: (if ($chains | length) == 3 and all($chains[]; .status == "PASS")
                   then "PASS" else "FAIL" end),
          chains: $chains
        }
    ' <"$records" >"$evidence_dir/$operation-summary.json"
  chmod 600 "$evidence_dir/$operation-summary.json"
  echo "[staging-multichain-e2e] evidence=$evidence_dir/$operation-summary.json"
  if [ "$failed" -ne 0 ]; then
    return 1
  fi
  if [ "$(wc -l <"$records")" -ne "${#CHAINS[@]}" ]; then
    return 1
  fi
  return 0
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
      --arg base "$matrix_dir/base" \
      --arg bsc "$matrix_dir/bsc" \
      --arg sepolia "$matrix_dir/sepolia" \
      '{version: 1, created_at: $created_at, repo_revision: $repo_revision,
        execution: "serial", required_chains: ["base", "bsc", "sepolia"],
        runs: {base: $base, bsc: $bsc, sepolia: $sepolia}}' \
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
