#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
E2E_BIN="$REPO_DIR/target/release/psy-cli-full-e2e"
USER_CLI="$REPO_DIR/target/release/psy_user_cli"
BASE_CONFIG="$REPO_DIR/psy-genesis/config.json"
STAGING_CHAIN="${STAGING_CHAIN:-${STAGING_NETWORK:-bsc}}"

usage() {
  cat <<'USAGE'
Usage:
  STAGING_CHAIN=sepolia|bsc|base run-cli-e2e.sh init [RUN_DIR] [EVM_KEY_FILE]
  STAGING_CHAIN=sepolia|bsc|base run-cli-e2e.sh status RUN_DIR
  AUTHORIZED_STAGING_TRANSACTIONS=1 STAGING_CHAIN=sepolia|bsc|base \
    run-cli-e2e.sh run RUN_DIR [RUN_OPTIONS...]

The default profile is BSC Testnet. Each run manifest pins the selected L1
chain ID, protocol bridge chain index, deployment artifacts, and public RPC.

Optional per-chain RPC overrides:
  SEPOLIA_RPC_URL, BSC_TESTNET_RPC_URL, BASE_SEPOLIA_RPC_URL

STAGING_L1_RPC_URL overrides the profile RPC for the current invocation.
The run is resumable. Never blindly rerun after a timeout; inspect the saved
intent, transaction receipt, and phase evidence first.
USAGE
}

fail() {
  echo "[staging-cli-e2e] ERROR: $*" >&2
  exit 1
}

select_profile() {
  case "$STAGING_CHAIN" in
    ethereum|sepolia)
      PROFILE_NAME="sepolia"
      CONFIG_NETWORK="sepolia"
      DEPLOYMENTS_NETWORK="sepolia"
      L1_CHAIN_ID="11155111"
      L1_CHAIN_INDEX="0"
      DEFAULT_L1_RPC_URL="https://rpc-eth-stg.psy-protocol.xyz"
      PROFILE_RPC_URL="${SEPOLIA_RPC_URL:-$DEFAULT_L1_RPC_URL}"
      RPC_ENV_NAME="SEPOLIA_RPC_URL"
      ;;
    bsc|bsc-testnet|bscTestnet)
      PROFILE_NAME="bsc"
      CONFIG_NETWORK="bsc-testnet"
      DEPLOYMENTS_NETWORK="bscTestnet"
      L1_CHAIN_ID="97"
      L1_CHAIN_INDEX="1"
      DEFAULT_L1_RPC_URL="https://rpc-bsc-stg.psy-protocol.xyz"
      PROFILE_RPC_URL="${BSC_TESTNET_RPC_URL:-$DEFAULT_L1_RPC_URL}"
      RPC_ENV_NAME="BSC_TESTNET_RPC_URL"
      ;;
    base|base-sepolia|baseSepolia)
      PROFILE_NAME="base"
      CONFIG_NETWORK="base-sepolia"
      DEPLOYMENTS_NETWORK="baseSepolia"
      L1_CHAIN_ID="84532"
      L1_CHAIN_INDEX="2"
      DEFAULT_L1_RPC_URL="https://rpc-base-stg.psy-protocol.xyz"
      PROFILE_RPC_URL="${BASE_SEPOLIA_RPC_URL:-$DEFAULT_L1_RPC_URL}"
      RPC_ENV_NAME="BASE_SEPOLIA_RPC_URL"
      ;;
    *)
      fail "unknown STAGING_CHAIN '$STAGING_CHAIN'; expected sepolia, bsc, or base"
      ;;
  esac
  L1_RPC_URL="${STAGING_L1_RPC_URL:-$PROFILE_RPC_URL}"
}

ensure_e2e_binary() {
  if [ ! -x "$E2E_BIN" ]; then
    echo "[staging-cli-e2e] building psy_cli_full_e2e"
    cargo build --release -p psy_cli_full_e2e
  fi
  [ -x "$E2E_BIN" ] || fail "missing E2E executable: $E2E_BIN"
}

ensure_user_cli() {
  [ -x "$USER_CLI" ] ||
    fail "missing release psy_user_cli; build the deployment-matching CLI first"
}

render_staging_config() {
  local output="$1"
  [ -f "$BASE_CONFIG" ] || fail "missing base client config: $BASE_CONFIG"
  mkdir -p "$(dirname "$output")"
  jq \
    --arg network "$CONFIG_NETWORK" \
    --argjson chain_id "$L1_CHAIN_ID" \
    --arg rpc_url "$L1_RPC_URL" \
    --arg rpc_env "$RPC_ENV_NAME" \
    '.defaultNetwork = $network
     | .networks[$network] = (
         .networks.sepolia
         | .l1_chain_id = $chain_id
         | .l1_rpc_urls = [$rpc_url]
         | .anvilForkSourceUrlEnv = $rpc_env
       )' \
    "$BASE_CONFIG" >"$output"
  chmod 600 "$output"
}

validate_run_profile() {
  local run_dir="$1"
  local manifest="$run_dir/manifest.json"
  [ -f "$manifest" ] || fail "missing run manifest: $manifest"
  local actual
  actual="$(jq -r '[.network, .deployments_network, (.l1_chain_id | tostring), (.l1_chain_index | tostring)] | join("|")' "$manifest")"
  local expected="$CONFIG_NETWORK|$DEPLOYMENTS_NETWORK|$L1_CHAIN_ID|$L1_CHAIN_INDEX"
  [ "$actual" = "$expected" ] ||
    fail "run profile mismatch: selected=$expected manifest=$actual"
}

command_name="${1:-}"
case "$command_name" in
  -h|--help|"")
    usage
    exit 0
    ;;
esac
shift

cd "$REPO_DIR"
umask 077
select_profile
rpc_args=(--l1-rpc-url "$L1_RPC_URL")

case "$command_name" in
  init)
    ensure_e2e_binary
    run_dir="${1:-}"
    evm_key_file="${2:-}"
    generated_config="$(mktemp "${TMPDIR:-/tmp}/psy-staging-$PROFILE_NAME-config.XXXXXX.json")"
    trap 'rm -f "$generated_config"' EXIT
    render_staging_config "$generated_config"
    args=(
      init
      --root "$REPO_DIR"
      --network "$CONFIG_NETWORK"
      --config-path "$generated_config"
      --deployments-network "$DEPLOYMENTS_NETWORK"
      --l1-chain-index "$L1_CHAIN_INDEX"
    )
    if [ -n "$run_dir" ]; then
      args+=(--run-dir "$run_dir")
    fi
    if [ -n "$evm_key_file" ]; then
      [ -f "$evm_key_file" ] || fail "EVM key file not found: $evm_key_file"
      args+=(--evm-key-file "$evm_key_file")
    fi
    "$E2E_BIN" "${args[@]}"
    ;;

  status)
    ensure_e2e_binary
    run_dir="${1:-}"
    [ -n "$run_dir" ] || fail "status requires RUN_DIR"
    [ -d "$run_dir" ] || fail "run directory not found: $run_dir"
    validate_run_profile "$run_dir"
    "$E2E_BIN" status --root "$REPO_DIR" --run-dir "$run_dir" "${rpc_args[@]}"
    ;;

  run)
    ensure_e2e_binary
    ensure_user_cli
    run_dir="${1:-}"
    [ -n "$run_dir" ] || fail "run requires RUN_DIR"
    shift
    [ -d "$run_dir" ] || fail "run directory not found: $run_dir"
    validate_run_profile "$run_dir"
    [ "${AUTHORIZED_STAGING_TRANSACTIONS:-0}" = "1" ] ||
      fail "set AUTHORIZED_STAGING_TRANSACTIONS=1 after explicit authorization"

    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$run_dir/logs"
    chmod 700 "$run_dir" "$run_dir/logs"
    {
      printf 'started_at=%s\n' "$(date --iso-8601=seconds)"
      printf 'repo=%s\n' "$REPO_DIR"
      printf 'repo_revision=%s\n' "$(git rev-parse HEAD)"
      printf 'profile=%s\n' "$PROFILE_NAME"
      printf 'network=%s\n' "$CONFIG_NETWORK"
      printf 'deployments_network=%s\n' "$DEPLOYMENTS_NETWORK"
      printf 'l1_chain_id=%s\n' "$L1_CHAIN_ID"
      printf 'l1_chain_index=%s\n' "$L1_CHAIN_INDEX"
      printf 'l1_rpc_host=%s\n' "$(printf '%s' "$L1_RPC_URL" | sed -E 's#(https?://[^/]+).*#\1#')"
      printf 'psy_user_cli_sha256=%s\n' "$(sha256sum "$USER_CLI" | awk '{print $1}')"
      printf 'e2e_sha256=%s\n' "$(sha256sum "$E2E_BIN" | awk '{print $1}')"
    } >"$run_dir/logs/wrapper-context-$timestamp.txt"

    echo "[staging-cli-e2e] transactions are authorized for $PROFILE_NAME"
    echo "[staging-cli-e2e] do not blindly rerun after a timeout"

    set +e
    "$E2E_BIN" run \
      --root "$REPO_DIR" \
      --run-dir "$run_dir" \
      "${rpc_args[@]}" \
      --authorized-staging-transactions \
      "$@" 2>&1 | tee "$run_dir/logs/run-$timestamp.log"
    result=${PIPESTATUS[0]}
    set -e

    printf 'exit_code=%s\nfinished_at=%s\n' \
      "$result" "$(date --iso-8601=seconds)" \
      >"$run_dir/logs/wrapper-result-$timestamp.txt"

    if [ "$result" -ne 0 ]; then
      fail "E2E stopped with exit code $result; inspect $run_dir before resuming"
    fi
    echo "[staging-cli-e2e] PASS profile=$PROFILE_NAME run_dir=$run_dir"
    ;;

  *)
    usage >&2
    fail "unknown command: $command_name"
    ;;
esac
