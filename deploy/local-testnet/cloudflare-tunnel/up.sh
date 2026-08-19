#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"
# shellcheck source=../local-staging/lib.sh
source "$PARTH_DIR/deploy/local-testnet/stack/lib.sh"

local_cf_render_all
LOCAL_CF_FULL_RESET_REQUESTED="${LOCAL_STAGING_RESET:-0}"

toml_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '%s' "$value"
}

build_relayer_if_requested() {
  [ "${LOCAL_STAGING_BUILD:-0}" = "1" ] || return 0

  echo "[local-cf-tunnel] building bridge relayer release binary"
  cargo build --manifest-path "$PARTH_DIR/Cargo.toml" --release --bin psy_relayer_cli
}

start_anvil_if_needed() {
  [ "${LOCAL_CF_START_ANVIL:-1}" = "1" ] || return 0
  local chain_id="${LOCAL_STAGING_L1_CHAIN_ID:-31338}"
  local block_time="${LOCAL_STAGING_L1_BLOCK_TIME:-1}"
  local pid_file="$PARTH_DIR/.local-staging/pids/anvil.pid"
  local existing_pid=""

  if timeout 2 bash -lc "</dev/tcp/127.0.0.1/$LOCAL_STAGING_L1_RPC_PORT" >/dev/null 2>&1; then
    if command -v pgrep >/dev/null 2>&1; then
      existing_pid="$(pgrep -u "$(id -u)" -f "(^|/)anvil .*--port[ =]$LOCAL_STAGING_L1_RPC_PORT([[:space:]]|$)" | head -n 1 || true)"
    fi
    if [ -n "$existing_pid" ] && kill -0 "$existing_pid" >/dev/null 2>&1; then
      mkdir -p "$(dirname "$pid_file")"
      printf '%s\n' "$existing_pid" > "$pid_file"
      echo "[local-cf-tunnel] adopted existing anvil pid=$existing_pid"
    else
      rm -f "$pid_file"
      echo "[local-cf-tunnel] l1 rpc is externally managed; removed stale anvil pid state"
    fi
    echo "[local-cf-tunnel] l1 rpc already listening on 127.0.0.1:$LOCAL_STAGING_L1_RPC_PORT"
    return 0
  fi

  local anvil_bin="${LOCAL_STAGING_ANVIL_BIN:-}"
  if [ -z "$anvil_bin" ]; then
    anvil_bin="$(command -v anvil || true)"
  fi
  if [ -z "$anvil_bin" ] || [ ! -x "$anvil_bin" ]; then
    echo "[local-cf-tunnel] warning: anvil not found; rpc tunnel will return 502 until 127.0.0.1:$LOCAL_STAGING_L1_RPC_PORT is listening" >&2
    return 0
  fi

  mkdir -p "$PARTH_DIR/.local-staging/logs" "$PARTH_DIR/.local-staging/pids"
  local anvil_args=(--host 127.0.0.1 --port "$LOCAL_STAGING_L1_RPC_PORT" --chain-id "$chain_id")
  if [ -n "$block_time" ] && [ "$block_time" != "0" ]; then
    anvil_args+=(--block-time "$block_time")
  fi

  echo "[local-cf-tunnel] starting anvil on 127.0.0.1:$LOCAL_STAGING_L1_RPC_PORT chain_id=$chain_id block_time=${block_time:-disabled}"
  if command -v setsid >/dev/null 2>&1; then
    setsid "$anvil_bin" "${anvil_args[@]}" \
      > "$PARTH_DIR/.local-staging/logs/anvil.log" 2>&1 &
  else
    nohup "$anvil_bin" "${anvil_args[@]}" \
      > "$PARTH_DIR/.local-staging/logs/anvil.log" 2>&1 &
  fi
  echo "$!" > "$pid_file"

  local i
  for i in $(seq 1 30); do
    if timeout 2 bash -lc "</dev/tcp/127.0.0.1/$LOCAL_STAGING_L1_RPC_PORT" >/dev/null 2>&1; then
      echo "[local-cf-tunnel] ready: l1 rpc"
      return 0
    fi
    sleep 1
  done

  echo "[local-cf-tunnel] warning: timed out waiting for l1 rpc" >&2
  tail -80 "$PARTH_DIR/.local-staging/logs/anvil.log" >&2 || true
}

snapshot_deployed_backend_abis() {
  local snapshot_root="${LOCAL_CF_BACKEND_ABI_SNAPSHOT_ROOT:-$LOCAL_CF_LIVE_PARTH_DIR/.local-staging/backend-abi}"
  if [ "${LOCAL_CF_UPDATE_BACKEND_ABI_SNAPSHOT:-${LOCAL_STAGING_BUILD:-0}}" != "1" ] \
     && [ -d "$snapshot_root/current" ]; then
    echo "[local-cf-tunnel] backend ABI snapshot unchanged"
    return 0
  fi

  local releases_dir="$snapshot_root/releases"
  local source_dir="$PARTH_DIR/genesis_abi"
  local release_id
  local release_dir
  local next_link="$snapshot_root/current.next.$$"
  local abi_file
  local abi_files=(
    PsyDepositTreeContract.json
    PsyFaucetContract.json
    PsyTokenContract.json
    PsyWithdrawalTreeContract.json
    USDTTokenContract.json
  )

  release_id="$(git -C "$PARTH_DIR" rev-parse --short=12 HEAD)-$(date -u +%Y%m%dT%H%M%SZ)"
  release_dir="$releases_dir/$release_id"
  mkdir -p "$release_dir"
  for abi_file in "${abi_files[@]}"; do
    local_cf_require_file "$source_dir/$abi_file"
    cp "$source_dir/$abi_file" "$release_dir/$abi_file"
  done
  jq -n \
    --arg parthCommit "$(git -C "$PARTH_DIR" rev-parse HEAD)" \
    --arg deployedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{parthCommit: $parthCommit, deployedAt: $deployedAt}' \
    > "$release_dir/deployment.json"
  ln -s "releases/$release_id" "$next_link"
  mv -Tf "$next_link" "$snapshot_root/current"
  echo "[local-cf-tunnel] backend ABI snapshot updated: $release_dir"
}

local_l1_verifier_sources_hash() {
  local contracts_dir="$1"
  sha256sum \
    "$contracts_dir/src/GnarkGroth16Verifier.sol" \
    "$contracts_dir/src/DepositBatchVerifier.sol" \
    "$contracts_dir/src/WithdrawalClaimVerifier.sol" \
    "$contracts_dir/deploy/001_deploy_verifier.ts" \
    | sha256sum \
    | awk '{print $1}'
}

local_l1_verifier_source_hash() {
  local contracts_dir="$1"
  local source_name="$2"
  sha256sum "$contracts_dir/src/$source_name" | awk '{print $1}'
}

local_groth16_keystore_dir() {
  local kind="$1"
  local target_root="${LOCAL_GROTH16_KEYSTORE_ROOT:-$HOME/.psy/keystore}"

  if [ "$kind" = "bridge" ]; then
    local_bridge_wrap_keystore_dir
    return 0
  fi

  if [ "$kind" = "withdrawal_claim" ]; then
    local_withdrawal_claim_keystore_dir
    return 0
  fi

  case "$kind" in
    deposit_batch_append) printf '%s\n' "$target_root/deposit_append" ;;
    *) return 1 ;;
  esac
}

local_bridge_wrap_keystore_dir() {
  local override="${LOCAL_GROTH16_BRIDGE_KEYSTORE_DIR:-}"

  if [ -n "$override" ]; then
    printf '%s\n' "$override"
    return 0
  fi

  printf '%s\n' "${LOCAL_GROTH16_KEYSTORE_ROOT:-$HOME/.psy/keystore}"
}

local_withdrawal_claim_keystore_dir() {
  local override="${LOCAL_GROTH16_WITHDRAWAL_CLAIM_KEYSTORE_DIR:-}"

  if [ -n "$override" ]; then
    printf '%s\n' "$override"
    return 0
  fi

  printf '%s\n' "${LOCAL_GROTH16_KEYSTORE_ROOT:-$HOME/.psy/keystore}/withdrawal_claim"
}

prepare_local_groth16_keystores() {
  local relayer_bin="$PARTH_DIR/target/release/psy_relayer_cli"
  local keystore_root="${LOCAL_GROTH16_KEYSTORE_ROOT:-$HOME/.psy/keystore}"
  local regenerate="${LOCAL_CF_REGENERATE_GROTH16_KEYSTORE:-0}"
  local source_stamp="$keystore_root/.bridge-circuit-source.sha256"
  local source_hash
  local dir file

  source_hash="$(
    git -C "$PARTH_DIR" rev-parse \
      HEAD:psy_plonky2_circuits \
      HEAD:psy_plonky2_common_circuits \
      HEAD:client_prover/psy_circuit \
      HEAD:client_prover/psy_core \
      HEAD:parth_core \
      | sha256sum \
      | awk '{print $1}'
  )"

  if [ "$regenerate" != "1" ] && [ "$LOCAL_CF_FULL_RESET_REQUESTED" = "1" ]; then
    if [ ! -s "$source_stamp" ] || [ "$(cat "$source_stamp")" != "$source_hash" ]; then
      regenerate=1
    fi
  fi

  if [ "$regenerate" != "1" ]; then
    for dir in "$keystore_root" "$keystore_root/deposit_append" "$keystore_root/withdrawal_claim"; do
      for file in circuit_groth16.bin pk_groth16.bin vk_groth16.bin; do
        if [ ! -s "$dir/$file" ]; then
          regenerate=1
        fi
      done
    done
  fi

  [ "$regenerate" = "1" ] || return 0
  echo "[local-cf-tunnel] regenerating Groth16 keystores for the current bridge circuits"
  "$relayer_bin" regenerate-groth16-keystore \
    --keystore-dir "$keystore_root" \
    --include-bridge-agg
  printf '%s\n' "$source_hash" > "$source_stamp"
}

export_local_l1_groth16_verifiers() {
  [ "${LOCAL_CF_EXPORT_GROTH16_VERIFIERS:-1}" = "1" ] || return 0

  local contracts_dir="$1"
  local relayer_bin="$PARTH_DIR/target/release/psy_relayer_cli"
  local kind keystore output

  if [ ! -x "$relayer_bin" ]; then
    echo "[local-cf-tunnel] missing executable: $relayer_bin" >&2
    echo "[local-cf-tunnel] build it with: cargo build --release --bin psy_relayer_cli" >&2
    exit 1
  fi

  prepare_local_groth16_keystores

  for kind in bridge deposit_batch_append withdrawal_claim; do
    keystore="$(local_groth16_keystore_dir "$kind")"
    case "$kind" in
      # 001_deploy_verifier.ts deploys this exact artifact. Keep the generated
      # verifier path aligned with Hardhat's source name and case.
      bridge) output="$contracts_dir/src/GnarkGroth16Verifier.sol" ;;
      deposit_batch_append) output="$contracts_dir/src/DepositBatchVerifier.sol" ;;
      withdrawal_claim) output="$contracts_dir/src/WithdrawalClaimVerifier.sol" ;;
    esac

    for file in circuit_groth16.bin pk_groth16.bin vk_groth16.bin; do
      [ -s "$keystore/$file" ] || {
        echo "[local-cf-tunnel] missing $kind Groth16 setup file: $keystore/$file" >&2
        echo "[local-cf-tunnel] install setup with: bash deploy/local-testnet/relayer/install-local-groth16-setup.sh" >&2
        exit 1
      }
    done

    echo "[local-cf-tunnel] exporting $kind Solidity verifier -> $output"
    "$relayer_bin" export-solidity-verifier "$keystore" "$output"
  done
}

stop_bridge_relayer_if_running() {
  local reason="${1:-requested}"
  local pid_file="$PARTH_DIR/.local-staging/pids/bridge-relayer.pid"
  local pid

  [ -f "$pid_file" ] || return 0
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  [ -n "$pid" ] || return 0
  kill -0 "$pid" >/dev/null 2>&1 || return 0

  echo "[local-cf-tunnel] stopping bridge relayer pid=$pid ($reason)"
  kill "$pid" >/dev/null 2>&1 || true

  local i
  for i in $(seq 1 20); do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "[local-cf-tunnel] bridge relayer did not stop after 20s; stop it manually before continuing" >&2
  exit 1
}

install_l1_contract_dependencies() {
  local contracts_dir="$1"

  if [ -f "$contracts_dir/pnpm-lock.yaml" ]; then
    local_cf_require_command pnpm
    (cd "$contracts_dir" && pnpm install --frozen-lockfile)
  elif [ -f "$contracts_dir/package-lock.json" ]; then
    local_cf_require_command npm
    (cd "$contracts_dir" && npm ci)
  else
    local_cf_require_command npm
    echo "[local-cf-tunnel] warning: no supported lockfile found in $contracts_dir; using npm install" >&2
    (cd "$contracts_dir" && npm install)
  fi
}

deploy_l1_contracts() {
  local contracts_dir="$1"
  local l1_rpc_url="$2"

  if [ -f "$contracts_dir/pnpm-lock.yaml" ]; then
    (cd "$contracts_dir" && LOCALHOST_RPC_URL="$l1_rpc_url" LOCALHOST_L1_CHAIN_ID="${LOCAL_STAGING_L1_CHAIN_ID:-31338}" pnpm run deploy:localhost --reset)
  else
    (cd "$contracts_dir" && LOCALHOST_RPC_URL="$l1_rpc_url" LOCALHOST_L1_CHAIN_ID="${LOCAL_STAGING_L1_CHAIN_ID:-31338}" npm run deploy:localhost -- --reset)
  fi
}

deploy_l1_verifiers_only() {
  local contracts_dir="$1"
  local l1_rpc_url="$2"

  if [ -f "$contracts_dir/pnpm-lock.yaml" ]; then
    (cd "$contracts_dir" && \
      LOCALHOST_RPC_URL="$l1_rpc_url" \
      LOCALHOST_L1_CHAIN_ID="${LOCAL_STAGING_L1_CHAIN_ID:-31338}" \
      pnpm exec hardhat deploy --network localhost --tags verifier)
  else
    (cd "$contracts_dir" && \
      LOCALHOST_RPC_URL="$l1_rpc_url" \
      LOCALHOST_L1_CHAIN_ID="${LOCAL_STAGING_L1_CHAIN_ID:-31338}" \
      npx hardhat deploy --network localhost --tags verifier)
  fi
}

rotate_local_withdrawal_claim_verifier() {
  local contracts_dir="$1"
  local l1_rpc_url="$2"
  local deployment_file="$3"
  local bridge_address
  local verifier_address
  local private_key="${LOCAL_STAGING_RELAYER_L1_PRIVATE_KEY:-ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
  local tmp_deployment

  local_cf_require_command cast
  deploy_l1_verifiers_only "$contracts_dir" "$l1_rpc_url"

  bridge_address="$(jq -er '.core.Bridge // .contracts.Bridge' "$deployment_file")"
  verifier_address="$(jq -er '.address' "$contracts_dir/deployments/localhost/WithdrawalClaimVerifier.json")"

  echo "[local-cf-tunnel] rotating withdrawal verifier on existing Bridge: $verifier_address"
  cast send "$bridge_address" \
    'setWithdrawalClaimVerifier(address)' "$verifier_address" \
    --private-key "$private_key" \
    --rpc-url "$l1_rpc_url"

  tmp_deployment="${deployment_file}.tmp.$$"
  jq --arg verifier "$verifier_address" '
    .core.WithdrawalClaimVerifier = $verifier
    | .contracts.WithdrawalClaimVerifier = $verifier
    | if .verify.WithdrawalClaimVerifier then
        .verify.WithdrawalClaimVerifier.address = $verifier
      else
        .
      end
  ' "$deployment_file" > "$tmp_deployment"
  mv "$tmp_deployment" "$deployment_file"
}

ensure_local_l1_contracts() (
  [ "${LOCAL_CF_DEPLOY_L1_CONTRACTS:-1}" = "1" ] || return 0

  local contracts_dir="${LOCAL_STAGING_CONTRACTS_DIR:-$PARTH_DIR/psy-contracts}"
  local deployment_file="$contracts_dir/deployments/localhost/deployed-contracts.json"
  local l1_rpc_url="http://127.0.0.1:$LOCAL_STAGING_L1_RPC_PORT"
  local verifier_stamp="$PARTH_DIR/.local-staging/l1-verifier-source.sha256"
  local bridge_verifier_stamp="$PARTH_DIR/.local-staging/l1-bridge-verifier-source.sha256"
  local deposit_verifier_stamp="$PARTH_DIR/.local-staging/l1-deposit-verifier-source.sha256"
  local withdrawal_verifier_stamp="$PARTH_DIR/.local-staging/l1-withdrawal-verifier-source.sha256"
  local verifier_hash
  local bridge_verifier_hash
  local deposit_verifier_hash
  local withdrawal_verifier_hash
  local needs_deploy=0
  local needs_withdrawal_verifier_rotation=0
  local component_stamps_ready=0
  local router_address=""
  local verifier_backup_dir
  local verifier_source

  verifier_backup_dir="$(mktemp -d)"
  for verifier_source in \
    GnarkGroth16Verifier.sol \
    DepositBatchVerifier.sol \
    WithdrawalClaimVerifier.sol; do
    cp "$contracts_dir/src/$verifier_source" "$verifier_backup_dir/$verifier_source"
  done
  restore_local_verifier_sources() {
    for verifier_source in \
      GnarkGroth16Verifier.sol \
      DepositBatchVerifier.sol \
      WithdrawalClaimVerifier.sol; do
      cp "$verifier_backup_dir/$verifier_source" "$contracts_dir/src/$verifier_source"
    done
    rm -rf "$verifier_backup_dir"
  }
  trap restore_local_verifier_sources EXIT

  export_local_l1_groth16_verifiers "$contracts_dir"
  verifier_hash="$(local_l1_verifier_sources_hash "$contracts_dir")"
  bridge_verifier_hash="$(local_l1_verifier_source_hash "$contracts_dir" GnarkGroth16Verifier.sol)"
  deposit_verifier_hash="$(local_l1_verifier_source_hash "$contracts_dir" DepositBatchVerifier.sol)"
  withdrawal_verifier_hash="$(local_l1_verifier_source_hash "$contracts_dir" WithdrawalClaimVerifier.sol)"

  if [ -f "$bridge_verifier_stamp" ] \
     && [ -f "$deposit_verifier_stamp" ] \
     && [ -f "$withdrawal_verifier_stamp" ]; then
    component_stamps_ready=1
  fi

  if [ "$component_stamps_ready" = "1" ]; then
    if [ "$(cat "$bridge_verifier_stamp")" != "$bridge_verifier_hash" ] \
       || [ "$(cat "$deposit_verifier_stamp")" != "$deposit_verifier_hash" ]; then
      echo "[local-cf-tunnel] bridge/deposit verifier source changed; forcing localhost L1 deploy"
      needs_deploy=1
    elif [ "$(cat "$withdrawal_verifier_stamp")" != "$withdrawal_verifier_hash" ]; then
      needs_withdrawal_verifier_rotation=1
    elif [ ! -f "$verifier_stamp" ] || [ "$(cat "$verifier_stamp")" != "$verifier_hash" ]; then
      echo "[local-cf-tunnel] L1 verifier deployment logic changed; forcing localhost L1 deploy"
      needs_deploy=1
    fi
  elif [ ! -f "$verifier_stamp" ] || [ "$(cat "$verifier_stamp")" != "$verifier_hash" ]; then
    echo "[local-cf-tunnel] L1 verifier source changed or not deployed yet; forcing localhost L1 deploy"
    needs_deploy=1
  fi

  if [ ! -f "$deployment_file" ]; then
    needs_deploy=1
  else
    router_address="$(jq -r '.core.Router // .contracts.Router // empty' "$deployment_file")"
    if [ -z "$router_address" ] || [ "$router_address" = "null" ]; then
      needs_deploy=1
    else
      local code
      code="$(curl -fsS --max-time 10 \
        -H 'content-type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getCode\",\"params\":[\"$router_address\",\"latest\"]}" \
        "$l1_rpc_url" | jq -r '.result // "0x"' 2>/dev/null || printf '0x')"
      if [ "$code" = "0x" ] || [ -z "$code" ]; then
        needs_deploy=1
      fi
    fi
  fi

  if [ "$needs_deploy" != "1" ]; then
    if [ "$needs_withdrawal_verifier_rotation" = "1" ]; then
      stop_bridge_relayer_if_running "withdrawal claim verifier is being rotated"
      rotate_local_withdrawal_claim_verifier "$contracts_dir" "$l1_rpc_url" "$deployment_file"
    fi
    mkdir -p "$(dirname "$verifier_stamp")"
    printf '%s\n' "$verifier_hash" > "$verifier_stamp"
    printf '%s\n' "$bridge_verifier_hash" > "$bridge_verifier_stamp"
    printf '%s\n' "$deposit_verifier_hash" > "$deposit_verifier_stamp"
    printf '%s\n' "$withdrawal_verifier_hash" > "$withdrawal_verifier_stamp"
    echo "[local-cf-tunnel] localhost L1 contracts are present"
    return 0
  fi

  echo "[local-cf-tunnel] deploying localhost L1 contracts"
  stop_bridge_relayer_if_running "localhost L1 contracts are being redeployed"
  if [ ! -x "$contracts_dir/node_modules/.bin/hardhat" ]; then
    echo "[local-cf-tunnel] installing psy-contracts dependencies"
    install_l1_contract_dependencies "$contracts_dir"
  fi
  deploy_l1_contracts "$contracts_dir" "$l1_rpc_url"
  mkdir -p "$(dirname "$verifier_stamp")"
  printf '%s\n' "$verifier_hash" > "$verifier_stamp"
  printf '%s\n' "$bridge_verifier_hash" > "$bridge_verifier_stamp"
  printf '%s\n' "$deposit_verifier_hash" > "$deposit_verifier_stamp"
  printf '%s\n' "$withdrawal_verifier_hash" > "$withdrawal_verifier_stamp"
)

start_eth_faucet_if_needed() {
  [ "${LOCAL_CF_START_ETH_FAUCET:-1}" = "1" ] || return 0

  if timeout 2 bash -lc "</dev/tcp/127.0.0.1/$LOCAL_CF_ETH_FAUCET_PORT" >/dev/null 2>&1; then
    echo "[local-cf-tunnel] eth faucet already listening on 127.0.0.1:$LOCAL_CF_ETH_FAUCET_PORT"
    return 0
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    echo "[local-cf-tunnel] warning: python3 not found; eth faucet will not start" >&2
    return 0
  fi

  mkdir -p "$PARTH_DIR/.local-staging/logs" "$PARTH_DIR/.local-staging/pids"
  echo "[local-cf-tunnel] starting eth faucet on 127.0.0.1:$LOCAL_CF_ETH_FAUCET_PORT"
  if command -v setsid >/dev/null 2>&1; then
    setsid bash "$SCRIPT_DIR/run-eth-faucet.sh" \
      > "$PARTH_DIR/.local-staging/logs/eth-faucet.log" 2>&1 &
  else
    nohup bash "$SCRIPT_DIR/run-eth-faucet.sh" \
      > "$PARTH_DIR/.local-staging/logs/eth-faucet.log" 2>&1 &
  fi
  echo "$!" > "$PARTH_DIR/.local-staging/pids/eth-faucet.pid"

  local i
  for i in $(seq 1 15); do
    if timeout 2 bash -lc "</dev/tcp/127.0.0.1/$LOCAL_CF_ETH_FAUCET_PORT" >/dev/null 2>&1; then
      echo "[local-cf-tunnel] ready: eth faucet"
      return 0
    fi
    sleep 1
  done

  echo "[local-cf-tunnel] warning: timed out waiting for eth faucet" >&2
  tail -80 "$PARTH_DIR/.local-staging/logs/eth-faucet.log" >&2 || true
}

stop_envio_if_running() {
  local reason="${1:-requested}"
  local envio_dir="$PARTH_DIR/psy_cli/psy_relayer_cli/indexer/envio"
  local pid_file="$PARTH_DIR/.local-staging/pids/envio.pid"
  local pid
  local worker_pid
  local worker_pids

  pid="$(cat "$pid_file" 2>/dev/null || true)"
  worker_pids="$(find_envio_worker_pids "$envio_dir")"

  if [ -z "$pid" ] && [ -z "$worker_pids" ]; then
    return 0
  fi

  if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
    echo "[local-cf-tunnel] stopping Envio indexer pid=$pid ($reason)"
    kill -- "-$pid" >/dev/null 2>&1 || true
    kill "$pid" >/dev/null 2>&1 || true
  fi
  while IFS= read -r worker_pid; do
    [ -n "$worker_pid" ] || continue
    if [ "$worker_pid" != "$pid" ] && kill -0 "$worker_pid" >/dev/null 2>&1; then
      echo "[local-cf-tunnel] stopping Envio worker pid=$worker_pid ($reason)"
      kill -- "-$worker_pid" >/dev/null 2>&1 || true
      kill "$worker_pid" >/dev/null 2>&1 || true
    fi
  done <<< "$worker_pids"

  local i
  for i in $(seq 1 20); do
    worker_pids="$(find_envio_worker_pids "$envio_dir")"
    if { [ -z "$pid" ] || ! kill -0 "$pid" >/dev/null 2>&1; } && [ -z "$worker_pids" ]; then
      return 0
    fi
    sleep 1
  done

  echo "[local-cf-tunnel] Envio indexer did not stop after 20s; stop it manually before continuing" >&2
  exit 1
}

find_envio_worker_pid() {
  local envio_dir="$1"
  find_envio_worker_pids "$envio_dir" | head -1 || true
}

find_envio_worker_pids() {
  local envio_dir="$1"
  {
    pgrep -f "$envio_dir/.*/envio dev --config ./config.yaml" || true
    pgrep -f "$envio_dir/generated/.*/ts-node/.*/bin.js src/Index.res.js" || true
    pgrep -f "node $envio_dir/generated/src/Index.res.js" || true
  } | sort -u
}

write_envio_config() {
  [ "${LOCAL_CF_START_ENVIO:-1}" = "1" ] || return 0

  local envio_dir="$PARTH_DIR/psy_cli/psy_relayer_cli/indexer/envio"
  local contracts_dir="${LOCAL_STAGING_CONTRACTS_DIR:-$PARTH_DIR/psy-contracts}"
  local deployments_json="$contracts_dir/deployments/localhost/deployed-contracts.json"
  local bridge_address
  local state_manager_address
  local start_block="${LOCAL_CF_ENVIO_START_BLOCK:-1}"

  local_cf_require_file "$deployments_json"
  bridge_address="$(jq -er '.core.Bridge // .contracts.Bridge' "$deployments_json")"
  state_manager_address="$(jq -er '.core.StateManager // .contracts.StateManager' "$deployments_json")"

  cat > "$envio_dir/config.yaml" <<YAML
# Envio config for the active local CF staging deployment.

name: psy-relayer-indexer
field_selection:
  transaction_fields:
    - hash

networks:
  - id: ${LOCAL_STAGING_L1_CHAIN_ID:-31338}
    start_block: ${start_block}
    rpc_config:
      url: http://127.0.0.1:${LOCAL_STAGING_L1_RPC_PORT}
    contracts:
      - name: Bridge
        address:
          - ${bridge_address}
        handler: ./handlers.ts
        events:
          - event: WithdrawalClaimed(bytes32 indexed nullifier, address indexed recipient, address indexed token, uint256 amount)
          - event: DepositRecorded(uint32 indexed index, bytes32 shieldAddress, address indexed token, bytes32 l2TokenContractId, uint256 amount, uint8 chainIndex, bytes32 noteCommitment, bytes32 leafHash)
      - name: StateManager
        address:
          - ${state_manager_address}
        handler: ./handlers.ts
        events:
          - event: Finalized(uint64 indexed newLastFinalizedCheckpointId, bytes32 indexed newLastVerifiedCheckpointRoot, bytes32 depositTreeRoot, bytes32 withdrawalTreeRoot)
YAML

  echo "[local-cf-tunnel] wrote Envio config: $envio_dir/config.yaml"
}

set_envio_yargs_package_type() {
  local envio_dir="$1"
  local package_type="$2"
  local yargs_pkg

  yargs_pkg="$(find "$envio_dir/node_modules/.pnpm" -path '*/node_modules/yargs/package.json' -print -quit 2>/dev/null || true)"
  if [ -z "$yargs_pkg" ] || [ ! -f "$yargs_pkg" ]; then
    return 0
  fi

  if node -e '
const fs = require("fs");
const path = process.argv[1];
const packageType = process.argv[2];
const pkg = JSON.parse(fs.readFileSync(path, "utf8"));
if (pkg.type !== packageType) {
  pkg.type = packageType;
  fs.writeFileSync(path, JSON.stringify(pkg, null, 2) + "\n");
  console.log(`${path}: type=${packageType}`);
}
' "$yargs_pkg" "$package_type"; then
    return 0
  fi

  echo "[local-cf-tunnel] failed to normalize Envio yargs package metadata: $yargs_pkg" >&2
  exit 1
}

start_envio_storage() {
  local envio_dir="$1"
  local compose_file="$2"
  local envio_pg_port="$3"
  local hasura_admin_secret="${LOCAL_CF_ENVIO_HASURA_ADMIN_SECRET:-${LOCAL_STAGING_HASURA_ADMIN_SECRET:-testing}}"

  echo "[local-cf-tunnel] starting Envio storage"
  (
    cd "$envio_dir"
    ENVIO_PG_PORT="$envio_pg_port" \
      HASURA_EXTERNAL_PORT="$LOCAL_STAGING_INDEXER_PORT" \
      HASURA_GRAPHQL_ADMIN_SECRET="$hasura_admin_secret" \
      docker compose -f "$compose_file" up -d
  )

  local i
  for i in $(seq 1 60); do
    if timeout 2 bash -lc "</dev/tcp/127.0.0.1/$envio_pg_port" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  if ! timeout 2 bash -lc "</dev/tcp/127.0.0.1/$envio_pg_port" >/dev/null 2>&1; then
    echo "[local-cf-tunnel] timed out waiting for Envio Postgres on 127.0.0.1:$envio_pg_port" >&2
    exit 1
  fi

  for i in $(seq 1 60); do
    if curl -fsS --max-time 5 "http://127.0.0.1:${LOCAL_STAGING_INDEXER_PORT}/healthz" >/dev/null 2>&1; then
      echo "[local-cf-tunnel] ready: Envio storage"
      return 0
    fi
    sleep 1
  done

  echo "[local-cf-tunnel] timed out waiting for Envio Hasura on 127.0.0.1:${LOCAL_STAGING_INDEXER_PORT}" >&2
  exit 1
}

start_envio_if_needed() {
  [ "${LOCAL_CF_START_ENVIO:-1}" = "1" ] || return 0

  local envio_dir="$PARTH_DIR/psy_cli/psy_relayer_cli/indexer/envio"
  local compose_file="$envio_dir/generated/docker-compose.yaml"
  local generated_config_file="$envio_dir/generated/src/Generated.res"
  local pid_file="$PARTH_DIR/.local-staging/pids/envio.pid"
  local log_file="$PARTH_DIR/.local-staging/logs/envio.log"
  local err_file="$PARTH_DIR/.local-staging/logs/envio.err.log"
  local envio_pg_port="${LOCAL_CF_ENVIO_PG_PORT:-5433}"
  local relayer_restart_marker="$PARTH_DIR/.local-staging/pids/bridge-relayer.restart"
  local envio_codegen_bin="$envio_dir/generated/node_modules/.bin/envio"
  local hasura_admin_secret="${LOCAL_CF_ENVIO_HASURA_ADMIN_SECRET:-${LOCAL_STAGING_HASURA_ADMIN_SECRET:-testing}}"
  local pid
  local needs_codegen=0
  local contracts_dir="${LOCAL_STAGING_CONTRACTS_DIR:-$PARTH_DIR/psy-contracts}"
  local deployments_json="$contracts_dir/deployments/localhost/deployed-contracts.json"
  local bridge_address=""
  local state_manager_address=""

  local_cf_require_command pnpm
  if [ ! -x "$envio_codegen_bin" ]; then
    envio_codegen_bin="$envio_dir/node_modules/.bin/envio"
  fi
  if [ ! -x "$envio_codegen_bin" ]; then
    echo "[local-cf-tunnel] installing Envio dependencies"
    if [ -f "$envio_dir/pnpm-lock.yaml" ]; then
      (cd "$envio_dir" && pnpm install --frozen-lockfile)
    else
      (cd "$envio_dir" && pnpm install --no-frozen-lockfile)
    fi
  fi
  local_cf_require_file "$envio_codegen_bin"

  if [ ! -f "$compose_file" ] \
    || [ ! -f "$generated_config_file" ] \
    || [ "$envio_dir/config.yaml" -nt "$compose_file" ] \
    || [ "$envio_dir/config.yaml" -nt "$generated_config_file" ] \
    || [ "$envio_dir/schema.graphql" -nt "$compose_file" ] \
    || [ "$envio_dir/schema.graphql" -nt "$generated_config_file" ] \
    || [ "$envio_dir/handlers.ts" -nt "$compose_file" ] \
    || [ "$envio_dir/handlers.ts" -nt "$generated_config_file" ]; then
    needs_codegen=1
  fi

  if [ "$needs_codegen" != "1" ] && [ -f "$deployments_json" ] && [ -f "$generated_config_file" ]; then
    bridge_address="$(jq -er '.core.Bridge // .contracts.Bridge' "$deployments_json")"
    state_manager_address="$(jq -er '.core.StateManager // .contracts.StateManager' "$deployments_json")"
    if ! grep -Fq "$bridge_address" "$generated_config_file" \
      || ! grep -Fq "$state_manager_address" "$generated_config_file"; then
      echo "[local-cf-tunnel] Envio generated config has stale contract addresses; forcing codegen"
      needs_codegen=1
    fi
  fi

  if [ "$needs_codegen" = "1" ]; then
    echo "[local-cf-tunnel] generating Envio indexer code"
    set_envio_yargs_package_type "$envio_dir" module
    if ! (cd "$envio_dir" && "$envio_codegen_bin" codegen --config ./config.yaml); then
      set_envio_yargs_package_type "$envio_dir" commonjs || true
      exit 1
    fi
    set_envio_yargs_package_type "$envio_dir" commonjs
    mkdir -p "$(dirname "$relayer_restart_marker")"
    printf '1\n' > "$relayer_restart_marker"
  fi
  local_cf_require_file "$compose_file"
  local_cf_require_file "$generated_config_file"

  # Envio is a derived L1 event index. Local Anvil is routinely restarted from
  # genesis with the same chain id and deterministic contract addresses, which
  # makes persisted Envio storage look healthy while serving old-chain rows.
  # Re-scan by default on local startup; disable only when intentionally
  # preserving an Anvil instance across script runs.
  if [ "${LOCAL_CF_RESET_ENVIO_ON_START:-1}" = "1" ]; then
    stop_envio_if_running "resetting derived L1 index"
    echo "[local-cf-tunnel] resetting Envio derived index storage"
    (
      cd "$envio_dir"
      ENVIO_PG_PORT="$envio_pg_port" \
        HASURA_EXTERNAL_PORT="$LOCAL_STAGING_INDEXER_PORT" \
        HASURA_GRAPHQL_ADMIN_SECRET="$hasura_admin_secret" \
        docker compose -f "$compose_file" down -v
    )
    mkdir -p "$(dirname "$relayer_restart_marker")"
    printf '1\n' > "$relayer_restart_marker"
  elif [ -f "$pid_file" ]; then
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
      echo "[local-cf-tunnel] Envio indexer already running pid=$pid"
      return 0
    fi
    pid="$(find_envio_worker_pid "$envio_dir")"
    if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
      echo "$pid" > "$pid_file"
      echo "[local-cf-tunnel] Envio indexer already running pid=$pid"
      return 0
    fi
  fi

  start_envio_storage "$envio_dir" "$compose_file" "$envio_pg_port"

  mkdir -p "$PARTH_DIR/.local-staging/logs" "$PARTH_DIR/.local-staging/pids"
  echo "[local-cf-tunnel] initializing Envio generated indexer storage"
  (
    cd "$envio_dir/generated"
    ENVIO_PG_HOST=127.0.0.1 \
      ENVIO_PG_PORT="$envio_pg_port" \
      HASURA_GRAPHQL_ENDPOINT="http://127.0.0.1:${LOCAL_STAGING_INDEXER_PORT}/v1/metadata" \
      HASURA_GRAPHQL_ADMIN_SECRET="$hasura_admin_secret" \
      TUI_OFF=true \
      pnpm db-setup
  )

  echo "[local-cf-tunnel] starting Envio indexer -> $log_file"
  if command -v setsid >/dev/null 2>&1; then
    (
      cd "$envio_dir/generated"
      ENVIO_PG_HOST=127.0.0.1 \
        ENVIO_PG_PORT="$envio_pg_port" \
        HASURA_GRAPHQL_ENDPOINT="http://127.0.0.1:${LOCAL_STAGING_INDEXER_PORT}/v1/metadata" \
        HASURA_GRAPHQL_ADMIN_SECRET="$hasura_admin_secret" \
        TUI_OFF=true \
        setsid node "$envio_dir/generated/src/Index.res.js" > "$log_file" 2> "$err_file" &
      echo "$!" > "$pid_file"
    )
  else
    (
      cd "$envio_dir/generated"
      ENVIO_PG_HOST=127.0.0.1 \
        ENVIO_PG_PORT="$envio_pg_port" \
        HASURA_GRAPHQL_ENDPOINT="http://127.0.0.1:${LOCAL_STAGING_INDEXER_PORT}/v1/metadata" \
        HASURA_GRAPHQL_ADMIN_SECRET="$hasura_admin_secret" \
        TUI_OFF=true \
        nohup node "$envio_dir/generated/src/Index.res.js" > "$log_file" 2> "$err_file" &
      echo "$!" > "$pid_file"
    )
  fi

  local i
  for i in $(seq 1 90); do
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [ -z "$pid" ] || ! kill -0 "$pid" >/dev/null 2>&1; then
      pid="$(find_envio_worker_pid "$envio_dir")"
      if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
        echo "$pid" > "$pid_file"
      else
        echo "[local-cf-tunnel] Envio indexer exited during startup" >&2
        tail -120 "$log_file" >&2 || true
        tail -80 "$err_file" >&2 || true
        exit 1
      fi
    fi
    if curl -fsS --max-time 5 "http://127.0.0.1:${LOCAL_STAGING_INDEXER_PORT}/healthz" >/dev/null 2>&1; then
      if curl -fsS --max-time 5 \
        -H 'content-type: application/json' \
        -H "x-hasura-admin-secret: $hasura_admin_secret" \
        --data '{"query":"query { depositType: __type(name:\"Deposit\") { name } finalizedBatchType: __type(name:\"FinalizedBatch\") { name } }"}' \
        "http://127.0.0.1:${LOCAL_STAGING_INDEXER_PORT}/v1/graphql" \
        | jq -e '.data.depositType.name == "Deposit" and .data.finalizedBatchType.name == "FinalizedBatch"' >/dev/null 2>&1; then
        pid="$(find_envio_worker_pid "$envio_dir")"
        if [ -n "$pid" ]; then
          echo "$pid" > "$pid_file"
        fi
        echo "[local-cf-tunnel] ready: Envio indexer"
        return 0
      fi
    fi
    sleep 1
  done

  echo "[local-cf-tunnel] timed out waiting for Envio indexer startup" >&2
  tail -120 "$log_file" >&2 || true
  tail -80 "$err_file" >&2 || true
  exit 1
}

write_bridge_relayer_config() {
  [ "${LOCAL_CF_START_RELAYER:-1}" = "1" ] || return 0

  local contracts_dir="${LOCAL_STAGING_CONTRACTS_DIR:-$PARTH_DIR/psy-contracts}"
  local deployments_json="$contracts_dir/deployments/localhost/deployed-contracts.json"
  local private_keys_path="${LOCAL_STAGING_PRIVATE_KEYS_PATH:-$PARTH_DIR/private_keys.json}"
  local relayer_config="${LOCAL_STAGING_RELAYER_CONFIG:-$PARTH_DIR/.local-staging/bridge-relayer.toml}"
  local restart_marker="$PARTH_DIR/.local-staging/pids/bridge-relayer.restart"
  local tmp_config="${relayer_config}.tmp.$$"
  local relayer_proof_dir="${LOCAL_STAGING_RELAYER_PROOF_DIR:-$PARTH_DIR/.local-staging/bridge-relayer}"
  local relayer_rpc_config="${LOCAL_STAGING_RELAYER_RPC_CONFIG:-$PARTH_DIR/.local-staging/bridge-relayer-client_prover-config.json}"
  local relayer_key_index="${LOCAL_STAGING_RELAYER_L2_KEY_INDEX:-2}"
  local relayer_l2_key
  local bridge_address
  local state_manager_address

  local_cf_require_file "$deployments_json"
  local_cf_require_file "$private_keys_path"
  write_bridge_relayer_rpc_config "$relayer_rpc_config" "$restart_marker"

  relayer_l2_key="$(local_staging_private_key_at_index "$private_keys_path" "$relayer_key_index")"
  bridge_address="$(jq -er '.core.Bridge // .contracts.Bridge' "$deployments_json")"
  state_manager_address="$(jq -er '.core.StateManager // .contracts.StateManager' "$deployments_json")"

  mkdir -p "$(dirname "$relayer_config")" "$relayer_proof_dir"
  {
    printf 'rpc_config = "%s"\n' "$(toml_escape "$relayer_rpc_config")"
    printf 'services_url = "%s"\n' "$(toml_escape "http://${LOCAL_STAGING_PSY_SERVICES_ADDR}")"
    printf 'withdraw_method_id = %s\n' "${LOCAL_STAGING_RELAYER_WITHDRAW_METHOD_ID:-4159421846}"
    printf 'proof_dir = "%s"\n' "$(toml_escape "$relayer_proof_dir")"
    printf 'poll_interval_secs = %s\n' "${LOCAL_STAGING_RELAYER_POLL_INTERVAL_SECS:-5}"
    printf 'confirmation_lag_checkpoints = %s\n' "${LOCAL_STAGING_RELAYER_CONFIRMATION_LAG_CHECKPOINTS:-1}"
    printf 'max_checkpoint_batch = %s\n' "${LOCAL_STAGING_RELAYER_MAX_CHECKPOINT_BATCH:-32}"
    printf 'services_event_settle_secs = %s\n' "${LOCAL_STAGING_RELAYER_SERVICES_EVENT_SETTLE_SECS:-1}"
    printf 'withdrawal_scan_lookback_checkpoints = %s\n' "${LOCAL_STAGING_RELAYER_WITHDRAWAL_SCAN_LOOKBACK_CHECKPOINTS:-64}"
    printf 'exit_after_successful_rounds = 0\n\n'
    printf '[relayer_wallet]\n'
    printf 'sign_type = "ZKSign"\n'
    printf 'private_key = "%s"\n\n' "$(toml_escape "$relayer_l2_key")"
    printf '[finalize]\n'
    printf 'l1_rpc_url = "%s"\n' "$(toml_escape "http://127.0.0.1:${LOCAL_STAGING_L1_RPC_PORT}")"
    printf 'deployments_network = "localhost"\n'
    printf 'private_key = "%s"\n' "$(toml_escape "${LOCAL_STAGING_RELAYER_L1_PRIVATE_KEY:-ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}")"
    printf 'bridge_address = "%s"\n' "$(toml_escape "$bridge_address")"
    printf 'state_manager = "%s"\n' "$(toml_escape "$state_manager_address")"
  } > "$tmp_config"

  if [ -f "$relayer_config" ] && ! cmp -s "$relayer_config" "$tmp_config"; then
    mkdir -p "$(dirname "$restart_marker")"
    printf '1\n' > "$restart_marker"
  fi

  mv "$tmp_config" "$relayer_config"
  chmod 0600 "$relayer_config"
  echo "[local-cf-tunnel] wrote bridge relayer config: $relayer_config"
}

write_bridge_relayer_rpc_config() {
  local output="$1"
  local restart_marker="$2"
  local tmp_output="${output}.tmp.$$"

  mkdir -p "$(dirname "$output")" "$(dirname "$restart_marker")"
  jq \
    --arg coordinator "http://127.0.0.1:${LOCAL_STAGING_COORDINATOR_EDGE_PORT}" \
    --arg realm0 "http://127.0.0.1:$(local_cf_realm_port 0)" \
    --arg realm1 "http://127.0.0.1:$(local_cf_realm_port 1)" \
    --arg prove "http://${LOCAL_STAGING_PROVE_PROXY_ADDR}" \
    --arg faucet "http://${LOCAL_STAGING_FAUCET_ADDR}" \
    --arg services "http://${LOCAL_STAGING_PSY_SERVICES_ADDR}" \
    --arg indexer "http://127.0.0.1:${LOCAL_STAGING_INDEXER_PORT}/v1/graphql" \
    --arg l1rpc "http://127.0.0.1:${LOCAL_STAGING_L1_RPC_PORT}" \
    --argjson l1chain "${LOCAL_STAGING_L1_CHAIN_ID:-31338}" \
    '
      .networks.localhost.coordinator_configs = [{id: 0, rpc_url: [$coordinator]}]
      | .networks.localhost.realm_configs = [
          {id: 0, rpc_url: [$realm0]},
          {id: 1, rpc_url: [$realm1]}
        ]
      | .networks.localhost.prove_proxy_url = [$prove]
      | .networks.localhost.faucet_rpc_url = [$faucet]
      | .networks.localhost.api_services_url = [$services]
      | .networks.localhost.indexer_graphql_url = [$indexer]
      | .networks.localhost.l1_rpc_urls = [$l1rpc]
      | .networks.localhost.l1_chain_id = $l1chain
    ' "$PARTH_DIR/client_prover/config.json" > "$tmp_output"

  if [ -f "$output" ] && ! cmp -s "$output" "$tmp_output"; then
    printf '1\n' > "$restart_marker"
  fi

  mv "$tmp_output" "$output"
  echo "[local-cf-tunnel] wrote bridge relayer RPC config: $output"
}

start_bridge_relayer_if_needed() {
  [ "${LOCAL_CF_START_RELAYER:-1}" = "1" ] || return 0

  local relayer_bin="$PARTH_DIR/target/release/psy_relayer_cli"
  local relayer_config="${LOCAL_STAGING_RELAYER_CONFIG:-$PARTH_DIR/.local-staging/bridge-relayer.toml}"
  local pid_file="$PARTH_DIR/.local-staging/pids/bridge-relayer.pid"
  local restart_marker="$PARTH_DIR/.local-staging/pids/bridge-relayer.restart"
  local binary_stamp="$PARTH_DIR/.local-staging/pids/bridge-relayer.binary.sha256"
  local log_file="$PARTH_DIR/.local-staging/logs/bridge-relayer.log"
  local pid relayer_sha256

  if [ ! -x "$relayer_bin" ]; then
    echo "[local-cf-tunnel] missing executable: $relayer_bin" >&2
    echo "[local-cf-tunnel] build it with: cargo build --release --bin psy_relayer_cli" >&2
    exit 1
  fi

  relayer_sha256="$(sha256sum "$relayer_bin" | awk '{print $1}')"
  if [ ! -f "$binary_stamp" ] || [ "$(cat "$binary_stamp")" != "$relayer_sha256" ]; then
    mkdir -p "$(dirname "$restart_marker")"
    printf '1\n' > "$restart_marker"
  fi

  if [ -f "$pid_file" ]; then
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
      if [ -f "$restart_marker" ]; then
        stop_bridge_relayer_if_running "bridge relayer config changed"
        rm -f "$restart_marker"
      else
        echo "[local-cf-tunnel] bridge relayer already running pid=$pid"
        return 0
      fi
    fi
  fi

  mkdir -p "$PARTH_DIR/.local-staging/logs" "$PARTH_DIR/.local-staging/pids"
  echo "[local-cf-tunnel] starting bridge relayer -> $log_file"
  if command -v setsid >/dev/null 2>&1; then
    env PARTH_HOME="$PARTH_DIR" \
      BRIDGE_RELAYER_LOG_FILE="$PARTH_DIR/.local-staging/logs/bridge-relayer-inner.log" \
      PSY_DEPLOYMENTS_DIR="${LOCAL_STAGING_CONTRACTS_DIR:-$PARTH_DIR/psy-contracts}/deployments" \
      RUST_LOG="${LOCAL_STAGING_RELAYER_RUST_LOG:-info}" \
      RELAYER_CONFIG="$relayer_config" \
      setsid bash "$PARTH_DIR/deploy/bin/run-parth-service" relayer \
      > "$log_file" 2>&1 &
  else
    env PARTH_HOME="$PARTH_DIR" \
      BRIDGE_RELAYER_LOG_FILE="$PARTH_DIR/.local-staging/logs/bridge-relayer-inner.log" \
      PSY_DEPLOYMENTS_DIR="${LOCAL_STAGING_CONTRACTS_DIR:-$PARTH_DIR/psy-contracts}/deployments" \
      RUST_LOG="${LOCAL_STAGING_RELAYER_RUST_LOG:-info}" \
      RELAYER_CONFIG="$relayer_config" \
      nohup bash "$PARTH_DIR/deploy/bin/run-parth-service" relayer \
      > "$log_file" 2>&1 &
  fi
  echo "$!" > "$pid_file"

  local i
  for i in $(seq 1 60); do
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [ -z "$pid" ] || ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "[local-cf-tunnel] bridge relayer exited during startup" >&2
      tail -120 "$log_file" >&2 || true
      exit 1
    fi
    if grep -Eq "bridge relayer started|bridge relayer checkpoint window|bridge deposit cursor sync" "$log_file" 2>/dev/null; then
      printf '%s\n' "$relayer_sha256" > "$binary_stamp"
      echo "[local-cf-tunnel] ready: bridge relayer"
      return 0
    fi
    sleep 1
  done

  echo "[local-cf-tunnel] timed out waiting for bridge relayer startup" >&2
  tail -120 "$log_file" >&2 || true
  exit 1
}

start_cf_tunnel_if_needed() {
  [ "${LOCAL_CF_START_TUNNEL:-1}" = "1" ] || return 0

  local_cf_ensure_cloudflared
  local_cf_render_cloudflared_config

  local pid_file="$PARTH_DIR/.local-staging/pids/cloudflared.pid"
  local log_file="$PARTH_DIR/.local-staging/logs/cloudflared.log"
  local config_stamp="$PARTH_DIR/.local-staging/cloudflared-config.sha256"
  local config_hash
  local pid

  config_hash="$(sha256sum "$LOCAL_CF_CONFIG_FILE" | awk '{print $1}')"

  mkdir -p "$PARTH_DIR/.local-staging/logs" "$PARTH_DIR/.local-staging/pids"
  if [ -f "$pid_file" ]; then
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
      if [ ! -f "$config_stamp" ] || [ "$(cat "$config_stamp")" != "$config_hash" ]; then
        echo "[local-cf-tunnel] restarting cloudflared because ingress config changed"
        kill -- "-$pid" >/dev/null 2>&1 || kill "$pid" >/dev/null 2>&1 || true
        for _ in $(seq 1 20); do
          kill -0 "$pid" >/dev/null 2>&1 || break
          sleep 1
        done
        rm -f "$pid_file"
      else
        echo "[local-cf-tunnel] cloudflared already running pid=$pid"
      fi
    else
      rm -f "$pid_file"
    fi
  fi

  if [ ! -f "$pid_file" ]; then
    echo "[local-cf-tunnel] starting cloudflared tunnel -> $log_file"
    if command -v setsid >/dev/null 2>&1; then
      setsid bash "$SCRIPT_DIR/run-tunnel.sh" > "$log_file" 2>&1 &
    else
      nohup bash "$SCRIPT_DIR/run-tunnel.sh" > "$log_file" 2>&1 &
    fi
    echo "$!" > "$pid_file"
  fi

  local i
  for i in $(seq 1 60); do
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [ -z "$pid" ] || ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "[local-cf-tunnel] cloudflared exited during startup" >&2
      tail -120 "$log_file" >&2 || true
      exit 1
    fi
    if curl -fsS --max-time 10 \
      -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_latest_checkpoint_id","params":[]}' \
      "$(local_cf_url "$LOCAL_CF_COORDINATOR_HOST")" | jq -e '.error == null and has("result")' >/dev/null; then
      printf '%s\n' "$config_hash" > "$config_stamp"
      echo "[local-cf-tunnel] ready: cloudflared tunnel"
      return 0
    fi
    sleep 2
  done

  echo "[local-cf-tunnel] timed out waiting for cloudflared public coordinator endpoint" >&2
  tail -120 "$log_file" >&2 || true
  exit 1
}

reset_local_staging_if_requested() {
  [ "${LOCAL_STAGING_RESET:-0}" = "1" ] || return 0

  echo "[local-cf-tunnel] resetting local staging runtime"
  LOCAL_STAGING_RESET=0 bash "$PARTH_DIR/deploy/local-testnet/stack/down.sh" --volumes || true
  export LOCAL_STAGING_RESET=0
}

reset_local_staging_if_requested
build_relayer_if_requested
start_anvil_if_needed
ensure_local_l1_contracts

echo "[local-cf-tunnel] starting local staging"
export LOCAL_STAGING_INDEXER_PORT
LOCAL_STAGING_RESET=0 LOCAL_STAGING_PUBLISH_FRONTENDS=0 bash "$PARTH_DIR/deploy/local-testnet/stack/up.sh"

start_eth_faucet_if_needed
write_envio_config
start_envio_if_needed
write_bridge_relayer_config
start_bridge_relayer_if_needed

start_cf_tunnel_if_needed

if [ "${LOCAL_CF_PUBLISH_FRONTENDS:-1}" = "1" ]; then
  echo "[local-cf-tunnel] building an atomic frontend release with tunnel URLs"
  frontend_release_dir_file="$(mktemp)"
  if ! LOCAL_CF_FRONTEND_RELEASE_DIR_FILE="$frontend_release_dir_file" \
    bash "$SCRIPT_DIR/build-frontends-release.sh"; then
    rm -f "$frontend_release_dir_file"
    exit 1
  fi
  frontend_release_dir="$(cat "$frontend_release_dir_file")"
  rm -f "$frontend_release_dir_file"
  bash "$SCRIPT_DIR/publish-frontends-release.sh" "$frontend_release_dir"
else
  echo "[local-cf-tunnel] skipping frontend publish (LOCAL_CF_PUBLISH_FRONTENDS=0)"
fi

bash "$SCRIPT_DIR/wait-relayer-ready.sh"
snapshot_deployed_backend_abis

echo
echo "[local-cf-tunnel] local staging is ready for tunnel exposure"
echo "tunnel log:"
echo "  tail -f $PARTH_DIR/.local-staging/logs/cloudflared.log"
echo
local_cf_print_urls
