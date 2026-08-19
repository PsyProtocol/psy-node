#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARTH_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

local_staging_source_env_defaults "$SCRIPT_DIR/local.env"

: "${LOCAL_STAGING_STATE_DIR:=$PARTH_DIR/.local-staging}"
: "${LOCAL_STAGING_REALMS:=0 1}"
: "${LOCAL_STAGING_BUILD:=0}"
: "${LOCAL_STAGING_RESET:=0}"
: "${LOCAL_STAGING_FAUCET_SPLIT_ONLY:=0}"
: "${LOCAL_STAGING_START_INDEXERS:=1}"
: "${LOCAL_STAGING_START_PROVE_PROXY:=1}"
: "${LOCAL_STAGING_START_FAUCET_SERVER:=1}"
: "${LOCAL_STAGING_START_PSY_SERVICES:=1}"
: "${LOCAL_STAGING_START_WORKERS:=1}"
: "${LOCAL_STAGING_START_NGINX:=1}"
: "${LOCAL_STAGING_PUBLISH_FRONTENDS:=1}"
: "${LOCAL_STAGING_BUILD_FRONTENDS:=1}"
: "${LOCAL_STAGING_ENABLE_PSY_FAUCET:=1}"
: "${LOCAL_STAGING_PSY_FAUCET_REQUIRE_TURNSTILE:=0}"
: "${LOCAL_STAGING_PSY_FAUCET_OPERATOR_KEY_INDICES:=4 5 6 7 8 9 10 11 12 13}"
: "${LOCAL_STAGING_SCHEMA_SETTLE_SECS:=2}"
: "${LOCAL_STAGING_COORDINATOR_WORKER_KEY_INDEX:=0}"
: "${LOCAL_STAGING_REALM0_WORKER_KEY_INDEX:=2}"
: "${LOCAL_STAGING_REALM1_WORKER_KEY_INDEX:=3}"
: "${LOCAL_STAGING_COORDINATOR_EDGE_PORT:=1337}"
: "${LOCAL_STAGING_REALM_EDGE_BASE_PORT:=13380}"
: "${LOCAL_STAGING_REALM_EDGE_PORT_STRIDE:=10}"
: "${LOCAL_STAGING_PROVE_PROXY_ADDR:=127.0.0.1:9999}"
: "${LOCAL_STAGING_FAUCET_ADDR:=127.0.0.1:9998}"
: "${LOCAL_STAGING_PSY_SERVICES_ADDR:=127.0.0.1:3000}"
: "${LOCAL_STAGING_APP_PORT:=8088}"
: "${LOCAL_STAGING_EXPLORER_PORT:=8089}"
: "${LOCAL_STAGING_IDE_PORT:=8090}"
: "${LOCAL_STAGING_L1_RPC_PORT:=8545}"
: "${LOCAL_STAGING_INDEXER_PORT:=8080}"
: "${LOCAL_STAGING_NETWORK:=local-devnet}"
: "${LOCAL_STAGING_PROVING_BACKEND:=plonky2-poseidon-goldilocks}"
: "${LOCAL_STAGING_RUST_LOG:=info}"
: "${LOCAL_REDIS_PORT:=6379}"
: "${LOCAL_NATS_PORT:=4222}"
: "${LOCAL_SCYLLA_PORT:=9042}"
: "${LOCAL_NOSTR_PORT:=8081}"
: "${LOCAL_POSTGRES_PORT:=15432}"
: "${LOCAL_POSTGRES_USER:=postgres}"
: "${LOCAL_POSTGRES_PASSWORD:=postgres}"
: "${LOCAL_POSTGRES_DB:=psy_services}"
: "${PSY_SERVICES_HOME:=$PARTH_DIR/../psy-services}"
: "${PSY_COMPILER_HOME:=$PARTH_DIR/../psy-compiler}"
: "${LOCAL_STAGING_BOOTSTRAP_GENESIS:=1}"
: "${LOCAL_STAGING_GENESIS_CONTRACTS_SEED:=}"
: "${LOCAL_STAGING_GENESIS_CONTRACTS_SEED_URL:=}"
: "${LOCAL_STAGING_GENESIS_USE_LLD:=1}"
: "${LOCAL_STAGING_GENESIS_OPT_LEVEL:=1}"
: "${LOCAL_STAGING_GENESIS_CODEGEN_UNITS:=256}"
: "${LOCAL_STAGING_CONTRACTS_DIR:=$PARTH_DIR/psy-contracts}"

LOG_DIR="$LOCAL_STAGING_STATE_DIR/logs"
PID_DIR="$LOCAL_STAGING_STATE_DIR/pids"
CHECKPOINT_DIR="$LOCAL_STAGING_STATE_DIR/checkpoints"
INDEXER_BACKUP_DIR="$LOCAL_STAGING_STATE_DIR/indexer-backups"
NGINX_ROOT="${LOCAL_STAGING_NGINX_ROOT:-$LOCAL_STAGING_STATE_DIR/nginx/html}"
GENESIS_PATH="${LOCAL_STAGING_GENESIS_PATH:-$PARTH_DIR/genesis.json}"
PRIVATE_KEYS_PATH="${LOCAL_STAGING_PRIVATE_KEYS_PATH:-$PARTH_DIR/private_keys.json}"
RPC_CONFIG="${LOCAL_STAGING_RPC_CONFIG:-$PARTH_DIR/client_prover/config.json}"
USER_CLI="$PARTH_DIR/target/release/psy_user_cli"
PSY_FAUCET_OPERATORS_JSON_PATH="${LOCAL_STAGING_PSY_FAUCET_OPERATORS_JSON_PATH:-}"
PSY_FAUCET_TEMPLATE_JSON_PATH="${LOCAL_STAGING_PSY_FAUCET_TEMPLATE_JSON_PATH:-$PARTH_DIR/client_prover/psy-privacy-bridge/src/config/faucetOperators.json}"
PSY_FAUCET_GENERATED_OPERATORS_JSON_PATH="${LOCAL_STAGING_PSY_FAUCET_GENERATED_OPERATORS_JSON_PATH:-$LOCAL_STAGING_STATE_DIR/faucetOperators.json}"
DATABASE_URL="${LOCAL_STAGING_DATABASE_URL:-postgres://$LOCAL_POSTGRES_USER:$LOCAL_POSTGRES_PASSWORD@127.0.0.1:$LOCAL_POSTGRES_PORT/$LOCAL_POSTGRES_DB}"
PSY_JWT_SECRET="${LOCAL_STAGING_PSY_JWT_SECRET:-local-staging-secret}"
L1_RPC_URL="${LOCAL_STAGING_L1_RPC_URL:-http://127.0.0.1:$LOCAL_STAGING_L1_RPC_PORT}"
L1_DEPLOYMENTS_JSON="${LOCAL_STAGING_L1_DEPLOYMENTS_JSON:-$LOCAL_STAGING_CONTRACTS_DIR/deployments/localhost/deployed-contracts.json}"

require_file() {
  local path="$1"
  [ -f "$path" ] || {
    echo "[local-staging] missing file: $path" >&2
    exit 1
  }
}

require_exec() {
  local path="$1"
  [ -x "$path" ] || {
    echo "[local-staging] missing executable: $path" >&2
    exit 1
  }
}

json_or_zstdcat() {
  local path="$1"
  if jq -e . "$path" >/dev/null 2>&1; then
    cat "$path"
  else
    command -v zstdcat >/dev/null 2>&1 || {
      echo "[local-staging] zstdcat is required to read compressed JSON: $path" >&2
      exit 1
    }
    zstdcat "$path"
  fi
}

is_usable_genesis_contracts() {
  local path="$1"
  [ -s "$path" ] || return 1
  LC_ALL=C head -c 256 "$path" | grep -q '^[[:space:]]*\['
}

generate_local_genesis_data() {
  local cargo_args=(
    --config "profile.release.package.psy_plonky2_circuits.opt-level=$LOCAL_STAGING_GENESIS_OPT_LEVEL"
    --config "profile.release.package.psy_plonky2_circuits.codegen-units=$LOCAL_STAGING_GENESIS_CODEGEN_UNITS"
    test --manifest-path "$PARTH_DIR/Cargo.toml" --release
    --package psy_plonky2_circuits --lib --
    node::config::networks::local_devnet::tests --nocapture
  )

  if [ "$LOCAL_STAGING_GENESIS_USE_LLD" = "1" ]; then
    local rust_host
    local rust_sysroot
    local lld_path
    local linker_env
    local rustflags="${RUSTFLAGS:-}"

    command -v clang >/dev/null 2>&1 || {
      echo "[local-staging] clang is required when LOCAL_STAGING_GENESIS_USE_LLD=1" >&2
      exit 1
    }
    rust_host="$(rustc -vV | sed -n 's/^host: //p')"
    rust_sysroot="$(rustc --print sysroot)"
    lld_path="$rust_sysroot/lib/rustlib/$rust_host/bin/gcc-ld/ld.lld"
    [ -x "$lld_path" ] || {
      echo "[local-staging] Rust toolchain LLD linker is missing: $lld_path" >&2
      exit 1
    }
    linker_env="CARGO_TARGET_$(printf '%s' "$rust_host" | tr '[:lower:]-' '[:upper:]_')_LINKER"
    rustflags="${rustflags:+$rustflags }-C link-arg=-fuse-ld=$lld_path"
    echo "[local-staging] linking genesis generator with LLD to limit peak memory"
    env "$linker_env=clang" RUSTFLAGS="$rustflags" cargo "${cargo_args[@]}"
  else
    cargo "${cargo_args[@]}"
  fi
}

ensure_genesis_artifacts() {
  local genesis_contracts="$PARTH_DIR/genesis_contracts.json"
  local bootstrap_tmp="$genesis_contracts.bootstrap.tmp"
  local regenerated_contracts=0

  if [ "$LOCAL_STAGING_BOOTSTRAP_GENESIS" != "1" ]; then
    return 0
  fi

  if ! is_usable_genesis_contracts "$genesis_contracts"; then
    [ -f "$PSY_COMPILER_HOME/Makefile" ] || {
      echo "[local-staging] psy-compiler is required to generate genesis_contracts.json: $PSY_COMPILER_HOME" >&2
      exit 1
    }

    # psy-compiler currently builds Parth's psy_config before replacing the
    # artifact, and that build embeds genesis_contracts.json. A previous valid
    # artifact is therefore required only as a compilation seed on clean clones.
    if [ -n "$LOCAL_STAGING_GENESIS_CONTRACTS_SEED" ]; then
      require_file "$LOCAL_STAGING_GENESIS_CONTRACTS_SEED"
      if [ "$(realpath "$LOCAL_STAGING_GENESIS_CONTRACTS_SEED")" = "$(realpath -m "$genesis_contracts")" ]; then
        echo "[local-staging] genesis contracts seed must differ from the generated artifact path" >&2
        exit 1
      fi
      echo "[local-staging] seeding genesis_contracts.json from $LOCAL_STAGING_GENESIS_CONTRACTS_SEED"
      cp "$LOCAL_STAGING_GENESIS_CONTRACTS_SEED" "$bootstrap_tmp"
    elif [ -n "$LOCAL_STAGING_GENESIS_CONTRACTS_SEED_URL" ]; then
      command -v curl >/dev/null 2>&1 || {
        echo "[local-staging] curl is required to download the genesis contracts seed" >&2
        exit 1
      }
      echo "[local-staging] downloading genesis_contracts.json compilation seed"
      curl --fail --location --retry 3 --output "$bootstrap_tmp" \
        "$LOCAL_STAGING_GENESIS_CONTRACTS_SEED_URL"
    else
      echo "[local-staging] genesis_contracts.json is absent from this clean checkout" >&2
      echo "[local-staging] configure LOCAL_STAGING_GENESIS_CONTRACTS_SEED or LOCAL_STAGING_GENESIS_CONTRACTS_SEED_URL" >&2
      echo "[local-staging] the seed is used only to compile psy-compiler and is replaced before deployment" >&2
      exit 1
    fi

    mv "$bootstrap_tmp" "$genesis_contracts"
    is_usable_genesis_contracts "$genesis_contracts" || {
      echo "[local-staging] genesis contracts compilation seed is not usable JSON" >&2
      exit 1
    }

    echo "[local-staging] generating genesis_contracts.json with psy-compiler"
    (
      cd "$PSY_COMPILER_HOME"
      make gen-deploy-json PARTH_GENERIC_V1="$PARTH_DIR"
    )
    is_usable_genesis_contracts "$genesis_contracts" || {
      echo "[local-staging] psy-compiler did not produce a usable genesis_contracts.json" >&2
      exit 1
    }
    regenerated_contracts=1
  fi

  if [ ! -s "$GENESIS_PATH" ] || [ ! -s "$PRIVATE_KEYS_PATH" ] || [ "$regenerated_contracts" = "1" ]; then
    echo "[local-staging] generating genesis.json and private_keys.json"
    generate_local_genesis_data
  fi
}

verify_claim_deposit_artifacts() {
  local genesis_contracts="$PARTH_DIR/genesis_contracts.json"
  local genesis="$PARTH_DIR/genesis.json"
  local token_abi="$PARTH_DIR/genesis_abi/PsyTokenContract.json"
  local deposit_tree_abi="$PARTH_DIR/genesis_abi/PsyDepositTreeContract.json"
  local method_id
  local input_count
  local set_chain_root_method_id
  local set_chain_root_input_count
  local append_deposit_method_id
  local append_deposit_input_count

  require_file "$genesis_contracts"
  require_file "$genesis"
  require_file "$token_abi"
  require_file "$deposit_tree_abi"

  command -v jq >/dev/null 2>&1 || {
    echo "[local-staging] jq is required to verify claim_deposit artifacts" >&2
    exit 1
  }

  method_id="$(jq -er '.contract.methods[] | select(.name == "claim_deposit") | .method_id' "$token_abi")"
  input_count="$(jq -er '.contract.methods[] | select(.name == "claim_deposit") | .input_felt_count' "$token_abi")"
  set_chain_root_method_id="$(jq -er '.contract.methods[] | select(.name == "set_chain_root") | .method_id' "$deposit_tree_abi")"
  set_chain_root_input_count="$(jq -er '.contract.methods[] | select(.name == "set_chain_root") | .input_felt_count' "$deposit_tree_abi")"
  append_deposit_method_id="$(jq -er '.contract.methods[] | select(.name == "append_deposit") | .method_id' "$deposit_tree_abi")"
  append_deposit_input_count="$(jq -er '.contract.methods[] | select(.name == "append_deposit") | .input_felt_count' "$deposit_tree_abi")"

  if ! json_or_zstdcat "$genesis_contracts" | jq -e \
    --argjson method_id "$method_id" \
    --argjson input_count "$input_count" \
    '[.[0], .[4]]
      | all(.code_definition.functions
        | any(.method_id == $method_id and .num_inputs == $input_count))' >/dev/null; then
    echo "[local-staging] claim_deposit artifact mismatch:" >&2
    echo "[local-staging]   genesis_abi expects method_id=$method_id inputs=$input_count" >&2
    json_or_zstdcat "$genesis_contracts" | jq -c '
      [to_entries[]
        | select(.key == 0 or .key == 4)
        | {
            contract_index: .key,
            claim_candidates: [
              .value.code_definition.functions[]
              | select(.method_id == 1626878261 or .method_id == 3052420124 or .num_inputs == 100 or .num_inputs == 307)
              | {method_id, num_inputs}
            ]
          }]' >&2 || true
    exit 1
  fi

  if ! json_or_zstdcat "$genesis_contracts" | jq -e \
    --argjson set_method_id "$set_chain_root_method_id" \
    --argjson set_input_count "$set_chain_root_input_count" \
    --argjson append_method_id "$append_deposit_method_id" \
    --argjson append_input_count "$append_deposit_input_count" \
    '.[2].code_definition.functions
      | any(.method_id == $set_method_id and .num_inputs == $set_input_count)
        or any(.method_id == $append_method_id and .num_inputs == $append_input_count)' >/dev/null; then
    echo "[local-staging] deposit tree sync artifact mismatch:" >&2
    echo "[local-staging]   genesis_abi expects set_chain_root method_id=$set_chain_root_method_id inputs=$set_chain_root_input_count" >&2
    echo "[local-staging]   or append_deposit method_id=$append_deposit_method_id inputs=$append_deposit_input_count" >&2
    json_or_zstdcat "$genesis_contracts" | jq -c '
      .[2].code_definition.functions[]
      | select(.method_id == 1226302432 or .method_id == 1676735501 or .num_inputs == 10 or .num_inputs == 9)
      | {method_id, num_inputs}' >&2 || true
    exit 1
  fi

  if ! jq -e \
    --argjson method_id "$method_id" \
    --argjson input_count "$input_count" \
    '[.contracts[0], .contracts[4]]
      | all(.code_definition.functions
        | any(.method_id == $method_id and .num_inputs == $input_count))' "$genesis" >/dev/null; then
    echo "[local-staging] claim_deposit genesis.json mismatch:" >&2
    echo "[local-staging]   genesis_abi expects method_id=$method_id inputs=$input_count" >&2
    jq -c '
      [.contracts
        | to_entries[]
        | select(.key == 0 or .key == 4)
        | {
            contract_index: .key,
            claim_candidates: [
              .value.code_definition.functions[]
              | select(.method_id == 1626878261 or .method_id == 3052420124 or .num_inputs == 100 or .num_inputs == 307)
              | {method_id, num_inputs}
            ]
          }]' "$genesis" >&2 || true
    exit 1
  fi

  if ! jq -e \
    --argjson set_method_id "$set_chain_root_method_id" \
    --argjson set_input_count "$set_chain_root_input_count" \
    --argjson append_method_id "$append_deposit_method_id" \
    --argjson append_input_count "$append_deposit_input_count" \
    '.contracts[2].code_definition.functions
      | any(.method_id == $set_method_id and .num_inputs == $set_input_count)
        or any(.method_id == $append_method_id and .num_inputs == $append_input_count)' "$genesis" >/dev/null; then
    echo "[local-staging] deposit tree sync genesis.json mismatch:" >&2
    echo "[local-staging]   genesis_abi expects set_chain_root method_id=$set_chain_root_method_id inputs=$set_chain_root_input_count" >&2
    echo "[local-staging]   or append_deposit method_id=$append_deposit_method_id inputs=$append_deposit_input_count" >&2
    jq -c '
      .contracts[2].code_definition.functions[]
      | select(.method_id == 1226302432 or .method_id == 1676735501 or .num_inputs == 10 or .num_inputs == 9)
      | {method_id, num_inputs}' "$genesis" >&2 || true
    exit 1
  fi
}

verify_genesis_runtime_abis() {
  local genesis_contracts="$PARTH_DIR/genesis_contracts.json"
  local genesis="$PARTH_DIR/genesis.json"
  local psy_token_abi="$PARTH_DIR/genesis_abi/PsyTokenContract.json"
  local withdrawal_tree_abi="$PARTH_DIR/genesis_abi/PsyWithdrawalTreeContract.json"
  local usdt_abi="$PARTH_DIR/genesis_abi/USDTTokenContract.json"
  local faucet_abi="$PARTH_DIR/genesis_abi/PsyFaucetContract.json"
  local artifact
  local mismatches

  require_file "$genesis_contracts"
  require_file "$genesis"
  require_file "$psy_token_abi"
  require_file "$withdrawal_tree_abi"
  require_file "$usdt_abi"
  require_file "$faucet_abi"

  for artifact in "$genesis_contracts" "$genesis"; do
    mismatches="$({ json_or_zstdcat "$artifact"; } | jq -c \
      --slurpfile psy_token "$psy_token_abi" \
      --slurpfile withdrawal_tree "$withdrawal_tree_abi" \
      --slurpfile usdt "$usdt_abi" \
      --slurpfile faucet "$faucet_abi" '
        def missing_methods($contract; $abi; $names):
          [$abi[0].contract.methods[] as $method
            | select($names | index($method.name))
            | select(
                (($contract.code_definition.functions // [])
                  | any(.method_id == $method.method_id
                    and .num_inputs == $method.input_felt_count))
                | not
              )
            | {
                name: $method.name,
                method_id: $method.method_id,
                input_felt_count: $method.input_felt_count
              }];
        (if type == "array" then . else .contracts end) as $contracts
        | ["withdraw", "simple_transfer", "simple_claim", "claim_deposit", "private_claim"] as $token_methods
        | ["append_withdrawal", "batch_append_withdrawals_2", "batch_append_withdrawals_5"] as $withdrawal_methods
        | [
            {contract_id: 0, abi: $psy_token[0].contract.name, missing: missing_methods($contracts[0]; $psy_token; $token_methods)},
            {contract_id: 3, abi: $withdrawal_tree[0].contract.name, missing: missing_methods($contracts[3]; $withdrawal_tree; $withdrawal_methods)},
            {contract_id: 4, abi: $usdt[0].contract.name, missing: missing_methods($contracts[4]; $usdt; $token_methods)},
            {contract_id: 5, abi: $faucet[0].contract.name, missing: missing_methods($contracts[5]; $faucet; ["faucet"])}
          ]
        | map(select(.missing | length > 0))
      ')"

    if [ "$mismatches" != "[]" ]; then
      echo "[local-staging] runtime ABI mismatch in $artifact:" >&2
      echo "$mismatches" | jq . >&2
      echo "[local-staging] regenerate genesis artifacts before starting the local testnet" >&2
      exit 1
    fi
  done

  echo "[local-staging] verified runtime ABI methods in genesis artifacts"
}

pid_is_running() {
  local pid_file="$1"
  [ -f "$pid_file" ] || return 1
  local pid
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  [ -n "$pid" ] || return 1
  kill -0 "$pid" >/dev/null 2>&1
}

wait_process_log_pattern() {
  local label="$1"
  local pattern="$2"
  local description="${3:-$label startup}"
  local attempts="${4:-180}"
  local delay="${5:-1}"
  local pid_file="$PID_DIR/$label.pid"
  local log_file="$LOG_DIR/$label.log"

  for _ in $(seq 1 "$attempts"); do
    if [ -f "$log_file" ] && grep -Eq "$pattern" "$log_file"; then
      echo "[local-staging] ready: $description"
      return 0
    fi
    if ! pid_is_running "$pid_file"; then
      echo "[local-staging] $label exited while waiting for $description" >&2
      tail -100 "$log_file" >&2 || true
      exit 1
    fi
    sleep "$delay"
  done

  echo "[local-staging] timed out waiting for $description" >&2
  tail -100 "$log_file" >&2 || true
  exit 1
}

wait_process_tcp() {
  local label="$1"
  local host="$2"
  local port="$3"
  local description="${4:-$label}"
  local attempts="${5:-90}"
  local delay="${6:-2}"
  local pid_file="$PID_DIR/$label.pid"
  local log_file="$LOG_DIR/$label.log"

  for _ in $(seq 1 "$attempts"); do
    if timeout 2 bash -lc "</dev/tcp/$host/$port" >/dev/null 2>&1; then
      echo "[local-staging] ready: $description"
      return 0
    fi
    if ! pid_is_running "$pid_file"; then
      echo "[local-staging] $label exited while waiting for $description" >&2
      tail -100 "$log_file" >&2 || true
      exit 1
    fi
    sleep "$delay"
  done

  echo "[local-staging] timed out waiting for $description" >&2
  tail -100 "$log_file" >&2 || true
  exit 1
}

settle_local_schema() {
  if [ "${LOCAL_STAGING_SCHEMA_SETTLE_SECS:-0}" -gt 0 ]; then
    echo "[local-staging] waiting ${LOCAL_STAGING_SCHEMA_SETTLE_SECS}s for local Scylla schema agreement"
    sleep "$LOCAL_STAGING_SCHEMA_SETTLE_SECS"
  fi
}

start_process() {
  local label="$1"
  local service="$2"
  shift 2

  START_PROCESS_WAS_STARTED=0

  local pid_file="$PID_DIR/$label.pid"
  local log_file="$LOG_DIR/$label.log"
  local env_args=(
    "PARTH_HOME=$PARTH_DIR"
    # The rollback verification journal (design-r1 §2.2.2) records every recorded
    # key before and after each commit.  It is the only evidence that a rollback
    # restored history rather than recomputing something merely self-consistent,
    # so a testnet whose purpose is verifying rollbacks runs with it on.  Passed
    # through only when exported, so an ordinary deployment is unaffected.
    ${PSY_ROLLBACK_VERIFICATION_JOURNAL:+"PSY_ROLLBACK_VERIFICATION_JOURNAL=$PSY_ROLLBACK_VERIFICATION_JOURNAL"}
    # Where a Realm reads the rollback phase it must obey (design-r1 §6.2: every
    # barrier is an LWT on the Coordinator's control row and participants read
    # it).  A Realm without this still commits normally but cannot take part in
    # a coordinated rollback, so it is named rather than defaulted -- a guessed
    # keyspace could belong to another network on the same cluster.
    "PSY_ROLLBACK_COORDINATOR_NO_TABLET_KEYSPACE=${PSY_ROLLBACK_COORDINATOR_NO_TABLET_KEYSPACE:-coordinator_no_tablet}"
    "PSY_SERVICES_HOME=$PSY_SERVICES_HOME"
    "NETWORK=$LOCAL_STAGING_NETWORK"
    "PROVING_BACKEND=$LOCAL_STAGING_PROVING_BACKEND"
    "SCYLLA_DB_URL=127.0.0.1:$LOCAL_SCYLLA_PORT"
    "NATS_JETSTREAM_URL=nats://127.0.0.1:$LOCAL_NATS_PORT"
    "REDIS_URL=redis://127.0.0.1:$LOCAL_REDIS_PORT"
    "GENESIS_DATA_PATH=$GENESIS_PATH"
    "CHECKPOINT_BACKUP_PATH=$CHECKPOINT_DIR"
    "RUST_LOG=$LOCAL_STAGING_RUST_LOG"
    "VERBOSE=${VERBOSE:-1}"
  )
  local kv

  if pid_is_running "$pid_file"; then
    echo "[local-staging] already running: $label pid=$(cat "$pid_file")"
    return 0
  fi

  echo "[local-staging] starting $label -> $log_file"
  START_PROCESS_WAS_STARTED=1
  for kv in "$@"; do
    env_args+=("$kv")
  done

  # Exit 75 (EX_TEMPFAIL) is a processor asking to be restarted after a
  # rollback: it has done its part and needs its in-memory state rebuilt by the
  # startup path.  A production deployment gets this from systemd or k8s; this
  # stack runs under nohup, so the loop is here.  Only that one code restarts --
  # a real crash still stops, because a stack that silently restarts through a
  # crash loop hides the thing you most need to see.
  local runner='
    while true; do
      bash "$1" "$2"
      code=$?
      if [ "$code" -ne 75 ]; then exit "$code"; fi
      echo "[local-staging] $2 asked to reload after a rollback; restarting"
    done
  '

  if command -v setsid >/dev/null 2>&1; then
    env "${env_args[@]}" setsid bash -c "$runner" _ "$PARTH_DIR/deploy/bin/run-parth-service" "$service" >"$log_file" 2>&1 &
  else
    env "${env_args[@]}" nohup bash -c "$runner" _ "$PARTH_DIR/deploy/bin/run-parth-service" "$service" >"$log_file" 2>&1 &
  fi

  echo "$!" > "$pid_file"
  sleep 1
  if ! pid_is_running "$pid_file"; then
    echo "[local-staging] $label exited during startup" >&2
    tail -80 "$log_file" >&2 || true
    exit 1
  fi
}

restart_process_if_env_changed() {
  local label="$1"
  shift

  local pid_file="$PID_DIR/$label.pid"
  local env_file="$PID_DIR/$label.env"
  local tmp_env_file="$env_file.tmp.$$"
  local pid

  printf '%s\n' "$@" > "$tmp_env_file"
  if pid_is_running "$pid_file"; then
    if [ ! -f "$env_file" ] || ! cmp -s "$env_file" "$tmp_env_file"; then
      pid="$(cat "$pid_file" 2>/dev/null || true)"
      echo "[local-staging] restarting $label because environment changed"
      kill "$pid" >/dev/null 2>&1 || true
      for _ in $(seq 1 30); do
        if ! kill -0 "$pid" >/dev/null 2>&1; then
          break
        fi
        sleep 1
      done
      if kill -0 "$pid" >/dev/null 2>&1; then
        kill -9 "$pid" >/dev/null 2>&1 || true
      fi
      rm -f "$pid_file"
    fi
  fi
  mv "$tmp_env_file" "$env_file"
}

wait_started_process_log_pattern() {
  local label="$1"
  local pattern="$2"
  local description="${3:-$label startup}"
  local attempts="${4:-180}"
  local delay="${5:-1}"

  if [ "${START_PROCESS_WAS_STARTED:-0}" = "0" ]; then
    echo "[local-staging] ready: $description (already running)"
    return 0
  fi

  wait_process_log_pattern "$label" "$pattern" "$description" "$attempts" "$delay"
}

realm_port() {
  local realm_id="$1"
  printf '%s\n' "$(( LOCAL_STAGING_REALM_EDGE_BASE_PORT + realm_id * LOCAL_STAGING_REALM_EDGE_PORT_STRIDE ))"
}

realm_url() {
  local realm_id="$1"
  printf 'http://127.0.0.1:%s\n' "$(realm_port "$realm_id")"
}

start_realm() {
  local realm_id="$1"
  local port
  port="$(realm_port "$realm_id")"

  start_process "realm-${realm_id}-processor" "realm-processor" \
    "REALM_ID=$realm_id" \
    "REALM_SUB_ID=1" \
    "DB_NAMESPACE=realm_$realm_id" \
    "COORDINATOR_API_URLS=http://127.0.0.1:$LOCAL_STAGING_COORDINATOR_EDGE_PORT"
  wait_started_process_log_pattern "realm-${realm_id}-processor" \
    "\\[REALM_STARTUP\\] load_realm_memory_trees_from_db done|\\[REALM_STARTUP\\] init_with_setup_and_genesis done|PSY_REALM_PROCESSOR_STARTED" \
    "realm-$realm_id processor memory trees loaded"
  settle_local_schema

  start_process "realm-${realm_id}-edge" "realm-edge" \
    "REALM_ID=$realm_id" \
    "REALM_SUB_ID=1" \
    "DB_NAMESPACE=realm_$realm_id" \
    "REALM_EDGE_PORT=$port" \
    "LISTEN_ADDR=127.0.0.1"
  wait_process_tcp "realm-${realm_id}-edge" 127.0.0.1 "$port" "realm-$realm_id edge"

  if [ "$LOCAL_STAGING_START_WORKERS" = "1" ]; then
    local key_var="LOCAL_STAGING_REALM${realm_id}_WORKER_KEY_INDEX"
    local key_index="${!key_var:-$((realm_id + 2))}"
    local private_key
    local worker_user_id
    private_key="$(local_staging_private_key_at_index "$PRIVATE_KEYS_PATH" "$key_index")"
    worker_user_id="$(local_staging_user_id_for_key_index "$key_index")"

    start_process "realm-${realm_id}-worker" "worker" \
      "WORKER_USER_ID=$worker_user_id" \
      "PRIVATE_KEY=$private_key" \
      "COMPLETED_JOBS_LOG_FILE=$CHECKPOINT_DIR/realm_${realm_id}_worker.backup" \
      "COORDINATOR_API_URLS=" \
      "REALM_API_URLS=http://127.0.0.1:$port" \
      "BATCH_SIZE=${LOCAL_STAGING_REALM_WORKER_BATCH_SIZE:-4}"
  fi

  if [ "$LOCAL_STAGING_START_INDEXERS" = "1" ]; then
    start_process "psy-indexer-realm-${realm_id}" "psy-indexer" \
      "PSY_INDEXER_MODE=realm" \
      "REALM_ID=$realm_id" \
      "REALM_SUB_ID=1" \
      "PSY_EDGE_RPC_URL=http://127.0.0.1:$port" \
      "PSY_SERVICES_URL=http://127.0.0.1:$LOCAL_STAGING_PSY_SERVICES_ADDR_PORT" \
      "PSY_JWT_SECRET=$PSY_JWT_SECRET" \
      "PSY_BACKUP_DIR=$CHECKPOINT_DIR" \
      "PSY_POLL_INTERVAL_MS=${LOCAL_STAGING_INDEXER_POLL_INTERVAL_MS:-2000}" \
      "PSY_NETWORK_TYPE=$LOCAL_STAGING_NETWORK"
  fi
}

generate_local_faucet_operators_json() {
  require_file "$PSY_FAUCET_TEMPLATE_JSON_PATH"
  require_file "$PRIVATE_KEYS_PATH"
  require_exec "$USER_CLI"

  local contract_id
  local method_name
  local method_id
  local amount_nano
  local expected_tx_count
  local allowed_contract_ids
  local allowed_method_ids
  local fingerprint
  local operators_file
  local output_file
  local key_index

  contract_id="$(jq -er '.faucetContractId' "$PSY_FAUCET_TEMPLATE_JSON_PATH")"
  method_name="$(jq -er '.faucetMethodName' "$PSY_FAUCET_TEMPLATE_JSON_PATH")"
  method_id="$(jq -er '.faucetMethodId' "$PSY_FAUCET_TEMPLATE_JSON_PATH")"
  amount_nano="$(jq -er '.faucetPerClaimAmount // .faucetPerClaimAmountNano' "$PSY_FAUCET_TEMPLATE_JSON_PATH")"
  expected_tx_count="$(jq -er '.sdKeyExpectedTxCount // .sdkKeyExpectedTxCount // 2' "$PSY_FAUCET_TEMPLATE_JSON_PATH")"
  allowed_contract_ids="$(jq -c '.sdKeyAllowedContractIds // [.faucetContractId]' "$PSY_FAUCET_TEMPLATE_JSON_PATH")"
  allowed_method_ids="$(jq -c '.sdKeyAllowedMethodIds // [.faucetMethodId]' "$PSY_FAUCET_TEMPLATE_JSON_PATH")"
  fingerprint="$(jq -er '.operators[0].fingerprint' "$PSY_FAUCET_TEMPLATE_JSON_PATH")"

  mkdir -p "$(dirname "$PSY_FAUCET_GENERATED_OPERATORS_JSON_PATH")"
  operators_file="$(mktemp)"
  output_file="${PSY_FAUCET_GENERATED_OPERATORS_JSON_PATH}.tmp.$$"

  for key_index in $LOCAL_STAGING_PSY_FAUCET_OPERATOR_KEY_INDICES; do
    local private_key
    local user_id
    local wallet_info
    local address

    private_key="$(local_staging_private_key_at_index "$PRIVATE_KEYS_PATH" "$key_index")"
    user_id="$(local_staging_user_id_for_key_index "$key_index")"
    local wallet_info_args=(
      wallet info
      --sign-type sd-key
      --fingerprint "$fingerprint"
      --sd-key-allowed-contract-id "$contract_id"
      --sd-key-allowed-method-id "$method_id"
      --private-key "$private_key"
    )
    if [ -n "$expected_tx_count" ]; then
      wallet_info_args+=(--sd-key-expected-tx-count "$expected_tx_count")
    fi
    wallet_info="$(RUST_LOG=error "$USER_CLI" "${wallet_info_args[@]}")"
    address="$(printf '%s\n' "$wallet_info" | awk '/^public_key:/{print $2; exit}')"
    if [ -z "$address" ]; then
      echo "[local-staging] failed to derive faucet operator public key for private_keys.json[$key_index]" >&2
      printf '%s\n' "$wallet_info" >&2
      rm -f "$operators_file" "$output_file"
      exit 1
    fi

    jq -cn \
      --arg userId "$user_id" \
      --arg address "$address" \
      --arg privateKey "$private_key" \
      --arg fingerprint "$fingerprint" \
      '{userId: $userId, address: $address, privateKey: $privateKey, fingerprint: $fingerprint, signType: "sd-key"}' \
      >> "$operators_file"
  done

  jq -n \
    --argjson faucetContractId "$contract_id" \
    --arg faucetMethodName "$method_name" \
    --argjson faucetMethodId "$method_id" \
    --arg faucetPerClaimAmount "$amount_nano" \
    --argjson sdKeyExpectedTxCount "$expected_tx_count" \
    --argjson sdKeyAllowedContractIds "$allowed_contract_ids" \
    --argjson sdKeyAllowedMethodIds "$allowed_method_ids" \
    --slurpfile operators "$operators_file" \
    '{
      faucetContractId: $faucetContractId,
      faucetMethodName: $faucetMethodName,
      faucetMethodId: $faucetMethodId,
      faucetPerClaimAmount: $faucetPerClaimAmount,
      sdKeyExpectedTxCount: $sdKeyExpectedTxCount,
      sdKeyAllowedContractIds: $sdKeyAllowedContractIds,
      sdKeyAllowedMethodIds: $sdKeyAllowedMethodIds,
      operators: $operators
    }' > "$output_file"

  mv "$output_file" "$PSY_FAUCET_GENERATED_OPERATORS_JSON_PATH"
  rm -f "$operators_file"
  echo "[local-staging] generated faucet operators from private_keys.json indices: $LOCAL_STAGING_PSY_FAUCET_OPERATOR_KEY_INDICES" >&2
  printf '%s\n' "$PSY_FAUCET_GENERATED_OPERATORS_JSON_PATH"
}

start_faucet_split_components() {
  local user_cli_sha256
  user_cli_sha256="$(sha256sum "$USER_CLI" | awk '{print $1}')"

  if [ "$LOCAL_STAGING_START_PROVE_PROXY" = "1" ]; then
    local prove_proxy_env=(
      "PSY_USER_CLI_SHA256=$user_cli_sha256"
      "PROVE_PROXY_LISTEN_ADDR=$LOCAL_STAGING_PROVE_PROXY_ADDR"
      "RPC_CONFIG=$RPC_CONFIG"
    )

    restart_process_if_env_changed "prove-proxy" "${prove_proxy_env[@]}"
    start_process "prove-proxy" "prove-proxy" "${prove_proxy_env[@]}"
    wait_process_tcp "prove-proxy" "${LOCAL_STAGING_PROVE_PROXY_ADDR%:*}" "${LOCAL_STAGING_PROVE_PROXY_ADDR##*:}" "prove-proxy" 240 2
  fi

  if [ "$LOCAL_STAGING_ENABLE_PSY_FAUCET" != "1" ] || [ "$LOCAL_STAGING_START_FAUCET_SERVER" != "1" ]; then
    return 0
  fi

  local faucet_operators_json_path="$PSY_FAUCET_OPERATORS_JSON_PATH"
  if [ -z "$faucet_operators_json_path" ]; then
    faucet_operators_json_path="$(generate_local_faucet_operators_json)"
  fi
  require_file "$faucet_operators_json_path"

  local psy_faucet_operators_json
  local faucet_operators_sha256
  local faucet_turnstile_secret_sha256
  psy_faucet_operators_json="$(<"$faucet_operators_json_path")"
  faucet_operators_sha256="$(sha256sum "$faucet_operators_json_path" | awk '{print $1}')"
  faucet_turnstile_secret_sha256="$(printf '%s' "${LOCAL_STAGING_PSY_FAUCET_TURNSTILE_SECRET:-}" | sha256sum | awk '{print $1}')"

  local faucet_server_env=(
    "PSY_USER_CLI_SHA256=$user_cli_sha256"
    "PSY_FAUCET_LISTEN_ADDR=$LOCAL_STAGING_FAUCET_ADDR"
    "RPC_CONFIG=$RPC_CONFIG"
    "PSY_FAUCET_OPERATORS_JSON=$psy_faucet_operators_json"
    "PSY_FAUCET_REQUIRE_TURNSTILE=$LOCAL_STAGING_PSY_FAUCET_REQUIRE_TURNSTILE"
  )
  if [ -n "${LOCAL_STAGING_PSY_FAUCET_TURNSTILE_SECRET:-}" ]; then
    faucet_server_env+=("PSY_FAUCET_TURNSTILE_SECRET=$LOCAL_STAGING_PSY_FAUCET_TURNSTILE_SECRET")
  fi
  if [ -n "${LOCAL_STAGING_PSY_FAUCET_TURNSTILE_ACTION:-}" ]; then
    faucet_server_env+=("PSY_FAUCET_TURNSTILE_ACTION=$LOCAL_STAGING_PSY_FAUCET_TURNSTILE_ACTION")
  fi
  if [ -n "${LOCAL_STAGING_PSY_FAUCET_TURNSTILE_ALLOWED_HOSTNAMES:-}" ]; then
    faucet_server_env+=("PSY_FAUCET_TURNSTILE_ALLOWED_HOSTNAMES=$LOCAL_STAGING_PSY_FAUCET_TURNSTILE_ALLOWED_HOSTNAMES")
  fi

  restart_process_if_env_changed "faucet-server" \
    "PSY_USER_CLI_SHA256=$user_cli_sha256" \
    "PSY_FAUCET_LISTEN_ADDR=$LOCAL_STAGING_FAUCET_ADDR" \
    "RPC_CONFIG=$RPC_CONFIG" \
    "PSY_FAUCET_OPERATORS_SHA256=$faucet_operators_sha256" \
    "PSY_FAUCET_REQUIRE_TURNSTILE=$LOCAL_STAGING_PSY_FAUCET_REQUIRE_TURNSTILE" \
    "PSY_FAUCET_TURNSTILE_SECRET_SHA256=$faucet_turnstile_secret_sha256" \
    "PSY_FAUCET_TURNSTILE_ACTION=${LOCAL_STAGING_PSY_FAUCET_TURNSTILE_ACTION:-}" \
    "PSY_FAUCET_TURNSTILE_ALLOWED_HOSTNAMES=${LOCAL_STAGING_PSY_FAUCET_TURNSTILE_ALLOWED_HOSTNAMES:-}"
  start_process "faucet-server" "faucet-server" "${faucet_server_env[@]}"
  wait_process_tcp "faucet-server" "${LOCAL_STAGING_FAUCET_ADDR%:*}" "${LOCAL_STAGING_FAUCET_ADDR##*:}" "faucet-server" 240 2
}

main() {
  if [ "$LOCAL_STAGING_FAUCET_SPLIT_ONLY" != "1" ]; then
    ensure_genesis_artifacts
  fi
  require_file "$GENESIS_PATH"
  require_file "$PRIVATE_KEYS_PATH"

  mkdir -p "$LOG_DIR" "$PID_DIR" "$CHECKPOINT_DIR" "$INDEXER_BACKUP_DIR"

  if [ "$LOCAL_STAGING_FAUCET_SPLIT_ONLY" = "1" ]; then
    if [ "$LOCAL_STAGING_BUILD" = "1" ]; then
      is_usable_genesis_contracts "$PARTH_DIR/genesis_contracts.json" || {
        echo "[local-staging] faucet-only build requires the existing matching genesis_contracts.json" >&2
        exit 1
      }
      echo "[local-staging] building psy_user_cli"
      cargo build --manifest-path "$PARTH_DIR/Cargo.toml" --release --bin psy_user_cli
    fi
    require_file "$PARTH_DIR/deploy/bin/run-parth-service"
    require_file "$RPC_CONFIG"
    require_exec "$USER_CLI"
    start_faucet_split_components
    echo "[local-staging] faucet split ready"
    echo "  prove-proxy: http://$LOCAL_STAGING_PROVE_PROXY_ADDR"
    echo "  faucet:      http://$LOCAL_STAGING_FAUCET_ADDR"
    return 0
  fi

  verify_genesis_runtime_abis
  verify_claim_deposit_artifacts

  if [ "$LOCAL_STAGING_BUILD" = "1" ]; then
    echo "[local-staging] building parth release binaries"
    cargo build --manifest-path "$PARTH_DIR/Cargo.toml" --release --bin psy_node_cli --bin psy_worker_cli --bin psy_user_cli
    if [ "$LOCAL_STAGING_START_PSY_SERVICES" = "1" ] || [ "$LOCAL_STAGING_START_INDEXERS" = "1" ]; then
      echo "[local-staging] building psy-services release binaries"
      cargo build --manifest-path "$PSY_SERVICES_HOME/Cargo.toml" --release --bin psy-services --bin psy-indexer
    fi
  fi

  require_file "$PARTH_DIR/deploy/bin/run-parth-service"
  require_exec "$PARTH_DIR/target/release/psy_node_cli"
  require_exec "$PARTH_DIR/target/release/psy_worker_cli"
  require_exec "$USER_CLI"

  if [ "$LOCAL_STAGING_START_PSY_SERVICES" = "1" ] || [ "$LOCAL_STAGING_START_INDEXERS" = "1" ]; then
    require_exec "$PSY_SERVICES_HOME/target/release/psy-services"
  fi
  if [ "$LOCAL_STAGING_START_INDEXERS" = "1" ]; then
    require_exec "$PSY_SERVICES_HOME/target/release/psy-indexer"
  fi

  if [ "$LOCAL_STAGING_RESET" = "1" ]; then
    echo "[local-staging] resetting local staging runtime"
    bash "$SCRIPT_DIR/down.sh" --volumes || true
  fi

  export LOCAL_STAGING_NGINX_ROOT="$NGINX_ROOT"
  export LOCAL_STAGING_APP_PORT
  export LOCAL_STAGING_EXPLORER_PORT
  export LOCAL_STAGING_IDE_PORT

  if [ "$LOCAL_STAGING_START_NGINX" = "1" ] && [ "$LOCAL_STAGING_PUBLISH_FRONTENDS" = "1" ]; then
    LOCAL_STAGING_BUILD_FRONTENDS="$LOCAL_STAGING_BUILD_FRONTENDS" \
      LOCAL_STAGING_NGINX_ROOT="$NGINX_ROOT" \
      bash "$SCRIPT_DIR/publish-frontends.sh"
  else
    for frontend_path in app explorer ide downloads; do
      if [ -L "$NGINX_ROOT/$frontend_path" ] && [ ! -e "$NGINX_ROOT/$frontend_path" ]; then
        rm -f "$NGINX_ROOT/$frontend_path"
      fi
    done
    mkdir -p "$NGINX_ROOT/app" "$NGINX_ROOT/explorer" "$NGINX_ROOT/ide" "$NGINX_ROOT/downloads"
  fi

  echo "[local-staging] starting Docker dependencies"
  local_staging_compose "$SCRIPT_DIR" up -d
  local_staging_wait_tcp 127.0.0.1 "$LOCAL_REDIS_PORT" "valkey"
  local_staging_wait_tcp 127.0.0.1 "$LOCAL_NATS_PORT" "nats"
  local_staging_wait_tcp 127.0.0.1 "$LOCAL_SCYLLA_PORT" "scylla"
  local_staging_wait_scylla_ready parth-local-scylla
  local_staging_wait_tcp 127.0.0.1 "$LOCAL_NOSTR_PORT" "nostr relay"
  local_staging_wait_tcp 127.0.0.1 "$LOCAL_POSTGRES_PORT" "postgres"
  if [ "$LOCAL_STAGING_START_NGINX" = "1" ]; then
    local_staging_wait_tcp 127.0.0.1 "$LOCAL_STAGING_APP_PORT" "nginx app"
    local_staging_wait_tcp 127.0.0.1 "$LOCAL_STAGING_EXPLORER_PORT" "nginx explorer"
    local_staging_wait_tcp 127.0.0.1 "$LOCAL_STAGING_IDE_PORT" "nginx ide"
  fi

  start_process "coordinator-processor" "coordinator-processor" \
    "DB_NAMESPACE=coordinator"
  wait_started_process_log_pattern "coordinator-processor" \
    "\\[COORD_STARTUP\\] init_with_setup_and_genesis done|PSY_COORDINATOR_PROCESSOR_STARTED" \
    "coordinator processor schema/genesis init"
  settle_local_schema

  start_process "coordinator-edge" "coordinator-edge" \
    "DB_NAMESPACE=coordinator" \
    "COORDINATOR_EDGE_PORT=$LOCAL_STAGING_COORDINATOR_EDGE_PORT" \
    "LISTEN_ADDR=127.0.0.1"
  wait_process_tcp "coordinator-edge" 127.0.0.1 "$LOCAL_STAGING_COORDINATOR_EDGE_PORT" "coordinator edge"

  if [ "$LOCAL_STAGING_START_WORKERS" = "1" ]; then
    local coordinator_private_key
    local coordinator_worker_user_id
    coordinator_private_key="$(local_staging_private_key_at_index "$PRIVATE_KEYS_PATH" "$LOCAL_STAGING_COORDINATOR_WORKER_KEY_INDEX")"
    coordinator_worker_user_id="$(local_staging_user_id_for_key_index "$LOCAL_STAGING_COORDINATOR_WORKER_KEY_INDEX")"
    start_process "coordinator-worker" "worker" \
      "WORKER_USER_ID=$coordinator_worker_user_id" \
      "PRIVATE_KEY=$coordinator_private_key" \
      "COMPLETED_JOBS_LOG_FILE=$CHECKPOINT_DIR/coordinator_worker.backup" \
      "COORDINATOR_API_URLS=http://127.0.0.1:$LOCAL_STAGING_COORDINATOR_EDGE_PORT" \
      "REALM_API_URLS=" \
      "BATCH_SIZE=${LOCAL_STAGING_COORDINATOR_WORKER_BATCH_SIZE:-4}"
  fi

  if [ "$LOCAL_STAGING_START_PSY_SERVICES" = "1" ]; then
    local psy_services_binary_sha256
    psy_services_binary_sha256="$(sha256sum "$PSY_SERVICES_HOME/target/release/psy-services" | awk '{print $1}')"
    local psy_services_env=(
      "PSY_SERVICES_BINARY_SHA256=$psy_services_binary_sha256" \
      "DATABASE_URL=$DATABASE_URL" \
      "PSY_SERVICES_REDIS_URL=redis://127.0.0.1:$LOCAL_REDIS_PORT" \
      "API_LISTEN=$LOCAL_STAGING_PSY_SERVICES_ADDR" \
      "PSY_NETWORK_TYPE=$LOCAL_STAGING_NETWORK" \
      "PSY_SERVICES_RUN_MIGRATIONS=true" \
      "PSY_SERVICES_DISABLE_AUTH=1" \
      "PSY_GENESIS_PATH=$GENESIS_PATH" \
      "PSY_NOSTR_ENABLED=true" \
      "PSY_NOSTR_RELAY_URLS=ws://127.0.0.1:$LOCAL_NOSTR_PORT" \
      "L1_RPC_URL=$L1_RPC_URL" \
      "INDEXER_GRAPHQL_URL=http://127.0.0.1:$LOCAL_STAGING_INDEXER_PORT/v1/graphql" \
      "ENVIO_GRAPHQL_URL=http://127.0.0.1:$LOCAL_STAGING_INDEXER_PORT/v1/graphql" \
      "HASURA_GRAPHQL_ADMIN_SECRET=${LOCAL_STAGING_HASURA_ADMIN_SECRET:-testing}"
    )

    if [ -f "$L1_DEPLOYMENTS_JSON" ]; then
      local state_manager_address
      state_manager_address="$(jq -er '.core.StateManager // .contracts.StateManager // empty' "$L1_DEPLOYMENTS_JSON" 2>/dev/null || true)"
      if [ -n "$state_manager_address" ]; then
        psy_services_env+=(
          "STATE_MANAGER_ADDRESS=$state_manager_address"
          "PSY_STATE_MANAGER_ADDRESS=$state_manager_address"
        )
      else
        echo "[local-staging] warning: StateManager address missing from $L1_DEPLOYMENTS_JSON; withdrawal claim proof API will fail until configured" >&2
      fi
    else
      echo "[local-staging] warning: missing L1 deployment file $L1_DEPLOYMENTS_JSON; withdrawal claim proof API will fail until configured" >&2
    fi

    restart_process_if_env_changed "psy-services" "${psy_services_env[@]}"
    start_process "psy-services" "psy-services" "${psy_services_env[@]}"
    local_staging_wait_http "http://$LOCAL_STAGING_PSY_SERVICES_ADDR/health" "psy-services"
  fi

  LOCAL_STAGING_PSY_SERVICES_ADDR_PORT="${LOCAL_STAGING_PSY_SERVICES_ADDR##*:}"
  export LOCAL_STAGING_PSY_SERVICES_ADDR_PORT

  if [ "$LOCAL_STAGING_START_INDEXERS" = "1" ]; then
    start_process "psy-indexer-coordinator" "psy-indexer" \
      "PSY_INDEXER_MODE=coordinator" \
      "PSY_EDGE_RPC_URL=http://127.0.0.1:$LOCAL_STAGING_COORDINATOR_EDGE_PORT" \
      "PSY_SERVICES_URL=http://127.0.0.1:$LOCAL_STAGING_PSY_SERVICES_ADDR_PORT" \
      "PSY_JWT_SECRET=$PSY_JWT_SECRET" \
      "PSY_BACKUP_DIR=$CHECKPOINT_DIR" \
      "PSY_POLL_INTERVAL_MS=${LOCAL_STAGING_INDEXER_POLL_INTERVAL_MS:-2000}" \
      "PSY_NETWORK_TYPE=$LOCAL_STAGING_NETWORK"
  fi

  local realm_id
  for realm_id in $LOCAL_STAGING_REALMS; do
    start_realm "$realm_id"
  done

  start_faucet_split_components

  echo
  echo "[local-staging] started"
  echo "  coordinator:  http://127.0.0.1:$LOCAL_STAGING_COORDINATOR_EDGE_PORT"
  for realm_id in $LOCAL_STAGING_REALMS; do
    echo "  realm $realm_id:      $(realm_url "$realm_id")"
  done
  echo "  prove-proxy:  http://$LOCAL_STAGING_PROVE_PROXY_ADDR"
  if [ "$LOCAL_STAGING_ENABLE_PSY_FAUCET" = "1" ] && [ "$LOCAL_STAGING_START_FAUCET_SERVER" = "1" ]; then
    echo "  faucet:       http://$LOCAL_STAGING_FAUCET_ADDR"
  fi
  echo "  psy-services: http://$LOCAL_STAGING_PSY_SERVICES_ADDR"
  echo "  nostr relay:  ws://127.0.0.1:$LOCAL_NOSTR_PORT"
  if [ "$LOCAL_STAGING_START_NGINX" = "1" ]; then
    echo "  app:          http://127.0.0.1:$LOCAL_STAGING_APP_PORT"
    echo "  explorer:     http://127.0.0.1:$LOCAL_STAGING_EXPLORER_PORT"
    echo "  ide:          http://127.0.0.1:$LOCAL_STAGING_IDE_PORT"
    echo "  wallet zip:   http://127.0.0.1:$LOCAL_STAGING_APP_PORT/downloads/psy-wallet-dev-latest.zip"
  fi
  echo
  echo "status:"
  echo "  bash $SCRIPT_DIR/status.sh"
  echo
  echo "logs:"
  echo "  tail -f $LOG_DIR/*.log"
}

main "$@"
