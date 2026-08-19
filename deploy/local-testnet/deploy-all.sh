#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARTH_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
STACK_DIR="$SCRIPT_DIR/stack"
CF_DIR="$SCRIPT_DIR/cloudflare-tunnel"

# shellcheck source=stack/lib.sh
source "$STACK_DIR/lib.sh"

SOURCE_VERSIONS_FILE="$PARTH_DIR/deploy/source-versions.env"
[ -f "$SOURCE_VERSIONS_FILE" ] || {
  echo "[local-testnet] missing source version manifest: $SOURCE_VERSIONS_FILE" >&2
  exit 1
}
# shellcheck source=../source-versions.env
source "$SOURCE_VERSIONS_FILE"

local_staging_source_env_defaults \
  "${LOCAL_TESTNET_ENV_FILE:-$SCRIPT_DIR/local.env}"
local_staging_source_env_defaults "$STACK_DIR/local.env"
local_staging_source_env_defaults "$CF_DIR/local.env"

: "${PSY_SERVICES_HOME:=$PARTH_DIR/../psy-services}"
: "${PSY_COMPILER_HOME:=$PARTH_DIR/../psy-compiler}"
: "${PSY_WALLET_DIR:=$PARTH_DIR/../psy-wallet}"
: "${PSY_SDK_DIR:=$PARTH_DIR/../psy-sdk}"
: "${LOCAL_CF_AUTODEPLOY_SERVICE_NAME:=parth-local-frontend-autodeploy}"
: "${LOCAL_TESTNET_PARTH_BRANCH:=deploy-unified}"
: "${LOCAL_TESTNET_PRODUCT_BRANCH:=feat/improve-bridge-relayer}"
: "${LOCAL_TESTNET_ALLOW_DIRTY:=0}"
: "${LOCAL_STAGING_GENESIS_DATA_SEED:=}"
: "${LOCAL_STAGING_PRIVATE_KEYS_SEED:=}"

BUILD=1
RESET=0
ENABLE_AUTODEPLOY=1
PREFLIGHT_ONLY=0
CURRENT_STAGE="initialization"
STATUS_OUTPUT=""

usage() {
  cat <<'EOF'
Usage: deploy/local-testnet/deploy-all.sh [options]

Build and start the complete local Parth/Psy testnet, publish the frontends,
start the Cloudflare Tunnel, enable frontend auto deploy, verify health, and
then exit.

Options:
  --fresh          Remove existing local chain state and Docker volumes first.
  --no-build       Reuse existing binaries and frontend build artifacts.
  --no-autodeploy  Do not install or enable the frontend auto-deploy timer.
  --preflight-only Validate the checkout, dependencies, and configuration only.
  -h, --help       Show this help.

The default rebuilds code while preserving the existing local-chain state.
EOF
}

stage() {
  CURRENT_STAGE="$1"
  printf '\n[local-testnet] === %s ===\n' "$CURRENT_STAGE"
}

fail() {
  echo "[local-testnet] error: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

require_directory() {
  [ -d "$1" ] || fail "missing directory: $1"
}

verify_source_checkout() {
  local label="$1"
  local path="$2"
  local expected_branch="$3"
  local branch

  git -C "$path" rev-parse --git-dir >/dev/null 2>&1 \
    || fail "$label is not a valid Git checkout: $path"
  branch="$(git -C "$path" branch --show-current)"
  [ "$branch" = "$expected_branch" ] \
    || fail "$label branch mismatch: expected=$expected_branch current=${branch:-detached}"
  if [ "$LOCAL_TESTNET_ALLOW_DIRTY" != "1" ] \
    && [ -n "$(git -C "$path" status --porcelain)" ]; then
    fail "$label checkout is dirty: $path"
  fi
}

verify_source_commit() {
  local label="$1"
  local path="$2"
  local expected_commit="$3"
  local mode="${4:-exact}"
  local actual_commit

  actual_commit="$(git -C "$path" rev-parse HEAD)"
  if [ "$mode" = "ancestor" ]; then
    git -C "$path" merge-base --is-ancestor "$expected_commit" HEAD \
      || fail "$label does not contain required runtime commit: expected ancestor=$expected_commit actual=$actual_commit"
  elif [ "$actual_commit" != "$expected_commit" ]; then
    fail "$label commit mismatch: expected=$expected_commit actual=$actual_commit"
  fi
}

verify_genesis_contracts_hash() {
  local artifact="$PARTH_DIR/genesis_contracts.json"
  local actual_hash

  [ -s "$artifact" ] || {
    echo "[local-testnet] genesis contracts artifact is absent and will be generated during deployment"
    return 0
  }
  actual_hash="$(sha256sum "$artifact" | awk '{print $1}')"
  [ "$actual_hash" = "$EXPECTED_GENESIS_CONTRACTS_SHA256" ] \
    || fail "genesis contracts hash mismatch: expected=$EXPECTED_GENESIS_CONTRACTS_SHA256 actual=$actual_hash"
  echo "[local-testnet] genesis contracts hash verified: $actual_hash"
}

prepare_pinned_artifact() {
  local label="$1"
  local artifact="$2"
  local seed="$3"
  local expected_hash="$4"
  local actual_hash
  local tmp

  if [ -s "$artifact" ]; then
    actual_hash="$(sha256sum "$artifact" | awk '{print $1}')"
    if [ "$actual_hash" = "$expected_hash" ]; then
      echo "[local-testnet] $label hash verified: $actual_hash"
      return 0
    fi
  fi

  [ -n "$seed" ] \
    || fail "$label is missing or mismatched; configure its private seed path before deployment: $artifact"
  [ -s "$seed" ] || fail "$label seed does not exist or is empty: $seed"
  [ "$(realpath -m "$seed")" != "$(realpath -m "$artifact")" ] \
    || fail "$label seed must differ from its deployment path: $seed"

  tmp="${artifact}.tmp.$$"
  cp "$seed" "$tmp"
  actual_hash="$(sha256sum "$tmp" | awk '{print $1}')"
  if [ "$actual_hash" != "$expected_hash" ]; then
    rm -f "$tmp"
    fail "$label seed hash mismatch: expected=$expected_hash actual=$actual_hash"
  fi
  mv "$tmp" "$artifact"
  echo "[local-testnet] installed pinned $label from private seed: $actual_hash"
}

prepare_gcp_genesis() {
  : "${EXPECTED_GENESIS_SHA256:?missing EXPECTED_GENESIS_SHA256 from source version manifest}"
  : "${EXPECTED_GENESIS_PRIVATE_KEYS_SHA256:?missing EXPECTED_GENESIS_PRIVATE_KEYS_SHA256 from source version manifest}"

  prepare_pinned_artifact \
    "GCP genesis" \
    "$PARTH_DIR/genesis.json" \
    "$LOCAL_STAGING_GENESIS_DATA_SEED" \
    "$EXPECTED_GENESIS_SHA256"
  prepare_pinned_artifact \
    "GCP genesis private keys" \
    "$PARTH_DIR/private_keys.json" \
    "$LOCAL_STAGING_PRIVATE_KEYS_SEED" \
    "$EXPECTED_GENESIS_PRIVATE_KEYS_SHA256"
}

genesis_contracts_json() {
  local artifact="$PARTH_DIR/genesis_contracts.json"

  if jq -e . "$artifact" >/dev/null 2>&1; then
    cat "$artifact"
  else
    command -v zstdcat >/dev/null 2>&1 \
      || fail "zstdcat is required to inspect compressed genesis contracts"
    zstdcat "$artifact"
  fi
}

verify_genesis_abi_alignment() {
  local artifact="$PARTH_DIR/genesis_contracts.json"
  local token_abi="$PARTH_DIR/genesis_abi/PsyTokenContract.json"
  local deposit_abi="$PARTH_DIR/genesis_abi/PsyDepositTreeContract.json"
  local claim_method claim_inputs root_method root_inputs

  [ -s "$artifact" ] || return 0
  [ -s "$token_abi" ] || fail "missing token ABI: $token_abi"
  [ -s "$deposit_abi" ] || fail "missing deposit tree ABI: $deposit_abi"

  claim_method="$(jq -er '.contract.methods[] | select(.name == "claim_deposit") | .method_id' "$token_abi")"
  claim_inputs="$(jq -er '.contract.methods[] | select(.name == "claim_deposit") | .input_felt_count' "$token_abi")"
  root_method="$(jq -er '.contract.methods[] | select(.name == "set_chain_root") | .method_id' "$deposit_abi")"
  root_inputs="$(jq -er '.contract.methods[] | select(.name == "set_chain_root") | .input_felt_count' "$deposit_abi")"

  genesis_contracts_json | jq -e \
    --argjson method "$claim_method" \
    --argjson inputs "$claim_inputs" \
    '[.[0], .[4]]
      | all(.code_definition.functions
        | any(.method_id == $method and .num_inputs == $inputs))' >/dev/null \
    || fail "claim_deposit ABI does not match genesis contracts"

  genesis_contracts_json | jq -e \
    --argjson method "$root_method" \
    --argjson inputs "$root_inputs" \
    '.[2].code_definition.functions
      | any(.method_id == $method and .num_inputs == $inputs)' >/dev/null \
    || fail "set_chain_root ABI does not match genesis contracts"

  echo "[local-testnet] genesis ABI alignment verified: claim_deposit=$claim_method/$claim_inputs set_chain_root=$root_method/$root_inputs"
}

checkpoint_id() {
  local url="$1"

  curl -fsS --max-time 10 \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_latest_checkpoint_id","params":[]}' \
    "$url" | jq -er '.result | tonumber'
}

absolute_difference() {
  local left="$1"
  local right="$2"

  if [ "$left" -ge "$right" ]; then
    printf '%s\n' "$((left - right))"
  else
    printf '%s\n' "$((right - left))"
  fi
}

verify_checkpoint_progress() {
  local wait_seconds="${LOCAL_TESTNET_CHECKPOINT_WAIT_SECONDS:-8}"
  local max_skew="${LOCAL_TESTNET_CHECKPOINT_MAX_SKEW:-1}"
  local coordinator_url="http://127.0.0.1:${LOCAL_STAGING_COORDINATOR_EDGE_PORT:-1337}"
  local realm0_url="http://127.0.0.1:${LOCAL_STAGING_REALM_EDGE_BASE_PORT:-13380}"
  local realm1_url="http://127.0.0.1:$(( ${LOCAL_STAGING_REALM_EDGE_BASE_PORT:-13380} + ${LOCAL_STAGING_REALM_EDGE_PORT_STRIDE:-10} ))"
  local before after realm0 realm1

  before="$(checkpoint_id "$coordinator_url")"
  sleep "$wait_seconds"
  after="$(checkpoint_id "$coordinator_url")"
  realm0="$(checkpoint_id "$realm0_url")"
  realm1="$(checkpoint_id "$realm1_url")"

  [ "$after" -gt "$before" ] \
    || fail "coordinator checkpoint did not advance: $before -> $after"
  [ "$(absolute_difference "$after" "$realm0")" -le "$max_skew" ] \
    || fail "realm 0 checkpoint is out of sync: coordinator=$after realm0=$realm0"
  [ "$(absolute_difference "$after" "$realm1")" -le "$max_skew" ] \
    || fail "realm 1 checkpoint is out of sync: coordinator=$after realm1=$realm1"

  echo "[local-testnet] checkpoints advanced and synchronized: coordinator=$before->$after realm0=$realm0 realm1=$realm1"
}

cleanup() {
  if [ -n "$STATUS_OUTPUT" ]; then
    rm -f "$STATUS_OUTPUT"
  fi
}

on_error() {
  local exit_code=$?
  echo "[local-testnet] failed during: $CURRENT_STAGE (exit=$exit_code)" >&2
  echo "[local-testnet] logs: $PARTH_DIR/.local-staging/logs" >&2
  exit "$exit_code"
}

trap cleanup EXIT
trap on_error ERR

while [ "$#" -gt 0 ]; do
  case "$1" in
    --fresh)
      RESET=1
      ;;
    --no-build)
      BUILD=0
      ;;
    --no-autodeploy)
      ENABLE_AUTODEPLOY=0
      ;;
    --preflight-only)
      PREFLIGHT_ONLY=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

stage "preflight"
for command_name in bash curl docker git grep jq mktemp realpath sha256sum sleep sort systemctl; do
  require_command "$command_name"
done
if [ "$BUILD" = "1" ]; then
  for command_name in cargo node npm pnpm; do
    require_command "$command_name"
  done
fi

git_root="$(git -C "$PARTH_DIR" rev-parse --show-toplevel 2>/dev/null)" \
  || fail "$PARTH_DIR is not a valid Git checkout"
[ "$(realpath "$git_root")" = "$(realpath "$PARTH_DIR")" ] \
  || fail "Git checkout root mismatch: expected $PARTH_DIR, got $git_root"

require_directory "$PSY_SERVICES_HOME"
require_directory "$PSY_COMPILER_HOME"
require_directory "$PSY_WALLET_DIR"
require_directory "$PSY_SDK_DIR"
verify_source_checkout "Parth" "$PARTH_DIR" "$LOCAL_TESTNET_PARTH_BRANCH"
verify_source_checkout "psy-services" "$PSY_SERVICES_HOME" "$LOCAL_TESTNET_PRODUCT_BRANCH"
verify_source_checkout "psy-compiler" "$PSY_COMPILER_HOME" "$LOCAL_TESTNET_PRODUCT_BRANCH"
verify_source_checkout "psy-wallet" "$PSY_WALLET_DIR" "$LOCAL_TESTNET_PRODUCT_BRANCH"
verify_source_checkout "psy-sdk" "$PSY_SDK_DIR" "$LOCAL_TESTNET_PRODUCT_BRANCH"
verify_source_commit "Parth" "$PARTH_DIR" "$EXPECTED_PARTH_RUNTIME_COMMIT" ancestor
verify_source_commit "psy-services" "$PSY_SERVICES_HOME" "$EXPECTED_PSY_SERVICES_COMMIT"
verify_source_commit "psy-compiler" "$PSY_COMPILER_HOME" "$EXPECTED_PSY_COMPILER_COMMIT"
verify_source_commit "psy-wallet" "$PSY_WALLET_DIR" "$EXPECTED_PSY_WALLET_COMMIT"
verify_source_commit "psy-sdk" "$PSY_SDK_DIR" "$EXPECTED_PSY_SDK_COMMIT"
prepare_gcp_genesis
verify_genesis_contracts_hash
verify_genesis_abi_alignment
docker info >/dev/null

echo "[local-testnet] Parth:       $PARTH_DIR"
echo "[local-testnet] psy-services: $PSY_SERVICES_HOME"
echo "[local-testnet] psy-compiler: $PSY_COMPILER_HOME"
echo "[local-testnet] psy-wallet:   $PSY_WALLET_DIR"
echo "[local-testnet] psy-sdk:      $PSY_SDK_DIR"
echo "[local-testnet] build:        $BUILD"
echo "[local-testnet] reset:        $RESET"
echo "[local-testnet] auto deploy:  $ENABLE_AUTODEPLOY"

if [ "$PREFLIGHT_ONLY" = "1" ]; then
  echo "[local-testnet] preflight passed; no services were started"
  exit 0
fi

stage "quiesce frontend automation"
systemctl --user disable --now "$LOCAL_CF_AUTODEPLOY_SERVICE_NAME.timer" \
  >/dev/null 2>&1 || true
systemctl --user stop "$LOCAL_CF_AUTODEPLOY_SERVICE_NAME.service" \
  >/dev/null 2>&1 || true

stage "complete stack, bridge, frontends, and Cloudflare Tunnel"
export LOCAL_STAGING_BUILD="$BUILD"
export LOCAL_STAGING_RESET="$RESET"
export PSY_SERVICES_HOME
export PSY_COMPILER_HOME
export PSY_WALLET_DIR
export PSY_SDK_DIR
bash "$CF_DIR/up.sh"

if [ "$ENABLE_AUTODEPLOY" = "1" ]; then
  stage "frontend auto deploy"
  bash "$CF_DIR/install-frontend-autodeploy-user-service.sh"
fi

stage "final health verification"
STATUS_OUTPUT="$(mktemp)"

bash "$STACK_DIR/status.sh" > "$STATUS_OUTPUT" 2>&1
cat "$STATUS_OUTPUT"
if grep -Eqi '(^|[[:space:]])(failed|unhealthy|stopped)([[:space:]]|$)' "$STATUS_OUTPUT"; then
  fail "local stack status reported a failed component"
fi

expected_services="$(
  local_staging_compose "$STACK_DIR" config --services | LC_ALL=C sort
)"
running_services="$(
  local_staging_compose "$STACK_DIR" ps --status running --services | LC_ALL=C sort
)"
[ "$expected_services" = "$running_services" ] || {
  echo "[local-testnet] expected running Docker services:" >&2
  echo "$expected_services" >&2
  echo "[local-testnet] actual running Docker services:" >&2
  echo "$running_services" >&2
  fail "one or more local stack containers are not running"
}

bash "$CF_DIR/status.sh" > "$STATUS_OUTPUT" 2>&1
cat "$STATUS_OUTPUT"
if grep -Eqi '(^|[[:space:]])(failed|unhealthy|stopped)([[:space:]]|$)' "$STATUS_OUTPUT"; then
  fail "Cloudflare/public status reported a failed component"
fi

verify_checkpoint_progress

if [ "$ENABLE_AUTODEPLOY" = "1" ]; then
  systemctl --user is-active --quiet "$LOCAL_CF_AUTODEPLOY_SERVICE_NAME.timer" \
    || fail "frontend auto-deploy timer is not active"
fi

stage "deployment complete"
echo "[local-testnet] all startup stages and health checks passed"
echo "[local-testnet] the services remain in the background; this script is exiting"
