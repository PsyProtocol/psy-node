#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CONFIG_FILE="${GCP_DEPLOY_CONFIG:-$REPO_ROOT/deploy/gcp/config.env}"
: "${WORKSPACE_HOME:=$(cd "$REPO_ROOT/.." && pwd)}"
export WORKSPACE_HOME

cd "$REPO_ROOT"

export GCP_DEPLOY_CONFIG="$CONFIG_FILE"
export YES="${YES:-1}"

[ -f "$CONFIG_FILE" ] || {
  echo "missing config: $CONFIG_FILE" >&2
  exit 1
}

bash -n "$CONFIG_FILE"
set -a
# shellcheck disable=SC1090
source "$CONFIG_FILE"
set +a

SOURCE_VERSIONS_FILE="$REPO_ROOT/deploy/source-versions.env"
[ -f "$SOURCE_VERSIONS_FILE" ] || {
  echo "missing deployment source versions: $SOURCE_VERSIONS_FILE" >&2
  exit 1
}
bash -n "$SOURCE_VERSIONS_FILE"
set -a
# shellcheck disable=SC1090
source "$SOURCE_VERSIONS_FILE"
set +a

# shellcheck source=../lib/public-domains.sh
source "$REPO_ROOT/deploy/gcp/lib/public-domains.sh"
set_public_domain_defaults

echo "[deploy_all] repo: $REPO_ROOT"
echo "[deploy_all] config: $GCP_DEPLOY_CONFIG"
echo "[deploy_all] source versions: $SOURCE_VERSIONS_FILE"
grep -E '^(export )?EXPECTED_(PARTH_RUNTIME|PSY_GENESIS|PSY_CONTRACTS|PSY_DAPP|PSY_SERVICES|PSY_WALLET|PSY_SDK)_(REPOSITORY|COMMIT)=|^(export )?EXPECTED_GENESIS_CONTRACTS_SHA256=' \
  "$SOURCE_VERSIONS_FILE"
{
grep -E '^(PUBLIC_BASE_DOMAIN|PUBLIC_ENV_SLUG|NOSTR_DOMAIN|NOSTR_ALIAS_DOMAINS|NOSTR_RELAY_URL|PSY_NOSTR_ENABLED|PSY_NOSTR_RELAY_URLS|PSY_NOSTR_LOOKBACK_SECONDS|PUBLIC_COORDINATOR_DOMAIN|PUBLIC_COORDINATOR_ALIAS_DOMAINS|PUBLIC_REALM_DOMAIN|PUBLIC_REALM0_DOMAIN|PUBLIC_REALM_ALIAS_DOMAINS|PUBLIC_REALM1_DOMAIN|PUBLIC_REALM1_ALIAS_DOMAINS|PUBLIC_PROVE_PROXY_DOMAIN|PUBLIC_PROVE_PROXY_ALIAS_DOMAINS|PUBLIC_PROVE_PROXY_UPSTREAM|PUBLIC_FAUCET_DOMAIN|PUBLIC_FAUCET_ALIAS_DOMAINS|PUBLIC_L1_RPC_DOMAIN|PUBLIC_L1_RPC_ALIAS_DOMAINS|PUBLIC_RPC_DOMAIN|PUBLIC_PSY_SERVICES_DOMAIN|PUBLIC_PSY_SERVICES_ALIAS_DOMAINS|PUBLIC_INDEXER_DOMAIN|PUBLIC_INDEXER_ALIAS_DOMAINS|PUBLIC_PRIVACY_BRIDGE_URL|PUBLIC_PSY_EXPLORER_URL|PUBLIC_PSY_IDE_URL|PUBLIC_CONFIG_PAGE_URL|PUBLIC_WALLET_DOWNLOAD_URL|L1_DEPLOYMENTS_NETWORK|CHAIN_ID|START_BLOCK|ETH_RPC_URL|ENVIO_USE_HYPERSYNC|ENVIO_HYPERSYNC_URL|ENVIO_CONFIRMED_BLOCK_THRESHOLD|ENVIO_RPC_POLLING_INTERVAL_MILLIS|ENVIO_RPC_INITIAL_BLOCK_INTERVAL|ENVIO_RPC_INTERVAL_CEILING|ENVIO_RPC_METERING|ENVIO_RPC_HEIGHT_LOG_EVERY|ENVIO_RPC_GET_LOGS_LOG_EVERY|PUBLISH_PUBLIC_TRUST_SETUP|PUBLIC_TRUST_SETUP_USE_CURRENT_KEYSTORE|TRUST_SETUP_SOURCE_PSY_ROOT|TRUST_SETUP_ARCHIVE_NAME|TRUST_SETUP_PUBLIC_HOST|TRUST_SETUP_PUBLIC_ROOT|PUBLIC_TRUST_SETUP_DOMAIN|PUBLIC_TRUST_SETUP_PATH|GROTH16_REGENERATE_SETUP|GROTH16_REGENERATE_OPTIONAL|GROTH16_FORCE_REGENERATE|GROTH16_SETUP_HOST|L1_DEPLOYER_KEYSTORE_PATH|L1_DEPLOYER_ADDRESS|RELAYER_FINALIZE_EXPECTED_ADDRESS|COORDINATOR_WORKER_VM_NAME|COORDINATOR_WORKER_LAYOUT|COORDINATOR_WORKER_BATCH_SIZE|COORDINATOR_WORKER_KEY_INDEXES|DEPLOY_CLOUD_REALM_WORKERS|CLOUD_REALM_WORKER_LAYOUT|CLOUD_REALM_WORKER_BATCH_SIZE|REALM_WORKER_KEY_INDEXES|DEPLOY_OFFSITE_WORKERS|OFFSITE_WORKER_HOST|OFFSITE_WORKER_REQUIRED|DEPLOY_OFFSITE_PROVE_PROXY|OFFSITE_PROVE_PROXY_HOST|OFFSITE_PROVE_PROXY_APPLY_STAGED|DEPLOY_LOCAL_COORDINATOR_WORKERS|START_LOCAL_COORDINATOR_WORKERS|LOCAL_COORDINATOR_WORKER_BATCH_SIZE|REALM_WORKER_1_VM_NAME|REALM_WORKER_2_VM_NAME|PROVE_PROXY_VM_NAME|DEPLOY_CLOUD_PROVE_PROXY|CLIENT_PROVE_PROXY_URL|PROVE_PROXY_CLEAN_LEGACY_WORKERS|PSY_CAPTURE_INPUTS_DIR|PSY_CAPTURE_METHODS|PSY_CAPTURE_LIMIT_PER_METHOD|PSY_CAPTURE_INCLUDE_OUTPUTS|DEPLOY_RELAYER|RELAYER_VM_NAME|PSY_FAUCET_SERVER_MODE|PSY_FAUCET_LISTEN_ADDR|PSY_FAUCET_REQUIRE_TURNSTILE|PSY_FAUCET_TURNSTILE_SITE_KEY|PSY_FAUCET_WINDOW_CHECKPOINTS|NATS_VM_NAME|REDIS_VM_NAME|NATS_HOST|REDIS_HOST|VALKEY_MAXMEMORY|VALKEY_MAXMEMORY_POLICY|VALKEY_APPENDONLY|VALKEY_APPENDONLY_FSYNC|VALKEY_AUTO_AOF_REWRITE_PERCENTAGE|VALKEY_AUTO_AOF_REWRITE_MIN_SIZE|VALKEY_OVERCOMMIT_MEMORY|PARTH_BUNDLE_DISTRIBUTION_MODE|PARTH_BUNDLE_CACHE_HOST|PARTH_BUNDLE_CACHE_PORT|GROTH16_SETUP_DISTRIBUTION_MODE|GROTH16_SETUP_CACHE_HOST|GROTH16_SETUP_CACHE_PORT|NATS_MONITOR_ENABLED|NATS_MONITOR_UPLOAD_HOST_VM|NATS_MONITOR_UPLOAD_PORT|NATS_MONITOR_INTERVAL_SECONDS|NATS_EPHEMERAL_ACK_WAIT_MS|NATS_WORKER_ACK_WAIT_MS|BUILD_LOCAL_PSY_SDK|SMOKE_SIMPLE_MINT_ENABLED)=' "$CONFIG_FILE" || true
grep -E '^FAUCET_VM_NAME=' "$CONFIG_FILE" || true
} | sed -E 's#^(ETH_RPC_URL)=.*$#\1="<configured; redacted>"#'
[ -n "${SKIP_STEPS:-}" ] && echo "[deploy_all] skip steps: $SKIP_STEPS"
[ "${USE_LOCAL_PROVE_PROXY:-0}" = "1" ] && echo "[deploy_all] local prove proxy tunnel: enabled"

if [ "${CONFIRM_FULL_FRESH_DEPLOY:-0}" != "1" ] && [ "${DRY_RUN:-0}" != "1" ]; then
  cat >&2 <<'EOF'
This will run the full destructive fresh deployment, including frontends,
the public staging config page, and the smoke test.
Set CONFIRM_FULL_FRESH_DEPLOY=1 to continue.
EOF
  exit 1
fi

if [ "${REGENERATE_GENESIS:-1}" = "1" ]; then
  export REGENERATE_GENESIS=1
fi

should_skip_step() {
  local step="$1"
  local item item_norm skip_steps step_norm

  skip_steps="${SKIP_STEPS:-}"
  skip_steps="${skip_steps//,/ }"
  step_norm="$((10#$step))"
  for item in $skip_steps; do
    item_norm="$((10#$item))"
    if [ "$item_norm" = "$step_norm" ]; then
      return 0
    fi
  done
  return 1
}

last_step="${DEPLOY_ALL_LAST_STEP:-31}"
if [ "${USE_LOCAL_PROVE_PROXY:-0}" = "1" ] && [ "$last_step" -lt 24 ]; then
  last_step=24
fi

if [ "${ALLOW_L1_L2_STATE_MISMATCH:-0}" != "1" ] \
  && [ "$last_step" -ge 3 ] \
  && ! should_skip_step 3 \
  && should_skip_step 10 \
  && { [ "${L1_DEPLOYMENTS_NETWORK:-localhost}" != "localhost" ] || [ "${CHAIN_ID:-31337}" != "31337" ]; }; then
  cat >&2 <<'EOF'
Refusing unsafe deploy plan: step 03 clears L2/database state while step 10
is skipped, so existing Sepolia L1 contracts would keep old finalized roots and
deposit indexes while L2 starts fresh.

Use one of:
  - Full fresh deploy including step 10.
  - Redeploy services/frontends only without running steps 02/03.

Set ALLOW_L1_L2_STATE_MISMATCH=1 only for deliberate debugging.
EOF
  exit 1
fi

step_script() {
  local step="$1"
  local script
  local -a matches=()

  mapfile -t matches < <(find "$SCRIPT_DIR" -maxdepth 1 -type f -name "${step}_*.sh" | sort)
  [ "${#matches[@]}" -gt 0 ] || {
    echo "missing deploy step: $step" >&2
    exit 1
  }
  [ "${#matches[@]}" -eq 1 ] || {
    echo "ambiguous deploy step $step: ${matches[*]}" >&2
    exit 1
  }
  script="${matches[0]}"
  printf '%s\n' "$script"
}

run_step() {
  local step="$1"
  local script start_ts end_ts

  if should_skip_step "$step"; then
    echo
    echo "[deploy_all] skipping step $step"
    return 0
  fi

  script="$(step_script "$step")"
  if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "[deploy_all][dry-run] bash ${script#"$REPO_ROOT"/}"
    return 0
  fi
  echo
  echo "[deploy_all] starting $(basename "$script")"
  start_ts="$(date +%s)"
  bash "$script"
  end_ts="$(date +%s)"
  echo "[deploy_all] completed $(basename "$script") in $((end_ts - start_ts))s"
}

build_step_order() {
  local steps=(
    01 02 03 04 05 06 07 08 09 10
    11 12 13 14 15 16 17 29 18
    27
    21
    26 28 30
  )

  if [ "${USE_LOCAL_PROVE_PROXY:-0}" = "1" ]; then
    steps+=(24)
  fi

  if [ "${DEPLOY_LOCAL_COORDINATOR_WORKERS:-0}" = "1" ] || [ "${START_LOCAL_COORDINATOR_WORKERS:-0}" = "1" ]; then
    steps+=(25)
  fi

  # Keep validation after frontend/config deploys so testers see the addresses
  # from this fresh run even if a later smoke test fails.
  steps+=(23)

  # Offsite workers are additional capacity, not the baseline. Deploy them only
  # after the cloud services and smoke test are healthy.
  if [ "${DEPLOY_OFFSITE_WORKERS:-0}" = "1" ]; then
    steps+=(31)
  fi

  printf '%s\n' "${steps[@]}"
}

selected_steps=()
while IFS= read -r step; do
  if [ "$((10#$step))" -le "$last_step" ]; then
    selected_steps+=("$step")
  fi
done < <(build_step_order)

echo "[deploy_all] step order: ${selected_steps[*]}"
DEPLOY_ALL_SELECTED_STEPS="${selected_steps[*]}" bash "$SCRIPT_DIR/preflight.sh"

if should_skip_step 2 || should_skip_step 3; then
  export PARTH_ALLOW_GENESIS_OVERWRITE="${PARTH_ALLOW_GENESIS_OVERWRITE:-0}"
else
  export PARTH_ALLOW_GENESIS_OVERWRITE="${PARTH_ALLOW_GENESIS_OVERWRITE:-1}"
fi
echo "[deploy_all] PARTH_ALLOW_GENESIS_OVERWRITE=${PARTH_ALLOW_GENESIS_OVERWRITE}"

groth16_uploaded_before_l1=0
for step in "${selected_steps[@]}"; do
  if [ "$step" = "15" ] && [ "$groth16_uploaded_before_l1" = "1" ]; then
    echo
    echo "[deploy_all] skipping step 15 because step 10 already uploaded Groth16 setup before L1 deployment"
    continue
  fi

  run_step "$step"
  if [ "$step" = "10" ] && [ "${UPLOAD_GROTH16_BEFORE_L1:-1}" = "1" ]; then
    groth16_uploaded_before_l1=1
  fi
done

echo
if [ "${DRY_RUN:-0}" = "1" ]; then
  echo "[deploy_all] dry-run complete; no deployment steps were executed"
else
  echo "[deploy_all] completed fresh staging deployment"
fi
