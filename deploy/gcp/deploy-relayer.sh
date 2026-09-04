#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"
# shellcheck source=lib/multichain.sh
source "$(dirname "$0")/lib/multichain.sh"

NAME="${RELAYER_VM_NAME:-${NODE_VM_NAME:-parth-node-1}}"
NODE_NAME="${NODE_VM_NAME:-gcp-cp-ce}"
NODE_HOST="$(instance_internal_dns "$NODE_NAME")"
ANVIL_VM_NAME="${ANVIL_VM_NAME:-${NODE_VM_NAME:-gcp-cp-ce}}"
ANVIL_HOST="${ANVIL_HOST:-$(instance_internal_dns "$ANVIL_VM_NAME")}"
ANVIL_PORT="${ANVIL_PORT:-8545}"
ETH_RPC_URL="${ETH_RPC_URL:-http://${ANVIL_HOST}:${ANVIL_PORT}}"
POSTGRES_HOST="${POSTGRES_HOST:-$(instance_internal_dns "${POSTGRES_VM_NAME:-gcp-postgres}")}"
ENVIO_PG_HOST="${ENVIO_PG_HOST:-$POSTGRES_HOST}"
ENVIO_PG_PORT="${ENVIO_PG_PORT:-5432}"
ENVIO_DATABASE_URL="${ENVIO_DATABASE_URL:-$(postgres_url "$ENVIO_PG_HOST" "$ENVIO_PG_PORT" "${ENVIO_PG_DATABASE:-envio_bridge}" "${ENVIO_PG_USER:-${POSTGRES_USER:-postgres}}" "${ENVIO_PG_PASSWORD:-${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set}}")}"
RELAYER_CONFIG="${RELAYER_CONFIG:-/etc/parth/bridge-relayer.toml}"
RELAYER_SERVICES_URL="${RELAYER_SERVICES_URL:-http://${NODE_HOST}:${PSY_SERVICES_PORT:-3000}}"
RELAYER_DEPLOYMENTS_NETWORK="${RELAYER_DEPLOYMENTS_NETWORK:-${L1_DEPLOYMENTS_NETWORK:-localhost}}"
RELAYER_LOCAL_DEPLOYMENTS_DIR="${RELAYER_LOCAL_DEPLOYMENTS_DIR:-$PARTH_DIR/psy-contracts/deployments/$RELAYER_DEPLOYMENTS_NETWORK}"
RELAYER_L2_PRIVATE_KEY="${RELAYER_L2_PRIVATE_KEY:-${BRIDGE_RELAYER_L2_PRIVATE_KEY:-}}"
RELAYER_L2_KEYSTORE_PATH="${RELAYER_L2_KEYSTORE_PATH:-${KEYSTORE_PATH:-}}"
RELAYER_L2_KEYSTORE_REMOTE_PATH="${RELAYER_L2_KEYSTORE_REMOTE_PATH:-/var/lib/parth/keystore/bridge-relayer-dev}"
RELAYER_L2_WALLET_PASSWORD="${RELAYER_L2_WALLET_PASSWORD:-${WALLET_PASSWORD:-}}"
RELAYER_FINALIZE_KEYSTORE_PATH="${RELAYER_FINALIZE_KEYSTORE_PATH:-${L1_DEPLOYER_KEYSTORE_PATH:-}}"
RELAYER_FINALIZE_KEYSTORE_REMOTE_PATH="${RELAYER_FINALIZE_KEYSTORE_REMOTE_PATH:-/var/lib/parth/.psy/keystore/bridge-relayer-dev}"
RELAYER_FINALIZE_WALLET_PASSWORD="${RELAYER_FINALIZE_WALLET_PASSWORD:-${L1_DEPLOYER_WALLET_PASSWORD:-${WALLET_PASSWORD:-}}}"
RELAYER_FINALIZE_EXPECTED_ADDRESS="${RELAYER_FINALIZE_EXPECTED_ADDRESS:-${L1_DEPLOYER_ADDRESS:-}}"
RELAYER_CHAINS_JSON="${RELAYER_CHAINS_JSON:-}"

if multichain_enabled; then
  primary_chain="$(multichain_primary_chain)"
  RELAYER_DEPLOYMENTS_NETWORK="$(jq -r '.network' <<<"$primary_chain")"
  RELAYER_LOCAL_DEPLOYMENTS_DIR="$PARTH_DIR/psy-contracts/deployments/$RELAYER_DEPLOYMENTS_NETWORK"
  RELAYER_CHAINS_JSON="$(multichain_relayer_chains_json)"
fi

normalize_eth_address() {
  local address="${1#0x}"
  printf '0x%s\n' "$(printf '%s' "$address" | tr '[:upper:]' '[:lower:]')"
}

is_local_finalize_network() {
  [ "$RELAYER_DEPLOYMENTS_NETWORK" = "localhost" ] \
    || [ "${CHAIN_ID:-31337}" = "31337" ]
}

validate_eth_address() {
  local name="$1"
  local address="${2#0x}"
  if ! printf '%s' "$address" | grep -Eq '^[0-9a-fA-F]{40}$'; then
    echo "invalid ${name}: expected a 20-byte Ethereum address, got '${2}'" >&2
    exit 1
  fi
}

assert_finalize_address() {
  local actual="$1"
  [ -n "$RELAYER_FINALIZE_EXPECTED_ADDRESS" ] || return 0

  validate_eth_address "RELAYER_FINALIZE_EXPECTED_ADDRESS" "$RELAYER_FINALIZE_EXPECTED_ADDRESS"
  validate_eth_address "relayer finalize signer address" "$actual"
  if [ "$(normalize_eth_address "$actual")" != "$(normalize_eth_address "$RELAYER_FINALIZE_EXPECTED_ADDRESS")" ]; then
    echo "refusing to deploy relayer with a different L1 finalize signer" >&2
    echo "expected: $RELAYER_FINALIZE_EXPECTED_ADDRESS" >&2
    echo "actual:   $actual" >&2
    exit 1
  fi
}

if [ -z "$RELAYER_L2_PRIVATE_KEY" ] && [ -z "$RELAYER_L2_KEYSTORE_PATH" ]; then
  RELAYER_L2_PRIVATE_KEY="${BRIDGE_USER_PRIVATE_KEY:-$(genesis_private_key_or_empty 2)}"
fi
if [ -z "$RELAYER_L2_PRIVATE_KEY" ] && [ -z "$RELAYER_L2_KEYSTORE_PATH" ]; then
  echo "missing bridge relayer L2 key; set RELAYER_L2_KEYSTORE_PATH or BRIDGE_RELAYER_L2_PRIVATE_KEY, or generate private_keys.json with key[2]" >&2
  exit 1
fi
DEFAULT_ANVIL_PRIVATE_KEY="ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
DEFAULT_ANVIL_ADDRESS="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
if [ -n "${RELAYER_FINALIZE_PRIVATE_KEY:-}" ]; then
  FINALIZE_PRIVATE_KEY="$RELAYER_FINALIZE_PRIVATE_KEY"
elif [ -n "${L1_DEPLOYER_PRIVATE_KEY:-}" ]; then
  FINALIZE_PRIVATE_KEY="$L1_DEPLOYER_PRIVATE_KEY"
elif is_local_finalize_network \
  && { [ -z "${L1_DEPLOYER_ADDRESS:-}" ] || [ "$(normalize_eth_address "$L1_DEPLOYER_ADDRESS")" = "$DEFAULT_ANVIL_ADDRESS" ]; }; then
  FINALIZE_PRIVATE_KEY="$DEFAULT_ANVIL_PRIVATE_KEY"
else
  FINALIZE_PRIVATE_KEY=""
fi

if ! is_local_finalize_network && [ -z "$RELAYER_FINALIZE_EXPECTED_ADDRESS" ]; then
  echo "RELAYER_FINALIZE_EXPECTED_ADDRESS or L1_DEPLOYER_ADDRESS is required for $RELAYER_DEPLOYMENTS_NETWORK" >&2
  exit 1
fi

if [ -n "$RELAYER_FINALIZE_KEYSTORE_PATH" ] && [ -f "$RELAYER_FINALIZE_KEYSTORE_PATH" ]; then
  [ -n "$RELAYER_FINALIZE_WALLET_PASSWORD" ] || {
    echo "RELAYER_FINALIZE_WALLET_PASSWORD, L1_DEPLOYER_WALLET_PASSWORD, or WALLET_PASSWORD is required to verify the finalize keystore" >&2
    exit 1
  }
  command -v cast >/dev/null 2>&1 || {
    echo "cast is required to verify the relayer finalize keystore address" >&2
    exit 1
  }
  FINALIZE_SIGNER_ADDRESS="$(
    cast wallet address \
      --keystore "$RELAYER_FINALIZE_KEYSTORE_PATH" \
      --password "$RELAYER_FINALIZE_WALLET_PASSWORD"
  )"
  assert_finalize_address "$FINALIZE_SIGNER_ADDRESS"
elif [ -n "$FINALIZE_PRIVATE_KEY" ]; then
  command -v cast >/dev/null 2>&1 || {
    echo "cast is required to verify the relayer finalize private-key address" >&2
    exit 1
  }
  FINALIZE_SIGNER_ADDRESS="$(cast wallet address "$FINALIZE_PRIVATE_KEY")"
  assert_finalize_address "$FINALIZE_SIGNER_ADDRESS"
elif ! is_local_finalize_network; then
  echo "$RELAYER_DEPLOYMENTS_NETWORK relayer deployment requires a local RELAYER_FINALIZE_KEYSTORE_PATH or an explicit finalize private key" >&2
  echo "refusing to reuse or generate an unverified signer" >&2
  exit 1
fi

ensure_parth_vm "$NAME"

if [ -n "$RELAYER_L2_KEYSTORE_PATH" ]; then
  if [ -f "$RELAYER_L2_KEYSTORE_PATH" ]; then
    remote_tmp="/tmp/parth-bridge-relayer-keystore"
    echo "uploading bridge relayer L2 keystore: $RELAYER_L2_KEYSTORE_PATH -> ${NAME}:${RELAYER_L2_KEYSTORE_REMOTE_PATH}"
    scp_to_remote "$NAME" "$RELAYER_L2_KEYSTORE_PATH" "$remote_tmp"
    run_remote_command "$NAME" "sudo install -d -m 0750 -o parth -g parth '$(dirname "$RELAYER_L2_KEYSTORE_REMOTE_PATH")' && sudo install -m 0640 -o parth -g parth '$remote_tmp' '$RELAYER_L2_KEYSTORE_REMOTE_PATH' && rm -f '$remote_tmp'"
    RELAYER_L2_KEYSTORE_PATH="$RELAYER_L2_KEYSTORE_REMOTE_PATH"
  fi
fi

if [ -n "$RELAYER_FINALIZE_KEYSTORE_PATH" ]; then
  if [ -f "$RELAYER_FINALIZE_KEYSTORE_PATH" ]; then
    remote_tmp="/tmp/parth-l1-deployer-keystore"
    local_finalize_keystore_sha256="$(sha256sum "$RELAYER_FINALIZE_KEYSTORE_PATH" | awk '{print $1}')"
    echo "uploading relayer finalize keystore: $RELAYER_FINALIZE_KEYSTORE_PATH -> ${NAME}:${RELAYER_FINALIZE_KEYSTORE_REMOTE_PATH}"
    scp_to_remote "$NAME" "$RELAYER_FINALIZE_KEYSTORE_PATH" "$remote_tmp"
    run_remote_command "$NAME" "sudo install -d -m 0750 -o parth -g parth '$(dirname "$RELAYER_FINALIZE_KEYSTORE_REMOTE_PATH")' && sudo install -m 0640 -o parth -g parth '$remote_tmp' '$RELAYER_FINALIZE_KEYSTORE_REMOTE_PATH' && rm -f '$remote_tmp'"
    remote_finalize_keystore_sha256="$(
      run_remote_command "$NAME" "sudo sha256sum '$RELAYER_FINALIZE_KEYSTORE_REMOTE_PATH' | awk '{print \$1}'"
    )"
    if [ "$remote_finalize_keystore_sha256" != "$local_finalize_keystore_sha256" ]; then
      echo "relayer finalize keystore checksum mismatch after upload" >&2
      exit 1
    fi
    RELAYER_FINALIZE_KEYSTORE_PATH="$RELAYER_FINALIZE_KEYSTORE_REMOTE_PATH"
  fi
fi

if [ -n "${FINALIZE_SIGNER_ADDRESS:-}" ]; then
  echo "verified relayer L1 finalize signer: $FINALIZE_SIGNER_ADDRESS"
fi

write_relayer_config() {
  run_remote_script "$NAME" "$GCP_DIR/remote/write-relayer-config.sh" \
    "RELAYER_CONFIG=$RELAYER_CONFIG" \
    "RELAYER_POLL_INTERVAL_SECS=${RELAYER_POLL_INTERVAL_SECS:-15}" \
    "RELAYER_CONFIRMATION_LAG_CHECKPOINTS=${RELAYER_CONFIRMATION_LAG_CHECKPOINTS:-3}" \
    "RELAYER_MAX_CHECKPOINT_BATCH=${RELAYER_MAX_CHECKPOINT_BATCH:-8}" \
    "RELAYER_SERVICES_EVENT_SETTLE_SECS=${RELAYER_SERVICES_EVENT_SETTLE_SECS:-5}" \
    "RELAYER_WITHDRAWAL_SCAN_LOOKBACK_CHECKPOINTS=${RELAYER_WITHDRAWAL_SCAN_LOOKBACK_CHECKPOINTS:-64}" \
    "RELAYER_EXIT_AFTER_SUCCESSFUL_ROUNDS=${RELAYER_EXIT_AFTER_SUCCESSFUL_ROUNDS:-1}" \
    "RELAYER_WITHDRAW_METHOD_ID=${RELAYER_WITHDRAW_METHOD_ID:-4159421846}" \
    "RELAYER_SERVICES_URL=$RELAYER_SERVICES_URL" \
    "RELAYER_L2_PRIVATE_KEY=$RELAYER_L2_PRIVATE_KEY" \
    "RELAYER_L2_KEYSTORE_PATH=$RELAYER_L2_KEYSTORE_PATH" \
    "RELAYER_L2_WALLET_PASSWORD=$RELAYER_L2_WALLET_PASSWORD" \
    "RELAYER_L2_RPC_CONFIG=${RELAYER_L2_RPC_CONFIG:-/opt/parth/current/client_prover/config.json}" \
    "RELAYER_PROOF_DIR=${RELAYER_PROOF_DIR:-/var/lib/parth/bridge-relayer}" \
    "RELAYER_L1_RPC_URL=${RELAYER_L1_RPC_URL:-$ETH_RPC_URL}" \
    "RELAYER_L1_RPC_FALLBACK_URL=${RELAYER_L1_RPC_FALLBACK_URL:-}" \
    "RELAYER_DEPLOYMENTS_NETWORK=$RELAYER_DEPLOYMENTS_NETWORK" \
    "RELAYER_DEPLOYED_CONTRACTS_JSON=${RELAYER_DEPLOYED_CONTRACTS_JSON:-/opt/parth/current/psy-contracts/deployments/${RELAYER_DEPLOYMENTS_NETWORK}/deployed-contracts.json}" \
    "RELAYER_FINALIZE_PRIVATE_KEY=$FINALIZE_PRIVATE_KEY" \
    "RELAYER_FINALIZE_KEYSTORE_PATH=$RELAYER_FINALIZE_KEYSTORE_PATH" \
    "RELAYER_FINALIZE_PASSWORD_ENV=WALLET_PASSWORD" \
    "RELAYER_BRIDGE_ADDRESS=${RELAYER_BRIDGE_ADDRESS:-${BRIDGE_ADDRESS:-}}" \
    "RELAYER_STATE_MANAGER_ADDRESS=${RELAYER_STATE_MANAGER_ADDRESS:-${STATE_MANAGER_ADDRESS:-}}" \
    "RELAYER_MULTICALL3_ADDRESS=${RELAYER_MULTICALL3_ADDRESS:-${MULTICALL3_ADDRESS:-}}" \
    "RELAYER_CHAINS_JSON=$RELAYER_CHAINS_JSON"
}

upload_l1_deployment_artifacts() {
  local network="$1"
  local local_deployments_dir="$PARTH_DIR/psy-contracts/deployments/$network"

  if [ ! -d "$local_deployments_dir" ]; then
    if multichain_enabled; then
      echo "missing required multichain L1 deployments dir: $local_deployments_dir" >&2
      return 1
    fi
    echo "warning: local L1 deployments dir missing; relayer may miss Hardhat artifacts: $local_deployments_dir" >&2
    return 0
  fi

  if ! find "$local_deployments_dir" -maxdepth 1 -type f -name '*.json' | grep -q .; then
    if multichain_enabled; then
      echo "no required multichain deployment JSON artifacts found in $local_deployments_dir" >&2
      return 1
    fi
    echo "warning: no deployment JSON artifacts found in $local_deployments_dir" >&2
    return 0
  fi

  local archive="/tmp/parth-l1-deployments-${network}.tar.gz"
  local remote_archive="/tmp/parth-l1-deployments-${network}.tar.gz"
  (
    cd "$local_deployments_dir"
    tar -czf "$archive" ./*.json
  )

  echo "uploading L1 deployment artifacts: $local_deployments_dir/*.json -> ${NAME}:${remote_archive}"
  scp_to_remote "$NAME" "$archive" "$remote_archive"
  run_remote_command "$NAME" "sudo install -d -m 0755 '/opt/parth/current/psy-contracts/deployments/$network' && sudo tar -xzf '$remote_archive' -C '/opt/parth/current/psy-contracts/deployments/$network' && sudo chown -R parth:parth /opt/parth/current/psy-contracts/deployments && rm -f '$remote_archive'"
  rm -f "$archive"
}

upload_l1_deployments_artifacts() {
  local network
  if multichain_enabled; then
    while IFS= read -r network; do
      upload_l1_deployment_artifacts "$network"
    done < <(jq -r '.[].deployments_network' <<<"$RELAYER_CHAINS_JSON")
  else
    upload_l1_deployment_artifacts "$RELAYER_DEPLOYMENTS_NETWORK"
  fi
}

write_relayer_config

deploy_parth_service "$NAME" "relayer" "deploy-relayer" "parth-relayer.service" \
  "RELAYER_CONFIG=$RELAYER_CONFIG" \
  "PSY_DEPLOYMENTS_DIR=${PSY_DEPLOYMENTS_DIR:-/opt/parth/current/psy-contracts/deployments}" \
  "WALLET_PASSWORD=${WALLET_PASSWORD:-}" \
  "BRIDGE_RELAYER_L2_PRIVATE_KEY=${BRIDGE_RELAYER_L2_PRIVATE_KEY:-}"

# The release symlink can change during deploy_parth_service, so write the
# deployment summary again into the final /opt/parth/current tree.
upload_l1_deployments_artifacts
write_relayer_config
run_remote_command "$NAME" "sudo systemctl restart parth-relayer.service"
run_health_check "$NAME" "systemd" "SYSTEMD_UNIT=parth-relayer.service"
