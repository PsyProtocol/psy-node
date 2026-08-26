#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"
# shellcheck source=lib/groth16-setup.sh
source "$(dirname "$0")/lib/groth16-setup.sh"

NAME="${ANVIL_VM_NAME:-${NODE_VM_NAME:-gcp-cp-ce}}"
ANVIL_HOST="${ANVIL_HOST:-$(instance_internal_dns "$NAME")}"
ANVIL_PORT="${ANVIL_PORT:-8545}"
L1_RPC_URL="${L1_RPC_URL:-${ETH_RPC_URL:-http://${ANVIL_HOST}:${ANVIL_PORT}}}"
CONTRACTS_SOURCE="${L1_CONTRACTS_SOURCE:-$PARTH_DIR/psy-contracts}"
REMOTE_CONTRACTS_UPLOAD="/tmp/parth-l1-contracts"
EXPORT_GROTH16_VERIFIERS="${EXPORT_GROTH16_VERIFIERS:-1}"
GROTH16_SETUP_KEYSTORE_ROOT="${GROTH16_SETUP_KEYSTORE_ROOT:-$REPO_ROOT/dist/groth16-keystore}"
PSY_GROTH16_CLI="${PSY_GROTH16_CLI:-${PSY_RELAYER_CLI:-$PARTH_DIR/target/release/psy_relayer_cli}}"
L1_DEPLOYMENTS_NETWORK="${L1_DEPLOYMENTS_NETWORK:-${L1_NETWORK:-localhost}}"
L1_DEPLOYER_KEYSTORE_PATH="${L1_DEPLOYER_KEYSTORE_PATH:-${KEYSTORE_PATH:-}}"
L1_DEPLOYER_KEYSTORE_REMOTE_PATH="${L1_DEPLOYER_KEYSTORE_REMOTE_PATH:-/var/lib/parth/.psy/keystore/bridge-relayer-dev}"
L1_DEPLOYER_WALLET_PASSWORD="${L1_DEPLOYER_WALLET_PASSWORD:-${WALLET_PASSWORD:-}}"
if [ -z "${CHAIN_ID:-}" ]; then
  case "$L1_DEPLOYMENTS_NETWORK" in
    sepolia) CHAIN_ID="11155111" ;;
    bsc-testnet) CHAIN_ID="97" ;;
    *) CHAIN_ID="31337" ;;
  esac
fi

[ -d "$CONTRACTS_SOURCE" ] || {
  echo "missing psy-contracts source: $CONTRACTS_SOURCE" >&2
  exit 1
}

provision_vm "$NAME"

export_solidity_verifier() {
  local kind="$1"
  local output="$2"
  local required="$3"
  local keystore="$GROTH16_SETUP_KEYSTORE_ROOT/$kind"

  if [ ! -s "$keystore/vk_groth16.bin" ]; then
    if [ "$required" = "1" ]; then
      echo "missing Groth16 verifier key: $keystore/vk_groth16.bin" >&2
      echo "generate/upload setup before deploying L1 contracts: bash deploy/gcp/fresh-staging/15_upload_bridge_trust_setup.sh" >&2
      exit 1
    fi
    echo "skipping optional verifier export for $kind; missing $keystore/vk_groth16.bin"
    return 0
  fi

  groth16_setup_validate_freshness "$kind" "$keystore" "${GROTH16_SETUP_HOST:-${GROTH16_PROVE_PROXY_HOST:-${PROVE_PROXY_VM_NAME:-${NODE_VM_NAME:-gcp-cp-ce}}}}"

  [ -x "$PSY_GROTH16_CLI" ] || {
    echo "missing executable: $PSY_GROTH16_CLI; run step 04_prepare_local_bundle.sh first" >&2
    exit 1
  }
  cli_help="$("$PSY_GROTH16_CLI" --help 2>/dev/null || true)"
  case "$cli_help" in
    *export-solidity-verifier*) ;;
    *)
      echo "$PSY_GROTH16_CLI does not support export-solidity-verifier; rebuild it with: cd $PARTH_DIR && cargo build -p psy_relayer_cli --release" >&2
      exit 1
      ;;
  esac

  echo "exporting Solidity verifier from $keystore -> $output"
  "$PSY_GROTH16_CLI" export-solidity-verifier "$keystore" "$output"
}

if [ "$EXPORT_GROTH16_VERIFIERS" = "1" ]; then
  # Hardhat deploy/001_deploy_verifier.ts compiles this exact, case-sensitive path.
  export_solidity_verifier "bridge" "$CONTRACTS_SOURCE/src/GnarkGroth16Verifier.sol" 1
  export_solidity_verifier "deposit_batch_append" "$CONTRACTS_SOURCE/src/DepositBatchVerifier.sol" 1
  export_solidity_verifier "withdrawal_claim" "$CONTRACTS_SOURCE/src/WithdrawalClaimVerifier.sol" 0
fi

if [ -n "$L1_DEPLOYER_KEYSTORE_PATH" ]; then
  if [ -f "$L1_DEPLOYER_KEYSTORE_PATH" ]; then
    remote_tmp="/tmp/parth-l1-deployer-keystore"
    echo "uploading L1 deployer keystore: $L1_DEPLOYER_KEYSTORE_PATH -> ${NAME}:${L1_DEPLOYER_KEYSTORE_REMOTE_PATH}"
    scp_to_remote "$NAME" "$L1_DEPLOYER_KEYSTORE_PATH" "$remote_tmp"
    run_remote_command "$NAME" "sudo install -d -m 0750 -o parth -g parth '$(dirname "$L1_DEPLOYER_KEYSTORE_REMOTE_PATH")' && sudo install -m 0640 -o parth -g parth '$remote_tmp' '$L1_DEPLOYER_KEYSTORE_REMOTE_PATH' && rm -f '$remote_tmp'"
    L1_DEPLOYER_KEYSTORE_PATH="$L1_DEPLOYER_KEYSTORE_REMOTE_PATH"
  else
    case "$L1_DEPLOYER_KEYSTORE_PATH" in
      /var/lib/parth/*|/etc/parth/*|/opt/parth/*)
        echo "using remote L1 deployer keystore path: $L1_DEPLOYER_KEYSTORE_PATH"
        ;;
      *)
        echo "missing local L1 deployer keystore: $L1_DEPLOYER_KEYSTORE_PATH" >&2
        echo "create the file locally or set L1_DEPLOYER_KEYSTORE_PATH to an existing keystore before running step 10" >&2
        exit 1
        ;;
    esac
  fi
fi

echo "uploading L1 contracts source with rsync --checksum: ${CONTRACTS_SOURCE} -> ${NAME}:${REMOTE_CONTRACTS_UPLOAD}"
command -v rsync >/dev/null 2>&1 || {
  echo "local rsync is required for L1 contracts upload" >&2
  exit 1
}
run_remote_command "$NAME" "command -v rsync >/dev/null 2>&1 || sudo env DEBIAN_FRONTEND=noninteractive sh -lc 'apt-get update && apt-get install -y rsync'" >/dev/null
run_remote_command "$NAME" "rm -rf '$REMOTE_CONTRACTS_UPLOAD'"
rsync -az --checksum --human-readable --progress \
  --exclude node_modules \
  --exclude cache \
  --exclude artifacts \
  --exclude deployments \
  "$CONTRACTS_SOURCE/" \
  "${NAME}:${REMOTE_CONTRACTS_UPLOAD}/"

run_remote_script "$NAME" "$GCP_DIR/remote/deploy-l1-contracts.sh" \
  "L1_CONTRACTS_UPLOAD=$REMOTE_CONTRACTS_UPLOAD" \
  "L1_CONTRACTS_HOME=${L1_CONTRACTS_HOME:-/opt/parth/l1-contracts/current}" \
  "L1_RPC_URL=$L1_RPC_URL" \
  "CHAIN_ID=$CHAIN_ID" \
  "L1_DEPLOYMENTS_NETWORK=$L1_DEPLOYMENTS_NETWORK" \
  "L1_DEPLOYER_PRIVATE_KEY=${L1_DEPLOYER_PRIVATE_KEY:-}" \
  "L1_DEPLOYER_KEYSTORE_PATH=$L1_DEPLOYER_KEYSTORE_PATH" \
  "L1_DEPLOYER_WALLET_PASSWORD=$L1_DEPLOYER_WALLET_PASSWORD" \
  "L1_DEPLOY_RESET=${L1_DEPLOY_RESET:-1}"
