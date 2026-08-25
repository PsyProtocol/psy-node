#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

require_cmd jq
require_cmd sha256sum

EXPECTED_GENESIS_USER_COUNT="${EXPECTED_GENESIS_USER_COUNT:-14}"
EXPECTED_BRIDGE_RELAYER_KEY_INDEX="${EXPECTED_BRIDGE_RELAYER_KEY_INDEX:-2}"
EXPECTED_FAUCET_OPERATOR_START_INDEX="${EXPECTED_FAUCET_OPERATOR_START_INDEX:-4}"
EXPECTED_FAUCET_OPERATOR_COUNT="${EXPECTED_FAUCET_OPERATOR_COUNT:-10}"
EXPECTED_GENESIS_ZK_FINGERPRINT="${EXPECTED_GENESIS_ZK_FINGERPRINT:-65e0169bfffd55f1c0ea9f76c111a5b15e652322ee253c1a9604a10d59066b50}"
EXPECTED_GENESIS_SDK_KEY_FINGERPRINT="${EXPECTED_GENESIS_SDK_KEY_FINGERPRINT:-38755910c4dfb3c9bef528a4af697edced7e2607a6b769d054c4985a7000f0eb}"
EXPECTED_GENESIS_RESERVED_SLOT_VALUE="${EXPECTED_GENESIS_RESERVED_SLOT_VALUE:-0000000000000000000000000000000000000000000000000000000000000000}"
EXPECTED_GENESIS_RELAYER_SLOT_VALUE="${EXPECTED_GENESIS_RELAYER_SLOT_VALUE:-00000000000000000000000000000000000000000000000000038d7ea4c68000}"
EXPECTED_GENESIS_FAUCET_OPERATOR_SLOT_VALUE="${EXPECTED_GENESIS_FAUCET_OPERATOR_SLOT_VALUE:-000000000000000000000000000000000000000000000000016345785d8a0000}"
EXPECTED_GENESIS_LAST_FAUCET_OPERATOR_SLOT_VALUE="${EXPECTED_GENESIS_LAST_FAUCET_OPERATOR_SLOT_VALUE:-000000000000000000000000000000000000000000000000015fb7f9b8c38000}"
EXPECTED_GENESIS_EMPTY_SLOT_VALUE="${EXPECTED_GENESIS_EMPTY_SLOT_VALUE:-0000000000000000000000000000000000000000000000000000000000000000}"
EXPECTED_GENESIS_TOTAL_SUPPLY_NANO="${EXPECTED_GENESIS_TOTAL_SUPPLY_NANO:-1000000000000000000}"
REWRITE_GENESIS_WALLET_ALLOCATION="${REWRITE_GENESIS_WALLET_ALLOCATION:-1}"
: "${EXPECTED_GENESIS_CONTRACTS_SHA256:?missing from deploy/source-versions.env}"
: "${EXPECTED_PARTH_RUNTIME_COMMIT:?missing from deploy/source-versions.env}"
: "${EXPECTED_PSY_GENESIS_REPOSITORY:?missing from deploy/source-versions.env}"
: "${EXPECTED_PSY_GENESIS_COMMIT:?missing from deploy/source-versions.env}"
PSY_GENESIS_DIR="${PSY_GENESIS_DIR:-$PARTH_DIR/psy-genesis}"

# shellcheck source=../lib/genesis-wallet-allocation.sh
source "$GCP_DIR/lib/genesis-wallet-allocation.sh"
# shellcheck source=../../scripts/lib/build-parallelism.sh
source "$PARTH_DIR/deploy/scripts/lib/build-parallelism.sh"

verify_genesis_contracts_artifact() {
  local artifact="$1"
  local actual_sha256

  actual_sha256="$(sha256sum "$artifact" | awk '{print $1}')"
  [ "$actual_sha256" = "$EXPECTED_GENESIS_CONTRACTS_SHA256" ] || {
    cat >&2 <<EOF
genesis_contracts.json checksum mismatch.
Expected compiler artifact: ${EXPECTED_GENESIS_CONTRACTS_SHA256}
Actual artifact:            ${actual_sha256}
Path:                       ${artifact}

Refusing to build a network from unverified contract bytecode.
EOF
    exit 1
  }
  log_step "verified genesis contracts artifact: $actual_sha256"
}

if [ "${REGENERATE_GENESIS:-0}" = "1" ]; then
  log_step "regenerating genesis users and private keys from canonical psy-genesis contracts"
  if [ -n "${BRIDGE_RELAYER_L2_PRIVATE_KEY:-}" ]; then
    log_step "using BRIDGE_RELAYER_L2_PRIVATE_KEY for genesis user index 2"
  elif [ -n "${RELAYER_L2_KEYSTORE_PATH:-}" ]; then
    log_step "using RELAYER_L2_KEYSTORE_PATH for genesis user index 2"
  else
    log_step "using the deterministic genesis key for relayer user index 2"
  fi
  bash "$PARTH_DIR/deploy/scripts/ensure-genesis-contracts.sh"
  genesis_build_jobs="$(resolve_rust_build_jobs "${GENESIS_BUILD_JOBS:-}")"
  log_step "generating genesis users with $genesis_build_jobs parallel Cargo jobs"
  (
    cd "$PARTH_DIR"
    CARGO_BUILD_JOBS="$genesis_build_jobs" \
      CARGO_PROFILE_RELEASE_PACKAGE_PSY_PLONKY2_CIRCUITS_OPT_LEVEL="${GENESIS_BUILD_OPT_LEVEL:-0}" \
      CARGO_PROFILE_RELEASE_PACKAGE_PSY_PLONKY2_CIRCUITS_CODEGEN_UNITS="${GENESIS_BUILD_CODEGEN_UNITS:-256}" \
      make generate-genesis-data
  )
else
  bash "$PARTH_DIR/deploy/scripts/ensure-genesis-contracts.sh"
fi

verify_genesis_contracts_artifact "$PSY_GENESIS_DIR/genesis_contracts.json"

log_step "verifying local genesis and private keys"
[ -f "$PARTH_DIR/private_keys.json" ] || {
  echo "missing $PARTH_DIR/private_keys.json; run REGENERATE_GENESIS=1 $0 or make generate-genesis-data" >&2
  exit 1
}
[ -f "$PARTH_DIR/genesis.json" ] || {
  echo "missing $PARTH_DIR/genesis.json; run REGENERATE_GENESIS=1 $0 or make generate-genesis-data" >&2
  exit 1
}
[ -s "$PSY_GENESIS_DIR/genesis_contracts.json" ] || {
  echo "missing canonical $PSY_GENESIS_DIR/genesis_contracts.json" >&2
  exit 1
}

private_key_count="$(jq 'length' "$PARTH_DIR/private_keys.json")"
genesis_user_count="$(jq '.users | length' "$PARTH_DIR/genesis.json")"
[ "$private_key_count" = "$EXPECTED_GENESIS_USER_COUNT" ] || {
  echo "expected $EXPECTED_GENESIS_USER_COUNT private keys, got $private_key_count" >&2
  exit 1
}
[ "$genesis_user_count" = "$EXPECTED_GENESIS_USER_COUNT" ] || {
  echo "expected $EXPECTED_GENESIS_USER_COUNT genesis users, got $genesis_user_count" >&2
  exit 1
}
jq -e 'all(.[]; type == "string" and test("^[0-9a-fA-F]{64}$"))' "$PARTH_DIR/private_keys.json" >/dev/null
if [ -n "${BRIDGE_RELAYER_L2_PRIVATE_KEY:-}" ]; then
  expected_relayer_key="$(printf '%s' "$BRIDGE_RELAYER_L2_PRIVATE_KEY" | tr '[:upper:]' '[:lower:]')"
  generated_relayer_key="$(
    jq -er --argjson index "$EXPECTED_BRIDGE_RELAYER_KEY_INDEX" \
      '.[$index] | select(type == "string") | ascii_downcase' \
      "$PARTH_DIR/private_keys.json"
  )"
  [ "$generated_relayer_key" = "$expected_relayer_key" ] || {
    echo "genesis relayer private key does not match BRIDGE_RELAYER_L2_PRIVATE_KEY" >&2
    exit 1
  }
  log_step "verified configured relayer key at genesis user index $EXPECTED_BRIDGE_RELAYER_KEY_INDEX"
fi
if [ "$REWRITE_GENESIS_WALLET_ALLOCATION" = "1" ]; then
  log_step "rewriting genesis wallet allocation"
  apply_genesis_wallet_allocation "$PARTH_DIR/genesis.json"
fi
verify_genesis_wallet_allocation "$PARTH_DIR/genesis.json" "local genesis.json"

if [ "${SKIP_BINARY_BUILD:-0}" != "1" ]; then
  log_step "building Linux release artifacts, packaging deploy artifacts, and building bundle"
  PACKAGE_ARTIFACTS=1 BUILD_PARTH_BUNDLE=1 \
    bash "$PARTH_DIR/deploy/scripts/build-linux-artifacts-bookworm.sh"
else
  log_step "SKIP_BINARY_BUILD=1; refreshing deploy artifacts from existing release binaries"
  bash "$PARTH_DIR/deploy/scripts/package-local-artifacts.sh"

  log_step "building Parth node bundle"
  bash "$GCP_DIR/build-parth-bundle.sh"
fi

log_step "verifying bundle contents"
bundle="${PARTH_BUNDLE:-$REPO_ROOT/dist/parth-node-bundle.tar.gz}"
[ -f "$bundle" ] || {
  echo "missing bundle: $bundle" >&2
  exit 1
}
bundle_genesis="$(mktemp)"
bundle_manifest="$(mktemp)"
trap 'rm -f "$bundle_genesis" "$bundle_manifest"' EXIT
tar -xOf "$bundle" ./genesis.json > "$bundle_genesis"
tar -xOf "$bundle" ./BUILD-MANIFEST.env > "$bundle_manifest"
[ "$(jq '.users | length' "$bundle_genesis")" = "$EXPECTED_GENESIS_USER_COUNT" ] || {
  echo "bundle genesis does not contain $EXPECTED_GENESIS_USER_COUNT users" >&2
  exit 1
}
verify_genesis_wallet_allocation "$bundle_genesis" "bundle genesis.json"
[ "$(sha256sum "$bundle_genesis" | awk '{print $1}')" = "$(sha256sum "$PARTH_DIR/genesis.json" | awk '{print $1}')" ] || {
  echo "bundle genesis.json differs from the verified local genesis.json" >&2
  exit 1
}
grep -Fx "REQUIRED_PARTH_RUNTIME_COMMIT=$EXPECTED_PARTH_RUNTIME_COMMIT" "$bundle_manifest" >/dev/null || {
  echo "bundle manifest does not identify the required Parth runtime commit" >&2
  cat "$bundle_manifest" >&2
  exit 1
}
grep -Fx "PSY_GENESIS_REPOSITORY=$EXPECTED_PSY_GENESIS_REPOSITORY" "$bundle_manifest" >/dev/null || {
  echo "bundle manifest does not identify the required psy-genesis repository" >&2
  cat "$bundle_manifest" >&2
  exit 1
}
grep -Fx "PSY_GENESIS_COMMIT=$EXPECTED_PSY_GENESIS_COMMIT" "$bundle_manifest" >/dev/null || {
  echo "bundle manifest does not identify the required psy-genesis commit" >&2
  cat "$bundle_manifest" >&2
  exit 1
}
grep -Fx "GENESIS_CONTRACTS_SHA256=$(sha256sum "$PSY_GENESIS_DIR/genesis_contracts.json" | awk '{print $1}')" "$bundle_manifest" >/dev/null || {
  echo "bundle manifest genesis_contracts.json hash mismatch" >&2
  exit 1
}
cat "$bundle_manifest"
tar -xOf "$bundle" ./client_prover/config.json | jq '.networks.localhost.realm_configs'
du -h "$bundle"
