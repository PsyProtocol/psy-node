#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BUNDLE_BUILDER="$ROOT/deploy/gcp/build-parth-bundle.sh"

validate_profile() {
  local profile="$1"
  local versions_file="$ROOT/deploy/$profile/gcp/source-versions.env"
  local config_example="$ROOT/deploy/$profile/gcp/config.example.env"
  local variable value

  bash -n "$versions_file"
  # shellcheck disable=SC1090
  source "$versions_file"

  for variable in \
    EXPECTED_PARTH_RUNTIME_REPOSITORY \
    EXPECTED_PSY_GENESIS_REPOSITORY \
    EXPECTED_PSY_CONTRACTS_REPOSITORY \
    EXPECTED_PSY_DAPP_REPOSITORY \
    EXPECTED_PSY_SERVICES_REPOSITORY \
    EXPECTED_PSY_WALLET_REPOSITORY \
    EXPECTED_PSY_SDK_REPOSITORY
  do
    value="${!variable}"
    [[ "$value" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
      echo "invalid $profile repository pin $variable=$value" >&2
      exit 1
    }
  done

  for variable in \
    EXPECTED_PARTH_RUNTIME_COMMIT \
    EXPECTED_PSY_GENESIS_COMMIT \
    EXPECTED_PSY_CONTRACTS_COMMIT \
    EXPECTED_PSY_DAPP_COMMIT \
    EXPECTED_PSY_SERVICES_COMMIT \
    EXPECTED_PSY_WALLET_COMMIT \
    EXPECTED_PSY_SDK_COMMIT
  do
    value="${!variable}"
    [[ "$value" =~ ^[0-9a-f]{40}$ ]] || {
      echo "invalid $profile commit pin $variable=$value" >&2
      exit 1
    }
  done

  [[ "$EXPECTED_GENESIS_CONTRACTS_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
    echo "invalid $profile Genesis contract checksum" >&2
    exit 1
  }

  if grep -Eq '^EXPECTED_(PARTH_RUNTIME|PSY_GENESIS|PSY_CONTRACTS|PSY_DAPP|PSY_SERVICES|PSY_WALLET|PSY_SDK)_(REPOSITORY|COMMIT)=' \
    "$config_example"; then
    echo "repository pins must not be duplicated in $profile config.example.env" >&2
    exit 1
  fi
}

validate_profile ethereum-sepolia
validate_profile bsc-testnet
validate_profile multi-chain

grep -Fq 'PSY_SERVICES_REPOSITORY=$EXPECTED_PSY_SERVICES_REPOSITORY' "$BUNDLE_BUILDER" || {
  echo "bundle manifest must record the psy-services repository" >&2
  exit 1
}

grep -Fq 'PSY_SERVICES_COMMIT=$(source_commit "$psy_services_dir")' "$BUNDLE_BUILDER" || {
  echo "bundle manifest must record the actual psy-services source commit" >&2
  exit 1
}

echo "[ok] deployment network profiles have independent source manifests"
