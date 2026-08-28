#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VERSIONS_FILE="$ROOT/deploy/source-versions.env"
CONFIG_EXAMPLE="$ROOT/deploy/gcp/config.example.env"
BUNDLE_BUILDER="$ROOT/deploy/gcp/build-parth-bundle.sh"

bash -n "$VERSIONS_FILE"
# shellcheck disable=SC1090
source "$VERSIONS_FILE"

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
    echo "invalid repository pin $variable=$value" >&2
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
    echo "invalid commit pin $variable=$value" >&2
    exit 1
  }
done

[[ "$EXPECTED_GENESIS_CONTRACTS_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
  echo "invalid Genesis contract checksum" >&2
  exit 1
}

if grep -Eq '^EXPECTED_(PARTH_RUNTIME|PSY_GENESIS|PSY_CONTRACTS|PSY_DAPP|PSY_SERVICES|PSY_WALLET|PSY_SDK)_(REPOSITORY|COMMIT)=' \
  "$CONFIG_EXAMPLE"; then
  echo "repository pins must not be duplicated in config.example.env" >&2
  exit 1
fi

grep -Fq 'PSY_SERVICES_REPOSITORY=$EXPECTED_PSY_SERVICES_REPOSITORY' "$BUNDLE_BUILDER" || {
  echo "bundle manifest must record the psy-services repository" >&2
  exit 1
}

grep -Fq 'PSY_SERVICES_COMMIT=$(source_commit "$psy_services_dir")' "$BUNDLE_BUILDER" || {
  echo "bundle manifest must record the actual psy-services source commit" >&2
  exit 1
}

echo "[ok] deployment repository pins have one authoritative source"
