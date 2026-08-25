#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

if [ "${L1_DEPLOYMENTS_NETWORK:-localhost}" != "localhost" ] && [ "${CHAIN_ID:-}" != "31337" ]; then
  log_step "skipping Anvil for L1_DEPLOYMENTS_NETWORK=${L1_DEPLOYMENTS_NETWORK:-} CHAIN_ID=${CHAIN_ID:-}"
  exit 0
fi

run_gcp_script create-anvil.sh
