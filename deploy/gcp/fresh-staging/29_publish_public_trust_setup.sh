#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

if [ "${PUBLISH_PUBLIC_TRUST_SETUP:-1}" != "1" ]; then
  log_step "skipping public Groth16 trust setup publish"
  exit 0
fi

log_step "packaging and publishing public Groth16 trust setup"
if [ "${PUBLIC_TRUST_SETUP_USE_CURRENT_KEYSTORE:-1}" = "1" ]; then
  TRUST_SETUP_SOURCE_PSY_ROOT="$(bash "$REPO_ROOT/deploy/gcp/stage-public-trust-setup.sh")"
  export TRUST_SETUP_SOURCE_PSY_ROOT
  echo "[trust-setup] staged public source from current Groth16 keystore: $TRUST_SETUP_SOURCE_PSY_ROOT"
elif [ -z "${TRUST_SETUP_SOURCE_PSY_ROOT:-}" ]; then
  echo "TRUST_SETUP_SOURCE_PSY_ROOT is required when PUBLIC_TRUST_SETUP_USE_CURRENT_KEYSTORE=0" >&2
  exit 1
fi

bash "$REPO_ROOT/deploy/gcp/publish-groth16-trust-setup.sh" --upload
