#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

PROVE_PROXY_INSTANCE="${PROVE_PROXY_INSTANCE:-1}"
NAME="${PROVE_PROXY_VM_NAME:-parth-prove-proxy-${PROVE_PROXY_INSTANCE}}"
provision_vm "$NAME"
run_remote_script "$NAME" "$GCP_DIR/remote/prepare-parth-host.sh"
upload_bundle_if_configured "$NAME"

PARTH_BUNDLE_EXPECTED=0
[ -n "${PARTH_BUNDLE:-}" ] && PARTH_BUNDLE_EXPECTED=1
run_health_check "$NAME" "parth-host" "PARTH_BUNDLE_EXPECTED=$PARTH_BUNDLE_EXPECTED"
run_health_check "$NAME" "ports" \
  "HEALTHCHECK_PORTS=${PROVE_PROXY_CREATE_HEALTHCHECK_PORTS:-}" \
  "HEALTHCHECK_HTTP_URLS=${PROVE_PROXY_CREATE_HEALTHCHECK_HTTP_URLS:-}" \
  "HEALTHCHECK_START_DELAY=${PROVE_PROXY_CREATE_HEALTHCHECK_START_DELAY:-0}"
