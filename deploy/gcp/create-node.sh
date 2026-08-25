#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

NAME="${NODE_VM_NAME:-parth-node-1}"
provision_vm "$NAME"
run_remote_script "$NAME" "$GCP_DIR/remote/prepare-parth-host.sh"
upload_bundle_if_configured "$NAME"

PARTH_BUNDLE_EXPECTED=0
[ -n "${PARTH_BUNDLE:-}" ] && PARTH_BUNDLE_EXPECTED=1
run_health_check "$NAME" "parth-host" "PARTH_BUNDLE_EXPECTED=$PARTH_BUNDLE_EXPECTED"
run_health_check "$NAME" "ports" \
  "HEALTHCHECK_PORTS=${NODE_HEALTHCHECK_PORTS:-}" \
  "HEALTHCHECK_HTTP_URLS=${NODE_HEALTHCHECK_HTTP_URLS:-}" \
  "HEALTHCHECK_START_DELAY=${NODE_HEALTHCHECK_START_DELAY:-0}"
