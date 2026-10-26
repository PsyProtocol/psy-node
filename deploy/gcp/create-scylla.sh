#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

NAME="${SCYLLA_VM_NAME:-parth-scylla-1}"
provision_vm "$NAME"
run_remote_script "$NAME" "$GCP_DIR/remote/install-scylla.sh" \
  "SCYLLA_SMP=${SCYLLA_SMP:-4}" \
  "SCYLLA_IMAGE=${SCYLLA_IMAGE:-scylladb/scylla:latest}" \
  "SCYLLA_MEMORY=${SCYLLA_MEMORY:-28g}" \
  "SCYLLA_DOCKER_MEMORY=${SCYLLA_DOCKER_MEMORY:-${SCYLLA_MEMORY:-28g}}"
run_health_check "$NAME" "scylla" \
  "HEALTHCHECK_ATTEMPTS=${SCYLLA_HEALTHCHECK_ATTEMPTS:-120}" \
  "HEALTHCHECK_DELAY=${SCYLLA_HEALTHCHECK_DELAY:-5}" \
  "HEALTHCHECK_START_DELAY=${SCYLLA_HEALTHCHECK_START_DELAY:-20}"
