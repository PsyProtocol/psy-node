#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set in deploy/gcp/config.env}"

NAME="${POSTGRES_VM_NAME:-parth-postgres-1}"
provision_vm "$NAME"
run_remote_script "$NAME" "$GCP_DIR/remote/install-postgres.sh" \
  "POSTGRES_USER=${POSTGRES_USER:-postgres}" \
  "POSTGRES_PASSWORD=$POSTGRES_PASSWORD" \
  "POSTGRES_VERSION=${POSTGRES_VERSION:-16}"
run_health_check "$NAME" "postgres" \
  "POSTGRES_USER=${POSTGRES_USER:-postgres}" \
  "POSTGRES_PASSWORD=$POSTGRES_PASSWORD"
