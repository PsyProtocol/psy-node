#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

NAME="${REDIS_VM_NAME:-parth-redis-1}"
provision_vm "$NAME"
run_remote_script "$NAME" "$GCP_DIR/remote/install-valkey.sh" \
  "VALKEY_MAXMEMORY=${VALKEY_MAXMEMORY:-24gb}" \
  "VALKEY_MAXMEMORY_POLICY=${VALKEY_MAXMEMORY_POLICY:-noeviction}" \
  "VALKEY_APPENDONLY=${VALKEY_APPENDONLY:-yes}" \
  "VALKEY_APPENDONLY_FSYNC=${VALKEY_APPENDONLY_FSYNC:-everysec}" \
  "VALKEY_AUTO_AOF_REWRITE_PERCENTAGE=${VALKEY_AUTO_AOF_REWRITE_PERCENTAGE:-100}" \
  "VALKEY_AUTO_AOF_REWRITE_MIN_SIZE=${VALKEY_AUTO_AOF_REWRITE_MIN_SIZE:-64mb}" \
  "VALKEY_OVERCOMMIT_MEMORY=${VALKEY_OVERCOMMIT_MEMORY:-1}"
run_health_check "$NAME" "valkey"
