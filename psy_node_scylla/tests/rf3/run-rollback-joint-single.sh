#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

cleanup() {
  if [[ "${PSY_ROLLBACK_JOINT_KEEP_CLUSTER:-0}" != "1" ]]; then
    docker compose -f "${COMPOSE_FILE}" down --volumes --remove-orphans
  fi
}
trap cleanup EXIT

docker compose -f "${COMPOSE_FILE}" down --volumes --remove-orphans
docker compose -f "${COMPOSE_FILE}" up --detach --wait --wait-timeout 300 scylla1

cd "${WORKSPACE_ROOT}"
PSY_ROLLBACK_JOINT_SINGLE=1 \
cargo test -p psy_node_scylla --test rollback_joint_delete_scylla -- --ignored --nocapture
