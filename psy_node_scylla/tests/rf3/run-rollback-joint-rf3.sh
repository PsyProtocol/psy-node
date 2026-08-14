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

cleanup
docker compose -f "${COMPOSE_FILE}" up --detach --wait --wait-timeout 300

for attempt in $(seq 1 90); do
  if [[ "$(docker exec psy-g0-02-rf3-scylla1-1 nodetool status | grep -c '^UN ')" == "3" ]]; then
    break
  fi
  if [[ "${attempt}" == "90" ]]; then
    docker exec psy-g0-02-rf3-scylla1-1 nodetool status
    echo "RF=3 cluster did not reach three Up/Normal members" >&2
    exit 1
  fi
  sleep 2
done

for keyspace in \
  psy_rollback_joint_control \
  psy_rollback_joint_control_no_tablet \
  psy_rollback_joint_control_realm_10 \
  psy_rollback_joint_control_realm_10_no_tablet \
  psy_rollback_joint_control_realm_20 \
  psy_rollback_joint_control_realm_20_no_tablet
do
  docker exec psy-g0-02-rf3-scylla1-1 cqlsh 172.29.86.11 9042 -e \
    "CREATE KEYSPACE IF NOT EXISTS ${keyspace} WITH replication = {'class': 'NetworkTopologyStrategy', 'datacenter1': 3} AND tablets = {'enabled': false}"
done

cd "${WORKSPACE_ROOT}"
PSY_ROLLBACK_JOINT_RF3=1 \
PSY_ROLLBACK_JOINT_COMPOSE_FILE="${COMPOSE_FILE}" \
RUST_MIN_STACK="${RUST_MIN_STACK:-67108864}" \
cargo test -p psy_node_scylla \
  --features rf3-test-support \
  explicit_admin_request_is_selected_by_every_production_realm_control \
  --lib -- --ignored --nocapture
