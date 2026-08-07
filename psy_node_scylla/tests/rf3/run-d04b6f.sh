#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
REPORT_PATH="${PSY_D04B6F_REPORT_PATH:-${WORKSPACE_ROOT}/target/d04b6f-realm-imt-predecessor-rf3-report.json}"

cleanup() {
  if [[ "${PSY_D04B6F_KEEP_CLUSTER:-0}" != "1" ]]; then
    docker compose -f "${COMPOSE_FILE}" down --volumes --remove-orphans
  fi
}
trap cleanup EXIT

docker compose -f "${COMPOSE_FILE}" down --volumes --remove-orphans
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

mkdir -p "$(dirname "${REPORT_PATH}")"
cd "${WORKSPACE_ROOT}"

PSY_D04B6F_RF3=1 \
PSY_D04B6F_REPORT_PATH="${REPORT_PATH}" \
cargo test -p psy_node_scylla d04b6f_realm_imt_predecessor_rf3_gate --lib -- --ignored --nocapture

echo "D-04b6f RF=3 report: ${REPORT_PATH}"
