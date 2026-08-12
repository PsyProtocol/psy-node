#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
REPORT_PATH="${PSY_D04B6H23C4E2C2B2B_REPORT_PATH:-${WORKSPACE_ROOT}/target/d04b6h23c4e2c2b2b-full-commit-executor-rf3-report.json}"

cleanup() {
  if [[ "${PSY_D04B6H23C4E2C2B2B_KEEP_CLUSTER:-0}" != "1" ]]; then
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

PSY_D04B6H23C4E2C2B2B_RF3=1 \
PSY_D04B6H23C4E2C2B2B_REPORT_PATH="${REPORT_PATH}" \
cargo test -p psy_node_scylla h23c4e2c2b2b_full_commit_executor_rf3_gate --lib -- --ignored --nocapture

jq -e '
  .qualification == "H23C4E2C2B2B_FULL_COMMIT_EXECUTOR_RF3_PASSED" and
  .replication_factor == 3 and
  .full_schedule_rows == 25 and
  .full_schedule_actions == 24 and
  .partial_prefix_actions == 7 and
  .partial_restart_recovered == true and
  .caller_discard_retry == true and
  .socket_response_loss_injected == false and
  .one_replica_offline == true and
  .exact_retry_digest_equal == true and
  .repair_ms > 0 and
  .direct_one_nodes == 3 and
  .direct_one_row_count == 25 and
  (.direct_one_table_names | length) == .direct_one_table_count and
  (.direct_one_dataset_digest | test("^[0-9a-f]{64}$")) and
  .direct_one_equal == true and
  .h22_typed_composite_manifest == false and
  .manifest_persisted == false and
  .processor_writer_invocation == false and
  .production_writer_covered_domains == 0 and
  .authority_head_published == false and
  .production_serving == false and
  .h8_domains_closed == 0
' "${REPORT_PATH}" >/dev/null

echo "D-04b6h23c4e2c2b2b RF=3 report: ${REPORT_PATH}"
