#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKSPACE_DIR="$(cd "${CRATE_DIR}/.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
REPORT_PATH="${WORKSPACE_DIR}/target/d04b6h23c4e2c3c2a-sidecar-v17-rf3-report.json"

cleanup() {
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans
}
trap cleanup EXIT

cleanup
docker compose -f "${COMPOSE_FILE}" up -d --wait

cd "${WORKSPACE_DIR}"
PSY_D04B6H23C4E2C3C2A_RF3=1 \
PSY_D04B6H23C4E2C3C2A_COMPOSE_FILE="${COMPOSE_FILE}" \
PSY_D04B6H23C4E2C3C2A_REPORT_PATH="${REPORT_PATH}" \
cargo test -p psy_node_scylla --features rf3-test-support \
  rollback::pending_queue_sidecar_schema_rf3::d04b6h23c4e2c3c2a_sidecar_v17_lifecycle_rf3_gate \
  --lib -- --ignored --exact --nocapture

jq -e '
  .qualification == "H23C4E2C3C2A_SIDECAR_V17_RF3_PASSED" and
  .replication_factor == 3 and
  .historical_schema_version == 16 and
  .current_schema_version == 17 and
  .historical_target_tables == 21 and
  .target_tables == 22 and
  .lifecycle_tables == 1 and
  .control_targets == 18 and
  .data_targets == 4 and
  .expected_columns == 108 and
  .v16_missing_exact_manifest_table == true and
  .v16_verified_rejected_for_v17 == true and
  .v16_payload_rejected_by_v17_decoder == true and
  .v17_slot_differs_from_v16 == true and
  .v17_deploy_idempotent == true and
  .different_current_rejected == true and
  .v16_lifecycle_preserved == true and
  .v16_representative_rows_preserved == true and
  .coordinator_submission_preserved == true and
  .manifest_table_added_without_drop == true and
  .one_replica_offline_deploy == true and
  .caller_discard_retry == true and
  .socket_response_loss_injected == false and
  .repair_flush_compact == true and
  .repair_ms > 0 and
  .direct_one_nodes == 3 and
  .direct_one_table_count == 7 and
  .direct_one_row_count == 8 and
  (.direct_one_dataset_digest | test("^[0-9a-f]{64}$")) and
  .direct_one_equal == true and
  .sidecar_v17_rf3 == true and
  .full_commit_manifest_data_rf3_in_this_gate == false and
  .production_processor_invocation == false and
  .production_terminal_transition == false and
  .production_pipeline_rotation == false and
  .authority_head_publish_integrated == false and
  .full_node_restart_tested == false and
  .production_serving == false and
  .h8_domains_closed == 0 and
  .h8_domains_total == 22
' "${REPORT_PATH}" >/dev/null

echo "D-04b6h23c4e2c3c2a sidecar v17 RF=3 report: ${REPORT_PATH}"
