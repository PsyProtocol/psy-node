#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKSPACE_DIR="$(cd "${CRATE_DIR}/.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
REPORT_PATH="${WORKSPACE_DIR}/target/d04b6h23c4d3b2b2a-sidecar-v15-submission-rf3-report.json"

cleanup() {
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans
}
trap cleanup EXIT

cleanup
docker compose -f "${COMPOSE_FILE}" up -d --wait

cd "${WORKSPACE_DIR}"
PSY_D04B6H23C4D3B2B2A_RF3=1 \
PSY_D04B6H23C4D3B2B2A_COMPOSE_FILE="${COMPOSE_FILE}" \
PSY_D04B6H23C4D3B2B2A_REPORT_PATH="${REPORT_PATH}" \
cargo test -p psy_node_scylla \
  --features rf3-test-support \
  rollback::pending_queue_sidecar_schema_rf3::d04b6h23c4d3b2b2a_sidecar_v15_submission_rf3_gate \
  --lib -- --ignored --exact --nocapture

jq -e '
  .qualification == "H23C4D3B2B2A_SIDECAR_V15_SUBMISSION_RF3_PASSED" and
  .replication_factor == 3 and
  .historical_schema_version == 14 and
  .current_schema_version == 15 and
  .historical_target_tables == 20 and
  .target_tables == 21 and
  .lifecycle_tables == 1 and
  .control_targets == 17 and
  .data_targets == 4 and
  .expected_columns == 105 and
  .historical_schema_fingerprint == "24ad4930ef560860d82b45445b309d420b0eab2383318c26932ec49dab31b85d" and
  (.current_schema_fingerprint | test("^[0-9a-f]{64}$")) and
  .current_schema_fingerprint != .historical_schema_fingerprint and
  .v14_missing_exact_coordinator_table == true and
  .v14_verified_rejected_for_v15 == true and
  .v14_payload_rejected_by_v15_decoder == true and
  .v15_slot_differs_from_v14 == true and
  .v15_deploy_idempotent == true and
  .different_current_rejected == true and
  .v14_lifecycle_preserved == true and
  .v14_representative_rows_preserved == true and
  .coordinator_submission_exact == true and
  .coordinator_submission_same_retry == true and
  .coordinator_submission_different_conflict == true and
  .one_replica_offline_deploy_and_write == true and
  .caller_discard_retry == true and
  .socket_response_loss_injected == false and
  .no_drop_upgrade == true and
  .repair_flush_compact == true and
  .repair_ms > 0 and
  .direct_one_nodes == 3 and
  .direct_one_table_count == 7 and
  .direct_one_table_names == [
    "branch_exact_pending_queue_sidecar_lifecycle_v1",
    "branch_exact_pending_pipeline_v2",
    "branch_exact_realm_application_archive_header_v1",
    "branch_exact_realm_application_archive_fragment_v1",
    "branch_exact_realm_processor_generation_terminal_v1",
    "branch_exact_realm_processor_deferred_carryover_v1",
    "branch_exact_coordinator_guta_submission_v1"
  ] and
  .direct_one_row_count == 8 and
  (.direct_one_dataset_digest | test("^[0-9a-f]{64}$")) and
  .direct_one_equal == true and
  .sidecar_v15_rf3 == true and
  .coordinator_submission_store_rf3 == true and
  .handler_processor_rf3 == false and
  .redis_loss_recovery_rf3 == false and
  .mixed_version_activation_safe == false and
  .production_terminal_transition == false and
  .production_pipeline_rotation == false and
  .production_writer_integrated == false and
  .authority_head_publish_integrated == false and
  .full_node_restart_tested == false and
  .production_serving == false and
  .h8_domains_closed == 0 and
  .h8_domains_total == 22
' "${REPORT_PATH}" >/dev/null

echo "D-04b6h23c4d3b2b2a sidecar v15 + Coordinator submission RF=3 report: ${REPORT_PATH}"
