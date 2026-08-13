#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKSPACE_DIR="$(cd "${CRATE_DIR}/.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
REPORT_PATH="${WORKSPACE_DIR}/target/d1a08-coordinator-archive-rf3-report.json"

cleanup() {
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans
}
trap cleanup EXIT

cleanup
docker compose -f "${COMPOSE_FILE}" up -d --wait

cd "${WORKSPACE_DIR}"
PSY_D1A08_RF3=1 \
PSY_D1A08_COMPOSE_FILE="${COMPOSE_FILE}" \
PSY_D1A08_REPORT_PATH="${REPORT_PATH}" \
cargo test -p psy_node_scylla \
  --features rf3-test-support \
  rollback::coordinator_rollback_archive_rf3::d1a08_coordinator_archive_rf3_gate \
  --lib -- --ignored --exact --nocapture

jq -e '
  .qualification == "D1A08_COORDINATOR_SUFFIX_ARCHIVE_RF3_PASSED" and
  .replication_factor == 3 and
  .checkpoint_archive_rows == 12 and
  .mapping_archive_rows == 12 and
  .reward_archive_rows == 3 and
  .archive_fragment_rows == 27 and
  .caller_discard_retry == true and
  .socket_response_loss_injected == false and
  .one_replica_offline_archive == true and
  .source_rows_preserved == true and
  .canonical_head_unchanged_during_archive == true and
  .archive_rerun_idempotent == true and
  .repair_flush_compact == true and
  .repair_ms > 0 and
  .direct_one_nodes == 3 and
  .direct_one_tables == 11 and
  .direct_one_rows == 57 and
  (.direct_one_dataset_digest | test("^[0-9a-f]{64}$")) and
  .direct_one_equal == true and
  .participant_archive_receipt == false and
  .global_archive_barrier == false and
  .destructive_started == false and
  .hot_suffix_deleted == false and
  .target_restored == false and
  .new_branch_t_plus_1 == false and
  .production_rollback_available == false
' "${REPORT_PATH}" >/dev/null

echo "D1-A08 Coordinator suffix archive RF=3 report: ${REPORT_PATH}"
