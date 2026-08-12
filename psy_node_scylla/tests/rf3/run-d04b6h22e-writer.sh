#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKSPACE_DIR="$(cd "${CRATE_DIR}/.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
REPORT_PATH="${WORKSPACE_DIR}/target/d04b6h22e-branch-exact-writer-rf3-report.json"

cleanup() {
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans
}
trap cleanup EXIT

cleanup
docker compose -f "${COMPOSE_FILE}" up -d --wait

cd "${WORKSPACE_DIR}"
PSY_D04B6H22E_RF3=1 \
PSY_D04B6H22E_COMPOSE_FILE="${COMPOSE_FILE}" \
PSY_D04B6H22E_REPORT_PATH="${REPORT_PATH}" \
cargo test -p psy_node_scylla \
  rollback::branch_exact_writer_rf3_gate::d04b6h22e_branch_exact_writer_rf3_gate \
  --lib -- --ignored --exact --nocapture

jq -e '
  .qualification == "PASS" and
  .full_commit_manifest_qualification == "H23C4E2C3C2_REALM_FULL_COMMIT_MANIFEST_RF3_PASSED" and
  .replication_factor == 3 and
  .one_replica_offline == true and
  .full_commit_manifest_missing_source_rejected == true and
  .full_commit_manifest_persisted == true and
  .full_commit_manifest_retry_bit_exact == true and
  .full_commit_typed_rows > 0 and
  .full_commit_total_mutations == (.full_commit_typed_rows + .dual_write_mutations) and
  (.full_commit_manifest_digest | test("^[0-9a-f]{64}$")) and
  .qualification_cutover_fence == true and
  .production_processor_invocation == false and
  .production_writer_covered_domains == 0 and
  .repair_direct_one_equal == true and
  .repair_ms > 0
' "${REPORT_PATH}" >/dev/null

echo "D-04b6h22e writer RF=3 report: ${REPORT_PATH}"
