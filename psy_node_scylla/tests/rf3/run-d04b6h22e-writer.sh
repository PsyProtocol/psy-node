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

echo "D-04b6h22e writer RF=3 report: ${REPORT_PATH}"
