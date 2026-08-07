#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKSPACE_DIR="$(cd "${CRATE_DIR}/.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
REPORT_PATH="${WORKSPACE_DIR}/target/d04b6h20-branch-exact-setup-rf3-report.json"

cleanup() {
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans
}
trap cleanup EXIT

cleanup
docker compose -f "${COMPOSE_FILE}" up -d --wait

cd "${WORKSPACE_DIR}"
PSY_D04B6H20_RF3=1 \
PSY_D04B6H20_COMPOSE_FILE="${COMPOSE_FILE}" \
PSY_D04B6H20_REPORT_PATH="${REPORT_PATH}" \
cargo test -p psy_node_scylla \
  rollback::branch_exact_schema_setup_rf3_gate::d04b6h20_branch_exact_controlled_setup_rf3_gate \
  --lib -- --ignored --exact --nocapture

echo "D-04b6h20 RF=3 report: ${REPORT_PATH}"
