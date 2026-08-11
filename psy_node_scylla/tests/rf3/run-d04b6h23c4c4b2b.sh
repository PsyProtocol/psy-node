#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKSPACE_DIR="$(cd "${CRATE_DIR}/.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
REPORT_PATH="${WORKSPACE_DIR}/target/d04b6h23c4c4b2b-terminal-carryover-rf3-report.json"

cleanup() {
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans
}
trap cleanup EXIT

cleanup
docker compose -f "${COMPOSE_FILE}" up -d --wait

cd "${WORKSPACE_DIR}"
PSY_D04B6H23C4C4B2B_RF3=1 \
PSY_D04B6H23C4C4B2B_COMPOSE_FILE="${COMPOSE_FILE}" \
PSY_D04B6H23C4C4B2B_REPORT_PATH="${REPORT_PATH}" \
cargo test -p psy_node_scylla \
  --features rf3-test-support \
  rollback::realm_processor_terminal_carryover_rf3::d04b6h23c4c4b2b_terminal_carryover_rf3_gate \
  --lib -- --ignored --exact --nocapture

echo "D-04b6h23c4c4b2b terminal/carryover RF=3 report: ${REPORT_PATH}"
