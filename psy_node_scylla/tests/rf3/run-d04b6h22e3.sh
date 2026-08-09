#!/usr/bin/env bash
set -euo pipefail

# Keep CI/agent logs deterministic and avoid Docker's TTY progress renderer
# obscuring the actual Rust test failure.
export COMPOSE_PROGRESS=plain

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKSPACE_DIR="$(cd "${CRATE_DIR}/.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
REPORT_PATH="${WORKSPACE_DIR}/target/d04b6h22e3-cutover-rf3-report.json"

cleanup() {
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans
}
trap cleanup EXIT

cleanup
docker compose -f "${COMPOSE_FILE}" up -d --wait

cd "${WORKSPACE_DIR}"
PSY_D04B6H22E3_RF3=1 \
PSY_D04B6H22E3_COMPOSE_FILE="${COMPOSE_FILE}" \
PSY_D04B6H22E3_REPORT_PATH="${REPORT_PATH}" \
RUST_MIN_STACK=67108864 \
cargo test -p psy_node_scylla \
  rollback::branch_exact_cutover_rf3::d04b6h22e3_cutover_rf3_gate \
  --lib -- --ignored --exact --nocapture

echo "D-04b6h22e3 cutover RF=3 report: ${REPORT_PATH}"
