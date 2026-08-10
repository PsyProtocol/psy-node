#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKSPACE_DIR="$(cd "${CRATE_DIR}/.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
REPORT_PATH="${WORKSPACE_DIR}/target/d04b6h23c4c2b3b2c2b-nonempty-terminal-source-rf3-report.json"
NATS_DIR="$(mktemp -d /tmp/psy-h23c2b-nats.XXXXXX)"

NATS1_PID=""
NATS2_PID=""
NATS3_PID=""

cleanup() {
  for pid in "${NATS1_PID}" "${NATS2_PID}" "${NATS3_PID}"; do
    if [[ -n "${pid}" ]]; then
      kill -CONT "${pid}" 2>/dev/null || true
      kill "${pid}" 2>/dev/null || true
    fi
  done
  wait "${NATS1_PID}" 2>/dev/null || true
  wait "${NATS2_PID}" 2>/dev/null || true
  wait "${NATS3_PID}" 2>/dev/null || true
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans
  rm -rf "${NATS_DIR}"
}
trap cleanup EXIT

docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans
docker compose -f "${COMPOSE_FILE}" up -d --wait

nats-server --server_name psy-h23c2b-n1 --cluster_name psy-h23c2b \
  -js -sd "${NATS_DIR}/n1" -p 45322 -m 47322 \
  --cluster nats://127.0.0.1:46322 \
  --routes nats://127.0.0.1:46323,nats://127.0.0.1:46324 \
  --connect_retries 120 >"${NATS_DIR}/n1.log" 2>&1 &
NATS1_PID=$!
nats-server --server_name psy-h23c2b-n2 --cluster_name psy-h23c2b \
  -js -sd "${NATS_DIR}/n2" -p 45323 -m 47323 \
  --cluster nats://127.0.0.1:46323 \
  --routes nats://127.0.0.1:46322,nats://127.0.0.1:46324 \
  --connect_retries 120 >"${NATS_DIR}/n2.log" 2>&1 &
NATS2_PID=$!
nats-server --server_name psy-h23c2b-n3 --cluster_name psy-h23c2b \
  -js -sd "${NATS_DIR}/n3" -p 45324 -m 47324 \
  --cluster nats://127.0.0.1:46324 \
  --routes nats://127.0.0.1:46322,nats://127.0.0.1:46323 \
  --connect_retries 120 >"${NATS_DIR}/n3.log" 2>&1 &
NATS3_PID=$!

for _ in $(seq 1 120); do
  READY=0
  curl -fsS "http://127.0.0.1:47322/healthz?js-enabled-only=true" >/dev/null && READY=$((READY + 1))
  curl -fsS "http://127.0.0.1:47323/healthz?js-enabled-only=true" >/dev/null && READY=$((READY + 1))
  curl -fsS "http://127.0.0.1:47324/healthz?js-enabled-only=true" >/dev/null && READY=$((READY + 1))
  if [[ "${READY}" -eq 3 ]]; then break; fi
  sleep 1
done
if ! curl -fsS "http://127.0.0.1:47322/healthz?js-enabled-only=true" >/dev/null \
  || ! curl -fsS "http://127.0.0.1:47323/healthz?js-enabled-only=true" >/dev/null \
  || ! curl -fsS "http://127.0.0.1:47324/healthz?js-enabled-only=true" >/dev/null; then
  sed -n '1,240p' "${NATS_DIR}/n1.log"
  sed -n '1,240p' "${NATS_DIR}/n2.log"
  sed -n '1,240p' "${NATS_DIR}/n3.log"
  exit 1
fi

cd "${WORKSPACE_DIR}"
PSY_D04B6H23C4C2B3B2C2B_RF3=1 \
PSY_D04B6H23C4C2B3B2C2B_COMPOSE_FILE="${COMPOSE_FILE}" \
PSY_D04B6H23C4C2B3B2C2B_REPORT_PATH="${REPORT_PATH}" \
PSY_D04B6H23C4C2B3B2C2B_NATS_URLS="nats://127.0.0.1:45322,nats://127.0.0.1:45323,nats://127.0.0.1:45324" \
PSY_D04B6H23C4C2B3B2C2B_NATS1_PID="${NATS1_PID}" \
PSY_D04B6H23C4C2B3B2C2B_NATS2_PID="${NATS2_PID}" \
PSY_D04B6H23C4C2B3B2C2B_NATS3_PID="${NATS3_PID}" \
RUST_MIN_STACK=67108864 \
cargo test -p psy_node_scylla \
  rollback::realm_user_update_admission_rf3::d04b6h23c4c2b3b2c2b_nonempty_terminal_source_joint_rf3 \
  --lib -- --ignored --exact --nocapture

echo "D-04b6h23c4c2b3b2c2b non-empty terminal/source RF=3 report: ${REPORT_PATH}"
