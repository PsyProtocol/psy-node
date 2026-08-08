#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKSPACE_DIR="$(cd "${CRATE_DIR}/.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
REPORT_PATH="${WORKSPACE_DIR}/target/d04b6h22e2-consumer-gate-rf3-report.json"
NATS_DIR="$(mktemp -d /tmp/psy-h22e2-nats.XXXXXX)"

NATS1_PID=""
NATS2_PID=""
NATS3_PID=""

cleanup() {
  if [[ -n "${NATS1_PID}" ]]; then kill "${NATS1_PID}" 2>/dev/null || true; fi
  if [[ -n "${NATS2_PID}" ]]; then kill "${NATS2_PID}" 2>/dev/null || true; fi
  if [[ -n "${NATS3_PID}" ]]; then kill "${NATS3_PID}" 2>/dev/null || true; fi
  wait "${NATS1_PID}" 2>/dev/null || true
  wait "${NATS2_PID}" 2>/dev/null || true
  wait "${NATS3_PID}" 2>/dev/null || true
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans
}
trap cleanup EXIT

docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans
docker compose -f "${COMPOSE_FILE}" up -d --wait

nats-server --server_name psy-h22e-n1 --cluster_name psy-h22e \
  -js -sd "${NATS_DIR}/n1" -p 45222 -m 47222 \
  --cluster nats://127.0.0.1:46222 \
  --routes nats://127.0.0.1:46223,nats://127.0.0.1:46224 \
  --connect_retries 120 >"${NATS_DIR}/n1.log" 2>&1 &
NATS1_PID=$!
nats-server --server_name psy-h22e-n2 --cluster_name psy-h22e \
  -js -sd "${NATS_DIR}/n2" -p 45223 -m 47223 \
  --cluster nats://127.0.0.1:46223 \
  --routes nats://127.0.0.1:46222,nats://127.0.0.1:46224 \
  --connect_retries 120 >"${NATS_DIR}/n2.log" 2>&1 &
NATS2_PID=$!
nats-server --server_name psy-h22e-n3 --cluster_name psy-h22e \
  -js -sd "${NATS_DIR}/n3" -p 45224 -m 47224 \
  --cluster nats://127.0.0.1:46224 \
  --routes nats://127.0.0.1:46222,nats://127.0.0.1:46223 \
  --connect_retries 120 >"${NATS_DIR}/n3.log" 2>&1 &
NATS3_PID=$!

for _ in $(seq 1 120); do
  READY=0
  curl -fsS "http://127.0.0.1:47222/healthz?js-enabled-only=true" >/dev/null && READY=$((READY + 1))
  curl -fsS "http://127.0.0.1:47223/healthz?js-enabled-only=true" >/dev/null && READY=$((READY + 1))
  curl -fsS "http://127.0.0.1:47224/healthz?js-enabled-only=true" >/dev/null && READY=$((READY + 1))
  if [[ "${READY}" -eq 3 ]]; then break; fi
  sleep 1
done
if ! curl -fsS "http://127.0.0.1:47222/healthz?js-enabled-only=true" >/dev/null \
  || ! curl -fsS "http://127.0.0.1:47223/healthz?js-enabled-only=true" >/dev/null \
  || ! curl -fsS "http://127.0.0.1:47224/healthz?js-enabled-only=true" >/dev/null; then
  sed -n '1,240p' "${NATS_DIR}/n1.log"
  sed -n '1,240p' "${NATS_DIR}/n2.log"
  sed -n '1,240p' "${NATS_DIR}/n3.log"
  exit 1
fi

cd "${WORKSPACE_DIR}"
PSY_D04B6H22E2_RF3=1 \
PSY_D04B6H22E2_COMPOSE_FILE="${COMPOSE_FILE}" \
PSY_D04B6H22E2_REPORT_PATH="${REPORT_PATH}" \
PSY_D04B6H22E2_NATS_URLS="nats://127.0.0.1:45222,nats://127.0.0.1:45223,nats://127.0.0.1:45224" \
PSY_D04B6H22E2_NATS1_PID="${NATS1_PID}" \
PSY_D04B6H22E2_NATS2_PID="${NATS2_PID}" \
PSY_D04B6H22E2_NATS3_PID="${NATS3_PID}" \
cargo test -p psy_node_scylla \
  rollback::pending_queue_consumer_gate_rf3::d04b6h22e2_consumer_gate_joint_rf3 \
  --lib -- --ignored --exact --nocapture

echo "D-04b6h22e2 consumer Gate RF=3 report: ${REPORT_PATH}"
