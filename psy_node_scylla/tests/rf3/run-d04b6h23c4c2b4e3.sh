#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKSPACE_DIR="$(cd "${CRATE_DIR}/.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
REPORT_PATH="${PSY_D04B6H23C4C2B4E3_REPORT_OVERRIDE:-${WORKSPACE_DIR}/target/d04b6h23c4c2b4e3-jtmb-handler-ingress-rf3-report.json}"
EXERCISE_DURABLE_CAPTURE="${PSY_D04B6H23C4C3A_RF3:-0}"
EXPECTED_QUALIFICATION="H23C4C2B4E3_JTMB_HANDLER_INGRESS_RF3_PASSED"
if [[ "${EXERCISE_DURABLE_CAPTURE}" == "1" ]]; then
  EXPECTED_QUALIFICATION="H23C4C3A_DURABLE_CAPTURE_OWNER_RF3_PASSED"
fi
NATS_DIR="$(mktemp -d /tmp/psy-h23e3-nats.XXXXXX)"

NATS1_PID=""
NATS2_PID=""
NATS3_PID=""

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  for pid in "${NATS1_PID}" "${NATS2_PID}" "${NATS3_PID}"; do
    if [[ -n "${pid}" ]]; then
      kill -CONT "${pid}" 2>/dev/null || true
      kill -TERM "${pid}" 2>/dev/null || true
    fi
  done
  for pid in "${NATS1_PID}" "${NATS2_PID}" "${NATS3_PID}"; do
    [[ -z "${pid}" ]] || wait "${pid}" 2>/dev/null || true
  done
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans || true
  rm -rf "${NATS_DIR}"
  exit "${rc}"
}
trap cleanup EXIT INT TERM

docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans
docker compose -f "${COMPOSE_FILE}" up -d --wait

nats-server --server_name psy-h23e3-n1 --cluster_name psy-h23e3 \
  -js -sd "${NATS_DIR}/n1" -p 45322 -m 47322 \
  --cluster nats://127.0.0.1:46322 \
  --routes nats://127.0.0.1:46323,nats://127.0.0.1:46324 \
  --connect_retries 120 >"${NATS_DIR}/n1.log" 2>&1 &
NATS1_PID=$!
nats-server --server_name psy-h23e3-n2 --cluster_name psy-h23e3 \
  -js -sd "${NATS_DIR}/n2" -p 45323 -m 47323 \
  --cluster nats://127.0.0.1:46323 \
  --routes nats://127.0.0.1:46322,nats://127.0.0.1:46324 \
  --connect_retries 120 >"${NATS_DIR}/n2.log" 2>&1 &
NATS2_PID=$!
nats-server --server_name psy-h23e3-n3 --cluster_name psy-h23e3 \
  -js -sd "${NATS_DIR}/n3" -p 45324 -m 47324 \
  --cluster nats://127.0.0.1:46324 \
  --routes nats://127.0.0.1:46322,nats://127.0.0.1:46323 \
  --connect_retries 120 >"${NATS_DIR}/n3.log" 2>&1 &
NATS3_PID=$!

for _ in $(seq 1 120); do
  ready=0
  curl -fsS "http://127.0.0.1:47322/healthz?js-enabled-only=true" >/dev/null && ready=$((ready + 1))
  curl -fsS "http://127.0.0.1:47323/healthz?js-enabled-only=true" >/dev/null && ready=$((ready + 1))
  curl -fsS "http://127.0.0.1:47324/healthz?js-enabled-only=true" >/dev/null && ready=$((ready + 1))
  if [[ "${ready}" -eq 3 ]]; then
    break
  fi
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

rm -f "${REPORT_PATH}"
cd "${WORKSPACE_DIR}"
PSY_D04B6H23C4C2B4E3_RF3=1 \
PSY_D04B6H23C4C3A_RF3="${EXERCISE_DURABLE_CAPTURE}" \
PSY_D04B6H23C4C2B4E3_COMPOSE_FILE="${COMPOSE_FILE}" \
PSY_D04B6H23C4C2B4E3_REPORT_PATH="${REPORT_PATH}" \
PSY_D04B6H23C4C2B4E3_NATS_URLS="nats://127.0.0.1:45322,nats://127.0.0.1:45323,nats://127.0.0.1:45324" \
PSY_D04B6H23C4C2B4E3_NATS1_PID="${NATS1_PID}" \
PSY_D04B6H23C4C2B4E3_NATS2_PID="${NATS2_PID}" \
PSY_D04B6H23C4C2B4E3_NATS3_PID="${NATS3_PID}" \
RUST_MIN_STACK=67108864 \
cargo test -p psy_node_scylla \
  rollback::realm_edge_handler_ingress_rf3::d04b6h23c4c2b4e3_jtmb_handler_ingress_joint_rf3 \
  --lib -- --ignored --exact --nocapture

jq -e \
  --arg expected_qualification "${EXPECTED_QUALIFICATION}" \
  --argjson exercise_durable_capture "${EXERCISE_DURABLE_CAPTURE}" '
  .qualification == $expected_qualification
  and .scylla_replication_factor == 3
  and .configured_nats_servers == 3
  and .nats_stream_replicas == 3
  and .real_realm_edge_handler == true
  and .jtmb_cli_profile_matched == true
  and .production_jtmb_zk_proof == false
  and .startup_route_attested == true
  and .invalid_pi_created_no_rows == true
  and .invalid_pi_nats_delta == 0
  and .planned_pointer_zero_fragment_replay == true
  and .planned_pointer_replay_messages == 1
  and .scylla_one_replica_offline == true
  and .concurrent_valid_attempts == 2
  and .concurrent_valid_single_publish == true
  and .first_publish_messages == 2
  and .response_loss_retry_messages == 2
  and .nats_leader_failover == true
  and .second_publish_messages == 3
  and .startup_restart_attested == true
  and .restart_retry_messages == 3
  and .dependency_explicit_timestamp_verified == true
  and .repair_direct_one_tables == 17
  and .repair_direct_one_equal == true
  and (
    if $exercise_durable_capture then
      .durable_capture_owner_tested == true
      and .durable_capture_items == 3
      and .durable_capture_empty_poll_not_close == true
      and .processor_gatherer_integrated == false
    else
      .durable_capture_owner_tested == false
    end
  )
' \
  "${REPORT_PATH}" >/dev/null
echo "D-04b6h23c4c2b4e3 JTMB Handler ingress RF=3 report: ${REPORT_PATH}"
