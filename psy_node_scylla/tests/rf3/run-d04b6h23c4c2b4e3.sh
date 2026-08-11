#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKSPACE_DIR="$(cd "${CRATE_DIR}/.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
REPORT_PATH="${PSY_D04B6H23C4C2B4E3_REPORT_OVERRIDE:-${WORKSPACE_DIR}/target/d04b6h23c4c2b4e3-jtmb-handler-ingress-rf3-report.json}"
EXERCISE_DURABLE_CAPTURE="${PSY_D04B6H23C4C3A_RF3:-0}"
EXERCISE_DURABLE_REPLAY="${PSY_D04B6H23C4C3B_RF3:-0}"
EXERCISE_APPLICATION_HANDOFF="${PSY_D04B6H23C4C4A2B_RF3:-0}"
EXERCISE_TERMINAL_RECOVERY="${PSY_D04B6H23C4C4B3B2_RF3:-0}"
EXERCISE_DEFERRED_ACTOR_ARCHIVE="${PSY_D04B6H23C4C4B4C2_RF3:-0}"
EXPECTED_QUALIFICATION="H23C4C2B4E3_JTMB_HANDLER_INGRESS_RF3_PASSED"
if [[ "${EXERCISE_DEFERRED_ACTOR_ARCHIVE}" == "1" ]]; then
  EXPECTED_QUALIFICATION="H23C4C4B4C2_DEFERRED_ACTOR_ARCHIVE_RF3_PASSED"
elif [[ "${EXERCISE_TERMINAL_RECOVERY}" == "1" ]]; then
  EXPECTED_QUALIFICATION="H23C4C4B3B2_TERMINAL_CARRYOVER_RECOVERY_RF3_PASSED"
elif [[ "${EXERCISE_APPLICATION_HANDOFF}" == "1" ]]; then
  EXPECTED_QUALIFICATION="H23C4C4A2B_REALM_APPLICATION_HANDOFF_RF3_PASSED"
elif [[ "${EXERCISE_DURABLE_REPLAY}" == "1" ]]; then
  EXPECTED_QUALIFICATION="H23C4C3B_PROCESSOR_GATHERER_REPLAY_RF3_PASSED"
elif [[ "${EXERCISE_DURABLE_CAPTURE}" == "1" ]]; then
  EXPECTED_QUALIFICATION="H23C4C3A_DURABLE_CAPTURE_OWNER_RF3_PASSED"
fi
CARGO_FEATURE_ARGS=(--features rf3-test-support)
NATS_DIR="$(mktemp -d /tmp/psy-h23e3-nats.XXXXXX)"

NATS1_PID=""
NATS2_PID=""
NATS3_PID=""

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [[ "${rc}" -ne 0 ]]; then
    for log in "${NATS_DIR}/n1.log" "${NATS_DIR}/n2.log" "${NATS_DIR}/n3.log"; do
      if [[ -f "${log}" ]]; then
        echo "NATS failure log: ${log}" >&2
        sed -n '1,240p' "${log}" >&2
      fi
    done
  fi
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
  meta_ready=0
  curl -fsS "http://127.0.0.1:47322/healthz?js-enabled-only=true" >/dev/null && ready=$((ready + 1))
  curl -fsS "http://127.0.0.1:47323/healthz?js-enabled-only=true" >/dev/null && ready=$((ready + 1))
  curl -fsS "http://127.0.0.1:47324/healthz?js-enabled-only=true" >/dev/null && ready=$((ready + 1))
  if curl -fsS "http://127.0.0.1:47322/jsz" \
    | jq -e '(.meta_cluster.leader | type == "string" and length > 0) and (.meta_cluster.cluster_size == 3) and (.meta_cluster.pending == 0)' >/dev/null; then
    meta_ready=1
  fi
  if [[ "${ready}" -eq 3 && "${meta_ready}" -eq 1 ]]; then
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

if ! curl -fsS "http://127.0.0.1:47322/jsz" \
  | jq -e '(.meta_cluster.leader | type == "string" and length > 0) and (.meta_cluster.cluster_size == 3) and (.meta_cluster.pending == 0)' >/dev/null; then
  curl -fsS "http://127.0.0.1:47322/jsz" | jq '.meta_cluster' || true
  exit 1
fi

rm -f "${REPORT_PATH}"
cd "${WORKSPACE_DIR}"
PSY_D04B6H23C4C2B4E3_RF3=1 \
PSY_D04B6H23C4C3A_RF3="${EXERCISE_DURABLE_CAPTURE}" \
PSY_D04B6H23C4C3B_RF3="${EXERCISE_DURABLE_REPLAY}" \
PSY_D04B6H23C4C4A2B_RF3="${EXERCISE_APPLICATION_HANDOFF}" \
PSY_D04B6H23C4C4B3B2_RF3="${EXERCISE_TERMINAL_RECOVERY}" \
PSY_D04B6H23C4C4B4C2_RF3="${EXERCISE_DEFERRED_ACTOR_ARCHIVE}" \
PSY_D04B6H23C4C2B4E3_COMPOSE_FILE="${COMPOSE_FILE}" \
PSY_D04B6H23C4C2B4E3_REPORT_PATH="${REPORT_PATH}" \
PSY_D04B6H23C4C2B4E3_NATS_URLS="nats://127.0.0.1:45322,nats://127.0.0.1:45323,nats://127.0.0.1:45324" \
PSY_D04B6H23C4C2B4E3_NATS1_PID="${NATS1_PID}" \
PSY_D04B6H23C4C2B4E3_NATS2_PID="${NATS2_PID}" \
PSY_D04B6H23C4C2B4E3_NATS3_PID="${NATS3_PID}" \
RUST_MIN_STACK=67108864 \
cargo test -p psy_node_scylla \
  "${CARGO_FEATURE_ARGS[@]}" \
  rollback::realm_edge_handler_ingress_rf3::d04b6h23c4c2b4e3_jtmb_handler_ingress_joint_rf3 \
  --lib -- --ignored --exact --nocapture

jq -e \
  --arg expected_qualification "${EXPECTED_QUALIFICATION}" \
  --argjson exercise_durable_capture "${EXERCISE_DURABLE_CAPTURE}" \
  --argjson exercise_durable_replay "${EXERCISE_DURABLE_REPLAY}" \
  --argjson exercise_application_handoff "${EXERCISE_APPLICATION_HANDOFF}" \
  --argjson exercise_terminal_recovery "${EXERCISE_TERMINAL_RECOVERY}" \
  --argjson exercise_deferred_actor_archive "${EXERCISE_DEFERRED_ACTOR_ARCHIVE}" '
  .qualification == $expected_qualification
  and .scylla_replication_factor == 3
  and .configured_nats_servers == 3
  and .nats_stream_replicas == 3
  and .nats_kv_replicas == 3
  and .nats_kv_replica_mismatch_rejected == true
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
  and .repair_direct_one_tables == (
    if $exercise_terminal_recovery == 1 then 25
    elif $exercise_application_handoff == 1 then 23
    elif $exercise_durable_replay == 1 then 20
    else 17 end
  )
  and .repair_direct_one_equal == true
  and .generation_terminal_integrated == false
  and .production_terminal_mint == false
  and .writer_head_provenance_verified == false
  and .terminal_authorization_qualified == false
  and .processor_recovery_invocation == false
  and .production_terminal_transition == false
  and .production_pipeline_rotation == false
  and .carryover_replay == false
  and .successor_actor_injection == false
  and .proof_publish == false
  and .mapping_reward_writer_integrated == false
  and .full_22_domain_writer == false
  and .production_writer_integrated == false
  and .authority_head_publish_integrated == false
  and .full_node_restart_tested == false
  and .production_serving == false
  and .h8_domains_closed == 0
  and .repair_direct_one_table_names == (.repair_direct_one_table_names | sort | unique)
  and (.repair_direct_one_dataset_digest | test("^[0-9a-f]{64}$"))
  and .repair_direct_one_rows > 0
  and .all_20_target_business_rows_qualified == false
  and (
    if $exercise_terminal_recovery == 1 then
      .affine_terminal_carryover_recovery == true
      and .qualification_seeded_terminal == true
      and .inbound_missing_zero_write == false
      and .nonterminal_zero_write == true
      and .terminal_absent_zero_write == true
      and .terminal_only_repaired == true
      and .post_persist_failure_recovered == true
      and .already_complete_recovered == true
      and .affine_retry_count == 8
      and .derived_same_retry_count == 32
      and .derived_different_contender_conflict == true
      and .application_toctou_rejected == true
      and .terminal_recovery_pipeline_unchanged == true
      and .terminal_recovery_nats_delta == 0
      and .terminal_recovery_socket_response_loss_injected == false
    else
      .affine_terminal_carryover_recovery == false
      and .qualification_seeded_terminal == false
      and .inbound_missing_zero_write == false
      and .nonterminal_zero_write == false
      and .terminal_absent_zero_write == false
      and .terminal_only_repaired == false
      and .post_persist_failure_recovered == false
      and .already_complete_recovered == false
      and .affine_retry_count == 0
      and .derived_same_retry_count == 0
      and .derived_different_contender_conflict == false
      and .application_toctou_rejected == false
      and .terminal_recovery_pipeline_unchanged == false
      and .terminal_recovery_nats_delta == 0
      and .terminal_recovery_socket_response_loss_injected == false
    end
  )
  and (
    if $exercise_application_handoff == 1 then
      .semantic_handoff_integrated == true
      and .application_archive_data_rf3 == true
      and (
        if $exercise_deferred_actor_archive == 1 then
          .application_semantic_bytes > 0
          and .application_fragments == 1
        else
          .application_semantic_bytes > 4194304
          and .application_fragments == 2
        end
      )
      and .application_pipeline_revision > 0
      and .application_restart_recovered == true
      and .fresh_source_assignment_close == true
      and .first_pipeline_cas == true
      and .missing_extra_corrupt_rf3 == true
    else
      .semantic_handoff_integrated == false
      and .application_archive_data_rf3 == false
      and .application_semantic_bytes == 0
      and .application_fragments == 0
      and .application_pipeline_revision == 0
      and .application_restart_recovered == false
      and .fresh_source_assignment_close == false
      and .first_pipeline_cas == false
      and .missing_extra_corrupt_rf3 == false
    end
  )
  and (
    if $exercise_deferred_actor_archive == 1 then
      .sidecar_v13_rf3_inherited == true
      and .v14_ready_receipt_consumed == true
      and .qualification_constructed_predecessor_semantic == true
      and .predecessor_nonempty_input_rf3 == true
      and .predecessor_deferred_count == 3
      and .explicit_empty_input_rf3 == true
      and .explicit_empty_reason == "LegacyActivation"
      and .predecessor_zero_input_rf3 == false
      and .external_generation_nonempty_rf3 == true
      and .external_generation_items == 3
      and .deferred_before_external_rf3 == true
      and (.ordered_actor_trace_digest | test("^[0-9a-f]{64}$"))
      and .fresh_c_fault_rf3 == true
      and .fresh_c_nats_delta == 0
      and .fresh_d_fault_rf3 == true
      and .fresh_d_actor_delta == 0
      and .apply_retry_bit_exact == true
      and .finalize_retry_bit_exact == true
      and .different_input_rejected == true
      and .actor_builder_create_count == 1
      and .actor_finalize_count == 1
      and .semantic_v3_input_bound == true
      and .successor_application_semantic_bytes > 0
      and .successor_application_fragments >= 1
      and .application_archive_handoff_rf3 == true
      and .handoff_recovery_without_actor_rerun == true
      and .successor_handoff_revision > 0
      and .actor_handoff_during_one_replica_offline == true
      and .qualification_temp_dependency_hydration == false
      and .production_external_dependency_projection == true
      and .deferred_input_rf3 == true
      and .actor_retry_socket_response_loss_injected == false
      and .full_processor_rf3_runtime == false
      and .nats_surviving_follower_current_lag_zero == true
      and .deferred_actor_nats_message_count_before > 0
      and .deferred_actor_nats_message_count_after == (.deferred_actor_nats_message_count_before + 4)
      and .nats_message_envelope_count == .deferred_actor_nats_message_count_after
      and (.nats_message_envelope_dataset_digest | test("^[0-9a-f]{64}$"))
      and .deferred_actor_nats_duplicate_delta == 0
    else
      .sidecar_v13_rf3_inherited == false
      and .v14_ready_receipt_consumed == false
      and .qualification_constructed_predecessor_semantic == false
      and .predecessor_nonempty_input_rf3 == false
      and .predecessor_deferred_count == 0
      and .explicit_empty_input_rf3 == false
      and .explicit_empty_reason == "none"
      and .predecessor_zero_input_rf3 == false
      and .external_generation_nonempty_rf3 == false
      and .external_generation_items == 0
      and .deferred_before_external_rf3 == false
      and .ordered_actor_trace_digest == ""
      and .fresh_c_fault_rf3 == false
      and .fresh_c_nats_delta == 0
      and .fresh_d_fault_rf3 == false
      and .fresh_d_actor_delta == 0
      and .apply_retry_bit_exact == false
      and .finalize_retry_bit_exact == false
      and .different_input_rejected == false
      and .actor_builder_create_count == 0
      and .actor_finalize_count == 0
      and .semantic_v3_input_bound == false
      and .successor_application_semantic_bytes == 0
      and .successor_application_fragments == 0
      and .application_archive_handoff_rf3 == false
      and .handoff_recovery_without_actor_rerun == false
      and .successor_handoff_revision == 0
      and .actor_handoff_during_one_replica_offline == false
      and .qualification_temp_dependency_hydration == false
      and .production_external_dependency_projection == false
      and .deferred_input_rf3 == false
      and .actor_retry_socket_response_loss_injected == false
      and .full_processor_rf3_runtime == false
      and .nats_surviving_follower_current_lag_zero == true
      and .nats_message_envelope_count == .restart_retry_messages
      and (.nats_message_envelope_dataset_digest | test("^[0-9a-f]{64}$"))
      and .deferred_actor_nats_message_count_before == 0
      and .deferred_actor_nats_message_count_after == 0
      and .deferred_actor_nats_duplicate_delta == 0
    end
  )
  and (
    if $exercise_durable_capture == 1 then
      .durable_capture_owner_tested == true
      and .durable_capture_items == 3
      and .durable_capture_empty_poll_not_close == true
    else
      .durable_capture_owner_tested == false
    end
  )
  and (
    if $exercise_durable_replay == 1 then
      .durable_generation_replayed == true
      and .durable_generation_items == 3
      and .durable_generation_digest_stable == true
      and .gather_task_restart_replayed == true
      and .processor_route_compiled == true
      and .command_only_with_tree_compiled == true
      and .processor_gatherer_integrated == true
      and .processor_gatherer_rf3_runtime == false
    else
      .durable_generation_replayed == false
      and .durable_generation_items == 0
      and .durable_generation_digest_stable == false
      and .gather_task_restart_replayed == false
      and .processor_route_compiled == false
      and .command_only_with_tree_compiled == false
      and .processor_gatherer_integrated == false
      and .processor_gatherer_rf3_runtime == false
    end
  )
' \
  "${REPORT_PATH}" >/dev/null
echo "D-04b6h23c4c2b4e3 JTMB Handler ingress RF=3 report: ${REPORT_PATH}"
