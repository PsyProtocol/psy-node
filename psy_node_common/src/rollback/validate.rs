//! Fail-closed rollback plan validation with no IO.

use std::collections::HashSet;

use serde_json::Value;
use psy_node_core::{
    psy_temp_db::{TEMP_TABLE_ID_WORKER_REPUTATION_BYTES, TEMP_TABLE_WORKER_REPUTATION_KEY_SIZE},
    store::traits::temp_db::PENDING_KEYED_TEMP_TABLE_ID_BYTES,
};

use crate::rollback::generator::{api_for_table, EMPTY_SCHEMA_TABLES, FINAL_TABLES, STAGE1_TABLES, STAGE2_TABLES, STAGE3_TABLES};
use crate::rollback::plan::{rollback_nats_consumer_kinds, RollbackNatsConsumerKind, RollbackPhaseStatus, RollbackPlan, RollbackRole};

const TEMP_TABLE_PI: [u8; 2] = [0x50, 0x49];
const TEMP_TABLE_GP: [u8; 2] = [0x47, 0x50];
const TEMP_TABLE_PS: [u8; 2] = [0x50, 0x53];

pub fn validate_rollback_plan(plan: &RollbackPlan) -> anyhow::Result<()> {
    if plan.target_checkpoint_id > plan.latest_checkpoint_id {
        anyhow::bail!("target_checkpoint_id {} > latest_checkpoint_id {}", plan.target_checkpoint_id, plan.latest_checkpoint_id);
    }
    if let Some(state) = &plan.target_contract_state {
        if state.last_finalized_checkpoint_id != plan.target_checkpoint_id {
            anyhow::bail!(
                "target_contract_state.last_finalized_checkpoint_id {} must equal target_checkpoint_id {}",
                state.last_finalized_checkpoint_id,
                plan.target_checkpoint_id
            );
        }
    }
    if plan.role == RollbackRole::Coordinator && (plan.realm_id != 0 || plan.realm_sub_id != 0) {
        anyhow::bail!("Coordinator RP must use realm_id=0 and realm_sub_id=0");
    }
    for (index, entry) in plan.ids.iter().enumerate() {
        if entry.pending_id == 0 {
            anyhow::bail!("ids pending_id 0 is never a delete key");
        }
        if index > 0 && plan.ids[index - 1].pending_id >= entry.pending_id {
            anyhow::bail!("ids pending_ids must be strictly ascending");
        }
        if entry.pending_id > plan.latest_pending_id {
            anyhow::bail!("ids pending_id {} exceeds frozen high-water {}", entry.pending_id, plan.latest_pending_id);
        }
        if let Some(checkpoint_id) = entry.checkpoint_id {
            if checkpoint_id == 0 || checkpoint_id <= plan.target_checkpoint_id || checkpoint_id > plan.latest_checkpoint_id {
                anyhow::bail!("ids checkpoint_id {} is outside (target, latest]", checkpoint_id);
            }
        }
    }

    let mut expected_tables = Vec::with_capacity(STAGE1_TABLES.len() + STAGE2_TABLES.len() + EMPTY_SCHEMA_TABLES.len() + STAGE3_TABLES.len() + FINAL_TABLES.len());
    expected_tables.extend_from_slice(STAGE1_TABLES);
    expected_tables.extend_from_slice(STAGE2_TABLES);
    expected_tables.extend_from_slice(EMPTY_SCHEMA_TABLES);
    expected_tables.extend_from_slice(STAGE3_TABLES);
    expected_tables.extend_from_slice(FINAL_TABLES);
    if plan.phases.len() != expected_tables.len() {
        anyhow::bail!("expected exactly {} phases, got {}", expected_tables.len(), plan.phases.len());
    }

    let mut seen = HashSet::new();
    for (index, (phase, expected_table)) in plan.phases.iter().zip(expected_tables.iter()).enumerate() {
        if phase.table != *expected_table {
            anyhow::bail!("phase {} must target real logical table {}, got {}", index, expected_table, phase.table);
        }
        if !seen.insert(phase.table.as_str()) {
            anyhow::bail!("duplicate phase table: {}", phase.table);
        }
        let expected_api = match phase.table.as_str() {
            "TKVSV1" => "qtdb_raw_kv_delete_key",
            "TMPPSV1-proof-buckets" => "delete_all_proofs_for_pending_id",
            table => api_for_table(table),
        };
        if expected_api == "UNKNOWN" || phase.api != expected_api {
            anyhow::bail!("phase {} ({}) must use API {}, got {}", index, phase.table, expected_api, phase.api);
        }
        match phase.status {
            RollbackPhaseStatus::Pending | RollbackPhaseStatus::Completed => {}
        }
    }
    // Marker write is last; verify must run immediately before it.
    let verify_index = plan.phases.len() - 2;
    if plan.phases[verify_index].table != "all" || plan.phases[verify_index].api != "verify" {
        anyhow::bail!("verify must be immediately before the marker phase");
    }
    let marker = plan.phases.last().expect("phase count checked");
    if marker.table != "u64_singleton_table" || marker.api != "set_latest_checkpoint_id" {
        anyhow::bail!("set_latest_checkpoint_id must be the final phase");
    }
    for mandatory in ["l2_block_state_table", "user_leaf_table", "user_public_key_table", "checkpointed_object_table", "pending_id_to_pending_proc_id_table"] {
        if !seen.contains(mandatory) {
            anyhow::bail!("mandatory logical phase {} is missing", mandatory);
        }
    }
    validate_semantic_keys(plan)
}

fn validate_semantic_keys(plan: &RollbackPlan) -> anyhow::Result<()> {
    let checkpoint_set: HashSet<u64> = plan.checkpoint_ids().into_iter().collect();
    let mapped_checkpoint_set: HashSet<u64> = plan.mapped_checkpoint_ids().into_iter().collect();
    let pending_set: HashSet<u64> = plan.ids.iter().map(|entry| entry.pending_id).collect();
    let proc_pairs: HashSet<(u64, u128)> = plan.ids
        .iter()
        .map(|entry| (entry.pending_id, entry.proc_id))
        .collect();
    let realm_le = u32::try_from(plan.realm_id).map_err(|_| anyhow::anyhow!("realm_id exceeds u32"))?.to_le_bytes();
    let sub_le = u16::try_from(plan.realm_sub_id).map_err(|_| anyhow::anyhow!("realm_sub_id exceeds u16"))?.to_le_bytes();

    validate_worker_reputation_fields(plan, &realm_le, &sub_le)?;

    for phase in &plan.phases {
        match phase.table.as_str() {
            "TKVSV1" => validate_temp_fields(&phase.keys, &pending_set, &realm_le, &sub_le)?,
            "TMPPSV1-proof-buckets" => require_exact_u64_set(&phase.table, &phase.keys, &pending_set)?,
            "nats_jetstream_consumers" => validate_nats_targets(plan, &phase.keys)?,
            "checkpoint_leaf_table"
            | "l2_block_state_table"
            | "checkpoint_state_roots_table"
            | "checkpoint_zk_proof_and_transition_table" => {
                require_exact_u64_set(&phase.table, &phase.keys, &checkpoint_set)?;
            }
            "checkpoint_id_to_pending_id_table" => {
                require_exact_u64_set(&phase.table, &phase.keys, &mapped_checkpoint_set)?;
            }
            "checkpoint_id_to_realm_root_table" | "checkpoint_leaf_to_checkpoint_id_table" => {
                require_empty(&phase.table, &phase.keys)?;
            }
            "checkpoint_root_to_checkpoint_id_table" => {
                validate_blob_root_pairs(&phase.table, &phase.keys, &checkpoint_set)?;
            }
            "pending_id_to_checkpoint_id_table" | "guta_reward_tag_tree_table" => {
                require_exact_u64_set(&phase.table, &phase.keys, &pending_set)?;
            }
            "pending_id_to_pending_proc_id_table" => {
                validate_pending_proc_pairs(&phase.keys, &proc_pairs)?;
            }
            "checkpointed_object_table" => {
                validate_checkpointed_object_keys(&phase.keys, &checkpoint_set, &pending_set)?;
            }
            "user_leaf_table"
            | "user_public_key_table"
            | "contract_state_tree_height_table"
            | "contract_leaf_table"
            | "contract_code_definition_table" => {
                validate_object_checkpoint_pairs(&phase.table, &phase.keys, &checkpoint_set)?;
            }
            "realm_rewards_tree_node_key_table" => {
                validate_reward_keys(plan, &phase.keys, &pending_set)?;
            }
            "public_key_hash_to_user_ids_table" => validate_hash_user_pairs(&phase.keys)?,
            "imt_key_index_table" => validate_imt_key_index(&phase.keys)?,
            "global_user_tree_table"
            | "global_checkpoint_tree_table"
            | "user_registration_tree_table"
            | "global_contract_tree_table" => {
                validate_merkle_checkpoints(&phase.table, &phase.keys, 2, &checkpoint_set)?;
            }
            "user_contract_tree_table" | "contract_function_tree_table" => {
                validate_merkle_checkpoints(&phase.table, &phase.keys, 3, &checkpoint_set)?;
            }
            "contract_state_tree_table" => {
                validate_merkle_checkpoints(&phase.table, &phase.keys, 4, &checkpoint_set)?;
            }
            "imt_leaf_table" => validate_imt_leaf_checkpoints(&phase.keys, &checkpoint_set)?,
            "latest_info_table" | "checkpoint_tree_backup" | "all" | "u64_singleton_table" => {
                require_empty(&phase.table, &phase.keys)?;
            }
            "imt_next_append_index_table" => validate_imt_append_indexes(&phase.keys)?,
            "TKVSV1-singletons" => validate_processor_state_singleton_keys(&phase.keys, &realm_le, &sub_le)?,
            table => anyhow::bail!("unexpected rollback table {table}"),
        }
    }
    Ok(())
}

fn validate_worker_reputation_fields(plan: &RollbackPlan, realm_le: &[u8; 4], sub_le: &[u8; 2]) -> anyhow::Result<()> {
    if decode_hex(&plan.snapshot.target_info).map_err(|err| anyhow::anyhow!("snapshot.target_info: {err}"))?.is_empty() {
        anyhow::bail!("snapshot.target_info must not be empty");
    }
    let mut seen_fields = HashSet::new();
    for (index, reputation) in plan.snapshot.worker_reputation_fields.iter().enumerate() {
        let field = decode_hex(&reputation.field).map_err(|err| anyhow::anyhow!("snapshot.worker_reputation_fields[{index}].field: {err}"))?;
        if field.len() != TEMP_TABLE_WORKER_REPUTATION_KEY_SIZE || field[0..4] != realm_le[..] || field[4..6] != sub_le[..] || field[6..8] != TEMP_TABLE_ID_WORKER_REPUTATION_BYTES {
            anyhow::bail!("snapshot.worker_reputation_fields[{index}] is not an exact worker reputation field for this processor");
        }
        if !seen_fields.insert(field) {
            anyhow::bail!("snapshot.worker_reputation_fields[{index}] duplicates an earlier worker reputation field");
        }
        if let Some(value) = &reputation.value {
            decode_hex(value).map_err(|err| anyhow::anyhow!("snapshot.worker_reputation_fields[{index}].value: {err}"))?;
        }
    }
    Ok(())
}

fn validate_temp_fields(
    keys: &Value,
    pending_set: &HashSet<u64>,
    realm_le: &[u8; 4],
    sub_le: &[u8; 2],
) -> anyhow::Result<()> {
    for (index, value) in require_array("TKVSV1", keys)?.iter().enumerate() {
        let field = hex_value("TKVSV1", index, value)?;
        if field.len() < 16 {
            anyhow::bail!("TKVSV1 key {index} is shorter than the 16-byte pending prefix");
        }
        if field[0..4] != realm_le[..] || field[4..6] != sub_le[..] {
            anyhow::bail!("TKVSV1 key {index} does not match plan realm_id/realm_sub_id");
        }
        let table_id = [field[6], field[7]];
        if !PENDING_KEYED_TEMP_TABLE_ID_BYTES.contains(&table_id) {
            anyhow::bail!("TKVSV1 key {index} targets an unsupported pending namespace");
        }
        let pending_id = u64::from_le_bytes(field[8..16].try_into().expect("16-byte prefix"));
        if !pending_set.contains(&pending_id) {
            anyhow::bail!("TKVSV1 key {index} pending_id {pending_id} is outside frozen pending_set");
        }
    }
    Ok(())
}

fn validate_processor_state_singleton_keys(keys: &Value, realm_le: &[u8; 4], sub_le: &[u8; 2]) -> anyhow::Result<()> {
    let expected: HashSet<Vec<u8>> = [TEMP_TABLE_PI, TEMP_TABLE_GP, TEMP_TABLE_PS]
        .into_iter()
        .map(|table_id| {
            let mut field = Vec::with_capacity(8);
            field.extend_from_slice(realm_le);
            field.extend_from_slice(sub_le);
            field.extend_from_slice(&table_id);
            field
        })
        .collect();
    let mut actual = HashSet::new();
    for (index, value) in require_array("TKVSV1-singletons", keys)?.iter().enumerate() {
        let field = hex_value("TKVSV1-singletons", index, value)?;
        if !expected.contains(&field) {
            anyhow::bail!("TKVSV1-singletons key {index} is not a processor-state singleton");
        }
        actual.insert(field);
    }
    if actual != expected {
        anyhow::bail!("TKVSV1-singletons keys must be exactly the processor-state singletons");
    }
    Ok(())
}

fn validate_blob_root_pairs(table: &str, keys: &Value, checkpoint_set: &HashSet<u64>) -> anyhow::Result<()> {
    let mut actual = HashSet::new();
    for (index, value) in require_array(table, keys)?.iter().enumerate() {
        let pair = require_tuple(table, index, value, 2)?;
        let root = hex_value(table, index, &pair[0])?;
        let checkpoint_bytes = hex_value(table, index, &pair[1])?;
        if root.len() != 32 || checkpoint_bytes.len() != 8 {
            anyhow::bail!("{table} key {index} is not one full (32-byte root, 8-byte checkpoint LE) pair");
        }
        let checkpoint_id = u64::from_le_bytes(checkpoint_bytes.try_into().expect("8-byte checkpoint"));
        if checkpoint_id == 0 || !checkpoint_set.contains(&checkpoint_id) {
            anyhow::bail!("{table} key {index} checkpoint {checkpoint_id} is outside frozen checkpoint_set");
        }
        actual.insert(checkpoint_id);
    }
    if actual != *checkpoint_set {
        anyhow::bail!("{table} blob checkpoint ids must equal frozen checkpoint_set");
    }
    Ok(())
}

fn validate_checkpointed_object_keys(
    keys: &Value,
    checkpoint_set: &HashSet<u64>,
    pending_set: &HashSet<u64>,
) -> anyhow::Result<()> {
    let mut actual_cp = HashSet::new();
    let mut actual_pending = HashSet::new();
    for (index, value) in require_array("checkpointed_object_table", keys)?.iter().enumerate() {
        let pair = require_tuple("checkpointed_object_table", index, value, 2)?;
        let tag = as_u64("checkpointed_object_table", index, &pair[0])?;
        let id = as_u64("checkpointed_object_table", index, &pair[1])?;
        match tag {
            1 => {
                if id == 0 || !checkpoint_set.contains(&id) {
                    anyhow::bail!("checkpointed_object_table key {index} [1, {id}] is outside frozen checkpoint_set");
                }
                actual_cp.insert(id);
            }
            2 => {
                if id == 0 || !pending_set.contains(&id) {
                    anyhow::bail!("checkpointed_object_table key {index} [2, {id}] is outside frozen pending_set");
                }
                actual_pending.insert(id);
            }
            _ => anyhow::bail!("checkpointed_object_table key {index} has invalid object tag {tag}"),
        }
    }
    if actual_cp != *checkpoint_set || actual_pending != *pending_set {
        anyhow::bail!("checkpointed_object_table keys must be exactly [1, checkpoint_set] ∪ [2, pending_set]");
    }
    Ok(())
}

fn validate_object_checkpoint_pairs(table: &str, keys: &Value, checkpoint_set: &HashSet<u64>) -> anyhow::Result<()> {
    for (index, value) in require_array(table, keys)?.iter().enumerate() {
        let pair = require_tuple(table, index, value, 2)?;
        let checkpoint_id = as_u64(table, index, &pair[1])?;
        if checkpoint_id == 0 || !checkpoint_set.contains(&checkpoint_id) {
            anyhow::bail!("{table} key {index} checkpoint {checkpoint_id} is outside frozen checkpoint_set");
        }
    }
    Ok(())
}

fn validate_reward_keys(plan: &RollbackPlan, keys: &Value, pending_set: &HashSet<u64>) -> anyhow::Result<()> {
    for (index, value) in require_array("realm_rewards_tree_node_key_table", keys)?.iter().enumerate() {
        let pair = require_tuple("realm_rewards_tree_node_key_table", index, value, 2)?;
        let realm_id = as_u64("realm_rewards_tree_node_key_table", index, &pair[0])?;
        let pending_id = as_u64("realm_rewards_tree_node_key_table", index, &pair[1])?;
        if pending_id == 0 || !pending_set.contains(&pending_id) {
            anyhow::bail!("realm_rewards_tree_node_key_table key {index} pending_id {pending_id} is outside frozen pending_set");
        }
        if plan.role == RollbackRole::Realm && realm_id != plan.realm_id {
            anyhow::bail!("realm_rewards_tree_node_key_table key {index} realm_id {realm_id} does not match this Realm RP");
        }
    }
    Ok(())
}

fn validate_pending_proc_pairs(keys: &Value, proc_pairs: &HashSet<(u64, u128)>) -> anyhow::Result<()> {
    let mut actual = HashSet::new();
    for (index, value) in require_array("pending_id_to_pending_proc_id_table", keys)?.iter().enumerate() {
        let pair = require_tuple("pending_id_to_pending_proc_id_table", index, value, 2)?;
        let pending_id = as_u64("pending_id_to_pending_proc_id_table", index, &pair[0])?;
        let proc_id = as_u128("pending_id_to_pending_proc_id_table", index, &pair[1])?;
        if pending_id == 0 || !proc_pairs.contains(&(pending_id, proc_id)) {
            anyhow::bail!("pending_id_to_pending_proc_id_table key {index} pair ({pending_id}, {proc_id}) is not an ids pair");
        }
        actual.insert((pending_id, proc_id));
    }
    if actual != *proc_pairs {
        anyhow::bail!("pending_id_to_pending_proc_id_table keys must equal frozen ids (pending, proc) pairs");
    }
    Ok(())
}

fn validate_hash_user_pairs(keys: &Value) -> anyhow::Result<()> {
    for (index, value) in require_array("public_key_hash_to_user_ids_table", keys)?.iter().enumerate() {
        let pair = require_tuple("public_key_hash_to_user_ids_table", index, value, 2)?;
        let hash = hex_value("public_key_hash_to_user_ids_table", index, &pair[0])?;
        if hash.is_empty() || hash.iter().all(|byte| *byte == 0) {
            anyhow::bail!("public_key_hash_to_user_ids_table key {index} has an empty/all-zero hash");
        }
        as_u64("public_key_hash_to_user_ids_table", index, &pair[1])?;
    }
    Ok(())
}

fn validate_imt_key_index(keys: &Value) -> anyhow::Result<()> {
    for (index, value) in require_array("imt_key_index_table", keys)?.iter().enumerate() {
        let tuple = require_tuple("imt_key_index_table", index, value, 4)?;
        as_i64("imt_key_index_table", index, &tuple[0])?;
        as_i64("imt_key_index_table", index, &tuple[1])?;
        let bucket = as_i64("imt_key_index_table", index, &tuple[2])?;
        if bucket < i16::MIN as i64 || bucket > i16::MAX as i64 {
            anyhow::bail!("imt_key_index_table key {index} key_bucket is outside i16");
        }
        let encoded = hex_value("imt_key_index_table", index, &tuple[3])?;
        if encoded.is_empty() {
            anyhow::bail!("imt_key_index_table key {index} has an empty encoded_key");
        }
    }
    Ok(())
}

fn validate_merkle_checkpoints(
    table: &str,
    keys: &Value,
    checkpoint_slot: usize,
    checkpoint_set: &HashSet<u64>,
) -> anyhow::Result<()> {
    let len = checkpoint_slot + 1;
    for (index, value) in require_array(table, keys)?.iter().enumerate() {
        let tuple = require_tuple(table, index, value, len)?;
        let checkpoint_id = as_u64(table, index, &tuple[checkpoint_slot])?;
        if checkpoint_id == 0 || !checkpoint_set.contains(&checkpoint_id) {
            anyhow::bail!("{table} key {index} checkpoint {checkpoint_id} is outside frozen checkpoint_set");
        }
    }
    Ok(())
}

fn validate_imt_leaf_checkpoints(keys: &Value, checkpoint_set: &HashSet<u64>) -> anyhow::Result<()> {
    for (index, value) in require_array("imt_leaf_table", keys)?.iter().enumerate() {
        let tuple = require_tuple("imt_leaf_table", index, value, 4)?;
        as_i64("imt_leaf_table", index, &tuple[0])?;
        as_i64("imt_leaf_table", index, &tuple[1])?;
        as_i64("imt_leaf_table", index, &tuple[2])?;
        let checkpoint_id = as_i64("imt_leaf_table", index, &tuple[3])?;
        if checkpoint_id <= 0 {
            anyhow::bail!("imt_leaf_table key {index} contains non-positive checkpoint {checkpoint_id}");
        }
        let checkpoint_u64 = checkpoint_id as u64;
        if !checkpoint_set.contains(&checkpoint_u64) {
            anyhow::bail!("imt_leaf_table key {index} checkpoint {checkpoint_u64} is outside frozen checkpoint_set");
        }
    }
    Ok(())
}

fn validate_imt_append_indexes(keys: &Value) -> anyhow::Result<()> {
    let mut seen = HashSet::new();
    for (index, value) in require_array("imt_next_append_index_table", keys)?.iter().enumerate() {
        let obj = value
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("imt_next_append_index_table key {index} must be an object"))?;
        if obj.len() != 3 || !obj.contains_key("tree_id") || !obj.contains_key("tree_sub_id") || !obj.contains_key("next_append_index") {
            anyhow::bail!("imt_next_append_index_table key {index} must contain exactly tree_id, tree_sub_id, next_append_index");
        }
        let tree_id = obj["tree_id"]
            .as_i64()
            .filter(|value| *value >= 0)
            .ok_or_else(|| anyhow::anyhow!("imt_next_append_index_table key {index} has invalid tree_id"))?;
        let tree_sub_id = obj["tree_sub_id"]
            .as_i64()
            .filter(|value| *value >= 0)
            .ok_or_else(|| anyhow::anyhow!("imt_next_append_index_table key {index} has invalid tree_sub_id"))?;
        if !seen.insert((tree_id, tree_sub_id)) {
            anyhow::bail!("imt_next_append_index_table duplicates tree coordinates ({tree_id}, {tree_sub_id})");
        }
        match &obj["next_append_index"] {
            Value::Null => {}
            Value::Number(number) => {
                let next = number
                    .as_i64()
                    .ok_or_else(|| anyhow::anyhow!("imt_next_append_index_table key {index} has invalid next_append_index"))?;
                if next <= 0 {
                    anyhow::bail!("imt_next_append_index_table key {index} has non-positive next_append_index");
                }
            }
            _ => anyhow::bail!("imt_next_append_index_table key {index} has invalid next_append_index"),
        }
    }
    Ok(())
}


fn require_exact_u64_set(table: &str, keys: &Value, expected: &HashSet<u64>) -> anyhow::Result<()> {
    let mut actual = HashSet::new();
    for (index, value) in require_array(table, keys)?.iter().enumerate() {
        let id = as_u64(table, index, value)?;
        if id == 0 {
            anyhow::bail!("{table} key {index} contains id 0");
        }
        actual.insert(id);
    }
    if actual != *expected {
        anyhow::bail!("{table} keys must equal the frozen ids set");
    }
    Ok(())
}

fn require_empty(table: &str, keys: &Value) -> anyhow::Result<()> {
    let values = require_array(table, keys)?;
    if !values.is_empty() {
        anyhow::bail!("{table} must stay empty (count-zero phase)");
    }
    Ok(())
}

fn require_array<'a>(table: &str, keys: &'a Value) -> anyhow::Result<&'a Vec<Value>> {
    keys.as_array().ok_or_else(|| anyhow::anyhow!("{table} keys must be an array"))
}

fn require_tuple<'a>(table: &str, index: usize, value: &'a Value, len: usize) -> anyhow::Result<&'a [Value]> {
    let values = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("{table} key {index} must be an array"))?;
    if values.len() != len {
        anyhow::bail!("{table} key {index} must contain exactly {len} values");
    }
    Ok(values)
}

fn as_u64(table: &str, index: usize, value: &Value) -> anyhow::Result<u64> {
    value
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("{table} key {index} contains a non-u64 value"))
}

fn as_i64(table: &str, index: usize, value: &Value) -> anyhow::Result<i64> {
    value
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("{table} key {index} contains a non-i64 value"))
}

fn as_u128(table: &str, index: usize, value: &Value) -> anyhow::Result<u128> {
    match value {
        Value::String(text) => text
            .parse::<u128>()
            .map_err(|_| anyhow::anyhow!("{table} key {index} has invalid u128 proc id")),
        Value::Number(number) => number
            .as_u64()
            .map(u128::from)
            .ok_or_else(|| anyhow::anyhow!("{table} key {index} has invalid u128 proc id")),
        _ => anyhow::bail!("{table} key {index} has invalid u128 proc id"),
    }
}

fn validate_nats_targets(plan: &RollbackPlan, keys: &Value) -> anyhow::Result<()> {
    let expected: HashSet<(RollbackNatsConsumerKind, u128, u32)> = plan
        .proc_ids()
        .into_iter()
        .flat_map(|proc_id| {
            rollback_nats_consumer_kinds(plan.role)
                .iter()
                .copied()
                .map(move |kind| (kind, proc_id, 0)) // task_group must be 0
        })
        .collect();
    let mut actual = HashSet::new();
    for (index, value) in require_array("nats_jetstream_consumers", keys)?.iter().enumerate() {
        let target = value.as_object().ok_or_else(|| anyhow::anyhow!("nats consumer key {index} must be an object"))?;
        if target.len() != 3 || !target.contains_key("kind") || !target.contains_key("proc_id") || !target.contains_key("task_group") {
            anyhow::bail!("nats consumer key {index} must contain exactly kind, proc_id, task_group");
        }
        let kind: RollbackNatsConsumerKind = serde_json::from_value(target["kind"].clone())
            .map_err(|_| anyhow::anyhow!("nats consumer key {index} has invalid kind"))?;
        let proc_id = as_u128("nats_jetstream_consumers", index, &target["proc_id"])?;
        let task_group = target["task_group"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| anyhow::anyhow!("nats consumer key {index} has invalid task_group"))?;
        if !actual.insert((kind, proc_id, task_group)) {
            anyhow::bail!("duplicate nats consumer target at key {index}");
        }
    }
    if actual != expected {
        anyhow::bail!("nats consumer keys must equal the exact role-local ids consumer catalog");
    }
    Ok(())
}
fn hex_value(table: &str, index: usize, value: &Value) -> anyhow::Result<Vec<u8>> {
    let text = value
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("{table} key {index} must contain a hex string"))?;
    decode_hex(text).map_err(|err| anyhow::anyhow!("{table} key {index}: {err}"))
}

fn decode_hex(value: &str) -> anyhow::Result<Vec<u8>> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(raw).map_err(|err| anyhow::anyhow!("invalid hexadecimal: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rollback::plan::{
        RollbackIds, RollbackPhase, RollbackPhaseStatus, RollbackPlan, RollbackRole,
        RollbackSnapshot, RollbackTempValueSnapshot, TargetContractState,
    };

    fn empty_coordinator_plan() -> RollbackPlan {
        RollbackPlan {
            role: RollbackRole::Coordinator,
            realm_id: 0,
            realm_sub_id: 0,
            target_checkpoint_id: 199,
            latest_checkpoint_id: 199,
            latest_pending_id: 87,
            ids: vec![],
            target_contract_state: None,
            snapshot: RollbackSnapshot {
                target_info: "00".into(),
                worker_reputation_fields: Vec::new(),
            },
            phases: vec![],
        }
    }

    #[test]
    fn validator_rejects_target_gt_latest() {
        let mut plan = empty_coordinator_plan();
        plan.target_checkpoint_id = 300;
        plan.latest_checkpoint_id = 200;
        assert!(validate_rollback_plan(&plan).is_err());
    }

    #[test]
    fn validator_accepts_absent_or_matching_contract_state_and_rejects_mismatch() {
        let mut plan = valid_plan();
        plan.target_contract_state = None;
        validate_rollback_plan(&plan).unwrap();

        plan.target_contract_state = Some(TargetContractState {
            last_finalized_checkpoint_id: plan.target_checkpoint_id,
            last_verified_checkpoint_root: None,
            last_verified_deposit_tree_root: None,
            last_verified_withdrawal_tree_root: None,
            withdrawal_subtree_root: None,
            deposit_root: None,
            proved_deposit_count: None,
            pending_deposit_count: None,
        });
        validate_rollback_plan(&plan).unwrap();

        plan.target_contract_state.as_mut().unwrap().last_finalized_checkpoint_id += 1;
        let err = validate_rollback_plan(&plan).unwrap_err();
        assert!(err.to_string().contains("must equal target_checkpoint_id"), "{err}");
    }

    #[test]
    fn validator_rejects_nonascending_ids() {
        let mut plan = empty_coordinator_plan();
        plan.ids = vec![
            RollbackIds { checkpoint_id: Some(201), pending_id: 89, proc_id: 10089 },
            RollbackIds { checkpoint_id: Some(200), pending_id: 88, proc_id: 10088 },
        ];
        assert!(validate_rollback_plan(&plan).is_err());
    }

    #[test]
    fn validator_rejects_empty_phases() {
        let plan = empty_coordinator_plan();
        assert!(validate_rollback_plan(&plan).is_err());
    }

    #[test]
    fn validator_rejects_wrong_last_phase() {
        let mut plan = empty_coordinator_plan();
        plan.phases = vec![RollbackPhase {
            table: "checkpoint_leaf_table".into(),
            api: "db_delete_many_object_ids".into(),
            keys: serde_json::json!([]),
            status: RollbackPhaseStatus::Pending,
        }];
        assert!(validate_rollback_plan(&plan).is_err());
    }

    #[test]
    fn validator_rejects_duplicate_tables() {
        let mut plan = empty_coordinator_plan();
        plan.phases = vec![
            RollbackPhase {
                table: "checkpoint_leaf_table".into(),
                api: "db_delete_many_object_ids".into(),
                keys: serde_json::json!([]),
                status: RollbackPhaseStatus::Pending,
            },
            RollbackPhase {
                table: "checkpoint_leaf_table".into(),
                api: "db_delete_many_object_ids".into(),
                keys: serde_json::json!([]),
                status: RollbackPhaseStatus::Pending,
            },
            RollbackPhase {
                table: "u64_singleton_table".into(),
                api: "set_latest_checkpoint_id".into(),
                keys: serde_json::json!([]),
                status: RollbackPhaseStatus::Pending,
            },
        ];
        assert!(validate_rollback_plan(&plan).is_err());
    }

    fn pending_field(realm_id: u32, realm_sub_id: u16, table_id: [u8; 2], pending_id: u64) -> String {
        let mut field = Vec::with_capacity(19);
        field.extend_from_slice(&realm_id.to_le_bytes());
        field.extend_from_slice(&realm_sub_id.to_le_bytes());
        field.extend_from_slice(&table_id);
        field.extend_from_slice(&pending_id.to_le_bytes());
        field.extend_from_slice(&[0x01, 0x02, 0x03]);
        hex::encode(field)
    }

    fn worker_reputation_field(realm_id: u32, realm_sub_id: u16) -> String {
        let mut field = vec![0u8; 41];
        field[0..4].copy_from_slice(&realm_id.to_le_bytes());
        field[4..6].copy_from_slice(&realm_sub_id.to_le_bytes());
        field[6..8].copy_from_slice(&TEMP_TABLE_ID_WORKER_REPUTATION_BYTES);
        hex::encode(field)
    }

    fn singleton_field(realm_id: u32, realm_sub_id: u16, table_id: [u8; 2]) -> String {
        let mut field = Vec::with_capacity(8);
        field.extend_from_slice(&realm_id.to_le_bytes());
        field.extend_from_slice(&realm_sub_id.to_le_bytes());
        field.extend_from_slice(&table_id);
        hex::encode(field)
    }

    fn phase_for(table: &str, keys: Value) -> RollbackPhase {
        let api = match table {
            "TKVSV1" => "qtdb_raw_kv_delete_key",
            "TMPPSV1-proof-buckets" => "delete_all_proofs_for_pending_id",
            other => api_for_table(other),
        };
        RollbackPhase {
            table: table.to_string(),
            api: api.to_string(),
            keys,
            status: RollbackPhaseStatus::Pending,
        }
    }

    fn blob_pair(checkpoint_id: u64) -> Value {
        let root = format!("0x{}", hex::encode([checkpoint_id as u8; 32]));
        let checkpoint = format!("0x{}", hex::encode(checkpoint_id.to_le_bytes()));
        serde_json::json!([root, checkpoint])
    }

    fn valid_plan() -> RollbackPlan {
        let ids = vec![
            RollbackIds { checkpoint_id: Some(200), pending_id: 88, proc_id: 10088 },
            RollbackIds { checkpoint_id: Some(201), pending_id: 89, proc_id: 10089 },
            RollbackIds { checkpoint_id: None, pending_id: 94, proc_id: 10094 },
        ];
        let checkpoint_ids: Vec<u64> = (200..=210).collect();
        let pending_ids = [88u64, 89, 94];
        let mut expected_tables = Vec::new();
        expected_tables.extend_from_slice(STAGE1_TABLES);
        expected_tables.extend_from_slice(STAGE2_TABLES);
        expected_tables.extend_from_slice(EMPTY_SCHEMA_TABLES);
        expected_tables.extend_from_slice(STAGE3_TABLES);
        expected_tables.extend_from_slice(FINAL_TABLES);

        let checkpoint_json = serde_json::json!(checkpoint_ids);
        let mapped_checkpoint_json = serde_json::json!([200u64, 201]);
        let pending_json = serde_json::json!(pending_ids);
        let proc_json = serde_json::json!([[88, "10088"], [89, "10089"], [94, "10094"]]);
        let nats_targets = serde_json::Value::Array(
            [10088u128, 10089, 10094]
                .into_iter()
                .flat_map(|proc_id| {
                    rollback_nats_consumer_kinds(RollbackRole::Coordinator)
                        .iter()
                        .map(move |kind| serde_json::json!({ "kind": kind, "proc_id": proc_id.to_string(), "task_group": 0 }))
                })
                .collect(),
        );
        let checkpointed = serde_json::Value::Array(
            (200u64..=210)
                .map(|checkpoint_id| serde_json::json!([1, checkpoint_id]))
                .chain(pending_ids.into_iter().map(|pending_id| serde_json::json!([2, pending_id])))
                .collect(),
        );
        let blobs = serde_json::Value::Array((200u64..=210).map(blob_pair).collect());
        let temp = serde_json::json!([
            pending_field(0, 0, [0x45, 0x50], 88),
            pending_field(0, 0, [0x45, 0x50], 89),
            pending_field(0, 0, [0x45, 0x50], 94),
        ]);
        let processor_singletons = serde_json::json!([
            singleton_field(0, 0, TEMP_TABLE_PI),
            singleton_field(0, 0, TEMP_TABLE_GP),
            singleton_field(0, 0, TEMP_TABLE_PS),
        ]);
        let merkle = serde_json::json!([[0, 0, 200], [0, 1, 201]]);
        let tree_merkle = serde_json::json!([[7, 0, 0, 200]]);
        let subtree = serde_json::json!([[7, 1, 0, 0, 201]]);
        let imt_leaves = serde_json::json!([[1, 0, 0, 200]]);

        let mut plan = RollbackPlan {
            role: RollbackRole::Coordinator,
            realm_id: 0,
            realm_sub_id: 0,
            target_checkpoint_id: 199,
            latest_checkpoint_id: 210,
            latest_pending_id: 104,
            ids,
            target_contract_state: None,
            snapshot: RollbackSnapshot {
                target_info: "00".into(),
                worker_reputation_fields: vec![RollbackTempValueSnapshot { field: worker_reputation_field(0, 0), value: Some("0100000000000000".into()) }],
            },
            phases: Vec::new(),
        };
        for table in expected_tables {
            let keys = match table {
                "TKVSV1" => temp.clone(),
                "TMPPSV1-proof-buckets"
                | "pending_id_to_checkpoint_id_table"
                | "guta_reward_tag_tree_table" => pending_json.clone(),
                "nats_jetstream_consumers" => nats_targets.clone(),
                "checkpoint_leaf_table"
                | "l2_block_state_table"
                | "checkpoint_state_roots_table"
                | "checkpoint_zk_proof_and_transition_table" => checkpoint_json.clone(),
                "checkpoint_id_to_pending_id_table" => mapped_checkpoint_json.clone(),
                "checkpoint_root_to_checkpoint_id_table" => blobs.clone(),
                "checkpoint_id_to_realm_root_table"
                | "checkpoint_leaf_to_checkpoint_id_table"
                | "latest_info_table"
                | "checkpoint_tree_backup"
                | "all"
                | "u64_singleton_table"
                | "user_leaf_table"
                | "user_public_key_table"
                | "contract_state_tree_height_table"
                | "contract_leaf_table"
                | "contract_code_definition_table"
                | "public_key_hash_to_user_ids_table"
                | "imt_key_index_table"
                | "realm_rewards_tree_node_key_table" => serde_json::json!([]),
                "checkpointed_object_table" => checkpointed.clone(),
                "pending_id_to_pending_proc_id_table" => proc_json.clone(),
                "global_user_tree_table"
                | "global_checkpoint_tree_table"
                | "user_registration_tree_table"
                | "global_contract_tree_table" => merkle.clone(),
                "user_contract_tree_table" | "contract_function_tree_table" => tree_merkle.clone(),
                "contract_state_tree_table" => subtree.clone(),
                "imt_leaf_table" => imt_leaves.clone(),
                "imt_next_append_index_table" => serde_json::json!([]),
                "TKVSV1-singletons" => processor_singletons.clone(),
                other => panic!("unhandled table {other}"),
            };
            plan.phases.push(phase_for(table, keys));
        }
        plan
    }

    fn tamper(table: &str, keys: Value) -> RollbackPlan {
        let mut plan = valid_plan();
        let phase = plan.phases.iter_mut().find(|phase| phase.table == table).expect(table);
        phase.keys = keys;
        plan
    }

    #[test]
    fn validator_accepts_frozen_generated_shape() {
        validate_rollback_plan(&valid_plan()).unwrap();
    }

    #[test]
    fn validator_accepts_complete_coordinator_plan() {
        validate_rollback_plan(&valid_plan()).unwrap();
    }

    #[test]
    fn validator_accepts_complete_realm_plan() {
        let mut plan = valid_plan();
        plan.role = RollbackRole::Realm;
        plan.realm_id = 7;
        plan.realm_sub_id = 2;
        plan.snapshot.worker_reputation_fields[0].field = worker_reputation_field(7, 2);
        let realm_nats_targets = serde_json::Value::Array(
            plan.proc_ids()
                .into_iter()
                .flat_map(|proc_id| {
                    rollback_nats_consumer_kinds(RollbackRole::Realm)
                        .iter()
                        .map(move |kind| serde_json::json!({ "kind": kind, "proc_id": proc_id.to_string(), "task_group": 0 }))
                })
                .collect(),
        );
        for phase in &mut plan.phases {
            match phase.table.as_str() {
                "TKVSV1" => {
                    phase.keys = serde_json::json!([
                        pending_field(7, 2, [0x45, 0x50], 88),
                        pending_field(7, 2, [0x45, 0x50], 89),
                        pending_field(7, 2, [0x45, 0x50], 94),
                    ]);
                }
                "TKVSV1-singletons" => {
                    phase.keys = serde_json::json!([
                        singleton_field(7, 2, TEMP_TABLE_PI),
                        singleton_field(7, 2, TEMP_TABLE_GP),
                        singleton_field(7, 2, TEMP_TABLE_PS),
                    ]);
                }
                "nats_jetstream_consumers" => phase.keys = realm_nats_targets.clone(),
                "realm_rewards_tree_node_key_table" => {
                    phase.keys = serde_json::json!([[7, 88], [7, 89], [7, 94]]);
                }
                _ => {}
            }
        }
        validate_rollback_plan(&plan).unwrap();
    }

    #[test]
    fn validator_accepts_realm_zero_identity_and_coordinator_reward_zero() {
        let mut realm = valid_plan();
        realm.role = RollbackRole::Realm;
        let realm_nats_targets = serde_json::Value::Array(
            realm.proc_ids()
                .into_iter()
                .flat_map(|proc_id| {
                    rollback_nats_consumer_kinds(RollbackRole::Realm)
                        .iter()
                        .map(move |kind| serde_json::json!({ "kind": kind, "proc_id": proc_id.to_string(), "task_group": 0 }))
                })
                .collect(),
        );
        realm.phases.iter_mut().find(|phase| phase.table == "nats_jetstream_consumers").unwrap().keys = realm_nats_targets;
        validate_rollback_plan(&realm).unwrap();

        let mut coordinator = valid_plan();
        let phase = coordinator
            .phases
            .iter_mut()
            .find(|phase| phase.table == "realm_rewards_tree_node_key_table")
            .unwrap();
        phase.keys = serde_json::json!([[0, 88], [0, 89], [0, 94]]);
        validate_rollback_plan(&coordinator).unwrap();
    }

    #[test]
    fn validator_rejects_tampered_checkpoint_zero() {
        let err = validate_rollback_plan(&tamper("checkpoint_leaf_table", serde_json::json!([0, 200, 201]))).unwrap_err();
        assert!(err.to_string().contains("id 0"), "{err}");
        let err = validate_rollback_plan(&tamper("checkpointed_object_table", serde_json::json!([[1, 0], [2, 88]]))).unwrap_err();
        assert!(err.to_string().contains("[1, 0]"), "{err}");
        let err = validate_rollback_plan(&tamper("l2_block_state_table", serde_json::json!([0]))).unwrap_err();
        assert!(err.to_string().contains("id 0"), "{err}");
    }

    #[test]
    fn validator_rejects_wrong_pending_or_proc_pair() {
        let err = validate_rollback_plan(&tamper("TMPPSV1-proof-buckets", serde_json::json!([88, 89, 1]))).unwrap_err();
        assert!(err.to_string().contains("frozen ids set"), "{err}");
        let err = validate_rollback_plan(&tamper(
            "pending_id_to_pending_proc_id_table",
            serde_json::json!([[88, "99999"], [89, "10089"], [94, "10094"]]),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("not an ids pair"), "{err}");
        let err = validate_rollback_plan(&tamper("guta_reward_tag_tree_table", serde_json::json!([88, 7]))).unwrap_err();
        assert!(err.to_string().contains("frozen ids set"), "{err}");
    }

    #[test]
    fn validator_rejects_missing_extra_or_wrong_task_group_nats_target() {
        let plan = valid_plan();
        let phase = plan.phases.iter().find(|phase| phase.table == "nats_jetstream_consumers").unwrap();
        let mut missing = phase.keys.as_array().unwrap().clone();
        missing.pop();
        assert!(validate_rollback_plan(&tamper("nats_jetstream_consumers", Value::Array(missing))).is_err());

        let mut extra = phase.keys.as_array().unwrap().clone();
        extra.push(serde_json::json!({ "kind": "realm_proving", "proc_id": "10088", "task_group": 0 }));
        assert!(validate_rollback_plan(&tamper("nats_jetstream_consumers", Value::Array(extra))).is_err());

        let mut wrong_group = phase.keys.as_array().unwrap().clone();
        wrong_group[0]["task_group"] = serde_json::json!(1);
        assert!(validate_rollback_plan(&tamper("nats_jetstream_consumers", Value::Array(wrong_group))).is_err());
    }

    #[test]
    fn validator_rejects_stale_or_unknown_temp_namespace() {
        for table_id in [*b"SC", *b"PA", *b"PL", *b"ER", *b"CF", *b"CI", *b"ZZ"] {
            let err = validate_rollback_plan(&tamper(
                "TKVSV1",
                serde_json::json!([pending_field(0, 0, table_id, 88)]),
            ))
            .unwrap_err();
            assert!(err.to_string().contains("unsupported pending namespace"), "{err}");
        }
    }
    #[test]
    fn validator_rejects_wrong_temp_pending() {
        let err = validate_rollback_plan(&tamper(
            "TKVSV1",
            serde_json::json!([pending_field(0, 0, [0x45, 0x50], 7)]),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("outside frozen pending_set"), "{err}");
    }

    #[test]
    fn validator_rejects_wrong_worker_reputation_realm_or_sub() {
        let mut plan = valid_plan();
        plan.snapshot.worker_reputation_fields[0].field = worker_reputation_field(3, 0);
        let err = validate_rollback_plan(&plan).unwrap_err();
        assert!(err.to_string().contains("exact worker reputation field"), "{err}");
        plan.snapshot.worker_reputation_fields[0].field = worker_reputation_field(0, 9);
        let err = validate_rollback_plan(&plan).unwrap_err();
        assert!(err.to_string().contains("exact worker reputation field"), "{err}");
    }

    #[test]
    fn validator_rejects_noncanonical_worker_reputation_key_length() {
        let mut plan = valid_plan();
        plan.snapshot.worker_reputation_fields[0].field = hex::encode([0u8; 8]);
        let err = validate_rollback_plan(&plan).unwrap_err();
        assert!(err.to_string().contains("exact worker reputation field"), "{err}");
    }

    #[test]
    fn validator_rejects_out_of_branch_protocol_tree_checkpoint() {
        let err = validate_rollback_plan(&tamper("global_user_tree_table", serde_json::json!([[0, 0, 199]]))).unwrap_err();
        assert!(err.to_string().contains("outside frozen checkpoint_set"), "{err}");
        let err = validate_rollback_plan(&tamper("global_checkpoint_tree_table", serde_json::json!([[0, 0, 0]]))).unwrap_err();
        assert!(err.to_string().contains("outside frozen checkpoint_set"), "{err}");
        let err = validate_rollback_plan(&tamper("imt_leaf_table", serde_json::json!([[1, 0, 0, 211]]))).unwrap_err();
        assert!(err.to_string().contains("outside frozen checkpoint_set"), "{err}");
    }

    #[test]
    fn validator_rejects_duplicate_or_zero_imt_append_indexes() {
        let duplicate = serde_json::json!([
            { "tree_id": 1, "tree_sub_id": 2, "next_append_index": 3 },
            { "tree_id": 1, "tree_sub_id": 2, "next_append_index": null }
        ]);
        let err = validate_rollback_plan(&tamper("imt_next_append_index_table", duplicate)).unwrap_err();
        assert!(err.to_string().contains("duplicates tree coordinates"), "{err}");

        let zero = serde_json::json!([{ "tree_id": 1, "tree_sub_id": 2, "next_append_index": 0 }]);
        let err = validate_rollback_plan(&tamper("imt_next_append_index_table", zero)).unwrap_err();
        assert!(err.to_string().contains("non-positive next_append_index"), "{err}");
    }

}