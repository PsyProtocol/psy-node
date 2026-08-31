//! Fail-closed, marker-last execution of a frozen rollback plan.

use std::path::PathBuf;

use psy_node_core::psy_temp_db::{TEMP_TABLE_ID_WORKER_REPUTATION_BYTES, TEMP_TABLE_WORKER_REPUTATION_KEY_SIZE};

use anyhow::{bail, Context};
use async_trait::async_trait;
use serde_json::Value;

use super::{
    plan::{
        write_rollback_plan_atomic, RollbackNatsConsumerKind, RollbackNatsConsumerTarget,
        RollbackPhase, RollbackPhaseStatus, RollbackPlan, RollbackTempValueSnapshot,
    },
    validate::validate_rollback_plan,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImtNextAppendIndex {
    pub tree_id: u64,
    pub tree_sub_id: u64,
    pub next_append_index: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackOperation {
    TempHashFields(Vec<Vec<u8>>),
    ProofPendingIds(Vec<u64>),
    NatsConsumers(Vec<RollbackNatsConsumerTarget>),
    ObjectIds(Vec<u64>),
    ObjectCheckpoints(Vec<(u64, u64)>),
    MerkleNodes(Vec<(u8, u64, u64)>),
    TreeMerkleNodes(Vec<(u64, u8, u64, u64)>),
    TreeSubtreeMerkleNodes(Vec<(u64, u64, u8, u64, u64)>),
    ImtLeaves(Vec<(i64, i64, i64, i64)>),
    ImtKeys(Vec<(i64, i64, i16, Vec<u8>)>),
    HashUserPairs(Vec<(Vec<u8>, u64)>),
    BlobPairs(Vec<(Vec<u8>, Vec<u8>)>),
    U64U128Pairs(Vec<(u64, u128)>),
    PendingPartitions(Vec<u64>),
    RestoreLatestInfo,
    RestoreImtNextAppendIndexes(Vec<ImtNextAppendIndex>),
    RebuildCheckpointRingBuffer,
    Verify,
    SetMarker,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableRollbackPhase {
    pub table: String,
    pub api: String,
    pub operation: RollbackOperation,
}

impl ExecutableRollbackPhase {
    pub fn is_marker(&self) -> bool {
        matches!(self.operation, RollbackOperation::SetMarker)
    }

    fn is_verify(&self) -> bool {
        matches!(self.operation, RollbackOperation::Verify)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackOutcome {
    Completed,
    Reconciled,
}

#[async_trait]
pub trait RollbackExecutionStore: Send + Sync {
    async fn latest_checkpoint_marker(&self) -> anyhow::Result<u64>;
    async fn pending_counter_high_water(&self) -> anyhow::Result<u64>;
    async fn delete_nats_consumers(
        &self,
        plan: &RollbackPlan,
        targets: &[RollbackNatsConsumerTarget],
    ) -> anyhow::Result<()>;

    async fn verify_nats_consumers_absent(
        &self,
        plan: &RollbackPlan,
        targets: &[RollbackNatsConsumerTarget],
    ) -> anyhow::Result<()>;

    async fn execute_phase(
        &self,
        plan: &RollbackPlan,
        phase: &ExecutableRollbackPhase,
    ) -> anyhow::Result<()>;

    async fn verify_phase(
        &self,
        plan: &RollbackPlan,
        phase: &ExecutableRollbackPhase,
    ) -> anyhow::Result<()>;

    async fn delete_post_target_backups(&self, plan: &RollbackPlan) -> anyhow::Result<()>;

    async fn write_latest_checkpoint_marker(&self, target_checkpoint_id: u64)
        -> anyhow::Result<()>;
}

#[async_trait]
pub trait RollbackProgressStore: Send + Sync {
    async fn persist(&self, plan: &RollbackPlan) -> anyhow::Result<()>;
}

#[derive(Debug, Clone)]
pub struct AtomicRollbackPlanProgress {
    path: PathBuf,
    fsync_parent: bool,
}

impl AtomicRollbackPlanProgress {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), fsync_parent: true }
    }
}

#[async_trait]
impl RollbackProgressStore for AtomicRollbackPlanProgress {
    async fn persist(&self, plan: &RollbackPlan) -> anyhow::Result<()> {
        write_rollback_plan_atomic(&self.path, plan, self.fsync_parent).await
    }
}

pub async fn execute_rollback_plan<S, P>(
    store: &S,
    progress: &P,
    plan: &mut RollbackPlan,
) -> anyhow::Result<RollbackOutcome>
where
    S: RollbackExecutionStore + ?Sized,
    P: RollbackProgressStore + ?Sized,
{
    validate_rollback_plan(plan)?;
    let phases = decode_all_phases(plan)?;

    let marker = store.latest_checkpoint_marker().await?;
    if marker != plan.latest_checkpoint_id && marker != plan.target_checkpoint_id {
        bail!(
            "rollback marker mismatch: current {}, RP latest {}, RP target {}",
            marker,
            plan.latest_checkpoint_id,
            plan.target_checkpoint_id
        );
    }
    require_counter_not_regressed(store, plan).await?;

    if marker == plan.target_checkpoint_id {
        reconcile_target(store, progress, plan, &phases).await?;
        return Ok(RollbackOutcome::Reconciled);
    }

    for index in 0..phases.len() {
        if plan.phases[index].status == RollbackPhaseStatus::Completed {
            continue;
        }
        let phase = &phases[index];
        require_marker(store, plan.latest_checkpoint_id, "before phase").await?;

        if phase.is_marker() {
            require_counter_not_regressed(store, plan).await?;
            store
                .delete_post_target_backups(plan)
                .await
                .context("failed to delete post-target gatherer backups")?;
            // Persisted verify does not authorize this write; re-check postconditions before the only commit mutation.
            verify_complete(store, plan, &phases, plan.latest_checkpoint_id).await?;
            store
                .write_latest_checkpoint_marker(plan.target_checkpoint_id)
                .await
                .context("failed to write rollback commit marker")?;
            require_marker(store, plan.target_checkpoint_id, "after marker phase").await?;
        } else if phase.is_verify() {
            verify_complete(store, plan, &phases, plan.latest_checkpoint_id).await?;
        } else {
            match &phase.operation {
                RollbackOperation::NatsConsumers(targets) => {
                    store.delete_nats_consumers(plan, targets).await.with_context(|| {
                        format!("rollback phase {} ({}) failed", phase.table, phase.api)
                    })?;
                }
                _ => store.execute_phase(plan, phase).await.with_context(|| {
                    format!("rollback phase {} ({}) failed", phase.table, phase.api)
                })?,
            }
            require_marker(store, plan.latest_checkpoint_id, "after phase").await?;
        }

        plan.phases[index].status = RollbackPhaseStatus::Completed;
        progress
            .persist(plan)
            .await
            .with_context(|| format!("failed to persist completion of phase {}", phase.table))?;
    }

    require_marker(store, plan.target_checkpoint_id, "after rollback").await?;
    require_counter_not_regressed(store, plan).await?;
    Ok(RollbackOutcome::Completed)
}

async fn reconcile_target<S, P>(
    store: &S,
    progress: &P,
    plan: &mut RollbackPlan,
    phases: &[ExecutableRollbackPhase],
) -> anyhow::Result<()>
where
    S: RollbackExecutionStore + ?Sized,
    P: RollbackProgressStore + ?Sized,
{
    store
        .delete_post_target_backups(plan)
        .await
        .context("failed to delete post-target gatherer backups")?;
    verify_complete(store, plan, phases, plan.target_checkpoint_id).await?;

    for (index, phase) in phases.iter().enumerate() {
        if plan.phases[index].status == RollbackPhaseStatus::Completed {
            continue;
        }
        if phase.is_marker() {
            require_marker(store, plan.target_checkpoint_id, "reconciling marker").await?;
        } else if phase.is_verify() {
            verify_complete(store, plan, phases, plan.target_checkpoint_id).await?;
        } else {
            match &phase.operation {
                RollbackOperation::NatsConsumers(targets) => {
                    store.verify_nats_consumers_absent(plan, targets).await.with_context(|| {
                        format!("reconciliation failed for {} ({})", phase.table, phase.api)
                    })?;
                }
                _ => store.verify_phase(plan, phase).await.with_context(|| {
                    format!("reconciliation failed for {} ({})", phase.table, phase.api)
                })?,
            }
        }
        plan.phases[index].status = RollbackPhaseStatus::Completed;
        progress.persist(plan).await?;
    }
    require_counter_not_regressed(store, plan).await
}

async fn verify_complete<S: RollbackExecutionStore + ?Sized>(
    store: &S,
    plan: &RollbackPlan,
    phases: &[ExecutableRollbackPhase],
    expected_marker: u64,
) -> anyhow::Result<()> {
    require_marker(store, expected_marker, "during postcondition checks").await?;
    for phase in phases {
        if phase.is_marker() || phase.is_verify() {
            continue;
        }
        match &phase.operation {
            RollbackOperation::NatsConsumers(targets) => store
                .verify_nats_consumers_absent(plan, targets)
                .await
                .with_context(|| format!("postcondition failed for {} ({})", phase.table, phase.api))?,
            _ => store
                .verify_phase(plan, phase)
                .await
                .with_context(|| format!("postcondition failed for {} ({})", phase.table, phase.api))?,
        }
        require_marker(store, expected_marker, "during postcondition checks").await?;
    }
    Ok(())
}

async fn require_counter_not_regressed<S: RollbackExecutionStore + ?Sized>(
    store: &S,
    plan: &RollbackPlan,
) -> anyhow::Result<()> {
    let actual = store.pending_counter_high_water().await?;
    if actual != plan.latest_pending_id {
        bail!(
            "pending counter mismatch: current {}, frozen RP high-water {}",
            actual,
            plan.latest_pending_id
        );
    }
    Ok(())
}

async fn require_marker<S: RollbackExecutionStore + ?Sized>(
    store: &S,
    expected: u64,
    context: &str,
) -> anyhow::Result<()> {
    let actual = store.latest_checkpoint_marker().await?;
    if actual != expected {
        bail!("checkpoint marker changed {}: expected {}, got {}", context, expected, actual);
    }
    Ok(())
}


pub fn decode_rollback_phase(phase: &RollbackPhase) -> anyhow::Result<ExecutableRollbackPhase> {
    let table = phase.table.as_str();
    let api = phase.api.as_str();
    let operation = match api {
        "qtdb_raw_kv_delete_key" if matches!(table, "TKVSV1" | "TKVSV1-singletons") => {
            RollbackOperation::TempHashFields(hex_array(&phase.keys, table)?)
        }
        "delete_all_proofs_for_pending_id" if table == "TMPPSV1-proof-buckets" => {
            RollbackOperation::ProofPendingIds(u64_array(&phase.keys, table)?)
        }
        "delete_nats_consumers" if table == "nats_jetstream_consumers" => {
            RollbackOperation::NatsConsumers(nats_consumer_targets(&phase.keys, table)?)
        }
        "db_delete_many_object_ids" if is_object_id_table(table) => {
            RollbackOperation::ObjectIds(u64_array(&phase.keys, table)?)
        }
        "db_delete_many_object_checkpoint" if is_object_checkpoint_table(table) => {
            RollbackOperation::ObjectCheckpoints(tuple2_u64(&phase.keys, table)?)
        }
        "db_delete_many_merkle_nodes" if is_merkle_table(table) => {
            let values = array(&phase.keys, table)?;
            let mut out = Vec::with_capacity(values.len());
            for (i, value) in values.iter().enumerate() {
                let t = fixed_array(value, 3, table, i)?;
                out.push((as_u8(&t[0], table, i)?, as_u64(&t[1], table, i)?, nonzero_checkpoint(&t[2], table, i)?));
            }
            RollbackOperation::MerkleNodes(out)
        }
        "db_delete_many_tree_merkle_nodes" if matches!(table, "user_contract_tree_table" | "contract_function_tree_table") => {
            let values = array(&phase.keys, table)?;
            let mut out = Vec::with_capacity(values.len());
            for (i, value) in values.iter().enumerate() {
                let t = fixed_array(value, 4, table, i)?;
                out.push((as_u64(&t[0], table, i)?, as_u8(&t[1], table, i)?, as_u64(&t[2], table, i)?, nonzero_checkpoint(&t[3], table, i)?));
            }
            RollbackOperation::TreeMerkleNodes(out)
        }
        "db_delete_many_tree_subtree_merkle_nodes" if table == "contract_state_tree_table" => {
            let values = array(&phase.keys, table)?;
            let mut out = Vec::with_capacity(values.len());
            for (i, value) in values.iter().enumerate() {
                let t = fixed_array(value, 5, table, i)?;
                out.push((as_u64(&t[0], table, i)?, as_u64(&t[1], table, i)?, as_u8(&t[2], table, i)?, as_u64(&t[3], table, i)?, nonzero_checkpoint(&t[4], table, i)?));
            }
            RollbackOperation::TreeSubtreeMerkleNodes(out)
        }
        "db_delete_many_imt_leaves" if table == "imt_leaf_table" => {
            let values = array(&phase.keys, table)?;
            let mut out = Vec::with_capacity(values.len());
            for (i, value) in values.iter().enumerate() {
                let t = fixed_array(value, 4, table, i)?;
                let checkpoint_id = as_i64(&t[3], table, i)?;
                if checkpoint_id <= 0 {
                    bail!("{table} key {i} contains non-positive checkpoint {checkpoint_id}");
                }
                out.push((
                    as_i64(&t[0], table, i)?,
                    as_i64(&t[1], table, i)?,
                    as_i64(&t[2], table, i)?,
                    checkpoint_id,
                ));
            }
            RollbackOperation::ImtLeaves(out)
        }
        "db_delete_many_imt_keys" if table == "imt_key_index_table" => {
            let values = array(&phase.keys, table)?;
            let mut out = Vec::with_capacity(values.len());
            for (i, value) in values.iter().enumerate() {
                let t = fixed_array(value, 4, table, i)?;
                out.push((
                    as_i64(&t[0], table, i)?,
                    as_i64(&t[1], table, i)?,
                    as_i16(&t[2], table, i)?,
                    decode_hex_value(&t[3], table, i)?,
                ));
            }
            RollbackOperation::ImtKeys(out)
        }
        "db_delete_many_hash_user_pairs" if table == "public_key_hash_to_user_ids_table" => {
            let values = array(&phase.keys, table)?;
            let mut out = Vec::with_capacity(values.len());
            for (i, value) in values.iter().enumerate() {
                let t = fixed_array(value, 2, table, i)?;
                let hash = decode_hex_value(&t[0], table, i)?;
                if hash.is_empty() || hash.iter().all(|byte| *byte == 0) { bail!("{table} key {i} has an empty/all-zero hash"); }
                out.push((hash, as_u64(&t[1], table, i)?));
            }
            RollbackOperation::HashUserPairs(out)
        }
        "db_delete_many_blob_pairs" if matches!(table, "checkpoint_root_to_checkpoint_id_table" | "checkpoint_leaf_to_checkpoint_id_table") => {
            let values = array(&phase.keys, table)?;
            let mut out = Vec::with_capacity(values.len());
            for (i, value) in values.iter().enumerate() {
                let t = fixed_array(value, 2, table, i)?;
                let root = decode_hex_value(&t[0], table, i)?;
                let cp = decode_hex_value(&t[1], table, i)?;
                if root.len() != 32 || cp.len() != 8 || cp.iter().all(|b| *b == 0) { bail!("{table} key {i} is not one full (32-byte root, nonzero 8-byte checkpoint LE) pair"); }
                out.push((root, cp));
            }
            RollbackOperation::BlobPairs(out)
        }
        "db_delete_many_u64_u128_pairs" if table == "pending_id_to_pending_proc_id_table" => {
            let values = array(&phase.keys, table)?;
            let mut out = Vec::with_capacity(values.len());
            for (i, value) in values.iter().enumerate() {
                let t = fixed_array(value, 2, table, i)?;
                let proc_id_text = match &t[1] {
                    Value::String(value) => value.clone(),
                    Value::Number(value) => value.to_string(),
                    _ => bail!("{table} key {i} has invalid u128 proc id"),
                };
                let proc_id = proc_id_text
                    .parse::<u128>()
                    .map_err(|_| anyhow::anyhow!("{table} key {i} has invalid u128 proc id"))?;
                out.push((as_u64(&t[0], table, i)?, proc_id));
            }
            RollbackOperation::U64U128Pairs(out)
        }
        "db_delete_many_pending_id_partitions" if table == "guta_reward_tag_tree_table" => {
            RollbackOperation::PendingPartitions(u64_array(&phase.keys, table)?)
        }
        "set_latest_info" if table == "latest_info_table" && empty_array(&phase.keys) => RollbackOperation::RestoreLatestInfo,
        "set_imt_next_append_index" if table == "imt_next_append_index_table" => {
            RollbackOperation::RestoreImtNextAppendIndexes(imt_indexes(&phase.keys, table)?)
        }
        "rebuild_checkpoint_tree_backup" if table == "checkpoint_tree_backup" && empty_array(&phase.keys) => RollbackOperation::RebuildCheckpointRingBuffer,
        "verify" if table == "all" && empty_array(&phase.keys) => RollbackOperation::Verify,
        "set_latest_checkpoint_id" if table == "u64_singleton_table" && empty_array(&phase.keys) => RollbackOperation::SetMarker,
        _ => bail!("unknown rollback table/API/key shape: table={table}, api={api}"),
    };
    Ok(ExecutableRollbackPhase { table: phase.table.clone(), api: phase.api.clone(), operation })
}

fn decode_all_phases(plan: &RollbackPlan) -> anyhow::Result<Vec<ExecutableRollbackPhase>> {
    plan.phases.iter().map(decode_rollback_phase).collect()
}

fn is_object_id_table(table: &str) -> bool {
    matches!(table, "checkpoint_leaf_table" | "l2_block_state_table" | "checkpoint_id_to_realm_root_table" | "checkpoint_state_roots_table" | "checkpoint_zk_proof_and_transition_table" | "checkpoint_id_to_pending_id_table" | "pending_id_to_checkpoint_id_table")
}

fn is_object_checkpoint_table(table: &str) -> bool {
    matches!(table, "user_leaf_table" | "user_public_key_table" | "contract_state_tree_height_table" | "contract_leaf_table" | "contract_code_definition_table" | "checkpointed_object_table" | "realm_rewards_tree_node_key_table")
}

fn is_merkle_table(table: &str) -> bool {
    matches!(table, "global_user_tree_table" | "global_checkpoint_tree_table" | "user_registration_tree_table" | "global_contract_tree_table")
}

fn nats_consumer_targets(value: &Value, label: &str) -> anyhow::Result<Vec<RollbackNatsConsumerTarget>> {
    array(value, label)?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let target = value.as_object().ok_or_else(|| anyhow::anyhow!("{label} key {index} must be an object"))?;
            if target.len() != 3 || !target.contains_key("kind") || !target.contains_key("proc_id") || !target.contains_key("task_group") {
                bail!("{label} key {index} must contain exactly kind, proc_id, task_group");
            }
            let kind: RollbackNatsConsumerKind = serde_json::from_value(target["kind"].clone())
                .map_err(|_| anyhow::anyhow!("{label} key {index} has invalid kind"))?;
            let proc_id = match &target["proc_id"] {
                Value::String(value) => value.parse::<u128>(),
                Value::Number(value) => value.to_string().parse::<u128>(),
                _ => bail!("{label} key {index} has invalid proc_id"),
            }
            .map_err(|_| anyhow::anyhow!("{label} key {index} has invalid proc_id"))?;
            let task_group = target["task_group"]
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| anyhow::anyhow!("{label} key {index} has invalid task_group"))?;
            Ok(RollbackNatsConsumerTarget { kind, proc_id, task_group })
        })
        .collect()
}

fn array<'a>(value: &'a Value, label: &str) -> anyhow::Result<&'a Vec<Value>> {
    value.as_array().ok_or_else(|| anyhow::anyhow!("{label} keys must be an array"))
}

fn empty_array(value: &Value) -> bool { value.as_array().is_some_and(Vec::is_empty) }

fn fixed_array<'a>(value: &'a Value, len: usize, table: &str, index: usize) -> anyhow::Result<&'a [Value]> {
    let values = value.as_array().ok_or_else(|| anyhow::anyhow!("{table} key {index} must be an array"))?;
    if values.len() != len { bail!("{table} key {index} must contain exactly {len} values"); }
    Ok(values)
}

fn as_u64(value: &Value, table: &str, index: usize) -> anyhow::Result<u64> {
    value.as_u64().ok_or_else(|| anyhow::anyhow!("{table} key {index} contains a non-u64 value"))
}

fn as_i64(value: &Value, table: &str, index: usize) -> anyhow::Result<i64> {
    value.as_i64().ok_or_else(|| anyhow::anyhow!("{table} key {index} contains a non-i64 value"))
}

fn as_i16(value: &Value, table: &str, index: usize) -> anyhow::Result<i16> {
    i16::try_from(as_i64(value, table, index)?)
        .map_err(|_| anyhow::anyhow!("{table} key {index} contains a value outside i16 range"))
}

fn as_u8(value: &Value, table: &str, index: usize) -> anyhow::Result<u8> {
    u8::try_from(as_u64(value, table, index)?).map_err(Into::into)
}

fn nonzero_checkpoint(value: &Value, table: &str, index: usize) -> anyhow::Result<u64> {
    let cp = as_u64(value, table, index)?;
    if cp == 0 { bail!("{table} key {index} contains checkpoint 0"); }
    Ok(cp)
}

fn u64_array(value: &Value, table: &str) -> anyhow::Result<Vec<u64>> {
    array(value, table)?.iter().enumerate().map(|(i, v)| as_u64(v, table, i)).collect()
}

fn tuple2_u64(value: &Value, table: &str) -> anyhow::Result<Vec<(u64, u64)>> {
    let mut out = Vec::new();
    for (i, value) in array(value, table)?.iter().enumerate() {
        let t = fixed_array(value, 2, table, i)?;
        let key = (as_u64(&t[0], table, i)?, as_u64(&t[1], table, i)?);
        if table != "checkpointed_object_table" && table != "realm_rewards_tree_node_key_table" && key.1 == 0 { bail!("{table} key {i} contains checkpoint 0"); }
        out.push(key);
    }
    Ok(out)
}

fn decode_hex(value: &str, label: &str) -> anyhow::Result<Vec<u8>> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(raw).with_context(|| format!("{label} is not valid hexadecimal"))
}

fn decode_hex_value(value: &Value, table: &str, index: usize) -> anyhow::Result<Vec<u8>> {
    let text = value.as_str().ok_or_else(|| anyhow::anyhow!("{table} key {index} must contain a hex string"))?;
    decode_hex(text, &format!("{table} key {index}"))
}

fn hex_array(value: &Value, table: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    array(value, table)?.iter().enumerate().map(|(i, v)| decode_hex_value(v, table, i)).collect()
}

fn imt_indexes(value: &Value, table: &str) -> anyhow::Result<Vec<ImtNextAppendIndex>> {
    let mut out = Vec::new();
    for (index, value) in array(value, table)?.iter().enumerate() {
        let obj = value.as_object().ok_or_else(|| anyhow::anyhow!("{table} key {index} must be an object"))?;
        if obj.len() != 3 || !obj.contains_key("tree_id") || !obj.contains_key("tree_sub_id") || !obj.contains_key("next_append_index") { bail!("{table} key {index} must contain exactly tree_id, tree_sub_id, next_append_index"); }
        let next_append_index = match &obj["next_append_index"] {
            Value::Null => None,
            Value::Number(value) => Some(value.as_i64().ok_or_else(|| anyhow::anyhow!("{table} key {index} has invalid next_append_index"))?),
            _ => bail!("{table} key {index} has invalid next_append_index"),
        };
        if next_append_index.is_some_and(|value| value <= 0) {
            bail!("{table} key {index} has non-positive next_append_index");
        }
        out.push(ImtNextAppendIndex {
            tree_id: obj["tree_id"].as_u64().ok_or_else(|| anyhow::anyhow!("{table} key {index} has invalid tree_id"))?,
            tree_sub_id: obj["tree_sub_id"].as_u64().ok_or_else(|| anyhow::anyhow!("{table} key {index} has invalid tree_sub_id"))?,
            next_append_index,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rollback::generator::{api_for_table, EMPTY_SCHEMA_TABLES, FINAL_TABLES, STAGE1_TABLES, STAGE2_TABLES, STAGE3_TABLES};
    use crate::rollback::plan::{
        rollback_nats_consumer_kinds, PostTargetGeneration, RollbackRole, RollbackSnapshot,
    };
    use std::collections::HashSet;
    use std::sync::Mutex;
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum StoreEvent {
        Execute(String),
        Verify(String),
        DeleteBackups,
        WriteMarker(u64),
    }

    struct FakeState {
        marker: u64,
        counter: u64,
        applied: Vec<String>,
        residual: HashSet<String>,
        marker_writes: usize,
        leftover_backups: bool,
        backup_deletes: usize,
        events: Vec<StoreEvent>,
    }

    struct FakeStore {
        state: Mutex<FakeState>,
        fail_execute: Mutex<Option<String>>,
        fail_verify: Mutex<Option<String>>,
        fail_marker_write: Mutex<bool>,
        fail_delete_backups: Mutex<bool>,
    }

    impl FakeStore {
        fn new(marker: u64, counter: u64) -> Self {
            Self {
                state: Mutex::new(FakeState {
                    marker,
                    counter,
                    applied: Vec::new(),
                    residual: HashSet::new(),
                    marker_writes: 0,
                    events: Vec::new(),
                    leftover_backups: false,
                    backup_deletes: 0,
                }),
                fail_execute: Mutex::new(None),
                fail_verify: Mutex::new(None),
                fail_marker_write: Mutex::new(false),
                fail_delete_backups: Mutex::new(false),
            }
        }

        fn fail_execute(&self, table: Option<String>) {
            *self.fail_execute.lock().unwrap() = table;
        }

        fn fail_verify(&self, table: Option<String>) {
            *self.fail_verify.lock().unwrap() = table;
        }

        fn fail_marker_write(&self, value: bool) {
            *self.fail_marker_write.lock().unwrap() = value;
        }

        fn fail_delete_backups(&self, value: bool) {
            *self.fail_delete_backups.lock().unwrap() = value;
        }

        fn add_leftover_backups(&self) {
            self.state.lock().unwrap().leftover_backups = true;
        }

        fn add_residual(&self, table: String) {
            self.state.lock().unwrap().residual.insert(table);
        }

        fn marker(&self) -> u64 {
            self.state.lock().unwrap().marker
        }

        fn counter(&self) -> u64 {
            self.state.lock().unwrap().counter
        }

        fn applied(&self) -> Vec<String> {
            self.state.lock().unwrap().applied.clone()
        }

        fn marker_writes(&self) -> usize {
            self.state.lock().unwrap().marker_writes
        }

        fn leftover_backups(&self) -> bool {
            self.state.lock().unwrap().leftover_backups
        }

        fn backup_deletes(&self) -> usize {
            self.state.lock().unwrap().backup_deletes
        }

        fn events(&self) -> Vec<StoreEvent> {
            self.state.lock().unwrap().events.clone()
        }
    }

    #[async_trait]
    impl RollbackExecutionStore for FakeStore {
        async fn latest_checkpoint_marker(&self) -> anyhow::Result<u64> {
            Ok(self.state.lock().unwrap().marker)
        }

        async fn pending_counter_high_water(&self) -> anyhow::Result<u64> {
            Ok(self.state.lock().unwrap().counter)
        }

        async fn delete_nats_consumers(
            &self,
            _plan: &RollbackPlan,
            _targets: &[RollbackNatsConsumerTarget],
        ) -> anyhow::Result<()> {
            let phase = "nats_jetstream_consumers".to_string();
            if self.fail_execute.lock().unwrap().as_deref() == Some(phase.as_str()) {
                *self.fail_execute.lock().unwrap() = None;
                bail!("injected execute failure at table {phase}");
            }
            let mut state = self.state.lock().unwrap();
            state.applied.push(phase.clone());
            state.events.push(StoreEvent::Execute(phase));
            Ok(())
        }

        async fn verify_nats_consumers_absent(
            &self,
            plan: &RollbackPlan,
            _targets: &[RollbackNatsConsumerTarget],
        ) -> anyhow::Result<()> {
            let phase = "nats_jetstream_consumers".to_string();
            {
                let mut fail = self.fail_verify.lock().unwrap();
                if fail.as_deref() == Some(phase.as_str()) {
                    *fail = None;
                    bail!("injected verify failure at table {phase}");
                }
            }
            let mut state = self.state.lock().unwrap();
            if state.residual.contains(phase.as_str()) {
                bail!("residual keys remain at table {phase}");
            }
            if !state.applied.iter().any(|applied| applied == &phase)
                && state.marker != plan.target_checkpoint_id
            {
                bail!("table {phase} not applied and marker not at target");
            }
            state.events.push(StoreEvent::Verify(phase));
            Ok(())
        }

        async fn execute_phase(
            &self,
            _plan: &RollbackPlan,
            phase: &ExecutableRollbackPhase,
        ) -> anyhow::Result<()> {
            {
                let mut fail = self.fail_execute.lock().unwrap();
                if fail.as_deref() == Some(phase.table.as_str()) {
                    *fail = None;
                    bail!("injected execute failure at table {}", phase.table);
                }
            }
            let mut state = self.state.lock().unwrap();
            state.applied.push(phase.table.clone());
            state.events.push(StoreEvent::Execute(phase.table.clone()));
            Ok(())
        }

        async fn verify_phase(
            &self,
            plan: &RollbackPlan,
            phase: &ExecutableRollbackPhase,
        ) -> anyhow::Result<()> {
            {
                let mut fail = self.fail_verify.lock().unwrap();
                if fail.as_deref() == Some(phase.table.as_str()) {
                    *fail = None;
                    bail!("injected verify failure at table {}", phase.table);
                }
            }
            let mut state = self.state.lock().unwrap();
            if state.residual.contains(phase.table.as_str()) {
                bail!("residual keys remain at table {}", phase.table);
            }
            if !state.applied.iter().any(|applied| applied == &phase.table)
                && state.marker != plan.target_checkpoint_id
            {
                bail!("table {} not applied and marker not at target", phase.table);
            }
            state.events.push(StoreEvent::Verify(phase.table.clone()));
            Ok(())
        }


        async fn delete_post_target_backups(&self, _plan: &RollbackPlan) -> anyhow::Result<()> {
            {
                let mut fail = self.fail_delete_backups.lock().unwrap();
                if *fail {
                    *fail = false;
                    bail!("injected post-target backup delete failure");
                }
            }
            let mut state = self.state.lock().unwrap();
            state.leftover_backups = false;
            state.backup_deletes += 1;
            state.events.push(StoreEvent::DeleteBackups);
            Ok(())
        }
        async fn write_latest_checkpoint_marker(
            &self,
            target_checkpoint_id: u64,
        ) -> anyhow::Result<()> {
            {
                let mut fail = self.fail_marker_write.lock().unwrap();
                if *fail {
                    *fail = false;
                    bail!("injected marker write failure");
                }
            }
            let mut state = self.state.lock().unwrap();
            state.marker = target_checkpoint_id;
            state.marker_writes += 1;
            state.events.push(StoreEvent::WriteMarker(target_checkpoint_id));
            Ok(())
        }
    }

    struct FakeProgressStore {
        snapshots: Mutex<Vec<RollbackPlan>>,
        fail_after_marker_status: Mutex<bool>,
    }

    impl FakeProgressStore {
        fn new() -> Self {
            Self {
                snapshots: Mutex::new(Vec::new()),
                fail_after_marker_status: Mutex::new(false),
            }
        }

        fn fail_after_marker_status(&self, value: bool) {
            *self.fail_after_marker_status.lock().unwrap() = value;
        }

        fn snapshots(&self) -> Vec<RollbackPlan> {
            self.snapshots.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl RollbackProgressStore for FakeProgressStore {
        async fn persist(&self, plan: &RollbackPlan) -> anyhow::Result<()> {
            self.snapshots.lock().unwrap().push(plan.clone());
            let marker_completed = plan
                .phases
                .last()
                .is_some_and(|phase| phase.status == RollbackPhaseStatus::Completed);
            let mut fail = self.fail_after_marker_status.lock().unwrap();
            if marker_completed && *fail {
                *fail = false;
                bail!("injected progress persist failure after marker status mutation");
            }
            Ok(())
        }
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
        let mut field = vec![0u8; TEMP_TABLE_WORKER_REPUTATION_KEY_SIZE];
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

    fn blob_pair(checkpoint_id: u64) -> Value {
        let root = format!("0x{}", hex::encode([checkpoint_id as u8; 32]));
        let checkpoint = format!("0x{}", hex::encode(checkpoint_id.to_le_bytes()));
        serde_json::json!([root, checkpoint])
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

    fn data_phase_tables() -> Vec<String> {
        let mut tables: Vec<String> = STAGE1_TABLES.iter().map(|table| table.to_string()).collect();
        tables.extend(STAGE2_TABLES.iter().map(|table| table.to_string()));
        tables.extend(EMPTY_SCHEMA_TABLES.iter().map(|table| table.to_string()));
        tables.extend(STAGE3_TABLES.iter().map(|table| table.to_string()));
        tables.extend(FINAL_TABLES[..4].iter().map(|table| table.to_string()));
        tables
    }

    fn build_plan(
        role: RollbackRole,
        realm_id: u64,
        realm_sub_id: u64,
        target: u64,
        latest: u64,
        latest_pending_id: u64,
        post_target_generations: Vec<PostTargetGeneration>,
    ) -> RollbackPlan {
        let checkpoint_ids: Vec<u64> = if target >= latest {
            Vec::new()
        } else {
            (target + 1..=latest).collect()
        };
        let checkpoint_set: HashSet<u64> = checkpoint_ids.iter().copied().collect();
        let mapped_checkpoint_ids: Vec<u64> = post_target_generations.iter().filter_map(|entry| entry.checkpoint_id).collect();
        let mapped_set: HashSet<u64> = mapped_checkpoint_ids.iter().copied().collect();
        let pending_ids: Vec<u64> = post_target_generations.iter().map(|entry| entry.pending_id).collect();
        let pending_set: HashSet<u64> = pending_ids.iter().copied().collect();
        let realm_le = u32::try_from(realm_id).expect("fixture realm_id fits u32").to_le_bytes();
        let sub_le = u16::try_from(realm_sub_id).expect("fixture realm_sub_id fits u16").to_le_bytes();

        let temp = serde_json::json!(pending_ids
            .iter()
            .map(|&pending| pending_field(realm_id as u32, realm_sub_id as u16, [0x45, 0x50], pending))
            .collect::<Vec<_>>());
        let pending_json = serde_json::json!(pending_ids);
        let checkpoint_json = serde_json::json!(checkpoint_ids);
        let mapped_json = serde_json::json!(mapped_checkpoint_ids);
        let proc_json = serde_json::json!(post_target_generations
            .iter()
            .map(|entry| {
                serde_json::json!([entry.pending_id, entry.proc_checkpoint_unique_id.to_string()])
            })
            .collect::<Vec<_>>());
        let checkpointed = serde_json::json!(checkpoint_ids
            .iter()
            .map(|&cp| serde_json::json!([1, cp]))
            .chain(pending_ids.iter().map(|&pending| serde_json::json!([2, pending])))
            .collect::<Vec<_>>());
        let blobs = serde_json::json!(checkpoint_ids.iter().map(|&cp| blob_pair(cp)).collect::<Vec<_>>());
        let object_pairs = serde_json::json!(checkpoint_ids
            .iter()
            .map(|&cp| serde_json::json!([1, cp]))
            .collect::<Vec<_>>());
        let rewards_realm = if role == RollbackRole::Realm { realm_id } else { 1 };
        let rewards = serde_json::json!(pending_ids
            .iter()
            .map(|&pending| serde_json::json!([rewards_realm, pending]))
            .collect::<Vec<_>>());
        let merkle = serde_json::json!(checkpoint_ids
            .iter()
            .map(|&cp| serde_json::json!([0, 0, cp]))
            .collect::<Vec<_>>());
        let tree_merkle = serde_json::json!(checkpoint_ids
            .iter()
            .map(|&cp| serde_json::json!([1, 0, 0, cp]))
            .collect::<Vec<_>>());
        let subtree = serde_json::json!(checkpoint_ids
            .iter()
            .map(|&cp| serde_json::json!([1, 0, 0, 0, cp]))
            .collect::<Vec<_>>());
        let imt_leaves = serde_json::json!(checkpoint_ids
            .iter()
            .map(|&cp| serde_json::json!([1, 0, 0, cp]))
            .collect::<Vec<_>>());
        let processor_singletons = serde_json::json!([
            singleton_field(realm_id as u32, realm_sub_id as u16, [0x50, 0x49]),
            singleton_field(realm_id as u32, realm_sub_id as u16, [0x47, 0x50]),
            singleton_field(realm_id as u32, realm_sub_id as u16, [0x50, 0x53]),
        ]);
        let imt_indexes = serde_json::json!([{ "tree_id": 1, "tree_sub_id": 0, "next_append_index": 5 }]);
        let empty = serde_json::json!([]);

        let mut plan = RollbackPlan {
            role,
            realm_id,
            realm_sub_id,
            target_checkpoint_id: target,
            latest_checkpoint_id: latest,
            latest_pending_id,
            post_target_generations,
            target_contract_state: None,
            snapshot: RollbackSnapshot {
                target_info: "00".into(),
                worker_reputation_fields: vec![RollbackTempValueSnapshot {
                    field: worker_reputation_field(realm_id as u32, realm_sub_id as u16),
                    value: Some("0100000000000000".into()),
                }],
            },
            phases: Vec::new(),
        };

        let nats_targets = serde_json::Value::Array(
            plan.proc_ids()
                .into_iter()
                .flat_map(|proc_id| {
                    rollback_nats_consumer_kinds(plan.role)
                        .iter()
                        .map(move |kind| serde_json::json!({ "kind": kind, "proc_id": proc_id.to_string(), "task_group": 0 }))
                })
                .collect(),
        );
        let mut expected_tables = Vec::new();
        expected_tables.extend_from_slice(STAGE1_TABLES);
        expected_tables.extend_from_slice(STAGE2_TABLES);
        expected_tables.extend_from_slice(EMPTY_SCHEMA_TABLES);
        expected_tables.extend_from_slice(STAGE3_TABLES);
        expected_tables.extend_from_slice(FINAL_TABLES);
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
                "checkpoint_id_to_pending_id_table" => mapped_json.clone(),
                "checkpoint_root_to_checkpoint_id_table" => blobs.clone(),
                "checkpointed_object_table" => checkpointed.clone(),
                "user_leaf_table"
                | "user_public_key_table"
                | "contract_state_tree_height_table"
                | "contract_leaf_table"
                | "contract_code_definition_table" => object_pairs.clone(),
                "realm_rewards_tree_node_key_table" => rewards.clone(),
                "public_key_hash_to_user_ids_table" => serde_json::json!([["0102", 1]]),
                "pending_id_to_pending_proc_id_table" => proc_json.clone(),
                "imt_key_index_table" => serde_json::json!([[1, 0, 1, "0102"]]),
                "global_user_tree_table"
                | "global_checkpoint_tree_table"
                | "user_registration_tree_table"
                | "global_contract_tree_table" => merkle.clone(),
                "user_contract_tree_table" | "contract_function_tree_table" => tree_merkle.clone(),
                "contract_state_tree_table" => subtree.clone(),
                "imt_leaf_table" => imt_leaves.clone(),
                "imt_next_append_index_table" => imt_indexes.clone(),
                "TKVSV1-singletons" => processor_singletons.clone(),
                "latest_info_table"
                | "checkpoint_id_to_realm_root_table"
                | "checkpoint_leaf_to_checkpoint_id_table"
                | "checkpoint_tree_backup"
                | "all"
                | "u64_singleton_table" => empty.clone(),
                other => panic!("unhandled table {other}"),
            };
            plan.phases.push(phase_for(table, keys));
        }
        plan
    }

    fn coordinator_plan() -> RollbackPlan {
        build_plan(
            RollbackRole::Coordinator,
            0,
            0,
            199,
            210,
            104,
            vec![
                PostTargetGeneration { checkpoint_id: Some(200), pending_id: 88, proc_checkpoint_unique_id: 10088 },
                PostTargetGeneration { checkpoint_id: Some(201), pending_id: 89, proc_checkpoint_unique_id: 10089 },
                PostTargetGeneration { checkpoint_id: None, pending_id: 94, proc_checkpoint_unique_id: 10094 },
            ],
        )
    }

    fn realm_plan() -> RollbackPlan {
        build_plan(
            RollbackRole::Realm,
            3,
            0,
            50,
            60,
            777,
            vec![
                PostTargetGeneration { checkpoint_id: Some(52), pending_id: 500, proc_checkpoint_unique_id: 50500 },
                PostTargetGeneration { checkpoint_id: Some(55), pending_id: 501, proc_checkpoint_unique_id: 50501 },
                PostTargetGeneration { checkpoint_id: None, pending_id: 600, proc_checkpoint_unique_id: 50600 },
                PostTargetGeneration { checkpoint_id: Some(60), pending_id: 601, proc_checkpoint_unique_id: 50601 },
            ],
        )
    }

    #[tokio::test]
    async fn coordinator_completes_all_phases_in_order() {
        let mut plan = coordinator_plan();
        let store = FakeStore::new(plan.latest_checkpoint_id, plan.latest_pending_id);
        let progress = FakeProgressStore::new();
        let contract_state_before = plan.target_contract_state.clone();

        let outcome = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap();
        assert_eq!(outcome, RollbackOutcome::Completed);

        let n = data_phase_tables().len();
        assert_eq!(store.applied(), data_phase_tables());

        let events = store.events();
        assert_eq!(events.len(), 3 * n + 2);
        assert!(events[..n].iter().all(|event| matches!(event, StoreEvent::Execute(_))));
        assert!(events[n..2 * n].iter().all(|event| matches!(event, StoreEvent::Verify(_))));
        assert_eq!(events[2 * n], StoreEvent::DeleteBackups);
        assert!(events[2 * n + 1..3 * n + 1].iter().all(|event| matches!(event, StoreEvent::Verify(_))));
        assert_eq!(events[3 * n + 1], StoreEvent::WriteMarker(plan.target_checkpoint_id));
        assert_eq!(store.backup_deletes(), 1);

        assert_eq!(store.marker(), plan.target_checkpoint_id);
        assert_eq!(store.marker_writes(), 1);
        assert_eq!(store.counter(), plan.latest_pending_id, "executor must not move the pending counter");
        assert_eq!(plan.target_contract_state, contract_state_before, "target contract state is passive and must not be mutated");
        assert!(plan.phases.iter().all(|phase| phase.status == RollbackPhaseStatus::Completed));

        let snapshots = progress.snapshots();
        assert_eq!(snapshots.len(), n + 2);
        for (k, snapshot) in snapshots.iter().enumerate() {
            let completed = snapshot
                .phases
                .iter()
                .filter(|phase| phase.status == RollbackPhaseStatus::Completed)
                .count();
            assert_eq!(completed, k + 1, "snapshot {k} must capture exactly the phases completed so far");
        }
    }

    #[tokio::test]
    async fn realm_completes_with_independent_post_target_generations() {
        let mut plan = realm_plan();
        assert_eq!(plan.role, RollbackRole::Realm);
        assert_ne!(plan.realm_id, 0, "Realm RP must use a nonzero realm_id");
        let post_target_generations_before = plan.post_target_generations.clone();
        let contract_state_before = plan.target_contract_state.clone();
        let store = FakeStore::new(plan.latest_checkpoint_id, plan.latest_pending_id);
        let progress = FakeProgressStore::new();

        let outcome = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap();
        assert_eq!(outcome, RollbackOutcome::Completed);
        assert_eq!(store.applied(), data_phase_tables());
        assert_eq!(store.marker(), plan.target_checkpoint_id);
        assert_eq!(store.counter(), plan.latest_pending_id);
        assert_eq!(plan.post_target_generations, post_target_generations_before, "post_target_generations is frozen input and must not be mutated");
        assert_eq!(plan.target_contract_state, contract_state_before);
        assert!(plan.phases.iter().all(|phase| phase.status == RollbackPhaseStatus::Completed));
    }

    #[tokio::test]
    async fn target_equals_latest_reconciles_without_mutation() {
        let mut plan = build_plan(
            RollbackRole::Coordinator,
            0,
            0,
            210,
            210,
            104,
            Vec::new(),
        );
        let store = FakeStore::new(plan.latest_checkpoint_id, plan.latest_pending_id);
        let progress = FakeProgressStore::new();

        let outcome = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap();

        assert_eq!(outcome, RollbackOutcome::Reconciled);
        assert!(store.applied().is_empty(), "§12 target==latest must not execute destructive phases");
        assert_eq!(store.marker_writes(), 0, "reconciliation must not rewrite the current marker");
        assert_eq!(store.backup_deletes(), 1, "reconciliation must still delete leftover post-target backups");
        let events = store.events();
        assert!(
            events.iter().all(|event| matches!(event, StoreEvent::Verify(_) | StoreEvent::DeleteBackups)),
            "reconciliation may only delete leftover backups and verify postconditions"
        );
        let delete_pos = events.iter().position(|event| matches!(event, StoreEvent::DeleteBackups)).expect("reconciliation must delete leftovers");
        let first_verify_pos = events.iter().position(|event| matches!(event, StoreEvent::Verify(_))).expect("reconciliation must verify postconditions");
        assert!(delete_pos < first_verify_pos, "reconciliation must delete leftover backups before verifying postconditions");
        assert!(plan.phases.iter().all(|phase| phase.status == RollbackPhaseStatus::Completed));
    }

    #[tokio::test]
    async fn crash_before_marker_resumes_without_duplicate_execution() {
        for crash in ["marker_write", "verify_phase", "data_phase"] {
            let mut plan = coordinator_plan();
            let store = FakeStore::new(plan.latest_checkpoint_id, plan.latest_pending_id);
            match crash {
                "marker_write" => store.fail_marker_write(true),
                "verify_phase" => store.fail_verify(Some("imt_leaf_table".into())),
                "data_phase" => store.fail_execute(Some("user_leaf_table".into())),
                other => panic!("unknown crash point {other}"),
            }
            let progress = FakeProgressStore::new();

            let err = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap_err();
            assert_eq!(store.marker(), plan.latest_checkpoint_id, "marker must be untouched after crash");
            match crash {
                "marker_write" => assert!(err.to_string().contains("marker"), "{err}"),
                "verify_phase" => assert!(err.to_string().contains("imt_leaf_table"), "{err}"),
                "data_phase" => assert!(err.to_string().contains("user_leaf_table"), "{err}"),
                other => panic!("unknown crash point {other}"),
            }
            let executed_before = store.applied().len();

            let outcome = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap();
            assert_eq!(outcome, RollbackOutcome::Completed);
            assert_eq!(store.applied(), data_phase_tables(), "resume must not duplicate or reorder execution");
            if crash == "data_phase" {
                assert!(store.applied().len() > executed_before, "resume must execute the remaining phases");
            }
            assert_eq!(store.marker(), plan.target_checkpoint_id);
            assert_eq!(store.marker_writes(), 1);
            assert_eq!(store.counter(), plan.latest_pending_id);
            assert!(plan.phases.iter().all(|phase| phase.status == RollbackPhaseStatus::Completed));
        }
    }

    #[tokio::test]
    async fn crash_after_verify_rechecks_postconditions_before_marker() {
        let mut plan = coordinator_plan();
        let store = FakeStore::new(plan.latest_checkpoint_id, plan.latest_pending_id);
        store.fail_marker_write(true);
        let progress = FakeProgressStore::new();

        let err = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap_err();
        assert!(err.to_string().contains("marker"), "{err}");
        assert_eq!(store.marker(), plan.latest_checkpoint_id);
        assert_eq!(store.marker_writes(), 0);
        assert_eq!(store.applied(), data_phase_tables());

        let verify_index = plan.phases.len() - 2;
        assert_eq!(plan.phases[verify_index].table, "all");
        assert_eq!(plan.phases[verify_index].status, RollbackPhaseStatus::Completed);
        assert_eq!(plan.phases.last().unwrap().status, RollbackPhaseStatus::Pending);

        store.add_residual("l2_block_state_table".into());
        let applied_before = store.applied();

        let err = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap_err();
        assert!(err.to_string().contains("l2_block_state_table"), "{err}");
        assert_eq!(store.applied(), applied_before, "resume must not re-execute destructive phases");
        assert_eq!(store.marker_writes(), 0, "residual after persisted verify must block the marker");
        assert_eq!(store.marker(), plan.latest_checkpoint_id);
        assert_eq!(plan.phases.last().unwrap().status, RollbackPhaseStatus::Pending);
        assert!(
            store.events().iter().rev().take_while(|event| !matches!(event, StoreEvent::Execute(_))).all(|event| {
                matches!(event, StoreEvent::Verify(_) | StoreEvent::DeleteBackups)
            }),
            "resume after persisted verify may only delete leftovers and re-check postconditions before refusing the marker"
        );
    }

    #[tokio::test]
    async fn marker_persist_failure_reconciles_on_second_run() {
        let mut plan = coordinator_plan();
        let store = FakeStore::new(plan.latest_checkpoint_id, plan.latest_pending_id);
        let progress = FakeProgressStore::new();
        progress.fail_after_marker_status(true);

        let err = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap_err();
        assert!(err.to_string().contains("persist"), "{err}");
        assert_eq!(store.marker(), plan.target_checkpoint_id);
        assert_eq!(store.marker_writes(), 1);
        assert_eq!(store.applied(), data_phase_tables());
        let snapshots = progress.snapshots();
        assert!(snapshots[snapshots.len() - 1]
            .phases
            .iter()
            .all(|phase| phase.status == RollbackPhaseStatus::Completed),
            "failed persist must carry the marker-phase status mutation");

        plan.phases.last_mut().unwrap().status = RollbackPhaseStatus::Pending;

        let snapshots_before = progress.snapshots().len();
        let outcome = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap();
        assert_eq!(outcome, RollbackOutcome::Reconciled);
        assert_eq!(store.applied(), data_phase_tables(), "reconciliation must not execute phases");
        assert_eq!(store.marker_writes(), 1, "reconciliation must not rewrite the marker");
        assert_eq!(store.marker(), plan.target_checkpoint_id);
        assert_eq!(store.counter(), plan.latest_pending_id);
        assert!(plan.phases.iter().all(|phase| phase.status == RollbackPhaseStatus::Completed));
        assert_eq!(
            progress.snapshots().len(),
            snapshots_before + 1,
            "reconciliation must persist the marker-phase completion"
        );
    }

    #[tokio::test]
    async fn residual_phase_fails_reconciliation_before_mutation() {
        let mut plan = coordinator_plan();
        let store = FakeStore::new(plan.target_checkpoint_id, plan.latest_pending_id);
        store.add_residual("l2_block_state_table".into());
        let progress = FakeProgressStore::new();

        let err = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap_err();
        assert!(err.to_string().contains("l2_block_state_table"), "{err}");
        assert!(store.applied().is_empty(), "residual must reject before any mutation");
        assert_eq!(store.marker_writes(), 0);
        assert_eq!(store.backup_deletes(), 1, "reconciliation still deletes leftover backups before residual verify");
        assert_eq!(store.marker(), plan.target_checkpoint_id);
        assert!(
            store.events().iter().all(|event| matches!(event, StoreEvent::Verify(_) | StoreEvent::DeleteBackups)),
            "only leftover backup delete and read-only postcondition checks may run before the residual is detected"
        );
        let delete_pos = store.events().iter().position(|event| matches!(event, StoreEvent::DeleteBackups)).expect("residual reconciliation must still delete leftovers");
        let first_verify_pos = store.events().iter().position(|event| matches!(event, StoreEvent::Verify(_))).expect("residual reconciliation must verify");
        assert!(delete_pos < first_verify_pos, "delete leftovers before residual verify");
        assert!(progress.snapshots().is_empty(), "residual must reject before any progress persist");
        assert!(plan.phases.iter().all(|phase| phase.status == RollbackPhaseStatus::Pending));
    }

    #[tokio::test]
    async fn present_nats_consumer_blocks_completion_and_reconciliation() {
        for marker_is_target in [false, true] {
            let mut plan = coordinator_plan();
            let marker = if marker_is_target { plan.target_checkpoint_id } else { plan.latest_checkpoint_id };
            let store = FakeStore::new(marker, plan.latest_pending_id);
            store.add_residual("nats_jetstream_consumers".into());
            let progress = FakeProgressStore::new();

            let err = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap_err();
            assert!(err.to_string().contains("nats_jetstream_consumers"), "{err}");
            assert_eq!(store.marker(), marker, "NATS residual must block marker mutation");
            assert_eq!(store.marker_writes(), 0);
        }
    }

    #[tokio::test]
    async fn counter_mismatch_rejects_before_mutation() {
        for drift in [-1i64, 1] {
            let mut plan = coordinator_plan();
            let counter = (plan.latest_pending_id as i64 + drift) as u64;
            let store = FakeStore::new(plan.latest_checkpoint_id, counter);
            let progress = FakeProgressStore::new();

            let err = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap_err();
            assert!(err.to_string().contains("pending counter mismatch"), "{err}");
            assert!(store.applied().is_empty(), "counter drift must reject before any phase executes");
            assert_eq!(store.marker_writes(), 0);
            assert_eq!(store.marker(), plan.latest_checkpoint_id);
            assert!(progress.snapshots().is_empty(), "counter drift must reject before any progress persist");
            assert!(plan.phases.iter().all(|phase| phase.status == RollbackPhaseStatus::Pending));
        }
    }
    #[tokio::test]
    async fn unexpected_marker_rejects_before_any_mutation_or_progress() {
        let mut plan = coordinator_plan();
        let store = FakeStore::new(plan.target_checkpoint_id + 1, plan.latest_pending_id);
        let progress = FakeProgressStore::new();

        let err = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap_err();

        assert!(err.to_string().contains("rollback marker mismatch"), "{err}");
        assert!(store.events().is_empty(), "marker mismatch must reject before executor I/O");
        assert!(store.applied().is_empty());
        assert_eq!(store.marker_writes(), 0);
        assert!(progress.snapshots().is_empty());
        assert!(plan.phases.iter().all(|phase| phase.status == RollbackPhaseStatus::Pending));
    }

    #[tokio::test]
    async fn target_zero_executes_to_genesis_boundary() {
        let mut plan = build_plan(
            RollbackRole::Coordinator,
            0,
            0,
            0,
            2,
            2,
            vec![
                PostTargetGeneration { checkpoint_id: Some(1), pending_id: 1, proc_checkpoint_unique_id: 1001 },
                PostTargetGeneration { checkpoint_id: Some(2), pending_id: 2, proc_checkpoint_unique_id: 1002 },
            ],
        );
        let store = FakeStore::new(plan.latest_checkpoint_id, plan.latest_pending_id);
        let progress = FakeProgressStore::new();

        let outcome = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap();

        assert_eq!(outcome, RollbackOutcome::Completed);
        assert_eq!(store.applied(), data_phase_tables());
        assert_eq!(store.marker(), 0);
        assert_eq!(store.marker_writes(), 1);
        assert_eq!(store.counter(), plan.latest_pending_id, "genesis rollback must not rewind the pending counter");
        assert!(plan.phases.iter().all(|phase| phase.status == RollbackPhaseStatus::Completed));
    }

    #[tokio::test]
    async fn successful_second_run_is_pure_reconciliation() {
        let mut plan = coordinator_plan();
        let store = FakeStore::new(plan.latest_checkpoint_id, plan.latest_pending_id);
        let progress = FakeProgressStore::new();

        let first = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap();
        assert_eq!(first, RollbackOutcome::Completed);
        let events_after_first = store.events();
        let marker_writes_after_first = store.marker_writes();
        let snapshots_after_first = progress.snapshots().len();

        let second = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap();

        assert_eq!(second, RollbackOutcome::Reconciled);
        assert_eq!(store.marker_writes(), marker_writes_after_first, "second run must not rewrite the marker");
        assert_eq!(progress.snapshots().len(), snapshots_after_first, "already-complete plan must not be persisted again");
        assert_eq!(store.backup_deletes(), 2, "reconciliation must retry leftover backup delete");
        let second_events = &store.events()[events_after_first.len()..];
        assert!(second_events
            .iter()
            .all(|event| matches!(event, StoreEvent::Verify(_) | StoreEvent::DeleteBackups)), "second run may only delete leftovers and verify postconditions");
        let delete_pos = second_events.iter().position(|event| matches!(event, StoreEvent::DeleteBackups)).expect("second run must delete leftovers");
        let first_verify_pos = second_events.iter().position(|event| matches!(event, StoreEvent::Verify(_))).expect("second run must verify postconditions");
        assert!(delete_pos < first_verify_pos, "reconciliation delete must precede postcondition checks");
        assert_eq!(store.applied(), data_phase_tables(), "second run must not duplicate execution");
    }

    #[tokio::test]
    async fn crash_at_every_data_phase_resumes_without_duplicate_execution() {
        for table in data_phase_tables() {
            let mut plan = coordinator_plan();
            let store = FakeStore::new(plan.latest_checkpoint_id, plan.latest_pending_id);
            let progress = FakeProgressStore::new();
            store.fail_execute(Some(table.clone()));

            let err = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap_err();
            assert!(err.to_string().contains(&table), "{table}: {err}");
            assert_eq!(store.marker(), plan.latest_checkpoint_id, "{table}: crash must leave marker at latest");
            assert_eq!(store.marker_writes(), 0, "{table}: crash must precede marker write");

            let outcome = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap();
            assert_eq!(outcome, RollbackOutcome::Completed, "{table}");
            assert_eq!(store.applied(), data_phase_tables(), "{table}: every phase must execute exactly once and in order");
            assert_eq!(store.marker(), plan.target_checkpoint_id, "{table}");
            assert_eq!(store.marker_writes(), 1, "{table}");
            assert!(plan.phases.iter().all(|phase| phase.status == RollbackPhaseStatus::Completed), "{table}");
        }
    }

    #[tokio::test]
    async fn verify_crash_in_every_phase_resumes_without_re_execution() {
        for table in data_phase_tables() {
            let mut plan = coordinator_plan();
            let store = FakeStore::new(plan.latest_checkpoint_id, plan.latest_pending_id);
            let progress = FakeProgressStore::new();
            store.fail_verify(Some(table.clone()));

            let err = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap_err();
            assert!(err.to_string().contains(&table), "{table}: {err}");
            assert_eq!(store.applied(), data_phase_tables(), "{table}: verify crash follows full execution");
            assert_eq!(store.marker(), plan.latest_checkpoint_id, "{table}: verify crash must leave marker at latest");
            assert_eq!(store.marker_writes(), 0, "{table}: verify crash must precede marker write");

            let applied_before_resume = store.applied();
            let outcome = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap();
            assert_eq!(outcome, RollbackOutcome::Completed, "{table}");
            assert_eq!(store.applied(), applied_before_resume, "{table}: resume after verify crash must not re-execute");
            assert_eq!(store.marker(), plan.target_checkpoint_id, "{table}");
            assert_eq!(store.marker_writes(), 1, "{table}");
            assert!(plan.phases.iter().all(|phase| phase.status == RollbackPhaseStatus::Completed), "{table}");
        }
    }

    #[tokio::test]
    async fn phase_key_outside_frozen_set_rejected_before_any_mutation() {
        let mut plan = coordinator_plan();
        let phase = plan.phases.iter_mut().find(|phase| phase.table == "checkpoint_leaf_table").unwrap();
        phase.keys.as_array_mut().unwrap().push(serde_json::json!(999));
        let store = FakeStore::new(plan.latest_checkpoint_id, plan.latest_pending_id);
        let progress = FakeProgressStore::new();

        let err = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap_err();

        assert!(err.to_string().contains("checkpoint_leaf_table"), "{err}");
        assert!(err.to_string().contains("must equal the frozen post_target_generations set"), "{err}");
        assert!(store.events().is_empty(), "validation must reject before executor I/O");
        assert_eq!(store.marker_writes(), 0);
        assert!(progress.snapshots().is_empty());
        assert!(plan.phases.iter().all(|phase| phase.status == RollbackPhaseStatus::Pending));
    }

    #[tokio::test]
    async fn malformed_phase_api_rejected_before_any_mutation() {
        let mut plan = coordinator_plan();
        plan.phases[0].api = "bogus_api".to_string();
        let store = FakeStore::new(plan.latest_checkpoint_id, plan.latest_pending_id);
        let progress = FakeProgressStore::new();

        let err = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap_err();

        assert!(err.to_string().contains("TKVSV1"), "{err}");
        assert!(err.to_string().contains("must use API"), "{err}");
        assert!(store.events().is_empty());
        assert_eq!(store.marker_writes(), 0);
        assert!(progress.snapshots().is_empty());
        assert!(plan.phases.iter().all(|phase| phase.status == RollbackPhaseStatus::Pending));
    }

    #[tokio::test]
    async fn malformed_worker_reputation_snapshot_rejected_before_any_mutation() {
        let mut plan = coordinator_plan();
        plan.snapshot.worker_reputation_fields.push(plan.snapshot.worker_reputation_fields[0].clone());
        let store = FakeStore::new(plan.latest_checkpoint_id, plan.latest_pending_id);
        let progress = FakeProgressStore::new();

        let err = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap_err();

        assert!(err.to_string().contains("duplicates an earlier worker reputation field"), "{err}");
        assert!(store.events().is_empty(), "snapshot validation must reject before executor I/O");
        assert_eq!(store.marker_writes(), 0);
        assert!(progress.snapshots().is_empty());
        assert!(plan.phases.iter().all(|phase| phase.status == RollbackPhaseStatus::Pending));
    }

    #[tokio::test]
    async fn residual_still_blocks_reconciliation_after_full_completion() {
        let mut plan = coordinator_plan();
        let store = FakeStore::new(plan.latest_checkpoint_id, plan.latest_pending_id);
        let progress = FakeProgressStore::new();

        let first = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap();
        assert_eq!(first, RollbackOutcome::Completed);
        let events_after_first = store.events();
        let marker_writes_after_first = store.marker_writes();
        let snapshots_after_first = progress.snapshots().len();
        store.add_residual("user_public_key_table".to_string());

        let err = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap_err();

        assert!(err.to_string().contains("user_public_key_table"), "{err}");
        assert_eq!(store.marker(), plan.target_checkpoint_id);
        assert_eq!(store.marker_writes(), marker_writes_after_first, "failed reconciliation must not rewrite the marker");
        assert_eq!(progress.snapshots().len(), snapshots_after_first, "failed reconciliation must not persist");
        assert!(store.events()[events_after_first.len()..]
            .iter()
            .all(|event| matches!(event, StoreEvent::Verify(_) | StoreEvent::DeleteBackups)), "failed reconciliation may only delete leftovers and run read-only postcondition checks");
        assert!(plan.phases.iter().all(|phase| phase.status == RollbackPhaseStatus::Completed));
    }

    #[tokio::test]
    async fn backup_delete_failure_blocks_marker_and_progress() {
        let mut plan = coordinator_plan();
        let store = FakeStore::new(plan.latest_checkpoint_id, plan.latest_pending_id);
        store.fail_delete_backups(true);
        let progress = FakeProgressStore::new();

        let err = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap_err();

        assert!(err.to_string().contains("post-target"), "{err}");
        assert_eq!(store.marker_writes(), 0);
        assert_eq!(store.backup_deletes(), 0);
        assert_eq!(store.marker(), plan.latest_checkpoint_id);
        assert_eq!(plan.phases.last().unwrap().status, RollbackPhaseStatus::Pending);
        assert!(
            progress.snapshots().last().is_none_or(|snapshot| snapshot.phases.last().unwrap().status != RollbackPhaseStatus::Completed),
            "delete failure must not persist marker-phase completion"
        );
    }

    #[tokio::test]
    async fn crash_after_backup_delete_before_marker_resumes() {
        let mut plan = coordinator_plan();
        let store = FakeStore::new(plan.latest_checkpoint_id, plan.latest_pending_id);
        store.fail_marker_write(true);
        let progress = FakeProgressStore::new();

        let err = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap_err();
        assert!(err.to_string().contains("marker"), "{err}");
        assert_eq!(store.backup_deletes(), 1);
        assert_eq!(store.marker_writes(), 0);
        assert_eq!(store.marker(), plan.latest_checkpoint_id);
        assert_eq!(plan.phases.last().unwrap().status, RollbackPhaseStatus::Pending);
        let delete_pos = store.events().iter().position(|event| matches!(event, StoreEvent::DeleteBackups)).unwrap();
        assert!(store.events()[delete_pos + 1..].iter().all(|event| matches!(event, StoreEvent::Verify(_))));

        let outcome = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap();
        assert_eq!(outcome, RollbackOutcome::Completed);
        assert_eq!(store.backup_deletes(), 2);
        assert_eq!(store.marker_writes(), 1);
        assert_eq!(store.marker(), plan.target_checkpoint_id);
        assert!(plan.phases.iter().all(|phase| phase.status == RollbackPhaseStatus::Completed));
        let events = store.events();
        let marker_pos = events.iter().position(|event| matches!(event, StoreEvent::WriteMarker(_))).unwrap();
        let last_delete_pos = events.iter().rposition(|event| matches!(event, StoreEvent::DeleteBackups)).unwrap();
        assert!(last_delete_pos < marker_pos, "delete event must precede marker write");
    }

    #[tokio::test]
    async fn marker_at_target_reconciliation_clears_leftover_backups() {
        let mut plan = coordinator_plan();
        let store = FakeStore::new(plan.target_checkpoint_id, plan.latest_pending_id);
        store.add_leftover_backups();
        let progress = FakeProgressStore::new();

        assert!(store.leftover_backups());
        let outcome = execute_rollback_plan(&store, &progress, &mut plan).await.unwrap();

        assert_eq!(outcome, RollbackOutcome::Reconciled);
        assert!(!store.leftover_backups(), "reconciliation must clear leftover post-target backups");
        assert_eq!(store.backup_deletes(), 1);
        assert_eq!(store.marker_writes(), 0);
        assert!(store.applied().is_empty());
        let events = store.events();
        let delete_pos = events.iter().position(|event| matches!(event, StoreEvent::DeleteBackups)).unwrap();
        let first_verify_pos = events.iter().position(|event| matches!(event, StoreEvent::Verify(_))).unwrap();
        assert!(delete_pos < first_verify_pos, "delete event must precede marker-path postcondition checks");
        assert!(plan.phases.iter().all(|phase| phase.status == RollbackPhaseStatus::Completed));
    }

    #[tokio::test]
    async fn delete_event_precedes_marker_on_happy_path() {
        let mut plan = coordinator_plan();
        let store = FakeStore::new(plan.latest_checkpoint_id, plan.latest_pending_id);
        let progress = FakeProgressStore::new();

        execute_rollback_plan(&store, &progress, &mut plan).await.unwrap();

        let events = store.events();
        let delete_pos = events.iter().position(|event| matches!(event, StoreEvent::DeleteBackups)).expect("delete event");
        let marker_pos = events.iter().position(|event| matches!(event, StoreEvent::WriteMarker(_))).expect("marker event");
        assert!(delete_pos < marker_pos, "delete event must precede marker write: {events:?}");
        assert!(
            events[delete_pos + 1..marker_pos].iter().all(|event| matches!(event, StoreEvent::Verify(_))),
            "verify-complete must sit between delete and marker: {events:?}"
        );
    }
}
