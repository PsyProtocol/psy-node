//! Builds a fully materialized RollbackPlan.

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::Context;
use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::protocol::core_types::{Q256BitHash, QNetworkTypesConfig};
use psy_data::v1::qdata::contract::{deserialize_imt_leaf_ffs_entry_v2, encode_imt_key_for_sorting, imt_key_bucket_to_i16, IMT_LEAF_FFS_ENTRY_SIZE_V2};
use psy_node_core::psy_temp_db::{TEMP_TABLE_ID_WORKER_REPUTATION_BYTES, TEMP_TABLE_WORKER_REPUTATION_KEY_SIZE};
use psy_io::tokio::TokioLikeFileSystem;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    coordinator::processor::gatherers::{
        coordinator_guta_update_gatherer::{get_new_coordinator_guta_update_gatherer_backup_file_path, read_coordinator_guta_update_gatherer_backup_file},
        deploy_contract_gatherer::{get_new_deploy_contract_gatherer_backup_file_path, read_deploy_contract_gatherer_backup_file_path},
        register_user_gatherer::{get_new_register_user_gatherer_backup_file_path, read_register_user_gatherer_backup_file_path},
        update_contract_gatherer::{get_new_update_contract_gatherer_backup_file_path, read_update_contract_gatherer_backup_file_path},
    },
    realm::processor::gatherers::realm_end_cap_gatherer::{get_new_realm_end_cap_gatherer_backup_file_path, read_realm_end_cap_gatherer_backup_file},
    rollback::{
        keys::{self, MerkleNodeKey, TempFieldKey, UserTransformParams},
        plan::{RollbackIds, RollbackPhase, RollbackPhaseStatus, RollbackPlan, RollbackRole, RollbackSnapshot, RollbackTempValueSnapshot, TargetContractState},
    },
};

#[async_trait::async_trait]
pub trait RollbackStateReader: Send + Sync {
    async fn pending_id_for_checkpoint(&self, checkpoint_id: u64) -> anyhow::Result<Option<u64>>;
    async fn checkpoint_id_for_pending(&self, pending_id: u64) -> anyhow::Result<Option<u64>>;
    async fn proc_id_for_pending(&self, pending_id: u64) -> anyhow::Result<Option<u128>>;
    async fn root_for_checkpoint(&self, checkpoint_id: u64) -> anyhow::Result<Option<[u8; 32]>>;
    async fn imt_leaf_at_target(
        &self,
        tree_id: i64,
        tree_sub_id: i64,
        leaf_index: i64,
        target_checkpoint_id: i64,
    ) -> anyhow::Result<bool>;
    async fn imt_next_append_index(
        &self,
        tree_id: i64,
        tree_sub_id: i64,
    ) -> anyhow::Result<Option<i64>>;
    async fn global_checkpoint_tree_delete_path_keys(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<Vec<MerkleNodeKey>>;
}

#[async_trait::async_trait]
pub trait RollbackTempEnumerator: Send + Sync {
    async fn scan_fields(&self, cursor: u64, count: u32) -> anyhow::Result<(u64, Vec<Vec<u8>>) >;
    async fn get_value(&self, field: &[u8]) -> anyhow::Result<Option<Vec<u8>>>;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CoordinatorCheckpointInfo {
    pub has_register_users: bool,
    pub has_deploy_contracts: bool,
    pub contract_root_changed: bool,
    pub has_guta_updates: bool,
    pub contract_root: [u8; 32],
}

#[async_trait::async_trait]
pub trait RollbackCheckpointInfoReader: Send + Sync {
    async fn coordinator_checkpoint_info(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<CoordinatorCheckpointInfo>;
}

#[derive(Default, Clone)]
pub struct BackupKeySource {
    pub register_user: HashMap<u64, RegisterUserBackup>,
    pub deploy_contract: HashMap<u64, DeployContractBackup>,
    pub update_contract: HashMap<u64, UpdateContractBackup>,
    pub coordinator_guta: HashMap<u64, CoordinatorGutaBackup>,
    pub realm_end_cap: HashMap<u64, RealmEndCapBackup>,
    pub global_checkpoint_tree_delete_path_keys: HashMap<u64, Vec<MerkleNodeKey>>,
}

#[derive(Debug, Clone)]
pub struct RegisterUserBackup {
    pub start_next_user_id: u64,
    pub new_user_public_keys_ffs: Vec<u8>,
    pub new_public_key_hash_to_user_id_rows_ffs: Vec<u8>,
    pub update_user_registration_tree_nodes_ffs: Vec<u8>,
}

impl RegisterUserBackup {
    pub fn user_count(&self) -> anyhow::Result<usize> {
        if self.new_user_public_keys_ffs.len() % 72 != 0 {
            anyhow::bail!("register-user public-key FFS length {} is not a multiple of 72", self.new_user_public_keys_ffs.len());
        }
        Ok(self.new_user_public_keys_ffs.len() / 72)
    }
}

#[derive(Debug, Clone)]
pub struct DeployContractBackup {
    pub new_contract_ids: Vec<u64>,
    pub update_contract_function_tree_nodes_ffs: Vec<u8>,
    pub update_global_contract_tree_nodes_ffs: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct UpdateContractBackup {
    pub updated_contract_ids: Vec<u64>,
    pub update_contract_function_tree_nodes_ffs: Vec<u8>,
    pub update_global_contract_tree_nodes_ffs: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CoordinatorGutaBackup {
    pub update_global_user_tree_nodes_ffs: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RealmEndCapBackup {
    pub update_user_leaves_ffs: Vec<u8>,
    pub update_user_contract_tree_nodes_ffs: Vec<u8>,
    pub update_contract_state_tree_nodes_ffs: Vec<u8>,
    pub update_global_user_tree_nodes_ffs: Vec<u8>,
    pub update_contract_state_imt_leaves_ffs: Vec<u8>,
    pub imt_key_index_keys: Vec<keys::ImtKeyIndexKey>,
}

/// Internally frozen next-append targets derived before rollback mutation begins.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ImtAppendIndexSnapshot {
    pub entries: Vec<ImtAppendIndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImtAppendIndexEntry {
    pub tree_id: i64,
    pub tree_sub_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_append_index: Option<i64>,
}

#[derive(Clone)]
pub struct RollbackPlanInput<'a> {
    pub role: RollbackRole,
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub target_checkpoint_id: u64,
    pub latest_checkpoint_id: u64,
    pub latest_pending_id: u64,
    pub state_reader: &'a (dyn RollbackStateReader + 'a),
    pub temp_enumerator: &'a (dyn RollbackTempEnumerator + 'a),
    pub backups: &'a BackupKeySource,
    pub reward_realm_ids: Vec<u64>,
    pub user_transform: UserTransformParams,
    pub imt_snapshot: ImtAppendIndexSnapshot,
    pub snapshot: RollbackSnapshot,
    pub target_contract_state: Option<TargetContractState>,
}

#[derive(Debug, Clone)]
pub struct RollbackBackupDirectories {
    pub register_user: String,
    pub deploy_contract: String,
    pub update_contract: String,
    pub coordinator_guta: String,
    pub realm_end_cap: String,
}

/// Recorder stores must match the boundary immediately before the first post-target pending.
pub struct RollbackPlanFromBackupPathsInput<'a, N: QNetworkTypesConfig, FS: TokioLikeFileSystem> {
    pub role: RollbackRole,
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub target_checkpoint_id: u64,
    pub latest_checkpoint_id: u64,
    pub latest_pending_id: u64,
    pub state_reader: &'a (dyn RollbackStateReader + 'a),
    pub temp_enumerator: &'a (dyn RollbackTempEnumerator + 'a),
    pub checkpoint_info_reader: &'a (dyn RollbackCheckpointInfoReader + 'a),
    pub file_system: &'a FS,
    pub backup_directories: &'a RollbackBackupDirectories,
    pub global_user_tree: &'a mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
    pub global_contract_tree: &'a mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
    pub user_registration_tree: &'a mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
    pub reward_realm_ids: Vec<u64>,
    pub user_transform: UserTransformParams,
    pub snapshot: RollbackSnapshot,
    pub target_contract_state: Option<TargetContractState>,
}

pub async fn collect_ids(
    reader: &dyn RollbackStateReader,
    target_checkpoint_id: u64,
    latest_pending_id: u64,
) -> anyhow::Result<Vec<RollbackIds>> {
    let boundary_pending = find_last_mapped_pending_at_or_before(reader, target_checkpoint_id).await?;

    let mut ids = Vec::new();
    if latest_pending_id == 0 {
        return Ok(ids);
    }
    let start = boundary_pending.saturating_add(1);
    for pending_id in start..=latest_pending_id {
        let Some(proc_id) = reader.proc_id_for_pending(pending_id).await? else {
            continue;
        };
        let checkpoint_id = reader.checkpoint_id_for_pending(pending_id).await?;
        ids.push(RollbackIds { checkpoint_id, pending_id, proc_id });
    }
    Ok(ids)
}

async fn find_last_mapped_pending_at_or_before(
    reader: &dyn RollbackStateReader,
    target_checkpoint_id: u64,
) -> anyhow::Result<u64> {
    let mut cp = target_checkpoint_id;
    loop {
        if let Some(pid) = reader.pending_id_for_checkpoint(cp).await? {
            return Ok(pid);
        }
        if cp == 0 {
            return Ok(0);
        }
        cp -= 1;
    }
}

pub async fn materialize_temp_snapshot(
    enumerator: &dyn RollbackTempEnumerator,
    realm_id: u32,
    realm_sub_id: u16,
    pending_ids: &[u64],
) -> anyhow::Result<(Vec<TempFieldKey>, Vec<RollbackTempValueSnapshot>)> {
    let mut all_fields = Vec::new();
    let mut cursor = 0u64;
    loop {
        let (next, mut fields) = enumerator.scan_fields(cursor, 512).await?;
        all_fields.append(&mut fields);
        if next == 0 {
            break;
        }
        cursor = next;
    }
    let mut keys = Vec::new();
    for &pending_id in pending_ids {
        for field in keys::filter_temp_fields(&all_fields, realm_id, realm_sub_id, pending_id) {
            keys.push(TempFieldKey { field: field.into_boxed_slice(), pending_id });
        }
    }
    let mut worker_reputation_prefix = Vec::with_capacity(8);
    worker_reputation_prefix.extend_from_slice(&realm_id.to_le_bytes());
    worker_reputation_prefix.extend_from_slice(&realm_sub_id.to_le_bytes());
    worker_reputation_prefix.extend_from_slice(&TEMP_TABLE_ID_WORKER_REPUTATION_BYTES);
    let mut seen = HashSet::new();
    let mut worker_reputation_fields = Vec::new();
    for field in all_fields.into_iter().filter(|field| field.len() == TEMP_TABLE_WORKER_REPUTATION_KEY_SIZE && field.starts_with(&worker_reputation_prefix)) {
        if !seen.insert(field.clone()) {
            anyhow::bail!("Temp HSCAN returned duplicate worker reputation field {}", hex::encode(&field));
        }
        let value = enumerator
            .get_value(&field)
            .await?
            .ok_or_else(|| anyhow::anyhow!("worker reputation field disappeared during snapshot: {}", hex::encode(&field)))?;
        worker_reputation_fields.push(RollbackTempValueSnapshot {
            field: hex::encode(field),
            value: Some(hex::encode(value)),
        });
    }
    worker_reputation_fields.sort_by(|left, right| left.field.cmp(&right.field));
    Ok((keys, worker_reputation_fields))
}

pub const STAGE1_TABLES: &[&str] = &[
    "TKVSV1",
    "TMPPSV1-proof-buckets",
    "nats_jetstream_consumers",
];

pub const STAGE2_TABLES: &[&str] = &[
    "checkpoint_leaf_table",
    "checkpoint_root_to_checkpoint_id_table",
    "l2_block_state_table",
    "checkpoint_id_to_realm_root_table",
    "checkpointed_object_table",
    "checkpoint_state_roots_table",
    "user_leaf_table",
    "user_public_key_table",
    "contract_state_tree_height_table",
    "checkpoint_id_to_pending_id_table",
    "pending_id_to_checkpoint_id_table",
    "pending_id_to_pending_proc_id_table",
    "realm_rewards_tree_node_key_table",
    "public_key_hash_to_user_ids_table",
    "guta_reward_tag_tree_table",
    "contract_leaf_table",
    "contract_code_definition_table",
    "checkpoint_zk_proof_and_transition_table",
    "imt_key_index_table",
];

pub const EMPTY_SCHEMA_TABLES: &[&str] = &["checkpoint_leaf_to_checkpoint_id_table"];

pub const STAGE3_TABLES: &[&str] = &[
    "global_user_tree_table",
    "user_contract_tree_table",
    "contract_state_tree_table",
    "global_checkpoint_tree_table",
    "user_registration_tree_table",
    "global_contract_tree_table",
    "contract_function_tree_table",
    "imt_leaf_table",
];

pub const FINAL_TABLES: &[&str] = &[
    "latest_info_table",
    "imt_next_append_index_table",
    "TKVSV1-singletons",
    "checkpoint_tree_backup",
    "all",
    "u64_singleton_table",
];

pub fn api_for_table(table: &str) -> &'static str {
    match table {
        "checkpoint_leaf_table" | "l2_block_state_table" => "db_delete_many_object_ids",
        "checkpoint_root_to_checkpoint_id_table" | "checkpoint_leaf_to_checkpoint_id_table" => "db_delete_many_blob_pairs",
        "checkpoint_id_to_realm_root_table" | "checkpoint_state_roots_table" | "checkpoint_zk_proof_and_transition_table" | "checkpoint_id_to_pending_id_table" | "pending_id_to_checkpoint_id_table" => "db_delete_many_object_ids",
        "user_leaf_table" | "user_public_key_table" | "contract_state_tree_height_table" | "contract_leaf_table" | "contract_code_definition_table" | "checkpointed_object_table" | "realm_rewards_tree_node_key_table" => "db_delete_many_object_checkpoint",
        "pending_id_to_pending_proc_id_table" => "db_delete_many_u64_u128_pairs",
        "public_key_hash_to_user_ids_table" => "db_delete_many_hash_user_pairs",
        "guta_reward_tag_tree_table" => "db_delete_many_pending_id_partitions",
        "imt_key_index_table" => "db_delete_many_imt_keys",
        "global_user_tree_table" | "global_checkpoint_tree_table" | "user_registration_tree_table" | "global_contract_tree_table" => "db_delete_many_merkle_nodes",
        "user_contract_tree_table" | "contract_function_tree_table" => "db_delete_many_tree_merkle_nodes",
        "contract_state_tree_table" => "db_delete_many_tree_subtree_merkle_nodes",
        "imt_leaf_table" => "db_delete_many_imt_leaves",
        "latest_info_table" => "set_latest_info",
        "imt_next_append_index_table" => "set_imt_next_append_index",
        "TKVSV1-singletons" => "qtdb_raw_kv_delete_key",
        "checkpoint_tree_backup" => "rebuild_checkpoint_tree_backup",
        "all" => "verify",
        "u64_singleton_table" => "set_latest_checkpoint_id",
        "nats_jetstream_consumers" => "delete_nats_consumers",
        _ => "UNKNOWN",
    }
}

fn pending_phase(table: &str, keys: serde_json::Value) -> RollbackPhase {
    RollbackPhase {
        table: table.to_string(),
        api: api_for_table(table).to_string(),
        keys,
        status: RollbackPhaseStatus::Pending,
    }
}

fn post_target_checkpoint_ids(target_checkpoint_id: u64, latest_checkpoint_id: u64) -> Vec<u64> {
    if target_checkpoint_id >= latest_checkpoint_id {
        return Vec::new();
    }
    (target_checkpoint_id + 1..=latest_checkpoint_id).collect()
}

pub async fn build_phases(
    plan: &RollbackPlan,
    temp_fields: &[TempFieldKey],
    backups: &BackupKeySource,
    reward_realm_ids: &[u64],
    user_transform: &UserTransformParams,
    imt_snapshot: &ImtAppendIndexSnapshot,
    state_reader: &dyn RollbackStateReader,
) -> anyhow::Result<Vec<RollbackPhase>> {
    let checkpoint_ids = post_target_checkpoint_ids(plan.target_checkpoint_id, plan.latest_checkpoint_id);
    let mapped_checkpoint_ids = plan.mapped_checkpoint_ids();
    let pending_ids = plan.pending_ids();
    let proc_ids = plan.proc_ids();
    let nats_consumer_kinds = crate::rollback::plan::rollback_nats_consumer_kinds(plan.role);
    let realm_id = plan.realm_id;
    let realm_sub_id = plan.realm_sub_id;
    let role = plan.role;

    let mut phases = Vec::new();

    phases.push(RollbackPhase {
        table: "TKVSV1".to_string(),
        api: "qtdb_raw_kv_delete_key".to_string(),
        keys: serde_json::Value::Array(
            temp_fields.iter().map(|field| serde_json::Value::String(hex::encode(&field.field))).collect(),
        ),
        status: RollbackPhaseStatus::Pending,
    });
    phases.push(RollbackPhase {
        table: "TMPPSV1-proof-buckets".to_string(),
        api: "delete_all_proofs_for_pending_id".to_string(),
        keys: serde_json::Value::Array(pending_ids.iter().copied().map(serde_json::Value::from).collect()),
        status: RollbackPhaseStatus::Pending,
    });
    phases.push(pending_phase(
        "nats_jetstream_consumers",
        serde_json::Value::Array(
            proc_ids
                .iter()
                .flat_map(|proc_id| {
                    nats_consumer_kinds.iter().map(move |kind| {
                        serde_json::json!({
                            "kind": kind,
                            "proc_id": proc_id.to_string(),
                            "task_group": 0,
                        })
                    })
                })
                .collect(),
        ),
    ));

    phases.push(pending_phase(
        "checkpoint_leaf_table",
        json_ids(&checkpoint_ids),
    ));
    let mut root_pairs = Vec::new();
    for &checkpoint_id in &checkpoint_ids {
        let root = state_reader
            .root_for_checkpoint(checkpoint_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!(
                "no checkpoint tree root mapping found for checkpoint {} — cannot materialize checkpoint_root_to_checkpoint_id_table pair",
                checkpoint_id
            ))?;
        let root_hex = format!("0x{}", hex::encode(root));
        let checkpoint_hex = format!("0x{}", hex::encode(checkpoint_id.to_le_bytes()));
        root_pairs.push(json!([root_hex, checkpoint_hex]));
    }
    phases.push(RollbackPhase {
        table: "checkpoint_root_to_checkpoint_id_table".to_string(),
        api: "db_delete_many_blob_pairs".to_string(),
        keys: serde_json::Value::Array(root_pairs),
        status: RollbackPhaseStatus::Pending,
    });
    phases.push(pending_phase("l2_block_state_table", json_ids(&checkpoint_ids)));
    phases.push(pending_phase("checkpoint_id_to_realm_root_table", json!([])));
    phases.push(pending_phase(
        "checkpoint_state_roots_table",
        json_ids(&checkpoint_ids),
    ));
    phases.push(pending_phase(
        "checkpoint_zk_proof_and_transition_table",
        json_ids(&checkpoint_ids),
    ));

    let checkpointed_object_keys: Vec<_> = checkpoint_ids
        .iter()
        .map(|&checkpoint_id| json!([1u64, checkpoint_id]))
        .chain(pending_ids.iter().map(|&pending_id| json!([2u64, pending_id])))
        .collect();
    phases.push(pending_phase("checkpointed_object_table", serde_json::Value::Array(checkpointed_object_keys)));

    let (user_leaf_keys, pubkey_keys) = keys::user_leaf_and_pubkey_keys(backups, role, &plan.ids)?;
    phases.push(pending_phase(
        "user_leaf_table",
        serde_json::Value::Array(user_leaf_keys.iter().map(|(user_id, checkpoint_id)| json!([user_id, checkpoint_id])).collect()),
    ));
    phases.push(pending_phase(
        "user_public_key_table",
        serde_json::Value::Array(pubkey_keys.iter().map(|(user_id, checkpoint_id)| json!([user_id, checkpoint_id])).collect()),
    ));

    let contract_keys = keys::contract_metadata_keys(backups, role, &plan.ids)?;
    phases.push(pending_phase(
        "contract_state_tree_height_table",
        serde_json::Value::Array(contract_keys.iter().map(|(c, cp)| json!([c, cp])).collect()),
    ));
    phases.push(pending_phase(
        "contract_leaf_table",
        serde_json::Value::Array(contract_keys.iter().map(|(c, cp)| json!([c, cp])).collect()),
    ));
    phases.push(pending_phase(
        "contract_code_definition_table",
        serde_json::Value::Array(contract_keys.iter().map(|(c, cp)| json!([c, cp])).collect()),
    ));

    phases.push(pending_phase(
        "checkpoint_id_to_pending_id_table",
        json_ids(&mapped_checkpoint_ids),
    ));
    phases.push(pending_phase(
        "pending_id_to_checkpoint_id_table",
        json_ids(&pending_ids),
    ));
    let pending_proc_keys: Vec<_> = pending_ids
        .iter()
        .zip(proc_ids.iter())
        .map(|(&pending_id, &proc_id)| json!([pending_id, proc_id.to_string()]))
        .collect();
    phases.push(pending_phase("pending_id_to_pending_proc_id_table", serde_json::Value::Array(pending_proc_keys)));

    let reward_keys: Vec<_> = reward_realm_ids
        .iter()
        .flat_map(|&rid| pending_ids.iter().map(move |&p| json!([rid, p])))
        .collect();
    phases.push(pending_phase(
        "realm_rewards_tree_node_key_table",
        serde_json::Value::Array(reward_keys),
    ));

    let hash_user_keys = keys::public_key_hash_user_pairs(backups, role, user_transform)?;
    let hu: Vec<_> = hash_user_keys
        .iter()
        .map(|(hash, uid)| json!([hex::encode(hash), uid]))
        .collect();
    phases.push(pending_phase(
        "public_key_hash_to_user_ids_table",
        serde_json::Value::Array(hu),
    ));

    let partition_keys: Vec<_> = pending_ids.iter().copied().map(serde_json::Value::from).collect();
    phases.push(pending_phase(
        "guta_reward_tag_tree_table",
        serde_json::Value::Array(partition_keys),
    ));

    // Match the unversioned key-index writer: new keys and zero-key/zero-value sentinels.
    let imt_key_keys = keys::imt_key_index_keys(backups, role)?;
    let ik: Vec<_> = imt_key_keys
        .iter()
        .map(|k| json!([k.tree_id, k.tree_sub_id, k.key_bucket, hex::encode(&k.encoded_key)]))
        .collect();
    phases.push(pending_phase("imt_key_index_table", serde_json::Value::Array(ik)));

    phases.push(pending_phase(
        "checkpoint_leaf_to_checkpoint_id_table",
        json!([]),
    ));

    let gu = keys::global_user_tree_keys(backups, role, &plan.ids)?;
    phases.push(pending_phase(
        "global_user_tree_table",
        serde_json::Value::Array(gu.iter().map(|n| json!([n.level, n.index, n.checkpoint_id])).collect()),
    ));
    let gck = keys::global_checkpoint_tree_keys(backups, role, &checkpoint_ids)?;
    phases.push(pending_phase(
        "global_checkpoint_tree_table",
        serde_json::Value::Array(gck.iter().map(|n| json!([n.level, n.index, n.checkpoint_id])).collect()),
    ));
    let ur = keys::user_registration_tree_keys(backups, role, &plan.ids)?;
    phases.push(pending_phase(
        "user_registration_tree_table",
        serde_json::Value::Array(ur.iter().map(|n| json!([n.level, n.index, n.checkpoint_id])).collect()),
    ));
    let gc = keys::global_contract_tree_keys(backups, role, &plan.ids)?;
    phases.push(pending_phase(
        "global_contract_tree_table",
        serde_json::Value::Array(gc.iter().map(|n| json!([n.level, n.index, n.checkpoint_id])).collect()),
    ));
    let uc = keys::user_contract_tree_keys(backups, role, &plan.ids)?;
    phases.push(pending_phase(
        "user_contract_tree_table",
        serde_json::Value::Array(uc.iter().map(|n| json!([n.tree_id, n.level, n.index, n.checkpoint_id])).collect()),
    ));
    let cf = keys::contract_function_tree_keys(backups, role, &plan.ids)?;
    phases.push(pending_phase(
        "contract_function_tree_table",
        serde_json::Value::Array(cf.iter().map(|n| json!([n.tree_id, n.level, n.index, n.checkpoint_id])).collect()),
    ));
    let cs = keys::contract_state_tree_keys(backups, role, &plan.ids)?;
    phases.push(pending_phase(
        "contract_state_tree_table",
        serde_json::Value::Array(
            cs.iter()
                .map(|n| json!([n.tree_id, n.tree_sub_id, n.level, n.index, n.checkpoint_id]))
                .collect(),
        ),
    ));
    let iml = keys::imt_leaf_keys(backups, role, &plan.ids)?;
    phases.push(pending_phase(
        "imt_leaf_table",
        serde_json::Value::Array(
            iml.iter().map(|n| json!([n.tree_id, n.tree_sub_id, n.leaf_index, n.checkpoint_id])).collect(),
        ),
    ));

    phases.push(pending_phase("latest_info_table", json!([])));
    let imt_idx: Vec<_> = imt_snapshot
        .entries
        .iter()
        .map(|entry| {
            json!({
                "tree_id": entry.tree_id,
                "tree_sub_id": entry.tree_sub_id,
                "next_append_index": entry.next_append_index,
            })
        })
        .collect();
    phases.push(pending_phase(
        "imt_next_append_index_table",
        serde_json::Value::Array(imt_idx),
    ));
    let processor_singletons = keys::processor_state_singleton_fields(realm_id, realm_sub_id)?;
    phases.push(pending_phase(
        "TKVSV1-singletons",
        serde_json::Value::Array(
            processor_singletons.iter().map(|field| serde_json::Value::String(hex::encode(field))).collect(),
        ),
    ));
    phases.push(pending_phase("checkpoint_tree_backup", json!([])));
    phases.push(pending_phase("all", json!([])));
    phases.push(pending_phase("u64_singleton_table", json!([])));

    let mut execution_order = Vec::with_capacity(STAGE1_TABLES.len() + STAGE2_TABLES.len() + EMPTY_SCHEMA_TABLES.len() + STAGE3_TABLES.len() + FINAL_TABLES.len());
    execution_order.extend(STAGE1_TABLES.iter().copied());
    execution_order.extend(STAGE2_TABLES.iter().copied());
    execution_order.extend(EMPTY_SCHEMA_TABLES.iter().copied());
    execution_order.extend(STAGE3_TABLES.iter().copied());
    execution_order.extend(FINAL_TABLES.iter().copied());
    phases.sort_by_key(|phase| {
        execution_order
            .iter()
            .position(|table| *table == phase.table)
            .unwrap_or(usize::MAX)
    });
    if phases.len() != execution_order.len()
        || phases.iter().zip(execution_order.iter()).any(|(phase, expected)| phase.table != *expected)
    {
        anyhow::bail!("rollback phase assembly does not match the frozen execution order");
    }

    Ok(phases)
}

async fn derive_imt_append_index_snapshot(
    backups: &BackupKeySource,
    ids: &[RollbackIds],
    target_checkpoint_id: u64,
    state_reader: &dyn RollbackStateReader,
) -> anyhow::Result<ImtAppendIndexSnapshot> {
    #[derive(Default)]
    struct PairState {
        insert_checkpoints: BTreeMap<i64, u64>,
        sentinel_index: Option<i64>,
    }

    let target_checkpoint_id = i64::try_from(target_checkpoint_id)
        .map_err(|_| anyhow::anyhow!("target checkpoint does not fit the IMT backend coordinate"))?;
    let mut mapped_ids: Vec<_> = ids
        .iter()
        .filter_map(|id| id.checkpoint_id.map(|checkpoint_id| (checkpoint_id, id.pending_id)))
        .collect();
    mapped_ids.sort_unstable();
    let mut pairs = BTreeMap::<(i64, i64), PairState>::new();

    for (checkpoint_id, pending_id) in mapped_ids {
        let backup = backups.realm_end_cap.get(&pending_id).ok_or_else(|| {
            anyhow::anyhow!("missing materialized Realm end-cap backup for committed pending {pending_id}")
        })?;
        let ffs = &backup.update_contract_state_imt_leaves_ffs;
        if ffs.len() % IMT_LEAF_FFS_ENTRY_SIZE_V2 != 0 {
            anyhow::bail!(
                "IMT leaf FFS length {} is not a multiple of {} for pending {}",
                ffs.len(),
                IMT_LEAF_FFS_ENTRY_SIZE_V2,
                pending_id
            );
        }
        for entry in ffs.chunks_exact(IMT_LEAF_FFS_ENTRY_SIZE_V2) {
            let (tree_id, tree_sub_id, leaf_index, _, leaf_key, leaf_value, _, _, is_new_key) =
                deserialize_imt_leaf_ffs_entry_v2(entry)?;
            let pair = (
                i64::try_from(tree_id).map_err(|_| anyhow::anyhow!("IMT tree_id {tree_id} exceeds backend coordinate range"))?,
                i64::try_from(tree_sub_id).map_err(|_| anyhow::anyhow!("IMT tree_sub_id {tree_sub_id} exceeds backend coordinate range"))?,
            );
            let leaf_index = i64::try_from(leaf_index)
                .map_err(|_| anyhow::anyhow!("IMT leaf_index {leaf_index} exceeds backend coordinate range"))?;
            let state = pairs.entry(pair).or_default();
            if is_new_key {
                match state.insert_checkpoints.insert(leaf_index, checkpoint_id) {
                    Some(previous_checkpoint) if previous_checkpoint != checkpoint_id => anyhow::bail!(
                        "IMT pair ({}, {}) repeats new leaf index {} across checkpoints {} and {}",
                        pair.0,
                        pair.1,
                        leaf_index,
                        previous_checkpoint,
                        checkpoint_id
                    ),
                    _ => {}
                }
            } else if leaf_key.iter().all(|byte| *byte == 0) && leaf_value.iter().all(|byte| *byte == 0) {
                match state.sentinel_index {
                    Some(previous) if previous != leaf_index => anyhow::bail!(
                        "IMT pair ({}, {}) has conflicting sentinel indices {} and {}",
                        pair.0,
                        pair.1,
                        previous,
                        leaf_index
                    ),
                    _ => state.sentinel_index = Some(leaf_index),
                }
            }
        }
    }

    let mut entries = Vec::with_capacity(pairs.len());
    for ((tree_id, tree_sub_id), state) in pairs {
        let next_append_index = if state.insert_checkpoints.is_empty() {
            let current = state_reader
                .imt_next_append_index(tree_id, tree_sub_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!(
                    "update-only IMT pair ({tree_id}, {tree_sub_id}) is missing its current next-append pointer"
                ))?;
            if current <= 0 {
                anyhow::bail!(
                    "update-only IMT pair ({tree_id}, {tree_sub_id}) has non-positive current next-append pointer {current}"
                );
            }
            Some(current)
        } else {
            let candidate = *state.insert_checkpoints.keys().next().expect("nonempty insert map");
            for (offset, actual) in state.insert_checkpoints.keys().copied().enumerate() {
                let expected = candidate
                    .checked_add(i64::try_from(offset)?)
                    .ok_or_else(|| anyhow::anyhow!("IMT insert index sequence overflows for pair ({tree_id}, {tree_sub_id})"))?;
                if actual != expected {
                    anyhow::bail!(
                        "IMT pair ({tree_id}, {tree_sub_id}) new leaf indices are not continuous: expected {expected}, got {actual}"
                    );
                }
            }

            match state.sentinel_index {
                Some(sentinel) => {
                    let first_real_index = sentinel.checked_add(1).ok_or_else(|| {
                        anyhow::anyhow!("IMT sentinel index overflows for pair ({tree_id}, {tree_sub_id})")
                    })?;
                    if candidate < first_real_index {
                        anyhow::bail!(
                            "IMT pair ({tree_id}, {tree_sub_id}) first new index {candidate} precedes sentinel boundary {first_real_index}"
                        );
                    }
                    if candidate == first_real_index {
                        if state_reader
                            .imt_leaf_at_target(tree_id, tree_sub_id, sentinel, target_checkpoint_id)
                            .await?
                        {
                            Some(candidate)
                        } else {
                            None
                        }
                    } else {
                        require_target_imt_predecessor(
                            state_reader,
                            tree_id,
                            tree_sub_id,
                            candidate,
                            target_checkpoint_id,
                        )
                        .await?;
                        Some(candidate)
                    }
                }
                None => {
                    require_target_imt_predecessor(
                        state_reader,
                        tree_id,
                        tree_sub_id,
                        candidate,
                        target_checkpoint_id,
                    )
                    .await?;
                    Some(candidate)
                }
            }
        };
        entries.push(ImtAppendIndexEntry { tree_id, tree_sub_id, next_append_index });
    }
    Ok(ImtAppendIndexSnapshot { entries })
}

async fn require_target_imt_predecessor(
    state_reader: &dyn RollbackStateReader,
    tree_id: i64,
    tree_sub_id: i64,
    candidate: i64,
    target_checkpoint_id: i64,
) -> anyhow::Result<()> {
    let predecessor = candidate.checked_sub(1).ok_or_else(|| {
        anyhow::anyhow!("IMT candidate index underflows for pair ({tree_id}, {tree_sub_id})")
    })?;
    if !state_reader
        .imt_leaf_at_target(tree_id, tree_sub_id, predecessor, target_checkpoint_id)
        .await?
    {
        anyhow::bail!(
            "IMT pair ({tree_id}, {tree_sub_id}) candidate {candidate} is not supported by target checkpoint predecessor {predecessor}"
        );
    }
    Ok(())
}

fn json_ids(ids: &[u64]) -> serde_json::Value {
    serde_json::Value::Array(ids.iter().copied().map(serde_json::Value::from).collect())
}

pub async fn generate_rollback_plan(input: &RollbackPlanInput<'_>) -> anyhow::Result<RollbackPlan> {
    if input.target_checkpoint_id > input.latest_checkpoint_id {
        anyhow::bail!(
            "target_checkpoint_id {} > latest_checkpoint_id {}",
            input.target_checkpoint_id,
            input.latest_checkpoint_id
        );
    }

    let ids = collect_ids(
        input.state_reader,
        input.target_checkpoint_id,
        input.latest_pending_id,
    )
    .await?;

    let realm_id_u32 = u32::try_from(input.realm_id)
        .map_err(|e| anyhow::anyhow!("realm_id {} does not fit u32: {}", input.realm_id, e))?;
    let realm_sub_u16 = u16::try_from(input.realm_sub_id)
        .map_err(|e| anyhow::anyhow!("realm_sub_id {} does not fit u16: {}", input.realm_sub_id, e))?;
    let pending_ids: Vec<u64> = ids.iter().map(|e| e.pending_id).collect();
    let (temp_fields, worker_reputation_fields) = materialize_temp_snapshot(
        input.temp_enumerator,
        realm_id_u32,
        realm_sub_u16,
        &pending_ids,
    )
    .await?;
    let snapshot = RollbackSnapshot {
        target_info: input.snapshot.target_info.clone(),
        worker_reputation_fields,
    };

    let plan = RollbackPlan {
        role: input.role,
        realm_id: input.realm_id,
        realm_sub_id: input.realm_sub_id,
        target_checkpoint_id: input.target_checkpoint_id,
        latest_checkpoint_id: input.latest_checkpoint_id,
        latest_pending_id: input.latest_pending_id,
        ids,
        target_contract_state: input.target_contract_state.clone().filter(|state| state.last_finalized_checkpoint_id == input.target_checkpoint_id),
        snapshot,
        phases: Vec::new(),
    };

    let phases = build_phases(
        &plan,
        &temp_fields,
        input.backups,
        &input.reward_realm_ids,
        &input.user_transform,
        &input.imt_snapshot,
        input.state_reader,
    )
    .await?;

    let plan = RollbackPlan { phases, ..plan };

    crate::rollback::validate::validate_rollback_plan(&plan)?;

    Ok(plan)
}

fn should_read_backup(path: &str, is_required: bool, exists: bool) -> anyhow::Result<bool> {
    if exists {
        return Ok(true);
    }
    if is_required {
        anyhow::bail!("required rollback backup is missing: {}", path);
    }
    Ok(false)
}

async fn backup_file_available<FS: TokioLikeFileSystem>(file_system: &FS, path: &str, is_required: bool) -> anyhow::Result<bool> {
    should_read_backup(path, is_required, file_system.file_like_exists(path).await?)
}
fn has_imt_key_index_row(is_new_key: bool, leaf_key: &[u8; 32], leaf_value: &[u8; 32]) -> bool {
    is_new_key || (leaf_key.iter().all(|byte| *byte == 0) && leaf_value.iter().all(|byte| *byte == 0))
}

fn materialize_imt_key_index_keys<N: QNetworkTypesConfig>(ffs: &[u8]) -> anyhow::Result<Vec<keys::ImtKeyIndexKey>> {
    if ffs.len() % IMT_LEAF_FFS_ENTRY_SIZE_V2 != 0 {
        anyhow::bail!("IMT leaf FFS length {} is not a multiple of {}", ffs.len(), IMT_LEAF_FFS_ENTRY_SIZE_V2);
    }
    let mut keys = Vec::new();
    for entry in ffs.chunks_exact(IMT_LEAF_FFS_ENTRY_SIZE_V2) {
        let (tree_id, tree_sub_id, _, _, leaf_key, leaf_value, _, _, is_new_key) =
            deserialize_imt_leaf_ffs_entry_v2(entry)?;
        if !has_imt_key_index_row(is_new_key, &leaf_key, &leaf_value) {
            continue;
        }
        let hash = N::QHash::from_owned_32bytes(leaf_key);
        let encoded_key = encode_imt_key_for_sorting::<N::F, N::QHash>(&hash);
        let key_bucket = imt_key_bucket_to_i16(u16::from_be_bytes([encoded_key[0], encoded_key[1]]));
        keys.push(keys::ImtKeyIndexKey {
            tree_id: tree_id as i64,
            tree_sub_id: tree_sub_id as i64,
            key_bucket,
            encoded_key: encoded_key.to_vec(),
        });
    }
    Ok(keys)
}

async fn collect_global_checkpoint_tree_delete_path_keys(
    state_reader: &dyn RollbackStateReader,
    target_checkpoint_id: u64,
    latest_checkpoint_id: u64,
) -> anyhow::Result<HashMap<u64, Vec<MerkleNodeKey>>> {
    let mut nodes_by_checkpoint = HashMap::new();
    for checkpoint_id in post_target_checkpoint_ids(target_checkpoint_id, latest_checkpoint_id) {
        let nodes = state_reader
            .global_checkpoint_tree_delete_path_keys(checkpoint_id)
            .await
            .with_context(|| {
                format!(
                    "failed to collect global checkpoint-tree delete path keys for checkpoint {}",
                    checkpoint_id
                )
            })?;
        if nodes.is_empty() {
            anyhow::bail!(
                "global checkpoint-tree delete path keys are empty for checkpoint {}",
                checkpoint_id
            );
        }
        nodes_by_checkpoint.insert(checkpoint_id, nodes);
    }
    Ok(nodes_by_checkpoint)
}

async fn materialize_backups_from_paths<N, FS>(
    input: &mut RollbackPlanFromBackupPathsInput<'_, N, FS>,
    ids: &[RollbackIds],
) -> anyhow::Result<BackupKeySource>
where
    N: QNetworkTypesConfig,
    FS: TokioLikeFileSystem + Send + Sync,
{
    let mut backups = BackupKeySource {
        global_checkpoint_tree_delete_path_keys: collect_global_checkpoint_tree_delete_path_keys(
            input.state_reader,
            input.target_checkpoint_id,
            input.latest_checkpoint_id,
        )
        .await?,
        ..Default::default()
    };
    for id in ids {
        let pending_id = id.pending_id;
        let is_committed = id.checkpoint_id.is_some();
        if !is_committed {
            continue;
        }
        let checkpoint_info = if input.role == RollbackRole::Coordinator {
            match id.checkpoint_id {
                Some(checkpoint_id) => input
                    .checkpoint_info_reader
                    .coordinator_checkpoint_info(checkpoint_id)
                    .await?,
                None => CoordinatorCheckpointInfo::default(),
            }
        } else {
            CoordinatorCheckpointInfo::default()
        };
        match input.role {
            RollbackRole::Coordinator => {
                let register_path = get_new_register_user_gatherer_backup_file_path(&input.backup_directories.register_user, input.realm_id, input.realm_sub_id, pending_id);
                if backup_file_available(input.file_system, &register_path, checkpoint_info.has_register_users).await? {
                    let register = read_register_user_gatherer_backup_file_path::<N, N::HasherBase, N::QHash, FS>(input.file_system, &register_path, input.user_registration_tree).await
                        .with_context(|| format!("failed to materialize register-user backup for pending {}", pending_id))?;
                    backups.register_user.insert(pending_id, RegisterUserBackup {
                        start_next_user_id: register.start_next_user_id,
                        new_user_public_keys_ffs: register.new_user_public_keys_ffs,
                        new_public_key_hash_to_user_id_rows_ffs: register.new_public_key_hash_to_user_id_rows_ffs,
                        update_user_registration_tree_nodes_ffs: register.update_user_registration_tree_nodes_ffs,
                    });
                }

                let deploy_path = get_new_deploy_contract_gatherer_backup_file_path(&input.backup_directories.deploy_contract, input.realm_id, input.realm_sub_id, pending_id);
                if backup_file_available(input.file_system, &deploy_path, checkpoint_info.has_deploy_contracts).await? {
                    let deploy = read_deploy_contract_gatherer_backup_file_path::<N::HasherBase, N::QHash, N::F, FS>(
                        input.file_system, &deploy_path, 1usize << N::CONTRACT_FUNCTION_TREE_HEIGHT, input.global_contract_tree,
                    ).await.with_context(|| format!("failed to materialize deploy-contract backup for pending {}", pending_id))?;
                    let new_contract_ids = (deploy.start_next_contract_id..deploy.next_contract_id).collect();
                    backups.deploy_contract.insert(pending_id, DeployContractBackup {
                        new_contract_ids,
                        update_contract_function_tree_nodes_ffs: deploy.update_contract_function_tree_nodes_ffs,
                        update_global_contract_tree_nodes_ffs: deploy.update_global_contract_tree_nodes_ffs,
                    });
                }

                let update_path = get_new_update_contract_gatherer_backup_file_path(&input.backup_directories.update_contract, input.realm_id, input.realm_sub_id, pending_id);
                if backup_file_available(input.file_system, &update_path, checkpoint_info.contract_root_changed).await? {
                    let update = read_update_contract_gatherer_backup_file_path::<N::HasherBase, N::QHash, N::F, FS>(
                        input.file_system, &update_path, 1usize << N::CONTRACT_FUNCTION_TREE_HEIGHT, input.global_contract_tree,
                    ).await.with_context(|| format!("failed to materialize update-contract backup for pending {}", pending_id))?;
                    backups.update_contract.insert(pending_id, UpdateContractBackup {
                        updated_contract_ids: update.updated_contract_ids,
                        update_contract_function_tree_nodes_ffs: update.update_contract_function_tree_nodes_ffs,
                        update_global_contract_tree_nodes_ffs: update.update_global_contract_tree_nodes_ffs,
                    });
                }
                if checkpoint_info.contract_root_changed {
                    let actual_root = input.global_contract_tree.get_root().into_owned_32bytes();
                    if actual_root != checkpoint_info.contract_root {
                        anyhow::bail!(
                            "contract gatherer backups for pending {} reconstruct root {}, expected checkpoint root {}",
                            pending_id,
                            hex::encode(actual_root),
                            hex::encode(checkpoint_info.contract_root)
                        );
                    }
                }

                let guta_path = get_new_coordinator_guta_update_gatherer_backup_file_path(&input.backup_directories.coordinator_guta, input.realm_id, input.realm_sub_id, pending_id);
                let guta_path = guta_path.to_string_lossy();
                if backup_file_available(input.file_system, &guta_path, checkpoint_info.has_guta_updates).await? {
                    let guta = read_coordinator_guta_update_gatherer_backup_file::<N::HasherBase, N::QHash, N::F, FS>(input.file_system, &guta_path, input.global_user_tree).await
                        .with_context(|| format!("failed to materialize coordinator GUTA backup for pending {}", pending_id))?;
                    backups.coordinator_guta.insert(pending_id, CoordinatorGutaBackup { update_global_user_tree_nodes_ffs: guta.update_global_user_tree_nodes_ffs });
                }
            }
            RollbackRole::Realm => {
                let path = get_new_realm_end_cap_gatherer_backup_file_path(&input.backup_directories.realm_end_cap, input.realm_id, input.realm_sub_id, pending_id);
                let path = path.to_string_lossy();
                if backup_file_available(input.file_system, &path, is_committed).await? {
                    let realm = read_realm_end_cap_gatherer_backup_file::<N::HasherBase, N::QHash, N::F, FS>(
                        input.file_system,
                        &path,
                        input.global_user_tree,
                        input.realm_id,
                        N::REALM_GLOBAL_USER_TREE_HEIGHT,
                        N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
                        false,
                    ).await.with_context(|| format!("failed to materialize realm end-cap backup for pending {}", pending_id))?;
                    let imt_key_index_keys = materialize_imt_key_index_keys::<N>(&realm.update_contract_state_imt_leaves_ffs)?;
                    backups.realm_end_cap.insert(pending_id, RealmEndCapBackup {
                        update_user_leaves_ffs: realm.update_user_leaves_ffs,
                        update_user_contract_tree_nodes_ffs: realm.update_user_contract_tree_nodes_ffs,
                        update_contract_state_tree_nodes_ffs: realm.update_contract_state_tree_nodes_ffs,
                        update_global_user_tree_nodes_ffs: realm.update_global_user_tree_nodes_ffs,
                        update_contract_state_imt_leaves_ffs: realm.update_contract_state_imt_leaves_ffs,
                        imt_key_index_keys,
                    });
                }
            }
        }
    }
    Ok(backups)
}

pub async fn generate_rollback_plan_from_backup_paths<N, FS>(
    input: &mut RollbackPlanFromBackupPathsInput<'_, N, FS>,
) -> anyhow::Result<RollbackPlan>
where
    N: QNetworkTypesConfig,
    FS: TokioLikeFileSystem + Send + Sync,
{
    let ids = collect_ids(input.state_reader, input.target_checkpoint_id, input.latest_pending_id).await?;
    let backups = materialize_backups_from_paths(input, &ids).await?;
    let imt_snapshot = if input.role == RollbackRole::Realm {
        derive_imt_append_index_snapshot(
            &backups,
            &ids,
            input.target_checkpoint_id,
            input.state_reader,
        )
        .await?
    } else {
        ImtAppendIndexSnapshot::default()
    };
    let materialized = RollbackPlanInput {
        role: input.role,
        realm_id: input.realm_id,
        realm_sub_id: input.realm_sub_id,
        target_checkpoint_id: input.target_checkpoint_id,
        latest_checkpoint_id: input.latest_checkpoint_id,
        latest_pending_id: input.latest_pending_id,
        state_reader: input.state_reader,
        temp_enumerator: input.temp_enumerator,
        backups: &backups,
        reward_realm_ids: input.reward_realm_ids.clone(),
        user_transform: input.user_transform,
        imt_snapshot,
        snapshot: input.snapshot.clone(),
        target_contract_state: input.target_contract_state.clone(),
    };
    generate_rollback_plan(&materialized).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_catalogs_are_exact() {
        assert_eq!(STAGE1_TABLES, ["TKVSV1", "TMPPSV1-proof-buckets", "nats_jetstream_consumers"]);
        assert_eq!(STAGE2_TABLES.len(), 19);
        assert_eq!(EMPTY_SCHEMA_TABLES, ["checkpoint_leaf_to_checkpoint_id_table"]);
        assert_eq!(STAGE3_TABLES.len(), 8);
        let stage3: std::collections::HashSet<_> = STAGE3_TABLES.iter().copied().collect();
        assert_eq!(stage3.len(), 8);
        for table in [
            "global_user_tree_table",
            "user_contract_tree_table",
            "contract_state_tree_table",
            "global_checkpoint_tree_table",
            "user_registration_tree_table",
            "global_contract_tree_table",
            "contract_function_tree_table",
            "imt_leaf_table",
        ] {
            assert!(stage3.contains(table), "Stage 3 missing {}", table);
        }
    }

    #[test]
    fn api_for_table_covers_all_tables() {
        for table in STAGE1_TABLES[2..].iter().chain(STAGE2_TABLES.iter()).chain(EMPTY_SCHEMA_TABLES.iter()).chain(STAGE3_TABLES.iter()).chain(FINAL_TABLES.iter()) {
            assert_ne!(api_for_table(table), "UNKNOWN", "no API for table {}", table);
        }
    }

    #[test]
    fn set_latest_checkpoint_id_api_name() {
        assert_eq!(api_for_table("u64_singleton_table"), "set_latest_checkpoint_id");
    }

    #[test]
    fn imt_key_index_matches_writer_predicate() {
        let nonzero = [1u8; 32];
        let zero = [0u8; 32];
        assert!(!has_imt_key_index_row(false, &nonzero, &nonzero));
        assert!(has_imt_key_index_row(true, &nonzero, &nonzero));
        assert!(has_imt_key_index_row(false, &zero, &zero));
        assert!(!has_imt_key_index_row(false, &zero, &nonzero));
    }

    #[test]
    fn missing_backup_fails_only_when_checkpoint_activity_requires_it() {
        assert!(!should_read_backup("missing.backup", false, false).unwrap());
        assert!(should_read_backup("missing.backup", true, false).is_err());
        assert!(should_read_backup("present.backup", false, true).unwrap());
        assert!(should_read_backup("present.backup", true, true).unwrap());
    }

    #[test]
    fn checkpoint_info_contract_flags_are_independent() {
        let info = CoordinatorCheckpointInfo {
            has_deploy_contracts: true,
            contract_root_changed: true,
            ..Default::default()
        };
        assert!(info.has_deploy_contracts);
        assert!(info.contract_root_changed);

        let deploy_only = CoordinatorCheckpointInfo {
            has_deploy_contracts: true,
            ..Default::default()
        };
        assert!(deploy_only.has_deploy_contracts);
        assert!(!deploy_only.contract_root_changed);
    }
    #[test]
    fn checkpoint_range_is_complete_despite_mapping_holes() {
        assert_eq!(post_target_checkpoint_ids(199, 203), vec![200, 201, 202, 203]);
        assert_eq!(post_target_checkpoint_ids(0, 2), vec![1, 2]);
        assert!(post_target_checkpoint_ids(203, 203).is_empty());
        assert!(post_target_checkpoint_ids(0, 0).is_empty());
    }

    #[test]
    fn post_target_checkpoint_ids_returns_empty_for_backward_target() {
        assert_eq!(post_target_checkpoint_ids(6, 5), Vec::<u64>::new());
    }

    struct TestRollbackStateReader {
        leaves: HashSet<(i64, i64, i64, i64)>,
        checkpoint_delete_path_keys: HashMap<u64, Vec<MerkleNodeKey>>,
    }

    #[async_trait::async_trait]
    impl RollbackStateReader for TestRollbackStateReader {
        async fn pending_id_for_checkpoint(&self, _checkpoint_id: u64) -> anyhow::Result<Option<u64>> { Ok(None) }
        async fn checkpoint_id_for_pending(&self, _pending_id: u64) -> anyhow::Result<Option<u64>> { Ok(None) }
        async fn proc_id_for_pending(&self, _pending_id: u64) -> anyhow::Result<Option<u128>> { Ok(None) }
        async fn root_for_checkpoint(&self, _checkpoint_id: u64) -> anyhow::Result<Option<[u8; 32]>> { Ok(None) }
        async fn imt_leaf_at_target(&self, tree_id: i64, tree_sub_id: i64, leaf_index: i64, target_checkpoint_id: i64) -> anyhow::Result<bool> {
            Ok(self.leaves.contains(&(tree_id, tree_sub_id, leaf_index, target_checkpoint_id)))
        }
        async fn imt_next_append_index(&self, tree_id: i64, tree_sub_id: i64) -> anyhow::Result<Option<i64>> {
            Ok(((tree_id, tree_sub_id) == (7, 9)).then_some(11))
        }
        async fn global_checkpoint_tree_delete_path_keys(&self, checkpoint_id: u64) -> anyhow::Result<Vec<MerkleNodeKey>> {
            Ok(self.checkpoint_delete_path_keys.get(&checkpoint_id).cloned().unwrap_or_default())
        }
    }

    struct EmptyTempEnumerator;

    #[async_trait::async_trait]
    impl RollbackTempEnumerator for EmptyTempEnumerator {
        async fn scan_fields(&self, _cursor: u64, _count: u32) -> anyhow::Result<(u64, Vec<Vec<u8>>)> {
            Ok((0, Vec::new()))
        }

        async fn get_value(&self, _field: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
            Ok(None)
        }
    }

    struct PagedTempEnumerator {
        pages: Vec<Vec<Vec<u8>>>,
        values: HashMap<Vec<u8>, Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl RollbackTempEnumerator for PagedTempEnumerator {
        async fn scan_fields(&self, cursor: u64, _count: u32) -> anyhow::Result<(u64, Vec<Vec<u8>>)> {
            let index = usize::try_from(cursor)?;
            let Some(fields) = self.pages.get(index) else {
                anyhow::bail!("invalid test cursor {cursor}");
            };
            let next = if index + 1 == self.pages.len() { 0 } else { (index + 1) as u64 };
            Ok((next, fields.clone()))
        }

        async fn get_value(&self, field: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
            Ok(self.values.get(field).cloned())
        }
    }

    fn pending_field(table_id: &[u8; 2], pending_id: u64) -> Vec<u8> {
        let mut field = Vec::with_capacity(17);
        field.extend_from_slice(&3u32.to_le_bytes());
        field.extend_from_slice(&0u16.to_le_bytes());
        field.extend_from_slice(table_id);
        field.extend_from_slice(&pending_id.to_le_bytes());
        field.push(0xAA);
        field
    }

    fn singleton_field(table_id: &[u8; 2], suffix: u8) -> Vec<u8> {
        let mut field = Vec::with_capacity(9);
        field.extend_from_slice(&3u32.to_le_bytes());
        field.extend_from_slice(&0u16.to_le_bytes());
        field.extend_from_slice(table_id);
        field.push(suffix);
        field
    }
    fn worker_reputation_field(suffix: u8) -> Vec<u8> {
        let mut field = vec![0u8; TEMP_TABLE_WORKER_REPUTATION_KEY_SIZE];
        field[0..4].copy_from_slice(&3u32.to_le_bytes());
        field[6..8].copy_from_slice(&TEMP_TABLE_ID_WORKER_REPUTATION_BYTES);
        field[8] = suffix;
        field
    }


    #[tokio::test]
    async fn temp_snapshot_collects_matching_pending_fields_and_sorted_worker_reputation() {
        let ep88 = pending_field(b"EP", 88);
        let ss88 = pending_field(b"SS", 88);
        let ep7 = pending_field(b"EP", 7);
        let pi = singleton_field(b"PI", 0);
        let stale_sc = pending_field(b"SC", 88);
        let short = vec![1, 2, 3];
        let reputation_field_b = worker_reputation_field(2);
        let reputation_field_a = worker_reputation_field(1);
        let enumerator = PagedTempEnumerator {
            pages: vec![vec![ep88.clone(), ep7, ss88.clone(), reputation_field_b.clone(), pi, stale_sc, short], vec![reputation_field_a.clone()]],
            values: HashMap::from([(reputation_field_a.clone(), vec![1]), (reputation_field_b.clone(), vec![2])]),
        };

        let (keys, worker_reputation_fields) = materialize_temp_snapshot(&enumerator, 3, 0, &[88]).await.unwrap();

        let key_fields: HashSet<Vec<u8>> = keys.iter().map(|key| key.field.to_vec()).collect();
        assert_eq!(key_fields, HashSet::from([ep88, ss88]));
        assert!(keys.iter().all(|key| key.pending_id == 88));
        let worker_reputation_raw: Vec<Vec<u8>> = worker_reputation_fields.iter().map(|field| hex::decode(&field.field).unwrap()).collect();
        assert_eq!(worker_reputation_raw, vec![reputation_field_a, reputation_field_b], "worker reputation snapshot must be sorted by hex field");
        assert_eq!(worker_reputation_fields[0].value.as_deref(), Some("01"));
        assert_eq!(worker_reputation_fields[1].value.as_deref(), Some("02"));
    }

    #[tokio::test]
    async fn temp_snapshot_fails_closed_on_duplicate_or_disappearing_worker_reputation_field() {
        let reputation_field = worker_reputation_field(1);
        let duplicate = PagedTempEnumerator {
            pages: vec![vec![reputation_field.clone()], vec![reputation_field.clone()]],
            values: HashMap::from([(reputation_field.clone(), vec![1])]),
        };
        let err = materialize_temp_snapshot(&duplicate, 3, 0, &[88]).await.unwrap_err();
        assert!(err.to_string().contains("duplicate worker reputation field"), "{err}");

        let disappearing = PagedTempEnumerator {
            pages: vec![vec![reputation_field]],
            values: HashMap::new(),
        };
        let err = materialize_temp_snapshot(&disappearing, 3, 0, &[88]).await.unwrap_err();
        assert!(err.to_string().contains("worker reputation field disappeared during snapshot"), "{err}");
    }

    #[tokio::test]
    async fn generate_rejects_target_newer_than_latest() {
        let reader = TestRollbackStateReader { leaves: HashSet::new(), checkpoint_delete_path_keys: HashMap::new() };
        let temp_enumerator = EmptyTempEnumerator;
        let backups = BackupKeySource::default();
        let input = RollbackPlanInput {
            role: RollbackRole::Realm,
            realm_id: 1,
            realm_sub_id: 0,
            target_checkpoint_id: 6,
            latest_checkpoint_id: 5,
            latest_pending_id: 0,
            state_reader: &reader,
            temp_enumerator: &temp_enumerator,
            backups: &backups,
            reward_realm_ids: Vec::new(),
            user_transform: UserTransformParams::default(),
            imt_snapshot: ImtAppendIndexSnapshot::default(),
            snapshot: RollbackSnapshot {
                target_info: String::new(),
                worker_reputation_fields: Vec::new(),
            },
            target_contract_state: Some(TargetContractState {
                last_finalized_checkpoint_id: 6,
                last_verified_checkpoint_root: None,
                last_verified_deposit_tree_root: None,
                last_verified_withdrawal_tree_root: None,
                withdrawal_subtree_root: None,
                deposit_root: None,
                proved_deposit_count: None,
                pending_deposit_count: None,
            }),
        };

        let error = generate_rollback_plan(&input).await.unwrap_err();
        assert_eq!(error.to_string(), "target_checkpoint_id 6 > latest_checkpoint_id 5");
    }

    #[tokio::test]
    async fn genesis_plan_generates_valid_full_phase_catalog_end_to_end() {
        let reader = TestRollbackStateReader { leaves: HashSet::new(), checkpoint_delete_path_keys: HashMap::new() };
        let temp_enumerator = EmptyTempEnumerator;
        let backups = BackupKeySource::default();
        let input = RollbackPlanInput {
            role: RollbackRole::Coordinator,
            realm_id: 0,
            realm_sub_id: 0,
            target_checkpoint_id: 0,
            latest_checkpoint_id: 0,
            latest_pending_id: 0,
            state_reader: &reader,
            temp_enumerator: &temp_enumerator,
            backups: &backups,
            reward_realm_ids: Vec::new(),
            user_transform: UserTransformParams::default(),
            imt_snapshot: ImtAppendIndexSnapshot::default(),
            snapshot: RollbackSnapshot {
                target_info: "00".into(),
                worker_reputation_fields: Vec::new(),
            },
            target_contract_state: None,
        };

        let plan = generate_rollback_plan(&input).await.unwrap();

        let expected_tables: Vec<&str> = STAGE1_TABLES
            .iter()
            .chain(STAGE2_TABLES)
            .chain(EMPTY_SCHEMA_TABLES)
            .chain(STAGE3_TABLES)
            .chain(FINAL_TABLES)
            .copied()
            .collect();
        assert_eq!(plan.phases.len(), expected_tables.len());
        assert_eq!(
            plan.phases.iter().map(|phase| phase.table.as_str()).collect::<Vec<_>>(),
            expected_tables
        );
        assert_eq!(plan.phases[plan.phases.len() - 2].table, "all");
        assert_eq!(plan.phases.last().unwrap().table, "u64_singleton_table");
        assert!(plan.ids.is_empty());
        let singleton_phase = plan.phases.iter().find(|phase| phase.table == "TKVSV1-singletons").unwrap();
        let expected_singletons: HashSet<String> = keys::processor_state_singleton_fields(0, 0)
            .unwrap()
            .into_iter()
            .map(hex::encode)
            .collect();
        let actual_singletons: HashSet<String> = singleton_phase.keys.as_array().unwrap().iter().map(|key| key.as_str().unwrap().to_string()).collect();
        assert_eq!(actual_singletons, expected_singletons);
    }

    #[tokio::test]
    async fn generation_retains_only_matching_target_contract_state() {
        let reader = TestRollbackStateReader { leaves: HashSet::new(), checkpoint_delete_path_keys: HashMap::new() };
        let temp_enumerator = EmptyTempEnumerator;
        let backups = BackupKeySource::default();
        let mut input = RollbackPlanInput {
            role: RollbackRole::Coordinator,
            realm_id: 0,
            realm_sub_id: 0,
            target_checkpoint_id: 0,
            latest_checkpoint_id: 0,
            latest_pending_id: 0,
            state_reader: &reader,
            temp_enumerator: &temp_enumerator,
            backups: &backups,
            reward_realm_ids: Vec::new(),
            user_transform: UserTransformParams::default(),
            imt_snapshot: ImtAppendIndexSnapshot::default(),
            snapshot: RollbackSnapshot { target_info: "00".into(), worker_reputation_fields: Vec::new() },
            target_contract_state: None,
        };

        assert!(generate_rollback_plan(&input).await.unwrap().target_contract_state.is_none());
        input.target_contract_state = Some(TargetContractState {
            last_finalized_checkpoint_id: 0,
            last_verified_checkpoint_root: Some("matching".into()),
            last_verified_deposit_tree_root: None,
            last_verified_withdrawal_tree_root: None,
            withdrawal_subtree_root: None,
            deposit_root: None,
            proved_deposit_count: None,
            pending_deposit_count: None,
        });
        assert_eq!(generate_rollback_plan(&input).await.unwrap().target_contract_state, input.target_contract_state);
        input.target_contract_state.as_mut().unwrap().last_finalized_checkpoint_id = 1;
        assert!(generate_rollback_plan(&input).await.unwrap().target_contract_state.is_none());
    }

    #[tokio::test]
    async fn checkpoint_delete_path_keys_require_every_post_target_checkpoint() {
        let mut reader = TestRollbackStateReader {
            leaves: HashSet::new(),
            checkpoint_delete_path_keys: HashMap::from([
                (42, vec![MerkleNodeKey { level: 0, index: 1, checkpoint_id: 42 }]),
                (44, vec![MerkleNodeKey { level: 0, index: 2, checkpoint_id: 44 }]),
            ]),
        };
        let error = collect_global_checkpoint_tree_delete_path_keys(&reader, 41, 44).await.unwrap_err();
        assert!(error.to_string().contains("checkpoint 43"), "{error}");

        reader.checkpoint_delete_path_keys.insert(
            43,
            vec![MerkleNodeKey { level: 1, index: 3, checkpoint_id: 43 }],
        );
        let keys = collect_global_checkpoint_tree_delete_path_keys(&reader, 41, 44).await.unwrap();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[&43][0].checkpoint_id, 43);
    }
    fn imt_entry(
        tree_id: u64,
        tree_sub_id: u64,
        leaf_index: u64,
        leaf_key: [u8; 32],
        leaf_value: [u8; 32],
        is_new_key: bool,
    ) -> Vec<u8> {
        let mut entry = vec![0u8; IMT_LEAF_FFS_ENTRY_SIZE_V2];
        entry[0..8].copy_from_slice(&tree_id.to_le_bytes());
        entry[8..16].copy_from_slice(&tree_sub_id.to_le_bytes());
        entry[16..24].copy_from_slice(&leaf_index.to_le_bytes());
        entry[56..88].copy_from_slice(&leaf_key);
        entry[88..120].copy_from_slice(&leaf_value);
        entry[160] = u8::from(is_new_key);
        entry
    }

    fn realm_backup_with_imt(ffs: Vec<u8>) -> RealmEndCapBackup {
        RealmEndCapBackup {
            update_user_leaves_ffs: Vec::new(),
            update_user_contract_tree_nodes_ffs: Vec::new(),
            update_contract_state_tree_nodes_ffs: Vec::new(),
            update_global_user_tree_nodes_ffs: Vec::new(),
            update_contract_state_imt_leaves_ffs: ffs,
            imt_key_index_keys: Vec::new(),
        }
    }

    fn imt_backups(entries: &[(u64, Vec<u8>)]) -> BackupKeySource {
        let mut backups = BackupKeySource::default();
        for (pending_id, ffs) in entries {
            backups.realm_end_cap.insert(*pending_id, realm_backup_with_imt(ffs.clone()));
        }
        backups
    }

    fn ids(checkpoints: &[(u64, u64)]) -> Vec<RollbackIds> {
        checkpoints
            .iter()
            .map(|(checkpoint_id, pending_id)| RollbackIds {
                checkpoint_id: Some(*checkpoint_id),
                pending_id: *pending_id,
                proc_id: u128::from(*pending_id),
            })
            .collect()
    }

    #[tokio::test]
    async fn imt_insert_indices_are_deduped_within_checkpoint_and_must_be_continuous() {
        let reader = TestRollbackStateReader {
            leaves: HashSet::from([(7, 9, 12, 42)]),
            checkpoint_delete_path_keys: HashMap::new(),
        };
        let one = [1u8; 32];
        let mut ffs = imt_entry(7, 9, 13, one, one, true);
        ffs.extend(imt_entry(7, 9, 13, one, one, true));
        ffs.extend(imt_entry(7, 9, 14, one, one, true));
        let snapshot = derive_imt_append_index_snapshot(
            &imt_backups(&[(88, ffs)]),
            &ids(&[(43, 88)]),
            42,
            &reader,
        )
        .await
        .unwrap();
        assert_eq!(snapshot.entries[0].next_append_index, Some(13));

        let mut gap = imt_entry(7, 9, 13, one, one, true);
        gap.extend(imt_entry(7, 9, 15, one, one, true));
        let error = derive_imt_append_index_snapshot(
            &imt_backups(&[(88, gap)]),
            &ids(&[(43, 88)]),
            42,
            &reader,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("not continuous"), "{error}");
    }

    #[tokio::test]
    async fn imt_rejects_new_index_repeated_across_checkpoints() {
        let reader = TestRollbackStateReader { leaves: HashSet::new(), checkpoint_delete_path_keys: HashMap::new() };
        let one = [1u8; 32];
        let backups = imt_backups(&[
            (88, imt_entry(7, 9, 13, one, one, true)),
            (89, imt_entry(7, 9, 13, one, one, true)),
        ]);
        let error = derive_imt_append_index_snapshot(
            &backups,
            &ids(&[(43, 88), (44, 89)]),
            42,
            &reader,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("across checkpoints"), "{error}");
    }

    #[tokio::test]
    async fn imt_update_only_freezes_current_pointer_and_rejects_missing_row() {
        let one = [1u8; 32];
        let reader = TestRollbackStateReader { leaves: HashSet::new(), checkpoint_delete_path_keys: HashMap::new() };
        let snapshot = derive_imt_append_index_snapshot(
            &imt_backups(&[(88, imt_entry(7, 9, 4, one, one, false))]),
            &ids(&[(43, 88)]),
            42,
            &reader,
        )
        .await
        .unwrap();
        assert_eq!(snapshot.entries[0].next_append_index, Some(11));

        let error = derive_imt_append_index_snapshot(
            &imt_backups(&[(88, imt_entry(8, 10, 4, one, one, false))]),
            &ids(&[(43, 88)]),
            42,
            &reader,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("missing its current"), "{error}");
    }

    #[tokio::test]
    async fn imt_nonzero_sentinel_decides_absent_or_existing_target_pair_without_leaf_zero() {
        let zero = [0u8; 32];
        let one = [1u8; 32];
        let mut ffs = imt_entry(7, 9, 10, zero, zero, false);
        ffs.extend(imt_entry(7, 9, 11, one, one, true));
        let backups = imt_backups(&[(88, ffs)]);
        let ids = ids(&[(43, 88)]);

        let absent = TestRollbackStateReader {
            leaves: HashSet::from([(7, 9, 0, 42)]),
            checkpoint_delete_path_keys: HashMap::new(),
        };
        let snapshot = derive_imt_append_index_snapshot(&backups, &ids, 42, &absent).await.unwrap();
        assert_eq!(snapshot.entries[0].next_append_index, None, "leaf zero must not determine pair existence");

        let present = TestRollbackStateReader {
            leaves: HashSet::from([(7, 9, 10, 42)]),
            checkpoint_delete_path_keys: HashMap::new(),
        };
        let snapshot = derive_imt_append_index_snapshot(&backups, &ids, 42, &present).await.unwrap();
        assert_eq!(snapshot.entries[0].next_append_index, Some(11));
    }

    #[tokio::test]
    async fn imt_insert_without_sentinel_requires_target_predecessor() {
        let one = [1u8; 32];
        let backups = imt_backups(&[(88, imt_entry(7, 9, 13, one, one, true))]);
        let ids = ids(&[(43, 88)]);
        let missing = TestRollbackStateReader { leaves: HashSet::new(), checkpoint_delete_path_keys: HashMap::new() };
        assert!(derive_imt_append_index_snapshot(&backups, &ids, 42, &missing).await.is_err());

        let present = TestRollbackStateReader {
            leaves: HashSet::from([(7, 9, 12, 42)]),
            checkpoint_delete_path_keys: HashMap::new(),
        };
        let snapshot = derive_imt_append_index_snapshot(&backups, &ids, 42, &present).await.unwrap();
        assert_eq!(snapshot.entries[0].next_append_index, Some(13));
    }
}