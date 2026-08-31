use std::{marker::PhantomData, sync::Arc};

use anyhow::{bail, ensure, Context};
use async_trait::async_trait;
use parth_core::protocol::core_types::{
    Q256BitHash, QNetworkHashTypes, QNetworkTreeConstants, QNetworkTypesConfigHelper,
};
use psy_core::{
    constants::{
        chain_id::PsyChainNetworkType,
        stale_checkpoint::{
            STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF,
            STALE_CHECKPOINT_AGE_USER_END_CAP_TO_REALM_PROOF,
        },
    },
    job::job_id::QProvingJobDataID,
    network_config::PsyNetworkLocalDevnetConstants,
};
use parth_core::data::queue::queue_key::QPBaseQueueType;
use psy_io::tokio::TokioStdFileSystem;
use psy_data::v1::qdata::checkpoint::QEDL2BlockState;
use psy_plonky2_circuits::protocol_types::ZKTypesPlonky2GoldilocksPoseidon;
use psy_node_common::{
    coordinator::{
        processor::gatherers::{
            coordinator_guta_update_gatherer::get_new_coordinator_guta_update_gatherer_backup_file_path,
            deploy_contract_gatherer::get_new_deploy_contract_gatherer_backup_file_path,
            register_user_gatherer::get_new_register_user_gatherer_backup_file_path,
            update_contract_gatherer::get_new_update_contract_gatherer_backup_file_path,
        },
        queue_key::{
            CoordinatorDeployContractQueueKey, CoordinatorProvingWorkQueueKey,
            CoordinatorRegisterUserPublicKeyQueueKey, CoordinatorSubmitRealmGUTAUpdateQueueKey,
            CoordinatorUpdateContractQueueKey,
        },
    },
    realm::{
        processor::gatherers::realm_end_cap_gatherer::get_new_realm_end_cap_gatherer_backup_file_path,
        queue_key::{RealmProvingWorkQueueKey, RealmUserUpdateQueueKey},
    },
    backup::checkpoint_tree::CheckpointTreeBackupManager,
    rollback::{
        execute_rollback_plan, AtomicRollbackPlanProgress, ExecutableRollbackPhase,
        RollbackExecutionStore, RollbackNatsConsumerKind, RollbackNatsConsumerTarget,
        RollbackOperation, RollbackPlan,
    },
};
use psy_node_core::{
    psy_core_db::{
        core_implementation::constants::{
            LATEST_INFO_TABLE_OBJ_ID_LATEST_CHECKPOINT_TREE_ROOT,
            LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE,
        },
        traits::full::{PsyNodeCheckpointObjectDatabaseWriter, PsyNodeCheckpointTreeDatabaseReader},
    },
    store::traits::{
        core_db::{
            CoreDatabaseBlobPairDeleter, CoreDatabaseBlobPairVerifier,
            CoreDatabaseHashUserPairDeleter, CoreDatabaseHashUserPairVerifier,
            CoreDatabaseIMTNextAppendIndexReader, CoreDatabaseIMTNextAppendIndexWriter,
            CoreDatabaseImtKeyDeleter, CoreDatabaseImtKeyVerifier,
            CoreDatabaseImtLeafDeleter, CoreDatabaseImtLeafVerifier,
            CoreDatabaseImtNextAppendIndexDeleter, CoreDatabaseKivReader,
            CoreDatabaseKivWriter, CoreDatabaseMerkleDeleter, CoreDatabaseMerkleVerifier,
            CoreDatabaseObjectCheckpointDeleter, CoreDatabaseObjectCheckpointVerifier,
            CoreDatabaseObjectIdDeleter, CoreDatabaseObjectIdVerifier,
            CoreDatabasePendingIdPartitionDeleter, CoreDatabasePendingIdPartitionVerifier,
            CoreDatabaseTreeMerkleDeleter, CoreDatabaseTreeMerkleVerifier,
            CoreDatabaseTreeSubtreeMerkleDeleter, CoreDatabaseTreeSubtreeMerkleVerifier,
            CoreDatabaseU64U128PairDeleter, CoreDatabaseU64U128PairVerifier,
        },
        proof_store::{QParthProofBucketPresenceReader, QParthProofStoreWriter},
        temp_db::{QTempDatabaseRawKVEnumeratorBase, QTempDatabaseRawKVReaderBase, QTempDatabaseRawKVWriterBase},
    },
};
use psy_node_core::queue::{
    ephemeral::QStandardEphemeralQueueSubscriber,
    worker_queue::QStandardWorkerQueueSubscriber,
};
use psy_node_redis::store::{new_redis_async_pool, StandardFredRedisStore};
use psy_node_nats::{psy_queue::{setup_nats_psy_queue_from_connection_str, NatsSetupMode}, queue::NatsJetStreamClient};
use psy_node_scylla::psy_setup::{
    setup_psy_scylla_database_store_from_connection_string, ScyllaUnifiedPsyStore,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use tokio::sync::Mutex;

use super::{ExecuteArgs, ProcessorConfig};

type Network = QNetworkTypesConfigHelper<
    QProvingJobDataID,
    ZKTypesPlonky2GoldilocksPoseidon,
    PsyNetworkLocalDevnetConstants,
>;
type Database = ScyllaUnifiedPsyStore<
    Network,
    <Network as QNetworkHashTypes>::QHash,
    <Network as QNetworkHashTypes>::HasherBase,
>;
type CheckpointManager = CheckpointTreeBackupManager<
    <Network as QNetworkHashTypes>::HasherBase,
    <Network as QNetworkHashTypes>::QHash,
    TokioStdFileSystem,
>;

struct ExecutionStore {
    database: Database,
    temp: StandardFredRedisStore,
    checkpoint_manager: Mutex<CheckpointManager>,
    frozen_counter_high_water: u64,
    nats: NatsJetStreamClient,
    config: ProcessorConfig,
}

struct RoleConfig<'a> {
    scylla_url: &'a str,
    nats_url: &'a str,
    redis_url: &'a str,
    namespace: &'a str,
    processor_id: u64,
    processor_sub_id: u64,
    checkpoint_path: String,
    ring_capacity: u64,
}

fn role_config(config: &ProcessorConfig) -> RoleConfig<'_> {
    match config {
        ProcessorConfig::Coordinator(c) => RoleConfig {
            scylla_url: &c.scylla_db_url,
            nats_url: &c.nats_jetstream_url,
            redis_url: &c.redis_url,
            namespace: &c.db_namespace,
            processor_id: c.coordinator_id,
            processor_sub_id: u64::from(c.coordinator_sub_id),
            checkpoint_path: c.get_checkpoint_tree_backup_file_path(),
            ring_capacity: STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF,
        },
        ProcessorConfig::Realm(c) => RoleConfig {
            scylla_url: &c.scylla_db_url,
            nats_url: &c.nats_jetstream_url,
            redis_url: &c.redis_url,
            namespace: &c.db_namespace,
            processor_id: c.realm_id,
            processor_sub_id: u64::from(c.realm_sub_id),
            checkpoint_path: c.get_checkpoint_tree_backup_file_path(),
            ring_capacity: STALE_CHECKPOINT_AGE_USER_END_CAP_TO_REALM_PROOF,
        },
    }
}

async fn open_rollback_execution_store(
    config: &ProcessorConfig,
    frozen_high_water: u64,
) -> anyhow::Result<ExecutionStore> {
    let role = role_config(config);
    let database = setup_psy_scylla_database_store_from_connection_string::<Network>(
        role.namespace, role.scylla_url, false,
    )
    .await
    .context("failed to prepare existing Scylla tables for rollback")?;
    let temp = StandardFredRedisStore::new(
        new_redis_async_pool(role.redis_url, 2)
            .await
            .context("failed to connect rollback Temp Redis store")?,
        role.namespace.to_string(),
        role.processor_id,
        role.processor_sub_id,
    );
    let nats = setup_nats_psy_queue_from_connection_str(role.nats_url, role.namespace, NatsSetupMode::ExistingOnly)
        .await
        .context("failed to open existing rollback NATS JetStream store")?;
    let checkpoint_manager = CheckpointTreeBackupManager::new_from_file_path(
        Arc::new(TokioStdFileSystem),
        role.ring_capacity,
        <Network as QNetworkTreeConstants>::CHECKPOINT_TREE_HEIGHT,
        &database,
        &role.checkpoint_path,
        false,
    )
    .await
    .with_context(|| format!("failed to open checkpoint ring buffer {}", role.checkpoint_path))?;
    let current_high_water = database.get_latest_pending_id().await.context("failed to read authoritative pending counter")?;
    ensure!(
        current_high_water == frozen_high_water,
        "pending counter differs from frozen RP high-water: current {}, RP {}",
        current_high_water,
        frozen_high_water
    );
    Ok(ExecutionStore {
        database,
        temp,
        nats,
        checkpoint_manager: Mutex::new(checkpoint_manager),
        frozen_counter_high_water: frozen_high_water,
        config: config.clone(),
    })
}

pub(super) async fn execute(
    args: &ExecuteArgs,
    config: &ProcessorConfig,
    plan: &mut RollbackPlan,
) -> anyhow::Result<()> {
    let store = open_rollback_execution_store(config, plan.latest_pending_id).await?;
    execute_rollback_plan(&store, &AtomicRollbackPlanProgress::new(&args.common.rp_path), plan).await?;
    Ok(())
}

async fn remove_backup_paths(config: &ProcessorConfig, plan: &RollbackPlan) -> anyhow::Result<()> {
    match config {
        ProcessorConfig::Coordinator(c) => {
            for entry in &plan.ids {
                let pending_id = entry.pending_id;
                let realm_id = c.coordinator_id;
                let realm_sub_id = u64::from(c.coordinator_sub_id);
                for path in [
                    get_new_register_user_gatherer_backup_file_path(
                        &c.get_register_users_backup_path(),
                        realm_id,
                        realm_sub_id,
                        pending_id,
                    ),
                    get_new_deploy_contract_gatherer_backup_file_path(
                        &c.get_deploy_contracts_backup_path(),
                        realm_id,
                        realm_sub_id,
                        pending_id,
                    ),
                    get_new_update_contract_gatherer_backup_file_path(
                        &c.get_update_contracts_backup_path(),
                        realm_id,
                        realm_sub_id,
                        pending_id,
                    ),
                    get_new_coordinator_guta_update_gatherer_backup_file_path(
                        &c.get_guta_updates_backup_path(),
                        realm_id,
                        realm_sub_id,
                        pending_id,
                    )
                    .to_string_lossy()
                    .to_string(),
                ] {
                    delete_backup_file_if_exists(&path, pending_id).await?;
                }
            }
        }
        ProcessorConfig::Realm(c) => {
            for entry in &plan.ids {
                let path = get_new_realm_end_cap_gatherer_backup_file_path(
                    &c.get_guta_updates_backup_path(),
                    c.realm_id,
                    u64::from(c.realm_sub_id),
                    entry.pending_id,
                )
                .to_string_lossy()
                .to_string();
                delete_backup_file_if_exists(&path, entry.pending_id).await?;
            }
        }
    }
    Ok(())
}

async fn delete_backup_file_if_exists(path: &str, pending_id: u64) -> anyhow::Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("failed to delete post-target gatherer backup for pending {pending_id} at {path}")),
    }
}

#[async_trait]
impl RollbackExecutionStore for ExecutionStore {
    async fn latest_checkpoint_marker(&self) -> anyhow::Result<u64> {
        self.database.get_latest_checkpoint_id().await
    }

    async fn pending_counter_high_water(&self) -> anyhow::Result<u64> {
        let current = self.database.get_latest_pending_id().await?;
        ensure!(
            current == self.frozen_counter_high_water,
            "pending counter changed during rollback: frozen {}, current {}",
            self.frozen_counter_high_water,
            current
        );
        Ok(current)
    }

    // Only deterministic durable consumers are in the RP; reply KV keys are skipped (proc_id is not authoritative).
    async fn delete_nats_consumers(
        &self,
        plan: &RollbackPlan,
        targets: &[RollbackNatsConsumerTarget],
    ) -> anyhow::Result<()> {
        for target in targets {
            mutate_nats_consumer(&self.nats, plan, *target, true).await?;
        }
        Ok(())
    }

    async fn verify_nats_consumers_absent(
        &self,
        plan: &RollbackPlan,
        targets: &[RollbackNatsConsumerTarget],
    ) -> anyhow::Result<()> {
        for target in targets {
            mutate_nats_consumer(&self.nats, plan, *target, false).await?;
        }
        Ok(())
    }

    async fn execute_phase(
        &self,
        plan: &RollbackPlan,
        phase: &ExecutableRollbackPhase,
    ) -> anyhow::Result<()> {
        let backend = self.database.store.as_ref();
        match &phase.operation {
            RollbackOperation::TempHashFields(fields) => {
                for field in fields {
                    self.temp.qtdb_raw_kv_delete_key(field).await?;
                }
            }
            RollbackOperation::ProofPendingIds(pending_ids) => {
                for &pending_id in pending_ids {
                    self.temp.delete_all_proofs_for_pending_id(pending_id).await?;
                }
            }
            RollbackOperation::NatsConsumers(_) => {
                bail!("NATS consumer phase must use delete_nats_consumers adapter")
            }
            RollbackOperation::ObjectIds(keys) => match phase.table.as_str() {
                "checkpoint_leaf_table" => backend.db_delete_many_object_ids(self.database.checkpoint_leaf_table.as_ref(), keys).await?,
                "l2_block_state_table" => backend.db_delete_many_object_ids(self.database.l2_block_state_table.as_ref(), keys).await?,
                "checkpoint_id_to_realm_root_table" => backend.db_delete_many_object_ids(self.database.checkpoint_id_to_realm_root_table.as_ref(), keys).await?,
                "checkpoint_state_roots_table" => backend.db_delete_many_object_ids(self.database.checkpoint_state_roots_table.as_ref(), keys).await?,
                "checkpoint_zk_proof_and_transition_table" => backend.db_delete_many_object_ids(self.database.checkpoint_zk_proof_and_transition_table.as_ref(), keys).await?,
                "checkpoint_id_to_pending_id_table" => backend.db_delete_many_object_ids(self.database.checkpoint_id_to_pending_id_table.as_ref(), keys).await?,
                "pending_id_to_checkpoint_id_table" => backend.db_delete_many_object_ids(self.database.pending_id_to_checkpoint_id_table.as_ref(), keys).await?,
                table => bail!("unknown object-id rollback table {table}"),
            },
            RollbackOperation::ObjectCheckpoints(keys) => match phase.table.as_str() {
                "user_leaf_table" => backend.db_delete_many_object_checkpoint(self.database.user_leaf_table.as_ref(), keys).await?,
                "user_public_key_table" => backend.db_delete_many_object_checkpoint(self.database.user_public_key_table.as_ref(), keys).await?,
                "contract_state_tree_height_table" => backend.db_delete_many_object_checkpoint(self.database.contract_state_tree_height_table.as_ref(), keys).await?,
                "contract_leaf_table" => backend.db_delete_many_object_checkpoint(self.database.contract_leaf_table.as_ref(), keys).await?,
                "contract_code_definition_table" => backend.db_delete_many_object_checkpoint(self.database.contract_code_definition_table.as_ref(), keys).await?,
                "checkpointed_object_table" => backend.db_delete_many_object_checkpoint(self.database.checkpointed_object_table.as_ref(), keys).await?,
                "realm_rewards_tree_node_key_table" => backend.db_delete_many_object_checkpoint(self.database.realm_rewards_tree_node_key.as_ref(), keys).await?,
                table => bail!("unknown object-checkpoint rollback table {table}"),
            },
            RollbackOperation::MerkleNodes(keys) => match phase.table.as_str() {
                "global_user_tree_table" => backend.db_delete_many_merkle_nodes(self.database.global_user_tree_table.as_ref(), keys).await?,
                "global_checkpoint_tree_table" => backend.db_delete_many_merkle_nodes(self.database.global_checkpoint_tree_table.as_ref(), keys).await?,
                "user_registration_tree_table" => backend.db_delete_many_merkle_nodes(self.database.user_registration_tree_table.as_ref(), keys).await?,
                "global_contract_tree_table" => backend.db_delete_many_merkle_nodes(self.database.global_contract_tree_table.as_ref(), keys).await?,
                table => bail!("unknown merkle rollback table {table}"),
            },
            RollbackOperation::TreeMerkleNodes(keys) => match phase.table.as_str() {
                "user_contract_tree_table" => backend.db_delete_many_tree_merkle_nodes(self.database.user_contract_tree_table.as_ref(), keys).await?,
                "contract_function_tree_table" => backend.db_delete_many_tree_merkle_nodes(self.database.contract_function_tree_table.as_ref(), keys).await?,
                table => bail!("unknown tree-merkle rollback table {table}"),
            },
            RollbackOperation::TreeSubtreeMerkleNodes(keys) => {
                ensure!(phase.table == "contract_state_tree_table", "unknown tree-subtree rollback table {}", phase.table);
                backend.db_delete_many_tree_subtree_merkle_nodes(self.database.contract_state_tree_table.as_ref(), keys).await?;
            }
            RollbackOperation::ImtLeaves(keys) => {
                ensure!(phase.table == "imt_leaf_table", "unknown IMT leaf rollback table {}", phase.table);
                backend.db_delete_many_imt_leaves(self.database.imt_leaf_table.as_ref(), keys).await?;
            }
            RollbackOperation::ImtKeys(keys) => {
                ensure!(phase.table == "imt_key_index_table", "unknown IMT key rollback table {}", phase.table);
                backend.db_delete_many_imt_keys(self.database.imt_key_index_table.as_ref(), keys).await?;
            }
            RollbackOperation::HashUserPairs(keys) => {
                let keys = decode_hash_user_pairs(keys)?;
                backend.db_delete_many_hash_user_pairs(self.database.public_key_hash_to_user_ids_table.as_ref(), &keys).await?;
            }
            RollbackOperation::BlobPairs(keys) => match phase.table.as_str() {
                "checkpoint_root_to_checkpoint_id_table" => backend.db_delete_many_blob_pairs(self.database.checkpoint_root_to_checkpoint_id_table.as_ref(), keys).await?,
                "checkpoint_leaf_to_checkpoint_id_table" => backend.db_delete_many_blob_pairs(self.database.checkpoint_leaf_to_checkpoint_id_table.as_ref(), keys).await?,
                table => bail!("unknown blob-pair rollback table {table}"),
            },
            RollbackOperation::U64U128Pairs(keys) => {
                ensure!(phase.table == "pending_id_to_pending_proc_id_table", "unknown u64/u128 rollback table {}", phase.table);
                backend.db_delete_many_u64_u128_pairs(self.database.pending_id_to_pending_proc_id_table.as_ref(), keys).await?;
            }
            RollbackOperation::PendingPartitions(keys) => {
                ensure!(phase.table == "guta_reward_tag_tree_table", "unknown pending-partition rollback table {}", phase.table);
                backend.db_delete_many_pending_id_partitions(self.database.guta_reward_tag_tree_table.as_ref(), keys).await?;
            }
            RollbackOperation::RestoreLatestInfo => {
                let bytes = decode_hex(&plan.snapshot.target_info, "snapshot.target_info")?;
                let latest_info = QEDL2BlockState::psy_ser_from_slice(&bytes)
                    .context("failed to decode frozen canonical latest_info bytes")?;
                ensure!(
                    latest_info.checkpoint_id == plan.target_checkpoint_id,
                    "frozen latest_info checkpoint {} does not equal rollback target {}",
                    latest_info.checkpoint_id,
                    plan.target_checkpoint_id
                );
                backend
                    .db_insert_one_kiv(
                        self.database.latest_info_table.as_ref(),
                        LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE,
                        &latest_info,
                    )
                    .await?;
                let checkpoint_root = self
                    .database
                    .checkpoint_tree_get_root_hash(plan.target_checkpoint_id)
                    .await?;
                backend
                    .db_insert_one_kiv(
                        self.database.latest_info_table.as_ref(),
                        LATEST_INFO_TABLE_OBJ_ID_LATEST_CHECKPOINT_TREE_ROOT,
                        &checkpoint_root,
                    )
                    .await?;
            }
            RollbackOperation::RestoreImtNextAppendIndexes(entries) => {
                let mut deletes = Vec::new();
                for entry in entries {
                    let tree_id = i64::try_from(entry.tree_id).context("IMT tree_id exceeds i64 backend range")?;
                    let tree_sub_id = i64::try_from(entry.tree_sub_id).context("IMT tree_sub_id exceeds i64 backend range")?;
                    match entry.next_append_index {
                        Some(next) => backend
                            .db_insert_imt_next_append_index(
                                self.database.imt_next_append_index_table.as_ref(),
                                tree_id,
                                tree_sub_id,
                                next,
                            )
                            .await?,
                        None => deletes.push((tree_id, tree_sub_id)),
                    }
                }
                backend
                    .db_delete_many_imt_next_append_indexes(
                        self.database.imt_next_append_index_table.as_ref(),
                        &deletes,
                    )
                    .await?;
            }
            RollbackOperation::RebuildCheckpointRingBuffer => {
                self.checkpoint_manager
                    .lock()
                    .await
                    .rebuild_from_database_at_checkpoint(&self.database, plan.target_checkpoint_id)
                    .await?;
            }
            RollbackOperation::Verify | RollbackOperation::SetMarker => {
                bail!("core executor attempted to dispatch reserved operation {}", phase.api)
            }
        }
        Ok(())
    }

    async fn verify_phase(
        &self,
        plan: &RollbackPlan,
        phase: &ExecutableRollbackPhase,
    ) -> anyhow::Result<()> {
        let backend = self.database.store.as_ref();
        match &phase.operation {
            RollbackOperation::TempHashFields(fields) => {
                verify_temp_fields_absent(&self.temp, fields).await?;
                if phase.table == "TKVSV1-singletons" {
                    verify_worker_reputation_snapshot(&self.temp, plan).await?;
                }
            }
            RollbackOperation::ProofPendingIds(pending_ids) => {
                for &pending_id in pending_ids {
                    ensure!(
                        !self.temp.contains_proofs_for_pending_id(pending_id).await?,
                        "proof bucket remains for pending id {pending_id}"
                    );
                }
            }
            RollbackOperation::NatsConsumers(_) => {
                bail!("NATS consumer phase must use verify_nats_consumers_absent adapter")
            }
            RollbackOperation::ObjectIds(keys) => {
                let residual = match phase.table.as_str() {
                    "checkpoint_leaf_table" => backend.db_get_existing_object_ids(self.database.checkpoint_leaf_table.as_ref(), keys).await?,
                    "l2_block_state_table" => backend.db_get_existing_object_ids(self.database.l2_block_state_table.as_ref(), keys).await?,
                    "checkpoint_id_to_realm_root_table" => backend.db_get_existing_object_ids(self.database.checkpoint_id_to_realm_root_table.as_ref(), keys).await?,
                    "checkpoint_state_roots_table" => backend.db_get_existing_object_ids(self.database.checkpoint_state_roots_table.as_ref(), keys).await?,
                    "checkpoint_zk_proof_and_transition_table" => backend.db_get_existing_object_ids(self.database.checkpoint_zk_proof_and_transition_table.as_ref(), keys).await?,
                    "checkpoint_id_to_pending_id_table" => backend.db_get_existing_object_ids(self.database.checkpoint_id_to_pending_id_table.as_ref(), keys).await?,
                    "pending_id_to_checkpoint_id_table" => backend.db_get_existing_object_ids(self.database.pending_id_to_checkpoint_id_table.as_ref(), keys).await?,
                    table => bail!("unknown object-id rollback table {table}"),
                };
                ensure!(residual.is_empty(), "{} retains object ids {:?}", phase.table, residual);
            }
            RollbackOperation::ObjectCheckpoints(keys) => {
                let residual = match phase.table.as_str() {
                    "user_leaf_table" => backend.db_get_existing_object_checkpoints(self.database.user_leaf_table.as_ref(), keys).await?,
                    "user_public_key_table" => backend.db_get_existing_object_checkpoints(self.database.user_public_key_table.as_ref(), keys).await?,
                    "contract_state_tree_height_table" => backend.db_get_existing_object_checkpoints(self.database.contract_state_tree_height_table.as_ref(), keys).await?,
                    "contract_leaf_table" => backend.db_get_existing_object_checkpoints(self.database.contract_leaf_table.as_ref(), keys).await?,
                    "contract_code_definition_table" => backend.db_get_existing_object_checkpoints(self.database.contract_code_definition_table.as_ref(), keys).await?,
                    "checkpointed_object_table" => backend.db_get_existing_object_checkpoints(self.database.checkpointed_object_table.as_ref(), keys).await?,
                    "realm_rewards_tree_node_key_table" => backend.db_get_existing_object_checkpoints(self.database.realm_rewards_tree_node_key.as_ref(), keys).await?,
                    table => bail!("unknown object-checkpoint rollback table {table}"),
                };
                ensure!(residual.is_empty(), "{} retains object/checkpoint keys {:?}", phase.table, residual);
            }
            RollbackOperation::MerkleNodes(keys) => {
                let residual = match phase.table.as_str() {
                    "global_user_tree_table" => backend.db_get_existing_merkle_nodes(self.database.global_user_tree_table.as_ref(), keys).await?,
                    "global_checkpoint_tree_table" => backend.db_get_existing_merkle_nodes(self.database.global_checkpoint_tree_table.as_ref(), keys).await?,
                    "user_registration_tree_table" => backend.db_get_existing_merkle_nodes(self.database.user_registration_tree_table.as_ref(), keys).await?,
                    "global_contract_tree_table" => backend.db_get_existing_merkle_nodes(self.database.global_contract_tree_table.as_ref(), keys).await?,
                    table => bail!("unknown merkle rollback table {table}"),
                };
                ensure!(residual.is_empty(), "{} retains merkle keys {:?}", phase.table, residual);
            }
            RollbackOperation::TreeMerkleNodes(keys) => {
                let residual = match phase.table.as_str() {
                    "user_contract_tree_table" => backend.db_get_existing_tree_merkle_nodes(self.database.user_contract_tree_table.as_ref(), keys).await?,
                    "contract_function_tree_table" => backend.db_get_existing_tree_merkle_nodes(self.database.contract_function_tree_table.as_ref(), keys).await?,
                    table => bail!("unknown tree-merkle rollback table {table}"),
                };
                ensure!(residual.is_empty(), "{} retains tree-merkle keys {:?}", phase.table, residual);
            }
            RollbackOperation::TreeSubtreeMerkleNodes(keys) => {
                let residual = backend.db_get_existing_tree_subtree_merkle_nodes(self.database.contract_state_tree_table.as_ref(), keys).await?;
                ensure!(residual.is_empty(), "contract_state_tree_table retains keys {:?}", residual);
            }
            RollbackOperation::ImtLeaves(keys) => {
                let residual = backend.db_get_existing_imt_leaves(self.database.imt_leaf_table.as_ref(), keys).await?;
                ensure!(residual.is_empty(), "imt_leaf_table retains keys {:?}", residual);
            }
            RollbackOperation::ImtKeys(keys) => {
                let residual = backend.db_get_existing_imt_keys(self.database.imt_key_index_table.as_ref(), keys).await?;
                ensure!(residual.is_empty(), "imt_key_index_table retains keys {:?}", residual);
            }
            RollbackOperation::HashUserPairs(keys) => {
                let keys = decode_hash_user_pairs(keys)?;
                let residual = backend.db_get_existing_hash_user_pairs(self.database.public_key_hash_to_user_ids_table.as_ref(), &keys).await?;
                ensure!(residual.is_empty(), "public_key_hash_to_user_ids_table retains pairs {:?}", residual);
            }
            RollbackOperation::BlobPairs(keys) => {
                let residual = match phase.table.as_str() {
                    "checkpoint_root_to_checkpoint_id_table" => backend.db_get_blob_pair_presence(self.database.checkpoint_root_to_checkpoint_id_table.as_ref(), keys).await?,
                    "checkpoint_leaf_to_checkpoint_id_table" => backend.db_get_blob_pair_presence(self.database.checkpoint_leaf_to_checkpoint_id_table.as_ref(), keys).await?,
                    table => bail!("unknown blob-pair rollback table {table}"),
                };
                ensure!(residual.is_empty(), "{} retains bidirectional pairs {:?}", phase.table, residual);
            }
            RollbackOperation::U64U128Pairs(keys) => {
                let residual = backend.db_get_u64_u128_pair_presence(self.database.pending_id_to_pending_proc_id_table.as_ref(), keys).await?;
                ensure!(residual.is_empty(), "pending/proc mapping retains bidirectional pairs {:?}", residual);
            }
            RollbackOperation::PendingPartitions(keys) => {
                let residual = backend.db_get_existing_pending_id_partitions(self.database.guta_reward_tag_tree_table.as_ref(), keys).await?;
                ensure!(residual.is_empty(), "guta reward tag tree retains pending partitions {:?}", residual);
            }
            RollbackOperation::RestoreLatestInfo => {
                let expected = decode_hex(&plan.snapshot.target_info, "snapshot.target_info")?;
                let actual: QEDL2BlockState = backend
                    .db_select_one_kiv_value(
                        self.database.latest_info_table.as_ref(),
                        LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE,
                    )
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("latest_info_table target singleton is absent"))?;
                ensure!(actual.psy_ser_to_bytes_vec()? == expected, "latest_info_table differs from frozen canonical bytes");
                let expected_root = self
                    .database
                    .checkpoint_tree_get_root_hash(plan.target_checkpoint_id)
                    .await?;
                let actual_root: <Network as QNetworkHashTypes>::QHash = backend
                    .db_select_one_kiv_value(
                        self.database.latest_info_table.as_ref(),
                        LATEST_INFO_TABLE_OBJ_ID_LATEST_CHECKPOINT_TREE_ROOT,
                    )
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("latest_info_table checkpoint-tree-root singleton is absent"))?;
                ensure!(actual_root == expected_root, "latest_info_table checkpoint-tree root differs from target");
            }
            RollbackOperation::RestoreImtNextAppendIndexes(entries) => {
                for entry in entries {
                    let tree_id = i64::try_from(entry.tree_id).context("IMT tree_id exceeds i64 backend range")?;
                    let tree_sub_id = i64::try_from(entry.tree_sub_id).context("IMT tree_sub_id exceeds i64 backend range")?;
                    let actual = backend
                        .db_select_imt_next_append_index(
                            self.database.imt_next_append_index_table.as_ref(),
                            tree_id,
                            tree_sub_id,
                        )
                        .await?;
                    ensure!(
                        actual == entry.next_append_index,
                        "IMT next append index ({}, {}) expected {:?}, got {:?}",
                        entry.tree_id,
                        entry.tree_sub_id,
                        entry.next_append_index,
                        actual
                    );
                }
            }
            RollbackOperation::RebuildCheckpointRingBuffer => verify_checkpoint_ring_buffer(self, plan.target_checkpoint_id).await?,
            RollbackOperation::Verify | RollbackOperation::SetMarker => {
                bail!("core executor attempted to verify reserved operation {}", phase.api)
            }
        }
        Ok(())
    }

    async fn delete_post_target_backups(&self, plan: &RollbackPlan) -> anyhow::Result<()> {
        remove_backup_paths(&self.config, plan).await
    }

    async fn write_latest_checkpoint_marker(&self, target_checkpoint_id: u64) -> anyhow::Result<()> {
        self.database.set_latest_checkpoint_id(target_checkpoint_id).await
    }
}

fn decode_hash_user_pairs(
    keys: &[(Vec<u8>, u64)],
) -> anyhow::Result<Vec<(<Network as QNetworkHashTypes>::QHash, u64)>> {
    keys.iter()
        .map(|(hash, user_id)| {
            Ok((
                <Network as QNetworkHashTypes>::QHash::from_slice_32bytes(hash)?,
                *user_id,
            ))
        })
        .collect()
}

async fn mutate_nats_consumer(
    nats: &NatsJetStreamClient,
    plan: &RollbackPlan,
    target: RollbackNatsConsumerTarget,
    should_delete: bool,
) -> anyhow::Result<()> {
    let realm_id = plan.realm_id;
    let realm_sub_id = plan.realm_sub_id;
    let proc_id = target.proc_id;
    let task_group = target.task_group;
    macro_rules! apply {
        ($key:expr, $delete:ident) => {{
            let key = $key;
            if should_delete {
                nats.$delete(&key, realm_id, realm_sub_id, proc_id, task_group).await
            } else {
                ensure!(
                    !nats.consumer_exists_for_queue(&key, realm_id, realm_sub_id, proc_id, task_group).await?,
                    "NATS consumer remains: kind={:?}, proc_id={}, task_group={}",
                    target.kind,
                    proc_id,
                    task_group
                );
                Ok(())
            }
        }};
    }
    match target.kind {
        RollbackNatsConsumerKind::CoordinatorRegisterUser => apply!(
            CoordinatorRegisterUserPublicKeyQueueKey::<<Network as QNetworkHashTypes>::QHash> {
                realm_id, realm_sub_id, unique_id: proc_id, task_group: u64::from(task_group),
                queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: PhantomData,
            },
            delete_ephemeral_queue_consumer
        ),
        RollbackNatsConsumerKind::CoordinatorDeployContract => apply!(
            CoordinatorDeployContractQueueKey::<<Network as QNetworkHashTypes>::F, <Network as QNetworkHashTypes>::QHash> {
                realm_id, realm_sub_id, unique_id: proc_id, task_group: u64::from(task_group),
                queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: PhantomData,
            },
            delete_ephemeral_queue_consumer
        ),
        RollbackNatsConsumerKind::CoordinatorUpdateContract => apply!(
            CoordinatorUpdateContractQueueKey::<<Network as QNetworkHashTypes>::F, <Network as QNetworkHashTypes>::QHash> {
                realm_id, realm_sub_id, unique_id: proc_id, task_group: u64::from(task_group),
                queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: PhantomData,
            },
            delete_ephemeral_queue_consumer
        ),
        RollbackNatsConsumerKind::CoordinatorGuta => apply!(
            CoordinatorSubmitRealmGUTAUpdateQueueKey::<<Network as QNetworkHashTypes>::F, <Network as QNetworkHashTypes>::QHash> {
                realm_id, realm_sub_id, unique_id: proc_id, task_group: u64::from(task_group),
                queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: PhantomData,
            },
            delete_ephemeral_queue_consumer
        ),
        RollbackNatsConsumerKind::CoordinatorProving => apply!(
            CoordinatorProvingWorkQueueKey::<<Network as QNetworkHashTypes>::QHash, QProvingJobDataID> {
                realm_id, realm_sub_id, unique_id: proc_id, task_group: u64::from(task_group),
                queue_type: QPBaseQueueType::WorkerQueue, _phantom_queue_item: PhantomData,
            },
            delete_worker_queue_consumer
        ),
        RollbackNatsConsumerKind::RealmUserUpdate => apply!(
            RealmUserUpdateQueueKey::<<Network as QNetworkHashTypes>::F, <Network as QNetworkHashTypes>::QHash> {
                realm_id, realm_sub_id, unique_id: proc_id, task_group: u64::from(task_group),
                queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: PhantomData,
            },
            delete_ephemeral_queue_consumer
        ),
        RollbackNatsConsumerKind::RealmProving => apply!(
            RealmProvingWorkQueueKey::<<Network as QNetworkHashTypes>::QHash, QProvingJobDataID> {
                realm_id, realm_sub_id, unique_id: proc_id, task_group: u64::from(task_group),
                queue_type: QPBaseQueueType::WorkerQueue, _phantom_queue_item: PhantomData,
            },
            delete_worker_queue_consumer
        ),
    }
}

async fn verify_temp_fields_absent(
    temp: &StandardFredRedisStore,
    fields: &[Vec<u8>],
) -> anyhow::Result<()> {
    for field in fields {
        ensure!(
            !temp.qtdb_raw_kv_contains_key(field).await?,
            "Temp Redis field remains: 0x{}",
            hex::encode(field)
        );
    }
    Ok(())
}

async fn verify_worker_reputation_snapshot(
    temp: &StandardFredRedisStore,
    plan: &RollbackPlan,
) -> anyhow::Result<()> {
    let realm_bytes = u32::try_from(plan.realm_id).context("rollback realm_id does not fit u32")?.to_le_bytes();
    let sub_bytes = u16::try_from(plan.realm_sub_id).context("rollback realm_sub_id does not fit u16")?.to_le_bytes();
    let mut live_fields = std::collections::BTreeSet::new();
    let mut cursor = 0u64;
    loop {
        let page = temp.qtdb_raw_kv_scan_fields(cursor, 1024).await?;
        for field in page.fields {
            if field.len() == psy_node_core::psy_temp_db::TEMP_TABLE_WORKER_REPUTATION_KEY_SIZE
                && field[0..4] == realm_bytes
                && field[4..6] == sub_bytes
                && field[6..8] == psy_node_core::psy_temp_db::TEMP_TABLE_ID_WORKER_REPUTATION_BYTES
            {
                ensure!(live_fields.insert(field), "duplicate worker reputation field returned by Temp enumeration");
            }
        }
        cursor = page.next_cursor;
        if cursor == 0 {
            break;
        }
    }

    let mut expected = std::collections::BTreeMap::new();
    for (index, snapshot) in plan.snapshot.worker_reputation_fields.iter().enumerate() {
        let field = decode_hex(&snapshot.field, &format!("snapshot.worker_reputation_fields[{index}].field"))?;
        let value = snapshot.value.as_deref().map(|value| decode_hex(value, &format!("snapshot.worker_reputation_fields[{index}].value"))).transpose()?;
        ensure!(expected.insert(field, value).is_none(), "duplicate worker reputation field in rollback snapshot");
    }

    let expected_fields: std::collections::BTreeSet<Vec<u8>> = expected.keys().cloned().collect();
    ensure!(live_fields == expected_fields, "retained worker reputation field set differs from the complete rollback snapshot");
    for field in live_fields {
        let actual = temp.qtdb_raw_kv_get_value(&field).await?;
        let expected_value = expected.get(&field).expect("field sets matched");
        ensure!(
            &actual == expected_value,
            "retained worker reputation field 0x{} expected {:?}, got {:?}",
            hex::encode(&field),
            expected_value.as_ref().map(hex::encode),
            actual.as_ref().map(hex::encode)
        );
    }
    Ok(())
}

async fn verify_checkpoint_ring_buffer(
    store: &ExecutionStore,
    target_checkpoint_id: u64,
) -> anyhow::Result<()> {
    let expected_root = store
        .database
        .checkpoint_tree_get_root_hash(target_checkpoint_id)
        .await?;
    let manager = store.checkpoint_manager.lock().await;
    ensure!(
        manager.get_current_checkpoint_id_head() == target_checkpoint_id,
        "checkpoint ring buffer head expected {}, got {}",
        target_checkpoint_id,
        manager.get_current_checkpoint_id_head()
    );
    ensure!(
        manager.get_current_checkpoint_tree_root_head() == expected_root,
        "checkpoint ring buffer root differs from target database root"
    );
    Ok(())
}

fn decode_hex(value: &str, label: &str) -> anyhow::Result<Vec<u8>> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(value).with_context(|| format!("{label} is not valid hex"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_node_core::config::node_start_config::CoordinatorProcessorStartConfig;
    use psy_node_common::rollback::{
        RollbackIds, RollbackRole, RollbackSnapshot,
    };

    #[tokio::test]
    async fn remove_backup_paths_deletes_existing_and_ignores_missing() {
        let dir = std::env::temp_dir().join(format!(
            "psy-rollback-backup-cleanup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let config = ProcessorConfig::Coordinator(CoordinatorProcessorStartConfig {
            scylla_db_url: String::new(),
            nats_jetstream_url: String::new(),
            redis_url: String::new(),
            db_namespace: String::new(),
            coordinator_id: 1,
            coordinator_sub_id: 2,
            network: PsyChainNetworkType::LocalDevnet,
            verbose: false,
            checkpoint_backup_path: dir.to_string_lossy().to_string(),
            genesis_data_path: None,
        });
        let plan = RollbackPlan {
            role: RollbackRole::Coordinator,
            realm_id: 1,
            realm_sub_id: 2,
            target_checkpoint_id: 0,
            latest_checkpoint_id: 0,
            latest_pending_id: 1,
            ids: vec![RollbackIds {
                checkpoint_id: None,
                pending_id: 1,
                proc_id: 1001,
            }],
            target_contract_state: None,
            snapshot: RollbackSnapshot {
                target_info: String::new(),
                worker_reputation_fields: Vec::new(),
            },
            phases: Vec::new(),
        };
        let ProcessorConfig::Coordinator(c) = &config else { unreachable!() };
        let existing = [
            get_new_register_user_gatherer_backup_file_path(
                &c.get_register_users_backup_path(),
                c.coordinator_id,
                u64::from(c.coordinator_sub_id),
                1,
            ),
            get_new_deploy_contract_gatherer_backup_file_path(
                &c.get_deploy_contracts_backup_path(),
                c.coordinator_id,
                u64::from(c.coordinator_sub_id),
                1,
            ),
            get_new_update_contract_gatherer_backup_file_path(
                &c.get_update_contracts_backup_path(),
                c.coordinator_id,
                u64::from(c.coordinator_sub_id),
                1,
            ),
            get_new_coordinator_guta_update_gatherer_backup_file_path(
                &c.get_guta_updates_backup_path(),
                c.coordinator_id,
                u64::from(c.coordinator_sub_id),
                1,
            )
            .to_string_lossy()
            .to_string(),
        ];
        let missing = get_new_register_user_gatherer_backup_file_path(
            &c.get_register_users_backup_path(),
            c.coordinator_id,
            u64::from(c.coordinator_sub_id),
            2,
        );
        let unrelated = dir.join("unrelated.backup");
        for path in &existing {
            if let Some(parent) = std::path::Path::new(path).parent() {
                tokio::fs::create_dir_all(parent).await.unwrap();
            }
            tokio::fs::write(path, b"data").await.unwrap();
        }
        tokio::fs::write(&unrelated, b"keep").await.unwrap();

        remove_backup_paths(&config, &plan).await.unwrap();

        for path in &existing {
            assert!(!std::path::Path::new(path).exists(), "existing backup {path} must be deleted");
        }
        assert!(!std::path::Path::new(&missing).exists(), "missing backup must be tolerated");
        assert!(unrelated.exists(), "unrelated file must be untouched");
        tokio::fs::remove_dir_all(&dir).await.unwrap();
    }
}
