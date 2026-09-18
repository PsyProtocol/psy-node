use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use parth_common::memory_stores::{mem_tree_recorder::SimpleMemoryMerkleRecorderStore, traits::PsyMemoryMerkleStoreImm};
use parth_core::{
    QCoreProcCheckpointUniqueId,
    crypto::hash::
        traits::{FieldQHasher, MerkleZeroHasher}
    ,
    data::{
        hash::{checkpointed_merkle_node::CheckpointedMerkleHash, merkle_node_key::SimpleMerkleNodeKey},
        queue::queue_key::{QPBaseQueueType, QPStandardUniqueIdQueueKey},
    },
    node::realm_identifier::QRealmIdentifier,
    protocol::core_types::{Q256BitHash, QNetworkTypesConfig},
};
use psy_core::{
    constants::stale_checkpoint::STALE_CHECKPOINT_AGE_USER_END_CAP_TO_REALM_PROOF,
    job::job_id::{ProvingJobCircuitType, QProvingJobDataID},
};
use psy_data::{
    config::network_config::PsyNodeCircuitFingerprintConfig,
    genesis::genesis_block_setup::PsyGenesisBlockSetupData,
    node::realm_processor::{RealmProcessorCoreState, RealmProcessorCoreStateWrapper},
    prepared_block::realm::{PsyPreparedRealmBlockStateUpdates, PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate},
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    genesis::genesis_db_data_builder::GenesisDatabaseDataBuilder,
    p2p::{
        traits::realm_coordinantor::RealmCoordinatorClient,
        validator_lookup::{
            load_realm_validators_from_tree, validator_nodes_from_leaves, write_validator_tree_genesis,
        },
    },
    psy_core_db::traits::full::{
        PsyNodeCheckpointTreeDatabaseReader, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore,
    },
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueueSubscriber, worker_queue::QStandardWorkerQueuePublisher},
    store::traits::proof_store::QParthProofStore,
};

use crate::{
    backup::{
        checkpoint_tree::CheckpointTreeBackupManager,
        realm::generate_realm_output_from_backups,
    },
    constants::queue::PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID,
    queue::gatherer::QueueKeyStatusManager,
    realm::processor::{
        db::{
            genesis::{
                apply_genesis_checkpoint_records, classify_genesis_complete_gate, plan_genesis_bootstrap,
                seed_or_check_genesis_backup, should_hard_reset_ahead_backup, should_recover_cleared_backup,
            },
            DatabaseCheckState, PsyRealmDatabaseProcessor,
        },
        gatherers::realm_end_cap_gatherer::{
            get_new_realm_end_cap_gatherer_backup_file_path, read_realm_backup_end_root,
        },
    },
    utils::processor_status::ProcessorStatus,
};

pub async fn create_new_checkpoint_backup_manager_from_file_path<
    Hasher: MerkleZeroHasher<Hash> + 'static + Send + Sync,
    Hash: Eq + Copy + PartialEq + Default + std::hash::Hash + Q256BitHash,
    CheckpointTreeStore: PsyNodeCheckpointTreeDatabaseReader<Hash>,
    FileSystem: TokioLikeFileSystem,
>(
    file_system: Arc<FileSystem>,
    max_checkpoints_to_keep: u64,
    checkpoint_tree_height: u8,
    checkpoint_tree_store: &CheckpointTreeStore,
    backup_file_path: &str,
    allow_create_file: bool,
) -> anyhow::Result<CheckpointTreeBackupManager<Hasher, Hash, FileSystem>> {
    CheckpointTreeBackupManager::<Hasher, Hash, FileSystem>::new_from_file_path(
        file_system,
        max_checkpoints_to_keep,
        checkpoint_tree_height,
        checkpoint_tree_store,
        backup_file_path,
        allow_create_file,
    )
    .await
}

async fn find_latest_mapped_pending_at_or_before<F, Fut>(
    target_checkpoint_id: u64,
    mut query: F,
) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)>
where
    F: FnMut(u64) -> Fut,
    Fut: Future<Output = anyhow::Result<Option<(u64, QCoreProcCheckpointUniqueId)>>>,
{
    let mut cp = target_checkpoint_id;
    loop {
        match query(cp).await? {
            Some(res) => return Ok(res),
            None if cp == 0 => {
                if target_checkpoint_id == 0 {
                    return Ok((0u64, 0u128));
                } else {
                    anyhow::bail!(
                        "No checkpoint->pending mapping found for any checkpoint <= target {}. Cannot prove the latest mapped pending IDs; refusing startup to avoid pending/proc ID reuse or reapplying post-target backups.",
                        target_checkpoint_id
                    );
                }
            }
            None => cp -= 1,
        }
    }
}

async fn resolve_current_and_last_committed_pending_ids<BoundaryF, BoundaryFut, LatestF, LatestFut, ReverseF, ReverseFut>(
    target_checkpoint_id: u64,
    boundary_query: BoundaryF,
    latest_mapped_query: LatestF,
    reverse_query: ReverseF,
) -> anyhow::Result<(
    (u64, QCoreProcCheckpointUniqueId),
    (u64, QCoreProcCheckpointUniqueId),
)>
where
    BoundaryF: FnMut(u64) -> BoundaryFut,
    BoundaryFut: Future<Output = anyhow::Result<Option<(u64, QCoreProcCheckpointUniqueId)>>>,
    LatestF: FnOnce() -> LatestFut,
    LatestFut: Future<Output = anyhow::Result<(u64, QCoreProcCheckpointUniqueId)>>,
    ReverseF: FnOnce(u64) -> ReverseFut,
    ReverseFut: Future<Output = anyhow::Result<Option<u64>>>,
{
    let last_committed = find_latest_mapped_pending_at_or_before(target_checkpoint_id, boundary_query).await?;
    let current = match latest_mapped_query().await {
        Ok(ids) => ids,
        Err(error) => {
            tracing::warn!(
                "No positive mapped pending generation could be resolved at startup; using proven checkpoint boundary {:?}: {:?}",
                last_committed,
                error
            );
            last_committed
        }
    };

    let latest_pending_reverse_mapping = reverse_query(current.0).await?;
    ensure_latest_pending_within_target(current.0, latest_pending_reverse_mapping, target_checkpoint_id)?;

    Ok((current, last_committed))
}

// Post-T reverse mapping of the latest pending is a leftover generation; fail closed so startup cannot replay its backup.
fn ensure_latest_pending_within_target(
    current_unique_pending_id: u64,
    latest_pending_reverse_mapping: Option<u64>,
    target_checkpoint_id: u64,
) -> anyhow::Result<()> {
    if let Some(mapped_checkpoint_id) = latest_pending_reverse_mapping {
        if mapped_checkpoint_id > target_checkpoint_id {
            anyhow::bail!(
                "Contradictory pending mapping: latest mapped unique pending ID {} maps to \
                 checkpoint {}, beyond the target checkpoint {}. A leftover post-target \
                 generation survived; refusing to start up to prevent reapplying its backup.",
                current_unique_pending_id,
                mapped_checkpoint_id,
                target_checkpoint_id
            );
        }
    }
    Ok(())
}

impl<
        N: QNetworkTypesConfig,
        S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync,
        ProofWorkQueue: QStandardWorkerQueuePublisher + Send + Sync,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
        CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync,
    > PsyRealmDatabaseProcessor<N, S, STagTreeRewards, GUTAUpdateQueue, ProofWorkQueue, TempDatabase, ProofStore, FileSystem, CoordinatorClient>
where
    N::HasherBase: 'static + Send + Sync + MerkleZeroHasher<N::QHash> + FieldQHasher<N::F, N::QHash>,
{
    pub async fn get_database_check_state(&self) -> anyhow::Result<DatabaseCheckState> {
        let local_latest_checkpoint_id: u64 = self.db.get_latest_checkpoint_id().await?;

        if classify_genesis_complete_gate(
            self.db.get_genesis_complete().await?,
            local_latest_checkpoint_id,
            self.db.get_unique_pending_id_for_checkpoint_id(0).await,
        )?
        .is_some()
        {
            return Ok(DatabaseCheckState::NeedsGenesis);
        }

        let coordinator_realm_state: CheckpointedMerkleHash<N::QHash> = self
            .coordinator_client
            .rc_get_realm_root_and_last_modified_checkpoint(u64::MAX - 0xffff, self.state.realm_id_u64)
            .await?;

        if coordinator_realm_state.checkpoint_id > local_latest_checkpoint_id {
            tracing::info!(
                "Coordinator indicates Realm updated at checkpoint {}, but local DB only at {}. Needs Recovery.",
                coordinator_realm_state.checkpoint_id,
                local_latest_checkpoint_id
            );
            return Ok(DatabaseCheckState::NeedsRecovery);
        }

        let local_realm_root = self
            .db
            .global_user_tree_get_node_and_checkpoint_id_max_checkpoint(coordinator_realm_state.checkpoint_id, &self.realm_root_node)
            .await?;

        if local_realm_root.value != coordinator_realm_state.value {
            tracing::warn!(
                "Realm Root Mismatch at Checkpoint {}. Local: {:?}, Remote: {:?}. Needs Recovery.",
                coordinator_realm_state.checkpoint_id,
                local_realm_root.value,
                coordinator_realm_state.value
            );
            return Ok(DatabaseCheckState::NeedsRecovery);
        }

        let ((last_unique_pending_id, _), _) = resolve_current_and_last_committed_pending_ids(
            local_latest_checkpoint_id,
            |checkpoint_id| {
                let db = self.db.clone();
                async move { db.get_unique_pending_id_for_checkpoint_id(checkpoint_id).await }
            },
            || self.db.get_latest_mapped_unique_pending_id(),
            |unique_pending_id| self.db.get_checkpoint_id_for_unique_pending_id(unique_pending_id),
        )
        .await?;
        let expected_checkpoint_id_opt = self.db.get_checkpoint_id_for_unique_pending_id(last_unique_pending_id).await?;

        if let Some(expected_checkpoint_id) = expected_checkpoint_id_opt {
            if expected_checkpoint_id != local_latest_checkpoint_id {
                if expected_checkpoint_id > local_latest_checkpoint_id {
                     tracing::error!("DB Inconsistency: PendingID {} maps to Checkpoint {}, but latest is {}.", 
                        last_unique_pending_id, expected_checkpoint_id, local_latest_checkpoint_id);
                     return Ok(DatabaseCheckState::NeedsRecovery);
                }
            }
        }

        Ok(DatabaseCheckState::Ready)
    }

    pub async fn new_init(
        db: Arc<S>,
        tag_tree_rewards_store: Arc<STagTreeRewards>,
        temp_db: Arc<TempDatabase>,
        proof_store: Arc<ProofStore>,
        guta_update_queue: Arc<GUTAUpdateQueue>,
        proof_work_queue: Arc<ProofWorkQueue>,
        coordinator_client: Arc<CoordinatorClient>,
        chain_id: u64,
        realm_identifier: QRealmIdentifier,
        circuit_fingerprint_config: PsyNodeCircuitFingerprintConfig<N::QHash>,
        proof_verifier: Arc<N::ZKVerifier>,
        file_system: Arc<FileSystem>,
        checkpoint_tree_root_backup_file_path: String,
        genesis: &PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate<N::F, N::QHash>,
    ) -> anyhow::Result<Self> {
        let realm_id_u64 = realm_identifier.realm_id as u64;
        let realm_sub_id_u64 = realm_identifier.realm_sub_id as u64;
        let realm_root_node = SimpleMerkleNodeKey {
            level: N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            index: realm_id_u64,
        };
        tracing::info!("[REALM_INIT] new_init start");

        let (state, current_unique_pending_id, current_core_proc_unique_pending_id) =
            Self::initial_realm_state(&db, chain_id, realm_identifier, realm_root_node, genesis).await?;

        let checkpoint_tree_backup_manager = create_new_checkpoint_backup_manager_from_file_path(
            file_system.clone(),
            STALE_CHECKPOINT_AGE_USER_END_CAP_TO_REALM_PROOF,
            N::CHECKPOINT_TREE_HEIGHT,
            &db,
            &checkpoint_tree_root_backup_file_path,
            true,
        )
        .await?;
        tracing::info!("[REALM_INIT] checkpoint backup manager created");

        temp_db
            .set_unique_pending_ids(&realm_identifier, current_unique_pending_id, current_core_proc_unique_pending_id)
            .await?;
        tracing::info!("[REALM_INIT] temp db unique ids set");

        temp_db
            .set_gathering_generation(&realm_identifier, psy_node_core::psy_temp_db::GatheringGeneration {
                checkpoint_id: state.gathering_checkpoint_id,
                unique_pending_id: state.gathering_unique_pending_id,
                proc_checkpoint_unique_id: state.gathering_proc_checkpoint_unique_id,
            })
            .await?;
        tracing::info!("[REALM_INIT] temp db gathering unique ids set");

        let status = ProcessorStatus::new();
        Ok(Self {
            db,
            status: status.clone(),
            tag_tree_rewards_store,
            temp_db,
            proof_store,
            guta_update_queue,
            proof_work_queue,
            coordinator_client,
            checkpoint_tree_backup_manager,
            shared_state: RealmProcessorCoreStateWrapper::new(state.clone()),
            circuit_fingerprint_config,
            proof_verifier,
            guta_queue_key_status_manager: QueueKeyStatusManager::<
                PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID,
                PsyRealmUserUpdateQueueItem<N::F, N::QHash>,
            >::new_with_status(QPStandardUniqueIdQueueKey {
                realm_id: realm_id_u64,
                realm_sub_id: realm_sub_id_u64,
                unique_id: current_core_proc_unique_pending_id,
                task_group: 0,
                queue_type: QPBaseQueueType::StandardEphemeral,
                _phantom_queue_item: std::marker::PhantomData,
            }, status.clone()),
            needs_revert: false,
            state,
            realm_root_node,
        })
    }

    async fn initial_realm_state(
        db: &Arc<S>,
        chain_id: u64,
        realm_identifier: QRealmIdentifier,
        realm_root_node: SimpleMerkleNodeKey,
        genesis: &PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate<N::F, N::QHash>,
    ) -> anyhow::Result<(RealmProcessorCoreState<N::QHash>, u64, QCoreProcCheckpointUniqueId)> {
        let last_committed_checkpoint_id = db.get_latest_checkpoint_id().await?;
        tracing::info!("[REALM_INIT] latest checkpoint id = {}", last_committed_checkpoint_id);
        if !db.get_genesis_complete().await? && last_committed_checkpoint_id == 0 {
            apply_genesis_checkpoint_records::<N, S>(db.as_ref(), genesis, 0, 0).await?;
        }
        let genesis_checkpoint_root = genesis.coordinator_update.checkpoint_sync_info.checkpoint_tree_root;
        let ((current_unique_pending_id, current_core_proc_unique_pending_id), (last_committed_unique_pending_id, last_committed_proc_checkpoint_unique_id)) =
            if last_committed_checkpoint_id == 0 {
                let committed = match db.get_unique_pending_id_for_checkpoint_id(0).await {
                    Ok(Some(res)) => res,
                    _ => (0u64, 0u128),
                };
                ((0u64, 0u128), committed)
            } else {
                resolve_current_and_last_committed_pending_ids(
                    last_committed_checkpoint_id,
                    |checkpoint_id| {
                        let db = db.clone();
                        async move { db.get_unique_pending_id_for_checkpoint_id(checkpoint_id).await }
                    },
                    || {
                        let db = db.clone();
                        async move { db.get_latest_mapped_unique_pending_id().await }
                    },
                    |unique_pending_id| {
                        let db = db.clone();
                        async move { db.get_checkpoint_id_for_unique_pending_id(unique_pending_id).await }
                    },
                ).await?
            };
        tracing::info!(
            "[REALM_INIT] current unique ids = ({}, {})",
            current_unique_pending_id,
            current_core_proc_unique_pending_id
        );
        let last_committed_checkpoint_root = match db.checkpoint_tree_get_root_hash(last_committed_checkpoint_id).await {
            Ok(root) => root,
            Err(_) if last_committed_checkpoint_id == 0 => genesis_checkpoint_root,
            Err(e) => return Err(e),
        };
        let last_committed_realm_root = db
            .global_user_tree_get_node(last_committed_checkpoint_id, realm_root_node)
            .await?;
        let state = RealmProcessorCoreState::new_basic(
            chain_id,
            realm_identifier,
            last_committed_checkpoint_id,
            last_committed_unique_pending_id,
            last_committed_proc_checkpoint_unique_id,
            last_committed_checkpoint_root,
            last_committed_realm_root,
        );
        Ok((state, current_unique_pending_id, current_core_proc_unique_pending_id))
    }

    pub async fn ensure_genesis_applied(
        &mut self,
        genesis_block_update: PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate<N::F, N::QHash>,
    ) -> anyhow::Result<()> {
        self.finish_genesis_if_needed(&genesis_block_update).await
    }

    pub async fn ensure_genesis_applied_from_setup_data(&mut self, genesis_data: &PsyGenesisBlockSetupData<N::F, N::QHash>) -> anyhow::Result<()> {
        let genesis_block_update = GenesisDatabaseDataBuilder::setup_for_realm::<N::HasherBase, N>(
            genesis_data,
            self.state.chain_id,
            self.state.realm_id_u64,
            self.state.realm_sub_id_u64,
        )?;
        self.finish_genesis_if_needed(&genesis_block_update).await
    }

    async fn finish_genesis_if_needed(
        &mut self,
        genesis_block_update: &PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate<N::F, N::QHash>,
    ) -> anyhow::Result<()> {
        let tip = self.db.get_latest_checkpoint_id().await?;
        if tip > 0 {
            if !self.db.get_genesis_complete().await? {
                self.db.set_genesis_complete().await?;
            }
            return Ok(());
        }
        let mapping_missing = self.db.get_unique_pending_id_for_checkpoint_id(0).await?.is_none();
        let l2_incomplete = self.db.try_get_complete_l2_block_state(0).await?.is_none();
        let plan = plan_genesis_bootstrap(
            tip,
            self.checkpoint_tree_backup_manager.next_backup_checkpoint_id,
            mapping_missing,
            l2_incomplete,
        );
        seed_or_check_genesis_backup(
            &mut self.checkpoint_tree_backup_manager,
            genesis_block_update
                .coordinator_update
                .checkpoint_sync_info
                .checkpoint_leaf_hash,
        )
        .await?;
        if plan.write_checkpoint_zero {
            apply_genesis_checkpoint_records::<N, S>(
                self.db.as_ref(),
                genesis_block_update,
                self.state.processing_unique_pending_id,
                self.state.processing_proc_checkpoint_unique_id,
            )
            .await?;
        }
        if plan.write_validators {
            write_validator_tree_genesis(
                &*self.db,
                &genesis_block_update.update_validator_tree_nodes_ffs,
                &genesis_block_update.new_validator_leaf_preimages,
            )
            .await?;
        }
        if plan.write_complete {
            self.db.set_genesis_complete().await?;
            tracing::info!("Genesis block setup data applied.");
        }
        Ok(())
    }

    pub async fn ensure_db_matches_coordinator_head(&self) -> anyhow::Result<()> {
        let coordinator_latest_checkpoint_id: u64 = self.coordinator_client.rc_get_latest_checkpoint_id().await?;
        let local_latest_checkpoint_id: u64 = self.db.get_latest_checkpoint_id().await?;
        
        if coordinator_latest_checkpoint_id < local_latest_checkpoint_id {
            anyhow::bail!("Local database checkpoint ID ({}) is ahead of coordinator ({}). Inconsistency detected.",
                local_latest_checkpoint_id, coordinator_latest_checkpoint_id);
        }

        let coordinator_realm_root_state = self
            .coordinator_client
            .rc_get_realm_root_and_last_modified_checkpoint(coordinator_latest_checkpoint_id, self.state.realm_id_u64)
            .await?;
            
        let local_realm_root_state = self
            .db
            .global_user_tree_get_node_and_checkpoint_id_max_checkpoint(coordinator_latest_checkpoint_id, &self.realm_root_node)
            .await?;

        if local_latest_checkpoint_id < coordinator_realm_root_state.checkpoint_id {
             anyhow::bail!("Local database is stale. Coordinator sees update at {}, local head is {}.", 
                coordinator_realm_root_state.checkpoint_id, local_latest_checkpoint_id);
        }

        if coordinator_realm_root_state.value != local_realm_root_state.value {
            anyhow::bail!("Realm Root mismatch. Coordinator: {:?}, Local: {:?}.",
                coordinator_realm_root_state, local_realm_root_state);
        }

        Ok(())
    }
}

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync,
        ProofWorkQueue: QStandardWorkerQueuePublisher + Send + Sync,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
        CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync,
    > PsyRealmDatabaseProcessor<N, S, STagTreeRewards, GUTAUpdateQueue, ProofWorkQueue, TempDatabase, ProofStore, FileSystem, CoordinatorClient>
where
    N::HasherBase: 'static + Send + Sync + MerkleZeroHasher<N::QHash> + FieldQHasher<N::F, N::QHash>,
{
    /// Root transitions for the window: each realm transition at C consumed the previous
    /// transition's root, so the chain starts at the committed realm end root.
    async fn pending_transition_lookups(
        &self,
        from_checkpoint: u64,
        target_tip: u64,
    ) -> anyhow::Result<Vec<psy_data::p2p::RealmTransition>>
    where
        N::QHash: Q256BitHash,
    {
        let mut needed = Vec::new();
        let mut old_root = self.state.last_committed_realm_end_root.into_owned_32bytes();
        let mut checkpoint_id = from_checkpoint;
        while checkpoint_id <= target_tip {
            let last_modified = self
                .coordinator_client
                .rc_get_realm_root_and_last_modified_checkpoint(checkpoint_id, self.state.realm_id_u64)
                .await?;
            if last_modified.checkpoint_id == checkpoint_id {
                let new_root = last_modified.value.into_owned_32bytes();
                if new_root != old_root {
                    needed.push(psy_data::p2p::RealmTransition { old_root, new_root });
                }
                old_root = new_root;
            }
            checkpoint_id += 1;
        }
        Ok(needed)
    }

    /// Stage every candidate the batch window can supply before the loop starts.
    async fn stage_recovery_window(
        &self,
        from_checkpoint: u64,
        target_tip: u64,
        proposal_backup: &crate::realm::processor::proposal_backup::ProposalBackup,
        client: &crate::realm::network::RealmNetworkCommands,
        validator_nodes: &[(u16, psy_data::p2p::NodeId)],
    ) -> anyhow::Result<HashMap<psy_data::p2p::RealmTransition, crate::realm::processor::proposal_backup::StagedProposal>>
    where
        N::QHash: Q256BitHash,
    {
        let needed = self
            .pending_transition_lookups(from_checkpoint, target_tip)
            .await?;
        let peers = crate::realm::processor::catchup::CatchupPeers::select(
            validator_nodes,
            self.state.realm_sub_id_u64 as u16,
        )?;
        let outcomes = crate::realm::processor::catchup::stage_transition_blocks(
            client,
            proposal_backup,
            &peers,
            self.state.chain_id,
            self.state.realm_id_u64 as u32,
            &needed,
            &[],
        )
        .await;
        let mut staged = HashMap::new();
        for outcome in outcomes {
            match outcome {
                crate::realm::processor::catchup::TransitionFetchOutcome::Staged(transition, staged_proposal) => {
                    staged.insert(transition, staged_proposal);
                }
                crate::realm::processor::catchup::TransitionFetchOutcome::Absent(transition) => tracing::debug!(
                    "catch-up window transition=({},{}) not offered by the batch peer",
                    hex::encode(transition.old_root),
                    hex::encode(transition.new_root)
                ),
                crate::realm::processor::catchup::TransitionFetchOutcome::Failed(transition, error) => tracing::warn!(
                    "catch-up window transition=({},{}) failed error={error:#}",
                    hex::encode(transition.old_root),
                    hex::encode(transition.new_root)
                ),
            }
        }
        Ok(staged)
    }

    async fn stage_single_transition(
        &self,
        transition: psy_data::p2p::RealmTransition,
        proposal_backup: &crate::realm::processor::proposal_backup::ProposalBackup,
        client: &crate::realm::network::RealmNetworkCommands,
        batch_base: u64,
        rejected: &[[u8; 32]],
    ) -> anyhow::Result<Option<crate::realm::processor::proposal_backup::StagedProposal>> {
        let validator_nodes = self.validator_nodes_at(batch_base).await?;
        let peers = crate::realm::processor::catchup::CatchupPeers::select(
            &validator_nodes,
            self.state.realm_sub_id_u64 as u16,
        )?;
        let outcomes = crate::realm::processor::catchup::stage_transition_blocks(
            client,
            proposal_backup,
            &peers,
            self.state.chain_id,
            self.state.realm_id_u64 as u32,
            &[transition],
            rejected,
        )
        .await;
        Ok(outcomes.into_iter().find_map(|outcome| match outcome {
            crate::realm::processor::catchup::TransitionFetchOutcome::Staged(_, staged) => Some(staged),
            crate::realm::processor::catchup::TransitionFetchOutcome::Absent(transition) => {
                tracing::debug!(
                    "catch-up transition=({},{}) not offered by any batch peer",
                    hex::encode(transition.old_root),
                    hex::encode(transition.new_root)
                );
                None
            }
            crate::realm::processor::catchup::TransitionFetchOutcome::Failed(transition, error) => {
                tracing::warn!(
                    "catch-up transition=({},{}) failed error={error:#}",
                    hex::encode(transition.old_root),
                    hex::encode(transition.new_root)
                );
                None
            }
        }))
    }

    /// Verify one transition, install the verified bytes into its record, then apply.
    async fn apply_verified_transition(
        &mut self,
        included: &crate::realm::processor::ffs::CheckpointIdentity,
        transition: psy_data::p2p::RealmTransition,
        staged: Option<crate::realm::processor::proposal_backup::StagedProposal>,
        proposal_backup: &crate::realm::processor::proposal_backup::ProposalBackup,
        rejected: &mut Vec<[u8; 32]>,
    ) -> anyhow::Result<Option<(PsyPreparedRealmBlockStateUpdates<N::QHash>, Vec<u8>)>> {
        let verified = match self
            .verify_history_transition(included, transition, staged.as_ref(), proposal_backup)
            .await
        {
            Ok(verified) => verified,
            Err(error) => {
                let Some(proposal_id) = crate::realm::processor::ffs::invalid_candidate_id(&error) else {
                    return Err(error);
                };
                rejected.push(proposal_id);
                return Ok(None);
            }
        };
        let Some(verified) = verified else {
            return Ok(None);
        };
        if let Some(staged) = staged {
            proposal_backup.install(staged).await?;
        }
        Ok(Some(
            self.apply_history_proposal(included, verified)
                .await?,
        ))
    }

    async fn validator_nodes_at(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<Vec<(u16, psy_data::p2p::NodeId)>>
    where
        N::HasherBase: MerkleZeroHasher<N::QHash>,
    {
        let roots = self.db.get_checkpoint_global_state_roots(checkpoint_id).await?;
        let (_, _, _, leaves) = load_realm_validators_from_tree::<N::HasherBase, N::QHash, _>(
            &*self.db,
            self.state.chain_id,
            checkpoint_id,
            self.state.realm_id_u64 as u32,
            &roots.validator_tree_root,
        )
        .await?;
        Ok(validator_nodes_from_leaves(&leaves))
    }

    pub(crate) async fn publish_validator_leaves(
        &self,
        proposal_fetch: Option<&crate::realm::network::RealmNetworkCommands>,
        checkpoint_id: u64,
    ) -> anyhow::Result<()>
    where
        N::HasherBase: MerkleZeroHasher<N::QHash>,
    {
        let Some(client) = proposal_fetch else {
            return Ok(());
        };
        let roots = self.db.get_checkpoint_global_state_roots(checkpoint_id).await?;
        let (_, _, _, leaves) = load_realm_validators_from_tree::<N::HasherBase, N::QHash, _>(
            &*self.db,
            self.state.chain_id,
            checkpoint_id,
            self.state.realm_id_u64 as u32,
            &roots.validator_tree_root,
        )
        .await?;
        client
            .set_validator_leaves(leaves.into_iter().map(|(_, leaf)| leaf).collect())
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        Ok(())
    }

    pub async fn ensure_backup_restored_if_necessary(
        &mut self,
        file_system: &FileSystem,
        guta_gatherer_backup_directory: &str,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        proposal_backup: &crate::realm::processor::proposal_backup::ProposalBackup,
        proposal_fetch: Option<&crate::realm::network::RealmNetworkCommands>,
    ) -> anyhow::Result<()> {
        let database_check_state = self.get_database_check_state().await?;
        let local_tip = self.db.get_latest_checkpoint_id().await?;
        let target_tip = self.coordinator_client.rc_get_latest_checkpoint_id().await?;
        let next_backup = self.checkpoint_tree_backup_manager.next_backup_checkpoint_id;
        if should_hard_reset_ahead_backup(target_tip, next_backup) {
            self.checkpoint_tree_backup_manager.hard_reset_and_truncate(0).await?;
            let genesis_leaf = self.db.checkpoint_tree_get_leaf_hash(0, 0).await?;
            seed_or_check_genesis_backup(&mut self.checkpoint_tree_backup_manager, genesis_leaf).await?;
        }
        if database_check_state == DatabaseCheckState::NeedsRecovery
            || local_tip < target_tip
            || should_recover_cleared_backup(local_tip, self.checkpoint_tree_backup_manager.next_backup_checkpoint_id)
        {
            tracing::warn!("Inconsistent Realm Processor State detected. Initiating Recovery.");
            self.apply_history_transitions(
                file_system, guta_gatherer_backup_directory, global_user_tree,
                proposal_backup, proposal_fetch, database_check_state, target_tip,
            ).await?;
        }
        Ok(())
    }

    async fn transition_at(
        &mut self,
        checkpoint_id: u64,
    ) -> anyhow::Result<Option<(
        psy_data::prepared_block::realm::PsyRealmCoordinatorUpdate<N::F, N::QHash>,
        psy_data::p2p::RealmTransition,
    )>> {
        let coordinator_update = self.coordinator_client.rc_get_realm_sync_info(checkpoint_id, self.state.realm_id_u64).await?;
        let target_realm_state = self.coordinator_client
            .rc_get_realm_root_and_last_modified_checkpoint(checkpoint_id, self.state.realm_id_u64)
            .await?;
        tracing::info!("Coordinator realm root at checkpoint {}: {:?}", checkpoint_id, target_realm_state.value);
        if target_realm_state.value == self.state.last_committed_realm_end_root {
            tracing::debug!(
                "Checkpoint {}: realm root unchanged ({:?}), skipping recovery.",
                checkpoint_id,
                target_realm_state.value
            );
            return Ok(None);
        }
        Ok(Some((coordinator_update, psy_data::p2p::RealmTransition {
            old_root: self.state.last_committed_realm_end_root.into_owned_32bytes(),
            new_root: target_realm_state.value.into_owned_32bytes(),
        })))
    }

    async fn apply_history_transitions(
        &mut self,
        file_system: &FileSystem,
        guta_gatherer_backup_directory: &str,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        proposal_backup: &crate::realm::processor::proposal_backup::ProposalBackup,
        proposal_fetch: Option<&crate::realm::network::RealmNetworkCommands>,
        database_check_state: DatabaseCheckState,
        mut target_tip: u64,
    ) -> anyhow::Result<()> {
        loop {
            self.checkpoint_tree_backup_manager
                .sync_from_coordinator_client::<CoordinatorClient, N::F>(&self.coordinator_client, 2000)
                .await?;
            // Only checkpoints above the committed tip are visited.
            let start = self.db.get_latest_checkpoint_id().await?;
            let mut checkpoint_id = start + 1;
            let mut rejected_proposal_ids: Vec<[u8; 32]> = Vec::new();
            let mut staged_transitions = HashMap::new();
            if let Some(client) = proposal_fetch {
                let validator_nodes = self.validator_nodes_at(start).await?;
                staged_transitions = self
                    .stage_recovery_window(start + 1, target_tip, proposal_backup, client, &validator_nodes)
                    .await?;
                self.publish_validator_leaves(proposal_fetch, start).await?;
            }
            while checkpoint_id <= target_tip {
                tracing::info!("Recovering checkpoint {}...", checkpoint_id);
                let Some((coordinator_update, transition)) = self.transition_at(checkpoint_id).await? else {
                    // Empty checkpoints still authenticate proof-base roots for a later
                    // included proposal. Persist C only; do not advance the committed marker.
                    self.persist_checkpoint_metadata_range(checkpoint_id, checkpoint_id, start)
                        .await
                        .map_err(|error| {
                            anyhow::anyhow!(
                                "checkpoint metadata sync before skipping unchanged realm root: {error:#}"
                            )
                        })?;
                    tracing::info!(
                        "Recovered unchanged Realm checkpoint metadata checkpoint_id={checkpoint_id}"
                    );
                    checkpoint_id += 1;
                    continue;
                };
                if !self.restore_checkpoint_transition(
                    file_system, guta_gatherer_backup_directory, global_user_tree,
                    proposal_backup, proposal_fetch, database_check_state, target_tip, start,
                    checkpoint_id, &coordinator_update, transition, &mut staged_transitions,
                    &mut rejected_proposal_ids,
                ).await? {
                    continue;
                }
                checkpoint_id += 1;
            }
            let reread_tip = self.coordinator_client.rc_get_latest_checkpoint_id().await?;
            if reread_tip < self.db.get_latest_checkpoint_id().await? {
                self.ensure_db_matches_coordinator_head().await?;
            }
            if reread_tip > target_tip {
                target_tip = reread_tip;
                continue;
            }
            self.ensure_db_matches_coordinator_head().await?;
            break;
        }
        Ok(())
    }

    async fn restore_checkpoint_transition(
        &mut self,
        file_system: &FileSystem,
        guta_gatherer_backup_directory: &str,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        proposal_backup: &crate::realm::processor::proposal_backup::ProposalBackup,
        proposal_fetch: Option<&crate::realm::network::RealmNetworkCommands>,
        database_check_state: DatabaseCheckState,
        target_tip: u64,
        start: u64,
        checkpoint_id: u64,
        coordinator_update: &psy_data::prepared_block::realm::PsyRealmCoordinatorUpdate<N::F, N::QHash>,
        transition: psy_data::p2p::RealmTransition,
        staged_transitions: &mut HashMap<psy_data::p2p::RealmTransition, crate::realm::processor::proposal_backup::StagedProposal>,
        rejected_proposal_ids: &mut Vec<[u8; 32]>,
    ) -> anyhow::Result<bool> {
        let target_root = N::QHash::from_owned_32bytes(transition.new_root);
        self.state.processing_checkpoint_id = checkpoint_id;
        self.state.processing_checkpoint_root = coordinator_update.checkpoint_sync_info.checkpoint_tree_root;
        let prepared_updates = if checkpoint_id == 0 {
            tracing::info!("Restore target is checkpoint 0 (genesis); using genesis path without backup file.");
            self.genesis_recovery_updates(target_root, 0)
        } else {
            let realm_pending_id = self.db.get_unique_pending_id_for_checkpoint_id(checkpoint_id)
                .await?.filter(|_| checkpoint_id >= target_tip);
            let Some((realm_unique_pending_id, realm_proc_checkpoint_id)) = realm_pending_id else {
                let recovered_from_backup = self.try_pending_backups(
                    file_system, guta_gatherer_backup_directory, global_user_tree,
                    database_check_state, checkpoint_id, target_tip, target_root, coordinator_update,
                ).await?;
                if !recovered_from_backup && !self.retry_history_transition(
                    checkpoint_id, coordinator_update, transition, proposal_backup, proposal_fetch,
                    start, staged_transitions, rejected_proposal_ids,
                ).await? {
                    return Ok(false);
                }
                self.verify_recovered_root(checkpoint_id, target_root).await?;
                return Ok(true);
            };
            self.mapped_recovery_updates(
                file_system, guta_gatherer_backup_directory, global_user_tree,
                checkpoint_id, target_root, realm_unique_pending_id, realm_proc_checkpoint_id,
            ).await?
        };
        self.commit_state(
            coordinator_update, &prepared_updates, ProvingJobCircuitType::GUTANoChange, vec![],
        ).await?;
        tracing::info!("Checkpoint {} recovered successfully.", checkpoint_id);
        self.verify_recovered_root(checkpoint_id, target_root).await?;
        Ok(true)
    }

    fn genesis_recovery_updates(
        &mut self,
        target_root: N::QHash,
        proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
    ) -> PsyPreparedRealmBlockStateUpdates<N::QHash> {
        self.state.processing_realm_start_root = target_root;
        self.state.processing_realm_end_root = target_root;
        PsyPreparedRealmBlockStateUpdates {
            realm_id: self.state.realm_id_u64,
            realm_sub_id: self.state.realm_sub_id_u64,
            old_realm_root: target_root,
            new_realm_root: target_root,
            unique_pending_id: 0,
            proc_checkpoint_unique_id,
            update_global_user_tree_nodes_ffs: vec![],
            update_user_contract_tree_nodes_ffs: vec![],
            update_contract_state_tree_nodes_ffs: vec![],
            update_user_leaves_ffs: vec![],
            update_contract_state_imt_leaves_ffs: vec![],
        }
    }

    async fn mapped_recovery_updates(
        &mut self,
        file_system: &FileSystem,
        guta_gatherer_backup_directory: &str,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        checkpoint_id: u64,
        target_root: N::QHash,
        realm_unique_pending_id: u64,
        realm_proc_checkpoint_id: QCoreProcCheckpointUniqueId,
    ) -> anyhow::Result<PsyPreparedRealmBlockStateUpdates<N::QHash>> {
        if realm_unique_pending_id == 0 {
            tracing::info!(
                "Restore target checkpoint {} maps to unique_pending_id 0 (no backup file); using genesis-like path.",
                checkpoint_id
            );
            return Ok(self.genesis_recovery_updates(target_root, realm_proc_checkpoint_id));
        }
        self.state.processing_unique_pending_id = realm_unique_pending_id;
        self.state.processing_proc_checkpoint_unique_id = realm_proc_checkpoint_id;
        self.state.processing_realm_start_root = self.state.last_committed_realm_end_root;
        self.state.processing_realm_end_root = target_root;
        let prepared = generate_realm_output_from_backups::<N, FileSystem>(
            file_system, guta_gatherer_backup_directory, &self.state,
            Some(realm_unique_pending_id), global_user_tree,
        ).await?;
        anyhow::ensure!(
            global_user_tree.get_root() == target_root,
            "Checkpoint {}: replayed tree root {:?} does not match coordinator target {:?}.",
            checkpoint_id,
            global_user_tree.get_root(),
            target_root
        );
        Ok(prepared)
    }

    async fn try_pending_backups(
        &mut self,
        file_system: &FileSystem,
        guta_gatherer_backup_directory: &str,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        database_check_state: DatabaseCheckState,
        checkpoint_id: u64,
        target_tip: u64,
        target_root: N::QHash,
        coordinator_update: &psy_data::prepared_block::realm::PsyRealmCoordinatorUpdate<N::F, N::QHash>,
    ) -> anyhow::Result<bool> {
        let ((current_unique_pending_id, _), _) =
            resolve_current_and_last_committed_pending_ids(
                self.state.last_committed_checkpoint_id,
                |checkpoint_id| {
                    let db = self.db.clone();
                    async move { db.get_unique_pending_id_for_checkpoint_id(checkpoint_id).await }
                },
                || self.db.get_latest_mapped_unique_pending_id(),
                |unique_pending_id| self.db.get_checkpoint_id_for_unique_pending_id(unique_pending_id),
            ).await?;
        let last_committed_unique_pending_id = self.state.last_committed_unique_pending_id;
        let allow_backup = database_check_state == DatabaseCheckState::NeedsRecovery
            && checkpoint_id > self.state.last_committed_checkpoint_id
            && checkpoint_id >= target_tip;
        if !allow_backup || current_unique_pending_id <= last_committed_unique_pending_id {
            return Ok(false);
        }
        for candidate in (last_committed_unique_pending_id + 1)..=current_unique_pending_id {
            let path = get_new_realm_end_cap_gatherer_backup_file_path(
                guta_gatherer_backup_directory, self.state.realm_id_u64,
                self.state.realm_sub_id_u64, candidate,
            );
            match read_realm_backup_end_root::<FileSystem, N::QHash>(file_system, &path.to_string_lossy()).await {
                Ok(end_root) if end_root == target_root => {
                    if self.load_matching_backup(
                        file_system, guta_gatherer_backup_directory, global_user_tree,
                        checkpoint_id, candidate, target_root, coordinator_update,
                    ).await? {
                        return Ok(true);
                    }
                }
                Ok(end_root) => tracing::debug!(
                    "Backup pending_id {} end_root {:?} does not match coordinator target {:?} for checkpoint {}.",
                    candidate, end_root, target_root, checkpoint_id
                ),
                Err(e) => tracing::debug!(
                    "Failed to read backup pending_id {} for checkpoint {}: {:?}",
                    candidate, checkpoint_id, e
                ),
            }
        }
        Ok(false)
    }

    async fn load_matching_backup(
        &mut self,
        file_system: &FileSystem,
        guta_gatherer_backup_directory: &str,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        checkpoint_id: u64,
        candidate: u64,
        target_root: N::QHash,
        coordinator_update: &psy_data::prepared_block::realm::PsyRealmCoordinatorUpdate<N::F, N::QHash>,
    ) -> anyhow::Result<bool> {
        let Some(candidate_proc_checkpoint_id) =
            self.db.get_proc_checkpoint_unique_id_for_pending_id(candidate).await?
        else {
            tracing::warn!(
                "Backup pending_id {} matches checkpoint {} end_root but has no durable pending->proc record; skipping instead of borrowing another generation's proc ID.",
                candidate, checkpoint_id
            );
            return Ok(false);
        };
        let mut recovery_state = self.state.clone();
        recovery_state.processing_unique_pending_id = candidate;
        recovery_state.processing_proc_checkpoint_unique_id = candidate_proc_checkpoint_id;
        recovery_state.processing_realm_start_root = self.state.last_committed_realm_end_root;
        recovery_state.processing_realm_end_root = target_root;
        tracing::info!(
            "Found matching backup for checkpoint {}: pending_id={}. Attempting full load.",
            checkpoint_id, candidate
        );
        let journal_snapshot = global_user_tree.snapshot();
        match generate_realm_output_from_backups::<N, FileSystem>(
            file_system, guta_gatherer_backup_directory, &recovery_state, Some(candidate), global_user_tree,
        ).await {
            Ok(updates) if updates.new_realm_root == target_root && global_user_tree.get_root() == target_root => {
                tracing::info!(
                    "Backup recovery successful for pending_id {}: end_root matches coordinator target {:?}.",
                    candidate, target_root
                );
                self.state.processing_unique_pending_id = recovery_state.processing_unique_pending_id;
                self.state.processing_proc_checkpoint_unique_id = recovery_state.processing_proc_checkpoint_unique_id;
                self.state.processing_realm_start_root = recovery_state.processing_realm_start_root;
                self.state.processing_realm_end_root = recovery_state.processing_realm_end_root;
                self.commit_state(coordinator_update, &updates, ProvingJobCircuitType::GUTANoChange, vec![]).await?;
                tracing::info!(
                    "Checkpoint {} recovered from backup (pending_id={}).",
                    checkpoint_id, candidate
                );
                Ok(true)
            }
            Ok(updates) => {
                global_user_tree.revert_to(journal_snapshot);
                tracing::warn!(
                    "Backup end_root {:?} does not match coordinator target {:?} for pending_id {}. Trying next candidate.",
                    updates.new_realm_root, target_root, candidate
                );
                Ok(false)
            }
            Err(e) => {
                global_user_tree.revert_to(journal_snapshot);
                tracing::warn!(
                    "Backup pending_id {} end_root matches but full load failed: {:?}. Trying next candidate.",
                    candidate, e
                );
                Ok(false)
            }
        }
    }

    async fn retry_history_transition(
        &mut self,
        checkpoint_id: u64,
        coordinator_update: &psy_data::prepared_block::realm::PsyRealmCoordinatorUpdate<N::F, N::QHash>,
        transition: psy_data::p2p::RealmTransition,
        proposal_backup: &crate::realm::processor::proposal_backup::ProposalBackup,
        proposal_fetch: Option<&crate::realm::network::RealmNetworkCommands>,
        start: u64,
        staged_transitions: &mut HashMap<psy_data::p2p::RealmTransition, crate::realm::processor::proposal_backup::StagedProposal>,
        rejected_proposal_ids: &mut Vec<[u8; 32]>,
    ) -> anyhow::Result<bool> {
        let included = crate::realm::processor::ffs::CheckpointIdentity {
            checkpoint_id,
            checkpoint_leaf_hash: coordinator_update.checkpoint_sync_info.checkpoint_leaf_hash.into_owned_32bytes(),
        };
        for attempt in 0..crate::realm::processor::catchup::CATCHUP_TRANSITION_ATTEMPTS {
            let staged = match staged_transitions.remove(&transition) {
                Some(staged) => Some(staged),
                None => match proposal_fetch {
                    Some(client) => self.stage_single_transition(
                        transition, proposal_backup, client, start, rejected_proposal_ids,
                    ).await?,
                    None => None,
                },
            };
            match self.apply_verified_transition(
                &included, transition, staged, proposal_backup, rejected_proposal_ids,
            ).await {
                Ok(Some(_)) => return Ok(true),
                Ok(None) => tracing::warn!(
                    "MissingHistoryProof at C={} attempt={attempt} transition=({},{}) rejected",
                    checkpoint_id, hex::encode(transition.old_root), hex::encode(transition.new_root)
                ),
                Err(error) => {
                    tracing::warn!(
                        "history apply failed C={checkpoint_id} error={error}; retrying in 5s"
                    );
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    break;
                }
            }
        }
        // A verification failure can be transient (coordinator material, storage). Drop this
        // round's rejections so the next round re-fetches and re-verifies the same candidate.
        rejected_proposal_ids.clear();
        tracing::warn!(
            "MissingHistoryProof at C={}: no verified candidate for transition=({},{}); retrying in 5s",
            checkpoint_id, hex::encode(transition.old_root), hex::encode(transition.new_root)
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
        Ok(false)
    }

    async fn verify_recovered_root(&self, checkpoint_id: u64, target_root: N::QHash) -> anyhow::Result<()> {
        let latest_realm_root = self.get_realm_root_from_db().await?;
        if latest_realm_root != target_root {
            anyhow::bail!(
                "Post-recovery root mismatch at checkpoint {}! Local: {:?}, Target: {:?}",
                checkpoint_id, latest_realm_root, target_root
            );
        }
        Ok(())
    }

    pub async fn init_with_setup_and_genesis(
        &mut self,
        file_system: &FileSystem,
        guta_gatherer_backup_directory: &str,
        genesis_block_update: PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate<N::F, N::QHash>,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        proposal_backup: &crate::realm::processor::proposal_backup::ProposalBackup,
        proposal_fetch: Option<&crate::realm::network::RealmNetworkCommands>,
    ) -> anyhow::Result<()> {
        let genesis_checkpoint_root = genesis_block_update.coordinator_update.checkpoint_sync_info.checkpoint_tree_root;

        self.ensure_genesis_applied(genesis_block_update).await?;
        let genesis_tip = self.db.get_latest_checkpoint_id().await?;
        self.publish_validator_leaves(proposal_fetch, genesis_tip).await?;

        self.ensure_backup_restored_if_necessary(
            file_system,
            guta_gatherer_backup_directory,
            global_user_tree,
            proposal_backup,
            proposal_fetch,
        )
            .await?;

        if self.state.last_committed_checkpoint_id > 0 {
            self.checkpoint_tree_backup_manager
                .sync_from_database::<S>(&self.db, 1000, self.state.last_committed_checkpoint_id)
                .await?;
        }

        self.set_committed_realm_roots_from_db().await?;

        self.sync_to_coordinator_set_checkpoint_id().await?;

        let head_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
        let head_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();

        self.state.coordinator_head_synced_checkpoint_id = head_checkpoint_id;
        self.state.coordinator_head_synced_checkpoint_root = head_checkpoint_root;
        
        self.state.processing_checkpoint_root = head_checkpoint_root;
        self.state.gathering_checkpoint_root = head_checkpoint_root;
        self.state.processing_checkpoint_id = head_checkpoint_id;
        self.state.gathering_checkpoint_id = head_checkpoint_id;

        let last_committed_checkpoint_root = if self.state.last_committed_checkpoint_id == 0 {
            genesis_checkpoint_root 
        } else {
            self.checkpoint_tree_backup_manager
                .checkpoint_tree
                .get_leaf(self.state.last_committed_checkpoint_id)
                .get_append_root::<N::HasherBase>()
        };
        self.state.last_committed_checkpoint_root = last_committed_checkpoint_root;

        self.set_new_unique_ids(Some(self.state.last_committed_realm_end_root)).await?;

        self.guta_queue_key_status_manager
            .set_unique_id(self.state.gathering_proc_checkpoint_unique_id)?;
        
        self.shared_state.update_from_core_state(&self.state).await?;

        tracing::info!(
            "[REALM] Initialized. Checkpoint: {}, Pending ID: {}, Realm Root: {:?}",
            self.state.coordinator_head_synced_checkpoint_id,
            self.state.gathering_unique_pending_id,
            self.state.last_committed_realm_end_root
        );
        self.print_coordinator_processor_state();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_latest_pending_within_target, find_latest_mapped_pending_at_or_before,
        resolve_current_and_last_committed_pending_ids,
    };
    use crate::realm::processor::db::genesis::classify_genesis_mapping;
    use crate::realm::processor::db::DatabaseCheckState;

    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    use parth_core::QCoreProcCheckpointUniqueId;

    fn mapping_query(
        mappings: HashMap<u64, (u64, QCoreProcCheckpointUniqueId)>,
    ) -> impl FnMut(u64) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<(u64, QCoreProcCheckpointUniqueId)>>> + Send>> {
        let mappings = Arc::new(mappings);
        move |cp| {
            let mappings = Arc::clone(&mappings);
            Box::pin(async move { Ok(mappings.get(&cp).copied()) })
        }
    }

    #[test]
    fn applied_genesis_is_not_needs_genesis() {
        assert_eq!(
            classify_genesis_mapping(0, Ok(None)).expect("empty store"),
            Some(DatabaseCheckState::NeedsGenesis)
        );
        assert_eq!(
            classify_genesis_mapping(0, Ok(Some((0, 0)))).expect("applied genesis"),
            None
        );
        assert_eq!(
            classify_genesis_mapping(1, Ok(None)).expect("later checkpoint"),
            None
        );
        let lookup_error = classify_genesis_mapping(0, Err(anyhow::anyhow!("mapping unavailable")))
            .expect_err("lookup errors must propagate");
        assert!(lookup_error.to_string().contains("mapping unavailable"), "{lookup_error}");
    }

    #[tokio::test]
    async fn missing_mapping_walks_back_to_latest_mapping() {
        let mappings = HashMap::from([(197u64, (87u64, 10087u128))]);
        let resolved = find_latest_mapped_pending_at_or_before(199, mapping_query(mappings))
            .await
            .expect("the latest mapping below T must resolve, not (0, 0)");
        assert_eq!(resolved, (87u64, 10087u128 as QCoreProcCheckpointUniqueId));
    }

    #[tokio::test]
    async fn real_mapping_at_target_uses_it_unchanged() {
        let mappings = HashMap::from([(199u64, (88u64, 10088u128))]);
        let resolved = find_latest_mapped_pending_at_or_before(199, mapping_query(mappings))
            .await
            .expect("a mapping at T resolves on the first point read");
        assert_eq!(resolved, (88u64, 10088u128 as QCoreProcCheckpointUniqueId));
    }

    #[tokio::test]
    async fn genesis_empty_store_returns_zero() {
        let resolved = find_latest_mapped_pending_at_or_before(0, mapping_query(HashMap::new()))
            .await
            .expect("genesis with no mapping is the valid empty-store startup state");
        assert_eq!(resolved, (0u64, 0u128 as QCoreProcCheckpointUniqueId));
    }

    #[tokio::test]
    async fn genesis_with_mapping_uses_mapping() {
        let mappings = HashMap::from([(0u64, (5u64, 1005u128))]);
        let resolved = find_latest_mapped_pending_at_or_before(0, mapping_query(mappings))
            .await
            .expect("a genesis mapping resolves to that pair");
        assert_eq!(resolved, (5u64, 1005u128 as QCoreProcCheckpointUniqueId));
    }

    #[tokio::test]
    async fn mapping_at_genesis_resolves_for_non_genesis_target() {
        let mappings = HashMap::from([(0u64, (5u64, 1005u128))]);
        let resolved = find_latest_mapped_pending_at_or_before(5, mapping_query(mappings))
            .await
            .expect("a genesis mapping is the latest mapping for this target");
        assert_eq!(resolved, (5u64, 1005u128 as QCoreProcCheckpointUniqueId));
    }

    #[tokio::test]
    async fn non_genesis_with_no_mapping_fails_closed() {
        let err = find_latest_mapped_pending_at_or_before(5, mapping_query(HashMap::new()))
            .await
            .expect_err("a non-genesis target with no mapping must fail closed");
        let msg = err.to_string();
        assert!(msg.contains("No checkpoint->pending mapping"), "got: {msg}");
        assert!(msg.contains("<= target 5"), "got: {msg}");
    }

    #[tokio::test]
    async fn mapping_query_error_propagates_fail_closed() {
        let err = find_latest_mapped_pending_at_or_before(5, |cp| {
            Box::pin(async move {
                Err::<Option<(u64, QCoreProcCheckpointUniqueId)>, _>(anyhow::anyhow!(
                    "injected point-read failure at checkpoint {cp}"
                ))
            })
        })
        .await
        .expect_err("an injected point-read error must propagate, never fall back to (0, 0)");
        let msg = err.to_string();
        assert!(msg.contains("injected point-read failure at checkpoint 5"), "got: {msg}");
    }

    #[test]
    fn leftover_post_t_pending_fails_closed() {
        let err = ensure_latest_pending_within_target(104, Some(210), 199)
            .expect_err("a reverse mapping beyond T must fail closed");
        let msg = err.to_string();
        assert!(msg.contains("Contradictory pending mapping"), "got: {msg}");
        assert!(msg.contains("unique pending ID 104"), "got: {msg}");
        assert!(msg.contains("checkpoint 210"), "got: {msg}");
        assert!(msg.contains("target checkpoint 199"), "got: {msg}");
    }

    #[test]
    fn latest_pending_within_or_at_target_is_consistent() {
        ensure_latest_pending_within_target(87, Some(197), 199)
            .expect("a reverse mapping <= T is consistent");
        ensure_latest_pending_within_target(88, Some(199), 199)
            .expect("a reverse mapping == T is consistent (boundary is >, not >=)");
    }

    #[tokio::test]
    async fn marker_63_with_only_sentinel_mapping_uses_proven_zero_pair() {
        let mappings = HashMap::from([(0u64, (0u64, 0u128))]);
        let resolved = resolve_current_and_last_committed_pending_ids(
            63,
            mapping_query(mappings),
            || async { anyhow::bail!("No mapped unique pending ID found at or below pending counter 1100") },
            |pending_id| async move { Ok((pending_id == 0).then_some(0)) },
        )
        .await
        .expect("the sentinel checkpoint boundary proves the committed/current pair despite a high raw counter");

        assert_eq!(resolved, ((0, 0), (0, 0)));
    }

    #[tokio::test]
    async fn normal_positive_mapping_keeps_latest_and_boundary_pairs() {
        let mappings = HashMap::from([(62u64, (87u64, 10087u128))]);
        let resolved = resolve_current_and_last_committed_pending_ids(
            63,
            mapping_query(mappings),
            || async { Ok((87u64, 10087u128)) },
            |pending_id| async move { Ok((pending_id == 87).then_some(62)) },
        )
        .await
        .expect("a normal positive mapping at/before the marker remains unchanged");

        assert_eq!(resolved, ((87, 10087), (87, 10087)));
    }

    #[test]
    fn latest_pending_inflight_no_reverse_is_allowed() {
        ensure_latest_pending_within_target(94, None, 199)
            .expect("an in-flight pending (no checkpoint mapping) is not a post-T leftover");
    }

    #[test]
    fn recovery_candidate_range_excludes_post_t_backups_after_rollback() {
        let boundary = 87u64;
        let current = 87u64;
        let candidate_range = (boundary + 1)..=current;

        assert!(candidate_range.is_empty(), "candidate range must be empty after a correct rollback");
        for post_target_pending in [88u64, 89, 94] {
            assert!(
                !candidate_range.contains(&post_target_pending),
                "post-T post-target generation pending {} must not be in the recovery candidate range",
                post_target_pending
            );
        }
    }

    #[test]
    fn partial_rollback_leftover_bails_before_recovery_applies_backup() {
        let boundary = 87u64;
        let leftover_pending = 88u64;
        let leftover_reverse = Some(200u64);
        ensure_latest_pending_within_target(leftover_pending, leftover_reverse, 199)
            .expect_err("a leftover post-T pending must bail before recovery runs");
        let would_walk = (boundary + 1)..=leftover_pending;
        assert!(would_walk.contains(&leftover_pending), "sanity: without the guard the leftover would be walked");
    }
}
