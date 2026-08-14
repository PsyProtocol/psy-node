use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use parth_common::memory_stores::{mem_tree_recorder::SimpleMemoryMerkleRecorderStore, traits::PsyMemoryMerkleStoreImm};
use parth_core::{
    QCoreProcCheckpointUniqueId, crypto::hash::{
        merkle_proof::{DeltaMerkleProofCore, MerkleProofCore},
        traits::{FieldQHasher, MerkleZeroHasher, QFieldHashable, ZeroableHash},
    }, data::queue::queue_key::{QPBaseQueueType, QPStandardUniqueIdQueueKey}, generic_traits::psy_debug_printable::PsyDebugPrintable, node::realm_identifier::QRealmIdentifier, protocol::core_types::{Q256BitHash, QNetworkTypesConfig}
};
use psy_node_core::queue::coordinator_guta_durable_submission::CoordinatorGutaQueueItem;
use crate::coordinator::queue_key::{CoordinatorSubmitRealmGUTAUpdateQueueKey, CoordinatorRegisterUserPublicKeyQueueKey, CoordinatorDeployContractQueueKey, CoordinatorProvingWorkQueueKey};

use psy_core::{
    constants::{
        chain_id::PsyChainNetworkType,
        stale_checkpoint::STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF,
    },
    job::job_id::{ProvingJobCircuitType, QProvingJobDataID},
};
use psy_data::{
    config::network_config::PsyNodeCircuitFingerprintConfig,
    genesis::genesis_block_setup::PsyGenesisBlockSetupData,
    node::coordinator_processor::{CoordinatorProcessorIdState, CoordinatorProcessorLastCommittedState},
    prepared_block::coordinator::PsyPreparedCoordinatorBlockStateUpdates,
    protocol::{
        canonical_chain::{
            CanonicalChainRef, CheckpointHash, CheckpointId, CheckpointRef,
            checkpoint_hash_from_previous,
            checkpoint_hash_from_saved_proof_bytes, genesis_checkpoint_hash,
        },
        chain_context::{
            AuthorityScope, PendingContext, WorkProcCheckpointUniqueId,
            WorkUniquePendingId,
        },
        checkpoint_transition_hash::CheckpointStateHashTransition,
        verifiable_checkpoint_transition::{PsyVerifiableCheckpointTransition, PsyVerifiableCheckpointTransitionWithProof},
    },
    v1::qdata::{checkpoint::QEDL2BlockState, contract::PsyDeployContractQueueItem, public_key::PZKPublicKeyInfo},
    worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId,
};
use psy_io::tokio::{TokioFileLike, TokioLikeFileSystem};
use psy_node_core::{
    genesis::genesis_db_data_builder::GenesisDatabaseDataBuilder,
    psy_core_db::traits::full::{
        PsyCoordinatorProcessorStore, PsyNodeCheckpointTreeDatabaseReader, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter,
    },
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueueSubscriber, worker_queue::QStandardWorkerQueuePublisher},
    store::{
        canonical_head::{
            plan_canonical_head_startup, CanonicalHeadBootstrap,
            CanonicalHeadBootstrapProfile,
            CanonicalHeadReadState, CanonicalHeadStartupPlan, CanonicalHeadTransition,
            CanonicalHeadWriteOutcome, CoordinatorCanonicalHeadStore, NetworkId,
            StoredCanonicalHead,
        },
        coordinator_commit_source::{
            CoordinatorCommitSource, CoordinatorCommitSourcePayload,
        },
        rollback_admission::{
            CoordinatorRollbackAdmissionBoundary,
            CoordinatorRollbackAdmissionStore,
            RollbackAdmissionBoundaryOutcome,
        },
        rollback_participant_maintenance::{
            CoordinatorRollbackMaintenanceExecutor,
            CoordinatorRollbackMaintenanceOutcome,
        },
        rollback_runtime_rebuild::{
            CoordinatorRollbackRuntimePublication, CoordinatorRollbackRuntimeRebuildStore,
            RollbackRuntimeRebuildDirective, RollbackRuntimeRebuildReport,
        },
        traits::proof_store::QParthProofStore,
    },
};
use psy_serialize::PsyIOReadWrite;

use crate::{
    backup::{checkpoint_tree::CheckpointTreeBackupManager, coordinator::generate_coordinator_output_from_backups},
    constants::queue::{
        PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID,
        PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID,
    },
    coordinator::processor::processor_shared_status::{PsyCoordinatorProcessorSharedStatus, PsyCoordinatorProcessorSharedStatusWrapper},
    queue::gatherer::QueueKeyStatusManager,
    utils::processor_status::ProcessorStatus,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum DatabaseCheckState {
    NeedsGenesis = 0,
    NeedsRecovery = 1,
    Ready = 2,
}

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

fn qhash_to_hex<Hash: Q256BitHash>(hash: &Hash) -> String {
    hex::encode(hash.into_owned_32bytes())
}

fn ensure_non_genesis_checkpoint_chain_commitment<F, Hash, Hasher>(
    checkpoint_id: u64,
    previous_chain_hash: Hash,
    checkpoint_tree_root: Hash,
    checkpoint_leaf_hash: Hash,
    checkpoint_state_transition_circuit_fingerprint: Hash,
    proof_public_inputs_hash: Hash,
) -> anyhow::Result<()>
where
    Hash: Q256BitHash,
    Hasher: FieldQHasher<F, Hash>,
{
    let expected_chain_hash = checkpoint_hash_from_previous::<_, Hasher>(
        CheckpointHash::from_last_chain_hash(previous_chain_hash),
        checkpoint_tree_root,
        checkpoint_leaf_hash,
        checkpoint_state_transition_circuit_fingerprint,
    )
    .into_inner();

    if proof_public_inputs_hash != expected_chain_hash {
        anyhow::bail!(
            "Checkpoint proof public-input hash mismatch for checkpoint ID {}. Expected chain hash: {}, actual proof public-input hash: {}",
            checkpoint_id,
            qhash_to_hex(&expected_chain_hash),
            qhash_to_hex(&proof_public_inputs_hash),
        );
    }

    Ok(())
}

pub struct PsyCoordinatorDatabaseProcessor<
    N: QNetworkTypesConfig,
    S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber,
    RegisterUserQueue: QStandardEphemeralQueueSubscriber,
    DeployContractQueue: QStandardEphemeralQueueSubscriber,
    ProofWorkQueue: QStandardWorkerQueuePublisher,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
    ProofStore: QParthProofStore,
    FileSystem: TokioLikeFileSystem,
> {
    // stores
    pub db: Arc<S>,
    pub tag_tree_rewards_store: Arc<STagTreeRewards>,
    pub temp_db: Arc<TempDatabase>,
    pub proof_store: Arc<ProofStore>,
    canonical_head_store: Arc<dyn CoordinatorCanonicalHeadStore<N::QHash>>,
    rollback_admission_boundary: CoordinatorRollbackAdmissionBoundary<N::QHash>,

    //queues
    pub guta_update_queue: Arc<GUTAUpdateQueue>,
    pub register_user_queue: Arc<RegisterUserQueue>,
    pub deploy_contract_queue: Arc<DeployContractQueue>,
    pub proof_work_queue: Arc<ProofWorkQueue>,

    //checkpoint tree
    pub checkpoint_tree_backup_manager: CheckpointTreeBackupManager<N::HasherBase, N::QHash, FileSystem>,

    // status
    pub status: ProcessorStatus,
    pub guta_queue_key_status_manager: QueueKeyStatusManager<
        PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID,
        CoordinatorGutaQueueItem<N::F, N::QHash>,
    >,
    pub register_user_queue_key_status_manager:
        QueueKeyStatusManager<PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID, PZKPublicKeyInfo<N::QHash>>,
    pub deploy_contract_queue_key_status_manager:
        QueueKeyStatusManager<PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, PsyDeployContractQueueItem<N::F, N::QHash>>,
    pub shared_status: PsyCoordinatorProcessorSharedStatusWrapper<N::F, N::QHash>,
    pub needs_revert: bool,

    // state
    pub last_committed: CoordinatorProcessorLastCommittedState<N::F, N::QHash>,
    pub ids: CoordinatorProcessorIdState,
    canonical_head: Option<StoredCanonicalHead<N::QHash>>,
    pending_genesis_head: Option<CanonicalHeadBootstrap<N::QHash>>,

    // config
    network_id: NetworkId,
    pub circuit_fingerprint_config: PsyNodeCircuitFingerprintConfig<N::QHash>,
    pub genesis_checkpoint_state_transition_hash: N::QHash,
    pub genesis_verifiable_state_transition: PsyVerifiableCheckpointTransition<N::F, N::QHash>,
}

impl<
        N: QNetworkTypesConfig,
        S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber,
        RegisterUserQueue: QStandardEphemeralQueueSubscriber,
        DeployContractQueue: QStandardEphemeralQueueSubscriber,
        ProofWorkQueue: QStandardWorkerQueuePublisher,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
    >
    PsyCoordinatorDatabaseProcessor<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        RegisterUserQueue,
        DeployContractQueue,
        ProofWorkQueue,
        TempDatabase,
        ProofStore,
        FileSystem,
    > where N::HasherBase: 'static + Send + Sync
{
    fn local_genesis_checkpoint_state_transition_hash(
        genesis_verifiable_state_transition: &PsyVerifiableCheckpointTransition<N::F, N::QHash>,
    ) -> N::QHash {
        genesis_verifiable_state_transition
            .state_transition
            .genesis_checkpoint_state_transition_hash
    }

    async fn resolve_canonical_genesis_checkpoint_state_transition_hash(
        db: &S,
        last_committed_checkpoint_id: u64,
        local_genesis_checkpoint_state_transition_hash: N::QHash,
    ) -> anyhow::Result<N::QHash> {
        if last_committed_checkpoint_id == 0 {
            return Ok(local_genesis_checkpoint_state_transition_hash);
        }

        let stored = db
            .get_verifiable_checkpoint_state_transition_and_zkp(last_committed_checkpoint_id)
            .await?;
        let canonical_genesis_checkpoint_state_transition_hash =
            stored.info.state_transition.genesis_checkpoint_state_transition_hash;

        if canonical_genesis_checkpoint_state_transition_hash
            != local_genesis_checkpoint_state_transition_hash
        {
            anyhow::bail!(
                "startup genesis checkpoint state transition hash mismatch at latest_checkpoint_id={}: local={}, db={}; refusing to start with non-canonical genesis CST hash",
                last_committed_checkpoint_id,
                qhash_to_hex(&local_genesis_checkpoint_state_transition_hash),
                qhash_to_hex(&canonical_genesis_checkpoint_state_transition_hash),
            );
        }

        Ok(canonical_genesis_checkpoint_state_transition_hash)
    }
    pub async fn get_next_checkpoint_id(&self) -> anyhow::Result<u64> {
        let latest_checkpoint_id = self.db.get_latest_checkpoint_id().await?;
        Ok(latest_checkpoint_id + 1)
    }
    pub async fn get_database_check_state(&self) -> anyhow::Result<DatabaseCheckState> {
        let actual_latest_applied_checkpoint_id: u64 = self.db.get_latest_checkpoint_id().await?;
        let (last_unique_pending_id, _last_unique_proc_checkpoint_id): (u64, QCoreProcCheckpointUniqueId) =
            match self.db.get_latest_mapped_unique_pending_id().await {
                Ok(ids) => ids,
                Err(_) if actual_latest_applied_checkpoint_id == 0 => return Ok(DatabaseCheckState::NeedsGenesis),
                Err(e) => return Err(e),
            };

        let expected_checkpoint_id: Option<u64> = self.db.get_checkpoint_id_for_unique_pending_id(last_unique_pending_id).await?;
        let database_check_state = if expected_checkpoint_id.is_none() && actual_latest_applied_checkpoint_id == 0 {
            // needs genesis
            DatabaseCheckState::NeedsGenesis
        } else if expected_checkpoint_id.is_none(){
            // died before setting anything in the database, we don't need to recover
            DatabaseCheckState::Ready
        }else{
            let expected_checkpoint_id = expected_checkpoint_id.unwrap();
            if expected_checkpoint_id != actual_latest_applied_checkpoint_id {
                if expected_checkpoint_id < actual_latest_applied_checkpoint_id {
                    anyhow::bail!("Inconsistent database state detected: expected checkpoint ID ({}) for unique pending ID ({}) is less than actual latest applied checkpoint ID ({}). This indicates a serious inconsistency in the database state.",
                        expected_checkpoint_id, last_unique_pending_id, actual_latest_applied_checkpoint_id);
                } else if expected_checkpoint_id > actual_latest_applied_checkpoint_id + 1 {
                    anyhow::bail!("Inconsistent database state detected: expected checkpoint ID ({}) for unique pending ID ({}) is greater than actual latest applied checkpoint ID + 1 ({}). This indicates a serious inconsistency in the database state.",
                        expected_checkpoint_id, last_unique_pending_id, actual_latest_applied_checkpoint_id + 1);
                } else if expected_checkpoint_id == 0 {
                    // needs genesis
                    DatabaseCheckState::NeedsGenesis
                } else {
                    // needs recovery
                    DatabaseCheckState::NeedsRecovery
                }
            } else {
                DatabaseCheckState::Ready
            }
        };
        Ok(database_check_state)
    }
    pub async fn new_init(
        db: Arc<S>,
        canonical_head_store: Arc<dyn CoordinatorCanonicalHeadStore<N::QHash>>,
        rollback_admission_store: Arc<dyn CoordinatorRollbackAdmissionStore<N::QHash>>,
        network: PsyChainNetworkType,
        canonical_head_bootstrap_profile: Option<CanonicalHeadBootstrapProfile>,
        tag_tree_rewards_store: Arc<STagTreeRewards>,
        temp_db: Arc<TempDatabase>,
        proof_store: Arc<ProofStore>,
        guta_update_queue: Arc<GUTAUpdateQueue>,
        register_user_queue: Arc<RegisterUserQueue>,
        deploy_contract_queue: Arc<DeployContractQueue>,
        proof_work_queue: Arc<ProofWorkQueue>,
        realm_identifier: QRealmIdentifier,
        circuit_fingerprint_config: PsyNodeCircuitFingerprintConfig<N::QHash>,
        genesis_verifiable_state_transition: PsyVerifiableCheckpointTransition<N::F, N::QHash>,
        file_system: Arc<FileSystem>,
        checkpoint_tree_root_backup_file_path: String,
    ) -> anyhow::Result<Self> {
        let realm_id_u64 = realm_identifier.realm_id as u64;
        let realm_sub_id_u64 = realm_identifier.realm_sub_id as u64;
        tracing::info!("[COORD_INIT] new_init start");

        let last_committed_checkpoint_id = db.get_latest_checkpoint_id().await?;
        let local_genesis_checkpoint_state_transition_hash =
            Self::local_genesis_checkpoint_state_transition_hash(&genesis_verifiable_state_transition);
        let genesis_checkpoint_state_transition_hash =
            Self::resolve_canonical_genesis_checkpoint_state_transition_hash(
                &db,
                last_committed_checkpoint_id,
                local_genesis_checkpoint_state_transition_hash,
            )
            .await?;
        tracing::info!("[COORD_INIT] latest checkpoint id = {}", last_committed_checkpoint_id);
        let (current_unique_pending_id, current_core_proc_unique_pending_id) = if last_committed_checkpoint_id == 0 {
            (0, 0u128)
        } else {
            // A crash can persist the pending-ID counter before its random
            // processor-ID mapping. Skip that abandoned generation rather
            // than making every subsequent coordinator restart fail closed.
            db.get_latest_mapped_unique_pending_id().await?
        };
        tracing::info!(
            "[COORD_INIT] current unique ids = ({}, {})",
            current_unique_pending_id,
            current_core_proc_unique_pending_id
        );

        let ids = CoordinatorProcessorIdState {
            realm_identifier: realm_identifier.clone(),
            realm_id_u64,
            realm_sub_id_u64,
            checkpoint_id: last_committed_checkpoint_id,
            next_checkpoint_id: last_committed_checkpoint_id + 1,
            unique_pending_id: current_unique_pending_id,
            proc_checkpoint_unique_id: current_core_proc_unique_pending_id,
            gathering_unique_pending_id: current_unique_pending_id,
            gathering_proc_checkpoint_unique_id: current_core_proc_unique_pending_id,
        };

        let mut checkpoint_tree_backup_manager = create_new_checkpoint_backup_manager_from_file_path(
            file_system.clone(),
            STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF,
            N::CHECKPOINT_TREE_HEIGHT,
            &db,
            &checkpoint_tree_root_backup_file_path,
            true,
        )
        .await?;
        tracing::info!("[COORD_INIT] checkpoint backup manager created");
        if last_committed_checkpoint_id > 0 {
            checkpoint_tree_backup_manager
                .sync_from_database::<S>(&db, 1000, last_committed_checkpoint_id)
                .await?;
            tracing::info!("[COORD_INIT] checkpoint backup manager synced from db");
        }

        let shared_status = if last_committed_checkpoint_id == 0 {
            PsyCoordinatorProcessorSharedStatus {
                last_committed_checkpoint_id,
                unique_pending_id: current_unique_pending_id,
                last_committed_checkpoint_leaf: genesis_verifiable_state_transition.checkpoint_leaf.to_checkpoint_leaf::<N::HasherBase>(),
                last_committed_checkpoint_state_roots: genesis_verifiable_state_transition.checkpoint_leaf.global_state_roots.clone(),
                should_revert_last_changes: false,
                block_state: QEDL2BlockState {
                    checkpoint_id: 0,
                    next_add_withdrawal_id: 0,
                    next_process_withdrawal_id: 0,
                    next_deposit_id: 0,
                    total_deposits_claimed_epoch: 0,
                    next_user_id: 0,
                    end_balance: 0,
                    next_contract_id: 0,
                },
            }
        } else {
            PsyCoordinatorProcessorSharedStatus {
                last_committed_checkpoint_id,
                unique_pending_id: current_unique_pending_id,
                last_committed_checkpoint_leaf: db.get_checkpoint_leaf_data(last_committed_checkpoint_id).await?,
                last_committed_checkpoint_state_roots: db.get_checkpoint_global_state_roots(last_committed_checkpoint_id).await?,
                should_revert_last_changes: false,
                block_state: db.get_l2_block_state(last_committed_checkpoint_id).await?,
            }
        };

        temp_db
            .set_unique_pending_ids(&realm_identifier, current_unique_pending_id, current_core_proc_unique_pending_id)
            .await?;
        tracing::info!("[COORD_INIT] temp db unique ids set");

        temp_db
            .set_gathering_unique_pending_ids(&realm_identifier, current_unique_pending_id, current_core_proc_unique_pending_id)
            .await?;
        tracing::info!("[COORD_INIT] temp db gathering unique ids set");
        let last_committed_l2_state = shared_status.block_state.clone();
        let last_committed_checkpoint_leaf = shared_status.last_committed_checkpoint_leaf.clone();
        let last_committed_checkpoint_root = db.checkpoint_tree_get_root_hash(last_committed_checkpoint_id).await?;
        let last_committed_checkpoint_state_roots = shared_status.last_committed_checkpoint_state_roots.clone();
        let last_committed_checkpoint_leaf_stats = last_committed_checkpoint_leaf.stats.clone();
        let last_committed_checkpoint_state_transition = if last_committed_checkpoint_id == 0 {
            genesis_verifiable_state_transition.state_transition.checkpoint_transition.clone()
        } else {
            CheckpointStateHashTransition {
                old_checkpoint_tree_root: db.checkpoint_tree_get_root_hash(last_committed_checkpoint_id - 1).await?,
                new_checkpoint_tree_root: last_committed_checkpoint_root,
                old_checkpoint_leaf_hash: db
                    .checkpoint_tree_get_leaf_hash(last_committed_checkpoint_id, last_committed_checkpoint_id - 1)
                    .await?,
                new_checkpoint_leaf_hash: last_committed_checkpoint_leaf.qfhash::<N::HasherBase>(),
            }
        };
        let last_chain_hash = if last_committed_checkpoint_id == 0 {
            genesis_verifiable_state_transition
                .state_transition
                .get_chain_0_from_genesis_leaf::<N::HasherBase>(&circuit_fingerprint_config.genesis_checkpoint_state_transition_fingerprint)
        } else {
            let verifiable = db
                .get_verifiable_checkpoint_state_transition_and_zkp(last_committed_checkpoint_id)
                .await?;
            checkpoint_hash_from_saved_proof_bytes::<N::QHash, N::ZKProof, N::ZKVerifier>(
                &verifiable.zk_proof,
            )?
            .into_inner()
        };
        let last_committed = CoordinatorProcessorLastCommittedState::<N::F, N::QHash> {
            l2_state: last_committed_l2_state,
            checkpoint_leaf_stats: last_committed_checkpoint_leaf_stats,
            checkpoint_leaf: last_committed_checkpoint_leaf,
            checkpoint_state_roots: last_committed_checkpoint_state_roots,
            checkpoint_state_transition: last_committed_checkpoint_state_transition,
            checkpoint_root: last_committed_checkpoint_root,
            checkpoint_leaf_hash: last_committed_checkpoint_leaf.qfhash::<N::HasherBase>(),
            last_chain_hash,
        };
        let status = ProcessorStatus::new();
        let network_id = NetworkId::from(network);
        let rollback_admission_boundary = CoordinatorRollbackAdmissionBoundary::new(
            network_id,
            canonical_head_store.clone(),
            rollback_admission_store,
        );
        let mut processor = Self {
            db,
            status: status.clone(),
            tag_tree_rewards_store,
            temp_db,
            proof_store,
            canonical_head_store,
            rollback_admission_boundary,
            guta_update_queue,
            register_user_queue,
            deploy_contract_queue,
            proof_work_queue,
            checkpoint_tree_backup_manager,
            shared_status: PsyCoordinatorProcessorSharedStatusWrapper::new(shared_status),

            circuit_fingerprint_config,
            genesis_verifiable_state_transition,
            guta_queue_key_status_manager: QueueKeyStatusManager::<
                PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID,
                CoordinatorGutaQueueItem<N::F, N::QHash>,
            >::new_with_status(QPStandardUniqueIdQueueKey {
                realm_id: realm_id_u64,
                realm_sub_id: realm_sub_id_u64,
                unique_id: current_core_proc_unique_pending_id,
                task_group: 0,
                queue_type: QPBaseQueueType::StandardEphemeral,
                _phantom_queue_item: std::marker::PhantomData,
            }, status.clone()),
            register_user_queue_key_status_manager: QueueKeyStatusManager::<
                PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID,
                PZKPublicKeyInfo<N::QHash>,
            >::new_with_status(QPStandardUniqueIdQueueKey {
                realm_id: realm_id_u64,
                realm_sub_id: realm_sub_id_u64,
                unique_id: current_core_proc_unique_pending_id,
                task_group: 0,
                queue_type: QPBaseQueueType::StandardEphemeral,
                _phantom_queue_item: std::marker::PhantomData,
            }, status.clone()),
            deploy_contract_queue_key_status_manager: QueueKeyStatusManager::<
                PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID,
                PsyDeployContractQueueItem<N::F, N::QHash>,
            >::new_with_status(QPStandardUniqueIdQueueKey {
                realm_id: realm_id_u64,
                realm_sub_id: realm_sub_id_u64,
                unique_id: current_core_proc_unique_pending_id,
                task_group: 0,
                queue_type: QPBaseQueueType::StandardEphemeral,
                _phantom_queue_item: std::marker::PhantomData,
            }, status.clone()),
            needs_revert: false,
            network_id,
            genesis_checkpoint_state_transition_hash,
            last_committed,
            ids,
            canonical_head: None,
            pending_genesis_head: None,
        };
        processor
            .reconcile_canonical_head_on_startup(canonical_head_bootstrap_profile)
            .await?;
        processor.reconcile_current_pending_context_on_startup().await?;
        processor
            .rollback_admission_boundary
            .ensure_slot_initialized()
            .await?;
        Ok(processor)
    }

    /// The only production bridge from an external durable inbox command to
    /// canonical-head rollback admission. The runner calls this immediately
    /// before starting a new block, never from Edge or inside proof execution.
    pub async fn reconcile_rollback_admission_at_loop_boundary(
        &mut self,
    ) -> anyhow::Result<RollbackAdmissionBoundaryOutcome<N::QHash>> {
        let outcome = self
            .rollback_admission_boundary
            .reconcile_at_loop_boundary()
            .await?;
        self.canonical_head = Some(*outcome.canonical_head());
        if !outcome.canonical_head().rollback_control().is_idle() {
            self.temp_db
                .clear_current_pending_context(&self.ids.realm_identifier)
                .await?;
        }
        Ok(outcome)
    }

    /// Continue the storage-selected Coordinator participant through archive
    /// and exact readback. The result is pre-barrier evidence only; it cannot
    /// delete, restore, or publish the target head.
    pub async fn prepare_coordinator_rollback_archive(
        &self,
    ) -> anyhow::Result<CoordinatorRollbackMaintenanceOutcome<N::QHash>>
    where
        S: CoordinatorRollbackMaintenanceExecutor<N::F, N::QHash>,
    {
        self.db
            .prepare_coordinator_archive(self.network_id, N::CHECKPOINT_TREE_HEIGHT)
            .await
    }

    pub async fn progress_coordinator_rollback(
        &mut self,
    ) -> anyhow::Result<
        psy_node_core::store::rollback_participant_maintenance::CoordinatorRollbackGlobalProgress<
            N::QHash,
        >,
    >
    where
        S: CoordinatorRollbackMaintenanceExecutor<N::F, N::QHash>,
    {
        let progress = self.db
            .progress_coordinator_rollback(self.network_id, N::CHECKPOINT_TREE_HEIGHT)
            .await?;
        if let psy_node_core::store::rollback_participant_maintenance::CoordinatorRollbackGlobalProgress::Progressed(head) = &progress {
            if head.rollback_control().is_idle() {
                self.canonical_head = Some(*head);
                self.publish_pending_context_for_head(*head).await?;
            }
        }
        Ok(progress)
    }

    fn materialized_pending_context(&self) -> anyhow::Result<PendingContext<N::QHash>> {
        let head = self.canonical_head.ok_or_else(|| {
            anyhow::anyhow!(
                "COORDINATOR_PENDING_CONTEXT_UNINITIALIZED: canonical head is not published"
            )
        })?;
        self.materialized_pending_context_for_head(head)
    }

    fn materialized_pending_context_for_head(
        &self,
        head: psy_node_core::store::canonical_head::StoredCanonicalHead<N::QHash>,
    ) -> anyhow::Result<PendingContext<N::QHash>> {
        if !head.rollback_control().is_idle() {
            anyhow::bail!(
                "COORDINATOR_PENDING_CONTEXT_MAINTENANCE: rollback control is active"
            );
        }
        Ok(PendingContext::new(
            *head.canonical_ref(),
            AuthorityScope::Coordinator,
            WorkUniquePendingId::new(self.ids.unique_pending_id),
            WorkProcCheckpointUniqueId::from_u128(self.ids.proc_checkpoint_unique_id),
        ))
    }

    async fn publish_current_pending_context(&self) -> anyhow::Result<()> {
        let context = self.materialized_pending_context()?;
        self.publish_pending_context(context).await
    }

    async fn publish_pending_context_for_head(
        &self,
        head: psy_node_core::store::canonical_head::StoredCanonicalHead<N::QHash>,
    ) -> anyhow::Result<()> {
        let context = self.materialized_pending_context_for_head(head)?;
        self.publish_pending_context(context).await
    }

    async fn publish_pending_context(
        &self,
        context: PendingContext<N::QHash>,
    ) -> anyhow::Result<()> {
        self.temp_db
            .set_current_pending_context(&self.ids.realm_identifier, &context)
            .await?;
        let persisted = self
            .temp_db
            .get_current_pending_context(&self.ids.realm_identifier)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "COORDINATOR_PENDING_CONTEXT_UNINITIALIZED_AFTER_WRITE"
                )
            })?;
        if persisted != context {
            anyhow::bail!("COORDINATOR_PENDING_CONTEXT_READ_AFTER_WRITE_MISMATCH");
        }
        Ok(())
    }

    async fn reconcile_current_pending_context_on_startup(&self) -> anyhow::Result<()> {
        if self
            .canonical_head
            .is_some_and(|head| head.rollback_control().is_idle())
        {
            self.publish_current_pending_context().await
        } else {
            self.temp_db
                .clear_current_pending_context(&self.ids.realm_identifier)
                .await
        }
    }

    fn materialized_checkpoint_ref(&self) -> CheckpointRef<N::QHash> {
        CheckpointRef::new(
            CheckpointId::new(self.ids.checkpoint_id),
            CheckpointHash::from_last_chain_hash(self.last_committed.last_chain_hash),
        )
    }

    fn require_published_outcome(
        operation: &str,
        outcome: CanonicalHeadWriteOutcome<N::QHash>,
    ) -> anyhow::Result<StoredCanonicalHead<N::QHash>> {
        match outcome {
            CanonicalHeadWriteOutcome::Applied(current)
            | CanonicalHeadWriteOutcome::Idempotent(current) => Ok(current),
            CanonicalHeadWriteOutcome::Conflict { current } => anyhow::bail!(
                "canonical-head {operation} conflict: durable revision={}, epoch={}, checkpoint={}",
                current.revision().get(),
                current.canonical_ref().chain_epoch().get(),
                current.canonical_ref().checkpoint().checkpoint_id().get(),
            ),
        }
    }

    async fn reconcile_canonical_head_on_startup(
        &mut self,
        bootstrap_profile: Option<CanonicalHeadBootstrapProfile>,
    ) -> anyhow::Result<()> {
        let database_check_state = self.get_database_check_state().await?;
        let durable = self
            .canonical_head_store
            .read_canonical_head(self.network_id)
            .await?;
        let plan = plan_canonical_head_startup(
            self.network_id,
            bootstrap_profile,
            durable,
            self.materialized_checkpoint_ref(),
            database_check_state == DatabaseCheckState::NeedsGenesis,
        )?;
        match plan {
            CanonicalHeadStartupPlan::AwaitGenesis(bootstrap) => {
                self.pending_genesis_head = Some(bootstrap);
                self.canonical_head = None;
            }
            CanonicalHeadStartupPlan::Bootstrap(bootstrap) => {
                let outcome = self
                    .canonical_head_store
                    .bootstrap_canonical_head(&bootstrap)
                    .await?;
                let current = Self::require_published_outcome(
                    "startup bootstrap",
                    outcome,
                )?;
                self.canonical_head_store
                    .ensure_coordinator_rollback_floor(&current)
                    .await?;
                self.canonical_head = Some(current);
            }
            CanonicalHeadStartupPlan::Current(current) => {
                // Starting rollback moves the canonical identity into the new
                // epoch before target restoration. That active epoch has no
                // normal-commit floor yet and must remain restartable. The
                // target floor is established only after the restored head is
                // idle, before the first new-branch normal commit.
                if current.rollback_control().is_idle() {
                    self.canonical_head_store
                        .ensure_coordinator_rollback_floor(&current)
                        .await?;
                }
                self.canonical_head = Some(current);
            }
            CanonicalHeadStartupPlan::PublishMaterialized(sealed) => {
                self.canonical_head_store
                    .ensure_coordinator_rollback_floor(sealed.expected())
                    .await?;
                let source = self
                    .canonical_head_store
                    .read_coordinator_commit_source(
                        sealed.candidate().canonical_ref(),
                    )
                    .await?
                    .ok_or_else(|| anyhow::anyhow!(
                        "materialized Coordinator checkpoint cannot be published because its durable commit source is missing"
                    ))?;
                if source.expected_revision()
                    != sealed.expected().revision().get()
                    || source.expected()
                        != sealed.expected().canonical_ref()
                    || source.candidate()
                        != sealed.candidate().canonical_ref()
                {
                    anyhow::bail!(
                        "materialized Coordinator checkpoint commit source does not match startup canonical-head transition"
                    );
                }
                self.canonical_head_store
                    .mark_coordinator_commit_source_committed(&source)
                    .await?;
                let outcome = self
                    .canonical_head_store
                    .compare_and_set_canonical_head(&sealed)
                    .await?;
                self.canonical_head = Some(Self::require_published_outcome(
                    "startup reconcile",
                    outcome,
                )?);
            }
        }
        Ok(())
    }

    async fn publish_canonical_head(
        &mut self,
        checkpoint_id: u64,
        checkpoint_hash: N::QHash,
        commit_source: Option<&CoordinatorCommitSource<N::QHash>>,
    ) -> anyhow::Result<()> {
        let checkpoint = CheckpointRef::new(
            CheckpointId::new(checkpoint_id),
            CheckpointHash::from_last_chain_hash(checkpoint_hash),
        );
        let published = if checkpoint_id == 0 {
            if commit_source.is_some() {
                anyhow::bail!("genesis canonical-head publish cannot consume a normal commit source");
            }
            let bootstrap = self.pending_genesis_head.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "genesis canonical-head publish requires an explicit pending GENESIS_NATIVE bootstrap"
                )
            })?;
            if bootstrap.candidate().canonical_ref().checkpoint() != &checkpoint
                || bootstrap.candidate().canonical_ref().network_id() != self.network_id
            {
                anyhow::bail!(
                    "materialized genesis does not match the sealed canonical-head bootstrap"
                );
            }
            let outcome = self
                .canonical_head_store
                .bootstrap_canonical_head(bootstrap)
                .await?;
            Self::require_published_outcome("genesis publish", outcome)?
        } else {
            let source = commit_source.ok_or_else(|| anyhow::anyhow!(
                "normal checkpoint canonical-head publish requires an exact COMMITTED source"
            ))?;
            let expected = self.canonical_head.ok_or_else(|| {
                anyhow::anyhow!(
                    "normal checkpoint {} cannot publish before canonical-head bootstrap",
                    checkpoint_id
                )
            })?;
            let proposed = CanonicalChainRef::new(
                self.network_id,
                expected.canonical_ref().chain_epoch(),
                checkpoint,
            );
            if source.expected_revision() != expected.revision().get()
                || source.expected() != expected.canonical_ref()
                || source.candidate() != &proposed
            {
                anyhow::bail!(
                    "normal checkpoint commit source does not match final canonical-head transition"
                );
            }
            let sealed = CanonicalHeadTransition::normal_checkpoint_advance(
                expected,
                proposed,
            )?
            .seal();
            let outcome = self
                .canonical_head_store
                .compare_and_set_canonical_head(&sealed)
                .await?;
            Self::require_published_outcome("normal final publish", outcome)?
        };
        self.canonical_head = Some(published);
        self.pending_genesis_head = None;
        Ok(())
    }

    pub async fn ensure_genesis_applied(
        &mut self,
        genesis_block_update: PsyPreparedCoordinatorBlockStateUpdates<N::F, N::QHash>,
    ) -> anyhow::Result<()> {
        // Check if genesis has already been applied
        let database_check_state = self.get_database_check_state().await?;
        if database_check_state == DatabaseCheckState::NeedsGenesis {
            tracing::info!("Applying genesis block setup data to coordinator processor database...");
            self.commit_state(genesis_block_update, ProvingJobCircuitType::GenesisBlockCheckpointStateTransition, vec![])
                .await?;
            tracing::info!("Genesis block setup data applied to coordinator processor database.");
        }
        Ok(())
    }

    pub async fn ensure_genesis_applied_from_setup_data(&mut self, genesis_data: &PsyGenesisBlockSetupData<N::F, N::QHash>) -> anyhow::Result<()> {
        // Check if genesis has already been applied
        let database_check_state = self.get_database_check_state().await?;
        if database_check_state == DatabaseCheckState::NeedsGenesis {
            tracing::info!("Applying genesis block setup data to coordinator processor database...");
            let (_, genesis_block_update) = GenesisDatabaseDataBuilder::setup_for_coordinator::<N::HasherBase, N>(
                &genesis_data,
                self.circuit_fingerprint_config.checkpoint_state_transition_circuit_fingerprint,
            )?;
            self.commit_state(genesis_block_update, ProvingJobCircuitType::GenesisBlockCheckpointStateTransition, vec![])
                .await?;
            tracing::info!("Genesis block setup data applied to coordinator processor database.");
        }
        Ok(())
    }
    pub async fn get_latest_checkpoint_id_internal(&self) -> anyhow::Result<u64> {
        self.db.get_latest_checkpoint_id().await
    }
    pub async fn get_current_unique_pending_id_internal(&self) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)> {
        self.db.get_current_unique_pending_id().await
    }

    /// Rebuild Coordinator process-local state after the global physical
    /// restore has reached VERIFYING. The durable target rows are read-only in
    /// this step: only the derived checkpoint backup, in-memory processor
    /// state, and temporary pending identities are rebuilt. Publishing the
    /// target canonical head remains a later global-barrier transition.
    pub async fn rebuild_coordinator_runtime_after_rollback(
        &mut self,
    ) -> anyhow::Result<Option<RollbackRuntimeRebuildReport<N::QHash>>>
    where
        S: CoordinatorRollbackRuntimeRebuildStore<N::QHash>,
    {
        let verifying_head = match self
            .canonical_head_store
            .read_canonical_head(self.network_id)
            .await?
        {
            CanonicalHeadReadState::Current(head) => head,
            CanonicalHeadReadState::Uninitialized => {
                anyhow::bail!("Coordinator canonical head is missing during rollback runtime rebuild")
            }
        };
        if !matches!(
            verifying_head.rollback_control(),
            psy_node_core::store::rollback_control::RollbackControlState::Verifying(_)
        ) {
            anyhow::bail!("Coordinator rollback runtime rebuild requires VERIFYING")
        }
        self.canonical_head = Some(verifying_head);

        let Some(directive) = self
            .db
            .read_selected_coordinator_runtime_rebuild(self.network_id)
            .await?
        else {
            return Ok(None);
        };
        if directive.authority() != AuthorityScope::Coordinator
            || directive.target().network_id() != self.network_id
        {
            anyhow::bail!("Coordinator rollback runtime directive identity mismatch")
        }
        let processing = directive.processing().ok_or_else(|| {
            anyhow::anyhow!("Coordinator rollback runtime directive is missing processing")
        })?;
        let gathering = directive.gathering().ok_or_else(|| {
            anyhow::anyhow!("Coordinator rollback runtime directive is missing gathering")
        })?;
        let target_checkpoint = directive.target().checkpoint().checkpoint_id().get();

        // Validate every durable input before touching the derived backup file
        // or process-local state. The physical restore executor must already
        // have made the target the latest visible checkpoint.
        let latest_checkpoint = self.db.get_latest_checkpoint_id().await?;
        if latest_checkpoint != target_checkpoint {
            anyhow::bail!(
                "Coordinator rollback target is not the latest restored checkpoint: target={}, latest={}",
                target_checkpoint,
                latest_checkpoint,
            )
        }
        let checkpoint_leaf = self.db.get_checkpoint_leaf_data(target_checkpoint).await?;
        let checkpoint_state_roots = self
            .db
            .get_checkpoint_global_state_roots(target_checkpoint)
            .await?;
        let l2_state = self.db.get_l2_block_state(target_checkpoint).await?;
        if l2_state.checkpoint_id != target_checkpoint {
            anyhow::bail!(
                "Coordinator restored L2 state checkpoint mismatch: target={}, state={}",
                target_checkpoint,
                l2_state.checkpoint_id,
            )
        }
        let checkpoint_root = self
            .db
            .checkpoint_tree_get_root_hash(target_checkpoint)
            .await?;
        let checkpoint_leaf_hash = checkpoint_leaf.qfhash::<N::HasherBase>();
        let checkpoint_state_transition = if target_checkpoint == 0 {
            self.genesis_verifiable_state_transition
                .state_transition
                .checkpoint_transition
                .clone()
        } else {
            CheckpointStateHashTransition {
                old_checkpoint_tree_root: self
                    .db
                    .checkpoint_tree_get_root_hash(target_checkpoint - 1)
                    .await?,
                new_checkpoint_tree_root: checkpoint_root,
                old_checkpoint_leaf_hash: self
                    .db
                    .checkpoint_tree_get_leaf_hash(target_checkpoint, target_checkpoint - 1)
                    .await?,
                new_checkpoint_leaf_hash: checkpoint_leaf_hash,
            }
        };

        let last_chain_hash = if target_checkpoint == 0 {
            genesis_checkpoint_hash::<_, N::HasherBase>(
                checkpoint_root,
                checkpoint_leaf_hash,
                self.circuit_fingerprint_config
                    .genesis_checkpoint_state_transition_fingerprint,
            )
            .into_inner()
        } else {
            let stored = self
                .db
                .get_verifiable_checkpoint_state_transition_and_zkp(target_checkpoint)
                .await?;
            let proof_checkpoint_hash =
                checkpoint_hash_from_saved_proof_bytes::<N::QHash, N::ZKProof, N::ZKVerifier>(
                    &stored.zk_proof,
                )?
                .into_inner();
            let parent_checkpoint_hash = if target_checkpoint == 1 {
                let parent_root = self.db.checkpoint_tree_get_root_hash(0).await?;
                let parent_leaf_hash = self
                    .db
                    .get_checkpoint_leaf_data(0)
                    .await?
                    .qfhash::<N::HasherBase>();
                genesis_checkpoint_hash::<_, N::HasherBase>(
                    parent_root,
                    parent_leaf_hash,
                    self.circuit_fingerprint_config
                        .genesis_checkpoint_state_transition_fingerprint,
                )
                .into_inner()
            } else {
                let parent = self
                    .db
                    .get_verifiable_checkpoint_state_transition_and_zkp(target_checkpoint - 1)
                    .await?;
                checkpoint_hash_from_saved_proof_bytes::<N::QHash, N::ZKProof, N::ZKVerifier>(
                    &parent.zk_proof,
                )?
                .into_inner()
            };
            ensure_non_genesis_checkpoint_chain_commitment::<
                N::F,
                N::QHash,
                N::HasherBase,
            >(
                target_checkpoint,
                parent_checkpoint_hash,
                checkpoint_root,
                checkpoint_leaf_hash,
                self.circuit_fingerprint_config
                    .checkpoint_state_transition_circuit_fingerprint,
                proof_checkpoint_hash,
            )?;
            proof_checkpoint_hash
        };
        if last_chain_hash
            != *directive
                .target()
                .checkpoint()
                .checkpoint_hash()
                .as_inner()
        {
            anyhow::bail!("Coordinator rollback target chain hash mismatch")
        }

        let required_history_start = target_checkpoint
            .saturating_sub(STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF)
            .max(if target_checkpoint
                >= self.checkpoint_tree_backup_manager.max_checkpoints_to_keep
            {
                target_checkpoint
                    - self.checkpoint_tree_backup_manager.max_checkpoints_to_keep
                    + 1
            } else {
                0
            });
        self.checkpoint_tree_backup_manager
            .hard_reset_and_truncate(required_history_start)
            .await?;
        self.checkpoint_tree_backup_manager
            .sync_from_database::<S>(&self.db, 1000, target_checkpoint)
            .await?;
        if self
            .checkpoint_tree_backup_manager
            .get_current_checkpoint_tree_root_head()
            != checkpoint_root
        {
            anyhow::bail!("Coordinator checkpoint backup root mismatch after rollback rebuild")
        }

        self.ids.checkpoint_id = target_checkpoint;
        self.ids.next_checkpoint_id = target_checkpoint
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Coordinator rollback target checkpoint overflow"))?;
        self.ids.unique_pending_id = processing.pending_id().get();
        self.ids.proc_checkpoint_unique_id = processing.proc_checkpoint_id().as_u128();
        self.ids.gathering_unique_pending_id = gathering.pending_id().get();
        self.ids.gathering_proc_checkpoint_unique_id = gathering.proc_checkpoint_id().as_u128();
        self.last_committed = CoordinatorProcessorLastCommittedState {
            l2_state: l2_state.clone(),
            checkpoint_leaf_stats: checkpoint_leaf.stats.clone(),
            checkpoint_leaf: checkpoint_leaf.clone(),
            checkpoint_state_roots: checkpoint_state_roots.clone(),
            checkpoint_state_transition,
            checkpoint_root,
            checkpoint_leaf_hash,
            last_chain_hash,
        };
        self.temp_db
            .set_unique_pending_ids(
                &self.ids.realm_identifier,
                self.ids.unique_pending_id,
                self.ids.proc_checkpoint_unique_id,
            )
            .await?;
        self.temp_db
            .set_gathering_unique_pending_ids(
                &self.ids.realm_identifier,
                self.ids.gathering_unique_pending_id,
                self.ids.gathering_proc_checkpoint_unique_id,
            )
            .await?;
        self.temp_db
            .clear_current_pending_context(&self.ids.realm_identifier)
            .await?;
        self.shared_status.update_status(
            self.ids.unique_pending_id,
            target_checkpoint,
            checkpoint_leaf.clone(),
            checkpoint_state_roots.clone(),
            l2_state.clone(),
            false,
        )?;
        self.needs_revert = false;

        // Bracket the process-local mutation with fresh target reads before
        // producing durable completion evidence.
        if self.db.get_latest_checkpoint_id().await? != target_checkpoint
            || self
                .db
                .checkpoint_tree_get_root_hash(target_checkpoint)
                .await?
                != checkpoint_root
            || self.db.get_l2_block_state(target_checkpoint).await? != l2_state
            || self
                .db
                .get_checkpoint_global_state_roots(target_checkpoint)
                .await?
                != checkpoint_state_roots
        {
            anyhow::bail!("Coordinator restored target changed during runtime rebuild")
        }
        let report = RollbackRuntimeRebuildReport::try_after_exact_rebuild(
            &directive,
            self.checkpoint_tree_backup_manager
                .min_backed_up_checkpoint_id,
            self.checkpoint_tree_backup_manager
                .next_backup_checkpoint_id,
            self.checkpoint_tree_backup_manager
                .get_current_checkpoint_tree_root_head(),
            self.ids.checkpoint_id,
            l2_state.checkpoint_id,
            checkpoint_state_roots.qfhash::<N::HasherBase>(),
            Some(processing),
            Some(gathering),
        )?;
        self.db
            .persist_coordinator_runtime_rebuild_report(directive, report)
            .await?;
        tracing::warn!(
            "Coordinator rollback runtime rebuilt at checkpoint {} with processing {} and gathering {}",
            target_checkpoint,
            processing.pending_id().get(),
            gathering.pending_id().get(),
        );
        Ok(Some(report))
    }

    /// Re-select the immutable rollback restart directive while VERIFYING or
    /// ALL_REALMS_READY is still durable. The runner retains this exact value
    /// across target publication because an Idle head intentionally no longer
    /// exposes the maintenance selector.
    pub async fn read_selected_coordinator_runtime_rebuild(
        &self,
    ) -> anyhow::Result<Option<RollbackRuntimeRebuildDirective<N::QHash>>>
    where
        S: CoordinatorRollbackRuntimeRebuildStore<N::QHash>,
    {
        self.db
            .read_selected_coordinator_runtime_rebuild(self.network_id)
            .await
    }

    pub async fn try_publish_restored_runtime(
        &mut self,
    ) -> anyhow::Result<CoordinatorRollbackRuntimePublication<N::QHash>>
    where
        S: CoordinatorRollbackRuntimeRebuildStore<N::QHash>,
    {
        let outcome = self.db.try_publish_restored_runtime(self.network_id).await?;
        if let CoordinatorRollbackRuntimePublication::Published(head) = outcome {
            if !head.rollback_control().is_idle()
                || head.canonical_ref().network_id() != self.network_id
                || head.canonical_ref().checkpoint().checkpoint_id().get()
                    != self.ids.checkpoint_id
            {
                anyhow::bail!("published rollback target differs from rebuilt Coordinator runtime");
            }
            self.canonical_head = Some(head);
            self.publish_current_pending_context().await?;
        }
        Ok(outcome)
    }

    async fn copy_checkpoint_backup_file_for_reset(&mut self, destination_path: &str) -> anyhow::Result<()> {
        let source_path = self.checkpoint_tree_backup_manager.backup_file_path.clone();
        self.checkpoint_tree_backup_manager
            .file_system
            .file_like_fs_sync_file_with_path(&source_path, &mut self.checkpoint_tree_backup_manager.backup_file)
            .await?;

        let mut source = self.checkpoint_tree_backup_manager.file_system.file_like_fs_open(&source_path).await?;
        let mut destination = self
            .checkpoint_tree_backup_manager
            .file_system
            .file_like_fs_create(destination_path)
            .await?;
        source.seek(std::io::SeekFrom::Start(0)).await?;
        destination.seek(std::io::SeekFrom::Start(0)).await?;
        destination.file_like_set_len(0).await?;

        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let bytes_read = source.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }
            destination.write_all(&buffer[..bytes_read]).await?;
        }
        self.checkpoint_tree_backup_manager
            .file_system
            .file_like_fs_sync_file_with_path(destination_path, &mut destination)
            .await?;
        Ok(())
    }

    async fn backup_before_reset(
        &mut self,
        target_checkpoint_id: u64,
        latest_checkpoint_id: u64,
        unique_pending_id: u64,
        proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
    ) -> anyhow::Result<String> {
        let timestamp_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        let backup_dir = format!(
            "{}.reset_backups/reset_{}_from_{}_to_{}",
            self.checkpoint_tree_backup_manager.backup_file_path,
            timestamp_ms,
            latest_checkpoint_id,
            target_checkpoint_id
        );
        self.checkpoint_tree_backup_manager
            .file_system
            .file_like_fs_create_dir_all(&backup_dir)
            .await?;

        let checkpoint_backup_copy_path = format!("{}/checkpoint_tree_backup.copy", backup_dir);
        let checkpoint_backup_copy_status = match self.copy_checkpoint_backup_file_for_reset(&checkpoint_backup_copy_path).await {
            Ok(()) => "ok".to_string(),
            Err(e) => {
                tracing::warn!(
                    "Failed to copy checkpoint backup file before coordinator reset; continuing because reset state is sourced from DB: {:?}",
                    e
                );
                format!("failed: {e:?}")
            }
        };

        let old_pending_checkpoint_mapping = self.db.get_checkpoint_id_for_unique_pending_id(unique_pending_id).await?;
        let old_target_checkpoint_pending_mapping = self.db.get_unique_pending_id_for_checkpoint_id(target_checkpoint_id).await?;
        let old_latest_l2_state = self.db.get_l2_block_state(latest_checkpoint_id).await?;
        let old_latest_checkpoint_root = self.db.checkpoint_tree_get_root_hash(latest_checkpoint_id).await?;

        let manifest = format!(
            "\
reset_backup_version=1
reset_state_source=db
created_at_unix_ms={timestamp_ms}
target_checkpoint_id={target_checkpoint_id}
latest_checkpoint_id_before_reset={latest_checkpoint_id}
unique_pending_id_before_reset={unique_pending_id}
proc_checkpoint_unique_id_before_reset={proc_checkpoint_unique_id}
old_unique_pending_id_to_checkpoint_id_mapping={old_pending_checkpoint_mapping:?}
old_target_checkpoint_id_to_unique_pending_id_mapping={old_target_checkpoint_pending_mapping:?}
old_latest_l2_state={old_latest_l2_state:?}
old_latest_checkpoint_root={}
checkpoint_backup_source_path={}
checkpoint_backup_copy_path={}
checkpoint_backup_copy_status={}
",
            old_latest_checkpoint_root.psy_debug_print(),
            self.checkpoint_tree_backup_manager.backup_file_path,
            checkpoint_backup_copy_path,
            checkpoint_backup_copy_status
        );
        let manifest_path = format!("{}/reset_manifest.txt", backup_dir);
        let mut manifest_file = self
            .checkpoint_tree_backup_manager
            .file_system
            .file_like_fs_create(&manifest_path)
            .await?;
        manifest_file.file_like_set_len(0).await?;
        manifest_file.write_all(manifest.as_bytes()).await?;
        self.checkpoint_tree_backup_manager
            .file_system
            .file_like_fs_sync_file_with_path(&manifest_path, &mut manifest_file)
            .await?;

        tracing::warn!(
            "Coordinator reset pre-backup complete. manifest={}, checkpoint_backup_copy={}, checkpoint_backup_copy_status={}",
            manifest_path,
            checkpoint_backup_copy_path,
            checkpoint_backup_copy_status
        );
        Ok(backup_dir)
    }

    pub async fn reset_to_checkpoint(&mut self, checkpoint_id: u64) -> anyhow::Result<()> {
        if self.canonical_head.is_some() {
            anyhow::bail!(
                "legacy reset_to_checkpoint is disabled once canonical-head authority is active; use the future C-01 rollback control/executor"
            );
        }
        let latest_checkpoint_id = self.db.get_latest_checkpoint_id().await?;
        if checkpoint_id > latest_checkpoint_id {
            anyhow::bail!(
                "Cannot reset coordinator to checkpoint {} because latest checkpoint is {}",
                checkpoint_id,
                latest_checkpoint_id
            );
        }

        tracing::warn!(
            "Resetting coordinator processor from checkpoint {} to checkpoint {}",
            latest_checkpoint_id,
            checkpoint_id
        );

        let checkpoint_leaf = self.db.get_checkpoint_leaf_data(checkpoint_id).await?;
        let checkpoint_state_roots = self.db.get_checkpoint_global_state_roots(checkpoint_id).await?;
        let l2_state = self.db.get_l2_block_state(checkpoint_id).await?;
        let checkpoint_root = self.db.checkpoint_tree_get_root_hash(checkpoint_id).await?;
        let checkpoint_leaf_hash = checkpoint_leaf.qfhash::<N::HasherBase>();
        let checkpoint_state_transition = if checkpoint_id == 0 {
            self.genesis_verifiable_state_transition.state_transition.checkpoint_transition.clone()
        } else {
            CheckpointStateHashTransition {
                old_checkpoint_tree_root: self.db.checkpoint_tree_get_root_hash(checkpoint_id - 1).await?,
                new_checkpoint_tree_root: checkpoint_root,
                old_checkpoint_leaf_hash: self.db.checkpoint_tree_get_leaf_hash(checkpoint_id, checkpoint_id - 1).await?,
                new_checkpoint_leaf_hash: checkpoint_leaf_hash,
            }
        };

        // Validate the target's canonical chain identity before any reset-side
        // mutation (backup truncate, mapping rewrite, or singleton update).
        let last_chain_hash = if checkpoint_id == 0 {
            genesis_checkpoint_hash::<_, N::HasherBase>(
                checkpoint_root,
                checkpoint_leaf_hash,
                self.circuit_fingerprint_config
                    .genesis_checkpoint_state_transition_fingerprint,
            )
            .into_inner()
        } else {
            let stored = self
                .db
                .get_verifiable_checkpoint_state_transition_and_zkp(checkpoint_id)
                .await?;
            let proof_checkpoint_hash =
                checkpoint_hash_from_saved_proof_bytes::<N::QHash, N::ZKProof, N::ZKVerifier>(
                    &stored.zk_proof,
                )?
                .into_inner();
            let parent_checkpoint_hash = if checkpoint_id == 1 {
                let parent_root = self.db.checkpoint_tree_get_root_hash(0).await?;
                let parent_leaf_hash = self.db.get_checkpoint_leaf_data(0).await?.qfhash::<N::HasherBase>();
                genesis_checkpoint_hash::<_, N::HasherBase>(
                    parent_root,
                    parent_leaf_hash,
                    self.circuit_fingerprint_config
                        .genesis_checkpoint_state_transition_fingerprint,
                )
                .into_inner()
            } else {
                let parent = self
                    .db
                    .get_verifiable_checkpoint_state_transition_and_zkp(checkpoint_id - 1)
                    .await?;
                checkpoint_hash_from_saved_proof_bytes::<N::QHash, N::ZKProof, N::ZKVerifier>(
                    &parent.zk_proof,
                )?
                .into_inner()
            };
            ensure_non_genesis_checkpoint_chain_commitment::<N::F, N::QHash, N::HasherBase>(
                checkpoint_id,
                parent_checkpoint_hash,
                checkpoint_root,
                checkpoint_leaf_hash,
                self.circuit_fingerprint_config
                    .checkpoint_state_transition_circuit_fingerprint,
                proof_checkpoint_hash,
            )?;
            proof_checkpoint_hash
        };

        let (unique_pending_id, proc_checkpoint_unique_id) = self
            .db
            .get_current_unique_pending_id()
            .await
            .unwrap_or((self.ids.unique_pending_id, self.ids.proc_checkpoint_unique_id));
        let reset_backup_dir = self
            .backup_before_reset(checkpoint_id, latest_checkpoint_id, unique_pending_id, proc_checkpoint_unique_id)
            .await?;

        // Reset target state is read only from DB. The checkpoint backup file is
        // rebuilt from DB and is not used as a source of truth for reset.
        let required_history_start = checkpoint_id.saturating_sub(STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF).max(
            if checkpoint_id >= self.checkpoint_tree_backup_manager.max_checkpoints_to_keep {
                checkpoint_id - self.checkpoint_tree_backup_manager.max_checkpoints_to_keep + 1
            } else {
                0
            },
        );
        self.checkpoint_tree_backup_manager
            .hard_reset_and_truncate(required_history_start)
            .await?;
        self.checkpoint_tree_backup_manager
            .sync_from_database::<S>(&self.db, 1000, checkpoint_id)
            .await?;

        // Keep the pending-id counter monotonic, but make the current pending id
        // point at the reset checkpoint so startup consistency checks pass after
        // this administrative rollback.
        self.db
            .set_unique_pending_id_checkpoint_id_mapping(unique_pending_id, checkpoint_id)
            .await?;
        self.db
            .set_checkpoint_id_to_unique_pending_id_mapping(checkpoint_id, unique_pending_id, &proc_checkpoint_unique_id)
            .await?;
        self.db.set_l2_latest_block_state(&l2_state).await?;
        self.db.set_latest_checkpoint_id(checkpoint_id).await?;

        self.ids.checkpoint_id = checkpoint_id;
        self.ids.next_checkpoint_id = checkpoint_id + 1;
        self.ids.unique_pending_id = unique_pending_id;
        self.ids.proc_checkpoint_unique_id = proc_checkpoint_unique_id;
        self.ids.gathering_unique_pending_id = unique_pending_id;
        self.ids.gathering_proc_checkpoint_unique_id = proc_checkpoint_unique_id;
        self.last_committed = CoordinatorProcessorLastCommittedState {
            l2_state: l2_state.clone(),
            checkpoint_leaf_stats: checkpoint_leaf.stats.clone(),
            checkpoint_leaf: checkpoint_leaf.clone(),
            checkpoint_state_roots: checkpoint_state_roots.clone(),
            checkpoint_state_transition,
            checkpoint_root,
            checkpoint_leaf_hash,
            last_chain_hash,
        };
        self.temp_db
            .set_unique_pending_ids(&self.ids.realm_identifier, unique_pending_id, proc_checkpoint_unique_id)
            .await?;
        self.temp_db
            .set_gathering_unique_pending_ids(&self.ids.realm_identifier, unique_pending_id, proc_checkpoint_unique_id)
            .await?;
        self.shared_status
            .update_status(unique_pending_id, checkpoint_id, checkpoint_leaf, checkpoint_state_roots, l2_state, true)?;
        // reset_to_checkpoint has already rebuilt DB / checkpoint-tree / in-memory state to the
        // target. The current process_block path silently clears needs_revert without acting on
        // it (see bugs.md CP-1), so setting it here is a no-op today; once CP-1 is fixed to bail!
        // on the flag this signal must be re-evaluated.
        self.needs_revert = true;
        tracing::info!(
            "Coordinator processor reset complete. checkpoint_id={}, next_checkpoint_id={}, unique_pending_id={}, gathering_unique_pending_id={}, reset_backup_dir={}",
            self.ids.checkpoint_id,
            self.ids.next_checkpoint_id,
            self.ids.unique_pending_id,
            self.ids.gathering_unique_pending_id,
            reset_backup_dir
        );
        Ok(())
    }
    /// Install the exact processing/gathering pair allocated by the durable
    /// rollback restore. Startup must not increment the pending counter here:
    /// doing so would skip the globally verified generation immediately after
    /// publishing the restored target.
    async fn resume_rollback_unique_ids(
        &mut self,
        directive: &RollbackRuntimeRebuildDirective<N::QHash>,
    ) -> anyhow::Result<()> {
        if directive.authority() != AuthorityScope::Coordinator
            || directive.target().network_id() != self.network_id
            || directive.target().checkpoint().checkpoint_id().get() != self.ids.checkpoint_id
        {
            anyhow::bail!("Coordinator rollback restart directive identity mismatch")
        }
        let processing = directive.processing().ok_or_else(|| {
            anyhow::anyhow!("Coordinator rollback restart directive is missing processing")
        })?;
        let gathering = directive.gathering().ok_or_else(|| {
            anyhow::anyhow!("Coordinator rollback restart directive is missing gathering")
        })?;
        if gathering.pending_id().get()
            != processing
                .pending_id()
                .get()
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("Coordinator rollback pending namespace overflow"))?
        {
            anyhow::bail!("Coordinator rollback restart pending contexts are not adjacent")
        }
        let head = self
            .canonical_head
            .ok_or_else(|| anyhow::anyhow!("Coordinator rollback restart canonical head is missing"))?;
        match head.rollback_control() {
            psy_node_core::store::rollback_control::RollbackControlState::Verifying(request)
            | psy_node_core::store::rollback_control::RollbackControlState::AllRealmsReady(
                request,
            ) => {
                if head.canonical_ref().network_id() != directive.target().network_id()
                    || head.canonical_ref().chain_epoch() != directive.target().chain_epoch()
                    || request.target() != directive.target().checkpoint()
                    || request.plan_digest().as_bytes() != directive.participant_plan_digest()
                {
                    anyhow::bail!(
                        "Coordinator rollback restart directive does not match active request"
                    )
                }
            }
            psy_node_core::store::rollback_control::RollbackControlState::Idle => {
                if head.canonical_ref() != directive.target() {
                    anyhow::bail!(
                        "Coordinator rollback restart directive does not match published target"
                    )
                }
            }
            _ => anyhow::bail!(
                "Coordinator rollback restart requires VERIFYING, ALL_REALMS_READY, or published target"
            ),
        }
        let durable_current = self.db.get_current_unique_pending_id().await?;
        if durable_current
            != (
                gathering.pending_id().get(),
                QCoreProcCheckpointUniqueId::from(
                    gathering.proc_checkpoint_id().as_u128(),
                ),
            )
        {
            anyhow::bail!(
                "Coordinator rollback gathering context is not the durable current pending"
            )
        }

        self.guta_update_queue.ensure_stream().await?;
        self.register_user_queue.ensure_stream().await?;
        self.deploy_contract_queue.ensure_stream().await?;
        self.proof_work_queue.ensure_stream().await?;
        let realm_id = self.ids.realm_id_u64;
        let realm_sub_id = self.ids.realm_sub_id_u64;
        for proc_id in [processing.proc_checkpoint_id(), gathering.proc_checkpoint_id()] {
            let unique_id = proc_id.as_u128();
            let guta_key = CoordinatorSubmitRealmGUTAUpdateQueueKey {
                realm_id,
                realm_sub_id,
                unique_id,
                task_group: 0,
                queue_type: QPBaseQueueType::StandardEphemeral,
                _phantom_queue_item: std::marker::PhantomData::<
                    CoordinatorGutaQueueItem<N::F, N::QHash>,
                >,
            };
            let registration_key = CoordinatorRegisterUserPublicKeyQueueKey {
                realm_id,
                realm_sub_id,
                unique_id,
                task_group: 0,
                queue_type: QPBaseQueueType::StandardEphemeral,
                _phantom_queue_item: std::marker::PhantomData::<PZKPublicKeyInfo<N::QHash>>,
            };
            let deploy_key = CoordinatorDeployContractQueueKey {
                realm_id,
                realm_sub_id,
                unique_id,
                task_group: 0,
                queue_type: QPBaseQueueType::StandardEphemeral,
                _phantom_queue_item: std::marker::PhantomData::<
                    PsyDeployContractQueueItem<N::F, N::QHash>,
                >,
            };
            let proof_key = CoordinatorProvingWorkQueueKey {
                realm_id,
                realm_sub_id,
                unique_id,
                task_group: 0,
                queue_type: QPBaseQueueType::WorkerQueue,
                _phantom_queue_item: std::marker::PhantomData::<
                    PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>,
                >,
            };
            self.guta_update_queue
                .ensure_consumer(&guta_key, realm_id, realm_sub_id, unique_id, 0)
                .await?;
            self.register_user_queue
                .ensure_consumer(&registration_key, realm_id, realm_sub_id, unique_id, 0)
                .await?;
            self.deploy_contract_queue
                .ensure_consumer(&deploy_key, realm_id, realm_sub_id, unique_id, 0)
                .await?;
            self.proof_work_queue
                .ensure_consumer(&proof_key, realm_id, realm_sub_id, unique_id, 0)
                .await?;
        }

        self.ids.unique_pending_id = processing.pending_id().get();
        self.ids.proc_checkpoint_unique_id = processing.proc_checkpoint_id().as_u128();
        self.ids.gathering_unique_pending_id = gathering.pending_id().get();
        self.ids.gathering_proc_checkpoint_unique_id = gathering.proc_checkpoint_id().as_u128();
        let gathering_proc = gathering.proc_checkpoint_id().as_u128();
        self.guta_queue_key_status_manager
            .set_unique_id(gathering_proc)?;
        self.register_user_queue_key_status_manager
            .set_unique_id(gathering_proc)?;
        self.deploy_contract_queue_key_status_manager
            .set_unique_id(gathering_proc)?;
        self.temp_db
            .set_unique_pending_ids(
                &self.ids.realm_identifier,
                self.ids.unique_pending_id,
                self.ids.proc_checkpoint_unique_id,
            )
            .await?;
        self.temp_db
            .set_gathering_unique_pending_ids(
                &self.ids.realm_identifier,
                self.ids.gathering_unique_pending_id,
                self.ids.gathering_proc_checkpoint_unique_id,
            )
            .await?;
        if head.rollback_control().is_idle() {
            self.publish_current_pending_context().await?;
        } else {
            self.temp_db
                .clear_current_pending_context(&self.ids.realm_identifier)
                .await?;
        }
        Ok(())
    }

    pub async fn set_new_unique_ids(&mut self) -> anyhow::Result<()> {
        println!(
            "old_unique_pending_id: {}, old_proc_checkpoint_unique_id: {}",
            self.ids.unique_pending_id, self.ids.proc_checkpoint_unique_id
        );
        println!(
            "old_gathering_unique_pending_id: {}, old_gathering_proc_checkpoint_unique_id: {}",
            self.ids.gathering_unique_pending_id, self.ids.gathering_proc_checkpoint_unique_id
        );
        // 1. ID rotation logic
        let (new_unique_pending_id, new_core_proc_unique_pending_id) = self.db.inc_unique_pending_id(1).await?;

        // 2. Ensure streams exist
        self.guta_update_queue.ensure_stream().await?;
        self.register_user_queue.ensure_stream().await?;
        self.deploy_contract_queue.ensure_stream().await?;
        self.proof_work_queue.ensure_stream().await?;

        // 3. Only create consumers for new gathering unique_id
        let realm_id = self.ids.realm_id_u64;
        let realm_sub_id = self.ids.realm_sub_id_u64;
        let unique_id = new_core_proc_unique_pending_id;

        // 4. Create consumers for gathering proc_checkpoint_unique_id, and also for processing if it's 0 (genesis case)
        let gathering_proc_id = self.ids.gathering_proc_checkpoint_unique_id;
        let should_create_genesis_consumers = gathering_proc_id == QCoreProcCheckpointUniqueId::from(0u128);

        let guta_key = CoordinatorSubmitRealmGUTAUpdateQueueKey {
            realm_id, realm_sub_id, unique_id, task_group: 0,
            queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: std::marker::PhantomData::<CoordinatorGutaQueueItem<N::F, N::QHash>>,
        };
        let user_reg_key = CoordinatorRegisterUserPublicKeyQueueKey {
            realm_id, realm_sub_id, unique_id, task_group: 0,
            queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: std::marker::PhantomData::<PZKPublicKeyInfo<N::QHash>>,
        };
        let deploy_key = CoordinatorDeployContractQueueKey {
            realm_id, realm_sub_id, unique_id, task_group: 0,
            queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: std::marker::PhantomData::<PsyDeployContractQueueItem<N::F, N::QHash>>,
        };
        let proof_key = CoordinatorProvingWorkQueueKey {
            realm_id, realm_sub_id, unique_id, task_group: 0,
            queue_type: QPBaseQueueType::WorkerQueue, _phantom_queue_item: std::marker::PhantomData::<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>,
        };

        // Create consumers for gathering proc_id
        self.guta_update_queue.ensure_consumer(&guta_key, realm_id, realm_sub_id, unique_id, 0).await?;
        self.register_user_queue.ensure_consumer(&user_reg_key, realm_id, realm_sub_id, unique_id, 0).await?;
        self.deploy_contract_queue.ensure_consumer(&deploy_key, realm_id, realm_sub_id, unique_id, 0).await?;
        self.proof_work_queue.ensure_consumer(&proof_key, realm_id, realm_sub_id, unique_id, 0).await?;

        // Also create consumers for processing proc_id if it's 0 (genesis case)
        if should_create_genesis_consumers {
            let processing_guta_key = CoordinatorSubmitRealmGUTAUpdateQueueKey {
                realm_id, realm_sub_id, unique_id: gathering_proc_id, task_group: 0,
                queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: std::marker::PhantomData::<CoordinatorGutaQueueItem<N::F, N::QHash>>,
            };
            let processing_user_reg_key = CoordinatorRegisterUserPublicKeyQueueKey {
                realm_id, realm_sub_id, unique_id: gathering_proc_id, task_group: 0,
                queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: std::marker::PhantomData::<PZKPublicKeyInfo<N::QHash>>,
            };
            let processing_deploy_key = CoordinatorDeployContractQueueKey {
                realm_id, realm_sub_id, unique_id: gathering_proc_id, task_group: 0,
                queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: std::marker::PhantomData::<PsyDeployContractQueueItem<N::F, N::QHash>>,
            };
            let processing_proof_key = CoordinatorProvingWorkQueueKey {
                realm_id, realm_sub_id, unique_id: gathering_proc_id, task_group: 0,
                queue_type: QPBaseQueueType::WorkerQueue, _phantom_queue_item: std::marker::PhantomData::<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>,
            };

            self.guta_update_queue.ensure_consumer(&processing_guta_key, realm_id, realm_sub_id, gathering_proc_id, 0).await?;
            self.register_user_queue.ensure_consumer(&processing_user_reg_key, realm_id, realm_sub_id, gathering_proc_id, 0).await?;
            self.deploy_contract_queue.ensure_consumer(&processing_deploy_key, realm_id, realm_sub_id, gathering_proc_id, 0).await?;
            self.proof_work_queue.ensure_consumer(&processing_proof_key, realm_id, realm_sub_id, gathering_proc_id, 0).await?;
        }

        self.ids.unique_pending_id = self.ids.gathering_unique_pending_id;
        self.ids.proc_checkpoint_unique_id = self.ids.gathering_proc_checkpoint_unique_id;
        self.ids.gathering_unique_pending_id = new_unique_pending_id;
        self.ids.gathering_proc_checkpoint_unique_id = new_core_proc_unique_pending_id;

        // 5. Update temp_db
        self.temp_db.set_gathering_unique_pending_ids(&self.ids.realm_identifier, self.ids.gathering_unique_pending_id, self.ids.gathering_proc_checkpoint_unique_id).await?;
        self.temp_db.set_unique_pending_ids(&self.ids.realm_identifier, self.ids.unique_pending_id, self.ids.proc_checkpoint_unique_id).await?;
        // Publish the complete branch + authority + pending/proc identity last.
        // Edge must consume this one value instead of composing independently
        // mutable canonical-head and legacy pending-ID reads.
        self.publish_current_pending_context().await?;

        println!(
            "new_unique_pending_id: {}, new_proc_checkpoint_unique_id: {}",
            self.ids.unique_pending_id, self.ids.proc_checkpoint_unique_id
        );
        println!(
            "new_gathering_unique_pending_id: {}, new_gathering_proc_checkpoint_unique_id: {}",
            self.ids.gathering_unique_pending_id, self.ids.gathering_proc_checkpoint_unique_id
        );

        Ok(())
    }
    pub fn get_proof_worker_queue_key(&self) -> CoordinatorProvingWorkQueueKey<N::QHash, N::JobId> {
        //println!("get_proof_worker_queue_key: self.db.ids.proc_checkpoint_unique_id: {:?}", self.ids.proc_checkpoint_unique_id);

        CoordinatorProvingWorkQueueKey {
            realm_id: self.ids.realm_id_u64,
            realm_sub_id: self.ids.realm_sub_id_u64,
            unique_id: self.ids.proc_checkpoint_unique_id,
            task_group: 0,
            queue_type: QPBaseQueueType::WorkerQueue,
            _phantom_queue_item: std::marker::PhantomData,
        }
    }
    pub async fn commit_state(
        &mut self,
        coordinator_update: PsyPreparedCoordinatorBlockStateUpdates<N::F, N::QHash>,
        state_transition_circuit_type: ProvingJobCircuitType,
        zk_proof: Vec<u8>,
    ) -> anyhow::Result<()> {
        let checkpoint_id: u64 = coordinator_update.checkpoint_id;
        tracing::info!("vaidation -> Committing coordinator state update to database for checkpoint_id: {}", checkpoint_id);
        let checkpoint_leaf_hash = coordinator_update.new_base.checkpoint_leaf.qfhash::<N::HasherBase>();
        if checkpoint_leaf_hash != coordinator_update.new_base.checkpoint_leaf_hash {
            tracing::error!(
                "Computed checkpoint leaf hash: {:?}, expected checkpoint leaf hash: {:?}",
                checkpoint_leaf_hash,
                coordinator_update.new_base.checkpoint_leaf_hash
            );
            anyhow::bail!(
                "Checkpoint leaf hash mismatch when committing coordinator state update to database. Computed hash: {:?}, expected hash: {:?}",
                checkpoint_leaf_hash,
                coordinator_update.new_base.checkpoint_leaf_hash
            );
        }

        let old_checkpoint_leaf_hash = coordinator_update.old_base.checkpoint_leaf_hash;
        if old_checkpoint_leaf_hash != self.last_committed.checkpoint_leaf_hash {
            tracing::error!(
                "Computed old checkpoint leaf hash: {:?}, expected old checkpoint leaf hash: {:?}",
                self.last_committed.checkpoint_leaf_hash,
                old_checkpoint_leaf_hash
            );
            anyhow::bail!(
                "Old checkpoint leaf hash mismatch when committing coordinator state update to database. Computed hash: {:?}, expected hash: {:?}",
                self.last_committed.checkpoint_leaf_hash,
                old_checkpoint_leaf_hash
            );
        }

        if checkpoint_id != 0 {
            let expected_checkpoint_id = self.ids.checkpoint_id.checked_add(1).ok_or_else(|| {
                anyhow::anyhow!("Committed checkpoint ID overflow while validating target checkpoint {}", checkpoint_id)
            })?;
            if checkpoint_id != expected_checkpoint_id {
                anyhow::bail!(
                    "Non-sequential coordinator commit: target checkpoint ID {} must follow committed checkpoint ID {}",
                    checkpoint_id,
                    self.ids.checkpoint_id
                );
            }

            if coordinator_update.unique_pending_id != self.ids.unique_pending_id
                || coordinator_update.proc_checkpoint_unique_id
                    != self.ids.proc_checkpoint_unique_id
            {
                anyhow::bail!(
                    "Coordinator prepared pending identity does not match the active commit identity"
                );
            }

            let checkpoint_proof = &coordinator_update.checkpoint_tree_update_proof;
            if checkpoint_proof.index != checkpoint_id
                || checkpoint_proof.siblings.len() != N::CHECKPOINT_TREE_HEIGHT_USIZE
                || checkpoint_proof.old_root
                    != coordinator_update.old_base.checkpoint_tree_root
                || checkpoint_proof.old_value
                    != coordinator_update.old_base.checkpoint_leaf_hash
                || checkpoint_proof.new_root
                    != coordinator_update.new_base.checkpoint_tree_root
                || checkpoint_proof.new_value
                    != coordinator_update.new_base.checkpoint_leaf_hash
                || !checkpoint_proof.verify::<N::HasherBase>()
            {
                anyhow::bail!(
                    "Coordinator prepared checkpoint-tree delta does not match the exact normal commit"
                );
            }

            let old_checkpoint_root = self.db.checkpoint_tree_get_root_hash(self.ids.checkpoint_id).await?;
            if old_checkpoint_root != coordinator_update.old_base.checkpoint_tree_root {
                let actual_checkpoint_root = self.checkpoint_tree_backup_manager.checkpoint_tree.get_root();
                tracing::error!(
                    "Computed old checkpoint tree root hash: {:?}, expected old checkpoint tree root hash: {:?}, actual root from backup manager: {:?}",
                    old_checkpoint_root,
                    coordinator_update.old_base.checkpoint_tree_root,
                    actual_checkpoint_root
                );
                anyhow::bail!("Old checkpoint tree root hash mismatch when committing coordinator state update to database. Computed hash: {:?}, expected hash: {:?}", old_checkpoint_root, coordinator_update.old_base.checkpoint_tree_root);
            }
        }

        tracing::info!("start -> Committing coordinator state update to database for checkpoint_id: {}", checkpoint_id);

        let checkpoint_proof_public_inputs_hash = if checkpoint_id == 0 && zk_proof.is_empty() {
            // Genesis commit path does not carry a checkpoint proof blob.
            // chain_0 = H(H(root, leaf), genesis_fingerprint) matches the
            // genesis checkpoint state transition circuit's public input hash.
            genesis_checkpoint_hash::<_, N::HasherBase>(
                coordinator_update.new_base.checkpoint_tree_root,
                coordinator_update.new_base.checkpoint_leaf_hash,
                self.circuit_fingerprint_config
                    .genesis_checkpoint_state_transition_fingerprint,
            )
            .into_inner()
        } else {
            checkpoint_hash_from_saved_proof_bytes::<N::QHash, N::ZKProof, N::ZKVerifier>(&zk_proof)?
                .into_inner()
        };
        if checkpoint_id != 0 {
            ensure_non_genesis_checkpoint_chain_commitment::<N::F, N::QHash, N::HasherBase>(
                checkpoint_id,
                self.last_committed.last_chain_hash,
                coordinator_update.new_base.checkpoint_tree_root,
                coordinator_update.new_base.checkpoint_leaf_hash,
                self.circuit_fingerprint_config.checkpoint_state_transition_circuit_fingerprint,
                checkpoint_proof_public_inputs_hash,
            )?;
        }
        let commit_source = if checkpoint_id == 0 {
            None
        } else {
            let expected = self.canonical_head.ok_or_else(|| anyhow::anyhow!(
                "normal checkpoint {} cannot persist a commit source before canonical-head bootstrap",
                checkpoint_id
            ))?;
            let candidate = CanonicalChainRef::new(
                self.network_id,
                expected.canonical_ref().chain_epoch(),
                CheckpointRef::new(
                    CheckpointId::new(checkpoint_id),
                    CheckpointHash::from_last_chain_hash(
                        checkpoint_proof_public_inputs_hash,
                    ),
                ),
            );
            let mut prepared_update = Vec::with_capacity(
                coordinator_update.pio_serialized_size(),
            );
            coordinator_update.pio_write_to_io(&mut prepared_update)?;
            let mut cursor = psy_io::Cursor::new(prepared_update.as_slice());
            let decoded = PsyPreparedCoordinatorBlockStateUpdates::<
                N::F,
                N::QHash,
            >::pio_read_from_io(&mut cursor)?;
            if decoded != coordinator_update
                || cursor.position() != prepared_update.len() as u64
            {
                anyhow::bail!(
                    "Coordinator prepared update failed canonical source roundtrip"
                );
            }
            let source_payload = CoordinatorCommitSourcePayload::try_new(
                prepared_update,
                state_transition_circuit_type as u32,
                zk_proof.clone(),
            )?;
            let source = CoordinatorCommitSource::try_new(
                expected,
                candidate,
                source_payload.encode_canonical(),
            )?;
            self.canonical_head_store
                .ensure_coordinator_rollback_floor(&expected)
                .await?;
            self.canonical_head_store
                .persist_coordinator_commit_source(&source)
                .await?;
            Some(source)
        };
        let mut verifiable_checkpoint_transition = coordinator_update.get_public_inputs_verifiable_state_transition(
            self.genesis_checkpoint_state_transition_hash,
            self.circuit_fingerprint_config.checkpoint_state_transition_circuit_fingerprint,
        );
        if checkpoint_id == 0 {
            verifiable_checkpoint_transition.state_transition.checkpoint_transition.old_checkpoint_tree_root = verifiable_checkpoint_transition.state_transition.checkpoint_transition.new_checkpoint_tree_root;
            verifiable_checkpoint_transition.state_transition.checkpoint_transition.old_checkpoint_leaf_hash = verifiable_checkpoint_transition.state_transition.checkpoint_transition.new_checkpoint_leaf_hash;
        }

        let verifiable_checkpoint_transition_with_proof = PsyVerifiableCheckpointTransitionWithProof {
            info: verifiable_checkpoint_transition,
            circuit_type: state_transition_circuit_type as u32,
            zk_proof,
        };
        let unique_pending_id = coordinator_update.unique_pending_id;

        let contract_tree_heights = coordinator_update
            .new_contract_code_definitions
            .iter()
            .enumerate()
            .map(|(ind, c)| {
                (
                    (coordinator_update.old_base.block_state.next_contract_id as u64 + ind as u64),
                    c.code_definition.state_tree_height as u8,
                )
            })
            .collect::<Vec<(u64, u8)>>();

        // CRITICAL: save the ZKP we generated FIRST before any state updates
        self.db
            .set_verifiable_checkpoint_state_transition_and_zkp(checkpoint_id, &verifiable_checkpoint_transition_with_proof)
            .await?;
        tracing::info!("Saved verifiable checkpoint state transition and ZKP for checkpoint ID: {}", checkpoint_id);
        // CRITICAL: set unique_pending_id to checkpoint_id mapping BEFORE ANY OTHER
        // STATE UPDATES so we can recover if something goes wrong
        self.db
            .set_unique_pending_id_checkpoint_id_mapping(unique_pending_id, checkpoint_id)
            .await?;
        self.db.set_checkpoint_id_to_unique_pending_id_mapping(checkpoint_id, unique_pending_id, &self.ids.proc_checkpoint_unique_id).await?;
        tracing::info!("Set unique pending ID to checkpoint ID mapping for checkpoint ID: {}", checkpoint_id);
        // START STANDARD STATE UPDATES (technically these can be done in any order
        // after the above two are done) start contract updates
        if !coordinator_update.new_contract_leaves_ffs.is_empty() {
            self.db
                .set_contract_leaves_ffs(checkpoint_id, &coordinator_update.new_contract_leaves_ffs)
                .await?;
            tracing::info!("Committed contract leaves ffs for checkpoint ID: {}", checkpoint_id);
            self.db
                .set_many_contract_code_definitions(checkpoint_id, &coordinator_update.new_contract_code_definitions)
                .await?;
            tracing::info!("Committed contract code definitions for checkpoint ID: {}", checkpoint_id);
            self.db.set_contract_tree_heights(checkpoint_id, &contract_tree_heights).await?;
            tracing::info!("Committed contract tree heights for checkpoint ID: {}, {:?}", checkpoint_id, contract_tree_heights);
            self.db
                .contract_function_tree_set_nodes_ffs(checkpoint_id, &coordinator_update.update_contract_function_tree_nodes_ffs)
                .await?;
            tracing::info!("Committed contract function tree updates for checkpoint ID: {}", checkpoint_id);
            self.db
                .global_contract_tree_set_nodes_ffs(checkpoint_id, &coordinator_update.update_global_contract_tree_nodes_ffs)
                .await?;
            tracing::info!("Committed global contract tree updates for checkpoint ID: {}", checkpoint_id);
        }
        tracing::info!("Committed contract state updates for checkpoint ID: {}", checkpoint_id);
        // start user registraion updates
        if !coordinator_update.new_user_public_keys_ffs.is_empty() {
            println!("committing new user public keys ffs (len: {}) for checkpoint ID: {}", coordinator_update.new_user_public_keys_ffs.len(), checkpoint_id);
            self.db
                .set_zk_public_keys_ffs(checkpoint_id, &coordinator_update.new_user_public_keys_ffs)
                .await?;
            println!("set_public_key_for_user_ids_ffs  (len: {}) for checkpoint ID: {}", coordinator_update.new_public_key_hash_to_user_id_rows_ffs.len(), checkpoint_id);
            self.db
                .set_public_key_for_user_ids_ffs(&coordinator_update.new_public_key_hash_to_user_id_rows_ffs)
                .await?;
                        println!("user_registration_tree_set_nodes_ffs  (len: {}) for checkpoint ID: {}", coordinator_update.update_user_registration_tree_nodes_ffs.len(), checkpoint_id);
            println!("coordinator_update.update_user_registration_tree_nodes_ffs len: {}", coordinator_update.update_user_registration_tree_nodes_ffs.len());
            self.db
                .user_registration_tree_set_nodes_ffs(checkpoint_id, &coordinator_update.update_user_registration_tree_nodes_ffs)
                .await?;
        }
        tracing::info!("Committed user registration state updates for checkpoint ID: {}", checkpoint_id);
        // start global user tree updates
        if !coordinator_update.update_global_user_tree_nodes_ffs.is_empty() {
            self.db
            .global_user_tree_set_nodes_ffs(checkpoint_id, &coordinator_update.update_global_user_tree_nodes_ffs)
            .await?;
        }
        tracing::info!("Committed global user tree state updates for checkpoint ID: {}", checkpoint_id);
        // start realm guta reward tree node keys updates
        if !coordinator_update.new_realm_guta_reward_tree_node_keys_ffs.is_empty() {
            self.db
                .set_realm_guta_reward_tree_node_keys_ffs(unique_pending_id, &coordinator_update.new_realm_guta_reward_tree_node_keys_ffs)
                .await?;
        }
        tracing::info!("Committed realm guta reward tree node keys for checkpoint ID: {}", checkpoint_id);
        // set l2 block state
        self.db
            .set_checkpoint_global_state_roots(checkpoint_id, &coordinator_update.new_base.checkpoint_leaf.global_state_roots)
            .await?;
        self.db
            .set_l2_block_state(checkpoint_id, &coordinator_update.new_base.block_state)
            .await?;
        self.db
            .set_l2_latest_block_state(&coordinator_update.new_base.block_state)
            .await?;
        let checkpoint_leaf_standard = coordinator_update.new_base.checkpoint_leaf.to_checkpoint_leaf::<N::HasherBase>();
        self.db.set_checkpoint_leaf_data(checkpoint_id, &checkpoint_leaf_standard).await?;
        let checkpoint_delta_merkle_proof: DeltaMerkleProofCore<N::QHash> =
            self.db.checkpoint_tree_set_leaf_hash(checkpoint_id, checkpoint_leaf_hash).await?;
        if checkpoint_id != 0
            && checkpoint_delta_merkle_proof
                != coordinator_update.checkpoint_tree_update_proof
        {
            anyhow::bail!(
                "Materialized checkpoint-tree delta differs from the durable Coordinator commit source"
            );
        }
        self.db
            .set_checkpoint_root_hash_to_id_mapping(checkpoint_delta_merkle_proof.new_root, checkpoint_id)
            .await?;
        tracing::info!("Set checkpoint root hash to ID mapping for checkpoint ID: {}\n{:#?}", checkpoint_id, checkpoint_delta_merkle_proof);
        // END STANDARD STATE UPDATES (technically these can be done in any order after
        // the above two are done)

        // CRITICAL: we need to set the checkpoint id at the VERY END otherwise the
        // recovery doesn't work this enables us to avoid having to do atomic
        // commits, since if the node dies during this process, it will load the backups
        // from disk SO LONG AS THE checkpoint_id is not set!!!!
        let previous_checkpoint_id = self.ids.checkpoint_id;
        self.db.set_latest_checkpoint_id(checkpoint_id).await?;
        if checkpoint_id > 0 && previous_checkpoint_id < checkpoint_id {
            if let Some((previous_pending_id, _)) = self
                .db
                .get_unique_pending_id_for_checkpoint_id(previous_checkpoint_id)
                .await?
            {
                if let Err(err) = self
                    .proof_store
                    .delete_all_proofs_for_pending_id(previous_pending_id)
                    .await
                {
                    tracing::warn!(
                        "Failed to delete coordinator proofs for previous checkpoint {} (pending_id={}): {}",
                        previous_checkpoint_id,
                        previous_pending_id,
                        err
                    );
                }
            }
        }
        tracing::info!("Committed coordinator processor state for checkpoint ID: {}", checkpoint_id);
        self.checkpoint_tree_backup_manager
            .append_checkpoint_leaf_hash(checkpoint_id, checkpoint_leaf_hash)
            .await?;
        tracing::info!("Backed up checkpoint tree root for checkpoint ID: {}", checkpoint_id);

        if let Some(source) = commit_source.as_ref() {
            self.canonical_head_store
                .mark_coordinator_commit_source_committed(source)
                .await?;
            tracing::info!(
                "Marked durable Coordinator commit source COMMITTED for checkpoint ID: {}",
                checkpoint_id
            );
        }

        // This is the final durable publish marker. All materialized state,
        // compatibility singletons, and the checkpoint-tree backup must be
        // durable before the canonical identity becomes externally usable.
        self.publish_canonical_head(
            checkpoint_id,
            checkpoint_proof_public_inputs_hash,
            commit_source.as_ref(),
        )
        .await?;
        tracing::info!(
            "Published durable canonical head for checkpoint ID: {}",
            checkpoint_id
        );

        if checkpoint_id != 0 {

            self.last_committed.checkpoint_state_transition = CheckpointStateHashTransition {
                old_checkpoint_tree_root: coordinator_update.old_base.checkpoint_tree_root,
                new_checkpoint_tree_root: coordinator_update.new_base.checkpoint_tree_root,
                old_checkpoint_leaf_hash: coordinator_update.old_base.checkpoint_leaf_hash,
                new_checkpoint_leaf_hash: coordinator_update.new_base.checkpoint_leaf_hash,
            };
        }else{
            self.last_committed.checkpoint_state_transition = CheckpointStateHashTransition {
                old_checkpoint_tree_root: coordinator_update.new_base.checkpoint_tree_root,
                new_checkpoint_tree_root: coordinator_update.new_base.checkpoint_tree_root,
                old_checkpoint_leaf_hash: coordinator_update.new_base.checkpoint_leaf_hash,
                new_checkpoint_leaf_hash: coordinator_update.new_base.checkpoint_leaf_hash,
            };
        }
        self.ids.checkpoint_id = checkpoint_id;
        self.ids.next_checkpoint_id = checkpoint_id + 1;
        self.last_committed.update_for_block::<N::HasherBase>(
            coordinator_update.new_base.block_state,
            verifiable_checkpoint_transition.checkpoint_leaf,
            verifiable_checkpoint_transition.state_transition.checkpoint_transition,
        )?;
        self.last_committed.last_chain_hash = checkpoint_proof_public_inputs_hash;

        tracing::info!("Updated last committed state for checkpoint ID: {}", checkpoint_id);
        // This just updates the RwLock protected shared status, this is ok because we
        // only read when we dump/create the queue builder
        self.shared_status.update_status(
            self.ids.unique_pending_id,
            checkpoint_id,
            checkpoint_leaf_standard,
            coordinator_update.new_base.checkpoint_leaf.global_state_roots,
            coordinator_update.new_base.block_state,
            false,
        )?;
        tracing::info!("Updated shared status for checkpoint ID: {}", checkpoint_id);

        Ok(())
    }

    pub async fn ensure_db_matches_verifiable_transition(
        &self,
        verifiable_transition: &PsyVerifiableCheckpointTransition<N::F, N::QHash>,
    ) -> anyhow::Result<()> {
        let checkpoint_id = self.ids.checkpoint_id;
        let db_checkpoint_tree_proof: MerkleProofCore<N::QHash> = self.db.checkpoint_tree_get_merkle_proof(checkpoint_id, checkpoint_id).await?;
        let db_checkpoint_tree_root = db_checkpoint_tree_proof.root;
        let v_checkpoint_tree_root = verifiable_transition.state_transition.checkpoint_transition.new_checkpoint_tree_root;
        if db_checkpoint_tree_root != v_checkpoint_tree_root {
            anyhow::bail!("Checkpoint tree root mismatch between database and verifiable transition at checkpoint ID: {}. Database root: {:?}, verifiable transition root: {:?}", checkpoint_id, db_checkpoint_tree_root, v_checkpoint_tree_root);
        }
        let p_state_transition_hash = self.last_committed.checkpoint_state_transition.qfhash::<N::HasherBase>();
        let v_state_transition_hash = verifiable_transition.state_transition.checkpoint_transition.qfhash::<N::HasherBase>();
        if p_state_transition_hash != v_state_transition_hash {
            anyhow::bail!("Checkpoint state transition hash mismatch between processor state and verifiable transition at checkpoint ID: {}. Database hash: {:?}, verifiable transition hash: {:?}", checkpoint_id, p_state_transition_hash, v_state_transition_hash);
        }
        let checkpoint_leaf = verifiable_transition.checkpoint_leaf.to_checkpoint_leaf::<N::HasherBase>();
        if checkpoint_leaf != self.last_committed.checkpoint_leaf {
            anyhow::bail!("Checkpoint leaf mismatch between processor state and verifiable transition at checkpoint ID: {}. Database leaf: {:?}, verifiable transition leaf: {:?}", checkpoint_id, self.last_committed.checkpoint_leaf, checkpoint_leaf);
        }

        let db_user_registration_tree_merkle_proof: MerkleProofCore<N::QHash> = self
            .db
            .user_registration_tree_get_merkle_proof(checkpoint_id, self.last_committed.l2_state.next_user_id.max(1) - 1)
            .await?;

        if !db_user_registration_tree_merkle_proof.verify::<N::HasherBase>() {
            anyhow::bail!(
                "User registration tree merkle proof verification failed for database at checkpoint ID: {}.\n Invalid Proof: \n {:#?}",
                checkpoint_id,
                &db_user_registration_tree_merkle_proof
            );
        }
        if verifiable_transition.checkpoint_leaf.global_state_roots.user_registration_tree_root != db_user_registration_tree_merkle_proof.root {
            anyhow::bail!("User registration tree root mismatch between database and verifiable transition at checkpoint ID: {}. Database root: {:?}, verifiable transition root: {:?}", checkpoint_id, db_user_registration_tree_merkle_proof.root, verifiable_transition.checkpoint_leaf.global_state_roots.user_registration_tree_root);
        }

        let db_deploy_contract_tree_merkle_proof: MerkleProofCore<N::QHash> = self
            .db
            .global_contract_tree_get_merkle_proof(checkpoint_id, (self.last_committed.l2_state.next_contract_id.max(1) - 1) as u64)
            .await?;
        if !db_deploy_contract_tree_merkle_proof.verify::<N::HasherBase>() {
            anyhow::bail!(
                "Global contract tree merkle proof verification failed for database at checkpoint ID: {}.\n Invalid Proof: \n {:#?}",
                checkpoint_id,
                &db_deploy_contract_tree_merkle_proof
            );
        }
        if verifiable_transition.checkpoint_leaf.global_state_roots.contract_tree_root != db_deploy_contract_tree_merkle_proof.root {
            anyhow::bail!("Global contract tree root mismatch between database and verifiable transition at checkpoint ID: {}. Database root: {:?}, verifiable transition root: {:?}", checkpoint_id, db_deploy_contract_tree_merkle_proof.root, verifiable_transition.checkpoint_leaf.global_state_roots.contract_tree_root);
        }

        let db_global_user_tree_merkle_proof: MerkleProofCore<N::QHash> = self
            .db
            .global_user_tree_get_merkle_proof(checkpoint_id, 1u64 << (N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT - 1))
            .await?;
        if !db_global_user_tree_merkle_proof.verify::<N::HasherBase>() {
            anyhow::bail!(
                "Global user tree merkle proof verification failed for database at checkpoint ID: {}.\n Invalid Proof: \n {:#?}",
                checkpoint_id,
                &db_global_user_tree_merkle_proof
            );
        }
        if verifiable_transition.checkpoint_leaf.global_state_roots.user_tree_root != db_global_user_tree_merkle_proof.root {
            anyhow::bail!("Global user tree root mismatch between database and verifiable transition at checkpoint ID: {}. Database root: {:?}, verifiable transition root: {:?}", checkpoint_id, db_global_user_tree_merkle_proof.root, verifiable_transition.checkpoint_leaf.global_state_roots.user_tree_root);
        }

        Ok(())
    }
}

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber,
        RegisterUserQueue: QStandardEphemeralQueueSubscriber,
        DeployContractQueue: QStandardEphemeralQueueSubscriber,
        ProofWorkQueue: QStandardWorkerQueuePublisher,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
    >
    PsyCoordinatorDatabaseProcessor<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        RegisterUserQueue,
        DeployContractQueue,
        ProofWorkQueue,
        TempDatabase,
        ProofStore,
        FileSystem,
    > where N::HasherBase: 'static + Send + Sync
{
    pub async fn get_reward_tree_root(&self, checkpoint_id: u64, unique_pending_id: u64) -> anyhow::Result<N::QHash> {
        let current_context = self
            .temp_db
            .get_current_pending_context(&self.ids.realm_identifier)
            .await?;
        let temp_store_reward_tree_root: Option<N::QHash> = if let Some(context) =
            current_context
                .as_ref()
                .filter(|context| context.unique_pending_id().get() == unique_pending_id)
        {
            self.temp_db
                .get_proof_miner_rewards_tree_value_or_none(
                    &self.ids.realm_identifier,
                    context,
                    QProvingJobDataID::get_checkpoint_state_transition_job_id(checkpoint_id),
                )
                .await?
        } else {
            None
        };
        if temp_store_reward_tree_root.is_some() {
            let root = temp_store_reward_tree_root.unwrap();
            if root != N::QHash::get_zero_value() || unique_pending_id == 0 {
                return Ok(root);
            } else {
                tracing::warn!(
                    "Temporary store returned zero value for reward tree root at unique pending ID: {}. Falling back to permanent store.",
                    unique_pending_id
                );
            }
        }
        let reward_tree_root = self
            .tag_tree_rewards_store
            .rewards_tag_tree_get_root_at_unique_pending_id(unique_pending_id)
            .await?;
        if reward_tree_root == N::QHash::get_zero_value() && unique_pending_id != 0 {
            anyhow::bail!("Permanent store returned zero value for reward tree root at unique pending ID: {}. This indicates an inconsistency in the database state.", unique_pending_id);
        }
        Ok(reward_tree_root)
    }
    pub async fn ensure_backup_restored_if_necessary(
        &mut self,
        file_system: &FileSystem,
        deploy_contract_gatherer_backup_directory: &str,
        register_user_gatherer_backup_directory: &str,
        guta_gatherer_backup_directory: &str,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        global_contract_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        user_registration_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
    ) -> anyhow::Result<()> {
        let database_check_state = self.get_database_check_state().await?;
        if database_check_state == DatabaseCheckState::NeedsRecovery {
            let restore_unique_pending_id = self.ids.unique_pending_id;
            let restore_checkpoint_id = self.ids.checkpoint_id;

            let next_checkpoint_id = self.ids.checkpoint_id + 1;
            tracing::warn!("Detected inconsistent coordinator processor database state. Initiating restoration from backups... last committed checkpoint ID: {}, unique pending ID: {}, target_checkpoint: {}", self.ids.checkpoint_id, self.ids.unique_pending_id, next_checkpoint_id);
            tracing::info!(
                "Restoring coordinator processor database to checkpoint ID: {} from backups...",
                next_checkpoint_id
            );

            let verifiable_transition_with_proof: PsyVerifiableCheckpointTransitionWithProof<N::F, N::QHash> = self
                .db
                .get_verifiable_checkpoint_state_transition_and_zkp(self.ids.checkpoint_id + 1)
                .await?;

            tracing::info!(
                "Found verifiable checkpoint transition and ZKP for checkpoint ID: {}. Proceeding with restoration...",
                next_checkpoint_id
            );
            tracing::info!("Restoring coordinator processor database from backups...");
            let append_checkpoint_update_siblings = self
                .checkpoint_tree_backup_manager
                .checkpoint_tree
                .get_leaf(self.ids.checkpoint_id + 1)
                .siblings;

            let reward_tree_root = self.get_reward_tree_root(restore_checkpoint_id, restore_unique_pending_id).await?;
            let expected_reward_tree_root = verifiable_transition_with_proof.info.checkpoint_leaf.get_rewards_tree_root();
            if reward_tree_root != expected_reward_tree_root {
                anyhow::bail!(
                    "Reward tree root mismatch during restoration from backups. Computed root: {:?}, expected root from verifiable transition: {:?}",
                    reward_tree_root,
                    expected_reward_tree_root
                );
            }

            let circuit_type = ProvingJobCircuitType::try_from_u32(verifiable_transition_with_proof.circuit_type)?;

            let coordinator_update = generate_coordinator_output_from_backups::<N, FileSystem>(
                file_system,
                deploy_contract_gatherer_backup_directory,
                register_user_gatherer_backup_directory,
                guta_gatherer_backup_directory,
                &self.ids,
                &self.last_committed,
                reward_tree_root,
                append_checkpoint_update_siblings,
                global_user_tree,
                global_contract_tree,
                user_registration_tree,
            )
            .await?;
            let (info, _, zk_proof) = verifiable_transition_with_proof.into_tuple();
            self.commit_state(coordinator_update, circuit_type, zk_proof).await?;
            self.ensure_db_matches_verifiable_transition(&info).await?;
            tracing::info!(
                "Coordinator processor database restored from backups.\n Restored checkpoint ID: {}, unique pending ID: {}",
                self.ids.checkpoint_id,
                self.ids.unique_pending_id
            );
        }
        Ok(())
    }

    pub fn print_coordinator_processor_state(&self) {
        tracing::info!(
            r#"======== Coordinator Processor State ========
[CORE_VITALS]
Last Committed Checkpoint ID: {}
Next Checkpoint ID: {}
Unique Pending ID: {}
Gatherer Unique Pending ID: {}
Checkpoint Root Hash: {}
[/CORE_VITALS]

[IDS]
{:#?}
[/IDS]

[LAST_COMMITTED]
{:#?}
[/LAST_COMMITTED]
============================================="#,
            self.ids.checkpoint_id,
            self.ids.next_checkpoint_id,
            self.ids.unique_pending_id,
            self.ids.gathering_unique_pending_id,
            self.last_committed.checkpoint_root.psy_debug_print(),
            self.ids,
            self.last_committed
        );
    }

    pub async fn init_with_setup_and_genesis(
        &mut self,
        file_system: &FileSystem,
        deploy_contract_gatherer_backup_directory: &str,
        register_user_gatherer_backup_directory: &str,
        guta_gatherer_backup_directory: &str,
        genesis_block_update: PsyPreparedCoordinatorBlockStateUpdates<N::F, N::QHash>,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        global_contract_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        user_registration_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        rollback_restart_directive: Option<&RollbackRuntimeRebuildDirective<N::QHash>>,
    ) -> anyhow::Result<()> {
        self.ensure_genesis_applied(genesis_block_update).await?;
        self.ensure_backup_restored_if_necessary(
            file_system,
            deploy_contract_gatherer_backup_directory,
            register_user_gatherer_backup_directory,
            guta_gatherer_backup_directory,
            global_user_tree,
            global_contract_tree,
            user_registration_tree,
        )
        .await?;
        if let Some(directive) = rollback_restart_directive {
            self.resume_rollback_unique_ids(directive).await?;
        } else {
            self.set_new_unique_ids().await?;
        }

        self.shared_status.update_status(
            self.ids.gathering_unique_pending_id,
            self.ids.checkpoint_id,
            self.last_committed.checkpoint_leaf.clone(),
            self.last_committed.checkpoint_state_roots.clone(),
            self.last_committed.l2_state.clone(),
            false,
        )?;

        tracing::info!(
            "[COORDINATOR] Started with checkpoint ID: {}, unique pending ID: {}",
            self.ids.checkpoint_id,
            self.ids.unique_pending_id
        );
        self.print_coordinator_processor_state();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::{pgoldilocks::PoseidonHasher, PHash};

    #[test]
    fn rollback_restart_reuses_exact_coordinator_pending_pair_without_allocation() {
        let source = include_str!("db.rs");
        let method = source
            .split("async fn resume_rollback_unique_ids")
            .nth(1)
            .expect("Coordinator rollback restart method")
            .split("pub async fn set_new_unique_ids")
            .next()
            .unwrap();
        assert!(!method.contains("inc_unique_pending_id"));
        assert!(method.contains("get_current_unique_pending_id"));
        assert!(method.contains("RollbackControlState::Verifying"));
        assert!(method.contains("RollbackControlState::AllRealmsReady"));
        assert!(method.contains("RollbackControlState::Idle"));
        assert!(method.contains("clear_current_pending_context"));
        assert!(method.contains("publish_current_pending_context"));
        assert_eq!(method.matches("ensure_consumer(").count(), 4);
        assert_eq!(method.matches("set_unique_id(gathering_proc)").count(), 3);
    }

    #[test]
    fn rollback_runtime_rebuild_only_mutates_derived_process_state() {
        let source = include_str!("db.rs");
        let rebuild = source
            .split("pub async fn rebuild_coordinator_runtime_after_rollback")
            .nth(1)
            .expect("runtime rebuild method")
            .split("pub async fn try_publish_restored_runtime")
            .next()
            .expect("runtime rebuild method end");

        for required in [
            "read_selected_coordinator_runtime_rebuild",
            "hard_reset_and_truncate",
            "sync_from_database",
            "set_unique_pending_ids",
            "set_gathering_unique_pending_ids",
            "clear_current_pending_context",
            "persist_coordinator_runtime_rebuild_report",
        ] {
            assert!(rebuild.contains(required), "missing {required}");
        }
        for forbidden in [
            "set_latest_checkpoint_id",
            "set_l2_latest_block_state",
            "set_unique_pending_id_checkpoint_id_mapping",
            "set_checkpoint_id_to_unique_pending_id_mapping",
            "complete_rollback_realm_barrier",
            "complete_rollback(",
        ] {
            assert!(!rebuild.contains(forbidden), "forbidden {forbidden}");
        }
    }

    #[test]
    fn restored_target_is_published_before_the_new_pending_context() {
        let source = include_str!("db.rs");
        let publish = source
            .split("pub async fn try_publish_restored_runtime")
            .nth(1)
            .unwrap()
            .split("async fn copy_checkpoint_backup_file_for_reset")
            .next()
            .unwrap();
        let durable = publish
            .find("self.db.try_publish_restored_runtime(self.network_id)")
            .unwrap();
        let local_head = publish.find("self.canonical_head = Some(head)").unwrap();
        let pending = publish.find("self.publish_current_pending_context()").unwrap();
        assert!(durable < local_head && local_head < pending);
    }

    #[test]
    fn coordinator_commit_source_brackets_all_hot_writes_and_head_publish() {
        let source = include_str!("db.rs");
        let commit = source
            .split("pub async fn commit_state(")
            .nth(1)
            .unwrap()
            .split("pub fn print_coordinator_processor_state")
            .next()
            .unwrap();
        let source_write = commit
            .find("persist_coordinator_commit_source")
            .unwrap();
        let pending_identity_validation = commit
            .find("Coordinator prepared pending identity does not match")
            .unwrap();
        let prepared_tree_validation = commit
            .find("Coordinator prepared checkpoint-tree delta does not match")
            .unwrap();
        let rollback_floor = commit
            .find("ensure_coordinator_rollback_floor")
            .unwrap();
        let first_hot_write = commit
            .find("set_verifiable_checkpoint_state_transition_and_zkp")
            .unwrap();
        let backup = commit.find("append_checkpoint_leaf_hash").unwrap();
        let committed = commit
            .find("mark_coordinator_commit_source_committed")
            .unwrap();
        let head = commit.rfind("self.publish_canonical_head(").unwrap();
        let materialized_tree_delta = commit
            .find("Materialized checkpoint-tree delta differs")
            .unwrap();
        let root_mapping = commit
            .find("set_checkpoint_root_hash_to_id_mapping")
            .unwrap();
        assert!(pending_identity_validation < source_write);
        assert!(prepared_tree_validation < source_write);
        assert!(rollback_floor < source_write);
        assert!(source_write < first_hot_write);
        assert!(first_hot_write < materialized_tree_delta);
        assert!(materialized_tree_delta < root_mapping);
        assert!(first_hot_write < backup);
        assert!(backup < committed);
        assert!(committed < head);
        assert!(commit.contains("CoordinatorCommitSourcePayload::try_new"));
    }

    #[test]
    fn startup_publish_requires_exact_source_before_committed_marker() {
        let source = include_str!("db.rs");
        let startup = source
            .split("CanonicalHeadStartupPlan::PublishMaterialized(sealed) =>")
            .nth(1)
            .unwrap()
            .split("async fn publish_canonical_head")
            .next()
            .unwrap();
        let read = startup
            .find("read_coordinator_commit_source")
            .unwrap();
        let rollback_floor = startup
            .find("ensure_coordinator_rollback_floor")
            .unwrap();
        let committed = startup
            .find("mark_coordinator_commit_source_committed")
            .unwrap();
        let head = startup
            .find("compare_and_set_canonical_head")
            .unwrap();
        assert!(rollback_floor < read && read < committed && committed < head);
    }

    #[test]
    fn validates_non_genesis_checkpoint_chain_commitment() {
        type Hasher = PoseidonHasher;

        let checkpoint_id = 367;
        let previous_chain_hash = PHash::from_values(1, 2, 3, 4);
        let checkpoint_tree_root = PHash::from_values(5, 6, 7, 8);
        let checkpoint_leaf_hash = PHash::from_values(9, 10, 11, 12);
        let fingerprint = PHash::from_values(13, 14, 15, 16);
        let root_leaf_hash = Hasher::q_two_to_one(checkpoint_tree_root, checkpoint_leaf_hash);
        let step_hash = Hasher::q_two_to_one(root_leaf_hash, fingerprint);
        let expected_chain_hash = Hasher::q_two_to_one(previous_chain_hash, step_hash);

        ensure_non_genesis_checkpoint_chain_commitment::<_, _, Hasher>(
            checkpoint_id,
            previous_chain_hash,
            checkpoint_tree_root,
            checkpoint_leaf_hash,
            fingerprint,
            expected_chain_hash,
        )
        .expect("matching checkpoint proof chain commitment must pass");

        let stale_proof_chain_hash = PHash::from_values(17, 18, 19, 20);
        let error = ensure_non_genesis_checkpoint_chain_commitment::<_, _, Hasher>(
            checkpoint_id,
            previous_chain_hash,
            checkpoint_tree_root,
            checkpoint_leaf_hash,
            fingerprint,
            stale_proof_chain_hash,
        )
        .expect_err("mismatching checkpoint proof chain commitment must fail");
        let error = error.to_string();

        assert!(error.contains("checkpoint ID 367"));
        assert!(error.contains(&qhash_to_hex(&expected_chain_hash)));
        assert!(error.contains(&qhash_to_hex(&stale_proof_chain_hash)));
    }
    // Mirrors `ensure_non_genesis_checkpoint_chain_commitment`'s formula so the defensive
    // cases below can build a matching proof or a "dropped-input" proof without restating
    // the hash nesting inline each time.
    fn chain_commitment_hash(
        previous_chain_hash: PHash,
        checkpoint_tree_root: PHash,
        checkpoint_leaf_hash: PHash,
        fingerprint: PHash,
    ) -> PHash {
        type H = PoseidonHasher;
        let root_leaf = H::q_two_to_one(checkpoint_tree_root, checkpoint_leaf_hash);
        let step = H::q_two_to_one(root_leaf, fingerprint);
        H::q_two_to_one(previous_chain_hash, step)
    }

    /// Pinned contract: the validator applies the full check uniformly for every checkpoint
    /// id, including 0. It does NOT internally short-circuit genesis, so the genesis exemption
    /// ("skip the non-genesis check and do not bail on an empty proof") lives entirely in the
    /// `commit_state` call site's `if checkpoint_id != 0` guard (exercised by process_block.rs).
    /// Arm A kills a `if checkpoint_id == 0 { bail }` regression; Arm B kills a
    /// `if checkpoint_id == 0 { return Ok }` regression; Arm C proves the non-genesis formula
    /// genuinely cannot fit genesis (its empty-proof hash omits previous_chain_hash), so the
    /// call-site guard is load-bearing.
    #[test]
    fn genesis_checkpoint_id_zero_is_not_internally_exempt() {
        type Hasher = PoseidonHasher;
        let checkpoint_id = 0u64;
        let previous_chain_hash = PHash::from_values(1, 2, 3, 4);
        let checkpoint_tree_root = PHash::from_values(5, 6, 7, 8);
        let checkpoint_leaf_hash = PHash::from_values(9, 10, 11, 12);
        let fingerprint = PHash::from_values(13, 14, 15, 16);
        let expected = chain_commitment_hash(
            previous_chain_hash, checkpoint_tree_root, checkpoint_leaf_hash, fingerprint,
        );

        // Arm A: id=0 with a formula-matching proof must NOT bail.
        ensure_non_genesis_checkpoint_chain_commitment::<_, _, Hasher>(
            checkpoint_id, previous_chain_hash, checkpoint_tree_root,
            checkpoint_leaf_hash, fingerprint, expected,
        )
        .expect("id=0 with a matching proof must not bail (no internal genesis rejection)");

        // Arm B: id=0 with a mismatched proof must bail — no internal `return Ok` for genesis.
        let wrong = PHash::from_values(17, 18, 19, 20);
        let error = ensure_non_genesis_checkpoint_chain_commitment::<_, _, Hasher>(
            checkpoint_id, previous_chain_hash, checkpoint_tree_root,
            checkpoint_leaf_hash, fingerprint, wrong,
        )
        .expect_err("id=0 with a mismatched proof must bail (no internal genesis exemption)");
        assert!(error.to_string().contains("checkpoint ID 0"));

        // Arm C: the real genesis public-inputs hash is H(H(root, leaf), fingerprint) and omits
        // previous_chain_hash, so it can never satisfy the non-genesis formula. This is why the
        // call-site `if checkpoint_id != 0` guard must exist.
        let genesis_proof_hash = {
            let root_leaf = Hasher::q_two_to_one(checkpoint_tree_root, checkpoint_leaf_hash);
            Hasher::q_two_to_one(root_leaf, fingerprint)
        };
        let error = ensure_non_genesis_checkpoint_chain_commitment::<_, _, Hasher>(
            checkpoint_id, previous_chain_hash, checkpoint_tree_root,
            checkpoint_leaf_hash, fingerprint, genesis_proof_hash,
        )
        .expect_err("genesis empty-proof hash omits previous_chain_hash and must fail the non-genesis check");
        assert!(error.to_string().contains("checkpoint ID 0"));
    }

    /// Pinned contract: the proof/expected comparison checks all four 256-bit limbs, not just
    /// limb[0]. For each limb, flip one bit in only that limb of the proof hash (leaving the
    /// other three equal to the expected hash) and assert the check still bails. Rows 1, 2, 3
    /// kill a `compare only elements[0]` regression; row 0 is the baseline that any check catches.
    #[test]
    fn mismatch_on_any_single_hash_limb_bails() {
        type Hasher = PoseidonHasher;
        let checkpoint_id = 367u64;
        let previous_chain_hash = PHash::from_values(1, 2, 3, 4);
        let checkpoint_tree_root = PHash::from_values(5, 6, 7, 8);
        let checkpoint_leaf_hash = PHash::from_values(9, 10, 11, 12);
        let fingerprint = PHash::from_values(13, 14, 15, 16);
        let expected = chain_commitment_hash(
            previous_chain_hash, checkpoint_tree_root, checkpoint_leaf_hash, fingerprint,
        );

        for limb in 0u8..4u8 {
            let mut bytes = expected.into_owned_32bytes();
            // Flip the low bit of this limb. A single-bit flip is never a nonzero multiple of
            // the Goldilocks prime, so the limb's field element genuinely changes.
            bytes[(limb as usize) * 8] ^= 0x01;
            let tampered = <PHash as Q256BitHash>::from_owned_32bytes(bytes);
            assert_ne!(tampered, expected, "tamper must actually change limb {limb}");

            let result = ensure_non_genesis_checkpoint_chain_commitment::<_, _, Hasher>(
                checkpoint_id, previous_chain_hash, checkpoint_tree_root,
                checkpoint_leaf_hash, fingerprint, tampered,
            );
            assert!(
                result.is_err(),
                "mismatch on limb {limb} alone must bail, got {result:?}"
            );
            assert!(result.unwrap_err().to_string().contains("checkpoint ID 367"));
        }
    }

    /// Pinned contract: previous_chain_hash is wired into the formula. The proof is the formula
    /// with previous_chain_hash collapsed away (the outer q_two_to_one removed -> expected =
    /// step), which is what an accidental "drop previous_chain_hash" produces. Correct code
    /// computes H(previous_chain_hash, step) != step and bails; the drop mutation computes
    /// step == proof and returns Ok, reddening this test.
    #[test]
    fn previous_chain_hash_dropped_from_formula_bails() {
        type Hasher = PoseidonHasher;
        let checkpoint_id = 367u64;
        let previous_chain_hash = PHash::from_values(1, 2, 3, 4);
        let checkpoint_tree_root = PHash::from_values(5, 6, 7, 8);
        let checkpoint_leaf_hash = PHash::from_values(9, 10, 11, 12);
        let fingerprint = PHash::from_values(13, 14, 15, 16);

        // Proof = step hash = the formula with previous_chain_hash collapsed out.
        let root_leaf = Hasher::q_two_to_one(checkpoint_tree_root, checkpoint_leaf_hash);
        let proof_dropped_prev = Hasher::q_two_to_one(root_leaf, fingerprint);
        // Sanity: the full formula genuinely differs from the dropped one.
        assert_ne!(
            chain_commitment_hash(previous_chain_hash, checkpoint_tree_root, checkpoint_leaf_hash, fingerprint),
            proof_dropped_prev,
        );

        let result = ensure_non_genesis_checkpoint_chain_commitment::<_, _, Hasher>(
            checkpoint_id, previous_chain_hash, checkpoint_tree_root,
            checkpoint_leaf_hash, fingerprint, proof_dropped_prev,
        );
        assert!(result.is_err(), "dropping previous_chain_hash from the formula must still bail against the dropped-formula proof");
        assert!(result.unwrap_err().to_string().contains("checkpoint ID 367"));
    }

    /// Pinned contract: checkpoint_tree_root is wired into the formula. Proof = formula with
    /// the root collapsed (inner q_two_to_one(root, leaf) -> leaf): H(prev, H(leaf, fp)).
    /// Correct code computes H(prev, H(H(root,leaf), fp)) and bails; the drop mutation matches
    /// the proof and returns Ok, reddening this test.
    #[test]
    fn checkpoint_tree_root_dropped_from_formula_bails() {
        type Hasher = PoseidonHasher;
        let checkpoint_id = 367u64;
        let previous_chain_hash = PHash::from_values(1, 2, 3, 4);
        let checkpoint_tree_root = PHash::from_values(5, 6, 7, 8);
        let checkpoint_leaf_hash = PHash::from_values(9, 10, 11, 12);
        let fingerprint = PHash::from_values(13, 14, 15, 16);

        let leaf_fp = Hasher::q_two_to_one(checkpoint_leaf_hash, fingerprint);
        let proof_dropped_root = Hasher::q_two_to_one(previous_chain_hash, leaf_fp);
        assert_ne!(
            chain_commitment_hash(previous_chain_hash, checkpoint_tree_root, checkpoint_leaf_hash, fingerprint),
            proof_dropped_root,
        );

        let result = ensure_non_genesis_checkpoint_chain_commitment::<_, _, Hasher>(
            checkpoint_id, previous_chain_hash, checkpoint_tree_root,
            checkpoint_leaf_hash, fingerprint, proof_dropped_root,
        );
        assert!(result.is_err(), "dropping checkpoint_tree_root from the formula must still bail against the dropped-formula proof");
        assert!(result.unwrap_err().to_string().contains("checkpoint ID 367"));
    }

    /// Pinned contract: checkpoint_leaf_hash is wired into the formula. Proof = formula with
    /// the leaf collapsed (inner q_two_to_one(root, leaf) -> root): H(prev, H(root, fp)).
    /// Correct code computes H(prev, H(H(root,leaf), fp)) and bails; the drop mutation matches
    /// the proof and returns Ok, reddening this test.
    #[test]
    fn checkpoint_leaf_hash_dropped_from_formula_bails() {
        type Hasher = PoseidonHasher;
        let checkpoint_id = 367u64;
        let previous_chain_hash = PHash::from_values(1, 2, 3, 4);
        let checkpoint_tree_root = PHash::from_values(5, 6, 7, 8);
        let checkpoint_leaf_hash = PHash::from_values(9, 10, 11, 12);
        let fingerprint = PHash::from_values(13, 14, 15, 16);

        let root_fp = Hasher::q_two_to_one(checkpoint_tree_root, fingerprint);
        let proof_dropped_leaf = Hasher::q_two_to_one(previous_chain_hash, root_fp);
        assert_ne!(
            chain_commitment_hash(previous_chain_hash, checkpoint_tree_root, checkpoint_leaf_hash, fingerprint),
            proof_dropped_leaf,
        );

        let result = ensure_non_genesis_checkpoint_chain_commitment::<_, _, Hasher>(
            checkpoint_id, previous_chain_hash, checkpoint_tree_root,
            checkpoint_leaf_hash, fingerprint, proof_dropped_leaf,
        );
        assert!(result.is_err(), "dropping checkpoint_leaf_hash from the formula must still bail against the dropped-formula proof");
        assert!(result.unwrap_err().to_string().contains("checkpoint ID 367"));
    }

    /// Pinned contract: the state-transition circuit fingerprint is wired into the formula.
    /// Proof = formula with the fingerprint collapsed (q_two_to_one(root_leaf, fp) ->
    /// root_leaf): H(prev, H(root, leaf)). Correct code computes H(prev, H(root_leaf, fp)) and
    /// bails; the drop mutation matches the proof and returns Ok, reddening this test.
    #[test]
    fn fingerprint_dropped_from_formula_bails() {
        type Hasher = PoseidonHasher;
        let checkpoint_id = 367u64;
        let previous_chain_hash = PHash::from_values(1, 2, 3, 4);
        let checkpoint_tree_root = PHash::from_values(5, 6, 7, 8);
        let checkpoint_leaf_hash = PHash::from_values(9, 10, 11, 12);
        let fingerprint = PHash::from_values(13, 14, 15, 16);

        let root_leaf = Hasher::q_two_to_one(checkpoint_tree_root, checkpoint_leaf_hash);
        let proof_dropped_fp = Hasher::q_two_to_one(previous_chain_hash, root_leaf);
        assert_ne!(
            chain_commitment_hash(previous_chain_hash, checkpoint_tree_root, checkpoint_leaf_hash, fingerprint),
            proof_dropped_fp,
        );

        let result = ensure_non_genesis_checkpoint_chain_commitment::<_, _, Hasher>(
            checkpoint_id, previous_chain_hash, checkpoint_tree_root,
            checkpoint_leaf_hash, fingerprint, proof_dropped_fp,
        );
        assert!(result.is_err(), "dropping the circuit fingerprint from the formula must still bail against the dropped-formula proof");
        assert!(result.unwrap_err().to_string().contains("checkpoint ID 367"));
    }
}
