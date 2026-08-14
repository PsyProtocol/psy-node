use std::sync::Arc;

use parth_core::{protocol::core_types::QNetworkTypesConfig, QCoreProcCheckpointUniqueId};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::prepared_block::realm::PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate;
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    p2p::traits::realm_coordinantor::RealmCoordinatorClient,
    psy_core_db::traits::full::{PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore},
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueueSubscriber, worker_queue::QStandardWorkerQueuePublisher},
    store::{
        rollback_runtime_rebuild::RealmRollbackRuntimeControl,
        rollback_runtime_rebuild::RollbackRuntimeRebuildDirective,
        traits::proof_store::QParthProofStore,
    },
};

use crate::{
    backup::realm::load_realm_memory_trees_from_db,
    queue::gatherer::EphemeralQueueGathererWithTree,
    realm::processor::{
        core::{
            control::new_realm_processor_control_plane, PsyRealmProcessor,
            RealmProcessorControlError, RealmProcessorControlHandle,
        },
        db::PsyRealmDatabaseProcessor,
        gatherers::realm_end_cap_gatherer::{RealmGUTAEndCapGatherer, RealmGUTAEndCapGathererConfig},
    },
};

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        ProofWorkQueue: QStandardWorkerQueuePublisher + Send + Sync,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
        CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync,
    > PsyRealmProcessor<N, S, STagTreeRewards, GUTAUpdateQueue, ProofWorkQueue, TempDatabase, ProofStore, FileSystem, CoordinatorClient>
where
    FileSystem::File: Send + Sync,
{
    pub(in crate::realm::processor) async fn new(
        mut db: PsyRealmDatabaseProcessor<
            N,
            S,
            STagTreeRewards,
            GUTAUpdateQueue,
            ProofWorkQueue,
            TempDatabase,
            ProofStore,
            FileSystem,
            CoordinatorClient,
        >,
        genesis_block_update: PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate<N::F, N::QHash>,
        file_system: Arc<FileSystem>,
        guta_gatherer_backup_directory: String,
        proof_verifier: Option<Arc<N::ZKVerifier>>,
        normal_commit_owner: super::RealmNormalCommitOwner<N::QHash>,
        rollback_runtime_control:
            Option<Arc<dyn RealmRollbackRuntimeControl<N::QHash>>>,
        rollback_restart_directive: Option<RollbackRuntimeRebuildDirective<N::QHash>>,
    ) -> anyhow::Result<(Self, tokio::task::JoinHandle<Result<(), anyhow::Error>>)> {
        tracing::info!("[REALM_STARTUP] processor new start");
        db.ensure_genesis_applied(genesis_block_update.clone()).await?;
        tracing::info!("[REALM_STARTUP] ensure_genesis_applied done");
        let (mut global_user_tree,) = load_realm_memory_trees_from_db::<N, _>(&db.db, db.state.gathering_checkpoint_id, db.state.realm_id_u64)
            .await?
            .into_tuple();
        tracing::info!("[REALM_STARTUP] load_realm_memory_trees_from_db done");
        let rollback_target_is_published = if let Some(directive) = rollback_restart_directive.as_ref() {
            let control = rollback_runtime_control.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "Realm rollback restart directive requires durable rollback control"
                )
            })?;
            let network = psy_data::protocol::canonical_chain::NetworkId::try_from_chain_id(
                db.state.chain_id,
            )?;
            let head = match control.read_realm_rollback_control_head(network).await? {
                psy_node_core::store::canonical_head::CanonicalHeadReadState::Current(head) => head,
                psy_node_core::store::canonical_head::CanonicalHeadReadState::Uninitialized => {
                    anyhow::bail!("Realm rollback restart canonical head is missing")
                }
            };
            match head.rollback_control() {
                psy_node_core::store::rollback_control::RollbackControlState::Idle => {
                    if head.canonical_ref() != directive.target() {
                        anyhow::bail!(
                            "Realm rollback restart directive does not match published target"
                        )
                    }
                    true
                }
                psy_node_core::store::rollback_control::RollbackControlState::Verifying(request)
                | psy_node_core::store::rollback_control::RollbackControlState::AllRealmsReady(
                    request,
                ) => {
                    if head.canonical_ref().network_id() != directive.target().network_id()
                        || head.canonical_ref().chain_epoch() != directive.target().chain_epoch()
                        || request.target() != directive.target().checkpoint()
                        || request.plan_digest().as_bytes()
                            != directive.participant_plan_digest()
                    {
                        anyhow::bail!(
                            "Realm rollback restart directive does not match active request"
                        )
                    }
                    false
                }
                _ => anyhow::bail!(
                    "Realm rollback restart requires VERIFYING, ALL_REALMS_READY, or published target"
                ),
            }
        } else {
            false
        };
        db.init_with_setup_and_genesis(
            &file_system,
            &guta_gatherer_backup_directory,
            genesis_block_update,
            &mut global_user_tree,
            rollback_restart_directive,
            rollback_target_is_published,
        )
            .await?;
        tracing::info!("[REALM_STARTUP] init_with_setup_and_genesis done");
        //db.set_new_unique_ids().await?;
        tracing::info!("intialized realm processor database, building gatherers...");

        let guta_create_builder_config = RealmGUTAEndCapGathererConfig::<N, TempDatabase, FileSystem> {
            realm_id_u64: db.state.realm_id_u64,
            realm_sub_id_u64: db.state.realm_sub_id_u64,
            status: db.shared_state.inner.clone(),
            temp_db: db.temp_db.clone(),
            backup_file_directory: guta_gatherer_backup_directory,
            coordinator_guta_updates_circuit_whitelist: db.circuit_fingerprint_config.guta_circuit_whitelist_root,
            checkpoint_tree: db.checkpoint_tree_backup_manager.checkpoint_tree.clone(),
            file_system: file_system.clone(),
            _phantom_n: std::marker::PhantomData,
            future_pending_end_cap_jobs: Arc::new(std::sync::RwLock::new(Vec::new())),
            durable_external_dependencies: None,
        };
        /*
        if db.last_committed.l2_state.next_contract_id as u64 != db_tree_next_contract_id {
            return Err(anyhow::anyhow!(
                "Inconsistent next contract id between db last committed l2 state {} and loaded tree next contract id {}",
                db.last_committed.l2_state.next_contract_id,
                db_tree_next_contract_id
            ));
        }
        if db.last_committed.l2_state.next_user_id != db_tree_next_user_registration_id {
            return Err(anyhow::anyhow!(
                "Inconsistent next user registration id between db last committed l2 state {} and loaded tree next user registration id {}",
                db.last_committed.l2_state.next_user_id,
                db_tree_next_user_registration_id
            ));
        }
        */
        let branch_exact = normal_commit_owner.is_branch_exact();
        let mut gatherer_queue_key =
            db.guta_queue_key_status_manager.get_queue_key()?;
        let (guta_queue_gatherer, guta_join_handle) = if branch_exact {
            // The branch-exact actor is command-only: it owns no subscriber
            // and is bound to the already-closed processing generation.
            gatherer_queue_key.unique_id =
                db.state.processing_proc_checkpoint_unique_id;
            EphemeralQueueGathererWithTree::new_durable_with_status::<
                RealmGUTAEndCapGathererConfig<N, TempDatabase, FileSystem>,
                N::QHash,
                N::HasherBase,
                RealmGUTAEndCapGatherer<N, TempDatabase, FileSystem>,
            >(
                guta_create_builder_config,
                gatherer_queue_key,
                global_user_tree,
                db.status.clone(),
            )
        } else {
            EphemeralQueueGathererWithTree::new_with_status::<
                GUTAUpdateQueue,
                RealmGUTAEndCapGathererConfig<N, TempDatabase, FileSystem>,
                N::QHash,
                N::HasherBase,
                RealmGUTAEndCapGatherer<N, TempDatabase, FileSystem>,
            >(
                db.guta_update_queue.clone(),
                guta_create_builder_config,
                gatherer_queue_key,
                global_user_tree,
                db.status.clone(),
            )
        };

        Ok((
            Self {
                db,
                guta_queue_gatherer: guta_queue_gatherer,
                proof_worker_queue_max_time_ms: u64::MAX,
                proof_verifier,
                iteration_quiescence: Default::default(),
                normal_commit_owner: Some(normal_commit_owner),
                control_owner: None,
                rollback_runtime_control,
            },
            guta_join_handle,
        ))
    }

    /// Install the process-local h23b2 drain owner. This is deliberately not
    /// called by ordinary startup: h23b3 must first prove durable route and
    /// activation readiness before a production composition root may opt in.
    pub(crate) fn enable_process_local_drain_control(
        &mut self,
    ) -> Result<RealmProcessorControlHandle, RealmProcessorControlError> {
        if self.control_owner.is_some() {
            return Err(RealmProcessorControlError::AlreadyEnabled);
        }
        let (owner, handle) = new_realm_processor_control_plane();
        self.iteration_quiescence =
            psy_node_core::store::realm_processor_quiescence::RealmProcessorIterationGate::controlled();
        self.control_owner = Some(owner);
        Ok(handle)
    }

    pub async fn get_latest_checkpoint_id_internal(&self) -> anyhow::Result<u64> {
        self.db.db.get_latest_checkpoint_id().await
    }
    pub async fn get_current_unique_pending_id_internal(&self) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)> {
        self.db.db.get_current_unique_pending_id().await
    }

    pub async fn setup(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    pub async fn write_all_updates_to_db(&self) -> anyhow::Result<()> {
        Ok(())
    }
}
