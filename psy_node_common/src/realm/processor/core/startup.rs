use std::sync::Arc;

use parth_core::felt::ToU64Value;
use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleZeroHasher},
    protocol::core_types::QNetworkTypesConfig,
    QCoreProcCheckpointUniqueId,
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::prepared_block::realm::PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate;
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    p2p::traits::realm_coordinantor::RealmCoordinatorClient,
    psy_core_db::traits::full::{PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore},
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueueSubscriber, worker_queue::QStandardWorkerQueuePublisher},
    store::traits::proof_store::QParthProofStore,
};

use crate::{
    backup::realm::load_realm_memory_trees_from_db,
    queue::gatherer::EphemeralQueueGathererWithTree,
    realm::processor::{
        core::PsyRealmProcessor,
        db::PsyRealmDatabaseProcessor,
        gatherers::realm_end_cap_gatherer::{load_checkpoint_validator, RealmGUTAEndCapGatherer, RealmGUTAEndCapGathererConfig},
    },
};

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync + 'static,
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
    N::HasherBase: MerkleZeroHasher<N::QHash> + FieldQHasher<N::F, N::QHash>,
{
    pub async fn new(
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
        proposal_store: std::sync::Arc<crate::realm::processor::proposal_store::ProposalStore>,
        proposal_fetch: Option<crate::realm::network::RealmNetworkCommands>,
    ) -> anyhow::Result<Self> {
        tracing::info!("[REALM_STARTUP] processor new start");
        db.ensure_genesis_applied(genesis_block_update.clone()).await?;
        tracing::info!("[REALM_STARTUP] ensure_genesis_applied done");
        let (mut global_user_tree,) = load_realm_memory_trees_from_db::<N, _>(&db.db, db.state.gathering_checkpoint_id, db.state.realm_id_u64)
            .await?
            .into_tuple();
        tracing::info!("[REALM_STARTUP] load_realm_memory_trees_from_db done");
        db.init_with_setup_and_genesis(
            &file_system,
            &guta_gatherer_backup_directory,
            genesis_block_update,
            &mut global_user_tree,
            proposal_store.as_ref(),
            proposal_fetch.as_ref(),
        )
            .await?;
        tracing::info!("[REALM_STARTUP] init_with_setup_and_genesis done");
        let (global_user_tree,) = load_realm_memory_trees_from_db::<N, _>(
            &db.db,
            db.state.last_committed_checkpoint_id,
            db.state.realm_id_u64,
        )
        .await?
        .into_tuple();
        tracing::info!("[REALM_STARTUP] reloaded gatherer tree after catch-up");
        tracing::info!("intialized realm processor database, building gatherers...");
        let (validator_preimage, _, _) = load_checkpoint_validator::<N, _>(
            &db.db, &db.state, db.state.last_committed_checkpoint_id).await?;
        let validator_leaf = db.db
            .get_user_leaf(db.state.last_committed_checkpoint_id, validator_preimage.validator_user_id).await?;
        anyhow::ensure!(validator_leaf.user_id.to_u64_value() == validator_preimage.validator_user_id,
            "checkpoint validator user leaf belongs to another user");
        let guta_create_builder_config = RealmGUTAEndCapGathererConfig::<N, TempDatabase, FileSystem> {
            realm_id_u64: db.state.realm_id_u64,
            realm_sub_id_u64: db.state.realm_sub_id_u64,
            status: db.shared_state.inner.clone(),
            temp_db: db.temp_db.clone(),
            file_system: file_system.clone(),
            backup_file_directory: guta_gatherer_backup_directory.clone(),
            coordinator_guta_updates_circuit_whitelist: db.circuit_fingerprint_config.guta_circuit_whitelist_root,
            checkpoint_tree: db.checkpoint_tree_backup_manager.checkpoint_tree.clone(),
            future_pending_end_cap_jobs: Arc::new(std::sync::RwLock::new(Vec::new())),
            current_validator_user_leaf: Arc::new(std::sync::Mutex::new(validator_leaf)),
            tree_store: db.db.clone(),
            _phantom_n: std::marker::PhantomData,
        };
        let (guta_queue_gatherer, guta_gatherer_join) = EphemeralQueueGathererWithTree::new_with_status::<
            GUTAUpdateQueue,
            RealmGUTAEndCapGathererConfig<N, TempDatabase, FileSystem>,
            N::QHash,
            N::HasherBase,
            RealmGUTAEndCapGatherer<N, TempDatabase, FileSystem>,
        >(
            db.guta_update_queue.clone(),
            guta_create_builder_config,
            db.guta_queue_key_status_manager.get_queue_key()?,
            global_user_tree,
            db.status.clone(),
        );

        Ok(Self {
            db,
            guta_queue_gatherer,
            proof_worker_queue_max_time_ms: u64::MAX,
            p2p: None,
            rotation: None,
            bls_secret: None,
            proposal_store,
            baseline_replay_rx: None,
            file_system,
            guta_gatherer_backup_directory,
            guta_gatherer_join: Some(guta_gatherer_join),
        })
    }

    /// Wire optional Realm P2P into the processor after construction.
    ///
    /// `commands` is a cloneable handle into the Realm network drive loop
    /// (which must be started separately — the processor never starts the
    /// Swarm or takes the event receiver). `rotation` gates the
    /// scheduled-proposer check; `bls_secret` signs the processor's own Vote.
    /// Until this is called the processor behaves exactly as today's
    /// single-producer HTTP/NATS path.
    pub fn set_realm_p2p(
        &mut self,
        commands: crate::realm::network::RealmNetworkCommands,
        rotation: parth_common::realm_rotation::RealmRotationConfig,
        bls_secret: psy_data::p2p::BlsSecretKey,
    ) {
        self.p2p = Some(commands);
        self.rotation = Some(rotation);
        self.bls_secret = Some(bls_secret);
    }

    pub fn set_baseline_replay_rx(
        &mut self,
        baseline_replay_rx: tokio::sync::mpsc::Receiver<
            crate::realm::processor::recovery::BaselineReplayRequest<N::QHash>,
        >,
    ) {
        self.baseline_replay_rx = Some(baseline_replay_rx);
    }

    pub async fn abort_production_gatherer(&mut self) {
        let Some(handle) = self.guta_gatherer_join.take() else {
            return;
        };
        handle.abort();
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::error!("production gatherer failed during abort: {error:#}");
            }
            Err(join_error) if !join_error.is_cancelled() => {
                tracing::error!("production gatherer join error during abort: {join_error}");
            }
            Err(_) => {}
        }
    }

    pub async fn run_init_catchup(&mut self) -> anyhow::Result<()>
    where
        N::HasherBase: parth_core::crypto::hash::traits::MerkleZeroHasher<N::QHash>,
    {
        self.abort_production_gatherer().await;
        let (mut global_user_tree,) = load_realm_memory_trees_from_db::<N, _>(
            &self.db.db,
            self.db.state.last_committed_checkpoint_id,
            self.db.state.realm_id_u64,
        )
        .await?
        .into_tuple();
        self.db.set_committed_realm_roots_from_db().await?;
        self.db
            .ensure_backup_restored_if_necessary(
                &self.file_system,
                &self.guta_gatherer_backup_directory,
                &mut global_user_tree,
                self.proposal_store.as_ref(),
                self.p2p.as_ref(),
            )
            .await?;
        self.db.sync_to_coordinator_set_checkpoint_id().await?;
        self.rebuild_production_gatherer().await
    }

    pub async fn rebuild_production_gatherer(&mut self) -> anyhow::Result<()>
    where
        N::HasherBase: parth_core::crypto::hash::traits::MerkleZeroHasher<N::QHash>,
    {
        self.abort_production_gatherer().await;
        let (global_user_tree,) = load_realm_memory_trees_from_db::<N, _>(
            &self.db.db,
            self.db.state.last_committed_checkpoint_id,
            self.db.state.realm_id_u64,
        )
        .await?
        .into_tuple();
        let (validator_preimage, _, _) = load_checkpoint_validator::<N, _>(
            &self.db.db,
            &self.db.state,
            self.db.state.last_committed_checkpoint_id,
        )
        .await?;
        let validator_leaf = self
            .db
            .db
            .get_user_leaf(self.db.state.last_committed_checkpoint_id, validator_preimage.validator_user_id)
            .await?;
        anyhow::ensure!(
            validator_leaf.user_id.to_u64_value() == validator_preimage.validator_user_id,
            "checkpoint validator user leaf belongs to another user"
        );
        let guta_create_builder_config = RealmGUTAEndCapGathererConfig::<N, TempDatabase, FileSystem> {
            realm_id_u64: self.db.state.realm_id_u64,
            realm_sub_id_u64: self.db.state.realm_sub_id_u64,
            status: self.db.shared_state.inner.clone(),
            temp_db: self.db.temp_db.clone(),
            file_system: self.file_system.clone(),
            backup_file_directory: self.guta_gatherer_backup_directory.clone(),
            coordinator_guta_updates_circuit_whitelist: self.db.circuit_fingerprint_config.guta_circuit_whitelist_root,
            checkpoint_tree: self.db.checkpoint_tree_backup_manager.checkpoint_tree.clone(),
            future_pending_end_cap_jobs: Arc::new(std::sync::RwLock::new(Vec::new())),
            current_validator_user_leaf: Arc::new(std::sync::Mutex::new(validator_leaf)),
            tree_store: self.db.db.clone(),
            _phantom_n: std::marker::PhantomData,
        };
        let (guta_queue_gatherer, guta_gatherer_join) = EphemeralQueueGathererWithTree::new_with_status::<
            GUTAUpdateQueue,
            RealmGUTAEndCapGathererConfig<N, TempDatabase, FileSystem>,
            N::QHash,
            N::HasherBase,
            RealmGUTAEndCapGatherer<N, TempDatabase, FileSystem>,
        >(
            self.db.guta_update_queue.clone(),
            guta_create_builder_config,
            self.db.guta_queue_key_status_manager.get_queue_key()?,
            global_user_tree,
            self.db.status.clone(),
        );
        self.guta_queue_gatherer = guta_queue_gatherer;
        self.guta_gatherer_join = Some(guta_gatherer_join);
        Ok(())
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
