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
        guta_resend::realm_guta_resend_after_checkpoints_from_env,
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
        proposal_backup: std::sync::Arc<crate::realm::processor::proposal_backup::ProposalBackup>,
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
            proposal_backup.as_ref(),
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

        let guta_resend_after_checkpoints = realm_guta_resend_after_checkpoints_from_env()?;

        Ok(Self {
            db,
            guta_queue_gatherer,
            proof_worker_queue_max_time_ms: u64::MAX,
            p2p: None,
            rotation: None,
            bls_secret: None,
            proposal_backup,
            baseline_replay_rx: None,
            file_system,
            guta_gatherer_backup_directory,
            guta_resend_after_checkpoints,
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
            crate::realm::processor::ffs::BaselineReplayRequest<N::QHash>,
        >,
    ) {
        self.baseline_replay_rx = Some(baseline_replay_rx);
    }

    pub async fn abort_guta_gatherer(&mut self) {
        let Some(handle) = self.guta_gatherer_join.take() else {
            return;
        };
        handle.abort();
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::error!("guta gatherer failed during abort: {error:#}");
            }
            Err(join_error) if !join_error.is_cancelled() => {
                tracing::error!("guta gatherer join error during abort: {join_error}");
            }
            Err(_) => {}
        }
    }

    pub async fn run_init_catchup(&mut self) -> anyhow::Result<()>
    where
        N::HasherBase: parth_core::crypto::hash::traits::MerkleZeroHasher<N::QHash>,
    {
        self.abort_guta_gatherer().await;
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
                self.proposal_backup.as_ref(),
                self.p2p.as_ref(),
            )
            .await?;
        self.db.sync_to_coordinator_set_checkpoint_id().await?;
        self.recreate_guta_gatherer().await
    }

    pub async fn recreate_guta_gatherer(&mut self) -> anyhow::Result<()>
    where
        N::HasherBase: parth_core::crypto::hash::traits::MerkleZeroHasher<N::QHash>,
    {
        self.abort_guta_gatherer().await;
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

#[cfg(test)]
pub(crate) mod startup_tests {
    use std::sync::Arc;

    use psy_node_core::psy_core_db::traits::full::PsyNodeCheckpointObjectDatabaseReader;

    use crate::{
        realm::processor::{
            core::PsyRealmProcessor,
            create::create_realm_processor,
            db::realm_db_test_env::{
                fingerprint_config, test_realm_identifier, RealmDbTestEnv, TestRealmProcessor as TestRealmDatabaseProcessor,
                TEST_BACKUP_PATH, TEST_CHAIN_ID, TEST_GUTA_BACKUP_DIR,
            },
        },
        test_common::{FakeEphemeralQueueSubscriber, FakeWorkerQueue, TestUnifiedDatabaseStore},
        utils::processor_status::ProcessorState,
    };
    use psy_node_core::file::memory_fs::SimpleMockMemoryFileSystem;
    use psy_node_store_memory::temp_store::InMemoryTempStore;

    use crate::realm::processor::db::realm_db_test_env::{FakeRealmCoordinatorClient, N};

    /// Realm processor wired the way `create_realm_processor` builds it in
    /// production, over the all-fake realm database test environment.
    pub(crate) type TestProcessor = PsyRealmProcessor<
        N,
        TestUnifiedDatabaseStore,
        TestUnifiedDatabaseStore,
        FakeEphemeralQueueSubscriber,
        FakeWorkerQueue,
        InMemoryTempStore,
        InMemoryTempStore,
        SimpleMockMemoryFileSystem,
        FakeRealmCoordinatorClient,
    >;

    /// Shared environment for realm processor tests: the realm database test
    /// env (fake coordinator, stores, queues) plus a processor built through
    /// the real `create_realm_processor` entry point. The gatherer background
    /// task stays alive so gatherer finalization can be driven; call
    /// `abort_gatherers` when the test is done with it.
    pub(crate) struct RealmProcessorTestEnv {
        pub db_env: RealmDbTestEnv,
        pub processor: TestProcessor,
        pub guta_gatherer_handle: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
    }

    impl RealmProcessorTestEnv {
        /// Builds the processor over the environment's stores with the
        /// coordinator sitting consistently at the genesis checkpoint.
        pub(crate) async fn create_over_db_env(db_env: RealmDbTestEnv) -> anyhow::Result<Self> {
            db_env.coordinator.seed_realm_root(0, db_env.genesis.prepared_updates.new_realm_root);
            let (processor, guta_gatherer_handle) = create_realm_processor::<N, _, _, _, _, _, _, _, _>(
                TEST_CHAIN_ID,
                &db_env.genesis_data,
                Arc::clone(&db_env.file_system),
                TEST_GUTA_BACKUP_DIR.to_string(),
                TEST_BACKUP_PATH.to_string(),
                Arc::clone(&db_env.db),
                Arc::clone(&db_env.db),
                Arc::clone(&db_env.temp_db),
                Arc::clone(&db_env.temp_db),
                Arc::clone(&db_env.guta_queue),
                Arc::clone(&db_env.proof_queue),
                test_realm_identifier(),
                fingerprint_config(),
                Arc::clone(&db_env.coordinator),
            )
            .await?;
            // the genesis commit writes the realm-root node into the store;
            // make the coordinator's checkpoint-0 view agree with the
            // committed node value so sync_and_verify sees a consistent head
            // out of the box
            db_env.coordinator.seed_realm_root(0, db_env.local_realm_root().await?);
            Ok(Self { db_env, processor, guta_gatherer_handle })
        }

        pub(crate) async fn create() -> anyhow::Result<Self> {
            Self::create_over_db_env(RealmDbTestEnv::create().await?).await
        }

        pub(crate) fn abort_gatherers(&self) {
            self.guta_gatherer_handle.abort();
        }

        /// The db-level processor from the underlying env, for seeding
        /// helpers that operate on the shared store.
        #[allow(dead_code)]
        pub(crate) fn db_processor(&self) -> &TestRealmDatabaseProcessor {
            &self.db_env.processor
        }
    }

    #[tokio::test]
    async fn create_applies_genesis_and_spawns_gatherer() -> anyhow::Result<()> {
        let env = RealmProcessorTestEnv::create().await?;

        // genesis was committed through the real startup path
        assert_eq!(env.db_env.db.get_latest_checkpoint_id().await?, 0);
        assert_eq!(env.db_env.db.get_checkpoint_id_for_unique_pending_id(0).await?, Some(0));

        // construction rotates the unique ids exactly once: processing stays
        // at the genesis ids while gathering graduates to the next pending id
        // with a fresh random processor id
        let state = &env.processor.db.state;
        assert_eq!(state.processing_unique_pending_id, 0);
        assert_eq!(state.gathering_unique_pending_id, 1);
        assert_eq!(state.processing_proc_checkpoint_unique_id, 0u128);
        assert_ne!(state.gathering_proc_checkpoint_unique_id, 0u128);
        assert_eq!(state.last_committed_checkpoint_id, 0);
        assert_eq!(state.chain_id, TEST_CHAIN_ID);
        assert_eq!(state.realm_id_u64, crate::realm::processor::db::realm_db_test_env::TEST_REALM_ID);

        // processor defaults: unlimited worker wait, starting status
        assert_eq!(env.processor.proof_worker_queue_max_time_ms, u64::MAX);
        assert_eq!(
            env.processor.guta_resend_after_checkpoints,
            crate::realm::processor::guta_resend::REALM_GUTA_RESEND_AFTER_CHECKPOINTS_DEFAULT
        );
        assert_eq!(env.processor.db.status.state(), ProcessorState::Starting);

        // the gatherer background task is alive until aborted
        assert!(!env.guta_gatherer_handle.is_finished());
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn second_create_over_committed_db_keeps_genesis_state() -> anyhow::Result<()> {
        let first = RealmProcessorTestEnv::create().await?;
        let db = Arc::clone(&first.db_env.db);
        let file_system = Arc::clone(&first.db_env.file_system);
        let coordinator = Arc::clone(&first.db_env.coordinator);
        let temp_db = Arc::clone(&first.db_env.temp_db);
        let genesis_data = first.db_env.genesis_data.clone();
        first.abort_gatherers();

        // restart with the same database, checkpoint-tree backup file and
        // coordinator, as a real process restart would
        let (second_processor, second_gatherer_handle) = create_realm_processor::<N, _, _, _, _, _, _, _, _>(
            TEST_CHAIN_ID,
            &genesis_data,
            file_system,
            TEST_GUTA_BACKUP_DIR.to_string(),
            TEST_BACKUP_PATH.to_string(),
            Arc::clone(&db),
            Arc::clone(&db),
            Arc::clone(&temp_db),
            Arc::clone(&temp_db),
            Arc::new(FakeEphemeralQueueSubscriber::new()),
            Arc::new(FakeWorkerQueue::new()),
            test_realm_identifier(),
            fingerprint_config(),
            coordinator,
        )
        .await?;
        second_gatherer_handle.abort();

        // still exactly the genesis checkpoint, with the original pending-id
        // mapping intact (a re-commit would have rewritten checkpoint state)
        assert_eq!(db.get_latest_checkpoint_id().await?, 0);
        assert_eq!(db.get_checkpoint_id_for_unique_pending_id(0).await?, Some(0));
        assert_eq!(second_processor.db.state.last_committed_checkpoint_id, 0);
        Ok(())
    }

    #[tokio::test]
    async fn accessors_read_database_state_and_lifecycle_helpers_are_noops() -> anyhow::Result<()> {
        let mut env = RealmProcessorTestEnv::create().await?;

        assert_eq!(env.processor.get_latest_checkpoint_id_internal().await?, 0);
        // the db reports the current (gathering) pending id pair: 1 with a
        // fresh nonzero processor id after the construction-time rotation
        let (current_pending, current_proc) = env.processor.get_current_unique_pending_id_internal().await?;
        assert_eq!(current_pending, 1);
        assert_ne!(current_proc, 0u128);

        env.processor.setup().await?;
        env.processor.write_all_updates_to_db().await?;
        env.abort_gatherers();
        Ok(())
    }
}
