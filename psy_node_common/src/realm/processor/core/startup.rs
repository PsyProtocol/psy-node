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
    store::traits::proof_store::QParthProofStore,
};

use crate::{
    backup::realm::load_realm_memory_trees_from_db,
    queue::gatherer::EphemeralQueueGathererWithTree,
    realm::processor::{
        core::PsyRealmProcessor,
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
    ) -> anyhow::Result<(Self, tokio::task::JoinHandle<Result<(), anyhow::Error>>)> {
        tracing::info!("[REALM_STARTUP] processor new start");
        db.ensure_genesis_applied(genesis_block_update.clone()).await?;
        tracing::info!("[REALM_STARTUP] ensure_genesis_applied done");
        let (mut global_user_tree,) = load_realm_memory_trees_from_db::<N, _>(&db.db, db.state.gathering_checkpoint_id, db.state.realm_id_u64)
            .await?
            .into_tuple();
        tracing::info!("[REALM_STARTUP] load_realm_memory_trees_from_db done");
        db.init_with_setup_and_genesis(&file_system, &guta_gatherer_backup_directory, genesis_block_update, &mut global_user_tree)
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
        let (guta_queue_gatherer, guta_join_handle) = EphemeralQueueGathererWithTree::new_with_status::<
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

        Ok((
            Self {
                db,
                guta_queue_gatherer: guta_queue_gatherer,
                proof_worker_queue_max_time_ms: u64::MAX,
            },
            guta_join_handle,
        ))
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
