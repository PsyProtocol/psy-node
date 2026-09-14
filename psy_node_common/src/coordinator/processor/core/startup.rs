use std::sync::Arc;

use parth_core::{protocol::core_types::QNetworkTypesConfig, QCoreProcCheckpointUniqueId};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::prepared_block::coordinator::PsyPreparedCoordinatorBlockStateUpdates;
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    psy_core_db::traits::full::{PsyCoordinatorProcessorStore, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter},
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueueSubscriber, worker_queue::QStandardWorkerQueuePublisher},
    store::traits::proof_store::QParthProofStore,
};

use crate::{
    backup::coordinator::load_coordinator_memory_trees_from_db,
    coordinator::processor::{
        db::PsyCoordinatorDatabaseProcessor,
        gatherers::{
            contract_gatherer::{ContractGathererConfig, ContractQueueGatherer},
            coordinator_guta_update_gatherer::{CoordinatorGUTAUpdateGatherer, CoordinatorGUTAUpdateGathererConfig},
            deploy_contract_gatherer::DeployContractGathererConfig,
            register_user_gatherer::{RegisterUserGatherer, RegisterUserGathererConfig},
            update_contract_gatherer::UpdateContractGathererConfig,
        },
        PsyCoordinatorProcessor,
    },
    queue::gatherer::EphemeralQueueGathererWithTree,
};

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync + 'static,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        RegisterUserQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        DeployContractQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        ProofWorkQueue: QStandardWorkerQueuePublisher + Send + Sync,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
    >
    PsyCoordinatorProcessor<
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
    >
where
    FileSystem::File: Send + Sync,
{
    pub async fn new(
        mut db: PsyCoordinatorDatabaseProcessor<
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
        >,
        genesis_block_update: PsyPreparedCoordinatorBlockStateUpdates<N::F, N::QHash>,
        file_system: Arc<FileSystem>,
        deploy_contract_gatherer_backup_directory: String,
        update_contract_gatherer_backup_directory: String,
        register_user_gatherer_backup_directory: String,
        guta_gatherer_backup_directory: String,
    ) -> anyhow::Result<(
        Self,
        tokio::task::JoinHandle<Result<(), anyhow::Error>>,
        tokio::task::JoinHandle<Result<(), anyhow::Error>>,
        tokio::task::JoinHandle<Result<(), anyhow::Error>>,
    )> {
        tracing::info!("[COORD_STARTUP] processor new start");
        db.ensure_genesis_applied(genesis_block_update.clone()).await?;
        tracing::info!("[COORD_STARTUP] ensure_genesis_applied done");
        let (
            _db_tree_next_user_registration_id,
            _db_tree_next_contract_id,
            mut user_registration_tree,
            mut global_user_tree,
            mut global_contract_tree,
        ) = load_coordinator_memory_trees_from_db::<N, _>(&db.db, db.ids.checkpoint_id + 1)
            .await?
            .into_tuple();
        tracing::info!("[COORD_STARTUP] load_coordinator_memory_trees_from_db done");
        db.init_with_setup_and_genesis(
            &file_system,
            &deploy_contract_gatherer_backup_directory,
            &update_contract_gatherer_backup_directory,
            &register_user_gatherer_backup_directory,
            &guta_gatherer_backup_directory,
            genesis_block_update,
            &mut global_user_tree,
            &mut global_contract_tree,
            &mut user_registration_tree,
        )
        .await?;
        tracing::info!("[COORD_STARTUP] init_with_setup_and_genesis done");
        //db.set_new_unique_ids().await?;
        tracing::info!("intialized coordinator processor database, building gatherers...");

        let guta_create_builder_config = CoordinatorGUTAUpdateGathererConfig::<N, TempDatabase, FileSystem> {
            realm_id_u64: db.ids.realm_id_u64,
            realm_sub_id_u64: db.ids.realm_sub_id_u64,
            status: db.shared_status.inner.clone(),
            temp_db: db.temp_db.clone(),
            backup_file_directory: guta_gatherer_backup_directory,
            coordinator_guta_updates_circuit_whitelist: db.circuit_fingerprint_config.guta_circuit_whitelist_root,
            checkpoint_tree: db.checkpoint_tree_backup_manager.checkpoint_tree.clone(),
            file_system: file_system.clone(),
            last_old_realm_roots: Arc::new(std::sync::RwLock::new(Vec::new())),
            _phantom_n: std::marker::PhantomData,
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
            CoordinatorGUTAUpdateGathererConfig<N, TempDatabase, FileSystem>,
            N::QHash,
            N::HasherBase,
            CoordinatorGUTAUpdateGatherer<N, TempDatabase, FileSystem>,
        >(
            db.guta_update_queue.clone(),
            guta_create_builder_config,
            db.guta_queue_key_status_manager.get_queue_key()?,
            global_user_tree,
            db.status.clone(),
        );

        let (register_user_queue_gatherer, register_user_join_handle) = EphemeralQueueGathererWithTree::new_with_status::<
            RegisterUserQueue,
            RegisterUserGathererConfig<N, TempDatabase, FileSystem>,
            N::QHash,
            N::HasherBase,
            RegisterUserGatherer<N, TempDatabase, FileSystem>,
        >(
            db.register_user_queue.clone(),
            RegisterUserGathererConfig {
                realm_id_u64: db.ids.realm_id_u64,
                realm_sub_id_u64: db.ids.realm_sub_id_u64,
                temp_db: db.temp_db.clone(),

                backup_file_directory: register_user_gatherer_backup_directory,
                _phantom_n: std::marker::PhantomData,
                status: db.shared_status.inner.clone(),
                register_users_circuit_whitelist: db.circuit_fingerprint_config.register_users_circuit_whitelist_root,
                last_job_next_user_id: Arc::new(std::sync::RwLock::new(db.last_committed.l2_state.next_user_id)),
                file_system: file_system.clone(),
            },
            db.register_user_queue_key_status_manager.get_queue_key()?,
            user_registration_tree,
            db.status.clone(),
        );
        let (deploy_contract_queue_gatherer, deploy_contract_join_handle) = ContractQueueGatherer::<N>::new_with_status::<
            DeployContractQueue,
            S,
            TempDatabase,
            FileSystem,
        >(
            db.deploy_contract_queue.clone(),
            ContractGathererConfig {
                deploy: DeployContractGathererConfig {
                    realm_id_u64: db.ids.realm_id_u64,
                    realm_sub_id_u64: db.ids.realm_sub_id_u64,
                    temp_db: db.temp_db.clone(),
                    backup_file_directory: deploy_contract_gatherer_backup_directory.clone(),
                    _phantom_n: std::marker::PhantomData,
                    shared_status: db.shared_status.inner.clone(),
                    deploy_contract_circuit_whitelist: db.circuit_fingerprint_config.deploy_contracts_circuit_whitelist_root,
                    last_job_next_contract_id: Arc::new(std::sync::RwLock::new(db.last_committed.l2_state.next_contract_id as u64)),
                    file_system: file_system.clone(),
                },
                update: UpdateContractGathererConfig {
                    realm_id_u64: db.ids.realm_id_u64,
                    realm_sub_id_u64: db.ids.realm_sub_id_u64,
                    shared_status: db.shared_status.inner.clone(),
                    temp_db: db.temp_db.clone(),
                    contract_leaf_reader: db.db.clone(),
                    backup_file_directory: update_contract_gatherer_backup_directory,
                    update_contract_circuit_whitelist: db.circuit_fingerprint_config.update_contracts_circuit_whitelist_root,
                    file_system: file_system.clone(),
                    _phantom_n: std::marker::PhantomData,
                },
            },
            db.deploy_contract_queue_key_status_manager.get_queue_key()?,
            db.update_contract_queue_key_status_manager.get_queue_key()?,
            global_contract_tree,
            db.status.clone(),
        );

        Ok((
            Self {
                db,
                guta_queue_gatherer: guta_queue_gatherer,
                register_user_queue_gatherer: register_user_queue_gatherer,
                deploy_contract_queue_gatherer: deploy_contract_queue_gatherer,
                proof_worker_queue_max_time_ms: u64::MAX,
            },
            guta_join_handle,
            register_user_join_handle,
            deploy_contract_join_handle,
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

    use parth_core::{
        crypto::hash::traits::MerkleZeroHasher, node::realm_identifier::QRealmIdentifier, utils::QPGenRandom, PHash, PF,
    };
    use psy_core::job::job_id::QProvingJobDataID;
    use psy_data::{
        config::network_config::PsyNodeCircuitFingerprintConfig,
        genesis::genesis_block_setup::PsyGenesisBlockSetupData,
        v1::qdata::{
            checkpoint::PQEDCheckpointLeafStats,
            contract::{ContractCodeDefinition, PQBCDeployContract},
        },
    };
    use psy_node_core::{
        file::memory_fs::SimpleMockMemoryFileSystem, psy_core_db::traits::full::PsyNodeCheckpointObjectDatabaseReader,
    };
    use psy_node_store_memory::temp_store::InMemoryTempStore;

    use crate::{
        coordinator::processor::{create::create_coordinator_processor, PsyCoordinatorProcessor},
        test_common::{
            create_test_unified_db, FakeEphemeralQueueSubscriber, FakeWorkerQueue, TestNetworkConfig,
            TestUnifiedDatabaseStore,
        },
        utils::processor_status::ProcessorState,
    };

    pub(crate) type N = TestNetworkConfig;

    /// Coordinator processor wired the way `create_coordinator_processor`
    /// builds it in production, but over the all-fake in-memory infrastructure.
    pub(crate) type TestProcessor = PsyCoordinatorProcessor<
        N,
        TestUnifiedDatabaseStore,
        TestUnifiedDatabaseStore,
        FakeEphemeralQueueSubscriber,
        FakeEphemeralQueueSubscriber,
        FakeEphemeralQueueSubscriber,
        FakeWorkerQueue,
        InMemoryTempStore,
        InMemoryTempStore,
        SimpleMockMemoryFileSystem,
    >;

    pub(crate) fn zh(level: usize) -> PHash {
        parth_core::pgoldilocks::PoseidonHasher::get_zero_hash(level)
    }

    pub(crate) fn fingerprint_config() -> PsyNodeCircuitFingerprintConfig<PHash> {
        PsyNodeCircuitFingerprintConfig {
            guta_circuit_whitelist_root: zh(21),
            register_users_circuit_whitelist_root: zh(22),
            deploy_contracts_circuit_whitelist_root: zh(23),
            update_contracts_circuit_whitelist_root: zh(24),
            checkpoint_state_transition_circuit_fingerprint: zh(25),
            genesis_checkpoint_state_transition_fingerprint: zh(26),
        }
    }

    pub(crate) fn genesis_setup_data() -> PsyGenesisBlockSetupData<PF, PHash> {
        let contract = PQBCDeployContract::new(
            PHash::from_values(1, 0, 0, 0),
            ContractCodeDefinition { state_tree_height: 8, functions: vec![] },
            vec![PHash::from_values(2, 0, 0, 0)],
            PHash::from_values(3, 0, 0, 0),
        );
        // the checkpoint witness reconstructs the genesis deposit/withdrawal
        // roots as the empty trees of their protocol heights, so genesis must
        // commit exactly those roots or the first block's witness consistency
        // check fails
        PsyGenesisBlockSetupData {
            contracts: vec![contract],
            users: vec![],
            checkpoint_stats: PQEDCheckpointLeafStats::qp_rand_gen(),
            deposit_tree_root: zh(psy_core::constants::protocol::TODO_DEPOSIT_TREE_HEIGHT as usize),
            withdrawal_tree_root: zh(psy_core::constants::protocol::TODO_WITHDRAWAL_TREE_HEIGHT as usize),
        }
    }

    /// Shared environment for coordinator processor tests: the processor is
    /// built through the real `create_coordinator_processor` entry point with
    /// every external dependency faked, so construction side effects land in
    /// the stores and queues exposed here. The gatherer background tasks stay
    /// alive so gatherer finalization can be driven; call `abort_gatherers`
    /// when the test is done with them.
    pub(crate) struct CoordinatorProcessorTestEnv {
        pub processor: TestProcessor,
        pub db: Arc<TestUnifiedDatabaseStore>,
        pub temp_db: Arc<InMemoryTempStore>,
        pub guta_queue: Arc<FakeEphemeralQueueSubscriber>,
        pub register_queue: Arc<FakeEphemeralQueueSubscriber>,
        pub deploy_queue: Arc<FakeEphemeralQueueSubscriber>,
        pub proof_work_queue: Arc<FakeWorkerQueue>,
        pub file_system: Arc<SimpleMockMemoryFileSystem>,
        pub guta_gatherer_handle: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
        pub register_gatherer_handle: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
        pub deploy_gatherer_handle: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
    }

    impl CoordinatorProcessorTestEnv {
        pub(crate) async fn create() -> anyhow::Result<Self> {
            Self::create_with_genesis(&genesis_setup_data()).await
        }

        /// Builds the processor over a fresh database, sharing `db` and
        /// `file_system` so tests that construct twice against the same store
        /// model a restart that keeps its checkpoint-tree backup file.
        pub(crate) async fn create_with_genesis_over_db(
            genesis_data: &PsyGenesisBlockSetupData<PF, PHash>,
            db: Arc<TestUnifiedDatabaseStore>,
            file_system: Arc<SimpleMockMemoryFileSystem>,
        ) -> anyhow::Result<Self> {
            let tag_tree = Arc::clone(&db);
            let temp_db = Arc::new(InMemoryTempStore::new("coord_proc_test".to_string(), 1, 2));
            let proof_store = Arc::clone(&temp_db);
            let guta_queue = Arc::new(FakeEphemeralQueueSubscriber::new());
            let register_queue = Arc::new(FakeEphemeralQueueSubscriber::new());
            let deploy_queue = Arc::new(FakeEphemeralQueueSubscriber::new());
            let proof_work_queue = Arc::new(FakeWorkerQueue::new());
            let (processor, guta_gatherer_handle, register_gatherer_handle, deploy_gatherer_handle) =
                create_coordinator_processor::<N, _, _, _, _, _, _, _, _, _>(
                    genesis_data,
                    Arc::clone(&file_system),
                    "coord_test_deploy_backups".to_string(),
                    "coord_test_update_backups".to_string(),
                    "coord_test_register_backups".to_string(),
                    "coord_test_guta_backups".to_string(),
                    "coord_test_checkpoint_tree_backup.bin".to_string(),
                    Arc::clone(&db),
                    tag_tree,
                    Arc::clone(&temp_db),
                    Arc::clone(&proof_store),
                    Arc::clone(&guta_queue),
                    Arc::clone(&register_queue),
                    Arc::clone(&deploy_queue),
                    Arc::clone(&proof_work_queue),
                    QRealmIdentifier::new(1, 2),
                    fingerprint_config(),
                )
                .await?;
            Ok(Self {
                processor,
                db,
                temp_db,
                guta_queue,
                register_queue,
                deploy_queue,
                proof_work_queue,
                file_system,
                guta_gatherer_handle,
                register_gatherer_handle,
                deploy_gatherer_handle,
            })
        }

        pub(crate) async fn create_with_genesis(
            genesis_data: &PsyGenesisBlockSetupData<PF, PHash>,
        ) -> anyhow::Result<Self> {
            Self::create_with_genesis_over_db(
                genesis_data,
                Arc::new(create_test_unified_db().await?),
                Arc::new(SimpleMockMemoryFileSystem::new()),
            )
            .await
        }

        pub(crate) fn abort_gatherers(&self) {
            self.guta_gatherer_handle.abort();
            self.register_gatherer_handle.abort();
            self.deploy_gatherer_handle.abort();
        }
    }

    #[tokio::test]
    async fn create_applies_genesis_and_spawns_gatherers() -> anyhow::Result<()> {
        let env = CoordinatorProcessorTestEnv::create().await?;

        // genesis was committed through the real startup path
        assert_eq!(env.db.get_latest_checkpoint_id().await?, 0);
        assert_eq!(env.db.get_checkpoint_id_for_unique_pending_id(0).await?, Some(0));

        // construction rotates the unique ids exactly once: the genesis
        // processing ids stay at 0 while gathering graduates to the next
        // pending id with a fresh random processor id
        let ids = &env.processor.db.ids;
        assert_eq!(ids.checkpoint_id, 0);
        assert_eq!(ids.next_checkpoint_id, 1);
        assert_eq!(ids.unique_pending_id, 0);
        assert_eq!(ids.proc_checkpoint_unique_id, 0u128);
        assert_eq!(ids.gathering_unique_pending_id, 1);
        assert_ne!(ids.gathering_proc_checkpoint_unique_id, 0u128);
        assert_eq!(ids.realm_id_u64, 1);
        assert_eq!(ids.realm_sub_id_u64, 2);

        // processor defaults: unlimited worker wait, starting status
        assert_eq!(env.processor.proof_worker_queue_max_time_ms, u64::MAX);
        assert_eq!(env.processor.db.status.state(), ProcessorState::Starting);

        // gatherer background tasks are alive until aborted
        assert!(!env.guta_gatherer_handle.is_finished());
        assert!(!env.register_gatherer_handle.is_finished());
        assert!(!env.deploy_gatherer_handle.is_finished());
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn second_create_over_committed_db_keeps_genesis_state() -> anyhow::Result<()> {
        // both constructions must use identical genesis data, as a real
        // restart re-reads the same genesis file
        let genesis_data = genesis_setup_data();
        let first = CoordinatorProcessorTestEnv::create_with_genesis(&genesis_data).await?;
        let db = Arc::clone(&first.db);
        let file_system = Arc::clone(&first.file_system);
        first.abort_gatherers();

        // restart with the same database and the same checkpoint-tree backup
        // file, as a real process restart would
        let second =
            CoordinatorProcessorTestEnv::create_with_genesis_over_db(&genesis_data, db.clone(), file_system).await?;
        second.abort_gatherers();

        // still exactly the genesis checkpoint, with the original pending-id
        // mapping intact (a re-commit would have rewritten checkpoint state)
        assert_eq!(db.get_latest_checkpoint_id().await?, 0);
        assert_eq!(db.get_checkpoint_id_for_unique_pending_id(0).await?, Some(0));
        assert_eq!(second.processor.db.ids.checkpoint_id, 0);
        Ok(())
    }

    #[tokio::test]
    async fn accessors_read_database_state_and_lifecycle_helpers_are_noops() -> anyhow::Result<()> {
        let mut env = CoordinatorProcessorTestEnv::create().await?;

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
