use std::sync::Arc;

use parth_core::{
    protocol::core_types::QNetworkTypesConfig,
    QCoreProcCheckpointUniqueId,
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    psy_core_db::traits::full::{
        PsyCoordinatorProcessorStore, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter,
    },
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::QStandardWorkerQueuePublisher,
    },
    store::traits::proof_store::QParthProofStore,
};

use crate::{
    backup::coordinator::load_coordinator_memory_trees_from_db,
    coordinator::processor::{
        data::CoordinatorProcessorInitData,
        db::PsyCoordinatorDatabaseProcessor,
        gatherers::{
            coordinator_guta_update_gatherer::{
                CoordinatorGUTAUpdateGatherer, CoordinatorGUTAUpdateGathererConfig,
            },
            deploy_contract_gatherer::{DeployContractGatherer, DeployContractGathererConfig},
            register_user_gatherer::{RegisterUserGatherer, RegisterUserGathererConfig},
        },
        PsyCoordinatorProcessor,
    },
    queue::gatherer::EphemeralQueueGathererWithTree,
};

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync,
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
    > where FileSystem::File: Send + Sync
{
    pub async fn new(
        db: PsyCoordinatorDatabaseProcessor<
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
        file_system: Arc<FileSystem>,
        coordinator_guta_updates_circuit_whitelist: N::QHash,
        register_users_circuit_whitelist: N::QHash,
        deploy_contract_circuit_whitelist: N::QHash,
        deploy_contract_gatherer_backup_directory: String,
        register_user_gatherer_backup_directory: String,
        guta_gatherer_backup_directory: String,
    ) -> anyhow::Result<(
        Self,
        tokio::task::JoinHandle<Result<(), anyhow::Error>>,
        tokio::task::JoinHandle<Result<(), anyhow::Error>>,
        tokio::task::JoinHandle<Result<(), anyhow::Error>>,
    )> {
        let guta_create_builder_config = CoordinatorGUTAUpdateGathererConfig::<N, TempDatabase, FileSystem> {
            realm_id_u64: db.realm_id_u64,
            realm_sub_id_u64: db.realm_sub_id_u64,
            status: db.shared_status.inner.clone(),
            temp_db: db.temp_db.clone(),
            backup_file_directory: guta_gatherer_backup_directory,
            coordinator_guta_updates_circuit_whitelist,
            checkpoint_tree: db.checkpoint_tree_backup_manager.checkpoint_tree.clone(),
            file_system: file_system.clone(),
            last_old_realm_roots: Arc::new(std::sync::RwLock::new(Vec::new())),
            _phantom_n: std::marker::PhantomData,
        };

        let (db_tree_next_user_registration_id, db_tree_next_contract_id, user_registration_tree, global_user_tree, global_contract_tree) =
            load_coordinator_memory_trees_from_db::<N, _>(&db.db, db.last_committed_checkpoint_id + 1)
                .await?
                .into_tuple();

        if db.last_committed_l2_state.next_contract_id as u64 != db_tree_next_contract_id {
            return Err(anyhow::anyhow!(
                "Inconsistent next contract id between db last committed l2 state {} and loaded tree next contract id {}",
                db.last_committed_l2_state.next_contract_id,
                db_tree_next_contract_id
            ));
        }
        if db.last_committed_l2_state.next_user_id != db_tree_next_user_registration_id {
            return Err(anyhow::anyhow!(
                "Inconsistent next user registration id between db last committed l2 state {} and loaded tree next user registration id {}",
                db.last_committed_l2_state.next_user_id,
                db_tree_next_user_registration_id
            ));
        }
        let init_data = CoordinatorProcessorInitData {
            db_tree_next_user_registration_id,
            db_tree_next_contract_id,
        };
        let (guta_queue_gatherer, guta_join_handle) = EphemeralQueueGathererWithTree::new_with_is_active::<
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
            db.is_active.clone(),
        );

        let (register_user_queue_gatherer, register_user_join_handle) = EphemeralQueueGathererWithTree::new_with_is_active::<
            RegisterUserQueue,
            RegisterUserGathererConfig<N, TempDatabase, FileSystem>,
            N::QHash,
            N::HasherBase,
            RegisterUserGatherer<N, TempDatabase, FileSystem>,
        >(
            db.register_user_queue.clone(),
            RegisterUserGathererConfig {
                realm_id_u64: db.realm_id_u64,
                realm_sub_id_u64: db.realm_sub_id_u64,
                temp_db: db.temp_db.clone(),
                
                backup_file_directory: register_user_gatherer_backup_directory,
                _phantom_n: std::marker::PhantomData,
                status: db.shared_status.inner.clone(),
                register_users_circuit_whitelist,
                last_job_next_user_id: Arc::new(std::sync::RwLock::new(init_data.db_tree_next_user_registration_id)),
                file_system: file_system.clone(),
            },
            db.register_user_queue_key_status_manager.get_queue_key()?,
            user_registration_tree,
            db.is_active.clone(),
        );
        let (deploy_contract_queue_gatherer, deploy_contract_join_handle) =
            EphemeralQueueGathererWithTree::new_with_is_active::<
                DeployContractQueue,
                DeployContractGathererConfig<N, TempDatabase, FileSystem>,
                N::QHash,
                N::HasherBase,
                DeployContractGatherer<N, TempDatabase, FileSystem>,
            >(
                db.deploy_contract_queue.clone(),
                DeployContractGathererConfig {
                    realm_id_u64: db.realm_id_u64,
                    realm_sub_id_u64: db.realm_sub_id_u64,
                    temp_db: db.temp_db.clone(),
                    backup_file_directory: deploy_contract_gatherer_backup_directory,
                    _phantom_n: std::marker::PhantomData,
                    shared_status: db.shared_status.inner.clone(),
                    deploy_contract_circuit_whitelist,
                    last_job_next_contract_id: Arc::new(std::sync::RwLock::new(init_data.db_tree_next_contract_id)),
                    file_system: file_system.clone(),
                    
                },
                db.deploy_contract_queue_key_status_manager.get_queue_key()?,
                global_contract_tree,
                db.is_active.clone(),
            );

        Ok((
            Self {
                db,
                guta_queue_gatherer: guta_queue_gatherer,
                register_user_queue_gatherer: register_user_queue_gatherer,
                deploy_contract_queue_gatherer: deploy_contract_queue_gatherer,
                proof_worker_queue_max_time_ms: 1000*6*10,
                coordinator_guta_updates_circuit_whitelist,
                register_users_circuit_whitelist,
                deploy_contract_circuit_whitelist,

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
