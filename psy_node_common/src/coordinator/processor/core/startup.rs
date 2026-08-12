use std::sync::Arc;

use parth_core::{protocol::core_types::QNetworkTypesConfig, QCoreProcCheckpointUniqueId};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::prepared_block::coordinator::PsyPreparedCoordinatorBlockStateUpdates;
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    psy_core_db::traits::full::{PsyCoordinatorProcessorStore, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter},
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{
        coordinator_guta_durable_submission::CoordinatorGutaDurableSubmissionStore,
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::QStandardWorkerQueuePublisher,
    },
    store::traits::proof_store::{QCanonicalProofStoreV2, QParthProofStore},
};

use crate::{
    backup::coordinator::load_coordinator_memory_trees_from_db,
    coordinator::processor::{
        db::PsyCoordinatorDatabaseProcessor,
        gatherers::{
            coordinator_guta_update_gatherer::{CoordinatorGUTAUpdateGatherer, CoordinatorGUTAUpdateGathererConfig},
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
        ProofStore: QParthProofStore + QCanonicalProofStoreV2 + Send + Sync + 'static,
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
    pub(crate) async fn new(
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
        register_user_gatherer_backup_directory: String,
        guta_gatherer_backup_directory: String,
        durable_guta_submissions:
            Option<Arc<dyn CoordinatorGutaDurableSubmissionStore<N::QHash>>>,
        normal_processing_owner: super::CoordinatorNormalProcessingOwner,
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

        let guta_create_builder_config = CoordinatorGUTAUpdateGathererConfig::<N, TempDatabase, ProofStore, FileSystem> {
            realm_id_u64: db.ids.realm_id_u64,
            realm_sub_id_u64: db.ids.realm_sub_id_u64,
            status: db.shared_status.inner.clone(),
            temp_db: db.temp_db.clone(),
            proof_store: db.proof_store.clone(),
            durable_guta_submissions,
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
        let branch_exact = normal_processing_owner.is_branch_exact();
        let guta_base_queue_key = db.guta_queue_key_status_manager.get_queue_key()?;
        let (guta_queue_gatherer, guta_join_handle) = if branch_exact {
            EphemeralQueueGathererWithTree::new_coordinator_durable_with_status::<
                CoordinatorGUTAUpdateGathererConfig<N, TempDatabase, ProofStore, FileSystem>,
                N::QHash,
                N::HasherBase,
                CoordinatorGUTAUpdateGatherer<N, TempDatabase, ProofStore, FileSystem>,
            >(
                guta_create_builder_config,
                guta_base_queue_key,
                global_user_tree,
                db.status.clone(),
                psy_node_core::queue::coordinator_processor_durable_capture::CoordinatorProcessorSourceKind::Guta,
            )
        } else {
            EphemeralQueueGathererWithTree::new_with_status::<
            GUTAUpdateQueue,
            CoordinatorGUTAUpdateGathererConfig<N, TempDatabase, ProofStore, FileSystem>,
            N::QHash,
            N::HasherBase,
            CoordinatorGUTAUpdateGatherer<N, TempDatabase, ProofStore, FileSystem>,
            >(
                db.guta_update_queue.clone(),
                guta_create_builder_config,
                guta_base_queue_key,
                global_user_tree,
                db.status.clone(),
            )
        };

        let register_config = RegisterUserGathererConfig {
            realm_id_u64: db.ids.realm_id_u64,
            realm_sub_id_u64: db.ids.realm_sub_id_u64,
            temp_db: db.temp_db.clone(),
            backup_file_directory: register_user_gatherer_backup_directory,
            _phantom_n: std::marker::PhantomData,
            status: db.shared_status.inner.clone(),
            register_users_circuit_whitelist: db.circuit_fingerprint_config.register_users_circuit_whitelist_root,
            last_job_next_user_id: Arc::new(std::sync::RwLock::new(db.last_committed.l2_state.next_user_id)),
            file_system: file_system.clone(),
        };
        let register_base_queue_key = db.register_user_queue_key_status_manager.get_queue_key()?;
        let (register_user_queue_gatherer, register_user_join_handle) = if branch_exact {
            EphemeralQueueGathererWithTree::new_coordinator_durable_with_status::<
                RegisterUserGathererConfig<N, TempDatabase, FileSystem>,
                N::QHash,
                N::HasherBase,
                RegisterUserGatherer<N, TempDatabase, FileSystem>,
            >(
                register_config,
                register_base_queue_key,
                user_registration_tree,
                db.status.clone(),
                psy_node_core::queue::coordinator_processor_durable_capture::CoordinatorProcessorSourceKind::Registration,
            )
        } else {
            EphemeralQueueGathererWithTree::new_with_status::<
            RegisterUserQueue,
            RegisterUserGathererConfig<N, TempDatabase, FileSystem>,
            N::QHash,
            N::HasherBase,
            RegisterUserGatherer<N, TempDatabase, FileSystem>,
            >(
                db.register_user_queue.clone(),
                register_config,
                register_base_queue_key,
                user_registration_tree,
                db.status.clone(),
            )
        };
        let deploy_config = DeployContractGathererConfig {
            realm_id_u64: db.ids.realm_id_u64,
            realm_sub_id_u64: db.ids.realm_sub_id_u64,
            temp_db: db.temp_db.clone(),
            backup_file_directory: deploy_contract_gatherer_backup_directory,
            _phantom_n: std::marker::PhantomData,
            shared_status: db.shared_status.inner.clone(),
            deploy_contract_circuit_whitelist: db.circuit_fingerprint_config.deploy_contracts_circuit_whitelist_root,
            last_job_next_contract_id: Arc::new(std::sync::RwLock::new(db.last_committed.l2_state.next_contract_id as u64)),
            file_system: file_system.clone(),
        };
        let deploy_base_queue_key = db.deploy_contract_queue_key_status_manager.get_queue_key()?;
        let (deploy_contract_queue_gatherer, deploy_contract_join_handle) = if branch_exact {
            EphemeralQueueGathererWithTree::new_coordinator_durable_with_status::<
                DeployContractGathererConfig<N, TempDatabase, FileSystem>,
                N::QHash,
                N::HasherBase,
                DeployContractGatherer<N, TempDatabase, FileSystem>,
            >(
                deploy_config,
                deploy_base_queue_key,
                global_contract_tree,
                db.status.clone(),
                psy_node_core::queue::coordinator_processor_durable_capture::CoordinatorProcessorSourceKind::Deploy,
            )
        } else {
            EphemeralQueueGathererWithTree::new_with_status::<
            DeployContractQueue,
            DeployContractGathererConfig<N, TempDatabase, FileSystem>,
            N::QHash,
            N::HasherBase,
            DeployContractGatherer<N, TempDatabase, FileSystem>,
            >(
                db.deploy_contract_queue.clone(),
                deploy_config,
                deploy_base_queue_key,
                global_contract_tree,
                db.status.clone(),
            )
        };

        Ok((
            Self {
                db,
                guta_queue_gatherer: guta_queue_gatherer,
                register_user_queue_gatherer: register_user_queue_gatherer,
                deploy_contract_queue_gatherer: deploy_contract_queue_gatherer,
                proof_worker_queue_max_time_ms: u64::MAX,
                normal_processing_owner: Some(normal_processing_owner),
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
