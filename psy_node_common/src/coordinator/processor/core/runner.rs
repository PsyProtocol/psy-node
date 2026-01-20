use std::sync::atomic::Ordering;

use cf_utils::log_indicator::print_cf_log_indicator;
use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_core::job::job_id::QProvingJobDataID;
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    psy_core_db::traits::full::{PsyCoordinatorProcessorStore, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter},
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    },
    store::traits::proof_store::QParthProofStore,
};
use tokio::time::sleep;

use crate::coordinator::processor::PsyCoordinatorProcessor;

pub async fn run_coordinator_processor_loop<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
    S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    RegisterUserQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    DeployContractQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    ProofStore: QParthProofStore,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
>(
    mut processor: PsyCoordinatorProcessor<
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
) -> anyhow::Result<()>
where
    N: 'static,
{
    let realm_id = processor.db.ids.realm_id_u64;
    let realm_sub_id = processor.db.ids.realm_sub_id_u64;
    print_cf_log_indicator("PSY_COORDINATOR_PROCESSOR_STARTED", &format!("R{}_{}", realm_id, realm_sub_id));

    let mut last_slot: u128 = 0;

    loop {
        let is_active = processor.db.is_active.load(Ordering::SeqCst);
        if is_active {
            let now = std::time::SystemTime::now();
            let since_epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap();
            let current_ms = since_epoch.as_millis();

            let current_slot = current_ms / 100;

            if current_slot != last_slot && current_slot % 70 == 0 {
                last_slot = current_slot;
                let start_processing_at = std::time::Instant::now();
                tracing::debug!("[COORDINATOR] Process block starting...");
                let result = processor.process_block().await;
                let elapsed = start_processing_at.elapsed();
                let duration_ms = elapsed.as_millis();

                match result {
                    Ok(_) => {
                        tracing::debug!("[COORDINATOR] Process block finished.");
                        tracing::info!("Generated block in {}ms at slot {}", duration_ms, current_slot);
                    }
                    Err(e) => {
                        tracing::error!("[COORDINATOR] Error processing block: {:?}, took {}ms at slot {}", e, duration_ms, current_slot);
                    }
                }
            } else {
                sleep(std::time::Duration::from_millis(50)).await;
            }
        } else {
            tracing::info!("Coordinator Processor is shutting down gracefully.");
            break;
        }
    }

    print_cf_log_indicator("PSY_COORDINATOR_PROCESSOR_STOPPED", &format!("R{}_{}", realm_id, realm_sub_id));

    Ok(())
}
pub async fn run_coordinator_processor<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
    S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync + 'static,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    RegisterUserQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    DeployContractQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    ProofStore: QParthProofStore + Send + Sync + 'static,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
>(
    processor: PsyCoordinatorProcessor<
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
    guta_gatherer_join_handle: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
    register_users_gatherer_join_handle: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
    deploy_contracts_gatherer_join_handle: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
) -> anyhow::Result<()>
where
    N: 'static,
    FileSystem::File: Send + Sync + 'static,
{

    let is_active = processor.db.is_active.clone();
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Ctrl-C signal received, cleaning up...");
            is_active.store(false, Ordering::SeqCst);
            sleep(std::time::Duration::from_secs(5)).await;
            Ok(())
        }
        _ = async {
            tokio::try_join!(
                tokio::spawn(run_coordinator_processor_loop(processor)),
                guta_gatherer_join_handle,
                register_users_gatherer_join_handle,
                deploy_contracts_gatherer_join_handle,
            )
        } => {
            tracing::info!("All coordinator processor threads completed");
            Ok(())
        }
    }
}
