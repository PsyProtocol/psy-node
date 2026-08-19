
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
    processor.db.status.mark_running();
    print_cf_log_indicator("PSY_COORDINATOR_PROCESSOR_STARTED", &format!("R{}_{}", realm_id, realm_sub_id));

    let mut last_slot: u128 = 0;
    // Logged on the edge so a long rollback does not bury the log.
    let mut reported_frozen = false;

    loop {
        if processor.db.status.should_run() {
            let now = std::time::SystemTime::now();
            let since_epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap();
            let current_ms = since_epoch.as_millis();

            let current_slot = current_ms / 100;

            if current_slot != last_slot && current_slot % 60 == 0 {
                last_slot = current_slot;

                // A rollback may be driven from another process -- an operator
                // command -- and nothing else would connect it to this loop,
                // which would otherwise keep publishing checkpoints on top of
                // the head being archived.  Read once per block attempt rather
                // than every tick: this is the only moment it changes anything.
                match processor
                    .db
                    .recording
                    .follow_published_phase(processor.db.network_id)
                    .await
                {
                    Ok(phase) if phase.permits_commit() => {}
                    Ok(phase) => {
                        if !std::mem::replace(&mut reported_frozen, true) {
                            tracing::info!(
                                "[COORDINATOR] frozen for a rollback: the control row says \
                                 {phase:?}; no checkpoint will be produced until it returns to \
                                 Idle"
                            );
                        }
                        continue;
                    }
                    Err(e) => {
                        // Fail closed, as the Realm does: a Coordinator that
                        // cannot read its own control row does not know whether
                        // it is mid-rollback, and producing a checkpoint on top
                        // of a head that is being archived is the one mistake
                        // that cannot be waited out.
                        tracing::error!(
                            "[COORDINATOR] cannot read the rollback control row ({e:#}); holding \
                             off rather than producing through a rollback that may be running"
                        );
                        continue;
                    }
                }
                reported_frozen = false;

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
                        let error = format!("coordinator process_block failed at slot {}: {:#}", current_slot, e);
                        processor.db.status.set_error(error.clone());
                        tracing::error!("[COORDINATOR] Fatal error processing block: {:?}, took {}ms at slot {}; processor parked in Error state until manually restarted", e, duration_ms, current_slot);
                        print_cf_log_indicator("PSY_COORDINATOR_PROCESSOR_ERROR", &format!("R{}_{}", realm_id, realm_sub_id));
                    }
                }
            } else {
                sleep(std::time::Duration::from_millis(50)).await;
            }
        } else if processor.db.status.state() == crate::utils::processor_status::ProcessorState::Error {
            sleep(std::time::Duration::from_secs(1)).await;
        } else {
            tracing::info!("Coordinator Processor is shutting down gracefully.");
            break;
        }
    }

    processor.db.status.mark_stopped();
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
    let status = processor.db.status.clone();
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Ctrl-C signal received, cleaning up...");
            status.begin_shutdown();
            sleep(std::time::Duration::from_secs(5)).await;
            Ok(())
        }
        result = async {
            let (processor_result, guta_result, register_result, deploy_result) = tokio::try_join!(
                tokio::spawn(run_coordinator_processor_loop(processor)),
                guta_gatherer_join_handle,
                register_users_gatherer_join_handle,
                deploy_contracts_gatherer_join_handle,
            )?;
            processor_result?;
            guta_result?;
            register_result?;
            deploy_result?;
            Ok::<(), anyhow::Error>(())
        } => {
            result?;
            tracing::info!("All coordinator processor threads completed");
            Ok(())
        }
    }
}
