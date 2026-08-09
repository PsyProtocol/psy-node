
use cf_utils::log_indicator::print_cf_log_indicator;
use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_core::job::job_id::QProvingJobDataID;
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    p2p::traits::realm_coordinantor::RealmCoordinatorClient, psy_core_db::traits::full::{PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore}, psy_temp_db::StandardProcessorTempDBStoreBase, queue::{
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    }, store::traits::proof_store::{QCanonicalProofStoreV2, QParthProofStore}
};
use tokio::time::sleep;

use crate::realm::processor::core::PsyRealmProcessor;

pub async fn run_realm_processor_loop<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
    S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    ProofStore: QParthProofStore + QCanonicalProofStoreV2 + Send + Sync + 'static,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
    CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync + 'static,
>(
    mut processor: PsyRealmProcessor<
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
) -> anyhow::Result<()>
where
    N: 'static, FileSystem::File: Send + Sync + 'static,
{
    let realm_id = processor.db.state.realm_id_u64;
    let realm_sub_id = processor.db.state.realm_sub_id_u64;
    processor.db.status.mark_running();
    print_cf_log_indicator("PSY_REALM_PROCESSOR_STARTED", &format!("R{}_{}", realm_id, realm_sub_id));

    let mut last_slot: u128 = 0;

    loop {
        if processor.db.status.should_run() {
            // This RAII owner covers the whole real iteration: sync may write
            // catch-up state and process_block includes commit, authority
            // publication, final sync, and cleanup. A controlled drain lets
            // the current owner finish but rejects every subsequent iteration.
            let _iteration_owner = match processor
                .iteration_quiescence
                .try_begin_iteration()
            {
                Ok(owner) => owner,
                Err(
                    psy_node_core::store::realm_processor_quiescence::RealmProcessorQuiescenceError::DrainInProgress,
                ) => {
                    sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
                Err(error) => {
                    let error = format!(
                        "Realm Processor iteration ownership failed closed: {error}"
                    );
                    processor.db.status.set_error(error.clone());
                    tracing::error!("{error}");
                    continue;
                }
            };
            // tracing::debug!("[REALM] Sync and verify starting...");
            let sync_result = processor.sync_and_verify().await;
            match sync_result {
                Ok(_) => {
                    // tracing::debug!("[REALM] Sync and verify completed.");
                }
                Err(e) => {
                    tracing::error!("[REALM] Sync and verify failed: {:?}, skipping block processing", e);
                    sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            }

            let now = std::time::SystemTime::now();
            let since_epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap();
            let current_slot = since_epoch.as_millis() / 100;

            if current_slot != last_slot && current_slot % 30 == 0 {
                last_slot = current_slot;
                let start_processing_at = std::time::Instant::now();

                tracing::debug!("[REALM] Process block starting...");
                let result = processor.process_block().await;
                let elapsed = start_processing_at.elapsed();
                let duration_ms = elapsed.as_millis();

                match result {
                    Ok(_) => {
                        tracing::debug!("[REALM] Process block finished.");
                        tracing::info!("Generated GUTA Realm update in {}ms at slot {}", duration_ms, current_slot);
                    }
                    Err(e) => {
                        let error = format!("realm process_block failed at slot {}: {:#}", current_slot, e);
                        processor.db.status.set_error(error.clone());
                        tracing::error!("[REALM] Fatal error processing block: {:?}, took {}ms at slot {}; processor parked in Error state until manually restarted", e, duration_ms, current_slot);
                        print_cf_log_indicator("PSY_REALM_PROCESSOR_ERROR", &format!("R{}_{}", realm_id, realm_sub_id));
                    }
                }
            } else {
                sleep(std::time::Duration::from_millis(50)).await;
            }
        } else if processor.db.status.state() == crate::utils::processor_status::ProcessorState::Error {
            sleep(std::time::Duration::from_secs(1)).await;
        } else {
            tracing::info!("Realm Processor is shutting down gracefully.");
            break;
        }
    }
    processor.db.status.mark_stopped();
    print_cf_log_indicator("PSY_REALM_PROCESSOR_STOPPED", &format!("R{}_{}", realm_id, realm_sub_id));

    Ok(())
}

#[cfg(test)]
mod h23a_tests {
    #[test]
    fn real_loop_owner_lexically_covers_sync_and_process() {
        let source = include_str!("runner.rs");
        let owner_needle = concat!("let _iteration_", "owner");
        let owner = source.find(owner_needle).unwrap();
        let sync = source.find("processor.sync_and_verify().await").unwrap();
        let process = source.find("processor.process_block().await").unwrap();
        assert!(owner < sync && sync < process);
        assert_eq!(source.matches(owner_needle).count(), 1);
    }

    #[test]
    fn common_crate_does_not_depend_on_scylla() {
        let cargo = include_str!("../../../../Cargo.toml");
        assert!(!cargo.contains("psy_node_scylla"));
    }
}
pub async fn run_realm_processor<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
    S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync + 'static,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    ProofStore: QParthProofStore + QCanonicalProofStoreV2 + Send + Sync + 'static,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
    CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync + 'static,
>(
    processor: PsyRealmProcessor<
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
    guta_gatherer_join_handle: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
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
            let (processor_result, gatherer_result) = tokio::try_join!(
                tokio::spawn(run_realm_processor_loop(processor)),
                guta_gatherer_join_handle,
            )?;
            processor_result?;
            gatherer_result?;
            Ok::<(), anyhow::Error>(())
        } => {
            result?;
            tracing::info!("All realm processor threads completed");
            Ok(())
        }
    }
}
