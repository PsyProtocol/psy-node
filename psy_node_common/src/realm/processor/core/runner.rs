
use cf_utils::log_indicator::print_cf_log_indicator;
use parth_core::{
    crypto::hash::traits::{HashTo4Felts, MerkleZeroHasher},
    felt::ToU64Value,
    protocol::core_types::QNetworkTypesConfig,
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    p2p::traits::realm_coordinantor::RealmCoordinatorClient, psy_core_db::traits::full::{PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore}, psy_temp_db::StandardProcessorTempDBStoreBase, queue::{
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    }, store::traits::proof_store::QParthProofStore
};
use tokio::time::sleep;

use crate::{p2p::guta_submit::GutaSubmitError, queue::gatherer::GathererChannelClosed, realm::processor::core::PsyRealmProcessor, utils::processor_status::ProcessorStatus};

async fn join_gatherer(
    handle: &mut Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
    status: &ProcessorStatus,
) -> anyhow::Result<bool> {
    let handle = handle.take().ok_or_else(|| anyhow::anyhow!("GUTA gatherer handle missing"))?;
    match handle.await {
        Ok(result) => result?,
        Err(error) if error.is_cancelled() && matches!(status.state(), crate::utils::processor_status::ProcessorState::Stopping | crate::utils::processor_status::ProcessorState::Stopped) => return Ok(false),
        Err(error) => return Err(anyhow::Error::new(error).context("GUTA gatherer task failed")),
    }
    Ok(status.should_run())
}

fn report_processor_failure(realm_id: u64, realm_sub_id: u64, error: &anyhow::Error) {
    let cause = format!("{error:#}").replace('\\', "\\\\").replace('\r', "\\r").replace('\n', "\\n");
    eprintln!("realm_processor_failure realm_id={realm_id} realm_sub_id={realm_sub_id} error={cause}");
    print_cf_log_indicator("PSY_REALM_PROCESSOR_ERROR", &format!("R{}_{}", realm_id, realm_sub_id));
}

pub async fn run_realm_processor_loop<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
    S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync + 'static,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    ProofStore: QParthProofStore + Send + Sync + 'static,
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
    N: 'static,
    N::HasherBase: MerkleZeroHasher<N::QHash>,
    FileSystem::File: Send + Sync + 'static,
{
    let realm_id = processor.db.state.realm_id_u64;
    let realm_sub_id = processor.db.state.realm_sub_id_u64;
    processor.db.status.mark_running();
    print_cf_log_indicator("PSY_REALM_PROCESSOR_STARTED", &format!("R{}_{}", realm_id, realm_sub_id));

    let mut last_slot: u128 = 0;

    let result: anyhow::Result<()> = async {
    loop {
        if processor.guta_gatherer_join.as_ref().is_some_and(|handle| handle.is_finished()) {
            if join_gatherer(&mut processor.guta_gatherer_join, &processor.db.status).await? {
                processor.run_init_catchup().await?;
            }
        }
        if processor.db.status.should_run() {
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
                        if e.downcast_ref::<GathererChannelClosed>().is_some() {
                            if join_gatherer(&mut processor.guta_gatherer_join, &processor.db.status).await? {
                                processor.run_init_catchup().await?;
                            }
                            continue;
                        }
                        if e.downcast_ref::<GutaSubmitError>().is_some_and(|submit| submit.is_retryable()) {
                            tracing::warn!(
                                "[REALM] Retryable process_block rejection at slot {} after {}ms: {:#}",
                                current_slot,
                                duration_ms,
                                e
                            );
                            if let Err(error) = processor.db.sync_to_coordinator_set_checkpoint_id().await {
                                tracing::warn!(
                                    "realm P2P retryable rejection metadata sync failed sub_id={} error={:#}",
                                    processor.db.state.realm_sub_id_u64,
                                    error
                                );
                            }
                        } else {
                            tracing::error!(
                                "[REALM] Fatal error processing block: {:?}, took {}ms at slot {}; aborting gatherer and re-entering init catch-up",
                                e,
                                duration_ms,
                                current_slot
                            );
                            report_processor_failure(realm_id, realm_sub_id, &e);
                            if let Err(error) = processor.run_init_catchup().await {
                                tracing::error!(
                                    "init catch-up after fatal process_block failed sub_id={} error={:#}",
                                    realm_sub_id,
                                    error
                                );
                                sleep(std::time::Duration::from_secs(5)).await;
                            }
                        }
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
    processor.abort_guta_gatherer().await;
    processor.db.status.mark_stopped();
    print_cf_log_indicator("PSY_REALM_PROCESSOR_STOPPED", &format!("R{}_{}", realm_id, realm_sub_id));

    Ok(())
    }.await;
    if let Err(error) = &result {
        processor.db.status.require_recovery(format!("{error:#}"));
        report_processor_failure(realm_id, realm_sub_id, error);
    }
    result
}
pub async fn run_realm_processor<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
    S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync + 'static,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    ProofStore: QParthProofStore + Send + Sync + 'static,
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
) -> anyhow::Result<()>
where
    N: 'static,
    N::HasherBase: MerkleZeroHasher<N::QHash>,
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
        result = run_realm_processor_loop(processor) => {
            result?;
            tracing::info!("All realm processor threads completed");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("validator preimage mismatch")]
    struct ProofFailure;

    #[tokio::test]
    async fn channel_close_waits_for_owner_and_preserves_failure_during_shutdown() {
        let status = ProcessorStatus::new();
        status.mark_running();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let mut handle = Some(tokio::spawn(async move {
            drop(closed_tx);
            release_rx.await.unwrap();
            Err(anyhow::Error::new(ProofFailure).context("gatherer bootstrap"))
        }));
        closed_rx.await.unwrap_err();
        assert!(!handle.as_ref().unwrap().is_finished());
        status.begin_shutdown();
        let mut joined = Box::pin(join_gatherer(&mut handle, &status));
        tokio::select! {
            biased;
            result = &mut joined => panic!("owner has not exited: {result:?}"),
            _ = std::future::ready(()) => {}
        }
        release_tx.send(()).unwrap();
        let error = joined.await.unwrap_err();
        assert!(error.downcast_ref::<ProofFailure>().is_some());
        assert!(handle.is_none());
    }

    #[tokio::test]
    async fn clean_owner_exit_rebuilds_only_while_running() {
        let status = ProcessorStatus::new();
        status.mark_running();
        let mut handle = Some(tokio::spawn(async { Ok(()) }));
        assert!(join_gatherer(&mut handle, &status).await.unwrap());
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let task_status = status.clone();
        let mut handle = Some(tokio::spawn(async move {
            release_rx.await.unwrap();
            task_status.begin_shutdown();
            Ok(())
        }));
        release_tx.send(()).unwrap();
        assert!(!join_gatherer(&mut handle, &status).await.unwrap());
        assert_eq!(status.state(), crate::utils::processor_status::ProcessorState::Stopping);
        assert!(status.error().is_none());
    }

    #[tokio::test]
    async fn cancelled_owner_is_expected_only_during_shutdown() {
        let status = ProcessorStatus::new();
        status.mark_running();
        let task = tokio::spawn(std::future::pending::<anyhow::Result<()>>());
        task.abort();
        assert!(join_gatherer(&mut Some(task), &status).await.unwrap_err().downcast_ref::<tokio::task::JoinError>().unwrap().is_cancelled());
        status.begin_shutdown();
        let task = tokio::spawn(std::future::pending::<anyhow::Result<()>>());
        task.abort();
        assert!(!join_gatherer(&mut Some(task), &status).await.unwrap());
    }
}
