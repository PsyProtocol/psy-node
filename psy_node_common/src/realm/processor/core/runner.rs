
use cf_utils::log_indicator::print_cf_log_indicator;
use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_core::job::job_id::QProvingJobDataID;
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    p2p::traits::realm_coordinantor::RealmCoordinatorClient, psy_core_db::traits::full::{PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore}, psy_temp_db::StandardProcessorTempDBStoreBase, queue::{
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    }, store::traits::proof_store::QParthProofStore
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
    N: 'static, FileSystem::File: Send + Sync + 'static,
{
    let realm_id = processor.db.state.realm_id_u64;
    let realm_sub_id = processor.db.state.realm_sub_id_u64;
    processor.db.status.mark_running();
    print_cf_log_indicator("PSY_REALM_PROCESSOR_STARTED", &format!("R{}_{}", realm_id, realm_sub_id));

    let mut last_slot: u128 = 0;

    loop {
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
                        let error = format!("realm process_block failed at slot {}: {:#}", current_slot, e);
                        processor.db.status.require_recovery(error.clone());
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

#[cfg(test)]
mod runner_tests {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use crate::{
        realm::processor::core::{
            runner::{run_realm_processor, run_realm_processor_loop},
            startup::startup_tests::RealmProcessorTestEnv,
        },
        utils::processor_status::ProcessorState,
    };

    /// Polls `check` every 10ms until it returns true or the deadline passes,
    /// returning the final answer. Never asserts on a wall-clock sleep.
    async fn poll_until(timeout_ms: u64, mut check: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            if check() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The loop processes a block only inside the 100ms window whose slot is a
    /// multiple of 30 (every 3s). Waiting for a slot safely inside [3, 25]
    /// keeps shutdown-oriented tests clear of that window, so they never race
    /// a block attempt.
    async fn wait_for_slot_away_from_processing_window() {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let slot = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() / 100;
            if slot % 30 >= 3 && slot % 30 <= 25 {
                return;
            }
            assert!(Instant::now() < deadline, "wall clock never left the processing window");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn loop_marks_running_and_shuts_down_gracefully() -> anyhow::Result<()> {
        let env = RealmProcessorTestEnv::create().await?;
        let status = env.processor.db.status.clone();
        wait_for_slot_away_from_processing_window().await;

        let handle = tokio::spawn(run_realm_processor_loop(env.processor));
        assert!(
            poll_until(5_000, || status.state() == ProcessorState::Running).await,
            "loop must mark itself running at startup"
        );

        status.begin_shutdown();
        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("loop must exit promptly after begin_shutdown")?;
        result?;
        assert_eq!(status.state(), ProcessorState::Stopped);
        Ok(())
    }

    #[tokio::test]
    async fn loop_parks_in_error_state_when_process_block_fails() -> anyhow::Result<()> {
        let mut env = RealmProcessorTestEnv::create().await?;
        // make every block attempt bail immediately: past genesis the unique
        // ids must be differentiated, and equal ids mark corrupt state. The
        // sync path itself stays healthy (it consults the store and the
        // backup manager, not these in-memory ids), so the failure is
        // attributable to process_block alone.
        env.processor.db.state.last_committed_checkpoint_id = 1;
        env.processor.db.state.processing_proc_checkpoint_unique_id =
            env.processor.db.state.gathering_proc_checkpoint_unique_id;
        env.processor.db.state.processing_unique_pending_id = env.processor.db.state.gathering_unique_pending_id;
        let status = env.processor.db.status.clone();

        let handle = tokio::spawn(run_realm_processor_loop(env.processor));
        assert!(poll_until(5_000, || status.state() == ProcessorState::Running).await);

        // a processing slot arrives at most 3s apart; the block attempt fails
        // and the loop must park in Error until manually restarted
        assert!(
            poll_until(20_000, || status.state() == ProcessorState::Error).await,
            "a failed process_block must park the loop in the Error state"
        );
        let error = status.error().unwrap_or_default().to_string();
        assert!(
            error.contains("realm process_block failed at slot"),
            "unexpected recorded error: {error}"
        );

        // the parked loop stays alive: begin_shutdown cannot clear Error, so
        // it must still be running
        status.begin_shutdown();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!handle.is_finished(), "an errored loop must keep running until aborted");
        assert_eq!(status.state(), ProcessorState::Error);
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn run_realm_processor_propagates_gatherer_join_errors() -> anyhow::Result<()> {
        let env = RealmProcessorTestEnv::create().await?;
        let status = env.processor.db.status.clone();

        // a crashed gatherer surfaces as an error from the joined runner
        env.guta_gatherer_handle.abort();

        let RealmProcessorTestEnv { processor, guta_gatherer_handle, .. } = env;
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            run_realm_processor(processor, guta_gatherer_handle),
        )
        .await
        .expect("runner must return once the gatherer join fails");

        assert!(result.is_err(), "an aborted gatherer must fail the runner");
        // the inner loop task was spawned and marked itself running before the
        // join error tore everything down; tell it to stop before dropping the
        // runtime
        status.begin_shutdown();
        Ok(())
    }
}
