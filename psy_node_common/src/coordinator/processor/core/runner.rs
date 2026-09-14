
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

    loop {
        if processor.db.status.should_run() {
            let now = std::time::SystemTime::now();
            let since_epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap();
            let current_ms = since_epoch.as_millis();

            let current_slot = current_ms / 100;

            if current_slot != last_slot && current_slot % 60 == 0 {
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
                        let error = format!("coordinator process_block failed at slot {}: {:#}", current_slot, e);
                        processor.db.status.require_recovery(error.clone());
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

#[cfg(test)]
mod runner_tests {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use crate::{
        coordinator::processor::core::{
            runner::{run_coordinator_processor, run_coordinator_processor_loop},
            startup::startup_tests::CoordinatorProcessorTestEnv,
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
    /// multiple of 60 (every 6s). Waiting for a slot safely inside
    /// [5, 50] keeps shutdown-oriented tests clear of that window, so they
    /// never race a block attempt.
    async fn wait_for_slot_away_from_processing_window() {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let slot = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() / 100;
            if slot % 60 >= 5 && slot % 60 <= 50 {
                return;
            }
            assert!(Instant::now() < deadline, "wall clock never left the processing window");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn loop_marks_running_and_shuts_down_gracefully() -> anyhow::Result<()> {
        let env = CoordinatorProcessorTestEnv::create().await?;
        let status = env.processor.db.status.clone();
        wait_for_slot_away_from_processing_window().await;

        let handle = tokio::spawn(run_coordinator_processor_loop(env.processor));
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
        let mut env = CoordinatorProcessorTestEnv::create().await?;
        // bound every worker wait so a failing block attempt returns quickly
        env.processor.proof_worker_queue_max_time_ms = 100;
        let status = env.processor.db.status.clone();

        let handle = tokio::spawn(run_coordinator_processor_loop(env.processor));
        assert!(poll_until(5_000, || status.state() == ProcessorState::Running).await);

        // a processing slot arrives at most 6s apart; the block attempt fails
        // against the fake proving infra and the loop must park in Error
        assert!(
            poll_until(20_000, || status.state() == ProcessorState::Error).await,
            "a failed process_block must park the loop in the Error state"
        );
        let error = status.error().unwrap_or_default().to_string();
        assert!(
            error.contains("coordinator process_block failed at slot"),
            "unexpected recorded error: {error}"
        );

        // the parked loop stays alive: begin_shutdown cannot clear Error (the
        // processor requires manual recovery), so it must still be running
        status.begin_shutdown();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!handle.is_finished(), "an errored loop must keep running until aborted");
        assert_eq!(status.state(), ProcessorState::Error);
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn run_coordinator_processor_propagates_gatherer_join_errors() -> anyhow::Result<()> {
        let env = CoordinatorProcessorTestEnv::create().await?;
        let status = env.processor.db.status.clone();

        // a crashed gatherer surfaces as an error from the joined runner
        env.guta_gatherer_handle.abort();
        env.register_gatherer_handle.abort();
        env.deploy_gatherer_handle.abort();

        let CoordinatorProcessorTestEnv { processor, guta_gatherer_handle, register_gatherer_handle, deploy_gatherer_handle, .. } =
            env;
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            run_coordinator_processor(
                processor,
                guta_gatherer_handle,
                register_gatherer_handle,
                deploy_gatherer_handle,
            ),
        )
        .await
        .expect("runner must return once a gatherer join fails");

        assert!(result.is_err(), "an aborted gatherer must fail the runner");
        // the inner loop task was spawned and marked itself running before the
        // join error tore everything down; tell it to stop before dropping the
        // runtime
        status.begin_shutdown();
        Ok(())
    }
}
