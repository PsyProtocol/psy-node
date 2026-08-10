
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

use crate::realm::processor::core::{
    process_block::RealmOwnedIterationError, PsyRealmProcessor,
};
use crate::{
    queue::gatherer::{GathererBoundaryPhase, GathererPauseRequest},
    realm::processor::core::control::RealmProcessorPendingContext,
};

fn owned_iteration_consumes_slot(
    should_process: bool,
    result: &Result<(), RealmOwnedIterationError>,
) -> bool {
    should_process
        && matches!(
            result,
            Ok(()) | Err(RealmOwnedIterationError::Process(_))
        )
}

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
        // The command receiver is owned by this loop. Dequeue happens only
        // between iterations, so a request can never cancel sync, proof,
        // commit, publish, or cleanup that already owns the iteration permit.
        if processor
            .control_owner
            .as_ref()
            .is_some_and(|owner| owner.is_whole_drained())
        {
            sleep(std::time::Duration::from_millis(50)).await;
            continue;
        }

        let accepted_request = match processor.control_owner.as_mut() {
            Some(owner) => owner.try_accept_next(
                &processor.iteration_quiescence,
                processor.db.state.chain_id,
                processor.db.state.realm_id_u64,
                processor.db.state.realm_sub_id_u64,
            ),
            None => Ok(None),
        };
        let accepted_request = match accepted_request {
            Ok(request) => request,
            Err(error) => {
                let message = format!(
                    "Realm Processor drain request failed closed before iteration: {error}"
                );
                processor.db.status.set_error(message.clone());
                tracing::error!("{message}");
                sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };

        if let Some(request) = accepted_request {
            let drain_result = async {
                let iteration = processor
                    .iteration_quiescence
                    .try_mint_iteration_drained(request)?;
                processor
                    .control_owner
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("accepted request lost its owner"))?
                    .mark_iteration_drained(request)?;

                // This actor status is itself a command boundary: an earlier
                // backend callback/update has finished before it returns.
                let gatherer_status = processor.guta_queue_gatherer.status().await?;
                let expected_gatherer_unique_id = if processor
                    .normal_commit_owner
                    .as_ref()
                    .is_some_and(|owner| owner.is_branch_exact())
                {
                    processor.db.state.processing_proc_checkpoint_unique_id
                } else {
                    processor.db.state.gathering_proc_checkpoint_unique_id
                };
                if gatherer_status.phase() != GathererBoundaryPhase::Running {
                    anyhow::bail!("gatherer was not running at drain boundary");
                }
                if gatherer_status.unique_id()
                    != expected_gatherer_unique_id
                {
                    anyhow::bail!(
                        "gatherer namespace differs from Realm gathering context"
                    );
                }
                processor
                    .control_owner
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("accepted request lost its owner"))?
                    .mark_gatherer_pause_pending(request)?;
                let gatherer = processor
                    .guta_queue_gatherer
                    .pause(GathererPauseRequest::new(
                        request,
                        gatherer_status.revision(),
                        expected_gatherer_unique_id,
                    ))
                    .await?;
                let pending_context = RealmProcessorPendingContext::new(
                    processor.db.state.processing_unique_pending_id,
                    processor.db.state.processing_proc_checkpoint_unique_id,
                    processor.db.state.gathering_unique_pending_id,
                    processor.db.state.gathering_proc_checkpoint_unique_id,
                );
                processor
                    .control_owner
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("accepted request lost its owner"))?
                    .install_whole_lease(iteration, gatherer, request, pending_context)?;
                Ok::<(), anyhow::Error>(())
            }
            .await;

            if let Err(error) = drain_result {
                if let Some(owner) = processor.control_owner.as_mut() {
                    owner.fail_closed(request);
                }
                let message = format!(
                    "Realm Processor whole-drain failed closed for {:?}: {error:#}",
                    request.digest()
                );
                processor.db.status.set_error(message.clone());
                tracing::error!("{message}");
            }
            // Successful drain is parked with both opaque leases retained;
            // failed drain is also parked. h23b2 intentionally has no resume.
            sleep(std::time::Duration::from_millis(50)).await;
            continue;
        }

        if processor.db.status.should_run() {
            // This RAII owner covers the whole real iteration: sync may write
            // catch-up state and process_block includes commit, authority
            // publication, final sync, and cleanup. A controlled drain lets
            // the current owner finish but rejects every subsequent iteration.
            let iteration_permit = match processor
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
            let now = std::time::SystemTime::now();
            let since_epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap();
            let current_slot = since_epoch.as_millis() / 100;
            let should_process = current_slot != last_slot && current_slot % 30 == 0;
            if should_process {
                tracing::debug!("[REALM] Process block starting...");
            }
            let started_at = std::time::Instant::now();
            let iteration_result = processor
                .run_owned_iteration(iteration_permit, should_process)
                .await;
            // Match the legacy retry boundary: begin/sync failures do not
            // consume this slot, while entering process_block does, whether
            // it succeeds or fails.
            if owned_iteration_consumes_slot(should_process, &iteration_result) {
                last_slot = current_slot;
            }
            match iteration_result {
                Ok(()) if should_process => {
                    let duration_ms = started_at.elapsed().as_millis();
                    tracing::debug!("[REALM] Process block finished.");
                    tracing::info!(
                        "Generated GUTA Realm update in {}ms at slot {}",
                        duration_ms,
                        current_slot
                    );
                }
                Ok(()) => {}
                Err(RealmOwnedIterationError::Sync(error)) => {
                    tracing::error!(
                        "[REALM] Sync and verify failed: {:?}, skipping block processing",
                        error
                    );
                    sleep(std::time::Duration::from_secs(1)).await;
                }
                Err(error) => {
                    let duration_ms = started_at.elapsed().as_millis();
                    let detail = match error {
                        RealmOwnedIterationError::MissingCommitOwner => {
                            "normal commit owner is already borrowed or missing".to_owned()
                        }
                        RealmOwnedIterationError::Begin(error)
                        | RealmOwnedIterationError::Process(error) => {
                            format!("{error:#}")
                        }
                        RealmOwnedIterationError::Sync(_) => unreachable!(),
                    };
                    let message = format!(
                        "realm owned iteration failed at slot {}: {}",
                        current_slot, detail
                    );
                    processor.db.status.set_error(message.clone());
                    tracing::error!(
                        "[REALM] Fatal error in owned iteration: {}, took {}ms; processor parked in Error state until manually restarted",
                        message,
                        duration_ms
                    );
                    print_cf_log_indicator(
                        "PSY_REALM_PROCESSOR_ERROR",
                        &format!("R{}_{}", realm_id, realm_sub_id),
                    );
                }
            }
            if !should_process && processor.db.status.should_run() {
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
    use super::{owned_iteration_consumes_slot, RealmOwnedIterationError};

    #[test]
    fn real_loop_owner_lexically_covers_sync_and_process() {
        let runner = include_str!("runner.rs");
        let permit = runner.find("let iteration_permit").unwrap();
        let routed = runner
            .find(".run_owned_iteration(iteration_permit, should_process)")
            .unwrap();
        assert!(permit < routed);

        let owned = include_str!("process_block.rs");
        let owner = owned.find("let mut owner = self").unwrap();
        let iteration = owned.find(".begin_iteration(permit)").unwrap();
        let sync = owned.find("self.sync_and_verify()").unwrap();
        let process = owned.find("self.process_block(&mut iteration)").unwrap();
        let restore = owned.find("self.normal_commit_owner = Some(owner)").unwrap();
        assert!(owner < iteration && iteration < sync && sync < process && process < restore);
    }

    #[test]
    fn common_crate_does_not_depend_on_scylla() {
        let cargo = include_str!("../../../../Cargo.toml");
        assert!(!cargo.contains("psy_node_scylla"));
    }

    #[test]
    fn slot_consumption_preserves_legacy_sync_retry_boundary() {
        let success: Result<(), RealmOwnedIterationError> = Ok(());
        assert!(owned_iteration_consumes_slot(true, &success));
        assert!(!owned_iteration_consumes_slot(false, &success));

        let process = Err(RealmOwnedIterationError::Process(anyhow::anyhow!("process")));
        assert!(owned_iteration_consumes_slot(true, &process));

        let sync = Err(RealmOwnedIterationError::Sync(anyhow::anyhow!("sync")));
        assert!(!owned_iteration_consumes_slot(true, &sync));

        let begin = Err(RealmOwnedIterationError::Begin(anyhow::anyhow!("begin")));
        assert!(!owned_iteration_consumes_slot(true, &begin));

        let missing = Err(RealmOwnedIterationError::MissingCommitOwner);
        assert!(!owned_iteration_consumes_slot(true, &missing));
    }
}

#[cfg(test)]
mod h23b2_tests {
    #[test]
    fn control_is_dequeued_before_any_new_iteration_owner() {
        let source = include_str!("runner.rs");
        let dequeue = source.find("owner.try_accept_next").unwrap();
        let iteration = source.find(".try_begin_iteration()").unwrap();
        assert!(dequeue < iteration);
    }

    #[test]
    fn whole_drain_orders_iteration_then_actor_status_then_pause() {
        let source = include_str!("runner.rs");
        let iteration = source.find(".try_mint_iteration_drained(request)").unwrap();
        let status = source.find("guta_queue_gatherer.status().await").unwrap();
        let pause = source.find(".pause(GathererPauseRequest::new(").unwrap();
        let install = source.find(".install_whole_lease(").unwrap();
        assert!(iteration < status && status < pause && pause < install);
    }

    #[test]
    fn ordinary_startup_does_not_enable_control() {
        let startup = include_str!("startup.rs");
        assert!(startup.contains("control_owner: None"));
        assert_eq!(startup.matches("enable_process_local_drain_control(").count(), 1);
        let create = include_str!("../create.rs");
        assert!(!create.contains("enable_process_local_drain_control"));
    }

    #[test]
    fn h23b2_exposes_no_resume_path() {
        let control = include_str!("control.rs");
        assert!(!control.contains("pub fn resume"));
        assert!(!control.contains("pub async fn resume"));
        assert!(control.contains("whole_lease: Option<RealmProcessorWholeDrainedLease>"));
        assert!(control.contains("GathererPauseReceipt"));
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
