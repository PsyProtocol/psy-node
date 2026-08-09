
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
use crate::{
    queue::gatherer::{GathererBoundaryPhase, GathererPauseRequest},
    realm::processor::core::control::RealmProcessorPendingContext,
};

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
                if gatherer_status.phase() != GathererBoundaryPhase::Running {
                    anyhow::bail!("gatherer was not running at drain boundary");
                }
                if gatherer_status.unique_id()
                    != processor.db.state.gathering_proc_checkpoint_unique_id
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
                        processor.db.state.gathering_proc_checkpoint_unique_id,
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
