
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
    store::traits::proof_store::{QCanonicalProofStoreV2, QParthProofStore},
    store::rollback_admission::RollbackAdmissionBoundaryOutcome,
    store::rollback_participant_maintenance::{
        CoordinatorRollbackMaintenanceExecutor,
        CoordinatorRollbackMaintenanceOutcome,
    },
    store::rollback_runtime_rebuild::{
        CoordinatorRollbackRuntimePublication, CoordinatorRollbackRuntimeRebuildStore,
    },
    store::canonical_head::StoredCanonicalHead,
    store::realm_processor_quiescence::RealmProcessorDrainRequest,
};
use tokio::time::sleep;

use crate::{
    coordinator::processor::PsyCoordinatorProcessor,
    queue::gatherer::{GathererBoundaryPhase, GathererPauseReceipt, GathererPauseRequest},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorProcessorRunExit<Hash> {
    ShutdownRequested,
    RestartAfterRollback(StoredCanonicalHead<Hash>),
}

struct CoordinatorRollbackGathererPauseSet {
    guta: GathererPauseReceipt,
    registration: GathererPauseReceipt,
    deploy: GathererPauseReceipt,
}

pub async fn run_coordinator_processor_loop<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
    S: PsyCoordinatorProcessorStore<N::F, N::QHash>
        + CoordinatorRollbackMaintenanceExecutor<N::F, N::QHash>
        + CoordinatorRollbackRuntimeRebuildStore<N::QHash>
        + Send
        + Sync,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    RegisterUserQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    DeployContractQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    ProofStore: QParthProofStore + QCanonicalProofStoreV2,
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
) -> anyhow::Result<CoordinatorProcessorRunExit<N::QHash>>
where
    N: 'static,
{
    let realm_id = processor.db.ids.realm_id_u64;
    let realm_sub_id = processor.db.ids.realm_sub_id_u64;
    processor.db.status.mark_running();
    print_cf_log_indicator("PSY_COORDINATOR_PROCESSOR_STARTED", &format!("R{}_{}", realm_id, realm_sub_id));

    let mut last_slot: u128 = 0;
    let mut rollback_gatherers: Option<CoordinatorRollbackGathererPauseSet> = None;

    loop {
        if processor.db.status.should_run() {
            let now = std::time::SystemTime::now();
            let since_epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap();
            let current_ms = since_epoch.as_millis();

            let current_slot = current_ms / 100;

            if current_slot != last_slot && current_slot % 60 == 0 {
                last_slot = current_slot;
                let admission = processor
                    .db
                    .reconcile_rollback_admission_at_loop_boundary()
                    .await;
                match admission {
                    Ok(RollbackAdmissionBoundaryOutcome::Maintenance(head)) => {
                        if rollback_gatherers.is_none() {
                            let request = head.rollback_control().requested().ok_or_else(|| {
                                anyhow::anyhow!(
                                    "Coordinator maintenance head has no rollback request"
                                )
                            })?;
                            let drain_request = RealmProcessorDrainRequest::try_new(
                                head.canonical_ref().network_id(),
                                u32::try_from(processor.db.ids.realm_id_u64)?,
                                u16::try_from(processor.db.ids.realm_sub_id_u64)?,
                                head.canonical_ref().chain_epoch().get(),
                                head.revision().get(),
                                *request.plan_digest().as_bytes(),
                                *request.plan_digest().as_bytes(),
                            )?;
                            let guta_status = processor.guta_queue_gatherer.status().await?;
                            let registration_status =
                                processor.register_user_queue_gatherer.status().await?;
                            let deploy_status =
                                processor.deploy_contract_queue_gatherer.status().await?;
                            if [guta_status, registration_status, deploy_status]
                                .iter()
                                .any(|status| status.phase() != GathererBoundaryPhase::Running)
                            {
                                anyhow::bail!(
                                    "Coordinator rollback requires three running gatherers before drain"
                                )
                            }
                            let guta = processor
                                .guta_queue_gatherer
                                .pause(GathererPauseRequest::new(
                                    drain_request,
                                    guta_status.revision(),
                                    guta_status.unique_id(),
                                ))
                                .await?;
                            let registration = processor
                                .register_user_queue_gatherer
                                .pause(GathererPauseRequest::new(
                                    drain_request,
                                    registration_status.revision(),
                                    registration_status.unique_id(),
                                ))
                                .await?;
                            let deploy = processor
                                .deploy_contract_queue_gatherer
                                .pause(GathererPauseRequest::new(
                                    drain_request,
                                    deploy_status.revision(),
                                    deploy_status.unique_id(),
                                ))
                                .await?;
                            rollback_gatherers = Some(CoordinatorRollbackGathererPauseSet {
                                guta,
                                registration,
                                deploy,
                            });
                            tracing::warn!(
                                "Coordinator rollback drained all three gatherer actors before archive/delete maintenance"
                            );
                        }
                        if matches!(
                            head.rollback_control(),
                            psy_node_core::store::rollback_control::RollbackControlState::Verifying(_)
                                | psy_node_core::store::rollback_control::RollbackControlState::AllRealmsReady(_)
                        ) {
                            if matches!(
                                head.rollback_control(),
                                psy_node_core::store::rollback_control::RollbackControlState::Verifying(_)
                            ) {
                                match processor
                                    .db
                                    .rebuild_coordinator_runtime_after_rollback()
                                    .await
                                {
                                    Ok(Some(report)) => tracing::warn!(
                                        "[COORDINATOR] Rollback runtime rebuilt at checkpoint {} (backup range [{}, {})); selecting the complete Realm report set",
                                        report.processor_checkpoint(),
                                        report.backup_min_checkpoint(),
                                        report.backup_next_checkpoint(),
                                    ),
                                    Ok(None) => {
                                        tracing::warn!(
                                            "[COORDINATOR] VERIFYING is active but its runtime rebuild directive is not available yet"
                                        );
                                        continue;
                                    }
                                    Err(error) => {
                                        let error = format!(
                                            "Coordinator rollback runtime rebuild failed closed at slot {}: {:#}",
                                            current_slot, error,
                                        );
                                        processor.db.status.set_error(error.clone());
                                        tracing::error!("{error}");
                                        continue;
                                    }
                                }
                            }
                            match processor
                                .db
                                .try_publish_restored_runtime()
                                .await
                            {
                                Ok(CoordinatorRollbackRuntimePublication::AwaitingRealmReports {
                                    completed,
                                    expected,
                                }) => tracing::warn!(
                                    "[COORDINATOR] Rollback runtime barrier awaits Realm reports: {completed}/{expected} complete"
                                ),
                                Ok(CoordinatorRollbackRuntimePublication::Published(published)) => {
                                    tracing::warn!(
                                        "[COORDINATOR] Globally published restored checkpoint {} at epoch {}; normal block admission may resume",
                                        published.canonical_ref().checkpoint().checkpoint_id().get(),
                                        published.canonical_ref().chain_epoch().get(),
                                    );
                                    return Ok(
                                        CoordinatorProcessorRunExit::RestartAfterRollback(
                                            published,
                                        ),
                                    );
                                }
                                Err(error) => {
                                    let error = format!(
                                        "Coordinator global runtime publication failed closed at slot {}: {:#}",
                                        current_slot, error,
                                    );
                                    processor.db.status.set_error(error.clone());
                                    tracing::error!("{error}");
                                }
                            }
                            continue;
                        }
                        match processor.db.prepare_coordinator_rollback_archive().await {
                            Ok(CoordinatorRollbackMaintenanceOutcome::ArchivePrepared(prepared)) => {
                                tracing::warn!(
                                    "[COORDINATOR] Rollback archive prepared at epoch {}, target checkpoint {}, archived entries {}; waiting for every Realm and the global archive barrier",
                                    prepared.archiving_head().canonical_ref().chain_epoch().get(),
                                    prepared.target().checkpoint().checkpoint_id().get(),
                                    prepared.entry_count(),
                                );
                            }
                            Ok(CoordinatorRollbackMaintenanceOutcome::AwaitingDownstream(current)) => {
                                tracing::warn!(
                                    "[COORDINATOR] Rollback maintenance awaits downstream global coordination at epoch {}, checkpoint {}",
                                    current.canonical_ref().chain_epoch().get(),
                                    current.canonical_ref().checkpoint().checkpoint_id().get(),
                                );
                            }
                            Ok(CoordinatorRollbackMaintenanceOutcome::Normal(current)) => {
                                let error = format!(
                                    "Coordinator maintenance observation unexpectedly returned an idle head at epoch {}, checkpoint {}",
                                    current.canonical_ref().chain_epoch().get(),
                                    current.canonical_ref().checkpoint().checkpoint_id().get(),
                                );
                                processor.db.status.set_error(error.clone());
                                tracing::error!("{error}");
                                continue;
                            }
                            Err(error) => {
                                let error = format!(
                                    "Coordinator rollback archive preparation failed closed at slot {}: {:#}",
                                    current_slot, error,
                                );
                                processor.db.status.set_error(error.clone());
                                tracing::error!("{error}");
                                continue;
                            }
                        }
                        match processor.db.progress_coordinator_rollback().await {
                            Ok(psy_node_core::store::rollback_participant_maintenance::CoordinatorRollbackGlobalProgress::AwaitingParticipants {
                                completed,
                                expected,
                                ..
                            }) => tracing::warn!(
                                "[COORDINATOR] Distributed rollback barrier awaits participant completions: {completed}/{expected}"
                            ),
                            Ok(psy_node_core::store::rollback_participant_maintenance::CoordinatorRollbackGlobalProgress::Progressed(head)) => {
                                tracing::warn!(
                                    "[COORDINATOR] Distributed rollback advanced at epoch {}, checkpoint {}",
                                    head.canonical_ref().chain_epoch().get(),
                                    head.canonical_ref().checkpoint().checkpoint_id().get(),
                                );
                                if head.rollback_control().is_idle() {
                                    let paused = rollback_gatherers.take().ok_or_else(|| {
                                        anyhow::anyhow!(
                                            "Coordinator abort completed without a gatherer drain"
                                        )
                                    })?;
                                    processor
                                        .guta_queue_gatherer
                                        .resume(paused.guta)
                                        .await?;
                                    processor
                                        .register_user_queue_gatherer
                                        .resume(paused.registration)
                                        .await?;
                                    processor
                                        .deploy_contract_queue_gatherer
                                        .resume(paused.deploy)
                                        .await?;
                                    tracing::warn!(
                                        "Coordinator rollback aborted before PONR; resumed all three original gatherer actors"
                                    );
                                }
                            }
                            Ok(psy_node_core::store::rollback_participant_maintenance::CoordinatorRollbackGlobalProgress::ReadyForRuntimeRebuild(_)) => {}
                            Err(error) => {
                                let error = format!(
                                    "Coordinator distributed rollback failed closed at slot {}: {:#}",
                                    current_slot, error,
                                );
                                processor.db.status.set_error(error.clone());
                                tracing::error!("{error}");
                            }
                        }
                        continue;
                    }
                    Ok(RollbackAdmissionBoundaryOutcome::StaleCommandRejected(head)) => {
                        tracing::warn!(
                            "[COORDINATOR] Rejected stale rollback command at current epoch {}, checkpoint {}; continuing normal processing",
                            head.canonical_ref().chain_epoch().get(),
                            head.canonical_ref().checkpoint().checkpoint_id().get(),
                        );
                    }
                    Ok(RollbackAdmissionBoundaryOutcome::Normal(_)) => {}
                    Err(error) => {
                        let error = format!(
                            "coordinator rollback admission boundary failed at slot {}: {:#}",
                            current_slot, error
                        );
                        processor.db.status.set_error(error.clone());
                        tracing::error!("{error}");
                        continue;
                    }
                }
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

    Ok(CoordinatorProcessorRunExit::ShutdownRequested)
}
pub async fn run_coordinator_processor<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
    S: PsyCoordinatorProcessorStore<N::F, N::QHash>
        + CoordinatorRollbackMaintenanceExecutor<N::F, N::QHash>
        + CoordinatorRollbackRuntimeRebuildStore<N::QHash>
        + Send
        + Sync
        + 'static,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    RegisterUserQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    DeployContractQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    ProofStore: QParthProofStore + QCanonicalProofStoreV2 + Send + Sync + 'static,
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
) -> anyhow::Result<CoordinatorProcessorRunExit<N::QHash>>
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
            Ok(CoordinatorProcessorRunExit::ShutdownRequested)
        }
        result = async {
            let (processor_result, guta_result, register_result, deploy_result) = tokio::try_join!(
                tokio::spawn(run_coordinator_processor_loop(processor)),
                guta_gatherer_join_handle,
                register_users_gatherer_join_handle,
                deploy_contracts_gatherer_join_handle,
            )?;
            let exit = processor_result?;
            guta_result?;
            register_result?;
            deploy_result?;
            Ok::<CoordinatorProcessorRunExit<N::QHash>, anyhow::Error>(exit)
        } => {
            let exit = result?;
            tracing::info!("All coordinator processor threads completed");
            Ok(exit)
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn rollback_maintenance_prepares_archive_and_parks_before_normal_block_processing() {
        let source = include_str!("runner.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let admission = production
            .find("RollbackAdmissionBoundaryOutcome::Maintenance")
            .expect("maintenance branch");
        let verifying = production[admission..]
            .find("RollbackControlState::Verifying")
            .map(|offset| admission + offset)
            .expect("verifying branch");
        let rebuild = production[verifying..]
            .find("rebuild_coordinator_runtime_after_rollback")
            .map(|offset| verifying + offset)
            .expect("runtime rebuild");
        let rebuild_park = production[rebuild..]
            .find("continue;")
            .map(|offset| rebuild + offset)
            .expect("runtime rebuild park");
        let publication = production[rebuild..]
            .find("try_publish_restored_runtime")
            .map(|offset| rebuild + offset)
            .expect("runtime target publication");
        let archive = production[admission..]
            .find("prepare_coordinator_rollback_archive")
            .map(|offset| admission + offset)
            .expect("archive preparation");
        let park = production[archive..]
            .find("continue;")
            .map(|offset| archive + offset)
            .expect("maintenance park");
        let process = production[park..]
            .find("processor.process_block()")
            .map(|offset| park + offset)
            .expect("normal block processing");

        assert!(
            admission < verifying
                && verifying < rebuild
                && rebuild < rebuild_park
                && rebuild < publication
                && publication < archive
                && rebuild_park < archive
                && archive < park
                && park < process
        );
        for forbidden in ["delete_suffix", "restore_target", "publish_target"] {
            assert!(!production.contains(forbidden));
        }
    }

    #[test]
    fn abort_completion_updates_in_memory_head_before_republishing_pending_context() {
        let source = include_str!("../db.rs");
        let progress = source
            .split("pub async fn progress_coordinator_rollback")
            .nth(1)
            .expect("Coordinator rollback progress method");
        let idle = progress
            .find("head.rollback_control().is_idle()")
            .expect("idle completion guard");
        let update = progress
            .find("self.canonical_head = Some(*head)")
            .expect("in-memory canonical head update");
        let publish = progress
            .find("self.publish_pending_context_for_head(*head)")
            .expect("pending context publication");
        assert!(idle < update && update < publish);
    }

    #[test]
    fn published_rollback_target_restarts_coordinator_actor_trees() {
        let source = include_str!("runner.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let published = production
            .find("CoordinatorRollbackRuntimePublication::Published(published)")
            .expect("restored target publication branch");
        let restart = production[published..]
            .find("CoordinatorProcessorRunExit::RestartAfterRollback")
            .map(|offset| published + offset)
            .expect("Coordinator restart exit");
        let normal_processing = production[published..]
            .find("processor.process_block()")
            .map(|offset| published + offset)
            .expect("normal processing call");
        assert!(published < restart && restart < normal_processing);
    }

    #[test]
    fn rollback_drains_all_coordinator_gatherers_and_only_abort_resumes_them() {
        let source = include_str!("runner.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let maintenance = production
            .find("RollbackAdmissionBoundaryOutcome::Maintenance(head)")
            .expect("maintenance branch");
        let branch = &production[maintenance..];
        let guta_pause = branch
            .find(".guta_queue_gatherer\n                                .pause")
            .expect("GUTA drain");
        let registration_pause = branch
            .find(".register_user_queue_gatherer\n                                .pause")
            .expect("registration drain");
        let deploy_pause = branch
            .find(".deploy_contract_queue_gatherer\n                                .pause")
            .expect("deploy drain");
        let archive = branch
            .find("prepare_coordinator_rollback_archive")
            .expect("archive preparation");
        let abort_idle = branch
            .find("head.rollback_control().is_idle()")
            .expect("abort completion");
        let guta_resume = branch[abort_idle..]
            .find(".guta_queue_gatherer\n                                        .resume")
            .map(|offset| abort_idle + offset)
            .expect("GUTA resume");
        assert!(guta_pause < registration_pause && registration_pause < deploy_pause);
        assert!(deploy_pause < archive && archive < abort_idle && abort_idle < guta_resume);
    }
}
