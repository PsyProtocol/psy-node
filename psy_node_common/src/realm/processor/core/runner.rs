
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
    // How long this process has been up, which is what separates a database
    // that stumbled from one that is not there.  A transient failure earns a
    // restart; a failure in the first minute after a restart means the last
    // restart did not help, and parking is better than a loop that hides why.
    let running_since = std::time::Instant::now();
    processor.db.status.mark_running();
    print_cf_log_indicator("PSY_REALM_PROCESSOR_STARTED", &format!("R{}_{}", realm_id, realm_sub_id));

    // A node that was down for a rollback comes back to an Idle control row and
    // no phase left to observe, so the published head is the only evidence it
    // has.  Checked once, here, for the same reason the Coordinator checks at
    // startup: this is the one moment such a node can still notice.
    if let Err(e) = processor.db.truncate_if_ahead_of_published_head().await {
        tracing::error!(
            "[REALM] could not reconcile the checkpoint cache against the published head \
             ({e:#}); starting anyway would risk proving a witness built from a discarded branch"
        );
        return Err(e);
    }
    // The height check above only sees a rollback this Realm came back to
    // before the Coordinator produced past the old head.  After that the
    // heights agree and only the contents differ, and the epoch is the only
    // thing left that can tell.
    if let Err(e) = processor.db.reconcile_missed_rollback_epochs().await.map(|_| ()) {
        tracing::error!(
            "[REALM] could not reconcile against rollbacks that happened while this Realm was \
             down ({e:#}); refusing to start on a cache whose provenance is unknown"
        );
        return Err(e);
    }

    let mut last_slot: u128 = 0;
    // Logged on the edge, not every second, so a long rollback does not bury the log.
    let mut reported_frozen = false;
    // What this Realm must undo once the rollback it is watching finishes.  Held
    // in memory only: it is evidence of a rollback this process *watched*, and a
    // process that did not watch one must not act on a leftover value.
    let mut rollback_target: Option<u64> = None;
    // An abort ends at Idle exactly as a success does, so without this the two
    // would be indistinguishable and an aborted rollback would throw away sync
    // state the Coordinator never discarded.
    let mut rollback_aborted = false;
    // Set once this Realm has run its own share, so neither the participation
    // nor the recovery path repeats it.
    let mut took_part = false;
    // Set once the verify receipt for this rollback has been filed.
    let mut confirmed = false;

    loop {
        if processor.db.status.should_run() {
            // A rollback the Coordinator has published outranks anything this
            // loop was about to do.  Checked before the sync and not only before
            // producing: a Realm that kept syncing would copy the very
            // checkpoints being discarded and end up recording a coordinator
            // height inside the deleted range.
            match processor.db.follow_coordinator_rollback_phase().await {
                Ok(None) => {}
                Ok(Some(phase)) if phase.permits_commit() => {
                    // Idle.  If this process watched a rollback reach a target,
                    // now is when it undoes its own copy of the discarded range:
                    // the Coordinator has finished and is publishing again, and
                    // the Realm still holds heights that no longer exist.
                    if let Some(target) = rollback_target.take() {
                        if rollback_aborted {
                            tracing::info!(
                                "[REALM] the rollback to {target} was aborted; keeping the sync \
                                 state the Coordinator never discarded"
                            );
                        } else if let Err(e) = processor
                            .db
                            .undo_everything_above(target)
                            .await
                            // Recording the epoch is part of finishing the
                            // reset, not a separate step: a Realm that
                            // truncated and then failed to record which epoch
                            // it truncated *to* would reconcile again on the
                            // next start, against a chain that has moved on.
                            .and(processor.db.note_current_chain_epoch().await)
                        {
                            tracing::error!(
                                "[REALM] could not reset to the rollback target {target} \
                                 ({e:#}); retrying rather than resuming on a discarded branch"
                            );
                            rollback_target = Some(target);
                            sleep(std::time::Duration::from_secs(1)).await;
                            continue;
                        }
                        // The database work is done by the process that knows
                        // the target; the in-memory state is rebuilt by the
                        // path that rebuilds it on every start.  Repairing the
                        // caches in place looked like it worked -- the Realm
                        // returned to step after several rollbacks -- and then
                        // produced a witness the worker could not prove, mixing
                        // the discarded branch's leaves with the current
                        // database, with no error logged anywhere.  A restart
                        // cleared it every time.  Same conclusion as the
                        // Coordinator's, reached the same way.
                        tracing::warn!(
                            "[REALM] undid this Realm's share of the rollback to {target}; \
                             restarting so its in-memory state is rebuilt by the path that \
                             already does it on every start (exit {})",
                            psy_node_core::store::rollback_reload::EXIT_CODE_ROLLBACK_RELOAD
                        );
                        processor.db.status.begin_shutdown();
                        sleep(std::time::Duration::from_millis(500)).await;
                        std::process::exit(
                            psy_node_core::store::rollback_reload::EXIT_CODE_ROLLBACK_RELOAD,
                        );
                    }
                    // Nothing watched, so nothing to undo from memory -- which
                    // is not the same as nothing to undo.  A Realm the grace
                    // window left behind never saw a phase at all: by the time
                    // it looked the Coordinator had finished and published Idle
                    // again, and the only evidence left that it missed
                    // something is the chain epoch on that head.  Without this
                    // it would sync and produce straight onto a branch that no
                    // longer exists, which is the cost of retiring I9 and this
                    // is where it is paid.
                    //
                    // Reached only when the branch above did not fire, so this
                    // never runs against a rollback this process took part in
                    // or watched to its end -- both of those restart, and
                    // startup reconciles.
                    match processor.db.reconcile_missed_rollback_epochs().await {
                        Ok(false) => {}
                        Ok(true) => {
                            // Same reason the two watched paths restart: the
                            // database is back on the surviving branch but the
                            // in-memory state was built from the discarded one,
                            // and repairing that in place is what produced
                            // unprovable witnesses before.
                            tracing::warn!(
                                "[REALM] this Realm was left behind by a rollback it never saw \
                                 and has undone its share; restarting so its in-memory state is \
                                 rebuilt from the surviving branch (exit {})",
                                psy_node_core::store::rollback_reload::EXIT_CODE_ROLLBACK_RELOAD
                            );
                            processor.db.status.begin_shutdown();
                            sleep(std::time::Duration::from_millis(500)).await;
                            std::process::exit(
                                psy_node_core::store::rollback_reload::EXIT_CODE_ROLLBACK_RELOAD,
                            );
                        }
                        Err(e) => {
                            // Fail closed, as the phase read above does: a
                            // Realm that cannot establish which of its
                            // checkpoints are still real must not build
                            // witnesses from them.
                            tracing::error!(
                                "[REALM] could not check whether a rollback happened without \
                                 this Realm ({e:#}); holding off rather than producing on a \
                                 branch that may be gone"
                            );
                            sleep(std::time::Duration::from_secs(1)).await;
                            continue;
                        }
                    }
                    rollback_aborted = false;
                    took_part = false;
                    confirmed = false;
                }
                Ok(Some(phase)) => {
                    // A Realm more than one rollback behind is not a
                    // participant in this one.  Following the published phase
                    // would have it undo down to *this* target and then record
                    // itself as current, leaving whatever an earlier rollback
                    // discarded above this target in place and no longer
                    // visible as wrong.
                    //
                    // Standing down is the whole response: file nothing, keep
                    // no target, wait.  The grace window excuses it, the
                    // Coordinator finishes, and once Idle is published the
                    // epoch check reconciles every rollback it missed at once,
                    // down to the lowest of their targets.
                    if matches!(
                        processor.db.epochs_behind_the_rollback_in_flight().await,
                        Some(behind) if behind > 1
                    ) {
                        if !std::mem::replace(&mut reported_frozen, true) {
                            tracing::warn!(
                                "[REALM_ROLLBACK] standing down from the rollback in flight: \
                                 this Realm is more than one rollback behind it and would undo \
                                 the wrong range. It reconciles them all together once the \
                                 Coordinator publishes Idle"
                            );
                        }
                        sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
                    // Remember the target while it is still being published,
                    // but only until this Realm has done its share.  A later
                    // phase re-arming it would send the recovery path over
                    // ground participation already covered, and replanning from
                    // a manifest whose rows are gone archives them as absent --
                    // overwriting the record of what was discarded with one
                    // saying there was nothing there.
                    if !took_part {
                        if let Some(target) = phase.target() {
                            rollback_target = Some(target);
                        }
                    }
                    // FROZEN is the only moment this Realm can join.  Taking
                    // part is what the archive barrier waits for: without a
                    // receipt from here the Coordinator would cross the point
                    // of no return while this Realm had copied none of its
                    // share.  Recovering afterwards still works and is what a
                    // Realm that was down has to fall back on, but it happens
                    // with no barrier protecting it.
                    // The verify receipt is owed by every participant, however
                    // it got here: one that took part, one restarted half way
                    // through and no longer knows it did, and one that never
                    // had anything above the target all owe the same thing.
                    // Filing it on the phase rather than on memory is what lets
                    // the last two file it at all.
                    if let psy_node_core::store::rollback_coordination::ObservedRollbackPhase::Verify {
                        target,
                    } = phase
                    {
                        if !confirmed {
                            match processor.db.confirm_rollback_target_reached(target).await {
                                Ok(true) => confirmed = true,
                                Ok(false) => {}
                                Err(e) => tracing::error!(
                                    "[REALM] could not confirm this Realm reached {target} \
                                     ({e:#}); the Coordinator cannot publish until it can"
                                ),
                            }
                        }
                    }
                    if let psy_node_core::store::rollback_coordination::ObservedRollbackPhase::Freeze {
                        target,
                        ..
                    } = phase
                    {
                        if !took_part {
                            match processor.db.take_part_in_rollback(target).await {
                                Ok(true) => {
                                    // Its share is done, so restart -- for the
                                    // same reason the recovery path does, plus
                                    // one this path has on its own: the chain
                                    // epoch moved, records are partitioned by
                                    // it, and a Realm carrying the old one
                                    // writes the replacement of a discarded
                                    // checkpoint into the discarded branch's
                                    // partition, where it collides with what is
                                    // already there.  Startup adopts the
                                    // Coordinator's epoch before anything can
                                    // stamp a record with it.
                                    tracing::warn!(
                                        "[REALM] took part in the rollback to {target}; \
                                         restarting so its state and the chain epoch it stamps \
                                         records with are both taken fresh (exit {})",
                                        psy_node_core::store::rollback_reload::EXIT_CODE_ROLLBACK_RELOAD
                                    );
                                    processor.db.status.begin_shutdown();
                                    sleep(std::time::Duration::from_millis(500)).await;
                                    std::process::exit(
                                        psy_node_core::store::rollback_reload::EXIT_CODE_ROLLBACK_RELOAD,
                                    );
                                }
                                Ok(false) => {}
                                Err(e) => {
                                    tracing::error!(
                                        "[REALM] could not take part in the rollback to \
                                         {target} ({e:#}); it will be recovered after the fact \
                                         instead, without the archive barrier waiting for it"
                                    );
                                    took_part = true;
                                }
                            }
                        }
                    }
                    if matches!(
                        phase,
                        psy_node_core::store::rollback_coordination::ObservedRollbackPhase::Aborting
                    ) {
                        rollback_aborted = true;
                    }
                    if !std::mem::replace(&mut reported_frozen, true) {
                        tracing::info!(
                            "[REALM] frozen for a rollback: the Coordinator has published \
                             {phase:?}; this Realm will not sync or produce until it publishes \
                             Idle again"
                        );
                    }
                    sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                Err(e) => {
                    // Fail closed.  A Realm that cannot read the control row
                    // does not know whether a rollback is running, and the cost
                    // of guessing wrong in the two directions is not
                    // symmetric: guessing Idle writes rows into a range that is
                    // about to be treated as final, while guessing frozen only
                    // costs the liveness this loop already gives up on a failed
                    // sync.
                    tracing::error!(
                        "[REALM] cannot read the Coordinator's rollback phase ({e:#}); holding \
                         off rather than committing through a rollback that may be running"
                    );
                    sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            }
            reported_frozen = false;

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
                    Err(e)
                        if psy_node_core::store::rollback_coordination::is_refused_because_rollback(
                            &e,
                        ) =>
                    {
                        // Same race as the Coordinator's: the phase was Idle
                        // when this iteration started and is not any more.
                        tracing::info!(
                            "[REALM] block at slot {} was refused because a rollback started \
                             under it ({:#}); waiting rather than treating this as a fault",
                            current_slot,
                            e
                        );
                    }
                    Err(e)
                        if e.downcast_ref::<
                            psy_node_core::store::rollback_coordination::RealmUpdateNeverIncluded,
                        >()
                        .is_some() =>
                    {
                        // Not a fault: the Coordinator never took the update
                        // this block submitted, and waiting longer was the old
                        // behaviour -- for two and a half hours, in the one case
                        // that produced this. The next block re-derives and
                        // submits again, which is what a lost submission needs.
                        tracing::warn!(
                            "[REALM] block at slot {} was abandoned because the Coordinator did \
                             not include its update ({:#}); the next one will submit again",
                            current_slot,
                            e
                        );
                    }
                    Err(e) if processor.db.chain_rolled_back_under_us().await => {
                        // Not a fault: the branch this block was being built on
                        // was discarded while it was being built.  The usual
                        // shape is a root proof that never arrives -- the jobs
                        // were published against a checkpoint that no longer
                        // exists -- and parking on that would leave the Realm
                        // waiting for a hand it should not need: being left
                        // behind is ordinary now, not exceptional.
                        //
                        // Restarting rather than reconciling here, because the
                        // in-memory state of a process that failed half way
                        // through a block is the last thing that should be
                        // deciding what to undo.  Startup does it from clean.
                        tracing::warn!(
                            "[REALM] the block at slot {} failed ({:#}) and a rollback has \
                             happened under this Realm since it last synced; restarting to \
                             reconcile rather than parking on a branch that is gone (exit {})",
                            current_slot,
                            e,
                            psy_node_core::store::rollback_reload::EXIT_CODE_ROLLBACK_RELOAD
                        );
                        processor.db.status.begin_shutdown();
                        sleep(std::time::Duration::from_millis(500)).await;
                        std::process::exit(
                            psy_node_core::store::rollback_reload::EXIT_CODE_ROLLBACK_RELOAD,
                        );
                    }
                    // Not a fault in the chain: the database was briefly
                    // unreachable or too busy to answer.  Parking on that left
                    // the chain stopped for two hours with all three
                    // participants in step at the same height and every
                    // keyspace intact -- which is exactly what made it look
                    // healthy -- over one `Unavailable` on a single-node
                    // cluster that was merely busy.
                    //
                    // Restarting rather than retrying in place, because the
                    // block failed part way through its commit and in-memory
                    // state may no longer agree with the database; startup
                    // rebuilds from the database, which is the same reason the
                    // rollback path above restarts.
                    Err(e)
                        if running_since.elapsed() > std::time::Duration::from_secs(60)
                            && psy_node_core::store::transient_failure::is_database_briefly_unavailable(&e) =>
                    {
                        tracing::warn!(
                            "[REALM] block at slot {} failed because the database was briefly \
                             unavailable ({:#}); restarting rather than parking, since nothing \
                             about the chain is wrong (exit {})",
                            current_slot,
                            e,
                            psy_node_core::store::rollback_reload::EXIT_CODE_ROLLBACK_RELOAD
                        );
                        processor.db.status.begin_shutdown();
                        sleep(std::time::Duration::from_millis(500)).await;
                        std::process::exit(
                            psy_node_core::store::rollback_reload::EXIT_CODE_ROLLBACK_RELOAD,
                        );
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
