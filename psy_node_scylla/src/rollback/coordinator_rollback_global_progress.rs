//! Production Coordinator driver for the distributed rollback barriers.
//!
//! Coordinator owns the global phase row and its own hot tables.  Realm hot
//! tables are deliberately absent: each Realm process writes immutable
//! completion rows into the shared rollback archive, and this driver only
//! selects those rows in the persisted participant-plan order.

use std::sync::Arc;

use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleHasher},
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::protocol::{canonical_chain::NetworkId, chain_context::AuthorityScope};
use psy_node_core::store::{
    canonical_head::{CanonicalHeadReadState, StoredCanonicalHead},
    rollback_control::RollbackControlState,
    rollback_participant_maintenance::CoordinatorRollbackGlobalProgress,
};
use scylla::client::session::Session;

use super::{
    CqlKeyspaceName, PendingCounterAdapter, ScyllaCanonicalHeadStore,
    ScyllaCoordinatorCommitSourceStore, ScyllaRollbackParticipantPlanStore,
    coordinator_commit_delete_restore_executor::ScyllaCoordinatorCommitDeleteRestoreExecutor,
    coordinator_rollback_delete_completion_store::ScyllaCoordinatorRollbackDeleteCompletionStore,
    realm_rollback_physical_archive_store::ScyllaRealmRollbackPhysicalArchiveStore,
    rollback_global_archive_barrier::{
        RollbackGlobalArchiveBarrierError, ScyllaRollbackGlobalArchiveBarrierOwner,
        read_deleting_rollback_authority,
    },
    rollback_global_delete_barrier::ScyllaRollbackGlobalDeleteBarrierStore,
    rollback_global_restore_barrier::ScyllaRollbackGlobalRestoreBarrierStore,
    rollback_global_restore_orchestrator::ScyllaRollbackGlobalRestoreOrchestrator,
    rollback_runtime_rebuild_store::ScyllaRollbackRuntimeRebuildStore,
};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn progress_coordinator_global_rollback<F, Hash, Hasher>(
    session: Arc<Session>,
    canonical_head: Arc<ScyllaCanonicalHeadStore>,
    commit_sources: Arc<ScyllaCoordinatorCommitSourceStore>,
    participant_plans: Arc<ScyllaRollbackParticipantPlanStore>,
    network: NetworkId,
    no_tablet_keyspace: CqlKeyspaceName,
    state_keyspace: CqlKeyspaceName,
    checkpoint_tree_height: u8,
) -> anyhow::Result<CoordinatorRollbackGlobalProgress<Hash>>
where
    F: QFelt64,
    Hash: Q256BitHash + QFHashBase<F>,
    Hasher: MerkleHasher<Hash> + FieldQHasher<F, Hash>,
{
    let initial: StoredCanonicalHead<Hash> = match canonical_head.read(network).await? {
        CanonicalHeadReadState::Current(head) => head,
        CanonicalHeadReadState::Uninitialized => {
            anyhow::bail!("Coordinator canonical head is uninitialized")
        }
    };
    match initial.rollback_control() {
        RollbackControlState::Idle => {
            return Ok(CoordinatorRollbackGlobalProgress::Progressed(initial));
        }
        RollbackControlState::Verifying(_) | RollbackControlState::AllRealmsReady(_) => {
            return Ok(CoordinatorRollbackGlobalProgress::ReadyForRuntimeRebuild(initial));
        }
        RollbackControlState::Requested(_) => {
            return Ok(CoordinatorRollbackGlobalProgress::Progressed(initial));
        }
        RollbackControlState::Aborting(_) => {
            // Abort convergence has its own all-participant runtime barrier;
            // the destructive rollback driver must never consume this phase.
            return Ok(CoordinatorRollbackGlobalProgress::Progressed(initial));
        }
        RollbackControlState::Restoring(_) => {
            return progress_restoring::<Hash>(
                session,
                canonical_head,
                participant_plans,
                network,
                no_tablet_keyspace,
                state_keyspace,
                initial,
            )
            .await;
        }
        RollbackControlState::Archiving(_)
        | RollbackControlState::ArchiveBarrierReady(_)
        | RollbackControlState::Deleting(_) => {}
    }

    let shared_archive = ScyllaRealmRollbackPhysicalArchiveStore::prepare(
        session.clone(),
        state_keyspace.clone(),
    )
    .await?;
    let mut archive_owner = ScyllaRollbackGlobalArchiveBarrierOwner::new(
        session.clone(),
        canonical_head.clone(),
        commit_sources,
        participant_plans.clone(),
        shared_archive,
        state_keyspace.clone(),
        state_keyspace.clone(),
        checkpoint_tree_height,
    );
    let deleting = match archive_owner
        .begin_delete_or_recover::<F, Hash, Hasher>(network)
        .await
    {
        Ok(deleting) => deleting,
        Err(RollbackGlobalArchiveBarrierError::ParticipantMissing) => {
            let plan_digest = initial
                .rollback_control()
                .requested()
                .ok_or_else(|| anyhow::anyhow!("ARCHIVING head has no rollback request"))?
                .plan_digest();
            let (completed, expected) = count_archive_completions::<Hash>(
                session,
                &participant_plans,
                &state_keyspace,
                network,
                *plan_digest.as_bytes(),
            )
            .await?;
            return Ok(CoordinatorRollbackGlobalProgress::AwaitingParticipants {
                head: initial,
                completed,
                expected,
            });
        }
        Err(error) => return Err(error.into()),
    };

    let coordinator_executor = ScyllaCoordinatorCommitDeleteRestoreExecutor::new(
        session.clone(),
        canonical_head.clone(),
        state_keyspace.clone(),
        state_keyspace.clone(),
    );
    let coordinator_completion = coordinator_executor
        .execute_and_persist(&deleting)
        .await?;

    let realm_store = ScyllaRealmRollbackPhysicalArchiveStore::prepare(
        session.clone(),
        state_keyspace.clone(),
    )
    .await?;
    let mut realm_completions = Vec::with_capacity(deleting.participant_plan().realms().len());
    for participant in deleting.participant_plan().realms() {
        let authority = AuthorityScope::Realm {
            realm_id: participant.realm_id(),
            realm_sub_id: participant.realm_sub_id(),
        };
        let archive = realm_store
            .read_participant_completion_selected::<Hash>(
                network,
                deleting.participant_plan().target().chain_epoch().get(),
                authority,
                *deleting.participant_plan().digest(),
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("planned Realm archive completion disappeared"))?;
        let Some(completion) = realm_store
            .read_delete_completion_for_participant(&deleting, &archive)
            .await?
        else {
            return Ok(CoordinatorRollbackGlobalProgress::AwaitingParticipants {
                head: *deleting.deleting_head(),
                completed: u64::try_from(realm_completions.len())? + 1,
                expected: u64::try_from(deleting.participant_plan().realms().len())? + 1,
            });
        };
        realm_completions.push(completion);
    }

    let delete_barrier_store = ScyllaRollbackGlobalDeleteBarrierStore::prepare(
        session,
        &state_keyspace,
    )
    .await?;
    let delete_barrier = delete_barrier_store
        .persist_or_recover(&deleting, &coordinator_completion, &realm_completions)
        .await?;
    let restoring = ScyllaRollbackGlobalRestoreOrchestrator::begin_restoring_with(
        &canonical_head,
        &delete_barrier_store,
        &delete_barrier,
    )
    .await?;
    Ok(CoordinatorRollbackGlobalProgress::Progressed(restoring))
}

#[allow(clippy::too_many_arguments)]
async fn progress_restoring<Hash: Q256BitHash>(
    session: Arc<Session>,
    canonical_head: Arc<ScyllaCanonicalHeadStore>,
    participant_plans: Arc<ScyllaRollbackParticipantPlanStore>,
    network: NetworkId,
    no_tablet_keyspace: CqlKeyspaceName,
    state_keyspace: CqlKeyspaceName,
    initial: StoredCanonicalHead<Hash>,
) -> anyhow::Result<CoordinatorRollbackGlobalProgress<Hash>> {
    let deleting = read_deleting_rollback_authority::<Hash>(
        session.clone(),
        canonical_head.clone(),
        participant_plans,
        &state_keyspace,
        network,
    )
    .await?;
    let realm_archive = Arc::new(
        ScyllaRealmRollbackPhysicalArchiveStore::prepare(
            session.clone(),
            state_keyspace.clone(),
        )
        .await?,
    );
    let coordinator_completion = Arc::new(
        ScyllaCoordinatorRollbackDeleteCompletionStore::prepare(
            session.clone(),
            &state_keyspace,
        )
        .await?,
    );
    let coordinator = coordinator_completion
        .read_for_authority(&deleting)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Coordinator delete completion is missing"))?;
    let delete_barrier = Arc::new(
        ScyllaRollbackGlobalDeleteBarrierStore::prepare(
            session.clone(),
            &state_keyspace,
        )
        .await?,
    );
    let delete_barrier_receipt = delete_barrier
        .read_for_authority(&deleting)
        .await?
        .ok_or_else(|| anyhow::anyhow!("global delete barrier is missing"))?;

    let mut realm_deletes = Vec::with_capacity(deleting.participant_plan().realms().len());
    for planned in deleting.participant_plan().realms() {
        let authority = AuthorityScope::Realm {
            realm_id: planned.realm_id(),
            realm_sub_id: planned.realm_sub_id(),
        };
        let archived = realm_archive
            .read_participant_completion_selected::<Hash>(
                network,
                deleting.participant_plan().target().chain_epoch().get(),
                authority,
                *deleting.participant_plan().digest(),
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("planned Realm archive completion is missing"))?;
        let deleted = realm_archive
            .read_delete_completion_for_participant(&deleting, &archived)
            .await?
            .ok_or_else(|| anyhow::anyhow!("planned Realm delete completion is missing"))?;
        realm_deletes.push(deleted);
    }

    let mut realm_restores = Vec::with_capacity(realm_deletes.len());
    let mut completed = 0_u64;
    for index in 0..realm_deletes.len() {
        let selected = delete_barrier
            .select_realm(
                &delete_barrier_receipt,
                &deleting,
                &coordinator,
                &realm_deletes,
                index,
            )
            .await?;
        if let Some(restored) = realm_archive
            .read_target_restore_completion_selected(&selected)
            .await?
        {
            completed = completed
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("participant count overflow"))?;
            realm_restores.push(restored);
        }
    }
    let expected = u64::try_from(realm_deletes.len())?;
    if completed != expected {
        return Ok(CoordinatorRollbackGlobalProgress::AwaitingParticipants {
            head: initial,
            completed,
            expected,
        });
    }

    let restore_barrier = Arc::new(
        ScyllaRollbackGlobalRestoreBarrierStore::prepare(
            session.clone(),
            &state_keyspace,
        )
        .await?,
    );
    let runtime_rebuild = Arc::new(
        ScyllaRollbackRuntimeRebuildStore::prepare(session.clone(), &state_keyspace).await?,
    );
    let counter = Arc::new(
        PendingCounterAdapter::prepare(
            session,
            no_tablet_keyspace,
            state_keyspace,
        )
        .await?,
    );
    let orchestrator = ScyllaRollbackGlobalRestoreOrchestrator::new(
        canonical_head.clone(),
        coordinator_completion,
        delete_barrier,
        realm_archive,
        restore_barrier,
        runtime_rebuild,
        counter,
    );
    orchestrator
        .persist_and_begin_verifying(
            &deleting,
            &delete_barrier_receipt,
            &coordinator,
            &realm_deletes,
            &realm_restores,
        )
        .await?;
    let current = match canonical_head.read(network).await? {
        CanonicalHeadReadState::Current(head) => head,
        CanonicalHeadReadState::Uninitialized => {
            anyhow::bail!("Coordinator canonical head disappeared after restore barrier")
        }
    };
    Ok(CoordinatorRollbackGlobalProgress::Progressed(current))
}

async fn count_archive_completions<Hash: Q256BitHash>(
    session: Arc<Session>,
    participant_plans: &ScyllaRollbackParticipantPlanStore,
    archive_keyspace: &CqlKeyspaceName,
    network: NetworkId,
    participant_plan_digest: [u8; 32],
) -> anyhow::Result<(u64, u64)> {
    let plan: psy_node_core::store::rollback_participant_plan::RollbackParticipantPlan<Hash> =
        participant_plans
            .read_participant_plan(network, &participant_plan_digest)
            .await?;
    let store = ScyllaRealmRollbackPhysicalArchiveStore::prepare(session, archive_keyspace.clone())
        .await?;
    let mut completed = 1_u64; // Coordinator archive is required before this driver runs.
    for participant in plan.realms() {
        let authority = AuthorityScope::Realm {
            realm_id: participant.realm_id(),
            realm_sub_id: participant.realm_sub_id(),
        };
        if store
            .read_participant_completion_selected::<Hash>(
                network,
                plan.target().chain_epoch().get(),
                authority,
                *plan.digest(),
            )
            .await?
            .is_some()
        {
            completed = completed.checked_add(1).ok_or_else(|| anyhow::anyhow!("participant count overflow"))?;
        }
    }
    Ok((completed, u64::try_from(plan.realms().len())? + 1))
}

#[cfg(test)]
mod tests {
    #[test]
    fn coordinator_uses_shared_completions_and_orders_global_barriers() {
        let source = include_str!("coordinator_rollback_global_progress.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(!source.contains("ScyllaRealmRollbackDeleteRestoreExecutor"));
        assert!(!source.contains("ScyllaRealmRollbackTargetRestoreExecutor"));
        let archive_select = source
            .find("read_participant_completion_selected::<Hash>")
            .unwrap();
        let realm_delete = source
            .find("read_delete_completion_for_participant")
            .unwrap();
        let delete_barrier = source.find("persist_or_recover(&deleting").unwrap();
        let begin_restore = source.find("begin_restoring_with").unwrap();
        assert!(archive_select < realm_delete);
        assert!(realm_delete < delete_barrier);
        assert!(delete_barrier < begin_restore);
    }

    #[test]
    fn verifying_waits_for_every_selected_realm_restore() {
        let source = include_str!("coordinator_rollback_global_progress.rs");
        let restoring = source.split("async fn progress_restoring").nth(1).unwrap();
        let select = restoring.find(".select_realm(").unwrap();
        let read_restore = restoring
            .find("read_target_restore_completion_selected")
            .unwrap();
        let complete_count = restoring.find("if completed != expected").unwrap();
        let verifying = restoring
            .find(".persist_and_begin_verifying(")
            .unwrap();
        assert!(select < read_restore);
        assert!(read_restore < complete_count);
        assert!(complete_count < verifying);
    }
}
