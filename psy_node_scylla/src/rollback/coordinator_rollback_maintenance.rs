//! Storage-selected Coordinator rollback maintenance up to, but not through,
//! the global archive barrier.
//!
//! This module may advance REQUESTED to ARCHIVING and may make the immutable
//! Coordinator archive evidence restartable. It deliberately exposes no
//! delete, target-restore, barrier, or canonical-head publication authority.

use std::sync::Arc;

use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleHasher},
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::protocol::canonical_chain::NetworkId;
use psy_node_core::store::{
    canonical_head::{
        CanonicalHeadReadState, CanonicalHeadTransition,
        CanonicalHeadWriteOutcome, StoredCanonicalHead,
    },
    rollback_control::RollbackControlState,
    rollback_participant_maintenance::{
        CoordinatorRollbackArchivePreparation,
        CoordinatorRollbackMaintenanceOutcome,
    },
    rollback_participant_plan::RollbackParticipantPlan,
};
use scylla::client::session::Session;

use super::{
    coordinator_commit_physical_archive_store::{
        CoordinatorCommitPhysicalArchiveOwnerError,
        ScyllaCoordinatorCommitPhysicalArchiveOwner,
    },
    CqlKeyspaceName,
    ScyllaCanonicalHeadStore, ScyllaCoordinatorCommitSourceStore,
    ScyllaRollbackParticipantPlanStore,
};

pub(crate) async fn prepare_coordinator_rollback_archive<F, Hash, Hasher>(
    session: Arc<Session>,
    canonical_head: Arc<ScyllaCanonicalHeadStore>,
    commit_sources: Arc<ScyllaCoordinatorCommitSourceStore>,
    participant_plans: Arc<ScyllaRollbackParticipantPlanStore>,
    network: NetworkId,
    state_keyspace: CqlKeyspaceName,
    checkpoint_tree_height: u8,
) -> anyhow::Result<CoordinatorRollbackMaintenanceOutcome<Hash>>
where
    F: QFelt64,
    Hash: Q256BitHash + QFHashBase<F>,
    Hasher: MerkleHasher<Hash> + FieldQHasher<F, Hash>,
{
    let initial = read_head::<Hash>(&canonical_head, network).await?;
    match initial.rollback_control() {
        RollbackControlState::Idle => {
            return Ok(CoordinatorRollbackMaintenanceOutcome::Normal(initial));
        }
        RollbackControlState::ArchiveBarrierReady(_)
        | RollbackControlState::Deleting(_) => {
            return Ok(CoordinatorRollbackMaintenanceOutcome::AwaitingDownstream(
                initial,
            ));
        }
        RollbackControlState::Requested(_) | RollbackControlState::Archiving(_) => {}
    }

    let request = *initial
        .rollback_control()
        .requested()
        .ok_or_else(|| anyhow::anyhow!("active rollback head has no request"))?;
    let plan = participant_plans
        .read_participant_plan(network, request.plan_digest().as_bytes())
        .await?;
    let topology_before = participant_plans
        .read_current_topology(network)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Coordinator rollback topology is missing"))?;
    if !topology_before.snapshot().validates_plan(&plan) {
        anyhow::bail!("durable rollback topology no longer validates the selected participant plan");
    }

    let expected_archiving = expected_archiving_head(&plan)?;
    let archiving_head = match initial.rollback_control() {
        RollbackControlState::Requested(_) => {
            let transition = CanonicalHeadTransition::begin_rollback_archive(initial)?;
            if transition.candidate() != &expected_archiving {
                anyhow::bail!("REQUESTED head does not match the selected participant plan");
            }
            let sealed = transition.seal();
            let outcome = canonical_head.compare_and_set(&sealed).await?;
            let current = *outcome.current();
            if current != expected_archiving
                || !matches!(
                    outcome,
                    CanonicalHeadWriteOutcome::Applied(_)
                        | CanonicalHeadWriteOutcome::Idempotent(_)
                )
            {
                anyhow::bail!("canonical head changed while entering rollback ARCHIVING");
            }
            current
        }
        RollbackControlState::Archiving(_) => {
            if initial != expected_archiving {
                anyhow::bail!("ARCHIVING head does not match the selected participant plan");
            }
            initial
        }
        _ => unreachable!("phase was exhaustively selected above"),
    };

    require_plan_and_topology_unchanged(
        &participant_plans,
        network,
        &plan,
        &topology_before,
    )
    .await?;
    if read_head::<Hash>(&canonical_head, network).await? != archiving_head {
        anyhow::bail!("canonical head changed after entering ARCHIVING");
    }

    let mut owner = ScyllaCoordinatorCommitPhysicalArchiveOwner::new(
        session,
        canonical_head.clone(),
        commit_sources,
        state_keyspace.clone(),
        state_keyspace,
        checkpoint_tree_height,
    );
    let readiness = match owner
        .recover_pre_barrier_readiness::<F, Hash, Hasher>(network)
        .await
    {
        Ok(readiness) => readiness,
        Err(CoordinatorCommitPhysicalArchiveOwnerError::CompletionMissing) => {
            let archive = owner
                .archive_current_request::<F, Hash, Hasher>(network)
                .await?;
            owner
                .persist_participant_completion::<F, Hash, Hasher>(network, &archive)
                .await?;
            owner
                .persist_target_restore_payload::<F, Hash, Hasher>(network)
                .await?;
            owner
                .recover_pre_barrier_readiness::<F, Hash, Hasher>(network)
                .await?
        }
        Err(CoordinatorCommitPhysicalArchiveOwnerError::TargetRestoreMissing) => {
            owner
                .persist_target_restore_payload::<F, Hash, Hasher>(network)
                .await?;
            owner
                .recover_pre_barrier_readiness::<F, Hash, Hasher>(network)
                .await?
        }
        Err(error) => return Err(error.into()),
    };
    let execution = owner
        .plan_delete_restore_execution::<F, Hash, Hasher>(network)
        .await?;

    require_plan_and_topology_unchanged(
        &participant_plans,
        network,
        &plan,
        &topology_before,
    )
    .await?;
    let final_head = read_head::<Hash>(&canonical_head, network).await?;
    if final_head != archiving_head
        || readiness.archiving_head() != &archiving_head
        || readiness.target() != plan.target()
    {
        anyhow::bail!("Coordinator archive readiness changed before maintenance return");
    }

    Ok(CoordinatorRollbackMaintenanceOutcome::ArchivePrepared(
        CoordinatorRollbackArchivePreparation::from_storage(
            archiving_head,
            *plan.target(),
            *plan.digest(),
            *readiness.digest(),
            *execution.digest(),
            readiness.entry_count(),
            *readiness.dataset_digest(),
        ),
    ))
}

async fn read_head<Hash: Q256BitHash>(
    store: &ScyllaCanonicalHeadStore,
    network: NetworkId,
) -> anyhow::Result<StoredCanonicalHead<Hash>> {
    match store.read(network).await? {
        CanonicalHeadReadState::Current(head) => Ok(head),
        CanonicalHeadReadState::Uninitialized => {
            anyhow::bail!("Coordinator canonical head is uninitialized")
        }
    }
}

fn expected_archiving_head<Hash: Q256BitHash>(
    plan: &RollbackParticipantPlan<Hash>,
) -> anyhow::Result<StoredCanonicalHead<Hash>> {
    let requested = CanonicalHeadTransition::start_rollback(
        *plan.expected_head(),
        plan.rollback_request()?,
    )?;
    Ok(*CanonicalHeadTransition::begin_rollback_archive(*requested.candidate())?
        .candidate())
}

async fn require_plan_and_topology_unchanged<Hash: Q256BitHash>(
    store: &ScyllaRollbackParticipantPlanStore,
    network: NetworkId,
    expected_plan: &RollbackParticipantPlan<Hash>,
    expected_topology: &super::rollback_participant_plan_store::PersistedRollbackTopologyReceipt,
) -> anyhow::Result<()> {
    let plan = store
        .read_participant_plan(network, expected_plan.digest())
        .await?;
    let topology = store
        .read_current_topology(network)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Coordinator rollback topology disappeared"))?;
    if &plan != expected_plan || topology.snapshot() != expected_topology.snapshot() {
        anyhow::bail!("rollback participant plan or topology changed during archive preparation");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn maintenance_has_no_destructive_or_barrier_transition() {
        let source = include_str!("coordinator_rollback_maintenance.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "delete_suffix",
            "restore_target",
            "enter_archive_barrier",
            "enter_deleting",
            "publish_target",
        ] {
            assert!(!production.contains(forbidden));
        }
        assert!(production.contains("begin_rollback_archive"));
        assert!(production.contains("archive_current_request"));
        assert!(production.contains("recover_pre_barrier_readiness"));
    }
}
