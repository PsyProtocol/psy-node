//! Production selection of the complete runtime-rebuild report set.
//!
//! The caller supplies only the network. Participant identities come from the
//! immutable rollback plan; reports, restore barrier and head transitions are
//! selected and revalidated inside storage.

use std::sync::Arc;

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::store::{
    canonical_head::{CanonicalHeadReadState, CanonicalHeadTransition, StoredCanonicalHead},
    rollback_runtime_rebuild::CoordinatorRollbackRuntimePublication,
};

use super::{
    CqlKeyspaceName, ScyllaCanonicalHeadStore, ScyllaRollbackParticipantPlanStore,
    ScyllaRollbackRuntimeRebuildStore,
    rollback_global_restore_barrier::ScyllaRollbackGlobalRestoreBarrierStore,
    rollback_global_restore_orchestrator::ScyllaRollbackGlobalRestoreOrchestrator,
};

pub(crate) async fn try_publish_restored_runtime<Hash: Q256BitHash>(
    canonical_head: Arc<ScyllaCanonicalHeadStore>,
    participant_plans: Arc<ScyllaRollbackParticipantPlanStore>,
    runtime: Arc<ScyllaRollbackRuntimeRebuildStore>,
    session: Arc<scylla::client::session::Session>,
    keyspace: CqlKeyspaceName,
    network: NetworkId,
) -> anyhow::Result<CoordinatorRollbackRuntimePublication<Hash>> {
    let current = read_head::<Hash>(&canonical_head, network).await?;
    let request = *current
        .rollback_control()
        .requested()
        .ok_or_else(|| anyhow::anyhow!("runtime publication requires an active rollback"))?;
    let plan = participant_plans
        .read_participant_plan(network, request.plan_digest().as_bytes())
        .await?;
    let topology = participant_plans
        .read_current_topology(network)
        .await?
        .ok_or_else(|| anyhow::anyhow!("rollback topology is missing during runtime publication"))?;
    if !topology.snapshot().validates_plan(&plan) {
        anyhow::bail!("rollback topology changed before runtime publication");
    }

    let verifying = expected_verifying_head(&plan)?;
    let all_ready = CanonicalHeadTransition::complete_rollback_realm_barrier(verifying)?;
    if current != verifying && current != *all_ready.candidate() {
        anyhow::bail!("canonical head is not the selected VERIFYING/ALL_REALMS_READY row");
    }

    let coordinator_directive = runtime
        .read_selected_directive(verifying, AuthorityScope::Coordinator)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Coordinator runtime rebuild directive is missing"))?;
    let restore_store = ScyllaRollbackGlobalRestoreBarrierStore::prepare(session, &keyspace).await?;
    let restore = restore_store
        .read_selected_for_runtime(verifying, coordinator_directive)
        .await?;
    if restore.barrier().realm_count()
        != u64::try_from(plan.realms().len())?
    {
        anyhow::bail!("restore barrier Realm count differs from participant plan");
    }
    let coordinator_report = runtime
        .read_report_for_directive(coordinator_directive)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Coordinator runtime rebuild report is missing"))?;

    let mut reports = Vec::with_capacity(plan.realms().len());
    let mut completed = 0_u64;
    for participant in plan.realms() {
        let authority = AuthorityScope::Realm {
            realm_id: participant.realm_id(),
            realm_sub_id: participant.realm_sub_id(),
        };
        let directive = runtime
            .read_selected_directive(verifying, authority)
            .await?
            .ok_or_else(|| anyhow::anyhow!("planned Realm runtime rebuild directive is missing"))?;
        if let Some(report) = runtime.read_report_for_directive(directive).await? {
            reports.push(report);
            completed = completed.checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("Realm report count overflow"))?;
        }
    }
    let expected = u64::try_from(plan.realms().len())?;
    if completed != expected {
        if current == *all_ready.candidate() {
            anyhow::bail!(
                "ALL_REALMS_READY is selected but a planned Realm report is missing"
            );
        }
        require_unchanged(
            &canonical_head,
            &participant_plans,
            network,
            &current,
            &plan,
            topology.snapshot(),
        )
        .await?;
        return Ok(CoordinatorRollbackRuntimePublication::AwaitingRealmReports {
            completed,
            expected,
        });
    }

    require_unchanged(
        &canonical_head,
        &participant_plans,
        network,
        &current,
        &plan,
        topology.snapshot(),
    )
    .await?;
    let published = ScyllaRollbackGlobalRestoreOrchestrator::
        persist_runtime_ready_and_publish_with(
            &canonical_head,
            &restore_store,
            &runtime,
            &restore,
            &coordinator_report,
            &reports,
        )
        .await?;
    let plan_after = participant_plans
        .read_participant_plan(network, plan.digest())
        .await?;
    let topology_after = participant_plans
        .read_current_topology(network)
        .await?
        .ok_or_else(|| anyhow::anyhow!("rollback topology disappeared after publication"))?;
    if plan_after != plan
        || topology_after.snapshot() != topology.snapshot()
        || !topology_after.snapshot().validates_plan(&plan_after)
        || published.canonical_ref().checkpoint() != plan.target().checkpoint()
    {
        anyhow::bail!("rollback plan/topology/target changed across runtime publication");
    }
    Ok(CoordinatorRollbackRuntimePublication::Published(published))
}

fn expected_verifying_head<Hash: Q256BitHash>(
    plan: &psy_node_core::store::rollback_participant_plan::RollbackParticipantPlan<Hash>,
) -> anyhow::Result<StoredCanonicalHead<Hash>> {
    let requested = CanonicalHeadTransition::start_rollback(
        *plan.expected_head(),
        plan.rollback_request()?,
    )?;
    let archiving = CanonicalHeadTransition::begin_rollback_archive(*requested.candidate())?;
    let barrier = CanonicalHeadTransition::complete_rollback_archive_barrier(*archiving.candidate())?;
    let deleting = CanonicalHeadTransition::begin_rollback_delete(*barrier.candidate())?;
    let restoring = CanonicalHeadTransition::begin_rollback_restore(*deleting.candidate())?;
    Ok(*CanonicalHeadTransition::begin_rollback_verify(*restoring.candidate())?.candidate())
}

async fn require_unchanged<Hash: Q256BitHash>(
    canonical_head: &ScyllaCanonicalHeadStore,
    participant_plans: &ScyllaRollbackParticipantPlanStore,
    network: NetworkId,
    expected_head: &StoredCanonicalHead<Hash>,
    expected_plan: &psy_node_core::store::rollback_participant_plan::RollbackParticipantPlan<Hash>,
    expected_topology: &psy_node_core::store::rollback_topology::RollbackTopologySnapshot,
) -> anyhow::Result<()> {
    let head = read_head(canonical_head, network).await?;
    let plan = participant_plans
        .read_participant_plan(network, expected_plan.digest())
        .await?;
    let topology = participant_plans
        .read_current_topology(network)
        .await?
        .ok_or_else(|| anyhow::anyhow!("rollback topology disappeared during publication"))?;
    if &head != expected_head
        || &plan != expected_plan
        || topology.snapshot() != expected_topology
        || !topology.snapshot().validates_plan(&plan)
    {
        anyhow::bail!("rollback head/plan/topology changed during runtime report selection");
    }
    Ok(())
}

async fn read_head<Hash: Q256BitHash>(
    canonical_head: &ScyllaCanonicalHeadStore,
    network: NetworkId,
) -> anyhow::Result<StoredCanonicalHead<Hash>> {
    match canonical_head.read(network).await? {
        CanonicalHeadReadState::Current(head) => Ok(head),
        CanonicalHeadReadState::Uninitialized => {
            anyhow::bail!("Coordinator canonical head is missing during runtime publication")
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn publication_selects_every_realm_from_the_plan() {
        let source = include_str!("coordinator_rollback_runtime_publication.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(source.contains("for participant in plan.realms()"));
        assert!(source.contains("read_selected_directive(verifying, authority)"));
        assert!(source.contains("read_report_for_directive(directive)"));
        assert!(source.contains("persist_runtime_ready_and_publish_with"));
        assert!(!source.contains("create_schema"));
    }
}
