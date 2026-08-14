//! Realm-side prepare-only view of the Coordinator rollback control store.
//!
//! The Realm process receives an explicit Coordinator namespace from its
//! operator.  It never guesses the namespace and never exposes canonical-head
//! mutation or raw report writes.

use std::sync::Arc;

use async_trait::async_trait;
use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::store::{
    canonical_head::{CanonicalHeadReadState, StoredCanonicalHead},
    rollback_control::RollbackControlState,
    rollback_runtime_rebuild::{
        RealmRollbackParticipantProgress, RealmRollbackRuntimeControl,
        RollbackRuntimeRebuildReport,
        SelectedRealmRollbackRuntimeRebuild,
    },
};
use scylla::client::session::Session;

use super::{
    AuthorityTimestampNoTabletKeyspace, BranchExactDeploymentNoTabletKeyspace,
    BranchExactSchemaReady, PendingCounterAdapter, PendingQueueArtifactDataKeyspace,
    ScyllaAuthorityLocalHeadStore, ScyllaAuthorityTimestampStore,
    ScyllaBranchExactWriterLifecycleStore, ScyllaPendingPipelineStore,
    branch_exact_dual_write_executor::ScyllaBranchExactDualWriteAdapter,
    canonical_head_prototype::ScyllaCanonicalHeadStore,
    coordinator_rollback_delete_completion_store::ScyllaCoordinatorRollbackDeleteCompletionStore,
    realm_rollback_physical_archive_owner::{
        RealmRollbackPhysicalArchiveOwnerError,
        ScyllaRealmRollbackPhysicalArchiveOwner,
    },
    realm_rollback_delete_restore_executor::ScyllaRealmRollbackDeleteRestoreExecutor,
    realm_rollback_physical_archive_store::ScyllaRealmRollbackPhysicalArchiveStore,
    realm_rollback_target_restore_executor::ScyllaRealmRollbackTargetRestoreExecutor,
    realm_rollback_target_restore_planner::ScyllaRealmRollbackTargetRestorePlanner,
    rollback_global_archive_barrier::read_deleting_rollback_authority,
    rollback_global_delete_barrier::ScyllaRollbackGlobalDeleteBarrierStore,
    rollback_abort_convergence_store::ScyllaRollbackAbortConvergenceStore,
    ScyllaRollbackParticipantPlanStore,
    rollback_runtime_rebuild_store::ScyllaRollbackRuntimeRebuildStore,
    AuthorityLocalHeadNoTabletKeyspace, CanonicalHeadNoTabletKeyspace,
    CqlKeyspaceName,
};

pub struct ScyllaRealmRollbackRuntimeControl {
    session: Arc<Session>,
    canonical_head: Arc<ScyllaCanonicalHeadStore>,
    participant_plans: Arc<ScyllaRollbackParticipantPlanStore>,
    runtime_rebuild: Arc<ScyllaRollbackRuntimeRebuildStore>,
    abort_convergence: Arc<ScyllaRollbackAbortConvergenceStore>,
    local_inventory: Arc<super::realm_rollback_commit_inventory_store::ScyllaRealmRollbackCommitInventoryStore>,
    local_head: Arc<ScyllaAuthorityLocalHeadStore>,
    local_control_keyspace: CqlKeyspaceName,
    local_state_keyspace: CqlKeyspaceName,
    coordinator_archive_keyspace: CqlKeyspaceName,
    branch_exact_ready: Arc<BranchExactSchemaReady>,
}

impl ScyllaRealmRollbackRuntimeControl {
    /// Prepare statements against an explicitly configured, already deployed
    /// Coordinator namespace.  No keyspace or table is created here.
    pub(crate) async fn prepare_with_local_participant(
        session: Arc<Session>,
        local_keyspace: &str,
        local_no_tablet_keyspace: &str,
        coordinator_keyspace: &str,
        branch_exact_ready: Arc<BranchExactSchemaReady>,
    ) -> anyhow::Result<Self> {
        let data = CqlKeyspaceName::try_new(coordinator_keyspace.to_owned())?;
        let control = CanonicalHeadNoTabletKeyspace::try_new(format!(
            "{}_no_tablet",
            coordinator_keyspace
        ))?;
        let local_state_keyspace = CqlKeyspaceName::try_new(local_keyspace.to_owned())?;
        let local_control_keyspace = CqlKeyspaceName::try_new(
            local_no_tablet_keyspace.to_owned(),
        )?;
        let local_control = BranchExactDeploymentNoTabletKeyspace::try_new(
            local_no_tablet_keyspace.to_owned(),
        )?;
        let local_data = PendingQueueArtifactDataKeyspace::try_new(
            local_keyspace.to_owned(),
        )?;
        let local_inventory =
            ScyllaRealmRollbackPhysicalArchiveOwner::prepare_inventory(
                session.clone(),
                local_control,
                local_data,
            )
            .await?;
        let local_head = Arc::new(
            ScyllaAuthorityLocalHeadStore::prepare(
                session.clone(),
                AuthorityLocalHeadNoTabletKeyspace::try_new(
                    local_no_tablet_keyspace.to_owned(),
                )?,
            )
            .await?,
        );
        Ok(Self {
            session: session.clone(),
            canonical_head: Arc::new(
                ScyllaCanonicalHeadStore::prepare(session.clone(), control.clone()).await?,
            ),
            participant_plans: Arc::new(
                ScyllaRollbackParticipantPlanStore::prepare(
                    session.clone(),
                    control,
                )
                .await?,
            ),
            runtime_rebuild: Arc::new(
                ScyllaRollbackRuntimeRebuildStore::prepare(session.clone(), &data).await?,
            ),
            abort_convergence: Arc::new(
                ScyllaRollbackAbortConvergenceStore::prepare(session, &data).await?,
            ),
            local_inventory,
            local_head,
            local_control_keyspace,
            local_state_keyspace,
            coordinator_archive_keyspace: data,
            branch_exact_ready,
        })
    }

    async fn prepare_archive_owner(
        &self,
    ) -> anyhow::Result<ScyllaRealmRollbackPhysicalArchiveOwner> {
        let narrow = ScyllaBranchExactDualWriteAdapter::prepare(
            self.session.clone(),
            &self.branch_exact_ready,
        )
        .await?;
        Ok(ScyllaRealmRollbackPhysicalArchiveOwner::prepare(
            self.session.clone(),
            self.local_inventory.clone(),
            self.local_head.clone(),
            narrow,
            self.local_state_keyspace.clone(),
            self.coordinator_archive_keyspace.clone(),
        )
        .await?)
    }

    /// Qualification setup only: persist a small canonical Realm commit
    /// history so the production archive owner can be exercised without
    /// duplicating the full Processor writer fixture in this integration test.
    #[cfg(test)]
    pub(crate) async fn qualification_seed_narrow_commit_history<
        Hash: Q256BitHash,
    >(
        &self,
        commits: Vec<(
            psy_node_core::store::branch_exact_dual_write::BranchExactDualWriteIntent<Hash>,
            psy_node_core::store::timestamp::CommitWriteTimestampUs,
            psy_node_core::store::authority_local_head::StoredAuthorityLocalHead<Hash>,
            psy_node_core::store::pending_generation_pipeline::StoredPendingPipeline<Hash>,
        )>,
        source_head: &psy_node_core::store::authority_local_head::AuthorityLocalHeadBootstrap<Hash>,
    ) -> anyhow::Result<()> {
        let narrow = ScyllaBranchExactDualWriteAdapter::prepare(
            self.session.clone(),
            &self.branch_exact_ready,
        )
        .await?;
        for (intent, timestamp, head, pipeline) in commits {
            narrow
                .qualification_write_inventory_exact(&intent, timestamp)
                .await?;
            let inventory = super::realm_rollback_commit_inventory::RealmRollbackCommitInventory::qualification_from_narrow(
                intent,
                timestamp,
            )?;
            self.local_inventory
                .qualification_persist_committed(inventory, &head, &pipeline)
                .await?;
        }
        self.local_head.bootstrap(source_head).await?;
        Ok(())
    }

    async fn prepare_delete_executor(
        &self,
    ) -> anyhow::Result<ScyllaRealmRollbackDeleteRestoreExecutor> {
        Ok(ScyllaRealmRollbackDeleteRestoreExecutor::prepare(
            self.session.clone(),
            self.canonical_head.clone(),
            self.local_head.clone(),
            self.prepare_archive_owner().await?,
            self.local_state_keyspace.clone(),
            self.coordinator_archive_keyspace.clone(),
        )
        .await?)
    }

    /// Select the complete plan-ordered global delete barrier from the shared
    /// Coordinator archive, then restore only this process's Realm keyspace.
    /// No caller-provided completion digest or target row is accepted.
    async fn restore_selected_realm<Hash: Q256BitHash>(
        &self,
        deleting: &super::rollback_global_archive_barrier::DeletingRollbackGlobalArchiveBarrier<Hash>,
        participant: psy_node_core::store::rollback_participant_plan::RollbackRealmParticipant,
    ) -> anyhow::Result<
        super::realm_rollback_physical_archive_store::PersistedRealmRollbackTargetRestoreCompletion<Hash>,
    > {
        let archive = Arc::new(
            ScyllaRealmRollbackPhysicalArchiveStore::prepare(
                self.session.clone(),
                self.coordinator_archive_keyspace.clone(),
            )
            .await?,
        );
        let coordinator_store = ScyllaCoordinatorRollbackDeleteCompletionStore::prepare(
            self.session.clone(),
            &self.coordinator_archive_keyspace,
        )
        .await?;
        let coordinator = coordinator_store
            .read_for_authority(deleting)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Coordinator delete completion is missing"))?;

        let mut realm_deletes = Vec::with_capacity(deleting.participant_plan().realms().len());
        for planned in deleting.participant_plan().realms() {
            let authority = AuthorityScope::Realm {
                realm_id: planned.realm_id(),
                realm_sub_id: planned.realm_sub_id(),
            };
            let archived = archive
                .read_participant_completion_selected::<Hash>(
                    deleting.participant_plan().target().network_id(),
                    deleting.participant_plan().target().chain_epoch().get(),
                    authority,
                    *deleting.participant_plan().digest(),
                )
                .await?
                .ok_or_else(|| anyhow::anyhow!("planned Realm archive completion is missing"))?;
            let deleted = archive
                .read_delete_completion_for_participant(deleting, &archived)
                .await?
                .ok_or_else(|| anyhow::anyhow!("planned Realm delete completion is missing"))?;
            realm_deletes.push(deleted);
        }
        let index = deleting
            .participant_plan()
            .realms()
            .iter()
            .position(|planned| planned == &participant)
            .ok_or_else(|| anyhow::anyhow!("Realm is absent from rollback plan"))?;
        let global_barrier = Arc::new(
            ScyllaRollbackGlobalDeleteBarrierStore::prepare(
                self.session.clone(),
                &self.coordinator_archive_keyspace,
            )
            .await?,
        );
        let barrier = global_barrier
            .read_for_authority(deleting)
            .await?
            .ok_or_else(|| anyhow::anyhow!("global delete barrier is missing"))?;
        let selected = global_barrier
            .select_realm(&barrier, deleting, &coordinator, &realm_deletes, index)
            .await?;

        let branch_keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            self.local_control_keyspace.as_str().to_owned(),
        )?;
        let pipeline = Arc::new(
            ScyllaPendingPipelineStore::prepare(
                self.session.clone(),
                branch_keyspace.clone(),
            )
            .await?,
        );
        let writer = Arc::new(
            ScyllaBranchExactWriterLifecycleStore::prepare(
                self.session.clone(),
                branch_keyspace,
            )
            .await?,
        );
        let timestamp = Arc::new(
            ScyllaAuthorityTimestampStore::prepare(
                self.session.clone(),
                AuthorityTimestampNoTabletKeyspace::try_new(
                    self.local_control_keyspace.as_str().to_owned(),
                )?,
            )
            .await?,
        );
        let counter = Arc::new(
            PendingCounterAdapter::prepare(
                self.session.clone(),
                self.local_control_keyspace.clone(),
                self.local_state_keyspace.clone(),
            )
            .await?,
        );
        let planner = Arc::new(ScyllaRealmRollbackTargetRestorePlanner::new(
            global_barrier.clone(),
            archive.clone(),
            self.local_inventory.clone(),
            self.local_head.clone(),
            pipeline.clone(),
            writer.clone(),
            timestamp.clone(),
            counter.clone(),
        ));
        let executor = ScyllaRealmRollbackTargetRestoreExecutor::new(
            planner,
            global_barrier,
            archive,
            self.local_head.clone(),
            pipeline,
            writer,
            timestamp,
            counter,
        );
        Ok(executor.restore(&selected).await?)
    }

    async fn read_head<Hash: Q256BitHash>(
        &self,
        network: NetworkId,
    ) -> anyhow::Result<Option<StoredCanonicalHead<Hash>>> {
        Ok(match self.canonical_head.read(network).await? {
            CanonicalHeadReadState::Uninitialized => None,
            CanonicalHeadReadState::Current(head) => Some(head),
        })
    }

    fn phase_matches_selected<Hash: Q256BitHash>(
        current: &StoredCanonicalHead<Hash>,
        selected: &SelectedRealmRollbackRuntimeRebuild<Hash>,
    ) -> bool {
        let selected_request = match selected.verifying_head().rollback_control() {
            RollbackControlState::Verifying(request) => request,
            _ => return false,
        };
        match current.rollback_control() {
            RollbackControlState::Verifying(request)
            | RollbackControlState::AllRealmsReady(request) => {
                request == selected_request
                    && current.canonical_ref().network_id()
                        == selected.directive().target().network_id()
                    && current.canonical_ref().chain_epoch()
                        == selected.directive().target().chain_epoch()
            }
            RollbackControlState::Idle => {
                current.canonical_ref() == selected.directive().target()
            }
            _ => false,
        }
    }

    fn same_active_rollback<Hash: Q256BitHash>(
        first: &StoredCanonicalHead<Hash>,
        second: &StoredCanonicalHead<Hash>,
    ) -> bool {
        first.canonical_ref() == second.canonical_ref()
            && first.rollback_control().requested()
                == second.rollback_control().requested()
            && first.rollback_control().requested().is_some()
    }
}

#[async_trait]
impl<Hash: Q256BitHash> RealmRollbackRuntimeControl<Hash>
    for ScyllaRealmRollbackRuntimeControl
{
    async fn progress_realm_rollback_participant(
        &self,
        network: NetworkId,
        authority: AuthorityScope,
    ) -> anyhow::Result<RealmRollbackParticipantProgress<Hash>> {
        let AuthorityScope::Realm { realm_id, realm_sub_id } = authority else {
            anyhow::bail!("Realm rollback participant maintenance requires Realm authority")
        };
        let Some(first_head) = self.read_head(network).await? else {
            anyhow::bail!("Coordinator canonical head is missing")
        };
        let Some(request) = first_head.rollback_control().requested() else {
            return Ok(RealmRollbackParticipantProgress::AwaitingCoordinator(first_head));
        };
        let plan: psy_node_core::store::rollback_participant_plan::RollbackParticipantPlan<Hash> = self
            .participant_plans
            .read_participant_plan(network, request.plan_digest().as_bytes())
            .await?;
        let participant = psy_node_core::store::rollback_participant_plan::RollbackRealmParticipant::new(
            realm_id,
            realm_sub_id,
        );
        if !plan.realms().contains(&participant)
            || plan.target().network_id() != network
            || plan.digest() != request.plan_digest().as_bytes()
        {
            anyhow::bail!("Realm is not a member of the storage-selected rollback plan")
        }
        let topology = self
            .participant_plans
            .read_current_topology(network)
            .await?
            .ok_or_else(|| anyhow::anyhow!("rollback topology is missing"))?;
        if !topology.snapshot().validates_plan(&plan) {
            anyhow::bail!("rollback topology changed after plan selection")
        }
        match first_head.rollback_control() {
            RollbackControlState::Requested(_) => {
                Ok(RealmRollbackParticipantProgress::AwaitingCoordinator(first_head))
            }
            RollbackControlState::Aborting(_) => {
                // The dedicated all-participant abort convergence path owns
                // this phase. Archive/delete/restore maintenance stops here.
                Ok(RealmRollbackParticipantProgress::AbortRequested(first_head))
            }
            RollbackControlState::Archiving(_) => {
                let mut owner = self.prepare_archive_owner().await?;
                let completion = match owner
                    .recover_participant_completion(network, authority, &plan)
                    .await
                {
                    Ok(completion) => completion,
                    Err(RealmRollbackPhysicalArchiveOwnerError::CompletionMissing) => {
                        let archive = owner
                            .archive_selected_realm(network, authority, &plan)
                            .await?;
                        owner
                            .persist_participant_completion(network, &plan, &archive)
                            .await?
                    }
                    Err(error) => return Err(error.into()),
                };
                let Some(second_head) = self.read_head(network).await? else {
                    anyhow::bail!("Coordinator canonical head disappeared after Realm archive")
                };
                if second_head != first_head
                    && !Self::same_active_rollback(&first_head, &second_head)
                {
                    anyhow::bail!("Coordinator rollback phase changed during Realm archive")
                }
                Ok(RealmRollbackParticipantProgress::ArchivePrepared {
                    head: second_head,
                    entry_count: completion.completion().entry_count(),
                })
            }
            RollbackControlState::Verifying(_) | RollbackControlState::AllRealmsReady(_) => {
                Ok(RealmRollbackParticipantProgress::ReadyForRuntimeRebuild(first_head))
            }
            RollbackControlState::Deleting(_) => {
                let deleting = read_deleting_rollback_authority::<Hash>(
                    self.session.clone(),
                    self.canonical_head.clone(),
                    self.participant_plans.clone(),
                    &self.coordinator_archive_keyspace,
                    network,
                )
                .await?;
                let mut executor = self.prepare_delete_executor().await?;
                let completion = executor
                    .execute_and_persist(&deleting, participant)
                    .await?;
                let Some(second_head) = self.read_head(network).await? else {
                    anyhow::bail!("Coordinator canonical head disappeared after Realm delete")
                };
                if second_head != first_head
                    && !Self::same_active_rollback(&first_head, &second_head)
                {
                    anyhow::bail!("Coordinator rollback phase changed during Realm delete")
                }
                Ok(RealmRollbackParticipantProgress::DeletePrepared {
                    head: second_head,
                    physical_delete_count: completion.completion().physical_delete_count(),
                    restored_row_count: completion.completion().restored_row_count(),
                })
            }
            RollbackControlState::Restoring(_) => {
                let deleting = read_deleting_rollback_authority::<Hash>(
                    self.session.clone(),
                    self.canonical_head.clone(),
                    self.participant_plans.clone(),
                    &self.coordinator_archive_keyspace,
                    network,
                )
                .await?;
                let completion = self
                    .restore_selected_realm(&deleting, participant)
                    .await?;
                let Some(second_head) = self.read_head(network).await? else {
                    anyhow::bail!("Coordinator canonical head disappeared after Realm restore")
                };
                if second_head != first_head
                    && !Self::same_active_rollback(&first_head, &second_head)
                {
                    anyhow::bail!("Coordinator rollback phase changed during Realm restore")
                }
                Ok(RealmRollbackParticipantProgress::RestorePrepared {
                    head: second_head,
                    final_rows_digest: *completion.completion().final_rows_digest(),
                })
            }
            RollbackControlState::ArchiveBarrierReady(_) => {
                Ok(RealmRollbackParticipantProgress::AwaitingCoordinator(first_head))
            }
            RollbackControlState::Idle => {
                Ok(RealmRollbackParticipantProgress::AwaitingCoordinator(first_head))
            }
        }
    }

    async fn read_realm_rollback_control_head(
        &self,
        network: NetworkId,
    ) -> anyhow::Result<CanonicalHeadReadState<Hash>> {
        Ok(match self.read_head(network).await? {
            None => CanonicalHeadReadState::Uninitialized,
            Some(head) => CanonicalHeadReadState::Current(head),
        })
    }

    async fn read_selected_realm_runtime_rebuild(
        &self,
        network: NetworkId,
        authority: AuthorityScope,
    ) -> anyhow::Result<Option<SelectedRealmRollbackRuntimeRebuild<Hash>>> {
        if !matches!(authority, AuthorityScope::Realm { .. }) {
            anyhow::bail!("Realm rollback runtime control requires Realm authority")
        }
        let Some(first_head) = self.read_head(network).await? else {
            return Ok(None);
        };
        if !matches!(first_head.rollback_control(), RollbackControlState::Verifying(_)) {
            return Ok(None);
        }
        let Some(directive) = self
            .runtime_rebuild
            .read_selected_directive(first_head, authority)
            .await?
        else {
            return Ok(None);
        };
        let Some(second_head) = self.read_head(network).await? else {
            anyhow::bail!("Coordinator canonical head disappeared while selecting Realm rebuild")
        };
        if second_head != first_head {
            anyhow::bail!("Coordinator canonical head changed while selecting Realm rebuild")
        }
        Ok(Some(SelectedRealmRollbackRuntimeRebuild::try_from_storage(
            second_head,
            directive,
        )?))
    }

    async fn persist_realm_runtime_rebuild_report(
        &self,
        selected: SelectedRealmRollbackRuntimeRebuild<Hash>,
        report: RollbackRuntimeRebuildReport<Hash>,
    ) -> anyhow::Result<()> {
        self.runtime_rebuild
            .revalidate_directive(selected.directive())
            .await?;
        let Some(before) = self
            .read_head(selected.directive().target().network_id())
            .await?
        else {
            anyhow::bail!("Coordinator canonical head disappeared before Realm report")
        };
        if !Self::phase_matches_selected(&before, &selected) {
            anyhow::bail!("Coordinator rollback phase changed before Realm report")
        }
        self.runtime_rebuild
            .persist_and_revalidate_report(*selected.directive(), report)
            .await?;
        let Some(after) = self
            .read_head(selected.directive().target().network_id())
            .await?
        else {
            anyhow::bail!("Coordinator canonical head disappeared after Realm report")
        };
        if !Self::phase_matches_selected(&after, &selected) {
            anyhow::bail!("Coordinator rollback phase changed incompatibly after Realm report")
        }
        Ok(())
    }

    async fn is_realm_runtime_rebuild_published(
        &self,
        selected: SelectedRealmRollbackRuntimeRebuild<Hash>,
    ) -> anyhow::Result<bool> {
        self.runtime_rebuild
            .revalidate_directive(selected.directive())
            .await?;
        let Some(current) = self
            .read_head(selected.directive().target().network_id())
            .await?
        else {
            anyhow::bail!("Coordinator canonical head disappeared after Realm rebuild")
        };
        if !Self::phase_matches_selected(&current, &selected) {
            anyhow::bail!("Coordinator rollback phase no longer matches Realm rebuild")
        }
        Ok(matches!(current.rollback_control(), RollbackControlState::Idle))
    }

    async fn persist_realm_rollback_abort_ack(
        &self,
        aborting_head: StoredCanonicalHead<Hash>,
        authority: AuthorityScope,
        paused_runtime_revision: u64,
        paused_runtime_identity: u128,
    ) -> anyhow::Result<()> {
        let request = aborting_head
            .rollback_control()
            .aborting()
            .ok_or_else(|| anyhow::anyhow!("Realm abort acknowledgement requires ABORTING"))?
            .request();
        let plan = self
            .participant_plans
            .read_participant_plan(
                aborting_head.canonical_ref().network_id(),
                request.plan_digest().as_bytes(),
            )
            .await?;
        let topology = self
            .participant_plans
            .read_current_topology(aborting_head.canonical_ref().network_id())
            .await?
            .ok_or_else(|| anyhow::anyhow!("rollback topology is missing"))?;
        if !topology.snapshot().validates_plan(&plan) {
            anyhow::bail!("rollback topology changed before Realm abort acknowledgement")
        }
        self.abort_convergence
            .persist_realm_ack(
                aborting_head,
                &plan,
                authority,
                paused_runtime_revision,
                paused_runtime_identity,
            )
            .await?;
        Ok(())
    }

    async fn is_realm_rollback_abort_published(
        &self,
        aborting_head: StoredCanonicalHead<Hash>,
        authority: AuthorityScope,
    ) -> anyhow::Result<bool> {
        let request = aborting_head
            .rollback_control()
            .aborting()
            .ok_or_else(|| anyhow::anyhow!("Realm abort observation requires ABORTING"))?
            .request();
        let plan = self
            .participant_plans
            .read_participant_plan(
                aborting_head.canonical_ref().network_id(),
                request.plan_digest().as_bytes(),
            )
            .await?;
        Ok(self
            .abort_convergence
            .is_published(
                self.canonical_head.as_ref(),
                aborting_head,
                &plan,
                authority,
            )
            .await?)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn realm_control_is_prepare_only_and_brackets_reports() {
        let source = include_str!("realm_rollback_runtime_control.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(!source.contains("create_schema"));
        assert!(!source.contains("compare_and_set"));
        assert!(!source.contains("persist_directive"));
        let selection = source
            .split("async fn read_selected_realm_runtime_rebuild")
            .nth(1)
            .unwrap();
        let select = selection.find("let Some(first_head)").unwrap();
        let directive = selection
            .find(".read_selected_directive(first_head, authority)")
            .unwrap();
        let second = selection.find("let Some(second_head)").unwrap();
        assert!(select < directive && directive < second);
        let persist = source.find(".persist_and_revalidate_report(").unwrap();
        let before = source[..persist].rfind("let Some(before)").unwrap();
        let after = source[persist..].find("let Some(after)").unwrap() + persist;
        assert!(before < persist && persist < after);
    }

    #[test]
    fn realm_restore_is_selected_from_global_barrier_before_local_mutation() {
        let source = include_str!("realm_rollback_runtime_control.rs");
        let method = source.split("async fn restore_selected_realm").nth(1).unwrap();
        let archive = method
            .find("read_participant_completion_selected::<Hash>")
            .unwrap();
        let deleted = method
            .find("read_delete_completion_for_participant")
            .unwrap();
        let barrier = method.find(".read_for_authority(deleting)").unwrap();
        let selected = method.find(".select_realm(").unwrap();
        let planner = method
            .find("ScyllaRealmRollbackTargetRestorePlanner::new")
            .unwrap();
        let restore = method.find("executor.restore(&selected)").unwrap();
        assert!(archive < deleted);
        assert!(barrier < selected);
        assert!(selected < planner);
        assert!(planner < restore);
    }
}
