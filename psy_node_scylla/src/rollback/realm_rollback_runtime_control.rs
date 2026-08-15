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
    authority_commit::AuthorityTimestampKey,
    authority_local_head::AuthorityLocalHeadReadState,
    canonical_head::{CanonicalHeadReadState, StoredCanonicalHead},
    rollback_control::RollbackControlState,
    rollback_runtime_rebuild::{
        RealmRollbackParticipantProgress, RealmRollbackRuntimeControl,
        RollbackRuntimeRebuildReport,
        SelectedRealmRollbackRuntimeRebuild,
    },
};
#[cfg(test)]
use psy_node_core::store::{
    authority_commit::{
        AuthorityClockSampleUs, AuthorityTimestampBootstrap, AuthorityTimestampBootstrapReason,
        AuthorityTimestampReadState,
    },
    authority_local_head::AuthorityLocalHeadWriteOutcome,
    pending_generation::ProcNamespacePrefix,
    pending_generation_identity::PendingGenerationLedgerKey,
    pending_generation_pipeline::{
        PendingPipelineIntentDigest, PendingPipelineReadState, PendingPipelineWriteOutcome,
        PendingPublishReceiptDigest, PendingQueueCloseIntentDigest, PendingWorkCaptureDigest,
    },
};
#[cfg(test)]
use super::BranchExactWriterPrepared;
#[cfg(test)]
use super::qualification_persist_realm_genesis_rollback_anchor;
#[cfg(test)]
use sha2::{Digest, Sha256};
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

    /// Qualification-only persistence of the same immutable checkpoint-zero
    /// anchor written by the production Genesis activation.  No live writer,
    /// pipeline, head, or serving route is changed here.
    #[cfg(test)]
    pub(crate) async fn qualification_seed_genesis_rollback_anchor<
        Hash: Q256BitHash,
    >(
        &self,
        genesis: psy_data::protocol::chain_context::AuthorityObservation<Hash>,
        genesis_l2_block_state: Vec<u8>,
        writer_activation_digest: [u8; 32],
    ) -> anyhow::Result<()> {
        qualification_persist_realm_genesis_rollback_anchor(
            self.session.clone(),
            self.local_state_keyspace.clone(),
            BranchExactDeploymentNoTabletKeyspace::try_new(
                self.local_control_keyspace.as_str().to_owned(),
            )?,
            genesis,
            genesis_l2_block_state,
            writer_activation_digest,
        )
        .await
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
        let mut source = None;
        let mut pending_owners = Vec::new();
        for (intent, timestamp, head, pipeline) in commits {
            pending_owners.push((
                intent.candidate().pending_id(),
                intent.proc_checkpoint_id(),
            ));
            source = Some((
                intent.authority(),
                *intent.candidate(),
                timestamp,
                intent.intent_digest(),
                pipeline.clone(),
            ));
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

        // Seed only the live control rows that the production restore planner
        // selects.  Every later restore mutation still runs through the real
        // QUORUM/LWT stores; these test-only IFNE helpers cannot overwrite a
        // current row or authorize serving.
        let (authority, watermark, source_write_timestamp, last_intent, source_pipeline) =
            source.ok_or_else(|| anyhow::anyhow!("source commit missing"))?;
        let timestamp_key = AuthorityTimestampKey::new(
            watermark.canonical_chain().network_id(),
            authority,
        );
        let timestamp_bootstrap = AuthorityTimestampBootstrap::new(
            timestamp_key,
            psy_node_core::store::timestamp::CommitWriteTimestampUs::try_from_i128(
                i128::from(source_write_timestamp.as_i64()) - 1,
            )?,
            AuthorityTimestampBootstrapReason::ControlledWriterCutover,
        );
        let timestamp_reservation = timestamp_bootstrap.candidate().seal_reservation(
            timestamp_key,
            last_intent.authority_intent(),
            AuthorityClockSampleUs::try_from_i128(i128::from(
                source_write_timestamp.as_i64(),
            ))?,
        )?;
        let timestamp_completion = timestamp_reservation
            .candidate()
            .seal_completion(timestamp_key, timestamp_reservation.lease())?;
        let timestamp_state = timestamp_completion.candidate();
        let branch_keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            self.local_control_keyspace.as_str().to_owned(),
        )?;
        let writer_store = ScyllaBranchExactWriterLifecycleStore::prepare(
            self.session.clone(),
            branch_keyspace.clone(),
        )
        .await?;
        let source_writer = super::StoredBranchExactWriterLifecycle::qualification_active_fixture(
            authority,
            watermark,
            timestamp_state,
            last_intent,
            u64::try_from(pending_owners.len())?,
            self.branch_exact_ready.expected_receipt().clone(),
        );
        match writer_store
            .qualification_persist_current(&source_writer)
            .await?
        {
            super::BranchExactWriterWriteOutcome::Applied(current)
            | super::BranchExactWriterWriteOutcome::Idempotent(current)
                if current == source_writer => {}
            other => anyhow::bail!("qualification writer seed conflict: {other:?}"),
        }

        let pipeline_store = ScyllaPendingPipelineStore::prepare(
            self.session.clone(),
            branch_keyspace,
        )
        .await?;
        match pipeline_store
            .qualification_persist_current(&source_pipeline)
            .await?
        {
            PendingPipelineWriteOutcome::Applied(current)
            | PendingPipelineWriteOutcome::Idempotent(current)
                if current == source_pipeline => {}
            other => anyhow::bail!("qualification pipeline seed conflict: {other:?}"),
        }

        let timestamp_store = ScyllaAuthorityTimestampStore::prepare(
            self.session.clone(),
            AuthorityTimestampNoTabletKeyspace::try_new(
                self.local_control_keyspace.as_str().to_owned(),
            )?,
        )
        .await?;
        timestamp_store.bootstrap(timestamp_bootstrap).await?;
        timestamp_store.reserve(timestamp_reservation).await?;
        timestamp_store.complete(timestamp_completion).await?;

        let counter = PendingCounterAdapter::prepare(
            self.session.clone(),
            self.local_control_keyspace.clone(),
            self.local_state_keyspace.clone(),
        )
        .await?;
        let prefix = ProcNamespacePrefix::for_authority(
            watermark.canonical_chain().network_id(),
            authority,
        );
        let counter_target = source_pipeline.gathering().pending_id().get();
        for value in 1..=counter_target {
            let candidate = psy_node_core::store::typed::UniquePendingId::try_new(value)?;
            let expected = if value == 1 {
                super::PendingCounterExpected::Absent
            } else {
                super::PendingCounterExpected::Present(
                    psy_node_core::store::typed::UniquePendingId::try_new(value - 1)?,
                )
            };
            let allocation = super::SealedPendingCounterAllocation::try_for_commit(
                expected,
                pending_owners
                    .iter()
                    .find_map(|(pending, proc_id)| (*pending == candidate).then_some(*proc_id))
                    .unwrap_or_else(|| prefix.derive_proc_id(candidate)),
                source_write_timestamp,
            )?;
            match counter.allocate(&allocation).await? {
                super::PendingCounterAllocationOutcome::Owned(owned)
                    if owned.pending() == candidate => {}
                other => anyhow::bail!(
                    "qualification pending counter seed conflict at {value}: {other:?}"
                ),
            }
        }
        Ok(())
    }

    /// Qualification-only post-rollback commit.  It deliberately reuses the
    /// real timestamp allocator, narrow physical writer and authority-head
    /// CAS, but does not stand in for the still-gated Processor/full-manifest
    /// assembly path.
    #[cfg(test)]
    pub(crate) async fn qualification_append_post_rollback_narrow_commit<
        Hash: Q256BitHash,
    >(
        &self,
        narrow: BranchExactWriterPrepared<Hash>,
        observation: psy_data::protocol::chain_context::AuthorityObservation<Hash>,
        clock_sample: AuthorityClockSampleUs,
    ) -> anyhow::Result<(
        psy_node_core::store::authority_local_head::StoredAuthorityLocalHead<Hash>,
        psy_node_core::store::timestamp::CommitWriteTimestampUs,
    )> {
        let intent = narrow.intent();
        let authority = intent.authority();
        let key = AuthorityTimestampKey::new(
            intent.candidate().canonical_chain().network_id(),
            authority,
        );
        let AuthorityLocalHeadReadState::Current(expected_head) =
            self.local_head.read(key).await?
        else {
            anyhow::bail!("post-rollback Realm head is missing")
        };
        if expected_head.head().chain() != intent.predecessor().canonical_chain()
            || observation.authority() != authority
            || observation.chain() != intent.candidate().canonical_chain()
        {
            anyhow::bail!("post-rollback Realm commit identity mismatch")
        }

        let timestamp_store = ScyllaAuthorityTimestampStore::prepare(
            self.session.clone(),
            AuthorityTimestampNoTabletKeyspace::try_new(
                self.local_control_keyspace.as_str().to_owned(),
            )?,
        )
        .await?;
        let AuthorityTimestampReadState::Current(timestamp_state) =
            timestamp_store.read(key).await?
        else {
            anyhow::bail!("post-rollback Realm timestamp state is missing")
        };
        let reservation = timestamp_state.seal_reservation(
            key,
            intent.intent_digest().authority_intent(),
            clock_sample,
        )?;
        if reservation.lease().timestamp() != narrow.timestamp() {
            anyhow::bail!("post-rollback Realm writer did not use the allocated timestamp")
        }
        let _ = timestamp_store.reserve(reservation).await?;

        let writer = ScyllaBranchExactDualWriteAdapter::prepare(
            self.session.clone(),
            &self.branch_exact_ready,
        )
        .await?;
        writer
            .qualification_write_inventory_exact(intent, narrow.timestamp())
            .await?;

        let pipeline_store = ScyllaPendingPipelineStore::prepare(
            self.session.clone(),
            BranchExactDeploymentNoTabletKeyspace::try_new(
                self.local_control_keyspace.as_str().to_owned(),
            )?,
        )
        .await?;
        let pipeline_key = PendingGenerationLedgerKey::new(
            intent.candidate().canonical_chain().network_id(),
            authority,
        );
        let PendingPipelineReadState::Current(pipeline) =
            pipeline_store.read::<Hash>(pipeline_key).await?
        else {
            anyhow::bail!("post-rollback Realm pipeline is missing")
        };

        // This qualification seam exercises the real pipeline CAS sequence
        // around the narrow physical write.  The evidence is derived from the
        // exact immutable write intent, so retry selects the same candidates;
        // it is not a substitute for the production application archive or
        // writer/head authorization path.
        let evidence = |domain: &[u8]| -> [u8; 32] {
            let mut hasher = Sha256::new();
            hasher.update(b"psy.rollback.post-restore-realm-qualification.v1\0");
            hasher.update(domain);
            hasher.update(intent.intent_digest().as_bytes());
            hasher.finalize().into()
        };
        let close = PendingQueueCloseIntentDigest::try_new(evidence(b"close"))?;
        let capture = PendingWorkCaptureDigest::try_new(evidence(b"capture"))?;
        let processing = PendingPipelineIntentDigest::try_new(evidence(b"processing"))?;
        let publish = PendingPublishReceiptDigest::try_new(evidence(b"publish"))?;
        let sealing = pipeline.seal_begin_queue_close(close)?;
        let sealing = match pipeline_store.apply(&sealing).await? {
            PendingPipelineWriteOutcome::Applied(current)
            | PendingPipelineWriteOutcome::Idempotent(current)
                if current == *sealing.candidate() => current,
            other => anyhow::bail!("post-rollback Realm close conflict: {other:?}"),
        };
        let captured = sealing.seal_capture_work(close, capture)?;
        let captured = match pipeline_store.apply(&captured).await? {
            PendingPipelineWriteOutcome::Applied(current)
            | PendingPipelineWriteOutcome::Idempotent(current)
                if current == *captured.candidate() => current,
            other => anyhow::bail!("post-rollback Realm capture conflict: {other:?}"),
        };
        let inflight = captured.seal_begin_processing(capture, processing)?;
        let inflight = match pipeline_store.apply(&inflight).await? {
            PendingPipelineWriteOutcome::Applied(current)
            | PendingPipelineWriteOutcome::Idempotent(current)
                if current == *inflight.candidate() => current,
            other => anyhow::bail!("post-rollback Realm processing conflict: {other:?}"),
        };
        let published = inflight.seal_publish(processing, publish, observation)?;
        let pipeline = match pipeline_store.apply(&published).await? {
            PendingPipelineWriteOutcome::Applied(current)
            | PendingPipelineWriteOutcome::Idempotent(current)
                if current == *published.candidate() => current,
            other => anyhow::bail!("post-rollback Realm publish conflict: {other:?}"),
        };

        let head_outcome = self
            .local_head
            .qualification_compare_and_set_realm_advance(
            expected_head,
            observation,
            narrow.timestamp(),
            *intent.manifest_digest().as_bytes(),
        )
            .await?;
        let current_head = match head_outcome {
            AuthorityLocalHeadWriteOutcome::Applied(current)
            | AuthorityLocalHeadWriteOutcome::Idempotent(current)
                if current.head().chain() == observation.chain() => current,
            other => anyhow::bail!("post-rollback Realm head publish conflict: {other:?}"),
        };

        let inventory = super::realm_rollback_commit_inventory::RealmRollbackCommitInventory::qualification_from_narrow(
            intent.clone(),
            narrow.timestamp(),
        )?;
        self.local_inventory
            .qualification_persist_committed(inventory, &current_head, &pipeline)
            .await?;
        let completion = reservation
            .candidate()
            .seal_completion(key, reservation.lease())?;
        let _ = timestamp_store.complete(completion).await?;
        Ok((current_head, narrow.timestamp()))
    }

    /// Qualification-only generation rotation used to prove that a restored
    /// Realm can continue beyond its first new block. The production route
    /// still requires the application terminal/carryover owner; this helper
    /// only allocates the next append-only identity and applies the exact
    /// terminal pipeline CAS selected from storage.
    #[cfg(all(test, feature = "rf3-test-support"))]
    pub(crate) async fn qualification_rotate_post_rollback_generation<
        Hash: Q256BitHash,
    >(
        &self,
        network: NetworkId,
        authority: AuthorityScope,
        write_timestamp: psy_node_core::store::timestamp::CommitWriteTimestampUs,
    ) -> anyhow::Result<
        psy_node_core::store::pending_generation_identity::PendingGenerationContext,
    > {
        let pipeline_store = ScyllaPendingPipelineStore::prepare(
            self.session.clone(),
            BranchExactDeploymentNoTabletKeyspace::try_new(
                self.local_control_keyspace.as_str().to_owned(),
            )?,
        )
        .await?;
        let key = PendingGenerationLedgerKey::new(network, authority);
        let PendingPipelineReadState::Current(pipeline) =
            pipeline_store.read::<Hash>(key).await?
        else {
            anyhow::bail!("post-rollback Realm pipeline is missing before rotation")
        };
        let next_pending = psy_node_core::store::typed::UniquePendingId::try_new(
            pipeline
                .gathering()
                .pending_id()
                .get()
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("post-rollback pending id overflow"))?,
        )?;
        let prefix = pipeline.proc_namespace_prefix();
        let next_proc = prefix.derive_proc_id(next_pending);
        let allocation = super::SealedPendingCounterAllocation::try_for_commit(
            super::PendingCounterExpected::Present(pipeline.gathering().pending_id()),
            next_proc,
            write_timestamp,
        )?;
        let counter = PendingCounterAdapter::prepare(
            self.session.clone(),
            self.local_control_keyspace.clone(),
            self.local_state_keyspace.clone(),
        )
        .await?;
        match counter.allocate(&allocation).await? {
            super::PendingCounterAllocationOutcome::Owned(owned)
                if owned.pending() == next_pending && owned.proc_id() == next_proc => {}
            other => anyhow::bail!("post-rollback Realm rotation allocation conflict: {other:?}"),
        }
        let reserved =
            psy_node_core::store::pending_generation::ReservedPendingGeneration::qualification_from_prefix(
                next_pending.get(),
                prefix,
            )?;
        let rotation = pipeline.seal_rotation(reserved)?;
        let ready = match pipeline_store.apply(&rotation).await? {
            PendingPipelineWriteOutcome::Applied(current)
            | PendingPipelineWriteOutcome::Idempotent(current)
                if current == *rotation.candidate() => current,
            other => anyhow::bail!("post-rollback Realm rotation conflict: {other:?}"),
        };
        Ok(ready.processing())
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
                current.canonical_ref().network_id()
                    == selected.directive().target().network_id()
                    && current.canonical_ref().chain_epoch()
                        == selected.directive().target().chain_epoch()
                    && current.canonical_ref().checkpoint().checkpoint_id()
                        == selected.directive().target().checkpoint().checkpoint_id()
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
        let local_key = AuthorityTimestampKey::new(network, authority);
        let first_local = match self.local_head.read(local_key).await? {
            AuthorityLocalHeadReadState::Current(current) => current,
            AuthorityLocalHeadReadState::Uninitialized => return Ok(None),
        };
        let Some(directive) = self
            .runtime_rebuild
            .read_selected_directive_for_target(
                first_head,
                authority,
                *first_local.head().chain(),
            )
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
        let AuthorityLocalHeadReadState::Current(second_local) =
            self.local_head.read(local_key).await?
        else {
            anyhow::bail!("Realm local head disappeared while selecting runtime rebuild")
        };
        if second_local != first_local {
            anyhow::bail!("Realm local head changed while selecting runtime rebuild")
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
        let file = include_str!("realm_rollback_runtime_control.rs")
            .rsplit_once("\n#[cfg(test)]\nmod tests")
            .map(|(production, _)| production)
            .unwrap();
        // Qualification-only fixtures above `prepare_delete_executor` are
        // compiled only for tests and deliberately exercise the underlying
        // stores.  This guard covers the production runtime-control route.
        let source = file
            .split("    async fn prepare_delete_executor")
            .nth(1)
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
            .find(".read_selected_directive_for_target(")
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
