//! Production-shaped two-stage Coordinator commit orchestration.
//!
//! This is intentionally a thin composition of the existing exact writer,
//! typed-row executor, manifest, completion, and canonical-head stores. It
//! adds no new durable record and exposes none of their private receipts.

use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleHasher},
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::store::{
    authority_commit::AuthorityClockSampleUs,
    branch_exact_dual_write::BranchExactDualWriteIntent,
    branch_pending_mapping::BranchPendingMapping,
    canonical_head::{
        CanonicalHeadReadState, SealedCanonicalHeadCas, StoredCanonicalHead,
    },
    coordinator_commit_source::{
        CoordinatorCheckpointBackupEvidence, CoordinatorCommitSource,
    },
    coordinator_processor_full_commit::{
        CoordinatorProcessorFullCommitError, CoordinatorProcessorFullCommitStore,
    },
    timestamp::{DeleteFenceTimestampUs, NewBranchWriteTimestampUs},
    typed::{ProcCheckpointUniqueId, UniquePendingId},
};
use scylla::{client::session::Session, statement::Consistency};

use super::{
    BranchExactDeploymentNoTabletKeyspace, BranchExactSchemaReady,
    BranchExactWriterAuthorityKey, BranchExactWriterReadState,
    BranchExactWriterRuntimeRequest, BranchExactWriterState, CqlKeyspaceName,
    ScyllaBranchExactWriterLifecycleStore, ScyllaBranchExactWriterRuntime,
    ScyllaCanonicalHeadStore, ScyllaCoordinatorCommitSourceStore,
    coordinator_commit_physical_execution::CoordinatorCommitPhysicalExecutionSchedule,
    coordinator_commit_physical_scylla::CoordinatorCommitPhysicalScyllaExecutor,
    coordinator_commit_physical_write_plan::CoordinatorCommitPhysicalWritePlan,
};

pub(crate) struct ScyllaCoordinatorProcessorFullCommitStore<F, Hash, Hasher> {
    session: Arc<Session>,
    sources: Arc<ScyllaCoordinatorCommitSourceStore>,
    heads: Arc<ScyllaCanonicalHeadStore>,
    writer: ScyllaBranchExactWriterRuntime<Hash>,
    executor: CoordinatorCommitPhysicalScyllaExecutor,
    genesis_checkpoint_state_transition_hash: Hash,
    checkpoint_state_transition_circuit_fingerprint: Hash,
    checkpoint_tree_height: u8,
    _field: PhantomData<F>,
    _hasher: PhantomData<Hasher>,
}

impl<F, Hash, Hasher> ScyllaCoordinatorProcessorFullCommitStore<F, Hash, Hasher>
where
    F: QFelt64,
    Hash: Q256BitHash + QFHashBase<F>,
    Hasher: MerkleHasher<Hash> + FieldQHasher<F, Hash>,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn prepare(
        session: Arc<Session>,
        standard_keyspace: &str,
        no_tablet_keyspace: &str,
        network: NetworkId,
        ready: &BranchExactSchemaReady,
        sources: Arc<ScyllaCoordinatorCommitSourceStore>,
        heads: Arc<ScyllaCanonicalHeadStore>,
        genesis_checkpoint_state_transition_hash: Hash,
        checkpoint_state_transition_circuit_fingerprint: Hash,
        checkpoint_tree_height: u8,
    ) -> Result<Self, CoordinatorProcessorFullCommitError> {
        if ready.view().authority() != AuthorityScope::Coordinator
            || checkpoint_tree_height == 0
        {
            return Err(CoordinatorProcessorFullCommitError::IdentityMismatch);
        }
        let control = BranchExactDeploymentNoTabletKeyspace::try_new(
            no_tablet_keyspace.to_owned(),
        )
        .map_err(backend)?;
        let lifecycle = ScyllaBranchExactWriterLifecycleStore::prepare(
            session.clone(),
            control,
        )
        .await
        .map_err(backend)?;
        let key = BranchExactWriterAuthorityKey::new(
            network,
            AuthorityScope::Coordinator,
        );
        let BranchExactWriterReadState::Current(initial) = lifecycle
            .read::<Hash>(key)
            .await
            .map_err(backend)?
        else {
            return Err(CoordinatorProcessorFullCommitError::AwaitingVerifiedWrites);
        };
        let writer = ScyllaBranchExactWriterRuntime::prepare_from_ready(
            session.clone(),
            no_tablet_keyspace,
            BranchExactWriterRuntimeRequest::new(
                network,
                AuthorityScope::Coordinator,
                initial.plan().digest(),
            ),
            ready,
        )
        .await
        .map_err(backend)?;
        let executor = CoordinatorCommitPhysicalScyllaExecutor::prepare_with_consistency(
            &session,
            CqlKeyspaceName::try_new(standard_keyspace.to_owned()).map_err(backend)?,
            Consistency::Quorum,
        )
        .await
        .map_err(backend)?;
        Ok(Self {
            session,
            sources,
            heads,
            writer,
            executor,
            genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint,
            checkpoint_tree_height,
            _field: PhantomData,
            _hasher: PhantomData,
        })
    }

    fn plan(
        &self,
        source: &CoordinatorCommitSource<Hash>,
        prepared: &super::BranchExactWriterPrepared<Hash>,
        post_rollback_fence: Option<DeleteFenceTimestampUs>,
    ) -> Result<CoordinatorCommitPhysicalWritePlan<Hash>, CoordinatorProcessorFullCommitError> {
        match post_rollback_fence {
            Some(fence) => {
                let timestamp = NewBranchWriteTimestampUs::try_after(
                    fence,
                    i128::from(prepared.timestamp().as_i64()),
                )
                .map_err(backend)?;
                CoordinatorCommitPhysicalWritePlan::try_new_after_rollback::<F, Hasher>(
                    source,
                    prepared,
                    timestamp,
                    self.genesis_checkpoint_state_transition_hash,
                    self.checkpoint_state_transition_circuit_fingerprint,
                    self.checkpoint_tree_height,
                )
                .map_err(backend)
            }
            None => CoordinatorCommitPhysicalWritePlan::try_new::<F, Hasher>(
                source,
                prepared,
                self.genesis_checkpoint_state_transition_hash,
                self.checkpoint_state_transition_circuit_fingerprint,
                self.checkpoint_tree_height,
            )
            .map_err(backend),
        }
    }

    async fn exact_intent(
        &self,
        source: &CoordinatorCommitSource<Hash>,
        pending: UniquePendingId,
        proc_id: ProcCheckpointUniqueId,
    ) -> Result<BranchExactDualWriteIntent<Hash>, CoordinatorProcessorFullCommitError> {
        let current = self.writer.read_writer().await.map_err(backend)?;
        let predecessor = match current.state() {
            BranchExactWriterState::Active(active) => *active.watermark(),
            BranchExactWriterState::WritePrepared(prepared) => {
                *prepared.intent().predecessor()
            }
            BranchExactWriterState::WritesVerified(verified) => {
                *verified.prepared().intent().predecessor()
            }
            _ => return Err(CoordinatorProcessorFullCommitError::AwaitingVerifiedWrites),
        };
        let candidate = BranchPendingMapping::new(*source.candidate(), pending);
        BranchExactDualWriteIntent::try_coordinator(predecessor, candidate, proc_id)
            .map_err(backend)
    }

    async fn already_published(
        &self,
        source: &CoordinatorCommitSource<Hash>,
        sealed: &SealedCanonicalHeadCas<Hash>,
    ) -> Result<Option<StoredCanonicalHead<Hash>>, CoordinatorProcessorFullCommitError> {
        let CanonicalHeadReadState::Current(current) = self
            .heads
            .read(source.candidate().network_id())
            .await
            .map_err(backend)?
        else {
            return Ok(None);
        };
        if current != *sealed.candidate() {
            return Ok(None);
        }
        let persisted = self
            .sources
            .read_source(source.candidate())
            .await
            .map_err(backend)?
            .ok_or(CoordinatorProcessorFullCommitError::IdentityMismatch)?;
        let committed = self
            .sources
            .read_committed(source.candidate())
            .await
            .map_err(backend)?
            .ok_or(CoordinatorProcessorFullCommitError::IdentityMismatch)?;
        let writer = self.writer.read_writer().await.map_err(backend)?;
        let BranchExactWriterState::Active(active) = writer.state() else {
            return Ok(None);
        };
        if persisted != *source
            || !committed.matches(source)
            || active.watermark().canonical_chain() != source.candidate()
        {
            return Err(CoordinatorProcessorFullCommitError::IdentityMismatch);
        }
        Ok(Some(current))
    }
}

#[async_trait]
impl<F, Hash, Hasher> CoordinatorProcessorFullCommitStore<Hash>
    for ScyllaCoordinatorProcessorFullCommitStore<F, Hash, Hasher>
where
    F: QFelt64 + Send + Sync + 'static,
    Hash: Q256BitHash + QFHashBase<F> + Send + Sync + 'static,
    Hasher: MerkleHasher<Hash> + FieldQHasher<F, Hash> + Send + Sync + 'static,
{
    async fn persist_full_write(
        &self,
        source: &CoordinatorCommitSource<Hash>,
        pending: UniquePendingId,
        proc_id: ProcCheckpointUniqueId,
        clock: AuthorityClockSampleUs,
        post_rollback_fence: Option<DeleteFenceTimestampUs>,
    ) -> Result<(), CoordinatorProcessorFullCommitError> {
        self.sources
            .persist_and_readback(source)
            .await
            .map_err(backend)?;
        let intent = self.exact_intent(source, pending, proc_id).await?;
        let barrier = self
            .writer
            .prepare_and_verify(intent, clock)
            .await
            .map_err(backend)?;
        self.writer
            .require_fresh_barrier(&barrier)
            .await
            .map_err(backend)?;
        let current = self.writer.read_writer().await.map_err(backend)?;
        let BranchExactWriterState::WritesVerified(verified) = current.state() else {
            return Err(CoordinatorProcessorFullCommitError::AwaitingVerifiedWrites);
        };
        let plan = self.plan(source, verified.prepared(), post_rollback_fence)?;
        let schedule = CoordinatorCommitPhysicalExecutionSchedule::try_from_plan(
            &plan,
            verified.prepared(),
        )
        .map_err(backend)?;
        let observation = self
            .executor
            .write_and_verify_full(
                &self.session,
                source,
                &schedule,
                verified,
            )
            .await
            .map_err(backend)?;
        self.sources
            .full_manifests()
            .persist_from_fresh_sources(
                &self.sources,
                &self.writer,
                &self.executor,
                source,
                &schedule,
                observation,
            )
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn publish_after_backup(
        &self,
        source: &CoordinatorCommitSource<Hash>,
        backup: CoordinatorCheckpointBackupEvidence<Hash>,
        sealed: &SealedCanonicalHeadCas<Hash>,
        post_rollback_fence: Option<DeleteFenceTimestampUs>,
    ) -> Result<StoredCanonicalHead<Hash>, CoordinatorProcessorFullCommitError> {
        if let Some(current) = self.already_published(source, sealed).await? {
            return Ok(current);
        }
        let current = self.writer.read_writer().await.map_err(backend)?;
        let BranchExactWriterState::WritesVerified(verified) = current.state() else {
            return Err(CoordinatorProcessorFullCommitError::AwaitingVerifiedWrites);
        };
        let plan = self.plan(source, verified.prepared(), post_rollback_fence)?;
        let schedule = CoordinatorCommitPhysicalExecutionSchedule::try_from_plan(
            &plan,
            verified.prepared(),
        )
        .map_err(backend)?;
        let manifest = self
            .sources
            .full_manifests()
            .read_for_fresh_sources(
                &self.sources,
                &self.writer,
                &self.executor,
                source,
                &schedule,
            )
            .await
            .map_err(backend)?;
        let completion = self
            .sources
            .full_completions()
            .persist_after_exact_backup(
                self.sources.full_manifests(),
                &self.sources,
                &self.writer,
                &self.executor,
                source,
                &schedule,
                &manifest,
                &backup,
            )
            .await
            .map_err(backend)?;
        let published = self
            .sources
            .mark_committed_and_publish_head_after_full_completion(
                &self.heads,
                source,
                &completion,
                sealed,
            )
            .await
            .map_err(backend)?;
        self.writer
            .finish_verified_after_published(source.candidate())
            .await
            .map_err(backend)?;
        Ok(published)
    }
}

fn backend(error: impl std::fmt::Display) -> CoordinatorProcessorFullCommitError {
    CoordinatorProcessorFullCommitError::Backend(error.to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn composition_keeps_backup_between_full_write_and_head_publish() {
        let source = include_str!("coordinator_processor_full_commit.rs");
        let persist = source
            .split("async fn persist_full_write")
            .nth(1)
            .unwrap()
            .split("async fn publish_after_backup")
            .next()
            .unwrap();
        assert!(persist.contains("persist_and_readback(source)"));
        assert!(persist.contains("write_and_verify_full"));
        assert!(persist.contains("persist_from_fresh_sources"));
        assert!(!persist.contains("mark_committed"));
        assert!(!persist.contains("compare_and_set"));

        let publish = source
            .split("async fn publish_after_backup")
            .nth(1)
            .unwrap()
            .split("fn backend")
            .next()
            .unwrap();
        let completion = publish.find("persist_after_exact_backup").unwrap();
        let head = publish
            .find("mark_committed_and_publish_head_after_full_completion")
            .unwrap();
        let finish = publish.find("finish_verified_after_published").unwrap();
        assert!(completion < head && head < finish);
    }
}
