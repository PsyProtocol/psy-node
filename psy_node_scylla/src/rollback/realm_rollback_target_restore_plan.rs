//! Immutable, deterministic control-state restore plan for one Realm.
//!
//! The hot business suffix has already been archived, verified, and deleted
//! when this plan is formed.  The plan freezes every mutable predecessor and
//! the next two pending/proc identities before the counter or any serving
//! control row can move.  It is data only: persistence and exact readback are
//! required before a later storage-private executor may use it.

#![allow(dead_code)]

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::{CanonicalChainRef, ChainEpoch, NetworkId, CANONICAL_CHAIN_REF_V1_LEN},
    chain_context::{AuthorityObservation, AuthorityScope},
};
use psy_node_core::store::{
    authority_commit::{
        AuthorityCommitIntentDigest, AuthorityTimestampKey, AuthorityTimestampPhase,
        ObservedAuthorityTimestampState, StoredAuthorityTimestampState,
    },
    authority_local_head::StoredAuthorityLocalHead,
    branch_pending_mapping::BranchPendingMapping,
    pending_generation::ProcNamespacePrefix,
    pending_generation_identity::{PendingGenerationContext, PendingGenerationLedgerKey},
    pending_generation_pipeline::{PendingProcessingPhase, StoredPendingPipeline},
    timestamp::{
        CommitWriteTimestampUs, DeleteFenceTimestampUs, NewBranchWriteTimestampUs,
    },
    typed::UniquePendingId,
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactWriterAuthorityKey, BranchExactWriterState, PendingCounterExpected,
    PendingCounterReadState, SealedPendingCounterAllocation,
    StoredBranchExactWriterLifecycle, TimestampedWriteKind,
};
use super::realm_rollback_commit_inventory_store::VerifiedRealmRollbackTarget;
use super::rollback_global_delete_barrier::SelectedRealmRollbackDeleteCompletion;

pub(super) const REALM_TARGET_RESTORE_PLAN_KEY_DOMAIN: i16 = -8;
const MAGIC: &[u8; 8] = b"PSYRTRP1";
const VERSION: u16 = 1;
const MAX_BYTES: usize = 128 * 1024;
const SLOT_DOMAIN: &[u8] = b"psy.rollback.realm-target-restore-plan-slot.v1\0";
const DIGEST_DOMAIN: &[u8] = b"psy.rollback.realm-target-restore-plan.v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RealmRollbackTargetRestorePlan<Hash> {
    authority: AuthorityScope,
    global_target: CanonicalChainRef<Hash>,
    target: CanonicalChainRef<Hash>,
    rollback_epoch: ChainEpoch,
    participant_plan_digest: [u8; 32],
    global_delete_barrier_slot: [u8; 32],
    global_delete_barrier_digest: [u8; 32],
    realm_delete_completion_slot: [u8; 32],
    realm_delete_completion_digest: [u8; 32],
    target_inventory_slot: [u8; 32],
    target_inventory_digest: [u8; 32],
    target_committed_marker_digest: [u8; 32],
    target_writer_revision: u64,
    target_head: StoredAuthorityLocalHead<Hash>,
    target_pipeline: StoredPendingPipeline<Hash>,
    source_head: StoredAuthorityLocalHead<Hash>,
    source_pipeline: StoredPendingPipeline<Hash>,
    source_writer: StoredBranchExactWriterLifecycle<Hash>,
    source_timestamp: StoredAuthorityTimestampState,
    counter_expected: UniquePendingId,
    processing: PendingGenerationContext,
    gathering: PendingGenerationContext,
    processing_allocation_digest: [u8; 32],
    gathering_allocation_digest: [u8; 32],
    delete_fence: DeleteFenceTimestampUs,
    new_branch_write: NewBranchWriteTimestampUs,
    archive_store_fingerprint: [u8; 32],
    slot: [u8; 32],
    digest: [u8; 32],
    canonical_bytes: Vec<u8>,
}

impl<Hash: Q256BitHash> RealmRollbackTargetRestorePlan<Hash> {
    pub(super) fn slot_for_selected(
        selected: &SelectedRealmRollbackDeleteCompletion<Hash>,
        archive_store_fingerprint: [u8; 32],
    ) -> [u8; 32] {
        restore_plan_slot(
            selected.barrier().target().network_id(),
            selected.completion().authority(),
            selected.barrier().target().chain_epoch().get(),
            selected.barrier().participant_plan_digest(),
            selected.barrier().slot(),
            selected.barrier().digest(),
            &archive_store_fingerprint,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn try_from_selected(
        selected: &SelectedRealmRollbackDeleteCompletion<Hash>,
        target: &VerifiedRealmRollbackTarget<Hash>,
        source_head: StoredAuthorityLocalHead<Hash>,
        source_pipeline: StoredPendingPipeline<Hash>,
        source_writer: StoredBranchExactWriterLifecycle<Hash>,
        source_timestamp: ObservedAuthorityTimestampState,
        counter: PendingCounterReadState,
        archive_store_fingerprint: [u8; 32],
    ) -> Result<Self, RealmRollbackTargetRestorePlanError> {
        let authority = selected.completion().authority();
        let target_head = target.stored_head().map_err(model)?;
        let target_pipeline = target.stored_pipeline().map_err(model)?;
        let PendingCounterReadState::Current(counter_expected) = counter else {
            return Err(RealmRollbackTargetRestorePlanError::CounterUninitialized);
        };
        let prefix = ProcNamespacePrefix::for_authority(
            selected.barrier().target().network_id(),
            authority,
        );
        let processing_pending = next_pending(counter_expected)?;
        let gathering_pending = next_pending(processing_pending)?;
        let processing = context(prefix, processing_pending)?;
        let gathering = context(prefix, gathering_pending)?;
        let processing_allocation = SealedPendingCounterAllocation::try_for_rollback(
            PendingCounterExpected::Present(counter_expected),
            processing.proc_checkpoint_id(),
            selected.new_branch_write(),
        ).map_err(model)?;
        let gathering_allocation = SealedPendingCounterAllocation::try_for_rollback(
            PendingCounterExpected::Present(processing_pending),
            gathering.proc_checkpoint_id(),
            selected.new_branch_write(),
        ).map_err(model)?;
        Self::try_from_fields(
            authority,
            *selected.barrier().target(),
            *target.chain(),
            ChainEpoch::new(selected.barrier().deleting_head().canonical_ref().chain_epoch().get()),
            *selected.barrier().participant_plan_digest(),
            *selected.barrier().slot(),
            *selected.barrier().digest(),
            *selected.completion().slot(),
            *selected.completion().digest(),
            target.evidence_slot(),
            *target.evidence_digest(),
            *target.marker_digest(),
            target.writer_revision(),
            target_head,
            target_pipeline,
            source_head,
            source_pipeline,
            source_writer,
            source_timestamp.state(),
            counter_expected,
            processing,
            gathering,
            *processing_allocation.digest().as_bytes(),
            *gathering_allocation.digest().as_bytes(),
            selected.new_branch_write().delete_fence(),
            selected.new_branch_write(),
            archive_store_fingerprint,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_from_fields(
        authority: AuthorityScope,
        global_target: CanonicalChainRef<Hash>,
        target: CanonicalChainRef<Hash>,
        rollback_epoch: ChainEpoch,
        participant_plan_digest: [u8; 32],
        global_delete_barrier_slot: [u8; 32],
        global_delete_barrier_digest: [u8; 32],
        realm_delete_completion_slot: [u8; 32],
        realm_delete_completion_digest: [u8; 32],
        target_inventory_slot: [u8; 32],
        target_inventory_digest: [u8; 32],
        target_committed_marker_digest: [u8; 32],
        target_writer_revision: u64,
        target_head: StoredAuthorityLocalHead<Hash>,
        target_pipeline: StoredPendingPipeline<Hash>,
        source_head: StoredAuthorityLocalHead<Hash>,
        source_pipeline: StoredPendingPipeline<Hash>,
        source_writer: StoredBranchExactWriterLifecycle<Hash>,
        source_timestamp: StoredAuthorityTimestampState,
        counter_expected: UniquePendingId,
        processing: PendingGenerationContext,
        gathering: PendingGenerationContext,
        processing_allocation_digest: [u8; 32],
        gathering_allocation_digest: [u8; 32],
        delete_fence: DeleteFenceTimestampUs,
        new_branch_write: NewBranchWriteTimestampUs,
        archive_store_fingerprint: [u8; 32],
    ) -> Result<Self, RealmRollbackTargetRestorePlanError> {
        let AuthorityScope::Realm { .. } = authority else {
            return Err(RealmRollbackTargetRestorePlanError::RealmRequired);
        };
        if [
            participant_plan_digest,
            global_delete_barrier_slot,
            global_delete_barrier_digest,
            realm_delete_completion_slot,
            realm_delete_completion_digest,
            target_inventory_slot,
            target_inventory_digest,
            target_committed_marker_digest,
            processing_allocation_digest,
            gathering_allocation_digest,
            archive_store_fingerprint,
        ].contains(&[0; 32]) {
            return Err(RealmRollbackTargetRestorePlanError::BindingMismatch);
        }
        let network = global_target.network_id();
        let key = AuthorityTimestampKey::new(network, authority);
        let pipeline_key = PendingGenerationLedgerKey::new(network, authority);
        let writer_key = BranchExactWriterAuthorityKey::new(network, authority);
        let target_epoch = global_target.chain_epoch().get();
        let target_checkpoint = global_target.checkpoint().checkpoint_id().get();
        let source_chain = source_head.head().chain();
        let source_checkpoint = source_chain.checkpoint().checkpoint_id().get();
        let expected_rollback_epoch = target_epoch.checked_add(1)
            .ok_or(RealmRollbackTargetRestorePlanError::EpochOverflow)?;
        let BranchExactWriterState::Active(active) = source_writer.state() else {
            return Err(RealmRollbackTargetRestorePlanError::WriterNotActive);
        };
        if rollback_epoch.get() != expected_rollback_epoch
            || target.network_id() != network
            || target.chain_epoch().get() != target_epoch
            || target.checkpoint().checkpoint_id().get() != target_checkpoint
            || target_head.head().key() != key
            || target_head.head().chain() != &target
            || target_pipeline.key() != pipeline_key
            || target_pipeline.frontier().chain() != target_head.head().chain()
            || !valid_target_pipeline(target_checkpoint, &target_pipeline)
            || source_head.head().key() != key
            || source_chain.chain_epoch().get() != target_epoch
            || source_checkpoint <= target_checkpoint
            || source_pipeline.key() != pipeline_key
            || source_pipeline.frontier().chain() != source_chain
            || !matches!(
                source_pipeline.phase(),
                PendingProcessingPhase::Published | PendingProcessingPhase::RetiredNoWork
            )
            || BranchExactWriterAuthorityKey::from_plan(source_writer.plan()) != writer_key
            || active.watermark().canonical_chain() != source_chain
            || active.watermark().pending_id() != source_pipeline.processing().pending_id()
            || active.timestamp_state() != source_timestamp
            || !matches!(source_timestamp.phase(), AuthorityTimestampPhase::Idle { .. })
            || source_timestamp.high_water().as_i64()
                >= new_branch_write.as_commit_timestamp().as_i64()
            || source_head.commit_write_timestamp().as_i64()
                >= new_branch_write.as_commit_timestamp().as_i64()
            || new_branch_write.delete_fence() != delete_fence
            || counter_expected.get() < source_pipeline.gathering().pending_id().get()
            || processing.pending_id().get() != counter_expected.get().checked_add(1)
                .ok_or(RealmRollbackTargetRestorePlanError::CounterOverflow)?
            || gathering.pending_id().get() != processing.pending_id().get().checked_add(1)
                .ok_or(RealmRollbackTargetRestorePlanError::CounterOverflow)?
        {
            return Err(RealmRollbackTargetRestorePlanError::BindingMismatch);
        }
        let prefix = ProcNamespacePrefix::for_authority(network, authority);
        if processing.proc_checkpoint_id() != prefix.derive_proc_id(processing.pending_id())
            || gathering.proc_checkpoint_id() != prefix.derive_proc_id(gathering.pending_id())
        {
            return Err(RealmRollbackTargetRestorePlanError::ProcNamespaceMismatch);
        }
        let expected_processing = SealedPendingCounterAllocation::try_for_rollback(
            PendingCounterExpected::Present(counter_expected),
            processing.proc_checkpoint_id(),
            new_branch_write,
        ).map_err(model)?;
        let expected_gathering = SealedPendingCounterAllocation::try_for_rollback(
            PendingCounterExpected::Present(processing.pending_id()),
            gathering.proc_checkpoint_id(),
            new_branch_write,
        ).map_err(model)?;
        if expected_processing.candidate() != processing.pending_id()
            || expected_gathering.candidate() != gathering.pending_id()
            || expected_processing.write_kind() != TimestampedWriteKind::NewBranchAfterFence
            || expected_gathering.write_kind() != TimestampedWriteKind::NewBranchAfterFence
            || expected_processing.digest().as_bytes() != &processing_allocation_digest
            || expected_gathering.digest().as_bytes() != &gathering_allocation_digest
        {
            return Err(RealmRollbackTargetRestorePlanError::AllocationMismatch);
        }
        let slot = restore_plan_slot(network, authority, target_epoch,
            &participant_plan_digest, &global_delete_barrier_slot,
            &global_delete_barrier_digest, &archive_store_fingerprint);
        let mut plan = Self {
            authority,
            global_target,
            target,
            rollback_epoch,
            participant_plan_digest,
            global_delete_barrier_slot,
            global_delete_barrier_digest,
            realm_delete_completion_slot,
            realm_delete_completion_digest,
            target_inventory_slot,
            target_inventory_digest,
            target_committed_marker_digest,
            target_writer_revision,
            target_head,
            target_pipeline,
            source_head,
            source_pipeline,
            source_writer,
            source_timestamp,
            counter_expected,
            processing,
            gathering,
            processing_allocation_digest,
            gathering_allocation_digest,
            delete_fence,
            new_branch_write,
            archive_store_fingerprint,
            slot,
            digest: [0; 32],
            canonical_bytes: Vec::new(),
        };
        let body = plan.encode_body()?;
        plan.digest = plan_digest(&body);
        plan.canonical_bytes = body;
        plan.canonical_bytes.extend_from_slice(&plan.digest);
        if plan.canonical_bytes.len() > MAX_BYTES {
            return Err(RealmRollbackTargetRestorePlanError::RowTooLarge);
        }
        Ok(plan)
    }

    pub(super) fn decode_canonical(bytes: &[u8]) -> Result<Self, RealmRollbackTargetRestorePlanError> {
        if bytes.len() < 32 || bytes.len() > MAX_BYTES {
            return Err(RealmRollbackTargetRestorePlanError::MalformedRow);
        }
        let body_len = bytes.len() - 32;
        if plan_digest(&bytes[..body_len]) != bytes[body_len..] {
            return Err(RealmRollbackTargetRestorePlanError::DigestMismatch);
        }
        let mut cursor = Cursor::new(&bytes[..body_len]);
        if cursor.take(8)? != MAGIC { return Err(RealmRollbackTargetRestorePlanError::InvalidMagic); }
        let version = cursor.u16()?;
        if version != VERSION { return Err(RealmRollbackTargetRestorePlanError::UnknownVersion(version)); }
        let network = NetworkId::try_from_chain_id(cursor.u32()?).map_err(model)?;
        let authority = decode_authority(cursor.take(7)?)?;
        let global_target = CanonicalChainRef::from_canonical_bytes(cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?).map_err(model)?;
        let target = CanonicalChainRef::from_canonical_bytes(cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?).map_err(model)?;
        if global_target.network_id() != network { return Err(RealmRollbackTargetRestorePlanError::BindingMismatch); }
        let rollback_epoch = ChainEpoch::new(cursor.u64()?);
        let participant_plan_digest = cursor.array32()?;
        let global_delete_barrier_slot = cursor.array32()?;
        let global_delete_barrier_digest = cursor.array32()?;
        let realm_delete_completion_slot = cursor.array32()?;
        let realm_delete_completion_digest = cursor.array32()?;
        let target_inventory_slot = cursor.array32()?;
        let target_inventory_digest = cursor.array32()?;
        let target_committed_marker_digest = cursor.array32()?;
        let target_writer_revision = cursor.u64()?;
        let key = AuthorityTimestampKey::new(network, authority);
        let pipeline_key = PendingGenerationLedgerKey::new(network, authority);
        let target_head = StoredAuthorityLocalHead::decode_persisted(key, cursor.i64()?, cursor.bytes()?).map_err(model)?;
        let target_pipeline = StoredPendingPipeline::decode_persisted(pipeline_key, cursor.i64()?, cursor.bytes()?).map_err(model)?;
        let source_head = StoredAuthorityLocalHead::decode_persisted(key, cursor.i64()?, cursor.bytes()?).map_err(model)?;
        let source_pipeline = StoredPendingPipeline::decode_persisted(pipeline_key, cursor.i64()?, cursor.bytes()?).map_err(model)?;
        let writer_slot = cursor.array32()?;
        let source_writer = StoredBranchExactWriterLifecycle::decode_persisted(&writer_slot, cursor.i64()?, cursor.bytes()?).map_err(model)?;
        let source_timestamp = StoredAuthorityTimestampState::decode_persisted(cursor.i64()?, cursor.bytes()?).map_err(model)?;
        let counter_expected = unique_pending(cursor.u64()?)?;
        let processing = PendingGenerationContext::try_from_legacy(cursor.u64()?, cursor.u128()?).map_err(model)?;
        let gathering = PendingGenerationContext::try_from_legacy(cursor.u64()?, cursor.u128()?).map_err(model)?;
        let processing_allocation_digest = cursor.array32()?;
        let gathering_allocation_digest = cursor.array32()?;
        let orphan_max = CommitWriteTimestampUs::try_from_i128(i128::from(cursor.i64()?)).map_err(model)?;
        let delete_fence = DeleteFenceTimestampUs::try_after(orphan_max, i128::from(cursor.i64()?)).map_err(model)?;
        let new_branch_write = NewBranchWriteTimestampUs::try_after(delete_fence, i128::from(cursor.i64()?)).map_err(model)?;
        let archive_store_fingerprint = cursor.array32()?;
        let slot = cursor.array32()?;
        if !cursor.is_empty() { return Err(RealmRollbackTargetRestorePlanError::TrailingBytes); }
        let decoded = Self::try_from_fields(
            authority, global_target, target, rollback_epoch, participant_plan_digest,
            global_delete_barrier_slot, global_delete_barrier_digest,
            realm_delete_completion_slot, realm_delete_completion_digest,
            target_inventory_slot, target_inventory_digest,
            target_committed_marker_digest, target_writer_revision,
            target_head, target_pipeline, source_head, source_pipeline, source_writer,
            source_timestamp, counter_expected, processing, gathering,
            processing_allocation_digest, gathering_allocation_digest,
            delete_fence, new_branch_write, archive_store_fingerprint,
        )?;
        if decoded.slot != slot || decoded.canonical_bytes != bytes {
            return Err(RealmRollbackTargetRestorePlanError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }

    fn encode_body(&self) -> Result<Vec<u8>, RealmRollbackTargetRestorePlanError> {
        let mut out = Vec::with_capacity(4096);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&self.target.network_id().chain_id().to_be_bytes());
        out.extend_from_slice(&encode_authority(self.authority));
        out.extend_from_slice(&self.global_target.to_canonical_bytes());
        out.extend_from_slice(&self.target.to_canonical_bytes());
        out.extend_from_slice(&self.rollback_epoch.get().to_be_bytes());
        out.extend_from_slice(&self.participant_plan_digest);
        out.extend_from_slice(&self.global_delete_barrier_slot);
        out.extend_from_slice(&self.global_delete_barrier_digest);
        out.extend_from_slice(&self.realm_delete_completion_slot);
        out.extend_from_slice(&self.realm_delete_completion_digest);
        out.extend_from_slice(&self.target_inventory_slot);
        out.extend_from_slice(&self.target_inventory_digest);
        out.extend_from_slice(&self.target_committed_marker_digest);
        out.extend_from_slice(&self.target_writer_revision.to_be_bytes());
        push_state(&mut out, self.target_head.revision().as_i64(), &self.target_head.encode_canonical())?;
        push_state(&mut out, self.target_pipeline.revision().as_i64(), &self.target_pipeline.canonical_payload())?;
        push_state(&mut out, self.source_head.revision().as_i64(), &self.source_head.encode_canonical())?;
        push_state(&mut out, self.source_pipeline.revision().as_i64(), &self.source_pipeline.canonical_payload())?;
        out.extend_from_slice(self.source_writer.slot().as_bytes());
        push_state(&mut out, self.source_writer.revision().as_i64(), &self.source_writer.to_canonical_bytes())?;
        push_state(&mut out, self.source_timestamp.revision().as_i64(), &self.source_timestamp.encode_canonical())?;
        out.extend_from_slice(&self.counter_expected.get().to_be_bytes());
        push_context(&mut out, self.processing);
        push_context(&mut out, self.gathering);
        out.extend_from_slice(&self.processing_allocation_digest);
        out.extend_from_slice(&self.gathering_allocation_digest);
        out.extend_from_slice(&self.delete_fence.orphan_write_max().as_i64().to_be_bytes());
        out.extend_from_slice(&self.delete_fence.as_i64().to_be_bytes());
        out.extend_from_slice(&self.new_branch_write.as_commit_timestamp().as_i64().to_be_bytes());
        out.extend_from_slice(&self.archive_store_fingerprint);
        out.extend_from_slice(&self.slot);
        Ok(out)
    }

    pub(super) const fn authority(&self) -> AuthorityScope { self.authority }
    pub(super) const fn global_target(&self) -> &CanonicalChainRef<Hash> { &self.global_target }
    pub(super) const fn target(&self) -> &CanonicalChainRef<Hash> { &self.target }
    pub(super) const fn rollback_epoch(&self) -> ChainEpoch { self.rollback_epoch }
    pub(super) const fn participant_plan_digest(&self) -> &[u8; 32] { &self.participant_plan_digest }
    pub(super) const fn global_delete_barrier_slot(&self) -> &[u8; 32] { &self.global_delete_barrier_slot }
    pub(super) const fn global_delete_barrier_digest(&self) -> &[u8; 32] { &self.global_delete_barrier_digest }
    pub(super) const fn realm_delete_completion_slot(&self) -> &[u8; 32] { &self.realm_delete_completion_slot }
    pub(super) const fn realm_delete_completion_digest(&self) -> &[u8; 32] { &self.realm_delete_completion_digest }
    pub(super) const fn target_inventory_slot(&self) -> &[u8; 32] { &self.target_inventory_slot }
    pub(super) const fn target_inventory_digest(&self) -> &[u8; 32] { &self.target_inventory_digest }
    pub(super) const fn target_committed_marker_digest(&self) -> &[u8; 32] { &self.target_committed_marker_digest }
    pub(super) const fn target_writer_revision(&self) -> u64 { self.target_writer_revision }
    pub(super) const fn target_head(&self) -> &StoredAuthorityLocalHead<Hash> { &self.target_head }
    pub(super) const fn target_pipeline(&self) -> &StoredPendingPipeline<Hash> { &self.target_pipeline }
    pub(super) const fn source_head(&self) -> &StoredAuthorityLocalHead<Hash> { &self.source_head }
    pub(super) const fn source_pipeline(&self) -> &StoredPendingPipeline<Hash> { &self.source_pipeline }
    pub(super) const fn source_writer(&self) -> &StoredBranchExactWriterLifecycle<Hash> { &self.source_writer }
    pub(super) const fn source_timestamp(&self) -> StoredAuthorityTimestampState { self.source_timestamp }
    pub(super) const fn counter_expected(&self) -> UniquePendingId { self.counter_expected }
    pub(super) const fn processing(&self) -> PendingGenerationContext { self.processing }
    pub(super) const fn gathering(&self) -> PendingGenerationContext { self.gathering }
    pub(super) const fn new_branch_write(&self) -> NewBranchWriteTimestampUs { self.new_branch_write }
    pub(super) const fn archive_store_fingerprint(&self) -> &[u8; 32] { &self.archive_store_fingerprint }
    pub(super) const fn slot(&self) -> &[u8; 32] { &self.slot }
    pub(super) const fn digest(&self) -> &[u8; 32] { &self.digest }
    pub(super) fn canonical_bytes(&self) -> &[u8] { &self.canonical_bytes }

    pub(super) const fn timestamp_intent(&self) -> AuthorityCommitIntentDigest {
        AuthorityCommitIntentDigest::from_sealed_commit_digest(self.digest)
    }

    pub(super) fn processing_allocation(
        &self,
    ) -> Result<SealedPendingCounterAllocation, RealmRollbackTargetRestorePlanError> {
        let plan = SealedPendingCounterAllocation::try_for_rollback(
            PendingCounterExpected::Present(self.counter_expected),
            self.processing.proc_checkpoint_id(),
            self.new_branch_write,
        )
        .map_err(model)?;
        if plan.digest().as_bytes() != &self.processing_allocation_digest {
            return Err(RealmRollbackTargetRestorePlanError::AllocationMismatch);
        }
        Ok(plan)
    }

    pub(super) fn gathering_allocation(
        &self,
    ) -> Result<SealedPendingCounterAllocation, RealmRollbackTargetRestorePlanError> {
        let plan = SealedPendingCounterAllocation::try_for_rollback(
            PendingCounterExpected::Present(self.processing.pending_id()),
            self.gathering.proc_checkpoint_id(),
            self.new_branch_write,
        )
        .map_err(model)?;
        if plan.digest().as_bytes() != &self.gathering_allocation_digest {
            return Err(RealmRollbackTargetRestorePlanError::AllocationMismatch);
        }
        Ok(plan)
    }

    pub(super) fn restored_observation(
        &self,
    ) -> Result<AuthorityObservation<Hash>, RealmRollbackTargetRestorePlanError> {
        let chain = CanonicalChainRef::new(
            self.target.network_id(),
            self.rollback_epoch,
            *self.target.checkpoint(),
        );
        AuthorityObservation::try_new(
            chain,
            self.authority,
            self.target_head.head().state_checkpoint(),
            *self.target_head.head().state_root(),
        )
        .map_err(model)
    }

    pub(super) fn restored_writer_watermark(
        &self,
    ) -> Result<BranchPendingMapping<Hash>, RealmRollbackTargetRestorePlanError> {
        Ok(BranchPendingMapping::new(
            *self.restored_observation()?.chain(),
            unique_pending(self.target_pipeline.processed_pending_id())?,
        ))
    }

    pub(super) const fn target_processed_pending_id(&self) -> u64 {
        self.target_pipeline.processed_pending_id()
    }

    /// Rebind a recovered immutable plan to the target marker selected by
    /// storage at the global rollback height. Realm hashes are authority-local,
    /// so this includes the local canonical reference and every marker identity
    /// copied into the plan.
    pub(super) fn revalidate_target_entry(
        &self,
        target: &VerifiedRealmRollbackTarget<Hash>,
    ) -> Result<(), RealmRollbackTargetRestorePlanError> {
        let head = target.stored_head().map_err(model)?;
        let pipeline = target.stored_pipeline().map_err(model)?;
        if target.authority() != self.authority
            || target.chain() != &self.target
            || target.evidence_slot() != self.target_inventory_slot
            || target.evidence_digest() != &self.target_inventory_digest
            || target.marker_digest() != &self.target_committed_marker_digest
            || target.writer_revision() != self.target_writer_revision
            || head != self.target_head
            || pipeline != self.target_pipeline
        {
            return Err(RealmRollbackTargetRestorePlanError::BindingMismatch);
        }
        Ok(())
    }
}

fn valid_target_pipeline<Hash: Q256BitHash>(
    target_checkpoint: u64,
    pipeline: &StoredPendingPipeline<Hash>,
) -> bool {
    if target_checkpoint == 0 {
        matches!(pipeline.phase(), PendingProcessingPhase::Ready)
            && pipeline.processed_pending_id() == 0
    } else {
        matches!(pipeline.phase(), PendingProcessingPhase::Published)
            && pipeline.processed_pending_id() == pipeline.processing().pending_id().get()
    }
}

fn next_pending(current: UniquePendingId) -> Result<UniquePendingId, RealmRollbackTargetRestorePlanError> {
    unique_pending(current.get().checked_add(1).ok_or(RealmRollbackTargetRestorePlanError::CounterOverflow)?)
}

fn unique_pending(value: u64) -> Result<UniquePendingId, RealmRollbackTargetRestorePlanError> {
    UniquePendingId::try_new(value).map_err(|_| RealmRollbackTargetRestorePlanError::CounterOverflow)
}

fn context(prefix: ProcNamespacePrefix, pending: UniquePendingId) -> Result<PendingGenerationContext, RealmRollbackTargetRestorePlanError> {
    PendingGenerationContext::try_from_legacy(pending.get(), prefix.derive_proc_id(pending).as_u128()).map_err(model)
}

fn push_context(out: &mut Vec<u8>, context: PendingGenerationContext) {
    out.extend_from_slice(&context.pending_id().get().to_be_bytes());
    out.extend_from_slice(&context.proc_checkpoint_id().as_u128().to_be_bytes());
}

fn push_state(out: &mut Vec<u8>, revision: i64, payload: &[u8]) -> Result<(), RealmRollbackTargetRestorePlanError> {
    let len = u32::try_from(payload.len()).map_err(|_| RealmRollbackTargetRestorePlanError::RowTooLarge)?;
    out.extend_from_slice(&revision.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn restore_plan_slot(
    network: NetworkId,
    authority: AuthorityScope,
    old_epoch: u64,
    participant_plan_digest: &[u8; 32],
    barrier_slot: &[u8; 32],
    barrier_digest: &[u8; 32],
    store_fingerprint: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(network.chain_id().to_be_bytes());
    hasher.update(encode_authority(authority));
    hasher.update(old_epoch.to_be_bytes());
    hasher.update(participant_plan_digest);
    hasher.update(barrier_slot);
    hasher.update(barrier_digest);
    hasher.update(store_fingerprint);
    hasher.finalize().into()
}

fn plan_digest(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(body);
    hasher.finalize().into()
}

fn encode_authority(authority: AuthorityScope) -> [u8; 7] {
    let mut bytes = [0_u8; 7];
    match authority {
        AuthorityScope::Coordinator => bytes[0] = 1,
        AuthorityScope::Realm { realm_id, realm_sub_id } => {
            bytes[0] = 2;
            bytes[1..5].copy_from_slice(&realm_id.to_be_bytes());
            bytes[5..7].copy_from_slice(&realm_sub_id.to_be_bytes());
        }
    }
    bytes
}

fn decode_authority(bytes: &[u8]) -> Result<AuthorityScope, RealmRollbackTargetRestorePlanError> {
    if bytes.len() != 7 { return Err(RealmRollbackTargetRestorePlanError::MalformedRow); }
    match bytes[0] {
        1 if bytes[1..] == [0; 6] => Ok(AuthorityScope::Coordinator),
        2 => Ok(AuthorityScope::Realm {
            realm_id: u32::from_be_bytes(bytes[1..5].try_into().unwrap()),
            realm_sub_id: u16::from_be_bytes(bytes[5..7].try_into().unwrap()),
        }),
        _ => Err(RealmRollbackTargetRestorePlanError::MalformedRow),
    }
}

fn model(error: impl fmt::Display) -> RealmRollbackTargetRestorePlanError {
    RealmRollbackTargetRestorePlanError::Model(error.to_string())
}

struct Cursor<'a> { bytes: &'a [u8], offset: usize }
impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }
    fn take(&mut self, len: usize) -> Result<&'a [u8], RealmRollbackTargetRestorePlanError> {
        let end = self.offset.checked_add(len).ok_or(RealmRollbackTargetRestorePlanError::MalformedRow)?;
        let value = self.bytes.get(self.offset..end).ok_or(RealmRollbackTargetRestorePlanError::MalformedRow)?;
        self.offset = end;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16, RealmRollbackTargetRestorePlanError> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32, RealmRollbackTargetRestorePlanError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, RealmRollbackTargetRestorePlanError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn i64(&mut self) -> Result<i64, RealmRollbackTargetRestorePlanError> { Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn u128(&mut self) -> Result<u128, RealmRollbackTargetRestorePlanError> { Ok(u128::from_be_bytes(self.take(16)?.try_into().unwrap())) }
    fn array32(&mut self) -> Result<[u8; 32], RealmRollbackTargetRestorePlanError> { Ok(self.take(32)?.try_into().unwrap()) }
    fn bytes(&mut self) -> Result<&'a [u8], RealmRollbackTargetRestorePlanError> { let len = self.u32()? as usize; self.take(len) }
    fn is_empty(&self) -> bool { self.offset == self.bytes.len() }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RealmRollbackTargetRestorePlanError {
    RealmRequired,
    CounterUninitialized,
    CounterOverflow,
    EpochOverflow,
    WriterNotActive,
    ProcNamespaceMismatch,
    AllocationMismatch,
    BindingMismatch,
    RowTooLarge,
    MalformedRow,
    InvalidMagic,
    UnknownVersion(u16),
    DigestMismatch,
    TrailingBytes,
    NonCanonicalEncoding,
    Model(String),
}

impl fmt::Display for RealmRollbackTargetRestorePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Realm target restore plan error: {self:?}")
    }
}
impl Error for RealmRollbackTargetRestorePlanError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_domain_and_slot_domains_are_stable_and_private() {
        assert_eq!(REALM_TARGET_RESTORE_PLAN_KEY_DOMAIN, -8);
        assert_ne!(SLOT_DOMAIN, DIGEST_DOMAIN);
        assert!(MAX_BYTES >= 64 * 1024);
    }

    #[test]
    fn truncated_and_unknown_codec_rows_fail_closed() {
        assert_eq!(RealmRollbackTargetRestorePlan::<parth_core::PHash>::decode_canonical(&[]), Err(RealmRollbackTargetRestorePlanError::MalformedRow));
        let mut bytes = vec![0_u8; 32 + 8 + 2];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&(VERSION + 1).to_be_bytes());
        let body_len = bytes.len() - 32;
        let digest = plan_digest(&bytes[..body_len]);
        bytes[body_len..].copy_from_slice(&digest);
        assert_eq!(RealmRollbackTargetRestorePlan::<parth_core::PHash>::decode_canonical(&bytes), Err(RealmRollbackTargetRestorePlanError::UnknownVersion(VERSION + 1)));
    }
}
