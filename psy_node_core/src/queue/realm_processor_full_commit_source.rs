//! Exact live source retained across the narrow-writer/full-commit boundary.
//!
//! The value carries a live proof seal, the exact canonical Coordinator
//! response and the checked logical write set. A storage backend must reselect
//! the application, pipeline and durable writer before executing the complete
//! physical plan and persisting its immutable verification manifest. The
//! resulting observation is still not a head, terminal, or rotation permit.

use std::{error::Error, fmt};

use async_trait::async_trait;
use parth_core::{
    crypto::hash::tag_tree::TagTreeMerkleProof,
    felt::QFelt64,
    protocol::core_types::Q256BitHash,
};
use psy_data::{
    prepared_block::realm::PsyRealmCoordinatorUpdate,
    protocol::{
        canonical_chain::{CanonicalChainRef, NetworkId},
        chain_context::{AuthorityObservation, AuthorityScope},
    },
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use sha2::{Digest, Sha256};

use crate::store::{
    authority_local_head::{SealedAuthorityLocalHeadCas, StoredAuthorityLocalHead},
    pending_generation_identity::PendingGenerationContext,
    pending_generation_pipeline::PendingPipelineRevision,
    realm_full_commit_write_set::RealmFullCommitWriteSet,
    realm_normal_commit_coverage::RealmNormalCommitCoveragePlan,
    realm_proof_binding::{RealmProofBindingDigest, SealedRealmProofBinding},
    realm_processor_startup::{
        RealmProcessorStartupPermitDigest,
    },
    timestamp::CommitWriteTimestampUs,
};

use super::{
    realm_processor_application_proof_work::RealmProcessorApplicationProofWork,
    realm_processor_generation_continuation::RealmProcessorApplicationContinuation,
    realm_processor_generation_terminal::{
        RealmProcessorDeferredCarryoverRecordDigest,
        RealmProcessorDeferredCarryoverSlot,
        RealmProcessorGenerationTerminalDigest,
        RealmProcessorGenerationTerminalSlot,
    },
};

const COORDINATOR_PAYLOAD_DIGEST_DOMAIN: &[u8] =
    b"psy/realm-processor-full-commit-coordinator-payload/v1";
const MAX_COORDINATOR_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Live proof/Coordinator source for the complete writer.
///
/// It is intentionally non-Clone. The Processor can reconstruct the same
/// value after a crash from the immutable application, proof store and exact
/// Coordinator inclusion response.
pub struct RealmProcessorVerifiedFullCommitSource<Hash> {
    realm_id: u32,
    realm_sub_id: u16,
    application: RealmProcessorApplicationContinuation,
    candidate: CanonicalChainRef<Hash>,
    reward_proof: TagTreeMerkleProof<Hash>,
    proof: SealedRealmProofBinding<Hash>,
    coordinator_payload: Vec<u8>,
    coordinator_payload_digest: [u8; 32],
    authority_observation: AuthorityObservation<Hash>,
    write_set: RealmFullCommitWriteSet,
}

impl<Hash: Q256BitHash> RealmProcessorVerifiedFullCommitSource<Hash> {
    pub fn try_from_verified<F: QFelt64>(
        realm_id: u32,
        realm_sub_id: u16,
        work: &RealmProcessorApplicationProofWork,
        proof: SealedRealmProofBinding<Hash>,
        coordinator: &PsyRealmCoordinatorUpdate<F, Hash>,
        write_set: RealmFullCommitWriteSet,
    ) -> Result<Self, RealmProcessorFullCommitSourceError> {
        let prepared = work.prepared_update::<Hash>(realm_id, realm_sub_id);
        proof
            .revalidate_exact_inputs(&prepared, coordinator)
            .map_err(|error| RealmProcessorFullCommitSourceError::Proof(error.to_string()))?;
        let coordinator_payload = coordinator
            .psy_ser_to_bytes_vec()
            .map_err(|error| RealmProcessorFullCommitSourceError::Codec(error.to_string()))?;
        if coordinator_payload.is_empty()
            || coordinator_payload.len() > MAX_COORDINATOR_PAYLOAD_BYTES
            || proof.record().canonical_chain() != &coordinator.canonical_chain_ref
            || proof.record().old_realm_root() != &prepared.old_realm_root
            || proof.record().new_realm_root() != &prepared.new_realm_root
            || write_set.coverage_plan()
                != RealmNormalCommitCoveragePlan::from_prepared(&prepared)
            || !work.application().has_application_work()
        {
            return Err(RealmProcessorFullCommitSourceError::IdentityMismatch);
        }
        let coordinator_payload_digest = digest_coordinator(&coordinator_payload);
        let authority_observation = write_set
            .authority_observation::<Hash>()
            .map_err(|error| RealmProcessorFullCommitSourceError::Writer(error.to_string()))?;
        let expected_authority = AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        };
        if authority_observation.authority() != expected_authority
            || authority_observation.chain() != &coordinator.canonical_chain_ref
            || authority_observation.state_checkpoint_id()
                != proof.record().state_checkpoint()
            || authority_observation.state_root().as_inner()
                != proof.record().new_realm_root()
        {
            return Err(RealmProcessorFullCommitSourceError::IdentityMismatch);
        }
        Ok(Self {
            realm_id,
            realm_sub_id,
            application: work.application(),
            candidate: coordinator.canonical_chain_ref,
            reward_proof: coordinator.reward_tree_top_proof.clone(),
            proof,
            coordinator_payload,
            coordinator_payload_digest,
            authority_observation,
            write_set,
        })
    }

    pub const fn application(&self) -> RealmProcessorApplicationContinuation {
        self.application
    }

    pub const fn candidate(&self) -> &CanonicalChainRef<Hash> {
        &self.candidate
    }

    pub const fn proof_binding_digest(&self) -> RealmProofBindingDigest {
        self.proof.digest()
    }

    pub const fn coordinator_payload_digest(&self) -> &[u8; 32] {
        &self.coordinator_payload_digest
    }
}

/// Request sealed by the affine commit iteration. Callers cannot select the
/// durable pending/proc identity or replace the installed runtime identity.
pub struct SealedRealmProcessorFullCommitSourceRequest<Hash> {
    startup_permit_digest: RealmProcessorStartupPermitDigest,
    network: NetworkId,
    realm_id: u32,
    realm_sub_id: u16,
    writer_activation_digest: [u8; 32],
    queue_readiness_digest: [u8; 32],
    application: RealmProcessorApplicationContinuation,
    candidate: CanonicalChainRef<Hash>,
    reward_proof: TagTreeMerkleProof<Hash>,
    proof: SealedRealmProofBinding<Hash>,
    coordinator_payload: Vec<u8>,
    coordinator_payload_digest: [u8; 32],
    authority_observation: AuthorityObservation<Hash>,
    write_set: RealmFullCommitWriteSet,
}

impl<Hash: Q256BitHash> SealedRealmProcessorFullCommitSourceRequest<Hash> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn seal(
        startup_permit_digest: RealmProcessorStartupPermitDigest,
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        writer_activation_digest: [u8; 32],
        queue_readiness_digest: [u8; 32],
        source: RealmProcessorVerifiedFullCommitSource<Hash>,
    ) -> Result<Self, RealmProcessorFullCommitSourceError> {
        if writer_activation_digest == [0; 32]
            || queue_readiness_digest == [0; 32]
            || source.realm_id != realm_id
            || source.realm_sub_id != realm_sub_id
            || source.candidate.network_id() != network
            || !source.application.has_application_work()
            || source.coordinator_payload.is_empty()
            || source.coordinator_payload.len() > MAX_COORDINATOR_PAYLOAD_BYTES
            || digest_coordinator(&source.coordinator_payload)
                != source.coordinator_payload_digest
        {
            return Err(RealmProcessorFullCommitSourceError::IdentityMismatch);
        }
        Ok(Self {
            startup_permit_digest,
            network,
            realm_id,
            realm_sub_id,
            writer_activation_digest,
            queue_readiness_digest,
            application: source.application,
            candidate: source.candidate,
            reward_proof: source.reward_proof,
            proof: source.proof,
            coordinator_payload: source.coordinator_payload,
            coordinator_payload_digest: source.coordinator_payload_digest,
            authority_observation: source.authority_observation,
            write_set: source.write_set,
        })
    }

    pub const fn startup_permit_digest(&self) -> RealmProcessorStartupPermitDigest {
        self.startup_permit_digest
    }
    pub const fn network(&self) -> NetworkId { self.network }
    pub const fn realm_id(&self) -> u32 { self.realm_id }
    pub const fn realm_sub_id(&self) -> u16 { self.realm_sub_id }
    pub const fn writer_activation_digest(&self) -> &[u8; 32] {
        &self.writer_activation_digest
    }
    pub const fn queue_readiness_digest(&self) -> &[u8; 32] {
        &self.queue_readiness_digest
    }
    pub const fn application(&self) -> RealmProcessorApplicationContinuation {
        self.application
    }
    pub const fn candidate(&self) -> &CanonicalChainRef<Hash> { &self.candidate }
    pub fn reward_proof(&self) -> &TagTreeMerkleProof<Hash> { &self.reward_proof }
    pub const fn proof(&self) -> &SealedRealmProofBinding<Hash> { &self.proof }
    pub fn coordinator_payload(&self) -> &[u8] { &self.coordinator_payload }
    pub const fn coordinator_payload_digest(&self) -> &[u8; 32] {
        &self.coordinator_payload_digest
    }
    pub const fn authority_observation(&self) -> AuthorityObservation<Hash> {
        self.authority_observation
    }
    pub const fn write_set(&self) -> &RealmFullCommitWriteSet {
        &self.write_set
    }

    /// Seal the authority-head CAS only while the affine full-commit request
    /// and its live proof binding are still present.  The storage adapter must
    /// first fresh-revalidate the manifest and pass its exact digest/timestamp.
    pub fn seal_authority_head_advance(
        &self,
        expected: StoredAuthorityLocalHead<Hash>,
        write_timestamp: CommitWriteTimestampUs,
        manifest_digest: [u8; 32],
    ) -> Result<SealedAuthorityLocalHeadCas<Hash>, RealmProcessorFullCommitSourceError> {
        let key = expected.head().key();
        let expected_authority = AuthorityScope::Realm {
            realm_id: self.realm_id,
            realm_sub_id: self.realm_sub_id,
        };
        if key.network() != self.network
            || key.authority() != expected_authority
            || expected.head().state_root().as_inner()
                != self.proof.record().old_realm_root()
            || self.authority_observation.state_root().as_inner()
                != self.proof.record().new_realm_root()
            || self.authority_observation.state_checkpoint_id()
                != self.proof.record().state_checkpoint()
        {
            return Err(RealmProcessorFullCommitSourceError::IdentityMismatch);
        }
        SealedAuthorityLocalHeadCas::seal_realm_full_commit_advance(
            expected,
            self.authority_observation,
            write_timestamp,
            manifest_digest,
        )
        .map_err(|error| RealmProcessorFullCommitSourceError::Backend(error.to_string()))
    }
}

/// Durable confirmation that the complete full-commit plan was written,
/// exactly read back and committed by an immutable verification manifest.
/// It remains an observation only; later head/terminal owners must fresh-read
/// the manifest rather than treating this copyable value as authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorFullCommitSourceObservation {
    processing: PendingGenerationContext,
    application: RealmProcessorApplicationContinuation,
    pipeline_revision: PendingPipelineRevision,
    writer_revision: u64,
    narrow_prepared_digest: [u8; 32],
    proof_binding_digest: RealmProofBindingDigest,
    coordinator_payload_digest: [u8; 32],
    full_coverage_digest: [u8; 32],
    semantic_domain_count: u8,
    manifest_slot: [u8; 32],
    manifest_digest: [u8; 32],
    typed_row_count: u32,
    total_mutation_count: u64,
}

/// Identity-only request for the crash window in which the pipeline is
/// already Published but the branch-exact writer has not yet reached Active.
/// It carries no manifest slot, digest, head or candidate supplied by the
/// caller; the backend must select every one from durable storage.
pub struct SealedRealmProcessorFullCommitPublicationRequest {
    startup_permit_digest: RealmProcessorStartupPermitDigest,
    network: NetworkId,
    realm_id: u32,
    realm_sub_id: u16,
    writer_activation_digest: [u8; 32],
    queue_readiness_digest: [u8; 32],
}

/// Identity-only request for closing one already-published generation and
/// rotating its durable pipeline.  The caller cannot choose either the
/// current/successor generation or any terminal/carryover content.
pub struct SealedRealmProcessorGenerationRotationRequest {
    startup_permit_digest: RealmProcessorStartupPermitDigest,
    network: NetworkId,
    realm_id: u32,
    realm_sub_id: u16,
    writer_activation_digest: [u8; 32],
    queue_readiness_digest: [u8; 32],
}

impl SealedRealmProcessorGenerationRotationRequest {
    pub(crate) fn seal(
        startup_permit_digest: RealmProcessorStartupPermitDigest,
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        writer_activation_digest: [u8; 32],
        queue_readiness_digest: [u8; 32],
    ) -> Result<Self, RealmProcessorFullCommitSourceError> {
        if writer_activation_digest == [0; 32]
            || queue_readiness_digest == [0; 32]
        {
            return Err(RealmProcessorFullCommitSourceError::IdentityMismatch);
        }
        Ok(Self {
            startup_permit_digest,
            network,
            realm_id,
            realm_sub_id,
            writer_activation_digest,
            queue_readiness_digest,
        })
    }

    pub const fn startup_permit_digest(&self) -> RealmProcessorStartupPermitDigest {
        self.startup_permit_digest
    }
    pub const fn network(&self) -> NetworkId { self.network }
    pub const fn realm_id(&self) -> u32 { self.realm_id }
    pub const fn realm_sub_id(&self) -> u16 { self.realm_sub_id }
    pub const fn writer_activation_digest(&self) -> &[u8; 32] {
        &self.writer_activation_digest
    }
    pub const fn queue_readiness_digest(&self) -> &[u8; 32] {
        &self.queue_readiness_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorGenerationRotationObservation {
    source: PendingGenerationContext,
    successor: PendingGenerationContext,
    reserved_next_gathering: PendingGenerationContext,
    pipeline_revision: PendingPipelineRevision,
    terminal_slot: RealmProcessorGenerationTerminalSlot,
    terminal_digest: RealmProcessorGenerationTerminalDigest,
    carryover_slot: RealmProcessorDeferredCarryoverSlot,
    carryover_digest: RealmProcessorDeferredCarryoverRecordDigest,
}

impl RealmProcessorGenerationRotationObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn try_from_storage(
        source: PendingGenerationContext,
        successor: PendingGenerationContext,
        reserved_next_gathering: PendingGenerationContext,
        pipeline_revision: PendingPipelineRevision,
        terminal_slot: RealmProcessorGenerationTerminalSlot,
        terminal_digest: RealmProcessorGenerationTerminalDigest,
        carryover_slot: RealmProcessorDeferredCarryoverSlot,
        carryover_digest: RealmProcessorDeferredCarryoverRecordDigest,
    ) -> Result<Self, RealmProcessorFullCommitSourceError> {
        if source.pending_id().get() == 0
            || successor.pending_id().get() <= source.pending_id().get()
            || reserved_next_gathering.pending_id().get()
                <= successor.pending_id().get()
        {
            return Err(RealmProcessorFullCommitSourceError::IdentityMismatch);
        }
        Ok(Self {
            source,
            successor,
            reserved_next_gathering,
            pipeline_revision,
            terminal_slot,
            terminal_digest,
            carryover_slot,
            carryover_digest,
        })
    }

    pub const fn source(&self) -> PendingGenerationContext { self.source }
    pub const fn successor(&self) -> PendingGenerationContext { self.successor }
    pub const fn reserved_next_gathering(&self) -> PendingGenerationContext {
        self.reserved_next_gathering
    }
    pub const fn pipeline_revision(&self) -> PendingPipelineRevision {
        self.pipeline_revision
    }
    pub const fn terminal_slot(&self) -> RealmProcessorGenerationTerminalSlot {
        self.terminal_slot
    }
    pub const fn terminal_digest(&self) -> RealmProcessorGenerationTerminalDigest {
        self.terminal_digest
    }
    pub const fn carryover_slot(&self) -> RealmProcessorDeferredCarryoverSlot {
        self.carryover_slot
    }
    pub const fn carryover_digest(&self) -> RealmProcessorDeferredCarryoverRecordDigest {
        self.carryover_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmProcessorGenerationRotationOutcome {
    AwaitSuccessorDependency {
        source: PendingGenerationContext,
        successor: PendingGenerationContext,
        pipeline_revision: PendingPipelineRevision,
    },
    Rotated(RealmProcessorGenerationRotationObservation),
}

impl SealedRealmProcessorFullCommitPublicationRequest {
    pub(crate) fn seal(
        startup_permit_digest: RealmProcessorStartupPermitDigest,
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        writer_activation_digest: [u8; 32],
        queue_readiness_digest: [u8; 32],
    ) -> Result<Self, RealmProcessorFullCommitSourceError> {
        if writer_activation_digest == [0; 32]
            || queue_readiness_digest == [0; 32]
        {
            return Err(RealmProcessorFullCommitSourceError::IdentityMismatch);
        }
        Ok(Self {
            startup_permit_digest,
            network,
            realm_id,
            realm_sub_id,
            writer_activation_digest,
            queue_readiness_digest,
        })
    }

    pub const fn startup_permit_digest(&self) -> RealmProcessorStartupPermitDigest {
        self.startup_permit_digest
    }
    pub const fn network(&self) -> NetworkId { self.network }
    pub const fn realm_id(&self) -> u32 { self.realm_id }
    pub const fn realm_sub_id(&self) -> u16 { self.realm_sub_id }
    pub const fn writer_activation_digest(&self) -> &[u8; 32] {
        &self.writer_activation_digest
    }
    pub const fn queue_readiness_digest(&self) -> &[u8; 32] {
        &self.queue_readiness_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorFullCommitPublicationObservation {
    processing: PendingGenerationContext,
    application: RealmProcessorApplicationContinuation,
    pipeline_revision: PendingPipelineRevision,
    writer_revision: u64,
    manifest_slot: [u8; 32],
    manifest_digest: [u8; 32],
    head_revision: u64,
}

impl RealmProcessorFullCommitPublicationObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn try_from_storage(
        processing: PendingGenerationContext,
        application: RealmProcessorApplicationContinuation,
        pipeline_revision: PendingPipelineRevision,
        writer_revision: u64,
        manifest_slot: [u8; 32],
        manifest_digest: [u8; 32],
        head_revision: u64,
    ) -> Result<Self, RealmProcessorFullCommitSourceError> {
        if writer_revision == 0
            || manifest_slot == [0; 32]
            || manifest_digest == [0; 32]
            || !application.has_application_work()
        {
            return Err(RealmProcessorFullCommitSourceError::IdentityMismatch);
        }
        Ok(Self {
            processing,
            application,
            pipeline_revision,
            writer_revision,
            manifest_slot,
            manifest_digest,
            head_revision,
        })
    }

    pub const fn processing(&self) -> PendingGenerationContext { self.processing }
    pub const fn application(&self) -> RealmProcessorApplicationContinuation {
        self.application
    }
    pub const fn pipeline_revision(&self) -> PendingPipelineRevision {
        self.pipeline_revision
    }
    pub const fn writer_revision(&self) -> u64 { self.writer_revision }
    pub const fn manifest_slot(&self) -> &[u8; 32] { &self.manifest_slot }
    pub const fn manifest_digest(&self) -> &[u8; 32] { &self.manifest_digest }
    pub const fn head_revision(&self) -> u64 { self.head_revision }
}

impl RealmProcessorFullCommitSourceObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn try_from_storage(
        processing: PendingGenerationContext,
        application: RealmProcessorApplicationContinuation,
        pipeline_revision: PendingPipelineRevision,
        writer_revision: u64,
        narrow_prepared_digest: [u8; 32],
        proof_binding_digest: RealmProofBindingDigest,
        coordinator_payload_digest: [u8; 32],
        full_coverage_digest: [u8; 32],
        semantic_domain_count: u8,
        manifest_slot: [u8; 32],
        manifest_digest: [u8; 32],
        typed_row_count: u32,
        total_mutation_count: u64,
    ) -> Result<Self, RealmProcessorFullCommitSourceError> {
        if writer_revision == 0
            || narrow_prepared_digest == [0; 32]
            || coordinator_payload_digest == [0; 32]
            || full_coverage_digest == [0; 32]
            || semantic_domain_count == 0
            || semantic_domain_count > 22
            || manifest_slot == [0; 32]
            || manifest_digest == [0; 32]
            || typed_row_count == 0
            || total_mutation_count <= u64::from(typed_row_count)
            || !application.has_application_work()
        {
            return Err(RealmProcessorFullCommitSourceError::IdentityMismatch);
        }
        Ok(Self {
            processing,
            application,
            pipeline_revision,
            writer_revision,
            narrow_prepared_digest,
            proof_binding_digest,
            coordinator_payload_digest,
            full_coverage_digest,
            semantic_domain_count,
            manifest_slot,
            manifest_digest,
            typed_row_count,
            total_mutation_count,
        })
    }

    pub const fn processing(&self) -> PendingGenerationContext { self.processing }
    pub const fn application(&self) -> RealmProcessorApplicationContinuation {
        self.application
    }
    pub const fn pipeline_revision(&self) -> PendingPipelineRevision {
        self.pipeline_revision
    }
    pub const fn writer_revision(&self) -> u64 { self.writer_revision }
    pub const fn narrow_prepared_digest(&self) -> &[u8; 32] {
        &self.narrow_prepared_digest
    }
    pub const fn proof_binding_digest(&self) -> RealmProofBindingDigest {
        self.proof_binding_digest
    }
    pub const fn coordinator_payload_digest(&self) -> &[u8; 32] {
        &self.coordinator_payload_digest
    }
    pub const fn full_coverage_digest(&self) -> &[u8; 32] {
        &self.full_coverage_digest
    }
    pub const fn semantic_domain_count(&self) -> u8 {
        self.semantic_domain_count
    }
    pub const fn manifest_slot(&self) -> &[u8; 32] { &self.manifest_slot }
    pub const fn manifest_digest(&self) -> &[u8; 32] { &self.manifest_digest }
    pub const fn typed_row_count(&self) -> u32 { self.typed_row_count }
    pub const fn total_mutation_count(&self) -> u64 {
        self.total_mutation_count
    }
}

#[async_trait]
pub trait RealmProcessorFullCommitSourceFactory<Hash>: Send + Sync {
    fn network(&self) -> NetworkId;
    fn realm_id(&self) -> u32;
    fn realm_sub_id(&self) -> u16;
    fn writer_activation_digest(&self) -> [u8; 32];
    fn queue_readiness_digest(&self) -> [u8; 32];

    async fn execute_source(
        &self,
        request: SealedRealmProcessorFullCommitSourceRequest<Hash>,
    ) -> Result<RealmProcessorFullCommitSourceObservation, RealmProcessorFullCommitSourceError>;

    async fn recover_publication(
        &self,
        request: SealedRealmProcessorFullCommitPublicationRequest,
    ) -> Result<
        RealmProcessorFullCommitPublicationObservation,
        RealmProcessorFullCommitSourceError,
    >;

    async fn terminalize_and_rotate(
        &self,
        request: SealedRealmProcessorGenerationRotationRequest,
    ) -> Result<RealmProcessorGenerationRotationOutcome, RealmProcessorFullCommitSourceError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmProcessorFullCommitSourceError {
    IdentityMismatch,
    ConcurrentMutation,
    Codec(String),
    Proof(String),
    Writer(String),
    Pipeline(String),
    Backend(String),
}

impl fmt::Display for RealmProcessorFullCommitSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmProcessorFullCommitSourceError {}

fn digest_coordinator(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COORDINATOR_PAYLOAD_DIGEST_DOMAIN);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    #[test]
    fn source_request_exposes_only_the_checked_head_model_not_storage_mutation() {
        let source = include_str!("realm_processor_full_commit_source.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("seal_authority_head_advance"));
        assert!(!production.contains("compare_and_set"));
        assert!(!production.contains("finish_published"));
        assert!(!production.contains("seal_rotation"));
        assert!(!production.contains("pipeline.apply"));
        assert!(!production.contains("impl Clone for RealmProcessorVerifiedFullCommitSource"));
        assert!(!production.contains("impl Clone for SealedRealmProcessorFullCommitSourceRequest"));
    }
}
