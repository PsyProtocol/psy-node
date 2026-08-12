//! Exact live source retained across the narrow-writer/full-commit boundary.
//!
//! The value carries a live proof seal and the exact canonical Coordinator
//! response. It is not a write, manifest, head, terminal, or rotation permit.
//! A storage backend must still reselect the application, pipeline and durable
//! writer before accepting it as the source of a later full commit.

use std::{error::Error, fmt};

use async_trait::async_trait;
use parth_core::{
    crypto::hash::tag_tree::TagTreeMerkleProof,
    felt::QFelt64,
    protocol::core_types::Q256BitHash,
};
use psy_data::{
    prepared_block::realm::PsyRealmCoordinatorUpdate,
    protocol::canonical_chain::{CanonicalChainRef, NetworkId},
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use sha2::{Digest, Sha256};

use crate::store::{
    pending_generation_identity::PendingGenerationContext,
    pending_generation_pipeline::PendingPipelineRevision,
    realm_proof_binding::{RealmProofBindingDigest, SealedRealmProofBinding},
    realm_processor_startup::{
        RealmProcessorStartupPermitDigest,
    },
};

use super::{
    realm_processor_application_proof_work::RealmProcessorApplicationProofWork,
    realm_processor_generation_continuation::RealmProcessorApplicationContinuation,
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
}

impl<Hash: Q256BitHash> RealmProcessorVerifiedFullCommitSource<Hash> {
    pub fn try_from_verified<F: QFelt64>(
        realm_id: u32,
        realm_sub_id: u16,
        work: &RealmProcessorApplicationProofWork,
        proof: SealedRealmProofBinding<Hash>,
        coordinator: &PsyRealmCoordinatorUpdate<F, Hash>,
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
            || !work.application().has_application_work()
        {
            return Err(RealmProcessorFullCommitSourceError::IdentityMismatch);
        }
        let coordinator_payload_digest = digest_coordinator(&coordinator_payload);
        Ok(Self {
            realm_id,
            realm_sub_id,
            application: work.application(),
            candidate: coordinator.canonical_chain_ref,
            reward_proof: coordinator.reward_tree_top_proof.clone(),
            proof,
            coordinator_payload,
            coordinator_payload_digest,
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
}

/// Read-only durable confirmation that the full-commit source still matches
/// the selected InFlight pipeline and WritesVerified narrow writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorFullCommitSourceObservation {
    processing: PendingGenerationContext,
    application: RealmProcessorApplicationContinuation,
    pipeline_revision: PendingPipelineRevision,
    writer_revision: u64,
    narrow_prepared_digest: [u8; 32],
    proof_binding_digest: RealmProofBindingDigest,
    coordinator_payload_digest: [u8; 32],
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
    ) -> Result<Self, RealmProcessorFullCommitSourceError> {
        if writer_revision == 0
            || narrow_prepared_digest == [0; 32]
            || coordinator_payload_digest == [0; 32]
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
}

#[async_trait]
pub trait RealmProcessorFullCommitSourceFactory<Hash>: Send + Sync {
    fn network(&self) -> NetworkId;
    fn realm_id(&self) -> u32;
    fn realm_sub_id(&self) -> u16;
    fn writer_activation_digest(&self) -> [u8; 32];
    fn queue_readiness_digest(&self) -> [u8; 32];

    async fn validate_source(
        &self,
        request: SealedRealmProcessorFullCommitSourceRequest<Hash>,
    ) -> Result<RealmProcessorFullCommitSourceObservation, RealmProcessorFullCommitSourceError>;
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
    fn source_request_and_observation_do_not_expose_publish_authority() {
        let source = include_str!("realm_processor_full_commit_source.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("finish_published"));
        assert!(!production.contains("seal_rotation"));
        assert!(!production.contains("authority_head"));
        assert!(!production.contains("pipeline.apply"));
        assert!(!production.contains("impl Clone for RealmProcessorVerifiedFullCommitSource"));
        assert!(!production.contains("impl Clone for SealedRealmProcessorFullCommitSourceRequest"));
    }
}
