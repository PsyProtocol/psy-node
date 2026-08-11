//! Affine, storage-revalidated entry to the first production Realm writer.
//!
//! The request deliberately omits pending/proc identity: the backend must
//! select those axes from the current durable pipeline and bind them to the
//! immutable application archive.  A successful observation means only that
//! the narrow mapping/reward-proof writer is `WritesVerified` and the pending
//! pipeline is `InFlight`; it is not authority-head, terminal, or rotation
//! authority.

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
        chain_context::AuthorityScope,
    },
};

use crate::store::{
    authority_commit::AuthorityClockSampleUs,
    pending_generation_identity::PendingGenerationContext,
    pending_generation_pipeline::PendingPipelineRevision,
    realm_proof_binding::{RealmProofBindingDigest, SealedRealmProofBinding},
    realm_processor_startup::RealmProcessorStartupPermitDigest,
};

use super::{
    realm_processor_application_proof_work::RealmProcessorApplicationProofWork,
    realm_processor_generation_continuation::RealmProcessorApplicationContinuation,
};

/// Exact proof/Coordinator capability accepted by the narrow writer seal.
///
/// It is non-Clone and can only be constructed from a live, ZK-verified
/// [`SealedRealmProofBinding`] plus the exact Coordinator response committed
/// by that binding. The reward proof is derived from that same response, so a
/// caller cannot swap it independently.
pub struct RealmProcessorVerifiedNarrowWriterEvidence<Hash> {
    realm_id: u32,
    realm_sub_id: u16,
    application: RealmProcessorApplicationContinuation,
    candidate: CanonicalChainRef<Hash>,
    reward_proof: TagTreeMerkleProof<Hash>,
    proof_binding_digest: RealmProofBindingDigest,
}

impl<Hash: Q256BitHash> RealmProcessorVerifiedNarrowWriterEvidence<Hash> {
    pub fn try_from_verified<F: QFelt64>(
        realm_id: u32,
        realm_sub_id: u16,
        work: &RealmProcessorApplicationProofWork,
        proof: &SealedRealmProofBinding<Hash>,
        coordinator: &PsyRealmCoordinatorUpdate<F, Hash>,
    ) -> Result<Self, RealmProcessorNarrowWriterError> {
        let prepared = work.prepared_update::<Hash>(realm_id, realm_sub_id);
        proof
            .revalidate_exact_inputs(&prepared, coordinator)
            .map_err(|error| RealmProcessorNarrowWriterError::Proof(error.to_string()))?;
        if proof.record().authority()
            != (AuthorityScope::Realm {
                realm_id,
                realm_sub_id,
            })
            || proof.record().canonical_chain() != &coordinator.canonical_chain_ref
            || proof.record().old_realm_root() != &prepared.old_realm_root
            || proof.record().new_realm_root() != &prepared.new_realm_root
            || !work.application().has_application_work()
        {
            return Err(RealmProcessorNarrowWriterError::IdentityMismatch);
        }
        Ok(Self {
            realm_id,
            realm_sub_id,
            application: work.application(),
            candidate: coordinator.canonical_chain_ref,
            reward_proof: coordinator.reward_tree_top_proof.clone(),
            proof_binding_digest: proof.digest(),
        })
    }

    pub const fn realm_id(&self) -> u32 {
        self.realm_id
    }

    pub const fn realm_sub_id(&self) -> u16 {
        self.realm_sub_id
    }

    pub const fn application(&self) -> RealmProcessorApplicationContinuation {
        self.application
    }

    pub const fn candidate(&self) -> &CanonicalChainRef<Hash> {
        &self.candidate
    }

    pub fn reward_proof(&self) -> &TagTreeMerkleProof<Hash> {
        &self.reward_proof
    }

    pub const fn proof_binding_digest(&self) -> RealmProofBindingDigest {
        self.proof_binding_digest
    }
}

/// Sealed by the single commit iteration. Callers may provide coordinator
/// evidence, but cannot select the durable pending/proc namespace.
pub struct SealedRealmProcessorNarrowWriterRequest<Hash> {
    startup_permit_digest: RealmProcessorStartupPermitDigest,
    network: NetworkId,
    realm_id: u32,
    realm_sub_id: u16,
    writer_activation_digest: [u8; 32],
    queue_readiness_digest: [u8; 32],
    application: RealmProcessorApplicationContinuation,
    candidate: CanonicalChainRef<Hash>,
    reward_proof: TagTreeMerkleProof<Hash>,
    proof_binding_digest: RealmProofBindingDigest,
    clock_sample: AuthorityClockSampleUs,
}

impl<Hash: Q256BitHash> SealedRealmProcessorNarrowWriterRequest<Hash> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn seal(
        startup_permit_digest: RealmProcessorStartupPermitDigest,
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        writer_activation_digest: [u8; 32],
        queue_readiness_digest: [u8; 32],
        evidence: &RealmProcessorVerifiedNarrowWriterEvidence<Hash>,
        clock_sample: AuthorityClockSampleUs,
    ) -> Result<Self, RealmProcessorNarrowWriterError> {
        if writer_activation_digest == [0; 32]
            || queue_readiness_digest == [0; 32]
            || evidence.candidate().network_id() != network
            || evidence.realm_id() != realm_id
            || evidence.realm_sub_id() != realm_sub_id
            || !evidence.application().has_application_work()
        {
            return Err(RealmProcessorNarrowWriterError::IdentityMismatch);
        }
        Ok(Self {
            startup_permit_digest,
            network,
            realm_id,
            realm_sub_id,
            writer_activation_digest,
            queue_readiness_digest,
            application: evidence.application(),
            candidate: *evidence.candidate(),
            reward_proof: evidence.reward_proof().clone(),
            proof_binding_digest: evidence.proof_binding_digest(),
            clock_sample,
        })
    }

    pub const fn startup_permit_digest(&self) -> RealmProcessorStartupPermitDigest {
        self.startup_permit_digest
    }

    pub const fn network(&self) -> NetworkId {
        self.network
    }

    pub const fn realm_id(&self) -> u32 {
        self.realm_id
    }

    pub const fn realm_sub_id(&self) -> u16 {
        self.realm_sub_id
    }

    pub const fn writer_activation_digest(&self) -> &[u8; 32] {
        &self.writer_activation_digest
    }

    pub const fn queue_readiness_digest(&self) -> &[u8; 32] {
        &self.queue_readiness_digest
    }

    pub const fn application(&self) -> RealmProcessorApplicationContinuation {
        self.application
    }

    pub const fn candidate(&self) -> &CanonicalChainRef<Hash> {
        &self.candidate
    }

    pub const fn clock_sample(&self) -> AuthorityClockSampleUs {
        self.clock_sample
    }

    pub fn reward_proof(&self) -> &TagTreeMerkleProof<Hash> {
        &self.reward_proof
    }

    pub const fn proof_binding_digest(&self) -> RealmProofBindingDigest {
        self.proof_binding_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorNarrowWriterObservation {
    processing: PendingGenerationContext,
    application: RealmProcessorApplicationContinuation,
    pipeline_revision: PendingPipelineRevision,
    writer_revision: u64,
    intent_digest: [u8; 32],
}

impl RealmProcessorNarrowWriterObservation {
    pub fn try_from_storage(
        processing: PendingGenerationContext,
        application: RealmProcessorApplicationContinuation,
        pipeline_revision: PendingPipelineRevision,
        writer_revision: u64,
        intent_digest: [u8; 32],
    ) -> Result<Self, RealmProcessorNarrowWriterError> {
        if !application.has_application_work()
            || writer_revision == 0
            || intent_digest == [0; 32]
        {
            return Err(RealmProcessorNarrowWriterError::IdentityMismatch);
        }
        Ok(Self {
            processing,
            application,
            pipeline_revision,
            writer_revision,
            intent_digest,
        })
    }

    pub const fn processing(&self) -> PendingGenerationContext {
        self.processing
    }

    pub const fn application(&self) -> RealmProcessorApplicationContinuation {
        self.application
    }

    pub const fn pipeline_revision(&self) -> PendingPipelineRevision {
        self.pipeline_revision
    }

    pub const fn writer_revision(&self) -> u64 {
        self.writer_revision
    }

    pub const fn intent_digest(&self) -> &[u8; 32] {
        &self.intent_digest
    }
}

#[async_trait]
pub trait RealmProcessorNarrowWriterFactory<Hash>: Send + Sync {
    fn network(&self) -> NetworkId;
    fn realm_id(&self) -> u32;
    fn realm_sub_id(&self) -> u16;
    fn writer_activation_digest(&self) -> [u8; 32];
    fn queue_readiness_digest(&self) -> [u8; 32];

    async fn prepare_and_verify(
        &self,
        request: SealedRealmProcessorNarrowWriterRequest<Hash>,
    ) -> Result<RealmProcessorNarrowWriterObservation, RealmProcessorNarrowWriterError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmProcessorNarrowWriterError {
    IdentityMismatch,
    ConcurrentMutation,
    Writer(String),
    Pipeline(String),
    Proof(String),
    Backend(String),
}

impl fmt::Display for RealmProcessorNarrowWriterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmProcessorNarrowWriterError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_core::constants::chain_id::PsyChainNetworkType;
    use psy_data::protocol::canonical_chain::{
        ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
    };

    use super::*;
    use crate::queue::{
        realm_processor_application_archive::{
            RealmProcessorApplicationArchiveDigest,
            RealmProcessorApplicationArchiveSlot,
        },
        realm_processor_generation_continuation::RealmProcessorDeferredCarryoverDigest,
        realm_processor_semantic_output::RealmProcessorSemanticOutputDigest,
    };

    fn network() -> NetworkId {
        NetworkId::from_network_type(PsyChainNetworkType::LocalDevnet)
    }

    fn candidate(network: NetworkId) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            network,
            ChainEpoch::new(2),
            CheckpointRef::new(
                CheckpointId::new(11),
                CheckpointHash::from_last_chain_hash(PHash::from_owned_32bytes([7; 32])),
            ),
        )
    }

    fn application(has_work: bool) -> RealmProcessorApplicationContinuation {
        RealmProcessorApplicationContinuation::try_from_committed_parts(
            RealmProcessorApplicationArchiveSlot::try_new([1; 32]).unwrap(),
            RealmProcessorApplicationArchiveDigest::try_new([2; 32]).unwrap(),
            RealmProcessorSemanticOutputDigest::try_new([3; 32]).unwrap(),
            has_work,
            0,
            RealmProcessorDeferredCarryoverDigest::try_new([4; 32]).unwrap(),
        )
        .unwrap()
    }

    fn evidence(
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        application: RealmProcessorApplicationContinuation,
    ) -> RealmProcessorVerifiedNarrowWriterEvidence<PHash> {
        RealmProcessorVerifiedNarrowWriterEvidence {
            realm_id,
            realm_sub_id,
            application,
            candidate: candidate(network),
            reward_proof: TagTreeMerkleProof::new_empty(),
            proof_binding_digest: RealmProofBindingDigest::from_bytes([8; 32]),
        }
    }

    #[test]
    fn sealed_request_rejects_foreign_network_empty_identity_and_no_work() {
        let seal = |writer, ready, evidence| {
            SealedRealmProcessorNarrowWriterRequest::seal(
                RealmProcessorStartupPermitDigest::try_new([9; 32]).unwrap(),
                network(),
                7,
                3,
                writer,
                ready,
                &evidence,
                AuthorityClockSampleUs::try_from_i128(100).unwrap(),
            )
        };
        assert!(seal(
            [1; 32],
            [2; 32],
            evidence(network(), 7, 3, application(true)),
        )
        .is_ok());
        assert!(matches!(
            seal(
                [0; 32],
                [2; 32],
                evidence(network(), 7, 3, application(true)),
            ),
            Err(RealmProcessorNarrowWriterError::IdentityMismatch)
        ));
        assert!(matches!(
            seal(
                [1; 32],
                [2; 32],
                evidence(network(), 7, 3, application(false)),
            ),
            Err(RealmProcessorNarrowWriterError::IdentityMismatch)
        ));
        assert!(matches!(
            seal(
                [1; 32],
                [2; 32],
                evidence(
                    NetworkId::try_from_chain_id(1).unwrap(),
                    7,
                    3,
                    application(true),
                ),
            ),
            Err(RealmProcessorNarrowWriterError::IdentityMismatch)
        ));
        assert!(matches!(
            seal(
                [1; 32],
                [2; 32],
                evidence(network(), 8, 3, application(true)),
            ),
            Err(RealmProcessorNarrowWriterError::IdentityMismatch)
        ));
    }

    #[test]
    fn observation_is_non_authoritative_but_rejects_empty_storage_evidence() {
        let processing = PendingGenerationContext::try_from_legacy(17, 19).unwrap();
        let revision = PendingPipelineRevision::try_new(4).unwrap();
        let exact = RealmProcessorNarrowWriterObservation::try_from_storage(
            processing,
            application(true),
            revision,
            8,
            [5; 32],
        )
        .unwrap();
        assert_eq!(exact.processing(), processing);
        assert_eq!(exact.pipeline_revision(), revision);
        assert_eq!(exact.writer_revision(), 8);
        assert_eq!(exact.intent_digest(), &[5; 32]);
        assert!(RealmProcessorNarrowWriterObservation::try_from_storage(
            processing,
            application(true),
            revision,
            0,
            [5; 32],
        )
        .is_err());
        assert!(RealmProcessorNarrowWriterObservation::try_from_storage(
            processing,
            application(false),
            revision,
            8,
            [5; 32],
        )
        .is_err());

        let source = include_str!("realm_processor_narrow_writer.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("impl Clone for SealedRealmProcessorNarrowWriterRequest"));
        assert!(!production.contains("finish_published"));
        assert!(!production.contains("authority_head"));
        assert!(!production.contains("seal_rotation"));
    }
}
