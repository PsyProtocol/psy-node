//! High-level, driver-independent Realm Edge durable ingress boundary.
//!
//! The legacy low-level publisher accepts an already-built queue payload. That
//! is intentionally insufficient for a production Edge: the durable owner must
//! bind one stable branch observation, verify the full canonical UserEndCap
//! input/proof, win the per-user claim, build deterministic artifacts and only
//! then complete publication. This port exposes that ordering without exposing
//! a raw publisher, claim store or storage session to the handler.

use std::{error::Error, fmt, sync::Arc};

use async_trait::async_trait;
use parth_core::{
    crypto::hash::traits::{FieldQHasher, QFieldHashable},
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::{
    proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput,
    protocol::{
        canonical_chain::NetworkId,
        chain_context::{AuthorityObservation, AuthorityScope},
    },
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
};

use super::{
    realm_user_update_claim::{
        RealmUserUpdateClaimPhase, RealmUserUpdatePublishReceiptDigest,
        StoredRealmUserUpdateClaim,
    },
    realm_user_update_artifact::{
        RealmUserUpdateContractSlots, RealmUserUpdateSlotEnvelope,
        ValidatedRealmUserUpdateArtifacts, VerifiedRealmUserUpdateRequest,
    },
    realm_user_update_publish::{
        RealmUserUpdatePublishAdmission, RealmUserUpdatePublishReceipt,
        RealmUserUpdatePublishRequest,
    },
};
use crate::store::realm_processor_startup::{
    RealmProcessorFreshRunPermit, RealmProcessorStartupPermitDigest,
};

/// Opaque, single-use authorization for installing a durable Realm Edge
/// ingress. Construction consumes the same fresh startup permit used by the
/// production storage composition and preserves its exact network/Realm scope
/// until the Handler validates it before listening.
///
/// This is an affine composition boundary, not a security boundary against
/// arbitrary trusted Rust code in the process: the port trait and startup
/// authorization API are public so tests and alternative stores can implement
/// them. Production callsite/source tests separately require that CLI startup
/// obtains this value from the Scylla composition.
///
/// A raw high-level port is not itself an installation capability:
///
/// ```compile_fail
/// use std::sync::Arc;
/// use parth_core::{PF, PHash};
/// use psy_node_core::queue::realm_user_update_ingress::{
///     RealmEdgeDurableIngressInstallation, RealmUserUpdateIngressPort,
/// };
/// let port: Arc<dyn RealmUserUpdateIngressPort<PF, PHash>> = todo!();
/// let _: RealmEdgeDurableIngressInstallation<PF, PHash> = port.into();
/// ```
///
/// The installation is affine and cannot be cloned for a second Handler:
///
/// ```compile_fail
/// use parth_core::{PF, PHash};
/// use psy_node_core::queue::realm_user_update_ingress::RealmEdgeDurableIngressInstallation;
/// fn duplicate(value: RealmEdgeDurableIngressInstallation<PF, PHash>) {
///     let _second = value.clone();
/// }
/// ```
pub struct RealmEdgeDurableIngressInstallation<F, Hash>
where
    F: QFelt64,
    Hash: Q256BitHash,
{
    ingress: Arc<dyn RealmUserUpdateIngressPort<F, Hash>>,
    permit_digest: RealmProcessorStartupPermitDigest,
    expected_network: NetworkId,
    expected_authority: AuthorityScope,
}

impl<F, Hash> RealmEdgeDurableIngressInstallation<F, Hash>
where
    F: QFelt64,
    Hash: Q256BitHash,
{
    pub fn seal_with_startup_permit(
        permit: RealmProcessorFreshRunPermit,
        ingress: Arc<dyn RealmUserUpdateIngressPort<F, Hash>>,
    ) -> Self {
        let expectation = permit.expectation();
        Self {
            ingress,
            permit_digest: permit.digest(),
            expected_network: expectation.network(),
            expected_authority: AuthorityScope::Realm {
                realm_id: expectation.realm_id(),
                realm_sub_id: expectation.realm_sub_id(),
            },
        }
    }

    pub const fn permit_digest(&self) -> RealmProcessorStartupPermitDigest {
        self.permit_digest
    }

    pub const fn expected_network(&self) -> NetworkId { self.expected_network }

    pub const fn expected_authority(&self) -> AuthorityScope {
        self.expected_authority
    }

    /// Consume the installation only for the exact Handler scope authorized
    /// by startup. A mismatch is rejected before the port can be extracted or
    /// an RPC listener can be started.
    pub fn try_into_ingress_for(
        self,
        actual_network: NetworkId,
        actual_authority: AuthorityScope,
    ) -> Result<Arc<dyn RealmUserUpdateIngressPort<F, Hash>>, RealmUserUpdateIngressError>
    {
        if actual_network != self.expected_network
            || actual_authority != self.expected_authority
        {
            return Err(RealmUserUpdateIngressError::InstallationScopeMismatch);
        }
        Ok(self.ingress)
    }
}

/// Stable authority observation surrounding all handler-side state reads.
///
/// Construction binds the observation to the exact durable admission and
/// rejects an observation change. It does not itself perform semantic state
/// validation; the Edge must execute those checks between `before` and `after`
/// and can only then hand the sealed fence to the durable ingress owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateStateFence<Hash> {
    admission: RealmUserUpdatePublishAdmission<Hash>,
    observation: AuthorityObservation<Hash>,
}

impl<Hash: Q256BitHash> RealmUserUpdateStateFence<Hash> {
    pub fn try_seal(
        admission: RealmUserUpdatePublishAdmission<Hash>,
        before: AuthorityObservation<Hash>,
        after: AuthorityObservation<Hash>,
    ) -> Result<Self, RealmUserUpdateIngressError> {
        if before != after {
            return Err(RealmUserUpdateIngressError::AuthorityObservationChanged);
        }
        if before.chain().network_id()
            != admission.pending().chain().network_id()
        {
            return Err(RealmUserUpdateIngressError::NetworkMismatch);
        }
        if before.authority() != admission.pending().authority() {
            return Err(RealmUserUpdateIngressError::AuthorityMismatch);
        }
        if before.chain() != admission.pending().chain() {
            return Err(RealmUserUpdateIngressError::BranchMismatch);
        }
        Ok(Self {
            admission,
            observation: before,
        })
    }

    pub const fn admission(&self) -> &RealmUserUpdatePublishAdmission<Hash> {
        &self.admission
    }

    pub const fn observation(&self) -> &AuthorityObservation<Hash> {
        &self.observation
    }

    pub fn into_admission(self) -> RealmUserUpdatePublishAdmission<Hash> {
        self.admission
    }
}

/// Terminal, non-authorizing result returned to the Edge after the durable
/// owner has completed all claim/dependency/NATS phases. Projection code may
/// use it as input, but downstream authority transitions must re-read Scylla.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateIngressReceipt<Hash> {
    claim: StoredRealmUserUpdateClaim<Hash>,
    publication: RealmUserUpdatePublishReceipt,
}

impl<Hash: Q256BitHash> RealmUserUpdateIngressReceipt<Hash> {
    pub fn try_from_terminal(
        claim: StoredRealmUserUpdateClaim<Hash>,
        publication: RealmUserUpdatePublishReceipt,
    ) -> Result<Self, RealmUserUpdateIngressError> {
        if claim.phase() != RealmUserUpdateClaimPhase::Published {
            return Err(RealmUserUpdateIngressError::ClaimNotPublished);
        }
        let publication_digest = RealmUserUpdatePublishReceiptDigest::try_new(
            *publication.receipt_digest(),
        )
        .map_err(|error| {
            RealmUserUpdateIngressError::MalformedTerminal(error.to_string())
        })?;
        if claim.publish_receipt_digest() != Some(publication_digest) {
            return Err(RealmUserUpdateIngressError::ReceiptMismatch);
        }
        Ok(Self { claim, publication })
    }

    pub const fn claim(&self) -> &StoredRealmUserUpdateClaim<Hash> {
        &self.claim
    }

    pub const fn publication(&self) -> &RealmUserUpdatePublishReceipt {
        &self.publication
    }
}

/// Pure artifact material returned by a backend-neutral factory after the
/// durable claim winner is known. It is non-authorizing: the ingress owner
/// still reconstructs the canonical queue payload and validates the QBlob and
/// slot envelope against the winner before any dependency write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateArtifactMaterial {
    contract_updates_qblob: Vec<u8>,
    slot_contracts: Vec<RealmUserUpdateContractSlots>,
}

impl RealmUserUpdateArtifactMaterial {
    pub fn try_new(
        contract_updates_qblob: Vec<u8>,
        slot_contracts: Vec<RealmUserUpdateContractSlots>,
    ) -> Result<Self, RealmUserUpdateIngressError> {
        if contract_updates_qblob.is_empty() {
            return Err(RealmUserUpdateIngressError::Artifact(
                "empty contract-update QBlob".to_owned(),
            ));
        }
        Ok(Self {
            contract_updates_qblob,
            slot_contracts,
        })
    }

    pub fn contract_updates_qblob(&self) -> &[u8] {
        &self.contract_updates_qblob
    }

    pub fn slot_contracts(&self) -> &[RealmUserUpdateContractSlots] {
        &self.slot_contracts
    }
}

/// Pure deterministic artifact builder injected into the storage-owned
/// ingress. Implementations have no queue or storage capability. Their output
/// is always revalidated by `seal_realm_user_update_ingress_artifacts`.
pub trait RealmUserUpdateArtifactFactory<F, Hash>: Send + Sync
where
    F: QFelt64,
    Hash: Q256BitHash,
{
    fn build(
        &self,
        claim: &StoredRealmUserUpdateClaim<Hash>,
        input: &SubmitUserEndCapNonProofInput<F, Hash>,
    ) -> Result<RealmUserUpdateArtifactMaterial, RealmUserUpdateIngressError>;
}

/// Read-only authority capability injected by the production composition.
///
/// The handler's before/after fence covers its state reads, but proof
/// verification may take long enough for the authority to advance before the
/// first claim LWT. The durable ingress therefore performs one additional
/// fresh observation after proof verification. Implementations must read the
/// same authoritative singleton used by the handler; caches and caller-
/// supplied observations are not valid implementations.
#[async_trait]
pub trait RealmAuthorityObservationReader<Hash>: Send + Sync
where
    Hash: Q256BitHash,
{
    async fn read_authority_observation(
        &self,
    ) -> Result<AuthorityObservation<Hash>, RealmUserUpdateIngressError>;
}

pub fn require_fresh_realm_authority_observation<Hash: Q256BitHash>(
    expected: &AuthorityObservation<Hash>,
    observed: &AuthorityObservation<Hash>,
) -> Result<(), RealmUserUpdateIngressError> {
    if expected == observed {
        Ok(())
    } else {
        Err(RealmUserUpdateIngressError::AuthorityObservationChanged)
    }
}

/// Build and validate the five durable artifacts from the proof-verified full
/// input, exact claim winner and pure deterministic material. Callers cannot
/// supply a queue payload, request digest, status or branch identity.
pub fn seal_realm_user_update_ingress_artifacts<F, Hash, Hasher>(
    admission: RealmUserUpdatePublishAdmission<Hash>,
    claim: &StoredRealmUserUpdateClaim<Hash>,
    verified_request: &VerifiedRealmUserUpdateRequest<F, Hash>,
    material: RealmUserUpdateArtifactMaterial,
) -> Result<ValidatedRealmUserUpdateArtifacts<Hash>, RealmUserUpdateIngressError>
where
    F: QFelt64,
    Hash: Q256BitHash + QFHashBase<F>,
    Hasher: FieldQHasher<F, Hash>,
{
    if !matches!(
        claim.phase(),
        RealmUserUpdateClaimPhase::Claimed
            | RealmUserUpdateClaimPhase::DependenciesPlanned
    )
        || claim.reconstruct_admission().map_err(|error| {
            RealmUserUpdateIngressError::Claim(error.to_string())
        })? != admission
        || claim.user_id() != verified_request.user_id()
        || claim.request_digest() != verified_request.request_digest()
    {
        return Err(RealmUserUpdateIngressError::Claim(
            "claim/admission/verified request mismatch".to_owned(),
        ));
    }
    let input = verified_request.decode_input().map_err(|error| {
        RealmUserUpdateIngressError::Artifact(error.to_string())
    })?;
    let queue_item = PsyRealmUserUpdateQueueItem {
        job_id: psy_core::job::job_id::QProvingJobDataID::try_get_realm_edge_proof_store_output_proof_id_for_end_cap(
            claim.user_id().get(),
            verified_request.global_user_tree_height().get(),
            claim.pending().unique_pending_id().get(),
        )
        .map_err(|error| RealmUserUpdateIngressError::Artifact(error.to_string()))?,
        expected_fake_checkpoint_id: claim.stable_status(),
        old_user_leaf_hash: input.core.state_transition.start_user_leaf_hash,
        new_user_leaf_hash: input.core.new_user_leaf.qfhash::<Hasher>(),
        new_user_leaf: input.core.new_user_leaf,
        stats: input.core.stats,
        events: input.events,
    };
    let publish_request = RealmUserUpdatePublishRequest::try_new(
        admission,
        claim.user_id(),
        claim.request_digest(),
        verified_request.global_user_tree_height(),
        queue_item,
    )
    .map_err(|error| RealmUserUpdateIngressError::Artifact(error.to_string()))?;
    let slot_envelope = RealmUserUpdateSlotEnvelope::try_new(
        claim.pending().clone(),
        claim.user_id(),
        material.slot_contracts,
    )
    .map_err(|error| RealmUserUpdateIngressError::Artifact(error.to_string()))?;
    ValidatedRealmUserUpdateArtifacts::try_new(
        claim,
        verified_request,
        material.contract_updates_qblob,
        slot_envelope,
        &publish_request,
    )
    .map_err(|error| RealmUserUpdateIngressError::Artifact(error.to_string()))
}

/// The only interface a branch-exact Realm Edge handler may use.
///
/// `submit_after_state_validation` deliberately accepts the typed full input
/// and proof bytes, not a caller-computed digest, queue payload, QBlob, claim,
/// timestamp or branch ID. The concrete owner must derive all of those from the
/// state fence and its durable configuration.
#[async_trait]
pub trait RealmUserUpdateIngressPort<F, Hash>: Send + Sync
where
    F: QFelt64,
    Hash: Q256BitHash,
{
    /// Read the exact authoritative head used by this ingress's post-proof
    /// freshness check. Keeping this capability on the same high-level port
    /// prevents the handler from fencing legacy and branch-exact singletons
    /// against one another.
    async fn read_authority_observation(
        &self,
    ) -> Result<AuthorityObservation<Hash>, RealmUserUpdateIngressError>;

    async fn admit(
        &self,
    ) -> Result<RealmUserUpdatePublishAdmission<Hash>, RealmUserUpdateIngressError>;

    async fn submit_after_state_validation(
        &self,
        fence: RealmUserUpdateStateFence<Hash>,
        input: SubmitUserEndCapNonProofInput<F, Hash>,
        proof: Vec<u8>,
    ) -> Result<RealmUserUpdateIngressReceipt<Hash>, RealmUserUpdateIngressError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmUserUpdateIngressError {
    AuthorityObservation(String),
    AuthorityObservationChanged,
    NetworkMismatch,
    AuthorityMismatch,
    BranchMismatch,
    InstallationScopeMismatch,
    ClaimNotPublished,
    ReceiptMismatch,
    MalformedTerminal(String),
    Admission(String),
    Proof(String),
    Claim(String),
    Artifact(String),
    Publication(String),
}

impl fmt::Display for RealmUserUpdateIngressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmUserUpdateIngressError {}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use async_trait::async_trait;
    use parth_core::{
        protocol::core_types::Q256BitHash, utils::QPGenRandom, PF, PHash,
    };
    use psy_core::job::job_id::QProvingJobDataID;
    use psy_data::{
        protocol::{
            canonical_chain::{
                CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
                CheckpointRef, NetworkId,
            },
            chain_context::{
                AuthorityScope, AuthorityStateCheckpointId,
                AuthorityStateRoot, PendingContext, WorkProcCheckpointUniqueId,
                WorkUniquePendingId,
            },
        },
        queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
    };

    use crate::{
        queue::{
            realm_user_update_claim::{
                RealmUserUpdateAdmissionOrdinal, RealmUserUpdateCreatedAtSeconds,
                RealmUserUpdateDependencyDigest,
            },
            realm_user_update_publish::{
                GlobalUserTreeHeight, RealmUserUpdatePublishRequest,
                RealmUserUpdateRequestDigest,
            },
            realm_user_update_verifier_profile::RealmUserUpdateVerifierProfileId,
            recoverable_ephemeral::PendingQueueCaptureContext,
        },
        store::{
            pending_generation_identity::{
                PendingGenerationActivationDigest, PendingGenerationContext,
                PendingGenerationLedgerKey,
            },
            typed::UserId,
            realm_processor_startup::{
                authorize_realm_processor_startup,
                RealmProcessorStartupAuthorization,
                RealmProcessorStartupError,
                RealmProcessorStartupEvidence,
                RealmProcessorStartupExpectation,
                RealmProcessorStartupMode,
                RealmProcessorStartupPreflightProvider,
                RealmProcessorStartupRouteObservation,
                RealmProcessorStartupRoutePhase,
            },
        },
    };

    use super::*;

    struct NeverCalledIngress;

    #[async_trait]
    impl RealmUserUpdateIngressPort<PF, PHash> for NeverCalledIngress {
        async fn read_authority_observation(
            &self,
        ) -> Result<AuthorityObservation<PHash>, RealmUserUpdateIngressError> {
            Err(RealmUserUpdateIngressError::AuthorityObservation(
                "not called".to_owned(),
            ))
        }

        async fn admit(
            &self,
        ) -> Result<RealmUserUpdatePublishAdmission<PHash>, RealmUserUpdateIngressError>
        {
            Err(RealmUserUpdateIngressError::Admission(
                "not called".to_owned(),
            ))
        }

        async fn submit_after_state_validation(
            &self,
            _fence: RealmUserUpdateStateFence<PHash>,
            _input: SubmitUserEndCapNonProofInput<PF, PHash>,
            _proof: Vec<u8>,
        ) -> Result<RealmUserUpdateIngressReceipt<PHash>, RealmUserUpdateIngressError>
        {
            Err(RealmUserUpdateIngressError::Proof(
                "not called".to_owned(),
            ))
        }
    }

    struct StableStartupProvider {
        calls: AtomicUsize,
        evidence: RealmProcessorStartupEvidence,
    }

    #[async_trait]
    impl RealmProcessorStartupPreflightProvider for StableStartupProvider {
        async fn fresh_read(
            &self,
            _expectation: RealmProcessorStartupExpectation,
        ) -> Result<RealmProcessorStartupEvidence, RealmProcessorStartupError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.evidence)
        }
    }

    async fn fresh_startup_permit(
    ) -> crate::store::realm_processor_startup::RealmProcessorFreshRunPermit {
        let network = NetworkId::try_from_chain_id(1337).unwrap();
        let expectation = RealmProcessorStartupExpectation::try_new(
            network, 7, 2, 11, [1; 32], [2; 32], [3; 32],
        )
        .unwrap();
        let route = RealmProcessorStartupRouteObservation::try_new(
            11,
            4,
            [1; 32],
            [5; 32],
            RealmProcessorStartupRoutePhase::LegacyPrimaryDualWrite,
        )
        .unwrap();
        let provider = StableStartupProvider {
            calls: AtomicUsize::new(0),
            evidence: RealmProcessorStartupEvidence::try_new(
                network,
                7,
                2,
                route,
                route,
                [2; 32],
                [6; 32],
                [7; 32],
            )
            .unwrap(),
        };
        let RealmProcessorStartupAuthorization::BranchExact(permit) =
            authorize_realm_processor_startup(
                RealmProcessorStartupMode::RequireBranchExact(expectation),
                Some(&provider),
            )
            .await
            .unwrap()
        else {
            panic!("expected branch-exact permit")
        };
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        permit
    }

    #[tokio::test]
    async fn installation_consumes_fresh_permit_and_preserves_exact_port() {
        let permit = fresh_startup_permit().await;
        let expected_digest = permit.digest();
        let expected_network = permit.expectation().network();
        let expected_authority = AuthorityScope::Realm {
            realm_id: permit.expectation().realm_id(),
            realm_sub_id: permit.expectation().realm_sub_id(),
        };
        let concrete = Arc::new(NeverCalledIngress);
        let port: Arc<dyn RealmUserUpdateIngressPort<PF, PHash>> = concrete;
        let expected_port = Arc::clone(&port);
        let installation =
            RealmEdgeDurableIngressInstallation::seal_with_startup_permit(
                permit, port,
            );
        assert_eq!(installation.permit_digest(), expected_digest);
        assert_eq!(installation.expected_network(), expected_network);
        assert_eq!(installation.expected_authority(), expected_authority);
        let installed = installation
            .try_into_ingress_for(expected_network, expected_authority)
            .unwrap();
        assert!(Arc::ptr_eq(&installed, &expected_port));
    }

    #[tokio::test]
    async fn installation_rejects_wrong_handler_scope_before_port_extraction() {
        let permit = fresh_startup_permit().await;
        let expected_network = permit.expectation().network();
        let concrete = Arc::new(NeverCalledIngress);
        let port: Arc<dyn RealmUserUpdateIngressPort<PF, PHash>> = concrete;
        let installation =
            RealmEdgeDurableIngressInstallation::seal_with_startup_permit(
                permit, port,
            );
        assert!(matches!(
            installation.try_into_ingress_for(
                expected_network,
                AuthorityScope::Realm {
                    realm_id: 8,
                    realm_sub_id: 2,
                },
            ),
            Err(RealmUserUpdateIngressError::InstallationScopeMismatch)
        ));
    }

    #[test]
    fn installation_is_affine_and_preserves_permit_scope() {
        let source = include_str!("realm_user_update_ingress.rs");
        let installation = source
            .split("pub struct RealmEdgeDurableIngressInstallation")
            .nth(1)
            .unwrap()
            .split("/// Stable authority observation")
            .next()
            .unwrap();
        assert!(installation.contains("permit: RealmProcessorFreshRunPermit"));
        assert!(!installation.contains("impl Clone"));
        assert!(!installation.contains("impl Copy"));
        assert!(!installation.contains("impl Default"));
        assert!(!installation.contains("From<Arc<dyn RealmUserUpdateIngressPort"));
        assert!(!installation.contains("pub fn new("));
        assert!(!installation.contains("pub fn try_new("));
        assert!(installation.contains("expected_network:"));
        assert!(installation.contains("expected_authority:"));
        assert!(installation.contains("try_into_ingress_for"));
        assert!(installation.contains("InstallationScopeMismatch"));
    }

    fn chain(
        network: u32,
        epoch: u64,
        checkpoint: u64,
        hash_byte: u8,
    ) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(network).unwrap(),
            ChainEpoch::new(epoch),
            CheckpointRef::new(
                CheckpointId::new(checkpoint),
                CheckpointHash::from_last_chain_hash(PHash::from_owned_32bytes([
                    hash_byte;
                    32
                ])),
            ),
        )
    }

    fn pending(
        branch: CanonicalChainRef<PHash>,
        authority: AuthorityScope,
    ) -> PendingContext<PHash> {
        PendingContext::new(
            branch,
            authority,
            WorkUniquePendingId::new(11),
            WorkProcCheckpointUniqueId::from_u128(12),
        )
    }

    fn admission(
        branch: CanonicalChainRef<PHash>,
        authority: AuthorityScope,
    ) -> RealmUserUpdatePublishAdmission<PHash> {
        let pending = pending(branch, authority);
        RealmUserUpdatePublishAdmission::try_from_pipeline(
            pending.clone(),
            PendingQueueCaptureContext::try_new(
                PendingGenerationLedgerKey::new(
                    pending.chain().network_id(),
                    pending.authority(),
                ),
                PendingGenerationActivationDigest::try_new([9; 32]).unwrap(),
                PendingGenerationContext::try_from_legacy(11, 12).unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn observation(
        branch: CanonicalChainRef<PHash>,
        authority: AuthorityScope,
        root_byte: u8,
    ) -> AuthorityObservation<PHash> {
        let checkpoint = branch.checkpoint().checkpoint_id().get();
        AuthorityObservation::try_new(
            branch,
            authority,
            AuthorityStateCheckpointId::new(checkpoint),
            AuthorityStateRoot::from_local_state_root(PHash::from_owned_32bytes([
                root_byte;
                32
            ])),
        )
        .unwrap()
    }

    fn terminal_pair() -> (
        StoredRealmUserUpdateClaim<PHash>,
        RealmUserUpdatePublishReceipt,
    ) {
        let authority = AuthorityScope::Realm {
            realm_id: 7,
            realm_sub_id: 2,
        };
        let admission = admission(chain(1337, 1, 10, 3), authority);
        let digest = RealmUserUpdateRequestDigest::derive(b"input", b"proof").unwrap();
        let user_id = UserId::new(13);
        let mut item = PsyRealmUserUpdateQueueItem::<PF, PHash>::qp_rand_gen();
        item.job_id = QProvingJobDataID::try_get_realm_edge_proof_store_output_proof_id_for_end_cap(
            user_id.get(),
            32,
            11,
        )
        .unwrap();
        item.expected_fake_checkpoint_id = digest.stable_status();
        let request = RealmUserUpdatePublishRequest::try_new(
            admission.clone(),
            user_id,
            digest,
            GlobalUserTreeHeight::try_new(32).unwrap(),
            item,
        )
        .unwrap();
        let publication = RealmUserUpdatePublishReceipt::durable(
            request.intent_id(),
            [5; 32],
            1,
            [6; 32],
            false,
        )
        .unwrap();
        let claimed = StoredRealmUserUpdateClaim::claimed(
            admission,
            RealmUserUpdateVerifierProfileId::try_from_persisted([7; 32])
                .unwrap(),
            user_id,
            digest,
            RealmUserUpdateCreatedAtSeconds::try_new(8).unwrap(),
            RealmUserUpdateAdmissionOrdinal::try_new(1).unwrap(),
        )
        .unwrap();
        let planned = StoredRealmUserUpdateClaim::dependencies_planned(
            &claimed,
            RealmUserUpdateDependencyDigest::try_new([4; 32]).unwrap(),
        )
        .unwrap();
        let ready = StoredRealmUserUpdateClaim::dependencies_ready(&planned).unwrap();
        let receipt_digest = RealmUserUpdatePublishReceiptDigest::try_new(
            *publication.receipt_digest(),
        )
        .unwrap();
        (
            StoredRealmUserUpdateClaim::published(&ready, receipt_digest).unwrap(),
            publication,
        )
    }

    #[test]
    fn state_fence_is_exact_branch_scope_and_observation_stable() {
        let authority = AuthorityScope::Realm {
            realm_id: 7,
            realm_sub_id: 2,
        };
        let branch = chain(1337, 1, 10, 3);
        let admission = admission(branch.clone(), authority);
        let stable = observation(branch.clone(), authority, 4);
        let fence = RealmUserUpdateStateFence::try_seal(
            admission.clone(),
            stable.clone(),
            stable.clone(),
        )
        .unwrap();
        assert_eq!(fence.admission(), &admission);
        assert_eq!(fence.observation(), &stable);

        let changed = observation(branch.clone(), authority, 5);
        assert_eq!(
            RealmUserUpdateStateFence::try_seal(
                admission.clone(),
                stable.clone(),
                changed,
            ),
            Err(RealmUserUpdateIngressError::AuthorityObservationChanged)
        );
        let foreign_branch = chain(1337, 2, 10, 9);
        let foreign = observation(foreign_branch, authority, 4);
        assert_eq!(
            RealmUserUpdateStateFence::try_seal(
                admission.clone(),
                foreign.clone(),
                foreign,
            ),
            Err(RealmUserUpdateIngressError::BranchMismatch)
        );
        let foreign_authority = AuthorityScope::Realm {
            realm_id: 8,
            realm_sub_id: 2,
        };
        let foreign = observation(branch, foreign_authority, 4);
        assert_eq!(
            RealmUserUpdateStateFence::try_seal(
                admission,
                foreign.clone(),
                foreign,
            ),
            Err(RealmUserUpdateIngressError::AuthorityMismatch)
        );
    }

    #[test]
    fn post_proof_observation_must_remain_bit_exact() {
        let authority = AuthorityScope::Realm {
            realm_id: 7,
            realm_sub_id: 2,
        };
        let branch = chain(1337, 1, 10, 3);
        let expected = observation(branch.clone(), authority, 4);
        assert_eq!(
            require_fresh_realm_authority_observation(&expected, &expected),
            Ok(())
        );

        let advanced_state = observation(branch.clone(), authority, 5);
        assert_eq!(
            require_fresh_realm_authority_observation(
                &expected,
                &advanced_state,
            ),
            Err(RealmUserUpdateIngressError::AuthorityObservationChanged)
        );
        let new_epoch = observation(chain(1337, 2, 10, 9), authority, 4);
        assert_eq!(
            require_fresh_realm_authority_observation(&expected, &new_epoch),
            Err(RealmUserUpdateIngressError::AuthorityObservationChanged)
        );
    }

    #[test]
    fn ingress_receipt_requires_exact_published_claim_receipt() {
        let (published, publication) = terminal_pair();
        let receipt = RealmUserUpdateIngressReceipt::try_from_terminal(
            published.clone(),
            publication.clone(),
        )
        .unwrap();
        assert_eq!(receipt.claim(), &published);
        assert_eq!(receipt.publication(), &publication);

        let foreign = RealmUserUpdatePublishReceipt::durable(
            publication.intent_id(),
            [8; 32],
            2,
            [9; 32],
            false,
        )
        .unwrap();
        assert_eq!(
            RealmUserUpdateIngressReceipt::try_from_terminal(
                published,
                foreign,
            ),
            Err(RealmUserUpdateIngressError::ReceiptMismatch)
        );
    }

    #[test]
    fn high_level_port_does_not_accept_low_level_authority_inputs() {
        let source = include_str!("realm_user_update_ingress.rs");
        let port = source
            .split("pub trait RealmUserUpdateIngressPort")
            .nth(1)
            .unwrap()
            .split("#[derive(Clone, Debug, Eq, PartialEq)]")
            .next()
            .unwrap();
        for forbidden in [
            "RealmUserUpdateRequestDigest",
            "RealmUserUpdatePublishRequest",
            "ValidatedRealmUserUpdateArtifacts",
            "StoredRealmUserUpdateClaim",
            "created_at",
            "timestamp",
            "Session",
        ] {
            assert!(
                !port.contains(forbidden),
                "high-level ingress leaked caller authority {forbidden}"
            );
        }
        assert!(port.contains("RealmUserUpdateStateFence<Hash>"));
        assert!(port.contains("SubmitUserEndCapNonProofInput<F, Hash>"));
        assert!(port.contains("proof: Vec<u8>"));
        assert!(port.contains("read_authority_observation"));
    }

    #[test]
    fn fence_fields_and_terminal_receipt_are_not_publicly_replaceable() {
        let source = include_str!("realm_user_update_ingress.rs");
        let fence = source
            .split("pub struct RealmUserUpdateStateFence")
            .nth(1)
            .unwrap()
            .split("impl<Hash: Q256BitHash>")
            .next()
            .unwrap();
        assert!(!fence.contains("pub admission:"));
        assert!(!fence.contains("pub observation:"));

        let receipt = source
            .split("pub struct RealmUserUpdateIngressReceipt")
            .nth(1)
            .unwrap()
            .split("impl<Hash: Q256BitHash>")
            .next()
            .unwrap();
        assert!(!receipt.contains("pub claim:"));
        assert!(!receipt.contains("pub publication:"));
        let fence_default = ["impl Default for RealmUserUpdate", "StateFence"].concat();
        let receipt_default =
            ["impl Default for RealmUserUpdate", "IngressReceipt"].concat();
        assert!(!source.contains(&fence_default));
        assert!(!source.contains(&receipt_default));
    }
}
