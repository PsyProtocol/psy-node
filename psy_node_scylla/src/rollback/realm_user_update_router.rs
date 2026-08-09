//! Combined durable Realm user-update router.
//!
//! The router is deliberately crate-private and default-off. It is the only
//! component allowed to compose the claim LWT, immutable dependency readback,
//! and concrete Scylla/NATS publication permit. Production Edge callsites are
//! wired in a later milestone.

use std::{error::Error, fmt, marker::PhantomData, sync::Arc};

use parth_core::{
    crypto::hash::traits::FieldQHasher,
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::{
    queue::{
        realm_user_update_admission::{
            RealmUserUpdateAdmissionCloseIntent,
            RealmUserUpdateAdmissionKey,
            RealmUserUpdateGenerationQualification,
            RealmUserUpdateQualificationFence,
            RealmUserUpdateTerminalEvidence,
        },
        realm_user_update_artifact::{
            rehydrate_realm_user_update_artifacts,
            ValidatedRealmUserUpdateArtifacts, VerifiedRealmUserUpdateProof,
            VerifiedRealmUserUpdateRequest,
        },
        realm_user_update_claim::{
            RealmUserUpdateClaimPartition, RealmUserUpdateClaimPhase,
            RealmUserUpdateCreatedAtSeconds,
            RealmUserUpdatePublishReceiptDigest, StoredRealmUserUpdateClaim,
        },
        realm_user_update_dependency::RealmUserUpdateDependencyBundle,
        realm_user_update_publish::{
            GlobalUserTreeHeight, RealmUserUpdatePublishAdmission,
            RealmUserUpdatePublishPort, RealmUserUpdatePublishReceipt,
            RealmUserUpdatePublishRequest,
        },
    },
    store::typed::UserId,
};
use psy_node_nats::{
    recoverable_segment::RecoverableNatsStreamSegment,
    recoverable_transport::RecoverablePendingQueueNatsPublisher,
};
use scylla::client::session::Session;

use super::{
    BranchExactDeploymentNoTabletKeyspace, PendingQueueArtifactDataKeyspace,
    PendingQueueSidecarReady, RealmUserUpdateClaimReadState,
    RealmUserUpdateClaimWriteOutcome, ScyllaRealmEdgeDurablePublisher,
    ScyllaRealmUserUpdateAdmissionGuard, ScyllaRealmUserUpdateAdmissionStore,
    ScyllaRealmUserUpdateClaimStore, ScyllaRealmUserUpdateDependencyStore,
    PersistedRealmUserUpdateGenerationQualifiedReceipt,
    RealmUserUpdateQualificationInput,
};

const MAX_PHASE_STEPS: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RealmUserUpdateRouterReceipt<Hash> {
    claim: StoredRealmUserUpdateClaim<Hash>,
    publication: RealmUserUpdatePublishReceipt,
}

impl<Hash> RealmUserUpdateRouterReceipt<Hash> {
    pub(crate) const fn claim(&self) -> &StoredRealmUserUpdateClaim<Hash> {
        &self.claim
    }

    pub(crate) const fn publication(&self) -> &RealmUserUpdatePublishReceipt {
        &self.publication
    }

}

pub(crate) struct ScyllaRealmUserUpdateDurableRouter<F, Hash, Hasher> {
    network: NetworkId,
    authority: AuthorityScope,
    global_user_tree_height: GlobalUserTreeHeight,
    realm_user_tree_height: u8,
    claims: Arc<ScyllaRealmUserUpdateClaimStore>,
    admission_guard: ScyllaRealmUserUpdateAdmissionGuard,
    dependencies: ScyllaRealmUserUpdateDependencyStore,
    publisher: ScyllaRealmEdgeDurablePublisher<F, Hash>,
    _hasher: PhantomData<Hasher>,
}

impl<F, Hash, Hasher> ScyllaRealmUserUpdateDurableRouter<F, Hash, Hasher>
where
    F: QFelt64 + Send + Sync,
    Hash: Q256BitHash + QFHashBase<F>,
    Hasher: FieldQHasher<F, Hash>,
{
    pub(crate) async fn prepare(
        session: Arc<Session>,
        network: NetworkId,
        authority: AuthorityScope,
        global_user_tree_height: GlobalUserTreeHeight,
        realm_user_tree_height: u8,
        ready: Arc<PendingQueueSidecarReady>,
        nats: Arc<RecoverablePendingQueueNatsPublisher>,
        segment: RecoverableNatsStreamSegment,
    ) -> Result<Self, RealmUserUpdateRouterError> {
        if !matches!(authority, AuthorityScope::Realm { .. })
            || realm_user_tree_height >= 64
        {
            return Err(RealmUserUpdateRouterError::InvalidUserRange);
        }
        let keyspaces = ready
            .view()
            .verified()
            .stored()
            .keyspaces()
            .clone();
        let control = BranchExactDeploymentNoTabletKeyspace::try_new(
            keyspaces.control().as_str().to_owned(),
        )
        .map_err(router)?;
        let data = PendingQueueArtifactDataKeyspace::try_new(
            keyspaces.data().as_str().to_owned(),
        )
        .map_err(router)?;
        let claims = Arc::new(ScyllaRealmUserUpdateClaimStore::prepare(
            session.clone(),
            control.clone(),
        )
        .await
        .map_err(router)?);
        let admission_gates = Arc::new(
            ScyllaRealmUserUpdateAdmissionStore::prepare(
                session.clone(),
                control,
            )
            .await
            .map_err(router)?,
        );
        let admission_guard = ScyllaRealmUserUpdateAdmissionGuard::new(
            admission_gates,
            claims.clone(),
        );
        let dependencies = ScyllaRealmUserUpdateDependencyStore::prepare(
            session.clone(),
            data,
        )
        .await
        .map_err(router)?;
        let publisher = ScyllaRealmEdgeDurablePublisher::prepare(
            session,
            network,
            authority,
            ready,
            nats,
            segment,
        )
        .await
        .map_err(router)?;
        Ok(Self {
            network,
            authority,
            global_user_tree_height,
            realm_user_tree_height,
            claims,
            admission_guard,
            dependencies,
            publisher,
            _hasher: PhantomData,
        })
    }

    /// Capture the exact gathering generation before proof/state work. The
    /// caller must then verify and seal a UserEndCap request before claiming.
    pub(crate) async fn admit(
        &self,
    ) -> Result<RealmUserUpdatePublishAdmission<Hash>, RealmUserUpdateRouterError> {
        self.publisher.admit().await.map_err(router)
    }

    /// Qualify one exact, already-closed gathering generation. This path is
    /// read-only until the final full-payload header CAS and never performs a
    /// new NATS publish. Every claim must already be Published and recover an
    /// exact historical SourceCommitted permit.
    pub(crate) async fn qualify_generation(
        &self,
        key: RealmUserUpdateAdmissionKey,
        close: RealmUserUpdateAdmissionCloseIntent,
    ) -> Result<
        PersistedRealmUserUpdateGenerationQualifiedReceipt<Hash>,
        RealmUserUpdateRouterError,
    > {
        if key.capture().key().network() != self.network
            || key.capture().key().authority() != self.authority
        {
            return Err(RealmUserUpdateRouterError::ScopeMismatch);
        }
        let input = self
            .admission_guard
            .qualification_input::<Hash>(key, close)
            .await
            .map_err(router)?;
        if let RealmUserUpdateQualificationInput::Qualified(receipt) = input {
            let pipeline = self
                .publisher
                .qualification_pipeline(key.capture())
                .await
                .map_err(router)?;
            receipt.revalidate_pipeline(&pipeline).map_err(router)?;
            return Ok(receipt);
        }
        let RealmUserUpdateQualificationInput::Closed(closed) = input else {
            unreachable!("qualified input returned above")
        };

        let total = closed.claims().len();
        let terminal = closed
            .claims()
            .iter()
            .filter(|claim| {
                claim.phase() == RealmUserUpdateClaimPhase::Published
                    && claim.dependency_digest().is_some()
                    && claim.publish_receipt_digest().is_some()
            })
            .count();
        if terminal != total {
            return Err(RealmUserUpdateRouterError::AwaitTerminalClaims {
                terminal,
                total,
            });
        }

        let pipeline = self
            .publisher
            .qualification_pipeline(key.capture())
            .await
            .map_err(router)?;
        let fence = RealmUserUpdateQualificationFence::try_from_pipeline(
            key,
            &pipeline,
        )
        .map_err(router)?;
        let mut evidence = Vec::with_capacity(total);
        for claim in closed.claims() {
            self.validate_claim_scope(claim)?;
            let bundle = self.read_dependencies(claim).await?;
            let request = RealmUserUpdatePublishRequest::try_from_persisted_dependencies(
                claim,
                &bundle,
                self.global_user_tree_height,
            )
            .map_err(router)?;
            let permit = self
                .publisher
                .observe_authorized(request.clone())
                .await
                .map_err(router)?
                .ok_or(RealmUserUpdateRouterError::TerminalSourceMissing)?;
            evidence.push(
                RealmUserUpdateTerminalEvidence::try_from_observed(
                    key,
                    &fence,
                    claim,
                    &request,
                    permit.receipt(),
                )
                .map_err(router)?,
            );
        }
        let membership = closed
            .header()
            .generation_manifest()
            .ok_or(RealmUserUpdateRouterError::QualificationConflict)?;
        let qualification = RealmUserUpdateGenerationQualification::from_terminal_evidence(
            key,
            close,
            membership,
            fence,
            &evidence,
        )
        .map_err(router)?;

        // A long 256-bucket/source scan never authorizes a stale frontier.
        let fresh = self
            .publisher
            .qualification_pipeline(key.capture())
            .await
            .map_err(router)?;
        if !qualification.fence().matches_pipeline(key, &fresh) {
            return Err(RealmUserUpdateRouterError::QualificationConflict);
        }
        self.admission_guard
            .persist_qualification(closed, qualification)
            .await
            .map_err(router)
    }

    /// Win or resume the exact already-verified request claim. Invalid proof
    /// bytes cannot reach the LWT. The returned winner is the only metadata
    /// that may be used to build deterministic QBlob/slot artifacts.
    pub(crate) async fn claim(
        &self,
        admission: RealmUserUpdatePublishAdmission<Hash>,
        verified_request: &VerifiedRealmUserUpdateRequest<F, Hash>,
        created_at: RealmUserUpdateCreatedAtSeconds,
    ) -> Result<StoredRealmUserUpdateClaim<Hash>, RealmUserUpdateRouterError> {
        let user_id = verified_request.user_id();
        self.validate_user(user_id)?;
        if let Some(current) = self
            .admission_guard
            .resume_existing(
                admission.clone(),
                user_id,
                verified_request.request_digest(),
                created_at,
            )
            .await
            .map_err(router)?
        {
            self.validate_claim_scope(&current)?;
            return Ok(current);
        }
        self.publisher
            .revalidate_admission(&admission)
            .await
            .map_err(router)?;
        let current = self
            .admission_guard
            .claim(
                admission,
                user_id,
                verified_request.request_digest(),
                created_at,
            )
            .await
            .map_err(router)?;
        self.validate_claim_scope(&current)?;
        Ok(current)
    }

    /// Complete a live request whose five artifacts were validated against the
    /// winner returned by [`Self::claim`].
    pub(crate) async fn complete_live(
        &self,
        winner: &StoredRealmUserUpdateClaim<Hash>,
        artifacts: &ValidatedRealmUserUpdateArtifacts<Hash>,
    ) -> Result<RealmUserUpdateRouterReceipt<Hash>, RealmUserUpdateRouterError> {
        let mut current = self.read_same_request(winner).await?;
        let bundle = RealmUserUpdateDependencyBundle::try_new_validated(
            &current,
            artifacts,
        )
        .map_err(router)?;
        for _ in 0..MAX_PHASE_STEPS {
            current = match current.phase() {
                RealmUserUpdateClaimPhase::Claimed => {
                    let candidate = StoredRealmUserUpdateClaim::dependencies_planned(
                        &current,
                        bundle.digest(),
                    )
                    .map_err(router)?;
                    self.advance_claim(&current, &candidate).await?
                }
                RealmUserUpdateClaimPhase::DependenciesPlanned => {
                    if current.dependency_digest() != Some(bundle.digest()) {
                        return Err(RealmUserUpdateRouterError::DependencyConflict);
                    }
                    let persisted = self
                        .dependencies
                        .persist_and_readback(&bundle)
                        .await
                        .map_err(router)?;
                    if persisted != bundle.digest() {
                        return Err(RealmUserUpdateRouterError::DependencyConflict);
                    }
                    let candidate =
                        StoredRealmUserUpdateClaim::dependencies_ready(&current)
                            .map_err(router)?;
                    self.advance_claim(&current, &candidate).await?
                }
                RealmUserUpdateClaimPhase::DependenciesReady => {
                    let persisted = self.read_dependencies(&current).await?;
                    if persisted != bundle {
                        return Err(RealmUserUpdateRouterError::DependencyConflict);
                    }
                    return self
                        .publish_and_finish(
                            current,
                            persisted,
                            self.global_user_tree_height,
                        )
                        .await;
                }
                RealmUserUpdateClaimPhase::Published => {
                    let persisted = self.read_dependencies(&current).await?;
                    if persisted != bundle {
                        return Err(RealmUserUpdateRouterError::DependencyConflict);
                    }
                    return self
                        .observe_terminal(
                            current,
                            persisted,
                            self.global_user_tree_height,
                        )
                        .await;
                }
            };
        }
        Err(RealmUserUpdateRouterError::PhaseStepLimit)
    }

    /// Resume one already-known claim coordinate. This performs semantic
    /// revalidation with a concrete verifier receipt. Discovery/scanning of
    /// claim coordinates is intentionally left to the next milestone.
    pub(crate) async fn resume_exact(
        &self,
        partition: RealmUserUpdateClaimPartition,
        user_id: UserId,
        verified_proof: VerifiedRealmUserUpdateProof<Hash>,
    ) -> Result<RealmUserUpdateRouterReceipt<Hash>, RealmUserUpdateRouterError> {
        self.validate_user(user_id)?;
        let RealmUserUpdateClaimReadState::Current(mut current) = self
            .claims
            .read(partition, user_id)
            .await
            .map_err(router)?
        else {
            return Err(RealmUserUpdateRouterError::Uninitialized);
        };
        self.validate_claim_scope(&current)?;
        if current.phase() == RealmUserUpdateClaimPhase::Claimed {
            return Err(RealmUserUpdateRouterError::AwaitExactRequestReplay);
        }
        if current.phase() == RealmUserUpdateClaimPhase::DependenciesPlanned {
            let persisted = self.read_dependencies(&current).await?;
            let candidate = StoredRealmUserUpdateClaim::dependencies_ready(&current)
                .map_err(router)?;
            current = self.advance_claim(&current, &candidate).await?;
            if current.dependency_digest() != Some(persisted.digest()) {
                return Err(RealmUserUpdateRouterError::DependencyConflict);
            }
        }
        let persisted = self.read_dependencies(&current).await?;
        let rehydrated = rehydrate_realm_user_update_artifacts::<F, Hash, Hasher>(
            &current,
            &persisted,
            verified_proof,
            self.global_user_tree_height,
        )
        .map_err(router)?;
        if rehydrated.artifacts().request_digest() != current.request_digest() {
            return Err(RealmUserUpdateRouterError::DependencyConflict);
        }
        match current.phase() {
            RealmUserUpdateClaimPhase::DependenciesReady => {
                self.publish_request_and_finish(
                    current,
                    rehydrated.into_publish_request(),
                )
                .await
            }
            RealmUserUpdateClaimPhase::Published => {
                self.observe_request_terminal(
                    current,
                    rehydrated.into_publish_request(),
                )
                .await
            }
            RealmUserUpdateClaimPhase::Claimed
            | RealmUserUpdateClaimPhase::DependenciesPlanned => {
                Err(RealmUserUpdateRouterError::InvalidPhase)
            }
        }
    }

    async fn publish_and_finish(
        &self,
        current: StoredRealmUserUpdateClaim<Hash>,
        bundle: RealmUserUpdateDependencyBundle,
        height: GlobalUserTreeHeight,
    ) -> Result<RealmUserUpdateRouterReceipt<Hash>, RealmUserUpdateRouterError> {
        let request = RealmUserUpdatePublishRequest::try_from_dependencies_ready(
            &current,
            &bundle,
            height,
        )
        .map_err(router)?;
        self.publish_request_and_finish(current, request).await
    }

    async fn publish_request_and_finish(
        &self,
        current: StoredRealmUserUpdateClaim<Hash>,
        request: RealmUserUpdatePublishRequest<F, Hash>,
    ) -> Result<RealmUserUpdateRouterReceipt<Hash>, RealmUserUpdateRouterError> {
        let permit = match self
            .publisher
            .observe_authorized(request.clone())
            .await
            .map_err(router)?
        {
            Some(committed) => committed,
            None => self
                .publisher
                .publish_authorized(request)
                .await
                .map_err(router)?,
        };
        let receipt_digest = RealmUserUpdatePublishReceiptDigest::try_new(
            *permit.receipt().receipt_digest(),
        )
        .map_err(router)?;
        let candidate = StoredRealmUserUpdateClaim::published(
            &current,
            receipt_digest,
        )
        .map_err(router)?;
        let terminal = self.advance_claim(&current, &candidate).await?;
        if terminal != candidate {
            return self
                .observe_terminal_from_claim(terminal, permit.receipt().clone())
                .await;
        }
        Ok(RealmUserUpdateRouterReceipt {
            claim: terminal,
            publication: permit.receipt().clone(),
        })
    }

    async fn observe_terminal(
        &self,
        current: StoredRealmUserUpdateClaim<Hash>,
        bundle: RealmUserUpdateDependencyBundle,
        height: GlobalUserTreeHeight,
    ) -> Result<RealmUserUpdateRouterReceipt<Hash>, RealmUserUpdateRouterError> {
        let request = RealmUserUpdatePublishRequest::try_from_persisted_dependencies(
            &current,
            &bundle,
            height,
        )
        .map_err(router)?;
        self.observe_request_terminal(current, request).await
    }

    async fn observe_request_terminal(
        &self,
        current: StoredRealmUserUpdateClaim<Hash>,
        request: RealmUserUpdatePublishRequest<F, Hash>,
    ) -> Result<RealmUserUpdateRouterReceipt<Hash>, RealmUserUpdateRouterError> {
        let permit = self
            .publisher
            .observe_authorized(request)
            .await
            .map_err(router)?
            .ok_or(RealmUserUpdateRouterError::TerminalEvidenceMismatch)?;
        self.observe_terminal_from_claim(current, permit.receipt().clone())
            .await
    }

    async fn observe_terminal_from_claim(
        &self,
        current: StoredRealmUserUpdateClaim<Hash>,
        receipt: RealmUserUpdatePublishReceipt,
    ) -> Result<RealmUserUpdateRouterReceipt<Hash>, RealmUserUpdateRouterError> {
        if current.phase() != RealmUserUpdateClaimPhase::Published
            || current.publish_receipt_digest().map(|value| *value.as_bytes())
                != Some(*receipt.receipt_digest())
        {
            return Err(RealmUserUpdateRouterError::TerminalEvidenceMismatch);
        }
        Ok(RealmUserUpdateRouterReceipt {
            claim: current,
            publication: receipt,
        })
    }

    async fn read_same_request(
        &self,
        expected: &StoredRealmUserUpdateClaim<Hash>,
    ) -> Result<StoredRealmUserUpdateClaim<Hash>, RealmUserUpdateRouterError> {
        let RealmUserUpdateClaimReadState::Current(current) = self
            .claims
            .read(expected.partition().map_err(router)?, expected.user_id())
            .await
            .map_err(router)?
        else {
            return Err(RealmUserUpdateRouterError::Uninitialized);
        };
        if !current.same_request_as(expected) {
            return Err(RealmUserUpdateRouterError::ClaimConflict {
                current_phase: current.phase(),
                current_revision: current.revision().get(),
            });
        }
        self.validate_claim_scope(&current)?;
        Ok(current)
    }

    async fn read_dependencies(
        &self,
        claim: &StoredRealmUserUpdateClaim<Hash>,
    ) -> Result<RealmUserUpdateDependencyBundle, RealmUserUpdateRouterError> {
        let digest = claim
            .dependency_digest()
            .ok_or(RealmUserUpdateRouterError::DependencyMissing)?;
        self.dependencies
            .read_bundle(
                claim.slot(),
                *claim.request_digest().as_bytes(),
                claim.stable_status(),
                claim.created_at().get(),
                digest,
            )
            .await
            .map_err(router)
    }

    async fn advance_claim(
        &self,
        expected: &StoredRealmUserUpdateClaim<Hash>,
        candidate: &StoredRealmUserUpdateClaim<Hash>,
    ) -> Result<StoredRealmUserUpdateClaim<Hash>, RealmUserUpdateRouterError> {
        match self
            .claims
            .compare_and_set(expected, candidate)
            .await
            .map_err(router)?
        {
            RealmUserUpdateClaimWriteOutcome::Applied(receipt)
            | RealmUserUpdateClaimWriteOutcome::Resumed(receipt) => {
                if receipt.current() != candidate {
                    return Err(RealmUserUpdateRouterError::TransitionConflict);
                }
                Ok(receipt.current().clone())
            }
            RealmUserUpdateClaimWriteOutcome::Conflict(current)
                if current.same_request_as(candidate)
                    && current.revision().get() >= candidate.revision().get()
                    && current.dependency_digest() == candidate.dependency_digest() =>
            {
                Ok(current)
            }
            RealmUserUpdateClaimWriteOutcome::Conflict(_) => {
                Err(RealmUserUpdateRouterError::TransitionConflict)
            }
        }
    }

    fn validate_user(&self, user_id: UserId) -> Result<(), RealmUserUpdateRouterError> {
        let AuthorityScope::Realm { realm_id, .. } = self.authority else {
            return Err(RealmUserUpdateRouterError::InvalidUserRange);
        };
        let users_per_realm = 1u64
            .checked_shl(u32::from(self.realm_user_tree_height))
            .ok_or(RealmUserUpdateRouterError::InvalidUserRange)?;
        let first = u64::from(realm_id)
            .checked_mul(users_per_realm)
            .ok_or(RealmUserUpdateRouterError::InvalidUserRange)?;
        let end = first
            .checked_add(users_per_realm)
            .ok_or(RealmUserUpdateRouterError::InvalidUserRange)?;
        if u32::try_from(user_id.get()).is_err()
            || user_id.get() < first
            || user_id.get() >= end
        {
            return Err(RealmUserUpdateRouterError::InvalidUserRange);
        }
        Ok(())
    }

    fn validate_claim_scope(
        &self,
        claim: &StoredRealmUserUpdateClaim<Hash>,
    ) -> Result<(), RealmUserUpdateRouterError> {
        if claim.pending().chain().network_id() != self.network
            || claim.pending().authority() != self.authority
        {
            return Err(RealmUserUpdateRouterError::ScopeMismatch);
        }
        self.validate_user(claim.user_id())
    }
}

fn router(error: impl fmt::Display) -> RealmUserUpdateRouterError {
    RealmUserUpdateRouterError::Backend(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RealmUserUpdateRouterError {
    Backend(String),
    Uninitialized,
    ClaimConflict {
        current_phase: RealmUserUpdateClaimPhase,
        current_revision: u64,
    },
    AwaitExactRequestReplay,
    DependencyMissing,
    DependencyConflict,
    TerminalEvidenceMismatch,
    AwaitTerminalClaims {
        terminal: usize,
        total: usize,
    },
    TerminalSourceMissing,
    QualificationConflict,
    TransitionConflict,
    InvalidPhase,
    PhaseStepLimit,
    InvalidUserRange,
    ScopeMismatch,
}

impl fmt::Display for RealmUserUpdateRouterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmUserUpdateRouterError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_is_default_off_and_concrete_permit_authorized() {
        let source = include_str!("realm_user_update_router.rs");
        let source = source.split("#[cfg(test)]").next().unwrap();
        assert!(source.contains("ScyllaRealmUserUpdateDurableRouter"));
        assert!(source.contains("publish_authorized"));
        assert!(source.contains("observe_authorized"));
        assert!(!source.contains("dyn RealmUserUpdatePublishPort"));
        assert!(!source.contains("legacy"));

        let setup = include_str!("../psy_setup.rs");
        let core = include_str!("../core.rs");
        assert!(!setup.contains("ScyllaRealmUserUpdateDurableRouter"));
        assert!(!core.contains("prepare_realm_user_update_router"));
    }

    #[test]
    fn phase_order_includes_durable_dependency_pointer() {
        assert_eq!(RealmUserUpdateClaimPhase::Claimed as u8, 1);
        assert_eq!(RealmUserUpdateClaimPhase::DependenciesPlanned as u8, 2);
        assert_eq!(RealmUserUpdateClaimPhase::DependenciesReady as u8, 3);
        assert_eq!(RealmUserUpdateClaimPhase::Published as u8, 4);
        assert_eq!(MAX_PHASE_STEPS, 8);
    }

    #[test]
    fn qualifier_is_terminal_first_historical_only_and_full_payload_cas() {
        let source = include_str!("realm_user_update_router.rs");
        let start = source.find("pub(crate) async fn qualify_generation").unwrap();
        let end = source[start..]
            .find("    /// Win or resume")
            .map(|offset| start + offset)
            .unwrap();
        let qualifier = &source[start..end];
        let terminal_check = qualifier.find("terminal != total").unwrap();
        let observer = qualifier.find("observe_authorized").unwrap();
        let persist = qualifier.find("persist_qualification").unwrap();
        assert!(terminal_check < observer && observer < persist);
        assert!(qualifier.contains("try_from_persisted_dependencies"));
        assert!(qualifier.contains("qualification_pipeline"));
        assert!(qualifier.contains("matches_pipeline"));
        assert!(!qualifier.contains("publish_authorized"));
        assert!(!qualifier.contains("materialize_data"));
        assert!(!qualifier.contains("publish_and_commit"));
    }

    #[test]
    fn new_claim_revalidation_preserves_response_loss_resume_order() {
        let source = include_str!("realm_user_update_router.rs");
        let source = source.split("#[cfg(test)]").next().unwrap();
        let resume = source.find(".resume_existing(").unwrap();
        let revalidate = source
            .find(".revalidate_admission(&admission)")
            .unwrap();
        let claim = source
            .find(".claim(\n                admission,")
            .unwrap();
        assert!(resume < revalidate && revalidate < claim);
        assert!(!source.contains("self.claims.claim("));
        assert!(source.contains("self.validate_claim_scope(&current)?"));
    }

    #[test]
    fn configured_authority_and_tree_heights_gate_user_before_claim_io() {
        let source = include_str!("realm_user_update_router.rs");
        let source = source.split("#[cfg(test)]").next().unwrap();
        let validate = source.find("self.validate_user(user_id)?").unwrap();
        let guarded = source.find(".resume_existing(").unwrap();
        assert!(validate < guarded);
        assert!(source.contains("self.global_user_tree_height"));
        assert!(source.contains("self.realm_user_tree_height"));
        assert!(source.contains("RealmUserUpdateRouterError::InvalidUserRange"));
        assert!(source.contains("self.validate_claim_scope(&current)?"));
        assert!(source.contains("claim.pending().chain().network_id() != self.network"));
        assert!(source.contains("verified_request: &VerifiedRealmUserUpdateRequest"));
        assert!(!source.contains("request_digest: RealmUserUpdateRequestDigest"));
    }

    #[test]
    fn exact_resume_does_not_claim_automatic_discovery() {
        let source = include_str!("realm_user_update_router.rs");
        let source = source.split("#[cfg(test)]").next().unwrap();
        assert!(source.contains("resume_exact"));
        assert!(source.contains("AwaitExactRequestReplay"));
        assert!(!source.contains("resume_all"));
        assert!(!source.contains("ALLOW FILTERING"));
    }

    #[test]
    fn errors_have_no_legacy_fallback_or_default_success() {
        let source = include_str!("realm_user_update_router.rs");
        let source = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in ["unwrap_or_default", "unwrap_or(RealmUserUpdate", "fallback"] {
            assert!(!source.contains(forbidden));
        }
    }
}
