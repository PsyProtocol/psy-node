//! Combined durable Realm user-update router.
//!
//! The router is deliberately crate-private and default-off. It is the only
//! component allowed to compose the claim LWT, immutable dependency readback,
//! and concrete Scylla/NATS publication permit. Production Edge callsites are
//! wired in a later milestone.

use std::{
    error::Error,
    fmt,
    marker::PhantomData,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use parth_core::{
    crypto::hash::traits::FieldQHasher,
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::{AuthorityObservation, AuthorityScope},
};
use psy_data::proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput;
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
            verify_persisted_realm_user_update_request,
            ValidatedRealmUserUpdateArtifacts, VerifiedRealmUserUpdateRequest,
        },
        realm_user_update_claim::{
            RealmUserUpdateClaimPartition, RealmUserUpdateClaimPhase,
            RealmUserUpdateCreatedAtSeconds,
            RealmUserUpdatePublishReceiptDigest, StoredRealmUserUpdateClaim,
        },
        realm_user_update_dependency::{
            RealmUserUpdateDependencyBundle, RealmUserUpdateDependencyError,
        },
        realm_user_update_publish::{
            GlobalUserTreeHeight, RealmUserUpdatePublishAdmission,
            RealmUserUpdatePublishPort, RealmUserUpdatePublishReceipt,
            RealmUserUpdatePublishRequest,
        },
        realm_user_update_ingress::{
            require_fresh_realm_authority_observation,
            seal_realm_user_update_ingress_artifacts,
            RealmAuthorityObservationReader, RealmUserUpdateArtifactFactory,
            RealmUserUpdateIngressReceipt, RealmUserUpdateStateFence,
        },
        realm_user_update_verifier_profile::{
            RealmUserUpdateVerifierProfileId, RealmUserUpdateVerifierRegistry,
        },
    },
    store::typed::UserId,
};
use psy_node_nats::{
    queue::NatsJetStreamClient,
};
#[cfg(test)]
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
    RealmUserUpdateDependencyStoreError,
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

pub(crate) struct ScyllaRealmUserUpdateDurableRouter<
    F,
    Hash,
    Hasher,
    Proof,
    Verifier,
> {
    network: NetworkId,
    authority: AuthorityScope,
    global_user_tree_height: GlobalUserTreeHeight,
    realm_user_tree_height: u8,
    claims: Arc<ScyllaRealmUserUpdateClaimStore>,
    admission_guard: ScyllaRealmUserUpdateAdmissionGuard,
    dependencies: ScyllaRealmUserUpdateDependencyStore,
    publisher: ScyllaRealmEdgeDurablePublisher<F, Hash>,
    active_verifier_profile: RealmUserUpdateVerifierProfileId,
    verifier_profiles: Arc<RealmUserUpdateVerifierRegistry<Verifier>>,
    authority_observations: Arc<dyn RealmAuthorityObservationReader<Hash>>,
    _proof: PhantomData<fn() -> (Hasher, Proof)>,
}

impl<F, Hash, Hasher, Proof, Verifier>
    ScyllaRealmUserUpdateDurableRouter<F, Hash, Hasher, Proof, Verifier>
where
    F: QFelt64 + Send + Sync + 'static,
    Hash: Q256BitHash + QFHashBase<F> + Send + Sync + 'static,
    Hasher: FieldQHasher<F, Hash> + Send + Sync + 'static,
    Proof: 'static,
    Verifier: parth_core::protocol::core_types::QZKProofVerifier<Hash, Proof>
        + Send
        + Sync
        + 'static,
{
    pub(crate) async fn prepare(
        session: Arc<Session>,
        network: NetworkId,
        authority: AuthorityScope,
        global_user_tree_height: GlobalUserTreeHeight,
        realm_user_tree_height: u8,
        active_verifier_profile: RealmUserUpdateVerifierProfileId,
        verifier_profiles: Arc<RealmUserUpdateVerifierRegistry<Verifier>>,
        authority_observations: Arc<dyn RealmAuthorityObservationReader<Hash>>,
        ready: Arc<PendingQueueSidecarReady>,
        nats: Arc<NatsJetStreamClient>,
    ) -> Result<Self, RealmUserUpdateRouterError> {
        let publisher = ScyllaRealmEdgeDurablePublisher::prepare(
            session.clone(),
            network,
            authority,
            Arc::clone(&ready),
            nats,
        )
        .await
        .map_err(router)?;
        Self::prepare_with_publisher(
            session,
            network,
            authority,
            global_user_tree_height,
            realm_user_tree_height,
            active_verifier_profile,
            verifier_profiles,
            authority_observations,
            ready,
            publisher,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn prepare_fixed_for_test(
        session: Arc<Session>,
        network: NetworkId,
        authority: AuthorityScope,
        global_user_tree_height: GlobalUserTreeHeight,
        realm_user_tree_height: u8,
        active_verifier_profile: RealmUserUpdateVerifierProfileId,
        verifier_profiles: Arc<RealmUserUpdateVerifierRegistry<Verifier>>,
        authority_observations: Arc<dyn RealmAuthorityObservationReader<Hash>>,
        ready: Arc<PendingQueueSidecarReady>,
        nats: Arc<RecoverablePendingQueueNatsPublisher>,
        segment: RecoverableNatsStreamSegment,
    ) -> Result<Self, RealmUserUpdateRouterError> {
        let publisher = ScyllaRealmEdgeDurablePublisher::prepare_fixed_for_test(
            session.clone(),
            network,
            authority,
            Arc::clone(&ready),
            nats,
            segment,
        )
        .await
        .map_err(router)?;
        Self::prepare_with_publisher(
            session,
            network,
            authority,
            global_user_tree_height,
            realm_user_tree_height,
            active_verifier_profile,
            verifier_profiles,
            authority_observations,
            ready,
            publisher,
        )
        .await
    }

    async fn prepare_with_publisher(
        session: Arc<Session>,
        network: NetworkId,
        authority: AuthorityScope,
        global_user_tree_height: GlobalUserTreeHeight,
        realm_user_tree_height: u8,
        active_verifier_profile: RealmUserUpdateVerifierProfileId,
        verifier_profiles: Arc<RealmUserUpdateVerifierRegistry<Verifier>>,
        authority_observations: Arc<dyn RealmAuthorityObservationReader<Hash>>,
        ready: Arc<PendingQueueSidecarReady>,
        publisher: ScyllaRealmEdgeDurablePublisher<F, Hash>,
    ) -> Result<Self, RealmUserUpdateRouterError> {
        if !matches!(authority, AuthorityScope::Realm { .. })
            || realm_user_tree_height >= 64
        {
            return Err(RealmUserUpdateRouterError::InvalidUserRange);
        }
        let active = verifier_profiles
            .resolve(active_verifier_profile)
            .map_err(|_| RealmUserUpdateRouterError::UnknownVerifierProfile(active_verifier_profile))?;
        if active.profile().network() != network
            || active.profile().global_user_tree_height()
                != global_user_tree_height.get()
        {
            return Err(RealmUserUpdateRouterError::VerifierProfileMismatch);
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
        Ok(Self {
            network,
            authority,
            global_user_tree_height,
            realm_user_tree_height,
            claims,
            admission_guard,
            dependencies,
            publisher,
            active_verifier_profile,
            verifier_profiles,
            authority_observations,
            _proof: PhantomData,
        })
    }

    /// Capture the exact gathering generation before proof/state work. The
    /// caller must then verify and seal a UserEndCap request before claiming.
    pub(crate) async fn read_authority_observation(
        &self,
    ) -> Result<AuthorityObservation<Hash>, RealmUserUpdateRouterError> {
        self.authority_observations
            .read_authority_observation()
            .await
            .map_err(|error| {
                RealmUserUpdateRouterError::AuthorityObservation(
                    error.to_string(),
                )
            })
    }

    /// Prove that the complete high-level ingress is usable before a CLI
    /// installs it and starts listening. The check is deliberately read-only:
    /// it resolves the exact gathering assignment to an already-Provisioned
    /// NATS instance, requires its admission header to be Open and fences the
    /// pending branch against the same authority-local head used by Handler.
    pub(crate) async fn attest_startup(
        &self,
    ) -> Result<(), RealmUserUpdateRouterError> {
        let admission = self
            .publisher
            .attest_startup_route()
            .await
            .map_err(router)?;
        let key = RealmUserUpdateAdmissionKey::try_new(admission.capture())
            .map_err(router)?;
        self.admission_guard
            .require_generation_open::<Hash>(key)
            .await
            .map_err(router)?;
        let observation = self
            .authority_observations
            .read_authority_observation()
            .await
            .map_err(|error| {
                RealmUserUpdateRouterError::AuthorityObservation(
                    error.to_string(),
                )
            })?;
        RealmUserUpdateStateFence::try_seal(
            admission,
            observation.clone(),
            observation,
        )
        .map_err(|error| {
            RealmUserUpdateRouterError::AuthorityObservation(error.to_string())
        })?;
        Ok(())
    }

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
        if verified_request.verifier_profile_id() != self.active_verifier_profile {
            return Err(RealmUserUpdateRouterError::VerifierProfileMismatch);
        }
        if let Some(current) = self
            .admission_guard
            .resume_existing(
                admission.clone(),
                self.active_verifier_profile,
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
                self.active_verifier_profile,
                user_id,
                verified_request.request_digest(),
                created_at,
            )
            .await
            .map_err(router)?;
        self.validate_claim_scope(&current)?;
        Ok(current)
    }

    /// Production-shaped high-level live submission. The full canonical input
    /// and proof are verified on a blocking thread before any claim LWT. Only
    /// the durable winner may seed the pure artifact factory; all returned
    /// material is revalidated before dependency persistence/publication.
    pub(crate) async fn submit_after_state_validation(
        &self,
        fence: RealmUserUpdateStateFence<Hash>,
        input: SubmitUserEndCapNonProofInput<F, Hash>,
        proof: Vec<u8>,
        artifact_factory: Arc<dyn RealmUserUpdateArtifactFactory<F, Hash>>,
    ) -> Result<RealmUserUpdateIngressReceipt<Hash>, RealmUserUpdateRouterError> {
        let fenced_observation = fence.observation().clone();
        let admission = fence.into_admission();
        let bound_verifier = self
            .verifier_profiles
            .resolve(self.active_verifier_profile)
            .map_err(|_| {
                RealmUserUpdateRouterError::UnknownVerifierProfile(
                    self.active_verifier_profile,
                )
            })?;
        let height = self.global_user_tree_height;
        let verify_input = input.clone();
        let verified_request = run_blocking_proof_recovery(move || {
            VerifiedRealmUserUpdateRequest::verify::<Proof, Verifier, Hasher>(
                &verify_input,
                proof,
                height,
                &bound_verifier,
            )
        })
        .await?;

        let fresh_observation = self.read_authority_observation().await?;
        require_fresh_realm_authority_observation(
            &fenced_observation,
            &fresh_observation,
        )
        .map_err(|_| RealmUserUpdateRouterError::AuthorityObservationChanged)?;

        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                RealmUserUpdateRouterError::Clock(error.to_string())
            })?
            .as_secs();
        let created_at = u32::try_from(created_at)
            .map_err(|_| RealmUserUpdateRouterError::ClockOverflow)?;
        let winner = self
            .claim(
                admission.clone(),
                &verified_request,
                RealmUserUpdateCreatedAtSeconds::try_new(created_at)
                    .map_err(router)?,
            )
            .await?;

        // Ready/Published retries already have a complete durable dependency
        // bundle, so resume from that authority after revalidating the caller's
        // proof and branch fence. A Planned winner is deliberately excluded:
        // the process may have crashed after the pointer CAS but before all
        // fragments were written. Exact replay must rebuild the deterministic
        // artifacts and let complete_live fill only the missing fragments.
        if matches!(
            winner.phase(),
            RealmUserUpdateClaimPhase::DependenciesReady
                | RealmUserUpdateClaimPhase::Published
        ) {
            let terminal = self
                .resume_exact(winner.partition().map_err(router)?, winner.user_id())
                .await?;
            return RealmUserUpdateIngressReceipt::try_from_terminal(
                terminal.claim,
                terminal.publication,
            )
            .map_err(router);
        }

        let artifact_claim = winner.clone();
        let artifact_verified = verified_request.clone();
        let artifacts = tokio::task::spawn_blocking(move || {
            let material = artifact_factory.build(&artifact_claim, &input)?;
            seal_realm_user_update_ingress_artifacts::<F, Hash, Hasher>(
                admission,
                &artifact_claim,
                &artifact_verified,
                material,
            )
        })
        .await
        .map_err(|error| {
            RealmUserUpdateRouterError::ArtifactTaskFailed(error.to_string())
        })?
        .map_err(|error| {
            RealmUserUpdateRouterError::ArtifactBuildFailed(error.to_string())
        })?;
        let terminal = self.complete_live(&winner, &artifacts).await?;
        RealmUserUpdateIngressReceipt::try_from_terminal(
            terminal.claim,
            terminal.publication,
        )
        .map_err(router)
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

    /// Resume one already-known claim coordinate. The router owns the concrete
    /// verifier and revalidates the durable canonical input/proof on a blocking
    /// thread. The claim and bundle are read again after verification before a
    /// Planned claim may advance to Ready.
    pub(crate) async fn resume_exact(
        &self,
        partition: RealmUserUpdateClaimPartition,
        user_id: UserId,
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
            current = self.reverify_planned_to_ready(current).await?;
        }
        let persisted = self.read_dependencies(&current).await?;
        match current.phase() {
            RealmUserUpdateClaimPhase::DependenciesReady => {
                self.publish_and_finish(
                    current,
                    persisted,
                    self.global_user_tree_height,
                )
                .await
            }
            RealmUserUpdateClaimPhase::Published => {
                self.observe_terminal(
                    current,
                    persisted,
                    self.global_user_tree_height,
                )
                .await
            }
            RealmUserUpdateClaimPhase::Claimed
            | RealmUserUpdateClaimPhase::DependenciesPlanned => {
                Err(RealmUserUpdateRouterError::InvalidPhase)
            }
        }
    }

    /// Test-only deterministic crash boundary immediately after the exact
    /// persisted proof has been reverified and Planned has advanced to Ready,
    /// but before any NATS materialization or publish is attempted.
    #[cfg(test)]
    pub(crate) async fn resume_through_ready_fixture(
        &self,
        partition: RealmUserUpdateClaimPartition,
        user_id: UserId,
    ) -> Result<StoredRealmUserUpdateClaim<Hash>, RealmUserUpdateRouterError> {
        self.validate_user(user_id)?;
        let RealmUserUpdateClaimReadState::Current(current) = self
            .claims
            .read(partition, user_id)
            .await
            .map_err(router)?
        else {
            return Err(RealmUserUpdateRouterError::Uninitialized);
        };
        self.validate_claim_scope(&current)?;
        if current.phase() != RealmUserUpdateClaimPhase::DependenciesPlanned {
            return Err(RealmUserUpdateRouterError::InvalidPhase);
        }
        self.reverify_planned_to_ready(current).await
    }

    async fn reverify_planned_to_ready(
        &self,
        sampled: StoredRealmUserUpdateClaim<Hash>,
    ) -> Result<StoredRealmUserUpdateClaim<Hash>, RealmUserUpdateRouterError> {
        let persisted_before_verify = self.read_planned_dependencies(&sampled).await?;
        let persisted_before_verify = self
            .verify_persisted_request(&sampled, persisted_before_verify)
            .await?;

        // Verification may take seconds. Never use the phase or dependency
        // rows sampled before it as CAS authority.
        let mut current = self.read_same_request(&sampled).await?;
        validate_post_verification_phase(
            sampled.phase(),
            sampled.revision().get(),
            current.phase(),
            current.revision().get(),
        )?;
        if current.dependency_digest() != Some(persisted_before_verify.digest()) {
            return Err(RealmUserUpdateRouterError::DependencyConflict);
        }
        let persisted_after_verify = if current.phase()
            == RealmUserUpdateClaimPhase::DependenciesPlanned
        {
            self.read_planned_dependencies(&current).await?
        } else {
            self.read_dependencies(&current).await?
        };
        if persisted_after_verify != persisted_before_verify {
            return Err(RealmUserUpdateRouterError::DependencyConflict);
        }
        if current.phase() == RealmUserUpdateClaimPhase::DependenciesPlanned {
            let candidate = StoredRealmUserUpdateClaim::dependencies_ready(&current)
                .map_err(router)?;
            current = self.advance_claim(&current, &candidate).await?;
            if current.dependency_digest() != Some(persisted_after_verify.digest()) {
                return Err(RealmUserUpdateRouterError::DependencyConflict);
            }
        }
        Ok(current)
    }

    async fn verify_persisted_request(
        &self,
        claim: &StoredRealmUserUpdateClaim<Hash>,
        bundle: RealmUserUpdateDependencyBundle,
    ) -> Result<RealmUserUpdateDependencyBundle, RealmUserUpdateRouterError> {
        let claim = claim.clone();
        let bound_verifier = self
            .verifier_profiles
            .resolve(claim.verifier_profile_id())
            .map_err(|_| {
                RealmUserUpdateRouterError::UnknownVerifierProfile(
                    claim.verifier_profile_id(),
                )
            })?;
        let height = self.global_user_tree_height;
        run_blocking_proof_recovery(move || {
            verify_persisted_realm_user_update_request::<
                F,
                Hash,
                Hasher,
                Proof,
                Verifier,
            >(&claim, &bundle, height, &bound_verifier)?;
            Ok::<_, psy_node_core::queue::realm_user_update_artifact::RealmUserUpdateArtifactError>(bundle)
        })
        .await
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
        let result = self.dependencies
            .read_bundle(
                claim.slot(),
                *claim.request_digest().as_bytes(),
                claim.stable_status(),
                claim.created_at().get(),
                digest,
            )
            .await;
        match result {
            Ok(bundle) => Ok(bundle),
            Err(error) => Err(classify_dependency_read_error(claim.phase(), error)),
        }
    }

    async fn read_planned_dependencies(
        &self,
        claim: &StoredRealmUserUpdateClaim<Hash>,
    ) -> Result<RealmUserUpdateDependencyBundle, RealmUserUpdateRouterError> {
        if claim.phase() != RealmUserUpdateClaimPhase::DependenciesPlanned {
            return Err(RealmUserUpdateRouterError::InvalidPhase);
        }
        let digest = claim
            .dependency_digest()
            .ok_or(RealmUserUpdateRouterError::DependencyMissing)?;
        self.dependencies
            .read_planned_bundle(
                claim.slot(),
                *claim.request_digest().as_bytes(),
                claim.stable_status(),
                claim.created_at().get(),
                digest,
            )
            .await
            .map_err(|error| classify_dependency_read_error(claim.phase(), error))
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
        let bound = self
            .verifier_profiles
            .resolve(claim.verifier_profile_id())
            .map_err(|_| {
                RealmUserUpdateRouterError::UnknownVerifierProfile(
                    claim.verifier_profile_id(),
                )
            })?;
        if bound.profile().network() != self.network
            || bound.profile().global_user_tree_height()
                != self.global_user_tree_height.get()
        {
            return Err(RealmUserUpdateRouterError::VerifierProfileMismatch);
        }
        self.validate_user(claim.user_id())
    }
}

async fn run_blocking_proof_recovery<T, E, Task>(
    task: Task,
) -> Result<T, RealmUserUpdateRouterError>
where
    T: Send + 'static,
    E: fmt::Display + Send + 'static,
    Task: FnOnce() -> Result<T, E> + Send + 'static,
{
    tokio::task::spawn_blocking(task)
        .await
        .map_err(|error| RealmUserUpdateRouterError::ProofTaskFailed(error.to_string()))?
        .map_err(|error| RealmUserUpdateRouterError::ProofRecoveryFailed(error.to_string()))
}

fn validate_post_verification_phase(
    sampled_phase: RealmUserUpdateClaimPhase,
    sampled_revision: u64,
    fresh_phase: RealmUserUpdateClaimPhase,
    fresh_revision: u64,
) -> Result<(), RealmUserUpdateRouterError> {
    let phase_is_monotonic = match sampled_phase {
        RealmUserUpdateClaimPhase::Claimed => true,
        RealmUserUpdateClaimPhase::DependenciesPlanned => matches!(
            fresh_phase,
            RealmUserUpdateClaimPhase::DependenciesPlanned
                | RealmUserUpdateClaimPhase::DependenciesReady
                | RealmUserUpdateClaimPhase::Published
        ),
        RealmUserUpdateClaimPhase::DependenciesReady => matches!(
            fresh_phase,
            RealmUserUpdateClaimPhase::DependenciesReady
                | RealmUserUpdateClaimPhase::Published
        ),
        RealmUserUpdateClaimPhase::Published => {
            fresh_phase == RealmUserUpdateClaimPhase::Published
        }
    };
    if fresh_revision < sampled_revision || !phase_is_monotonic {
        return Err(RealmUserUpdateRouterError::PhaseRegression);
    }
    Ok(())
}

fn classify_dependency_read_error(
    phase: RealmUserUpdateClaimPhase,
    error: RealmUserUpdateDependencyStoreError,
) -> RealmUserUpdateRouterError {
    match error {
        RealmUserUpdateDependencyStoreError::Dependency(
            RealmUserUpdateDependencyError::MissingFragment,
        ) if phase == RealmUserUpdateClaimPhase::DependenciesPlanned => {
            RealmUserUpdateRouterError::AwaitExactArtifactReplay
        }
        RealmUserUpdateDependencyStoreError::Dependency(
            RealmUserUpdateDependencyError::MissingFragment,
        ) => RealmUserUpdateRouterError::DurableDependencyLoss,
        RealmUserUpdateDependencyStoreError::Cql(error) => {
            RealmUserUpdateRouterError::DependencyUnavailable(error)
        }
        error => RealmUserUpdateRouterError::DependencyCorruption(error.to_string()),
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
    AwaitExactArtifactReplay,
    DurableDependencyLoss,
    DependencyCorruption(String),
    DependencyUnavailable(String),
    ProofTaskFailed(String),
    ProofRecoveryFailed(String),
    ArtifactTaskFailed(String),
    ArtifactBuildFailed(String),
    Clock(String),
    ClockOverflow,
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
    PhaseRegression,
    InvalidPhase,
    PhaseStepLimit,
    InvalidUserRange,
    ScopeMismatch,
    UnknownVerifierProfile(RealmUserUpdateVerifierProfileId),
    VerifierProfileMismatch,
    AuthorityObservation(String),
    AuthorityObservationChanged,
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

    fn production_source() -> &'static str {
        include_str!("realm_user_update_router.rs")
            .split("#[cfg(test)]\nmod tests")
            .next()
            .unwrap()
    }

    #[test]
    fn router_is_default_off_and_concrete_permit_authorized() {
        let source = production_source();
        assert!(source.contains("ScyllaRealmUserUpdateDurableRouter"));
        assert!(source.contains("publish_authorized"));
        assert!(source.contains("observe_authorized"));
        assert!(!source.contains("dyn RealmUserUpdatePublishPort"));
        assert!(!source.contains("legacy"));

        let setup = include_str!("../psy_setup.rs")
            .split("#[cfg(test)]\nmod realm_startup_composition_tests")
            .next()
            .unwrap();
        let generic_setup = setup
            .split("pub async fn setup_psy_scylla_database_store<")
            .nth(1)
            .unwrap()
            .split("pub async fn prepare_psy_scylla_database_store<")
            .next()
            .unwrap();
        let edge_installation = setup
            .split("pub struct ScyllaRealmEdgeStartupComposition")
            .nth(1)
            .unwrap();
        let core = include_str!("../core.rs");
        assert!(!generic_setup.contains("ScyllaRealmUserUpdateDurableRouter"));
        assert!(edge_installation.contains("ScyllaRealmUserUpdateDurableRouter"));
        assert!(edge_installation.contains(
            "RealmEdgeDurableIngressInstallation::seal_with_startup_permit"
        ));
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
        let source = production_source();
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
    fn high_level_ingress_verifies_before_claim_and_seals_before_publish() {
        let source = production_source();
        let start = source
            .find("pub(crate) async fn submit_after_state_validation")
            .unwrap();
        let end = source[start..]
            .find("    /// Complete a live request")
            .map(|offset| start + offset)
            .unwrap();
        let ingress = &source[start..end];
        let verify = ingress
            .find("VerifiedRealmUserUpdateRequest::verify")
            .unwrap();
        let observe = ingress
            .find("read_authority_observation")
            .unwrap();
        let clock = ingress.find("SystemTime::now()").unwrap();
        let claim = ingress.find(".claim(").unwrap();
        let resume = ingress.find(".resume_exact(").unwrap();
        let build = ingress.find("artifact_factory.build").unwrap();
        let seal = ingress
            .find("seal_realm_user_update_ingress_artifacts")
            .unwrap();
        let complete = ingress.find("self.complete_live").unwrap();
        assert!(verify < observe && observe < clock && clock < claim);
        assert!(claim < resume && resume < build);
        assert!(build < seal && seal < complete);
        assert!(ingress.contains("RealmUserUpdateClaimPhase::DependenciesReady"));
        assert!(ingress.contains("RealmUserUpdateClaimPhase::Published"));
        assert!(!ingress.contains(
            "winner.phase() != RealmUserUpdateClaimPhase::Claimed"
        ));
        assert!(ingress.contains("A Planned winner is deliberately excluded"));
        assert!(ingress.contains("fence: RealmUserUpdateStateFence<Hash>"));
        assert!(ingress.contains("input: SubmitUserEndCapNonProofInput<F, Hash>"));
        assert!(ingress.contains("proof: Vec<u8>"));
        assert!(!ingress.contains("request_digest:"));
        assert!(!ingress.contains("created_at:"));
        assert!(!ingress.contains("RealmUserUpdatePublishRequest"));
        assert!(ingress.contains("fenced_observation"));
        assert!(ingress.contains("require_fresh_realm_authority_observation"));
    }

    #[test]
    fn configured_authority_and_tree_heights_gate_user_before_claim_io() {
        let source = production_source();
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
        let source = production_source();
        assert!(source.contains("resume_exact"));
        assert!(source.contains("AwaitExactRequestReplay"));
        assert!(source.contains(
            "verifier_profiles: Arc<RealmUserUpdateVerifierRegistry<Verifier>>"
        ));
        assert!(source.contains(".resolve(claim.verifier_profile_id())"));
        assert!(!source.contains("verifier: Arc<Verifier>"));
        assert!(source.contains("tokio::task::spawn_blocking"));
        assert!(source.contains("verify_persisted_realm_user_update_request::<"));
        assert!(source.contains(
            "let persisted_before_verify = self.read_planned_dependencies(&sampled).await?"
        ));
        let resume = source.find("pub(crate) async fn resume_exact").unwrap();
        let verify = source[resume..]
            .find(".verify_persisted_request(")
            .map(|offset| resume + offset)
            .unwrap();
        let fresh = source[verify..]
            .find("self.read_same_request(&sampled).await?")
            .map(|offset| verify + offset)
            .unwrap();
        let ready = source[fresh..]
            .find("StoredRealmUserUpdateClaim::dependencies_ready")
            .map(|offset| fresh + offset)
            .unwrap();
        assert!(verify < fresh && fresh < ready);
        let signature_end = source[resume..]
            .find(") -> Result<")
            .map(|offset| resume + offset)
            .unwrap();
        assert!(!source[resume..signature_end].contains("VerifiedRealmUserUpdateProof"));
        assert!(!source.contains("resume_all"));
        assert!(!source.contains("ALLOW FILTERING"));
    }

    #[test]
    fn errors_have_no_legacy_fallback_or_default_success() {
        let source = production_source();
        for forbidden in ["unwrap_or_default", "unwrap_or(RealmUserUpdate", "fallback"] {
            assert!(!source.contains(forbidden));
        }
    }

    #[test]
    fn post_verification_phase_must_be_monotonic() {
        use RealmUserUpdateClaimPhase::{
            Claimed, DependenciesPlanned, DependenciesReady, Published,
        };
        for fresh in [DependenciesPlanned, DependenciesReady, Published] {
            assert!(validate_post_verification_phase(
                DependenciesPlanned,
                2,
                fresh,
                2,
            )
            .is_ok());
        }
        assert_eq!(
            validate_post_verification_phase(
                DependenciesPlanned,
                2,
                Claimed,
                3,
            ),
            Err(RealmUserUpdateRouterError::PhaseRegression),
        );
        assert_eq!(
            validate_post_verification_phase(
                DependenciesPlanned,
                2,
                DependenciesReady,
                1,
            ),
            Err(RealmUserUpdateRouterError::PhaseRegression),
        );
        assert!(validate_post_verification_phase(
            DependenciesReady,
            3,
            Published,
            4,
        )
        .is_ok());
        assert_eq!(
            validate_post_verification_phase(Published, 4, DependenciesReady, 5),
            Err(RealmUserUpdateRouterError::PhaseRegression),
        );
    }

    #[test]
    fn dependency_read_errors_are_phase_specific() {
        let missing = || {
            RealmUserUpdateDependencyStoreError::Dependency(
                RealmUserUpdateDependencyError::MissingFragment,
            )
        };
        assert_eq!(
            classify_dependency_read_error(
                RealmUserUpdateClaimPhase::DependenciesPlanned,
                missing(),
            ),
            RealmUserUpdateRouterError::AwaitExactArtifactReplay,
        );
        for phase in [
            RealmUserUpdateClaimPhase::DependenciesReady,
            RealmUserUpdateClaimPhase::Published,
        ] {
            assert_eq!(
                classify_dependency_read_error(phase, missing()),
                RealmUserUpdateRouterError::DurableDependencyLoss,
            );
        }
        assert!(matches!(
            classify_dependency_read_error(
                RealmUserUpdateClaimPhase::DependenciesPlanned,
                RealmUserUpdateDependencyStoreError::Dependency(
                    RealmUserUpdateDependencyError::ConflictingFragment,
                ),
            ),
            RealmUserUpdateRouterError::DependencyCorruption(_)
        ));
        assert_eq!(
            classify_dependency_read_error(
                RealmUserUpdateClaimPhase::DependenciesPlanned,
                RealmUserUpdateDependencyStoreError::Cql("offline".to_owned()),
            ),
            RealmUserUpdateRouterError::DependencyUnavailable(
                "offline".to_owned(),
            ),
        );
    }

    #[tokio::test]
    async fn blocking_proof_task_reports_rejection_and_panic() {
        let rejected = run_blocking_proof_recovery::<(), _, _>(|| {
            Err::<(), _>("rejected")
        })
        .await;
        assert_eq!(
            rejected,
            Err(RealmUserUpdateRouterError::ProofRecoveryFailed(
                "rejected".to_owned(),
            )),
        );

        let panicked = run_blocking_proof_recovery::<(), &'static str, _>(|| {
            panic!("verifier panic")
        })
        .await;
        assert!(matches!(
            panicked,
            Err(RealmUserUpdateRouterError::ProofTaskFailed(_))
        ));
    }
}
