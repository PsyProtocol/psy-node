//! Opaque installation boundary between Realm startup admission and the
//! branch-exact commit composition.
//!
//! A fresh-run permit is deliberately insufficient on its own.  The exact
//! storage-backed runtime must consume that permit, revalidate its identity,
//! and return this module's non-Clone installed capability.  No live commit
//! h23c4c3a adds one narrow operation: an affine durable-capture port whose
//! concrete delivery token and ACK authority remain storage-private.  The
//! production gatherer and application handoff are wired behind the serving
//! guard, which remains fail closed until the later terminal/writer gates.

use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use psy_data::protocol::canonical_chain::NetworkId;
use psy_data::protocol::chain_context::AuthorityScope;

use crate::queue::{
    realm_processor_durable_capture::{
        RealmProcessorApplicationHandoffObservation,
        RealmProcessorDurableCaptureError, RealmProcessorDurableCaptureFactory,
        RealmProcessorDurableCaptureOutcome, RealmProcessorDurableCapturePort,
        RealmProcessorDurableCapturedGeneration,
        SealedRealmProcessorDurableCaptureRequest,
    },
    realm_processor_semantic_output::RealmProcessorSemanticOutput,
    recoverable_ephemeral::PendingQueueCaptureContext,
};

use super::realm_processor_startup::{
    RealmProcessorFreshRunPermit, RealmProcessorStartupError,
    RealmProcessorStartupPermitDigest,
};
use super::pending_generation_identity::{
    PendingGenerationActivationDigest, PendingGenerationContext,
    PendingGenerationLedgerKey,
};
use super::realm_processor_quiescence::RealmProcessorIterationPermit;

/// Exact, deliberately narrow scope of the runtime being installed.  It does
/// not claim full 22-domain normal-commit coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmBranchExactRuntimeScope {
    MappingAndRewardProofDualWrite,
}

/// Driver-independent identity exposed by a storage-owned runtime.
///
/// The shared trait intentionally remains identity-only. Mutating operations
/// are installed as separate affine factories and can only be consumed by a
/// borrowed single-owner iteration.
pub trait RealmBranchExactCommitRuntime<Hash>: Send + Sync {
    fn network(&self) -> NetworkId;
    fn realm_id(&self) -> u32;
    fn realm_sub_id(&self) -> u16;
    fn writer_activation_digest(&self) -> [u8; 32];
    fn queue_readiness_digest(&self) -> [u8; 32];
    fn scope(&self) -> RealmBranchExactRuntimeScope;
}

/// Non-Clone capability proving that one exact fresh-run permit has been
/// consumed by an identity-matching runtime.
pub struct InstalledRealmBranchExactCommitRuntime<Hash> {
    startup_permit: RealmProcessorFreshRunPermit,
    runtime: Arc<dyn RealmBranchExactCommitRuntime<Hash>>,
    capture_factory: Arc<dyn RealmProcessorDurableCaptureFactory>,
}

impl<Hash> InstalledRealmBranchExactCommitRuntime<Hash> {
    /// The only constructor.  It consumes the non-Clone permit and rejects a
    /// runtime prepared for another network, Realm, or writer activation.
    pub fn seal(
        startup_permit: RealmProcessorFreshRunPermit,
        runtime: Arc<dyn RealmBranchExactCommitRuntime<Hash>>,
        capture_factory: Arc<dyn RealmProcessorDurableCaptureFactory>,
    ) -> Result<Self, RealmProcessorStartupError> {
        let expectation = startup_permit.expectation();
        if runtime.network() != expectation.network()
            || runtime.realm_id() != expectation.realm_id()
            || runtime.realm_sub_id() != expectation.realm_sub_id()
            || runtime.writer_activation_digest()
                != *expectation.expected_writer_activation_digest().as_bytes()
            || runtime.scope()
                != RealmBranchExactRuntimeScope::MappingAndRewardProofDualWrite
            || capture_factory.network() != runtime.network()
            || capture_factory.realm_id() != runtime.realm_id()
            || capture_factory.realm_sub_id() != runtime.realm_sub_id()
            || capture_factory.writer_activation_digest()
                != runtime.writer_activation_digest()
            || capture_factory.queue_readiness_digest()
                != runtime.queue_readiness_digest()
        {
            return Err(RealmProcessorStartupError::CommitRuntimeIdentityMismatch);
        }
        Ok(Self {
            startup_permit,
            runtime,
            capture_factory,
        })
    }

    pub const fn startup_permit_digest(&self) -> RealmProcessorStartupPermitDigest {
        self.startup_permit.digest()
    }

    pub fn runtime(&self) -> &dyn RealmBranchExactCommitRuntime<Hash> {
        self.runtime.as_ref()
    }

    fn capture_factory(&self) -> &Arc<dyn RealmProcessorDurableCaptureFactory> {
        &self.capture_factory
    }
}

/// Storage-owned installer.  Implementations must fresh-read their durable
/// composite after startup authorization and before calling `seal`.
#[async_trait]
pub trait RealmBranchExactCommitRuntimeInstaller<Hash>: Send + Sync {
    async fn install(
        self: Arc<Self>,
        startup_permit: RealmProcessorFreshRunPermit,
    ) -> Result<InstalledRealmBranchExactCommitRuntime<Hash>, RealmProcessorStartupError>;
}

/// The only process-local owner allowed to grow future queue, writer and
/// authority-marker operations.
///
/// It is deliberately non-Clone and owns the installed runtime by value.  The
/// inner runtime remains identity-only even though its implementation uses an
/// `Arc`; mutation APIs must be added to an iteration borrowing this owner,
/// never to the shared runtime trait.
pub struct RealmBranchExactSingleCommitOwner<Hash> {
    installed: InstalledRealmBranchExactCommitRuntime<Hash>,
}

impl<Hash> RealmBranchExactSingleCommitOwner<Hash> {
    pub fn from_installed(
        installed: InstalledRealmBranchExactCommitRuntime<Hash>,
    ) -> Self {
        Self { installed }
    }

    pub const fn startup_permit_digest(&self) -> RealmProcessorStartupPermitDigest {
        self.installed.startup_permit_digest()
    }

    pub fn runtime(&self) -> &dyn RealmBranchExactCommitRuntime<Hash> {
        self.installed.runtime()
    }

    /// Bind the owner to the real loop's sole controlled iteration permit.
    /// A disabled legacy gate can mint compatibility permits, but those may
    /// never authorize branch-exact queue/write/publish work.
    pub fn begin_iteration(
        &mut self,
        iteration_permit: RealmProcessorIterationPermit,
    ) -> Result<RealmBranchExactCommitIteration<'_, Hash>, RealmBranchExactCommitOwnerError>
    {
        if !iteration_permit.is_controlled() {
            return Err(RealmBranchExactCommitOwnerError::UncontrolledIterationPermit);
        }
        Ok(RealmBranchExactCommitIteration {
            owner: self,
            _iteration_permit: iteration_permit,
        })
    }
}

/// Borrowed owner of one complete `sync + queue + commit + publish`
/// iteration. h23c4c3a exposes only durable capture here; future writer and
/// marker ports must likewise require `&mut self` and private typestate
/// receipts. A bare checkpoint or shared runtime reference is never
/// sufficient.
pub struct RealmBranchExactCommitIteration<'a, Hash> {
    owner: &'a mut RealmBranchExactSingleCommitOwner<Hash>,
    _iteration_permit: RealmProcessorIterationPermit,
}

impl<Hash> RealmBranchExactCommitIteration<'_, Hash> {
    pub fn network(&self) -> NetworkId {
        self.owner.runtime().network()
    }

    pub fn realm_id(&self) -> u32 {
        self.owner.runtime().realm_id()
    }

    pub fn realm_sub_id(&self) -> u16 {
        self.owner.runtime().realm_sub_id()
    }

    pub const fn startup_permit_digest(&self) -> RealmProcessorStartupPermitDigest {
        self.owner.startup_permit_digest()
    }

    /// Opens one backend-owned capture authority while borrowing this whole
    /// iteration mutably.  The returned port cannot outlive the iteration and
    /// no second queue mutation can be opened through the same owner until it
    /// is dropped.
    async fn open_durable_capture<'capture>(
        &'capture mut self,
        context: PendingQueueCaptureContext,
    ) -> Result<RealmBranchExactDurableCapture<'capture>, RealmProcessorDurableCaptureError> {
        let runtime = self.owner.runtime();
        let factory = Arc::clone(self.owner.installed.capture_factory());
        let request = SealedRealmProcessorDurableCaptureRequest::seal(
            self.owner.startup_permit_digest(),
            runtime.network(),
            runtime.realm_id(),
            runtime.realm_sub_id(),
            runtime.writer_activation_digest(),
            runtime.queue_readiness_digest(),
            context,
        )?;
        let port = factory.open(request).await?;
        Ok(RealmBranchExactDurableCapture {
            port,
            _iteration: PhantomData,
        })
    }

    /// Production-shaped capture entry.  The Processor supplies only its
    /// exact durable processing pending/proc context; network, Realm scope and
    /// activation are derived from the installed runtime and cannot be mixed
    /// from caller-provided values.
    pub async fn open_durable_capture_for_processing<'capture>(
        &'capture mut self,
        processing: PendingGenerationContext,
    ) -> Result<RealmBranchExactDurableCapture<'capture>, RealmProcessorDurableCaptureError> {
        let runtime = self.owner.runtime();
        let context = PendingQueueCaptureContext::try_new(
            PendingGenerationLedgerKey::new(
                runtime.network(),
                AuthorityScope::Realm {
                    realm_id: runtime.realm_id(),
                    realm_sub_id: runtime.realm_sub_id(),
                },
            ),
            PendingGenerationActivationDigest::try_new(
                runtime.writer_activation_digest(),
            )
            .map_err(|_| RealmProcessorDurableCaptureError::RuntimeCapabilityMismatch)?,
            processing,
        )
        .map_err(|_| RealmProcessorDurableCaptureError::IdentityMismatch)?;
        self.open_durable_capture(context).await
    }
}

/// Lifetime-bound affine capture handle.  It exposes canonical outcomes only;
/// backend delivery/ACK receipts remain private to the adapter.
pub struct RealmBranchExactDurableCapture<'iteration> {
    port: Box<dyn RealmProcessorDurableCapturePort>,
    _iteration: PhantomData<&'iteration mut ()>,
}

impl RealmBranchExactDurableCapture<'_> {
    pub async fn capture_next(
        &mut self,
    ) -> Result<Option<RealmProcessorDurableCaptureOutcome>, RealmProcessorDurableCaptureError> {
        self.port.capture_next().await
    }

    /// Reconstructs the complete closed generation from durable artifacts.
    /// The returned input is restart-safe; individual live outcomes are not.
    pub async fn replay_complete_generation(
        &mut self,
    ) -> Result<Option<RealmProcessorDurableCapturedGeneration>, RealmProcessorDurableCaptureError>
    {
        self.port.replay_complete_generation().await
    }

    /// Recovers the exact first application handoff when the pipeline CAS
    /// committed before the Processor received its response.
    pub async fn recover_application_handoff(
        &mut self,
    ) -> Result<Option<RealmProcessorApplicationHandoffObservation>, RealmProcessorDurableCaptureError>
    {
        self.port.recover_application_handoff().await
    }

    /// Persists one canonical application output and performs the only first
    /// pipeline CAS allowed by this affine capture owner.
    pub async fn persist_application_and_handoff(
        &mut self,
        semantic: RealmProcessorSemanticOutput,
    ) -> Result<RealmProcessorApplicationHandoffObservation, RealmProcessorDurableCaptureError>
    {
        self.port
            .persist_application_and_handoff(semantic)
            .await
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmBranchExactCommitOwnerError {
    UncontrolledIterationPermit,
}

impl std::fmt::Display for RealmBranchExactCommitOwnerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RealmBranchExactCommitOwnerError {}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use parth_core::PHash;
    use psy_core::constants::chain_id::PsyChainNetworkType;
    use psy_data::protocol::chain_context::AuthorityScope;

    use super::*;
    use crate::store::pending_generation_identity::PendingGenerationContext;
    use crate::store::realm_processor_startup::{
        authorize_realm_processor_startup, RealmProcessorStartupAuthorization,
        RealmProcessorStartupEvidence, RealmProcessorStartupExpectation,
        RealmProcessorStartupMode, RealmProcessorStartupPreflightProvider,
        RealmProcessorStartupRouteObservation,
        RealmProcessorStartupRoutePhase,
    };

    fn network() -> NetworkId {
        NetworkId::from_network_type(PsyChainNetworkType::LocalDevnet)
    }

    fn expectation() -> RealmProcessorStartupExpectation {
        RealmProcessorStartupExpectation::try_new(
            network(), 7, 3, 11, [1; 32], [2; 32], [4; 32],
        )
        .unwrap()
    }

    fn evidence() -> RealmProcessorStartupEvidence {
        let route = RealmProcessorStartupRouteObservation::try_new(
            11,
            13,
            [1; 32],
            [5; 32],
            RealmProcessorStartupRoutePhase::LegacyPrimaryDualWrite,
        )
        .unwrap();
        RealmProcessorStartupEvidence::try_new(
            network(), network_realm(), 3, route, route, [2; 32], [3; 32], [6; 32],
        )
        .unwrap()
    }

    const fn network_realm() -> u32 {
        7
    }

    struct Provider;

    #[async_trait]
    impl RealmProcessorStartupPreflightProvider for Provider {
        async fn fresh_read(
            &self,
            _expectation: RealmProcessorStartupExpectation,
        ) -> Result<RealmProcessorStartupEvidence, RealmProcessorStartupError> {
            Ok(evidence())
        }
    }

    async fn permit() -> RealmProcessorFreshRunPermit {
        let RealmProcessorStartupAuthorization::BranchExact(permit) =
            authorize_realm_processor_startup(
                RealmProcessorStartupMode::RequireBranchExact(expectation()),
                Some(&Provider),
            )
            .await
            .unwrap()
        else {
            panic!("expected branch-exact permit")
        };
        permit
    }

    struct Runtime {
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        activation: [u8; 32],
        drops: Arc<AtomicUsize>,
    }

    impl RealmBranchExactCommitRuntime<PHash> for Runtime {
        fn network(&self) -> NetworkId {
            self.network
        }

        fn realm_id(&self) -> u32 {
            self.realm_id
        }

        fn realm_sub_id(&self) -> u16 {
            self.realm_sub_id
        }

        fn writer_activation_digest(&self) -> [u8; 32] {
            self.activation
        }

        fn queue_readiness_digest(&self) -> [u8; 32] {
            [6; 32]
        }

        fn scope(&self) -> RealmBranchExactRuntimeScope {
            RealmBranchExactRuntimeScope::MappingAndRewardProofDualWrite
        }
    }

    impl Drop for Runtime {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn runtime(
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        activation: [u8; 32],
        drops: Arc<AtomicUsize>,
    ) -> Arc<dyn RealmBranchExactCommitRuntime<PHash>> {
        Arc::new(Runtime {
            network,
            realm_id,
            realm_sub_id,
            activation,
            drops,
        })
    }

    struct CapturePort;

    #[async_trait]
    impl RealmProcessorDurableCapturePort for CapturePort {
        async fn capture_next(
            &mut self,
        ) -> Result<Option<RealmProcessorDurableCaptureOutcome>, RealmProcessorDurableCaptureError>
        {
            Ok(None)
        }

        async fn replay_complete_generation(
            &mut self,
        ) -> Result<
            Option<RealmProcessorDurableCapturedGeneration>,
            RealmProcessorDurableCaptureError,
        > {
            Ok(None)
        }

        async fn recover_application_handoff(
            &mut self,
        ) -> Result<
            Option<RealmProcessorApplicationHandoffObservation>,
            RealmProcessorDurableCaptureError,
        > {
            Ok(None)
        }

        async fn persist_application_and_handoff(
            &mut self,
            _semantic: RealmProcessorSemanticOutput,
        ) -> Result<
            RealmProcessorApplicationHandoffObservation,
            RealmProcessorDurableCaptureError,
        > {
            Err(RealmProcessorDurableCaptureError::ApplicationHandoffNotSealing)
        }
    }

    struct CaptureFactory {
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        activation: [u8; 32],
    }

    #[async_trait]
    impl RealmProcessorDurableCaptureFactory for CaptureFactory {
        fn network(&self) -> NetworkId {
            self.network
        }

        fn realm_id(&self) -> u32 {
            self.realm_id
        }

        fn realm_sub_id(&self) -> u16 {
            self.realm_sub_id
        }

        fn writer_activation_digest(&self) -> [u8; 32] {
            self.activation
        }

        fn queue_readiness_digest(&self) -> [u8; 32] {
            [6; 32]
        }

        async fn open(
            &self,
            request: SealedRealmProcessorDurableCaptureRequest,
        ) -> Result<Box<dyn RealmProcessorDurableCapturePort>, RealmProcessorDurableCaptureError>
        {
            if request.network() != self.network
                || request.realm_id() != self.realm_id
                || request.realm_sub_id() != self.realm_sub_id
                || request.writer_activation_digest() != &self.activation
                || request.queue_readiness_digest() != &self.queue_readiness_digest()
                || request.context().key().network() != self.network
                || request.context().key().authority()
                    != (AuthorityScope::Realm {
                        realm_id: self.realm_id,
                        realm_sub_id: self.realm_sub_id,
                    })
                || request.context().activation().as_bytes() != &self.activation
            {
                return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
            }
            Ok(Box::new(CapturePort))
        }
    }

    fn capture_factory(
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        activation: [u8; 32],
    ) -> Arc<dyn RealmProcessorDurableCaptureFactory> {
        Arc::new(CaptureFactory {
            network,
            realm_id,
            realm_sub_id,
            activation,
        })
    }

    #[tokio::test]
    async fn exact_runtime_consumes_permit_into_nonclone_capability() {
        let permit = permit().await;
        let expected_digest = permit.digest();
        let drops = Arc::new(AtomicUsize::new(0));
        let installed = InstalledRealmBranchExactCommitRuntime::seal(
            permit,
            runtime(network(), 7, 3, [2; 32], drops.clone()),
            capture_factory(network(), 7, 3, [2; 32]),
        )
        .unwrap();
        assert_eq!(installed.startup_permit_digest(), expected_digest);
        assert_eq!(installed.runtime().realm_id(), 7);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(installed);
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        let source = include_str!("realm_processor_branch_exact_runtime.rs");
        let installed = source
            .split("pub struct InstalledRealmBranchExactCommitRuntime")
            .nth(1)
            .unwrap()
            .split("impl<Hash> InstalledRealmBranchExactCommitRuntime")
            .next()
            .unwrap();
        assert!(!installed.contains("derive(Clone"));
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("impl Clone for InstalledRealmBranchExactCommitRuntime"));
    }

    #[tokio::test]
    async fn network_realm_sub_or_activation_mismatch_fails_closed() {
        for (candidate_network, realm_id, realm_sub_id, activation) in [
            (NetworkId::try_from_chain_id(1).unwrap(), 7, 3, [2; 32]),
            (network(), 8, 3, [2; 32]),
            (network(), 7, 4, [2; 32]),
            (network(), 7, 3, [9; 32]),
        ] {
            let result = InstalledRealmBranchExactCommitRuntime::seal(
                permit().await,
                runtime(
                    candidate_network,
                    realm_id,
                    realm_sub_id,
                    activation,
                    Arc::new(AtomicUsize::new(0)),
                ),
                capture_factory(network(), 7, 3, [2; 32]),
            );
            let Err(error) = result else {
                panic!("mismatched runtime must not install")
            };
            assert_eq!(
                error,
                RealmProcessorStartupError::CommitRuntimeIdentityMismatch
            );
        }

        let result = InstalledRealmBranchExactCommitRuntime::seal(
            permit().await,
            runtime(
                network(),
                7,
                3,
                [2; 32],
                Arc::new(AtomicUsize::new(0)),
            ),
            capture_factory(network(), 7, 3, [9; 32]),
        );
        assert!(matches!(
            result,
            Err(RealmProcessorStartupError::CommitRuntimeIdentityMismatch)
        ));
    }

    #[tokio::test]
    async fn single_owner_requires_the_real_controlled_iteration_permit() {
        let installed = InstalledRealmBranchExactCommitRuntime::seal(
            permit().await,
            runtime(
                network(),
                7,
                3,
                [2; 32],
                Arc::new(AtomicUsize::new(0)),
            ),
            capture_factory(network(), 7, 3, [2; 32]),
        )
        .unwrap();
        let mut owner = RealmBranchExactSingleCommitOwner::from_installed(installed);

        let disabled = crate::store::realm_processor_quiescence::RealmProcessorIterationGate::disabled();
        assert!(matches!(
            owner.begin_iteration(disabled.try_begin_iteration().unwrap()),
            Err(RealmBranchExactCommitOwnerError::UncontrolledIterationPermit)
        ));

        let controlled = crate::store::realm_processor_quiescence::RealmProcessorIterationGate::controlled();
        {
            let mut attempt = owner
                .begin_iteration(controlled.try_begin_iteration().unwrap())
                .unwrap();
            assert_eq!(attempt.network(), network());
            assert_eq!(attempt.realm_id(), 7);
            assert_eq!(attempt.realm_sub_id(), 3);
            let mut capture = attempt
                .open_durable_capture_for_processing(
                    PendingGenerationContext::try_from_legacy(17, 19).unwrap(),
                )
                .await
                .unwrap();
            assert!(capture.capture_next().await.unwrap().is_none());
            assert!(controlled.snapshot().active_iteration());
        }
        assert!(!controlled.snapshot().active_iteration());
        drop(owner
            .begin_iteration(controlled.try_begin_iteration().unwrap())
            .unwrap());
    }

    #[test]
    fn h23c4a_runtime_has_no_live_mutation_api() {
        let source = include_str!("realm_processor_branch_exact_runtime.rs");
        let runtime_trait = source
            .split("pub trait RealmBranchExactCommitRuntime")
            .nth(1)
            .unwrap()
            .split("pub struct InstalledRealmBranchExactCommitRuntime")
            .next()
            .unwrap();
        assert!(!runtime_trait.contains("async fn"));
        assert!(!runtime_trait.contains("prepare_and_verify"));
        assert!(!runtime_trait.contains("finish_published"));
    }

    #[test]
    fn owner_and_attempt_are_nonclone_and_expose_only_affine_capture() {
        let source = include_str!("realm_processor_branch_exact_runtime.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for declaration in [
            "pub struct RealmBranchExactSingleCommitOwner",
            "pub struct RealmBranchExactCommitIteration",
        ] {
            let before = production.split(declaration).next().unwrap();
            let attributes = before.lines().rev().take(3).collect::<Vec<_>>().join("\n");
            assert!(!attributes.contains("Clone"));
            assert!(!attributes.contains("Default"));
        }
        assert!(!production.contains("impl Clone for RealmBranchExactSingleCommitOwner"));
        assert!(!production.contains("impl Clone for RealmBranchExactCommitIteration"));

        let attempt = production
            .split("impl<Hash> RealmBranchExactCommitIteration")
            .nth(1)
            .unwrap();
        assert_eq!(attempt.matches("pub async fn open_durable_capture").count(), 1);
        assert!(attempt.contains("open_durable_capture_for_processing"));
        for forbidden in [
            "prepare_and_verify",
            "finish_published",
            "publish_marker",
            "queue_close",
            "ack_token",
            "CanonicalChainRef",
            "Session",
        ] {
            assert!(!attempt.contains(forbidden));
        }
    }
}
