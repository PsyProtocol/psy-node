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
use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::NetworkId;

use crate::queue::{
    realm_processor_durable_capture::{
        RealmProcessorApplicationHandoffObservation,
        RealmProcessorDurableCaptureError, RealmProcessorDurableCaptureFactory,
        RealmProcessorDurableCaptureOutcome, RealmProcessorDurableCapturePort,
        RealmProcessorDurableCapturedGeneration,
        SealedRealmProcessorDurableCaptureRequest,
        SealedRealmProcessorGenerationContinuationRequest,
    },
    realm_processor_deferred_actor_input::{
        RealmProcessorDeferredActorInput, RealmProcessorDeferredActorInputOutcome,
    },
    realm_processor_application_proof_work::RealmProcessorApplicationProofWorkOutcome,
    realm_processor_external_dependency_input::RealmProcessorQualifiedExternalActorInput,
    realm_processor_generation_continuation::RealmProcessorGenerationContinuation,
    realm_processor_narrow_writer::{
        RealmProcessorNarrowWriterError, RealmProcessorNarrowWriterFactory,
        RealmProcessorNarrowWriterObservation,
        RealmProcessorVerifiedNarrowWriterEvidence,
        SealedRealmProcessorNarrowWriterRequest,
    },
    realm_processor_continuation_restart::{
        RealmProcessorContinuationRestartFactory,
        RealmProcessorContinuationRestartPort,
        RealmProcessorReadOnlyRestartPreparation,
        RealmProcessorTerminalCarryoverRecoveryFactory,
        RealmProcessorTerminalCarryoverRecoveryOutcome,
        RealmProcessorTerminalCarryoverRecoveryPort,
        SealedRealmProcessorContinuationRestartRequest,
        SealedRealmProcessorTerminalCarryoverRecoveryRequest,
    },
    realm_processor_semantic_output::RealmProcessorSemanticOutput,
};

use super::realm_processor_startup::{
    RealmProcessorFreshRunPermit, RealmProcessorStartupError,
    RealmProcessorStartupPermitDigest,
};
use super::realm_processor_quiescence::RealmProcessorIterationPermit;
use super::authority_commit::AuthorityClockSampleUs;

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
    restart_factory: Arc<dyn RealmProcessorContinuationRestartFactory<Hash>>,
    terminal_carryover_recovery_factory:
        Arc<dyn RealmProcessorTerminalCarryoverRecoveryFactory<Hash>>,
    narrow_writer_factory: Arc<dyn RealmProcessorNarrowWriterFactory<Hash>>,
}

impl<Hash> InstalledRealmBranchExactCommitRuntime<Hash> {
    /// The only constructor.  It consumes the non-Clone permit and rejects a
    /// runtime prepared for another network, Realm, or writer activation.
    pub fn seal(
        startup_permit: RealmProcessorFreshRunPermit,
        runtime: Arc<dyn RealmBranchExactCommitRuntime<Hash>>,
        capture_factory: Arc<dyn RealmProcessorDurableCaptureFactory>,
        restart_factory: Arc<dyn RealmProcessorContinuationRestartFactory<Hash>>,
        terminal_carryover_recovery_factory: Arc<
            dyn RealmProcessorTerminalCarryoverRecoveryFactory<Hash>,
        >,
        narrow_writer_factory: Arc<dyn RealmProcessorNarrowWriterFactory<Hash>>,
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
            || restart_factory.network() != runtime.network()
            || restart_factory.realm_id() != runtime.realm_id()
            || restart_factory.realm_sub_id() != runtime.realm_sub_id()
            || restart_factory.writer_activation_digest()
                != runtime.writer_activation_digest()
            || restart_factory.queue_readiness_digest()
                != runtime.queue_readiness_digest()
            || terminal_carryover_recovery_factory.network() != runtime.network()
            || terminal_carryover_recovery_factory.realm_id() != runtime.realm_id()
            || terminal_carryover_recovery_factory.realm_sub_id() != runtime.realm_sub_id()
            || terminal_carryover_recovery_factory.writer_activation_digest()
                != runtime.writer_activation_digest()
            || terminal_carryover_recovery_factory.queue_readiness_digest()
                != runtime.queue_readiness_digest()
            || narrow_writer_factory.network() != runtime.network()
            || narrow_writer_factory.realm_id() != runtime.realm_id()
            || narrow_writer_factory.realm_sub_id() != runtime.realm_sub_id()
            || narrow_writer_factory.writer_activation_digest()
                != runtime.writer_activation_digest()
            || narrow_writer_factory.queue_readiness_digest()
                != runtime.queue_readiness_digest()
        {
            return Err(RealmProcessorStartupError::CommitRuntimeIdentityMismatch);
        }
        Ok(Self {
            startup_permit,
            runtime,
            capture_factory,
            restart_factory,
            terminal_carryover_recovery_factory,
            narrow_writer_factory,
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

    fn restart_factory(
        &self,
    ) -> &Arc<dyn RealmProcessorContinuationRestartFactory<Hash>> {
        &self.restart_factory
    }

    fn terminal_carryover_recovery_factory(
        &self,
    ) -> &Arc<dyn RealmProcessorTerminalCarryoverRecoveryFactory<Hash>> {
        &self.terminal_carryover_recovery_factory
    }

    fn narrow_writer_factory(&self) -> &Arc<dyn RealmProcessorNarrowWriterFactory<Hash>> {
        &self.narrow_writer_factory
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

    /// Verifies the existing eight-leg Realm mapping/reward-proof writer and
    /// advances only the first application candidate from `WorkCaptured` to
    /// `InFlight`. Pending/proc identity is selected from durable storage;
    /// this operation cannot publish the authority head, terminalize, or
    /// rotate a generation.
    pub async fn prepare_mapping_and_reward_proof(
        &mut self,
        evidence: &RealmProcessorVerifiedNarrowWriterEvidence<Hash>,
        clock_sample: AuthorityClockSampleUs,
    ) -> Result<RealmProcessorNarrowWriterObservation, RealmProcessorNarrowWriterError>
    where
        Hash: Q256BitHash + 'static,
    {
        let runtime = self.owner.runtime();
        let factory = Arc::clone(self.owner.installed.narrow_writer_factory());
        let request = SealedRealmProcessorNarrowWriterRequest::seal(
            self.owner.startup_permit_digest(),
            runtime.network(),
            runtime.realm_id(),
            runtime.realm_sub_id(),
            runtime.writer_activation_digest(),
            runtime.queue_readiness_digest(),
            evidence,
            clock_sample,
        )?;
        factory.prepare_and_verify(request).await
    }

    /// Freshly observes the storage-selected processing generation. This is
    /// the only branch-exact source of pending/proc identity; the legacy DB
    /// singleton is intentionally not an input.
    pub async fn observe_generation_continuation(
        &mut self,
    ) -> Result<RealmProcessorGenerationContinuation, RealmProcessorDurableCaptureError> {
        let runtime = self.owner.runtime();
        let factory = Arc::clone(self.owner.installed.capture_factory());
        factory
            .observe_generation_continuation(
                SealedRealmProcessorGenerationContinuationRequest::seal(
                    self.owner.startup_permit_digest(),
                    runtime.network(),
                    runtime.realm_id(),
                    runtime.realm_sub_id(),
                    runtime.writer_activation_digest(),
                    runtime.queue_readiness_digest(),
                ),
            )
            .await
    }

    /// Freshly reconstruct the storage-selected successor carryover. This
    /// returns a non-Clone typed actor input but does not yet open capture or
    /// authorize actor mutation; c4b4b moves it into the sealed capture-open
    /// boundary for the third freshness check.
    pub async fn prepare_deferred_actor_input(
        &mut self,
    ) -> Result<RealmProcessorDeferredActorInputOutcome, RealmProcessorDurableCaptureError> {
        let runtime = self.owner.runtime();
        let factory = Arc::clone(self.owner.installed.capture_factory());
        factory
            .prepare_deferred_actor_input(
                SealedRealmProcessorGenerationContinuationRequest::seal(
                    self.owner.startup_permit_digest(),
                    runtime.network(),
                    runtime.realm_id(),
                    runtime.realm_sub_id(),
                    runtime.writer_activation_digest(),
                    runtime.queue_readiness_digest(),
                ),
            )
            .await
    }

    /// Rebuilds the exact immutable application selected by `WorkCaptured`.
    /// Pending/proc identity and archive slot are selected by storage, never
    /// supplied by the Processor or its legacy mutable state.
    pub async fn prepare_application_proof_work(
        &mut self,
    ) -> Result<RealmProcessorApplicationProofWorkOutcome, RealmProcessorDurableCaptureError> {
        let runtime = self.owner.runtime();
        let factory = Arc::clone(self.owner.installed.capture_factory());
        factory
            .prepare_application_proof_work(
                SealedRealmProcessorGenerationContinuationRequest::seal(
                    self.owner.startup_permit_digest(),
                    runtime.network(),
                    runtime.realm_id(),
                    runtime.realm_sub_id(),
                    runtime.writer_activation_digest(),
                    runtime.queue_readiness_digest(),
                ),
            )
            .await
    }

    /// Opens one storage-owned, one-shot restart preparation while borrowing
    /// the complete iteration. It cannot coexist with a durable-capture
    /// handle borrowed from the same owner.
    pub async fn open_continuation_restart<'restart>(
        &'restart mut self,
    ) -> Result<RealmBranchExactContinuationRestart<'restart>, RealmProcessorDurableCaptureError>
    where
        Hash: 'static,
    {
        let runtime = self.owner.runtime();
        let factory = Arc::clone(self.owner.installed.restart_factory());
        let request = SealedRealmProcessorContinuationRestartRequest::seal(
            self.owner.startup_permit_digest(),
            runtime.network(),
            runtime.realm_id(),
            runtime.realm_sub_id(),
            runtime.writer_activation_digest(),
            runtime.queue_readiness_digest(),
        );
        let port = factory.open(request).await?;
        Ok(RealmBranchExactContinuationRestart {
            port,
            _iteration: PhantomData,
        })
    }

    /// Opens the separate terminal-to-carryover repair capability. Storage
    /// selects the processing generation and may only derive a successor
    /// carryover from an already durable terminal record. The capability
    /// cannot create a terminal, reserve a generation or rotate the pipeline.
    pub async fn open_terminal_carryover_recovery<'recovery>(
        &'recovery mut self,
    ) -> Result<RealmBranchExactTerminalCarryoverRecovery<'recovery>, RealmProcessorDurableCaptureError>
    where
        Hash: 'static,
    {
        let runtime = self.owner.runtime();
        let factory = Arc::clone(
            self.owner
                .installed
                .terminal_carryover_recovery_factory(),
        );
        let request = SealedRealmProcessorTerminalCarryoverRecoveryRequest::seal(
            self.owner.startup_permit_digest(),
            runtime.network(),
            runtime.realm_id(),
            runtime.realm_sub_id(),
            runtime.writer_activation_digest(),
            runtime.queue_readiness_digest(),
        );
        let port = factory.open(request).await?;
        Ok(RealmBranchExactTerminalCarryoverRecovery {
            port,
            _iteration: PhantomData,
        })
    }

    /// Opens one backend-owned capture authority while borrowing this whole
    /// iteration mutably.  The returned port cannot outlive the iteration and
    /// no second queue mutation can be opened through the same owner until it
    /// is dropped.
    async fn open_durable_capture<'capture>(
        &'capture mut self,
        deferred_input: RealmProcessorDeferredActorInput,
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
            deferred_input,
        )?;
        let port = factory.open(request).await?;
        Ok(RealmBranchExactDurableCapture {
            port,
            _iteration: PhantomData,
        })
    }

    /// Production-shaped capture entry. The Processor moves the exact
    /// storage-loaded input into this sealed boundary; processing identity is
    /// derived from the input and cannot be supplied independently.
    pub async fn open_durable_capture_for_deferred_input<'capture>(
        &'capture mut self,
        deferred_input: RealmProcessorDeferredActorInput,
    ) -> Result<RealmBranchExactDurableCapture<'capture>, RealmProcessorDurableCaptureError> {
        self.open_durable_capture(deferred_input).await
    }
}

/// Lifetime-bound affine capture handle.  It exposes canonical outcomes only;
/// backend delivery/ACK receipts remain private to the adapter.
pub struct RealmBranchExactDurableCapture<'iteration> {
    port: Box<dyn RealmProcessorDurableCapturePort>,
    _iteration: PhantomData<&'iteration mut ()>,
}

/// Lifetime-bound, non-Clone restart preparation. The sole operation consumes
/// the handle, preventing a stale private snapshot from being reused.
pub struct RealmBranchExactContinuationRestart<'iteration> {
    port: Box<dyn RealmProcessorContinuationRestartPort>,
    _iteration: PhantomData<&'iteration mut ()>,
}

/// Lifetime-bound, non-Clone derived-repair capability. The sole operation
/// consumes the handle and returns only a non-authoritative observation.
pub struct RealmBranchExactTerminalCarryoverRecovery<'iteration> {
    port: Box<dyn RealmProcessorTerminalCarryoverRecoveryPort>,
    _iteration: PhantomData<&'iteration mut ()>,
}

impl RealmBranchExactContinuationRestart<'_> {
    pub async fn observe_and_prepare(
        self,
    ) -> Result<RealmProcessorReadOnlyRestartPreparation, RealmProcessorDurableCaptureError> {
        self.port.observe_and_prepare().await
    }
}

impl RealmBranchExactTerminalCarryoverRecovery<'_> {
    pub async fn recover_and_prepare(
        self,
    ) -> Result<RealmProcessorTerminalCarryoverRecoveryOutcome, RealmProcessorDurableCaptureError>
    {
        self.port.recover_and_prepare().await
    }
}

impl RealmBranchExactDurableCapture<'_> {
    pub async fn take_deferred_actor_input(
        &mut self,
    ) -> Result<RealmProcessorDeferredActorInput, RealmProcessorDurableCaptureError> {
        self.port.take_deferred_actor_input().await
    }

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

    /// Rebuilds and joins the exact external dependency bytes selected by the
    /// predecessor terminal. The closed transport generation is consumed so
    /// it cannot be paired with another dependency projection.
    pub async fn qualify_external_actor_input(
        &mut self,
        generation: RealmProcessorDurableCapturedGeneration,
    ) -> Result<RealmProcessorQualifiedExternalActorInput, RealmProcessorDurableCaptureError> {
        self.port.qualify_external_actor_input(generation).await
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

    struct CapturePort {
        deferred_input: Option<RealmProcessorDeferredActorInput>,
    }

    struct RestartPort {
        preparation: RealmProcessorReadOnlyRestartPreparation,
    }

    struct TerminalCarryoverRecoveryPort {
        outcome: RealmProcessorTerminalCarryoverRecoveryOutcome,
    }

    #[async_trait]
    impl RealmProcessorContinuationRestartPort for RestartPort {
        async fn observe_and_prepare(
            self: Box<Self>,
        ) -> Result<RealmProcessorReadOnlyRestartPreparation, RealmProcessorDurableCaptureError>
        {
            Ok(self.preparation)
        }
    }

    #[async_trait]
    impl RealmProcessorTerminalCarryoverRecoveryPort for TerminalCarryoverRecoveryPort {
        async fn recover_and_prepare(
            self: Box<Self>,
        ) -> Result<RealmProcessorTerminalCarryoverRecoveryOutcome, RealmProcessorDurableCaptureError>
        {
            Ok(self.outcome)
        }
    }

    #[async_trait]
    impl RealmProcessorDurableCapturePort for CapturePort {
        async fn take_deferred_actor_input(
            &mut self,
        ) -> Result<RealmProcessorDeferredActorInput, RealmProcessorDurableCaptureError> {
            self.deferred_input
                .take()
                .ok_or(RealmProcessorDurableCaptureError::IdentityMismatch)
        }

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

        async fn qualify_external_actor_input(
            &mut self,
            _generation: RealmProcessorDurableCapturedGeneration,
        ) -> Result<RealmProcessorQualifiedExternalActorInput, RealmProcessorDurableCaptureError>
        {
            Err(RealmProcessorDurableCaptureError::IdentityMismatch)
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

        async fn observe_generation_continuation(
            &self,
            request: SealedRealmProcessorGenerationContinuationRequest,
        ) -> Result<RealmProcessorGenerationContinuation, RealmProcessorDurableCaptureError> {
            if request.network() != self.network
                || request.realm_id() != self.realm_id
                || request.realm_sub_id() != self.realm_sub_id
                || request.writer_activation_digest() != &self.activation
                || request.queue_readiness_digest() != &[6; 32]
            {
                return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
            }
            RealmProcessorGenerationContinuation::try_from_storage(
                PendingGenerationContext::try_from_legacy(17, 19).unwrap(),
                crate::store::pending_generation_pipeline::PendingPipelineRevision::try_new(3)
                    .unwrap(),
                crate::queue::realm_processor_generation_continuation::RealmProcessorGenerationContinuationPhase::CaptureClosedSource,
                None,
            )
            .map_err(|_| RealmProcessorDurableCaptureError::IdentityMismatch)
        }

        async fn prepare_deferred_actor_input(
            &self,
            request: SealedRealmProcessorGenerationContinuationRequest,
        ) -> Result<RealmProcessorDeferredActorInputOutcome, RealmProcessorDurableCaptureError> {
            let continuation = self.observe_generation_continuation(request).await?;
            let successor = continuation.processing();
            let reason = crate::store::pending_generation_identity::PendingGenerationBootstrapReason::LegacyActivation;
            let key = crate::store::pending_generation_identity::PendingGenerationLedgerKey::new(
                self.network,
                AuthorityScope::Realm {
                    realm_id: self.realm_id,
                    realm_sub_id: self.realm_sub_id,
                },
            );
            let activation = crate::store::pending_generation_identity::PendingGenerationActivationDigest::try_new(
                self.activation,
            )
            .map_err(|_| RealmProcessorDurableCaptureError::IdentityMismatch)?;
            let carryover = crate::queue::realm_processor_generation_terminal::RealmProcessorDeferredCarryover::try_bootstrap_empty(
                key,
                activation,
                successor,
                reason,
            )
            .map_err(|_| RealmProcessorDurableCaptureError::IdentityMismatch)?;
            let input = RealmProcessorDeferredActorInput::try_from_storage(
                successor,
                reason,
                carryover,
                None,
            )
            .map_err(|_| RealmProcessorDurableCaptureError::IdentityMismatch)?;
            Ok(RealmProcessorDeferredActorInputOutcome::Ready(input))
        }

        async fn prepare_application_proof_work(
            &self,
            request: SealedRealmProcessorGenerationContinuationRequest,
        ) -> Result<RealmProcessorApplicationProofWorkOutcome, RealmProcessorDurableCaptureError> {
            let _ = self.observe_generation_continuation(request).await?;
            Err(RealmProcessorDurableCaptureError::Backend(
                "proof-work fixture is intentionally unavailable".to_owned(),
            ))
        }

        async fn open(
            self: Arc<Self>,
            request: SealedRealmProcessorDurableCaptureRequest,
        ) -> Result<Box<dyn RealmProcessorDurableCapturePort>, RealmProcessorDurableCaptureError>
        {
            if request.network() != self.network
                || request.realm_id() != self.realm_id
                || request.realm_sub_id() != self.realm_sub_id
                || request.writer_activation_digest() != &self.activation
                || request.queue_readiness_digest() != &[6; 32]
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
            Ok(Box::new(CapturePort {
                deferred_input: Some(request.into_deferred_input()),
            }))
        }
    }

    #[async_trait]
    impl RealmProcessorContinuationRestartFactory<PHash> for CaptureFactory {
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
            self: Arc<Self>,
            request: SealedRealmProcessorContinuationRestartRequest,
        ) -> Result<Box<dyn RealmProcessorContinuationRestartPort>, RealmProcessorDurableCaptureError>
        {
            if request.network() != self.network
                || request.realm_id() != self.realm_id
                || request.realm_sub_id() != self.realm_sub_id
                || request.writer_activation_digest() != &self.activation
                || request.queue_readiness_digest() != &[6; 32]
            {
                return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
            }
            let continuation = RealmProcessorGenerationContinuation::try_from_storage(
                PendingGenerationContext::try_from_legacy(17, 19).unwrap(),
                crate::store::pending_generation_pipeline::PendingPipelineRevision::try_new(3)
                    .unwrap(),
                crate::queue::realm_processor_generation_continuation::RealmProcessorGenerationContinuationPhase::AwaitQueueClose,
                None,
            )
            .map_err(|_| RealmProcessorDurableCaptureError::IdentityMismatch)?;
            let preparation = RealmProcessorReadOnlyRestartPreparation::try_from_storage(
                continuation,
                crate::queue::realm_processor_continuation_restart::RealmProcessorInboundCarryoverObservation::Missing,
                crate::queue::realm_processor_continuation_restart::RealmProcessorTerminalCarryoverObservation::NotEvaluated,
            )
            .map_err(|_| RealmProcessorDurableCaptureError::IdentityMismatch)?;
            Ok(Box::new(RestartPort { preparation }))
        }
    }

    #[async_trait]
    impl RealmProcessorTerminalCarryoverRecoveryFactory<PHash> for CaptureFactory {
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
            self: Arc<Self>,
            request: SealedRealmProcessorTerminalCarryoverRecoveryRequest,
        ) -> Result<Box<dyn RealmProcessorTerminalCarryoverRecoveryPort>, RealmProcessorDurableCaptureError>
        {
            if request.network() != self.network
                || request.realm_id() != self.realm_id
                || request.realm_sub_id() != self.realm_sub_id
                || request.writer_activation_digest() != &self.activation
                || request.queue_readiness_digest() != &[6; 32]
            {
                return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
            }
            let continuation = RealmProcessorGenerationContinuation::try_from_storage(
                PendingGenerationContext::try_from_legacy(17, 19).unwrap(),
                crate::store::pending_generation_pipeline::PendingPipelineRevision::try_new(3)
                    .unwrap(),
                crate::queue::realm_processor_generation_continuation::RealmProcessorGenerationContinuationPhase::AwaitQueueClose,
                None,
            )
            .map_err(|_| RealmProcessorDurableCaptureError::IdentityMismatch)?;
            let preparation = RealmProcessorReadOnlyRestartPreparation::try_from_storage(
                continuation,
                crate::queue::realm_processor_continuation_restart::RealmProcessorInboundCarryoverObservation::Missing,
                crate::queue::realm_processor_continuation_restart::RealmProcessorTerminalCarryoverObservation::NotEvaluated,
            )
            .map_err(|_| RealmProcessorDurableCaptureError::IdentityMismatch)?;
            let outcome = RealmProcessorTerminalCarryoverRecoveryOutcome::try_from_storage(
                preparation,
            )
            .map_err(|_| RealmProcessorDurableCaptureError::IdentityMismatch)?;
            Ok(Box::new(TerminalCarryoverRecoveryPort { outcome }))
        }
    }

    #[async_trait]
    impl RealmProcessorNarrowWriterFactory<PHash> for CaptureFactory {
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

        async fn prepare_and_verify(
            &self,
            request: SealedRealmProcessorNarrowWriterRequest<PHash>,
        ) -> Result<RealmProcessorNarrowWriterObservation, RealmProcessorNarrowWriterError> {
            if request.network() != self.network
                || request.realm_id() != self.realm_id
                || request.realm_sub_id() != self.realm_sub_id
                || request.writer_activation_digest() != &self.activation
                || request.queue_readiness_digest() != &[6; 32]
            {
                return Err(RealmProcessorNarrowWriterError::IdentityMismatch);
            }
            Err(RealmProcessorNarrowWriterError::Backend(
                "writer fixture is installation-only".to_owned(),
            ))
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

    fn restart_factory(
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        activation: [u8; 32],
    ) -> Arc<dyn RealmProcessorContinuationRestartFactory<PHash>> {
        Arc::new(CaptureFactory {
            network,
            realm_id,
            realm_sub_id,
            activation,
        })
    }

    fn terminal_carryover_recovery_factory(
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        activation: [u8; 32],
    ) -> Arc<dyn RealmProcessorTerminalCarryoverRecoveryFactory<PHash>> {
        Arc::new(CaptureFactory {
            network,
            realm_id,
            realm_sub_id,
            activation,
        })
    }

    fn narrow_writer_factory(
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        activation: [u8; 32],
    ) -> Arc<dyn RealmProcessorNarrowWriterFactory<PHash>> {
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
            restart_factory(network(), 7, 3, [2; 32]),
            terminal_carryover_recovery_factory(network(), 7, 3, [2; 32]),
            narrow_writer_factory(network(), 7, 3, [2; 32]),
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
                restart_factory(network(), 7, 3, [2; 32]),
                terminal_carryover_recovery_factory(network(), 7, 3, [2; 32]),
                narrow_writer_factory(network(), 7, 3, [2; 32]),
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
            restart_factory(network(), 7, 3, [2; 32]),
            terminal_carryover_recovery_factory(network(), 7, 3, [2; 32]),
            narrow_writer_factory(network(), 7, 3, [2; 32]),
        );
        assert!(matches!(
            result,
            Err(RealmProcessorStartupError::CommitRuntimeIdentityMismatch)
        ));

        let result = InstalledRealmBranchExactCommitRuntime::seal(
            permit().await,
            runtime(
                network(),
                7,
                3,
                [2; 32],
                Arc::new(AtomicUsize::new(0)),
            ),
            capture_factory(network(), 7, 3, [2; 32]),
            restart_factory(network(), 7, 4, [2; 32]),
            terminal_carryover_recovery_factory(network(), 7, 3, [2; 32]),
            narrow_writer_factory(network(), 7, 3, [2; 32]),
        );
        assert!(matches!(
            result,
            Err(RealmProcessorStartupError::CommitRuntimeIdentityMismatch)
        ));

        let result = InstalledRealmBranchExactCommitRuntime::seal(
            permit().await,
            runtime(
                network(),
                7,
                3,
                [2; 32],
                Arc::new(AtomicUsize::new(0)),
            ),
            capture_factory(network(), 7, 3, [2; 32]),
            restart_factory(network(), 7, 3, [2; 32]),
            terminal_carryover_recovery_factory(network(), 7, 4, [2; 32]),
            narrow_writer_factory(network(), 7, 3, [2; 32]),
        );
        assert!(matches!(
            result,
            Err(RealmProcessorStartupError::CommitRuntimeIdentityMismatch)
        ));

        let result = InstalledRealmBranchExactCommitRuntime::seal(
            permit().await,
            runtime(
                network(),
                7,
                3,
                [2; 32],
                Arc::new(AtomicUsize::new(0)),
            ),
            capture_factory(network(), 7, 3, [2; 32]),
            restart_factory(network(), 7, 3, [2; 32]),
            terminal_carryover_recovery_factory(network(), 7, 3, [2; 32]),
            narrow_writer_factory(network(), 8, 3, [2; 32]),
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
            restart_factory(network(), 7, 3, [2; 32]),
            terminal_carryover_recovery_factory(network(), 7, 3, [2; 32]),
            narrow_writer_factory(network(), 7, 3, [2; 32]),
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
            let continuation = attempt.observe_generation_continuation().await.unwrap();
            assert_eq!(continuation.processing().pending_id().get(), 17);
            let input = match attempt.prepare_deferred_actor_input().await.unwrap() {
                RealmProcessorDeferredActorInputOutcome::Ready(input) => input,
                RealmProcessorDeferredActorInputOutcome::AwaitExplicitCarryover { .. } => {
                    panic!("fixture must provide explicit bootstrap carryover")
                }
            };
            let expected_input_digest = input.digest();
            let mut capture = attempt
                .open_durable_capture_for_deferred_input(input)
                .await
                .unwrap();
            assert_eq!(
                capture.take_deferred_actor_input().await.unwrap().digest(),
                expected_input_digest
            );
            assert!(capture.take_deferred_actor_input().await.is_err());
            assert!(capture.capture_next().await.unwrap().is_none());
            assert!(controlled.snapshot().active_iteration());
        }
        {
            let mut attempt = owner
                .begin_iteration(controlled.try_begin_iteration().unwrap())
                .unwrap();
            let restart = attempt.open_continuation_restart().await.unwrap();
            let preparation = restart.observe_and_prepare().await.unwrap();
            assert_eq!(
                preparation.continuation().phase(),
                crate::queue::realm_processor_generation_continuation::RealmProcessorGenerationContinuationPhase::AwaitQueueClose
            );
            assert_eq!(
                preparation.inbound(),
                crate::queue::realm_processor_continuation_restart::RealmProcessorInboundCarryoverObservation::Missing
            );
        }
        {
            let mut attempt = owner
                .begin_iteration(controlled.try_begin_iteration().unwrap())
                .unwrap();
            let recovery = attempt
                .open_terminal_carryover_recovery()
                .await
                .unwrap();
            let outcome = recovery.recover_and_prepare().await.unwrap();
            assert!(matches!(
                outcome,
                RealmProcessorTerminalCarryoverRecoveryOutcome::AwaitExplicitInboundCarryover(_)
            ));
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
    fn owner_and_attempt_are_nonclone_and_expose_only_affine_ports() {
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
        assert!(attempt.contains("open_durable_capture_for_deferred_input"));
        assert!(attempt.contains("prepare_mapping_and_reward_proof"));
        assert!(attempt.contains("narrow_writer_factory"));
        for forbidden in [
            "finish_published",
            "publish_marker",
            "ack_token",
            "Session",
            "seal_branch_exact_publish",
            "seal_branch_exact_no_work",
            "seal_rotation",
            "authority_head",
        ] {
            assert!(!attempt.contains(forbidden));
        }
    }
}
