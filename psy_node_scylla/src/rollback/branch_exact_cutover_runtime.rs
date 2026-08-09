//! Default-off composition fence between the h22 writer and h22e3 route row.
//!
//! An independent control read is not an atomic fence. This wrapper therefore
//! samples the exact route before and after writer preparation and before and
//! after publish finalization. Any route revision or full-payload change makes
//! the writer barrier stale. Production Processor ownership is intentionally
//! not wired in this slice; finalization additionally requires an opaque drain
//! lease so a future caller cannot accidentally omit that protocol step.

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::{CanonicalChainRef, NetworkId},
    chain_context::AuthorityScope,
};
use psy_node_core::store::{
    authority_commit::{AuthorityClockSampleUs, AuthorityTimestampPhase},
    branch_exact_dual_write::BranchExactDualWriteIntent,
};
use scylla::client::session::Session;

use super::{
    BranchExactCutoverAuthorityKey, BranchExactCutoverBindingDigest,
    BranchExactCutoverGeneration, BranchExactCutoverPhase,
    BranchExactCutoverReadState, BranchExactCutoverRevision,
    BranchExactCutoverPermit, BranchExactCutoverWriteOutcome,
    BranchExactDeploymentNoTabletKeyspace,
    BranchExactPublishBarrier, BranchExactWriterRuntimeError,
    BranchExactWriterCutoverFence,
    BranchExactWriterState, SealedBranchExactCutoverCas,
    ScyllaBranchExactCutoverStore, ScyllaBranchExactWriterRuntime,
    StoredBranchExactCutover,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BranchExactCutoverRuntimeRequest {
    network: NetworkId,
    authority: AuthorityScope,
    expected_generation: BranchExactCutoverGeneration,
    expected_binding_digest: BranchExactCutoverBindingDigest,
}

impl BranchExactCutoverRuntimeRequest {
    pub fn try_new(
        network: NetworkId,
        authority: AuthorityScope,
        expected_generation: BranchExactCutoverGeneration,
        expected_binding_digest: BranchExactCutoverBindingDigest,
    ) -> Result<Self, BranchExactCutoverRuntimeError> {
        BranchExactCutoverAuthorityKey::try_new(network, authority)
            .map_err(|error| BranchExactCutoverRuntimeError::Store(error.to_string()))?;
        Ok(Self {
            network,
            authority,
            expected_generation,
            expected_binding_digest,
        })
    }
}

/// Exact serving-route observation held across one h22 writer operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactCutoverRouteFence {
    writer_fence: BranchExactWriterCutoverFence,
}

impl BranchExactCutoverRouteFence {
    pub(crate) fn try_from_current<Hash: Q256BitHash>(
        current: &StoredBranchExactCutover<Hash>,
    ) -> Result<Self, BranchExactCutoverRuntimeError> {
        Ok(Self {
            writer_fence: BranchExactWriterCutoverFence::try_from_current(current)
                .map_err(|_| BranchExactCutoverRuntimeError::RouteQuiescing)?,
        })
    }

    pub(crate) fn matches<Hash: Q256BitHash>(
        &self,
        current: &StoredBranchExactCutover<Hash>,
    ) -> bool {
        self.writer_fence.matches(current)
    }

    pub const fn generation(&self) -> BranchExactCutoverGeneration {
        self.writer_fence.generation()
    }

    pub const fn revision(&self) -> BranchExactCutoverRevision {
        self.writer_fence.revision()
    }

    pub const fn phase(&self) -> BranchExactCutoverPhase {
        self.writer_fence.phase()
    }

    pub(crate) fn writer_fence(&self) -> BranchExactWriterCutoverFence {
        self.writer_fence.clone()
    }
}

/// Verified Processor observation required to hold the route stable while a
/// durable authority marker is published. The constructor is crate-private;
/// h22e3 does not yet connect it to the real Processor loop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BranchExactProcessorDrainObservation {
    new_work_guarded: bool,
    in_flight_work: u64,
    publish_in_flight: bool,
}

impl BranchExactProcessorDrainObservation {
    pub(crate) const fn try_new(
        new_work_guarded: bool,
        in_flight_work: u64,
        publish_in_flight: bool,
    ) -> Result<Self, BranchExactCutoverRuntimeError> {
        if !new_work_guarded || in_flight_work != 0 || publish_in_flight {
            return Err(BranchExactCutoverRuntimeError::ProcessorNotDrained);
        }
        Ok(Self {
            new_work_guarded,
            in_flight_work,
            publish_in_flight,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactProcessorOwnedLease {
    fence: BranchExactCutoverRouteFence,
    observation: BranchExactProcessorDrainObservation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchExactCutoverTransitionAction {
    PrepareTarget,
    PublishTarget,
    AbortTarget,
    PrepareLegacy,
    PublishLegacy,
    AbortLegacy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactCutoverTransitionOutcome<Hash> {
    Applied(StoredBranchExactCutover<Hash>),
    Idempotent(StoredBranchExactCutover<Hash>),
}

impl BranchExactProcessorOwnedLease {
    pub(crate) fn seal(
        fence: BranchExactCutoverRouteFence,
        observation: BranchExactProcessorDrainObservation,
    ) -> Self {
        Self { fence, observation }
    }
}

/// h22 publish barrier plus the exact h22e3 route sampled around its creation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactCutoverPublishBarrier<Hash> {
    route: BranchExactCutoverRouteFence,
    writer: BranchExactPublishBarrier<Hash>,
}

impl<Hash> BranchExactCutoverPublishBarrier<Hash> {
    pub const fn candidate(&self) -> &CanonicalChainRef<Hash> {
        self.writer.candidate()
    }

    pub const fn route(&self) -> &BranchExactCutoverRouteFence {
        &self.route
    }
}

pub struct ScyllaBranchExactCutoverRuntime<Hash> {
    control: ScyllaBranchExactCutoverStore,
    writer: ScyllaBranchExactWriterRuntime<Hash>,
    key: BranchExactCutoverAuthorityKey,
    expected_generation: BranchExactCutoverGeneration,
    expected_binding_digest: BranchExactCutoverBindingDigest,
}

impl<Hash: Q256BitHash> ScyllaBranchExactCutoverRuntime<Hash> {
    /// Prepare-only: no CREATE, bootstrap, CAS, or setup activation occurs.
    pub(crate) async fn prepare(
        session: Arc<Session>,
        no_tablet_keyspace: &str,
        request: BranchExactCutoverRuntimeRequest,
        writer: ScyllaBranchExactWriterRuntime<Hash>,
    ) -> Result<Self, BranchExactCutoverRuntimeError> {
        if writer.authority() != request.authority
            || writer.network() != request.network
        {
            return Err(BranchExactCutoverRuntimeError::AuthorityMismatch);
        }
        let key = BranchExactCutoverAuthorityKey::try_new(
            request.network,
            request.authority,
        )
        .map_err(store)?;
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            no_tablet_keyspace.to_owned(),
        )
        .map_err(|error| BranchExactCutoverRuntimeError::Store(error.to_string()))?;
        let control = ScyllaBranchExactCutoverStore::prepare(session, keyspace)
            .await
            .map_err(store)?;
        let runtime = Self {
            control,
            writer,
            key,
            expected_generation: request.expected_generation,
            expected_binding_digest: request.expected_binding_digest,
        };
        let current = runtime.read_current().await?;
        runtime.validate_current_binding(&current)?;
        Ok(runtime)
    }

    /// Fresh route read. Missing, quiescing, generation drift, or binding
    /// drift rejects new work.
    pub(crate) async fn begin_write(
        &self,
    ) -> Result<BranchExactCutoverRouteFence, BranchExactCutoverRuntimeError> {
        let current = self.read_current().await?;
        let fence = BranchExactCutoverRouteFence::try_from_current(&current)?;
        self.validate_configured(&fence)?;
        Ok(fence)
    }

    /// Read the durable h22 writer row through the managed runtime boundary.
    /// This is crate-visible for recovery qualification only; callers cannot
    /// obtain the underlying store or bypass the route fence on writes.
    pub(crate) async fn read_writer_state(
        &self,
    ) -> Result<super::StoredBranchExactWriterLifecycle<Hash>, BranchExactCutoverRuntimeError>
    {
        self.writer.read_writer().await.map_err(writer)
    }

    /// The route must be stable both before and after h22 writes become
    /// WritesVerified. A changed route may leave harmless dual-written rows,
    /// but no authority marker can be published from the returned error.
    pub(crate) async fn prepare_and_verify(
        &self,
        fence: &BranchExactCutoverRouteFence,
        intent: BranchExactDualWriteIntent<Hash>,
        clock_sample: AuthorityClockSampleUs,
    ) -> Result<BranchExactCutoverPublishBarrier<Hash>, BranchExactCutoverRuntimeError> {
        self.require_route(fence).await?;
        let writer = self
            .writer
            .prepare_and_verify_with_cutover(
                intent,
                clock_sample,
                fence.writer_fence(),
            )
            .await
            .map_err(writer)?;
        self.require_route(fence).await?;
        Ok(BranchExactCutoverPublishBarrier {
            route: fence.clone(),
            writer,
        })
    }

    /// Fresh route -> fresh h22 barrier -> fresh route. This detects a cutover
    /// CAS at either side of the independent writer read.
    pub(crate) async fn require_fresh_barrier(
        &self,
        barrier: &BranchExactCutoverPublishBarrier<Hash>,
    ) -> Result<(), BranchExactCutoverRuntimeError> {
        self.require_route(&barrier.route).await?;
        self.writer
            .require_fresh_barrier(&barrier.writer)
            .await
            .map_err(writer)?;
        self.require_route(&barrier.route).await
    }

    /// Finalization additionally requires the Processor-owned drained lease.
    /// Production integration must hold the actual single-owner guard for the
    /// whole call; this substrate verifies the lease is for this exact route.
    pub(crate) async fn finish_published(
        &self,
        lease: &BranchExactProcessorOwnedLease,
        barrier: &BranchExactCutoverPublishBarrier<Hash>,
        published: &CanonicalChainRef<Hash>,
    ) -> Result<(), BranchExactCutoverRuntimeError> {
        if lease.fence != barrier.route
            || !lease.observation.new_work_guarded
            || lease.observation.in_flight_work != 0
            || lease.observation.publish_in_flight
        {
            return Err(BranchExactCutoverRuntimeError::ProcessorLeaseMismatch);
        }
        self.require_route(&barrier.route).await?;
        self.writer
            .finish_published(&barrier.writer, published)
            .await
            .map_err(writer)?;
        self.require_route(&barrier.route).await
    }

    /// Advance one route phase only while the h22 writer and allocator are
    /// exactly idle. The real Processor must hold its single-owner guard for
    /// this whole call; this default-off substrate verifies the durable rows
    /// immediately before and after the route LWT.
    pub(crate) async fn transition_route(
        &self,
        observation: BranchExactProcessorDrainObservation,
        decision_nonce: [u8; 32],
        action: BranchExactCutoverTransitionAction,
    ) -> Result<BranchExactCutoverTransitionOutcome<Hash>, BranchExactCutoverRuntimeError> {
        if !observation.new_work_guarded
            || observation.in_flight_work != 0
            || observation.publish_in_flight
        {
            return Err(BranchExactCutoverRuntimeError::ProcessorNotDrained);
        }
        let current = self.read_current().await?;
        self.validate_current_binding(&current)?;
        self.require_writer_idle().await?;
        let permit = BranchExactCutoverPermit::after_processor_drain(
            &current,
            decision_nonce,
        )
        .map_err(|error| BranchExactCutoverRuntimeError::Lifecycle(error.to_string()))?;
        let sealed = match action {
            BranchExactCutoverTransitionAction::PrepareTarget => {
                SealedBranchExactCutoverCas::prepare_target(&current, &permit)
            }
            BranchExactCutoverTransitionAction::PublishTarget => {
                SealedBranchExactCutoverCas::publish_target(&current, &permit)
            }
            BranchExactCutoverTransitionAction::AbortTarget => {
                SealedBranchExactCutoverCas::abort_target(&current, &permit)
            }
            BranchExactCutoverTransitionAction::PrepareLegacy => {
                SealedBranchExactCutoverCas::prepare_legacy(&current, &permit)
            }
            BranchExactCutoverTransitionAction::PublishLegacy => {
                SealedBranchExactCutoverCas::publish_legacy(&current, &permit)
            }
            BranchExactCutoverTransitionAction::AbortLegacy => {
                SealedBranchExactCutoverCas::abort_legacy(&current, &permit)
            }
        }
        .map_err(|error| BranchExactCutoverRuntimeError::Lifecycle(error.to_string()))?;
        let outcome = match self.control.compare_and_set(&sealed).await.map_err(store)? {
            BranchExactCutoverWriteOutcome::Applied(next) => {
                BranchExactCutoverTransitionOutcome::Applied(next)
            }
            BranchExactCutoverWriteOutcome::Idempotent(next) => {
                BranchExactCutoverTransitionOutcome::Idempotent(next)
            }
            BranchExactCutoverWriteOutcome::Conflict(_) => {
                return Err(BranchExactCutoverRuntimeError::TransitionConflict)
            }
        };
        self.require_writer_idle().await?;
        Ok(outcome)
    }

    async fn require_route(
        &self,
        fence: &BranchExactCutoverRouteFence,
    ) -> Result<(), BranchExactCutoverRuntimeError> {
        self.validate_configured(fence)?;
        let current = self.read_current().await?;
        if !fence.matches(&current) {
            return Err(BranchExactCutoverRuntimeError::StaleRouteFence);
        }
        if !matches!(
            current.phase(),
            BranchExactCutoverPhase::LegacyPrimaryDualWrite
                | BranchExactCutoverPhase::TargetPrimaryDualWrite
        ) {
            return Err(BranchExactCutoverRuntimeError::RouteQuiescing);
        }
        Ok(())
    }

    fn validate_configured(
        &self,
        fence: &BranchExactCutoverRouteFence,
    ) -> Result<(), BranchExactCutoverRuntimeError> {
        if fence.generation() != self.expected_generation
            || fence.writer_fence.binding_digest() != self.expected_binding_digest
        {
            return Err(BranchExactCutoverRuntimeError::ConfiguredEvidenceMismatch);
        }
        Ok(())
    }

    fn validate_current_binding(
        &self,
        current: &StoredBranchExactCutover<Hash>,
    ) -> Result<(), BranchExactCutoverRuntimeError> {
        if current.binding().generation() != self.expected_generation
            || current.binding().digest() != self.expected_binding_digest
            || current.binding().writer_activation_digest_bytes()
                != self.writer.activation_digest().as_bytes()
        {
            return Err(BranchExactCutoverRuntimeError::ConfiguredEvidenceMismatch);
        }
        Ok(())
    }

    async fn require_writer_idle(&self) -> Result<(), BranchExactCutoverRuntimeError> {
        let sample = self.writer.read_recovery_sample().await.map_err(writer)?;
        let BranchExactWriterState::Active(active) = sample.writer().state() else {
            return Err(BranchExactCutoverRuntimeError::WriterNotIdle);
        };
        if sample.timestamp().state() != active.timestamp_state()
            || !matches!(
                sample.timestamp().state().phase(),
                AuthorityTimestampPhase::Idle { .. }
            )
        {
            return Err(BranchExactCutoverRuntimeError::WriterNotIdle);
        }
        Ok(())
    }

    async fn read_current(
        &self,
    ) -> Result<StoredBranchExactCutover<Hash>, BranchExactCutoverRuntimeError> {
        match self.control.read(self.key).await.map_err(store)? {
            BranchExactCutoverReadState::Uninitialized => {
                Err(BranchExactCutoverRuntimeError::CutoverUninitialized)
            }
            BranchExactCutoverReadState::Current(current) => Ok(current),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactCutoverRuntimeError {
    Store(String),
    Writer(String),
    CutoverUninitialized,
    ConfiguredEvidenceMismatch,
    AuthorityMismatch,
    RouteQuiescing,
    StaleRouteFence,
    ProcessorNotDrained,
    ProcessorLeaseMismatch,
    WriterNotIdle,
    TransitionConflict,
    Lifecycle(String),
}

impl fmt::Display for BranchExactCutoverRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "branch-exact cutover runtime rejected: {self:?}")
    }
}

impl Error for BranchExactCutoverRuntimeError {}

fn store(error: impl fmt::Display) -> BranchExactCutoverRuntimeError {
    BranchExactCutoverRuntimeError::Store(error.to_string())
}

fn writer(error: BranchExactWriterRuntimeError) -> BranchExactCutoverRuntimeError {
    BranchExactCutoverRuntimeError::Writer(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn processor_drain_observation_is_fail_closed() {
        assert!(BranchExactProcessorDrainObservation::try_new(true, 0, false).is_ok());
        assert_eq!(
            BranchExactProcessorDrainObservation::try_new(false, 0, false),
            Err(BranchExactCutoverRuntimeError::ProcessorNotDrained)
        );
        assert_eq!(
            BranchExactProcessorDrainObservation::try_new(true, 1, false),
            Err(BranchExactCutoverRuntimeError::ProcessorNotDrained)
        );
        assert_eq!(
            BranchExactProcessorDrainObservation::try_new(true, 0, true),
            Err(BranchExactCutoverRuntimeError::ProcessorNotDrained)
        );
    }

    #[test]
    fn runtime_is_default_off_and_not_processor_wired() {
        let setup = include_str!("../psy_setup.rs");
        let core = include_str!("../core.rs");
        assert!(!setup.contains("ScyllaBranchExactCutoverRuntime"));
        assert!(!core.contains("ScyllaBranchExactCutoverRuntime"));
        assert!(!setup.contains("branch_exact_cutover_lifecycle_v1"));
    }

    #[test]
    fn lexical_gate_keeps_route_checks_on_both_sides() {
        let source = include_str!("branch_exact_cutover_runtime.rs");
        let prepare = source
            .split("pub(crate) async fn prepare_and_verify")
            .nth(1)
            .unwrap()
            .split("pub(crate) async fn require_fresh_barrier")
            .next()
            .unwrap();
        assert_eq!(prepare.matches("self.require_route(fence).await?").count(), 2);
        assert!(prepare.contains("prepare_and_verify_with_cutover"));
        assert!(prepare.contains("fence.writer_fence()"));

        let fresh = source
            .split("pub(crate) async fn require_fresh_barrier")
            .nth(1)
            .unwrap()
            .split("pub(crate) async fn finish_published")
            .next()
            .unwrap();
        assert_eq!(fresh.matches("self.require_route(&barrier.route)").count(), 2);

        let transition = source
            .split("pub(crate) async fn transition_route")
            .nth(1)
            .unwrap()
            .split("async fn require_route")
            .next()
            .unwrap();
        assert_eq!(transition.matches("self.require_writer_idle().await?").count(), 2);
        assert!(transition.contains("BranchExactCutoverPermit::after_processor_drain"));
        assert!(transition.contains("compare_and_set(&sealed)"));
    }
}
