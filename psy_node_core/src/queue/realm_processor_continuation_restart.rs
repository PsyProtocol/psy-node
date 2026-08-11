//! Affine, read-only restart preparation for one Realm processing generation.
//!
//! Storage owns the concrete port and consumes it exactly once.  The public
//! result is deliberately only an observation: it carries no terminal
//! authorization, store receipt, writer/head proof, or rotation capability.

use std::{error::Error, fmt, sync::Arc};

use async_trait::async_trait;
use psy_data::protocol::canonical_chain::NetworkId;

use crate::store::realm_processor_startup::RealmProcessorStartupPermitDigest;

use super::{
    realm_processor_durable_capture::RealmProcessorDurableCaptureError,
    realm_processor_generation_continuation::{
        RealmProcessorGenerationContinuation,
        RealmProcessorGenerationContinuationPhase,
    },
};

/// Whether the current processing generation has an explicit durable input
/// locator.  Missing is never interpreted as an empty carryover.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmProcessorInboundCarryoverObservation {
    Missing,
    Bootstrap,
    Predecessor,
}

/// Read-only observation of the current generation's outbound terminal and
/// successor locator.  "Observed" never means writer/head-qualified or ready
/// to rotate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmProcessorTerminalCarryoverObservation {
    /// Inbound carryover is missing, so no later state is evaluated.
    NotEvaluated,
    /// The pipeline phase is not Published/RetiredNoWork.
    NotTerminalPhase,
    /// A terminal phase exists but no immutable terminal record exists.
    AwaitVerifiedTerminalAuthorization,
    /// The terminal record exists, but its successor carryover is absent.
    UnqualifiedTerminalObservedAwaitCarryover,
    /// Both immutable records exist and match; rotation remains forbidden.
    TerminalAndCarryoverObserved,
}

/// Public read-only result of one consumed storage-owned restart port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorReadOnlyRestartPreparation {
    continuation: RealmProcessorGenerationContinuation,
    inbound: RealmProcessorInboundCarryoverObservation,
    terminal: RealmProcessorTerminalCarryoverObservation,
}

impl RealmProcessorReadOnlyRestartPreparation {
    pub fn try_from_storage(
        continuation: RealmProcessorGenerationContinuation,
        inbound: RealmProcessorInboundCarryoverObservation,
        terminal: RealmProcessorTerminalCarryoverObservation,
    ) -> Result<Self, RealmProcessorContinuationRestartError> {
        let terminal_phase = matches!(
            continuation.phase(),
            RealmProcessorGenerationContinuationPhase::AwaitPublishedTerminal
                | RealmProcessorGenerationContinuationPhase::AwaitRetiredNoWorkTerminal
        );
        let valid = match (inbound, terminal, terminal_phase) {
            (
                RealmProcessorInboundCarryoverObservation::Missing,
                RealmProcessorTerminalCarryoverObservation::NotEvaluated,
                _,
            ) => true,
            (
                RealmProcessorInboundCarryoverObservation::Bootstrap
                | RealmProcessorInboundCarryoverObservation::Predecessor,
                RealmProcessorTerminalCarryoverObservation::NotTerminalPhase,
                false,
            ) => true,
            (
                RealmProcessorInboundCarryoverObservation::Bootstrap
                | RealmProcessorInboundCarryoverObservation::Predecessor,
                RealmProcessorTerminalCarryoverObservation::AwaitVerifiedTerminalAuthorization
                | RealmProcessorTerminalCarryoverObservation::UnqualifiedTerminalObservedAwaitCarryover
                | RealmProcessorTerminalCarryoverObservation::TerminalAndCarryoverObserved,
                true,
            ) => true,
            _ => false,
        };
        if !valid {
            return Err(RealmProcessorContinuationRestartError::StateMismatch);
        }
        Ok(Self {
            continuation,
            inbound,
            terminal,
        })
    }

    pub const fn continuation(&self) -> RealmProcessorGenerationContinuation {
        self.continuation
    }

    pub const fn inbound(&self) -> RealmProcessorInboundCarryoverObservation {
        self.inbound
    }

    pub const fn terminal(&self) -> RealmProcessorTerminalCarryoverObservation {
        self.terminal
    }
}

/// Non-Clone identity-only request. Pending/proc, pipeline phase, slots and
/// digests are intentionally absent; storage selects all of them.
#[derive(Debug)]
pub struct SealedRealmProcessorContinuationRestartRequest {
    startup_permit_digest: RealmProcessorStartupPermitDigest,
    network: NetworkId,
    realm_id: u32,
    realm_sub_id: u16,
    writer_activation_digest: [u8; 32],
    queue_readiness_digest: [u8; 32],
}

impl SealedRealmProcessorContinuationRestartRequest {
    pub(crate) fn seal(
        startup_permit_digest: RealmProcessorStartupPermitDigest,
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        writer_activation_digest: [u8; 32],
        queue_readiness_digest: [u8; 32],
    ) -> Self {
        Self {
            startup_permit_digest,
            network,
            realm_id,
            realm_sub_id,
            writer_activation_digest,
            queue_readiness_digest,
        }
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
}

/// Concrete implementations retain all private rows/receipts.  Consuming the
/// box prevents a caller from reusing one stale preparation across a later
/// storage transition.
#[async_trait]
pub trait RealmProcessorContinuationRestartPort: Send {
    async fn observe_and_prepare(
        self: Box<Self>,
    ) -> Result<RealmProcessorReadOnlyRestartPreparation, RealmProcessorDurableCaptureError>;
}

/// Identity-bound factory installed beside, but distinct from, durable
/// capture.  Opening a port still requires an affine commit iteration.
#[async_trait]
pub trait RealmProcessorContinuationRestartFactory<Hash>: Send + Sync {
    fn network(&self) -> NetworkId;
    fn realm_id(&self) -> u32;
    fn realm_sub_id(&self) -> u16;
    fn writer_activation_digest(&self) -> [u8; 32];
    fn queue_readiness_digest(&self) -> [u8; 32];

    async fn open(
        self: Arc<Self>,
        request: SealedRealmProcessorContinuationRestartRequest,
    ) -> Result<Box<dyn RealmProcessorContinuationRestartPort>, RealmProcessorDurableCaptureError>;
}

/// Typed result of the separate terminal-to-carryover recovery capability.
/// `Prepared` only means the immutable successor locator is now exact; it
/// grants no pipeline terminal, rotation, writer, or head authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmProcessorTerminalCarryoverRecoveryOutcome {
    AwaitExplicitInboundCarryover(RealmProcessorReadOnlyRestartPreparation),
    AwaitTerminalPhase(RealmProcessorReadOnlyRestartPreparation),
    AwaitVerifiedTerminalAuthorization(RealmProcessorReadOnlyRestartPreparation),
    Prepared(RealmProcessorReadOnlyRestartPreparation),
}

impl RealmProcessorTerminalCarryoverRecoveryOutcome {
    pub fn try_from_storage(
        preparation: RealmProcessorReadOnlyRestartPreparation,
    ) -> Result<Self, RealmProcessorContinuationRestartError> {
        match (preparation.inbound(), preparation.terminal()) {
            (
                RealmProcessorInboundCarryoverObservation::Missing,
                RealmProcessorTerminalCarryoverObservation::NotEvaluated,
            ) => Ok(Self::AwaitExplicitInboundCarryover(preparation)),
            (
                RealmProcessorInboundCarryoverObservation::Bootstrap
                | RealmProcessorInboundCarryoverObservation::Predecessor,
                RealmProcessorTerminalCarryoverObservation::NotTerminalPhase,
            ) => Ok(Self::AwaitTerminalPhase(preparation)),
            (
                RealmProcessorInboundCarryoverObservation::Bootstrap
                | RealmProcessorInboundCarryoverObservation::Predecessor,
                RealmProcessorTerminalCarryoverObservation::AwaitVerifiedTerminalAuthorization,
            ) => Ok(Self::AwaitVerifiedTerminalAuthorization(preparation)),
            (
                RealmProcessorInboundCarryoverObservation::Bootstrap
                | RealmProcessorInboundCarryoverObservation::Predecessor,
                RealmProcessorTerminalCarryoverObservation::TerminalAndCarryoverObserved,
            ) => Ok(Self::Prepared(preparation)),
            _ => Err(RealmProcessorContinuationRestartError::StateMismatch),
        }
    }

    pub const fn preparation(self) -> RealmProcessorReadOnlyRestartPreparation {
        match self {
            Self::AwaitExplicitInboundCarryover(value)
            | Self::AwaitTerminalPhase(value)
            | Self::AwaitVerifiedTerminalAuthorization(value)
            | Self::Prepared(value) => value,
        }
    }
}

/// Identity-only request for the mutating-but-non-terminal recovery port.
/// Storage still selects pending/proc, terminal slot and carryover content.
#[derive(Debug)]
pub struct SealedRealmProcessorTerminalCarryoverRecoveryRequest {
    startup_permit_digest: RealmProcessorStartupPermitDigest,
    network: NetworkId,
    realm_id: u32,
    realm_sub_id: u16,
    writer_activation_digest: [u8; 32],
    queue_readiness_digest: [u8; 32],
}

impl SealedRealmProcessorTerminalCarryoverRecoveryRequest {
    pub(crate) fn seal(
        startup_permit_digest: RealmProcessorStartupPermitDigest,
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        writer_activation_digest: [u8; 32],
        queue_readiness_digest: [u8; 32],
    ) -> Self {
        Self {
            startup_permit_digest,
            network,
            realm_id,
            realm_sub_id,
            writer_activation_digest,
            queue_readiness_digest,
        }
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

#[async_trait]
pub trait RealmProcessorTerminalCarryoverRecoveryPort: Send {
    async fn recover_and_prepare(
        self: Box<Self>,
    ) -> Result<RealmProcessorTerminalCarryoverRecoveryOutcome, RealmProcessorDurableCaptureError>;
}

#[async_trait]
pub trait RealmProcessorTerminalCarryoverRecoveryFactory<Hash>: Send + Sync {
    fn network(&self) -> NetworkId;
    fn realm_id(&self) -> u32;
    fn realm_sub_id(&self) -> u16;
    fn writer_activation_digest(&self) -> [u8; 32];
    fn queue_readiness_digest(&self) -> [u8; 32];

    async fn open(
        self: Arc<Self>,
        request: SealedRealmProcessorTerminalCarryoverRecoveryRequest,
    ) -> Result<Box<dyn RealmProcessorTerminalCarryoverRecoveryPort>, RealmProcessorDurableCaptureError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmProcessorContinuationRestartError {
    StateMismatch,
}

impl fmt::Display for RealmProcessorContinuationRestartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmProcessorContinuationRestartError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        queue::{
            realm_processor_application_archive::{
                RealmProcessorApplicationArchiveDigest,
                RealmProcessorApplicationArchiveSlot,
            },
            realm_processor_generation_continuation::{
                RealmProcessorApplicationContinuation,
                RealmProcessorDeferredCarryoverDigest,
                RealmProcessorGenerationContinuation,
            },
            realm_processor_semantic_output::RealmProcessorSemanticOutputDigest,
        },
        store::{
            pending_generation_identity::PendingGenerationContext,
            pending_generation_pipeline::PendingPipelineRevision,
        },
    };

    fn continuation(
        phase: RealmProcessorGenerationContinuationPhase,
    ) -> RealmProcessorGenerationContinuation {
        let application = phase.requires_application().then(|| {
            RealmProcessorApplicationContinuation::try_from_committed_parts(
                RealmProcessorApplicationArchiveSlot::try_new([1; 32]).unwrap(),
                RealmProcessorApplicationArchiveDigest::try_new([2; 32]).unwrap(),
                RealmProcessorSemanticOutputDigest::try_new([3; 32]).unwrap(),
                phase.expects_application_work().unwrap(),
                0,
                RealmProcessorDeferredCarryoverDigest::try_new([4; 32]).unwrap(),
            )
            .unwrap()
        });
        RealmProcessorGenerationContinuation::try_from_storage(
            PendingGenerationContext::try_from_legacy(7, 9).unwrap(),
            PendingPipelineRevision::try_new(11).unwrap(),
            phase,
            application,
        )
        .unwrap()
    }

    #[test]
    fn missing_is_not_empty_and_terminal_status_is_exhaustive() {
        let ready = continuation(RealmProcessorGenerationContinuationPhase::AwaitQueueClose);
        assert!(RealmProcessorReadOnlyRestartPreparation::try_from_storage(
            ready,
            RealmProcessorInboundCarryoverObservation::Missing,
            RealmProcessorTerminalCarryoverObservation::NotEvaluated,
        )
        .is_ok());
        assert!(RealmProcessorReadOnlyRestartPreparation::try_from_storage(
            ready,
            RealmProcessorInboundCarryoverObservation::Bootstrap,
            RealmProcessorTerminalCarryoverObservation::NotTerminalPhase,
        )
        .is_ok());
        assert!(RealmProcessorReadOnlyRestartPreparation::try_from_storage(
            ready,
            RealmProcessorInboundCarryoverObservation::Bootstrap,
            RealmProcessorTerminalCarryoverObservation::TerminalAndCarryoverObserved,
        )
        .is_err());
    }

    #[test]
    fn request_and_result_are_observations_not_mutation_authority() {
        let source = include_str!("realm_processor_continuation_restart.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("impl Clone for SealedRealmProcessorContinuationRestartRequest"));
        assert!(!production.contains(
            "impl Clone for SealedRealmProcessorTerminalCarryoverRecoveryRequest"
        ));
        let recovery_request = production
            .split("pub struct SealedRealmProcessorTerminalCarryoverRecoveryRequest")
            .nth(1)
            .unwrap()
            .split("impl SealedRealmProcessorTerminalCarryoverRecoveryRequest")
            .next()
            .unwrap();
        assert!(!recovery_request.contains("pending_id"));
        assert!(!recovery_request.contains("proc"));
        assert!(!recovery_request.contains("terminal_slot"));
        assert!(!recovery_request.contains("carryover"));
        assert!(!production.contains("terminal_authorization: Vec"));
        assert!(!production.contains("seal_rotation("));
        assert!(!production.contains("apply_pipeline"));
    }

    #[test]
    fn all_eight_phases_have_explicit_fail_closed_restart_classification() {
        use RealmProcessorGenerationContinuationPhase as Phase;
        for phase in [
            Phase::AwaitPrimeOrRotate,
            Phase::AwaitQueueClose,
            Phase::CaptureClosedSource,
            Phase::AwaitWriter,
            Phase::AwaitWriterCompletion,
            Phase::AwaitNoWorkTerminal,
        ] {
            assert!(RealmProcessorReadOnlyRestartPreparation::try_from_storage(
                continuation(phase),
                RealmProcessorInboundCarryoverObservation::Predecessor,
                RealmProcessorTerminalCarryoverObservation::NotTerminalPhase,
            )
            .is_ok());
        }
        for phase in [Phase::AwaitPublishedTerminal, Phase::AwaitRetiredNoWorkTerminal] {
            for terminal in [
                RealmProcessorTerminalCarryoverObservation::AwaitVerifiedTerminalAuthorization,
                RealmProcessorTerminalCarryoverObservation::UnqualifiedTerminalObservedAwaitCarryover,
                RealmProcessorTerminalCarryoverObservation::TerminalAndCarryoverObserved,
            ] {
                assert!(RealmProcessorReadOnlyRestartPreparation::try_from_storage(
                    continuation(phase),
                    RealmProcessorInboundCarryoverObservation::Predecessor,
                    terminal,
                )
                .is_ok());
            }
            assert!(RealmProcessorReadOnlyRestartPreparation::try_from_storage(
                continuation(phase),
                RealmProcessorInboundCarryoverObservation::Predecessor,
                RealmProcessorTerminalCarryoverObservation::NotTerminalPhase,
            )
            .is_err());
        }
    }

    #[test]
    fn terminal_carryover_recovery_has_four_exhaustive_non_authority_outcomes() {
        use RealmProcessorGenerationContinuationPhase as Phase;
        let missing = RealmProcessorReadOnlyRestartPreparation::try_from_storage(
            continuation(Phase::AwaitPublishedTerminal),
            RealmProcessorInboundCarryoverObservation::Missing,
            RealmProcessorTerminalCarryoverObservation::NotEvaluated,
        )
        .unwrap();
        assert!(matches!(
            RealmProcessorTerminalCarryoverRecoveryOutcome::try_from_storage(missing),
            Ok(RealmProcessorTerminalCarryoverRecoveryOutcome::AwaitExplicitInboundCarryover(_))
        ));

        let nonterminal = RealmProcessorReadOnlyRestartPreparation::try_from_storage(
            continuation(Phase::AwaitWriter),
            RealmProcessorInboundCarryoverObservation::Predecessor,
            RealmProcessorTerminalCarryoverObservation::NotTerminalPhase,
        )
        .unwrap();
        assert!(matches!(
            RealmProcessorTerminalCarryoverRecoveryOutcome::try_from_storage(nonterminal),
            Ok(RealmProcessorTerminalCarryoverRecoveryOutcome::AwaitTerminalPhase(_))
        ));

        let await_authorization = RealmProcessorReadOnlyRestartPreparation::try_from_storage(
            continuation(Phase::AwaitPublishedTerminal),
            RealmProcessorInboundCarryoverObservation::Predecessor,
            RealmProcessorTerminalCarryoverObservation::AwaitVerifiedTerminalAuthorization,
        )
        .unwrap();
        assert!(matches!(
            RealmProcessorTerminalCarryoverRecoveryOutcome::try_from_storage(await_authorization),
            Ok(RealmProcessorTerminalCarryoverRecoveryOutcome::AwaitVerifiedTerminalAuthorization(_))
        ));

        let prepared = RealmProcessorReadOnlyRestartPreparation::try_from_storage(
            continuation(Phase::AwaitRetiredNoWorkTerminal),
            RealmProcessorInboundCarryoverObservation::Bootstrap,
            RealmProcessorTerminalCarryoverObservation::TerminalAndCarryoverObserved,
        )
        .unwrap();
        assert!(matches!(
            RealmProcessorTerminalCarryoverRecoveryOutcome::try_from_storage(prepared),
            Ok(RealmProcessorTerminalCarryoverRecoveryOutcome::Prepared(_))
        ));

        let terminal_only = RealmProcessorReadOnlyRestartPreparation::try_from_storage(
            continuation(Phase::AwaitPublishedTerminal),
            RealmProcessorInboundCarryoverObservation::Predecessor,
            RealmProcessorTerminalCarryoverObservation::UnqualifiedTerminalObservedAwaitCarryover,
        )
        .unwrap();
        assert_eq!(
            RealmProcessorTerminalCarryoverRecoveryOutcome::try_from_storage(terminal_only),
            Err(RealmProcessorContinuationRestartError::StateMismatch)
        );
    }
}
