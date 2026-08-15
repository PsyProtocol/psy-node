//! Durable state machine for one authority's two-slot pending pipeline.
//!
//! The processing slot cannot be rotated away until it is durably terminal.
//! Both a materialized publish and a verified no-work retirement durably bind
//! one exact authority observation. No-work always advances the processed
//! pending high-water and may retain the identical chain/state observation,
//! so idle Realm generations never require a backwards mapping scan.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::CanonicalChainRef,
    chain_context::{AuthorityObservation, AuthorityScope, AUTHORITY_OBSERVATION_V1_LEN},
};

use super::{
    pending_generation::{ProcNamespacePrefix, ReservedPendingGeneration},
    pending_generation_identity::{
        PendingGenerationActivationDigest, PendingGenerationBootstrapReason,
        PendingGenerationContext, PendingGenerationLedgerKey,
    },
};

pub const PENDING_PIPELINE_MAGIC: [u8; 8] = *b"PSYPGPLN";
pub const PENDING_PIPELINE_CODEC_VERSION: u16 = 2;
pub const PENDING_PIPELINE_V2_LEN: usize =
    8 + 2 + 4 + 1 + 4 + 2 + 32 + 8 + 8 + 1 + 24 + 24 + 1 + 32
        + 32
        + 32
        + AUTHORITY_OBSERVATION_V1_LEN
        + 8;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PendingPipelineRevision(u64);

impl PendingPipelineRevision {
    pub const fn try_new(value: u64) -> Result<Self, PendingPipelineError> {
        if value <= i64::MAX as u64 {
            Ok(Self(value))
        } else {
            Err(PendingPipelineError::RevisionOutOfRange(value))
        }
    }

    pub const fn try_from_i64(value: i64) -> Result<Self, PendingPipelineError> {
        if value < 0 {
            Err(PendingPipelineError::NegativeRevision(value))
        } else {
            Self::try_new(value as u64)
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    const fn next(self) -> Result<Self, PendingPipelineError> {
        match self.0.checked_add(1) {
            Some(next) if next <= i64::MAX as u64 => Ok(Self(next)),
            _ => Err(PendingPipelineError::RevisionOverflow),
        }
    }
}

macro_rules! evidence_digest {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; 32]);

        impl $name {
            pub fn try_new(bytes: [u8; 32]) -> Result<Self, PendingPipelineError> {
                if bytes == [0; 32] {
                    Err(PendingPipelineError::EmptyEvidenceDigest)
                } else {
                    Ok(Self(bytes))
                }
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

evidence_digest!(PendingPipelineIntentDigest);
evidence_digest!(PendingQueueCloseIntentDigest);
evidence_digest!(PendingWorkCaptureDigest);
evidence_digest!(PendingEmptyQueueSealDigest);
evidence_digest!(PendingNoWorkReceiptDigest);
evidence_digest!(PendingPublishReceiptDigest);
evidence_digest!(PendingBlockedReasonDigest);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PendingProcessingPhase {
    Baseline = 1,
    Ready = 2,
    Sealing = 3,
    WorkCaptured = 4,
    InFlight = 5,
    EmptyQueueSealed = 6,
    RetiredNoWork = 7,
    Published = 8,
}

impl PendingProcessingPhase {
    fn try_from_u8(value: u8) -> Result<Self, PendingPipelineError> {
        match value {
            1 => Ok(Self::Baseline),
            2 => Ok(Self::Ready),
            3 => Ok(Self::Sealing),
            4 => Ok(Self::WorkCaptured),
            5 => Ok(Self::InFlight),
            6 => Ok(Self::EmptyQueueSealed),
            7 => Ok(Self::RetiredNoWork),
            8 => Ok(Self::Published),
            other => Err(PendingPipelineError::UnknownPhase(other)),
        }
    }

    const fn is_terminal(self) -> bool {
        matches!(self, Self::Baseline | Self::RetiredNoWork | Self::Published)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PendingProcessingState {
    Baseline(PendingGenerationActivationDigest),
    Ready,
    Sealing(PendingQueueCloseIntentDigest),
    WorkCaptured(PendingWorkCaptureDigest),
    InFlight {
        capture: PendingWorkCaptureDigest,
        intent: PendingPipelineIntentDigest,
    },
    EmptyQueueSealed(PendingEmptyQueueSealDigest),
    RetiredNoWork {
        seal: PendingEmptyQueueSealDigest,
        receipt: PendingNoWorkReceiptDigest,
    },
    Published {
        capture: PendingWorkCaptureDigest,
        receipt: PendingPublishReceiptDigest,
    },
}

impl PendingProcessingState {
    pub const fn phase(self) -> PendingProcessingPhase {
        match self {
            Self::Baseline(_) => PendingProcessingPhase::Baseline,
            Self::Ready => PendingProcessingPhase::Ready,
            Self::Sealing(_) => PendingProcessingPhase::Sealing,
            Self::WorkCaptured(_) => PendingProcessingPhase::WorkCaptured,
            Self::InFlight { .. } => PendingProcessingPhase::InFlight,
            Self::EmptyQueueSealed(_) => PendingProcessingPhase::EmptyQueueSealed,
            Self::RetiredNoWork { .. } => PendingProcessingPhase::RetiredNoWork,
            Self::Published { .. } => PendingProcessingPhase::Published,
        }
    }

    fn evidence_bytes(self) -> ([u8; 32], [u8; 32]) {
        match self {
            Self::Baseline(digest) => (*digest.as_bytes(), [0; 32]),
            Self::Ready => ([0; 32], [0; 32]),
            Self::Sealing(close) => (*close.as_bytes(), [0; 32]),
            Self::WorkCaptured(capture) => (*capture.as_bytes(), [0; 32]),
            Self::InFlight { capture, intent } => {
                (*capture.as_bytes(), *intent.as_bytes())
            }
            Self::EmptyQueueSealed(seal) => (*seal.as_bytes(), [0; 32]),
            Self::RetiredNoWork { seal, receipt } => {
                (*seal.as_bytes(), *receipt.as_bytes())
            }
            Self::Published { capture, receipt } => {
                (*capture.as_bytes(), *receipt.as_bytes())
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredPendingPipeline<Hash> {
    key: PendingGenerationLedgerKey,
    revision: PendingPipelineRevision,
    activation_digest: PendingGenerationActivationDigest,
    proc_namespace_prefix: ProcNamespacePrefix,
    derived_start_pending_id: u64,
    bootstrap_reason: PendingGenerationBootstrapReason,
    processing: PendingGenerationContext,
    gathering: PendingGenerationContext,
    processing_state: PendingProcessingState,
    blocked_reason: Option<PendingBlockedReasonDigest>,
    frontier: AuthorityObservation<Hash>,
    processed_pending_id: u64,
}

impl<Hash> StoredPendingPipeline<Hash> {
    pub const fn key(&self) -> PendingGenerationLedgerKey {
        self.key
    }

    pub const fn revision(&self) -> PendingPipelineRevision {
        self.revision
    }

    pub const fn activation_digest(&self) -> PendingGenerationActivationDigest {
        self.activation_digest
    }

    pub const fn proc_namespace_prefix(&self) -> ProcNamespacePrefix {
        self.proc_namespace_prefix
    }

    pub const fn derived_start_pending_id(&self) -> u64 {
        self.derived_start_pending_id
    }

    pub const fn bootstrap_reason(&self) -> PendingGenerationBootstrapReason {
        self.bootstrap_reason
    }

    pub const fn processing(&self) -> PendingGenerationContext {
        self.processing
    }

    pub const fn gathering(&self) -> PendingGenerationContext {
        self.gathering
    }

    pub const fn phase(&self) -> PendingProcessingPhase {
        self.processing_state.phase()
    }

    pub const fn processing_state(&self) -> PendingProcessingState {
        self.processing_state
    }

    pub const fn blocked_reason(&self) -> Option<PendingBlockedReasonDigest> {
        self.blocked_reason
    }

    pub const fn frontier(&self) -> &AuthorityObservation<Hash> {
        &self.frontier
    }

    /// Highest pending generation whose work/no-work terminal result is
    /// durably reflected by `frontier`. This is not the materialized writer
    /// watermark when the phase is `RetiredNoWork`.
    pub const fn processed_pending_id(&self) -> u64 {
        self.processed_pending_id
    }

    pub fn validate_counter_high_water(&self, counter: u64) -> Result<(), PendingPipelineError> {
        if counter < self.gathering.pending_id().get() {
            Err(PendingPipelineError::CounterBehindLedger {
                counter,
                gathering: self.gathering.pending_id().get(),
            })
        } else {
            Ok(())
        }
    }
}

impl<Hash: Q256BitHash> StoredPendingPipeline<Hash> {
    pub fn canonical_payload(&self) -> [u8; PENDING_PIPELINE_V2_LEN] {
        encode_payload(self)
    }

    pub fn decode_persisted(
        selected_key: PendingGenerationLedgerKey,
        revision: i64,
        payload: &[u8],
    ) -> Result<Self, PendingPipelineError> {
        if payload.len() != PENDING_PIPELINE_V2_LEN {
            return Err(PendingPipelineError::InvalidPayloadLength(payload.len()));
        }
        let mut cursor = 0;
        if take::<8>(payload, &mut cursor) != PENDING_PIPELINE_MAGIC {
            return Err(PendingPipelineError::InvalidMagic);
        }
        let version = u16::from_be_bytes(take::<2>(payload, &mut cursor));
        if version != PENDING_PIPELINE_CODEC_VERSION {
            return Err(PendingPipelineError::UnknownCodecVersion(version));
        }
        let network = psy_data::protocol::canonical_chain::NetworkId::try_from_chain_id(
            u32::from_be_bytes(take::<4>(payload, &mut cursor)),
        )
        .map_err(|_| PendingPipelineError::UnknownNetwork)?;
        let kind = payload[cursor];
        cursor += 1;
        let realm_id = u32::from_be_bytes(take::<4>(payload, &mut cursor));
        let realm_sub_id = u16::from_be_bytes(take::<2>(payload, &mut cursor));
        let authority = decode_authority(kind, realm_id, realm_sub_id)?;
        let key = PendingGenerationLedgerKey::new(network, authority);
        if key != selected_key {
            return Err(PendingPipelineError::PartitionPayloadMismatch);
        }
        let activation_digest = PendingGenerationActivationDigest::try_new(take::<32>(
            payload,
            &mut cursor,
        ))
        .map_err(|_| PendingPipelineError::InvalidActivationDigest)?;
        let proc_namespace_prefix = ProcNamespacePrefix::try_new(u64::from_be_bytes(take::<8>(
            payload,
            &mut cursor,
        )))
        .map_err(|_| PendingPipelineError::InvalidProcNamespacePrefix)?;
        let derived_start_pending_id =
            u64::from_be_bytes(take::<8>(payload, &mut cursor));
        let bootstrap_reason = decode_bootstrap_reason(payload[cursor])?;
        cursor += 1;
        let processing = decode_context(payload, &mut cursor)?;
        let gathering = decode_context(payload, &mut cursor)?;
        let phase = PendingProcessingPhase::try_from_u8(payload[cursor])?;
        cursor += 1;
        let primary_evidence = take::<32>(payload, &mut cursor);
        let secondary_evidence = take::<32>(payload, &mut cursor);
        let processing_state = match phase {
            PendingProcessingPhase::Baseline if secondary_evidence == [0; 32] => PendingProcessingState::Baseline(
                PendingGenerationActivationDigest::try_new(primary_evidence)
                    .map_err(|_| PendingPipelineError::EmptyEvidenceDigest)?,
            ),
            PendingProcessingPhase::Baseline => {
                return Err(PendingPipelineError::UnexpectedSecondaryEvidence)
            }
            PendingProcessingPhase::Ready
                if primary_evidence == [0; 32] && secondary_evidence == [0; 32] =>
            {
                PendingProcessingState::Ready
            }
            PendingProcessingPhase::Ready => {
                return Err(PendingPipelineError::ReadyHasEvidence)
            }
            PendingProcessingPhase::Sealing if secondary_evidence == [0; 32] => {
                PendingProcessingState::Sealing(PendingQueueCloseIntentDigest::try_new(
                    primary_evidence,
                )?)
            }
            PendingProcessingPhase::Sealing => {
                return Err(PendingPipelineError::UnexpectedSecondaryEvidence)
            }
            PendingProcessingPhase::WorkCaptured if secondary_evidence == [0; 32] => {
                PendingProcessingState::WorkCaptured(PendingWorkCaptureDigest::try_new(
                    primary_evidence,
                )?)
            }
            PendingProcessingPhase::WorkCaptured => {
                return Err(PendingPipelineError::UnexpectedSecondaryEvidence)
            }
            PendingProcessingPhase::InFlight => PendingProcessingState::InFlight {
                capture: PendingWorkCaptureDigest::try_new(primary_evidence)?,
                intent: PendingPipelineIntentDigest::try_new(secondary_evidence)?,
            },
            PendingProcessingPhase::EmptyQueueSealed if secondary_evidence == [0; 32] => {
                PendingProcessingState::EmptyQueueSealed(
                    PendingEmptyQueueSealDigest::try_new(primary_evidence)?,
                )
            }
            PendingProcessingPhase::EmptyQueueSealed => {
                return Err(PendingPipelineError::UnexpectedSecondaryEvidence)
            }
            PendingProcessingPhase::RetiredNoWork => PendingProcessingState::RetiredNoWork {
                seal: PendingEmptyQueueSealDigest::try_new(primary_evidence)?,
                receipt: PendingNoWorkReceiptDigest::try_new(secondary_evidence)?,
            },
            PendingProcessingPhase::Published => PendingProcessingState::Published {
                capture: PendingWorkCaptureDigest::try_new(primary_evidence)?,
                receipt: PendingPublishReceiptDigest::try_new(secondary_evidence)?,
            },
        };
        let blocked_bytes = take::<32>(payload, &mut cursor);
        let blocked_reason = if blocked_bytes == [0; 32] {
            None
        } else {
            Some(PendingBlockedReasonDigest::try_new(blocked_bytes)?)
        };
        let frontier = AuthorityObservation::<Hash>::from_canonical_bytes(
            &payload[cursor..cursor + AUTHORITY_OBSERVATION_V1_LEN],
        )
        .map_err(|error| PendingPipelineError::InvalidFrontier(error.to_string()))?;
        cursor += AUTHORITY_OBSERVATION_V1_LEN;
        let processed_pending_id = u64::from_be_bytes(take::<8>(payload, &mut cursor));
        debug_assert_eq!(cursor, payload.len());
        let state = Self {
            key,
            revision: PendingPipelineRevision::try_from_i64(revision)?,
            activation_digest,
            proc_namespace_prefix,
            derived_start_pending_id,
            bootstrap_reason,
            processing,
            gathering,
            processing_state,
            blocked_reason,
            frontier,
            processed_pending_id,
        };
        validate_state(&state)?;
        Ok(state)
    }

    pub fn seal_rotation(
        &self,
        reserved: ReservedPendingGeneration,
    ) -> Result<SealedPendingPipelineTransition<Hash>, PendingPipelineError> {
        self.require_unblocked()?;
        if self.bootstrap_reason == PendingGenerationBootstrapReason::Genesis
            && self.processing.pending_id().get() == 0
            && self.gathering.pending_id().get() == 0
        {
            return Err(PendingPipelineError::GenesisRequiresPrime);
        }
        if !self.phase().is_terminal() {
            return Err(PendingPipelineError::ProcessingNotTerminal(self.phase()));
        }
        if self.processed_pending_id != self.processing.pending_id().get() {
            return Err(PendingPipelineError::TerminalFrontierMismatch);
        }
        let next = PendingGenerationContext::try_from_legacy(
            reserved.pending_id().get(),
            reserved.proc_checkpoint_id().as_u128(),
        )
        .map_err(|error| PendingPipelineError::InvalidContext(error.to_string()))?;
        if next.proc_checkpoint_id()
            != self.proc_namespace_prefix.derive_proc_id(next.pending_id())
        {
            return Err(PendingPipelineError::ProcNamespacePrefixMismatch);
        }
        if next.pending_id().get() <= self.gathering.pending_id().get() {
            return Err(PendingPipelineError::PendingNotMonotonic {
                previous: self.gathering.pending_id().get(),
                candidate: next.pending_id().get(),
            });
        }
        let mut candidate = self.clone();
        candidate.revision = self.revision.next()?;
        candidate.processing = self.gathering;
        candidate.gathering = next;
        candidate.processing_state = PendingProcessingState::Ready;
        seal(self, candidate, PendingPipelineTransitionKind::Rotate)
    }

    /// Reset the two-slot pipeline after an in-place rollback has restored an
    /// older committed frontier.
    ///
    /// This is intentionally crate-private. A storage-owned rollback
    /// finalizer must first prove the global delete barrier, the exact target
    /// committed marker, and two durable counter allocations. Old pending/proc
    /// identities are never reused: both new slots must be strictly newer than
    /// the abandoned gathering slot.
    pub(crate) fn seal_rollback_reset(
        &self,
        processing: ReservedPendingGeneration,
        gathering: ReservedPendingGeneration,
        restored_frontier: AuthorityObservation<Hash>,
        target_processed_pending_id: u64,
    ) -> Result<SealedPendingPipelineTransition<Hash>, PendingPipelineError> {
        let processing = PendingGenerationContext::try_from_legacy(
            processing.pending_id().get(),
            processing.proc_checkpoint_id().as_u128(),
        )
        .map_err(|error| PendingPipelineError::InvalidContext(error.to_string()))?;
        let gathering = PendingGenerationContext::try_from_legacy(
            gathering.pending_id().get(),
            gathering.proc_checkpoint_id().as_u128(),
        )
        .map_err(|error| PendingPipelineError::InvalidContext(error.to_string()))?;
        self.seal_rollback_reset_contexts(
            processing,
            gathering,
            restored_frontier,
            target_processed_pending_id,
        )
    }

    /// Storage-adapter form of [`Self::seal_rollback_reset`]. The adapter must
    /// first prove both contexts came from exact durable counter allocations;
    /// this constructor independently revalidates namespace, monotonicity,
    /// frontier, epoch, and full predecessor state before sealing a CAS.
    pub fn seal_rollback_reset_contexts(
        &self,
        processing: PendingGenerationContext,
        gathering: PendingGenerationContext,
        restored_frontier: AuthorityObservation<Hash>,
        target_processed_pending_id: u64,
    ) -> Result<SealedPendingPipelineTransition<Hash>, PendingPipelineError> {
        self.seal_rollback_reset_against_source_chain_contexts(
            processing,
            gathering,
            *self.frontier.chain(),
            restored_frontier,
            target_processed_pending_id,
            false,
        )
    }

    /// Reset a Realm pipeline whose normal Coordinator-sync head is ahead of
    /// its last Realm-work frontier. The storage owner calls this only after
    /// the process-local actor has drained and the distributed archive/delete
    /// barrier is durable. Consequently an in-progress generation
    /// (`Sealing`, captured, in-flight, or empty-sealed) is abandoned suffix,
    /// just like a `Ready` generation with no Realm work. `Baseline` and
    /// `Blocked` remain ineligible.
    pub fn seal_rollback_reset_from_synced_head_contexts(
        &self,
        processing: PendingGenerationContext,
        gathering: PendingGenerationContext,
        source_chain: CanonicalChainRef<Hash>,
        restored_frontier: AuthorityObservation<Hash>,
        target_processed_pending_id: u64,
    ) -> Result<SealedPendingPipelineTransition<Hash>, PendingPipelineError> {
        self.seal_rollback_reset_against_source_chain_contexts(
            processing,
            gathering,
            source_chain,
            restored_frontier,
            target_processed_pending_id,
            true,
        )
    }

    fn seal_rollback_reset_against_source_chain_contexts(
        &self,
        processing: PendingGenerationContext,
        gathering: PendingGenerationContext,
        source_chain: CanonicalChainRef<Hash>,
        restored_frontier: AuthorityObservation<Hash>,
        target_processed_pending_id: u64,
        allow_ready_source: bool,
    ) -> Result<SealedPendingPipelineTransition<Hash>, PendingPipelineError> {
        self.require_unblocked()?;
        if !matches!(
            self.phase(),
            PendingProcessingPhase::Published | PendingProcessingPhase::RetiredNoWork
        ) && !(allow_ready_source
            && matches!(
                self.phase(),
                PendingProcessingPhase::Ready
                    | PendingProcessingPhase::Sealing
                    | PendingProcessingPhase::WorkCaptured
                    | PendingProcessingPhase::InFlight
                    | PendingProcessingPhase::EmptyQueueSealed
            ))
        {
            return Err(PendingPipelineError::RollbackSourceNotTerminal(self.phase()));
        }
        if restored_frontier.chain().network_id() != self.key.network()
            || restored_frontier.authority() != self.key.authority()
        {
            return Err(PendingPipelineError::FrontierAuthorityMismatch);
        }
        if source_chain.network_id() != self.key.network()
            || source_chain.chain_epoch() != self.frontier.chain().chain_epoch()
            || source_chain.checkpoint().checkpoint_id().get()
                < self.frontier.chain().checkpoint().checkpoint_id().get()
        {
            return Err(PendingPipelineError::RollbackSourceHeadMismatch);
        }
        let source_epoch = source_chain.chain_epoch().get();
        let next_epoch = source_epoch
            .checked_add(1)
            .ok_or(PendingPipelineError::RollbackEpochOverflow(source_epoch))?;
        if restored_frontier.chain().chain_epoch().get() != next_epoch {
            return Err(PendingPipelineError::RollbackEpochNotNext {
                expected: next_epoch,
                proposed: restored_frontier.chain().chain_epoch().get(),
            });
        }
        let source_checkpoint = source_chain.checkpoint().checkpoint_id().get();
        let target_checkpoint = restored_frontier
            .chain()
            .checkpoint()
            .checkpoint_id()
            .get();
        if target_checkpoint >= source_checkpoint {
            return Err(PendingPipelineError::RollbackTargetNotBeforeCurrent {
                current: source_checkpoint,
                target: target_checkpoint,
            });
        }
        if target_processed_pending_id > self.processed_pending_id {
            return Err(PendingPipelineError::RollbackProcessedPendingAdvanced {
                current: self.processed_pending_id,
                target: target_processed_pending_id,
            });
        }
        if processing.pending_id().get() <= self.gathering.pending_id().get() {
            return Err(PendingPipelineError::RollbackProcessingNotFresh {
                abandoned_gathering: self.gathering.pending_id().get(),
                candidate: processing.pending_id().get(),
            });
        }
        if gathering.pending_id().get() <= processing.pending_id().get() {
            return Err(PendingPipelineError::RollbackGatheringNotAfterProcessing {
                processing: processing.pending_id().get(),
                gathering: gathering.pending_id().get(),
            });
        }
        if processing.proc_checkpoint_id()
            != self.proc_namespace_prefix.derive_proc_id(processing.pending_id())
            || gathering.proc_checkpoint_id()
                != self.proc_namespace_prefix.derive_proc_id(gathering.pending_id())
        {
            return Err(PendingPipelineError::ProcNamespacePrefixMismatch);
        }
        let mut candidate = self.clone();
        candidate.revision = self.revision.next()?;
        candidate.processing = processing;
        candidate.gathering = gathering;
        candidate.processing_state = PendingProcessingState::Ready;
        candidate.blocked_reason = None;
        candidate.frontier = restored_frontier;
        candidate.processed_pending_id = target_processed_pending_id;
        seal(self, candidate, PendingPipelineTransitionKind::RollbackReset)
    }

    /// Fill the empty gathering slot once at genesis without turning the zero
    /// processing sentinel into runnable work. Normal rotation is used after
    /// the second reservation exists.
    pub fn seal_prime_genesis(
        &self,
        reserved: ReservedPendingGeneration,
    ) -> Result<SealedPendingPipelineTransition<Hash>, PendingPipelineError> {
        self.require_unblocked()?;
        if self.bootstrap_reason != PendingGenerationBootstrapReason::Genesis
            || self.phase() != PendingProcessingPhase::Baseline
            || self.processing.pending_id().get() != 0
            || self.gathering.pending_id().get() != 0
            || self.processed_pending_id != 0
        {
            return Err(PendingPipelineError::GenesisNotPrimeable);
        }
        let next = PendingGenerationContext::try_from_legacy(
            reserved.pending_id().get(),
            reserved.proc_checkpoint_id().as_u128(),
        )
        .map_err(|error| PendingPipelineError::InvalidContext(error.to_string()))?;
        if next.pending_id().get() == 0
            || next.proc_checkpoint_id()
                != self.proc_namespace_prefix.derive_proc_id(next.pending_id())
        {
            return Err(PendingPipelineError::ProcNamespacePrefixMismatch);
        }
        let mut candidate = self.clone();
        candidate.revision = self.revision.next()?;
        candidate.gathering = next;
        seal(self, candidate, PendingPipelineTransitionKind::PrimeGenesis)
    }

    pub fn seal_begin_queue_close(
        &self,
        close: PendingQueueCloseIntentDigest,
    ) -> Result<SealedPendingPipelineTransition<Hash>, PendingPipelineError> {
        self.require_unblocked()?;
        self.require_ready()?;
        let mut candidate = self.clone();
        candidate.revision = self.revision.next()?;
        candidate.processing_state = PendingProcessingState::Sealing(close);
        seal(self, candidate, PendingPipelineTransitionKind::BeginQueueClose)
    }

    pub fn seal_capture_work(
        &self,
        expected_close: PendingQueueCloseIntentDigest,
        capture: PendingWorkCaptureDigest,
    ) -> Result<SealedPendingPipelineTransition<Hash>, PendingPipelineError> {
        self.require_unblocked()?;
        self.require_sealing(expected_close)?;
        let mut candidate = self.clone();
        candidate.revision = self.revision.next()?;
        candidate.processing_state = PendingProcessingState::WorkCaptured(capture);
        seal(self, candidate, PendingPipelineTransitionKind::CaptureWork)
    }

    pub fn seal_begin_processing(
        &self,
        expected_capture: PendingWorkCaptureDigest,
        intent: PendingPipelineIntentDigest,
    ) -> Result<SealedPendingPipelineTransition<Hash>, PendingPipelineError> {
        self.require_unblocked()?;
        if self.processing_state != PendingProcessingState::WorkCaptured(expected_capture) {
            if self.phase() != PendingProcessingPhase::WorkCaptured {
                return Err(PendingPipelineError::WorkNotCaptured(self.phase()));
            }
            return Err(PendingPipelineError::WorkCaptureMismatch);
        }
        let mut candidate = self.clone();
        candidate.revision = self.revision.next()?;
        candidate.processing_state = PendingProcessingState::InFlight {
            capture: expected_capture,
            intent,
        };
        seal(self, candidate, PendingPipelineTransitionKind::BeginProcessing)
    }

    pub fn seal_empty_queue(
        &self,
        expected_close: PendingQueueCloseIntentDigest,
        seal_digest: PendingEmptyQueueSealDigest,
    ) -> Result<SealedPendingPipelineTransition<Hash>, PendingPipelineError> {
        self.require_unblocked()?;
        self.require_sealing(expected_close)?;
        if self.key.authority() == AuthorityScope::Coordinator {
            return Err(PendingPipelineError::CoordinatorCannotRetireNoWork);
        }
        let mut candidate = self.clone();
        candidate.revision = self.revision.next()?;
        candidate.processing_state = PendingProcessingState::EmptyQueueSealed(seal_digest);
        seal(self, candidate, PendingPipelineTransitionKind::SealEmptyQueue)
    }

    pub fn seal_retire_no_work(
        &self,
        expected_seal: PendingEmptyQueueSealDigest,
        no_work_receipt: PendingNoWorkReceiptDigest,
        observed: AuthorityObservation<Hash>,
    ) -> Result<SealedPendingPipelineTransition<Hash>, PendingPipelineError> {
        self.require_unblocked()?;
        if self.processing_state != PendingProcessingState::EmptyQueueSealed(expected_seal) {
            if self.phase() != PendingProcessingPhase::EmptyQueueSealed {
                return Err(PendingPipelineError::EmptyQueueNotSealed(self.phase()));
            }
            return Err(PendingPipelineError::EmptyQueueSealMismatch);
        }
        if self.key.authority() == AuthorityScope::Coordinator {
            return Err(PendingPipelineError::CoordinatorCannotRetireNoWork);
        }
        validate_observed_advance(self, &observed, false)?;
        if observed.state_checkpoint_id() != self.frontier.state_checkpoint_id()
            || observed.state_root() != self.frontier.state_root()
        {
            return Err(PendingPipelineError::NoWorkChangedState);
        }
        let mut candidate = self.clone();
        candidate.revision = self.revision.next()?;
        candidate.processing_state = PendingProcessingState::RetiredNoWork {
            seal: expected_seal,
            receipt: no_work_receipt,
        };
        candidate.frontier = observed;
        candidate.processed_pending_id = self.processing.pending_id().get();
        seal(self, candidate, PendingPipelineTransitionKind::RetireNoWork)
    }

    /// Retire a generation whose immutable application contains only
    /// successor-deferred jobs. The application archive slot is carried in
    /// the original WorkCaptured evidence; the durable storage owner must
    /// prove the exact semantic is deferred-only before calling this model.
    pub fn seal_retire_deferred_work(
        &self,
        expected_capture: PendingWorkCaptureDigest,
        no_work_receipt: PendingNoWorkReceiptDigest,
        observed: AuthorityObservation<Hash>,
    ) -> Result<SealedPendingPipelineTransition<Hash>, PendingPipelineError> {
        self.require_unblocked()?;
        if self.processing_state != PendingProcessingState::WorkCaptured(expected_capture) {
            if self.phase() != PendingProcessingPhase::WorkCaptured {
                return Err(PendingPipelineError::WorkNotCaptured(self.phase()));
            }
            return Err(PendingPipelineError::WorkCaptureMismatch);
        }
        if self.key.authority() == AuthorityScope::Coordinator {
            return Err(PendingPipelineError::CoordinatorCannotRetireNoWork);
        }
        validate_observed_advance(self, &observed, false)?;
        if observed.state_checkpoint_id() != self.frontier.state_checkpoint_id()
            || observed.state_root() != self.frontier.state_root()
        {
            return Err(PendingPipelineError::NoWorkChangedState);
        }
        let seal_digest = PendingEmptyQueueSealDigest::try_new(*expected_capture.as_bytes())?;
        let mut candidate = self.clone();
        candidate.revision = self.revision.next()?;
        candidate.processing_state = PendingProcessingState::RetiredNoWork {
            seal: seal_digest,
            receipt: no_work_receipt,
        };
        candidate.frontier = observed;
        candidate.processed_pending_id = self.processing.pending_id().get();
        seal(
            self,
            candidate,
            PendingPipelineTransitionKind::RetireDeferredWork,
        )
    }

    pub fn seal_publish(
        &self,
        expected_intent: PendingPipelineIntentDigest,
        publish_receipt: PendingPublishReceiptDigest,
        observed: AuthorityObservation<Hash>,
    ) -> Result<SealedPendingPipelineTransition<Hash>, PendingPipelineError> {
        self.require_unblocked()?;
        let capture = self.require_inflight(expected_intent)?;
        validate_observed_advance(self, &observed, true)?;
        if observed.state_checkpoint_id().get()
            <= self.frontier.state_checkpoint_id().get()
        {
            return Err(PendingPipelineError::PublishedStateDidNotAdvance);
        }
        let mut candidate = self.clone();
        candidate.revision = self.revision.next()?;
        candidate.processing_state = PendingProcessingState::Published {
            capture,
            receipt: publish_receipt,
        };
        candidate.frontier = observed;
        candidate.processed_pending_id = self.processing.pending_id().get();
        seal(self, candidate, PendingPipelineTransitionKind::Publish)
    }

    pub fn seal_block(
        &self,
        reason: PendingBlockedReasonDigest,
    ) -> Result<SealedPendingPipelineTransition<Hash>, PendingPipelineError> {
        if self.blocked_reason.is_some() {
            return Err(PendingPipelineError::AlreadyBlocked);
        }
        let mut candidate = self.clone();
        candidate.revision = self.revision.next()?;
        candidate.blocked_reason = Some(reason);
        seal(self, candidate, PendingPipelineTransitionKind::Block)
    }

    fn require_inflight(
        &self,
        expected_intent: PendingPipelineIntentDigest,
    ) -> Result<PendingWorkCaptureDigest, PendingPipelineError> {
        match self.processing_state {
            PendingProcessingState::InFlight { capture, intent }
                if intent == expected_intent => Ok(capture),
            PendingProcessingState::InFlight { .. } => {
                Err(PendingPipelineError::InFlightIntentMismatch)
            }
            _ => Err(PendingPipelineError::ProcessingNotInFlight(self.phase())),
        }
    }

    fn require_ready(&self) -> Result<(), PendingPipelineError> {
        if self.processing_state != PendingProcessingState::Ready {
            return Err(PendingPipelineError::ProcessingNotReady(self.phase()));
        }
        // Early Genesis-native activations encoded `processed_pending_id=1`
        // even though generation 1 had not run. Accept only that exact
        // durable shape; new bootstraps encode the correct value 0 below.
        let legacy_genesis_ready = self.bootstrap_reason
            == PendingGenerationBootstrapReason::Genesis
            && self.derived_start_pending_id == 1
            && self.processing.pending_id().get() == 1
            && self.processed_pending_id == 1
            && self.frontier.chain().checkpoint().checkpoint_id().get() == 0
            && self.frontier.state_checkpoint_id().get() == 0;
        if self.processing.pending_id().get() <= self.processed_pending_id
            && !legacy_genesis_ready
        {
            return Err(PendingPipelineError::ProcessingNotAheadOfFrontier);
        }
        Ok(())
    }

    fn require_sealing(
        &self,
        expected_close: PendingQueueCloseIntentDigest,
    ) -> Result<(), PendingPipelineError> {
        match self.processing_state {
            PendingProcessingState::Sealing(close) if close == expected_close => Ok(()),
            PendingProcessingState::Sealing(_) => {
                Err(PendingPipelineError::QueueCloseIntentMismatch)
            }
            _ => Err(PendingPipelineError::QueueNotSealing(self.phase())),
        }
    }

    fn require_unblocked(&self) -> Result<(), PendingPipelineError> {
        if self.blocked_reason.is_some() {
            Err(PendingPipelineError::PipelineBlocked)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingPipelineBootstrap<Hash> {
    candidate: StoredPendingPipeline<Hash>,
    payload: [u8; PENDING_PIPELINE_V2_LEN],
}

impl<Hash: Q256BitHash> PendingPipelineBootstrap<Hash> {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        key: PendingGenerationLedgerKey,
        activation_digest: PendingGenerationActivationDigest,
        proc_namespace_prefix: ProcNamespacePrefix,
        bootstrap_reason: PendingGenerationBootstrapReason,
        processing: PendingGenerationContext,
        gathering: PendingGenerationContext,
        frontier: AuthorityObservation<Hash>,
        processed_pending_id: u64,
    ) -> Result<Self, PendingPipelineError> {
        let candidate = StoredPendingPipeline {
            key,
            revision: PendingPipelineRevision::try_new(0)?,
            activation_digest,
            proc_namespace_prefix,
            derived_start_pending_id: match bootstrap_reason {
                PendingGenerationBootstrapReason::Genesis => 1,
                PendingGenerationBootstrapReason::LegacyActivation => gathering
                    .pending_id()
                    .get()
                    .checked_add(1)
                    .ok_or(PendingPipelineError::DerivedCutoffOverflow)?,
            },
            bootstrap_reason,
            processing,
            gathering,
            processing_state: PendingProcessingState::Baseline(activation_digest),
            blocked_reason: None,
            frontier,
            processed_pending_id,
        };
        validate_state(&candidate)?;
        if processed_pending_id != processing.pending_id().get() {
            return Err(PendingPipelineError::BootstrapFrontierMismatch);
        }
        match bootstrap_reason {
            PendingGenerationBootstrapReason::Genesis
                if processing.pending_id().get() != 0
                    || gathering.pending_id().get() != 0 =>
            {
                return Err(PendingPipelineError::GenesisMustBeZero)
            }
            PendingGenerationBootstrapReason::LegacyActivation
                if processing.pending_id().get() == 0
                    || gathering.pending_id().get()
                        <= processing.pending_id().get() =>
            {
                return Err(PendingPipelineError::LegacyPipelineNotPrimed)
            }
            _ => {}
        }
        Ok(Self {
            payload: candidate.canonical_payload(),
            candidate,
        })
    }

    /// Bootstrap a brand-new authority directly at its deterministic first
    /// runnable generation. The ordinary Genesis commit owns the legacy
    /// pending counter; this sidecar bootstrap must not advance that counter
    /// before the legacy Genesis rows are installed.
    pub fn try_new_ready_genesis(
        key: PendingGenerationLedgerKey,
        activation_digest: PendingGenerationActivationDigest,
        proc_namespace_prefix: ProcNamespacePrefix,
        processing: PendingGenerationContext,
        gathering: PendingGenerationContext,
        frontier: AuthorityObservation<Hash>,
    ) -> Result<Self, PendingPipelineError> {
        if processing.pending_id().get() != 1
            || gathering.pending_id().get() != 2
            || processing.proc_checkpoint_id()
                != proc_namespace_prefix.derive_proc_id(processing.pending_id())
            || gathering.proc_checkpoint_id()
                != proc_namespace_prefix.derive_proc_id(gathering.pending_id())
        {
            return Err(PendingPipelineError::GenesisNotPrimeable);
        }
        let candidate = StoredPendingPipeline {
            key,
            // Baseline -> PrimeGenesis -> Rotate are represented by the
            // durable allocator evidence consumed before this single IFNE.
            revision: PendingPipelineRevision::try_new(2)?,
            activation_digest,
            proc_namespace_prefix,
            derived_start_pending_id: 1,
            bootstrap_reason: PendingGenerationBootstrapReason::Genesis,
            processing,
            gathering,
            processing_state: PendingProcessingState::Ready,
            blocked_reason: None,
            frontier,
            // Genesis is the committed frontier; generation 1 is the first
            // unprocessed queue generation and must be ahead of it.
            processed_pending_id: 0,
        };
        validate_state(&candidate)?;
        Ok(Self {
            payload: candidate.canonical_payload(),
            candidate,
        })
    }

    pub const fn candidate(&self) -> &StoredPendingPipeline<Hash> {
        &self.candidate
    }

    pub const fn candidate_payload(&self) -> &[u8; PENDING_PIPELINE_V2_LEN] {
        &self.payload
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PendingPipelineTransitionKind {
    PrimeGenesis = 1,
    Rotate = 2,
    BeginQueueClose = 3,
    CaptureWork = 4,
    BeginProcessing = 5,
    SealEmptyQueue = 6,
    RetireNoWork = 7,
    Publish = 8,
    Block = 9,
    RetireDeferredWork = 10,
    RollbackReset = 11,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedPendingPipelineTransition<Hash> {
    kind: PendingPipelineTransitionKind,
    expected: StoredPendingPipeline<Hash>,
    candidate: StoredPendingPipeline<Hash>,
    expected_payload: [u8; PENDING_PIPELINE_V2_LEN],
    candidate_payload: [u8; PENDING_PIPELINE_V2_LEN],
}

impl<Hash> SealedPendingPipelineTransition<Hash> {
    pub const fn kind(&self) -> PendingPipelineTransitionKind {
        self.kind
    }

    pub const fn expected(&self) -> &StoredPendingPipeline<Hash> {
        &self.expected
    }

    pub const fn candidate(&self) -> &StoredPendingPipeline<Hash> {
        &self.candidate
    }

    pub const fn expected_payload(&self) -> &[u8; PENDING_PIPELINE_V2_LEN] {
        &self.expected_payload
    }

    pub const fn candidate_payload(&self) -> &[u8; PENDING_PIPELINE_V2_LEN] {
        &self.candidate_payload
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingPipelineReadState<Hash> {
    Uninitialized,
    Current(StoredPendingPipeline<Hash>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingPipelineWriteOutcome<Hash> {
    Applied(StoredPendingPipeline<Hash>),
    Idempotent(StoredPendingPipeline<Hash>),
    Conflict(StoredPendingPipeline<Hash>),
}

impl<Hash: PartialEq> SealedPendingPipelineTransition<Hash> {
    pub fn classify(
        &self,
        applied: bool,
        current: StoredPendingPipeline<Hash>,
    ) -> PendingPipelineWriteOutcome<Hash> {
        classify(applied, &self.candidate, current)
    }
}

impl<Hash: PartialEq> PendingPipelineBootstrap<Hash> {
    pub fn classify(
        &self,
        applied: bool,
        current: StoredPendingPipeline<Hash>,
    ) -> PendingPipelineWriteOutcome<Hash> {
        classify(applied, &self.candidate, current)
    }
}

fn classify<Hash: PartialEq>(
    applied: bool,
    candidate: &StoredPendingPipeline<Hash>,
    current: StoredPendingPipeline<Hash>,
) -> PendingPipelineWriteOutcome<Hash> {
    if applied && &current == candidate {
        PendingPipelineWriteOutcome::Applied(current)
    } else if &current == candidate {
        PendingPipelineWriteOutcome::Idempotent(current)
    } else {
        PendingPipelineWriteOutcome::Conflict(current)
    }
}

fn seal<Hash: Q256BitHash>(
    expected: &StoredPendingPipeline<Hash>,
    candidate: StoredPendingPipeline<Hash>,
    kind: PendingPipelineTransitionKind,
) -> Result<SealedPendingPipelineTransition<Hash>, PendingPipelineError> {
    validate_state(&candidate)?;
    Ok(SealedPendingPipelineTransition {
        kind,
        expected_payload: expected.canonical_payload(),
        candidate_payload: candidate.canonical_payload(),
        expected: expected.clone(),
        candidate,
    })
}

fn validate_state<Hash: Q256BitHash>(
    state: &StoredPendingPipeline<Hash>,
) -> Result<(), PendingPipelineError> {
    if state.frontier.chain().network_id() != state.key.network()
        || state.frontier.authority() != state.key.authority()
    {
        return Err(PendingPipelineError::FrontierAuthorityMismatch);
    }
    if state.proc_namespace_prefix
        != ProcNamespacePrefix::for_authority(
            state.key.network(),
            state.key.authority(),
        )
    {
        return Err(PendingPipelineError::ProcNamespacePrefixMismatch);
    }
    validate_context_order(state.processing, state.gathering)?;
    validate_context_prefix(
        state.proc_namespace_prefix,
        state.derived_start_pending_id,
        state.processing,
    )?;
    validate_context_prefix(
        state.proc_namespace_prefix,
        state.derived_start_pending_id,
        state.gathering,
    )?;
    if let PendingProcessingState::Baseline(digest) = state.processing_state {
        if digest != state.activation_digest {
            return Err(PendingPipelineError::BaselineActivationMismatch);
        }
    }
    if state.phase().is_terminal()
        && state.processed_pending_id != state.processing.pending_id().get()
    {
        return Err(PendingPipelineError::TerminalFrontierMismatch);
    }
    if state.processed_pending_id > state.processing.pending_id().get() {
        return Err(PendingPipelineError::FrontierAheadOfProcessing);
    }
    Ok(())
}

fn validate_context_order(
    processing: PendingGenerationContext,
    gathering: PendingGenerationContext,
) -> Result<(), PendingPipelineError> {
    if processing.pending_id().get() > gathering.pending_id().get() {
        return Err(PendingPipelineError::ContextOrderInvalid);
    }
    if processing.pending_id() == gathering.pending_id() && processing != gathering {
        return Err(PendingPipelineError::SamePendingDifferentProc);
    }
    if processing.pending_id() != gathering.pending_id()
        && processing.proc_checkpoint_id() == gathering.proc_checkpoint_id()
    {
        return Err(PendingPipelineError::DuplicateProcNamespace);
    }
    Ok(())
}

fn validate_context_prefix(
    prefix: ProcNamespacePrefix,
    derived_start_pending_id: u64,
    context: PendingGenerationContext,
) -> Result<(), PendingPipelineError> {
    if context.pending_id().get() == 0 && context.proc_checkpoint_id().as_u128() == 0 {
        return Ok(());
    }
    if context.pending_id().get() >= derived_start_pending_id
        && context.proc_checkpoint_id() != prefix.derive_proc_id(context.pending_id())
    {
        Err(PendingPipelineError::ProcNamespacePrefixMismatch)
    } else {
        Ok(())
    }
}

fn validate_observed_advance<Hash: Q256BitHash>(
    state: &StoredPendingPipeline<Hash>,
    observed: &AuthorityObservation<Hash>,
    materialized: bool,
) -> Result<(), PendingPipelineError> {
    if observed.chain().network_id() != state.key.network()
        || observed.authority() != state.key.authority()
    {
        return Err(PendingPipelineError::FrontierAuthorityMismatch);
    }
    let old_chain = state.frontier.chain();
    let new_chain = observed.chain();
    if new_chain.chain_epoch() != old_chain.chain_epoch() {
        return Err(PendingPipelineError::EpochChangedDuringNormalProcessing);
    }
    let old_height = old_chain.checkpoint().checkpoint_id().get();
    let new_height = new_chain.checkpoint().checkpoint_id().get();
    if new_height < old_height {
        return Err(PendingPipelineError::BranchFrontierDidNotAdvance {
            old: old_height,
            new: new_height,
        });
    }
    if new_height == old_height {
        if materialized || new_chain != old_chain {
            return Err(PendingPipelineError::SameHeightBranchMismatch);
        }
        return Ok(());
    }
    if state.key.authority() == AuthorityScope::Coordinator
        && new_height != old_height.saturating_add(1)
    {
        return Err(PendingPipelineError::CoordinatorCheckpointNotContiguous {
            old: old_height,
            new: new_height,
        });
    }
    if materialized
        && observed.state_checkpoint_id().get()
            > observed.chain().checkpoint().checkpoint_id().get()
    {
        return Err(PendingPipelineError::PublishedStateAheadOfChain);
    }
    Ok(())
}

fn encode_payload<Hash: Q256BitHash>(
    state: &StoredPendingPipeline<Hash>,
) -> [u8; PENDING_PIPELINE_V2_LEN] {
    let mut bytes = Vec::with_capacity(PENDING_PIPELINE_V2_LEN);
    bytes.extend_from_slice(&PENDING_PIPELINE_MAGIC);
    bytes.extend_from_slice(&PENDING_PIPELINE_CODEC_VERSION.to_be_bytes());
    bytes.extend_from_slice(&state.key.network().chain_id().to_be_bytes());
    let (kind, realm, sub) = encode_authority(state.key.authority());
    bytes.push(kind);
    bytes.extend_from_slice(&realm.to_be_bytes());
    bytes.extend_from_slice(&sub.to_be_bytes());
    bytes.extend_from_slice(state.activation_digest.as_bytes());
    bytes.extend_from_slice(&state.proc_namespace_prefix.get().to_be_bytes());
    bytes.extend_from_slice(&state.derived_start_pending_id.to_be_bytes());
    bytes.push(encode_bootstrap_reason(state.bootstrap_reason));
    encode_context(&mut bytes, state.processing);
    encode_context(&mut bytes, state.gathering);
    bytes.push(state.phase() as u8);
    let (primary, secondary) = state.processing_state.evidence_bytes();
    bytes.extend_from_slice(&primary);
    bytes.extend_from_slice(&secondary);
    let blocked_reason = state
        .blocked_reason
        .map_or([0; 32], |reason| *reason.as_bytes());
    bytes.extend_from_slice(&blocked_reason);
    bytes.extend_from_slice(&state.frontier.to_canonical_bytes());
    bytes.extend_from_slice(&state.processed_pending_id.to_be_bytes());
    bytes.try_into().expect("fixed pending pipeline payload")
}

fn encode_context(bytes: &mut Vec<u8>, context: PendingGenerationContext) {
    bytes.extend_from_slice(&context.pending_id().get().to_be_bytes());
    bytes.extend_from_slice(context.proc_checkpoint_id().as_bytes());
}

fn decode_context(
    payload: &[u8],
    cursor: &mut usize,
) -> Result<PendingGenerationContext, PendingPipelineError> {
    let pending = u64::from_be_bytes(take::<8>(payload, cursor));
    let proc_id = u128::from_be_bytes(take::<16>(payload, cursor));
    PendingGenerationContext::try_from_legacy(pending, proc_id)
        .map_err(|error| PendingPipelineError::InvalidContext(error.to_string()))
}

const fn encode_bootstrap_reason(reason: PendingGenerationBootstrapReason) -> u8 {
    match reason {
        PendingGenerationBootstrapReason::Genesis => 1,
        PendingGenerationBootstrapReason::LegacyActivation => 2,
    }
}

fn decode_bootstrap_reason(value: u8) -> Result<PendingGenerationBootstrapReason, PendingPipelineError> {
    match value {
        1 => Ok(PendingGenerationBootstrapReason::Genesis),
        2 => Ok(PendingGenerationBootstrapReason::LegacyActivation),
        other => Err(PendingPipelineError::UnknownBootstrapReason(other)),
    }
}

fn encode_authority(authority: AuthorityScope) -> (u8, u32, u16) {
    match authority {
        AuthorityScope::Coordinator => (1, 0, 0),
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => (2, realm_id, realm_sub_id),
    }
}

fn decode_authority(kind: u8, realm: u32, sub: u16) -> Result<AuthorityScope, PendingPipelineError> {
    match (kind, realm, sub) {
        (1, 0, 0) => Ok(AuthorityScope::Coordinator),
        (1, _, _) => Err(PendingPipelineError::CoordinatorRealmIdsNonZero),
        (2, realm_id, realm_sub_id) => Ok(AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        }),
        (other, _, _) => Err(PendingPipelineError::UnknownAuthorityKind(other)),
    }
}

fn take<const N: usize>(payload: &[u8], cursor: &mut usize) -> [u8; N] {
    let end = *cursor + N;
    let value = payload[*cursor..end]
        .try_into()
        .expect("payload length checked");
    *cursor = end;
    value
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingPipelineError {
    RevisionOutOfRange(u64),
    NegativeRevision(i64),
    RevisionOverflow,
    EmptyEvidenceDigest,
    InvalidPayloadLength(usize),
    InvalidMagic,
    UnknownCodecVersion(u16),
    UnknownNetwork,
    UnknownAuthorityKind(u8),
    CoordinatorRealmIdsNonZero,
    UnknownBootstrapReason(u8),
    PartitionPayloadMismatch,
    InvalidActivationDigest,
    InvalidProcNamespacePrefix,
    DerivedCutoffOverflow,
    InvalidContext(String),
    InvalidFrontier(String),
    FrontierAuthorityMismatch,
    ContextOrderInvalid,
    SamePendingDifferentProc,
    DuplicateProcNamespace,
    ProcNamespacePrefixMismatch,
    GenesisMustBeZero,
    GenesisRequiresPrime,
    GenesisNotPrimeable,
    LegacyPipelineNotPrimed,
    BootstrapFrontierMismatch,
    UnknownPhase(u8),
    ReadyHasEvidence,
    BaselineActivationMismatch,
    TerminalFrontierMismatch,
    FrontierAheadOfProcessing,
    ProcessingNotTerminal(PendingProcessingPhase),
    ProcessingNotReady(PendingProcessingPhase),
    ProcessingNotAheadOfFrontier,
    QueueNotSealing(PendingProcessingPhase),
    QueueCloseIntentMismatch,
    WorkNotCaptured(PendingProcessingPhase),
    WorkCaptureMismatch,
    EmptyQueueNotSealed(PendingProcessingPhase),
    EmptyQueueSealMismatch,
    ProcessingNotInFlight(PendingProcessingPhase),
    InFlightIntentMismatch,
    UnexpectedSecondaryEvidence,
    PendingNotMonotonic { previous: u64, candidate: u64 },
    CoordinatorCannotRetireNoWork,
    NoWorkChangedState,
    PublishedStateDidNotAdvance,
    PublishedStateAheadOfChain,
    EpochChangedDuringNormalProcessing,
    BranchFrontierDidNotAdvance { old: u64, new: u64 },
    SameHeightBranchMismatch,
    CoordinatorCheckpointNotContiguous { old: u64, new: u64 },
    AlreadyBlocked,
    PipelineBlocked,
    CounterBehindLedger { counter: u64, gathering: u64 },
    RollbackSourceNotTerminal(PendingProcessingPhase),
    RollbackSourceHeadMismatch,
    RollbackEpochOverflow(u64),
    RollbackEpochNotNext { expected: u64, proposed: u64 },
    RollbackTargetNotBeforeCurrent { current: u64, target: u64 },
    RollbackProcessedPendingAdvanced { current: u64, target: u64 },
    RollbackProcessingNotFresh { abandoned_gathering: u64, candidate: u64 },
    RollbackGatheringNotAfterProcessing { processing: u64, gathering: u64 },
}

impl fmt::Display for PendingPipelineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PendingPipelineError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_core::constants::chain_id::PsyChainNetworkType;
    use psy_data::protocol::{
        canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
            CheckpointRef, NetworkId,
        },
        chain_context::{AuthorityStateCheckpointId, AuthorityStateRoot},
    };

    use super::*;

    fn key() -> PendingGenerationLedgerKey {
        PendingGenerationLedgerKey::new(
            NetworkId::from(PsyChainNetworkType::PsyMainnet),
            AuthorityScope::Realm {
                realm_id: 3,
                realm_sub_id: 4,
            },
        )
    }

    fn prefix() -> ProcNamespacePrefix {
        ProcNamespacePrefix::for_authority(key().network(), key().authority())
    }

    fn context(pending: u64) -> PendingGenerationContext {
        if pending == 0 {
            PendingGenerationContext::try_from_legacy(0, 0).unwrap()
        } else {
            PendingGenerationContext::try_from_legacy(
                pending,
                (prefix().get() as u128) << 64 | pending as u128,
            )
            .unwrap()
        }
    }

    fn legacy_context(pending: u64, proc_id: u128) -> PendingGenerationContext {
        PendingGenerationContext::try_from_legacy(pending, proc_id).unwrap()
    }

    fn observation(
        checkpoint: u64,
        state_checkpoint: u64,
        state_root: u64,
    ) -> AuthorityObservation<PHash> {
        observation_with_hash(checkpoint, checkpoint, state_checkpoint, state_root)
    }

    fn observation_with_hash(
        checkpoint: u64,
        chain_hash: u64,
        state_checkpoint: u64,
        state_root: u64,
    ) -> AuthorityObservation<PHash> {
        observation_custom(
            key().authority(),
            0,
            checkpoint,
            chain_hash,
            state_checkpoint,
            state_root,
        )
    }

    fn observation_custom(
        authority: AuthorityScope,
        epoch: u64,
        checkpoint: u64,
        chain_hash: u64,
        state_checkpoint: u64,
        state_root: u64,
    ) -> AuthorityObservation<PHash> {
        AuthorityObservation::try_new(
            CanonicalChainRef::new(
                key().network(),
                ChainEpoch::new(epoch),
                CheckpointRef::new(
                    CheckpointId::new(checkpoint),
                    CheckpointHash::from_last_chain_hash(PHash::from_values(
                        chain_hash,
                        chain_hash + 1,
                        chain_hash + 2,
                        chain_hash + 3,
                    )),
                ),
            ),
            authority,
            AuthorityStateCheckpointId::new(state_checkpoint),
            AuthorityStateRoot::from_local_state_root(PHash::from_values(
                state_root,
                state_root + 1,
                state_root + 2,
                state_root + 3,
            )),
        )
        .unwrap()
    }

    fn intent(value: u8) -> PendingPipelineIntentDigest {
        PendingPipelineIntentDigest::try_new([value; 32]).unwrap()
    }

    fn close(value: u8) -> PendingQueueCloseIntentDigest {
        PendingQueueCloseIntentDigest::try_new([value; 32]).unwrap()
    }

    fn capture(value: u8) -> PendingWorkCaptureDigest {
        PendingWorkCaptureDigest::try_new([value; 32]).unwrap()
    }

    fn empty_seal(value: u8) -> PendingEmptyQueueSealDigest {
        PendingEmptyQueueSealDigest::try_new([value; 32]).unwrap()
    }

    fn capture_work(
        ready: &StoredPendingPipeline<PHash>,
        close_value: u8,
        capture_value: u8,
    ) -> StoredPendingPipeline<PHash> {
        let sealing = ready
            .seal_begin_queue_close(close(close_value))
            .unwrap()
            .candidate()
            .clone();
        sealing
            .seal_capture_work(close(close_value), capture(capture_value))
            .unwrap()
            .candidate()
            .clone()
    }

    fn seal_empty(
        ready: &StoredPendingPipeline<PHash>,
        close_value: u8,
        seal_value: u8,
    ) -> StoredPendingPipeline<PHash> {
        let sealing = ready
            .seal_begin_queue_close(close(close_value))
            .unwrap()
            .candidate()
            .clone();
        sealing
            .seal_empty_queue(close(close_value), empty_seal(seal_value))
            .unwrap()
            .candidate()
            .clone()
    }

    fn no_work(value: u8) -> PendingNoWorkReceiptDigest {
        PendingNoWorkReceiptDigest::try_new([value; 32]).unwrap()
    }

    fn publish(value: u8) -> PendingPublishReceiptDigest {
        PendingPublishReceiptDigest::try_new([value; 32]).unwrap()
    }

    fn block_reason(value: u8) -> PendingBlockedReasonDigest {
        PendingBlockedReasonDigest::try_new([value; 32]).unwrap()
    }

    fn bootstrap() -> PendingPipelineBootstrap<PHash> {
        PendingPipelineBootstrap::try_new(
            key(),
            PendingGenerationActivationDigest::try_new([0xa5; 32]).unwrap(),
            prefix(),
            PendingGenerationBootstrapReason::LegacyActivation,
            legacy_context(8, 80),
            legacy_context(9, 90),
            observation(8, 8, 80),
            8,
        )
        .unwrap()
    }

    fn genesis_bootstrap() -> PendingPipelineBootstrap<PHash> {
        let zero = context(0);
        PendingPipelineBootstrap::try_new(
            key(),
            PendingGenerationActivationDigest::try_new([0xa5; 32]).unwrap(),
            prefix(),
            PendingGenerationBootstrapReason::Genesis,
            zero,
            zero,
            observation(0, 0, 80),
            0,
        )
        .unwrap()
    }

    #[test]
    fn round_trip_publish_and_two_consecutive_no_work_generations_at_one_observation() {
        let initial = bootstrap();
        let decoded = StoredPendingPipeline::<PHash>::decode_persisted(
            key(),
            0,
            initial.candidate_payload(),
        )
        .unwrap();
        assert_eq!(decoded, *initial.candidate());

        let ready = initial
            .candidate()
            .seal_rotation(
                ReservedPendingGeneration::try_from_prefix(12, prefix()).unwrap(),
            )
            .unwrap()
            .candidate()
            .clone();
        assert_eq!(ready.phase(), PendingProcessingPhase::Ready);
        let empty = seal_empty(&ready, 1, 2);
        let retired = empty
            .seal_retire_no_work(empty_seal(2), no_work(3), observation(10, 8, 80))
            .unwrap()
            .candidate()
            .clone();
        assert_eq!(retired.phase(), PendingProcessingPhase::RetiredNoWork);
        assert_eq!(retired.processed_pending_id(), 9);

        let ready = retired
            .seal_rotation(
                ReservedPendingGeneration::try_from_prefix(15, prefix()).unwrap(),
            )
            .unwrap()
            .candidate()
            .clone();
        let empty = seal_empty(&ready, 4, 5);
        let retired_same_head = empty
            .seal_retire_no_work(empty_seal(5), no_work(6), observation(10, 8, 80))
            .unwrap()
            .candidate()
            .clone();
        assert_eq!(retired_same_head.processed_pending_id(), 12);
        let ready = retired_same_head
            .seal_rotation(
                ReservedPendingGeneration::try_from_prefix(18, prefix()).unwrap(),
            )
            .unwrap()
            .candidate()
            .clone();
        let captured = capture_work(&ready, 7, 8);
        let inflight = captured
            .seal_begin_processing(capture(8), intent(9))
            .unwrap()
            .candidate()
            .clone();
        let published = inflight
            .seal_publish(intent(9), publish(10), observation(14, 14, 140))
            .unwrap()
            .candidate()
            .clone();
        assert_eq!(published.phase(), PendingProcessingPhase::Published);
        assert_eq!(published.processed_pending_id(), 15);
    }

    #[test]
    fn deferred_only_work_retires_from_capture_without_changing_state() {
        let ready = bootstrap()
            .candidate()
            .seal_rotation(
                ReservedPendingGeneration::try_from_prefix(10, prefix()).unwrap(),
            )
            .unwrap()
            .candidate()
            .clone();
        let captured = capture_work(&ready, 1, 2);
        let retired = captured
            .seal_retire_deferred_work(
                capture(2),
                no_work(3),
                *captured.frontier(),
            )
            .unwrap();
        assert_eq!(retired.kind(), PendingPipelineTransitionKind::RetireDeferredWork);
        assert_eq!(retired.candidate().phase(), PendingProcessingPhase::RetiredNoWork);
        assert_eq!(retired.candidate().frontier(), captured.frontier());
        assert_eq!(
            retired.candidate().processed_pending_id(),
            captured.processing().pending_id().get(),
        );
        assert!(matches!(
            captured.seal_retire_deferred_work(
                capture(4),
                no_work(3),
                *captured.frontier(),
            ),
            Err(PendingPipelineError::WorkCaptureMismatch),
        ));
    }

    #[test]
    fn rollback_reset_rewinds_frontier_but_allocates_two_fresh_generations() {
        let ready = bootstrap()
            .candidate()
            .seal_rotation(
                ReservedPendingGeneration::try_from_prefix(12, prefix()).unwrap(),
            )
            .unwrap()
            .candidate()
            .clone();
        let captured = capture_work(&ready, 1, 2);
        let published = captured
            .seal_begin_processing(capture(2), intent(3))
            .unwrap()
            .candidate()
            .seal_publish(intent(3), publish(4), observation(14, 14, 140))
            .unwrap()
            .candidate()
            .clone();
        let restored = observation_custom(key().authority(), 1, 8, 8, 8, 80);
        let sealed = published
            .seal_rollback_reset(
                ReservedPendingGeneration::try_from_prefix(20, prefix()).unwrap(),
                ReservedPendingGeneration::try_from_prefix(21, prefix()).unwrap(),
                restored,
                8,
            )
            .unwrap();

        assert_eq!(sealed.kind(), PendingPipelineTransitionKind::RollbackReset);
        assert_eq!(sealed.candidate().revision().get(), published.revision().get() + 1);
        assert_eq!(sealed.candidate().processing(), context(20));
        assert_eq!(sealed.candidate().gathering(), context(21));
        assert_eq!(sealed.candidate().phase(), PendingProcessingPhase::Ready);
        assert_eq!(sealed.candidate().frontier(), &restored);
        assert_eq!(sealed.candidate().processed_pending_id(), 8);

        assert!(matches!(
            ready.seal_rollback_reset(
                ReservedPendingGeneration::try_from_prefix(20, prefix()).unwrap(),
                ReservedPendingGeneration::try_from_prefix(21, prefix()).unwrap(),
                restored,
                8,
            ),
            Err(PendingPipelineError::RollbackSourceNotTerminal(_))
        ));
        assert!(matches!(
            published.seal_rollback_reset(
                ReservedPendingGeneration::try_from_prefix(12, prefix()).unwrap(),
                ReservedPendingGeneration::try_from_prefix(21, prefix()).unwrap(),
                restored,
                8,
            ),
            Err(PendingPipelineError::RollbackProcessingNotFresh { .. })
        ));
        assert!(matches!(
            published.seal_rollback_reset(
                ReservedPendingGeneration::try_from_prefix(20, prefix()).unwrap(),
                ReservedPendingGeneration::try_from_prefix(20, prefix()).unwrap(),
                restored,
                8,
            ),
            Err(PendingPipelineError::RollbackGatheringNotAfterProcessing { .. })
        ));
        assert!(matches!(
            published.seal_rollback_reset(
                ReservedPendingGeneration::try_from_prefix(20, prefix()).unwrap(),
                ReservedPendingGeneration::try_from_prefix(21, prefix()).unwrap(),
                observation_custom(key().authority(), 0, 8, 8, 8, 80),
                8,
            ),
            Err(PendingPipelineError::RollbackEpochNotNext { .. })
        ));
        assert!(matches!(
            published.seal_rollback_reset(
                ReservedPendingGeneration::try_from_prefix(20, prefix()).unwrap(),
                ReservedPendingGeneration::try_from_prefix(21, prefix()).unwrap(),
                restored,
                10,
            ),
            Err(PendingPipelineError::RollbackProcessedPendingAdvanced { .. })
        ));
    }

    #[test]
    fn rollback_reset_accepts_ready_pipeline_behind_exact_realm_sync_head() {
        let ready = bootstrap()
            .candidate()
            .seal_rotation(
                ReservedPendingGeneration::try_from_prefix(12, prefix()).unwrap(),
            )
            .unwrap()
            .candidate()
            .clone();
        assert_eq!(ready.phase(), PendingProcessingPhase::Ready);
        assert_eq!(
            ready.frontier().chain().checkpoint().checkpoint_id().get(),
            8
        );
        let source_chain = *observation(14, 8, 80).chain();
        let restored = observation_custom(key().authority(), 1, 0, 0, 0, 10);
        let sealed = ready
            .seal_rollback_reset_from_synced_head_contexts(
                context(20),
                context(21),
                source_chain,
                restored,
                0,
            )
            .unwrap();
        assert_eq!(sealed.candidate().phase(), PendingProcessingPhase::Ready);
        assert_eq!(sealed.candidate().frontier(), &restored);
        assert_eq!(sealed.candidate().processed_pending_id(), 0);
        assert!(matches!(
            ready.seal_rollback_reset_from_synced_head_contexts(
                context(20),
                context(21),
                *observation(7, 7, 70).chain(),
                restored,
                0,
            ),
            Err(PendingPipelineError::RollbackSourceHeadMismatch)
        ));

        let sealing = ready
            .seal_begin_queue_close(close(9))
            .unwrap()
            .candidate()
            .clone();
        let reset = sealing
            .seal_rollback_reset_from_synced_head_contexts(
                context(22),
                context(23),
                source_chain,
                observation_custom(key().authority(), 1, 0, 0, 0, 10),
                0,
            )
            .unwrap();
        assert_eq!(reset.candidate().phase(), PendingProcessingPhase::Ready);
        assert_eq!(reset.candidate().processing(), context(22));
    }

    #[test]
    fn non_terminal_rotation_wrong_intent_and_state_claims_fail_closed() {
        let ready = bootstrap()
            .candidate()
            .seal_rotation(
                ReservedPendingGeneration::try_from_prefix(10, prefix()).unwrap(),
            )
            .unwrap()
            .candidate()
            .clone();
        assert!(matches!(
            ready.seal_rotation(
                ReservedPendingGeneration::try_from_prefix(11, prefix()).unwrap()
            ),
            Err(PendingPipelineError::ProcessingNotTerminal(_))
        ));
        assert!(matches!(
            ready.seal_begin_processing(capture(2), intent(1)),
            Err(PendingPipelineError::WorkNotCaptured(_))
        ));
        let sealing = ready
            .seal_begin_queue_close(close(1))
            .unwrap()
            .candidate()
            .clone();
        assert_eq!(
            sealing.seal_capture_work(close(2), capture(3)),
            Err(PendingPipelineError::QueueCloseIntentMismatch)
        );
        let captured = sealing
            .seal_capture_work(close(1), capture(3))
            .unwrap()
            .candidate()
            .clone();
        assert_eq!(
            captured.seal_begin_processing(capture(4), intent(1)),
            Err(PendingPipelineError::WorkCaptureMismatch)
        );
        let inflight = captured
            .seal_begin_processing(capture(3), intent(1))
            .unwrap()
            .candidate()
            .clone();
        assert_eq!(
            inflight.seal_publish(intent(2), publish(3), observation(9, 9, 90)),
            Err(PendingPipelineError::InFlightIntentMismatch)
        );
        assert_eq!(
            inflight.seal_publish(intent(1), publish(3), observation(9, 8, 80)),
            Err(PendingPipelineError::PublishedStateDidNotAdvance)
        );

        let empty = seal_empty(&ready, 5, 6);
        assert_eq!(
            empty.seal_retire_no_work(empty_seal(7), no_work(3), observation(9, 9, 90)),
            Err(PendingPipelineError::EmptyQueueSealMismatch)
        );
        assert_eq!(
            empty.seal_retire_no_work(empty_seal(6), no_work(3), observation(9, 9, 90)),
            Err(PendingPipelineError::NoWorkChangedState)
        );
        assert_eq!(
            empty.seal_retire_no_work(
                empty_seal(6),
                no_work(3),
                observation_with_hash(8, 999, 8, 80),
            ),
            Err(PendingPipelineError::SameHeightBranchMismatch)
        );
        assert_eq!(
            empty.seal_retire_no_work(
                empty_seal(6),
                no_work(3),
                observation_custom(key().authority(), 1, 8, 8, 8, 80),
            ),
            Err(PendingPipelineError::EpochChangedDuringNormalProcessing)
        );
        assert_eq!(
            empty.seal_retire_no_work(
                empty_seal(6),
                no_work(3),
                observation_custom(
                    AuthorityScope::Realm {
                        realm_id: 99,
                        realm_sub_id: 1,
                    },
                    0,
                    8,
                    8,
                    8,
                    80,
                ),
            ),
            Err(PendingPipelineError::FrontierAuthorityMismatch)
        );
    }

    #[test]
    fn counter_holes_are_allowed_but_counter_behind_and_prefix_forgery_fail() {
        let state = bootstrap().candidate().clone();
        assert_eq!(state.validate_counter_high_water(100), Ok(()));
        assert_eq!(
            state.validate_counter_high_water(7),
            Err(PendingPipelineError::CounterBehindLedger {
                counter: 7,
                gathering: 9,
            })
        );
        assert_eq!(
            state.seal_rotation(ReservedPendingGeneration::try_new(12, 44).unwrap()),
            Err(PendingPipelineError::ProcNamespacePrefixMismatch)
        );
    }

    #[test]
    fn blocked_is_terminal_fail_closed_and_payload_size_is_constant() {
        let state = bootstrap().candidate().clone();
        let blocked = state
            .seal_block(block_reason(9))
            .unwrap()
            .candidate()
            .clone();
        assert_eq!(blocked.phase(), state.phase());
        assert_eq!(blocked.blocked_reason(), Some(block_reason(9)));
        assert!(blocked
            .seal_rotation(
                ReservedPendingGeneration::try_from_prefix(10, prefix()).unwrap()
            )
            .is_err());
        assert_eq!(blocked.canonical_payload().len(), PENDING_PIPELINE_V2_LEN);
        assert_eq!(state.canonical_payload().len(), PENDING_PIPELINE_V2_LEN);
    }

    #[test]
    fn same_candidate_retry_is_idempotent_and_old_revision_conflicts() {
        let initial = bootstrap();
        let transition = initial
            .candidate()
            .seal_rotation(
                ReservedPendingGeneration::try_from_prefix(10, prefix()).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            transition.classify(false, transition.candidate().clone()),
            PendingPipelineWriteOutcome::Idempotent(_)
        ));
        assert!(matches!(
            transition.classify(false, initial.candidate().clone()),
            PendingPipelineWriteOutcome::Conflict(_)
        ));
    }

    #[test]
    fn sixty_four_competing_rotations_have_one_winner_and_stale_revision_cannot_aba() {
        let initial = bootstrap().candidate().clone();
        let contenders = (0..64)
            .map(|offset| {
                initial
                    .seal_rotation(
                        ReservedPendingGeneration::try_from_prefix(
                            10 + offset,
                            prefix(),
                        )
                        .unwrap(),
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let mut current = initial.clone();
        let mut winners = 0;
        for contender in &contenders {
            if current == *contender.expected() {
                current = contender.candidate().clone();
                assert!(matches!(
                    contender.classify(true, current.clone()),
                    PendingPipelineWriteOutcome::Applied(_)
                ));
                winners += 1;
            } else {
                assert!(matches!(
                    contender.classify(false, current.clone()),
                    PendingPipelineWriteOutcome::Conflict(_)
                ));
            }
        }
        assert_eq!(winners, 1);
        let advanced = current
            .seal_begin_queue_close(close(7))
            .unwrap()
            .candidate()
            .clone();
        assert!(matches!(
            contenders[0].classify(false, advanced),
            PendingPipelineWriteOutcome::Conflict(_)
        ));
    }

    #[test]
    fn persisted_non_authority_prefix_is_rejected() {
        let bootstrap = bootstrap();
        let mut payload = *bootstrap.candidate_payload();
        // magic/version/network/authority/activation occupy 53 bytes.
        payload[53..61].copy_from_slice(&42_u64.to_be_bytes());
        assert_eq!(
            StoredPendingPipeline::<PHash>::decode_persisted(key(), 0, &payload),
            Err(PendingPipelineError::ProcNamespacePrefixMismatch)
        );
    }

    #[test]
    fn v1_payload_is_not_silently_reinterpreted_as_v2() {
        let bootstrap = bootstrap();
        let mut payload = *bootstrap.candidate_payload();
        payload[8..10].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            StoredPendingPipeline::<PHash>::decode_persisted(key(), 0, &payload),
            Err(PendingPipelineError::UnknownCodecVersion(1))
        );
    }

    #[test]
    fn ten_thousand_idle_generations_keep_one_constant_size_recoverable_row() {
        let observed = observation(8, 8, 80);
        let mut state = bootstrap().candidate().clone();
        for offset in 0..10_000_u64 {
            state = state
                .seal_rotation(
                    ReservedPendingGeneration::try_from_prefix(
                        10 + offset,
                        prefix(),
                    )
                    .unwrap(),
                )
                .unwrap()
                .candidate()
                .clone();
            state = seal_empty(&state, 1, 2);
            state = state
                .seal_retire_no_work(empty_seal(2), no_work(3), observed)
                .unwrap()
                .candidate()
                .clone();
            assert_eq!(state.canonical_payload().len(), PENDING_PIPELINE_V2_LEN);
        }
        assert_eq!(state.processed_pending_id(), 10_008);
        assert_eq!(state.gathering().pending_id().get(), 10_009);
        assert_eq!(state.revision().get(), 40_000);
        assert_eq!(
            StoredPendingPipeline::<PHash>::decode_persisted(
                key(),
                state.revision().as_i64(),
                &state.canonical_payload(),
            )
            .unwrap(),
            state
        );
    }

    #[test]
    fn genesis_requires_prime_then_rotate_before_processing() {
        let genesis = genesis_bootstrap().candidate().clone();
        assert_eq!(
            genesis.seal_rotation(
                ReservedPendingGeneration::try_from_prefix(1, prefix()).unwrap()
            ),
            Err(PendingPipelineError::GenesisRequiresPrime)
        );
        let primed = genesis
            .seal_prime_genesis(
                ReservedPendingGeneration::try_from_prefix(1, prefix()).unwrap(),
            )
            .unwrap()
            .candidate()
            .clone();
        assert_eq!(primed.processing(), context(0));
        assert_eq!(primed.gathering(), context(1));
        assert_eq!(primed.phase(), PendingProcessingPhase::Baseline);
        let ready = primed
            .seal_rotation(
                ReservedPendingGeneration::try_from_prefix(2, prefix()).unwrap(),
            )
            .unwrap()
            .candidate()
            .clone();
        assert_eq!(ready.processing(), context(1));
        let captured = capture_work(&ready, 1, 2);
        assert!(captured
            .seal_begin_processing(capture(2), intent(1))
            .is_ok());
    }

    #[test]
    fn genesis_bootstrap_is_ready_and_rejects_wrong_identities() {
        let ready = PendingPipelineBootstrap::try_new_ready_genesis(
            key(),
            PendingGenerationActivationDigest::try_new([0xa5; 32]).unwrap(),
            prefix(),
            context(1),
            context(2),
            observation(0, 0, 80),
        )
        .unwrap();
        assert_eq!(ready.candidate().revision().get(), 2);
        assert_eq!(ready.candidate().phase(), PendingProcessingPhase::Ready);
        assert_eq!(ready.candidate().processing(), context(1));
        assert_eq!(ready.candidate().gathering(), context(2));
        assert_eq!(ready.candidate().processed_pending_id(), 0);
        assert!(ready
            .candidate()
            .seal_begin_queue_close(close(1))
            .is_ok());

        let mut legacy = ready.candidate().clone();
        legacy.processed_pending_id = 1;
        assert!(legacy.seal_begin_queue_close(close(1)).is_ok());

        assert_eq!(
            PendingPipelineBootstrap::try_new_ready_genesis(
                key(),
                PendingGenerationActivationDigest::try_new([0xa5; 32]).unwrap(),
                prefix(),
                context(2),
                context(3),
                observation(0, 0, 80),
            ),
            Err(PendingPipelineError::GenesisNotPrimeable)
        );
    }
}
