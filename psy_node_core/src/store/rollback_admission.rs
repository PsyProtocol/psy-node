//! Durable single-slot handoff from Coordinator Edge/admin tooling to the
//! Coordinator Processor.
//!
//! Edge and Processor are separate processes. Edge must therefore never call
//! the canonical-head admission CAS directly: a block may already have
//! materialized state while its final canonical-head publish is still pending.
//! This module provides a durable inbox. Only the Processor consumes the slot
//! and performs the sealed admission at a normal loop boundary.

use std::{error::Error, fmt, sync::Arc};

use async_trait::async_trait;
use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::{CanonicalChainRef, NetworkId};

use super::{
    canonical_head::{
        CanonicalHeadModelError, CanonicalHeadReadState, CanonicalHeadTransition,
        CanonicalHeadWriteOutcome, CoordinatorCanonicalHeadStore,
        SealedCanonicalHeadCas, StoredCanonicalHead,
    },
    rollback_control::{
        RollbackControlCodecError, RollbackControlState, RollbackRequest,
    },
};

pub const ROLLBACK_ADMISSION_SLOT_MAGIC: [u8; 8] = *b"PSYRBINB";
pub const ROLLBACK_ADMISSION_SLOT_CODEC_VERSION: u16 = 1;
pub const ROLLBACK_ADMISSION_SLOT_V1_LEN: usize = 243;

const SLOT_KIND_EMPTY: u8 = 0;
const SLOT_KIND_PENDING: u8 = 1;
const HEADER_RESERVED_END: usize = 16;
const EXPECTED_REVISION_START: usize = 16;
const EXPECTED_REVISION_END: usize = 24;
const EXPECTED_CANONICAL_START: usize = 24;
const EXPECTED_CANONICAL_END: usize = 89;
const REQUESTED_CONTROL_START: usize = 89;

/// Monotonic revision of the operational inbox row. It is not a rollback ID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RollbackAdmissionSlotRevision(u64);

impl RollbackAdmissionSlotRevision {
    pub const fn try_new(value: u64) -> Result<Self, RollbackAdmissionError> {
        if value <= i64::MAX as u64 {
            Ok(Self(value))
        } else {
            Err(RollbackAdmissionError::RevisionOutOfCqlRange(value))
        }
    }

    pub const fn try_from_i64(value: i64) -> Result<Self, RollbackAdmissionError> {
        if value < 0 {
            Err(RollbackAdmissionError::NegativeRevision(value))
        } else {
            Ok(Self(value as u64))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    const fn initial() -> Self {
        Self(0)
    }

    pub const fn checked_next(self) -> Result<Self, RollbackAdmissionError> {
        match self.0.checked_add(1) {
            Some(next) if next <= i64::MAX as u64 => Ok(Self(next)),
            _ => Err(RollbackAdmissionError::RevisionOverflow(self.0)),
        }
    }
}

/// Exact canonical-head transition proposed by an external admin process.
///
/// Construction is intentionally only possible from the validated
/// `IDLE -> REQUESTED` builder. The inbox does not permit arbitrary rewinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackAdmissionCommand<Hash> {
    sealed: SealedCanonicalHeadCas<Hash>,
}

impl<Hash: Q256BitHash> RollbackAdmissionCommand<Hash> {
    pub fn try_new(
        expected: StoredCanonicalHead<Hash>,
        request: RollbackRequest<Hash>,
    ) -> Result<Self, RollbackAdmissionError> {
        let sealed = CanonicalHeadTransition::start_rollback(expected, request)?.seal();
        Ok(Self { sealed })
    }

    pub const fn sealed(&self) -> &SealedCanonicalHeadCas<Hash> {
        &self.sealed
    }

    pub const fn expected(&self) -> &StoredCanonicalHead<Hash> {
        self.sealed.expected()
    }

    pub fn request(&self) -> &RollbackRequest<Hash> {
        match self.sealed.candidate().rollback_control() {
            RollbackControlState::Requested(request) => request,
            RollbackControlState::Idle => {
                unreachable!("start-rollback command always carries REQUESTED control")
            }
            RollbackControlState::Archiving(_)
            | RollbackControlState::ArchiveBarrierReady(_)
            | RollbackControlState::Deleting(_) => {
                unreachable!("admission command cannot contain a post-REQUESTED phase")
            }
        }
    }

    pub const fn network_id(&self) -> NetworkId {
        self.sealed.expected().canonical_ref().network_id()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackAdmissionSlotState<Hash> {
    Empty,
    Pending(RollbackAdmissionCommand<Hash>),
}

impl<Hash> RollbackAdmissionSlotState<Hash> {
    pub const fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    pub const fn pending(&self) -> Option<&RollbackAdmissionCommand<Hash>> {
        match self {
            Self::Empty => None,
            Self::Pending(command) => Some(command),
        }
    }
}

impl<Hash: Q256BitHash> RollbackAdmissionSlotState<Hash> {
    pub fn to_canonical_bytes(&self) -> [u8; ROLLBACK_ADMISSION_SLOT_V1_LEN] {
        let mut encoded = [0_u8; ROLLBACK_ADMISSION_SLOT_V1_LEN];
        encoded[0..8].copy_from_slice(&ROLLBACK_ADMISSION_SLOT_MAGIC);
        encoded[8..10].copy_from_slice(&ROLLBACK_ADMISSION_SLOT_CODEC_VERSION.to_le_bytes());
        match self {
            Self::Empty => encoded[10] = SLOT_KIND_EMPTY,
            Self::Pending(command) => {
                encoded[10] = SLOT_KIND_PENDING;
                encoded[EXPECTED_REVISION_START..EXPECTED_REVISION_END]
                    .copy_from_slice(&command.expected().revision().as_i64().to_le_bytes());
                encoded[EXPECTED_CANONICAL_START..EXPECTED_CANONICAL_END]
                    .copy_from_slice(command.sealed().expected_payload());
                encoded[REQUESTED_CONTROL_START..]
                    .copy_from_slice(command.sealed().candidate_control_payload());
            }
        }
        encoded
    }

    pub fn from_canonical_bytes(
        partition_network: NetworkId,
        bytes: &[u8],
    ) -> Result<Self, RollbackAdmissionCodecError> {
        if bytes.len() != ROLLBACK_ADMISSION_SLOT_V1_LEN {
            return Err(RollbackAdmissionCodecError::InvalidLength {
                expected: ROLLBACK_ADMISSION_SLOT_V1_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0..8] != ROLLBACK_ADMISSION_SLOT_MAGIC {
            return Err(RollbackAdmissionCodecError::InvalidMagic);
        }
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version != ROLLBACK_ADMISSION_SLOT_CODEC_VERSION {
            return Err(RollbackAdmissionCodecError::UnsupportedVersion(version));
        }
        if bytes[11..HEADER_RESERVED_END].iter().any(|byte| *byte != 0) {
            return Err(RollbackAdmissionCodecError::NonCanonicalReservedBytes);
        }
        match bytes[10] {
            SLOT_KIND_EMPTY => {
                if bytes[EXPECTED_REVISION_START..].iter().any(|byte| *byte != 0) {
                    return Err(RollbackAdmissionCodecError::NonCanonicalEmpty);
                }
                Ok(Self::Empty)
            }
            SLOT_KIND_PENDING => {
                let expected_revision = i64::from_le_bytes(
                    bytes[EXPECTED_REVISION_START..EXPECTED_REVISION_END]
                        .try_into()
                        .expect("fixed revision slice"),
                );
                let expected_ref: CanonicalChainRef<Hash> = CanonicalChainRef::from_canonical_bytes(
                    &bytes[EXPECTED_CANONICAL_START..EXPECTED_CANONICAL_END],
                )?;
                if expected_ref.network_id() != partition_network {
                    return Err(RollbackAdmissionCodecError::PartitionNetworkMismatch {
                        partition: partition_network,
                        payload: expected_ref.network_id(),
                    });
                }
                let idle = RollbackControlState::<Hash>::Idle.to_canonical_bytes();
                let expected = StoredCanonicalHead::decode_persisted(
                    partition_network,
                    expected_revision,
                    &bytes[EXPECTED_CANONICAL_START..EXPECTED_CANONICAL_END],
                    &idle,
                )?;
                let requested = RollbackControlState::from_canonical_bytes(
                    &bytes[REQUESTED_CONTROL_START..],
                )?;
                let request = requested
                    .requested()
                    .copied()
                    .ok_or(RollbackAdmissionCodecError::PendingMustCarryRequestedControl)?;
                let command = RollbackAdmissionCommand::try_new(expected, request)?;
                Ok(Self::Pending(command))
            }
            other => Err(RollbackAdmissionCodecError::UnknownSlotKind(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredRollbackAdmissionSlot<Hash> {
    revision: RollbackAdmissionSlotRevision,
    state: RollbackAdmissionSlotState<Hash>,
}

impl<Hash> StoredRollbackAdmissionSlot<Hash> {
    pub const fn revision(&self) -> RollbackAdmissionSlotRevision {
        self.revision
    }

    pub const fn state(&self) -> &RollbackAdmissionSlotState<Hash> {
        &self.state
    }
}

impl<Hash: Q256BitHash> StoredRollbackAdmissionSlot<Hash> {
    pub fn decode_persisted(
        partition_network: NetworkId,
        revision: i64,
        payload: &[u8],
    ) -> Result<Self, RollbackAdmissionCodecError> {
        Ok(Self {
            revision: RollbackAdmissionSlotRevision::try_from_i64(revision)?,
            state: RollbackAdmissionSlotState::from_canonical_bytes(
                partition_network,
                payload,
            )?,
        })
    }

    pub fn payload(&self) -> [u8; ROLLBACK_ADMISSION_SLOT_V1_LEN] {
        self.state.to_canonical_bytes()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackAdmissionSlotBootstrap<Hash> {
    network: NetworkId,
    candidate: StoredRollbackAdmissionSlot<Hash>,
    candidate_payload: [u8; ROLLBACK_ADMISSION_SLOT_V1_LEN],
}

impl<Hash: Q256BitHash> RollbackAdmissionSlotBootstrap<Hash> {
    pub fn new(network: NetworkId) -> Self {
        let state = RollbackAdmissionSlotState::Empty;
        Self {
            network,
            candidate: StoredRollbackAdmissionSlot {
                revision: RollbackAdmissionSlotRevision::initial(),
                state,
            },
            candidate_payload: state.to_canonical_bytes(),
        }
    }

    pub const fn network(&self) -> NetworkId {
        self.network
    }

    pub const fn candidate(&self) -> &StoredRollbackAdmissionSlot<Hash> {
        &self.candidate
    }

    pub const fn candidate_payload(&self) -> &[u8; ROLLBACK_ADMISSION_SLOT_V1_LEN] {
        &self.candidate_payload
    }

    pub fn classify_lwt_observation(
        &self,
        applied: bool,
        current: StoredRollbackAdmissionSlot<Hash>,
    ) -> RollbackAdmissionSlotWriteOutcome<Hash> {
        classify_slot_lwt(applied, self.candidate, current)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackAdmissionSlotTransitionKind {
    Offer,
    Clear,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedRollbackAdmissionSlotCas<Hash> {
    kind: RollbackAdmissionSlotTransitionKind,
    network: NetworkId,
    expected: StoredRollbackAdmissionSlot<Hash>,
    candidate: StoredRollbackAdmissionSlot<Hash>,
    expected_payload: [u8; ROLLBACK_ADMISSION_SLOT_V1_LEN],
    candidate_payload: [u8; ROLLBACK_ADMISSION_SLOT_V1_LEN],
}

impl<Hash: Q256BitHash> SealedRollbackAdmissionSlotCas<Hash> {
    pub fn offer(
        network: NetworkId,
        expected: StoredRollbackAdmissionSlot<Hash>,
        command: RollbackAdmissionCommand<Hash>,
    ) -> Result<Self, RollbackAdmissionError> {
        if !expected.state().is_empty() {
            return Err(RollbackAdmissionError::SlotNotEmpty);
        }
        if command.network_id() != network {
            return Err(RollbackAdmissionError::NetworkMismatch {
                expected: network,
                proposed: command.network_id(),
            });
        }
        Self::build(
            RollbackAdmissionSlotTransitionKind::Offer,
            network,
            expected,
            RollbackAdmissionSlotState::Pending(command),
        )
    }

    pub fn clear(
        network: NetworkId,
        expected: StoredRollbackAdmissionSlot<Hash>,
    ) -> Result<Self, RollbackAdmissionError> {
        if expected.state().pending().is_none() {
            return Err(RollbackAdmissionError::SlotNotPending);
        }
        Self::build(
            RollbackAdmissionSlotTransitionKind::Clear,
            network,
            expected,
            RollbackAdmissionSlotState::Empty,
        )
    }

    fn build(
        kind: RollbackAdmissionSlotTransitionKind,
        network: NetworkId,
        expected: StoredRollbackAdmissionSlot<Hash>,
        candidate_state: RollbackAdmissionSlotState<Hash>,
    ) -> Result<Self, RollbackAdmissionError> {
        let candidate = StoredRollbackAdmissionSlot {
            revision: expected.revision.checked_next()?,
            state: candidate_state,
        };
        Ok(Self {
            kind,
            network,
            expected_payload: expected.payload(),
            candidate_payload: candidate.payload(),
            expected,
            candidate,
        })
    }

    pub const fn kind(&self) -> RollbackAdmissionSlotTransitionKind {
        self.kind
    }

    pub const fn network(&self) -> NetworkId {
        self.network
    }

    pub const fn expected(&self) -> &StoredRollbackAdmissionSlot<Hash> {
        &self.expected
    }

    pub const fn candidate(&self) -> &StoredRollbackAdmissionSlot<Hash> {
        &self.candidate
    }

    pub const fn expected_payload(&self) -> &[u8; ROLLBACK_ADMISSION_SLOT_V1_LEN] {
        &self.expected_payload
    }

    pub const fn candidate_payload(&self) -> &[u8; ROLLBACK_ADMISSION_SLOT_V1_LEN] {
        &self.candidate_payload
    }

    pub fn classify_lwt_observation(
        &self,
        applied: bool,
        current: StoredRollbackAdmissionSlot<Hash>,
    ) -> RollbackAdmissionSlotWriteOutcome<Hash> {
        classify_slot_lwt(applied, self.candidate, current)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackAdmissionSlotReadState<Hash> {
    Uninitialized,
    Current(StoredRollbackAdmissionSlot<Hash>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackAdmissionSlotWriteOutcome<Hash> {
    Applied(StoredRollbackAdmissionSlot<Hash>),
    Idempotent(StoredRollbackAdmissionSlot<Hash>),
    Conflict {
        current: StoredRollbackAdmissionSlot<Hash>,
    },
}

fn classify_slot_lwt<Hash: PartialEq + Copy>(
    applied: bool,
    candidate: StoredRollbackAdmissionSlot<Hash>,
    current: StoredRollbackAdmissionSlot<Hash>,
) -> RollbackAdmissionSlotWriteOutcome<Hash> {
    if applied {
        RollbackAdmissionSlotWriteOutcome::Applied(current)
    } else if current == candidate {
        RollbackAdmissionSlotWriteOutcome::Idempotent(current)
    } else {
        RollbackAdmissionSlotWriteOutcome::Conflict { current }
    }
}

#[async_trait]
pub trait CoordinatorRollbackAdmissionReader<Hash>: Send + Sync {
    async fn read_rollback_admission_slot(
        &self,
        network: NetworkId,
    ) -> anyhow::Result<RollbackAdmissionSlotReadState<Hash>>;
}

#[async_trait]
pub trait CoordinatorRollbackAdmissionStore<Hash>:
    CoordinatorRollbackAdmissionReader<Hash>
{
    async fn bootstrap_rollback_admission_slot(
        &self,
        bootstrap: &RollbackAdmissionSlotBootstrap<Hash>,
    ) -> anyhow::Result<RollbackAdmissionSlotWriteOutcome<Hash>>;

    async fn compare_and_set_rollback_admission_slot(
        &self,
        sealed: &SealedRollbackAdmissionSlotCas<Hash>,
    ) -> anyhow::Result<RollbackAdmissionSlotWriteOutcome<Hash>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackAdmissionBoundaryOutcome<Hash> {
    Normal(StoredCanonicalHead<Hash>),
    StaleCommandRejected(StoredCanonicalHead<Hash>),
    Maintenance(StoredCanonicalHead<Hash>),
}

impl<Hash> RollbackAdmissionBoundaryOutcome<Hash> {
    pub const fn canonical_head(&self) -> &StoredCanonicalHead<Hash> {
        match self {
            Self::Normal(head)
            | Self::StaleCommandRejected(head)
            | Self::Maintenance(head) => head,
        }
    }

    pub const fn permits_normal_processing(&self) -> bool {
        matches!(self, Self::Normal(_) | Self::StaleCommandRejected(_))
    }
}

/// Processor-owned arbiter. Edge can write only the inbox; this object is the
/// sole bridge from an inbox command to the canonical-head admission CAS.
pub struct CoordinatorRollbackAdmissionBoundary<Hash> {
    network: NetworkId,
    canonical_head_store: Arc<dyn CoordinatorCanonicalHeadStore<Hash>>,
    admission_store: Arc<dyn CoordinatorRollbackAdmissionStore<Hash>>,
}

impl<Hash: Q256BitHash + Send + Sync + 'static>
    CoordinatorRollbackAdmissionBoundary<Hash>
{
    pub fn new(
        network: NetworkId,
        canonical_head_store: Arc<dyn CoordinatorCanonicalHeadStore<Hash>>,
        admission_store: Arc<dyn CoordinatorRollbackAdmissionStore<Hash>>,
    ) -> Self {
        Self {
            network,
            canonical_head_store,
            admission_store,
        }
    }

    pub async fn ensure_slot_initialized(&self) -> anyhow::Result<()> {
        let bootstrap = RollbackAdmissionSlotBootstrap::new(self.network);
        let _ = self
            .admission_store
            .bootstrap_rollback_admission_slot(&bootstrap)
            .await?;
        Ok(())
    }

    pub async fn reconcile_at_loop_boundary(
        &self,
    ) -> anyhow::Result<RollbackAdmissionBoundaryOutcome<Hash>> {
        let slot = match self
            .admission_store
            .read_rollback_admission_slot(self.network)
            .await?
        {
            RollbackAdmissionSlotReadState::Uninitialized => {
                anyhow::bail!("ROLLBACK_ADMISSION_SLOT_UNINITIALIZED")
            }
            RollbackAdmissionSlotReadState::Current(slot) => slot,
        };
        let current_head = match self
            .canonical_head_store
            .read_canonical_head(self.network)
            .await?
        {
            CanonicalHeadReadState::Uninitialized => {
                anyhow::bail!("CANONICAL_HEAD_UNINITIALIZED_AT_ROLLBACK_BOUNDARY")
            }
            CanonicalHeadReadState::Current(head) => head,
        };

        let Some(command) = slot.state().pending().copied() else {
            return Ok(if current_head.rollback_control().is_idle() {
                RollbackAdmissionBoundaryOutcome::Normal(current_head)
            } else {
                RollbackAdmissionBoundaryOutcome::Maintenance(current_head)
            });
        };

        let write = self
            .canonical_head_store
            .compare_and_set_canonical_head(command.sealed())
            .await?;
        let (head, accepted) = match write {
            CanonicalHeadWriteOutcome::Applied(head)
            | CanonicalHeadWriteOutcome::Idempotent(head) => (head, true),
            CanonicalHeadWriteOutcome::Conflict { current } => {
                let same_active_request = current
                    .rollback_control()
                    .requested()
                    .is_some_and(|request| request == command.request());
                (current, same_active_request)
            }
        };

        let clear = SealedRollbackAdmissionSlotCas::clear(self.network, slot)?;
        match self
            .admission_store
            .compare_and_set_rollback_admission_slot(&clear)
            .await?
        {
            RollbackAdmissionSlotWriteOutcome::Applied(current)
            | RollbackAdmissionSlotWriteOutcome::Idempotent(current)
                if current.state().is_empty() => {}
            RollbackAdmissionSlotWriteOutcome::Conflict { .. }
            | RollbackAdmissionSlotWriteOutcome::Applied(_)
            | RollbackAdmissionSlotWriteOutcome::Idempotent(_) => {
                anyhow::bail!("ROLLBACK_ADMISSION_SLOT_CLEAR_CONFLICT")
            }
        }

        if accepted || !head.rollback_control().is_idle() {
            Ok(RollbackAdmissionBoundaryOutcome::Maintenance(head))
        } else {
            Ok(RollbackAdmissionBoundaryOutcome::StaleCommandRejected(head))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RollbackAdmissionError {
    NegativeRevision(i64),
    RevisionOutOfCqlRange(u64),
    RevisionOverflow(u64),
    SlotNotEmpty,
    SlotNotPending,
    NetworkMismatch {
        expected: NetworkId,
        proposed: NetworkId,
    },
    CanonicalHead(CanonicalHeadModelError),
}

impl fmt::Display for RollbackAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NegativeRevision(value) => write!(formatter, "negative inbox revision {value}"),
            Self::RevisionOutOfCqlRange(value) => {
                write!(formatter, "inbox revision {value} exceeds CQL BIGINT")
            }
            Self::RevisionOverflow(value) => {
                write!(formatter, "inbox revision cannot advance past {value}")
            }
            Self::SlotNotEmpty => formatter.write_str("rollback admission slot is not empty"),
            Self::SlotNotPending => formatter.write_str("rollback admission slot is not pending"),
            Self::NetworkMismatch { expected, proposed } => write!(
                formatter,
                "rollback admission network mismatch: expected {}, proposed {}",
                expected.chain_id(),
                proposed.chain_id()
            ),
            Self::CanonicalHead(error) => error.fmt(formatter),
        }
    }
}

impl Error for RollbackAdmissionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CanonicalHead(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CanonicalHeadModelError> for RollbackAdmissionError {
    fn from(value: CanonicalHeadModelError) -> Self {
        Self::CanonicalHead(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RollbackAdmissionCodecError {
    InvalidLength { expected: usize, actual: usize },
    InvalidMagic,
    UnsupportedVersion(u16),
    UnknownSlotKind(u8),
    NonCanonicalReservedBytes,
    NonCanonicalEmpty,
    PendingMustCarryRequestedControl,
    PartitionNetworkMismatch {
        partition: NetworkId,
        payload: NetworkId,
    },
    CanonicalChain(psy_data::protocol::canonical_chain::CanonicalChainRefCodecError),
    CanonicalHead(CanonicalHeadModelError),
    RollbackControl(RollbackControlCodecError),
    Model(RollbackAdmissionError),
}

impl fmt::Display for RollbackAdmissionCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(formatter, "inbox payload length {actual}, expected {expected}")
            }
            Self::InvalidMagic => formatter.write_str("invalid rollback admission inbox magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported rollback admission inbox version {version}")
            }
            Self::UnknownSlotKind(kind) => write!(formatter, "unknown inbox slot kind {kind}"),
            Self::NonCanonicalReservedBytes => {
                formatter.write_str("rollback admission inbox reserved bytes are non-zero")
            }
            Self::NonCanonicalEmpty => {
                formatter.write_str("empty rollback admission inbox carries trailing data")
            }
            Self::PendingMustCarryRequestedControl => {
                formatter.write_str("pending inbox must carry REQUESTED control")
            }
            Self::PartitionNetworkMismatch { partition, payload } => write!(
                formatter,
                "inbox partition network {} differs from payload network {}",
                partition.chain_id(),
                payload.chain_id()
            ),
            Self::CanonicalChain(error) => error.fmt(formatter),
            Self::CanonicalHead(error) => error.fmt(formatter),
            Self::RollbackControl(error) => error.fmt(formatter),
            Self::Model(error) => error.fmt(formatter),
        }
    }
}

impl Error for RollbackAdmissionCodecError {}

impl From<psy_data::protocol::canonical_chain::CanonicalChainRefCodecError>
    for RollbackAdmissionCodecError
{
    fn from(value: psy_data::protocol::canonical_chain::CanonicalChainRefCodecError) -> Self {
        Self::CanonicalChain(value)
    }
}

impl From<CanonicalHeadModelError> for RollbackAdmissionCodecError {
    fn from(value: CanonicalHeadModelError) -> Self {
        Self::CanonicalHead(value)
    }
}

impl From<RollbackControlCodecError> for RollbackAdmissionCodecError {
    fn from(value: RollbackControlCodecError) -> Self {
        Self::RollbackControl(value)
    }
}

impl From<RollbackAdmissionError> for RollbackAdmissionCodecError {
    fn from(value: RollbackAdmissionError) -> Self {
        Self::Model(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::PHash;
    use psy_core::constants::chain_id::PsyChainNetworkType;
    use psy_data::protocol::canonical_chain::{
        ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
    };

    use crate::store::{
        canonical_head::{
            CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile,
            CanonicalHeadTransitionKind, CanonicalHeadWriteOutcome,
        },
        rollback_control::{RollbackExecutionMode, RollbackPlanDigest},
        timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
    };
    use std::sync::Mutex;

    struct MemoryCanonicalStore {
        current: Mutex<Option<StoredCanonicalHead<PHash>>>,
    }

    impl MemoryCanonicalStore {
        fn with_current(current: StoredCanonicalHead<PHash>) -> Self {
            Self {
                current: Mutex::new(Some(current)),
            }
        }

        fn force_current(&self, current: StoredCanonicalHead<PHash>) {
            *self.current.lock().unwrap() = Some(current);
        }
    }

    #[async_trait]
    impl super::super::canonical_head::CoordinatorCanonicalHeadReader<PHash>
        for MemoryCanonicalStore
    {
        async fn read_canonical_head(
            &self,
            _network: NetworkId,
        ) -> anyhow::Result<CanonicalHeadReadState<PHash>> {
            Ok(match *self.current.lock().unwrap() {
                Some(current) => CanonicalHeadReadState::Current(current),
                None => CanonicalHeadReadState::Uninitialized,
            })
        }
    }

    #[async_trait]
    impl super::super::coordinator_commit_source::CoordinatorCommitSourceStore<PHash>
        for MemoryCanonicalStore
    {
        async fn persist_coordinator_rollback_floor(
            &self,
            _floor: &super::super::coordinator_commit_source::CoordinatorRollbackFloor<PHash>,
        ) -> anyhow::Result<()> {
            anyhow::bail!("rollback-admission fixture has no rollback-floor writer")
        }

        async fn read_coordinator_rollback_floor(
            &self,
            _network: NetworkId,
            _chain_epoch: u64,
        ) -> anyhow::Result<Option<
            super::super::coordinator_commit_source::CoordinatorRollbackFloor<PHash>,
        >> {
            Ok(None)
        }

        async fn persist_coordinator_commit_source(
            &self,
            _source: &super::super::coordinator_commit_source::CoordinatorCommitSource<PHash>,
        ) -> anyhow::Result<()> {
            anyhow::bail!("rollback-admission fixture has no normal commit-source writer")
        }

        async fn read_coordinator_commit_source(
            &self,
            _candidate: &CanonicalChainRef<PHash>,
        ) -> anyhow::Result<Option<
            super::super::coordinator_commit_source::CoordinatorCommitSource<PHash>,
        >> {
            Ok(None)
        }

        async fn mark_coordinator_commit_source_committed(
            &self,
            _source: &super::super::coordinator_commit_source::CoordinatorCommitSource<PHash>,
        ) -> anyhow::Result<()> {
            anyhow::bail!("rollback-admission fixture has no normal commit-source writer")
        }
    }

    #[async_trait]
    impl CoordinatorCanonicalHeadStore<PHash> for MemoryCanonicalStore {
        async fn bootstrap_canonical_head(
            &self,
            bootstrap: &CanonicalHeadBootstrap<PHash>,
        ) -> anyhow::Result<CanonicalHeadWriteOutcome<PHash>> {
            let mut current = self.current.lock().unwrap();
            match *current {
                None => {
                    *current = Some(*bootstrap.candidate());
                    Ok(CanonicalHeadWriteOutcome::Applied(*bootstrap.candidate()))
                }
                Some(observed) if observed == *bootstrap.candidate() => {
                    Ok(CanonicalHeadWriteOutcome::Idempotent(observed))
                }
                Some(observed) => Ok(CanonicalHeadWriteOutcome::Conflict {
                    current: observed,
                }),
            }
        }

        async fn compare_and_set_canonical_head(
            &self,
            sealed: &SealedCanonicalHeadCas<PHash>,
        ) -> anyhow::Result<CanonicalHeadWriteOutcome<PHash>> {
            let mut current = self.current.lock().unwrap();
            let observed = current.expect("test canonical row initialized");
            if observed == *sealed.expected() {
                *current = Some(*sealed.candidate());
                Ok(CanonicalHeadWriteOutcome::Applied(*sealed.candidate()))
            } else if observed == *sealed.candidate() {
                Ok(CanonicalHeadWriteOutcome::Idempotent(observed))
            } else {
                Ok(CanonicalHeadWriteOutcome::Conflict { current: observed })
            }
        }
    }

    struct MemoryAdmissionStore {
        current: Mutex<Option<StoredRollbackAdmissionSlot<PHash>>>,
    }

    impl MemoryAdmissionStore {
        fn with_empty(network: NetworkId) -> Self {
            Self {
                current: Mutex::new(Some(
                    *RollbackAdmissionSlotBootstrap::new(network).candidate(),
                )),
            }
        }

        fn current(&self) -> StoredRollbackAdmissionSlot<PHash> {
            self.current.lock().unwrap().expect("test inbox initialized")
        }
    }

    #[async_trait]
    impl CoordinatorRollbackAdmissionReader<PHash> for MemoryAdmissionStore {
        async fn read_rollback_admission_slot(
            &self,
            _network: NetworkId,
        ) -> anyhow::Result<RollbackAdmissionSlotReadState<PHash>> {
            Ok(match *self.current.lock().unwrap() {
                Some(current) => RollbackAdmissionSlotReadState::Current(current),
                None => RollbackAdmissionSlotReadState::Uninitialized,
            })
        }
    }

    #[async_trait]
    impl CoordinatorRollbackAdmissionStore<PHash> for MemoryAdmissionStore {
        async fn bootstrap_rollback_admission_slot(
            &self,
            bootstrap: &RollbackAdmissionSlotBootstrap<PHash>,
        ) -> anyhow::Result<RollbackAdmissionSlotWriteOutcome<PHash>> {
            let mut current = self.current.lock().unwrap();
            match *current {
                None => {
                    *current = Some(*bootstrap.candidate());
                    Ok(RollbackAdmissionSlotWriteOutcome::Applied(
                        *bootstrap.candidate(),
                    ))
                }
                Some(observed) if observed == *bootstrap.candidate() => {
                    Ok(RollbackAdmissionSlotWriteOutcome::Idempotent(observed))
                }
                Some(observed) => Ok(RollbackAdmissionSlotWriteOutcome::Conflict {
                    current: observed,
                }),
            }
        }

        async fn compare_and_set_rollback_admission_slot(
            &self,
            sealed: &SealedRollbackAdmissionSlotCas<PHash>,
        ) -> anyhow::Result<RollbackAdmissionSlotWriteOutcome<PHash>> {
            let mut current = self.current.lock().unwrap();
            let observed = current.expect("test inbox initialized");
            if observed == *sealed.expected() {
                *current = Some(*sealed.candidate());
                Ok(RollbackAdmissionSlotWriteOutcome::Applied(
                    *sealed.candidate(),
                ))
            } else if observed == *sealed.candidate() {
                Ok(RollbackAdmissionSlotWriteOutcome::Idempotent(observed))
            } else {
                Ok(RollbackAdmissionSlotWriteOutcome::Conflict { current: observed })
            }
        }
    }

    fn checkpoint(height: u64, seed: u64) -> CheckpointRef<PHash> {
        CheckpointRef::new(
            CheckpointId::new(height),
            CheckpointHash::from_last_chain_hash(PHash::from_values(
                seed,
                seed + 1,
                seed + 2,
                seed + 3,
            )),
        )
    }

    fn head() -> StoredCanonicalHead<PHash> {
        *CanonicalHeadBootstrap::try_new(
            CanonicalHeadBootstrapProfile::PostGenesisFloor,
            CanonicalChainRef::new(
                NetworkId::from(PsyChainNetworkType::PsyMainnet),
                ChainEpoch::new(0),
                checkpoint(100, 10),
            ),
        )
        .unwrap()
        .candidate()
    }

    fn command() -> RollbackAdmissionCommand<PHash> {
        command_with_target(90, 20, 0xA5)
    }

    fn command_with_target(
        target_height: u64,
        target_seed: u64,
        digest_byte: u8,
    ) -> RollbackAdmissionCommand<PHash> {
        let expected = head();
        let request = RollbackRequest::try_new(
            *expected.canonical_ref().checkpoint(),
            checkpoint(target_height, target_seed),
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
                1_001,
                1_002,
            )
            .unwrap(),
            RollbackExecutionMode::InPlace,
            RollbackPlanDigest::try_new([digest_byte; 32]).unwrap(),
        )
        .unwrap();
        RollbackAdmissionCommand::try_new(expected, request).unwrap()
    }

    async fn offer(
        network: NetworkId,
        inbox: &MemoryAdmissionStore,
        command: RollbackAdmissionCommand<PHash>,
    ) {
        let sealed =
            SealedRollbackAdmissionSlotCas::offer(network, inbox.current(), command).unwrap();
        assert!(matches!(
            inbox
                .compare_and_set_rollback_admission_slot(&sealed)
                .await
                .unwrap(),
            RollbackAdmissionSlotWriteOutcome::Applied(_)
        ));
    }

    #[test]
    fn empty_and_pending_slot_codec_are_fixed_and_fail_closed() {
        let network = NetworkId::from(PsyChainNetworkType::PsyMainnet);
        let empty = RollbackAdmissionSlotState::<PHash>::Empty;
        let empty_bytes = empty.to_canonical_bytes();
        assert_eq!(empty_bytes.len(), ROLLBACK_ADMISSION_SLOT_V1_LEN);
        assert_eq!(
            RollbackAdmissionSlotState::from_canonical_bytes(network, &empty_bytes).unwrap(),
            empty
        );

        let pending = RollbackAdmissionSlotState::Pending(command());
        let pending_bytes = pending.to_canonical_bytes();
        assert_eq!(pending_bytes, pending.to_canonical_bytes());
        assert_eq!(
            RollbackAdmissionSlotState::from_canonical_bytes(network, &pending_bytes).unwrap(),
            pending
        );

        let mut malformed = pending_bytes;
        malformed[11] = 1;
        assert_eq!(
            RollbackAdmissionSlotState::<PHash>::from_canonical_bytes(network, &malformed),
            Err(RollbackAdmissionCodecError::NonCanonicalReservedBytes)
        );
        let mut unknown = pending_bytes;
        unknown[8..10].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(
            RollbackAdmissionSlotState::<PHash>::from_canonical_bytes(network, &unknown),
            Err(RollbackAdmissionCodecError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn offer_and_clear_are_revisioned_and_exact() {
        let network = NetworkId::from(PsyChainNetworkType::PsyMainnet);
        let bootstrap = RollbackAdmissionSlotBootstrap::<PHash>::new(network);
        let offer = SealedRollbackAdmissionSlotCas::offer(
            network,
            *bootstrap.candidate(),
            command(),
        )
        .unwrap();
        assert_eq!(offer.expected().revision().get(), 0);
        assert_eq!(offer.candidate().revision().get(), 1);
        assert!(offer.candidate().state().pending().is_some());
        assert!(SealedRollbackAdmissionSlotCas::offer(
            network,
            *offer.candidate(),
            command(),
        )
        .is_err());

        let clear = SealedRollbackAdmissionSlotCas::clear(network, *offer.candidate()).unwrap();
        assert_eq!(clear.candidate().revision().get(), 2);
        assert!(clear.candidate().state().is_empty());
        assert_eq!(clear.expected_payload(), offer.candidate_payload());
    }

    #[test]
    fn command_can_only_represent_start_rollback() {
        let command = command();
        assert_eq!(command.sealed().kind(), CanonicalHeadTransitionKind::StartRollback);
        assert_eq!(command.request().target().checkpoint_id().get(), 90);
        assert_eq!(command.expected().canonical_ref().checkpoint().checkpoint_id().get(), 100);
    }

    #[test]
    fn revision_range_and_network_binding_fail_closed() {
        assert!(RollbackAdmissionSlotRevision::try_from_i64(-1).is_err());
        assert!(RollbackAdmissionSlotRevision::try_new(i64::MAX as u64 + 1).is_err());
        let other_network = NetworkId::from(PsyChainNetworkType::PsyPublicTestnet);
        let bootstrap = RollbackAdmissionSlotBootstrap::<PHash>::new(other_network);
        assert!(SealedRollbackAdmissionSlotCas::offer(
            other_network,
            *bootstrap.candidate(),
            command(),
        )
        .is_err());
    }

    #[tokio::test]
    async fn processor_boundary_admits_then_parks_and_clears_transient_slot() {
        let network = NetworkId::from(PsyChainNetworkType::PsyMainnet);
        let canonical = Arc::new(MemoryCanonicalStore::with_current(head()));
        let inbox = Arc::new(MemoryAdmissionStore::with_empty(network));
        offer(network, &inbox, command()).await;
        let boundary = CoordinatorRollbackAdmissionBoundary::new(
            network,
            canonical.clone(),
            inbox.clone(),
        );

        let outcome = boundary.reconcile_at_loop_boundary().await.unwrap();
        assert!(matches!(
            outcome,
            RollbackAdmissionBoundaryOutcome::Maintenance(_)
        ));
        assert!(!outcome.permits_normal_processing());
        assert_eq!(outcome.canonical_head().canonical_ref().chain_epoch().get(), 1);
        assert_eq!(
            outcome
                .canonical_head()
                .canonical_ref()
                .checkpoint()
                .checkpoint_id()
                .get(),
            100
        );
        assert!(outcome.canonical_head().rollback_control().requested().is_some());
        assert!(inbox.current().state().is_empty());
        assert_eq!(inbox.current().revision().get(), 2);

        let retry = boundary.reconcile_at_loop_boundary().await.unwrap();
        assert!(matches!(
            retry,
            RollbackAdmissionBoundaryOutcome::Maintenance(_)
        ));
    }

    #[tokio::test]
    async fn command_arriving_during_previous_block_is_stale_not_rebound() {
        let network = NetworkId::from(PsyChainNetworkType::PsyMainnet);
        let canonical = Arc::new(MemoryCanonicalStore::with_current(head()));
        let inbox = Arc::new(MemoryAdmissionStore::with_empty(network));
        offer(network, &inbox, command()).await;

        let old = head();
        let next_ref = CanonicalChainRef::new(
            network,
            old.canonical_ref().chain_epoch(),
            checkpoint(101, 30),
        );
        let next = CanonicalHeadTransition::normal_checkpoint_advance(old, next_ref)
            .unwrap()
            .seal();
        canonical.force_current(*next.candidate());

        let boundary = CoordinatorRollbackAdmissionBoundary::new(
            network,
            canonical,
            inbox.clone(),
        );
        let outcome = boundary.reconcile_at_loop_boundary().await.unwrap();
        assert!(matches!(
            outcome,
            RollbackAdmissionBoundaryOutcome::StaleCommandRejected(_)
        ));
        assert!(outcome.permits_normal_processing());
        assert_eq!(
            outcome
                .canonical_head()
                .canonical_ref()
                .checkpoint()
                .checkpoint_id()
                .get(),
            101
        );
        assert_eq!(outcome.canonical_head().canonical_ref().chain_epoch().get(), 0);
        assert!(outcome.canonical_head().rollback_control().is_idle());
        assert!(inbox.current().state().is_empty());
    }

    #[tokio::test]
    async fn crash_after_head_admission_before_slot_clear_recovers_idempotently() {
        let network = NetworkId::from(PsyChainNetworkType::PsyMainnet);
        let canonical = Arc::new(MemoryCanonicalStore::with_current(head()));
        let inbox = Arc::new(MemoryAdmissionStore::with_empty(network));
        let command = command();
        offer(network, &inbox, command).await;

        let applied = canonical
            .compare_and_set_canonical_head(command.sealed())
            .await
            .unwrap();
        assert!(matches!(applied, CanonicalHeadWriteOutcome::Applied(_)));
        assert!(inbox.current().state().pending().is_some());

        let boundary = CoordinatorRollbackAdmissionBoundary::new(
            network,
            canonical,
            inbox.clone(),
        );
        let outcome = boundary.reconcile_at_loop_boundary().await.unwrap();
        assert!(matches!(
            outcome,
            RollbackAdmissionBoundaryOutcome::Maintenance(_)
        ));
        assert!(inbox.current().state().is_empty());
    }

    #[tokio::test]
    async fn concurrent_monitors_share_one_slot_winner() {
        let network = NetworkId::from(PsyChainNetworkType::PsyMainnet);
        let inbox = Arc::new(MemoryAdmissionStore::with_empty(network));
        let expected_slot = inbox.current();
        let first = command_with_target(90, 20, 0xA5);
        let second = command_with_target(80, 40, 0xB6);
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..64 {
            let inbox = inbox.clone();
            let command = if index % 2 == 0 { first } else { second };
            let sealed = SealedRollbackAdmissionSlotCas::offer(
                network,
                expected_slot,
                command,
            )
            .unwrap();
            tasks.spawn(async move {
                inbox
                    .compare_and_set_rollback_admission_slot(&sealed)
                    .await
                    .unwrap()
            });
        }

        let mut applied = 0;
        let mut idempotent = 0;
        let mut conflict = 0;
        while let Some(outcome) = tasks.join_next().await {
            match outcome.unwrap() {
                RollbackAdmissionSlotWriteOutcome::Applied(_) => applied += 1,
                RollbackAdmissionSlotWriteOutcome::Idempotent(_) => idempotent += 1,
                RollbackAdmissionSlotWriteOutcome::Conflict { .. } => conflict += 1,
            }
        }
        assert_eq!(applied, 1);
        assert_eq!(idempotent, 31);
        assert_eq!(conflict, 32);
        assert!(inbox.current().state().pending().is_some());
    }
}
