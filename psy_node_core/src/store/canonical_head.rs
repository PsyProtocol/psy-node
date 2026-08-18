//! Driver-independent durable canonical-head contracts.
//!
//! Besides ordinary checkpoint advance and rollback admission, this module
//! permits the complete rollback control progression on the same
//! canonical-head row. Storage adapters remain responsible for proving the
//! matching archive/delete barriers before applying the destructive and final
//! transitions.

use std::{error::Error, fmt};

use async_trait::async_trait;
use parth_core::protocol::core_types::Q256BitHash;
pub use psy_data::protocol::canonical_chain::NetworkId;
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, CanonicalChainRefCodecError, ChainEpoch, CheckpointRef,
    CANONICAL_CHAIN_REF_V1_LEN,
};
use serde::{Deserialize, Serialize};

use super::rollback_control::{
    RollbackControlCodecError, RollbackControlState, RollbackRequest,
    ROLLBACK_CONTROL_V1_LEN,
};

/// Monotonic revision of one durable Coordinator canonical-head row.
///
/// The value is intentionally distinct from checkpoint, epoch, pending, and
/// ordinary integers:
///
/// ```compile_fail
/// use psy_data::protocol::canonical_chain::CheckpointId;
/// use psy_node_core::store::canonical_head::CanonicalHeadRevision;
/// let revision = CanonicalHeadRevision::try_new(7).unwrap();
/// let _: CheckpointId = revision;
/// ```
///
/// ```compile_fail
/// use psy_data::protocol::canonical_chain::ChainEpoch;
/// use psy_node_core::store::canonical_head::CanonicalHeadRevision;
/// let revision = CanonicalHeadRevision::try_new(7).unwrap();
/// let _: ChainEpoch = revision;
/// ```
///
/// ```compile_fail
/// use psy_node_core::store::{canonical_head::CanonicalHeadRevision, typed::UniquePendingId};
/// let pending = UniquePendingId::try_new(7).unwrap();
/// let _: CanonicalHeadRevision = pending;
/// ```
///
/// ```compile_fail
/// use psy_node_core::store::canonical_head::CanonicalHeadRevision;
/// let _: CanonicalHeadRevision = 7_u64;
/// ```
///
/// It has no default or unchecked public constructor:
///
/// ```compile_fail
/// use psy_node_core::store::canonical_head::CanonicalHeadRevision;
/// let _: CanonicalHeadRevision = Default::default();
/// ```
///
/// ```compile_fail
/// use psy_node_core::store::canonical_head::CanonicalHeadRevision;
/// let _ = CanonicalHeadRevision::new(7);
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalHeadRevision(u64);

impl CanonicalHeadRevision {
    pub const fn try_new(value: u64) -> Result<Self, CanonicalHeadModelError> {
        if value <= i64::MAX as u64 {
            Ok(Self(value))
        } else {
            Err(CanonicalHeadModelError::RevisionOutOfCqlRange(value))
        }
    }

    pub const fn try_from_i64(value: i64) -> Result<Self, CanonicalHeadModelError> {
        if value < 0 {
            Err(CanonicalHeadModelError::NegativeRevision(value))
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

    pub const fn checked_next(self) -> Result<Self, CanonicalHeadModelError> {
        match self.0.checked_add(1) {
            Some(next) if next <= i64::MAX as u64 => Ok(Self(next)),
            _ => Err(CanonicalHeadModelError::RevisionOverflow(self.0)),
        }
    }
}

/// One validated row decoded from the durable canonical-head table.
///
/// There is no public `new`/`from_parts`; database material must cross the
/// named [`decode_persisted`](Self::decode_persisted) trust boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredCanonicalHead<Hash> {
    revision: CanonicalHeadRevision,
    canonical_ref: CanonicalChainRef<Hash>,
    rollback_control: RollbackControlState<Hash>,
}

impl<Hash> StoredCanonicalHead<Hash> {
    pub const fn revision(&self) -> CanonicalHeadRevision {
        self.revision
    }

    pub const fn canonical_ref(&self) -> &CanonicalChainRef<Hash> {
        &self.canonical_ref
    }

    pub const fn rollback_control(&self) -> &RollbackControlState<Hash> {
        &self.rollback_control
    }
}

impl<Hash: Q256BitHash> StoredCanonicalHead<Hash> {
    /// Decode a database row and prove that its partition key agrees with the
    /// network encoded inside the single canonical payload.
    pub fn decode_persisted(
        partition_network: NetworkId,
        revision: i64,
        canonical_payload: &[u8],
        rollback_control_payload: &[u8],
    ) -> Result<Self, CanonicalHeadModelError> {
        let revision = CanonicalHeadRevision::try_from_i64(revision)?;
        let canonical_ref = CanonicalChainRef::from_canonical_bytes(canonical_payload)?;
        if canonical_ref.network_id() != partition_network {
            return Err(CanonicalHeadModelError::PartitionNetworkMismatch {
                partition: partition_network,
                payload: canonical_ref.network_id(),
            });
        }
        let rollback_control =
            RollbackControlState::from_canonical_bytes(rollback_control_payload)?;
        validate_control_against_head(&canonical_ref, &rollback_control)?;
        Ok(Self {
            revision,
            canonical_ref,
            rollback_control,
        })
    }

    pub fn canonical_ref_bytes(&self) -> [u8; CANONICAL_CHAIN_REF_V1_LEN] {
        self.canonical_ref.to_canonical_bytes()
    }

    pub fn rollback_control_bytes(&self) -> [u8; ROLLBACK_CONTROL_V1_LEN] {
        self.rollback_control.to_canonical_bytes()
    }
}

/// Explicit deployment reason for creating the one initial durable row.
///
/// The choice is made by release/operations policy; this enum does not infer a
/// profile from an empty database.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanonicalHeadBootstrapProfile {
    GenesisNative,
    PostGenesisFloor,
}

/// Validated, sealed initial write. Its revision is exactly zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalHeadBootstrap<Hash> {
    profile: CanonicalHeadBootstrapProfile,
    candidate: StoredCanonicalHead<Hash>,
    candidate_payload: [u8; CANONICAL_CHAIN_REF_V1_LEN],
    candidate_control_payload: [u8; ROLLBACK_CONTROL_V1_LEN],
}

impl<Hash: Q256BitHash> CanonicalHeadBootstrap<Hash> {
    pub fn try_new(
        profile: CanonicalHeadBootstrapProfile,
        canonical_ref: CanonicalChainRef<Hash>,
    ) -> Result<Self, CanonicalHeadModelError> {
        if canonical_ref.chain_epoch().get() != 0 {
            return Err(CanonicalHeadModelError::BootstrapEpochMustBeZero(
                canonical_ref.chain_epoch().get(),
            ));
        }
        let checkpoint_id = canonical_ref.checkpoint().checkpoint_id().get();
        match profile {
            CanonicalHeadBootstrapProfile::GenesisNative if checkpoint_id != 0 => {
                return Err(CanonicalHeadModelError::GenesisBootstrapMustUseCheckpointZero(
                    checkpoint_id,
                ));
            }
            CanonicalHeadBootstrapProfile::PostGenesisFloor if checkpoint_id == 0 => {
                return Err(CanonicalHeadModelError::PostGenesisFloorMustBePositive);
            }
            CanonicalHeadBootstrapProfile::GenesisNative
            | CanonicalHeadBootstrapProfile::PostGenesisFloor => {}
        }
        let candidate_payload = canonical_ref.to_canonical_bytes();
        let rollback_control = RollbackControlState::Idle;
        let candidate_control_payload = rollback_control.to_canonical_bytes();
        Ok(Self {
            profile,
            candidate: StoredCanonicalHead {
                revision: CanonicalHeadRevision::initial(),
                canonical_ref,
                rollback_control,
            },
            candidate_payload,
            candidate_control_payload,
        })
    }

    pub const fn profile(&self) -> CanonicalHeadBootstrapProfile {
        self.profile
    }

    pub const fn candidate(&self) -> &StoredCanonicalHead<Hash> {
        &self.candidate
    }

    pub const fn candidate_payload(&self) -> &[u8; CANONICAL_CHAIN_REF_V1_LEN] {
        &self.candidate_payload
    }

    pub const fn candidate_control_payload(&self) -> &[u8; ROLLBACK_CONTROL_V1_LEN] {
        &self.candidate_control_payload
    }

    pub fn classify_lwt_observation(
        &self,
        applied: bool,
        current: StoredCanonicalHead<Hash>,
    ) -> Result<CanonicalHeadWriteOutcome<Hash>, CanonicalHeadModelError> {
        classify_lwt_observation(applied, self.candidate, current)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CanonicalHeadTransitionKind {
    NormalCheckpointAdvance,
    StartRollback,
    BeginRollbackArchive,
    CompleteRollbackArchiveBarrier,
    BeginRollbackDelete,
    BeginRollbackRestore,
    BeginRollbackVerify,
    CompleteRollbackRealmBarrier,
    CompleteRollback,
    BeginRollbackAbort,
    CompleteRollbackAbort,
}

/// A validated transition before its canonical payloads are sealed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalHeadTransition<Hash> {
    kind: CanonicalHeadTransitionKind,
    expected: StoredCanonicalHead<Hash>,
    candidate: StoredCanonicalHead<Hash>,
}

impl<Hash: Q256BitHash> CanonicalHeadTransition<Hash> {
    /// Validate a normal one-checkpoint advance. The full proposed reference is
    /// accepted so invalid jumps/network/epoch changes are observable errors.
    pub fn normal_checkpoint_advance(
        expected: StoredCanonicalHead<Hash>,
        proposed: CanonicalChainRef<Hash>,
    ) -> Result<Self, CanonicalHeadModelError> {
        if !expected.rollback_control().is_idle() {
            return Err(CanonicalHeadModelError::NormalAdvanceWhileRollbackActive);
        }
        require_same_network(expected.canonical_ref(), &proposed)?;
        if proposed.chain_epoch() != expected.canonical_ref().chain_epoch() {
            return Err(CanonicalHeadModelError::ChainEpochChangedDuringNormalAdvance {
                expected: expected.canonical_ref().chain_epoch().get(),
                proposed: proposed.chain_epoch().get(),
            });
        }
        let old_checkpoint = expected.canonical_ref().checkpoint().checkpoint_id().get();
        let next_checkpoint = old_checkpoint
            .checked_add(1)
            .ok_or(CanonicalHeadModelError::CheckpointOverflow(old_checkpoint))?;
        if proposed.checkpoint().checkpoint_id().get() != next_checkpoint {
            return Err(CanonicalHeadModelError::CheckpointNotNext {
                expected: next_checkpoint,
                proposed: proposed.checkpoint().checkpoint_id().get(),
            });
        }
        Ok(Self {
            kind: CanonicalHeadTransitionKind::NormalCheckpointAdvance,
            expected,
            candidate: StoredCanonicalHead {
                revision: expected.revision.checked_next()?,
                canonical_ref: proposed,
                rollback_control: RollbackControlState::Idle,
            },
        })
    }

    /// Atomically open the next epoch and publish the exact rollback request.
    /// The target and plan cannot be attached in a second row after this CAS.
    pub fn start_rollback(
        expected: StoredCanonicalHead<Hash>,
        request: RollbackRequest<Hash>,
    ) -> Result<Self, CanonicalHeadModelError> {
        if !expected.rollback_control().is_idle() {
            return Err(CanonicalHeadModelError::RollbackAlreadyActive);
        }
        if request.requested_head() != expected.canonical_ref().checkpoint() {
            return Err(CanonicalHeadModelError::RollbackRequestedHeadMismatch);
        }
        let old_epoch = expected.canonical_ref().chain_epoch().get();
        let next_epoch = old_epoch
            .checked_add(1)
            .ok_or(CanonicalHeadModelError::ChainEpochOverflow(old_epoch))?;
        let proposed = CanonicalChainRef::new(
            expected.canonical_ref().network_id(),
            ChainEpoch::new(next_epoch),
            *expected.canonical_ref().checkpoint(),
        );
        Ok(Self {
            kind: CanonicalHeadTransitionKind::StartRollback,
            expected,
            candidate: StoredCanonicalHead {
                revision: expected.revision.checked_next()?,
                canonical_ref: proposed,
                rollback_control: RollbackControlState::Requested(request),
            },
        })
    }

    /// Enter the archive-copy phase without changing checkpoint, epoch, plan,
    /// or fence.  This remains pre-PONR and grants no archive or delete write
    /// capability; it only makes the durable maintenance phase explicit.
    pub fn begin_rollback_archive(
        expected: StoredCanonicalHead<Hash>,
    ) -> Result<Self, CanonicalHeadModelError> {
        let request = match expected.rollback_control() {
            RollbackControlState::Requested(request) => *request,
            RollbackControlState::Idle => {
                return Err(CanonicalHeadModelError::RollbackNotRequested);
            }
            RollbackControlState::Archiving(_)
            | RollbackControlState::ArchiveBarrierReady(_)
            | RollbackControlState::Deleting(_)
            | RollbackControlState::Restoring(_)
            | RollbackControlState::Verifying(_)
            | RollbackControlState::AllRealmsReady(_)
            | RollbackControlState::Aborting(_) => {
                return Err(CanonicalHeadModelError::RollbackArchiveAlreadyStarted);
            }
        };
        Ok(Self {
            kind: CanonicalHeadTransitionKind::BeginRollbackArchive,
            expected,
            candidate: StoredCanonicalHead {
                revision: expected.revision.checked_next()?,
                canonical_ref: *expected.canonical_ref(),
                rollback_control: RollbackControlState::Archiving(request),
            },
        })
    }

    /// Publish the all-participant archive barrier on the canonical-head row.
    ///
    /// Takes the sealed barrier by value, so the phase that precedes the point
    /// of no return cannot be entered without evidence that every participant
    /// archived the requested range.  This used to be a comment asking the
    /// storage adapter to check first, which is the kind of requirement that
    /// holds until someone adds a second caller: nothing stopped a Coordinator
    /// from crossing while a Realm had archived nothing, and §0.2 D2 makes
    /// archiving a precondition rather than a backup.
    ///
    /// The barrier must describe this rollback.  A barrier sealed for another
    /// range is evidence about something else.
    pub fn complete_rollback_archive_barrier(
        expected: StoredCanonicalHead<Hash>,
        barrier: super::rollback_participants::SealedArchiveBarrier,
    ) -> Result<Self, CanonicalHeadModelError> {
        let request = match expected.rollback_control() {
            RollbackControlState::Archiving(request) => *request,
            _ => return Err(CanonicalHeadModelError::RollbackArchiveNotActive),
        };
        if barrier.target() != request.target().checkpoint_id().get()
            || barrier.head() != request.requested_head().checkpoint_id().get()
        {
            return Err(CanonicalHeadModelError::ArchiveBarrierRangeMismatch {
                barrier: (barrier.target(), barrier.head()),
                request: (
                    request.target().checkpoint_id().get(),
                    request.requested_head().checkpoint_id().get(),
                ),
            });
        }
        Ok(Self {
            kind: CanonicalHeadTransitionKind::CompleteRollbackArchiveBarrier,
            expected,
            candidate: StoredCanonicalHead {
                revision: expected.revision.checked_next()?,
                canonical_ref: *expected.canonical_ref(),
                rollback_control: RollbackControlState::ArchiveBarrierReady(request),
            },
        })
    }

    /// Cross the rollback point of no return after the durable global archive
    /// barrier has been selected.  No checkpoint changes at this step.
    pub fn begin_rollback_delete(
        expected: StoredCanonicalHead<Hash>,
    ) -> Result<Self, CanonicalHeadModelError> {
        let request = match expected.rollback_control() {
            RollbackControlState::ArchiveBarrierReady(request) => *request,
            _ => return Err(CanonicalHeadModelError::RollbackArchiveBarrierNotReady),
        };
        Ok(Self {
            kind: CanonicalHeadTransitionKind::BeginRollbackDelete,
            expected,
            candidate: StoredCanonicalHead {
                revision: expected.revision.checked_next()?,
                canonical_ref: *expected.canonical_ref(),
                rollback_control: RollbackControlState::Deleting(request),
            },
        })
    }

    /// Enter target restoration only after storage has selected the durable
    /// all-participant delete-completion barrier.
    pub fn begin_rollback_restore(
        expected: StoredCanonicalHead<Hash>,
    ) -> Result<Self, CanonicalHeadModelError> {
        let request = match expected.rollback_control() {
            RollbackControlState::Deleting(request) => *request,
            _ => return Err(CanonicalHeadModelError::RollbackDeleteNotActive),
        };
        Ok(Self {
            kind: CanonicalHeadTransitionKind::BeginRollbackRestore,
            expected,
            candidate: StoredCanonicalHead {
                revision: expected.revision.checked_next()?,
                canonical_ref: *expected.canonical_ref(),
                rollback_control: RollbackControlState::Restoring(request),
            },
        })
    }

    /// Freeze target mutations and enter the exact verification phase.
    pub fn begin_rollback_verify(
        expected: StoredCanonicalHead<Hash>,
    ) -> Result<Self, CanonicalHeadModelError> {
        let request = match expected.rollback_control() {
            RollbackControlState::Restoring(request) => *request,
            _ => return Err(CanonicalHeadModelError::RollbackRestoreNotActive),
        };
        Ok(Self {
            kind: CanonicalHeadTransitionKind::BeginRollbackVerify,
            expected,
            candidate: StoredCanonicalHead {
                revision: expected.revision.checked_next()?,
                canonical_ref: *expected.canonical_ref(),
                rollback_control: RollbackControlState::Verifying(request),
            },
        })
    }

    /// Record that Coordinator and every fixed Realm participant are ready.
    /// The checkpoint remains unpublished until the final, separately fenced
    /// transition.
    pub fn complete_rollback_realm_barrier(
        expected: StoredCanonicalHead<Hash>,
    ) -> Result<Self, CanonicalHeadModelError> {
        let request = match expected.rollback_control() {
            RollbackControlState::Verifying(request) => *request,
            _ => return Err(CanonicalHeadModelError::RollbackVerifyNotActive),
        };
        Ok(Self {
            kind: CanonicalHeadTransitionKind::CompleteRollbackRealmBarrier,
            expected,
            candidate: StoredCanonicalHead {
                revision: expected.revision.checked_next()?,
                canonical_ref: *expected.canonical_ref(),
                rollback_control: RollbackControlState::AllRealmsReady(request),
            },
        })
    }

    /// Publish the request's exact target and return rollback control to IDLE.
    ///
    /// This transition is valid only from `ALL_REALMS_READY`. The storage
    /// owner must additionally prove the durable all-participant restore and
    /// runtime-rebuild barriers before applying the sealed CAS. The already
    /// opened rollback epoch is preserved, so the restored checkpoint cannot
    /// be confused with the abandoned branch at the same height.
    pub fn complete_rollback(
        expected: StoredCanonicalHead<Hash>,
    ) -> Result<Self, CanonicalHeadModelError> {
        let request = match expected.rollback_control() {
            RollbackControlState::AllRealmsReady(request) => *request,
            _ => return Err(CanonicalHeadModelError::RollbackRealmsNotReady),
        };
        let restored = CanonicalChainRef::new(
            expected.canonical_ref().network_id(),
            expected.canonical_ref().chain_epoch(),
            *request.target(),
        );
        Ok(Self {
            kind: CanonicalHeadTransitionKind::CompleteRollback,
            expected,
            candidate: StoredCanonicalHead {
                revision: expected.revision.checked_next()?,
                canonical_ref: restored,
                rollback_control: RollbackControlState::Idle,
            },
        })
    }

    /// Enter the durable pre-PONR abort phase without changing the opened
    /// epoch or the still-published old checkpoint.
    pub fn begin_rollback_abort(
        expected: StoredCanonicalHead<Hash>,
        reason_code: super::rollback_control::RollbackAbortReasonCode,
    ) -> Result<Self, CanonicalHeadModelError> {
        let request = match expected.rollback_control() {
            RollbackControlState::Requested(request)
            | RollbackControlState::Archiving(request)
            | RollbackControlState::ArchiveBarrierReady(request) => *request,
            RollbackControlState::Deleting(_)
            | RollbackControlState::Restoring(_)
            | RollbackControlState::Verifying(_)
            | RollbackControlState::AllRealmsReady(_) => {
                return Err(CanonicalHeadModelError::RollbackPointOfNoReturn);
            }
            RollbackControlState::Aborting(_) => {
                return Err(CanonicalHeadModelError::RollbackAbortAlreadyStarted);
            }
            RollbackControlState::Idle => {
                return Err(CanonicalHeadModelError::RollbackNotActiveForAbort);
            }
        };
        Ok(Self {
            kind: CanonicalHeadTransitionKind::BeginRollbackAbort,
            expected,
            candidate: StoredCanonicalHead {
                revision: expected.revision.checked_next()?,
                canonical_ref: *expected.canonical_ref(),
                rollback_control: RollbackControlState::Aborting(
                    super::rollback_control::RollbackAbort::new(request, reason_code),
                ),
            },
        })
    }

    /// Return to IDLE only after Coordinator and every Realm have rotated
    /// away from the aborted request's pending/proc contexts.
    ///
    /// No destructive work is allowed before this transition, so abort also
    /// closes the provisional rollback epoch and restores the exact source
    /// epoch. Keeping the provisional epoch would make a later rollback scan
    /// look for the unchanged hot history in the wrong epoch partition.
    pub fn complete_rollback_abort(
        expected: StoredCanonicalHead<Hash>,
    ) -> Result<Self, CanonicalHeadModelError> {
        if !matches!(expected.rollback_control(), RollbackControlState::Aborting(_)) {
            return Err(CanonicalHeadModelError::RollbackAbortNotActive);
        }
        let opened_epoch = expected.canonical_ref().chain_epoch().get();
        let source_epoch = opened_epoch
            .checked_sub(1)
            .ok_or(CanonicalHeadModelError::RollbackAbortEpochUnderflow)?;
        let restored = CanonicalChainRef::new(
            expected.canonical_ref().network_id(),
            ChainEpoch::new(source_epoch),
            *expected.canonical_ref().checkpoint(),
        );
        Ok(Self {
            kind: CanonicalHeadTransitionKind::CompleteRollbackAbort,
            expected,
            candidate: StoredCanonicalHead {
                revision: expected.revision.checked_next()?,
                canonical_ref: restored,
                rollback_control: RollbackControlState::Idle,
            },
        })
    }

    pub const fn kind(&self) -> CanonicalHeadTransitionKind {
        self.kind
    }

    pub const fn expected(&self) -> &StoredCanonicalHead<Hash> {
        &self.expected
    }

    pub const fn candidate(&self) -> &StoredCanonicalHead<Hash> {
        &self.candidate
    }

    pub fn seal(self) -> SealedCanonicalHeadCas<Hash> {
        let expected_payload = self.expected.canonical_ref_bytes();
        let candidate_payload = self.candidate.canonical_ref_bytes();
        let expected_control_payload = self.expected.rollback_control_bytes();
        let candidate_control_payload = self.candidate.rollback_control_bytes();
        SealedCanonicalHeadCas {
            transition: self,
            expected_payload,
            candidate_payload,
            expected_control_payload,
            candidate_control_payload,
        }
    }
}

/// Immutable expected/candidate pair accepted by the Scylla CAS adapter.
///
/// No public arbitrary constructor exists:
///
/// ```compile_fail
/// use psy_node_core::store::canonical_head::SealedCanonicalHeadCas;
/// let _ = SealedCanonicalHeadCas::<parth_core::PHash>::new();
/// ```
///
/// ```compile_fail
/// use psy_node_core::store::canonical_head::SealedCanonicalHeadCas;
/// let _ = SealedCanonicalHeadCas::<parth_core::PHash> {
///     transition: unsafe { std::mem::zeroed() },
///     expected_payload: [0; 65],
///     candidate_payload: [0; 65],
/// };
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedCanonicalHeadCas<Hash> {
    transition: CanonicalHeadTransition<Hash>,
    expected_payload: [u8; CANONICAL_CHAIN_REF_V1_LEN],
    candidate_payload: [u8; CANONICAL_CHAIN_REF_V1_LEN],
    expected_control_payload: [u8; ROLLBACK_CONTROL_V1_LEN],
    candidate_control_payload: [u8; ROLLBACK_CONTROL_V1_LEN],
}

impl<Hash: Q256BitHash> SealedCanonicalHeadCas<Hash> {
    pub const fn kind(&self) -> CanonicalHeadTransitionKind {
        self.transition.kind
    }

    pub const fn expected(&self) -> &StoredCanonicalHead<Hash> {
        &self.transition.expected
    }

    pub const fn candidate(&self) -> &StoredCanonicalHead<Hash> {
        &self.transition.candidate
    }

    pub const fn expected_payload(&self) -> &[u8; CANONICAL_CHAIN_REF_V1_LEN] {
        &self.expected_payload
    }

    pub const fn candidate_payload(&self) -> &[u8; CANONICAL_CHAIN_REF_V1_LEN] {
        &self.candidate_payload
    }

    pub const fn expected_control_payload(&self) -> &[u8; ROLLBACK_CONTROL_V1_LEN] {
        &self.expected_control_payload
    }

    pub const fn candidate_control_payload(&self) -> &[u8; ROLLBACK_CONTROL_V1_LEN] {
        &self.candidate_control_payload
    }

    pub fn classify_lwt_observation(
        &self,
        applied: bool,
        current: StoredCanonicalHead<Hash>,
    ) -> Result<CanonicalHeadWriteOutcome<Hash>, CanonicalHeadModelError> {
        classify_lwt_observation(applied, self.transition.candidate, current)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalHeadReadState<Hash> {
    Uninitialized,
    Current(StoredCanonicalHead<Hash>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalHeadWriteOutcome<Hash> {
    Applied(StoredCanonicalHead<Hash>),
    Idempotent(StoredCanonicalHead<Hash>),
    Conflict { current: StoredCanonicalHead<Hash> },
}

impl<Hash> CanonicalHeadWriteOutcome<Hash> {
    pub const fn current(&self) -> &StoredCanonicalHead<Hash> {
        match self {
            Self::Applied(current) | Self::Idempotent(current) | Self::Conflict { current } => current,
        }
    }

    pub const fn was_applied(&self) -> bool {
        matches!(self, Self::Applied(_))
    }

    pub const fn was_idempotent(&self) -> bool {
        matches!(self, Self::Idempotent(_))
    }
}

/// Driver-independent read boundary for the one Coordinator canonical-head
/// row. Edge/API code depends only on this capability.
#[async_trait]
pub trait CoordinatorCanonicalHeadReader<Hash: Q256BitHash>: Send + Sync {
    async fn read_canonical_head(
        &self,
        network: NetworkId,
    ) -> anyhow::Result<CanonicalHeadReadState<Hash>>;
}

/// Full Coordinator authority boundary. Implementations must preserve the
/// exact LWT semantics modeled by [`CanonicalHeadBootstrap`] and
/// [`SealedCanonicalHeadCas`].
#[async_trait]
/// Publishing a head and recording a commit source are separate capabilities.
/// The spike bundled them because one Scylla type happened to implement both;
/// a caller that needs both now takes both, so neither can drag the other in.
pub trait CoordinatorCanonicalHeadStore<Hash: Q256BitHash>:
    CoordinatorCanonicalHeadReader<Hash>
{
    async fn bootstrap_canonical_head(
        &self,
        bootstrap: &CanonicalHeadBootstrap<Hash>,
    ) -> anyhow::Result<CanonicalHeadWriteOutcome<Hash>>;

    async fn compare_and_set_canonical_head(
        &self,
        sealed: &SealedCanonicalHeadCas<Hash>,
    ) -> anyhow::Result<CanonicalHeadWriteOutcome<Hash>>;
}

/// Exhaustive startup decision. It never invents a durable head and only
/// permits reconciliation of a fully materialized checkpoint that is equal to
/// or exactly one checkpoint ahead of the durable publish marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalHeadStartupPlan<Hash> {
    /// A fresh database has not materialized genesis yet. Keep this exact
    /// bootstrap sealed until genesis state and its backup are durable.
    AwaitGenesis(CanonicalHeadBootstrap<Hash>),
    /// Materialized state exists but the durable row does not. This is allowed
    /// only under an explicit deployment bootstrap profile.
    Bootstrap(CanonicalHeadBootstrap<Hash>),
    /// Durable head and materialized state already agree.
    Current(StoredCanonicalHead<Hash>),
    /// Materialized state is exactly one checkpoint ahead because the process
    /// crashed before the final head publish.
    PublishMaterialized(SealedCanonicalHeadCas<Hash>),
}

/// Decide how startup reconciles the durable canonical head with the already
/// validated materialized checkpoint/proof state.
///
/// `genesis_pending` must only be true for an actually empty database. A
/// missing row never implies genesis and a profile is always explicit.
pub fn plan_canonical_head_startup<Hash: Q256BitHash>(
    network: NetworkId,
    bootstrap_profile: Option<CanonicalHeadBootstrapProfile>,
    durable: CanonicalHeadReadState<Hash>,
    materialized_checkpoint: CheckpointRef<Hash>,
    genesis_pending: bool,
) -> Result<CanonicalHeadStartupPlan<Hash>, CanonicalHeadModelError> {
    let materialized_checkpoint_id = materialized_checkpoint.checkpoint_id().get();
    match durable {
        CanonicalHeadReadState::Uninitialized => {
            if genesis_pending && materialized_checkpoint_id != 0 {
                return Err(CanonicalHeadModelError::GenesisPendingAtNonZeroCheckpoint(
                    materialized_checkpoint_id,
                ));
            }
            let profile = bootstrap_profile
                .ok_or(CanonicalHeadModelError::BootstrapProfileRequired)?;
            let bootstrap = CanonicalHeadBootstrap::try_new(
                profile,
                CanonicalChainRef::new(network, ChainEpoch::new(0), materialized_checkpoint),
            )?;
            if genesis_pending {
                Ok(CanonicalHeadStartupPlan::AwaitGenesis(bootstrap))
            } else {
                Ok(CanonicalHeadStartupPlan::Bootstrap(bootstrap))
            }
        }
        CanonicalHeadReadState::Current(current) => {
            if genesis_pending {
                return Err(CanonicalHeadModelError::DurableHeadBeforeGenesisMaterialized);
            }
            if current.canonical_ref().network_id() != network {
                return Err(CanonicalHeadModelError::NetworkChanged {
                    expected: network,
                    proposed: current.canonical_ref().network_id(),
                });
            }

            let durable_checkpoint = current
                .canonical_ref()
                .checkpoint()
                .checkpoint_id()
                .get();
            if materialized_checkpoint_id == durable_checkpoint {
                if current.canonical_ref().checkpoint() != &materialized_checkpoint {
                    return Err(CanonicalHeadModelError::MaterializedCheckpointConflict {
                        checkpoint_id: durable_checkpoint,
                    });
                }
                return Ok(CanonicalHeadStartupPlan::Current(current));
            }

            if durable_checkpoint.checked_add(1) == Some(materialized_checkpoint_id) {
                let proposed = CanonicalChainRef::new(
                    network,
                    current.canonical_ref().chain_epoch(),
                    materialized_checkpoint,
                );
                return Ok(CanonicalHeadStartupPlan::PublishMaterialized(
                    CanonicalHeadTransition::normal_checkpoint_advance(current, proposed)?.seal(),
                ));
            }

            Err(CanonicalHeadModelError::MaterializedCheckpointNotCurrentOrNext {
                durable: durable_checkpoint,
                materialized: materialized_checkpoint_id,
            })
        }
    }
}

fn require_same_network<Hash>(
    expected: &CanonicalChainRef<Hash>,
    proposed: &CanonicalChainRef<Hash>,
) -> Result<(), CanonicalHeadModelError> {
    if expected.network_id() != proposed.network_id() {
        Err(CanonicalHeadModelError::NetworkChanged {
            expected: expected.network_id(),
            proposed: proposed.network_id(),
        })
    } else {
        Ok(())
    }
}

fn validate_control_against_head<Hash: PartialEq>(
    canonical_ref: &CanonicalChainRef<Hash>,
    control: &RollbackControlState<Hash>,
) -> Result<(), CanonicalHeadModelError> {
    if let Some(request) = control.requested() {
        if canonical_ref.chain_epoch().get() == 0 {
            return Err(CanonicalHeadModelError::RequestedControlAtEpochZero);
        }
        if request.requested_head() != canonical_ref.checkpoint() {
            return Err(CanonicalHeadModelError::RollbackRequestedHeadMismatch);
        }
    }
    Ok(())
}

fn classify_lwt_observation<Hash: Copy + PartialEq>(
    applied: bool,
    candidate: StoredCanonicalHead<Hash>,
    current: StoredCanonicalHead<Hash>,
) -> Result<CanonicalHeadWriteOutcome<Hash>, CanonicalHeadModelError> {
    if current == candidate {
        return Ok(if applied {
            CanonicalHeadWriteOutcome::Applied(current)
        } else {
            CanonicalHeadWriteOutcome::Idempotent(current)
        });
    }
    if applied {
        Err(CanonicalHeadModelError::AppliedStateMismatch)
    } else {
        Ok(CanonicalHeadWriteOutcome::Conflict { current })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalHeadModelError {
    /// The sealed archive barrier describes a different range than this
    /// rollback requested, so it is evidence about something else.
    ArchiveBarrierRangeMismatch {
        barrier: (u64, u64),
        request: (u64, u64),
    },
    RevisionOutOfCqlRange(u64),
    NegativeRevision(i64),
    RevisionOverflow(u64),
    Codec(CanonicalChainRefCodecError),
    RollbackControlCodec(RollbackControlCodecError),
    PartitionNetworkMismatch { partition: NetworkId, payload: NetworkId },
    BootstrapEpochMustBeZero(u64),
    GenesisBootstrapMustUseCheckpointZero(u64),
    PostGenesisFloorMustBePositive,
    NetworkChanged { expected: NetworkId, proposed: NetworkId },
    ChainEpochChangedDuringNormalAdvance { expected: u64, proposed: u64 },
    CheckpointNotNext { expected: u64, proposed: u64 },
    CheckpointOverflow(u64),
    ChainEpochOverflow(u64),
    NormalAdvanceWhileRollbackActive,
    RollbackAlreadyActive,
    RollbackNotRequested,
    RollbackArchiveAlreadyStarted,
    RollbackArchiveNotActive,
    RollbackArchiveBarrierNotReady,
    RollbackDeleteNotActive,
    RollbackRestoreNotActive,
    RollbackVerifyNotActive,
    RollbackRealmsNotReady,
    RollbackNotActiveForAbort,
    RollbackAbortAlreadyStarted,
    RollbackAbortNotActive,
    RollbackAbortEpochUnderflow,
    RollbackPointOfNoReturn,
    RollbackRequestedHeadMismatch,
    RequestedControlAtEpochZero,
    AppliedStateMismatch,
    BootstrapProfileRequired,
    GenesisPendingAtNonZeroCheckpoint(u64),
    DurableHeadBeforeGenesisMaterialized,
    MaterializedCheckpointConflict { checkpoint_id: u64 },
    MaterializedCheckpointNotCurrentOrNext { durable: u64, materialized: u64 },
}

impl fmt::Display for CanonicalHeadModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArchiveBarrierRangeMismatch { barrier, request } => write!(
                formatter,
                "the sealed archive barrier covers ({}, {}] but this rollback discards \
                 ({}, {}]; crossing the point of no return needs evidence about this range",
                barrier.0, barrier.1, request.0, request.1
            ),
            Self::RevisionOutOfCqlRange(value) => {
                write!(formatter, "canonical-head revision {value} exceeds CQL BIGINT")
            }
            Self::NegativeRevision(value) => {
                write!(formatter, "canonical-head revision cannot be negative: {value}")
            }
            Self::RevisionOverflow(value) => {
                write!(formatter, "canonical-head revision has no successor: {value}")
            }
            Self::Codec(error) => error.fmt(formatter),
            Self::RollbackControlCodec(error) => error.fmt(formatter),
            Self::PartitionNetworkMismatch { partition, payload } => write!(
                formatter,
                "canonical-head partition network {:?} does not match payload network {:?}",
                partition, payload
            ),
            Self::BootstrapEpochMustBeZero(epoch) => {
                write!(formatter, "canonical-head bootstrap epoch must be zero, got {epoch}")
            }
            Self::GenesisBootstrapMustUseCheckpointZero(checkpoint) => write!(
                formatter,
                "GENESIS_NATIVE bootstrap must use checkpoint zero, got {checkpoint}"
            ),
            Self::PostGenesisFloorMustBePositive => {
                formatter.write_str("POST_GENESIS_FLOOR bootstrap checkpoint must be positive")
            }
            Self::NetworkChanged { expected, proposed } => write!(
                formatter,
                "canonical-head transition cannot change network {:?} to {:?}",
                expected, proposed
            ),
            Self::ChainEpochChangedDuringNormalAdvance { expected, proposed } => write!(
                formatter,
                "normal checkpoint advance must keep epoch {expected}, got {proposed}"
            ),
            Self::CheckpointNotNext { expected, proposed } => write!(
                formatter,
                "normal checkpoint advance requires checkpoint {expected}, got {proposed}"
            ),
            Self::CheckpointOverflow(checkpoint) => {
                write!(formatter, "checkpoint {checkpoint} has no successor")
            }
            Self::ChainEpochOverflow(epoch) => write!(formatter, "chain epoch {epoch} has no successor"),
            Self::NormalAdvanceWhileRollbackActive => formatter.write_str(
                "normal checkpoint advance is forbidden while rollback control is active",
            ),
            Self::RollbackAlreadyActive => {
                formatter.write_str("rollback admission requires idle canonical control")
            }
            Self::RollbackNotRequested => formatter.write_str(
                "rollback archive cannot begin before an explicit rollback request",
            ),
            Self::RollbackArchiveAlreadyStarted => formatter.write_str(
                "rollback archive can begin only from the exact REQUESTED phase",
            ),
            Self::RollbackArchiveNotActive => formatter.write_str(
                "rollback archive barrier can complete only from the exact ARCHIVING phase",
            ),
            Self::RollbackArchiveBarrierNotReady => formatter.write_str(
                "rollback deletion can begin only from the exact ARCHIVE_BARRIER_READY phase",
            ),
            Self::RollbackDeleteNotActive => formatter.write_str(
                "rollback restoration can begin only from the exact DELETING phase",
            ),
            Self::RollbackRestoreNotActive => formatter.write_str(
                "rollback verification can begin only from the exact RESTORING phase",
            ),
            Self::RollbackVerifyNotActive => formatter.write_str(
                "rollback Realm barrier can complete only from the exact VERIFYING phase",
            ),
            Self::RollbackRealmsNotReady => formatter.write_str(
                "rollback target can be published only from the exact ALL_REALMS_READY phase",
            ),
            Self::RollbackNotActiveForAbort => formatter.write_str(
                "rollback abort requires an active pre-PONR rollback",
            ),
            Self::RollbackAbortAlreadyStarted => {
                formatter.write_str("rollback abort is already active")
            }
            Self::RollbackAbortNotActive => formatter.write_str(
                "rollback abort completion requires the exact ABORTING phase",
            ),
            Self::RollbackAbortEpochUnderflow => formatter.write_str(
                "rollback abort completion requires an opened non-zero epoch",
            ),
            Self::RollbackPointOfNoReturn => formatter.write_str(
                "ROLLBACK_POINT_OF_NO_RETURN: destructive rollback work has started",
            ),
            Self::RollbackRequestedHeadMismatch => formatter.write_str(
                "rollback request head must equal the exact current canonical checkpoint",
            ),
            Self::RequestedControlAtEpochZero => {
                formatter.write_str("REQUESTED rollback control requires an opened non-zero epoch")
            }
            Self::AppliedStateMismatch => formatter.write_str(
                "LWT reported applied but durable canonical head is not the sealed candidate",
            ),
            Self::BootstrapProfileRequired => formatter.write_str(
                "canonical-head row is uninitialized and no explicit bootstrap profile was configured",
            ),
            Self::GenesisPendingAtNonZeroCheckpoint(checkpoint) => write!(
                formatter,
                "genesis cannot be pending while materialized checkpoint is {checkpoint}"
            ),
            Self::DurableHeadBeforeGenesisMaterialized => formatter.write_str(
                "durable canonical head exists before genesis state is materialized",
            ),
            Self::MaterializedCheckpointConflict { checkpoint_id } => write!(
                formatter,
                "materialized checkpoint {checkpoint_id} has a different hash from the durable canonical head"
            ),
            Self::MaterializedCheckpointNotCurrentOrNext { durable, materialized } => write!(
                formatter,
                "materialized checkpoint {materialized} must equal durable checkpoint {durable} or be its exact successor"
            ),
        }
    }
}

impl Error for CanonicalHeadModelError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            Self::RollbackControlCodec(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CanonicalChainRefCodecError> for CanonicalHeadModelError {
    fn from(value: CanonicalChainRefCodecError) -> Self {
        Self::Codec(value)
    }
}

impl From<RollbackControlCodecError> for CanonicalHeadModelError {
    fn from(value: RollbackControlCodecError) -> Self {
        Self::RollbackControlCodec(value)
    }
}

#[cfg(test)]
mod tests {
    /// A sealed barrier for the request a head is carrying.
    ///
    /// These tests exercise phase ordering, not participant aggregation, so the
    /// set is the Coordinator alone -- which is still a real barrier: it files
    /// its own receipt for the requested range and the seal succeeds.
    fn barrier_for<Hash: super::Q256BitHash>(
        head: &super::StoredCanonicalHead<Hash>,
    ) -> crate::store::rollback_participants::SealedArchiveBarrier {
        use crate::store::rollback_participants::{
            ArchiveBarrier, ArchiveReceipt, RollbackParticipant, RollbackParticipantSet,
        };
        let request = head
            .rollback_control()
            .requested()
            .expect("a barrier is only sealed while a rollback is active");
        let target = request.target().checkpoint_id().get();
        let requested_head = request.requested_head().checkpoint_id().get();
        let coordinator = RollbackParticipant::new(
            psy_data::protocol::chain_context::AuthorityScope::Coordinator,
        );
        let set = RollbackParticipantSet::try_new([coordinator]).expect("valid set");
        let mut barrier = ArchiveBarrier::new(set, target, requested_head);
        barrier
            .file(ArchiveReceipt::new(coordinator, target, requested_head, 1, [1u8; 32]))
            .expect("valid receipt");
        barrier.seal().expect("met")
    }
    use super::*;
    use parth_core::PHash;
    use psy_core::constants::chain_id::PsyChainNetworkType;
    use psy_data::protocol::canonical_chain::{
        ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
    };
    use crate::store::{
        rollback_control::{
            RollbackAbortReasonCode, RollbackExecutionMode, RollbackPlanDigest,
            RollbackRequest,
        },
        timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
    };

    fn canonical_ref(network: PsyChainNetworkType, epoch: u64, checkpoint: u64, hash: u64) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            NetworkId::from(network),
            ChainEpoch::new(epoch),
            CheckpointRef::new(
                CheckpointId::new(checkpoint),
                CheckpointHash::from_last_chain_hash(PHash::from_values(hash, hash + 1, hash + 2, hash + 3)),
            ),
        )
    }

    fn genesis() -> CanonicalHeadBootstrap<PHash> {
        CanonicalHeadBootstrap::try_new(
            CanonicalHeadBootstrapProfile::GenesisNative,
            canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 0, 1),
        )
        .unwrap()
    }

    fn idle_control_bytes() -> [u8; ROLLBACK_CONTROL_V1_LEN] {
        RollbackControlState::<PHash>::Idle.to_canonical_bytes()
    }

    fn rollback_request(
        requested_head: CheckpointRef<PHash>,
        target: CheckpointRef<PHash>,
    ) -> RollbackRequest<PHash> {
        RollbackRequest::try_new(
            requested_head,
            target,
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(100).unwrap(),
                101,
                102,
            )
            .unwrap(),
            RollbackExecutionMode::InPlace,
            RollbackPlanDigest::try_new([7; 32]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn revision_range_and_overflow_fail_closed() {
        assert_eq!(CanonicalHeadRevision::try_new(i64::MAX as u64).unwrap().as_i64(), i64::MAX);
        assert_eq!(
            CanonicalHeadRevision::try_new(i64::MAX as u64 + 1),
            Err(CanonicalHeadModelError::RevisionOutOfCqlRange(i64::MAX as u64 + 1))
        );
        assert_eq!(
            CanonicalHeadRevision::try_from_i64(-1),
            Err(CanonicalHeadModelError::NegativeRevision(-1))
        );
        assert_eq!(
            CanonicalHeadRevision::try_new(i64::MAX as u64).unwrap().checked_next(),
            Err(CanonicalHeadModelError::RevisionOverflow(i64::MAX as u64))
        );
    }

    #[test]
    fn persisted_round_trip_uses_the_existing_canonical_codec() {
        let bootstrap = genesis();
        let candidate = bootstrap.candidate();
        let decoded = StoredCanonicalHead::decode_persisted(
            candidate.canonical_ref().network_id(),
            candidate.revision().as_i64(),
            bootstrap.candidate_payload(),
            bootstrap.candidate_control_payload(),
        )
        .unwrap();
        assert_eq!(&decoded, candidate);
        assert_eq!(candidate.canonical_ref_bytes(), candidate.canonical_ref().to_canonical_bytes());
    }

    #[test]
    fn persisted_decode_rejects_partition_and_codec_mismatches() {
        let encoded = genesis().candidate_payload;
        assert!(matches!(
            StoredCanonicalHead::<PHash>::decode_persisted(
                NetworkId::from(PsyChainNetworkType::PsyPublicTestnet),
                0,
                &encoded,
                &idle_control_bytes(),
            ),
            Err(CanonicalHeadModelError::PartitionNetworkMismatch { .. })
        ));
        for cut in 0..CANONICAL_CHAIN_REF_V1_LEN {
            assert!(StoredCanonicalHead::<PHash>::decode_persisted(
                NetworkId::from(PsyChainNetworkType::PsyMainnet),
                0,
                &encoded[..cut],
                &idle_control_bytes(),
            )
            .is_err());
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(StoredCanonicalHead::<PHash>::decode_persisted(
            NetworkId::from(PsyChainNetworkType::PsyMainnet),
            0,
            &trailing,
            &idle_control_bytes(),
        )
        .is_err());
        let mut unknown_version = encoded;
        unknown_version[8..10].copy_from_slice(&2_u16.to_le_bytes());
        assert!(matches!(
            StoredCanonicalHead::<PHash>::decode_persisted(
                NetworkId::from(PsyChainNetworkType::PsyMainnet),
                0,
                &unknown_version,
                &idle_control_bytes(),
            ),
            Err(CanonicalHeadModelError::Codec(
                CanonicalChainRefCodecError::UnsupportedVersion(2)
            ))
        ));
        let mut invalid_magic = encoded;
        invalid_magic[0] ^= 1;
        assert!(matches!(
            StoredCanonicalHead::<PHash>::decode_persisted(
                NetworkId::from(PsyChainNetworkType::PsyMainnet),
                0,
                &invalid_magic,
                &idle_control_bytes(),
            ),
            Err(CanonicalHeadModelError::Codec(
                CanonicalChainRefCodecError::InvalidMagic
            ))
        ));
    }

    #[test]
    fn bootstrap_profile_is_explicit_and_validated() {
        assert!(CanonicalHeadBootstrap::try_new(
            CanonicalHeadBootstrapProfile::GenesisNative,
            canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 9, 1),
        )
        .is_err());
        assert!(CanonicalHeadBootstrap::try_new(
            CanonicalHeadBootstrapProfile::PostGenesisFloor,
            canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 0, 1),
        )
        .is_err());
        assert!(CanonicalHeadBootstrap::try_new(
            CanonicalHeadBootstrapProfile::PostGenesisFloor,
            canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 9, 1),
        )
        .is_ok());
        assert!(CanonicalHeadBootstrap::try_new(
            CanonicalHeadBootstrapProfile::GenesisNative,
            canonical_ref(PsyChainNetworkType::PsyMainnet, 1, 0, 1),
        )
        .is_err());
    }

    #[test]
    fn normal_advance_validates_every_non_hash_field() {
        let expected = *genesis().candidate();
        let valid = canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 1, 10);
        let transition = CanonicalHeadTransition::normal_checkpoint_advance(expected, valid).unwrap();
        assert_eq!(transition.kind(), CanonicalHeadTransitionKind::NormalCheckpointAdvance);
        assert_eq!(transition.candidate().revision().get(), 1);
        assert_eq!(transition.candidate().canonical_ref().network_id(), expected.canonical_ref().network_id());
        assert_eq!(transition.candidate().canonical_ref().chain_epoch(), expected.canonical_ref().chain_epoch());

        for proposed in [
            canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 0, 10),
            canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 2, 10),
            canonical_ref(PsyChainNetworkType::PsyMainnet, 1, 1, 10),
            canonical_ref(PsyChainNetworkType::PsyPublicTestnet, 0, 1, 10),
        ] {
            assert!(CanonicalHeadTransition::normal_checkpoint_advance(expected, proposed).is_err());
        }

        let later = stored_for_test(canonical_ref(
            PsyChainNetworkType::PsyMainnet,
            5,
            10,
            30,
        ));
        assert!(CanonicalHeadTransition::normal_checkpoint_advance(
            later,
            canonical_ref(PsyChainNetworkType::PsyMainnet, 5, 9, 40),
        )
        .is_err());
    }

    #[test]
    fn rollback_admission_opens_epoch_and_attaches_exact_request() {
        let head = canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 10, 50);
        let expected = stored_for_test(head);
        let target = *canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 7, 40).checkpoint();
        let request = rollback_request(*head.checkpoint(), target);
        let transition = CanonicalHeadTransition::start_rollback(expected, request).unwrap();
        assert_eq!(transition.kind(), CanonicalHeadTransitionKind::StartRollback);
        assert_eq!(transition.candidate().revision().get(), 1);
        assert_eq!(transition.candidate().canonical_ref().chain_epoch().get(), 1);
        assert_eq!(transition.candidate().canonical_ref().checkpoint(), expected.canonical_ref().checkpoint());
        assert_eq!(transition.candidate().rollback_control().requested(), Some(&request));

        let wrong_head = *canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 9, 49).checkpoint();
        assert_eq!(
            CanonicalHeadTransition::start_rollback(
                expected,
                rollback_request(wrong_head, target),
            ),
            Err(CanonicalHeadModelError::RollbackRequestedHeadMismatch)
        );
        assert_eq!(
            CanonicalHeadTransition::normal_checkpoint_advance(
                *transition.candidate(),
                canonical_ref(PsyChainNetworkType::PsyMainnet, 1, 11, 60),
            ),
            Err(CanonicalHeadModelError::NormalAdvanceWhileRollbackActive)
        );
        assert_eq!(
            CanonicalHeadTransition::start_rollback(*transition.candidate(), request),
            Err(CanonicalHeadModelError::RollbackAlreadyActive)
        );

        let requested_bytes = transition.candidate().rollback_control_bytes();
        assert_eq!(
            StoredCanonicalHead::<PHash>::decode_persisted(
                head.network_id(),
                1,
                &head.to_canonical_bytes(),
                &requested_bytes,
            ),
            Err(CanonicalHeadModelError::RequestedControlAtEpochZero)
        );
        let mismatched_head =
            canonical_ref(PsyChainNetworkType::PsyMainnet, 1, 11, 60);
        assert_eq!(
            StoredCanonicalHead::<PHash>::decode_persisted(
                mismatched_head.network_id(),
                1,
                &mismatched_head.to_canonical_bytes(),
                &requested_bytes,
            ),
            Err(CanonicalHeadModelError::RollbackRequestedHeadMismatch)
        );
    }

    #[test]
    fn rollback_archive_begin_is_same_row_pre_ponr_and_exactly_once() {
        let head = canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 10, 50);
        let expected = stored_for_test(head);
        let target = *canonical_ref(
            PsyChainNetworkType::PsyMainnet,
            0,
            7,
            40,
        )
        .checkpoint();
        let request = rollback_request(*head.checkpoint(), target);
        let requested = CanonicalHeadTransition::start_rollback(expected, request)
            .unwrap();
        let archiving = CanonicalHeadTransition::begin_rollback_archive(
            *requested.candidate(),
        )
        .unwrap();

        assert_eq!(
            archiving.kind(),
            CanonicalHeadTransitionKind::BeginRollbackArchive
        );
        assert_eq!(
            archiving.candidate().revision().get(),
            requested.candidate().revision().get() + 1
        );
        assert_eq!(
            archiving.candidate().canonical_ref(),
            requested.candidate().canonical_ref()
        );
        assert!(archiving.candidate().rollback_control().is_archiving());
        assert!(!archiving
            .candidate()
            .rollback_control()
            .archive_barrier_ready());
        assert!(!archiving
            .candidate()
            .rollback_control()
            .destructive_started());
        assert_eq!(
            archiving.candidate().rollback_control().requested(),
            Some(&request)
        );
        assert_eq!(
            CanonicalHeadTransition::begin_rollback_archive(expected),
            Err(CanonicalHeadModelError::RollbackNotRequested)
        );
        assert_eq!(
            CanonicalHeadTransition::begin_rollback_archive(
                *archiving.candidate()
            ),
            Err(CanonicalHeadModelError::RollbackArchiveAlreadyStarted)
        );
    }

    #[test]
    fn rollback_abort_is_pre_ponr_only_and_closes_the_provisional_epoch() {
        let head = canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 10, 50);
        let target = *canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 7, 40)
            .checkpoint();
        let request = rollback_request(*head.checkpoint(), target);
        let requested = CanonicalHeadTransition::start_rollback(
            stored_for_test(head),
            request,
        )
        .unwrap();
        let archiving = CanonicalHeadTransition::begin_rollback_archive(
            *requested.candidate(),
        )
        .unwrap();
        let barrier = CanonicalHeadTransition::complete_rollback_archive_barrier(
            *archiving.candidate(),
            barrier_for(archiving.candidate()),
        )
        .unwrap();
        let reason = RollbackAbortReasonCode::try_new(42).unwrap();

        for expected in [
            *requested.candidate(),
            *archiving.candidate(),
            *barrier.candidate(),
        ] {
            let aborting = CanonicalHeadTransition::begin_rollback_abort(expected, reason)
                .unwrap();
            assert_eq!(aborting.kind(), CanonicalHeadTransitionKind::BeginRollbackAbort);
            assert_eq!(aborting.candidate().canonical_ref(), expected.canonical_ref());
            assert_eq!(aborting.candidate().revision().get(), expected.revision().get() + 1);
            assert_eq!(
                aborting
                    .candidate()
                    .rollback_control()
                    .aborting()
                    .unwrap()
                    .reason_code(),
                reason
            );
            assert!(!aborting.candidate().rollback_control().destructive_started());

            let idle = CanonicalHeadTransition::complete_rollback_abort(
                *aborting.candidate(),
            )
            .unwrap();
            assert_eq!(idle.kind(), CanonicalHeadTransitionKind::CompleteRollbackAbort);
            assert_eq!(idle.candidate().canonical_ref(), &head);
            assert_eq!(
                idle.candidate().revision().get(),
                aborting.candidate().revision().get() + 1
            );
            assert!(idle.candidate().rollback_control().is_idle());

            let continued = CanonicalHeadTransition::normal_checkpoint_advance(
                *idle.candidate(),
                canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 11, 60),
            )
            .unwrap();
            assert_eq!(continued.candidate().canonical_ref().chain_epoch().get(), 0);
            assert_eq!(
                continued
                    .candidate()
                    .canonical_ref()
                    .checkpoint()
                    .checkpoint_id()
                    .get(),
                11
            );

            let retry = CanonicalHeadTransition::start_rollback(
                *idle.candidate(),
                request,
            )
            .unwrap();
            assert_eq!(
                retry.candidate().canonical_ref().chain_epoch().get(),
                1
            );
            assert_eq!(
                retry.candidate().canonical_ref().chain_epoch().get().checked_sub(1),
                Some(head.chain_epoch().get())
            );
        }

        let deleting = CanonicalHeadTransition::begin_rollback_delete(
            *barrier.candidate(),
        )
        .unwrap();
        assert_eq!(
            CanonicalHeadTransition::begin_rollback_abort(*deleting.candidate(), reason),
            Err(CanonicalHeadModelError::RollbackPointOfNoReturn)
        );
        assert_eq!(
            CanonicalHeadTransition::begin_rollback_abort(stored_for_test(head), reason),
            Err(CanonicalHeadModelError::RollbackNotActiveForAbort)
        );
        assert_eq!(
            CanonicalHeadTransition::complete_rollback_abort(*requested.candidate()),
            Err(CanonicalHeadModelError::RollbackAbortNotActive)
        );
    }

    #[test]
    fn archive_barrier_then_delete_is_the_only_destructive_phase_path() {
        let head = canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 10, 50);
        let target = *canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 7, 40)
            .checkpoint();
        let request = rollback_request(*head.checkpoint(), target);
        let requested = CanonicalHeadTransition::start_rollback(
            stored_for_test(head),
            request,
        )
        .unwrap();
        let archiving = CanonicalHeadTransition::begin_rollback_archive(
            *requested.candidate(),
        )
        .unwrap();
        let barrier = CanonicalHeadTransition::complete_rollback_archive_barrier(
            *archiving.candidate(),
            barrier_for(archiving.candidate()),
        )
        .unwrap();
        assert_eq!(
            barrier.kind(),
            CanonicalHeadTransitionKind::CompleteRollbackArchiveBarrier
        );
        assert_eq!(
            barrier.candidate().revision().get(),
            archiving.candidate().revision().get() + 1
        );
        assert_eq!(
            barrier.candidate().canonical_ref(),
            archiving.candidate().canonical_ref()
        );
        assert!(barrier
            .candidate()
            .rollback_control()
            .archive_barrier_ready());
        assert!(!barrier
            .candidate()
            .rollback_control()
            .destructive_started());

        let deleting = CanonicalHeadTransition::begin_rollback_delete(
            *barrier.candidate(),
        )
        .unwrap();
        assert_eq!(
            deleting.kind(),
            CanonicalHeadTransitionKind::BeginRollbackDelete
        );
        assert_eq!(
            deleting.candidate().revision().get(),
            barrier.candidate().revision().get() + 1
        );
        assert_eq!(
            deleting.candidate().canonical_ref(),
            barrier.candidate().canonical_ref()
        );
        assert!(deleting
            .candidate()
            .rollback_control()
            .destructive_started());

        let restoring = CanonicalHeadTransition::begin_rollback_restore(
            *deleting.candidate(),
        )
        .unwrap();
        assert_eq!(restoring.kind(), CanonicalHeadTransitionKind::BeginRollbackRestore);
        assert!(restoring.candidate().rollback_control().destructive_started());
        let verifying = CanonicalHeadTransition::begin_rollback_verify(
            *restoring.candidate(),
        )
        .unwrap();
        assert_eq!(verifying.kind(), CanonicalHeadTransitionKind::BeginRollbackVerify);
        let all_ready = CanonicalHeadTransition::complete_rollback_realm_barrier(
            *verifying.candidate(),
        )
        .unwrap();
        assert_eq!(
            all_ready.kind(),
            CanonicalHeadTransitionKind::CompleteRollbackRealmBarrier
        );
        let completed = CanonicalHeadTransition::complete_rollback(
            *all_ready.candidate(),
        )
        .unwrap();
        assert_eq!(
            completed.kind(),
            CanonicalHeadTransitionKind::CompleteRollback
        );
        assert_eq!(
            completed.candidate().revision().get(),
            all_ready.candidate().revision().get() + 1
        );
        assert_eq!(
            completed.candidate().canonical_ref().chain_epoch(),
            all_ready.candidate().canonical_ref().chain_epoch()
        );
        assert_eq!(
            completed.candidate().canonical_ref().checkpoint(),
            request.target()
        );
        assert!(completed.candidate().rollback_control().is_idle());

        let b2 = CanonicalHeadTransition::normal_checkpoint_advance(
            *completed.candidate(),
            canonical_ref(PsyChainNetworkType::PsyMainnet, 1, 8, 80),
        )
        .unwrap();
        let b3 = CanonicalHeadTransition::normal_checkpoint_advance(
            *b2.candidate(),
            canonical_ref(PsyChainNetworkType::PsyMainnet, 1, 9, 90),
        )
        .unwrap();
        assert_eq!(b2.candidate().canonical_ref().chain_epoch().get(), 1);
        assert_eq!(b3.candidate().canonical_ref().chain_epoch().get(), 1);
        assert_eq!(
            b3.candidate()
                .canonical_ref()
                .checkpoint()
                .checkpoint_id()
                .get(),
            9
        );
        assert_eq!(
            CanonicalHeadTransition::normal_checkpoint_advance(
                *completed.candidate(),
                canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 8, 81),
            ),
            Err(CanonicalHeadModelError::ChainEpochChangedDuringNormalAdvance {
                expected: 1,
                proposed: 0,
            })
        );

        assert_eq!(
            CanonicalHeadTransition::complete_rollback_archive_barrier(
                *requested.candidate(),
                barrier_for(requested.candidate()),
            ),
            Err(CanonicalHeadModelError::RollbackArchiveNotActive)
        );
        assert_eq!(
            CanonicalHeadTransition::begin_rollback_delete(*archiving.candidate()),
            Err(CanonicalHeadModelError::RollbackArchiveBarrierNotReady)
        );
        assert_eq!(
            CanonicalHeadTransition::complete_rollback(*barrier.candidate()),
            Err(CanonicalHeadModelError::RollbackRealmsNotReady)
        );
        assert_eq!(
            CanonicalHeadTransition::complete_rollback(*completed.candidate()),
            Err(CanonicalHeadModelError::RollbackRealmsNotReady)
        );
    }

    #[test]
    fn sealed_retry_is_stable_and_lwt_observation_is_fail_closed() {
        let expected = *genesis().candidate();
        let transition = CanonicalHeadTransition::normal_checkpoint_advance(
            expected,
            canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 1, 10),
        )
        .unwrap();
        let sealed = transition.seal();
        let retry = sealed;
        assert_eq!(sealed, retry);
        assert_eq!(sealed.expected_payload(), &expected.canonical_ref_bytes());
        assert_eq!(sealed.candidate_payload(), &sealed.candidate().canonical_ref_bytes());
        assert!(sealed
            .classify_lwt_observation(true, *sealed.candidate())
            .unwrap()
            .was_applied());
        assert!(sealed
            .classify_lwt_observation(false, *sealed.candidate())
            .unwrap()
            .was_idempotent());
        assert!(matches!(
            sealed.classify_lwt_observation(false, expected).unwrap(),
            CanonicalHeadWriteOutcome::Conflict { current } if current == expected
        ));
        assert_eq!(
            sealed.classify_lwt_observation(true, expected),
            Err(CanonicalHeadModelError::AppliedStateMismatch)
        );
    }

    #[test]
    fn overflow_blocks_transition_builders() {
        let max_checkpoint_ref = canonical_ref(PsyChainNetworkType::PsyMainnet, 0, u64::MAX, 1);
        let max_checkpoint = StoredCanonicalHead::decode_persisted(
            max_checkpoint_ref.network_id(),
            0,
            &max_checkpoint_ref.to_canonical_bytes(),
            &idle_control_bytes(),
        )
        .unwrap();
        assert_eq!(
            CanonicalHeadTransition::normal_checkpoint_advance(max_checkpoint, max_checkpoint_ref),
            Err(CanonicalHeadModelError::CheckpointOverflow(u64::MAX))
        );

        let max_epoch_ref = canonical_ref(PsyChainNetworkType::PsyMainnet, u64::MAX, 7, 1);
        let max_epoch = StoredCanonicalHead::decode_persisted(
            max_epoch_ref.network_id(),
            0,
            &max_epoch_ref.to_canonical_bytes(),
            &idle_control_bytes(),
        )
        .unwrap();
        assert_eq!(
            CanonicalHeadTransition::start_rollback(
                max_epoch,
                rollback_request(
                    *max_epoch_ref.checkpoint(),
                    *canonical_ref(PsyChainNetworkType::PsyMainnet, u64::MAX, 6, 2)
                        .checkpoint(),
                ),
            ),
            Err(CanonicalHeadModelError::ChainEpochOverflow(u64::MAX))
        );

        let max_revision = StoredCanonicalHead::decode_persisted(
            NetworkId::from(PsyChainNetworkType::PsyMainnet),
            i64::MAX,
            genesis().candidate_payload(),
            genesis().candidate_control_payload(),
        )
        .unwrap();
        assert_eq!(
            CanonicalHeadTransition::normal_checkpoint_advance(
                max_revision,
                canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 1, 10),
            ),
            Err(CanonicalHeadModelError::RevisionOverflow(i64::MAX as u64))
        );
    }

    #[test]
    fn startup_requires_explicit_profile_and_defers_fresh_genesis_publish() {
        let network = NetworkId::from(PsyChainNetworkType::PsyMainnet);
        let materialized = *canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 0, 1)
            .checkpoint();
        assert_eq!(
            plan_canonical_head_startup::<PHash>(
                network,
                None,
                CanonicalHeadReadState::Uninitialized,
                materialized,
                true,
            ),
            Err(CanonicalHeadModelError::BootstrapProfileRequired)
        );

        let plan = plan_canonical_head_startup::<PHash>(
            network,
            Some(CanonicalHeadBootstrapProfile::GenesisNative),
            CanonicalHeadReadState::Uninitialized,
            materialized,
            true,
        )
        .unwrap();
        assert!(matches!(
            plan,
            CanonicalHeadStartupPlan::AwaitGenesis(bootstrap)
                if bootstrap.candidate().canonical_ref().checkpoint() == &materialized
        ));
    }

    #[test]
    fn bootstrap_profile_config_spelling_is_stable_and_missing_stays_absent() {
        #[derive(Deserialize)]
        struct Config {
            #[serde(default)]
            profile: Option<CanonicalHeadBootstrapProfile>,
        }

        let genesis: Config = serde_yaml::from_str("profile: GENESIS_NATIVE\n").unwrap();
        assert_eq!(
            genesis.profile,
            Some(CanonicalHeadBootstrapProfile::GenesisNative)
        );
        let floor: Config = serde_yaml::from_str("profile: POST_GENESIS_FLOOR\n").unwrap();
        assert_eq!(
            floor.profile,
            Some(CanonicalHeadBootstrapProfile::PostGenesisFloor)
        );
        let missing: Config = serde_yaml::from_str("{}\n").unwrap();
        assert_eq!(missing.profile, None);
        assert!(serde_yaml::from_str::<Config>("profile: genesis_native\n").is_err());
    }

    #[test]
    fn startup_bootstraps_only_explicit_materialized_genesis_or_floor() {
        let network = NetworkId::from(PsyChainNetworkType::PsyMainnet);
        let genesis_checkpoint = *canonical_ref(
            PsyChainNetworkType::PsyMainnet,
            0,
            0,
            1,
        )
        .checkpoint();
        assert!(matches!(
            plan_canonical_head_startup::<PHash>(
                network,
                Some(CanonicalHeadBootstrapProfile::GenesisNative),
                CanonicalHeadReadState::Uninitialized,
                genesis_checkpoint,
                false,
            )
            .unwrap(),
            CanonicalHeadStartupPlan::Bootstrap(_)
        ));

        let floor_checkpoint = *canonical_ref(
            PsyChainNetworkType::PsyMainnet,
            0,
            900,
            10,
        )
        .checkpoint();
        assert!(matches!(
            plan_canonical_head_startup::<PHash>(
                network,
                Some(CanonicalHeadBootstrapProfile::PostGenesisFloor),
                CanonicalHeadReadState::Uninitialized,
                floor_checkpoint,
                false,
            )
            .unwrap(),
            CanonicalHeadStartupPlan::Bootstrap(bootstrap)
                if bootstrap.profile() == CanonicalHeadBootstrapProfile::PostGenesisFloor
        ));
        assert!(plan_canonical_head_startup::<PHash>(
            network,
            Some(CanonicalHeadBootstrapProfile::PostGenesisFloor),
            CanonicalHeadReadState::Uninitialized,
            genesis_checkpoint,
            false,
        )
        .is_err());
    }

    #[test]
    fn startup_accepts_exact_head_or_seals_one_missing_final_publish() {
        let network = NetworkId::from(PsyChainNetworkType::PsyMainnet);
        let current_ref = canonical_ref(PsyChainNetworkType::PsyMainnet, 7, 41, 100);
        let current = StoredCanonicalHead::decode_persisted(
            network,
            9,
            &current_ref.to_canonical_bytes(),
            &idle_control_bytes(),
        )
        .unwrap();
        assert_eq!(
            plan_canonical_head_startup(
                network,
                None,
                CanonicalHeadReadState::Current(current),
                *current_ref.checkpoint(),
                false,
            )
            .unwrap(),
            CanonicalHeadStartupPlan::Current(current)
        );

        let next = *canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 42, 200)
            .checkpoint();
        let plan = plan_canonical_head_startup(
            network,
            None,
            CanonicalHeadReadState::Current(current),
            next,
            false,
        )
        .unwrap();
        assert!(matches!(
            plan,
            CanonicalHeadStartupPlan::PublishMaterialized(sealed)
                if sealed.expected() == &current
                    && sealed.candidate().revision().get() == 10
                    && sealed.candidate().canonical_ref().chain_epoch().get() == 7
                    && sealed.candidate().canonical_ref().checkpoint() == &next
        ));
    }

    #[test]
    fn startup_reconciliation_rejects_hash_conflict_gap_and_head_ahead() {
        let network = NetworkId::from(PsyChainNetworkType::PsyMainnet);
        let current_ref = canonical_ref(PsyChainNetworkType::PsyMainnet, 3, 41, 100);
        let current = StoredCanonicalHead::decode_persisted(
            network,
            9,
            &current_ref.to_canonical_bytes(),
            &idle_control_bytes(),
        )
        .unwrap();
        for materialized in [
            *canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 41, 999).checkpoint(),
            *canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 40, 90).checkpoint(),
            *canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 43, 300).checkpoint(),
        ] {
            assert!(plan_canonical_head_startup(
                network,
                None,
                CanonicalHeadReadState::Current(current),
                materialized,
                false,
            )
            .is_err());
        }
        assert_eq!(
            plan_canonical_head_startup(
                network,
                None,
                CanonicalHeadReadState::Current(current),
                *current_ref.checkpoint(),
                true,
            ),
            Err(CanonicalHeadModelError::DurableHeadBeforeGenesisMaterialized)
        );
    }

    fn stored_for_test(canonical_ref: CanonicalChainRef<PHash>) -> StoredCanonicalHead<PHash> {
        StoredCanonicalHead::decode_persisted(
            canonical_ref.network_id(),
            0,
            &canonical_ref.to_canonical_bytes(),
            &idle_control_bytes(),
        )
        .unwrap()
    }
}
