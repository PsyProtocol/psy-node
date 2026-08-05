//! Driver-independent rollback admission data stored beside the canonical head.
//!
//! The first control slice deliberately models only `IDLE -> REQUESTED`.
//! Later phase/PONR transitions must extend this sealed authority rather than
//! create a second independently writable control row.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::{
    CheckpointHash, CheckpointId, CheckpointRef,
};

use super::timestamp::{
    CommitWriteTimestampUs, TimestampFenceWindow, TimestampOrderingError,
};

pub const ROLLBACK_CONTROL_MAGIC: [u8; 8] = *b"PSYRBCTL";
pub const ROLLBACK_CONTROL_CODEC_VERSION: u16 = 1;
pub const ROLLBACK_CONTROL_V1_LEN: usize = 154;

const CONTROL_KIND_IDLE: u8 = 0;
const CONTROL_KIND_REQUESTED: u8 = 1;
const PHASE_REQUESTED: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RollbackPlanDigest([u8; 32]);

impl RollbackPlanDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, RollbackControlError> {
        if bytes == [0; 32] {
            return Err(RollbackControlError::ZeroPlanDigest);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RollbackExecutionMode {
    InPlace = 1,
    SnapshotReplay = 2,
}

impl RollbackExecutionMode {
    fn try_from_byte(value: u8) -> Result<Self, RollbackControlCodecError> {
        match value {
            1 => Ok(Self::InPlace),
            2 => Ok(Self::SnapshotReplay),
            other => Err(RollbackControlCodecError::UnknownExecutionMode(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackRequest<Hash> {
    requested_head: CheckpointRef<Hash>,
    target: CheckpointRef<Hash>,
    fence_window: TimestampFenceWindow,
    execution_mode: RollbackExecutionMode,
    plan_digest: RollbackPlanDigest,
}

impl<Hash> RollbackRequest<Hash> {
    pub fn try_new(
        requested_head: CheckpointRef<Hash>,
        target: CheckpointRef<Hash>,
        fence_window: TimestampFenceWindow,
        execution_mode: RollbackExecutionMode,
        plan_digest: RollbackPlanDigest,
    ) -> Result<Self, RollbackControlError> {
        let requested_height = requested_head.checkpoint_id().get();
        let target_height = target.checkpoint_id().get();
        if target_height >= requested_height {
            return Err(RollbackControlError::TargetMustPrecedeRequestedHead {
                requested_height,
                target_height,
            });
        }
        Ok(Self {
            requested_head,
            target,
            fence_window,
            execution_mode,
            plan_digest,
        })
    }

    pub const fn requested_head(&self) -> &CheckpointRef<Hash> {
        &self.requested_head
    }

    pub const fn target(&self) -> &CheckpointRef<Hash> {
        &self.target
    }

    pub const fn fence_window(&self) -> TimestampFenceWindow {
        self.fence_window
    }

    pub const fn execution_mode(&self) -> RollbackExecutionMode {
        self.execution_mode
    }

    pub const fn plan_digest(&self) -> RollbackPlanDigest {
        self.plan_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackControlState<Hash> {
    Idle,
    Requested(RollbackRequest<Hash>),
}

impl<Hash> RollbackControlState<Hash> {
    pub const fn is_idle(&self) -> bool {
        matches!(self, Self::Idle)
    }

    pub const fn requested(&self) -> Option<&RollbackRequest<Hash>> {
        match self {
            Self::Idle => None,
            Self::Requested(request) => Some(request),
        }
    }
}

impl<Hash: Q256BitHash> RollbackControlState<Hash> {
    pub fn to_canonical_bytes(&self) -> [u8; ROLLBACK_CONTROL_V1_LEN] {
        let mut encoded = [0_u8; ROLLBACK_CONTROL_V1_LEN];
        encoded[0..8].copy_from_slice(&ROLLBACK_CONTROL_MAGIC);
        encoded[8..10].copy_from_slice(&ROLLBACK_CONTROL_CODEC_VERSION.to_le_bytes());
        match self {
            Self::Idle => {
                encoded[10] = CONTROL_KIND_IDLE;
            }
            Self::Requested(request) => {
                encoded[10] = CONTROL_KIND_REQUESTED;
                encoded[11] = PHASE_REQUESTED;
                encode_checkpoint_ref(&mut encoded[12..52], request.requested_head());
                encode_checkpoint_ref(&mut encoded[52..92], request.target());
                let orphan_max = request
                    .fence_window()
                    .delete_fence()
                    .orphan_write_max()
                    .as_i64();
                let delete_fence = request.fence_window().delete_fence().as_i64();
                let new_branch = request
                    .fence_window()
                    .new_branch_write()
                    .as_commit_timestamp()
                    .as_i64();
                encoded[92..100].copy_from_slice(&orphan_max.to_le_bytes());
                encoded[100..108].copy_from_slice(&delete_fence.to_le_bytes());
                encoded[108..116].copy_from_slice(&new_branch.to_le_bytes());
                encoded[116] = request.execution_mode() as u8;
                encoded[117..149].copy_from_slice(request.plan_digest().as_bytes());
                // destructive_started=false, abort_code=0, error_code=0.
                encoded[149] = 0;
            }
        }
        encoded
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RollbackControlCodecError> {
        if bytes.len() != ROLLBACK_CONTROL_V1_LEN {
            return Err(RollbackControlCodecError::InvalidLength {
                expected: ROLLBACK_CONTROL_V1_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0..8] != ROLLBACK_CONTROL_MAGIC {
            return Err(RollbackControlCodecError::InvalidMagic);
        }
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version != ROLLBACK_CONTROL_CODEC_VERSION {
            return Err(RollbackControlCodecError::UnsupportedVersion(version));
        }
        match bytes[10] {
            CONTROL_KIND_IDLE => {
                if bytes[11..].iter().any(|byte| *byte != 0) {
                    return Err(RollbackControlCodecError::NonCanonicalIdle);
                }
                Ok(Self::Idle)
            }
            CONTROL_KIND_REQUESTED => {
                if bytes[11] != PHASE_REQUESTED {
                    return Err(RollbackControlCodecError::UnknownPhase(bytes[11]));
                }
                if bytes[149] != 0 || bytes[150..154].iter().any(|byte| *byte != 0) {
                    return Err(RollbackControlCodecError::RequestedMustBePreDestructive);
                }
                let requested_head = decode_checkpoint_ref(&bytes[12..52]);
                let target = decode_checkpoint_ref(&bytes[52..92]);
                let orphan_max = i64::from_le_bytes(bytes[92..100].try_into().expect("fixed slice"));
                let delete_fence = i64::from_le_bytes(bytes[100..108].try_into().expect("fixed slice"));
                let new_branch = i64::from_le_bytes(bytes[108..116].try_into().expect("fixed slice"));
                let orphan_max = CommitWriteTimestampUs::try_from_i128(i128::from(orphan_max))
                    .expect("every i64 is a valid CQL timestamp");
                let fence_window = TimestampFenceWindow::try_new(
                    orphan_max,
                    i128::from(delete_fence),
                    i128::from(new_branch),
                )?;
                let execution_mode = RollbackExecutionMode::try_from_byte(bytes[116])?;
                let digest: [u8; 32] = bytes[117..149].try_into().expect("fixed slice");
                let plan_digest = RollbackPlanDigest::try_new(digest)?;
                let request = RollbackRequest::try_new(
                    requested_head,
                    target,
                    fence_window,
                    execution_mode,
                    plan_digest,
                )?;
                Ok(Self::Requested(request))
            }
            other => Err(RollbackControlCodecError::UnknownControlKind(other)),
        }
    }
}

fn encode_checkpoint_ref<Hash: Q256BitHash>(output: &mut [u8], checkpoint: &CheckpointRef<Hash>) {
    output[0..8].copy_from_slice(&checkpoint.checkpoint_id().get().to_le_bytes());
    output[8..40].copy_from_slice(&checkpoint.checkpoint_hash().as_inner().into_owned_32bytes());
}

fn decode_checkpoint_ref<Hash: Q256BitHash>(input: &[u8]) -> CheckpointRef<Hash> {
    let checkpoint_id = CheckpointId::new(u64::from_le_bytes(input[0..8].try_into().expect("fixed slice")));
    let hash = Hash::from_owned_32bytes(input[8..40].try_into().expect("fixed slice"));
    CheckpointRef::new(
        checkpoint_id,
        CheckpointHash::from_last_chain_hash(hash),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackControlError {
    ZeroPlanDigest,
    TargetMustPrecedeRequestedHead {
        requested_height: u64,
        target_height: u64,
    },
    Timestamp(TimestampOrderingError),
}

impl fmt::Display for RollbackControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroPlanDigest => write!(formatter, "rollback plan digest cannot be zero"),
            Self::TargetMustPrecedeRequestedHead {
                requested_height,
                target_height,
            } => write!(
                formatter,
                "rollback target {target_height} must precede requested head {requested_height}"
            ),
            Self::Timestamp(error) => error.fmt(formatter),
        }
    }
}

impl Error for RollbackControlError {}

impl From<TimestampOrderingError> for RollbackControlError {
    fn from(value: TimestampOrderingError) -> Self {
        Self::Timestamp(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackControlCodecError {
    InvalidLength { expected: usize, actual: usize },
    InvalidMagic,
    UnsupportedVersion(u16),
    UnknownControlKind(u8),
    UnknownPhase(u8),
    UnknownExecutionMode(u8),
    NonCanonicalIdle,
    RequestedMustBePreDestructive,
    Model(RollbackControlError),
}

impl fmt::Display for RollbackControlCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(formatter, "rollback control length {actual}, expected {expected}")
            }
            Self::InvalidMagic => write!(formatter, "invalid rollback control magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported rollback control version {version}")
            }
            Self::UnknownControlKind(kind) => write!(formatter, "unknown rollback control kind {kind}"),
            Self::UnknownPhase(phase) => write!(formatter, "unknown rollback phase {phase}"),
            Self::UnknownExecutionMode(mode) => write!(formatter, "unknown rollback execution mode {mode}"),
            Self::NonCanonicalIdle => write!(formatter, "idle rollback control has non-zero trailing fields"),
            Self::RequestedMustBePreDestructive => write!(
                formatter,
                "REQUESTED rollback control cannot be destructive or carry abort/error codes"
            ),
            Self::Model(error) => error.fmt(formatter),
        }
    }
}

impl Error for RollbackControlCodecError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Model(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RollbackControlError> for RollbackControlCodecError {
    fn from(value: RollbackControlError) -> Self {
        Self::Model(value)
    }
}

impl From<TimestampOrderingError> for RollbackControlCodecError {
    fn from(value: TimestampOrderingError) -> Self {
        Self::Model(RollbackControlError::Timestamp(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::PHash;

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

    fn request() -> RollbackRequest<PHash> {
        RollbackRequest::try_new(
            checkpoint(100, 10),
            checkpoint(90, 20),
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
                1_001,
                1_002,
            )
            .unwrap(),
            RollbackExecutionMode::InPlace,
            RollbackPlanDigest::try_new([0xA5; 32]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn idle_and_requested_codec_are_fixed_deterministic_and_round_trip() {
        let idle = RollbackControlState::<PHash>::Idle;
        let idle_bytes = idle.to_canonical_bytes();
        assert_eq!(idle_bytes.len(), ROLLBACK_CONTROL_V1_LEN);
        assert_eq!(
            RollbackControlState::from_canonical_bytes(&idle_bytes).unwrap(),
            idle
        );

        let requested = RollbackControlState::Requested(request());
        let first = requested.to_canonical_bytes();
        let second = requested.to_canonical_bytes();
        assert_eq!(first, second);
        assert_eq!(
            hex::encode(first),
            "505359524243544c0100010164000000000000000a000000000000000b000000000000000c000000000000000d000000000000005a000000000000001400000000000000150000000000000016000000000000001700000000000000e803000000000000e903000000000000ea0300000000000001a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a50000000000"
        );
        assert_ne!(first, idle_bytes);
        assert_eq!(
            RollbackControlState::from_canonical_bytes(&first).unwrap(),
            requested
        );
    }

    #[test]
    fn request_rejects_noop_forward_target_zero_digest_and_invalid_fence() {
        let head = checkpoint(100, 10);
        let fence = TimestampFenceWindow::try_new(
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
            1_001,
            1_002,
        )
        .unwrap();
        let digest = RollbackPlanDigest::try_new([1; 32]).unwrap();
        for target in [checkpoint(100, 20), checkpoint(101, 20)] {
            assert!(matches!(
                RollbackRequest::try_new(
                    head,
                    target,
                    fence,
                    RollbackExecutionMode::SnapshotReplay,
                    digest,
                ),
                Err(RollbackControlError::TargetMustPrecedeRequestedHead { .. })
            ));
        }
        assert_eq!(
            RollbackPlanDigest::try_new([0; 32]),
            Err(RollbackControlError::ZeroPlanDigest)
        );
        assert!(TimestampFenceWindow::try_new(
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
            1_000,
            1_002,
        )
        .is_err());
    }

    #[test]
    fn malformed_unknown_and_noncanonical_control_fail_closed() {
        let idle = RollbackControlState::<PHash>::Idle.to_canonical_bytes();
        for cut in 0..ROLLBACK_CONTROL_V1_LEN {
            assert!(RollbackControlState::<PHash>::from_canonical_bytes(
                &idle[..cut]
            )
            .is_err());
        }
        let mut trailing = idle.to_vec();
        trailing.push(0);
        assert!(matches!(
            RollbackControlState::<PHash>::from_canonical_bytes(&trailing),
            Err(RollbackControlCodecError::InvalidLength { .. })
        ));

        let mut bad_magic = idle;
        bad_magic[0] ^= 1;
        assert_eq!(
            RollbackControlState::<PHash>::from_canonical_bytes(&bad_magic),
            Err(RollbackControlCodecError::InvalidMagic)
        );
        let mut bad_version = idle;
        bad_version[8..10].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(
            RollbackControlState::<PHash>::from_canonical_bytes(&bad_version),
            Err(RollbackControlCodecError::UnsupportedVersion(2))
        );
        let mut unknown_kind = idle;
        unknown_kind[10] = 99;
        assert_eq!(
            RollbackControlState::<PHash>::from_canonical_bytes(&unknown_kind),
            Err(RollbackControlCodecError::UnknownControlKind(99))
        );
        let mut noncanonical_idle = idle;
        noncanonical_idle[153] = 1;
        assert_eq!(
            RollbackControlState::<PHash>::from_canonical_bytes(
                &noncanonical_idle
            ),
            Err(RollbackControlCodecError::NonCanonicalIdle)
        );

        let requested =
            RollbackControlState::Requested(request()).to_canonical_bytes();
        let mut unknown_phase = requested;
        unknown_phase[11] = 99;
        assert_eq!(
            RollbackControlState::<PHash>::from_canonical_bytes(&unknown_phase),
            Err(RollbackControlCodecError::UnknownPhase(99))
        );
        let mut unknown_mode = requested;
        unknown_mode[116] = 99;
        assert_eq!(
            RollbackControlState::<PHash>::from_canonical_bytes(&unknown_mode),
            Err(RollbackControlCodecError::UnknownExecutionMode(99))
        );
        let mut zero_digest = requested;
        zero_digest[117..149].fill(0);
        assert_eq!(
            RollbackControlState::<PHash>::from_canonical_bytes(&zero_digest),
            Err(RollbackControlCodecError::Model(
                RollbackControlError::ZeroPlanDigest
            ))
        );
        let mut invalid_fence = requested;
        invalid_fence[100..108].copy_from_slice(&1_000_i64.to_le_bytes());
        assert!(matches!(
            RollbackControlState::<PHash>::from_canonical_bytes(&invalid_fence),
            Err(RollbackControlCodecError::Model(
                RollbackControlError::Timestamp(_)
            ))
        ));
        let mut destructive = requested;
        destructive[149] = 1;
        assert_eq!(
            RollbackControlState::<PHash>::from_canonical_bytes(&destructive),
            Err(RollbackControlCodecError::RequestedMustBePreDestructive)
        );
    }
}
