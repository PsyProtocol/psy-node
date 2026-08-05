//! Driver-independent durable canonical-head contracts.
//!
//! This module deliberately models only two safe transitions: advancing one
//! checkpoint in the current epoch and opening the next rollback epoch while
//! keeping the checkpoint unchanged. Publishing a rewind target remains a
//! responsibility of the future durable rollback-control state machine.

use std::{error::Error, fmt};

use async_trait::async_trait;
use parth_core::protocol::core_types::Q256BitHash;
pub use psy_data::protocol::canonical_chain::NetworkId;
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, CanonicalChainRefCodecError, ChainEpoch, CheckpointRef,
    CANONICAL_CHAIN_REF_V1_LEN,
};
use serde::{Deserialize, Serialize};

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
}

impl<Hash> StoredCanonicalHead<Hash> {
    pub const fn revision(&self) -> CanonicalHeadRevision {
        self.revision
    }

    pub const fn canonical_ref(&self) -> &CanonicalChainRef<Hash> {
        &self.canonical_ref
    }
}

impl<Hash: Q256BitHash> StoredCanonicalHead<Hash> {
    /// Decode a database row and prove that its partition key agrees with the
    /// network encoded inside the single canonical payload.
    pub fn decode_persisted(
        partition_network: NetworkId,
        revision: i64,
        canonical_payload: &[u8],
    ) -> Result<Self, CanonicalHeadModelError> {
        let revision = CanonicalHeadRevision::try_from_i64(revision)?;
        let canonical_ref = CanonicalChainRef::from_canonical_bytes(canonical_payload)?;
        if canonical_ref.network_id() != partition_network {
            return Err(CanonicalHeadModelError::PartitionNetworkMismatch {
                partition: partition_network,
                payload: canonical_ref.network_id(),
            });
        }
        Ok(Self {
            revision,
            canonical_ref,
        })
    }

    pub fn canonical_ref_bytes(&self) -> [u8; CANONICAL_CHAIN_REF_V1_LEN] {
        self.canonical_ref.to_canonical_bytes()
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
        Ok(Self {
            profile,
            candidate: StoredCanonicalHead {
                revision: CanonicalHeadRevision::initial(),
                canonical_ref,
            },
            candidate_payload,
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
    OpenRollbackEpoch,
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
            },
        })
    }

    /// Validate opening a new rollback epoch while leaving the exact checkpoint
    /// occurrence unchanged.
    pub fn open_rollback_epoch(
        expected: StoredCanonicalHead<Hash>,
        proposed: CanonicalChainRef<Hash>,
    ) -> Result<Self, CanonicalHeadModelError> {
        require_same_network(expected.canonical_ref(), &proposed)?;
        let old_epoch = expected.canonical_ref().chain_epoch().get();
        let next_epoch = old_epoch
            .checked_add(1)
            .ok_or(CanonicalHeadModelError::ChainEpochOverflow(old_epoch))?;
        if proposed.chain_epoch().get() != next_epoch {
            return Err(CanonicalHeadModelError::ChainEpochNotNext {
                expected: next_epoch,
                proposed: proposed.chain_epoch().get(),
            });
        }
        if proposed.checkpoint() != expected.canonical_ref().checkpoint() {
            return Err(CanonicalHeadModelError::CheckpointChangedWhileOpeningEpoch);
        }
        Ok(Self {
            kind: CanonicalHeadTransitionKind::OpenRollbackEpoch,
            expected,
            candidate: StoredCanonicalHead {
                revision: expected.revision.checked_next()?,
                canonical_ref: proposed,
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
        SealedCanonicalHeadCas {
            transition: self,
            expected_payload,
            candidate_payload,
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
    RevisionOutOfCqlRange(u64),
    NegativeRevision(i64),
    RevisionOverflow(u64),
    Codec(CanonicalChainRefCodecError),
    PartitionNetworkMismatch { partition: NetworkId, payload: NetworkId },
    BootstrapEpochMustBeZero(u64),
    GenesisBootstrapMustUseCheckpointZero(u64),
    PostGenesisFloorMustBePositive,
    NetworkChanged { expected: NetworkId, proposed: NetworkId },
    ChainEpochChangedDuringNormalAdvance { expected: u64, proposed: u64 },
    CheckpointNotNext { expected: u64, proposed: u64 },
    CheckpointOverflow(u64),
    ChainEpochNotNext { expected: u64, proposed: u64 },
    ChainEpochOverflow(u64),
    CheckpointChangedWhileOpeningEpoch,
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
            Self::ChainEpochNotNext { expected, proposed } => write!(
                formatter,
                "opening rollback epoch requires epoch {expected}, got {proposed}"
            ),
            Self::ChainEpochOverflow(epoch) => write!(formatter, "chain epoch {epoch} has no successor"),
            Self::CheckpointChangedWhileOpeningEpoch => formatter.write_str(
                "opening rollback epoch must preserve the exact checkpoint ID and hash",
            ),
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
            _ => None,
        }
    }
}

impl From<CanonicalChainRefCodecError> for CanonicalHeadModelError {
    fn from(value: CanonicalChainRefCodecError) -> Self {
        Self::Codec(value)
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
            ),
            Err(CanonicalHeadModelError::PartitionNetworkMismatch { .. })
        ));
        for cut in 0..CANONICAL_CHAIN_REF_V1_LEN {
            assert!(StoredCanonicalHead::<PHash>::decode_persisted(
                NetworkId::from(PsyChainNetworkType::PsyMainnet),
                0,
                &encoded[..cut],
            )
            .is_err());
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(StoredCanonicalHead::<PHash>::decode_persisted(
            NetworkId::from(PsyChainNetworkType::PsyMainnet),
            0,
            &trailing,
        )
        .is_err());
        let mut unknown_version = encoded;
        unknown_version[8..10].copy_from_slice(&2_u16.to_le_bytes());
        assert!(matches!(
            StoredCanonicalHead::<PHash>::decode_persisted(
                NetworkId::from(PsyChainNetworkType::PsyMainnet),
                0,
                &unknown_version,
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
    fn open_epoch_validates_next_epoch_and_exact_checkpoint_ref() {
        let expected = *genesis().candidate();
        let unchanged = *expected.canonical_ref().checkpoint();
        let valid = CanonicalChainRef::new(
            expected.canonical_ref().network_id(),
            ChainEpoch::new(1),
            unchanged,
        );
        let transition = CanonicalHeadTransition::open_rollback_epoch(expected, valid).unwrap();
        assert_eq!(transition.kind(), CanonicalHeadTransitionKind::OpenRollbackEpoch);
        assert_eq!(transition.candidate().revision().get(), 1);
        assert_eq!(transition.candidate().canonical_ref().checkpoint(), expected.canonical_ref().checkpoint());

        for proposed in [
            canonical_ref(PsyChainNetworkType::PsyMainnet, 0, 0, 1),
            canonical_ref(PsyChainNetworkType::PsyMainnet, 2, 0, 1),
            canonical_ref(PsyChainNetworkType::PsyMainnet, 1, 1, 1),
            canonical_ref(PsyChainNetworkType::PsyMainnet, 1, 0, 99),
            canonical_ref(PsyChainNetworkType::PsyPublicTestnet, 1, 0, 1),
        ] {
            assert!(CanonicalHeadTransition::open_rollback_epoch(expected, proposed).is_err());
        }
        let later = stored_for_test(canonical_ref(
            PsyChainNetworkType::PsyMainnet,
            5,
            10,
            30,
        ));
        assert!(CanonicalHeadTransition::open_rollback_epoch(
            later,
            canonical_ref(PsyChainNetworkType::PsyMainnet, 4, 10, 30),
        )
        .is_err());
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
        )
        .unwrap();
        assert_eq!(
            CanonicalHeadTransition::open_rollback_epoch(max_epoch, max_epoch_ref),
            Err(CanonicalHeadModelError::ChainEpochOverflow(u64::MAX))
        );

        let max_revision = StoredCanonicalHead::decode_persisted(
            NetworkId::from(PsyChainNetworkType::PsyMainnet),
            i64::MAX,
            genesis().candidate_payload(),
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
        )
        .unwrap()
    }
}
