//! Driver-independent durable authority commit-intent and timestamp lease.
//!
//! This module does not read a clock and does not execute storage mutations.
//! It models the small LWT-protected substrate required before an authority
//! may attach one explicit CQL timestamp to a sealed commit batch. Production
//! processor integration remains part of D-04 after the manifest protocol.

use std::{error::Error, fmt};

pub use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};

use super::timestamp::{CommitWriteTimestampUs, TimestampOutOfCqlRange};

pub const AUTHORITY_TIMESTAMP_STATE_MAGIC: [u8; 8] = *b"PSYATINT";
pub const AUTHORITY_TIMESTAMP_STATE_CODEC_VERSION: u16 = 1;
pub const AUTHORITY_TIMESTAMP_STATE_V1_LEN: usize = 8 + 2 + 1 + 1 + 8 + 32;

const PHASE_BOOTSTRAP_IDLE: u8 = 1;
const PHASE_ACTIVE: u8 = 2;
const PHASE_COMPLETED_IDLE: u8 = 3;

/// Exact durable row identity for one storage authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AuthorityTimestampKey {
    network: NetworkId,
    authority: AuthorityScope,
}

impl AuthorityTimestampKey {
    pub const fn new(network: NetworkId, authority: AuthorityScope) -> Self {
        Self { network, authority }
    }

    pub const fn network(self) -> NetworkId {
        self.network
    }

    pub const fn authority(self) -> AuthorityScope {
        self.authority
    }
}

/// Monotonic revision protecting the durable allocator row from ABA.
///
/// It is deliberately not interchangeable with a checkpoint, epoch, pending
/// ID, timestamp, or ordinary integer.
///
/// ```compile_fail
/// use psy_node_core::store::{authority_commit::AuthorityTimestampRevision, typed::CheckpointId};
/// let revision = AuthorityTimestampRevision::try_new(7).unwrap();
/// let _: CheckpointId = revision;
/// ```
///
/// ```compile_fail
/// use psy_node_core::store::authority_commit::AuthorityTimestampRevision;
/// let _: AuthorityTimestampRevision = Default::default();
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityTimestampRevision(u64);

impl AuthorityTimestampRevision {
    pub const fn try_new(value: u64) -> Result<Self, AuthorityCommitModelError> {
        if value <= i64::MAX as u64 {
            Ok(Self(value))
        } else {
            Err(AuthorityCommitModelError::RevisionOutOfCqlRange(value))
        }
    }

    pub const fn try_from_i64(value: i64) -> Result<Self, AuthorityCommitModelError> {
        if value < 0 {
            Err(AuthorityCommitModelError::NegativeRevision(value))
        } else {
            Ok(Self(value as u64))
        }
    }

    const fn initial() -> Self {
        Self(0)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    pub const fn checked_next(self) -> Result<Self, AuthorityCommitModelError> {
        match self.0.checked_add(1) {
            Some(value) if value <= i64::MAX as u64 => Ok(Self(value)),
            _ => Err(AuthorityCommitModelError::RevisionOverflow(self.0)),
        }
    }
}

/// Digest of the complete, authority-scoped commit intent before timestamp
/// allocation. The future manifest builder owns the digest construction.
///
/// ```compile_fail
/// use psy_node_core::store::{authority_commit::AuthorityCommitIntentDigest, timestamp::CommitWriteTimestampUs};
/// let digest = AuthorityCommitIntentDigest::from_sealed_commit_digest([7; 32]);
/// let _: CommitWriteTimestampUs = digest;
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityCommitIntentDigest([u8; 32]);

impl AuthorityCommitIntentDigest {
    /// Wraps a digest already produced by the future sealed commit/manifest
    /// builder. This function does not hash partial inputs.
    pub const fn from_sealed_commit_digest(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A caller-supplied wall-clock sample in signed CQL microseconds.
///
/// The type does not read `SystemTime`; allocation remains deterministic and
/// testable. It is not itself an allocated write timestamp.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityClockSampleUs(i64);

impl AuthorityClockSampleUs {
    pub const fn try_from_i128(value: i128) -> Result<Self, TimestampOutOfCqlRange> {
        match CommitWriteTimestampUs::try_from_i128(value) {
            Ok(value) => Ok(Self(value.as_i64())),
            Err(error) => Err(error),
        }
    }

    pub const fn as_i64(self) -> i64 {
        self.0
    }
}

/// Why an operator explicitly initialized the durable timestamp high-water.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum AuthorityTimestampBootstrapReason {
    GenesisNative = 1,
    ControlledWriterCutover = 2,
}

impl AuthorityTimestampBootstrapReason {
    const fn try_from_u8(value: u8) -> Result<Self, AuthorityCommitModelError> {
        match value {
            1 => Ok(Self::GenesisNative),
            2 => Ok(Self::ControlledWriterCutover),
            value => Err(AuthorityCommitModelError::UnknownBootstrapReason(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthorityTimestampPhase {
    Idle { last_completed: Option<AuthorityCommitIntentDigest> },
    Active { intent: AuthorityCommitIntentDigest },
}

/// Exact durable allocator state. Revision is stored in a separate CQL cell,
/// while `phase + high_water` use one canonical payload compared by LWT.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StoredAuthorityTimestampState {
    revision: AuthorityTimestampRevision,
    bootstrap_reason: AuthorityTimestampBootstrapReason,
    high_water: CommitWriteTimestampUs,
    phase: AuthorityTimestampPhase,
}

/// A durable allocator row bound to the exact partition key used to read it.
///
/// The Scylla adapter is the trust boundary that constructs this value after
/// selecting one row. Recovery planners accept this key-bound observation
/// instead of a bare payload, so they cannot silently reinterpret a row from
/// another network or authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedAuthorityTimestampState {
    key: AuthorityTimestampKey,
    state: StoredAuthorityTimestampState,
}

impl ObservedAuthorityTimestampState {
    pub const fn from_selected_row(
        key: AuthorityTimestampKey,
        state: StoredAuthorityTimestampState,
    ) -> Self {
        Self { key, state }
    }

    pub const fn key(self) -> AuthorityTimestampKey {
        self.key
    }

    pub const fn state(self) -> StoredAuthorityTimestampState {
        self.state
    }

    pub fn observe_intent(
        self,
        intent: AuthorityCommitIntentDigest,
    ) -> AuthorityIntentObservation {
        self.state.observe_intent(self.key, intent)
    }
}

impl StoredAuthorityTimestampState {
    pub const fn revision(self) -> AuthorityTimestampRevision {
        self.revision
    }

    pub const fn high_water(self) -> CommitWriteTimestampUs {
        self.high_water
    }

    pub const fn bootstrap_reason(self) -> AuthorityTimestampBootstrapReason {
        self.bootstrap_reason
    }

    pub const fn phase(self) -> AuthorityTimestampPhase {
        self.phase
    }

    pub fn encode_canonical(self) -> [u8; AUTHORITY_TIMESTAMP_STATE_V1_LEN] {
        let mut bytes = [0u8; AUTHORITY_TIMESTAMP_STATE_V1_LEN];
        bytes[..8].copy_from_slice(&AUTHORITY_TIMESTAMP_STATE_MAGIC);
        bytes[8..10].copy_from_slice(&AUTHORITY_TIMESTAMP_STATE_CODEC_VERSION.to_be_bytes());
        bytes[10] = self.bootstrap_reason as u8;
        bytes[12..20].copy_from_slice(&self.high_water.as_i64().to_be_bytes());
        match self.phase {
            AuthorityTimestampPhase::Idle { last_completed: None } => {
                bytes[11] = PHASE_BOOTSTRAP_IDLE;
            }
            AuthorityTimestampPhase::Active { intent } => {
                bytes[11] = PHASE_ACTIVE;
                bytes[20..52].copy_from_slice(intent.as_bytes());
            }
            AuthorityTimestampPhase::Idle { last_completed: Some(intent) } => {
                bytes[11] = PHASE_COMPLETED_IDLE;
                bytes[20..52].copy_from_slice(intent.as_bytes());
            }
        }
        bytes
    }

    pub fn decode_persisted(
        revision: i64,
        bytes: &[u8],
    ) -> Result<Self, AuthorityCommitModelError> {
        if bytes.len() != AUTHORITY_TIMESTAMP_STATE_V1_LEN {
            return Err(AuthorityCommitModelError::InvalidPayloadLength {
                expected: AUTHORITY_TIMESTAMP_STATE_V1_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[..8] != AUTHORITY_TIMESTAMP_STATE_MAGIC {
            return Err(AuthorityCommitModelError::InvalidPayloadMagic);
        }
        let version = u16::from_be_bytes([bytes[8], bytes[9]]);
        if version != AUTHORITY_TIMESTAMP_STATE_CODEC_VERSION {
            return Err(AuthorityCommitModelError::UnknownCodecVersion(version));
        }
        let bootstrap_reason = AuthorityTimestampBootstrapReason::try_from_u8(bytes[10])?;
        let high_water = CommitWriteTimestampUs::try_from_i128(i64::from_be_bytes(
            bytes[12..20].try_into().expect("fixed-size timestamp slice"),
        ) as i128)?;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[20..52]);
        let phase = match bytes[11] {
            PHASE_BOOTSTRAP_IDLE => {
                if digest != [0u8; 32] {
                    return Err(AuthorityCommitModelError::NonCanonicalBootstrapPayload);
                }
                AuthorityTimestampPhase::Idle { last_completed: None }
            }
            PHASE_ACTIVE => AuthorityTimestampPhase::Active {
                intent: AuthorityCommitIntentDigest::from_sealed_commit_digest(digest),
            },
            PHASE_COMPLETED_IDLE => AuthorityTimestampPhase::Idle {
                last_completed: Some(
                    AuthorityCommitIntentDigest::from_sealed_commit_digest(digest),
                ),
            },
            phase => return Err(AuthorityCommitModelError::UnknownPhase(phase)),
        };
        Ok(Self {
            revision: AuthorityTimestampRevision::try_from_i64(revision)?,
            bootstrap_reason,
            high_water,
            phase,
        })
    }

    /// Observes a durable intent after restart without allocating anything.
    pub fn observe_intent(
        self,
        key: AuthorityTimestampKey,
        intent: AuthorityCommitIntentDigest,
    ) -> AuthorityIntentObservation {
        match self.phase {
            AuthorityTimestampPhase::Active { intent: active } if active == intent => {
                AuthorityIntentObservation::Active(AuthorityTimestampLease {
                    key,
                    active_revision: self.revision,
                    intent,
                    timestamp: self.high_water,
                })
            }
            AuthorityTimestampPhase::Active { intent: active } => {
                AuthorityIntentObservation::BlockedByActive {
                    active_intent: active,
                    timestamp: self.high_water,
                }
            }
            AuthorityTimestampPhase::Idle { last_completed: Some(completed) }
                if completed == intent =>
            {
                AuthorityIntentObservation::Completed {
                    timestamp: self.high_water,
                    revision: self.revision,
                }
            }
            AuthorityTimestampPhase::Idle { last_completed } => {
                AuthorityIntentObservation::Idle { last_completed }
            }
        }
    }

    pub fn seal_reservation(
        self,
        key: AuthorityTimestampKey,
        intent: AuthorityCommitIntentDigest,
        clock_sample: AuthorityClockSampleUs,
    ) -> Result<SealedAuthorityTimestampReservation, AuthorityCommitModelError> {
        if let AuthorityTimestampPhase::Active { intent: active_intent } = self.phase {
            return Err(AuthorityCommitModelError::IntentAlreadyActive {
                active_intent,
            });
        }
        let successor = self
            .high_water
            .as_i64()
            .checked_add(1)
            .ok_or(AuthorityCommitModelError::TimestampHighWaterExhausted(
                self.high_water.as_i64(),
            ))?;
        let allocated = successor.max(clock_sample.as_i64());
        let timestamp = CommitWriteTimestampUs::try_from_i128(allocated as i128)?;
        let candidate = Self {
            revision: self.revision.checked_next()?,
            bootstrap_reason: self.bootstrap_reason,
            high_water: timestamp,
            phase: AuthorityTimestampPhase::Active { intent },
        };
        let lease = AuthorityTimestampLease {
            key,
            active_revision: candidate.revision,
            intent,
            timestamp,
        };
        Ok(SealedAuthorityTimestampReservation {
            key,
            expected: self,
            candidate,
            clock_sample,
            lease,
        })
    }

    pub fn seal_completion(
        self,
        key: AuthorityTimestampKey,
        lease: AuthorityTimestampLease,
    ) -> Result<SealedAuthorityTimestampCompletion, AuthorityCommitModelError> {
        if key != lease.key
            || self.revision != lease.active_revision
            || self.high_water != lease.timestamp
            || self.phase != (AuthorityTimestampPhase::Active { intent: lease.intent })
        {
            return Err(AuthorityCommitModelError::LeaseDoesNotMatchActiveState);
        }
        let candidate = Self {
            revision: self.revision.checked_next()?,
            bootstrap_reason: self.bootstrap_reason,
            high_water: self.high_water,
            phase: AuthorityTimestampPhase::Idle {
                last_completed: Some(lease.intent),
            },
        };
        Ok(SealedAuthorityTimestampCompletion {
            key,
            expected: self,
            candidate,
            lease,
        })
    }
}

/// Explicit bootstrap request. Missing rows are never initialized from a
/// default clock or guessed timestamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityTimestampBootstrap {
    key: AuthorityTimestampKey,
    reason: AuthorityTimestampBootstrapReason,
    candidate: StoredAuthorityTimestampState,
}

impl AuthorityTimestampBootstrap {
    pub const fn new(
        key: AuthorityTimestampKey,
        initial_high_water: CommitWriteTimestampUs,
        reason: AuthorityTimestampBootstrapReason,
    ) -> Self {
        Self {
            key,
            reason,
            candidate: StoredAuthorityTimestampState {
                revision: AuthorityTimestampRevision::initial(),
                bootstrap_reason: reason,
                high_water: initial_high_water,
                phase: AuthorityTimestampPhase::Idle { last_completed: None },
            },
        }
    }

    pub const fn key(self) -> AuthorityTimestampKey {
        self.key
    }

    pub const fn reason(self) -> AuthorityTimestampBootstrapReason {
        self.reason
    }

    pub const fn candidate(self) -> StoredAuthorityTimestampState {
        self.candidate
    }

    pub fn classify_lwt_observation(
        self,
        applied: bool,
        current: StoredAuthorityTimestampState,
    ) -> Result<AuthorityTimestampWriteOutcome, AuthorityCommitModelError> {
        classify_cas(applied, current, self.candidate)
    }
}

/// Capability proving which exact intent owns an allocated timestamp.
///
/// ```compile_fail
/// use psy_node_core::store::authority_commit::AuthorityTimestampLease;
/// let _forged = AuthorityTimestampLease { /* private fields */ };
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AuthorityTimestampLease {
    key: AuthorityTimestampKey,
    active_revision: AuthorityTimestampRevision,
    intent: AuthorityCommitIntentDigest,
    timestamp: CommitWriteTimestampUs,
}

impl AuthorityTimestampLease {
    pub const fn key(self) -> AuthorityTimestampKey {
        self.key
    }

    pub const fn active_revision(self) -> AuthorityTimestampRevision {
        self.active_revision
    }

    pub const fn intent(self) -> AuthorityCommitIntentDigest {
        self.intent
    }

    pub const fn timestamp(self) -> CommitWriteTimestampUs {
        self.timestamp
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityIntentObservation {
    Idle { last_completed: Option<AuthorityCommitIntentDigest> },
    Active(AuthorityTimestampLease),
    Completed {
        timestamp: CommitWriteTimestampUs,
        revision: AuthorityTimestampRevision,
    },
    BlockedByActive {
        active_intent: AuthorityCommitIntentDigest,
        timestamp: CommitWriteTimestampUs,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedAuthorityTimestampReservation {
    key: AuthorityTimestampKey,
    expected: StoredAuthorityTimestampState,
    candidate: StoredAuthorityTimestampState,
    clock_sample: AuthorityClockSampleUs,
    lease: AuthorityTimestampLease,
}

impl SealedAuthorityTimestampReservation {
    pub const fn key(self) -> AuthorityTimestampKey {
        self.key
    }

    pub const fn expected(self) -> StoredAuthorityTimestampState {
        self.expected
    }

    pub const fn candidate(self) -> StoredAuthorityTimestampState {
        self.candidate
    }

    pub const fn clock_sample(self) -> AuthorityClockSampleUs {
        self.clock_sample
    }

    pub const fn lease(self) -> AuthorityTimestampLease {
        self.lease
    }

    pub fn classify_lwt_observation(
        self,
        applied: bool,
        current: StoredAuthorityTimestampState,
    ) -> Result<AuthorityTimestampWriteOutcome, AuthorityCommitModelError> {
        classify_cas(applied, current, self.candidate)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedAuthorityTimestampCompletion {
    key: AuthorityTimestampKey,
    expected: StoredAuthorityTimestampState,
    candidate: StoredAuthorityTimestampState,
    lease: AuthorityTimestampLease,
}

impl SealedAuthorityTimestampCompletion {
    pub const fn key(self) -> AuthorityTimestampKey {
        self.key
    }

    pub const fn expected(self) -> StoredAuthorityTimestampState {
        self.expected
    }

    pub const fn candidate(self) -> StoredAuthorityTimestampState {
        self.candidate
    }

    pub const fn lease(self) -> AuthorityTimestampLease {
        self.lease
    }

    pub fn classify_lwt_observation(
        self,
        applied: bool,
        current: StoredAuthorityTimestampState,
    ) -> Result<AuthorityTimestampWriteOutcome, AuthorityCommitModelError> {
        classify_cas(applied, current, self.candidate)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityTimestampReadState {
    Uninitialized,
    Current(StoredAuthorityTimestampState),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityTimestampWriteOutcome {
    Applied(StoredAuthorityTimestampState),
    Idempotent(StoredAuthorityTimestampState),
    Conflict(StoredAuthorityTimestampState),
}

fn classify_cas(
    applied: bool,
    current: StoredAuthorityTimestampState,
    candidate: StoredAuthorityTimestampState,
) -> Result<AuthorityTimestampWriteOutcome, AuthorityCommitModelError> {
    if applied {
        if current == candidate {
            Ok(AuthorityTimestampWriteOutcome::Applied(current))
        } else {
            Err(AuthorityCommitModelError::AppliedStateMismatch)
        }
    } else if current == candidate {
        Ok(AuthorityTimestampWriteOutcome::Idempotent(current))
    } else {
        Ok(AuthorityTimestampWriteOutcome::Conflict(current))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityCommitModelError {
    TimestampOutOfRange(TimestampOutOfCqlRange),
    NegativeRevision(i64),
    RevisionOutOfCqlRange(u64),
    RevisionOverflow(u64),
    TimestampHighWaterExhausted(i64),
    InvalidPayloadLength { expected: usize, actual: usize },
    InvalidPayloadMagic,
    UnknownCodecVersion(u16),
    UnknownBootstrapReason(u8),
    UnknownPhase(u8),
    NonCanonicalBootstrapPayload,
    IntentAlreadyActive { active_intent: AuthorityCommitIntentDigest },
    LeaseDoesNotMatchActiveState,
    AppliedStateMismatch,
}

impl fmt::Display for AuthorityCommitModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimestampOutOfRange(error) => error.fmt(formatter),
            Self::NegativeRevision(value) => write!(formatter, "negative authority timestamp revision {value}"),
            Self::RevisionOutOfCqlRange(value) => write!(formatter, "authority timestamp revision {value} exceeds CQL BIGINT"),
            Self::RevisionOverflow(value) => write!(formatter, "authority timestamp revision {value} has no successor"),
            Self::TimestampHighWaterExhausted(value) => write!(formatter, "authority timestamp high-water {value} has no successor"),
            Self::InvalidPayloadLength { expected, actual } => write!(formatter, "authority timestamp payload length {actual}, expected {expected}"),
            Self::InvalidPayloadMagic => formatter.write_str("invalid authority timestamp payload magic"),
            Self::UnknownCodecVersion(version) => write!(formatter, "unknown authority timestamp codec version {version}"),
            Self::UnknownBootstrapReason(reason) => write!(formatter, "unknown authority timestamp bootstrap reason {reason}"),
            Self::UnknownPhase(phase) => write!(formatter, "unknown authority timestamp phase {phase}"),
            Self::NonCanonicalBootstrapPayload => formatter.write_str("bootstrap-idle payload must have a zero digest field"),
            Self::IntentAlreadyActive { active_intent } => write!(formatter, "authority already has active intent {}", hex::encode(active_intent.as_bytes())),
            Self::LeaseDoesNotMatchActiveState => formatter.write_str("timestamp lease does not match the exact active state"),
            Self::AppliedStateMismatch => formatter.write_str("LWT reported applied but durable state differs from the sealed candidate"),
        }
    }
}

impl Error for AuthorityCommitModelError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TimestampOutOfRange(error) => Some(error),
            _ => None,
        }
    }
}

impl From<TimestampOutOfCqlRange> for AuthorityCommitModelError {
    fn from(value: TimestampOutOfCqlRange) -> Self {
        Self::TimestampOutOfRange(value)
    }
}

#[cfg(test)]
mod tests {
    use psy_core::constants::chain_id::PsyChainNetworkType;

    use super::*;

    fn key() -> AuthorityTimestampKey {
        AuthorityTimestampKey::new(
            NetworkId::from_network_type(PsyChainNetworkType::LocalDevnet),
            AuthorityScope::Realm { realm_id: 7, realm_sub_id: 2 },
        )
    }

    fn timestamp(value: i64) -> CommitWriteTimestampUs {
        CommitWriteTimestampUs::try_from_i128(value as i128).unwrap()
    }

    fn sample(value: i64) -> AuthorityClockSampleUs {
        AuthorityClockSampleUs::try_from_i128(value as i128).unwrap()
    }

    fn digest(value: u8) -> AuthorityCommitIntentDigest {
        AuthorityCommitIntentDigest::from_sealed_commit_digest([value; 32])
    }

    fn bootstrap() -> AuthorityTimestampBootstrap {
        AuthorityTimestampBootstrap::new(
            key(),
            timestamp(100),
            AuthorityTimestampBootstrapReason::GenesisNative,
        )
    }

    #[test]
    fn allocates_strictly_after_high_water_or_at_clock_sample() {
        let initial = bootstrap().candidate();
        let first = initial.seal_reservation(key(), digest(1), sample(90)).unwrap();
        assert_eq!(first.lease().timestamp().as_i64(), 101);
        assert_eq!(first.candidate().revision().get(), 1);

        let completed = first
            .candidate()
            .seal_completion(key(), first.lease())
            .unwrap()
            .candidate();
        let second = completed.seal_reservation(key(), digest(2), sample(500)).unwrap();
        assert_eq!(second.lease().timestamp().as_i64(), 500);
        assert_eq!(second.candidate().revision().get(), 3);
    }

    #[test]
    fn restart_recovers_exact_lease_and_blocks_other_intent() {
        let reservation = bootstrap()
            .candidate()
            .seal_reservation(key(), digest(1), sample(200))
            .unwrap();
        let active = reservation.candidate();
        assert_eq!(
            active.observe_intent(key(), digest(1)),
            AuthorityIntentObservation::Active(reservation.lease())
        );
        assert_eq!(
            active.observe_intent(key(), digest(2)),
            AuthorityIntentObservation::BlockedByActive {
                active_intent: digest(1),
                timestamp: timestamp(200),
            }
        );
        assert!(matches!(
            active.seal_reservation(key(), digest(2), sample(201)),
            Err(AuthorityCommitModelError::IntentAlreadyActive { .. })
        ));
    }

    #[test]
    fn completion_requires_exact_lease_and_is_observable_after_restart() {
        let reservation = bootstrap()
            .candidate()
            .seal_reservation(key(), digest(1), sample(200))
            .unwrap();
        let completion = reservation
            .candidate()
            .seal_completion(key(), reservation.lease())
            .unwrap();
        assert_eq!(
            completion.candidate().observe_intent(key(), digest(1)),
            AuthorityIntentObservation::Completed {
                timestamp: timestamp(200),
                revision: AuthorityTimestampRevision::try_new(2).unwrap(),
            }
        );

        let other_key = AuthorityTimestampKey::new(key().network(), AuthorityScope::Coordinator);
        let wrong_lease = AuthorityTimestampLease {
            key: other_key,
            ..reservation.lease()
        };
        assert_eq!(
            reservation
                .candidate()
                .seal_completion(key(), wrong_lease),
            Err(AuthorityCommitModelError::LeaseDoesNotMatchActiveState)
        );
    }

    #[test]
    fn codec_round_trip_is_fixed_and_fail_closed() {
        let reservation = bootstrap()
            .candidate()
            .seal_reservation(key(), digest(7), sample(200))
            .unwrap();
        for state in [bootstrap().candidate(), reservation.candidate()] {
            let bytes = state.encode_canonical();
            assert_eq!(bytes.len(), AUTHORITY_TIMESTAMP_STATE_V1_LEN);
            assert_eq!(
                StoredAuthorityTimestampState::decode_persisted(state.revision().as_i64(), &bytes)
                    .unwrap(),
                state
            );
        }

        let bytes = bootstrap().candidate().encode_canonical();
        assert!(matches!(
            StoredAuthorityTimestampState::decode_persisted(0, &bytes[..51]),
            Err(AuthorityCommitModelError::InvalidPayloadLength { .. })
        ));
        let mut unknown_version = bytes;
        unknown_version[8..10].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(
            StoredAuthorityTimestampState::decode_persisted(0, &unknown_version),
            Err(AuthorityCommitModelError::UnknownCodecVersion(2))
        );
        let mut unknown_reason = bytes;
        unknown_reason[10] = 99;
        assert_eq!(
            StoredAuthorityTimestampState::decode_persisted(0, &unknown_reason),
            Err(AuthorityCommitModelError::UnknownBootstrapReason(99))
        );
        let mut non_canonical = bytes;
        non_canonical[20] = 1;
        assert_eq!(
            StoredAuthorityTimestampState::decode_persisted(0, &non_canonical),
            Err(AuthorityCommitModelError::NonCanonicalBootstrapPayload)
        );
        assert!(matches!(
            StoredAuthorityTimestampState::decode_persisted(-1, &bytes),
            Err(AuthorityCommitModelError::NegativeRevision(-1))
        ));

        let cutover = AuthorityTimestampBootstrap::new(
            key(),
            timestamp(100),
            AuthorityTimestampBootstrapReason::ControlledWriterCutover,
        );
        assert_eq!(
            bootstrap()
                .classify_lwt_observation(false, cutover.candidate())
                .unwrap(),
            AuthorityTimestampWriteOutcome::Conflict(cutover.candidate())
        );
    }

    #[test]
    fn response_loss_is_idempotent_but_aba_is_not() {
        let reservation = bootstrap()
            .candidate()
            .seal_reservation(key(), digest(1), sample(200))
            .unwrap();
        assert_eq!(
            reservation
                .classify_lwt_observation(false, reservation.candidate())
                .unwrap(),
            AuthorityTimestampWriteOutcome::Idempotent(reservation.candidate())
        );

        let completion = reservation
            .candidate()
            .seal_completion(key(), reservation.lease())
            .unwrap();
        let later = completion
            .candidate()
            .seal_reservation(key(), digest(2), sample(300))
            .unwrap();
        assert_eq!(
            reservation
                .classify_lwt_observation(false, later.candidate())
                .unwrap(),
            AuthorityTimestampWriteOutcome::Conflict(later.candidate())
        );
    }

    #[test]
    fn cql_numeric_boundaries_fail_closed() {
        assert!(AuthorityTimestampRevision::try_new(i64::MAX as u64).is_ok());
        assert!(matches!(
            AuthorityTimestampRevision::try_new(i64::MAX as u64 + 1),
            Err(AuthorityCommitModelError::RevisionOutOfCqlRange(_))
        ));
        let maximum = AuthorityTimestampBootstrap::new(
            key(),
            timestamp(i64::MAX),
            AuthorityTimestampBootstrapReason::ControlledWriterCutover,
        );
        assert_eq!(
            maximum
                .candidate()
                .seal_reservation(key(), digest(1), sample(i64::MAX)),
            Err(AuthorityCommitModelError::TimestampHighWaterExhausted(i64::MAX))
        );
    }
}

/// Durable boundary for the per-authority commit timestamp allocator.
///
/// Defined here rather than beside the Scylla adapter because `commit_state`
/// reserves a timestamp and must not name a driver.  Implementations must keep
/// the LWT semantics the sealed reservation and completion model above expresses:
/// a write only lands against the exact expected revision.
#[async_trait::async_trait]
pub trait AuthorityCommitTimestampStore: Send + Sync {
    async fn read_timestamp_state(
        &self,
        key: AuthorityTimestampKey,
    ) -> anyhow::Result<AuthorityTimestampReadState>;

    /// Materialise the first row for an authority.
    async fn bootstrap_timestamp_state(
        &self,
        bootstrap: &AuthorityTimestampBootstrap,
    ) -> anyhow::Result<AuthorityTimestampWriteOutcome>;

    /// Take the lease.  Fails closed when another writer holds it.
    async fn reserve_timestamp(
        &self,
        reservation: &SealedAuthorityTimestampReservation,
    ) -> anyhow::Result<AuthorityTimestampWriteOutcome>;

    /// Release the lease once the commit it covers is durable.
    async fn complete_timestamp(
        &self,
        completion: &SealedAuthorityTimestampCompletion,
    ) -> anyhow::Result<AuthorityTimestampWriteOutcome>;
}
