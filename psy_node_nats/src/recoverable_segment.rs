//! Default-off stream-segment and finite-retention contract for branch-exact
//! recoverable queues.
//!
//! The legacy JetStream stream contains both ephemeral checkpoint queues and
//! worker queues. Changing its retention would therefore change unrelated
//! production behavior. This module derives a disjoint V2 namespace and one
//! bounded stream per segment. It deliberately does not create, rotate, or
//! delete streams; the durable active-segment binding and VERIFIED GC receipt
//! are separate milestones.

use std::{error::Error, fmt, num::NonZeroU64, time::Duration};

use async_nats::jetstream::stream::{
    Compression, Config as StreamConfig, DiscardPolicy, RetentionPolicy,
    Info as StreamInfo, StorageType,
};
use psy_data::protocol::chain_context::AuthorityScope;
use psy_node_core::store::pending_generation_identity::PendingGenerationLedgerKey;
use sha2::{Digest, Sha256};

const CONTRACT_DOMAIN: &[u8] = b"psy/rollback/recoverable-nats-segment/v1";
const INSTANCE_DOMAIN: &[u8] = b"psy/rollback/recoverable-nats-stream-instance/v1";
const V2_RESERVED_SUBJECT_ROOT: &str = "PSY_BEQ_V2";
const MAX_BASE_NAMESPACE_BYTES: usize = 96;
const MAX_SUBJECT_SUFFIX_BYTES: usize = 256;
const MAX_LIVE_SEGMENTS: u16 = 64;
const MAX_STREAM_REPLICAS: usize = 5;
const MAX_CONSUMERS_PER_SEGMENT: i32 = 1_000_000;
const RETRY_DEDUPLICATION_WINDOW: Duration = Duration::from_secs(120);

/// Maximum encoded queue item admitted by the current capture contract plus
/// room for the future Data/Seal envelope.
pub const RECOVERABLE_NATS_MAX_MESSAGE_BYTES: i32 = 64 * 1024 * 1024 + 4096;
pub const RECOVERABLE_NATS_CAPACITY_HEADROOM_BYTES: i64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct RecoverableNatsSegmentId(NonZeroU64);

impl RecoverableNatsSegmentId {
    pub const fn try_new(value: u64) -> Result<Self, RecoverableNatsSegmentError> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(RecoverableNatsSegmentError::ZeroSegmentId),
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RecoverableNatsSegmentContractDigest([u8; 32]);

impl RecoverableNatsSegmentContractDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, RecoverableNatsSegmentError> {
        if bytes == [0; 32] {
            Err(RecoverableNatsSegmentError::EmptyContractDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Opaque result of structurally comparing the complete expected stream
/// contract with a supplied configuration.
///
/// This token deliberately does **not** claim that the configuration came
/// from a live NATS server. The c2b1 ledger uses it to prevent arbitrary
/// stream addresses/config shapes; activation must additionally obtain and
/// compare live server metadata before reserving a generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructurallyValidatedRecoverableNatsSegment {
    segment: RecoverableNatsStreamSegment,
}

/// Stable identity of one server-created stream incarnation. Recreating the
/// same named stream with the same config yields a different value because
/// JetStream's server-provided creation timestamp is committed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RecoverableNatsStreamInstanceId([u8; 32]);

impl RecoverableNatsStreamInstanceId {
    pub fn try_from_bytes(bytes: [u8; 32]) -> Result<Self, RecoverableNatsSegmentError> {
        if bytes == [0; 32] {
            Err(RecoverableNatsSegmentError::InvalidInstanceIdentity)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact state snapshot bound to a live or sealed stream observation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RecoverableNatsStreamStateSnapshot {
    messages: u64,
    bytes: u64,
    first_sequence: u64,
    last_sequence: u64,
    consumer_count: u64,
    subject_count: u64,
}

impl RecoverableNatsStreamStateSnapshot {
    pub fn try_new(
        messages: u64,
        bytes: u64,
        first_sequence: u64,
        last_sequence: u64,
        consumer_count: u64,
        subject_count: u64,
    ) -> Result<Self, RecoverableNatsSegmentError> {
        let snapshot = Self {
            messages,
            bytes,
            first_sequence,
            last_sequence,
            consumer_count,
            subject_count,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub const fn messages(self) -> u64 {
        self.messages
    }

    pub const fn bytes(self) -> u64 {
        self.bytes
    }

    pub const fn first_sequence(self) -> u64 {
        self.first_sequence
    }

    pub const fn last_sequence(self) -> u64 {
        self.last_sequence
    }

    pub const fn consumer_count(self) -> u64 {
        self.consumer_count
    }

    pub const fn subject_count(self) -> u64 {
        self.subject_count
    }

    fn from_info(info: &StreamInfo) -> Result<Self, RecoverableNatsSegmentError> {
        if info.state.deleted_count.unwrap_or(0) != 0
            || info.state.deleted.as_ref().is_some_and(|values| !values.is_empty())
        {
            return Err(RecoverableNatsSegmentError::StreamHasDeletedMessages);
        }
        Self::try_new(
            info.state.messages,
            info.state.bytes,
            info.state.first_sequence,
            info.state.last_sequence,
            u64::try_from(info.state.consumer_count)
                .map_err(|_| RecoverableNatsSegmentError::StreamStateOverflow)?,
            info.state.subjects_count,
        )
    }

    fn validate(self) -> Result<(), RecoverableNatsSegmentError> {
        let contiguous = if self.messages == 0 {
            self.first_sequence == 0 && self.last_sequence == 0 && self.subject_count == 0
        } else {
            self.first_sequence == 1
                && self.last_sequence == self.messages
                && self.subject_count > 0
                && self.subject_count <= self.messages
        };
        if !contiguous {
            return Err(RecoverableNatsSegmentError::StreamSequenceGap);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AttestedRecoverableNatsStreamInstance {
    segment: RecoverableNatsStreamSegment,
    instance_id: RecoverableNatsStreamInstanceId,
    created_unix_nanos: i128,
    state: RecoverableNatsStreamStateSnapshot,
}

/// Exact observation of the writable stream contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveRecoverableNatsStreamInstance(AttestedRecoverableNatsStreamInstance);

impl LiveRecoverableNatsStreamInstance {
    pub const fn segment(&self) -> &RecoverableNatsStreamSegment {
        &self.0.segment
    }

    pub const fn instance_id(&self) -> RecoverableNatsStreamInstanceId {
        self.0.instance_id
    }

    pub const fn state(&self) -> RecoverableNatsStreamStateSnapshot {
        self.0.state
    }
}

/// Exact observation of the same contract after JetStream has irreversibly
/// fenced new writes with `sealed=true`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedRecoverableNatsStreamInstance(AttestedRecoverableNatsStreamInstance);

impl SealedRecoverableNatsStreamInstance {
    pub const fn segment(&self) -> &RecoverableNatsStreamSegment {
        &self.0.segment
    }

    pub const fn instance_id(&self) -> RecoverableNatsStreamInstanceId {
        self.0.instance_id
    }

    pub const fn state(&self) -> RecoverableNatsStreamStateSnapshot {
        self.0.state
    }
}

impl StructurallyValidatedRecoverableNatsSegment {
    pub const fn segment(&self) -> &RecoverableNatsStreamSegment {
        &self.segment
    }
}

/// Capacity policy for one stream segment and the finite live-segment set.
///
/// `max_age=0` is intentional: DiscardNew protects capacity limits but does
/// not stop age-based eviction. Space is bounded by `max_stream_bytes` and
/// `max_live_segments`; a whole old stream may be deleted only after a future
/// exact member manifest has produced a VERIFIED GC receipt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RecoverableNatsRetentionContract {
    stream_replicas: usize,
    max_stream_bytes: i64,
    generation_admission_budget_bytes: i64,
    max_live_segments: u16,
    max_consumers_per_segment: i32,
}

impl RecoverableNatsRetentionContract {
    pub fn try_new(
        stream_replicas: usize,
        max_stream_bytes: i64,
        generation_admission_budget_bytes: i64,
        max_live_segments: u16,
        max_consumers_per_segment: i32,
    ) -> Result<Self, RecoverableNatsSegmentError> {
        if !(3..=MAX_STREAM_REPLICAS).contains(&stream_replicas) {
            return Err(RecoverableNatsSegmentError::InvalidReplicaCount(
                stream_replicas,
            ));
        }
        if max_stream_bytes <= 0 {
            return Err(RecoverableNatsSegmentError::InvalidStreamCapacity(
                max_stream_bytes,
            ));
        }
        let minimum_generation_admission_budget = i64::from(RECOVERABLE_NATS_MAX_MESSAGE_BYTES)
            .checked_add(RECOVERABLE_NATS_CAPACITY_HEADROOM_BYTES)
            .ok_or(RecoverableNatsSegmentError::CapacityOverflow)?;
        let minimum_stream_capacity = generation_admission_budget_bytes
            .checked_add(RECOVERABLE_NATS_CAPACITY_HEADROOM_BYTES)
            .ok_or(RecoverableNatsSegmentError::CapacityOverflow)?;
        if generation_admission_budget_bytes < minimum_generation_admission_budget
            || minimum_stream_capacity > max_stream_bytes
        {
            return Err(
                RecoverableNatsSegmentError::InvalidGenerationAdmissionBudget {
                    budget: generation_admission_budget_bytes,
                capacity: max_stream_bytes,
                },
            );
        }
        if !(2..=MAX_LIVE_SEGMENTS).contains(&max_live_segments) {
            return Err(RecoverableNatsSegmentError::InvalidLiveSegmentLimit(
                max_live_segments,
            ));
        }
        if !(1..=MAX_CONSUMERS_PER_SEGMENT).contains(&max_consumers_per_segment) {
            return Err(RecoverableNatsSegmentError::InvalidConsumerLimit(
                max_consumers_per_segment,
            ));
        }
        let contract = Self {
            stream_replicas,
            max_stream_bytes,
            generation_admission_budget_bytes,
            max_live_segments,
            max_consumers_per_segment,
        };
        contract.max_cluster_replicated_message_bytes()?;
        Ok(contract)
    }

    pub const fn stream_replicas(self) -> usize {
        self.stream_replicas
    }

    pub const fn max_stream_bytes(self) -> i64 {
        self.max_stream_bytes
    }

    /// Provisional per-generation admission budget. This is not yet a proof
    /// that a complete generation fits: c2b2 must bind an envelope/source
    /// count based maximum and charge every encoded Data/Seal byte.
    pub const fn generation_admission_budget_bytes(self) -> i64 {
        self.generation_admission_budget_bytes
    }

    pub const fn max_live_segments(self) -> u16 {
        self.max_live_segments
    }

    pub const fn max_consumers_per_segment(self) -> i32 {
        self.max_consumers_per_segment
    }

    /// Upper bound for replicated message bytes admitted by all live
    /// segments. JetStream file/index/consumer metadata and filesystem
    /// amplification are deliberately excluded and must be measured by h22e.
    pub fn max_cluster_replicated_message_bytes(
        self,
    ) -> Result<u128, RecoverableNatsSegmentError> {
        let logical = u128::try_from(self.max_stream_bytes)
            .map_err(|_| RecoverableNatsSegmentError::CapacityOverflow)?
            .checked_mul(u128::from(self.max_live_segments))
            .ok_or(RecoverableNatsSegmentError::CapacityOverflow)?;
        logical
            .checked_mul(self.stream_replicas as u128)
            .ok_or(RecoverableNatsSegmentError::CapacityOverflow)
    }
}

/// Exact, non-overlapping address and normalized stream contract for one V2
/// segment. Construction accepts no dynamic stream name or subject prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverableNatsStreamSegment {
    base_namespace: String,
    generation_key: PendingGenerationLedgerKey,
    segment_id: RecoverableNatsSegmentId,
    stream_name: String,
    subject_prefix: String,
    retention: RecoverableNatsRetentionContract,
    digest: RecoverableNatsSegmentContractDigest,
}

impl RecoverableNatsStreamSegment {
    pub fn try_new(
        base_namespace: impl Into<String>,
        generation_key: PendingGenerationLedgerKey,
        segment_id: RecoverableNatsSegmentId,
        retention: RecoverableNatsRetentionContract,
    ) -> Result<Self, RecoverableNatsSegmentError> {
        let base_namespace = base_namespace.into();
        validate_base_namespace(&base_namespace)?;
        // Full byte encoding is injective; unlike dot-to-underscore or a short
        // hash it cannot alias two accepted namespaces such as `a.b`/`a_b`.
        let base_tag = hex::encode(base_namespace.as_bytes());
        let authority_tag = authority_tag(generation_key);
        let stream_name = format!(
            "PSY_BEQ_V2_{base_tag}_{authority_tag}_SG{}",
            segment_id.get()
        );
        // A global reserved root plus the injective base tag prevents one
        // configured base from capturing another base's V2 traffic through a
        // legacy `<base>.>` wildcard (for example `a_beq_v2.>`).
        let subject_prefix = format!(
            "{V2_RESERVED_SUBJECT_ROOT}.{base_tag}.{authority_tag}.SG{}",
            segment_id.get()
        );
        if stream_name.len() > 255 || subject_prefix.len() > 255 {
            return Err(RecoverableNatsSegmentError::AddressTooLong);
        }
        let normalized = normalized_stream_config(&stream_config_for(
            &stream_name,
            &subject_prefix,
            segment_id,
            retention,
        ))?;
        let digest = contract_digest(
            &base_namespace,
            generation_key,
            segment_id,
            retention,
            &normalized,
        )?;
        Ok(Self {
            base_namespace,
            generation_key,
            segment_id,
            stream_name,
            subject_prefix,
            retention,
            digest,
        })
    }

    pub fn base_namespace(&self) -> &str {
        &self.base_namespace
    }

    pub const fn generation_key(&self) -> PendingGenerationLedgerKey {
        self.generation_key
    }

    pub const fn segment_id(&self) -> RecoverableNatsSegmentId {
        self.segment_id
    }

    pub fn stream_name(&self) -> &str {
        &self.stream_name
    }

    pub fn subject_prefix(&self) -> &str {
        &self.subject_prefix
    }

    pub const fn retention(&self) -> RecoverableNatsRetentionContract {
        self.retention
    }

    pub const fn digest(&self) -> RecoverableNatsSegmentContractDigest {
        self.digest
    }

    pub fn legacy_stream_name(&self) -> String {
        format!("{}_stream", self.base_namespace.replace('.', "_"))
    }

    pub fn legacy_subject_filter(&self) -> String {
        format!("{}.>", self.base_namespace)
    }

    pub fn exact_subject(
        &self,
        suffix: &str,
    ) -> Result<String, RecoverableNatsSegmentError> {
        validate_subject_suffix(suffix)?;
        let subject = format!("{}.{}", self.subject_prefix, suffix);
        if subject.len() > 512 {
            return Err(RecoverableNatsSegmentError::AddressTooLong);
        }
        Ok(subject)
    }

    pub fn stream_config(&self) -> StreamConfig {
        stream_config_for(
            &self.stream_name,
            &self.subject_prefix,
            self.segment_id,
            self.retention,
        )
    }

    /// Exact one-way config used by the future durable segment lifecycle.
    /// This module does not itself execute the update.
    pub fn sealed_stream_config(&self) -> StreamConfig {
        let mut config = self.stream_config();
        config.sealed = true;
        config
    }

    pub fn validate_stream_config_structure(
        &self,
        actual: &StreamConfig,
    ) -> Result<StructurallyValidatedRecoverableNatsSegment, RecoverableNatsSegmentError> {
        let expected = normalized_stream_config(&self.stream_config())?;
        let actual = normalized_stream_config(actual)?;
        if actual != expected {
            return Err(RecoverableNatsSegmentError::StreamContractMismatch);
        }
        Ok(StructurallyValidatedRecoverableNatsSegment {
            segment: self.clone(),
        })
    }

    pub fn attest_live_instance(
        &self,
        info: &StreamInfo,
    ) -> Result<LiveRecoverableNatsStreamInstance, RecoverableNatsSegmentError> {
        let observed = self.attest_instance(info, false)?;
        Ok(LiveRecoverableNatsStreamInstance(observed))
    }

    pub fn attest_sealed_instance(
        &self,
        info: &StreamInfo,
    ) -> Result<SealedRecoverableNatsStreamInstance, RecoverableNatsSegmentError> {
        let observed = self.attest_instance(info, true)?;
        Ok(SealedRecoverableNatsStreamInstance(observed))
    }

    fn attest_instance(
        &self,
        info: &StreamInfo,
        sealed: bool,
    ) -> Result<AttestedRecoverableNatsStreamInstance, RecoverableNatsSegmentError> {
        let expected = if sealed {
            self.sealed_stream_config()
        } else {
            self.stream_config()
        };
        if normalized_stream_config(&info.config)? != normalized_stream_config(&expected)? {
            return Err(RecoverableNatsSegmentError::StreamContractMismatch);
        }
        let created_unix_nanos = info.created.unix_timestamp_nanos();
        if created_unix_nanos <= 0 {
            return Err(RecoverableNatsSegmentError::InvalidStreamCreatedAt);
        }
        let state = RecoverableNatsStreamStateSnapshot::from_info(info)?;
        Ok(self.attest_instance_parts(created_unix_nanos, state))
    }

    fn attest_instance_parts(
        &self,
        created_unix_nanos: i128,
        state: RecoverableNatsStreamStateSnapshot,
    ) -> AttestedRecoverableNatsStreamInstance {
        let mut hasher = Sha256::new();
        hasher.update(INSTANCE_DOMAIN);
        hasher.update(self.digest.as_bytes());
        hasher.update(created_unix_nanos.to_be_bytes());
        AttestedRecoverableNatsStreamInstance {
            segment: self.clone(),
            instance_id: RecoverableNatsStreamInstanceId(hasher.finalize().into()),
            created_unix_nanos,
            state,
        }
    }

    #[cfg(test)]
    pub(crate) fn model_live_instance(
        &self,
        created_unix_nanos: i128,
        state: RecoverableNatsStreamStateSnapshot,
    ) -> LiveRecoverableNatsStreamInstance {
        LiveRecoverableNatsStreamInstance(
            self.attest_instance_parts(created_unix_nanos, state),
        )
    }

    #[cfg(test)]
    pub(crate) fn model_sealed_instance(
        &self,
        created_unix_nanos: i128,
        state: RecoverableNatsStreamStateSnapshot,
    ) -> SealedRecoverableNatsStreamInstance {
        SealedRecoverableNatsStreamInstance(
            self.attest_instance_parts(created_unix_nanos, state),
        )
    }
}

fn stream_config_for(
    stream_name: &str,
    subject_prefix: &str,
    segment_id: RecoverableNatsSegmentId,
    retention: RecoverableNatsRetentionContract,
) -> StreamConfig {
    StreamConfig {
        name: stream_name.to_owned(),
        description: Some(format!(
            "Psy branch-exact recoverable queue segment {}",
            segment_id.get()
        )),
        subjects: vec![format!("{subject_prefix}.>")],
        retention: RetentionPolicy::Limits,
        storage: StorageType::File,
        num_replicas: retention.stream_replicas,
        max_bytes: retention.max_stream_bytes,
        max_messages: -1,
        max_messages_per_subject: -1,
        max_consumers: retention.max_consumers_per_segment,
        max_age: Duration::ZERO,
        max_message_size: RECOVERABLE_NATS_MAX_MESSAGE_BYTES,
        discard: DiscardPolicy::New,
        discard_new_per_subject: false,
        no_ack: false,
        duplicate_window: RETRY_DEDUPLICATION_WINDOW,
        sealed: false,
        allow_rollup: false,
        deny_delete: true,
        deny_purge: true,
        allow_direct: false,
        mirror_direct: false,
        mirror: None,
        sources: None,
        republish: None,
        compression: Some(Compression::None),
        ..Default::default()
    }
}

/// NATS may add `_nats.*` metadata while normalizing an otherwise identical
/// stream. No other server/operator metadata is accepted. Clearing only those
/// reserved entries yields one value used by both equality and digest, so the
/// attestation and durable identity cannot drift as two hand-maintained lists.
fn normalized_stream_config(
    config: &StreamConfig,
) -> Result<StreamConfig, RecoverableNatsSegmentError> {
    if config
        .metadata
        .keys()
        .any(|key| !key.starts_with("_nats."))
    {
        return Err(RecoverableNatsSegmentError::StreamContractMismatch);
    }
    let mut normalized = config.clone();
    normalized.metadata.clear();
    Ok(normalized)
}

fn validate_base_namespace(value: &str) -> Result<(), RecoverableNatsSegmentError> {
    if value.is_empty()
        || value.len() > MAX_BASE_NAMESPACE_BYTES
        || value == V2_RESERVED_SUBJECT_ROOT
        || value.starts_with(&format!("{V2_RESERVED_SUBJECT_ROOT}."))
        || value.starts_with('.')
        || value.ends_with('.')
        || value.contains("..")
        || value.contains('*')
        || value.contains('>')
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(RecoverableNatsSegmentError::InvalidBaseNamespace);
    }
    Ok(())
}

fn validate_subject_suffix(value: &str) -> Result<(), RecoverableNatsSegmentError> {
    if value.is_empty()
        || value.len() > MAX_SUBJECT_SUFFIX_BYTES
        || value.starts_with('.')
        || value.ends_with('.')
        || value.contains("..")
        || value.contains('*')
        || value.contains('>')
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(RecoverableNatsSegmentError::InvalidSubjectSuffix);
    }
    Ok(())
}

fn contract_digest(
    base_namespace: &str,
    generation_key: PendingGenerationLedgerKey,
    segment_id: RecoverableNatsSegmentId,
    retention: RecoverableNatsRetentionContract,
    normalized: &StreamConfig,
) -> Result<RecoverableNatsSegmentContractDigest, RecoverableNatsSegmentError> {
    let normalized_bytes = serde_json::to_vec(normalized)
        .map_err(|_| RecoverableNatsSegmentError::StreamContractEncoding)?;
    let mut hasher = Sha256::new();
    hasher.update(CONTRACT_DOMAIN);
    hash_component(&mut hasher, base_namespace.as_bytes());
    encode_generation_key(&mut hasher, generation_key);
    hasher.update(segment_id.get().to_be_bytes());
    hasher.update(
        retention
            .generation_admission_budget_bytes
            .to_be_bytes(),
    );
    hasher.update(retention.max_live_segments.to_be_bytes());
    hasher.update(RECOVERABLE_NATS_CAPACITY_HEADROOM_BYTES.to_be_bytes());
    hash_component(&mut hasher, &normalized_bytes);
    Ok(RecoverableNatsSegmentContractDigest(hasher.finalize().into()))
}

fn authority_tag(key: PendingGenerationLedgerKey) -> String {
    match key.authority() {
        AuthorityScope::Coordinator => format!("N{}_C", key.network().chain_id()),
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => format!(
            "N{}_R{}_{}",
            key.network().chain_id(),
            realm_id,
            realm_sub_id
        ),
    }
}

fn encode_generation_key(hasher: &mut Sha256, key: PendingGenerationLedgerKey) {
    hasher.update(key.network().chain_id().to_be_bytes());
    match key.authority() {
        AuthorityScope::Coordinator => {
            hasher.update([1]);
            hasher.update(0_u32.to_be_bytes());
            hasher.update(0_u16.to_be_bytes());
        }
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            hasher.update([2]);
            hasher.update(realm_id.to_be_bytes());
            hasher.update(realm_sub_id.to_be_bytes());
        }
    }
}

fn hash_component(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoverableNatsSegmentError {
    ZeroSegmentId,
    EmptyContractDigest,
    InvalidReplicaCount(usize),
    InvalidStreamCapacity(i64),
    InvalidGenerationAdmissionBudget { budget: i64, capacity: i64 },
    InvalidLiveSegmentLimit(u16),
    InvalidConsumerLimit(i32),
    CapacityOverflow,
    InvalidBaseNamespace,
    InvalidSubjectSuffix,
    AddressTooLong,
    StreamContractMismatch,
    StreamContractEncoding,
    InvalidInstanceIdentity,
    InvalidStreamCreatedAt,
    StreamStateOverflow,
    StreamSequenceGap,
    StreamHasDeletedMessages,
}

impl fmt::Display for RecoverableNatsSegmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSegmentId => formatter.write_str("segment id must be non-zero"),
            Self::EmptyContractDigest => formatter.write_str("segment contract digest must be non-zero"),
            Self::InvalidReplicaCount(value) => write!(
                formatter,
                "recoverable stream replicas must be in 3..=5, got {value}"
            ),
            Self::InvalidStreamCapacity(value) => write!(
                formatter,
                "recoverable stream max bytes must be positive, got {value}"
            ),
            Self::InvalidGenerationAdmissionBudget { budget, capacity } => write!(
                formatter,
                "generation admission budget {budget} must hold one admitted message plus headroom and leave headroom within stream capacity {capacity}"
            ),
            Self::InvalidLiveSegmentLimit(value) => write!(
                formatter,
                "max live segment count must be in 2..={MAX_LIVE_SEGMENTS}, got {value}"
            ),
            Self::InvalidConsumerLimit(value) => write!(
                formatter,
                "max consumers per segment must be in 1..={MAX_CONSUMERS_PER_SEGMENT}, got {value}"
            ),
            Self::CapacityOverflow => formatter.write_str("retention capacity calculation overflowed"),
            Self::InvalidBaseNamespace => formatter.write_str("invalid NATS base namespace"),
            Self::InvalidSubjectSuffix => formatter.write_str("invalid exact V2 subject suffix"),
            Self::AddressTooLong => formatter.write_str("derived NATS stream or subject address is too long"),
            Self::StreamContractMismatch => formatter.write_str("recoverable NATS stream contract mismatch"),
            Self::StreamContractEncoding => formatter.write_str("recoverable NATS stream contract encoding failed"),
            Self::InvalidInstanceIdentity => {
                formatter.write_str("recoverable NATS stream instance identity must be non-zero")
            }
            Self::InvalidStreamCreatedAt => formatter.write_str("recoverable NATS stream creation timestamp is invalid"),
            Self::StreamStateOverflow => formatter.write_str("recoverable NATS stream state cannot be represented canonically"),
            Self::StreamSequenceGap => formatter.write_str("recoverable NATS stream contains a missing or truncated sequence"),
            Self::StreamHasDeletedMessages => formatter.write_str("recoverable NATS stream reports deleted messages"),
        }
    }
}

impl Error for RecoverableNatsSegmentError {}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use bytes::Bytes;

    use super::*;

    fn coordinator_key() -> PendingGenerationLedgerKey {
        PendingGenerationLedgerKey::new(
            psy_data::protocol::canonical_chain::NetworkId::try_from_chain_id(1337).unwrap(),
            AuthorityScope::Coordinator,
        )
    }

    fn retention() -> RecoverableNatsRetentionContract {
        RecoverableNatsRetentionContract::try_new(
            3,
            8 * 1024 * 1024 * 1024,
            3 * 1024 * 1024 * 1024,
            3,
            16,
        )
        .unwrap()
    }

    fn segment(id: u64) -> RecoverableNatsStreamSegment {
        RecoverableNatsStreamSegment::try_new(
            "psy.mainnet",
            coordinator_key(),
            RecoverableNatsSegmentId::try_new(id).unwrap(),
            retention(),
        )
        .unwrap()
    }

    #[test]
    fn segment_and_subject_identity_are_deterministic_and_disjoint() {
        let first = segment(7);
        let same = segment(7);
        let next = segment(8);
        assert_eq!(first, same);
        assert!(first.stream_name().starts_with("PSY_BEQ_V2_"));
        assert!(first.stream_name().ends_with("_SG7"));
        assert_eq!(
            first.subject_prefix(),
            "PSY_BEQ_V2.7073792e6d61696e6e6574.N1337_C.SG7"
        );
        assert_ne!(first.stream_name(), next.stream_name());
        assert_ne!(first.subject_prefix(), next.subject_prefix());
        assert_ne!(first.digest(), next.digest());
        assert_ne!(first.stream_name(), first.legacy_stream_name());
        assert!(!first.subject_prefix().starts_with("psy.mainnet."));
        assert_eq!(first.legacy_subject_filter(), "psy.mainnet.>");

        let exact = first
            .exact_subject("coord.r0.rs0.p100.topic1.g0")
            .unwrap();
        assert_eq!(
            exact,
            "PSY_BEQ_V2.7073792e6d61696e6e6574.N1337_C.SG7.coord.r0.rs0.p100.topic1.g0"
        );
        assert!(!exact.starts_with("psy.mainnet."));

        let dot = RecoverableNatsStreamSegment::try_new(
            "a.b",
            coordinator_key(),
            RecoverableNatsSegmentId::try_new(1).unwrap(),
            retention(),
        )
        .unwrap();
        let underscore = RecoverableNatsStreamSegment::try_new(
            "a_b",
            coordinator_key(),
            RecoverableNatsSegmentId::try_new(1).unwrap(),
            retention(),
        )
        .unwrap();
        assert_ne!(dot.stream_name(), underscore.stream_name());
        assert_ne!(dot.subject_prefix(), underscore.subject_prefix());

        let legacy_capture_candidate = RecoverableNatsStreamSegment::try_new(
            "a_beq_v2",
            coordinator_key(),
            RecoverableNatsSegmentId::try_new(1).unwrap(),
            retention(),
        )
        .unwrap();
        assert!(!dot.subject_prefix().starts_with("a_beq_v2."));
        assert_ne!(dot.subject_prefix(), legacy_capture_candidate.subject_prefix());
    }

    #[test]
    fn physical_segment_identity_is_scoped_by_network_and_authority() {
        let coordinator = segment(7);
        let realm_key = PendingGenerationLedgerKey::new(
            psy_data::protocol::canonical_chain::NetworkId::try_from_chain_id(1337).unwrap(),
            AuthorityScope::Realm {
                realm_id: 3,
                realm_sub_id: 2,
            },
        );
        let realm = RecoverableNatsStreamSegment::try_new(
            "psy.mainnet",
            realm_key,
            RecoverableNatsSegmentId::try_new(7).unwrap(),
            retention(),
        )
        .unwrap();

        assert_ne!(coordinator.stream_name(), realm.stream_name());
        assert_ne!(coordinator.subject_prefix(), realm.subject_prefix());
        assert_ne!(coordinator.digest(), realm.digest());
        assert!(realm.stream_name().contains("_N1337_R3_2_"));
        assert!(realm.subject_prefix().contains(".N1337_R3_2."));
    }

    #[test]
    fn retention_has_a_finite_replicated_message_budget_and_generation_admission_budget() {
        let contract = retention();
        assert_eq!(contract.stream_replicas(), 3);
        assert_eq!(contract.max_live_segments(), 3);
        assert_eq!(contract.max_consumers_per_segment(), 16);
        assert_eq!(
            contract.max_cluster_replicated_message_bytes().unwrap(),
            72_u128 * 1024 * 1024 * 1024
        );

        for invalid in [0, 1, 6] {
            assert!(matches!(
                RecoverableNatsRetentionContract::try_new(
                    invalid,
                    256 * 1024 * 1024,
                    128 * 1024 * 1024,
                    2,
                    16,
                ),
                Err(RecoverableNatsSegmentError::InvalidReplicaCount(_))
            ));
        }
        for invalid in [0, 1, 65] {
            assert!(matches!(
                RecoverableNatsRetentionContract::try_new(
                    3,
                    256 * 1024 * 1024,
                    128 * 1024 * 1024,
                    invalid,
                    16,
                ),
                Err(RecoverableNatsSegmentError::InvalidLiveSegmentLimit(_))
            ));
        }
        assert!(matches!(
            RecoverableNatsRetentionContract::try_new(
                3,
                256 * 1024 * 1024,
                32 * 1024 * 1024,
                2,
                16,
            ),
            Err(RecoverableNatsSegmentError::InvalidGenerationAdmissionBudget { .. })
        ));
        assert!(matches!(
            RecoverableNatsRetentionContract::try_new(
                3,
                128 * 1024 * 1024,
                128 * 1024 * 1024,
                2,
                16,
            ),
            Err(RecoverableNatsSegmentError::InvalidGenerationAdmissionBudget { .. })
        ));
        for invalid in [-1, 0, 1_000_001] {
            assert!(matches!(
                RecoverableNatsRetentionContract::try_new(
                    3,
                    256 * 1024 * 1024,
                    128 * 1024 * 1024,
                    2,
                    invalid,
                ),
                Err(RecoverableNatsSegmentError::InvalidConsumerLimit(_))
            ));
        }
    }

    #[test]
    fn stream_config_is_finite_discard_new_and_has_no_age_eviction() {
        let segment = segment(7);
        let config = segment.stream_config();
        assert_eq!(config.name, segment.stream_name());
        assert_eq!(
            config.subjects,
            vec!["PSY_BEQ_V2.7073792e6d61696e6e6574.N1337_C.SG7.>"]
        );
        assert_eq!(config.retention, RetentionPolicy::Limits);
        assert_eq!(config.storage, StorageType::File);
        assert_eq!(config.num_replicas, 3);
        assert_eq!(config.max_bytes, 8 * 1024 * 1024 * 1024);
        assert_eq!(config.max_messages, -1);
        assert_eq!(config.max_messages_per_subject, -1);
        assert_eq!(config.max_consumers, 16);
        assert_eq!(config.max_age, Duration::ZERO);
        assert_eq!(config.discard, DiscardPolicy::New);
        assert_eq!(config.duplicate_window, RETRY_DEDUPLICATION_WINDOW);
        assert!(!config.discard_new_per_subject);
        assert!(config.deny_delete);
        assert!(config.deny_purge);
        assert!(!config.allow_message_ttl);
        assert!(config.subject_delete_marker_ttl.is_none());
        assert_eq!(config.compression, Some(Compression::None));
        segment.validate_stream_config_structure(&config).unwrap();
        let sealed = segment.sealed_stream_config();
        assert!(sealed.sealed);
        assert!(segment.validate_stream_config_structure(&sealed).is_err());
    }

    #[test]
    fn created_instance_identity_is_stable_and_recreation_safe() {
        let segment = segment(7);
        let state = RecoverableNatsStreamStateSnapshot {
            messages: 3,
            bytes: 900,
            first_sequence: 1,
            last_sequence: 3,
            consumer_count: 1,
            subject_count: 2,
        };
        state.validate().unwrap();
        let first = segment.attest_instance_parts(1_700_000_000_000_000_000, state);
        let retry = segment.attest_instance_parts(1_700_000_000_000_000_000, state);
        let recreated = segment.attest_instance_parts(1_700_000_000_000_000_001, state);
        assert_eq!(first, retry);
        assert_ne!(first.instance_id, recreated.instance_id);
        assert_eq!(first.segment.digest(), segment.digest());

        assert!(RecoverableNatsStreamStateSnapshot {
            messages: 3,
            bytes: 900,
            first_sequence: 2,
            last_sequence: 4,
            consumer_count: 1,
            subject_count: 2,
        }
        .validate()
        .is_err());
        assert!(RecoverableNatsStreamStateSnapshot {
            messages: 0,
            bytes: 0,
            first_sequence: 1,
            last_sequence: 1,
            consumer_count: 0,
            subject_count: 0,
        }
        .validate()
        .is_err());
    }

    #[test]
    fn any_eviction_or_routing_drift_fails_attestation() {
        let segment = segment(7);
        let mut mutations: Vec<Box<dyn FnOnce(&mut StreamConfig)>> = vec![
            Box::new(|value| value.max_bytes += 1),
            Box::new(|value| value.max_messages = 10),
            Box::new(|value| value.max_messages_per_subject = 10),
            Box::new(|value| value.max_consumers = 17),
            Box::new(|value| value.max_age = Duration::from_secs(1)),
            Box::new(|value| value.discard = DiscardPolicy::Old),
            Box::new(|value| value.num_replicas = 2),
            Box::new(|value| value.subjects = vec!["psy.mainnet.>".into()]),
            Box::new(|value| value.deny_delete = false),
            Box::new(|value| value.deny_purge = false),
            Box::new(|value| value.allow_rollup = true),
            Box::new(|value| value.allow_message_ttl = true),
            Box::new(|value| value.allow_direct = true),
            Box::new(|value| value.duplicate_window = Duration::from_secs(1)),
            Box::new(|value| value.compression = Some(Compression::S2)),
            Box::new(|value| value.allow_atomic_publish = true),
            Box::new(|value| value.first_sequence = Some(17)),
        ];
        for mutate in mutations.drain(..) {
            let mut config = segment.stream_config();
            mutate(&mut config);
            assert_eq!(
                segment.validate_stream_config_structure(&config),
                Err(RecoverableNatsSegmentError::StreamContractMismatch)
            );
        }

        let mut server_metadata = segment.stream_config();
        server_metadata
            .metadata
            .insert("_nats.level".into(), "1".into());
        segment
            .validate_stream_config_structure(&server_metadata)
            .unwrap();
        server_metadata
            .metadata
            .insert("operator.override".into(), "true".into());
        assert!(segment
            .validate_stream_config_structure(&server_metadata)
            .is_err());
    }

    #[test]
    fn invalid_names_and_wildcard_suffixes_fail_closed() {
        for invalid in [
            "",
            ".psy",
            "psy.",
            "psy..main",
            "psy.*",
            "psy.>",
            "psy main",
            "PSY_BEQ_V2",
            "PSY_BEQ_V2.707379",
        ] {
            assert!(RecoverableNatsStreamSegment::try_new(
                invalid,
                coordinator_key(),
                RecoverableNatsSegmentId::try_new(1).unwrap(),
                retention(),
            )
            .is_err());
        }
        let segment = segment(1);
        for invalid in ["", ".coord", "coord.", "coord..r0", "coord.*", "coord.>"] {
            assert!(segment.exact_subject(invalid).is_err());
        }
    }

    #[test]
    fn contract_digest_binds_every_capacity_and_segment_dimension() {
        let baseline = segment(7);
        // The current v1 digest includes async-nats' normalized StreamConfig
        // JSON. Dependency/default-field drift must therefore be an explicit
        // contract migration, never a silent durable-identity change.
        assert_eq!(
            hex::encode(baseline.digest().as_bytes()),
            "397bddf98ba65071d79877190ebf67a3bfac8a966fee504afb712b55c1de722e"
        );
        let changed_capacity = RecoverableNatsStreamSegment::try_new(
            "psy.mainnet",
            coordinator_key(),
            RecoverableNatsSegmentId::try_new(7).unwrap(),
            RecoverableNatsRetentionContract::try_new(
                3,
                9 * 1024 * 1024 * 1024,
                3 * 1024 * 1024 * 1024,
                3,
                16,
            )
            .unwrap(),
        )
        .unwrap();
        let changed_reserve = RecoverableNatsStreamSegment::try_new(
            "psy.mainnet",
            coordinator_key(),
            RecoverableNatsSegmentId::try_new(7).unwrap(),
            RecoverableNatsRetentionContract::try_new(
                3,
                8 * 1024 * 1024 * 1024,
                2 * 1024 * 1024 * 1024,
                3,
                16,
            )
            .unwrap(),
        )
        .unwrap();
        assert_ne!(baseline.digest(), changed_capacity.digest());
        assert_ne!(baseline.digest(), changed_reserve.digest());
        let changed_consumers = RecoverableNatsStreamSegment::try_new(
            "psy.mainnet",
            coordinator_key(),
            RecoverableNatsSegmentId::try_new(7).unwrap(),
            RecoverableNatsRetentionContract::try_new(
                3,
                8 * 1024 * 1024 * 1024,
                3 * 1024 * 1024 * 1024,
                3,
                17,
            )
            .unwrap(),
        )
        .unwrap();
        assert_ne!(baseline.digest(), changed_consumers.digest());
        assert_ne!(baseline.digest().as_bytes(), &[0; 32]);
    }

    /// Single-node transport probe only. RF=3 requalification belongs to
    /// h22e; this test validates the NATS server semantics on which the typed
    /// contract relies without weakening the production RF>=3 constructor.
    #[tokio::test]
    #[ignore = "requires PSY_TEST_NATS_URL and a disposable JetStream server"]
    async fn real_nats_discard_new_age_and_whole_stream_delete_contract() {
        let url = std::env::var("PSY_TEST_NATS_URL")
            .expect("PSY_TEST_NATS_URL must point at a disposable server");
        let client = async_nats::connect(url).await.unwrap();
        let context = async_nats::jetstream::new(client);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let typed = RecoverableNatsStreamSegment::try_new(
            format!("psy_c2b0_typed_{nonce}"),
            coordinator_key(),
            RecoverableNatsSegmentId::try_new(1).unwrap(),
            RecoverableNatsRetentionContract::try_new(
                3,
                72 * 1024 * 1024,
                70 * 1024 * 1024,
                2,
                16,
            )
            .unwrap(),
        )
        .unwrap();
        let mut single_node_config = typed.stream_config();
        single_node_config.num_replicas = 1;
        let mut typed_stream = context.create_stream(single_node_config).await.unwrap();
        let mut normalized = typed_stream.info().await.unwrap().config.clone();
        normalized.num_replicas = 3;
        typed
            .validate_stream_config_structure(&normalized)
            .unwrap_or_else(|error| {
            panic!(
                "server-normalized config failed typed attestation: {error}; actual={normalized:#?}; expected={:#?}",
                typed.stream_config()
            )
            });
        let typed_subject = typed.exact_subject("cas.probe").unwrap();
        let publish = async_nats::jetstream::context::Publish::build()
            .payload(Bytes::from_static(b"same-intent"))
            .message_id("same-intent")
            .expected_stream(typed.stream_name())
            .expected_last_subject_sequence(0);
        let first_ack = context
            .send_publish(typed_subject.clone(), publish.clone())
            .await
            .unwrap()
            .await
            .unwrap();
        let retry_error = context
            .send_publish(typed_subject.clone(), publish)
            .await
            .unwrap()
            .await
            .unwrap_err();
        assert_eq!(
            retry_error.kind(),
            async_nats::jetstream::context::PublishErrorKind::WrongLastSequence
        );
        let leader_readback = typed_stream
            .get_last_raw_message_by_subject(&typed_subject)
            .await
            .unwrap();
        assert_eq!(leader_readback.sequence, first_ack.sequence);
        assert_eq!(leader_readback.payload, Bytes::from_static(b"same-intent"));
        assert!(context
            .delete_stream(typed.stream_name())
            .await
            .unwrap()
            .success);

        let capacity_name = format!("PSY_C2B0_CAP_{nonce}");
        let capacity_subject = format!("psy_c2b0_cap_{nonce}");
        let mut capacity_stream = context
            .create_stream(StreamConfig {
                name: capacity_name.clone(),
                subjects: vec![capacity_subject.clone()],
                storage: StorageType::File,
                retention: RetentionPolicy::Limits,
                max_bytes: 512,
                max_messages: -1,
                max_messages_per_subject: -1,
                discard: DiscardPolicy::New,
                num_replicas: 1,
                deny_delete: true,
                deny_purge: true,
                ..Default::default()
            })
            .await
            .unwrap();

        let mut accepted = Vec::new();
        for value in 0_u8..16 {
            let future = context
                .publish(capacity_subject.clone(), Bytes::from(vec![value; 128]))
                .await
                .unwrap();
            match future.await {
                Ok(ack) => accepted.push(ack.sequence),
                Err(_) => break,
            }
        }
        assert!(!accepted.is_empty());
        assert!(accepted.len() < 16, "finite max_bytes must reject a publish");
        let info = capacity_stream.info().await.unwrap();
        assert_eq!(info.state.messages as usize, accepted.len());
        capacity_stream
            .get_raw_message(accepted[0])
            .await
            .expect("DiscardNew must retain the first message");
        assert!(capacity_stream.purge().await.is_err());

        let overlap = context
            .create_stream(StreamConfig {
                name: format!("PSY_C2B0_OVERLAP_{nonce}"),
                subjects: vec![capacity_subject],
                storage: StorageType::File,
                num_replicas: 1,
                ..Default::default()
            })
            .await;
        assert!(overlap.is_err(), "exact subject overlap must be rejected");
        assert!(context
            .delete_stream(&capacity_name)
            .await
            .unwrap()
            .success);

        let age_name = format!("PSY_C2B0_AGE_{nonce}");
        let age_subject = format!("psy_c2b0_age_{nonce}");
        let mut age_stream = context
            .create_stream(StreamConfig {
                name: age_name.clone(),
                subjects: vec![age_subject.clone()],
                storage: StorageType::File,
                retention: RetentionPolicy::Limits,
                max_bytes: 1024 * 1024,
                max_messages: -1,
                max_messages_per_subject: -1,
                max_age: Duration::from_millis(250),
                discard: DiscardPolicy::New,
                num_replicas: 1,
                ..Default::default()
            })
            .await
            .unwrap();
        context
            .publish(age_subject, Bytes::from_static(b"expires"))
            .await
            .unwrap()
            .await
            .unwrap();

        let mut expired = false;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if age_stream.info().await.unwrap().state.messages == 0 {
                expired = true;
                break;
            }
        }
        assert!(expired, "max_age silently removes data despite DiscardNew");
        assert!(context.delete_stream(age_name).await.unwrap().success);
    }
}
