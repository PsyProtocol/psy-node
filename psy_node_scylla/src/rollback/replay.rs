//! Driver-independent G0-05 replay-record prototype.
//!
//! Nothing in this module executes CQL or is wired into production writers.
//! It compares a complete physical mutation delta with a content-addressed
//! prepared payload plus explicitly typed derived supplements.

use std::{error::Error, fmt};

use psy_node_core::store::typed::{
    CheckpointId, ImtCursorTransition, ImtCursorTransitionError,
    ImtEncodedKey, LeafIndex, LogicalMutation, MerkleNode, MutationOperation,
    MutationValue, NodeIndex, StructuredValueSchema, TreeId, TreeSubId,
    TypedTableKey, U64SingletonSlot, UserId,
};
use sha2::{Digest, Sha256};
use strum::IntoEnumIterator;

use super::{
    expand_logical_mutation, physical_descriptor, MutationBuildError,
    MutationDecodeError, RegistryBlocker, RegistryReadiness,
    ResolvedScyllaMutation, ScyllaPhysicalTableId,
};

const PREPARED_MAGIC: &[u8; 4] = b"PSPP";
const BATCH_MAGIC: &[u8; 4] = b"PSPB";
const FULL_MAGIC: &[u8; 4] = b"PSFD";
const COMPACT_MAGIC: &[u8; 4] = b"PSCR";
const REPLAY_SCHEMA_VERSION: u16 = 1;
const MUTATION_DIGEST_DOMAIN: &[u8] = b"psy.rollback.physical-mutation-batch.v1\0";
const PAYLOAD_DIGEST_DOMAIN: &[u8] = b"psy.rollback.prepared-payload.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ReplayRecordKind {
    FullPhysicalDelta = 1,
    PreparedReferencePlusSupplement = 2,
}

impl TryFrom<u8> for ReplayRecordKind {
    type Error = ReplayPrototypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::FullPhysicalDelta),
            2 => Ok(Self::PreparedReferencePlusSupplement),
            value => Err(ReplayPrototypeError::UnknownReplayRecordKind(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PreparedPayloadKind {
    Coordinator = 1,
    Realm = 2,
}

impl TryFrom<u8> for PreparedPayloadKind {
    type Error = ReplayPrototypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Coordinator),
            2 => Ok(Self::Realm),
            value => Err(ReplayPrototypeError::UnknownPreparedPayloadKind(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayAdapterDescriptor {
    pub payload_kind: PreparedPayloadKind,
    pub codec_version: u16,
    pub writer_version: u16,
    pub replay_adapter_version: u16,
}

/// Deliberately closed registry. Adding a codec/writer requires an explicit
/// match arm and compatibility tests; no wildcard version fallback exists.
pub fn resolve_replay_adapter(
    payload_kind: u8,
    codec_version: u16,
    writer_version: u16,
    replay_adapter_version: u16,
) -> Result<ReplayAdapterDescriptor, ReplayPrototypeError> {
    let payload_kind = PreparedPayloadKind::try_from(payload_kind)?;
    match (payload_kind, codec_version, writer_version, replay_adapter_version) {
        (PreparedPayloadKind::Coordinator, 1, 1, 1) | (PreparedPayloadKind::Realm, 1, 1, 1) => Ok(ReplayAdapterDescriptor {
            payload_kind,
            codec_version,
            writer_version,
            replay_adapter_version,
        }),
        (_, codec_version, _, _) if codec_version != 1 => Err(ReplayPrototypeError::UnknownPayloadCodec(codec_version)),
        (_, _, writer_version, _) if writer_version != 1 => Err(ReplayPrototypeError::UnknownWriterVersion(writer_version)),
        (_, _, _, replay_adapter_version) => Err(ReplayPrototypeError::UnknownReplayAdapterVersion(replay_adapter_version)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayDigest([u8; 32]);

impl ReplayDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn domain_digest(domain: &[u8], payload: &[u8]) -> ReplayDigest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    ReplayDigest(hasher.finalize().into())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReplayBatchMetrics {
    pub mutation_count: usize,
    pub key_bytes: usize,
    pub value_bytes: usize,
    pub encoded_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalPhysicalMutationBatch {
    mutations: Vec<ResolvedScyllaMutation>,
    canonical_bytes: Vec<u8>,
    digest: ReplayDigest,
    metrics: ReplayBatchMetrics,
}

impl CanonicalPhysicalMutationBatch {
    pub fn try_new(mut mutations: Vec<ResolvedScyllaMutation>) -> Result<Self, ReplayPrototypeError> {
        for mutation in &mutations {
            if matches!(
                mutation.mutation().operation(),
                MutationOperation::Put(MutationValue::Digest { .. })
            ) {
                return Err(ReplayPrototypeError::DigestOnlyValueNotExecutable);
            }
        }
        mutations.sort_by(|left, right| left.locator_bytes().cmp(right.locator_bytes()));
        for pair in mutations.windows(2) {
            if pair[0].locator_bytes() == pair[1].locator_bytes() {
                return Err(ReplayPrototypeError::DuplicatePhysicalKey);
            }
        }

        let mut canonical_bytes = Vec::new();
        canonical_bytes.extend_from_slice(BATCH_MAGIC);
        canonical_bytes.extend_from_slice(&REPLAY_SCHEMA_VERSION.to_be_bytes());
        canonical_bytes.extend_from_slice(&(mutations.len() as u32).to_be_bytes());
        let mut metrics = ReplayBatchMetrics { mutation_count: mutations.len(), ..ReplayBatchMetrics::default() };
        for mutation in &mutations {
            let encoded = mutation.encode_canonical();
            canonical_bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            canonical_bytes.extend_from_slice(&encoded);
            metrics.key_bytes += mutation.locator_bytes().len();
            metrics.value_bytes += executable_value_len(mutation.mutation().operation());
        }
        metrics.encoded_bytes = canonical_bytes.len();
        let digest = domain_digest(MUTATION_DIGEST_DOMAIN, &canonical_bytes);
        Ok(Self { mutations, canonical_bytes, digest, metrics })
    }

    pub fn from_logical(intents: Vec<LogicalMutation>) -> Result<Self, ReplayPrototypeError> {
        let mut resolved = Vec::new();
        for intent in intents {
            resolved.extend(expand_logical_mutation(intent)?);
        }
        Self::try_new(resolved)
    }

    /// Strictly recovers a persisted physical batch. Every mutation is
    /// reconstructed through the typed key registry and the canonical bytes
    /// must round-trip exactly; this is not a raw-byte execution path.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ReplayPrototypeError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take(4)? != BATCH_MAGIC {
            return Err(ReplayPrototypeError::InvalidCanonicalPayload("bad physical batch magic"));
        }
        if cursor.u16()? != REPLAY_SCHEMA_VERSION {
            return Err(ReplayPrototypeError::UnknownReplaySchemaVersion);
        }
        let count = cursor.u32()? as usize;
        if count > cursor.remaining_len() / 4 {
            return Err(ReplayPrototypeError::InvalidCanonicalPayload("physical batch count exceeds encoded bytes"));
        }
        let mut mutations = Vec::with_capacity(count);
        for _ in 0..count {
            mutations.push(ResolvedScyllaMutation::decode_canonical(cursor.bytes()?)?);
        }
        if !cursor.is_empty() {
            return Err(ReplayPrototypeError::InvalidCanonicalPayload("trailing physical batch bytes"));
        }
        let decoded = Self::try_new(mutations)?;
        if decoded.encode_canonical() != bytes {
            return Err(ReplayPrototypeError::NonCanonicalPhysicalMutationBatch);
        }
        Ok(decoded)
    }

    pub fn mutations(&self) -> &[ResolvedScyllaMutation] {
        &self.mutations
    }

    pub fn encode_canonical(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> ReplayDigest {
        self.digest
    }

    pub const fn metrics(&self) -> ReplayBatchMetrics {
        self.metrics
    }
}

fn executable_value_len(operation: &MutationOperation) -> usize {
    match operation {
        MutationOperation::Put(MutationValue::PsyCanonicalBytes(value)) => value.len(),
        MutationOperation::Put(MutationValue::CqlU64(_)) => 8,
        MutationOperation::Put(MutationValue::CqlU128(_)) => 16,
        MutationOperation::Put(MutationValue::KeyOnly) => 0,
        MutationOperation::Put(MutationValue::Structured { canonical_bytes, .. }) => canonical_bytes.len(),
        MutationOperation::Put(MutationValue::Digest { .. }) => 32,
        MutationOperation::Delete => 0,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedSemanticMutation {
    CheckpointLeaf { checkpoint: CheckpointId, value: Vec<u8> },
    L2BlockState { checkpoint: CheckpointId, value: Vec<u8> },
    CheckpointStateRoots { checkpoint: CheckpointId, value: Vec<u8> },
    GlobalUserMerkle { checkpoint: CheckpointId, node: MerkleNode, value: Vec<u8> },
    UserLeaf { user: UserId, checkpoint: CheckpointId, value: Vec<u8> },
    ImtLeaf {
        tree: TreeId,
        tree_sub: TreeSubId,
        leaf: LeafIndex,
        checkpoint: CheckpointId,
        canonical_row: Vec<u8>,
    },
}

impl PreparedSemanticMutation {
    fn tag(&self) -> u8 {
        match self {
            Self::CheckpointLeaf { .. } => 1,
            Self::L2BlockState { .. } => 2,
            Self::CheckpointStateRoots { .. } => 3,
            Self::GlobalUserMerkle { .. } => 4,
            Self::UserLeaf { .. } => 6,
            Self::ImtLeaf { .. } => 7,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.tag()];
        match self {
            Self::CheckpointLeaf { checkpoint, value }
            | Self::L2BlockState { checkpoint, value }
            | Self::CheckpointStateRoots { checkpoint, value } => {
                put_u64(&mut out, checkpoint.get());
                put_bytes(&mut out, value);
            }
            Self::GlobalUserMerkle { checkpoint, node, value } => {
                put_u64(&mut out, checkpoint.get());
                out.push(node.level());
                put_u64(&mut out, node.index().get());
                put_bytes(&mut out, value);
            }
            Self::UserLeaf { user, checkpoint, value } => {
                put_u64(&mut out, user.get());
                put_u64(&mut out, checkpoint.get());
                put_bytes(&mut out, value);
            }
            Self::ImtLeaf { tree, tree_sub, leaf, checkpoint, canonical_row } => {
                put_u64(&mut out, tree.get());
                put_u64(&mut out, tree_sub.get());
                put_u64(&mut out, leaf.get());
                put_u64(&mut out, checkpoint.get());
                put_bytes(&mut out, canonical_row);
            }
        }
        out
    }

    fn into_logical(self) -> LogicalMutation {
        let (key, value) = match self {
            Self::CheckpointLeaf { checkpoint, value } => {
                (TypedTableKey::CheckpointLeaf(checkpoint), MutationValue::PsyCanonicalBytes(value))
            }
            Self::L2BlockState { checkpoint, value } => {
                (TypedTableKey::L2BlockState(checkpoint), MutationValue::PsyCanonicalBytes(value))
            }
            Self::CheckpointStateRoots { checkpoint, value } => {
                (TypedTableKey::CheckpointStateRoots(checkpoint), MutationValue::PsyCanonicalBytes(value))
            }
            Self::GlobalUserMerkle { checkpoint, node, value } => (
                TypedTableKey::GlobalUserMerkle { checkpoint, node },
                MutationValue::PsyCanonicalBytes(value),
            ),
            Self::UserLeaf { user, checkpoint, value } => (
                TypedTableKey::UserLeaf { user, checkpoint },
                MutationValue::PsyCanonicalBytes(value),
            ),
            Self::ImtLeaf { tree, tree_sub, leaf, checkpoint, canonical_row } => (
                TypedTableKey::ImtLeaf { tree, tree_sub, leaf, checkpoint },
                MutationValue::Structured { schema: StructuredValueSchema::ImtLeafRowV1, canonical_bytes: canonical_row },
            ),
        };
        LogicalMutation::Put { key, value }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedPayload {
    kind: PreparedPayloadKind,
    codec_version: u16,
    writer_version: u16,
    mutations: Vec<PreparedSemanticMutation>,
}

impl PreparedPayload {
    pub fn try_v1(kind: PreparedPayloadKind, mutations: Vec<PreparedSemanticMutation>) -> Result<Self, ReplayPrototypeError> {
        validate_payload_kind(kind, &mutations)?;
        Ok(Self { kind, codec_version: 1, writer_version: 1, mutations })
    }

    pub const fn kind(&self) -> PreparedPayloadKind {
        self.kind
    }

    pub fn mutations(&self) -> &[PreparedSemanticMutation] {
        &self.mutations
    }

    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut items: Vec<Vec<u8>> = self.mutations.iter().map(PreparedSemanticMutation::encode).collect();
        items.sort();
        let mut out = Vec::new();
        out.extend_from_slice(PREPARED_MAGIC);
        out.extend_from_slice(&self.codec_version.to_be_bytes());
        out.extend_from_slice(&self.writer_version.to_be_bytes());
        out.push(self.kind as u8);
        out.extend_from_slice(&(items.len() as u32).to_be_bytes());
        for item in items {
            put_bytes(&mut out, &item);
        }
        out
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ReplayPrototypeError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take(4)? != PREPARED_MAGIC {
            return Err(ReplayPrototypeError::InvalidCanonicalPayload("bad prepared magic"));
        }
        let codec_version = cursor.u16()?;
        let writer_version = cursor.u16()?;
        let kind = PreparedPayloadKind::try_from(cursor.u8()?)?;
        resolve_replay_adapter(kind as u8, codec_version, writer_version, 1)?;
        let count = cursor.u32()? as usize;
        if count > cursor.remaining_len() / 4 {
            return Err(ReplayPrototypeError::InvalidCanonicalPayload("prepared mutation count exceeds encoded bytes"));
        }
        let mut mutations = Vec::with_capacity(count);
        let mut previous_item: Option<Vec<u8>> = None;
        for _ in 0..count {
            let item = cursor.bytes()?;
            if previous_item.as_deref().is_some_and(|previous| previous >= item) {
                return Err(ReplayPrototypeError::NonCanonicalPreparedOrdering);
            }
            mutations.push(decode_semantic_mutation(item)?);
            previous_item = Some(item.to_vec());
        }
        if !cursor.is_empty() {
            return Err(ReplayPrototypeError::InvalidCanonicalPayload("trailing prepared bytes"));
        }
        validate_payload_kind(kind, &mutations)?;
        Ok(Self { kind, codec_version, writer_version, mutations })
    }

    /// Expand a strictly decoded durable prepared payload through the typed
    /// registry. Callers must still compare the resulting batch digest with
    /// the manifest commitment before executing it.
    pub(crate) fn expand_physical(
        self,
    ) -> Result<Vec<ResolvedScyllaMutation>, ReplayPrototypeError> {
        let mut mutations = Vec::new();
        for mutation in self.mutations {
            mutations.extend(expand_logical_mutation(mutation.into_logical())?);
        }
        Ok(mutations)
    }
}

fn decode_semantic_mutation(bytes: &[u8]) -> Result<PreparedSemanticMutation, ReplayPrototypeError> {
    let mut cursor = Cursor::new(bytes);
    let tag = cursor.u8()?;
    let mutation = match tag {
        1 => PreparedSemanticMutation::CheckpointLeaf { checkpoint: cursor.checkpoint()?, value: cursor.bytes()?.to_vec() },
        2 => PreparedSemanticMutation::L2BlockState { checkpoint: cursor.checkpoint()?, value: cursor.bytes()?.to_vec() },
        3 => PreparedSemanticMutation::CheckpointStateRoots { checkpoint: cursor.checkpoint()?, value: cursor.bytes()?.to_vec() },
        4 => {
            let checkpoint = cursor.checkpoint()?;
            let level = cursor.u8()?;
            let node = MerkleNode::new(level, NodeIndex::new(cursor.u64()?));
            let value = cursor.bytes()?.to_vec();
            PreparedSemanticMutation::GlobalUserMerkle { checkpoint, node, value }
        }
        6 => PreparedSemanticMutation::UserLeaf {
            user: UserId::new(cursor.u64()?),
            checkpoint: cursor.checkpoint()?,
            value: cursor.bytes()?.to_vec(),
        },
        7 => PreparedSemanticMutation::ImtLeaf {
            tree: TreeId::new(cursor.u64()?),
            tree_sub: TreeSubId::new(cursor.u64()?),
            leaf: LeafIndex::new(cursor.u64()?),
            checkpoint: cursor.checkpoint()?,
            canonical_row: cursor.bytes()?.to_vec(),
        },
        tag => return Err(ReplayPrototypeError::UnknownPreparedSchemaTag(tag)),
    };
    if !cursor.is_empty() {
        return Err(ReplayPrototypeError::InvalidCanonicalPayload("trailing semantic mutation bytes"));
    }
    Ok(mutation)
}

fn validate_payload_kind(kind: PreparedPayloadKind, mutations: &[PreparedSemanticMutation]) -> Result<(), ReplayPrototypeError> {
    if kind == PreparedPayloadKind::Coordinator
        && mutations.iter().any(|mutation| {
            matches!(
                mutation,
                PreparedSemanticMutation::UserLeaf { .. } | PreparedSemanticMutation::ImtLeaf { .. }
            )
        })
    {
        return Err(ReplayPrototypeError::PayloadMutationNotAllowedForAuthority);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedPayloadSource<'a> {
    ContentAddressedBytes(&'a [u8]),
    LocalGathererFile(&'a str),
    RedisKey(&'a str),
    TemporaryPendingFile(&'a str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurablePreparedPayloadReference {
    payload_kind: PreparedPayloadKind,
    codec_version: u16,
    writer_version: u16,
    payload_digest: ReplayDigest,
    payload_length: u64,
}

impl DurablePreparedPayloadReference {
    pub fn try_from_source(
        payload_kind: PreparedPayloadKind,
        codec_version: u16,
        writer_version: u16,
        source: PreparedPayloadSource<'_>,
    ) -> Result<Self, ReplayPrototypeError> {
        resolve_replay_adapter(payload_kind as u8, codec_version, writer_version, 1)?;
        let bytes = match source {
            PreparedPayloadSource::ContentAddressedBytes(bytes) => bytes,
            PreparedPayloadSource::LocalGathererFile(_) => return Err(ReplayPrototypeError::NonDurablePayloadSource("gatherer-file")),
            PreparedPayloadSource::RedisKey(_) => return Err(ReplayPrototypeError::NonDurablePayloadSource("redis")),
            PreparedPayloadSource::TemporaryPendingFile(_) => {
                return Err(ReplayPrototypeError::NonDurablePayloadSource("temporary-pending-file"));
            }
        };
        Ok(Self {
            payload_kind,
            codec_version,
            writer_version,
            payload_digest: domain_digest(PAYLOAD_DIGEST_DOMAIN, bytes),
            payload_length: bytes.len() as u64,
        })
    }

    pub const fn payload_digest(&self) -> ReplayDigest {
        self.payload_digest
    }

    pub const fn payload_length(&self) -> u64 {
        self.payload_length
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.payload_kind as u8);
        out.extend_from_slice(&self.codec_version.to_be_bytes());
        out.extend_from_slice(&self.writer_version.to_be_bytes());
        out.extend_from_slice(self.payload_digest.as_bytes());
        out.extend_from_slice(&self.payload_length.to_be_bytes());
    }

    fn verify(&self, bytes: &[u8]) -> Result<(), ReplayPrototypeError> {
        resolve_replay_adapter(self.payload_kind as u8, self.codec_version, self.writer_version, 1)?;
        if bytes.len() as u64 != self.payload_length {
            return Err(ReplayPrototypeError::PreparedPayloadLengthMismatch);
        }
        if domain_digest(PAYLOAD_DIGEST_DOMAIN, bytes) != self.payload_digest {
            return Err(ReplayPrototypeError::PreparedPayloadDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedSupplementBatch(CanonicalPhysicalMutationBatch);

impl DerivedSupplementBatch {
    pub fn from_logical(intents: Vec<LogicalMutation>) -> Result<Self, ReplayPrototypeError> {
        Ok(Self(CanonicalPhysicalMutationBatch::from_logical(intents)?))
    }

    pub const fn batch(&self) -> &CanonicalPhysicalMutationBatch {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ReplayAuthority {
    Coordinator = 1,
    Realm = 2,
}

impl TryFrom<u8> for ReplayAuthority {
    type Error = ReplayPrototypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Coordinator),
            2 => Ok(Self::Realm),
            _ => Err(ReplayPrototypeError::UnknownReplayAuthority(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum OperationalReplayAction {
    RotatePendingCheckpointNamespace = 1,
    RotatePendingProcNamespace = 2,
    RotateRewardTagNamespace = 3,
}

impl TryFrom<u8> for OperationalReplayAction {
    type Error = ReplayPrototypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::RotatePendingCheckpointNamespace),
            2 => Ok(Self::RotatePendingProcNamespace),
            3 => Ok(Self::RotateRewardTagNamespace),
            _ => Err(ReplayPrototypeError::UnknownOperationalReplayAction(value)),
        }
    }
}

/// The semantic checkpoint receipt is shared by both record strategies. It
/// accounts for branch state/metadata mutations while keeping operational
/// pending namespaces out of the physical replay digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayReceipt {
    authority: ReplayAuthority,
    checkpoint: CheckpointId,
    state_mutation_count: u32,
    metadata_mutation_count: u32,
    operational_actions: Vec<OperationalReplayAction>,
}

impl ReplayReceipt {
    pub fn new(
        authority: ReplayAuthority,
        checkpoint: CheckpointId,
        state_mutation_count: u32,
        metadata_mutation_count: u32,
        mut operational_actions: Vec<OperationalReplayAction>,
    ) -> Self {
        operational_actions.sort();
        operational_actions.dedup();
        Self {
            authority,
            checkpoint,
            state_mutation_count,
            metadata_mutation_count,
            operational_actions,
        }
    }

    pub const fn authority(&self) -> ReplayAuthority {
        self.authority
    }

    pub const fn checkpoint(&self) -> CheckpointId {
        self.checkpoint
    }

    pub const fn state_mutation_count(&self) -> u32 {
        self.state_mutation_count
    }

    pub const fn metadata_mutation_count(&self) -> u32 {
        self.metadata_mutation_count
    }

    pub fn operational_actions(&self) -> &[OperationalReplayAction] {
        &self.operational_actions
    }

    fn validate_count(&self, actual: usize) -> Result<(), ReplayPrototypeError> {
        if self.state_mutation_count as usize + self.metadata_mutation_count as usize != actual {
            return Err(ReplayPrototypeError::ReceiptMutationCountMismatch {
                receipt: self.state_mutation_count as usize + self.metadata_mutation_count as usize,
                actual,
            });
        }
        Ok(())
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.authority as u8);
        out.extend_from_slice(&self.checkpoint.get().to_be_bytes());
        out.extend_from_slice(&self.state_mutation_count.to_be_bytes());
        out.extend_from_slice(&self.metadata_mutation_count.to_be_bytes());
        out.extend_from_slice(&(self.operational_actions.len() as u16).to_be_bytes());
        out.extend(self.operational_actions.iter().map(|action| *action as u8));
    }

    fn decode_from(cursor: &mut Cursor<'_>) -> Result<Self, ReplayPrototypeError> {
        let authority = ReplayAuthority::try_from(cursor.u8()?)?;
        let checkpoint = cursor.checkpoint()?;
        let state_mutation_count = cursor.u32()?;
        let metadata_mutation_count = cursor.u32()?;
        let action_count = cursor.u16()? as usize;
        if action_count > cursor.remaining_len() {
            return Err(ReplayPrototypeError::InvalidCanonicalPayload("operational action count exceeds encoded bytes"));
        }
        let mut operational_actions = Vec::with_capacity(action_count);
        for _ in 0..action_count {
            let action = OperationalReplayAction::try_from(cursor.u8()?)?;
            if operational_actions.last().is_some_and(|previous| previous >= &action) {
                return Err(ReplayPrototypeError::NonCanonicalOperationalActions);
            }
            operational_actions.push(action);
        }
        Ok(Self { authority, checkpoint, state_mutation_count, metadata_mutation_count, operational_actions })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FullPhysicalDeltaRecord {
    batch: CanonicalPhysicalMutationBatch,
    receipt: ReplayReceipt,
}

impl FullPhysicalDeltaRecord {
    pub fn try_new(batch: CanonicalPhysicalMutationBatch, receipt: ReplayReceipt) -> Result<Self, ReplayPrototypeError> {
        receipt.validate_count(batch.mutations().len())?;
        validate_imt_cursor_transitions(&batch, &receipt)?;
        Ok(Self { batch, receipt })
    }

    pub const fn batch(&self) -> &CanonicalPhysicalMutationBatch {
        &self.batch
    }

    pub const fn receipt(&self) -> &ReplayReceipt {
        &self.receipt
    }

    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(FULL_MAGIC);
        out.extend_from_slice(&REPLAY_SCHEMA_VERSION.to_be_bytes());
        out.push(ReplayRecordKind::FullPhysicalDelta as u8);
        self.receipt.encode_into(&mut out);
        put_bytes(&mut out, self.batch.encode_canonical());
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedReferencePlusSupplementRecord {
    prepared: DurablePreparedPayloadReference,
    supplements: DerivedSupplementBatch,
    receipt: ReplayReceipt,
    replay_adapter_version: u16,
    expected_full_digest: ReplayDigest,
    expected_mutation_count: u32,
}

impl PreparedReferencePlusSupplementRecord {
    pub fn try_v1(
        prepared: DurablePreparedPayloadReference,
        supplements: DerivedSupplementBatch,
        receipt: ReplayReceipt,
        durable_payload_bytes: &[u8],
        expected_full: &CanonicalPhysicalMutationBatch,
    ) -> Result<Self, ReplayPrototypeError> {
        receipt.validate_count(expected_full.mutations().len())?;
        validate_receipt_payload_authority(&receipt, prepared.payload_kind)?;
        validate_imt_cursor_transitions(supplements.batch(), &receipt)?;
        validate_imt_cursor_transitions(expected_full, &receipt)?;
        let record = Self {
            prepared,
            supplements,
            receipt,
            replay_adapter_version: 1,
            expected_full_digest: expected_full.digest(),
            expected_mutation_count: expected_full.mutations().len() as u32,
        };
        record.expand(durable_payload_bytes)?;
        Ok(record)
    }

    pub const fn supplements(&self) -> &DerivedSupplementBatch {
        &self.supplements
    }

    pub const fn receipt(&self) -> &ReplayReceipt {
        &self.receipt
    }

    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(COMPACT_MAGIC);
        out.extend_from_slice(&REPLAY_SCHEMA_VERSION.to_be_bytes());
        out.push(ReplayRecordKind::PreparedReferencePlusSupplement as u8);
        out.extend_from_slice(&self.replay_adapter_version.to_be_bytes());
        self.receipt.encode_into(&mut out);
        self.prepared.encode_into(&mut out);
        put_bytes(&mut out, self.supplements.batch().encode_canonical());
        out.extend_from_slice(self.expected_full_digest.as_bytes());
        out.extend_from_slice(&self.expected_mutation_count.to_be_bytes());
        out
    }

    /// Decodes the compact record exactly as it is loaded from durable
    /// manifest chunks. Expansion remains a separate step because it also
    /// verifies the independently persisted prepared payload.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ReplayPrototypeError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take(4)? != COMPACT_MAGIC {
            return Err(ReplayPrototypeError::InvalidCanonicalPayload("bad compact replay magic"));
        }
        if cursor.u16()? != REPLAY_SCHEMA_VERSION {
            return Err(ReplayPrototypeError::UnknownReplaySchemaVersion);
        }
        if ReplayRecordKind::try_from(cursor.u8()?)? != ReplayRecordKind::PreparedReferencePlusSupplement {
            return Err(ReplayPrototypeError::UnexpectedReplayRecordKind);
        }
        let replay_adapter_version = cursor.u16()?;
        let receipt = ReplayReceipt::decode_from(&mut cursor)?;
        let payload_kind = PreparedPayloadKind::try_from(cursor.u8()?)?;
        let codec_version = cursor.u16()?;
        let writer_version = cursor.u16()?;
        let payload_digest = ReplayDigest(cursor.array_32()?);
        let payload_length = cursor.u64()?;
        resolve_replay_adapter(payload_kind as u8, codec_version, writer_version, replay_adapter_version)?;
        let prepared = DurablePreparedPayloadReference {
            payload_kind,
            codec_version,
            writer_version,
            payload_digest,
            payload_length,
        };
        validate_receipt_payload_authority(&receipt, payload_kind)?;
        let supplements = DerivedSupplementBatch(CanonicalPhysicalMutationBatch::decode_canonical(cursor.bytes()?)?);
        let expected_full_digest = ReplayDigest(cursor.array_32()?);
        let expected_mutation_count = cursor.u32()?;
        if !cursor.is_empty() {
            return Err(ReplayPrototypeError::InvalidCanonicalPayload("trailing compact replay bytes"));
        }
        receipt.validate_count(expected_mutation_count as usize)?;
        validate_imt_cursor_transitions(supplements.batch(), &receipt)?;
        let decoded = Self {
            prepared,
            supplements,
            receipt,
            replay_adapter_version,
            expected_full_digest,
            expected_mutation_count,
        };
        if decoded.encode_canonical() != bytes {
            return Err(ReplayPrototypeError::NonCanonicalCompactReplayRecord);
        }
        Ok(decoded)
    }

    pub fn expand(&self, durable_payload_bytes: &[u8]) -> Result<CanonicalPhysicalMutationBatch, ReplayPrototypeError> {
        resolve_replay_adapter(
            self.prepared.payload_kind as u8,
            self.prepared.codec_version,
            self.prepared.writer_version,
            self.replay_adapter_version,
        )?;
        self.prepared.verify(durable_payload_bytes)?;
        let payload = PreparedPayload::decode_canonical(durable_payload_bytes)?;
        if payload.kind != self.prepared.payload_kind {
            return Err(ReplayPrototypeError::PreparedPayloadKindMismatch);
        }
        let mut mutations = payload.expand_physical()?;
        mutations.extend(self.supplements.batch().mutations().iter().cloned());
        let expanded = CanonicalPhysicalMutationBatch::try_new(mutations)?;
        if expanded.mutations().len() != self.expected_mutation_count as usize || expanded.digest() != self.expected_full_digest {
            return Err(ReplayPrototypeError::ExpandedMutationDigestMismatch);
        }
        Ok(expanded)
    }
}

fn validate_imt_cursor_transitions(
    batch: &CanonicalPhysicalMutationBatch,
    receipt: &ReplayReceipt,
) -> Result<(), ReplayPrototypeError> {
    for resolved in batch.mutations() {
        if resolved.mutation().physical_table()
            != ScyllaPhysicalTableId::ImtNextAppendIndex
        {
            continue;
        }
        if receipt.authority() != ReplayAuthority::Realm {
            return Err(ReplayPrototypeError::ImtCursorAuthorityMismatch);
        }
        let transition = match resolved.mutation().operation() {
            MutationOperation::Put(MutationValue::Structured {
                schema: StructuredValueSchema::ImtCursorTransitionV1,
                canonical_bytes,
            }) => ImtCursorTransition::decode_canonical(canonical_bytes)?,
            _ => return Err(ReplayPrototypeError::ImtCursorTransitionRequired),
        };
        if transition.checkpoint() != receipt.checkpoint() {
            return Err(ReplayPrototypeError::ImtCursorCheckpointMismatch {
                receipt: receipt.checkpoint(),
                transition: transition.checkpoint(),
            });
        }
    }
    Ok(())
}

fn validate_receipt_payload_authority(
    receipt: &ReplayReceipt,
    payload_kind: PreparedPayloadKind,
) -> Result<(), ReplayPrototypeError> {
    if matches!(
        (receipt.authority(), payload_kind),
        (ReplayAuthority::Coordinator, PreparedPayloadKind::Coordinator)
            | (ReplayAuthority::Realm, PreparedPayloadKind::Realm)
    ) {
        Ok(())
    } else {
        Err(ReplayPrototypeError::ReceiptPayloadAuthorityMismatch)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayCoverageAction {
    PreparedPayloadDirect,
    DerivedSupplement,
    OperationalExcluded,
    RetireUnused,
    BlockedSchema(RegistryBlocker),
    SnapshotRebuildOrRotate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalReplayCoverage {
    pub physical_table: ScyllaPhysicalTableId,
    pub action: ReplayCoverageAction,
    pub rationale: &'static str,
}

/// Exhaustive by construction: adding a physical identity requires a new arm.
pub const fn physical_replay_coverage(id: ScyllaPhysicalTableId) -> PhysicalReplayCoverage {
    use ReplayCoverageAction as A;
    use ScyllaPhysicalTableId as P;
    let (action, rationale) = match id {
        P::CheckpointLeaf => (A::PreparedPayloadDirect, "checkpoint-keyed KIV from checkpoint commit/sync receipt"),
        P::CheckpointRootToCheckpointIdK1 | P::CheckpointRootToCheckpointIdK2 => {
            (A::DerivedSupplement, "writer-derived root pair; both directions must be emitted")
        }
        P::CheckpointLeafToCheckpointIdK1 | P::CheckpointLeafToCheckpointIdK2 | P::CheckpointIdToRealmRoot => {
            (A::RetireUnused, "registered but unused legacy physical table")
        }
        P::L2BlockState | P::CheckpointStateRoots => (A::PreparedPayloadDirect, "checkpoint metadata receipt"),
        P::LatestInfo | P::U64Singleton => (A::DerivedSupplement, "mutable singleton restore mutation"),
        P::CheckpointedObject => (A::BlockedSchema(RegistryBlocker::MixedCheckpointPendingAxis), "mixed checkpoint/pending axis"),
        P::UserLeaf | P::UserPublicKey => (A::PreparedPayloadDirect, "prepared authoritative user mutation"),
        P::U64CounterSingleton => (A::OperationalExcluded, "monotonic operational counter is preserved"),
        P::ContractStateTreeHeight => (A::DerivedSupplement, "writer-derived height, including Realm metadata sync"),
        P::CheckpointIdToPendingId => {
            (A::BlockedSchema(RegistryBlocker::ReusableCheckpointHeightKey), "reused height can retain old mapping")
        }
        P::PendingIdToCheckpointId
        | P::PendingIdToPendingProcIdU64ToU128
        | P::PendingIdToPendingProcIdU128ToU64 => (A::OperationalExcluded, "pending/proc context is rotated, not replayed"),
        P::RealmRewardsTreeNodeKey => {
            (A::BlockedSchema(RegistryBlocker::PendingSuffixReadThrough), "<= pending reads can cross an orphan branch")
        }
        P::PublicKeyHashToUserIds
        | P::GlobalUserTree
        | P::UserContractTree
        | P::ContractStateTree
        | P::UserRegistrationTree
        | P::GlobalContractTree
        | P::ContractFunctionTree
        | P::ContractLeaf
        | P::ContractCodeDefinition
        | P::ImtLeaf => (A::PreparedPayloadDirect, "prepared authoritative mutation"),
        P::GlobalCheckpointTree => {
            (A::DerivedSupplement, "current writer recomputes the checkpoint-tree path from live DB state")
        }
        P::GutaRewardTagTree => (A::SnapshotRebuildOrRotate, "unique_pending_id namespace rotates; old partition is GC-only"),
        P::CheckpointZkProofAndTransition => (A::DerivedSupplement, "proof is a commit input outside current prepared struct"),
        P::ImtKeyIndex => (A::DerivedSupplement, "derived from IMT leaf birth"),
        P::ImtNextAppendIndex => (A::DerivedSupplement, "mutable cursor restore derived from IMT leaf workload"),
    };
    PhysicalReplayCoverage { physical_table: id, action, rationale }
}

pub fn replay_coverage_matrix() -> Vec<PhysicalReplayCoverage> {
    ScyllaPhysicalTableId::iter().map(physical_replay_coverage).collect()
}

pub fn validate_replay_coverage() -> Result<(), ReplayPrototypeError> {
    let matrix = replay_coverage_matrix();
    if matrix.len() != 35 {
        return Err(ReplayPrototypeError::CoverageCountMismatch(matrix.len()));
    }
    for row in matrix {
        let registry = physical_descriptor(row.physical_table);
        match (registry.readiness, row.action) {
            (RegistryReadiness::Blocked(expected), ReplayCoverageAction::BlockedSchema(actual)) if expected == actual => {}
            (RegistryReadiness::RetireCandidate, ReplayCoverageAction::RetireUnused) => {}
            (RegistryReadiness::Ready, ReplayCoverageAction::BlockedSchema(_))
            | (RegistryReadiness::Ready, ReplayCoverageAction::RetireUnused)
            | (RegistryReadiness::Blocked(_), _)
            | (RegistryReadiness::RetireCandidate, _) => return Err(ReplayPrototypeError::CoverageReadinessMismatch(row.physical_table)),
            (RegistryReadiness::Ready, _) => {}
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayPrototypeError {
    MutationBuild(MutationBuildError),
    MutationDecode(MutationDecodeError),
    UnknownReplayRecordKind(u8),
    UnknownPreparedPayloadKind(u8),
    UnknownPayloadCodec(u16),
    UnknownWriterVersion(u16),
    UnknownReplayAdapterVersion(u16),
    UnknownPreparedSchemaTag(u8),
    UnknownReplaySchemaVersion,
    UnknownReplayAuthority(u8),
    UnknownOperationalReplayAction(u8),
    UnexpectedReplayRecordKind,
    InvalidCanonicalPayload(&'static str),
    NonDurablePayloadSource(&'static str),
    PreparedPayloadLengthMismatch,
    PreparedPayloadDigestMismatch,
    PreparedPayloadKindMismatch,
    PayloadMutationNotAllowedForAuthority,
    NonCanonicalPreparedOrdering,
    NonCanonicalOperationalActions,
    NonCanonicalPhysicalMutationBatch,
    NonCanonicalCompactReplayRecord,
    CompactReplayArtifactsRequired,
    DurablePreparedPayloadMissing,
    ManifestMutationDigestMismatch,
    ReceiptPayloadAuthorityMismatch,
    ExpandedMutationDigestMismatch,
    DigestOnlyValueNotExecutable,
    DuplicatePhysicalKey,
    CoverageCountMismatch(usize),
    CoverageReadinessMismatch(ScyllaPhysicalTableId),
    ReceiptMutationCountMismatch { receipt: usize, actual: usize },
    ImtCursorTransition(ImtCursorTransitionError),
    ImtCursorTransitionRequired,
    ImtCursorAuthorityMismatch,
    ImtCursorCheckpointMismatch {
        receipt: CheckpointId,
        transition: CheckpointId,
    },
}

impl From<MutationBuildError> for ReplayPrototypeError {
    fn from(value: MutationBuildError) -> Self {
        Self::MutationBuild(value)
    }
}

impl From<MutationDecodeError> for ReplayPrototypeError {
    fn from(value: MutationDecodeError) -> Self {
        Self::MutationDecode(value)
    }
}

impl From<ImtCursorTransitionError> for ReplayPrototypeError {
    fn from(value: ImtCursorTransitionError) -> Self {
        Self::ImtCursorTransition(value)
    }
}

impl fmt::Display for ReplayPrototypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for ReplayPrototypeError {}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ReplayPrototypeError> {
        if self.remaining.len() < length {
            return Err(ReplayPrototypeError::InvalidCanonicalPayload("truncated payload"));
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ReplayPrototypeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ReplayPrototypeError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("fixed length")))
    }

    fn u32(&mut self) -> Result<u32, ReplayPrototypeError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("fixed length")))
    }

    fn u64(&mut self) -> Result<u64, ReplayPrototypeError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("fixed length")))
    }

    fn array_32(&mut self) -> Result<[u8; 32], ReplayPrototypeError> {
        Ok(self.take(32)?.try_into().expect("fixed length"))
    }

    fn checkpoint(&mut self) -> Result<CheckpointId, ReplayPrototypeError> {
        CheckpointId::try_new(self.u64()?).map_err(|_| ReplayPrototypeError::InvalidCanonicalPayload("checkpoint out of range"))
    }

    fn bytes(&mut self) -> Result<&'a [u8], ReplayPrototypeError> {
        let length = self.u32()? as usize;
        self.take(length)
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    const fn remaining_len(&self) -> usize {
        self.remaining.len()
    }
}

/// Helper used by representative Realm fixtures to build the two IMT writer-
/// derived supplements from one prepared leaf mutation.
pub fn imt_leaf_supplements(
    tree: TreeId,
    tree_sub: TreeSubId,
    encoded_key: ImtEncodedKey,
    birth_checkpoint: CheckpointId,
    cursor_before: u64,
    cursor_after: u64,
) -> Result<Vec<LogicalMutation>, ReplayPrototypeError> {
    let cursor_transition = ImtCursorTransition::try_new(
        birth_checkpoint,
        cursor_before,
        cursor_after,
    )?;
    Ok(vec![
        LogicalMutation::Put {
            key: TypedTableKey::ImtKeyIndex { tree, tree_sub, encoded_key },
            value: MutationValue::Structured {
                schema: StructuredValueSchema::ImtKeyIndexRowV1,
                canonical_bytes: birth_checkpoint.get().to_be_bytes().to_vec(),
            },
        },
        LogicalMutation::Put {
            key: TypedTableKey::ImtCursor { tree, tree_sub },
            value: MutationValue::imt_cursor_transition(cursor_transition),
        },
    ])
}

/// Explicit restore mutation for the mutable latest-checkpoint singleton.
pub fn latest_checkpoint_restore(checkpoint: CheckpointId) -> LogicalMutation {
    LogicalMutation::Put {
        key: TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint),
        value: MutationValue::CqlU64(checkpoint.get()),
    }
}
