//! D-02T10 typed writes for the pending-keyed reward tag tree.
//!
//! Rollback never rewrites or synchronously deletes an old tag-tree partition.
//! A new branch first allocates a fresh pending/proc context through D-02T9,
//! then this adapter accepts writes only for that current-at-reconcile pending
//! capability. Historical mapping-backfill ownership cannot be narrowed to the
//! capability required here.
//!
//! This prototype is not wired into production setup. D-04 must durably retain
//! the sealed allocation and hold the processor/context-rotation guard while a
//! current capability is used, closing the time-of-check/time-of-use window.
//!
//! ```compile_fail
//! use psy_node_scylla::rollback::RewardTagTreeAdapter;
//! ```

use std::{collections::BTreeSet, error::Error, fmt};

use psy_node_core::store::typed::{
    MerkleNode, MutationOperation, MutationValue, StructuredValueSchema,
    TypedTableKey, UniquePendingId,
};
use scylla::{
    client::session::Session,
    statement::{
        batch::{Batch, BatchType},
        prepared::PreparedStatement,
        Consistency,
    },
};
use sha2::{Digest, Sha256};

use crate::utils::{u64_to_i64_exact, u8_to_i8_exact};

use super::{
    physical_descriptor, CqlKeyspaceName, PendingCounterPlanDigest,
    PrototypeBindValue, ScyllaPhysicalTableId, SealedTimestampedPut,
    TimestampedIntentDigest, TimestampedWriteKind,
    VerifiedCurrentPendingOwnership,
};

const TAG_TREE_HASH_BYTES: usize = 32;
const TAG_TREE_PAYLOAD_MAGIC: &[u8; 4] = b"PTRN";
const TAG_TREE_PAYLOAD_VERSION: u16 = 1;
const TAG_TREE_VALUE_ONLY_BYTES: usize = 4 + 2 + 1 + TAG_TREE_HASH_BYTES;
const TAG_TREE_FULL_BYTES: usize = TAG_TREE_VALUE_ONLY_BYTES + TAG_TREE_HASH_BYTES;
const MAX_UNLOGGED_BATCH_ROWS: usize = 100;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RewardTagTreeWriteMode {
    FullNode = 1,
    ValueOnly = 2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewardTagTreeNodePayloadV1 {
    mode: RewardTagTreeWriteMode,
    value: [u8; TAG_TREE_HASH_BYTES],
    tag: Option<[u8; TAG_TREE_HASH_BYTES]>,
}

impl RewardTagTreeNodePayloadV1 {
    pub fn try_full(
        value: &[u8],
        tag: &[u8],
    ) -> Result<Self, RewardTagTreePayloadError> {
        Ok(Self {
            mode: RewardTagTreeWriteMode::FullNode,
            value: exact_hash("node_value", value)?,
            tag: Some(exact_hash("node_tag", tag)?),
        })
    }

    pub fn try_value_only(
        value: &[u8],
    ) -> Result<Self, RewardTagTreePayloadError> {
        Ok(Self {
            mode: RewardTagTreeWriteMode::ValueOnly,
            value: exact_hash("node_value", value)?,
            tag: None,
        })
    }

    pub const fn mode(&self) -> RewardTagTreeWriteMode {
        self.mode
    }

    pub const fn value(&self) -> &[u8; TAG_TREE_HASH_BYTES] {
        &self.value
    }

    pub const fn tag(&self) -> Option<&[u8; TAG_TREE_HASH_BYTES]> {
        self.tag.as_ref()
    }

    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(match self.mode {
            RewardTagTreeWriteMode::FullNode => TAG_TREE_FULL_BYTES,
            RewardTagTreeWriteMode::ValueOnly => TAG_TREE_VALUE_ONLY_BYTES,
        });
        bytes.extend_from_slice(TAG_TREE_PAYLOAD_MAGIC);
        bytes.extend_from_slice(&TAG_TREE_PAYLOAD_VERSION.to_be_bytes());
        bytes.push(self.mode as u8);
        bytes.extend_from_slice(&self.value);
        if let Some(tag) = self.tag {
            bytes.extend_from_slice(&tag);
        }
        bytes
    }

    pub fn into_mutation_value(self) -> MutationValue {
        MutationValue::Structured {
            schema: StructuredValueSchema::TagTreeNodeV1,
            canonical_bytes: self.encode_canonical(),
        }
    }

    pub fn try_decode(bytes: &[u8]) -> Result<Self, RewardTagTreePayloadError> {
        if bytes.len() < 7 {
            return Err(RewardTagTreePayloadError::Truncated {
                actual: bytes.len(),
            });
        }
        if &bytes[..4] != TAG_TREE_PAYLOAD_MAGIC {
            return Err(RewardTagTreePayloadError::InvalidMagic);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != TAG_TREE_PAYLOAD_VERSION {
            return Err(RewardTagTreePayloadError::UnknownVersion(version));
        }
        let (mode, expected_len) = match bytes[6] {
            1 => (RewardTagTreeWriteMode::FullNode, TAG_TREE_FULL_BYTES),
            2 => (
                RewardTagTreeWriteMode::ValueOnly,
                TAG_TREE_VALUE_ONLY_BYTES,
            ),
            value => return Err(RewardTagTreePayloadError::UnknownMode(value)),
        };
        if bytes.len() != expected_len {
            return Err(RewardTagTreePayloadError::InvalidLength {
                mode,
                expected: expected_len,
                actual: bytes.len(),
            });
        }
        let value = bytes[7..7 + TAG_TREE_HASH_BYTES]
            .try_into()
            .expect("length was checked");
        let tag = match mode {
            RewardTagTreeWriteMode::FullNode => Some(
                bytes[7 + TAG_TREE_HASH_BYTES..]
                    .try_into()
                    .expect("length was checked"),
            ),
            RewardTagTreeWriteMode::ValueOnly => None,
        };
        Ok(Self { mode, value, tag })
    }
}

fn exact_hash(
    field: &'static str,
    value: &[u8],
) -> Result<[u8; TAG_TREE_HASH_BYTES], RewardTagTreePayloadError> {
    value.try_into().map_err(|_| {
        RewardTagTreePayloadError::InvalidHashLength {
            field,
            actual: value.len(),
        }
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RewardTagTreePayloadError {
    InvalidHashLength { field: &'static str, actual: usize },
    Truncated { actual: usize },
    InvalidMagic,
    UnknownVersion(u16),
    UnknownMode(u8),
    InvalidLength {
        mode: RewardTagTreeWriteMode,
        expected: usize,
        actual: usize,
    },
}

impl fmt::Display for RewardTagTreePayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid reward tag-tree payload: {self:?}")
    }
}

impl Error for RewardTagTreePayloadError {}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RewardTagTreeQueryKind {
    FullNodePut = 1,
    ValueOnlyPut = 2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewardTagTreeQuery {
    kind: RewardTagTreeQueryKind,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl RewardTagTreeQuery {
    pub const fn kind(&self) -> RewardTagTreeQueryKind {
        self.kind
    }

    pub fn cql(&self) -> &str {
        &self.cql
    }

    pub const fn bind_shape(&self) -> &'static [&'static str] {
        self.bind_shape
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewardTagTreeQueries {
    full_node_put: RewardTagTreeQuery,
    value_only_put: RewardTagTreeQuery,
}

impl RewardTagTreeQueries {
    pub fn new(keyspace: &CqlKeyspaceName) -> Self {
        let table = physical_descriptor(
            ScyllaPhysicalTableId::GutaRewardTagTree,
        )
        .physical_name;
        let qualified = format!("{}.{table}", keyspace.as_str());
        Self {
            full_node_put: RewardTagTreeQuery {
                kind: RewardTagTreeQueryKind::FullNodePut,
                cql: format!(
                    "INSERT INTO {qualified} (unique_pending_id, level, node_index, node_value, node_tag) VALUES (?, ?, ?, ?, ?) USING TIMESTAMP ?"
                ),
                bind_shape: &[
                    "unique_pending_id:BIGINT",
                    "level:TINYINT",
                    "node_index:BIGINT",
                    "node_value:BLOB",
                    "node_tag:BLOB",
                    "write_timestamp_us:BIGINT",
                ],
            },
            value_only_put: RewardTagTreeQuery {
                kind: RewardTagTreeQueryKind::ValueOnlyPut,
                cql: format!(
                    "UPDATE {qualified} USING TIMESTAMP ? SET node_value = ? WHERE unique_pending_id = ? AND level = ? AND node_index = ?"
                ),
                bind_shape: &[
                    "write_timestamp_us:BIGINT",
                    "node_value:BLOB",
                    "unique_pending_id:BIGINT",
                    "level:TINYINT",
                    "node_index:BIGINT",
                ],
            },
        }
    }

    pub const fn full_node_put(&self) -> &RewardTagTreeQuery {
        &self.full_node_put
    }

    pub const fn value_only_put(&self) -> &RewardTagTreeQuery {
        &self.value_only_put
    }

    pub fn render_golden(&self) -> String {
        let mut output = String::new();
        for query in [self.full_node_put(), self.value_only_put()] {
            output.push_str(&format!(
                "{:?}\n{}\n{}\n",
                query.kind(),
                query.cql(),
                query.bind_shape().join(",")
            ));
        }
        output
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RewardTagTreeWriteDigest([u8; 32]);

impl RewardTagTreeWriteDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewardTagTreePutBinding {
    pending: UniquePendingId,
    proc_id: psy_node_core::store::typed::ProcCheckpointUniqueId,
    node: MerkleNode,
    payload: RewardTagTreeNodePayloadV1,
    write_timestamp_us: i64,
    write_kind: TimestampedWriteKind,
    timestamped_intent_digest: TimestampedIntentDigest,
    ownership_digest: PendingCounterPlanDigest,
    digest: RewardTagTreeWriteDigest,
}

impl RewardTagTreePutBinding {
    pub fn try_from_sealed(
        sealed: &SealedTimestampedPut,
        ownership: VerifiedCurrentPendingOwnership,
    ) -> Result<Self, RewardTagTreePlanError> {
        let mutation = sealed.resolved().mutation();
        if mutation.physical_table()
            != ScyllaPhysicalTableId::GutaRewardTagTree
        {
            return Err(RewardTagTreePlanError::WrongPhysicalTable(
                mutation.physical_table(),
            ));
        }
        let (pending, node) = match mutation.key() {
            TypedTableKey::RewardTagMerkle { pending, node } => {
                (*pending, *node)
            }
            _ => return Err(RewardTagTreePlanError::WrongTypedKey),
        };
        if pending != ownership.pending() {
            return Err(RewardTagTreePlanError::PendingMismatch {
                owned: ownership.pending(),
                mutation: pending,
            });
        }
        if sealed.write_kind() != ownership.write_kind() {
            return Err(RewardTagTreePlanError::WriteKindMismatch {
                namespace: ownership.write_kind(),
                mutation: sealed.write_kind(),
            });
        }
        if sealed.timestamp().as_i64()
            < ownership.write_timestamp_us().as_i64()
        {
            return Err(RewardTagTreePlanError::WriteBeforeNamespace {
                namespace_timestamp: ownership.write_timestamp_us().as_i64(),
                write_timestamp: sealed.timestamp().as_i64(),
            });
        }
        let payload = match mutation.operation() {
            MutationOperation::Put(MutationValue::Structured {
                schema: StructuredValueSchema::TagTreeNodeV1,
                canonical_bytes,
            }) => RewardTagTreeNodePayloadV1::try_decode(canonical_bytes)?,
            _ => return Err(RewardTagTreePlanError::ExpectedTagTreeNodeV1),
        };
        let digest = write_digest(sealed, ownership);
        Ok(Self {
            pending,
            proc_id: ownership.proc_id(),
            node,
            payload,
            write_timestamp_us: sealed.timestamp().as_i64(),
            write_kind: sealed.write_kind(),
            timestamped_intent_digest: sealed.intent_digest(),
            ownership_digest: ownership.plan_digest(),
            digest,
        })
    }

    pub const fn pending(&self) -> UniquePendingId {
        self.pending
    }

    pub const fn proc_id(
        &self,
    ) -> psy_node_core::store::typed::ProcCheckpointUniqueId {
        self.proc_id
    }

    pub const fn node(&self) -> MerkleNode {
        self.node
    }

    pub const fn payload(&self) -> &RewardTagTreeNodePayloadV1 {
        &self.payload
    }

    pub const fn write_timestamp_us(&self) -> i64 {
        self.write_timestamp_us
    }

    pub const fn write_kind(&self) -> TimestampedWriteKind {
        self.write_kind
    }

    pub const fn timestamped_intent_digest(
        &self,
    ) -> TimestampedIntentDigest {
        self.timestamped_intent_digest
    }

    pub const fn ownership_digest(&self) -> PendingCounterPlanDigest {
        self.ownership_digest
    }

    pub const fn digest(&self) -> RewardTagTreeWriteDigest {
        self.digest
    }

    pub fn ensure_exact_retry(
        &self,
        sealed: &SealedTimestampedPut,
        ownership: VerifiedCurrentPendingOwnership,
    ) -> Result<(), RewardTagTreePlanError> {
        let candidate = Self::try_from_sealed(sealed, ownership)?;
        if candidate == *self {
            Ok(())
        } else {
            Err(RewardTagTreePlanError::RetryChanged)
        }
    }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        match self.payload.mode() {
            RewardTagTreeWriteMode::FullNode => vec![
                PrototypeBindValue::BigInt(u64_to_i64_exact(
                    self.pending.get(),
                )),
                PrototypeBindValue::TinyInt(u8_to_i8_exact(
                    self.node.level(),
                )),
                PrototypeBindValue::BigInt(u64_to_i64_exact(
                    self.node.index().get(),
                )),
                PrototypeBindValue::Blob(self.payload.value().to_vec()),
                PrototypeBindValue::Blob(
                    self.payload.tag().expect("full payload has tag").to_vec(),
                ),
                PrototypeBindValue::BigInt(self.write_timestamp_us),
            ],
            RewardTagTreeWriteMode::ValueOnly => vec![
                PrototypeBindValue::BigInt(self.write_timestamp_us),
                PrototypeBindValue::Blob(self.payload.value().to_vec()),
                PrototypeBindValue::BigInt(u64_to_i64_exact(
                    self.pending.get(),
                )),
                PrototypeBindValue::TinyInt(u8_to_i8_exact(
                    self.node.level(),
                )),
                PrototypeBindValue::BigInt(u64_to_i64_exact(
                    self.node.index().get(),
                )),
            ],
        }
    }

    fn full_driver_values(
        &self,
    ) -> Result<(i64, i8, i64, Vec<u8>, Vec<u8>, i64), RewardTagTreePlanError>
    {
        let tag = self
            .payload
            .tag()
            .ok_or(RewardTagTreePlanError::ExpectedFullNode)?;
        Ok((
            u64_to_i64_exact(self.pending.get()),
            u8_to_i8_exact(self.node.level()),
            u64_to_i64_exact(self.node.index().get()),
            self.payload.value().to_vec(),
            tag.to_vec(),
            self.write_timestamp_us,
        ))
    }

    fn value_only_driver_values(
        &self,
    ) -> (i64, Vec<u8>, i64, i8, i64) {
        (
            self.write_timestamp_us,
            self.payload.value().to_vec(),
            u64_to_i64_exact(self.pending.get()),
            u8_to_i8_exact(self.node.level()),
            u64_to_i64_exact(self.node.index().get()),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewardTagTreeFullPutBatch {
    pending: UniquePendingId,
    write_timestamp_us: i64,
    members: Vec<RewardTagTreePutBinding>,
}

impl RewardTagTreeFullPutBatch {
    pub fn try_from_sealed(
        sealed: &[SealedTimestampedPut],
        ownership: VerifiedCurrentPendingOwnership,
    ) -> Result<Self, RewardTagTreePlanError> {
        if sealed.is_empty() {
            return Err(RewardTagTreePlanError::EmptyBatch);
        }
        let mut keys = BTreeSet::new();
        let mut members = Vec::with_capacity(sealed.len());
        let mut write_timestamp_us = None;
        for member in sealed {
            let binding =
                RewardTagTreePutBinding::try_from_sealed(member, ownership)?;
            if binding.payload.mode() != RewardTagTreeWriteMode::FullNode {
                return Err(RewardTagTreePlanError::ExpectedFullNode);
            }
            if let Some(expected) = write_timestamp_us {
                if expected != binding.write_timestamp_us {
                    return Err(RewardTagTreePlanError::MixedWriteTimestamps {
                        expected,
                        actual: binding.write_timestamp_us,
                    });
                }
            } else {
                write_timestamp_us = Some(binding.write_timestamp_us);
            }
            if !keys.insert(binding.node) {
                return Err(RewardTagTreePlanError::DuplicatePhysicalKey);
            }
            members.push(binding);
        }
        Ok(Self {
            pending: ownership.pending(),
            write_timestamp_us: write_timestamp_us.expect("non-empty"),
            members,
        })
    }

    pub const fn pending(&self) -> UniquePendingId {
        self.pending
    }

    pub const fn write_timestamp_us(&self) -> i64 {
        self.write_timestamp_us
    }

    pub fn members(&self) -> &[RewardTagTreePutBinding] {
        &self.members
    }
}

fn write_digest(
    sealed: &SealedTimestampedPut,
    ownership: VerifiedCurrentPendingOwnership,
) -> RewardTagTreeWriteDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"psy/reward-tag-tree-write/v1");
    hasher.update(sealed.intent_digest().as_bytes());
    hasher.update(ownership.plan_digest().as_bytes());
    hasher.update(ownership.proc_id().as_bytes());
    RewardTagTreeWriteDigest(hasher.finalize().into())
}

struct PreparedRewardTagTree {
    full_node_put: PreparedStatement,
    value_only_put: PreparedStatement,
}

#[allow(dead_code)]
pub(crate) struct RewardTagTreeAdapter {
    queries: RewardTagTreeQueries,
    consistency: Consistency,
    prepared: PreparedRewardTagTree,
}

#[allow(dead_code)]
impl RewardTagTreeAdapter {
    pub(crate) async fn prepare_with_consistency(
        session: &Session,
        keyspace: CqlKeyspaceName,
        consistency: Consistency,
    ) -> anyhow::Result<Self> {
        let queries = RewardTagTreeQueries::new(&keyspace);
        let prepared = PreparedRewardTagTree {
            full_node_put: prepare_idempotent(
                session,
                queries.full_node_put().cql(),
                consistency,
            )
            .await?,
            value_only_put: prepare_idempotent(
                session,
                queries.value_only_put().cql(),
                consistency,
            )
            .await?,
        };
        Ok(Self {
            queries,
            consistency,
            prepared,
        })
    }

    pub(crate) const fn queries(&self) -> &RewardTagTreeQueries {
        &self.queries
    }

    pub(crate) async fn put_one(
        &self,
        session: &Session,
        binding: &RewardTagTreePutBinding,
    ) -> anyhow::Result<()> {
        match binding.payload.mode() {
            RewardTagTreeWriteMode::FullNode => {
                session
                    .execute_unpaged(
                        &self.prepared.full_node_put,
                        binding.full_driver_values()?,
                    )
                    .await?;
            }
            RewardTagTreeWriteMode::ValueOnly => {
                session
                    .execute_unpaged(
                        &self.prepared.value_only_put,
                        binding.value_only_driver_values(),
                    )
                    .await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn put_full_batch(
        &self,
        session: &Session,
        plan: &RewardTagTreeFullPutBatch,
    ) -> anyhow::Result<()> {
        for chunk in plan.members.chunks(MAX_UNLOGGED_BATCH_ROWS) {
            let mut batch = Batch::new(BatchType::Unlogged);
            batch.set_consistency(self.consistency);
            batch.set_is_idempotent(true);
            for _ in chunk {
                batch.append_statement(self.prepared.full_node_put.clone());
            }
            let values = chunk
                .iter()
                .map(RewardTagTreePutBinding::full_driver_values)
                .collect::<Result<Vec<_>, _>>()?;
            session.batch(&batch, values).await?;
        }
        Ok(())
    }
}

async fn prepare_idempotent(
    session: &Session,
    cql: &str,
    consistency: Consistency,
) -> anyhow::Result<PreparedStatement> {
    let mut statement = session.prepare(cql).await?;
    statement.set_consistency(consistency);
    statement.set_is_idempotent(true);
    Ok(statement)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RewardTagTreePlanError {
    WrongPhysicalTable(ScyllaPhysicalTableId),
    WrongTypedKey,
    ExpectedTagTreeNodeV1,
    Payload(RewardTagTreePayloadError),
    PendingMismatch {
        owned: UniquePendingId,
        mutation: UniquePendingId,
    },
    WriteKindMismatch {
        namespace: TimestampedWriteKind,
        mutation: TimestampedWriteKind,
    },
    WriteBeforeNamespace {
        namespace_timestamp: i64,
        write_timestamp: i64,
    },
    EmptyBatch,
    ExpectedFullNode,
    MixedWriteTimestamps { expected: i64, actual: i64 },
    DuplicatePhysicalKey,
    RetryChanged,
}

impl fmt::Display for RewardTagTreePlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "reward tag-tree write rejected: {self:?}")
    }
}

impl Error for RewardTagTreePlanError {}

impl From<RewardTagTreePayloadError> for RewardTagTreePlanError {
    fn from(value: RewardTagTreePayloadError) -> Self {
        Self::Payload(value)
    }
}
