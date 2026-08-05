//! Isolated G0-06 adapters for two representative production schemas.
//!
//! Nothing in production setup constructs these adapters. They exist to give
//! the later RF=3 harness real prepare/execute paths without claiming full
//! table coverage.

use std::{error::Error, fmt};

use psy_node_core::store::{
    timestamp::DeleteFenceTimestampUs,
    typed::{CheckpointId, CheckpointRootKey, MerkleNode, MutationOperation, MutationValue, TypedTableKey},
};
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Consistency},
};

use crate::utils::{convert_checkpoint_id_to_i64, u64_to_i64_exact, u8_to_i8_exact};

use super::{
    physical_descriptor, resolve_key_for_rollback, RegistryReadinessError, ScyllaPhysicalTableId, SealedTimestampedPut,
    SealedTimestampedPutBatch,
};

const MERKLE_ZERO_HASH_BYTES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidCqlKeyspaceName(pub String);

impl fmt::Display for InvalidCqlKeyspaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid unquoted CQL keyspace identifier {:?}", self.0)
    }
}

impl Error for InvalidCqlKeyspaceName {}

/// A validated unquoted CQL identifier. Representative table names are never
/// supplied by callers; they are resolved from the typed physical registry.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CqlKeyspaceName(String);

impl CqlKeyspaceName {
    pub fn try_new(name: impl Into<String>) -> Result<Self, InvalidCqlKeyspaceName> {
        let name = name.into();
        let mut chars = name.chars();
        let valid_first = chars.next().is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic());
        let valid_rest = chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric());
        if name.len() <= 48 && valid_first && valid_rest {
            Ok(Self(name))
        } else {
            Err(InvalidCqlKeyspaceName(name))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum TimestampPrototypeQueryId {
    CheckpointLeafPut = 1,
    CheckpointLeafVersionPartitionDelete = 2,
    GlobalUserMerklePut = 3,
    GlobalUserMerklePointDelete = 4,
    GlobalUserMerkleBoundedRangeDelete = 5,
}

/// The exact value order consumed by each prepared statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrototypeBindValue {
    TinyInt(i8),
    BigInt(i64),
    Blob(Vec<u8>),
}

impl PrototypeBindValue {
    fn shape_name(&self) -> &'static str {
        match self {
            Self::TinyInt(_) => "TINYINT",
            Self::BigInt(_) => "BIGINT",
            Self::Blob(_) => "BLOB",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimestampPrototypeQuery {
    id: TimestampPrototypeQueryId,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl TimestampPrototypeQuery {
    pub const fn id(&self) -> TimestampPrototypeQueryId {
        self.id
    }

    pub fn cql(&self) -> &str {
        &self.cql
    }

    pub const fn bind_shape(&self) -> &'static [&'static str] {
        self.bind_shape
    }
}

/// The single source of query text for both production-shaped prepare calls
/// and offline golden tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimestampPrototypeQueries {
    checkpoint_leaf_put: TimestampPrototypeQuery,
    checkpoint_leaf_delete: TimestampPrototypeQuery,
    global_user_merkle_put: TimestampPrototypeQuery,
    global_user_merkle_point_delete: TimestampPrototypeQuery,
    global_user_merkle_range_delete: TimestampPrototypeQuery,
}

impl TimestampPrototypeQueries {
    pub fn new(keyspace: &CqlKeyspaceName) -> Self {
        let checkpoint_leaf = physical_descriptor(ScyllaPhysicalTableId::CheckpointLeaf).physical_name;
        let global_user = physical_descriptor(ScyllaPhysicalTableId::GlobalUserTree).physical_name;
        let qualified_leaf = format!("{}.{}", keyspace.as_str(), checkpoint_leaf);
        let qualified_global_user = format!("{}.{}", keyspace.as_str(), global_user);
        Self {
            checkpoint_leaf_put: TimestampPrototypeQuery {
                id: TimestampPrototypeQueryId::CheckpointLeafPut,
                cql: format!("INSERT INTO {qualified_leaf} (obj_id, value) VALUES (?, ?) USING TIMESTAMP ?"),
                bind_shape: &["obj_id:BIGINT", "value:BLOB", "write_timestamp_us:BIGINT"],
            },
            checkpoint_leaf_delete: TimestampPrototypeQuery {
                id: TimestampPrototypeQueryId::CheckpointLeafVersionPartitionDelete,
                cql: format!("DELETE FROM {qualified_leaf} USING TIMESTAMP ? WHERE obj_id = ?"),
                bind_shape: &["delete_fence_us:BIGINT", "obj_id:BIGINT"],
            },
            global_user_merkle_put: TimestampPrototypeQuery {
                id: TimestampPrototypeQueryId::GlobalUserMerklePut,
                cql: format!(
                    "INSERT INTO {qualified_global_user} (level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?) USING TIMESTAMP ?"
                ),
                bind_shape: &[
                    "level:TINYINT",
                    "node_index:BIGINT",
                    "checkpoint_id:BIGINT",
                    "value:BLOB",
                    "write_timestamp_us:BIGINT",
                ],
            },
            global_user_merkle_point_delete: TimestampPrototypeQuery {
                id: TimestampPrototypeQueryId::GlobalUserMerklePointDelete,
                cql: format!(
                    "DELETE FROM {qualified_global_user} USING TIMESTAMP ? WHERE level = ? AND node_index = ? AND checkpoint_id = ?"
                ),
                bind_shape: &[
                    "delete_fence_us:BIGINT",
                    "level:TINYINT",
                    "node_index:BIGINT",
                    "checkpoint_id:BIGINT",
                ],
            },
            global_user_merkle_range_delete: TimestampPrototypeQuery {
                id: TimestampPrototypeQueryId::GlobalUserMerkleBoundedRangeDelete,
                cql: format!(
                    "DELETE FROM {qualified_global_user} USING TIMESTAMP ? WHERE level = ? AND node_index = ? AND checkpoint_id > ? AND checkpoint_id <= ?"
                ),
                bind_shape: &[
                    "delete_fence_us:BIGINT",
                    "level:TINYINT",
                    "node_index:BIGINT",
                    "target_checkpoint_id:BIGINT",
                    "old_head_checkpoint_id:BIGINT",
                ],
            },
        }
    }

    pub const fn checkpoint_leaf_put(&self) -> &TimestampPrototypeQuery {
        &self.checkpoint_leaf_put
    }

    pub const fn checkpoint_leaf_delete(&self) -> &TimestampPrototypeQuery {
        &self.checkpoint_leaf_delete
    }

    pub const fn global_user_merkle_put(&self) -> &TimestampPrototypeQuery {
        &self.global_user_merkle_put
    }

    pub const fn global_user_merkle_point_delete(&self) -> &TimestampPrototypeQuery {
        &self.global_user_merkle_point_delete
    }

    pub const fn global_user_merkle_range_delete(&self) -> &TimestampPrototypeQuery {
        &self.global_user_merkle_range_delete
    }

    pub fn all(&self) -> [&TimestampPrototypeQuery; 5] {
        [
            &self.checkpoint_leaf_put,
            &self.checkpoint_leaf_delete,
            &self.global_user_merkle_put,
            &self.global_user_merkle_point_delete,
            &self.global_user_merkle_range_delete,
        ]
    }

    pub fn render_golden(&self) -> String {
        let mut output = String::new();
        for query in self.all() {
            output.push_str(&format!("{:?}\n{}\n{}\n", query.id(), query.cql(), query.bind_shape().join(",")));
        }
        output
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimestampPrototypePlanError {
    RegistryReadiness(RegistryReadinessError),
    WrongPhysicalTable { expected: ScyllaPhysicalTableId, actual: ScyllaPhysicalTableId },
    WrongTypedKey,
    ExpectedPsyCanonicalBytes,
    InvalidMerkleValueLength { expected: usize, actual: usize },
    ValueCodec(String),
    EmptyOrReversedRange { target: u64, old_head: u64 },
    ExpectedRootPair { actual: usize },
    InvalidCheckpointBytes { actual: usize },
}

impl fmt::Display for TimestampPrototypePlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegistryReadiness(error) => write!(f, "key domain is not rollback ready: {error:?}"),
            Self::WrongPhysicalTable { expected, actual } => {
                write!(f, "prototype expected physical table {expected:?}, got {actual:?}")
            }
            Self::WrongTypedKey => write!(f, "typed key does not match the representative adapter"),
            Self::ExpectedPsyCanonicalBytes => write!(f, "representative adapter requires executable Psy canonical bytes"),
            Self::InvalidMerkleValueLength { expected, actual } => {
                write!(f, "Merkle-zero value must be exactly {expected} bytes, got {actual}")
            }
            Self::ValueCodec(error) => write!(f, "value codec failed: {error}"),
            Self::EmptyOrReversedRange { target, old_head } => {
                write!(f, "bounded delete requires target < old_head, got {target} >= {old_head}")
            }
            Self::ExpectedRootPair { actual } => write!(f, "checkpoint root mapping must contain exactly two physical PUTs, got {actual}"),
            Self::InvalidCheckpointBytes { actual } => {
                write!(f, "checkpoint mapping value must decode to exactly 8 canonical bytes, got {actual}")
            }
        }
    }
}

impl Error for TimestampPrototypePlanError {}

impl From<RegistryReadinessError> for TimestampPrototypePlanError {
    fn from(value: RegistryReadinessError) -> Self {
        Self::RegistryReadiness(value)
    }
}

fn require_physical(
    actual: ScyllaPhysicalTableId,
    expected: ScyllaPhysicalTableId,
) -> Result<(), TimestampPrototypePlanError> {
    if actual == expected {
        Ok(())
    } else {
        Err(TimestampPrototypePlanError::WrongPhysicalTable { expected, actual })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointLeafPutBinding {
    obj_id: i64,
    stored_value: Vec<u8>,
    write_timestamp_us: i64,
}

impl CheckpointLeafPutBinding {
    pub fn try_from_sealed(sealed: &SealedTimestampedPut) -> Result<Self, TimestampPrototypePlanError> {
        let mutation = sealed.resolved().mutation();
        require_physical(mutation.physical_table(), ScyllaPhysicalTableId::CheckpointLeaf)?;
        let checkpoint = match mutation.key() {
            TypedTableKey::CheckpointLeaf(checkpoint) => *checkpoint,
            _ => return Err(TimestampPrototypePlanError::WrongTypedKey),
        };
        let canonical_value = match mutation.operation() {
            MutationOperation::Put(MutationValue::PsyCanonicalBytes(value)) => value,
            _ => return Err(TimestampPrototypePlanError::ExpectedPsyCanonicalBytes),
        };
        let stored_value = crate::compression::compress(canonical_value)
            .map_err(|error| TimestampPrototypePlanError::ValueCodec(error.to_string()))?;
        Ok(Self {
            obj_id: u64_to_i64_exact(checkpoint.get()),
            stored_value,
            write_timestamp_us: sealed.timestamp().as_i64(),
        })
    }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        let (obj_id, stored_value, write_timestamp_us) = self.driver_values();
        vec![
            PrototypeBindValue::BigInt(obj_id),
            PrototypeBindValue::Blob(stored_value.clone()),
            PrototypeBindValue::BigInt(write_timestamp_us),
        ]
    }

    fn driver_values(&self) -> (i64, &Vec<u8>, i64) {
        (self.obj_id, &self.stored_value, self.write_timestamp_us)
    }
}

/// Complete VERSION_PARTITION delete for `checkpoint_leaf_table`.
///
/// ```compile_fail
/// use psy_node_scylla::rollback::CheckpointLeafVersionDeletePlan;
/// // A partition id without a typed key and fence cannot construct a plan.
/// let _plan = CheckpointLeafVersionDeletePlan::try_new(7_u64);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointLeafVersionDeletePlan {
    checkpoint: CheckpointId,
    fence: DeleteFenceTimestampUs,
}

impl CheckpointLeafVersionDeletePlan {
    pub fn try_new(
        key: TypedTableKey,
        fence: DeleteFenceTimestampUs,
    ) -> Result<Self, TimestampPrototypePlanError> {
        let resolved = resolve_key_for_rollback(&key)?;
        require_physical(resolved.physical_table(), ScyllaPhysicalTableId::CheckpointLeaf)?;
        match key {
            TypedTableKey::CheckpointLeaf(checkpoint) => Ok(Self { checkpoint, fence }),
            _ => Err(TimestampPrototypePlanError::WrongTypedKey),
        }
    }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        let (fence, checkpoint) = self.driver_values();
        vec![
            PrototypeBindValue::BigInt(fence),
            PrototypeBindValue::BigInt(checkpoint),
        ]
    }

    fn driver_values(&self) -> (i64, i64) {
        (self.fence.as_i64(), u64_to_i64_exact(self.checkpoint.get()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GlobalUserMerklePutBinding {
    level: i8,
    node_index: i64,
    checkpoint: i64,
    value: Vec<u8>,
    write_timestamp_us: i64,
}

impl GlobalUserMerklePutBinding {
    pub fn try_from_sealed(sealed: &SealedTimestampedPut) -> Result<Self, TimestampPrototypePlanError> {
        let mutation = sealed.resolved().mutation();
        require_physical(mutation.physical_table(), ScyllaPhysicalTableId::GlobalUserTree)?;
        let (node, checkpoint) = match mutation.key() {
            TypedTableKey::GlobalUserMerkle { node, checkpoint } => (*node, *checkpoint),
            _ => return Err(TimestampPrototypePlanError::WrongTypedKey),
        };
        let value = match mutation.operation() {
            MutationOperation::Put(MutationValue::PsyCanonicalBytes(value)) => value.clone(),
            _ => return Err(TimestampPrototypePlanError::ExpectedPsyCanonicalBytes),
        };
        if value.len() != MERKLE_ZERO_HASH_BYTES {
            return Err(TimestampPrototypePlanError::InvalidMerkleValueLength {
                expected: MERKLE_ZERO_HASH_BYTES,
                actual: value.len(),
            });
        }
        Ok(Self {
            level: u8_to_i8_exact(node.level()),
            node_index: u64_to_i64_exact(node.index().get()),
            checkpoint: convert_checkpoint_id_to_i64(checkpoint.get()),
            value,
            write_timestamp_us: sealed.timestamp().as_i64(),
        })
    }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        let (level, node_index, checkpoint, value, write_timestamp_us) = self.driver_values();
        vec![
            PrototypeBindValue::TinyInt(level),
            PrototypeBindValue::BigInt(node_index),
            PrototypeBindValue::BigInt(checkpoint),
            PrototypeBindValue::Blob(value.clone()),
            PrototypeBindValue::BigInt(write_timestamp_us),
        ]
    }

    fn driver_values(&self) -> (i8, i64, i64, &Vec<u8>, i64) {
        (self.level, self.node_index, self.checkpoint, &self.value, self.write_timestamp_us)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GlobalUserMerklePointDeletePlan {
    node: MerkleNode,
    checkpoint: CheckpointId,
    fence: DeleteFenceTimestampUs,
}

impl GlobalUserMerklePointDeletePlan {
    pub fn try_new(
        key: TypedTableKey,
        fence: DeleteFenceTimestampUs,
    ) -> Result<Self, TimestampPrototypePlanError> {
        let resolved = resolve_key_for_rollback(&key)?;
        require_physical(resolved.physical_table(), ScyllaPhysicalTableId::GlobalUserTree)?;
        match key {
            TypedTableKey::GlobalUserMerkle { node, checkpoint } => Ok(Self { node, checkpoint, fence }),
            _ => Err(TimestampPrototypePlanError::WrongTypedKey),
        }
    }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        let (fence, level, node_index, checkpoint) = self.driver_values();
        vec![
            PrototypeBindValue::BigInt(fence),
            PrototypeBindValue::TinyInt(level),
            PrototypeBindValue::BigInt(node_index),
            PrototypeBindValue::BigInt(checkpoint),
        ]
    }

    fn driver_values(&self) -> (i64, i8, i64, i64) {
        (
            self.fence.as_i64(),
            u8_to_i8_exact(self.node.level()),
            u64_to_i64_exact(self.node.index().get()),
            convert_checkpoint_id_to_i64(self.checkpoint.get()),
        )
    }
}

/// A complete `(target, old_head]` clustering slice for one Merkle position.
///
/// ```compile_fail
/// use psy_node_scylla::rollback::GlobalUserMerkleBoundedRangeDeletePlan;
/// // Position and both bounds are mandatory and cannot be omitted.
/// let _plan = GlobalUserMerkleBoundedRangeDeletePlan::try_new(None, None, None);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GlobalUserMerkleBoundedRangeDeletePlan {
    node: MerkleNode,
    target: CheckpointId,
    old_head: CheckpointId,
    fence: DeleteFenceTimestampUs,
}

impl GlobalUserMerkleBoundedRangeDeletePlan {
    pub fn try_new(
        target_key: TypedTableKey,
        old_head: CheckpointId,
        fence: DeleteFenceTimestampUs,
    ) -> Result<Self, TimestampPrototypePlanError> {
        let resolved = resolve_key_for_rollback(&target_key)?;
        require_physical(resolved.physical_table(), ScyllaPhysicalTableId::GlobalUserTree)?;
        let (node, target) = match target_key {
            TypedTableKey::GlobalUserMerkle { node, checkpoint } => (node, checkpoint),
            _ => return Err(TimestampPrototypePlanError::WrongTypedKey),
        };
        if target >= old_head {
            return Err(TimestampPrototypePlanError::EmptyOrReversedRange { target: target.get(), old_head: old_head.get() });
        }
        Ok(Self { node, target, old_head, fence })
    }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        let (fence, level, node_index, target, old_head) = self.driver_values();
        vec![
            PrototypeBindValue::BigInt(fence),
            PrototypeBindValue::TinyInt(level),
            PrototypeBindValue::BigInt(node_index),
            PrototypeBindValue::BigInt(target),
            PrototypeBindValue::BigInt(old_head),
        ]
    }

    fn driver_values(&self) -> (i64, i8, i64, i64, i64) {
        (
            self.fence.as_i64(),
            u8_to_i8_exact(self.node.level()),
            u64_to_i64_exact(self.node.index().get()),
            convert_checkpoint_id_to_i64(self.target.get()),
            convert_checkpoint_id_to_i64(self.old_head.get()),
        )
    }
}

/// Prepared, executable prototype using the same query catalog and bindings as
/// the offline contract tests.
pub struct TimestampPrototypeAdapter {
    queries: TimestampPrototypeQueries,
    checkpoint_leaf_put: PreparedStatement,
    checkpoint_leaf_delete: PreparedStatement,
    global_user_merkle_put: PreparedStatement,
    global_user_merkle_point_delete: PreparedStatement,
    global_user_merkle_range_delete: PreparedStatement,
}

impl TimestampPrototypeAdapter {
    pub async fn prepare(session: &Session, keyspace: CqlKeyspaceName) -> anyhow::Result<Self> {
        Self::prepare_with_consistency(session, keyspace, Consistency::LocalOne).await
    }

    /// Prepares the same production-shaped statements at an explicit
    /// consistency level. The RF=3 harness uses ALL for fully replicated
    /// writes and QUORUM while one replica is intentionally unavailable.
    pub async fn prepare_with_consistency(
        session: &Session,
        keyspace: CqlKeyspaceName,
        consistency: Consistency,
    ) -> anyhow::Result<Self> {
        let queries = TimestampPrototypeQueries::new(&keyspace);
        let checkpoint_leaf_put = prepare_idempotent(session, queries.checkpoint_leaf_put().cql(), consistency).await?;
        let checkpoint_leaf_delete = prepare_idempotent(session, queries.checkpoint_leaf_delete().cql(), consistency).await?;
        let global_user_merkle_put = prepare_idempotent(session, queries.global_user_merkle_put().cql(), consistency).await?;
        let global_user_merkle_point_delete =
            prepare_idempotent(session, queries.global_user_merkle_point_delete().cql(), consistency).await?;
        let global_user_merkle_range_delete =
            prepare_idempotent(session, queries.global_user_merkle_range_delete().cql(), consistency).await?;
        Ok(Self {
            queries,
            checkpoint_leaf_put,
            checkpoint_leaf_delete,
            global_user_merkle_put,
            global_user_merkle_point_delete,
            global_user_merkle_range_delete,
        })
    }

    pub const fn queries(&self) -> &TimestampPrototypeQueries {
        &self.queries
    }

    pub async fn put_checkpoint_leaf(&self, session: &Session, sealed: &SealedTimestampedPut) -> anyhow::Result<()> {
        let binding = CheckpointLeafPutBinding::try_from_sealed(sealed)?;
        session.execute_unpaged(&self.checkpoint_leaf_put, binding.driver_values()).await?;
        Ok(())
    }

    pub async fn delete_checkpoint_leaf_version(
        &self,
        session: &Session,
        plan: &CheckpointLeafVersionDeletePlan,
    ) -> anyhow::Result<()> {
        session.execute_unpaged(&self.checkpoint_leaf_delete, plan.driver_values()).await?;
        Ok(())
    }

    pub async fn put_global_user_merkle(
        &self,
        session: &Session,
        sealed: &SealedTimestampedPut,
    ) -> anyhow::Result<()> {
        let binding = GlobalUserMerklePutBinding::try_from_sealed(sealed)?;
        session.execute_unpaged(&self.global_user_merkle_put, binding.driver_values()).await?;
        Ok(())
    }

    pub async fn delete_global_user_merkle_point(
        &self,
        session: &Session,
        plan: &GlobalUserMerklePointDeletePlan,
    ) -> anyhow::Result<()> {
        session.execute_unpaged(&self.global_user_merkle_point_delete, plan.driver_values()).await?;
        Ok(())
    }

    pub async fn delete_global_user_merkle_range(
        &self,
        session: &Session,
        plan: &GlobalUserMerkleBoundedRangeDeletePlan,
    ) -> anyhow::Result<()> {
        session.execute_unpaged(&self.global_user_merkle_range_delete, plan.driver_values()).await?;
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

/// Separate query catalog for the derived root <-> checkpoint mapping used by
/// S16. It stays outside the original two-table G0-06 golden so the earlier
/// representative contract remains stable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointRootPrototypeQueries {
    k1_put: String,
    k2_put: String,
    k1_delete: String,
    k1_select: String,
}

impl CheckpointRootPrototypeQueries {
    pub fn new(keyspace: &CqlKeyspaceName) -> Self {
        let k1 = physical_descriptor(ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1).physical_name;
        let k2 = physical_descriptor(ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2).physical_name;
        Self {
            k1_put: format!("INSERT INTO {}.{k1} (obj_id, value) VALUES (?, ?) USING TIMESTAMP ?", keyspace.as_str()),
            k2_put: format!("INSERT INTO {}.{k2} (obj_id, value) VALUES (?, ?) USING TIMESTAMP ?", keyspace.as_str()),
            k1_delete: format!("DELETE FROM {}.{k1} USING TIMESTAMP ? WHERE obj_id = ?", keyspace.as_str()),
            k1_select: format!("SELECT value FROM {}.{k1} WHERE obj_id = ? LIMIT 1", keyspace.as_str()),
        }
    }

    pub fn k1_put(&self) -> &str {
        &self.k1_put
    }

    pub fn k2_put(&self) -> &str {
        &self.k2_put
    }

    pub fn k1_delete(&self) -> &str {
        &self.k1_delete
    }

    pub fn k1_select(&self) -> &str {
        &self.k1_select
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CheckpointRootPutBinding {
    obj_id: Vec<u8>,
    stored_value: Vec<u8>,
    write_timestamp_us: i64,
}

impl CheckpointRootPutBinding {
    fn try_from_member(
        member: &SealedTimestampedPut,
        expected: ScyllaPhysicalTableId,
    ) -> Result<Self, TimestampPrototypePlanError> {
        let mutation = member.resolved().mutation();
        require_physical(mutation.physical_table(), expected)?;
        let obj_id = match mutation.key() {
            TypedTableKey::CheckpointRootByHash(root) => root.as_bytes().to_vec(),
            TypedTableKey::CheckpointRootByCheckpoint(checkpoint) => checkpoint.get().to_le_bytes().to_vec(),
            _ => return Err(TimestampPrototypePlanError::WrongTypedKey),
        };
        let value = match mutation.operation() {
            MutationOperation::Put(MutationValue::PsyCanonicalBytes(value)) => value,
            _ => return Err(TimestampPrototypePlanError::ExpectedPsyCanonicalBytes),
        };
        Ok(Self {
            obj_id,
            stored_value: crate::compression::compress(value)
                .map_err(|error| TimestampPrototypePlanError::ValueCodec(error.to_string()))?,
            write_timestamp_us: member.timestamp().as_i64(),
        })
    }

    fn driver_values(&self) -> (&Vec<u8>, &Vec<u8>, i64) {
        (&self.obj_id, &self.stored_value, self.write_timestamp_us)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointRootOrphanDeletePlan {
    root: CheckpointRootKey,
    fence: DeleteFenceTimestampUs,
}

impl CheckpointRootOrphanDeletePlan {
    pub fn try_new(root: CheckpointRootKey, fence: DeleteFenceTimestampUs) -> Result<Self, TimestampPrototypePlanError> {
        let key = TypedTableKey::CheckpointRootByHash(root.clone());
        let resolved = resolve_key_for_rollback(&key)?;
        require_physical(resolved.physical_table(), ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1)?;
        Ok(Self { root, fence })
    }

    fn driver_values(&self) -> (i64, &[u8]) {
        (self.fence.as_i64(), self.root.as_bytes())
    }
}

pub struct CheckpointRootPrototypeAdapter {
    queries: CheckpointRootPrototypeQueries,
    k1_put: PreparedStatement,
    k2_put: PreparedStatement,
    k1_delete: PreparedStatement,
    k1_select: PreparedStatement,
}

impl CheckpointRootPrototypeAdapter {
    pub async fn prepare_with_consistency(
        session: &Session,
        keyspace: CqlKeyspaceName,
        consistency: Consistency,
    ) -> anyhow::Result<Self> {
        let queries = CheckpointRootPrototypeQueries::new(&keyspace);
        Ok(Self {
            k1_put: prepare_idempotent(session, queries.k1_put(), consistency).await?,
            k2_put: prepare_idempotent(session, queries.k2_put(), consistency).await?,
            k1_delete: prepare_idempotent(session, queries.k1_delete(), consistency).await?,
            k1_select: prepare_idempotent(session, queries.k1_select(), consistency).await?,
            queries,
        })
    }

    pub const fn queries(&self) -> &CheckpointRootPrototypeQueries {
        &self.queries
    }

    pub async fn put_mapping(
        &self,
        session: &Session,
        sealed: &SealedTimestampedPutBatch,
    ) -> anyhow::Result<()> {
        if sealed.members().len() != 2 {
            return Err(TimestampPrototypePlanError::ExpectedRootPair { actual: sealed.members().len() }.into());
        }
        let k1 = CheckpointRootPutBinding::try_from_member(
            &sealed.members()[0],
            ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1,
        )?;
        let k2 = CheckpointRootPutBinding::try_from_member(
            &sealed.members()[1],
            ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2,
        )?;
        session.execute_unpaged(&self.k1_put, k1.driver_values()).await?;
        session.execute_unpaged(&self.k2_put, k2.driver_values()).await?;
        Ok(())
    }

    pub async fn delete_orphan_root(
        &self,
        session: &Session,
        plan: &CheckpointRootOrphanDeletePlan,
    ) -> anyhow::Result<()> {
        session.execute_unpaged(&self.k1_delete, plan.driver_values()).await?;
        Ok(())
    }

    pub async fn get_checkpoint_for_root(
        &self,
        session: &Session,
        root: &CheckpointRootKey,
    ) -> anyhow::Result<Option<CheckpointId>> {
        let resolved = resolve_key_for_rollback(&TypedTableKey::CheckpointRootByHash(root.clone()))
            .map_err(TimestampPrototypePlanError::from)?;
        require_physical(resolved.physical_table(), ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1)?;
        let result = session.execute_unpaged(&self.k1_select, (root.as_bytes(),)).await?;
        let Some((stored,)) = result.into_rows_result()?.maybe_first_row::<(Vec<u8>,)>()? else {
            return Ok(None);
        };
        let bytes = crate::compression::decompress(&stored)?;
        let raw: [u8; 8] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| TimestampPrototypePlanError::InvalidCheckpointBytes { actual: bytes.len() })?;
        Ok(Some(CheckpointId::try_new(u64::from_le_bytes(raw))?))
    }
}

/// Validates that a binding's runtime values still match the declared golden
/// shape. Tests and future harness diagnostics use this without a Scylla node.
pub fn validate_bind_shape(query: &TimestampPrototypeQuery, values: &[PrototypeBindValue]) -> bool {
    query.bind_shape().len() == values.len()
        && query
            .bind_shape()
            .iter()
            .zip(values)
            .all(|(declared, value)| declared.ends_with(value.shape_name()))
}
