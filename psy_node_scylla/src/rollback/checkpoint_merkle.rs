//! D-02T2 timestamp/fence adapter for checkpoint-clustering Merkle tables.
//!
//! Seven active physical tables share three concrete schemas. Every delete
//! plan contains the complete logical position prefix before constraining the
//! final `checkpoint_id` clustering column.
//!
//! The executable adapter stays behind the crate boundary until the final
//! `RollbackableStore` composition root owns it:
//!
//! ```compile_fail
//! use psy_node_scylla::rollback::CheckpointMerkleAdapter;
//! ```

use std::{collections::BTreeSet, error::Error, fmt};

use psy_node_core::store::{
    timestamp::DeleteFenceTimestampUs,
    typed::{CheckpointId, MerkleNode, MutationOperation, MutationValue, TypedTableKey},
};
use scylla::{
    client::session::Session,
    statement::{
        batch::{Batch, BatchType},
        prepared::PreparedStatement,
        Consistency,
    },
};

use crate::utils::{convert_checkpoint_id_to_i64, u64_to_i64_exact, u8_to_i8_exact};

use super::{
    physical_descriptor, resolve_key_for_rollback, CqlKeyspaceName, PrototypeBindValue,
    RegistryReadinessError, ScyllaPhysicalTableId, ScyllaSchemaFamily, SealedTimestampedPut,
};

const MERKLE_HASH_BYTES: usize = 32;
const MAX_UNLOGGED_BATCH_ROWS: usize = 100;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CheckpointMerkleTable {
    GlobalUserTree = 1,
    UserContractTree = 2,
    ContractStateTree = 3,
    GlobalCheckpointTree = 4,
    UserRegistrationTree = 5,
    GlobalContractTree = 6,
    ContractFunctionTree = 7,
}

pub const CHECKPOINT_MERKLE_TABLES: [CheckpointMerkleTable; 7] = [
    CheckpointMerkleTable::GlobalUserTree,
    CheckpointMerkleTable::UserContractTree,
    CheckpointMerkleTable::ContractStateTree,
    CheckpointMerkleTable::GlobalCheckpointTree,
    CheckpointMerkleTable::UserRegistrationTree,
    CheckpointMerkleTable::GlobalContractTree,
    CheckpointMerkleTable::ContractFunctionTree,
];

impl CheckpointMerkleTable {
    pub const fn physical_table(self) -> ScyllaPhysicalTableId {
        match self {
            Self::GlobalUserTree => ScyllaPhysicalTableId::GlobalUserTree,
            Self::UserContractTree => ScyllaPhysicalTableId::UserContractTree,
            Self::ContractStateTree => ScyllaPhysicalTableId::ContractStateTree,
            Self::GlobalCheckpointTree => ScyllaPhysicalTableId::GlobalCheckpointTree,
            Self::UserRegistrationTree => ScyllaPhysicalTableId::UserRegistrationTree,
            Self::GlobalContractTree => ScyllaPhysicalTableId::GlobalContractTree,
            Self::ContractFunctionTree => ScyllaPhysicalTableId::ContractFunctionTree,
        }
    }

    pub const fn schema_family(self) -> ScyllaSchemaFamily {
        match self {
            Self::GlobalUserTree
            | Self::GlobalCheckpointTree
            | Self::UserRegistrationTree
            | Self::GlobalContractTree => ScyllaSchemaFamily::MerkleZero,
            Self::UserContractTree | Self::ContractFunctionTree => {
                ScyllaSchemaFamily::MerkleSingle
            }
            Self::ContractStateTree => ScyllaSchemaFamily::MerkleDouble,
        }
    }

    fn try_from_physical(
        physical: ScyllaPhysicalTableId,
    ) -> Result<Self, CheckpointMerklePlanError> {
        match physical {
            ScyllaPhysicalTableId::GlobalUserTree => Ok(Self::GlobalUserTree),
            ScyllaPhysicalTableId::UserContractTree => Ok(Self::UserContractTree),
            ScyllaPhysicalTableId::ContractStateTree => Ok(Self::ContractStateTree),
            ScyllaPhysicalTableId::GlobalCheckpointTree => Ok(Self::GlobalCheckpointTree),
            ScyllaPhysicalTableId::UserRegistrationTree => Ok(Self::UserRegistrationTree),
            ScyllaPhysicalTableId::GlobalContractTree => Ok(Self::GlobalContractTree),
            ScyllaPhysicalTableId::ContractFunctionTree => Ok(Self::ContractFunctionTree),
            _ => Err(CheckpointMerklePlanError::UnsupportedPhysicalTable(
                physical,
            )),
        }
    }

    fn position_from_key(
        self,
        key: &TypedTableKey,
    ) -> Result<(CheckpointMerklePosition, CheckpointId), CheckpointMerklePlanError> {
        match (self, key) {
            (
                Self::GlobalUserTree,
                TypedTableKey::GlobalUserMerkle { node, checkpoint },
            )
            | (
                Self::GlobalCheckpointTree,
                TypedTableKey::GlobalCheckpointMerkle { node, checkpoint },
            )
            | (
                Self::UserRegistrationTree,
                TypedTableKey::UserRegistrationMerkle { node, checkpoint },
            )
            | (
                Self::GlobalContractTree,
                TypedTableKey::GlobalContractMerkle { node, checkpoint },
            ) => Ok((CheckpointMerklePosition::Zero { node: *node }, *checkpoint)),
            (
                Self::UserContractTree,
                TypedTableKey::UserContractMerkle {
                    user,
                    node,
                    checkpoint,
                },
            ) => Ok((
                CheckpointMerklePosition::Single {
                    tree_id: user.get(),
                    node: *node,
                },
                *checkpoint,
            )),
            (
                Self::ContractFunctionTree,
                TypedTableKey::ContractFunctionMerkle {
                    contract,
                    node,
                    checkpoint,
                },
            ) => Ok((
                CheckpointMerklePosition::Single {
                    tree_id: contract.get(),
                    node: *node,
                },
                *checkpoint,
            )),
            (
                Self::ContractStateTree,
                TypedTableKey::ContractStateMerkle {
                    user,
                    contract,
                    node,
                    checkpoint,
                },
            ) => Ok((
                CheckpointMerklePosition::Double {
                    tree_id: user.get(),
                    tree_sub_id: contract.get(),
                    node: *node,
                },
                *checkpoint,
            )),
            _ => Err(CheckpointMerklePlanError::WrongTypedKey { table: self }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CheckpointMerklePosition {
    Zero {
        node: MerkleNode,
    },
    Single {
        tree_id: u64,
        node: MerkleNode,
    },
    Double {
        tree_id: u64,
        tree_sub_id: u64,
        node: MerkleNode,
    },
}

impl CheckpointMerklePosition {
    pub const fn node(self) -> MerkleNode {
        match self {
            Self::Zero { node } | Self::Single { node, .. } | Self::Double { node, .. } => {
                node
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum CheckpointMerkleQueryKind {
    Put = 1,
    PointDelete = 2,
    BoundedRangeDelete = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointMerkleQuery {
    table: CheckpointMerkleTable,
    kind: CheckpointMerkleQueryKind,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl CheckpointMerkleQuery {
    pub const fn table(&self) -> CheckpointMerkleTable {
        self.table
    }

    pub const fn kind(&self) -> CheckpointMerkleQueryKind {
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
pub struct CheckpointMerkleTableQueries {
    table: CheckpointMerkleTable,
    put: CheckpointMerkleQuery,
    point_delete: CheckpointMerkleQuery,
    bounded_range_delete: CheckpointMerkleQuery,
}

impl CheckpointMerkleTableQueries {
    fn new(keyspace: &CqlKeyspaceName, table: CheckpointMerkleTable) -> Self {
        let qualified = format!(
            "{}.{}",
            keyspace.as_str(),
            physical_descriptor(table.physical_table()).physical_name
        );
        let (put, point, range) = match table.schema_family() {
            ScyllaSchemaFamily::MerkleZero => (
                format!("INSERT INTO {qualified} (level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?) USING TIMESTAMP ?"),
                format!("DELETE FROM {qualified} USING TIMESTAMP ? WHERE level = ? AND node_index = ? AND checkpoint_id = ?"),
                format!("DELETE FROM {qualified} USING TIMESTAMP ? WHERE level = ? AND node_index = ? AND checkpoint_id > ? AND checkpoint_id <= ?"),
            ),
            ScyllaSchemaFamily::MerkleSingle => (
                format!("INSERT INTO {qualified} (tree_id, level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?, ?) USING TIMESTAMP ?"),
                format!("DELETE FROM {qualified} USING TIMESTAMP ? WHERE tree_id = ? AND level = ? AND node_index = ? AND checkpoint_id = ?"),
                format!("DELETE FROM {qualified} USING TIMESTAMP ? WHERE tree_id = ? AND level = ? AND node_index = ? AND checkpoint_id > ? AND checkpoint_id <= ?"),
            ),
            ScyllaSchemaFamily::MerkleDouble => (
                format!("INSERT INTO {qualified} (tree_id, tree_sub_id, level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?, ?, ?) USING TIMESTAMP ?"),
                format!("DELETE FROM {qualified} USING TIMESTAMP ? WHERE tree_id = ? AND tree_sub_id = ? AND level = ? AND node_index = ? AND checkpoint_id = ?"),
                format!("DELETE FROM {qualified} USING TIMESTAMP ? WHERE tree_id = ? AND tree_sub_id = ? AND level = ? AND node_index = ? AND checkpoint_id > ? AND checkpoint_id <= ?"),
            ),
            _ => unreachable!("closed checkpoint Merkle table has non-Merkle schema"),
        };
        let (put_shape, point_shape, range_shape): (
            &'static [&'static str],
            &'static [&'static str],
            &'static [&'static str],
        ) = match table.schema_family() {
            ScyllaSchemaFamily::MerkleZero => (
                &[
                    "level:TINYINT",
                    "node_index:BIGINT",
                    "checkpoint_id:BIGINT",
                    "value:BLOB",
                    "write_timestamp_us:BIGINT",
                ],
                &[
                    "delete_fence_us:BIGINT",
                    "level:TINYINT",
                    "node_index:BIGINT",
                    "checkpoint_id:BIGINT",
                ],
                &[
                    "delete_fence_us:BIGINT",
                    "level:TINYINT",
                    "node_index:BIGINT",
                    "target_checkpoint_id:BIGINT",
                    "old_head_checkpoint_id:BIGINT",
                ],
            ),
            ScyllaSchemaFamily::MerkleSingle => (
                &[
                    "tree_id:BIGINT",
                    "level:TINYINT",
                    "node_index:BIGINT",
                    "checkpoint_id:BIGINT",
                    "value:BLOB",
                    "write_timestamp_us:BIGINT",
                ],
                &[
                    "delete_fence_us:BIGINT",
                    "tree_id:BIGINT",
                    "level:TINYINT",
                    "node_index:BIGINT",
                    "checkpoint_id:BIGINT",
                ],
                &[
                    "delete_fence_us:BIGINT",
                    "tree_id:BIGINT",
                    "level:TINYINT",
                    "node_index:BIGINT",
                    "target_checkpoint_id:BIGINT",
                    "old_head_checkpoint_id:BIGINT",
                ],
            ),
            ScyllaSchemaFamily::MerkleDouble => (
                &[
                    "tree_id:BIGINT",
                    "tree_sub_id:BIGINT",
                    "level:TINYINT",
                    "node_index:BIGINT",
                    "checkpoint_id:BIGINT",
                    "value:BLOB",
                    "write_timestamp_us:BIGINT",
                ],
                &[
                    "delete_fence_us:BIGINT",
                    "tree_id:BIGINT",
                    "tree_sub_id:BIGINT",
                    "level:TINYINT",
                    "node_index:BIGINT",
                    "checkpoint_id:BIGINT",
                ],
                &[
                    "delete_fence_us:BIGINT",
                    "tree_id:BIGINT",
                    "tree_sub_id:BIGINT",
                    "level:TINYINT",
                    "node_index:BIGINT",
                    "target_checkpoint_id:BIGINT",
                    "old_head_checkpoint_id:BIGINT",
                ],
            ),
            _ => unreachable!("closed checkpoint Merkle table has non-Merkle schema"),
        };
        Self {
            table,
            put: CheckpointMerkleQuery {
                table,
                kind: CheckpointMerkleQueryKind::Put,
                cql: put,
                bind_shape: put_shape,
            },
            point_delete: CheckpointMerkleQuery {
                table,
                kind: CheckpointMerkleQueryKind::PointDelete,
                cql: point,
                bind_shape: point_shape,
            },
            bounded_range_delete: CheckpointMerkleQuery {
                table,
                kind: CheckpointMerkleQueryKind::BoundedRangeDelete,
                cql: range,
                bind_shape: range_shape,
            },
        }
    }

    pub const fn table(&self) -> CheckpointMerkleTable {
        self.table
    }

    pub const fn put(&self) -> &CheckpointMerkleQuery {
        &self.put
    }

    pub const fn point_delete(&self) -> &CheckpointMerkleQuery {
        &self.point_delete
    }

    pub const fn bounded_range_delete(&self) -> &CheckpointMerkleQuery {
        &self.bounded_range_delete
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointMerkleQueries {
    tables: [CheckpointMerkleTableQueries; 7],
}

impl CheckpointMerkleQueries {
    pub fn new(keyspace: &CqlKeyspaceName) -> Self {
        Self {
            tables: CHECKPOINT_MERKLE_TABLES
                .map(|table| CheckpointMerkleTableQueries::new(keyspace, table)),
        }
    }

    pub fn for_table(&self, table: CheckpointMerkleTable) -> &CheckpointMerkleTableQueries {
        &self.tables[table as usize - 1]
    }

    pub fn all(&self) -> &[CheckpointMerkleTableQueries; 7] {
        &self.tables
    }

    pub fn render_golden(&self) -> String {
        let mut output = String::new();
        for table in &self.tables {
            for query in [
                table.put(),
                table.point_delete(),
                table.bounded_range_delete(),
            ] {
                output.push_str(&format!(
                    "{:?}/{:?}\n{}\n{}\n",
                    query.table(),
                    query.kind(),
                    query.cql(),
                    query.bind_shape().join(",")
                ));
            }
        }
        output
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckpointMerklePlanError {
    RegistryReadiness(RegistryReadinessError),
    UnsupportedPhysicalTable(ScyllaPhysicalTableId),
    WrongTypedKey {
        table: CheckpointMerkleTable,
    },
    ExpectedPsyCanonicalBytes,
    InvalidHashLength {
        expected: usize,
        actual: usize,
    },
    EmptyOrReversedRange {
        target: u64,
        old_head: u64,
    },
    EmptyBatch,
    MixedPhysicalTables {
        expected: CheckpointMerkleTable,
        actual: CheckpointMerkleTable,
    },
    MixedWriteTimestamps {
        expected: i64,
        actual: i64,
    },
    DuplicatePhysicalKey,
    PositionSchemaMismatch,
}

impl fmt::Display for CheckpointMerklePlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegistryReadiness(error) => {
                write!(f, "checkpoint Merkle key is not rollback ready: {error:?}")
            }
            Self::UnsupportedPhysicalTable(table) => {
                write!(f, "physical table {table:?} is not a checkpoint Merkle table")
            }
            Self::WrongTypedKey { table } => {
                write!(f, "typed key does not match checkpoint Merkle table {table:?}")
            }
            Self::ExpectedPsyCanonicalBytes => {
                write!(f, "checkpoint Merkle PUT requires executable canonical hash bytes")
            }
            Self::InvalidHashLength { expected, actual } => {
                write!(f, "Merkle hash must contain {expected} bytes, got {actual}")
            }
            Self::EmptyOrReversedRange { target, old_head } => write!(
                f,
                "bounded delete requires target < old_head, got {target} >= {old_head}"
            ),
            Self::EmptyBatch => write!(f, "checkpoint Merkle PUT batch cannot be empty"),
            Self::MixedPhysicalTables { expected, actual } => {
                write!(f, "checkpoint Merkle batch mixes {expected:?} with {actual:?}")
            }
            Self::MixedWriteTimestamps { expected, actual } => write!(
                f,
                "checkpoint Merkle batch mixes sealed timestamps {expected} and {actual}"
            ),
            Self::DuplicatePhysicalKey => {
                write!(f, "checkpoint Merkle batch contains a duplicate physical key")
            }
            Self::PositionSchemaMismatch => {
                write!(f, "Merkle position does not match its physical schema family")
            }
        }
    }
}

impl Error for CheckpointMerklePlanError {}

impl From<RegistryReadinessError> for CheckpointMerklePlanError {
    fn from(value: RegistryReadinessError) -> Self {
        Self::RegistryReadiness(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointMerklePutBinding {
    table: CheckpointMerkleTable,
    position: CheckpointMerklePosition,
    checkpoint: CheckpointId,
    value: [u8; MERKLE_HASH_BYTES],
    write_timestamp_us: i64,
}

impl CheckpointMerklePutBinding {
    pub fn try_from_sealed(
        sealed: &SealedTimestampedPut,
    ) -> Result<Self, CheckpointMerklePlanError> {
        let mutation = sealed.resolved().mutation();
        let table = CheckpointMerkleTable::try_from_physical(mutation.physical_table())?;
        let (position, checkpoint) = table.position_from_key(mutation.key())?;
        let value = match mutation.operation() {
            MutationOperation::Put(MutationValue::PsyCanonicalBytes(value)) => value,
            _ => return Err(CheckpointMerklePlanError::ExpectedPsyCanonicalBytes),
        };
        let value: [u8; MERKLE_HASH_BYTES] = value.as_slice().try_into().map_err(|_| {
            CheckpointMerklePlanError::InvalidHashLength {
                expected: MERKLE_HASH_BYTES,
                actual: value.len(),
            }
        })?;
        Ok(Self {
            table,
            position,
            checkpoint,
            value,
            write_timestamp_us: sealed.timestamp().as_i64(),
        })
    }

    pub const fn table(&self) -> CheckpointMerkleTable {
        self.table
    }

    pub const fn position(&self) -> CheckpointMerklePosition {
        self.position
    }

    pub const fn checkpoint(&self) -> CheckpointId {
        self.checkpoint
    }

    pub const fn write_timestamp_us(&self) -> i64 {
        self.write_timestamp_us
    }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        let node = self.position.node();
        let mut values = Vec::with_capacity(self.table.schema_family().primary_key().partition.len() + 5);
        match self.position {
            CheckpointMerklePosition::Zero { .. } => {}
            CheckpointMerklePosition::Single { tree_id, .. } => {
                values.push(PrototypeBindValue::BigInt(u64_to_i64_exact(tree_id)));
            }
            CheckpointMerklePosition::Double {
                tree_id,
                tree_sub_id,
                ..
            } => {
                values.push(PrototypeBindValue::BigInt(u64_to_i64_exact(tree_id)));
                values.push(PrototypeBindValue::BigInt(u64_to_i64_exact(tree_sub_id)));
            }
        }
        values.extend([
            PrototypeBindValue::TinyInt(u8_to_i8_exact(node.level())),
            PrototypeBindValue::BigInt(u64_to_i64_exact(node.index().get())),
            PrototypeBindValue::BigInt(convert_checkpoint_id_to_i64(
                self.checkpoint.get(),
            )),
            PrototypeBindValue::Blob(self.value.to_vec()),
            PrototypeBindValue::BigInt(self.write_timestamp_us),
        ]);
        values
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointMerklePutBatch {
    table: CheckpointMerkleTable,
    write_timestamp_us: i64,
    members: Vec<CheckpointMerklePutBinding>,
}

impl CheckpointMerklePutBatch {
    pub fn try_from_sealed(
        sealed: &[SealedTimestampedPut],
    ) -> Result<Self, CheckpointMerklePlanError> {
        let mut iter = sealed.iter();
        let first_sealed = iter.next().ok_or(CheckpointMerklePlanError::EmptyBatch)?;
        let first = CheckpointMerklePutBinding::try_from_sealed(first_sealed)?;
        let table = first.table;
        let write_timestamp_us = first.write_timestamp_us;
        let mut locators = BTreeSet::new();
        locators.insert(first_sealed.resolved().locator_bytes().to_vec());
        let mut members = Vec::with_capacity(sealed.len());
        members.push(first);
        for sealed in iter {
            let binding = CheckpointMerklePutBinding::try_from_sealed(sealed)?;
            if binding.table != table {
                return Err(CheckpointMerklePlanError::MixedPhysicalTables {
                    expected: table,
                    actual: binding.table,
                });
            }
            if binding.write_timestamp_us != write_timestamp_us {
                return Err(CheckpointMerklePlanError::MixedWriteTimestamps {
                    expected: write_timestamp_us,
                    actual: binding.write_timestamp_us,
                });
            }
            if !locators.insert(sealed.resolved().locator_bytes().to_vec()) {
                return Err(CheckpointMerklePlanError::DuplicatePhysicalKey);
            }
            members.push(binding);
        }
        Ok(Self {
            table,
            write_timestamp_us,
            members,
        })
    }

    pub const fn table(&self) -> CheckpointMerkleTable {
        self.table
    }

    pub const fn write_timestamp_us(&self) -> i64 {
        self.write_timestamp_us
    }

    pub fn members(&self) -> &[CheckpointMerklePutBinding] {
        &self.members
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointMerklePointDeletePlan {
    table: CheckpointMerkleTable,
    position: CheckpointMerklePosition,
    checkpoint: CheckpointId,
    fence: DeleteFenceTimestampUs,
}

impl CheckpointMerklePointDeletePlan {
    pub fn try_new(
        key: TypedTableKey,
        fence: DeleteFenceTimestampUs,
    ) -> Result<Self, CheckpointMerklePlanError> {
        let resolved = resolve_key_for_rollback(&key)?;
        let table = CheckpointMerkleTable::try_from_physical(resolved.physical_table())?;
        let (position, checkpoint) = table.position_from_key(&key)?;
        Ok(Self {
            table,
            position,
            checkpoint,
            fence,
        })
    }

    pub const fn table(&self) -> CheckpointMerkleTable {
        self.table
    }

    pub const fn position(&self) -> CheckpointMerklePosition {
        self.position
    }

    pub const fn checkpoint(&self) -> CheckpointId {
        self.checkpoint
    }

    pub const fn fence(&self) -> DeleteFenceTimestampUs {
        self.fence
    }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        delete_bind_values(
            self.position,
            self.fence,
            &[self.checkpoint],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointMerkleBoundedRangeDeletePlan {
    table: CheckpointMerkleTable,
    position: CheckpointMerklePosition,
    target: CheckpointId,
    old_head: CheckpointId,
    fence: DeleteFenceTimestampUs,
}

impl CheckpointMerkleBoundedRangeDeletePlan {
    pub fn try_new(
        target_key: TypedTableKey,
        old_head: CheckpointId,
        fence: DeleteFenceTimestampUs,
    ) -> Result<Self, CheckpointMerklePlanError> {
        let resolved = resolve_key_for_rollback(&target_key)?;
        let table = CheckpointMerkleTable::try_from_physical(resolved.physical_table())?;
        let (position, target) = table.position_from_key(&target_key)?;
        if target >= old_head {
            return Err(CheckpointMerklePlanError::EmptyOrReversedRange {
                target: target.get(),
                old_head: old_head.get(),
            });
        }
        Ok(Self {
            table,
            position,
            target,
            old_head,
            fence,
        })
    }

    pub const fn table(&self) -> CheckpointMerkleTable {
        self.table
    }

    pub const fn position(&self) -> CheckpointMerklePosition {
        self.position
    }

    pub const fn target(&self) -> CheckpointId {
        self.target
    }

    pub const fn old_head(&self) -> CheckpointId {
        self.old_head
    }

    pub const fn fence(&self) -> DeleteFenceTimestampUs {
        self.fence
    }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        delete_bind_values(self.position, self.fence, &[self.target, self.old_head])
    }
}

fn delete_bind_values(
    position: CheckpointMerklePosition,
    fence: DeleteFenceTimestampUs,
    checkpoints: &[CheckpointId],
) -> Vec<PrototypeBindValue> {
    let node = position.node();
    let mut values = vec![PrototypeBindValue::BigInt(fence.as_i64())];
    match position {
        CheckpointMerklePosition::Zero { .. } => {}
        CheckpointMerklePosition::Single { tree_id, .. } => {
            values.push(PrototypeBindValue::BigInt(u64_to_i64_exact(tree_id)));
        }
        CheckpointMerklePosition::Double {
            tree_id,
            tree_sub_id,
            ..
        } => {
            values.push(PrototypeBindValue::BigInt(u64_to_i64_exact(tree_id)));
            values.push(PrototypeBindValue::BigInt(u64_to_i64_exact(tree_sub_id)));
        }
    }
    values.push(PrototypeBindValue::TinyInt(u8_to_i8_exact(node.level())));
    values.push(PrototypeBindValue::BigInt(u64_to_i64_exact(
        node.index().get(),
    )));
    values.extend(checkpoints.iter().map(|checkpoint| {
        PrototypeBindValue::BigInt(convert_checkpoint_id_to_i64(checkpoint.get()))
    }));
    values
}

struct PreparedCheckpointMerkleTable {
    table: CheckpointMerkleTable,
    put: PreparedStatement,
    point_delete: PreparedStatement,
    bounded_range_delete: PreparedStatement,
}

#[allow(dead_code)]
pub(crate) struct CheckpointMerkleAdapter {
    queries: CheckpointMerkleQueries,
    consistency: Consistency,
    prepared: Vec<PreparedCheckpointMerkleTable>,
}

#[allow(dead_code)]
impl CheckpointMerkleAdapter {
    pub(crate) async fn prepare_with_consistency(
        session: &Session,
        keyspace: CqlKeyspaceName,
        consistency: Consistency,
    ) -> anyhow::Result<Self> {
        let queries = CheckpointMerkleQueries::new(&keyspace);
        let mut prepared = Vec::with_capacity(CHECKPOINT_MERKLE_TABLES.len());
        for table in CHECKPOINT_MERKLE_TABLES {
            let table_queries = queries.for_table(table);
            prepared.push(PreparedCheckpointMerkleTable {
                table,
                put: prepare_idempotent(session, table_queries.put().cql(), consistency).await?,
                point_delete: prepare_idempotent(
                    session,
                    table_queries.point_delete().cql(),
                    consistency,
                )
                .await?,
                bounded_range_delete: prepare_idempotent(
                    session,
                    table_queries.bounded_range_delete().cql(),
                    consistency,
                )
                .await?,
            });
        }
        Ok(Self {
            queries,
            consistency,
            prepared,
        })
    }

    pub(crate) const fn queries(&self) -> &CheckpointMerkleQueries {
        &self.queries
    }

    pub(crate) async fn put(
        &self,
        session: &Session,
        sealed: &SealedTimestampedPut,
    ) -> anyhow::Result<()> {
        let binding = CheckpointMerklePutBinding::try_from_sealed(sealed)?;
        let prepared = self.prepared(binding.table);
        match binding.position {
            CheckpointMerklePosition::Zero { node } => {
                session
                    .execute_unpaged(
                        &prepared.put,
                        (
                            u8_to_i8_exact(node.level()),
                            u64_to_i64_exact(node.index().get()),
                            convert_checkpoint_id_to_i64(binding.checkpoint.get()),
                            binding.value,
                            binding.write_timestamp_us,
                        ),
                    )
                    .await?;
            }
            CheckpointMerklePosition::Single { tree_id, node } => {
                session
                    .execute_unpaged(
                        &prepared.put,
                        (
                            u64_to_i64_exact(tree_id),
                            u8_to_i8_exact(node.level()),
                            u64_to_i64_exact(node.index().get()),
                            convert_checkpoint_id_to_i64(binding.checkpoint.get()),
                            binding.value,
                            binding.write_timestamp_us,
                        ),
                    )
                    .await?;
            }
            CheckpointMerklePosition::Double {
                tree_id,
                tree_sub_id,
                node,
            } => {
                session
                    .execute_unpaged(
                        &prepared.put,
                        (
                            u64_to_i64_exact(tree_id),
                            u64_to_i64_exact(tree_sub_id),
                            u8_to_i8_exact(node.level()),
                            u64_to_i64_exact(node.index().get()),
                            convert_checkpoint_id_to_i64(binding.checkpoint.get()),
                            binding.value,
                            binding.write_timestamp_us,
                        ),
                    )
                    .await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn put_batch(
        &self,
        session: &Session,
        plan: &CheckpointMerklePutBatch,
    ) -> anyhow::Result<()> {
        let prepared = self.prepared(plan.table);
        for chunk in plan.members.chunks(MAX_UNLOGGED_BATCH_ROWS) {
            let mut batch = Batch::new(BatchType::Unlogged);
            batch.set_consistency(self.consistency);
            batch.set_is_idempotent(true);
            for _ in chunk {
                batch.append_statement(prepared.put.clone());
            }
            match plan.table.schema_family() {
                ScyllaSchemaFamily::MerkleZero => {
                    let values = chunk
                        .iter()
                        .map(zero_put_driver_values)
                        .collect::<Result<Vec<_>, _>>()?;
                    session.batch(&batch, values).await?;
                }
                ScyllaSchemaFamily::MerkleSingle => {
                    let values = chunk
                        .iter()
                        .map(single_put_driver_values)
                        .collect::<Result<Vec<_>, _>>()?;
                    session.batch(&batch, values).await?;
                }
                ScyllaSchemaFamily::MerkleDouble => {
                    let values = chunk
                        .iter()
                        .map(double_put_driver_values)
                        .collect::<Result<Vec<_>, _>>()?;
                    session.batch(&batch, values).await?;
                }
                _ => return Err(CheckpointMerklePlanError::PositionSchemaMismatch.into()),
            }
        }
        Ok(())
    }

    pub(crate) async fn delete_point(
        &self,
        session: &Session,
        plan: &CheckpointMerklePointDeletePlan,
    ) -> anyhow::Result<()> {
        let prepared = self.prepared(plan.table);
        match plan.position {
            CheckpointMerklePosition::Zero { node } => {
                session
                    .execute_unpaged(
                        &prepared.point_delete,
                        (
                            plan.fence.as_i64(),
                            u8_to_i8_exact(node.level()),
                            u64_to_i64_exact(node.index().get()),
                            convert_checkpoint_id_to_i64(plan.checkpoint.get()),
                        ),
                    )
                    .await?;
            }
            CheckpointMerklePosition::Single { tree_id, node } => {
                session
                    .execute_unpaged(
                        &prepared.point_delete,
                        (
                            plan.fence.as_i64(),
                            u64_to_i64_exact(tree_id),
                            u8_to_i8_exact(node.level()),
                            u64_to_i64_exact(node.index().get()),
                            convert_checkpoint_id_to_i64(plan.checkpoint.get()),
                        ),
                    )
                    .await?;
            }
            CheckpointMerklePosition::Double {
                tree_id,
                tree_sub_id,
                node,
            } => {
                session
                    .execute_unpaged(
                        &prepared.point_delete,
                        (
                            plan.fence.as_i64(),
                            u64_to_i64_exact(tree_id),
                            u64_to_i64_exact(tree_sub_id),
                            u8_to_i8_exact(node.level()),
                            u64_to_i64_exact(node.index().get()),
                            convert_checkpoint_id_to_i64(plan.checkpoint.get()),
                        ),
                    )
                    .await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn delete_bounded_range(
        &self,
        session: &Session,
        plan: &CheckpointMerkleBoundedRangeDeletePlan,
    ) -> anyhow::Result<()> {
        let prepared = self.prepared(plan.table);
        match plan.position {
            CheckpointMerklePosition::Zero { node } => {
                session
                    .execute_unpaged(
                        &prepared.bounded_range_delete,
                        (
                            plan.fence.as_i64(),
                            u8_to_i8_exact(node.level()),
                            u64_to_i64_exact(node.index().get()),
                            convert_checkpoint_id_to_i64(plan.target.get()),
                            convert_checkpoint_id_to_i64(plan.old_head.get()),
                        ),
                    )
                    .await?;
            }
            CheckpointMerklePosition::Single { tree_id, node } => {
                session
                    .execute_unpaged(
                        &prepared.bounded_range_delete,
                        (
                            plan.fence.as_i64(),
                            u64_to_i64_exact(tree_id),
                            u8_to_i8_exact(node.level()),
                            u64_to_i64_exact(node.index().get()),
                            convert_checkpoint_id_to_i64(plan.target.get()),
                            convert_checkpoint_id_to_i64(plan.old_head.get()),
                        ),
                    )
                    .await?;
            }
            CheckpointMerklePosition::Double {
                tree_id,
                tree_sub_id,
                node,
            } => {
                session
                    .execute_unpaged(
                        &prepared.bounded_range_delete,
                        (
                            plan.fence.as_i64(),
                            u64_to_i64_exact(tree_id),
                            u64_to_i64_exact(tree_sub_id),
                            u8_to_i8_exact(node.level()),
                            u64_to_i64_exact(node.index().get()),
                            convert_checkpoint_id_to_i64(plan.target.get()),
                            convert_checkpoint_id_to_i64(plan.old_head.get()),
                        ),
                    )
                    .await?;
            }
        }
        Ok(())
    }

    fn prepared(&self, table: CheckpointMerkleTable) -> &PreparedCheckpointMerkleTable {
        let prepared = &self.prepared[table as usize - 1];
        debug_assert_eq!(prepared.table, table);
        prepared
    }
}

fn zero_put_driver_values(
    binding: &CheckpointMerklePutBinding,
) -> Result<(i8, i64, i64, [u8; 32], i64), CheckpointMerklePlanError> {
    let CheckpointMerklePosition::Zero { node } = binding.position else {
        return Err(CheckpointMerklePlanError::PositionSchemaMismatch);
    };
    Ok((
        u8_to_i8_exact(node.level()),
        u64_to_i64_exact(node.index().get()),
        convert_checkpoint_id_to_i64(binding.checkpoint.get()),
        binding.value,
        binding.write_timestamp_us,
    ))
}

fn single_put_driver_values(
    binding: &CheckpointMerklePutBinding,
) -> Result<(i64, i8, i64, i64, [u8; 32], i64), CheckpointMerklePlanError> {
    let CheckpointMerklePosition::Single { tree_id, node } = binding.position else {
        return Err(CheckpointMerklePlanError::PositionSchemaMismatch);
    };
    Ok((
        u64_to_i64_exact(tree_id),
        u8_to_i8_exact(node.level()),
        u64_to_i64_exact(node.index().get()),
        convert_checkpoint_id_to_i64(binding.checkpoint.get()),
        binding.value,
        binding.write_timestamp_us,
    ))
}

fn double_put_driver_values(
    binding: &CheckpointMerklePutBinding,
) -> Result<(i64, i64, i8, i64, i64, [u8; 32], i64), CheckpointMerklePlanError> {
    let CheckpointMerklePosition::Double {
        tree_id,
        tree_sub_id,
        node,
    } = binding.position
    else {
        return Err(CheckpointMerklePlanError::PositionSchemaMismatch);
    };
    Ok((
        u64_to_i64_exact(tree_id),
        u64_to_i64_exact(tree_sub_id),
        u8_to_i8_exact(node.level()),
        u64_to_i64_exact(node.index().get()),
        convert_checkpoint_id_to_i64(binding.checkpoint.get()),
        binding.value,
        binding.write_timestamp_us,
    ))
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

