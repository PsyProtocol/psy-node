//! D-02T3 timestamp/fence adapter for rollback-ready object-single tables.
//!
//! The five admitted tables use `PRIMARY KEY ((obj_id), checkpoint_id)` and
//! the legacy `PSZ1` zstd value codec. The two other tables sharing this Rust
//! schema family remain blocked by the typed registry and cannot be resolved
//! through this adapter.
//!
//! The executable adapter stays behind the crate boundary until the final
//! `RollbackableStore` composition root owns it:
//!
//! ```compile_fail
//! use psy_node_scylla::rollback::CheckpointObjectSingleAdapter;
//! ```

use std::{collections::BTreeSet, error::Error, fmt};

use psy_node_core::store::{
    timestamp::DeleteFenceTimestampUs,
    typed::{CheckpointId, MutationOperation, MutationValue, TypedTableKey},
};
use scylla::{
    client::session::Session,
    statement::{
        batch::{Batch, BatchType},
        prepared::PreparedStatement,
        Consistency,
    },
};

use crate::{
    compression,
    utils::{convert_checkpoint_id_to_i64, u64_to_i64_exact},
};

use super::{
    physical_descriptor, resolve_key_for_rollback, CqlKeyspaceName, PrototypeBindValue,
    RegistryReadinessError, ScyllaPhysicalTableId, ScyllaSchemaFamily, SealedTimestampedPut,
};

const MAX_UNLOGGED_BATCH_ROWS: usize = 100;

/// The exact closed set of rollback-ready object-single physical tables.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CheckpointObjectSingleTable {
    UserLeaf = 1,
    UserPublicKey = 2,
    ContractStateTreeHeight = 3,
    ContractLeaf = 4,
    ContractCodeDefinition = 5,
}

pub const CHECKPOINT_OBJECT_SINGLE_TABLES: [CheckpointObjectSingleTable; 5] = [
    CheckpointObjectSingleTable::UserLeaf,
    CheckpointObjectSingleTable::UserPublicKey,
    CheckpointObjectSingleTable::ContractStateTreeHeight,
    CheckpointObjectSingleTable::ContractLeaf,
    CheckpointObjectSingleTable::ContractCodeDefinition,
];

impl CheckpointObjectSingleTable {
    pub const fn physical_table(self) -> ScyllaPhysicalTableId {
        match self {
            Self::UserLeaf => ScyllaPhysicalTableId::UserLeaf,
            Self::UserPublicKey => ScyllaPhysicalTableId::UserPublicKey,
            Self::ContractStateTreeHeight => ScyllaPhysicalTableId::ContractStateTreeHeight,
            Self::ContractLeaf => ScyllaPhysicalTableId::ContractLeaf,
            Self::ContractCodeDefinition => ScyllaPhysicalTableId::ContractCodeDefinition,
        }
    }

    fn try_from_physical(
        physical: ScyllaPhysicalTableId,
    ) -> Result<Self, CheckpointObjectSinglePlanError> {
        match physical {
            ScyllaPhysicalTableId::UserLeaf => Ok(Self::UserLeaf),
            ScyllaPhysicalTableId::UserPublicKey => Ok(Self::UserPublicKey),
            ScyllaPhysicalTableId::ContractStateTreeHeight => Ok(Self::ContractStateTreeHeight),
            ScyllaPhysicalTableId::ContractLeaf => Ok(Self::ContractLeaf),
            ScyllaPhysicalTableId::ContractCodeDefinition => Ok(Self::ContractCodeDefinition),
            _ => Err(CheckpointObjectSinglePlanError::UnsupportedPhysicalTable(
                physical,
            )),
        }
    }

    fn object_and_checkpoint_from_key(
        self,
        key: &TypedTableKey,
    ) -> Result<(u64, CheckpointId), CheckpointObjectSinglePlanError> {
        match (self, key) {
            (Self::UserLeaf, TypedTableKey::UserLeaf { user, checkpoint })
            | (
                Self::UserPublicKey,
                TypedTableKey::UserPublicKey { user, checkpoint },
            ) => Ok((user.get(), *checkpoint)),
            (
                Self::ContractStateTreeHeight,
                TypedTableKey::ContractStateTreeHeight {
                    contract,
                    checkpoint,
                },
            )
            | (
                Self::ContractLeaf,
                TypedTableKey::ContractLeaf {
                    contract,
                    checkpoint,
                },
            )
            | (
                Self::ContractCodeDefinition,
                TypedTableKey::ContractCodeDefinition {
                    contract,
                    checkpoint,
                },
            ) => Ok((contract.get(), *checkpoint)),
            _ => Err(CheckpointObjectSinglePlanError::WrongTypedKey { table: self }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum CheckpointObjectSingleQueryKind {
    Put = 1,
    PointDelete = 2,
    BoundedRangeDelete = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointObjectSingleQuery {
    table: CheckpointObjectSingleTable,
    kind: CheckpointObjectSingleQueryKind,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl CheckpointObjectSingleQuery {
    pub const fn table(&self) -> CheckpointObjectSingleTable {
        self.table
    }

    pub const fn kind(&self) -> CheckpointObjectSingleQueryKind {
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
pub struct CheckpointObjectSingleTableQueries {
    table: CheckpointObjectSingleTable,
    put: CheckpointObjectSingleQuery,
    point_delete: CheckpointObjectSingleQuery,
    bounded_range_delete: CheckpointObjectSingleQuery,
}

impl CheckpointObjectSingleTableQueries {
    fn new(keyspace: &CqlKeyspaceName, table: CheckpointObjectSingleTable) -> Self {
        let qualified = format!(
            "{}.{}",
            keyspace.as_str(),
            physical_descriptor(table.physical_table()).physical_name
        );
        Self {
            table,
            put: CheckpointObjectSingleQuery {
                table,
                kind: CheckpointObjectSingleQueryKind::Put,
                cql: format!(
                    "INSERT INTO {qualified} (obj_id, checkpoint_id, value) VALUES (?, ?, ?) USING TIMESTAMP ?"
                ),
                bind_shape: &[
                    "obj_id:BIGINT",
                    "checkpoint_id:BIGINT",
                    "psz1_value:BLOB",
                    "write_timestamp_us:BIGINT",
                ],
            },
            point_delete: CheckpointObjectSingleQuery {
                table,
                kind: CheckpointObjectSingleQueryKind::PointDelete,
                cql: format!(
                    "DELETE FROM {qualified} USING TIMESTAMP ? WHERE obj_id = ? AND checkpoint_id = ?"
                ),
                bind_shape: &[
                    "delete_fence_us:BIGINT",
                    "obj_id:BIGINT",
                    "checkpoint_id:BIGINT",
                ],
            },
            bounded_range_delete: CheckpointObjectSingleQuery {
                table,
                kind: CheckpointObjectSingleQueryKind::BoundedRangeDelete,
                cql: format!(
                    "DELETE FROM {qualified} USING TIMESTAMP ? WHERE obj_id = ? AND checkpoint_id > ? AND checkpoint_id <= ?"
                ),
                bind_shape: &[
                    "delete_fence_us:BIGINT",
                    "obj_id:BIGINT",
                    "target_exclusive:BIGINT",
                    "old_head_inclusive:BIGINT",
                ],
            },
        }
    }

    pub const fn table(&self) -> CheckpointObjectSingleTable {
        self.table
    }

    pub const fn put(&self) -> &CheckpointObjectSingleQuery {
        &self.put
    }

    pub const fn point_delete(&self) -> &CheckpointObjectSingleQuery {
        &self.point_delete
    }

    pub const fn bounded_range_delete(&self) -> &CheckpointObjectSingleQuery {
        &self.bounded_range_delete
    }
}

/// Closed query catalog. All physical names come from the typed registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointObjectSingleQueries {
    tables: [CheckpointObjectSingleTableQueries; 5],
}

impl CheckpointObjectSingleQueries {
    pub fn new(keyspace: &CqlKeyspaceName) -> Self {
        Self {
            tables: CHECKPOINT_OBJECT_SINGLE_TABLES
                .map(|table| CheckpointObjectSingleTableQueries::new(keyspace, table)),
        }
    }

    pub fn for_table(
        &self,
        table: CheckpointObjectSingleTable,
    ) -> &CheckpointObjectSingleTableQueries {
        &self.tables[table as usize - 1]
    }

    pub fn all(&self) -> &[CheckpointObjectSingleTableQueries; 5] {
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
pub struct CheckpointObjectSinglePutBinding {
    table: CheckpointObjectSingleTable,
    object_id: u64,
    checkpoint: CheckpointId,
    compressed_value: Vec<u8>,
    write_timestamp_us: i64,
}

impl CheckpointObjectSinglePutBinding {
    pub fn try_from_sealed(
        sealed: &SealedTimestampedPut,
    ) -> Result<Self, CheckpointObjectSinglePlanError> {
        let mutation = sealed.resolved().mutation();
        let table = CheckpointObjectSingleTable::try_from_physical(mutation.physical_table())?;
        let (object_id, checkpoint) = table.object_and_checkpoint_from_key(mutation.key())?;
        let canonical_value = match mutation.operation() {
            MutationOperation::Put(MutationValue::PsyCanonicalBytes(value)) => value,
            _ => return Err(CheckpointObjectSinglePlanError::ExpectedPsyCanonicalBytes),
        };
        let compressed_value = compression::compress(canonical_value).map_err(|source| {
            CheckpointObjectSinglePlanError::ValueCompression(source.to_string())
        })?;
        Ok(Self {
            table,
            object_id,
            checkpoint,
            compressed_value,
            write_timestamp_us: sealed.timestamp().as_i64(),
        })
    }

    pub const fn table(&self) -> CheckpointObjectSingleTable {
        self.table
    }

    pub const fn object_id(&self) -> u64 {
        self.object_id
    }

    pub const fn checkpoint(&self) -> CheckpointId {
        self.checkpoint
    }

    pub fn compressed_value(&self) -> &[u8] {
        &self.compressed_value
    }

    pub const fn write_timestamp_us(&self) -> i64 {
        self.write_timestamp_us
    }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.object_id)),
            PrototypeBindValue::BigInt(convert_checkpoint_id_to_i64(self.checkpoint.get())),
            PrototypeBindValue::Blob(self.compressed_value.clone()),
            PrototypeBindValue::BigInt(self.write_timestamp_us),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointObjectSinglePutBatch {
    table: CheckpointObjectSingleTable,
    write_timestamp_us: i64,
    members: Vec<CheckpointObjectSinglePutBinding>,
}

impl CheckpointObjectSinglePutBatch {
    pub fn try_from_sealed(
        sealed: &[SealedTimestampedPut],
    ) -> Result<Self, CheckpointObjectSinglePlanError> {
        let mut iter = sealed.iter();
        let first_sealed = iter.next().ok_or(CheckpointObjectSinglePlanError::EmptyBatch)?;
        let first = CheckpointObjectSinglePutBinding::try_from_sealed(first_sealed)?;
        let table = first.table;
        let write_timestamp_us = first.write_timestamp_us;
        let mut locators = BTreeSet::new();
        locators.insert(first_sealed.resolved().locator_bytes().to_vec());
        let mut members = Vec::with_capacity(sealed.len());
        members.push(first);
        for sealed in iter {
            let binding = CheckpointObjectSinglePutBinding::try_from_sealed(sealed)?;
            if binding.table != table {
                return Err(CheckpointObjectSinglePlanError::MixedPhysicalTables {
                    expected: table,
                    actual: binding.table,
                });
            }
            if binding.write_timestamp_us != write_timestamp_us {
                return Err(CheckpointObjectSinglePlanError::MixedWriteTimestamps {
                    expected: write_timestamp_us,
                    actual: binding.write_timestamp_us,
                });
            }
            if !locators.insert(sealed.resolved().locator_bytes().to_vec()) {
                return Err(CheckpointObjectSinglePlanError::DuplicatePhysicalKey);
            }
            members.push(binding);
        }
        Ok(Self {
            table,
            write_timestamp_us,
            members,
        })
    }

    pub const fn table(&self) -> CheckpointObjectSingleTable {
        self.table
    }

    pub const fn write_timestamp_us(&self) -> i64 {
        self.write_timestamp_us
    }

    pub fn members(&self) -> &[CheckpointObjectSinglePutBinding] {
        &self.members
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointObjectSinglePointDeletePlan {
    table: CheckpointObjectSingleTable,
    object_id: u64,
    checkpoint: CheckpointId,
    fence: DeleteFenceTimestampUs,
}

impl CheckpointObjectSinglePointDeletePlan {
    pub fn try_new(
        key: TypedTableKey,
        fence: DeleteFenceTimestampUs,
    ) -> Result<Self, CheckpointObjectSinglePlanError> {
        let resolved = resolve_key_for_rollback(&key)?;
        let table = CheckpointObjectSingleTable::try_from_physical(resolved.physical_table())?;
        let (object_id, checkpoint) = table.object_and_checkpoint_from_key(&key)?;
        Ok(Self {
            table,
            object_id,
            checkpoint,
            fence,
        })
    }

    pub const fn table(&self) -> CheckpointObjectSingleTable {
        self.table
    }

    pub const fn object_id(&self) -> u64 {
        self.object_id
    }

    pub const fn checkpoint(&self) -> CheckpointId {
        self.checkpoint
    }

    pub const fn fence(&self) -> DeleteFenceTimestampUs {
        self.fence
    }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::BigInt(self.fence.as_i64()),
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.object_id)),
            PrototypeBindValue::BigInt(convert_checkpoint_id_to_i64(self.checkpoint.get())),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointObjectSingleBoundedRangeDeletePlan {
    table: CheckpointObjectSingleTable,
    object_id: u64,
    target: CheckpointId,
    old_head: CheckpointId,
    fence: DeleteFenceTimestampUs,
}

impl CheckpointObjectSingleBoundedRangeDeletePlan {
    pub fn try_new(
        target_key: TypedTableKey,
        old_head: CheckpointId,
        fence: DeleteFenceTimestampUs,
    ) -> Result<Self, CheckpointObjectSinglePlanError> {
        let resolved = resolve_key_for_rollback(&target_key)?;
        let table = CheckpointObjectSingleTable::try_from_physical(resolved.physical_table())?;
        let (object_id, target) = table.object_and_checkpoint_from_key(&target_key)?;
        if target >= old_head {
            return Err(CheckpointObjectSinglePlanError::EmptyOrReversedRange {
                target: target.get(),
                old_head: old_head.get(),
            });
        }
        Ok(Self {
            table,
            object_id,
            target,
            old_head,
            fence,
        })
    }

    pub const fn table(&self) -> CheckpointObjectSingleTable {
        self.table
    }

    pub const fn object_id(&self) -> u64 {
        self.object_id
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
        vec![
            PrototypeBindValue::BigInt(self.fence.as_i64()),
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.object_id)),
            PrototypeBindValue::BigInt(convert_checkpoint_id_to_i64(self.target.get())),
            PrototypeBindValue::BigInt(convert_checkpoint_id_to_i64(self.old_head.get())),
        ]
    }
}

struct PreparedCheckpointObjectSingleTable {
    table: CheckpointObjectSingleTable,
    put: PreparedStatement,
    point_delete: PreparedStatement,
    bounded_range_delete: PreparedStatement,
}

#[allow(dead_code)]
pub(crate) struct CheckpointObjectSingleAdapter {
    queries: CheckpointObjectSingleQueries,
    consistency: Consistency,
    prepared: Vec<PreparedCheckpointObjectSingleTable>,
}

#[allow(dead_code)]
impl CheckpointObjectSingleAdapter {
    pub(crate) async fn prepare_with_consistency(
        session: &Session,
        keyspace: CqlKeyspaceName,
        consistency: Consistency,
    ) -> anyhow::Result<Self> {
        let queries = CheckpointObjectSingleQueries::new(&keyspace);
        let mut prepared = Vec::with_capacity(CHECKPOINT_OBJECT_SINGLE_TABLES.len());
        for table in CHECKPOINT_OBJECT_SINGLE_TABLES {
            let table_queries = queries.for_table(table);
            prepared.push(PreparedCheckpointObjectSingleTable {
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

    pub(crate) const fn queries(&self) -> &CheckpointObjectSingleQueries {
        &self.queries
    }

    pub(crate) async fn put(
        &self,
        session: &Session,
        sealed: &SealedTimestampedPut,
    ) -> anyhow::Result<()> {
        let binding = CheckpointObjectSinglePutBinding::try_from_sealed(sealed)?;
        let prepared = self.prepared(binding.table);
        session
            .execute_unpaged(
                &prepared.put,
                (
                    u64_to_i64_exact(binding.object_id),
                    convert_checkpoint_id_to_i64(binding.checkpoint.get()),
                    binding.compressed_value,
                    binding.write_timestamp_us,
                ),
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn put_batch(
        &self,
        session: &Session,
        plan: &CheckpointObjectSinglePutBatch,
    ) -> anyhow::Result<()> {
        let prepared = self.prepared(plan.table);
        for chunk in plan.members.chunks(MAX_UNLOGGED_BATCH_ROWS) {
            let mut batch = Batch::new(BatchType::Unlogged);
            batch.set_consistency(self.consistency);
            batch.set_is_idempotent(true);
            for _ in chunk {
                batch.append_statement(prepared.put.clone());
            }
            let values = chunk
                .iter()
                .map(|binding| {
                    (
                        u64_to_i64_exact(binding.object_id),
                        convert_checkpoint_id_to_i64(binding.checkpoint.get()),
                        binding.compressed_value.clone(),
                        binding.write_timestamp_us,
                    )
                })
                .collect::<Vec<_>>();
            session.batch(&batch, values).await?;
        }
        Ok(())
    }

    pub(crate) async fn delete_point(
        &self,
        session: &Session,
        plan: &CheckpointObjectSinglePointDeletePlan,
    ) -> anyhow::Result<()> {
        let prepared = self.prepared(plan.table);
        session
            .execute_unpaged(
                &prepared.point_delete,
                (
                    plan.fence.as_i64(),
                    u64_to_i64_exact(plan.object_id),
                    convert_checkpoint_id_to_i64(plan.checkpoint.get()),
                ),
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn delete_bounded_range(
        &self,
        session: &Session,
        plan: &CheckpointObjectSingleBoundedRangeDeletePlan,
    ) -> anyhow::Result<()> {
        let prepared = self.prepared(plan.table);
        session
            .execute_unpaged(
                &prepared.bounded_range_delete,
                (
                    plan.fence.as_i64(),
                    u64_to_i64_exact(plan.object_id),
                    convert_checkpoint_id_to_i64(plan.target.get()),
                    convert_checkpoint_id_to_i64(plan.old_head.get()),
                ),
            )
            .await?;
        Ok(())
    }

    fn prepared(
        &self,
        table: CheckpointObjectSingleTable,
    ) -> &PreparedCheckpointObjectSingleTable {
        let prepared = &self.prepared[table as usize - 1];
        debug_assert_eq!(prepared.table, table);
        prepared
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
pub enum CheckpointObjectSinglePlanError {
    Registry(RegistryReadinessError),
    UnsupportedPhysicalTable(ScyllaPhysicalTableId),
    WrongTypedKey {
        table: CheckpointObjectSingleTable,
    },
    ExpectedPsyCanonicalBytes,
    ValueCompression(String),
    EmptyBatch,
    MixedPhysicalTables {
        expected: CheckpointObjectSingleTable,
        actual: CheckpointObjectSingleTable,
    },
    MixedWriteTimestamps {
        expected: i64,
        actual: i64,
    },
    DuplicatePhysicalKey,
    EmptyOrReversedRange {
        target: u64,
        old_head: u64,
    },
}

impl fmt::Display for CheckpointObjectSinglePlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(source) => {
                write!(f, "object-single key is not rollback ready: {source:?}")
            }
            Self::UnsupportedPhysicalTable(table) => {
                write!(f, "{table:?} is not an admitted object-single table")
            }
            Self::WrongTypedKey { table } => {
                write!(f, "typed key does not belong to {table:?}")
            }
            Self::ExpectedPsyCanonicalBytes => {
                f.write_str("object-single PUT requires Psy canonical bytes")
            }
            Self::ValueCompression(message) => {
                write!(f, "object-single value compression failed: {message}")
            }
            Self::EmptyBatch => f.write_str("object-single PUT batch cannot be empty"),
            Self::MixedPhysicalTables { expected, actual } => write!(
                f,
                "object-single PUT batch mixes {expected:?} with {actual:?}"
            ),
            Self::MixedWriteTimestamps { expected, actual } => write!(
                f,
                "object-single PUT batch mixes timestamps {expected} and {actual}"
            ),
            Self::DuplicatePhysicalKey => {
                f.write_str("object-single PUT batch contains a duplicate physical key")
            }
            Self::EmptyOrReversedRange { target, old_head } => write!(
                f,
                "object-single range requires target < old_head, got {target} >= {old_head}"
            ),
        }
    }
}

impl Error for CheckpointObjectSinglePlanError {}

impl From<RegistryReadinessError> for CheckpointObjectSinglePlanError {
    fn from(value: RegistryReadinessError) -> Self {
        Self::Registry(value)
    }
}

const _: () = {
    assert!(CHECKPOINT_OBJECT_SINGLE_TABLES.len() == 5);
    let mut index = 0;
    while index < CHECKPOINT_OBJECT_SINGLE_TABLES.len() {
        let table = CHECKPOINT_OBJECT_SINGLE_TABLES[index];
        assert!(table as usize == index + 1);
        assert!(matches!(
            physical_descriptor(table.physical_table()).schema_family,
            ScyllaSchemaFamily::ObjectSingle
        ));
        index += 1;
    }
};
