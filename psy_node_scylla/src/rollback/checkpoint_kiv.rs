//! D-02T1 typed timestamp adapter for the active checkpoint-keyed KIV family.
//!
//! This module deliberately covers only the four active KIV tables whose
//! complete partition key is a checkpoint ID.  The mutable `latest_info_table`
//! and retired `checkpoint_id_to_realm_root_table` share the legacy Rust table
//! implementation, but cannot be constructed through this adapter.
//!
//! The executable driver object remains crate-private until it is owned by the
//! final `RollbackableStore` composition root:
//!
//! ```compile_fail
//! use psy_node_scylla::rollback::CheckpointKivAdapter;
//! ```

use std::{error::Error, fmt};

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

use crate::utils::u64_to_i64_exact;

use super::{
    physical_descriptor, resolve_key_for_rollback, CqlKeyspaceName, PrototypeBindValue,
    RegistryReadinessError, ScyllaPhysicalTableId, SealedTimestampedPut,
};

const MAX_UNLOGGED_BATCH_ROWS: usize = 100;

/// The exact, closed set of active `PRIMARY KEY ((obj_id))` tables where
/// `obj_id` is a checkpoint version partition.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CheckpointKivTable {
    CheckpointLeaf = 1,
    L2BlockState = 2,
    CheckpointStateRoots = 3,
    CheckpointZkProofAndTransition = 4,
}

pub const CHECKPOINT_KIV_TABLES: [CheckpointKivTable; 4] = [
    CheckpointKivTable::CheckpointLeaf,
    CheckpointKivTable::L2BlockState,
    CheckpointKivTable::CheckpointStateRoots,
    CheckpointKivTable::CheckpointZkProofAndTransition,
];

impl CheckpointKivTable {
    pub const fn physical_table(self) -> ScyllaPhysicalTableId {
        match self {
            Self::CheckpointLeaf => ScyllaPhysicalTableId::CheckpointLeaf,
            Self::L2BlockState => ScyllaPhysicalTableId::L2BlockState,
            Self::CheckpointStateRoots => ScyllaPhysicalTableId::CheckpointStateRoots,
            Self::CheckpointZkProofAndTransition => {
                ScyllaPhysicalTableId::CheckpointZkProofAndTransition
            }
        }
    }

    fn try_from_physical(
        physical: ScyllaPhysicalTableId,
    ) -> Result<Self, CheckpointKivPlanError> {
        match physical {
            ScyllaPhysicalTableId::CheckpointLeaf => Ok(Self::CheckpointLeaf),
            ScyllaPhysicalTableId::L2BlockState => Ok(Self::L2BlockState),
            ScyllaPhysicalTableId::CheckpointStateRoots => Ok(Self::CheckpointStateRoots),
            ScyllaPhysicalTableId::CheckpointZkProofAndTransition => {
                Ok(Self::CheckpointZkProofAndTransition)
            }
            _ => Err(CheckpointKivPlanError::UnsupportedPhysicalTable(physical)),
        }
    }

    fn checkpoint_from_key(
        self,
        key: &TypedTableKey,
    ) -> Result<CheckpointId, CheckpointKivPlanError> {
        match (self, key) {
            (Self::CheckpointLeaf, TypedTableKey::CheckpointLeaf(checkpoint))
            | (Self::L2BlockState, TypedTableKey::L2BlockState(checkpoint))
            | (
                Self::CheckpointStateRoots,
                TypedTableKey::CheckpointStateRoots(checkpoint),
            )
            | (
                Self::CheckpointZkProofAndTransition,
                TypedTableKey::CheckpointZkProof(checkpoint),
            ) => Ok(*checkpoint),
            _ => Err(CheckpointKivPlanError::WrongTypedKey { table: self }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum CheckpointKivQueryKind {
    Put = 1,
    VersionPartitionDelete = 2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointKivQuery {
    table: CheckpointKivTable,
    kind: CheckpointKivQueryKind,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl CheckpointKivQuery {
    pub const fn table(&self) -> CheckpointKivTable {
        self.table
    }

    pub const fn kind(&self) -> CheckpointKivQueryKind {
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
pub struct CheckpointKivTableQueries {
    table: CheckpointKivTable,
    put: CheckpointKivQuery,
    version_partition_delete: CheckpointKivQuery,
}

impl CheckpointKivTableQueries {
    fn new(keyspace: &CqlKeyspaceName, table: CheckpointKivTable) -> Self {
        let physical_name = physical_descriptor(table.physical_table()).physical_name;
        let qualified = format!("{}.{physical_name}", keyspace.as_str());
        Self {
            table,
            put: CheckpointKivQuery {
                table,
                kind: CheckpointKivQueryKind::Put,
                cql: format!(
                    "INSERT INTO {qualified} (obj_id, value) VALUES (?, ?) USING TIMESTAMP ?"
                ),
                bind_shape: &[
                    "obj_id:BIGINT",
                    "value:BLOB",
                    "write_timestamp_us:BIGINT",
                ],
            },
            version_partition_delete: CheckpointKivQuery {
                table,
                kind: CheckpointKivQueryKind::VersionPartitionDelete,
                cql: format!("DELETE FROM {qualified} USING TIMESTAMP ? WHERE obj_id = ?"),
                bind_shape: &["delete_fence_us:BIGINT", "obj_id:BIGINT"],
            },
        }
    }

    pub const fn table(&self) -> CheckpointKivTable {
        self.table
    }

    pub const fn put(&self) -> &CheckpointKivQuery {
        &self.put
    }

    pub const fn version_partition_delete(&self) -> &CheckpointKivQuery {
        &self.version_partition_delete
    }
}

/// Closed query catalog. Table names come only from the physical registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointKivQueries {
    tables: [CheckpointKivTableQueries; 4],
}

impl CheckpointKivQueries {
    pub fn new(keyspace: &CqlKeyspaceName) -> Self {
        Self {
            tables: CHECKPOINT_KIV_TABLES.map(|table| {
                CheckpointKivTableQueries::new(keyspace, table)
            }),
        }
    }

    pub fn for_table(&self, table: CheckpointKivTable) -> &CheckpointKivTableQueries {
        &self.tables[table as usize - 1]
    }

    pub fn all(&self) -> &[CheckpointKivTableQueries; 4] {
        &self.tables
    }

    pub fn render_golden(&self) -> String {
        let mut output = String::new();
        for table in &self.tables {
            for query in [table.put(), table.version_partition_delete()] {
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
pub enum CheckpointKivPlanError {
    RegistryReadiness(RegistryReadinessError),
    UnsupportedPhysicalTable(ScyllaPhysicalTableId),
    WrongTypedKey { table: CheckpointKivTable },
    ExpectedPsyCanonicalBytes,
    ValueCodec(String),
    EmptyBatch,
    MixedPhysicalTables {
        expected: CheckpointKivTable,
        actual: CheckpointKivTable,
    },
    MixedWriteTimestamps { expected: i64, actual: i64 },
}

impl fmt::Display for CheckpointKivPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegistryReadiness(error) => {
                write!(f, "checkpoint KIV key is not rollback ready: {error:?}")
            }
            Self::UnsupportedPhysicalTable(table) => {
                write!(f, "physical table {table:?} is not an active checkpoint-keyed KIV")
            }
            Self::WrongTypedKey { table } => {
                write!(f, "typed key does not match checkpoint KIV table {table:?}")
            }
            Self::ExpectedPsyCanonicalBytes => {
                write!(f, "checkpoint KIV PUT requires executable Psy canonical bytes")
            }
            Self::ValueCodec(error) => write!(f, "checkpoint KIV value codec failed: {error}"),
            Self::EmptyBatch => write!(f, "checkpoint KIV PUT batch cannot be empty"),
            Self::MixedPhysicalTables { expected, actual } => write!(
                f,
                "checkpoint KIV batch mixes {expected:?} with {actual:?}"
            ),
            Self::MixedWriteTimestamps { expected, actual } => write!(
                f,
                "checkpoint KIV batch mixes sealed timestamps {expected} and {actual}"
            ),
        }
    }
}

impl Error for CheckpointKivPlanError {}

impl From<RegistryReadinessError> for CheckpointKivPlanError {
    fn from(value: RegistryReadinessError) -> Self {
        Self::RegistryReadiness(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointKivPutBinding {
    table: CheckpointKivTable,
    checkpoint: CheckpointId,
    stored_value: Vec<u8>,
    write_timestamp_us: i64,
}

impl CheckpointKivPutBinding {
    pub fn try_from_sealed(
        sealed: &SealedTimestampedPut,
    ) -> Result<Self, CheckpointKivPlanError> {
        let mutation = sealed.resolved().mutation();
        let table = CheckpointKivTable::try_from_physical(mutation.physical_table())?;
        let checkpoint = table.checkpoint_from_key(mutation.key())?;
        let canonical = match mutation.operation() {
            MutationOperation::Put(MutationValue::PsyCanonicalBytes(value)) => value,
            _ => return Err(CheckpointKivPlanError::ExpectedPsyCanonicalBytes),
        };
        let stored_value = crate::compression::compress(canonical)
            .map_err(|error| CheckpointKivPlanError::ValueCodec(error.to_string()))?;
        Ok(Self {
            table,
            checkpoint,
            stored_value,
            write_timestamp_us: sealed.timestamp().as_i64(),
        })
    }

    pub const fn table(&self) -> CheckpointKivTable {
        self.table
    }

    pub const fn checkpoint(&self) -> CheckpointId {
        self.checkpoint
    }

    pub const fn write_timestamp_us(&self) -> i64 {
        self.write_timestamp_us
    }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.checkpoint.get())),
            PrototypeBindValue::Blob(self.stored_value.clone()),
            PrototypeBindValue::BigInt(self.write_timestamp_us),
        ]
    }

    fn driver_values(&self) -> (i64, &Vec<u8>, i64) {
        (
            u64_to_i64_exact(self.checkpoint.get()),
            &self.stored_value,
            self.write_timestamp_us,
        )
    }

    fn owned_driver_values(&self) -> (i64, Vec<u8>, i64) {
        (
            u64_to_i64_exact(self.checkpoint.get()),
            self.stored_value.clone(),
            self.write_timestamp_us,
        )
    }
}

/// One homogeneous, retry-stable batch for a physical KIV table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointKivPutBatch {
    table: CheckpointKivTable,
    write_timestamp_us: i64,
    members: Vec<CheckpointKivPutBinding>,
}

impl CheckpointKivPutBatch {
    pub fn try_from_sealed(
        sealed: &[SealedTimestampedPut],
    ) -> Result<Self, CheckpointKivPlanError> {
        let mut iter = sealed.iter();
        let first = iter.next().ok_or(CheckpointKivPlanError::EmptyBatch)?;
        let first = CheckpointKivPutBinding::try_from_sealed(first)?;
        let table = first.table;
        let write_timestamp_us = first.write_timestamp_us;
        let mut members = Vec::with_capacity(sealed.len());
        members.push(first);
        for sealed in iter {
            let binding = CheckpointKivPutBinding::try_from_sealed(sealed)?;
            if binding.table != table {
                return Err(CheckpointKivPlanError::MixedPhysicalTables {
                    expected: table,
                    actual: binding.table,
                });
            }
            if binding.write_timestamp_us != write_timestamp_us {
                return Err(CheckpointKivPlanError::MixedWriteTimestamps {
                    expected: write_timestamp_us,
                    actual: binding.write_timestamp_us,
                });
            }
            members.push(binding);
        }
        Ok(Self {
            table,
            write_timestamp_us,
            members,
        })
    }

    pub const fn table(&self) -> CheckpointKivTable {
        self.table
    }

    pub const fn write_timestamp_us(&self) -> i64 {
        self.write_timestamp_us
    }

    pub fn members(&self) -> &[CheckpointKivPutBinding] {
        &self.members
    }
}

/// Complete checkpoint partition delete. No constructor accepts a bare u64.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointKivVersionDeletePlan {
    table: CheckpointKivTable,
    checkpoint: CheckpointId,
    fence: DeleteFenceTimestampUs,
}

impl CheckpointKivVersionDeletePlan {
    pub fn try_new(
        key: TypedTableKey,
        fence: DeleteFenceTimestampUs,
    ) -> Result<Self, CheckpointKivPlanError> {
        let resolved = resolve_key_for_rollback(&key)?;
        let table = CheckpointKivTable::try_from_physical(resolved.physical_table())?;
        let checkpoint = table.checkpoint_from_key(&key)?;
        Ok(Self {
            table,
            checkpoint,
            fence,
        })
    }

    pub const fn table(&self) -> CheckpointKivTable {
        self.table
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
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.checkpoint.get())),
        ]
    }

    fn driver_values(&self) -> (i64, i64) {
        (
            self.fence.as_i64(),
            u64_to_i64_exact(self.checkpoint.get()),
        )
    }
}

struct PreparedCheckpointKivTable {
    table: CheckpointKivTable,
    put: PreparedStatement,
    version_partition_delete: PreparedStatement,
}

/// Production-shaped executable adapter, still isolated from production setup.
#[allow(dead_code)]
pub(crate) struct CheckpointKivAdapter {
    queries: CheckpointKivQueries,
    consistency: Consistency,
    prepared: Vec<PreparedCheckpointKivTable>,
}

#[allow(dead_code)]
impl CheckpointKivAdapter {
    pub(crate) async fn prepare_with_consistency(
        session: &Session,
        keyspace: CqlKeyspaceName,
        consistency: Consistency,
    ) -> anyhow::Result<Self> {
        let queries = CheckpointKivQueries::new(&keyspace);
        let mut prepared = Vec::with_capacity(CHECKPOINT_KIV_TABLES.len());
        for table in CHECKPOINT_KIV_TABLES {
            let table_queries = queries.for_table(table);
            prepared.push(PreparedCheckpointKivTable {
                table,
                put: prepare_idempotent(session, table_queries.put().cql(), consistency).await?,
                version_partition_delete: prepare_idempotent(
                    session,
                    table_queries.version_partition_delete().cql(),
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

    pub(crate) const fn queries(&self) -> &CheckpointKivQueries {
        &self.queries
    }

    pub(crate) async fn put(
        &self,
        session: &Session,
        sealed: &SealedTimestampedPut,
    ) -> anyhow::Result<()> {
        let binding = CheckpointKivPutBinding::try_from_sealed(sealed)?;
        let prepared = self.prepared(binding.table);
        session
            .execute_unpaged(&prepared.put, binding.driver_values())
            .await?;
        Ok(())
    }

    /// Executes homogeneous rows as bounded unlogged batches. Every statement
    /// still binds the timestamp embedded in its sealed mutation; the batch
    /// does not supply a replaceable default timestamp.
    pub(crate) async fn put_batch(
        &self,
        session: &Session,
        plan: &CheckpointKivPutBatch,
    ) -> anyhow::Result<()> {
        let prepared = self.prepared(plan.table);
        for chunk in plan.members.chunks(MAX_UNLOGGED_BATCH_ROWS) {
            let mut batch = Batch::new(BatchType::Unlogged);
            batch.set_consistency(self.consistency);
            batch.set_is_idempotent(true);
            for _ in chunk {
                batch.append_statement(prepared.put.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(CheckpointKivPutBinding::owned_driver_values)
                .collect();
            session.batch(&batch, values).await?;
        }
        Ok(())
    }

    pub(crate) async fn delete_version_partition(
        &self,
        session: &Session,
        plan: &CheckpointKivVersionDeletePlan,
    ) -> anyhow::Result<()> {
        let prepared = self.prepared(plan.table);
        session
            .execute_unpaged(
                &prepared.version_partition_delete,
                plan.driver_values(),
            )
            .await?;
        Ok(())
    }

    fn prepared(&self, table: CheckpointKivTable) -> &PreparedCheckpointKivTable {
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
