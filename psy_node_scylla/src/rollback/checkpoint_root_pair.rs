//! D-02T4 timestamp/fence adapter for the active checkpoint-root mapping.
//!
//! One logical mapping expands to two physical tables. The adapter accepts
//! only the ordered `SealedTimestampedPutBatch`, validates both directions,
//! and executes them as one logged CQL batch. The matching delete plan always
//! contains both the orphan-root partition and the reused-checkpoint partition.
//!
//! The executable adapter remains crate-private:
//!
//! ```compile_fail
//! use psy_node_scylla::rollback::CheckpointRootPairAdapter;
//! ```

use std::{error::Error, fmt};

use psy_node_core::store::{
    timestamp::DeleteFenceTimestampUs,
    typed::{
        CheckpointId, CheckpointRootKey, MutationOperation, MutationValue, TypedTableKey,
    },
};
use scylla::{
    client::session::Session,
    statement::{
        batch::{Batch, BatchType},
        prepared::PreparedStatement,
        Consistency,
    },
};

use crate::compression;

use super::{
    physical_descriptor, resolve_key_for_rollback, CqlKeyspaceName, PrototypeBindValue,
    RegistryReadinessError, ScyllaPhysicalTableId, SealedTimestampedPutBatch,
    TimestampedIntentDigest,
};

const CHECKPOINT_ROOT_BYTES: usize = 32;
const CHECKPOINT_CANONICAL_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum CheckpointRootPairDirection {
    RootToCheckpoint = 1,
    CheckpointToRoot = 2,
}

impl CheckpointRootPairDirection {
    pub const fn physical_table(self) -> ScyllaPhysicalTableId {
        match self {
            Self::RootToCheckpoint => ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1,
            Self::CheckpointToRoot => ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum CheckpointRootPairQueryKind {
    Put = 1,
    DeletePartition = 2,
    ExactRead = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointRootPairQuery {
    direction: CheckpointRootPairDirection,
    kind: CheckpointRootPairQueryKind,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl CheckpointRootPairQuery {
    pub const fn direction(&self) -> CheckpointRootPairDirection {
        self.direction
    }

    pub const fn kind(&self) -> CheckpointRootPairQueryKind {
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
pub struct CheckpointRootPairQueries {
    k1_put: CheckpointRootPairQuery,
    k2_put: CheckpointRootPairQuery,
    k1_delete: CheckpointRootPairQuery,
    k2_delete: CheckpointRootPairQuery,
    k1_exact_read: CheckpointRootPairQuery,
    k2_exact_read: CheckpointRootPairQuery,
}

impl CheckpointRootPairQueries {
    pub fn new(keyspace: &CqlKeyspaceName) -> Self {
        let k1 = physical_descriptor(
            CheckpointRootPairDirection::RootToCheckpoint.physical_table(),
        )
        .physical_name;
        let k2 = physical_descriptor(
            CheckpointRootPairDirection::CheckpointToRoot.physical_table(),
        )
        .physical_name;
        let k1_qualified = format!("{}.{k1}", keyspace.as_str());
        let k2_qualified = format!("{}.{k2}", keyspace.as_str());
        Self {
            k1_put: CheckpointRootPairQuery {
                direction: CheckpointRootPairDirection::RootToCheckpoint,
                kind: CheckpointRootPairQueryKind::Put,
                cql: format!(
                    "INSERT INTO {k1_qualified} (obj_id, value) VALUES (?, ?) USING TIMESTAMP ?"
                ),
                bind_shape: &[
                    "root: BLOB",
                    "psz1_checkpoint: BLOB",
                    "write_timestamp_us: BIGINT",
                ],
            },
            k2_put: CheckpointRootPairQuery {
                direction: CheckpointRootPairDirection::CheckpointToRoot,
                kind: CheckpointRootPairQueryKind::Put,
                cql: format!(
                    "INSERT INTO {k2_qualified} (obj_id, value) VALUES (?, ?) USING TIMESTAMP ?"
                ),
                bind_shape: &[
                    "checkpoint_le: BLOB",
                    "psz1_root: BLOB",
                    "write_timestamp_us: BIGINT",
                ],
            },
            k1_delete: CheckpointRootPairQuery {
                direction: CheckpointRootPairDirection::RootToCheckpoint,
                kind: CheckpointRootPairQueryKind::DeletePartition,
                cql: format!(
                    "DELETE FROM {k1_qualified} USING TIMESTAMP ? WHERE obj_id = ?"
                ),
                bind_shape: &["delete_fence_us: BIGINT", "root: BLOB"],
            },
            k2_delete: CheckpointRootPairQuery {
                direction: CheckpointRootPairDirection::CheckpointToRoot,
                kind: CheckpointRootPairQueryKind::DeletePartition,
                cql: format!(
                    "DELETE FROM {k2_qualified} USING TIMESTAMP ? WHERE obj_id = ?"
                ),
                bind_shape: &["delete_fence_us: BIGINT", "checkpoint_le: BLOB"],
            },
            k1_exact_read: CheckpointRootPairQuery {
                direction: CheckpointRootPairDirection::RootToCheckpoint,
                kind: CheckpointRootPairQueryKind::ExactRead,
                cql: format!(
                    "SELECT value FROM {k1_qualified} WHERE obj_id = ?"
                ),
                bind_shape: &["root: BLOB"],
            },
            k2_exact_read: CheckpointRootPairQuery {
                direction: CheckpointRootPairDirection::CheckpointToRoot,
                kind: CheckpointRootPairQueryKind::ExactRead,
                cql: format!(
                    "SELECT value FROM {k2_qualified} WHERE obj_id = ?"
                ),
                bind_shape: &["checkpoint_le: BLOB"],
            },
        }
    }

    pub const fn k1_put(&self) -> &CheckpointRootPairQuery {
        &self.k1_put
    }

    pub const fn k2_put(&self) -> &CheckpointRootPairQuery {
        &self.k2_put
    }

    pub const fn k1_delete(&self) -> &CheckpointRootPairQuery {
        &self.k1_delete
    }

    pub const fn k2_delete(&self) -> &CheckpointRootPairQuery {
        &self.k2_delete
    }

    pub const fn k1_exact_read(&self) -> &CheckpointRootPairQuery {
        &self.k1_exact_read
    }

    pub const fn k2_exact_read(&self) -> &CheckpointRootPairQuery {
        &self.k2_exact_read
    }

    pub fn render_golden(&self) -> String {
        let mut output = String::new();
        for query in [
            self.k1_put(),
            self.k2_put(),
            self.k1_delete(),
            self.k2_delete(),
            self.k1_exact_read(),
            self.k2_exact_read(),
        ] {
            output.push_str(&format!(
                "{:?}/{:?}\n{}\n{}\n",
                query.direction(),
                query.kind(),
                query.cql(),
                query.bind_shape().join(",")
            ));
        }
        output
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointRootPairPutPlan {
    root: [u8; CHECKPOINT_ROOT_BYTES],
    checkpoint: CheckpointId,
    k1_stored_checkpoint: Vec<u8>,
    k2_stored_root: Vec<u8>,
    write_timestamp_us: i64,
    intent_digest: TimestampedIntentDigest,
}

impl CheckpointRootPairPutPlan {
    pub fn try_from_sealed(
        sealed: &SealedTimestampedPutBatch,
    ) -> Result<Self, CheckpointRootPairPlanError> {
        if sealed.members().len() != 2 {
            return Err(CheckpointRootPairPlanError::ExpectedPair {
                actual: sealed.members().len(),
            });
        }
        let k1 = &sealed.members()[0];
        let k2 = &sealed.members()[1];
        require_physical(
            k1.resolved().mutation().physical_table(),
            ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1,
        )?;
        require_physical(
            k2.resolved().mutation().physical_table(),
            ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2,
        )?;

        let root_bytes = match k1.resolved().mutation().key() {
            TypedTableKey::CheckpointRootByHash(root) => root.as_bytes(),
            _ => return Err(CheckpointRootPairPlanError::WrongTypedKey),
        };
        let root: [u8; CHECKPOINT_ROOT_BYTES] = root_bytes.try_into().map_err(|_| {
            CheckpointRootPairPlanError::InvalidRootLength {
                actual: root_bytes.len(),
            }
        })?;
        let k1_checkpoint_bytes = canonical_value(k1)?;
        let checkpoint_raw: [u8; CHECKPOINT_CANONICAL_BYTES] = k1_checkpoint_bytes
            .try_into()
            .map_err(|_| CheckpointRootPairPlanError::InvalidCheckpointLength {
                actual: k1_checkpoint_bytes.len(),
            })?;
        let checkpoint_from_k1 = CheckpointId::try_new(u64::from_le_bytes(checkpoint_raw))
            .map_err(|_| CheckpointRootPairPlanError::CheckpointOutOfRange)?;

        let checkpoint_from_k2 = match k2.resolved().mutation().key() {
            TypedTableKey::CheckpointRootByCheckpoint(checkpoint) => *checkpoint,
            _ => return Err(CheckpointRootPairPlanError::WrongTypedKey),
        };
        let k2_root_bytes = canonical_value(k2)?;
        if checkpoint_from_k1 != checkpoint_from_k2 || k2_root_bytes != root.as_slice() {
            return Err(CheckpointRootPairPlanError::InconsistentPair);
        }
        if k1.timestamp() != k2.timestamp() {
            return Err(CheckpointRootPairPlanError::MixedWriteTimestamps {
                k1: k1.timestamp().as_i64(),
                k2: k2.timestamp().as_i64(),
            });
        }

        Ok(Self {
            root,
            checkpoint: checkpoint_from_k1,
            k1_stored_checkpoint: compression::compress(k1_checkpoint_bytes)
                .map_err(|error| CheckpointRootPairPlanError::ValueCodec(error.to_string()))?,
            k2_stored_root: compression::compress(k2_root_bytes)
                .map_err(|error| CheckpointRootPairPlanError::ValueCodec(error.to_string()))?,
            write_timestamp_us: k1.timestamp().as_i64(),
            intent_digest: sealed.intent_digest(),
        })
    }

    pub const fn root(&self) -> &[u8; CHECKPOINT_ROOT_BYTES] {
        &self.root
    }

    pub const fn checkpoint(&self) -> CheckpointId {
        self.checkpoint
    }

    pub const fn write_timestamp_us(&self) -> i64 {
        self.write_timestamp_us
    }

    pub const fn intent_digest(&self) -> TimestampedIntentDigest {
        self.intent_digest
    }

    pub fn expected_canonical_values(&self) -> [Vec<u8>; 2] {
        [
            self.checkpoint.get().to_le_bytes().to_vec(),
            self.root.to_vec(),
        ]
    }

    pub fn k1_bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::Blob(self.root.to_vec()),
            PrototypeBindValue::Blob(self.k1_stored_checkpoint.clone()),
            PrototypeBindValue::BigInt(self.write_timestamp_us),
        ]
    }

    pub fn k2_bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::Blob(self.checkpoint.get().to_le_bytes().to_vec()),
            PrototypeBindValue::Blob(self.k2_stored_root.clone()),
            PrototypeBindValue::BigInt(self.write_timestamp_us),
        ]
    }

    fn driver_values(&self) -> Vec<(Vec<u8>, Vec<u8>, i64)> {
        vec![
            (
                self.root.to_vec(),
                self.k1_stored_checkpoint.clone(),
                self.write_timestamp_us,
            ),
            (
                self.checkpoint.get().to_le_bytes().to_vec(),
                self.k2_stored_root.clone(),
                self.write_timestamp_us,
            ),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointRootPairDeletePlan {
    root: [u8; CHECKPOINT_ROOT_BYTES],
    checkpoint: CheckpointId,
    fence: DeleteFenceTimestampUs,
}

impl CheckpointRootPairDeletePlan {
    pub fn try_new(
        root: CheckpointRootKey,
        checkpoint: CheckpointId,
        fence: DeleteFenceTimestampUs,
    ) -> Result<Self, CheckpointRootPairPlanError> {
        let root_bytes = root.as_bytes();
        let root_array: [u8; CHECKPOINT_ROOT_BYTES] = root_bytes.try_into().map_err(|_| {
            CheckpointRootPairPlanError::InvalidRootLength {
                actual: root_bytes.len(),
            }
        })?;
        let k1 = resolve_key_for_rollback(&TypedTableKey::CheckpointRootByHash(root))?;
        require_physical(
            k1.physical_table(),
            ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1,
        )?;
        let k2 = resolve_key_for_rollback(&TypedTableKey::CheckpointRootByCheckpoint(checkpoint))?;
        require_physical(
            k2.physical_table(),
            ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2,
        )?;
        Ok(Self {
            root: root_array,
            checkpoint,
            fence,
        })
    }

    pub const fn root(&self) -> &[u8; CHECKPOINT_ROOT_BYTES] {
        &self.root
    }

    pub const fn checkpoint(&self) -> CheckpointId {
        self.checkpoint
    }

    pub const fn fence(&self) -> DeleteFenceTimestampUs {
        self.fence
    }

    pub fn k1_bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::BigInt(self.fence.as_i64()),
            PrototypeBindValue::Blob(self.root.to_vec()),
        ]
    }

    pub fn k2_bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::BigInt(self.fence.as_i64()),
            PrototypeBindValue::Blob(self.checkpoint.get().to_le_bytes().to_vec()),
        ]
    }

    fn driver_values(&self) -> Vec<(i64, Vec<u8>)> {
        vec![
            (self.fence.as_i64(), self.root.to_vec()),
            (
                self.fence.as_i64(),
                self.checkpoint.get().to_le_bytes().to_vec(),
            ),
        ]
    }
}

fn canonical_value(
    member: &super::SealedTimestampedPut,
) -> Result<&[u8], CheckpointRootPairPlanError> {
    match member.resolved().mutation().operation() {
        MutationOperation::Put(MutationValue::PsyCanonicalBytes(value)) => Ok(value),
        _ => Err(CheckpointRootPairPlanError::ExpectedPsyCanonicalBytes),
    }
}

struct PreparedCheckpointRootPair {
    k1_put: PreparedStatement,
    k2_put: PreparedStatement,
    k1_delete: PreparedStatement,
    k2_delete: PreparedStatement,
    k1_exact_read: PreparedStatement,
    k2_exact_read: PreparedStatement,
}

#[allow(dead_code)]
pub(crate) struct CheckpointRootPairAdapter {
    queries: CheckpointRootPairQueries,
    consistency: Consistency,
    prepared: PreparedCheckpointRootPair,
}

#[allow(dead_code)]
impl CheckpointRootPairAdapter {
    pub(crate) async fn prepare_with_consistency(
        session: &Session,
        keyspace: CqlKeyspaceName,
        consistency: Consistency,
    ) -> anyhow::Result<Self> {
        let queries = CheckpointRootPairQueries::new(&keyspace);
        let prepared = PreparedCheckpointRootPair {
            k1_put: prepare_idempotent(session, queries.k1_put().cql(), consistency).await?,
            k2_put: prepare_idempotent(session, queries.k2_put().cql(), consistency).await?,
            k1_delete: prepare_idempotent(session, queries.k1_delete().cql(), consistency)
                .await?,
            k2_delete: prepare_idempotent(session, queries.k2_delete().cql(), consistency)
                .await?,
            k1_exact_read: prepare_idempotent(
                session,
                queries.k1_exact_read().cql(),
                consistency,
            )
            .await?,
            k2_exact_read: prepare_idempotent(
                session,
                queries.k2_exact_read().cql(),
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

    pub(crate) const fn queries(&self) -> &CheckpointRootPairQueries {
        &self.queries
    }

    pub(crate) async fn put_pair(
        &self,
        session: &Session,
        plan: &CheckpointRootPairPutPlan,
    ) -> anyhow::Result<()> {
        let mut batch = Batch::new(BatchType::Logged);
        batch.set_consistency(self.consistency);
        batch.set_is_idempotent(true);
        batch.append_statement(self.prepared.k1_put.clone());
        batch.append_statement(self.prepared.k2_put.clone());
        session.batch(&batch, plan.driver_values()).await?;
        Ok(())
    }

    pub(crate) async fn delete_pair(
        &self,
        session: &Session,
        plan: &CheckpointRootPairDeletePlan,
    ) -> anyhow::Result<()> {
        let mut batch = Batch::new(BatchType::Logged);
        batch.set_consistency(self.consistency);
        batch.set_is_idempotent(true);
        batch.append_statement(self.prepared.k1_delete.clone());
        batch.append_statement(self.prepared.k2_delete.clone());
        session.batch(&batch, plan.driver_values()).await?;
        Ok(())
    }

    /// Read both exact physical directions and return their decompressed
    /// canonical values in k1/k2 order. Missing directions remain explicit;
    /// malformed stored values fail instead of being treated as absence.
    pub(crate) async fn read_pair_exact(
        &self,
        session: &Session,
        plan: &CheckpointRootPairPutPlan,
    ) -> anyhow::Result<[Option<Vec<u8>>; 2]> {
        let k1 = session
            .execute_unpaged(&self.prepared.k1_exact_read, (plan.root.as_slice(),))
            .await?
            .into_rows_result()?
            .maybe_first_row::<(Vec<u8>,)>()?
            .map(|row| compression::decompress(&row.0))
            .transpose()?;
        let checkpoint_key = plan.checkpoint.get().to_le_bytes();
        let k2 = session
            .execute_unpaged(&self.prepared.k2_exact_read, (checkpoint_key.as_slice(),))
            .await?
            .into_rows_result()?
            .maybe_first_row::<(Vec<u8>,)>()?
            .map(|row| compression::decompress(&row.0))
            .transpose()?;
        Ok([k1, k2])
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

fn require_physical(
    actual: ScyllaPhysicalTableId,
    expected: ScyllaPhysicalTableId,
) -> Result<(), CheckpointRootPairPlanError> {
    if actual == expected {
        Ok(())
    } else {
        Err(CheckpointRootPairPlanError::WrongPhysicalTable { expected, actual })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckpointRootPairPlanError {
    Registry(RegistryReadinessError),
    ExpectedPair {
        actual: usize,
    },
    WrongPhysicalTable {
        expected: ScyllaPhysicalTableId,
        actual: ScyllaPhysicalTableId,
    },
    WrongTypedKey,
    ExpectedPsyCanonicalBytes,
    InvalidRootLength {
        actual: usize,
    },
    InvalidCheckpointLength {
        actual: usize,
    },
    CheckpointOutOfRange,
    InconsistentPair,
    MixedWriteTimestamps {
        k1: i64,
        k2: i64,
    },
    ValueCodec(String),
}

impl fmt::Display for CheckpointRootPairPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(error) => {
                write!(f, "checkpoint-root key is not rollback ready: {error:?}")
            }
            Self::ExpectedPair { actual } => {
                write!(f, "checkpoint-root mapping requires two physical members, got {actual}")
            }
            Self::WrongPhysicalTable { expected, actual } => {
                write!(f, "checkpoint-root pair expected {expected:?}, got {actual:?}")
            }
            Self::WrongTypedKey => f.write_str("checkpoint-root member has the wrong typed key"),
            Self::ExpectedPsyCanonicalBytes => {
                f.write_str("checkpoint-root pair requires executable Psy canonical bytes")
            }
            Self::InvalidRootLength { actual } => write!(
                f,
                "checkpoint root must be {CHECKPOINT_ROOT_BYTES} bytes, got {actual}"
            ),
            Self::InvalidCheckpointLength { actual } => write!(
                f,
                "checkpoint mapping must be {CHECKPOINT_CANONICAL_BYTES} bytes, got {actual}"
            ),
            Self::CheckpointOutOfRange => {
                f.write_str("checkpoint mapping exceeds the typed Scylla BIGINT range")
            }
            Self::InconsistentPair => {
                f.write_str("checkpoint-root physical directions do not describe the same pair")
            }
            Self::MixedWriteTimestamps { k1, k2 } => {
                write!(f, "checkpoint-root pair mixes timestamps {k1} and {k2}")
            }
            Self::ValueCodec(error) => write!(f, "checkpoint-root value codec failed: {error}"),
        }
    }
}

impl Error for CheckpointRootPairPlanError {}

impl From<RegistryReadinessError> for CheckpointRootPairPlanError {
    fn from(value: RegistryReadinessError) -> Self {
        Self::Registry(value)
    }
}
