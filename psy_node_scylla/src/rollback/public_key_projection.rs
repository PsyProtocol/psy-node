//! D-02T5 timestamp/fence adapter for the public-key-to-user projection.
//!
//! The physical row is key-only: `(hash_id, value_u64)`. Its checkpoint birth
//! is therefore carried by the typed execution plan for the future manifest,
//! rather than being invented as a CQL version column.
//!
//! The executable adapter remains crate-private:
//!
//! ```compile_fail
//! use psy_node_scylla::rollback::PublicKeyProjectionAdapter;
//! ```

use std::{collections::BTreeSet, error::Error, fmt};

use psy_node_core::store::{
    timestamp::DeleteFenceTimestampUs,
    typed::{
        CheckpointId, MutationOperation, MutationValue, PublicKeyHash, TypedTableKey, UserId,
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
use sha2::{Digest, Sha256};

use crate::utils::u64_to_i64_exact;

use super::{
    physical_descriptor, resolve_key_for_rollback, CqlKeyspaceName, PrototypeBindValue,
    RegistryReadinessError, ScyllaPhysicalTableId, SealedTimestampedPut,
    TimestampedIntentDigest,
};

const PUBLIC_KEY_HASH_BYTES: usize = 32;
const MAX_UNLOGGED_BATCH_ROWS: usize = 100;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PublicKeyProjectionQueryKind {
    Put = 1,
    PointDelete = 2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKeyProjectionQuery {
    kind: PublicKeyProjectionQueryKind,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl PublicKeyProjectionQuery {
    pub const fn kind(&self) -> PublicKeyProjectionQueryKind {
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
pub struct PublicKeyProjectionQueries {
    put: PublicKeyProjectionQuery,
    point_delete: PublicKeyProjectionQuery,
}

impl PublicKeyProjectionQueries {
    pub fn new(keyspace: &CqlKeyspaceName) -> Self {
        let physical = physical_descriptor(ScyllaPhysicalTableId::PublicKeyHashToUserIds);
        let qualified = format!("{}.{}", keyspace.as_str(), physical.physical_name);
        Self {
            put: PublicKeyProjectionQuery {
                kind: PublicKeyProjectionQueryKind::Put,
                cql: format!(
                    "INSERT INTO {qualified} (hash_id, value_u64) VALUES (?, ?) USING TIMESTAMP ?"
                ),
                bind_shape: &[
                    "public_key_hash:BLOB",
                    "user_id:BIGINT",
                    "write_timestamp_us:BIGINT",
                ],
            },
            point_delete: PublicKeyProjectionQuery {
                kind: PublicKeyProjectionQueryKind::PointDelete,
                cql: format!(
                    "DELETE FROM {qualified} USING TIMESTAMP ? WHERE hash_id = ? AND value_u64 = ?"
                ),
                bind_shape: &[
                    "delete_fence_us:BIGINT",
                    "public_key_hash:BLOB",
                    "user_id:BIGINT",
                ],
            },
        }
    }

    pub const fn put(&self) -> &PublicKeyProjectionQuery {
        &self.put
    }

    pub const fn point_delete(&self) -> &PublicKeyProjectionQuery {
        &self.point_delete
    }

    pub fn render_golden(&self) -> String {
        let mut output = String::new();
        for query in [self.put(), self.point_delete()] {
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

/// Retry identity for the CQL mutation plus its non-key checkpoint birth.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PublicKeyProjectionBirthDigest([u8; 32]);

impl PublicKeyProjectionBirthDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKeyProjectionPutBinding {
    public_key_hash: [u8; PUBLIC_KEY_HASH_BYTES],
    user: UserId,
    birth_checkpoint: CheckpointId,
    write_timestamp_us: i64,
    timestamped_intent_digest: TimestampedIntentDigest,
    birth_digest: PublicKeyProjectionBirthDigest,
}

impl PublicKeyProjectionPutBinding {
    pub fn try_from_sealed(
        sealed: &SealedTimestampedPut,
        birth_checkpoint: CheckpointId,
    ) -> Result<Self, PublicKeyProjectionPlanError> {
        let mutation = sealed.resolved().mutation();
        if mutation.physical_table() != ScyllaPhysicalTableId::PublicKeyHashToUserIds {
            return Err(PublicKeyProjectionPlanError::WrongPhysicalTable(
                mutation.physical_table(),
            ));
        }
        let (public_key_hash, user) = match mutation.key() {
            TypedTableKey::PublicKeyToUser {
                public_key_hash,
                user,
            } => (public_key_hash.as_bytes(), *user),
            _ => return Err(PublicKeyProjectionPlanError::WrongTypedKey),
        };
        let public_key_hash: [u8; PUBLIC_KEY_HASH_BYTES] =
            public_key_hash.try_into().map_err(|_| {
                PublicKeyProjectionPlanError::InvalidHashLength {
                    actual: public_key_hash.len(),
                }
            })?;
        if mutation.operation() != &MutationOperation::Put(MutationValue::KeyOnly) {
            return Err(PublicKeyProjectionPlanError::ExpectedKeyOnly);
        }

        let mut hasher = Sha256::new();
        hasher.update(b"psy/public-key-projection-birth/v1");
        hasher.update(sealed.intent_digest().as_bytes());
        hasher.update(birth_checkpoint.get().to_be_bytes());
        let birth_digest = PublicKeyProjectionBirthDigest(hasher.finalize().into());

        Ok(Self {
            public_key_hash,
            user,
            birth_checkpoint,
            write_timestamp_us: sealed.timestamp().as_i64(),
            timestamped_intent_digest: sealed.intent_digest(),
            birth_digest,
        })
    }

    pub const fn public_key_hash(&self) -> &[u8; PUBLIC_KEY_HASH_BYTES] {
        &self.public_key_hash
    }

    pub const fn user(&self) -> UserId {
        self.user
    }

    pub const fn birth_checkpoint(&self) -> CheckpointId {
        self.birth_checkpoint
    }

    pub const fn write_timestamp_us(&self) -> i64 {
        self.write_timestamp_us
    }

    pub const fn timestamped_intent_digest(&self) -> TimestampedIntentDigest {
        self.timestamped_intent_digest
    }

    pub const fn birth_digest(&self) -> PublicKeyProjectionBirthDigest {
        self.birth_digest
    }

    pub fn ensure_exact_retry(
        &self,
        sealed: &SealedTimestampedPut,
        birth_checkpoint: CheckpointId,
    ) -> Result<(), PublicKeyProjectionPlanError> {
        let candidate = Self::try_from_sealed(sealed, birth_checkpoint)?;
        if candidate == *self {
            Ok(())
        } else {
            Err(PublicKeyProjectionPlanError::RetryChanged)
        }
    }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::Blob(self.public_key_hash.to_vec()),
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.user.get())),
            PrototypeBindValue::BigInt(self.write_timestamp_us),
        ]
    }

    fn driver_values(&self) -> (Vec<u8>, i64, i64) {
        (
            self.public_key_hash.to_vec(),
            u64_to_i64_exact(self.user.get()),
            self.write_timestamp_us,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKeyProjectionPutBatch {
    birth_checkpoint: CheckpointId,
    write_timestamp_us: i64,
    members: Vec<PublicKeyProjectionPutBinding>,
}

impl PublicKeyProjectionPutBatch {
    pub fn try_from_sealed(
        sealed: &[SealedTimestampedPut],
        birth_checkpoint: CheckpointId,
    ) -> Result<Self, PublicKeyProjectionPlanError> {
        let mut iter = sealed.iter();
        let first = PublicKeyProjectionPutBinding::try_from_sealed(
            iter.next().ok_or(PublicKeyProjectionPlanError::EmptyBatch)?,
            birth_checkpoint,
        )?;
        let write_timestamp_us = first.write_timestamp_us;
        let mut locators = BTreeSet::new();
        locators.insert((first.public_key_hash, first.user));
        let mut members = vec![first];

        for member in iter {
            let binding =
                PublicKeyProjectionPutBinding::try_from_sealed(member, birth_checkpoint)?;
            if binding.write_timestamp_us != write_timestamp_us {
                return Err(PublicKeyProjectionPlanError::MixedWriteTimestamps {
                    expected: write_timestamp_us,
                    actual: binding.write_timestamp_us,
                });
            }
            if !locators.insert((binding.public_key_hash, binding.user)) {
                return Err(PublicKeyProjectionPlanError::DuplicatePhysicalKey);
            }
            members.push(binding);
        }
        Ok(Self {
            birth_checkpoint,
            write_timestamp_us,
            members,
        })
    }

    pub const fn birth_checkpoint(&self) -> CheckpointId {
        self.birth_checkpoint
    }

    pub const fn write_timestamp_us(&self) -> i64 {
        self.write_timestamp_us
    }

    pub fn members(&self) -> &[PublicKeyProjectionPutBinding] {
        &self.members
    }
}

/// Exact deletion of a derived row whose manifest birth is after the target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKeyProjectionPointDeletePlan {
    public_key_hash: [u8; PUBLIC_KEY_HASH_BYTES],
    user: UserId,
    birth_checkpoint: CheckpointId,
    target_checkpoint: CheckpointId,
    fence: DeleteFenceTimestampUs,
}

impl PublicKeyProjectionPointDeletePlan {
    pub fn try_from_orphaned_birth(
        birth: &PublicKeyProjectionPutBinding,
        target_checkpoint: CheckpointId,
        fence: DeleteFenceTimestampUs,
    ) -> Result<Self, PublicKeyProjectionPlanError> {
        if birth.birth_checkpoint <= target_checkpoint {
            return Err(PublicKeyProjectionPlanError::BirthNotAfterTarget {
                birth: birth.birth_checkpoint,
                target: target_checkpoint,
            });
        }
        if fence.as_i64() <= birth.write_timestamp_us {
            return Err(PublicKeyProjectionPlanError::FenceNotAfterWrite {
                fence: fence.as_i64(),
                write: birth.write_timestamp_us,
            });
        }
        let resolved = resolve_key_for_rollback(&TypedTableKey::PublicKeyToUser {
            public_key_hash: PublicKeyHash::new(birth.public_key_hash.to_vec()),
            user: birth.user,
        })?;
        if resolved.physical_table() != ScyllaPhysicalTableId::PublicKeyHashToUserIds {
            return Err(PublicKeyProjectionPlanError::WrongPhysicalTable(
                resolved.physical_table(),
            ));
        }
        Ok(Self {
            public_key_hash: birth.public_key_hash,
            user: birth.user,
            birth_checkpoint: birth.birth_checkpoint,
            target_checkpoint,
            fence,
        })
    }

    pub const fn birth_checkpoint(&self) -> CheckpointId {
        self.birth_checkpoint
    }

    pub const fn target_checkpoint(&self) -> CheckpointId {
        self.target_checkpoint
    }

    pub const fn fence(&self) -> DeleteFenceTimestampUs {
        self.fence
    }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::BigInt(self.fence.as_i64()),
            PrototypeBindValue::Blob(self.public_key_hash.to_vec()),
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.user.get())),
        ]
    }

    fn driver_values(&self) -> (i64, Vec<u8>, i64) {
        (
            self.fence.as_i64(),
            self.public_key_hash.to_vec(),
            u64_to_i64_exact(self.user.get()),
        )
    }
}

struct PreparedPublicKeyProjection {
    put: PreparedStatement,
    point_delete: PreparedStatement,
}

#[allow(dead_code)]
pub(crate) struct PublicKeyProjectionAdapter {
    queries: PublicKeyProjectionQueries,
    consistency: Consistency,
    prepared: PreparedPublicKeyProjection,
}

#[allow(dead_code)]
impl PublicKeyProjectionAdapter {
    pub(crate) async fn prepare_with_consistency(
        session: &Session,
        keyspace: CqlKeyspaceName,
        consistency: Consistency,
    ) -> anyhow::Result<Self> {
        let queries = PublicKeyProjectionQueries::new(&keyspace);
        let prepared = PreparedPublicKeyProjection {
            put: prepare_idempotent(session, queries.put().cql(), consistency).await?,
            point_delete: prepare_idempotent(
                session,
                queries.point_delete().cql(),
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

    pub(crate) const fn queries(&self) -> &PublicKeyProjectionQueries {
        &self.queries
    }

    pub(crate) async fn put_one(
        &self,
        session: &Session,
        binding: &PublicKeyProjectionPutBinding,
    ) -> anyhow::Result<()> {
        session
            .execute_unpaged(&self.prepared.put, binding.driver_values())
            .await?;
        Ok(())
    }

    pub(crate) async fn put_batch(
        &self,
        session: &Session,
        batch_plan: &PublicKeyProjectionPutBatch,
    ) -> anyhow::Result<()> {
        for chunk in batch_plan.members.chunks(MAX_UNLOGGED_BATCH_ROWS) {
            let mut batch = Batch::new(BatchType::Unlogged);
            batch.set_consistency(self.consistency);
            batch.set_is_idempotent(true);
            for _ in chunk {
                batch.append_statement(self.prepared.put.clone());
            }
            let values = chunk
                .iter()
                .map(PublicKeyProjectionPutBinding::driver_values)
                .collect::<Vec<_>>();
            session.batch(&batch, values).await?;
        }
        Ok(())
    }

    pub(crate) async fn delete_one(
        &self,
        session: &Session,
        plan: &PublicKeyProjectionPointDeletePlan,
    ) -> anyhow::Result<()> {
        session
            .execute_unpaged(&self.prepared.point_delete, plan.driver_values())
            .await?;
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
pub enum PublicKeyProjectionPlanError {
    Registry(RegistryReadinessError),
    WrongPhysicalTable(ScyllaPhysicalTableId),
    WrongTypedKey,
    ExpectedKeyOnly,
    InvalidHashLength { actual: usize },
    EmptyBatch,
    MixedWriteTimestamps { expected: i64, actual: i64 },
    DuplicatePhysicalKey,
    RetryChanged,
    BirthNotAfterTarget { birth: CheckpointId, target: CheckpointId },
    FenceNotAfterWrite { fence: i64, write: i64 },
}

impl fmt::Display for PublicKeyProjectionPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(error) => write!(f, "public-key projection is not rollback ready: {error:?}"),
            Self::WrongPhysicalTable(table) => write!(f, "physical table {table:?} is not the public-key projection"),
            Self::WrongTypedKey => f.write_str("public-key projection has the wrong typed key"),
            Self::ExpectedKeyOnly => f.write_str("public-key projection PUT must be key-only"),
            Self::InvalidHashLength { actual } => write!(f, "public-key hash must be {PUBLIC_KEY_HASH_BYTES} bytes, got {actual}"),
            Self::EmptyBatch => f.write_str("public-key projection PUT batch cannot be empty"),
            Self::MixedWriteTimestamps { expected, actual } => write!(f, "public-key projection batch mixes timestamps {expected} and {actual}"),
            Self::DuplicatePhysicalKey => f.write_str("public-key projection batch contains a duplicate physical key"),
            Self::RetryChanged => f.write_str("public-key projection retry changed mutation, timestamp, or birth checkpoint"),
            Self::BirthNotAfterTarget { birth, target } => write!(f, "projection born at {} is not orphaned by target {}", birth.get(), target.get()),
            Self::FenceNotAfterWrite { fence, write } => write!(f, "delete fence {fence} must be greater than projection write timestamp {write}"),
        }
    }
}

impl Error for PublicKeyProjectionPlanError {}

impl From<RegistryReadinessError> for PublicKeyProjectionPlanError {
    fn from(value: RegistryReadinessError) -> Self {
        Self::Registry(value)
    }
}
